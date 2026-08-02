#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
"""High-speed, wordlist-driven web path scanner for authorized testing."""

from __future__ import annotations

import argparse
import asyncio
import csv
import gzip
import hashlib
import json
import os
import random
import secrets
import signal
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

from fastbusterlib.banner import FASTBUSTER_BANNER
from fastbusterlib.cli import build_parser, print_startup_screen

try:
    import aiohttp
except ModuleNotFoundError:
    aiohttp = None  # type: ignore[assignment]


def try_install_uvloop(disabled: bool) -> None:
    if disabled:
        return
    try:
        import uvloop  # type: ignore

        uvloop.install()
    except Exception:
        # uvloop is optional; continue with default event loop.
        return


@dataclass(frozen=True)
class Candidate:
    idx: int
    path: str
    source: str


class AsyncRateLimiter:
    """Simple global token spacing limiter for requests/second."""

    def __init__(self, rate: Optional[float]) -> None:
        self.rate = rate if rate and rate > 0 else None
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        rate = self.rate
        if not rate:
            return
        interval = 1.0 / rate
        async with self._lock:
            now = time.perf_counter()
            if now < self._next:
                await asyncio.sleep(self._next - now)
                now = time.perf_counter()
            self._next = max(now, self._next) + interval

    async def set_rate(self, rate: float) -> None:
        async with self._lock:
            self.rate = max(1.0, rate)


class AdaptiveConcurrencyGate:
    """Dynamic cap on in-flight requests without recreating workers."""

    def __init__(self, initial_limit: int, max_limit: int) -> None:
        self.limit = max(1, initial_limit)
        self.max_limit = max(1, max_limit)
        self.active = 0
        self._cond = asyncio.Condition()

    async def acquire(self) -> None:
        async with self._cond:
            while self.active >= self.limit:
                await self._cond.wait()
            self.active += 1

    async def release(self) -> None:
        async with self._cond:
            self.active = max(0, self.active - 1)
            self._cond.notify_all()

    async def set_limit(self, new_limit: int) -> None:
        async with self._cond:
            self.limit = max(1, min(self.max_limit, new_limit))
            self._cond.notify_all()


class StatusFilter:
    def __init__(self, allow: Optional[Set[int]], deny: Optional[Set[int]]) -> None:
        self.allow = allow
        self.deny = deny

    def matches(self, status: int) -> bool:
        if self.allow is not None and status not in self.allow:
            return False
        if self.deny is not None and status in self.deny:
            return False
        return True


class Checkpoint:
    def __init__(self, path: Path, enabled: bool = True) -> None:
        self.path = path
        self.enabled = enabled

    def load(self) -> int:
        if not self.enabled or not self.path.exists():
            return 0
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            value = int(data.get("processed_candidates", 0))
            return max(0, value)
        except Exception:
            return 0

    def save(self, processed_candidates: int, matches: int, errors: int) -> None:
        if not self.enabled:
            return
        payload = {
            "processed_candidates": processed_candidates,
            "matches": matches,
            "errors": errors,
            "updated_unix": int(time.time()),
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)


class OutputWriter:
    def __init__(self, handle, output_format: str) -> None:
        self.handle = handle
        self.output_format = output_format
        self._seen_urls: Set[str] = set()
        self._buffered_matches: List[Dict[str, Any]] = []
        if self.handle is not None and self.output_format == "csv":
            self._csv_writer = csv.DictWriter(
                self.handle,
                fieldnames=["status", "length", "url", "path", "source", "candidate_index"],
            )
            if self.handle.tell() == 0:
                self._csv_writer.writeheader()
        else:
            self._csv_writer = None

    def _supports_color(self) -> bool:
        return sys.stdout.isatty() and os.getenv("NO_COLOR") is None

    def _colorize(self, text: str, ansi_code: str) -> str:
        if not self._supports_color():
            return text
        return f"{ansi_code}{text}\033[0m"

    def _status_label(self, status: int) -> str:
        return {
            100: "100 Continue",
            101: "101 Switching Protocols",
            200: "200 OK",
            201: "201 Created",
            202: "202 Accepted",
            204: "204 No Content",
            301: "301 Moved Permanently",
            302: "302 Found",
            303: "303 See Other",
            304: "304 Not Modified",
            307: "307 Temporary Redirect",
            308: "308 Permanent Redirect",
            400: "400 Bad Request",
            401: "401 Unauthorized",
            403: "403 Forbidden",
            404: "404 Not Found",
            405: "405 Method Not Allowed",
            429: "429 Too Many Requests",
            500: "500 Internal Server Error",
            502: "502 Bad Gateway",
            503: "503 Service Unavailable",
        }.get(status, f"{status}")

    def format_match_line(self, match: Dict[str, Any]) -> str:
        status = int(match["status"])
        status_label = self._status_label(status)
        if 200 <= status < 300:
            color = "\033[92m"
        elif 300 <= status < 400:
            color = "\033[93m"
        elif 400 <= status < 500:
            color = "\033[91m"
        else:
            color = "\033[95m"

        status_text = self._colorize(f"{status_label:<24}", color)
        size_text = self._colorize(f"{match['length']:>8}", "\033[36m")
        source_text = self._colorize(f"{str(match.get('source', 'unknown')):<10}", "\033[35m")
        path_text = self._colorize(f"{match['path']:<30}", "\033[34m")
        url_text = self._colorize(match["url"], "\033[90m")
        return f" {status_text} | {size_text} | {source_text} | {path_text} | {url_text}"

    def _table_separator(self) -> str:
        return "-" * 26 + "+" + "-" * 10 + "+" + "-" * 12 + "+" + "-" * 32 + "+" + "-" * 40

    def format_header(self) -> str:
        h_status = f"{'STATUS':<24}"
        h_size = f"{'SIZE':>8}"
        h_source = f"{'SOURCE':<10}"
        h_path = f"{'PATH':<30}"
        h_url = "URL"
        header = f" {h_status} | {h_size} | {h_source} | {h_path} | {h_url}"
        return "\n[RESULTS]\n" + self._colorize(header, "\033[1;33m") + "\n" + self._table_separator()

    def format_summary(self, matches: int, candidates: int, errors: int, elapsed: float) -> str:
        summary = f"[SUMMARY] matches={matches} candidates={candidates} errors={errors} elapsed={elapsed:.2f}s"
        return self._table_separator() + "\n" + self._colorize(summary, "\033[1m")

    def format_results(self, matches: Optional[Iterable[Dict[str, Any]]] = None) -> str:
        rows = list(matches if matches is not None else self._buffered_matches)
        rows.sort(key=lambda item: str(item.get("path", "")))
        lines = [self.format_header()]
        for match in rows:
            lines.append(self.format_match_line(match))
        return "\n".join(lines)

    def record_match(self, match: Dict[str, Any]) -> None:
        self._buffered_matches.append(match)

    def _canonical_url(self, url: str) -> str:
        normalized = url.rstrip("/")
        return normalized if normalized else url

    def should_emit(self, match: Dict[str, Any]) -> bool:
        url = str(match.get("url", ""))
        if not url:
            return False
        canonical = self._canonical_url(url)
        if canonical in self._seen_urls:
            return False
        self._seen_urls.add(canonical)
        return True

    def write(self, match: Dict[str, Any]) -> None:
        if self.handle is None:
            return
        if self.output_format == "text":
            self.handle.write(
                f"[{match['status']}] {match['length']:>8}  {match.get('source', 'unknown')}  {match['path']}  {match['url']}\n"
            )
            return
        if self.output_format == "jsonl":
            self.handle.write(json.dumps(match, separators=(",", ":")) + "\n")
            return
        if self._csv_writer is not None:
            self._csv_writer.writerow(match)


def parse_statuses(value: Optional[str]) -> Optional[Set[int]]:
    if not value:
        return None

    statuses: Set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            left, right = token.split("-", 1)
            start = int(left)
            end = int(right)
            if start > end:
                start, end = end, start
            statuses.update(range(start, end + 1))
        else:
            statuses.add(int(token))
    return statuses


def parse_headers(values: List[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in values:
        if ":" not in item:
            raise ValueError(f"Invalid header format: {item!r}. Use 'Key: Value'.")
        k, v = item.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def build_default_headers() -> Dict[str, str]:
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "DNT": "1",
    }


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
]


def pick_user_agent() -> str:
    return random.choice(USER_AGENTS)


def normalize_base_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def ensure_aiohttp_available() -> None:
    if aiohttp is None:
        raise ModuleNotFoundError(
            "No module named 'aiohttp'. Install runtime dependencies with:\n"
            "  sudo apt install -y python3-aiohttp python3-uvloop"
        )


async def check_host_reachable(
    session: aiohttp.ClientSession,
    base_url: str,
    timeout: float,
    method: str,
    follow_redirects: bool,
) -> bool:
    probe_method = "HEAD" if method == "GET" else method
    try:
        async with session.request(
            probe_method,
            base_url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=follow_redirects,
            headers=build_default_headers(),
        ) as resp:
            if resp.status in {405, 501} and probe_method == "HEAD":
                async with session.get(
                    base_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=follow_redirects,
                    headers=build_default_headers(),
                ) as fallback_resp:
                    return fallback_resp.status < 500
            return resp.status < 500 or resp.status in {405, 501}
    except Exception:
        return False


async def fetch_robots_lines(session: aiohttp.ClientSession, base_url: str, timeout: float) -> List[str]:
    robots_url = f"{base_url}/robots.txt"
    try:
        async with session.get(robots_url, timeout=aiohttp.ClientTimeout(total=timeout), headers=build_default_headers()) as resp:
            if resp.status >= 400:
                return []
            body = await resp.text(encoding="utf-8", errors="ignore")
            paths: List[str] = []
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                key, value = line.split(":", 1)
                if key.lower() == "disallow" and value.strip():
                    value = value.strip()
                    if value == "/":
                        continue
                    value = value.lstrip("/")
                    if value:
                        paths.append(value)
            return paths
    except Exception:
        return []


def iter_wordlist(path: Path) -> Iterable[str]:
    opener = gzip.open if path.suffix.lower() == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            word = raw.strip()
            if not word or word.startswith("#"):
                continue
            yield word


def expand_word(word: str, extensions: List[str], append_slash: bool) -> Iterable[str]:
    base = word.lstrip("/")
    if base:
        yield base
        if append_slash:
            yield base + "/"
    for ext in extensions:
        if not ext:
            continue
        ext = ext.lstrip(".")
        if not ext:
            continue
        yield f"{base}.{ext}"


class Stats:
    def __init__(self) -> None:
        self.processed = 0
        self.matches = 0
        self.errors = 0
        self.total_candidates: Optional[int] = None
        self.start = time.perf_counter()
        self._lock = asyncio.Lock()
        self._recent: Deque[Tuple[float, bool]] = deque(maxlen=2500)

    def set_total_candidates(self, total: int) -> None:
        self.total_candidates = max(0, total)

    async def inc_processed(self) -> int:
        async with self._lock:
            self.processed += 1
            return self.processed

    async def inc_match(self) -> None:
        async with self._lock:
            self.matches += 1

    async def inc_error(self) -> None:
        async with self._lock:
            self.errors += 1

    async def record_latency(self, latency_ms: float, is_error: bool) -> None:
        async with self._lock:
            self._recent.append((latency_ms, is_error))

    async def recent_snapshot(self) -> Tuple[int, float, float]:
        async with self._lock:
            if not self._recent:
                return 0, 0.0, 0.0
            count = len(self._recent)
            err_count = sum(1 for _, e in self._recent if e)
            avg_ms = sum(v for v, _ in self._recent) / count
            return count, err_count / count, avg_ms

    def rps(self) -> float:
        elapsed = time.perf_counter() - self.start
        if elapsed <= 0:
            return 0.0
        return self.processed / elapsed


async def producer(
    queue: asyncio.Queue[Optional[Candidate]],
    wordlist: Path,
    extensions: List[str],
    append_slash: bool,
    skip_candidates: int,
    workers: int,
    session: aiohttp.ClientSession,
    base_url: str,
    timeout: float,
) -> int:
    candidates: List[Candidate] = []
    idx = 0
    for word in iter_wordlist(wordlist):
        for candidate in expand_word(word, extensions, append_slash):
            idx += 1
            if idx <= skip_candidates:
                continue
            candidates.append(Candidate(idx=idx, path=candidate, source="wordlist"))

    robots_paths = await fetch_robots_lines(session=session, base_url=base_url, timeout=timeout)
    for path in robots_paths:
        idx += 1
        if idx <= skip_candidates:
            continue
        candidates.append(Candidate(idx=idx, path=path, source="robots"))

    random.shuffle(candidates)
    for candidate in candidates:
        await queue.put(candidate)
    for _ in range(workers):
        await queue.put(None)
    return idx


def response_signature(status: int, length: int, body: bytes) -> str:
    digest = hashlib.blake2b(body[:1024], digest_size=8).hexdigest()
    return f"{status}:{length}:{digest}"


async def fetch_once(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    timeout: float,
    retries: int,
    follow_redirects: bool,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[int], Optional[int], Optional[str], Optional[str], float]:
    last_error: Optional[str] = None
    t0 = time.perf_counter()
    for attempt in range(retries + 1):
        try:
            req_timeout = aiohttp.ClientTimeout(total=timeout)
            request_headers = dict(headers or build_default_headers())
            request_headers.update({k: v for k, v in build_default_headers().items() if k not in request_headers})
            # Rotate a random valid UA per request unless the caller pinned one.
            request_headers.setdefault("User-Agent", pick_user_agent())

            async with session.request(
                method,
                url,
                timeout=req_timeout,
                allow_redirects=follow_redirects,
                headers=request_headers,
            ) as resp:
                body = await resp.read()
                lat_ms = (time.perf_counter() - t0) * 1000.0
                sig = response_signature(resp.status, len(body), body)
                return resp.status, len(body), sig, None, lat_ms
        except Exception as exc:
            last_error = str(exc)
            if attempt < retries:
                await asyncio.sleep(0)
    lat_ms = (time.perf_counter() - t0) * 1000.0
    return None, None, None, last_error, lat_ms


async def detect_wildcard_signatures(
    session: aiohttp.ClientSession,
    base_url: str,
    method: str,
    timeout: float,
    retries: int,
    follow_redirects: bool,
    samples: int,
) -> Set[str]:
    signatures: Set[str] = set()
    for _ in range(max(1, samples)):
        rand_path = f"__fastbuster_{secrets.token_hex(12)}__"
        target = f"{base_url}/{rand_path}"
        status, length, sig, err, _ = await fetch_once(
            session=session,
            method=method,
            url=target,
            timeout=timeout,
            retries=retries,
            follow_redirects=follow_redirects,
        )
        if err is None and status is not None and length is not None and sig is not None:
            signatures.add(sig)
    return signatures


async def worker(
    worker_id: int,
    queue: asyncio.Queue[Optional[Candidate]],
    session: aiohttp.ClientSession,
    base_url: str,
    method: str,
    limiter: AsyncRateLimiter,
    gate: AdaptiveConcurrencyGate,
    status_filter: StatusFilter,
    min_size: Optional[int],
    max_size: Optional[int],
    timeout: float,
    retries: int,
    follow_redirects: bool,
    stats: Stats,
    checkpoint: Checkpoint,
    checkpoint_every: int,
    resume_offset: int,
    output_writer: OutputWriter,
    wildcard_signatures: Set[str],
    output_lock: asyncio.Lock,
    verbose_errors: bool,
    headers: Optional[Dict[str, str]],
) -> None:
    del worker_id
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            return

        await limiter.wait()
        await gate.acquire()
        target = f"{base_url}/{item.path}"

        try:
            status, length, sig, err, lat_ms = await fetch_once(
                session=session,
                method=method,
                url=target,
                timeout=timeout,
                retries=retries,
                follow_redirects=follow_redirects,
                headers=headers,
            )
        finally:
            await gate.release()

        processed = await stats.inc_processed()
        await stats.record_latency(lat_ms, err is not None)

        if err is not None:
            await stats.inc_error()
            if verbose_errors:
                async with output_lock:
                    print(f"[ERR] {target} -> {err}")
        else:
            assert status is not None
            assert length is not None
            assert sig is not None
            if sig in wildcard_signatures:
                queue.task_done()
                continue

            if status_filter.matches(status):
                if min_size is not None and length < min_size:
                    pass
                elif max_size is not None and length > max_size:
                    pass
                else:
                    match = {
                        "status": status,
                        "length": length,
                        "url": target,
                        "path": item.path,
                        "candidate_index": item.idx,
                        "source": item.source,
                    }
                    if output_writer.should_emit(match):
                        await stats.inc_match()
                        output_writer.record_match(match)
                        output_writer.write(match)

        if checkpoint_every > 0 and processed % checkpoint_every == 0:
            checkpoint.save(stats.processed + resume_offset, stats.matches, stats.errors)

        queue.task_done()


def format_progress_message(stats: Stats, gate: AdaptiveConcurrencyGate, limiter: AsyncRateLimiter) -> str:
    processed = stats.processed
    total_candidates = stats.total_candidates
    if total_candidates is None or total_candidates <= 0:
        percent = 0.0
    else:
        percent = min(100.0, (processed / total_candidates) * 100.0)
    bar_width = 30
    filled = int(percent / 100.0 * bar_width)
    bar = "#" * filled + "-" * (bar_width - filled)
    return f"[PROGRESS] {bar} {percent:5.1f}% | matches={stats.matches} | errors={stats.errors} | rps={stats.rps():.1f}"


async def progress_reporter(
    stats: Stats,
    interval: float,
    stop_event: asyncio.Event,
    gate: AdaptiveConcurrencyGate,
    limiter: AsyncRateLimiter,
) -> None:
    while not stop_event.is_set():
        await asyncio.sleep(interval)
        if stop_event.is_set():
            break
        message = format_progress_message(stats, gate, limiter)
        print(f"\r{message}", file=sys.stderr, end="", flush=True)
    print(file=sys.stderr)


async def auto_tuner(
    stats: Stats,
    stop_event: asyncio.Event,
    gate: AdaptiveConcurrencyGate,
    limiter: AsyncRateLimiter,
    min_limit: int,
    max_limit: int,
    min_rate: float,
    max_rate: float,
    interval: float,
    target_error: float,
    latency_budget_ms: float,
) -> None:
    while not stop_event.is_set():
        await asyncio.sleep(interval)
        if stop_event.is_set():
            break

        count, err_rate, avg_ms = await stats.recent_snapshot()
        if count < 200:
            continue

        next_limit = gate.limit
        next_rate = limiter.rate if limiter.rate else max(min_rate, float(gate.limit) * 4.0)

        overloaded = err_rate > target_error or avg_ms > latency_budget_ms
        healthy = err_rate < (target_error * 0.35) and avg_ms < (latency_budget_ms * 0.7)

        if overloaded:
            next_limit = max(min_limit, int(gate.limit * 0.85))
            next_rate = max(min_rate, next_rate * 0.85)
        elif healthy:
            next_limit = min(max_limit, gate.limit + max(1, int(gate.limit * 0.08)))
            next_rate = min(max_rate, next_rate * 1.08)

        if next_limit != gate.limit:
            await gate.set_limit(next_limit)
        if abs(next_rate - (limiter.rate or 0.0)) > 0.25:
            await limiter.set_rate(next_rate)


async def shutdown_tasks(
    stop_event: asyncio.Event,
    tasks: Iterable[asyncio.Task[Any]],
    reporter_task: Optional[asyncio.Task[Any]] = None,
    tuner_task: Optional[asyncio.Task[Any]] = None,
    producer_task: Optional[asyncio.Task[Any]] = None,
) -> None:
    stop_event.set()

    all_tasks: List[asyncio.Task[Any]] = []
    for task in tasks:
        if not task.done():
            task.cancel()
            all_tasks.append(task)

    if reporter_task is not None and not reporter_task.done():
        reporter_task.cancel()
        all_tasks.append(reporter_task)

    if tuner_task is not None and not tuner_task.done():
        tuner_task.cancel()
        all_tasks.append(tuner_task)

    if producer_task is not None and not producer_task.done():
        producer_task.cancel()
        all_tasks.append(producer_task)

    if all_tasks:
        await asyncio.gather(*all_tasks, return_exceptions=True)


async def run(args: argparse.Namespace) -> int:
    ensure_aiohttp_available()
    base_url = normalize_base_url(args.url)
    wordlist = Path(args.wordlist)

    if not wordlist.exists() or not wordlist.is_file():
        print(f"[FATAL] wordlist not found: {wordlist}", file=sys.stderr)
        return 2

    if args.concurrency < 1:
        print("[FATAL] --concurrency must be >= 1", file=sys.stderr)
        return 2

    if args.queue_size < args.concurrency:
        print("[FATAL] --queue-size must be >= --concurrency", file=sys.stderr)
        return 2

    headers = build_default_headers()
    headers.update(parse_headers(args.header))
    if args.user_agent:
        headers["User-Agent"] = args.user_agent

    allow = parse_statuses(args.status_allow)
    deny = parse_statuses(args.status_deny)
    status_filter = StatusFilter(allow=allow, deny=deny)

    extensions = [e.strip() for e in args.extensions.split(",") if e.strip()]

    checkpoint = Checkpoint(Path(args.resume_file), enabled=not args.no_resume)
    skip = checkpoint.load()
    if skip > 0 and not args.no_resume and checkpoint.path.exists():
        print(
            f"[INFO] resuming from checkpoint {checkpoint.path} (processed_candidates={skip}); "
            "rerun with --no-resume to start from the beginning"
        )

    queue: asyncio.Queue[Optional[Candidate]] = asyncio.Queue(maxsize=args.queue_size)
    limiter = AsyncRateLimiter(args.rate if args.rate > 0 else None)
    gate = AdaptiveConcurrencyGate(
        initial_limit=args.concurrency,
        max_limit=args.concurrency,
    )
    stats = Stats()
    output_lock = asyncio.Lock()

    output_handle = None
    if args.output:
        output_handle = open(args.output, "a", encoding="utf-8", newline="")
    output_writer = OutputWriter(output_handle, args.output_format)

    stop_event = asyncio.Event()

    connector = aiohttp.TCPConnector(
        limit=0,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
        ssl=False,
    )

    client_timeout = aiohttp.ClientTimeout(total=None)

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=client_timeout,
        headers=headers,
        raise_for_status=False,
        trust_env=True,
    ) as session:
        if not await check_host_reachable(
            session=session,
            base_url=base_url,
            timeout=args.timeout,
            method=args.method,
            follow_redirects=args.follow_redirects,
        ):
            print(f"[FATAL] host not reachable: {base_url}", file=sys.stderr)
            return 2

        user_agent = headers.get("User-Agent", "random (rotating)")
        print(FASTBUSTER_BANNER)
        print()
        print("[RUN] starting scan")
        print(f"  url          {base_url}")
        print(f"  concurrency  {args.concurrency}")
        print(f"  wordlist     {wordlist}")
        print(f"  useragent    {user_agent}")

        wildcard_signatures: Set[str] = set()
        if args.wildcard_detect:
            wildcard_signatures = await detect_wildcard_signatures(
                session=session,
                base_url=base_url,
                method=args.method,
                timeout=args.timeout,
                retries=args.retries,
                follow_redirects=args.follow_redirects,
                samples=args.wildcard_samples,
            )
            print(f"[INFO] wildcard_signatures={len(wildcard_signatures)}")

        if args.auto_tune and not limiter.rate:
            initial_rate = min(
                args.auto_tune_max_rate,
                max(args.auto_tune_min_rate, float(args.concurrency) * 4.0),
            )
            await limiter.set_rate(initial_rate)

        reporter = asyncio.create_task(
            progress_reporter(stats, args.progress_interval, stop_event, gate, limiter)
        )

        tuner_task = None
        if args.auto_tune:
            min_limit = min(max(1, args.auto_tune_min_concurrency), args.concurrency)
            tuner_task = asyncio.create_task(
                auto_tuner(
                    stats=stats,
                    stop_event=stop_event,
                    gate=gate,
                    limiter=limiter,
                    min_limit=min_limit,
                    max_limit=args.concurrency,
                    min_rate=max(1.0, args.auto_tune_min_rate),
                    max_rate=max(1.0, args.auto_tune_max_rate),
                    interval=max(0.5, args.auto_tune_interval),
                    target_error=max(0.001, min(0.5, args.auto_tune_target_error)),
                    latency_budget_ms=max(50.0, args.auto_tune_latency_ms),
                )
            )

        worker_tasks = [
            asyncio.create_task(
                worker(
                    worker_id=i,
                    queue=queue,
                    session=session,
                    base_url=base_url,
                    method=args.method,
                    limiter=limiter,
                    gate=gate,
                    status_filter=status_filter,
                    min_size=args.min_size,
                    max_size=args.max_size,
                    timeout=args.timeout,
                    retries=args.retries,
                    follow_redirects=args.follow_redirects,
                    stats=stats,
                    checkpoint=checkpoint,
                    checkpoint_every=args.checkpoint_every,
                    resume_offset=skip,
                    output_writer=output_writer,
                    wildcard_signatures=wildcard_signatures,
                    output_lock=output_lock,
                    verbose_errors=args.verbose_errors,
                    headers=headers,
                )
            )
            for i in range(args.concurrency)
        ]

        prod_task = asyncio.create_task(
            producer(
                queue=queue,
                wordlist=wordlist,
                extensions=extensions,
                append_slash=args.append_slash,
                skip_candidates=skip,
                workers=args.concurrency,
                session=session,
                base_url=base_url,
                timeout=args.timeout,
            )
        )

        total_candidates = 0
        interrupted = False
        try:
            total_candidates = await prod_task
            stats.set_total_candidates(total_candidates)
            if not stop_event.is_set():
                await queue.join()
            if not stop_event.is_set():
                await asyncio.gather(*worker_tasks)
        except KeyboardInterrupt:
            interrupted = True
            raise
        except asyncio.CancelledError:
            interrupted = True
            raise
        finally:
            stop_event.set()
            if interrupted:
                await shutdown_tasks(
                    stop_event,
                    worker_tasks,
                    reporter_task=reporter,
                    tuner_task=tuner_task,
                    producer_task=prod_task,
                )
            else:
                await reporter
                if tuner_task is not None:
                    await tuner_task

    if not interrupted:
        checkpoint.save(stats.processed + skip, stats.matches, stats.errors)

    if output_handle is not None:
        output_handle.flush()
        output_handle.close()

    if interrupted:
        return 130

    print(output_writer.format_results())
    elapsed = max(0.001, time.perf_counter() - stats.start)
    print(output_writer.format_summary(stats.matches, total_candidates, stats.errors, elapsed))

    return 0


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        print_startup_screen(parser)
        return 0
    args = parser.parse_args()
    try_install_uvloop(args.no_uvloop)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("[INFO] interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())