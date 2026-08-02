from __future__ import annotations

import argparse


from .banner import STARTER_PARAMETERS, render_startup_screen


def _enable_completion(parser: argparse.ArgumentParser) -> None:
    """Enable shell tab-completion when the optional argcomplete package is present."""
    try:
        import argcomplete
    except ModuleNotFoundError:
        return
    argcomplete.autocomplete(parser)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fastbuster",
        description="Blazing-fast wordlist web path scanner.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    target = p.add_argument_group("target (required)")
    target.add_argument("-u", "--url", required=True, help="Base target URL (e.g., http://10.10.10.10:8080)")
    target.add_argument("-w", "--wordlist", required=True, help="Path to wordlist (.txt or .gz)")

    request = p.add_argument_group("request")
    request.add_argument("-X", "--method", choices=["GET", "HEAD"], default="GET", help="HTTP method")
    request.add_argument("-t", "--timeout", type=float, default=6.0, help="HTTP timeout per request (seconds)")
    request.add_argument("-r", "--retries", type=int, default=1, help="Retry count per request")
    request.add_argument("-H", "--header", action="append", default=[], help="Custom header 'Key: Value' (repeatable)")
    request.add_argument("-A", "--user-agent", default=None, help="Pin a User-Agent (default: random valid UA per request)")
    request.add_argument("-L", "--follow-redirects", action="store_true", help="Follow redirects")

    matching = p.add_argument_group("matching / filtering")
    matching.add_argument("-x", "--extensions", default="", help="Comma-separated extensions (php,txt,bak)")
    matching.add_argument("--status-allow", default="200,204,301-308,401,403", help="Allowed status codes")
    matching.add_argument("--status-deny", default=None, help="Denied status codes")
    matching.add_argument("--min-size", type=int, default=None, help="Minimum body length")
    matching.add_argument("--max-size", type=int, default=None, help="Maximum body length")
    matching.add_argument("--append-slash", action="store_true", help="Also test path with trailing slash")
    matching.add_argument("--wildcard-detect", action="store_true", help="Detect and suppress wildcard responses")

    output = p.add_argument_group("output")
    output.add_argument("-o", "--output", default=None, help="Findings output file")
    output.add_argument("-f", "--output-format", choices=["text", "jsonl", "csv"], default="text", help="Output format")
    output.add_argument("--progress-interval", type=float, default=2.0, help="Progress log interval")
    output.add_argument("--verbose-errors", action="store_true", help="Print request errors")

    perf = p.add_argument_group("performance")
    perf.add_argument("-c", "--concurrency", type=int, default=40, help="Max async workers")
    perf.add_argument("--rate", type=float, default=0.0, help="Global max requests/sec (0 disables)")
    perf.add_argument("--auto-tune", action="store_true", help="Adapt concurrency/rate from live latency and errors")
    perf.add_argument("--no-uvloop", action="store_true", help="Disable uvloop install")

    advanced = p.add_argument_group("advanced")
    advanced.add_argument("--queue-size", type=int, default=20000, help="In-memory candidate queue limit")
    advanced.add_argument("--wildcard-samples", type=int, default=4, help="Random probes for wildcard fingerprinting")
    advanced.add_argument("--resume-file", default=".fastbuster.resume.json", help="Checkpoint file path")
    advanced.add_argument("--no-resume", action="store_true", help="Disable reading/writing checkpoint")
    advanced.add_argument("--checkpoint-every", type=int, default=2000, help="Save checkpoint every N requests")
    advanced.add_argument("--auto-tune-min-concurrency", type=int, default=40, help="Auto-tune floor for inflight requests")
    advanced.add_argument("--auto-tune-min-rate", type=float, default=80.0, help="Auto-tune minimum rps")
    advanced.add_argument("--auto-tune-max-rate", type=float, default=120000.0, help="Auto-tune maximum rps")
    advanced.add_argument("--auto-tune-interval", type=float, default=2.0, help="Auto-tune loop interval")
    advanced.add_argument("--auto-tune-target-error", type=float, default=0.03, help="Target request error rate")
    advanced.add_argument("--auto-tune-latency-ms", type=float, default=900.0, help="Latency budget for tuning")

    _enable_completion(p)
    return p


def print_startup_screen(parser: argparse.ArgumentParser) -> None:
    print(render_startup_screen())
    print()
    print("Base CLI parameters:")
    for key, value in STARTER_PARAMETERS:
        print(f"  --{key:<13} {value}")
