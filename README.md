# PyBuster

PyBuster is a high-speed, wordlist-driven web path scanner inspired by Gobuster/DirBuster patterns.

It is designed for **authorized security testing only**.

## Why this is fast

- Async HTTP client (`aiohttp`) with high concurrency
- Streaming wordlist reader (no full in-memory load)
- Bounded async queue to keep memory stable on huge lists
- Optional `uvloop` acceleration on Unix-like systems
- Connection pooling and keep-alive reuse
- Optional global rate limiting to avoid overwhelming targets
- Adaptive auto-tuning for request rate and active in-flight concurrency

## Features

- Supports very large wordlists (`.txt` and `.gz`)
- Concurrent scanning with configurable worker count
- Status code allow/deny filters
- Response length filters
- Extension expansion (`admin` -> `admin.php`, `admin.bak`, etc.)
- Output file support (`text`, `jsonl`, or `csv`)
- Resume support with checkpoint file
- Custom headers, user-agent, timeout, retries
- Wildcard response fingerprint detection and suppression

## Install

### Kali/Debian: install via APT package name (`fastbuster`)

`fastbuster` is not in the default Debian/Kali repos yet, so this repo includes packaging scripts
to create a local APT repo and install it by package name.

```bash
sudo apt update
sudo apt install -y dpkg-dev python3 python3-aiohttp python3-uvloop

# from this repo root
./packaging/deb/setup-local-apt-repo.sh 0.1.0

# now installs by package name
sudo apt install -y fastbuster
```

Run it directly after install:

```bash
fastbuster --help
```

### Python virtualenv install (development)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 fastbuster.py \
  --url https://example.com \
  --wordlist /path/to/wordlist.txt \
  --concurrency 600 \
  --timeout 5 \
  --status-allow 200,204,301-308,401,403 \
  --extensions php,txt,bak \
  --append-slash \
  --output findings.txt \
  --output-format text
```

### Gzip wordlist example

```bash
python3 fastbuster.py \
  --url https://example.com \
  --wordlist /path/to/big-list.txt.gz \
  --concurrency 800
```

### Auto-tune + wildcard suppression

```bash
python3 fastbuster.py \
  --url https://example.com \
  --wordlist /path/to/huge.txt.gz \
  --concurrency 1200 \
  --auto-tune \
  --auto-tune-min-concurrency 80 \
  --wildcard-detect \
  --wildcard-samples 6
```

### JSONL output example

```bash
python3 fastbuster.py \
  --url https://example.com \
  --wordlist /path/to/wordlist.txt \
  --output results.jsonl \
  --output-format jsonl
```

### CSV output example

```bash
python3 fastbuster.py \
  --url https://example.com \
  --wordlist /path/to/wordlist.txt \
  --output results.csv \
  --output-format csv
```

### Resume example

```bash
python3 fastbuster.py \
  --url https://example.com \
  --wordlist /path/to/wordlist.txt \
  --resume-file .pybuster.resume.json
```

If interrupted, rerun with the same command to continue from the last checkpoint.

## Notes on tuning

- Start around `--concurrency 200` and increase gradually.
- Use `--rate` if the target or network cannot handle burst traffic.
- Use `--auto-tune` for unstable links or rate-limited targets.
- Use `--method HEAD` for lightweight discovery when servers support it.

## Main advanced flags

- `--output-format text|jsonl|csv`: output serializer for saved findings.
- `--wildcard-detect`: probe random paths and suppress matching wildcard fingerprints.
- `--wildcard-samples N`: number of random wildcard probes (default `4`).
- `--auto-tune`: enables adaptive control loop for in-flight concurrency and request rate.
- `--auto-tune-min-concurrency`: lower bound of active in-flight requests during auto-tune.
- `--auto-tune-min-rate`: lower bound of auto-tuned requests/second.
- `--auto-tune-max-rate`: upper bound of auto-tuned requests/second.
- `--auto-tune-latency-ms`: target latency budget used by tuner decisions.

## Disclaimer

You are responsible for obtaining permission before scanning any system.
