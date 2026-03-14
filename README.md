# port-scan

A high-performance, asynchronous TCP port scanner written in Rust. Built for cybersecurity professionals and network engineers who need reliable, fast, and safe reconnaissance tooling.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Security Model](#security-model)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [CLI Reference](#cli-reference)
- [Output Format](#output-format)
- [Service Detection](#service-detection)
- [Testing](#testing)
- [CI/CD](#cicd)
- [Legal Notice](#legal-notice)

---

## Overview

`port-scan` combines the Tokio asynchronous runtime with a semaphore-based concurrency model to perform large-scale TCP scanning without exhausting OS-level file descriptors. It supports two operation modes: a guided interactive wizard for manual use, and a fully non-interactive CLI mode suitable for automation and scripting pipelines.

---

## Features

**Scanning**
- Asynchronous TCP connection engine via Tokio
- Configurable worker pool with semaphore-based concurrency limiting
- CIDR block scanning with automated host enumeration (up to /16)
- DNS hostname resolution with duplicate IP deduplication
- Port range scanning and explicit port list support with automatic deduplication
- Per-connection configurable timeout

**Intelligence**
- Banner grabbing on open ports with a dedicated 500ms read window
- Automatic service identification from banner content and port number
- Detection of 14 common services including SSH, HTTP, SMTP, MySQL, Redis, and MongoDB

**Output**
- Real-time terminal progress bar with elapsed time and ETA
- Inline open-port reporting with service label and banner during the scan
- Structured JSON report generation with service and banner fields
- Output path validation with parent directory existence check

**Interface**
- Interactive wizard mode with sensible defaults for guided use
- Full CLI mode with short and long flag variants for scripting

---

## Security Model

The tool enforces the following protections to prevent misuse and resource abuse:

| Protection | Detail |
| :--- | :--- |
| CIDR size limit | Blocks networks larger than /16 (65,534 hosts) to prevent memory exhaustion |
| Blocked endpoints | Rejects scans targeting cloud metadata services (169.254.169.254, 100.100.100.200) |
| Port deduplication | Sorts and deduplicates port lists to prevent task-multiplication from repeated entries |
| Workers validation | Rejects a workers value of 0 to prevent indefinite semaphore blocking |
| Port range validation | Rejects inverted ranges where start port exceeds end port |
| Deadlock prevention | The channel receiver runs in a dedicated concurrent task, ensuring producers never block indefinitely regardless of how many ports are found open |
| Banner sanitization | Banner content is filtered to printable ASCII characters only, preventing terminal control sequence injection |
| Output path validation | Validates parent directory existence before writing; does not restrict to the current directory |
| Zero-allocation connect | Uses `SocketAddr` directly instead of string formatting per connection |

---

## Architecture

```
main()
  |
  |-- parse_targets()     Resolves CIDR, IP, or hostname to Vec<IpAddr>
  |-- parse_ports()       Builds deduplicated, sorted Vec<u16> from range or list
  |
  |-- tokio::spawn(receiver_task)
  |     Drains the mpsc channel concurrently, builds Vec<ScanResult>
  |
  |-- producer loop (semaphore-gated)
  |     For each (ip, port):
  |       acquire semaphore permit
  |       tokio::spawn -> scan_port() -> read_banner() -> detect_service()
  |       send (ip, port, banner) to channel
  |       drop permit
  |
  |-- drop(tx)            Signals receiver task that all producers are done
  |-- receiver_handle.await  Collects final results
  |-- fs::write()         Optional JSON report
```

The receiver task is spawned before the producer loop begins. This is the critical design decision that prevents deadlock: with a bounded channel (200 slots) and up to 1,000 concurrent workers, a naive sequential receiver would allow the channel to fill while all semaphore permits are held by blocked producers, causing permanent suspension. The concurrent receiver ensures the channel is drained in real time.

---

## Installation

### Prerequisites

- Rust toolchain 1.70 or later ([rustup.rs](https://rustup.rs))

### Build from Source

```bash
git clone <repository-url>
cd rust-scan-main
cargo build --release
```

### Install System-Wide (Linux / macOS)

```bash
sudo cp target/release/port-scan /usr/local/bin/
```

After installation, `port-scan` is available from any directory.

### Windows

Build with `cargo build --release`. The binary will be located at `target\release\port-scan.exe`. Add its directory to `PATH` or invoke it directly.

---

## Usage

### Interactive Mode

Running the binary with no arguments launches the interactive wizard:

```
port-scan
```

The wizard prompts for target, timeout, port range, worker count, and optional JSON output path.

### CLI Mode — Single IP

```bash
port-scan --target 192.168.1.1
```

### CLI Mode — Hostname with DNS Resolution

```bash
port-scan --target example.com --start-port 1 --end-port 1024
```

### CLI Mode — CIDR Subnet

```bash
port-scan --target 192.168.0.0/24 --start-port 1 --end-port 65535 --output report.json
```

### CLI Mode — Specific Ports

```bash
port-scan -t 10.0.0.1 -p 22,80,443,3306,5432,6379
```

### CLI Mode — High-Speed Scan Without Banner Grabbing

```bash
port-scan -t 192.168.1.0/24 -p 22,80,443,8080,8443 -w 2000 --no-banner --output fast_scan.json
```

### CLI Mode — Reduced Timeout for Local Networks

```bash
port-scan -t 192.168.1.0/24 -o 50 --start-port 1 --end-port 1024
```

---

## CLI Reference

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--target` | `-t` | — | Target IP address, hostname, or CIDR block |
| `--timeout` | `-o` | `200` | Per-connection timeout in milliseconds |
| `--start-port` | — | `1` | Start of port range (inclusive) |
| `--end-port` | — | `1024` | End of port range (inclusive) |
| `--ports` | `-p` | — | Comma-separated port list. Overrides `--start-port`/`--end-port` |
| `--workers` | `-w` | `1000` | Maximum number of concurrent TCP connections |
| `--output` | — | — | Path to write the JSON report (e.g., `report.json`, `./out/scan.json`) |
| `--no-banner` | — | — | Skip banner grabbing for faster scans |

**Notes**

- `--ports` and the `--start-port`/`--end-port` range are mutually exclusive. When `--ports` is provided, it takes precedence.
- Duplicate ports in `--ports` are silently deduplicated before scanning.
- CIDR blocks larger than /16 are rejected to protect against memory exhaustion.
- Scanning `169.254.169.254` and `100.100.100.200` (cloud instance metadata endpoints) is blocked.
- `--workers 0` is rejected. Values above your OS file descriptor limit will result in connection errors on the excess workers.

---

## Output Format

### Terminal

During the scan, open ports are reported inline as they are discovered:

```
  [+] 192.168.1.1:22 [OPEN] SSH | SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  [+] 192.168.1.1:80 [OPEN] HTTP
  [+] 192.168.1.1:3306 [OPEN] MySQL
```

### JSON Report

When `--output` is specified, a structured JSON file is written after the scan completes. Fields `service` and `banner` are omitted when not available.

```json
[
  {
    "ip": "192.168.1.1",
    "port": 22,
    "status": "OPEN",
    "service": "SSH",
    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  },
  {
    "ip": "192.168.1.1",
    "port": 80,
    "status": "OPEN",
    "service": "HTTP"
  },
  {
    "ip": "192.168.1.1",
    "port": 3306,
    "status": "OPEN",
    "service": "MySQL"
  }
]
```

---

## Service Detection

Service identification uses a two-stage strategy:

1. **Banner analysis (primary):** The tool attempts to read the first 256 bytes from the open connection within a 500ms window. The content is matched against known protocol signatures.

2. **Port-based fallback:** If no banner is received or banner grabbing is disabled, the port number is matched against a table of well-known services.

| Port(s) | Service |
| :---: | :--- |
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25, 587 | SMTP |
| 53 | DNS |
| 80, 8000, 8080 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443, 8443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 27017 | MongoDB |

Ports not listed in the table that produce no recognizable banner are reported as open without a service label.

---

## Testing

### Unit Tests

The test suite covers input parsing, service detection, and output path validation.

```bash
cargo test
```

```
running 15 tests
test tests::test_detect_service_by_banner         ... ok
test tests::test_detect_service_by_port           ... ok
test tests::test_parse_blocked_ip                 ... ok
test tests::test_parse_cidr_slash24               ... ok
test tests::test_parse_cidr_too_large             ... ok
test tests::test_parse_invalid_cidr               ... ok
test tests::test_parse_invalid_ip                 ... ok
test tests::test_parse_ports_dedup                ... ok
test tests::test_parse_ports_invalid              ... ok
test tests::test_parse_ports_inverted_range       ... ok
test tests::test_parse_ports_list                 ... ok
test tests::test_parse_ports_range                ... ok
test tests::test_parse_single_ip                  ... ok
test tests::test_validate_output_path_invalid_dir ... ok
test tests::test_validate_output_path_valid       ... ok

test result: ok. 15 passed; 0 failed; 0 ignored
```

### Manual Verification

Before running a scan, check which ports are actually open on the target so you know what results to expect:

```bash
# Linux
ss -tlnp

# macOS
netstat -an | grep LISTEN
```

**Scanning localhost — basic connectivity check:**

```bash
./target/release/port-scan -t 127.0.0.1 --start-port 1 --end-port 1024
```

**Testing banner grabbing and service detection:**

```bash
./target/release/port-scan -t 127.0.0.1 -p 22,80,443,3306,5432,6379
```

**Testing JSON output:**

```bash
./target/release/port-scan -t 127.0.0.1 -p 22,80,443 --output resultado.json
cat resultado.json
```

**Testing DNS resolution:**

```bash
./target/release/port-scan -t localhost -p 22,80,443
```

**Testing high-speed mode (no banner grabbing, high worker count):**

```bash
./target/release/port-scan -t 127.0.0.1 --start-port 1 --end-port 65535 -w 2000 --no-banner
```

### Verifying Security Guardrails

Each of the following commands must fail with a clear error message and a non-zero exit code:

```bash
# CIDR larger than /16 — memory exhaustion protection
./target/release/port-scan -t 10.0.0.0/8

# Cloud metadata endpoint — SSRF protection
./target/release/port-scan -t 169.254.169.254

# Zero workers — indefinite hang protection
./target/release/port-scan -t 127.0.0.1 -w 0

# Inverted port range
./target/release/port-scan -t 127.0.0.1 --start-port 1024 --end-port 1

# Invalid port in list
./target/release/port-scan -t 127.0.0.1 -p 80,abc,443

# Non-existent output directory
./target/release/port-scan -t 127.0.0.1 -p 80 --output /nonexistent/report.json
```

---

## CI/CD

A GitHub Actions workflow runs on every push and pull request to `main`. It builds and tests the project across three platforms in parallel.

| Platform | Job |
| :--- | :--- |
| ubuntu-latest | `cargo test` + `cargo build --release` |
| windows-latest | `cargo test` + `cargo build --release` |
| macos-latest | `cargo test` + `cargo build --release` |

---

## Legal Notice

This tool is intended for use on networks and systems you own or have explicit written authorization to test. Unauthorized port scanning may be illegal in your jurisdiction. The authors assume no liability for misuse.
