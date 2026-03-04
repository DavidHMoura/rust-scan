# Port-Scan (Rusty-Scan)

A high-performance, asynchronous TCP port scanner built with Rust and Tokio. Designed for cybersecurity analysis, it provides extremely fast concurrent scanning, CIDR block support, and JSON report generation.

## Architecture & Security Features

* **Asynchronous Engine:** Utilizes the Tokio runtime for non-blocking, highly concurrent network requests.
* **Concurrency Limiting:** Implements asynchronous semaphores (max 1,000 workers) to prevent OS resource exhaustion (File Descriptors) and unintentional DoS behavior.
* **Path Traversal Protection:** Sanitizes user input during JSON report generation to prevent arbitrary file overwrite vulnerabilities.
* **CIDR Support:** Scans entire subnets (e.g., 192.168.1.0/24) with automated host discovery.
* **Unit Tested:** Core network parsing logic is covered by native Rust unit tests.
* **Thread-Safe UI:** Real-time terminal progress tracking via indicatif.

## Installation

### Prerequisites
* Rust toolchain (Cargo)

### Build and Install (Linux/macOS)
1. Clone the repository:
   ```bash
   git clone <your-repository-url>
   cd rusty_scanner
Compile the optimized release binary:

Bash
cargo build --release
Move the binary to your local bin path for global execution:

Bash
sudo cp target/release/port-scan /usr/local/bin/
Usage
Run the tool globally from any directory. You can use the interactive wizard or pass arguments directly.

Interactive Mode:

Bash
port-scan
CLI Mode (Single IP):

Bash
port-scan --target 127.0.0.1
CLI Mode (Subnet with JSON Export):

Bash
port-scan -t 192.168.0.0/24 -o 100 --start-port 1 --end-port 1024 --output report.json