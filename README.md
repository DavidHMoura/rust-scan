# Port-Scan (Rusty-Scan)

A high-performance, asynchronous TCP port scanner built with Rust and Tokio. Designed for cybersecurity analysis, it provides extremely fast concurrent scanning, CIDR block support, and JSON report generation.

## Features

* **Asynchronous Engine:** Utilizes the Tokio runtime for non-blocking, highly concurrent network requests.
* **CIDR Support:** Scans entire subnets (e.g., 192.168.1.0/24) with automated host discovery.
* **Customizable Timeouts:** Adjust connection timeouts for different network environments to prevent false negatives.
* **Data Export:** Serializes scan results directly to JSON using Serde for SIEM integration and automated reporting.
* **Thread-Safe UI:** Real-time terminal progress tracking via indicatif.

## Installation

### Prerequisites
* Rust toolchain (Cargo)

### Build from Source
1. Clone the repository:
   ```bash
   git clone <your-repository-url>
   cd rusty_scanner
Compile the optimized release binary:

Bash
cargo build --release
Global Execution (Linux)
To run the scanner from any directory in your terminal, move the compiled binary to your local binaries folder:

Bash
sudo cp target/release/rusty_scanner /usr/local/bin/port-scan
Usage
You can use the tool by passing the required arguments directly.

Basic Single IP Scan:

Bash
port-scan --target 127.0.0.1
Subnet Scan with Custom Timeout and JSON Export:

Bash
port-scan -t 192.168.0.0/24 -o 100 --start-port 1 --end-port 1024 --output report.json
Help Menu:

Bash
port-scan --help
Roadmap
[x] Initial Project Setup

[x] Implement Single IP Scanning (Asynchronous)

[x] Custom Timeout Handling

[x] Multi-IP Range Support

[x] Terminal Progress Bar (TUI)

[x] JSON Export for Reports

[ ] Interactive Terminal Prompt (Wizard Mode)