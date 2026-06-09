# Vigil IDS Documentation

Welcome to the documentation for **Vigil IDS**, a minimal, memory-safe Network Intrusion Detection System written in Rust.

## Overview

Vigil is built to combine the performance of C (using `libpcap`) for raw packet capture with the memory safety and fearless concurrency of Rust for packet parsing and rule matching. It's designed to be simple, fast, and secure against common memory-corruption exploits that traditionally affect C/C++ security tools.

### Core Architecture

1. **Capture Module (`capture/`)**: Interacts with raw network data. Supports live network interfaces (via `libpcap` FFI) or offline `.pcap` files using a pure-Rust reader.
2. **Parser Module (`parser/`)**: A hand-rolled, fast protocol decoder capable of extracting Ethernet, IPv4, TCP, and UDP header information.
3. **Engine Module (`engine/`)**: The core detection logic. Uses `rayon` to evaluate stateless rules (like blocklists and protocol anomalies) in parallel across all available CPU cores, while safely maintaining sequential execution for stateful rules (like port scan detection).
4. **Rules Module (`rules/`)**: Loads and parses detection rules written in YAML format using `serde`.
5. **Alerts Module (`alerts/`)**: Formats matched detection events into structured JSON logs for easy integration with SIEMs.

## Execution Steps

### 1. Build the Project

Vigil requires Rust to be installed.

```bash
# Standard build (PCAP file analysis only, no libpcap dependency)
cargo build --release

# Live capture build (Requires libpcap/Npcap installed on your system)
# Linux/macOS
cargo build --release --features pcap

# Windows
set VIGIL_ENABLE_PCAP_DISCOVERY=1
cargo build --release
```

### 2. Run Offline PCAP Analysis

You don't need root/administrator privileges to analyze `.pcap` files.

```bash
./target/release/vigil-ids --pcap tests/pcap_samples/port_scan.pcap --rules rules/default.yaml
```

### 3. Run Live Interface Capture

Live capture requires root/Administrator privileges.

```bash
# Linux
sudo ./target/release/vigil-ids --interface eth0 --rules rules/default.yaml --output alerts.json

# Windows (Run as Administrator)
.\target\release\vigil-ids.exe --interface "\Device\NPF_{...}" --rules rules\default.yaml
```

*Tip: Use `--list-interfaces` to see available network adapters.*

### 4. Viewing Alerts

Alerts are output to standard error by default, or to the file specified by `--output`. They are formatted as JSON lines:

```json
{"timestamp_secs":1685600000,"rule_id":"BL-001","severity":"critical","action":"alert","src_ip":"192.168.1.100","dst_ip":"10.0.0.2","message":"Traffic from a known malicious IP matched for destination 10.0.0.2"}
```

## Further Reading

- For instructions on writing your own detection rules, see [Writing Rules (RULES.md)](RULES.md).
- For contributing guidelines, see the root [CONTRIBUTING.md](../CONTRIBUTING.md).
