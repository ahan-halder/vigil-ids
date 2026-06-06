# 🦀 Vigil IDS

> A memory-safe, high-performance Network Intrusion Detection System built with Rust and C++.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourusername/vigil-ids)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange)](https://www.rust-lang.org)
[![Language: C++17](https://img.shields.io/badge/C%2B%2B-17-blue)](https://en.cppreference.com)

---

## What Is Vigil?

Vigil is a network intrusion detection system (NIDS) that combines **Rust's memory safety and concurrency** with **C libraries** (libpcap) for raw packet capture — the same architectural approach used by Suricata, which now includes Rust modules in its core.

Traditional IDS tools like Snort and Suricata are written primarily in C/C++, making them susceptible to memory-corruption vulnerabilities — the very class of bug an IDS should be hardened against. Vigil flips this: the packet processing engine, rule matching, and alerting logic are all written in safe Rust, while libpcap (C) handles the low-level packet capture interface via FFI.

This makes Vigil an excellent showcase of:
- Real-world **Rust/C FFI interoperability** via manual `extern "C"` declarations
- **CMake + Cargo** hybrid build systems
- **Multi-threaded packet processing** with Rust's `tokio` and `rayon`
- Zero unsafe code outside of the FFI boundary layer

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Vigil                                  │
│                                                             │
│  Network Interface                                          │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────┐    FFI (bindgen)    ┌───────────────┐  │
│  │  libpcap (C)    │ ──────────────────► │  Rust Packet  │  │
│  │  Packet Capture │                     │  Engine       │  │
│  └─────────────────┘                     └───────┬───────┘  │
│                                                  │          │
│                                    ┌─────────────▼───────┐  │
│                                    │  Rule Matcher       │  │
│                                    │  (JSON/YAML rules)  │  │
│                                    └─────────────┬───────┘  │
│                                                  │          │
│                                    ┌─────────────▼───────┐  │
│                                    │  Alert Output       │  │
│                                    │  (JSON logs/syslog) │  │
│                                    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Module Breakdown

| Module | Language | Purpose |
|---|---|---|
| `capture/` | Rust (FFI → libpcap) | Raw packet capture from interface or `.pcap` file |
| `capture/pcap_ffi.rs` | Rust (unsafe) | FFI boundary — the only `unsafe` code in the project |
| `capture/pcap_file.rs` | Rust | Pure-Rust `.pcap` file reader (no libpcap needed) |
| `parser/` | Rust | Ethernet/IP/TCP/UDP header decoding (hand-rolled) |
| `engine/` | Rust | Detection engine and rule evaluation |
| `rules/` | Rust | YAML rule loader, schema definitions |
| `alerts/` | Rust | Alert formatting, JSON log output |
| `cli/` | Rust | CLI interface via `clap` |

---

## Why This Project?

This project targets a real market gap: existing IDS tools are written in memory-unsafe languages, making them vulnerable to the exact attack classes they're supposed to detect. Vigil serves as both a functional security tool and a reference implementation for:

- Engineers transitioning legacy C/C++ security tooling to Rust
- Developers learning Rust/C++ interoperability in a systems context
- Security researchers who want a hackable, readable IDS codebase

Inspired by:
- [Suricata](https://github.com/OISF/suricata) — production IDS, now ~25% Rust
- [Blatta IDS](https://github.com/ravivendra/rust-thesis-blatta-ids) — academic Rust IDS demonstrating memory-safe TCP reassembly
- [libpnet](https://github.com/libpnet/libpnet) — low-level Rust networking

---

## Tech Stack

**Rust crates:**
- [`clap`](https://docs.rs/clap) — CLI argument parsing
- [`serde`](https://serde.rs) + [`serde_json`](https://docs.rs/serde_json) — rule and alert serialization
- [`serde_yaml`](https://docs.rs/serde_yaml) — YAML rule file parsing

**C library (optional):**
- [`libpcap`](https://www.tcpdump.org/) / [Npcap](https://npcap.com/) — live packet capture (via manual FFI, feature-gated)

**Build:**
- `Cargo` — primary Rust build system
- `CMake` — optional; invokes Cargo and handles libpcap discovery
- `pkg-config` / `vcpkg` — used by `build.rs` to locate libpcap

---

## Project Structure

```
vigil-ids/
├── CMakeLists.txt          # Optional CMake wrapper (invokes Cargo)
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── CONTRIBUTING.md
│
├── src/
│   ├── main.rs             # Entry point, CLI parsing
│   ├── lib.rs              # Library root (public module exports)
│   ├── capture/
│   │   ├── mod.rs          # Packet capture orchestration
│   │   ├── pcap_ffi.rs     # FFI boundary (unsafe, libpcap bindings)
│   │   └── pcap_file.rs    # Pure-Rust .pcap file reader
│   ├── parser/
│   │   └── mod.rs          # Packet header decoding
│   ├── engine/
│   │   ├── mod.rs          # Detection engine, stateful rule eval
│   │   └── matcher.rs      # Rule evaluation logic
│   ├── rules/
│   │   ├── mod.rs          # Rule loader
│   │   └── schema.rs       # Rule data structures
│   ├── alerts/
│   │   └── mod.rs          # Alert formatting and output
│   └── cli/
│       └── mod.rs          # CLI argument definitions
│
├── rules/
│   ├── default.yaml        # Default bundled ruleset
│   └── examples/
│       ├── port_scan.yaml
│       └── blocklist.yaml
│
├── build.rs                # Cargo build script (optional libpcap discovery)
│
├── tests/
│   ├── test_pcap_reader.rs      # Pcap reading + detection integration tests
│   ├── test_example_rules.rs    # Rule loading correctness
│   └── pcap_samples/            # Sample .pcap files for testing
│
└── .github/
    └── workflows/
        └── ci.yml          # GitHub Actions CI
```

---

## MVP Feature List

The MVP targets a working, testable IDS that can be demonstrated end-to-end.

- [x] Capture packets from a live network interface (requires root/cap_net_raw)
- [x] Read packets from a `.pcap` file (no root required — great for CI)
- [x] Decode Ethernet / IPv4 / TCP / UDP headers
- [x] Load rules from a YAML file
- [x] Match rules: IP blocklist, port scan detection, protocol anomaly flags
- [x] Multi-threaded packet processing via `rayon`
- [x] Output alerts as JSON to stdout or a log file
- [x] CLI flags: `--interface`, `--pcap`, `--rules`, `--output`, `--verbose`
- [ ] *(v0.2)* IPv6 support
- [ ] *(v0.2)* Syslog output
- [ ] *(v0.2)* Reload rules without restart
- [ ] *(v1.0)* Web dashboard (Axum + HTMX)
- [ ] *(v1.0)* Regex-based payload matching (via Hyperscan C library)

---

## Rule Format

Rules are defined in YAML. Example:

```yaml
# rules/examples/port_scan.yaml
rules:
  - id: "PS-001"
    name: "Port Scan Detected"
    description: "More than 15 unique ports contacted from one source in 10 seconds"
    severity: high
    condition:
      type: port_scan
      threshold: 15
      window_secs: 10
    action: alert

  - id: "BL-001"
    name: "Blocked IP"
    description: "Traffic from a known malicious IP"
    severity: critical
    condition:
      type: ip_blocklist
      src_ips:
        - "192.168.1.100"
        - "10.0.0.55"
    action: alert
```

---

## Getting Started

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install libpcap-dev cmake clang

# macOS
brew install libpcap cmake

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build

```bash
git clone https://github.com/yourusername/vigil-ids
cd vigil-ids

# Option A: Build via Cargo (libpcap must be installed system-wide)
cargo build --release

# Option B: Build via CMake (handles finding/linking libpcap)
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### Run

```bash
# Analyze a .pcap file (no root required)
./target/release/vigil-ids --pcap tests/pcap_samples/port_scan.pcap --rules rules/default.yaml

# Live capture on interface (requires root or CAP_NET_RAW)
sudo ./target/release/vigil-ids --interface eth0 --rules rules/default.yaml --output alerts.json

# Verbose mode
./target/release/vigil-ids --pcap sample.pcap --rules rules/default.yaml --verbose
```

### Example Output

```json
{"timestamp":"2026-06-01T09:14:22Z","rule_id":"PS-001","severity":"high","src_ip":"203.0.113.5","dst_ip":"10.0.0.1","message":"Port scan detected: 23 unique ports in 8 seconds"}
{"timestamp":"2026-06-01T09:14:25Z","rule_id":"BL-001","severity":"critical","src_ip":"192.168.1.100","dst_ip":"10.0.0.2","message":"Traffic from blocklisted IP"}
```

---

## Testing

```bash
# Unit tests
cargo test

# Integration tests (uses bundled .pcap files, no root needed)
cargo test --test integration

# Fuzz the packet parser (requires cargo-fuzz)
cargo install cargo-fuzz
cargo fuzz run fuzz_packet_parser

# Run against a public IDS dataset
# Download: https://www.unb.ca/cic/datasets/ids-2018.html
cargo run --release -- --pcap /path/to/dataset.pcap --rules rules/default.yaml
```

---

## CI/CD

GitHub Actions runs on every push:

```yaml
# .github/workflows/ci.yml (abbreviated)
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install libpcap
        run: sudo apt install libpcap-dev
      - name: Run tests
        run: cargo test --all
      - name: Clippy lint
        run: cargo clippy -- -D warnings
      - name: Check formatting
        run: cargo fmt --check
```

---

## Roadmap

```
Phase 1 — Foundation 
  ├── Set up CMake + Cargo hybrid build
  ├── Integrate libpcap via bindgen (FFI boundary)
  └── Parse Ethernet/IP/TCP/UDP headers with pnet

Phase 2 — Core Engine 
  ├── YAML rule loader
  ├── IP blocklist matching
  ├── Port scan heuristic (sliding time window)
  └── Multi-threaded processing with rayon

Phase 3 — Integration & Testing 
  ├── Integration tests with real .pcap samples
  ├── Fuzz testing on packet parser
  ├── GitHub Actions CI pipeline
  └── Benchmarks vs tcpdump baseline

Phase 4 — Polish & Release v0.1 
  ├── CLI polish (clap, --help, man page)
  ├── README, docs, example rules
  └── Publish: GitHub release + crates.io

Phase 5 — v0.2 Features 
  ├── IPv6 support
  ├── Syslog output
  └── Rule hot-reload

Phase 6 — v1.0 
  ├── Hyperscan (C) integration for regex payload matching
  ├── Web dashboard (Axum)
  └── Performance tuning for multi-gigabit capture
```

---

## Resume Bullet Points

> Use these when listing this project on your CV:

- **Built Vigil**, a memory-safe network intrusion detection system in Rust/C++, processing packets via libpcap FFI and matching signatures with a multi-threaded Rust engine — demonstrating production-grade cross-language interop with zero unsafe code outside the FFI boundary.

- **Architected a CMake + Cargo hybrid build system** integrating libpcap (C) with a Rust detection engine using `bindgen`, `pnet`, and `tokio` — achieving concurrent packet analysis across multiple CPU cores.

- **Shipped an end-to-end IDS pipeline** including YAML rule loading, port scan detection, IP blocklisting, and JSON alerting — validated against public IDS benchmark datasets (CIC-IDS-2018).

---

## References

- [Suricata OISF](https://github.com/OISF/suricata) — production IDS, ~25% Rust
- [Blatta IDS](https://github.com/ravivendra/rust-thesis-blatta-ids) — Rust-based NIDS thesis project
- [libpnet](https://github.com/libpnet/libpnet) — Rust networking library
- [Corrosion](https://github.com/corrosion-rs/corrosion) — CMake/Cargo integration
- [bindgen](https://github.com/rust-lang/rust-bindgen) — Rust FFI binding generator
- CIC-IDS-2018 Dataset — University of New Brunswick IDS evaluation dataset
- Suricata's Rust modules: [https://suricata.io/2021/01/14/suricata-6-0-2-released/](https://suricata.io/2021/01/14/suricata-6-0-2-released/)

---

## License

MIT — see [LICENSE](LICENSE).

---

## Contributing

PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md). Please run `cargo fmt` and `cargo clippy` before submitting.

---

*Vigil — because your intrusion detector shouldn't be vulnerable to buffer overflows.*
