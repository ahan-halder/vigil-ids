# Roadmap

Development phases for Vigil IDS, from initial foundation through production-ready v1.0.

```
Phase 1 — Foundation (✅ Complete)
  ├── Set up CMake + Cargo hybrid build
  ├── Integrate libpcap via manual FFI boundary
  └── Parse Ethernet/IPv4/TCP/UDP headers (hand-rolled)

Phase 2 — Core Engine (✅ Complete)
  ├── YAML rule loader
  ├── IP blocklist matching
  ├── Port scan heuristic (sliding time window)
  ├── Protocol anomaly detection
  └── Multi-threaded rule processing with rayon

Phase 3 — Integration & Testing (✅ Complete)
  ├── Integration tests with .pcap samples
  ├── GitHub Actions CI pipeline
  └── clippy + fmt enforcement

Phase 4 — Polish & Release v0.1 (✅ Complete)
  ├── CLI polish (clap, --help)
  ├── README, docs, example rules
  └── Publish: GitHub release

Phase 5 — v0.2 Features (Planned)
  ├── IPv6 support
  ├── Syslog output
  └── Rule hot-reload

Phase 6 — v1.0 (Planned)
  ├── Hyperscan (C) integration for regex payload matching
  ├── Web dashboard (Axum)
  └── Performance tuning for multi-gigabit capture
```
