# Resume Bullet Points

> Use these when listing this project on your CV.

- **Built Vigil**, a memory-safe network intrusion detection system in Rust, processing packets via libpcap FFI and matching signatures with a multi-threaded detection engine (`rayon`) — demonstrating production-grade C/Rust interop with zero unsafe code outside the FFI boundary.

- **Architected a hybrid build system** with `Cargo` and `CMake`, integrating optional libpcap (C) live-capture with a pure-Rust packet parser and YAML-driven rule engine — enabling CI testing without root privileges or native library dependencies.

- **Shipped an end-to-end IDS pipeline** including YAML rule loading, IP blocklist matching, sliding-window port scan detection, protocol anomaly heuristics, and structured JSON alerting — validated with integration tests against crafted `.pcap` files.

- **Implemented parallel rule evaluation** using `rayon` data parallelism — stateless rules (blocklists, protocol anomalies) execute across all CPU cores while stateful rules (port scans) maintain sequential consistency without lock overhead.
