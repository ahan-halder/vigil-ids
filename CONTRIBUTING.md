# Contributing to Vigil IDS

Thank you for your interest in contributing to Vigil! This document covers the
basics you need to get started.

## Getting Started

1. Fork the repository and clone your fork.
2. Install the prerequisites listed in the [README](README.md#prerequisites).
3. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Building

```bash
cargo build
```

Vigil builds without libpcap by default. To enable live packet capture:

```bash
# Linux/macOS — install libpcap-dev, then:
cargo build --features pcap

# Windows — install the Npcap SDK, then:
set VIGIL_ENABLE_PCAP_DISCOVERY=1
cargo build
```

### Running Tests

```bash
cargo test --all
```

All integration tests use bundled `.pcap` sample files, so no root privileges or
live network interfaces are needed.

### Code Quality

Before submitting a PR, ensure:

```bash
# Format code
cargo fmt

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Verify formatting (this is what CI checks)
cargo fmt --check
```

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR.
- Write clear commit messages.
- Add or update tests for any new functionality.
- Make sure CI passes (`cargo fmt --check`, `cargo test`, `cargo clippy`).
- Update documentation (README, doc comments) if your change affects the public
  API or user-facing behavior.

## Code Style

- Follow standard Rust conventions (`cargo fmt` enforces formatting).
- Keep `unsafe` code confined to `src/capture/pcap_ffi.rs` — the FFI boundary.
- Prefer returning `Result<T, String>` for error propagation in this project.
- Add doc comments for public functions and types.

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests.
- Include reproduction steps, expected behavior, and actual behavior.
- For security vulnerabilities, please email the maintainer directly instead of
  opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
