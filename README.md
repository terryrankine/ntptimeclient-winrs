# ntptimeclient-winrs

An open-source Windows service written in Rust. It keeps the system clock as close to correct as it can, all the time. Its job is to fix the clock, not to report that the clock is wrong. It takes time from the config file, then DHCP, then the global pool, and prefers slewing over stepping.

## Status

Pre-alpha. Unsigned previews only. Not for production machines.

## Prerequisites

- MSVC build tools (Visual Studio Build Tools with the C++ workload)
- PowerShell 7
- Rust stable (pinned by `rust-toolchain.toml`, minimum 1.88)
- `cargo-deny`
- `cargo-fuzz` and a nightly toolchain, for fuzzing only
- `gh`, for GitHub work

## Checks

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pwsh scripts/check-deps.ps1
cargo deny check
```

See `docs/architecture.md` for the crate layout.

## Licence

`MIT OR Apache-2.0`. See `LICENSE-MIT` and `LICENSE-APACHE`.
