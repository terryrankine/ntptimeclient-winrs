# ntptimeclient-winrs

An open-source Windows service written in Rust. It aims to keep the system clock as close to correct as it can, all the time. The aim is to fix the clock, not to report that the clock is wrong.

## Status

**Alpha. Unsigned. Not for machines that matter.**

- Current version: `0.1.0-alpha.1`. Versions and releases follow `docs/releasing.md`.
- Install, service run and uninstall have not been verified on a real machine. First use is a throwaway virtual machine with a snapshot. See `docs/preview-vm-test.md`.
- No accuracy figure against the Windows Time service (`w32time`) has been measured.
- Binaries are not code signed. Windows SmartScreen, Smart App Control or antivirus may warn or block them.

## What it does

- Takes time from servers in strict order: the config file, then DHCP, then the global NTP pool.
- Prefers slewing over stepping. It steps once after start and once after resume.
- Pool servers cross-check the chosen tier and can veto a step.
- Stops and disables `w32time`. It restores `w32time` if the service fails to start.
- Needs an elevated PowerShell to install. Runs as LocalSystem with the clock privilege only.
- Windows 10 and Windows Server 2016 or later, x86_64.

## Get it

Releases are on the GitHub Releases page. Each release is a zip with the exe, install and uninstall scripts, a default config, `README-PREVIEW.txt` and a SHA-256 list. Read `README-PREVIEW.txt` before you run anything. Extract only into a folder that only administrators can write.

Every green CI run on `main` also leaves a gated exe as a workflow artifact for 14 days. That is a CI build and not a release.

## Build

Prerequisites:

- MSVC build tools (Visual Studio Build Tools with the C++ workload)
- PowerShell 7
- Rust, stable channel (`rust-toolchain.toml` says `stable`, which floats), minimum 1.88
- `cargo-deny`
- `cargo-fuzz` and a nightly toolchain, for fuzzing only
- `gh`, for GitHub work

```
cargo build --release --locked -p ntpc-service
```

The exe is `target/release/ntptimeclient-winrs.exe`.

## Checks

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
pwsh scripts/check-deps.ps1
cargo deny check
pwsh scripts/check-version.ps1
pwsh scripts/check-workflows.ps1
```

Tests never change the clock, services, registry or ACLs of the machine. Tests that need a throwaway VM are marked `#[ignore]`.

## Pipelines

| Workflow | When | What |
| --- | --- | --- |
| `ci.yml` | push to `main`, pull request, nightly | fmt, clippy, tests, MSRV, `cargo-deny`, packaging tests, exe gate, gated exe artifact, version and pin lint, fuzz smoke |
| `release.yml` | tag `vX.Y.Z[-alpha.N]` | version rules, build, exe gate, zip, GitHub release |
| `monitor.yml` | daily | pin monitor (moved or missing action pins), package checker (advisories, licences) |
| Dependabot | weekly | pull requests for action pins and Rust crates |

Versioning, tags and the release steps are in `docs/releasing.md`. The crate layout is in `docs/architecture.md`.

## Licence

`MIT OR Apache-2.0`. See `LICENSE-MIT` and `LICENSE-APACHE`.
