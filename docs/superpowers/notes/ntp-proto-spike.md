# ntp-proto spike

Date: 2026-11-10. Machine: Windows 11 Pro, rustc/cargo 1.92.0 stable, target `x86_64-pc-windows-msvc`. Probe: `spikes/probe/` (throwaway, never sets the clock).

## Decision

**use** `ntp-proto` 1.9.0 for packet parsing only (default path from the brief). Selection and discipline stay in our own `ntpc-core`.

- "use" means the packet parser only. Filter, selection and discipline are written in our own `ntpc-core`.
- Packet parser works on Windows with no C toolchain crates in the `x86_64-pc-windows-msvc` tree. Verified against a real pool reply.
- Selection and filter algorithms are not public on their own. See question 3.
- The Kalman controller accepted plain offset and delay values from three mock sources with no tokio runtime. It then produced `used_sources` and one clock step on the mock. Only one scenario was run. See question 3.
- Re-plan gate (Step 5): not triggered. The parser is usable.

Conditions to carry into Tasks 3 to 9:

1. Every public item needs the feature `__internal-api`. Without it the build fails with `struct NoCipher is private` and so on. The crate docs say it is "not intended as a public interface at this time". Pin `=1.9.x` and review every bump.
2. Use `default-features = false, features = ["rustcrypto", "__internal-api"]`.
3. The crate always pulls `tokio` (`io-util` only, no runtime), `rustls`, `tokio-rustls`, `rustls-platform-verifier`, `rand`, `serde`, `tracing`. We cannot drop them.

## What each later task does

"use" means: the packet parser from `ntp-proto` only. Filter, selection and discipline are written in our own `ntpc-core`. `ntp-proto` is not used in `ntpc-core`.

- Pin: `ntp-proto` on the 1.9 line, `default-features = false`, features `rustcrypto` and `__internal-api`. The whole public API sits behind `__internal-api`, so any bump needs review. Commit `Cargo.lock`.
- Task 3: no `ntp-proto` types. Own newtypes. `Sample.unsynchronised` comes from `NtpLeapIndicator::Unsynchronized`. `leap_alarm` is that same wire value, so the two flags need a rule in Task 9. `KodCode::Other` is needed because the kiss code string is not readable.
- Task 4: own filter and `select`. Marzullo-style selection is not available from `ntp-proto`, because its `select` is private. Step 4 (differential test) is skipped for `select`.
- Task 6: own discipline. No `ntp-proto` use.
- Task 7: no `ntp-proto` use. Engine stays dependency free.
- Task 9: `ntp-proto` parser, in `ntpc-service` only. `build_request` uses `NtpPacket::poll_message` plus `serialize`, and takes the origin check from `valid_server_response`. `parse_response` converts `NtpTimestamp` differences to `f64` deltas (`Sub` then `to_seconds`). Kiss mapping uses `is_kiss_deny`, `is_kiss_rstr`, `is_kiss_rate(interval)`. Any other kiss code maps to `KodCode::Other`. Wrong mode, version and length come back as `PacketParsingError`. Source address check is ours.
- Differential test against `KalmanClockController`: not worth doing as a pass or fail test. The two use different models (Kalman versus Marzullo), so results will legitimately differ and the test has no right answer. It may be worth a one-off comparison report in Task 8 or 16. That is optional.

## Question 1: builds on Windows without a C toolchain?

Probe dependency: `ntp-proto = { version = "=1.9.0", default-features = false, features = ["rustcrypto", "__internal-api"] }`.

- `cargo build`: `Finished dev profile in 18.45s`. `cargo run` works.
- For `x86_64-pc-windows-msvc` only, the tree has no `cc`, `cmake`, `aws-lc-*`, `ring` or `openssl` crate. Other targets were not checked. Checked with `cargo tree -e normal,build --prefix none`.
- Default features (`aws-lc` plus `rustcrypto`): also built, `Finished in 37.96s`. The tree gains `aws-lc-rs`, `aws-lc-sys`, `cc`, `cmake`, `pkg-config` and others.
- Not verified: building on a machine with no MSVC at all. This machine has VS 2019 Build Tools, so the `aws-lc` build succeeded here and says nothing about a bare machine. Rust itself needs MSVC `link.exe` for the msvc target, so "no C toolchain" can only mean no C compiler, CMake or NASM.
- Not verified: runtime behaviour of `rustls` without the `aws-lc` provider. NTS is not used in the parser-only path, so it is not exercised.

Answer: yes. `rustcrypto` with `default-features = false` builds with pure Rust crates only. Use it.

## Question 2: build a request and parse a reply

All are crate root re-exports, read from `~/.cargo/registry/src/*/ntp-proto-1.9.0/src/packet/mod.rs`.

Build:

```rust
NtpPacket::poll_message(poll_interval: PollInterval) -> (NtpPacket<'static>, RequestIdentifier)
// RequestIdentifier has private fields. It holds the random origin timestamp.
NtpPacket::serialize(&self, w: &mut Cursor<&mut [u8]>, cipher: &(impl CipherProvider + ?Sized), desired_size: Option<usize>) -> std::io::Result<()>
// Use &NoCipher and None. Output is 48 bytes.
PollInterval::from_byte(u8) -> PollInterval
```

Parse and validate:

```rust
NtpPacket::deserialize(data: &'a [u8], cipher: &(impl CipherProvider + ?Sized))
    -> Result<(NtpPacket<'a>, Option<DecodedServerCookie>), PacketParsingError<'a>>
NtpPacket::valid_server_response(&self, identifier: RequestIdentifier, nts_enabled: bool) -> bool
NtpPacket::into_owned(self) -> NtpPacket<'static>
```

Getters: `version() -> NtpVersion`, `leap() -> NtpLeapIndicator`, `mode() -> NtpAssociationMode`, `poll() -> PollInterval`, `stratum() -> u8`, `precision() -> i8`, `root_delay() -> NtpDuration`, `root_dispersion() -> NtpDuration`, `receive_timestamp()` and `transmit_timestamp() -> NtpTimestamp`, `reference_id() -> ReferenceId`.

Gaps found:

- No getter for the origin or reference timestamp on `NtpPacket`. `valid_server_response` does the origin check for us.
- `NtpTimestamp` has no public accessor for seconds. It has `from_seconds_nanos_since_ntp_era(u32, u32)`, `Sub` giving `NtpDuration`, `Add<NtpDuration>`, and a `Debug` that prints the raw `u64`. `NtpDuration` has `to_seconds() -> f64` and `from_seconds(f64)`.
- `ReferenceId::to_bytes` is `pub(crate)`. The kiss code string is not readable. See question 4.
- `PacketParsingError` variants seen: `InvalidVersion(u8)`, `IncorrectLength`, `MalformedNtsExtensionFields`, `MalformedNonce`, `MalformedCookiePlaceholder`, `DecryptError(T)`, `V5(..)`. A 20 byte truncation gives `IncorrectLength`.
- T1 and T4 are ours. The probe builds them from `SystemTime` with `from_seconds_nanos_since_ntp_era` and computes `offset = ((T2 - T1) + (T3 - T4)) / 2` and `delay = (T4 - T1) - (T3 - T2)`.

Evidence, probe against `pool.ntp.org:123` (`spikes/probe/fixture-reply.bin`, 48 bytes, captured 2026-11-10):

```
version V4, leap NoWarning synchronized=true, mode Server, stratum 2
poll 64 s, precision -24, root_delay 0.000122s, root_disp 0.000046s
valid_server_response = true
offset -0.001069s delay 0.080554s
```

`cargo run -- file fixture-reply.bin` parses the saved file to the same fields.

## Question 3: filter, selection, discipline public? Drivable without tokio?

Read from `src/algorithm/` and `src/lib.rs`.

- ntpd-rs 1.9 does not use the RFC 5905 clock filter, selection, clustering and combine pipeline. It uses a Kalman filter per source (`algorithm/kalman/`).
- `select.rs` (`pub(super) fn select`), `combiner.rs` (`pub(super) fn combine`) and `matrix.rs` are private modules. They are not reachable.
- Public: the traits `TimeSyncController` and `SourceController`, and the types `KalmanClockController<C: NtpClock, SourceId>`, `KalmanSourceController`, `TwoWayKalmanSourceController`, `AlgorithmConfig`, `SynchronizationConfig`, `SourceConfig`, `StateUpdate`, `TimeSnapshot`, `Measurement<D>`.
- `Measurement` has all public fields: `delay`, `offset: NtpDuration`, `localtime: NtpTimestamp`, `monotime: NtpInstant`, `stratum`, `root_delay`, `root_dispersion`, `leap`, `precision`. Plain offset and delay values can be fed in.
- Flow: `KalmanClockController::new(clock, SynchronizationConfig, AlgorithmConfig)`, `add_source(id, SourceConfig)` returns a source controller, `source_update(id, usable)`, `handle_measurement(Measurement) -> Option<SourceMessage>`, then `source_message(id, msg) -> StateUpdate`.
- The controller needs a type that implements `NtpClock` (7 methods: `now`, `set_frequency`, `get_frequency`, `step_clock`, `disable_ntp_algorithm`, `error_estimate_update`, `status_update`). The probe uses a mock. `step_clock` and `set_frequency` are where our Windows clock layer would plug in.
- No tokio runtime is involved. All calls are synchronous. `tokio` is a dependency only for `io-util`.
- Evidence, first run: one mock source, 8 measurements. `used_sources` stayed `None`.
- Evidence, second run: three mock sources with offsets 12.3, 12.4 and 12.5 ms, delays 20 to 22 ms, 12 rounds each (`baseline/kalman-3-sources.txt`). On round 7 the third source's update returned `used_sources = Some([3, 2, 1])` and the mock `step_clock` was called with +11.82 ms. Later rounds returned no new messages. This fits `minimum_agreeing_sources` defaulting to 3, but I did not run a test that changes that value.
- `Measurement.monotime` is `NtpInstant`, which wraps `std::time::Instant`. `NtpInstant::now()` is public. Replaying old data needs real instants.
- Not verified: falsetickers, unequal sources, slew versus step choice, frequency learning, real timing, long runs, and whether the output is accurate. One synthetic scenario with identical offsets only shows that the plumbing works.

Answer: selection and filter are not public as standalone functions. The whole Kalman controller is public behind `__internal-api`. It accepted plain `Measurement` values with no tokio runtime in one three-source scenario. It brings its own model and is not RFC 5905. Our `ntpc-core` selection and discipline is separate work. A differential test against `KalmanClockController` is feasible.

## Question 4: KoD, stratum 0, leap alarm

- Stratum 0 and KoD: `NtpPacket::is_kiss() -> bool` is true when stratum is 0. Plain stratum 0 and KoD are the same flag.
- Public kiss helpers: `is_kiss_deny()`, `is_kiss_rate(own_interval: PollInterval)`, `is_kiss_rstr()`, `is_kiss_ntsn()`. All return `bool`.
- The code itself is not readable. `ReferenceId::is_deny`, `is_rate`, `is_rstr`, `is_ntsn` and `to_bytes` are `pub(crate)`. Public consts exist: `ReferenceId::KISS_DENY`, `KISS_RATE`, `KISS_RSTR`, `KISS_NTSN`, `NONE`. A kiss code other than those four cannot be named.
- Evidence: a copy of the fixture with stratum 0, refid `RATE` and leap 3 parsed with `is_kiss=true`. `is_kiss_rate` needs an interval argument and was not exercised by the probe.
- Leap: `NtpLeapIndicator { NoWarning, Leap61, Leap59, Unknown, Unsynchronized }`. Wire value 3 parses as `Unsynchronized`. `Unknown` is never produced by the parser. `is_synchronized() -> bool` is false only for `Unsynchronized`. The alarm is wire value 3, so it shows as `Unsynchronized`.
- NTPv5 packets use a different kiss scheme inside the same methods. We send v4 only.

## Question 5: dependency tree

`cargo tree -e normal,build --prefix none -f '{p}' | sort -u`, probe crate excluded:

| Config | Unique crates | C-toolchain crates |
|---|---|---|
| `rustcrypto`, no defaults | 51 | none |
| defaults (`aws-lc` + `rustcrypto`) | 61 | `aws-lc-sys`, `cc`, `cmake` |

Direct dependencies of `ntp-proto`: `tokio` (`io-util`), `rustls`, `tokio-rustls`, `rustls-platform-verifier`, `rand` 0.8, `serde`, `tracing`, `zeroize`, plus optional `md-5`, `aead`, `aes-siv`. Edition 2024, `rust-version` 1.88. `#![forbid(unsafe_code)]` in the crate. Not checked: licences of transitive crates, binary size.

## Baseline: w32tm against pool.ntp.org

Command: `w32tm /stripchart /computer:pool.ntp.org /samples:120 /dataonly`, run unelevated, 2 second interval, server `144.6.227.199`. No w32time or system setting changed. Offset is as w32tm reports it, in seconds, against the local clock.

| Run | Samples ok | Min | Max | Median | Mean abs |
|---|---|---|---|---|---|
| Idle | 120 of 120 | -4.1 ms | +15.7 ms | +4.9 ms | 4.7 ms |
| CPU load (24 busy PowerShell jobs, 24 logical cores) | 92 of 120 | -2.4 ms | +20.9 ms | +9.0 ms | 9.0 ms |

- Under load 28 samples returned `error: 0x80072733`. Cause not confirmed. It looks like receive failures or timeouts.
- One pool path, so network noise is in these numbers. They show the floor we must beat on this host, not a w32time accuracy limit.
- Burn jobs were stopped afterwards (`Get-Job` count 0).
- Raw output is committed: [idle](../../../spikes/probe/baseline/w32tm-idle.txt), [under load](../../../spikes/probe/baseline/w32tm-load.txt). The stats script is `spikes/probe/baseline/stats.ps1`.
