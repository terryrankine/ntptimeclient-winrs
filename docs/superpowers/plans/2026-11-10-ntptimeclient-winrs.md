# ntptimeclient-winrs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an open-source Windows service that keeps the system clock as close to correct as it can, using config file, DHCP and global pool sources in strict priority order.

**Architecture:** Ports and adapters around a sans-IO core. The core (`ntpc-core`) is a pure engine. It takes events and returns actions. It never touches the OS, the network, a clock or a runtime. `ntpc-platform` holds every Win32 call and all unsafe code. `ntpc-service` holds the host, network transport, config and glue. Behaviour is tested in a deterministic simulation inside `ntpc-core`.

**Tech Stack:** Rust edition 2024, `ntp-proto` (packet parsing, subject to the Task 1 spike), `tokio`, `windows-sys`, `windows-service`, `serde` with `toml`, `tracing`, `thiserror`, `cargo-fuzz`.

**Spec:** `docs/superpowers/specs/2026-11-10-ntptimeclient-winrs-design.md`

## Terms

- **Sans-IO:** the core is a state machine. Inputs are events. Outputs are actions. The host does the I/O.
- **Kiss-of-Death (KoD):** an NTP reply from a server that tells the client to stop or slow down.
- **Falseticker:** a source whose time disagrees with the majority.
- **Slew:** correct the clock by changing its rate. **Step:** set the clock directly.
- **Author:** the planning agent. **Builder:** the implementing agent. **Terry:** the owner.

## Global Constraints

- Rust only. Edition 2024. `rust-version = "1.88"`.
- Windows 10 and later, Windows Server 2016 and later. CI runs Windows 11 and one Windows Server release. Server 2016 is best effort.
- Licence `MIT OR Apache-2.0`. Copyright line reads "ntptimeclient-winrs contributors". Terry may change it.
- Source precedence is strict: config file, then DHCP, then the global pool `pool.ntp.org`. The first tier with usable sources wins for selection. Tiers are never mixed in selection.
- Pool cross-check (Terry, chosen 2026-11-10): while the active tier is Config or Dhcp, the engine also queries the pool in observe-only mode. If the pool's offset disagrees with the active tier by more than the step threshold, the engine refuses any step and slews within the cap only. The pool never feeds selection.
- DHCP sources are detected, logged and shown when they differ from the config file.
- No alerts. A log file and a `status.json` only.
- Slew small offsets. Step only above 128 ms (author's call, ntpd convention from training data, unverified). Refuse a step above the panic threshold of 1000 s unless config allows it (same source).
- Poll limits default 64 s to 1024 s (author's call, unverified against pool guidance).
- On KoD `DENY` or `RSTR`, stop querying that source for one hour. On `RATE`, double its poll interval (author's call).
- No NTS, no server mode, no PTP, no GUI, no DHCPv6, no VM detection in version one.
- `w32time`: stop and disable on install, record state, restore on uninstall. If it runs and cannot be stopped, measure but do not adjust.
- Domain-joined machine: detect, log at every start. Interactive install warns and asks. Silent install aborts unless `--confirm-domain-joined` is given (author's call).
- One step allowed after resume if above the step threshold. Drift saved to disk and bounded to plus or minus 500 ppm on load.
- Depend on `ntp-proto` on the 1.9 line. Commit `Cargo.lock`. Review every bump.
- Previews unsigned and labelled. Public releases signed. Signing is not in this plan.
- British English. No em dashes. No semicolons in prose.

## Review Focus

1. A server replies with stratum 0, an unsynchronised flag, a leap alarm or KoD. Expected: ignored or backed off. The clock never moves on it. (Tasks 4, 7)
2. `w32time` is restarted by policy while the service runs. Expected: the engine stops adjusting and logs why. (Tasks 7, 12)
3. Resume from sleep with a large gap. Expected: one step if above the threshold, then slewing. (Tasks 6, 8)
4. A tier has one source and it is a falseticker. Expected: the clock slews within the cap, no step is taken while the pool cross-check disagrees, and the log says the tier has a single source. (Tasks 6, 7)
5. No network at boot, or the DHCP lease changes while running. Expected: free-run on saved drift, no crash, tier recheck. (Tasks 8, 10)
6. A reply from the wrong address or with the wrong origin timestamp. Expected: dropped. (Task 9)
7. The service crashes while a non-nominal clock rate is set. Expected: the next start reads the rate and resets it. (Task 11)

---

### Task 1: Spike on `ntp-proto` and baseline (throwaway)

**Files:**
- Create: `spikes/probe/` (excluded from any workspace), `docs/superpowers/notes/ntp-proto-spike.md`

**Interfaces:**
- Produces: a written note with answers to the five questions and one decision. The decision gates Tasks 3 to 9.

Questions, each answered with evidence:
1. Does `ntp-proto` 1.9 build on Windows 10 or 11 with `default-features = false` and `rustcrypto`, with no C toolchain?
2. Which public items build a request and parse a reply? Names and signatures.
3. Are filtering, selection and discipline algorithms public, and can plain offset and delay values drive them without `tokio`?
4. How are KoD, stratum 0 and leap alarm represented?
5. Size of the dependency tree.

- [ ] **Step 1: Build the probe.** Build one request, parse a reply fixture captured with the probe itself from `pool.ntp.org`, print the fields.
- [ ] **Step 2: Run on Windows.** `cargo build` then `cargo run`. Record success or the exact error.
- [ ] **Step 3: Measure the baseline.** Run `w32tm /stripchart /computer:pool.ntp.org /samples:120 /dataonly` on this machine idle, then under CPU load. Save the output in the note. This shows what we must beat.
- [ ] **Step 4: Write the note and decide.** Default path: `ntp-proto` for packet parsing only, own selection and discipline in `ntpc-core`. If question 3 is yes, the same functions may wrap `ntp-proto` internals later behind the same signatures, and a differential test compares both.
- [ ] **Step 5: Re-plan gate.** If the note says the packet parser is unusable, stop and rewrite Tasks 3 to 9 before continuing.
- [ ] **Step 6: Commit the note.** The probe is throwaway and gets no tests.

### Task 2: Repository, workspace and architecture note

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`, `.gitignore`, `LICENSE-MIT`, `LICENSE-APACHE`, `README.md`, `docs/architecture.md`, `scripts/check-deps.ps1`, `.github/workflows/ci.yml`
- Create: `crates/ntpc-core/`, `crates/ntpc-platform/`, `crates/ntpc-service/` (the service has `src/main.rs`), `fuzz/`

**Interfaces:**
- Produces: three crates. Dependency rule: `ntpc-core` depends on `thiserror` only. `ntpc-platform` and `ntpc-service` depend on `ntpc-core`. `ntpc-service` depends on `ntpc-platform`.
- Produces: workspace lints. `unsafe_code = "forbid"` everywhere except `ntpc-platform`, which uses `deny` with one `#[allow(unsafe_code)]` module `win32`. Clippy `pedantic` at warn.

Prerequisites to install first and list in `README.md`: MSVC build tools, PowerShell 7, `cargo-deny`, `cargo-fuzz`, nightly toolchain for fuzzing, `gh`.

- [ ] **Step 1: Write a failing check.** `scripts/check-deps.ps1` fails if `cargo tree -p ntpc-core -e normal --prefix none` lists any crate outside `thiserror` and its own dependencies.
- [ ] **Step 2: Run it.** Expected: FAIL (no workspace yet).
- [ ] **Step 3: Create the workspace.** This directory is the repo root. `git init`. The repo name on GitHub is `ntptimeclient-winrs`. The local directory name does not matter.
- [ ] **Step 4: Write `docs/architecture.md`.** Crate map, dependency rule, sans-IO pattern, unsafe policy, how simulation works. Under one page.
- [ ] **Step 5: Add `deny.toml`.** Allow MIT, Apache-2.0, BSD-3-Clause, ISC, Unicode-3.0 and OpenSSL-compatible licences when they appear. Deny known advisories.
- [ ] **Step 6: Add CI.** `windows-latest` and `windows-2022`: fmt, clippy with `-D warnings`, test, deny. `ubuntu-latest`: build and test `ntpc-core` only, as proof that the core has no OS dependency. A nightly job runs each fuzz target for 60 seconds.
- [ ] **Step 7: Verify.** `cargo build --workspace` and `pwsh scripts/check-deps.ps1`. Expected: both pass.
- [ ] **Step 8: Commit locally.** No remote.
- [ ] **Step 9: Ask Terry before creating the remote.** Run `git remote -v`. Ask: create a private repo `ntptimeclient-winrs` on the personal account with `gh repo create`? Do not push until Terry says yes.

### Task 3: Core types and ports

**Files:**
- Create: `crates/ntpc-core/src/{types.rs,ports.rs,error.rs}`

**Interfaces:**
- Produces, all private-field newtypes with constructors and accessors:
  - `Offset` (seconds, remote minus local), `Delay` (seconds), `Ppm`, `Mono` (an instant, nanoseconds, counts awake time only), `SourceId`.
  - Intervals use `std::time::Duration`.
  - `pub enum Tier { Config, Dhcp, Pool }`. `Config` has the highest priority and sorts first.
  - `pub struct SourceSpec { pub id: SourceId, pub tier: Tier, pub addr: SocketAddr, pub label: String }`.
  - `pub struct Sample { pub source: SourceId, pub offset: Offset, pub delay: Delay, pub stratum: u8, pub unsynchronised: bool, pub leap_alarm: bool, pub at: Mono }`.
  - `pub enum QueryFailure { Timeout, KissOfDeath(KodCode), Unreachable, Malformed }` with `KodCode { Deny, Rstr, Rate, Other }`.
- Ports: `pub trait Clock { fn mono(&self) -> Mono; fn wall_ns(&self) -> i128; fn step(&mut self, by: Offset) -> Result<(), ClockError>; fn set_frequency(&mut self, ppm: Ppm) -> Result<(), ClockError>; fn reset_frequency(&mut self) -> Result<(), ClockError>; }`
- Ports: `pub trait DriftStore { fn load(&self) -> Option<Ppm>; fn save(&self, ppm: Ppm) -> Result<(), StoreError>; }`
- `Clock` and `DriftStore` are implemented by adapters and used by the host and the simulation. The engine itself does not call them.

- [ ] **Step 1: Write failing tests:** `tier_sorts_config_first`, `offset_is_remote_minus_local`, `ppm_to_fraction_round_trips`, `fields_are_private` (a compile-fail doc test).
- [ ] **Step 2: Run.** `cargo test -p ntpc-core`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit.**

### Task 4: Source filter and selection

**Files:**
- Create: `crates/ntpc-core/src/{filter.rs,select.rs}`

**Interfaces:**
- Produces: `pub struct SourceFilter` with `fn push(&mut self, s: Sample)` and `fn best(&self) -> Option<Sample>` (8-sample window, lowest delay wins, as in NTP practice).
- Produces: `pub struct SelectionConfig { pub min_survivors: usize /*1*/, pub max_stratum: u8 /*15*/, pub max_age: Duration }`.
- Produces: `pub struct Selection { pub offset: Offset, pub error_bound: Duration, pub survivors: Vec<SourceId> }`.
- Produces: `pub fn select(samples: &[Sample], now: Mono, cfg: &SelectionConfig) -> Option<Selection>`.

- [ ] **Step 1: Write failing tests:** `filter_prefers_lowest_delay_sample`, `rejects_falseticker_when_majority_agrees`, `single_source_is_selected_without_cross_check`, `ignores_stratum_zero_unsynchronised_and_leap_alarm`, `drops_samples_older_than_max_age`, `prefers_low_delay_among_agreeing_sources`, `min_survivors_two_rejects_single_source`.
- [ ] **Step 2: Run.** `cargo test -p ntpc-core select filter`. Expected: FAIL.
- [ ] **Step 3: Implement.** Largest agreeing cluster by offset intervals (Marzullo style), weight by inverse delay.
- [ ] **Step 4: If Task 1 allows it, add a differential test** comparing `select` with the `ntp-proto` algorithm on recorded samples. Skip it if not.
- [ ] **Step 5: Run.** Expected: PASS.
- [ ] **Step 6: Commit.**

### Task 5: Tier chooser with probing

**Files:**
- Create: `crates/ntpc-core/src/tier.rs`

**Interfaces:**
- Produces: `pub struct TierConfig { pub failures_before_fallback: u32 /*3*/, pub stable_before_return: Duration /*10 min*/, pub reprobe_every: Duration /*15 min*/ }`.
- Produces: `TierChooser::new(cfg: TierConfig)`, `fn observe(&mut self, tier: Tier, usable: bool, now: Mono)`, `fn active(&self) -> Option<Tier>`, `fn due_probe(&self, now: Mono) -> Option<Tier>`.
- "Usable" means: the tier produced a `Selection` from fresh samples in the last poll round. The engine computes it.
- Probing means: the engine queries sources of a higher tier in observe-only mode. Their samples feed `observe` and never feed selection. Selection stays inside the active tier.

- [ ] **Step 1: Write failing tests:** `uses_config_tier_when_usable`, `falls_to_dhcp_after_n_failures`, `selection_never_mixes_tiers`, `does_not_flap`, `returns_to_higher_tier_only_after_stable_period`, `tier_with_no_sources_is_unusable`, `due_probe_returns_higher_tier_on_schedule`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit.**

### Task 6: Clock discipline

**Files:**
- Create: `crates/ntpc-core/src/discipline.rs`

**Interfaces:**
- Produces: `pub struct DisciplineConfig { pub step_threshold: Duration /*128 ms*/, pub panic_threshold: Duration /*1000 s*/, pub allow_panic_step: bool /*false*/, pub max_slew: Ppm /*500*/ }`.
- Produces: `pub enum Correction { None, SetFrequency(Ppm), Step(Offset), RefuseStep(Offset) }`. `SetFrequency` is absolute from nominal and already includes the learned drift. The engine re-emits it after every update. The host applies and the platform quantises.
- Produces: `Discipline::new(cfg, initial_drift: Option<Ppm>)`, `fn update(&mut self, sel: &Selection, cross_check: Option<Offset>, now: Mono) -> Correction`, `fn free_run(&mut self, now: Mono) -> Correction`, `fn note_resume(&mut self)`, `fn drift(&self) -> Ppm`.
- Step rules: a step is allowed once after start and once after each resume, when the offset is above `step_threshold`. During normal operation (after the first sync, no resume) a large offset is slewed at `max_slew`. A step above `panic_threshold` returns `RefuseStep` unless `allow_panic_step` is set. These rules are the author's call and need review.

- [ ] **Step 1: Write failing tests:** `small_offset_sets_frequency_not_step`, `first_large_offset_steps_once_then_slews`, `step_threshold_is_configurable`, `learns_drift_from_stable_samples` (20 ppm simulated, learned within 2 ppm), `free_run_uses_saved_drift`, `resume_allows_one_step_only`, `large_offset_during_normal_operation_slews_at_max_rate`, `step_above_panic_threshold_is_refused`, `frequency_is_clamped_to_max_slew`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** a phase and frequency locked loop. Document the gains as constants and say why.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit.**

### Task 7: Engine with feedback

**Files:**
- Create: `crates/ntpc-core/src/engine.rs`

**Interfaces:**
- Produces: `pub struct EngineConfig { pub selection: SelectionConfig, pub tier: TierConfig, pub discipline: DisciplineConfig, pub min_poll: Duration, pub max_poll: Duration }`.
- Produces: `pub enum Event { Tick(Mono), Sample(Sample), Failed(SourceId, QueryFailure), SourcesChanged(Vec<SourceSpec>), Resumed(Mono), AdjustmentAllowed(bool), ClockResult(Result<(), ClockError>) }`.
- Produces: `pub enum Action { Query { source: SourceId, observe_only: bool }, SetFrequency(Ppm), Step(Offset), SaveDrift(Ppm), Log(LogEvent) }`.
- Produces: `pub enum LogEvent` covering tier change, single-source tier, DHCP differs from config, KoD back-off, step taken, step refused, adjustment disabled, clock command failed, holdover started.
- Produces: `Engine::new(cfg: EngineConfig, drift: Option<Ppm>) -> Self`, `fn handle(&mut self, ev: Event) -> Vec<Action>`, `fn next_wake(&self) -> Option<Mono>`, `fn status(&self) -> EngineStatus` (active tier, last offset, drift, age of last good sample).
- The engine holds `adjustment_allowed` as state. When false it emits no `Step` or `SetFrequency`. The host sets it from `w32time` monitoring and the domain-join rule. A failed `ClockResult` turns adjustment off and logs.
- Poll rule: poll at `min_poll` while the offset jitter is high, double towards `max_poll` while stable. KoD back-off per Global Constraints.
- Drift saves are rate limited to once per 10 minutes.
- Pool cross-check: when the active tier is not Pool, the engine emits `Query { observe_only: true }` for pool sources on the `reprobe_every` schedule. It passes the pool's best offset to `Discipline` as a veto input. `Discipline::update` gains a parameter `cross_check: Option<Offset>` and returns `RefuseStep` when it disagrees by more than `step_threshold`. With no cross-check sample yet, steps are refused.

- [ ] **Step 1: Write failing scripted tests:** `backs_off_on_kiss_of_death`, `deny_kod_silences_source_for_one_hour`, `polls_faster_when_unstable`, `respects_min_and_max_poll`, `sources_changed_rechecks_tier`, `logs_single_source_tier`, `logs_when_dhcp_differs_from_config`, `no_actions_that_touch_clock_when_adjustment_disallowed`, `failed_clock_result_disables_adjustment`, `reports_holdover_age_when_no_sources_answer`, `saves_drift_at_most_every_ten_minutes`, `refuses_step_when_pool_cross_check_disagrees`, `allows_step_when_pool_cross_check_agrees`, `slews_only_when_no_pool_cross_check_sample_exists_yet`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** The engine owns the tier chooser, a `SourceFilter` per source, the discipline and the poll timers.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit.**

### Task 8: Simulation scenarios

**Files:**
- Create: `crates/ntpc-core/src/sim/{mod.rs,world.rs}` (behind a `sim` feature, used by tests), `crates/ntpc-core/tests/scenarios.rs`

**Interfaces:**
- Produces: `SimWorld::new(seed: u64, tick_granularity_ppm: f64)`, `fn add_server(&mut self, label: &str, spec: ServerSpec)`, `fn schedule(&mut self, at_secs: u64, ev: SimEvent)`, `fn run(&mut self, engine: &mut Engine, secs: u64) -> SimReport`.
- `ServerSpec { offset, delay, jitter, asymmetry, loss_rate, fault: Fault }`. `SimEvent { Resume, SourcesChanged, NetworkDown, NetworkUp, ExternalStep(Offset), W32TimeStarted }`. `SimReport { max_abs_error, steps, final_error }`.
- The simulated clock quantises frequency changes to `tick_granularity_ppm`, so the controller meets the Windows constraint.

- [ ] **Step 1: Write failing scenarios:** `converges_with_20ppm_drift`, `converges_with_quantised_frequency_steps`, `survives_one_falseticker_among_four`, `kod_server_is_not_followed`, `no_network_at_boot_free_runs_on_saved_drift`, `resume_with_large_gap_steps_once`, `first_boot_with_clock_one_hour_off_steps`, `never_steps_during_normal_operation`, `dhcp_lease_change_switches_sources_without_clock_jump`, `w32time_restart_stops_adjustment`, `asymmetric_delay_error_stays_within_half_the_asymmetry`.
- [ ] **Step 2: Run.** `cargo test -p ntpc-core --features sim`. Expected: FAIL.
- [ ] **Step 3: Implement the world.** Deterministic, seeded, virtual time.
- [ ] **Step 4: Run.** Expected: PASS. Fix engine bugs in the Task 4 to 7 files.
- [ ] **Step 5: Commit.**

### Task 9: Protocol adapter

**Files:**
- Create: `crates/ntpc-service/src/proto.rs`, `fuzz/fuzz_targets/parse_response.rs`
- Test: `crates/ntpc-service/tests/proto_fixtures.rs`

**Interfaces:**
- Consumes: the Task 1 note.
- Produces: `pub struct RequestToken { /* random origin timestamp, destination address */ }`, `pub fn build_request(now: NtpTime, dest: SocketAddr) -> (Vec<u8>, RequestToken)`, `pub fn parse_response(bytes: &[u8], from: SocketAddr, token: &RequestToken, received: NtpTime, source: SourceId, at: Mono) -> Result<Sample, QueryFailure>`.
- Invariant: absolute NTP times are converted to deltas before any `f64`. No absolute time is stored as `f64`.

- [ ] **Step 1: Write failing tests:** `parses_valid_fixture_into_sample`, `kod_maps_to_failure`, `stratum_zero_maps_to_failure`, `rejects_wrong_origin_timestamp`, `rejects_reply_from_unexpected_address`, `rejects_wrong_mode_or_version`, `rejects_truncated_packet`, `origin_timestamp_is_random_per_request`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** over `ntp-proto`, or own parser per the note.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Fuzz.** `cargo +nightly fuzz run parse_response -- -max_total_time=120`. Expected: no crash.
- [ ] **Step 6: Commit.**

### Task 10: Config, resolver, drift store

**Files:**
- Create: `crates/ntpc-service/src/{config.rs,resolver.rs,drift_store.rs}`

**Interfaces:**
- Produces: `Config { servers: Vec<String>, dhcp: bool, pool: String /*"pool.ntp.org"*/, step_threshold_ms: u32, panic_threshold_s: u32, allow_panic_step: bool, min_poll_s: u32, max_poll_s: u32, state_dir: PathBuf }`, `Config::default()`, `Config::parse(&str) -> Result<Config, ConfigError>`, `Config::load(&Path)`, `Config::engine_config(&self) -> EngineConfig`. TOML with unknown keys rejected.
- Produces: `Resolver` with `fn expand(&mut self, names: &[(String, Tier)]) -> Vec<SourceSpec>`. It owns `SourceId` allocation. It caps results at 4 addresses per name and 8 per tier. It drops loopback, link-local, multicast, broadcast and unspecified addresses and the machine's own addresses. It re-resolves on a timer.
- Produces: `FileDriftStore` implementing `DriftStore`. A value outside plus or minus 500 ppm or an unreadable file loads as `None`.
- State directory is created with an ACL allowing only SYSTEM and Administrators to write. The ACL call is in `ntpc-platform` and verified there (Task 11).

- [ ] **Step 1: Write failing tests:** `defaults_match_the_spec`, `rejects_min_poll_above_max_poll`, `rejects_unknown_keys`, `empty_file_gives_defaults`, `resolver_caps_addresses_per_name`, `resolver_drops_loopback_and_own_addresses`, `resolver_gives_stable_ids_for_same_address`, `pool_name_expands_to_several_sources`, `drift_store_ignores_out_of_range_value`, `drift_store_ignores_corrupt_file`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit.**

### Task 11: Windows clock adapter

**Files:**
- Create: `crates/ntpc-platform/src/{lib.rs,win32.rs,clock.rs,acl.rs}`
- Test: `crates/ntpc-platform/tests/clock_windows.rs` (`#[ignore]`, needs admin)

**Interfaces:**
- Produces: `WindowsClock::new() -> Result<Self, ClockError>` implementing `Clock`. It acquires the system-time privilege. On creation it reads the current adjustment, and it can `reset_frequency` to nominal.
- Produces: `pub fn ppm_to_adjustment(ppm: Ppm, nominal: u64) -> u64` (width confirmed in Step 1) and `pub fn quantise(ppm: Ppm, granularity_ppm: f64) -> Ppm`.
- Produces: `pub fn secure_state_dir(path: &Path) -> Result<(), AclError>`.

- [ ] **Step 1: Verify the Win32 APIs** on Microsoft Learn: `SetSystemTimeAdjustmentPrecise`, `GetSystemTimeAdjustmentPrecise`, `SetSystemTime` (precision of `SYSTEMTIME`), `QueryUnbiasedInterruptTime`, `AdjustTokenPrivileges` with `SeSystemtimePrivilege`, and ACL setting on a directory. Record signatures, the width of the adjustment value and the step precision in `docs/architecture.md`. Decide the `wall_ns` and `mono` sources there. Note whether the adjustment persists after the process exits.
- [ ] **Step 2: Write failing tests:** `adjustment_zero_ppm_is_nominal`, `adjustment_is_monotonic`, `adjustment_clamps_to_valid_range`, `quantise_rounds_to_granularity`.
- [ ] **Step 3: Implement.** Unsafe only in `win32.rs`, each block with a `// SAFETY:` comment.
- [ ] **Step 4: Run unit tests.** Expected: PASS.
- [ ] **Step 5: Run the ignored test** in an elevated shell on a throwaway VM with its hypervisor time sync turned off: step +1 s then -1 s, set 100 ppm then reset, kill the process and confirm the next start reads and resets the rate (Review Focus 7).
- [ ] **Step 6: Commit.**

### Task 12: `w32time` takeover, monitor and domain detection

**Files:**
- Create: `crates/ntpc-platform/src/{w32time.rs,domain.rs}`; `crates/ntpc-service/src/cli.rs` (subcommands `install`, `uninstall`)

**Interfaces:**
- Produces: `JoinState { Workgroup, Domain, Unknown }`, `join_state() -> JoinState`.
- Produces: `trait ServiceControl { fn query(&self, name: &str) -> Result<SvcState, SvcError>; fn stop(&mut self, name: &str) -> Result<(), SvcError>; fn set_start_type(&mut self, name: &str, t: StartType) -> Result<(), SvcError>; }`, `Restore` (serialised to `restore.json` in the state directory), `take_over(ctl) -> Result<Restore, TakeoverError>`, `restore(ctl, Restore)`, `is_running(ctl) -> bool`.
- The `install` and `uninstall` subcommands own the `w32time` logic and the domain-join rule. The PowerShell scripts in Task 15 only call them.
- The service polls `is_running` every 30 seconds and sends `AdjustmentAllowed(false)` while `w32time` is running.

- [ ] **Step 1: Write failing tests with a fake `ServiceControl`:** `take_over_records_previous_state`, `restore_returns_previous_state`, `take_over_fails_cleanly_when_stop_refused`, `restart_after_takeover_is_detected`, `install_aborts_on_domain_joined_silent_without_flag`, `install_proceeds_on_domain_joined_with_flag`, `uninstall_restores_w32time_even_if_service_missing`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** against the service control manager. Verify the domain-join call on Microsoft Learn first. Azure AD and hybrid join are noted in `docs/architecture.md` as out of scope for version one.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit.**

### Task 13: DHCP source reader (IPv4 only)

**Files:**
- Create: `crates/ntpc-platform/src/dhcp.rs`

**Interfaces:**
- Produces: `pub fn parse_option42(bytes: &[u8]) -> Vec<Ipv4Addr>` (pure), `pub fn read_lease_servers() -> Result<Vec<Ipv4Addr>, DhcpError>`, `DhcpWatcher` that signals when the lease changes.

- [ ] **Step 1: Find a way to read option 42 on Windows.** Check the DHCP client APIs and registry on Microsoft Learn. Write the method and the reason in `docs/architecture.md`. If no supported method exists, record that, ship version one without DHCP and log it. Tell Terry.
- [ ] **Step 2: Write failing tests:** `parses_one_server`, `parses_several_servers`, `rejects_length_not_multiple_of_four`, `empty_input_gives_empty_vec`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit.**

### Task 14: Service host, wiring and hardening

**Files:**
- Create: `crates/ntpc-service/src/{main.rs,host.rs,transport.rs,logging.rs,status.rs}`
- Test: `crates/ntpc-service/tests/wiring.rs`, `crates/ntpc-service/tests/udp_fake_server.rs`

**Interfaces:**
- Produces: `trait Transport { async fn query(&self, dest: SocketAddr, timeout: Duration) -> Result<Sample, QueryFailure>; }`, `UdpTransport` (stamps receive time immediately after `recv` and uses a raised thread priority).
- Produces: `pub async fn run(cfg: Config, clock: impl Clock, transport: impl Transport, drift: impl DriftStore, shutdown: impl Future<Output = ()>)`.
- Host duties: map engine actions to I/O, feed results back as events (including `ClockResult`), emit `Resumed` from the service power event, emit `AdjustmentAllowed`, write `status.json` every 30 seconds, call `reset_frequency` on stop, log at start the join state and the active config. Escape control characters in logged strings.
- Subcommands: `run` (console, for development), `service`, `status`, `install`, `uninstall`.
- Account: run as a low-privilege service account with only the system-time privilege. Verify the Windows way to set required privileges in `docs/architecture.md`. The author's decision: one process in version one, with parsers fuzzed. A privileged broker split is a later option.

- [ ] **Step 1: Write failing tests with fakes:** `applies_frequency_from_engine_actions`, `feeds_clock_failure_back_as_event`, `resets_frequency_on_shutdown`, `saves_drift`, `writes_status_json`, `status_command_prints_status_json`, `logs_join_state_at_start`, `escapes_control_characters_in_logs`.
- [ ] **Step 2: Write the UDP test** against a loopback fake NTP server in the test with faults: wrong time, KoD, delay, truncated packet. Name: `udp_transport_handles_fake_server_faults`.
- [ ] **Step 3: Run.** Expected: FAIL.
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run.** Expected: PASS.
- [ ] **Step 6: Run manually** in console mode on a throwaway VM and watch the log for ten minutes.
- [ ] **Step 7: Commit.**

### Task 15: Developer preview packaging

**Files:**
- Create: `packaging/install.ps1`, `packaging/uninstall.ps1`, `.github/workflows/preview.yml`

**Interfaces:**
- Produces: a zip labelled UNSIGNED PREVIEW with the binary, a default config, the scripts and a warning not to use it on machines that matter. The scripts only call `ntptimeclient-winrs.exe install` and `uninstall`.

- [ ] **Step 1: Write the scripts and workflow.** The workflow builds on tag and uploads the zip.
- [ ] **Step 2: Test by hand** on a throwaway VM: install, check `w32time` is stopped and disabled, run ten minutes, uninstall, check `w32time` is restored.
- [ ] **Step 3: Commit.**

### Task 16: Measurement procedure

**Files:**
- Create: `docs/measuring.md`

- [ ] **Step 1: Write the procedure.** Reference: a different public NTP source from the one the service uses, or a LAN server. Sampler: a PowerShell loop around `w32tm /stripchart`. Cases: idle, CPU load, sleep and resume, a VM. Run length and the comparison table format.
- [ ] **Step 2: Run it** for the Windows default and for the service. Attach the CSVs.
- [ ] **Step 3: Report.** One table and one paragraph, including cases where we lose.
- [ ] **Step 4: Commit.**

---

## Self-review

- **Spec coverage:** strict tiers (Tasks 5, 10, 13), DHCP differs (Task 7), pool expansion (Task 10), filter and selection (Task 4), slew, step, panic, resume (Task 6), polling and KoD (Task 7), feedback and `w32time` (Tasks 7, 12, 14), domain join (Task 12), crash recovery of the clock rate (Tasks 11, 14), reply validation (Task 9), state directory bounds and ACL (Tasks 10, 11), logging safety (Task 14), measurement (Tasks 1, 16), previews (Task 15), `ntp-proto` reuse and gate (Tasks 1, 9).
- **Dropped from version one on purpose:** DHCPv6, VM detection, privilege broker, config and DHCP fuzzing, property tests, a separate simulation crate. Secure Time Seeding is a `w32time` feature. With `w32time` stopped it should not act. That is unverified and Task 1 notes it.
- **Gaps by design:** signed releases (certificate decision), pool vendor zone request (a human action).
- **Open for Terry:** a single-source tier can still move the clock within the panic threshold of 1000 s. A cross-check against the pool in observe-only mode would remove that, at the cost of your strict tier rule. Decide.
- **Type consistency:** `Offset`, `Ppm`, `Mono`, `Duration`, `SourceSpec`, `Sample`, `Selection`, `Correction`, `Event`, `Action` are defined in Tasks 3 to 7 and used unchanged after.
- **Author's calls to check:** crate names, TOML, 128 ms and 1000 s thresholds, poll limits, KoD timings, silent install abort, one-process privilege design.
