# Architecture

## Crate map

- `ntpc-core`: the engine. Source selection, filtering, clock discipline, poll timing. No OS or network code.
- `ntpc-platform`: Windows adapters. Clock, sockets, registry, DHCP.
- `ntpc-service`: the service binary. It wires the core to the adapters.
- `fuzz/`: `cargo-fuzz` targets. Outside the workspace. A future `fuzz/Cargo.toml` must have its own `[workspace]` table.

## Dependency rule

- `ntpc-core` depends on `thiserror` only.
- `ntpc-platform` depends on `ntpc-core`, and on Windows on `windows-sys` (which brings only `windows-link`).
- `ntpc-service` depends on `ntpc-core` and `ntpc-platform`.

`scripts/check-deps.ps1` fails if `ntpc-core` gains any other dependency. CI also builds and tests `ntpc-core` alone on Linux. That proves it has no OS dependency.

## Sans-IO pattern

The core never reads a clock, opens a socket or touches a file. The caller feeds it events and carries out the actions it returns.

- Events in: a reply arrived, a timer fired, sources changed, the machine resumed.
- Actions out: send a query, set a timer, slew, step, log.

Time is passed in as a value. Nothing inside the core calls "now". The exact types are defined by later tasks.

## Unsafe policy

- The workspace sets `unsafe_code = "forbid"`.
- `ntpc-platform` sets `deny` and allows `unsafe` in one module, `win32`.
- Each `unsafe` block carries a `// SAFETY:` comment.
- `win32` is compiled on Windows only. The pure rate functions in `clock` build everywhere, so the fuzz job on Linux still builds `ntpc-service`.
- Win32 API names and units: see "Platform: Windows clock and state directory" below.

## Simulation testing

Because the core is sans-IO, tests drive it with a simulated world. The world has virtual time, seeded randomness and scripted servers and faults. Scenarios run in milliseconds and give the same result every time. The world sits behind the `sim` feature of `ntpc-core`. A later task builds it.

## How to add an adapter

1. Decide what the core needs from the outside world. Express it as an event or an action in `ntpc-core`, not as a call.
2. Implement the effect in `ntpc-platform`. Keep any `unsafe` inside `win32`.
3. Wire it in `ntpc-service`.
4. Add a simulation scenario for the new event or action in `ntpc-core`.
5. Run `scripts/check-deps.ps1` to confirm the core gained no dependency.

## Platform: Windows clock and state directory

Task 11 facts. Each line names its source. "Measured" means read on the builder's Windows 11 machine (build 26300) with read-only calls. "Guess" means not found in the docs.

### Sources

- [SetSystemTimeAdjustmentPrecise](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-setsystemtimeadjustmentprecise)
- [GetSystemTimeAdjustmentPrecise](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeadjustmentprecise)
- [SetSystemTimeAdjustment](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-setsystemtimeadjustment)
- [GetSystemTimeAdjustment](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeadjustment)
- [SetSystemTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-setsystemtime)
- [SYSTEMTIME](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime)
- [GetSystemTimePreciseAsFileTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime)
- [QueryUnbiasedInterruptTime](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime)
- [QueryUnbiasedInterruptTimePrecise](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttimeprecise)
- [AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)
- [SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)
- [GetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow) and [SetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow)
- [ConvertStringSecurityDescriptorToSecurityDescriptorW](https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw)
- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [FILE_ATTRIBUTE_TAG_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_attribute_tag_info)

### Rate control

- Signatures (Learn): `BOOL SetSystemTimeAdjustmentPrecise(DWORD64 dwTimeAdjustment, BOOL bTimeAdjustmentDisabled)` and `BOOL GetSystemTimeAdjustmentPrecise(PDWORD64 lpTimeAdjustment, PDWORD64 lpTimeIncrement, PBOOL lpTimeAdjustmentDisabled)`. Windows 10 and Server 2016 or later.
- Width: 64-bit unsigned (Learn). The plan guessed 64-bit. That holds.
- Units: the precise pages say only "adjusted clock update frequency" and "clock update frequency". The Learn sample converts ppm to units as `ppm * QueryPerformanceFrequency / 1e6`. Measured: the increment is 10 000 000 and QPF is 10 000 000. So the units look like counts per second of a 10 MHz base on this machine. The code does not assume 10 MHz. It reads the increment at start and treats it as nominal.
- Rate rule: the legacy pages state it. The clock runs fast when the adjustment is above the increment, slow when below, normal when equal. The precise pages do not restate it. The code assumes the same rule for the precise pair. Rate in ppm is `(adjustment - increment) / increment * 1e6`. Positive `Ppm` means faster, so `adjustment = increment + round(increment * ppm / 1e6)`.
- Granularity: one count is `1e6 / increment` ppm. Measured: 0.1 ppm. The legacy pair measured increment 156 250 (100 ns units per 15.625 ms), so one count there is 6.4 ppm. The sim's 6.4 ppm guess is the legacy granularity. The precise API is 64 times finer on this machine.
- Valid range: not documented on any of the four pages. The Learn sample refuses more than 1000 ppm ("Adjustment too large"). `ppm_to_adjustment` clamps to plus or minus 1000 ppm. The discipline caps at 500 ppm, so the clamp never bites in normal use.
- Disable flag (Learn): TRUE means "the system should synchronize time-of-day using its own internal mechanisms" and the value is ignored. The legacy Get page says that with TRUE "the system time-of-day clock advances at the normal rate". `reset_frequency` calls `SetSystemTimeAdjustmentPrecise(0, TRUE)`.
- Privilege (Learn): `SE_SYSTEMTIME_NAME`, disabled by default, enable with `AdjustTokenPrivileges`. The docs suggest disabling it again after each call. The service keeps it enabled for its lifetime. Setting the clock is its only privileged job.
- `AdjustTokenPrivileges` (Learn): it can return success with `ERROR_NOT_ALL_ASSIGNED` when the token lacks the privilege. The code treats that as `ClockError::PermissionDenied`.
- Persistence after the process exits: NOT DOCUMENTED. No Learn page read says whether the rate survives the caller. UNVERIFIED. The pages describe a system-wide setting, not a per-process one, so the design assumes it survives. Review Focus 7 is tested by the owner on a VM.
- Measured hint: `w32time` runs on the builder's machine. A new process read `9999919 / 10000000`, disabled FALSE, so -8.1 ppm. A rate set by another process is visible from a new process. That shows the state is system-wide. It does not prove what happens when the setting process dies.
- Measured oddity, not explained: the legacy pair read `156251 / 156250` (+6.4 ppm) a moment before. `w32time` may have changed it in between. The code uses only the precise pair.

### Step

- `SetSystemTime(const SYSTEMTIME *)` takes UTC. It enables and disables `SE_SYSTEMTIME_NAME` itself (Learn).
- `SYSTEMTIME` resolves milliseconds only. `wYear` is valid from 1601 to 30827 (Learn).
- Sub-millisecond steps: `NtSetSystemTime` is an undocumented native call. No documented user-mode API takes a finer value. Choice: round the target to the nearest millisecond and call `SetSystemTime`. The error is at most 0.5 ms plus the call latency. The latency is not measured. The engine slews any residual after the step.
- Target built in integers: read `GetSystemTimePreciseAsFileTime`, add the offset in nanoseconds, round to a millisecond, convert with `FileTimeToSystemTime`.
- The step refuses a target before 1970-01-01 or from 2106-02-07T06:28:16Z (the end of 32-bit Unix seconds). That bound is our choice. It sits well inside `SYSTEMTIME` and covers NTP era 1, which starts 2036-02-07.

### Time sources

- `wall_ns`: `GetSystemTimePreciseAsFileTime`. Learn: "highest possible level of precision (<1us)", UTC, `FILETIME` in 100 ns units since 1601. Converted to Unix nanoseconds in integers.
- `mono`: `QueryUnbiasedInterruptTimePrecise`, 100 ns units (Learn). It excludes sleep and hibernation (Learn). That is the engine's "awake time only" contract. The interrupt-time count "is not subject to adjustments by users or the Windows time service" (QueryUnbiasedInterruptTime page). So a step does not move it. The precise form reads the timer hardware, not the last tick (Learn).
- Not chosen: `QueryUnbiasedInterruptTime` resolves only one tick, 0.5 to 15.625 ms (Learn). `QueryInterruptTime` counts sleep (the "biased" count). `QueryPerformanceCounter` is for intervals, but the pages read do not say whether it counts sleep.
- Whether `SetSystemTimeAdjustmentPrecise` also changes the interrupt-time rate is not stated. Guess: no, per the "not subject to adjustments" sentence.

### State directory (`secure_state_dir`)

- Open with `CreateFileW` and `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`. Learn: the backup flag is needed "to obtain a handle to a directory". With the reparse flag "Normal reparse point processing will not occur; CreateFile will attempt to open the reparse point".
- Reparse check: `GetFileInformationByHandleEx(FileAttributeTagInfo)` on that handle. A set `FILE_ATTRIBUTE_REPARSE_POINT` is refused.
- Parents: the reparse flag covers the last component only. The CreateFileW page says nothing about the others, so the code assumes they are followed. Each ancestor from the drive root down is opened the same way and checked. Only absolute local drive paths with plain components are accepted.
- Residual race: someone able to rename an ancestor between the check and the open could swap it. That needs write access to the ancestor's parent.
- Owner and DACL are read and written through the open handle (`GetSecurityInfo`, `SetSecurityInfo`), not by name. A swap after the open cannot redirect them.
- The owner must be SYSTEM or BUILTIN\Administrators. Any other owner is refused. The owner of an object can always rewrite its DACL, so re-ACLing a foreign-owned directory would not secure it. No "remove and recreate" path is offered.
- Target DACL, SDDL `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`: protected (no inheritance from the parent), SYSTEM and Administrators full control, inherited by child files and folders, nothing for Users. The directory holds only the drift value. Nobody else needs to read it.
- A new directory is created with that DACL in the `CreateDirectoryW` security attributes, so it is never open in between. Only the last component is created. The parent must exist.
- Owner: the code tries to set the owner to Administrators. If the token cannot assign it (`ERROR_INVALID_OWNER`) it keeps the current owner. It then checks the owner is SYSTEM or Administrators.
- Existing directory with a right owner and a wrong DACL: the DACL is replaced, then read back and checked.
- Error text carries no paths (engine host contract).
- Load-side hardening (reparse flag and `SECURITY_IDENTIFICATION` on opens of `drift.txt` and the config) lives in `ntpc-service` `safe_open`. It is not duplicated here.
