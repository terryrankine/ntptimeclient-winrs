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
- `SetSystemTime` "enables the SE_SYSTEMTIME_NAME privilege before changing the system time and disables the privilege before returning" (Learn). So after a step the adapter enables the privilege again. Every set call also retries once after re-enabling if it gets `ERROR_PRIVILEGE_NOT_HELD` (1314). Whether `SetSystemTime` disables a privilege that was already enabled is not stated. The fix covers both cases.
- Start and stop (R71): at start the host calls `WindowsClock::take_rate_control`, which sets `SetSystemTimeAdjustmentPrecise(increment, FALSE)`. That is the nominal rate with the OS kept out. At stop `reset_frequency` sets `(0, TRUE)` and hands timekeeping back so `w32time` can take over. `new` changes nothing. Both are unverified on a VM.
- No magnitude cap in the adapter (R70). The discipline caps at 500 ppm and the mapping clamps at 1000 ppm.
- `quantise` uses the same whole nano-ppm integers as the mapping. So it reports exactly the applied rate whenever the granularity is a whole number of nano-ppm.
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
- Parents: the reparse flag covers the last component only. The CreateFileW page says nothing about the others, so the code assumes they are followed. Each ancestor from the drive root down is opened the same way and checked. Every reparse tag is refused, on purpose. Only absolute local drive paths with plain components are accepted.
- Parent owners (R69): every ancestor below the drive root must be owned by SYSTEM (`S-1-5-18`), Administrators (`S-1-5-32-544`) or TrustedInstaller (`S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`). Else `UntrustedParent`. The owner of a parent can rename the state directory away and put a junction in its place. The owner is read from the same no-follow handle as the reparse check. SIDs are compared in string form (`ConvertSidToStringSidW`). The drive root is exempt.
- Residual race: someone able to rename an ancestor between the check and the open could swap it. That needs write access to the ancestor's parent.
- Owner and DACL are read and written through the open handle (`GetSecurityInfo`, `SetSecurityInfo`), not by name. A swap after the open cannot redirect them.
- The owner must be SYSTEM or BUILTIN\Administrators. Any other owner is refused. The owner of an object can always rewrite its DACL, so re-ACLing a foreign-owned directory would not secure it. A foreign-owned directory is refused, not replaced. Replacement (quarantine and recreate, below) is only for a trusted-owned directory.
- Target DACL, SDDL `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`: protected (no inheritance from the parent), SYSTEM and Administrators full control, inherited by child files and folders, nothing for Users. The directory holds only service state (drift, the w32time restore record, status). Nobody else needs to read it.
- A new directory is created with that DACL in the `CreateDirectoryW` security attributes, so it is never open in between. Only the last component is created. The parent must exist.
- Before creating, the token's default owner (`TokenOwner`) must be SYSTEM or Administrators. Otherwise nothing is created and the call returns `UntrustedOwner`. Measured on the builder's machine: a plain user that creates the directory with this DACL can no longer delete it by path (`RemoveDirectoryW` and `std::fs::remove_dir` both got access denied). Why is not confirmed. A directory this call created and then failed to secure is removed, best effort.
- Owner: the code tries to set the owner to Administrators. If the token cannot assign it (`ERROR_INVALID_OWNER`) it keeps the current owner. It then checks the owner is SYSTEM or Administrators.
- Guarantee on Ok: the path names a directory, not a link, owned by SYSTEM or Administrators, with exactly the protected secure DACL. Its only children are plain single-link files from `KNOWN_CHILDREN`, owned by SYSTEM or Administrators.
- Known names (`KNOWN_CHILDREN`, R80): `drift.txt` and `drift.txt.tmp` (drift store, Task 10), `restore.json` and `restore.json.tmp` (w32time takeover record, Task 12), `status.json` and `status.json.tmp` (status output, later task). Any other name refuses.
- Result: `secure_state_dir(path: &Path) -> Result<Secured, AclError>`, where `Secured { restore_record: RestoreRecord }` and `RestoreRecord` is `Kept`, `Dropped` or `Absent`. `Kept`: `restore.json` is in the secured directory, kept on the fast path or carried. `Dropped`: it existed but failed a provenance check, so it was not carried and stays in the quarantine. Install must treat the record as lost. `Absent`: there was none, also for a newly created directory.
- Existing directory, every start: the children are listed through the directory handle (`GetFileInformationByHandleEx(FileFullDirectoryInfo)`). Each known file is opened without following a reparse point, and its kind, link count (`GetFileInformationByHandle`) and owner are read from that handle. A pure rule then decides:
  - Unknown name, directory, any reparse point, or a link count other than 1: refuse with `UnexpectedChild`. Persistence is off.
  - DACL exact and every child owned by SYSTEM or Administrators: keep the directory as it is (fast path).
  - Otherwise (wrong DACL, or a known file with a foreign owner): quarantine and replace (R78).
- Why not re-ACL the old directory (R78): a handle opened before a DACL change keeps the rights it was granted. Under the inherited `ProgramData` DACL, Users can hold `FILE_WRITE_DATA` and `FILE_WRITE_ATTRIBUTES` on the directory. Through such a handle they can still add files, or turn the emptied directory into a junction with `FSCTL_SET_REPARSE_POINT`, after the DACL change. Neither a listing nor an identity check sees a later change. A fresh directory has no such handles and no children, because it is born with the secure descriptor.
- Quarantine and replace: clean the known files (each checked and deleted through its own handle). Rename the old directory, through its checked handle (`SetFileInformationByHandle(FileRenameInfo)`, absolute target, no replace), to `<name>.old-<16 hex>` next to it. The hex comes from the standard library's per-process random hash keys, so another user cannot guess it. A name clash is tried three times. Then create a fresh directory with the secure descriptor and run the full fresh-directory checks. On success, delete the quarantine through its handle, best effort, never following links. If anything fails after the rename, the fresh directory is removed and the old one is renamed back. If that also fails, `RollbackFailed` carries both errors.
- The rename through a handle moves exactly the checked object, whatever the path names by now. `MoveFileExW` would look the source up by path again. The rename fails when another handle to the directory was opened without `FILE_SHARE_DELETE`. Then the call refuses and persistence is off (R75).
- Carry on quarantine (R80): only `restore.json` is carried. Before the rename it is opened without following links, and checked on that handle: plain file, one link, at most 4 KiB, owner SYSTEM or Administrators. The bytes are read through the same handle. After the fresh directory passes its checks, the bytes are written there with `create_new`, the reparse no-follow flag and `SECURITY_IDENTIFICATION`, synced, and read back without following links. A mismatch or error removes the new file and counts as a failure after the rename: the fresh directory is removed and the old one renamed back. On success the original is deleted from the quarantine if that name still holds the very file read. A record that fails a check is not carried and not deleted (`Dropped`). The `.tmp` files, `drift.txt` (a hint, relearnt) and `status.json` (regenerated) are never carried. Content checks belong to the restore reader (Task 12), not here.
- Quarantine leftovers: a `<name>.old-<hex>` directory stays when its delete fails, for example because a held handle added something to it. It also stays when a `restore.json` was dropped: the delete is then skipped and the record stays in it. Nothing reads it. The service never cleans up `*.old-*` siblings. Removing them is an administrator step.
- The fast path trusts any directory whose DACL is exactly the secure one. An administrator must never re-ACL the state directory in place: a handle opened before such a change keeps its rights.
- Failure order on the quarantine path: if the fresh create, the fresh checks or the carry fail, the fresh directory (if made) is deleted through its handle, and the old directory is renamed back. If the rename back fails too, the result is `RollbackFailed` with both errors, and nothing in the quarantine is deleted.
- `RollbackFailed` recovery (R88, accepted): a local user who creates a directory at the original name between the quarantine rename and the fresh create makes both the create (183) and the rename back fail. That needs a weak pre-existing directory and a user racing the window. The previous directory, possibly with `restore.json`, is left as `<name>.old-<hex>`. To recover: delete the squatter directory, rename `<name>.old-<hex>` back to `<name>`, then run again. The error text says a previous directory was left under a sibling name and may hold the restore record. It carries no path, and the quarantine name is not returned, so a script cannot be tricked into acting on a path an attacker chose.
- Caller duties: install must refuse on `RollbackFailed` with its own exit code, and on `RestoreRecord::Dropped`. Task 12 treats `RollbackFailed` as "the restore record may be in quarantine". `AclError` is `#[non_exhaustive]` and `Secured` is `#[must_use]`.
- Deferred (m-5): a file created at `restore.json` between the inspection and the read can turn `Absent` into `Dropped`. That fails safe, because install refuses.
- Clean-up errors: an unknown entry or a known name that fails a check gives `UnexpectedChild` and deletes nothing. An OS error while listing, opening or checking gives `Os` and deletes nothing. An OS error on the second delete after the first worked gives `Os` after a partial delete. Only our own drift file is gone, and the next save writes it again.
- Fresh directory: set the owner to Administrators where the token can, read owner and DACL back, list the directory through the handle (it must be empty), then check identity. The order is pinned by a test.
- Identity check, at the end of every path: the path is opened again without following links. It must not be a reparse point (`Link`), and its volume serial and 64-bit file index must match the secured handle (`PathChanged`). The 128-bit ReFS `FileIdInfo` is deferred.
- R73: the drive must be `DRIVE_FIXED` (`GetDriveTypeW` on `X:\`), else `NotFixedDrive`. A path component that ends in a dot or a space is refused (`TrailingDotOrSpace`), because Windows strips those and the name checked would not be the name opened.
- R74: parent owners are checked, parent DACLs are not. A parent owned by SYSTEM, Administrators or TrustedInstaller whose DACL grants Users `FILE_DELETE_CHILD` would let them remove the state directory. That is an administrator misconfiguration, out of scope.
- Names: a component holding a colon (named stream syntax) is refused, and so is a DOS device name (CON, PRN, AUX, NUL, COM1 to COM9, LPT1 to LPT9, with or without an extension, any case) in a non-verbatim path. Error `ReservedName`.
- R79: a `subst` drive reports `DRIVE_FIXED` and is accepted. Pointing one at a user directory is an administrator misconfiguration, like R74.
- Error text carries no paths (engine host contract).
- Load-side hardening (reparse flag and `SECURITY_IDENTIFICATION` on opens of `drift.txt` and the config) lives in `ntpc-service` `safe_open`. It is not duplicated here.

## Platform: `w32time` takeover and domain join (Task 12)

Each line names its source. "Measured" means read on the builder's Windows 11 machine with read-only calls (`sc qc`, `sc enumdepend`, `sc qtriggerinfo` and the read-only live tests). "Guess" means not found in the docs.

### Sources

- [NetGetJoinInformation](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetjoininformation)
- [NetGetAadJoinInformation](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation)
- [QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
- [QueryServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw)
- [ChangeServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw)
- [ControlService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice)
- [StartServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)
- [SERVICE_DELAYED_AUTO_START_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info)
- [Service Trigger Events](https://learn.microsoft.com/en-us/windows/win32/services/service-trigger-events)
- [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings)

### Domain join

- `NET_API_STATUS NetGetJoinInformation(LPCWSTR lpServer, LPWSTR *lpNameBuffer, PNETSETUP_JOIN_STATUS BufferType)`. A null server means the local computer. Netapi32. No special group membership is needed (Learn).
- The name buffer "is allocated by the system and must be freed using the NetApiBufferFree function" (Learn). The code frees it on every path and never reads it. No domain or workgroup name leaves `join_state`.
- `NETSETUP_JOIN_STATUS` (Learn, the enum on the function page): `NetSetupUnknownStatus = 0`, `NetSetupUnjoined = 1`, `NetSetupWorkgroupName = 2`, `NetSetupDomainName = 3`.
- Mapping: 3 is `Domain`. 1 and 2 are `Workgroup`. 0, any other value and any error are `Unknown`.
- Install rule: `Unknown` is treated like `Domain`, the safe direction. A silent install aborts on both unless `--confirm-domain-joined` is given. An interactive install warns and asks.
- Out of scope for version one: Entra ID (Azure AD) join and hybrid join. `NetGetAadJoinInformation` (Windows 10 and Server 2016 or later, Learn) reports Entra join and work accounts. It is not called. Guess: an Entra-only device reports `NetSetupWorkgroupName` and a hybrid device reports `NetSetupDomainName`. Not verified. A `DsRegGetJoinInfo` function was not found on Learn. It is not needed for v1.

### Service control

- Service name `w32time` (Learn, the `sc qtriggerinfo w32time` example on the trigger page).
- Access rights per call (Learn): `QueryServiceStatusEx` needs `SERVICE_QUERY_STATUS`. `QueryServiceConfigW` needs `SERVICE_QUERY_CONFIG`. `ControlService(SERVICE_CONTROL_STOP)` needs `SERVICE_STOP`. `StartServiceW` needs `SERVICE_START`. `ChangeServiceConfigW` needs `SERVICE_CHANGE_CONFIG`. Each wrapper opens its own handle with only the rights its call needs. The query path never asks for more than `SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG`.
- `QueryServiceConfigW` buffer: "The maximum size of this array is 8K bytes". A null buffer of size 0 fails with `ERROR_INSUFFICIENT_BUFFER` and sets the size (Learn). The code uses that two-call pattern with a u64 buffer for alignment. Only `dwStartType` is read. The strings in the struct are never read.
- The config query reflects "the configuration of the service when it is next run" if it was changed while running (Learn). So the recorded start type is the one that applies at next boot.
- Start types (Learn, ChangeServiceConfigW): `SERVICE_BOOT_START 0` and `SERVICE_SYSTEM_START 1` (drivers only), `SERVICE_AUTO_START 2`, `SERVICE_DEMAND_START 3`, `SERVICE_DISABLED 4`. Disabled: "Attempts to start the service result in the error code ERROR_SERVICE_DISABLED".
- Delayed auto start is a separate flag, `SERVICE_CONFIG_DELAYED_AUTO_START_INFO` (3), read and set with `QueryServiceConfig2W` and `ChangeServiceConfig2W`. "This setting is ignored unless the service is an auto-start service" (Learn). `StartType::AutomaticDelayed` is auto start plus the flag. Setting `Automatic` clears the flag. `Manual` and `Disabled` leave it alone, because it is ignored.
- Boot and system start are driver-only (Learn). A query that returns them is refused with `SvcError::UnsupportedStartType`. The restore record cannot hold them.
- Stop: `ControlService` returns `ERROR_DEPENDENT_SERVICES_RUNNING` (1051) when running services depend on the target. We never stop dependents. `ERROR_SERVICE_NOT_ACTIVE` (1062) means it is already stopped. The stop is asynchronous. The code polls the status until `SERVICE_STOPPED`, for at most 30 s (our choice).
- `ControlService` and `StartServiceW` "will block for 30 seconds if any service is busy handling a control code" (Learn).
- `StartServiceW` returns once the service thread is created, in `SERVICE_START_PENDING` (Learn). Restore does not wait for running. `ERROR_SERVICE_ALREADY_RUNNING` (1056) counts as success.
- Measured: `w32time` is `WIN32_SHARE_PROCESS`, start type `AUTO_START (DELAYED)`, no dependencies, 0 dependent services.
- Measured: `w32time` has two start triggers, "DOMAIN JOINED STATUS" and a "CUSTOM SYSTEM STATE CHANGE EVENT". The trigger page example also shows a not-joined stop trigger.
- Trigger start of a disabled service: not stated on the trigger page. Guess: a disabled service is not trigger-started, because a disabled service "cannot be started" (ChangeServiceConfigW). Not verified. The triggers are left untouched, so restore needs nothing for them. If the guess is wrong, the 30 s monitor sees `w32time` running and stops clock adjustment.
- Group Policy: policy values "overwrite any preexisting values in the W32Time section of the registry" (Learn, Tools and Settings). The page says nothing about policy changing the start type. Guess: a GPO "System Services" setting can set `w32time` back to automatic. The monitor covers that case.

### Takeover and restore rules

- Order: query the original state, persist the restore record, stop, disable, query again to verify. A crash between record and stop leaves a record of the true original. Restore from it is idempotent.
- A valid existing record always wins over the current state. Re-running install on a taken-over machine must not record "disabled, stopped" as the original.
- Stop refused: nothing changed. Stop timeout: the stop was sent and may still finish. The record stays so uninstall can restore. Disable fails after the stop: `w32time` is started again if it was running (rollback), and both errors are reported.
- Restore sets the recorded start type. It starts `w32time` only if it was running and the recorded start type is not `Disabled`, because a disabled service cannot be started.
- Uninstall with no record leaves `w32time` alone and says so. Guessing a start type could undo an administrator's deliberate choice. If `w32time` is disabled at that point (no record, a `Dropped` or untrusted record, an invalid record, or a missing state directory), uninstall exits 18 (`NO_RECORD_DISABLED`) instead of 0, says `w32time` is still disabled and prints the manual restore hint once (R92).
- Uninstall order (R94): stop our service, put `w32time` back, then remove our registration. When `w32time` was not put back (exit 10 or 18) the registration is kept, stopped, and the run says so. The machine then keeps our time sync rather than none. Since Task 14c-B the run also starts our service again when it stopped it at the start, and says so. A failed restart is reported with `sc.exe start ntptimeclient-winrs`.
- Uninstall does not create a missing state directory (N5). It looks first without creating anything (`symlink_metadata` on the path and its parent). Missing means no record. A missing parent folder is reported as "state directory unavailable". Install refuses on a missing parent folder with exit 6 and that text. The read-only verify variant of `secure_state_dir` is still deferred. For an existing directory, uninstall calls `secure_state_dir`, which may fix its DACL.
- Install exit 9 means registration is not built (not ready: since Task 14c-B, the Windows host adapters are missing), nothing changed. Exit 20 means the exe location is not administrators-only, nothing changed. Exit 19 means registering failed after the takeover. The text says whether `w32time` was put back (R95).
- `is_running` reports true on any query error, `NotFound` included (R85). When we cannot tell, the engine must not adjust the clock. A "not found" can also come from a broken service database.
- The rollback start after a failed disable keys on the state seen at entry, not on the record. On a re-install the record can say "was running" while `w32time` was stopped at entry (M2).
- A takeover that fails before any change (first query, record save, refused stop) removes the record this run wrote. A pre-existing record is never removed there. A failure after a change keeps the record and says to run uninstall (M8).
- No record and `w32time` already disabled: install refuses with exit 12 and changes nothing, unless `--accept-disabled-original` is given (R84). A lost record must not make "disabled" the original for ever.
- Interactive means stdin and stderr are both consoles (R83). The question goes to stderr with a newline. The answer read stops at a newline, at end of input or at 16 bytes (M11). End of input, a read error and an overlong line are a no. Under a wrapper that pipes stderr the run is silent and aborts on a domain-joined machine. The message names `--confirm-domain-joined` and the script's `-ConfirmDomainJoined`. The domain warning goes to stderr too, next to the question, so redirecting stdout cannot hide it (N6).
- The answer waits at most 120 s (`ANSWER_TIMEOUT`), then counts as no, exit 5 (R93). A console read cannot be cancelled, so the read runs on a helper thread and the main thread uses `recv_timeout`. The helper is never joined on timeout. The process exits right after. A deployment tool, a scheduled task or a hidden console must pass `--silent` or `--confirm-domain-joined`, so no question is asked.
- Monitor: every 30 s the host sends `AdjustmentAllowed(!running)`. The event is a level, so it is sent every period, not only on change. After a clock failure latch (R39) only `false` then `true` reopens adjustment. `monitor_decision` also says when the state changed, so the host logs transitions only.

### `restore.json`

- Location: `restore.json` in `Config.state_dir` (R86). Install and uninstall take the directory from the config value the caller passes, never from `current_exe` or the environment. Until Task 14 loads the config file, `main` passes `Config::default()`. Risk: a `state_dir` changed between install and uninstall points uninstall at a directory with no record. It then leaves `w32time` alone and says so (safe direction).
- The state directory is secured by `secure_state_dir` before the record is written. If it cannot be secured or the record cannot be written, install refuses and changes nothing. A stopped `w32time` with no record is worse than no install.
- Content: one of eight canonical byte strings, `{"version":1,"service":"w32time","start_type":"<t>","was_running":<b>}` and a newline. `<t>` is one of `automatic`, `automatic_delayed`, `manual`, `disabled`. The reader accepts only an exact match. A wrong version, another service name, an unknown start type, a duplicate key, extra whitespace or a truncated file are all refused. Reads stop at 512 bytes.
- Write: temp file, `sync_all`, then `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` (M1). Learn ([MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)): with write-through "The function does not return until the file is actually moved on the disk". The page then says the flag "guarantees that a move performed as a copy and delete operation is flushed". Whether a same-volume rename is also flushed is not stated in more words. Guess: yes, per the first sentence. Non-Windows builds (fuzz job only) use `std::fs::rename` and never write a record.
- Read (R86): install and uninstall both call `secure_state_dir` first and read only from the directory it verified. The file is opened through `safe_open` (no reparse follow, a symlink is refused). Before any byte is read, the open handle must show a plain file, no reparse attribute, one hard link, at most 512 bytes and an owner of SYSTEM or Administrators (`ntpc_platform::w32time::record_file_facts`, built on the existing `attribute_tag`, `link_info` and `read_security` wrappers). A `Kept` file was only checked on the fast path of `secure_state_dir`, so the read checks again. A junction at the record name fails both read and write, and nothing is written through it (M10, tested).
- Uninstall when the directory cannot be secured, the record was `Dropped`, or the file fails a check: `w32time` is left alone, exit 17 (`RECORD_NOT_TRUSTED`), or 18 if `w32time` is disabled, and a manual restore hint that names no start type. A `Dropped` record gets uninstall's own words: it may be in a sibling directory named like the state directory with `.old-` and a hex suffix (N3).
- Install exit codes per `secure_state_dir` refusal class: directory refused 6, bad configured path (bad path, trailing dot or space, reserved name, not a fixed drive) 16, `RollbackFailed` 14, `RestoreCarryFailed` 15, a `Dropped` record 13, an untrusted record file 17. A future `AclError` variant (the enum is non-exhaustive) falls into class 6. Every one of these refusals touches neither `w32time` nor the record.
- No checksum. A checksum does not stop anyone who can write the file. The defences are the secured directory, the fixed service name and the closed set of values.
- Since the Task 11 merge `restore.json` and `restore.json.tmp` are in `KNOWN_CHILDREN`, and a weak directory is replaced with `restore.json` carried over when it passes the checks (R80). The earlier note that the record blocks a re-ACL no longer applies.

## Platform: DHCP option 42 (Task 13)

Task 13 facts. "Learn" means Microsoft Learn. "Observed" means a read-only probe on the builder's Windows 11 machine (build 26300). Probes read registry value names, value kinds and option numbers only. No address, name or lease value was copied anywhere.

### Sources

- [DhcpRequestParams](https://learn.microsoft.com/en-us/windows/win32/api/dhcpcsdk/nf-dhcpcsdk-dhcprequestparams)
- [DhcpCApiInitialize](https://learn.microsoft.com/en-us/windows/win32/api/dhcpcsdk/nf-dhcpcsdk-dhcpcapiinitialize)
- [DHCP Client API Examples](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/dhcp/dhcp-client-api-examples) (archived)
- [IP_ADAPTER_ADDRESSES_LH](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh)
- [Win32_NetworkAdapterConfiguration](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkadapterconfiguration)
- [NotifyUnicastIpAddressChange](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyunicastipaddresschange)
- [CancelMibChangeNotify2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-cancelmibchangenotify2)
- RFC 2132 section 8.3: option 42 holds one or more IPv4 addresses, minimum length 4, length a multiple of 4. From training data, not re-read.

### Candidates

| Candidate | Documented | Gives option 42 | Admin | Network traffic | Observed |
| --- | --- | --- | --- | --- | --- |
| IP Helper `GetAdaptersAddresses` | yes | no. Members cover DNS, WINS, gateways and `Dhcpv4Server`. Nothing for NTP or other options | no | none | used for the adapter list |
| Registry `Tcpip\Parameters\Interfaces\{GUID}` named values | only in old KB pages | no. There is no `DhcpNTPServer` value | no | none | 14 interface keys. Named DHCP values found: `DhcpIPAddress`, `DhcpServer`, `DhcpSubnetMask`, `DhcpDefaultGateway`, `DhcpNameServer`, `DhcpDomain`, lease times and a few more. No value names NTP. |
| Registry `DhcpInterfaceOptions` (REG_BINARY) | no | only if the client asked for it | no | none | Present on 2 keys. A guessed record layout (20-byte header, data padded to 4) walks both blobs exactly. Option 42 is absent on both. |
| Registry `Dhcp\Parameters\Options\<n>` | no | no | read no, write yes | none | Keys exist for options 1, 3, 6, 15, 44, 46, 47 and 220. No key for 42. |
| DHCP client API `DhcpRequestParams` | yes, since Windows 2000 | yes, as the raw option data | not stated. Guess: no | from the cache if every option asked for is there, else a DHCPINFORM to the server (Learn remarks). May block up to 2 minutes (Learn) | NOT RUN. Option 42 is not in the cache on this machine, so a call would send an INFORM. Forbidden here. |
| WMI `Win32_NetworkAdapterConfiguration` | yes | no. DHCP properties are `DHCPEnabled`, `DHCPLeaseExpires`, `DHCPLeaseObtained`, `DHCPServer` only | no | none | not needed |
| `w32time` learning from DHCP | n/a | out of scope | n/a | n/a | not checked |

### Choice

- Method: `DhcpRequestParams` with `DHCPCAPI_REQUEST_SYNCHRONOUS`, asking for option 42 only, once per adapter that has a DHCPv4 lease. It is the only documented and supported way to get option 42. It exists since Windows 2000, so it is stable across every supported release.
- DHCP ships in version one with this method. The live read is UNVERIFIED on a real network. It was not run on the builder's machine because it may send a DHCPINFORM.
- Cost: option 42 is not in the Windows default request list (observed). So in the normal case every read sends one DHCPINFORM per leased adapter. That is an ordinary DHCP client message on the local link. The call may block up to 2 minutes. `read_lease_servers` blocks and must run on its own thread. The host reads at start, after a network change and on a long timer. It never reads in a tight loop.
- `Flags = 0` (no SYNCHRONOUS) is not described by Learn. Not used.
- Not chosen: `DhcpInterfaceOptions`. It is undocumented, the layout is a guess and option 42 is never there unless something asked for it. It stays a possible cache-only fallback for Terry to decide.
- Possible later step, for Terry: a persistent request (`DHCPCAPI_REQUEST_PERSISTENT` with a `RequestIdStr`, undone by `DhcpUndoRequestParams`) would make the client ask for 42 in every lease. Reads would then come from the cache with no INFORM. It changes system state, so it belongs to install and uninstall. Whether the cache then also records "server sent no 42" is not documented.

### Reader rules (`read_lease_servers`)

- Adapters come from `GetAdaptersAddresses(AF_INET)`. Kept: operational status up, DHCPv4 enabled, a non-zero `Dhcpv4Server` (that is "has a lease"), not loopback, not a tunnel. Virtual adapters with a lease are kept. They carry real traffic.
- Order: lowest `Ipv4Metric` first, then lowest `IfIndex`. The route the OS prefers comes first. The order is deterministic.
- An adapter with no lease is skipped before any DHCP call. So an unplugged or APIPA adapter never triggers an INFORM.
- Servers from all adapters are joined in that order, deduplicated (first wins) and capped at 16.
- `Ok(empty)` when no adapter has a lease or no lease carries option 42. `Err` only when every adapter call failed, or the adapter list or API start failed. A failed adapter next to a working one is skipped.
- The OS buffers are walked with bounds checks. Every pointer the OS returns must lie inside the buffer we passed, or the record is skipped. The adapter name must be a plain GUID string of at most 255 ASCII characters before it is widened.
- Error text holds Win32 error codes only. No address, adapter name or GUID.

### Parser rules (`parse_option42`)

- Input is the option data only (no code or length byte), as `DhcpRequestParams` returns it.
- Empty input or a length that is not a multiple of 4 gives an empty list. A malformed option must not give a half-trusted list.
- Duplicates are removed, first wins. At most 16 addresses are returned. Parsing stops there, so a huge input costs no memory.
- Address classes are NOT filtered here. The resolver (`ntpc-service` `is_usable_address`) already drops unspecified, loopback, link-local, multicast, broadcast and own addresses for every tier. DHCP servers reach it as IP literals with `Tier::Dhcp`. One layer owns the rule. A junk address still counts towards the cap of 16. The resolver caps the tier at 8 anyway.

### Watcher (`DhcpWatcher`)

- Subscription: `NotifyUnicastIpAddressChange(AF_INET)`. Read only. It fires when an IPv4 unicast address is added, removed or changed. A new or lost lease changes the address. Learn says callbacks are serialised.
- Not chosen: `NotifyAddrChange` needs an overlapped event and a cancel whose completion we would have to wait for. `RegNotifyChangeKeyValue` on the Interfaces key watches undocumented data. `DhcpRegisterParamChange` is per adapter, and adapters come and go.
- Signal: any IPv4 address change. That is the R66 "network change" that resets the resolver backoff. It is not only a lease change. The host then calls `read_lease_servers` and feeds the list to `LeaseTracker`, which says whether the DHCP servers changed.
- Gap: a renewal that keeps the address and only changes option 42 may not fire. Guess, not checked. The host's long re-read timer covers it.
- `wait(timeout)` blocks until a change, the timeout or a cancel. Bursts coalesce into one change. `WatchCanceller` wakes a blocked `wait` from another thread.
- Drop: cancels waiters, then calls `CancelMibChangeNotify2`. Learn says the cancel must not run on the callback thread, else deadlock. That only makes sense if the cancel waits for a running callback. So the context is freed after the cancel returns. Inference, not stated outright. If the cancel fails, the context is leaked on purpose (a few bytes) and never freed under a live callback. The callback only takes a short mutex and never blocks, so the cancel cannot hang on it.
- `LeaseTracker`: the first list counts as a change. The same set in another order is not a change, because the resolver keys sources by address and the reader's order is already deterministic. Any add or remove is a change. All removed is a change to empty. On a read error the host keeps the last good list. An error is not a lost lease.

## Service wrapper (Task 14c-B)

Each line names its source. "Learn" means the linked Microsoft Learn page. "Measured" means read on the builder's machine with read-only calls. "Guess" means not found in the docs.

### Sources

- [StartServiceCtrlDispatcherW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw)
- [ServiceMain (LPSERVICE_MAIN_FUNCTIONW)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nc-winsvc-lpservice_main_functionw)
- [RegisterServiceCtrlHandlerExW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-registerservicectrlhandlerexw)
- [HandlerEx (LPHANDLER_FUNCTION_EX)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nc-winsvc-lphandler_function_ex)
- [SetServiceStatus](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus)
- [SERVICE_STATUS](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status)
- [WM_POWERBROADCAST](https://learn.microsoft.com/en-us/windows/win32/power/wm-powerbroadcast)
- [CreateServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)
- [ChangeServiceConfig2W](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)
- [SERVICE_REQUIRED_PRIVILEGES_INFOW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow)
- [SERVICE_FAILURE_ACTIONSW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw)
- [SERVICE_FAILURE_ACTIONS_FLAG](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag)
- [SERVICE_SID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
- [DeleteService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice)
- [Service Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [ReportEventW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw)
- [Event Sources](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-sources)
- [eventcreate](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/eventcreate)
- [HandlerRoutine (console)](https://learn.microsoft.com/en-us/windows/console/handlerroutine)

### Dispatcher and `ServiceMain`

- The main thread calls `StartServiceCtrlDispatcherW` "within 30 seconds" of start. It "does not return until all running services in the process have entered the SERVICE_STOPPED state". The table ends with an all-null entry. For `SERVICE_WIN32_OWN_PROCESS` "the service name in the table entry is ignored" (Learn).
- Run from a console it fails with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (1063) (Learn). `service` then exits 26 with a hint to use `run`. A read-only test checks the 1063.
- The dispatcher "creates a new thread to execute the ServiceMain function" (Learn). Our `ServiceMain` runs the Rust body under `catch_unwind`. Its arguments are ignored.
- `ServiceMain` "should immediately call RegisterServiceCtrlHandlerEx", then `SetServiceStatus` (Learn). Ours registers first, reports `START_PENDING`, then loads the config and opens the Event Log.
- Learn suggests ending `ServiceMain` and finishing on a thread pool wait. Ours blocks `ServiceMain` until the host returns instead, as Learn's own sample (`SvcInit` in "Writing a ServiceMain Function") does. Guess that this is fine for an own-process service. The SCM gets reports from the handler and from `ServiceMain` either way.
- The status handle "does not have to be closed" (Learn). `SetServiceStatus` may be called "at any time from any thread" (Learn), so the handle is `Send` and `Sync`.

### Status reports

- States (Learn, `SERVICE_STATUS`): `STOPPED 1`, `START_PENDING 2`, `STOP_PENDING 3`, `RUNNING 4`. Accept flags: `ACCEPT_STOP 0x1`, `ACCEPT_SHUTDOWN 0x4`, `ACCEPT_POWEREVENT 0x40`.
- "Do not register to accept controls while the status is SERVICE_START_PENDING" (Learn). Ours accepts nothing while starting or stopping. `RUNNING` accepts STOP, SHUTDOWN and POWEREVENT.
- `dwCheckPoint` counts up during a pending state and "should be zero" otherwise. Before `dwWaitHint` passes the service must bump the checkpoint or change state (Learn). Ours bumps about once a second while stopping, for at most the stop budget, so a hung host cannot fake progress for ever.
- A service-specific code needs `dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR` (1066) and the code in `dwServiceSpecificExitCode` (Learn). A non-zero stop is logged by the SCM as event 7023 (Learn, `SetServiceStatus`).
- `SERVICE_STOPPED` is sent "one time only". "Subsequent calls can cause the process to crash", and no work may follow it (Learn). The reporter refuses a second `STOPPED` and any backwards step. The Event Log is drained (2 s at most) before it.
- Timing: start hint 30 s, stop hint 20 s, stop budget 15 s, poll 1 s. Learn gives "about 20 seconds" at system shutdown and 125 s from the Services snap-in. The budget plus one poll stays under the stop hint (tested). When the budget runs out the wrapper reports `STOPPED` with code 4 and the process ends. The next start resets the clock rate (R71).

### Control handler

- Codes (Learn): `STOP 1`, `INTERROGATE 4`, `SHUTDOWN 5`, `POWEREVENT 13`. STOP and SHUTDOWN: "must stop ... and return NO_ERROR". After them the SCM sends no other control. Unhandled: `ERROR_CALL_NOT_IMPLEMENTED` (120). `INTERROGATE`: `NO_ERROR`.
- The handler "is intended to receive notification and return immediately", must not take a lock that could block, and must return within 30 s (Learn). Ours does one status report under a short uncontended mutex, a channel send to `HostControl::shutdown` or `HostControl::wake`, and two atomics. It runs under `catch_unwind` in `win32/service.rs` and answers `NO_ERROR` if a panic is caught.
- `SERVICE_CONTROL_PRESHUTDOWN` is not used. Learn: it blocks system shutdown and should be used "only if it is absolutely necessary". The shutdown work (rate reset, drift, status) fits in the SHUTDOWN window.
- Power events (Learn, `WM_POWERBROADCAST`): `PBT_APMSUSPEND 4`, `PBT_APMRESUMESUSPEND 7`, `PBT_APMRESUMEAUTOMATIC 18`, `PBT_POWERSETTINGCHANGE 0x8013`. "The system always sends a PBT_APMRESUMEAUTOMATIC message whenever the system resumes." `RESUMESUSPEND` follows it after user input. Both call the 14c-A `ResumeNotifier` (`notify_resumed`), which debounces calls within 5 s into one `Resumed` event (R107), so the engine gets one step, not two. The handler returns `NO_ERROR` at once. A resume before the host is built is ignored.

### Registration (`registration.rs`)

- `CreateServiceW` (Learn): the manager handle needs `SC_MANAGER_CREATE_SERVICE`. "If the path contains a space, it must be quoted". A null account means LocalSystem. Errors `ERROR_SERVICE_EXISTS` (1073) and `ERROR_SERVICE_MARKED_FOR_DELETE` (1072).
- Image path: always `"<exe>" service`, quoted even without a space, so the unquoted service path weakness cannot apply. Only a plain `X:\...` path is accepted: no UNC share, no `\\?\` prefix, no quote or NUL, no trailing backslash (inside quotes it would escape the closing quote), at most 32,767 UTF-16 units. The exe path is the running exe from `current_exe`, resolved by `canonicalize` (the `\\?\` prefix is stripped for a drive path), never a path from the user.
- Settings: `SERVICE_WIN32_OWN_PROCESS`, `SERVICE_AUTO_START` plus delayed auto start, `SERVICE_ERROR_NORMAL`, no dependencies, LocalSystem. Display name and an honest description (what it does, that it replaces `w32time` while installed, that it is an unsigned preview).
- Re-install: `ERROR_SERVICE_EXISTS` leads to `ChangeServiceConfigW` with the same values, then the optional settings again. The account is passed as `LocalSystem` with an empty password. Guess: Learn for `ChangeServiceConfigW` was not re-read for the exact account spelling. VM check item.
- `ChangeServiceConfig2W` (Learn) levels used: `DESCRIPTION 1`, `FAILURE_ACTIONS 2`, `DELAYED_AUTO_START_INFO 3`, `FAILURE_ACTIONS_FLAG 4`, `SERVICE_SID_INFO 5`, `REQUIRED_PRIVILEGES_INFO 6`. The handle needs `SERVICE_CHANGE_CONFIG`, and `SERVICE_START` for a restart action (Learn).
- Failure actions: restart after 60 s, 60 s, then 5 min. "If N is greater than cActions, the service controller repeats the last action" (Learn). Reset period 1 day (guess, our choice). `fFailureActionsOnNonCrashFailures = TRUE`: actions also run when the service "enters the SERVICE_STOPPED state but the dwWin32ExitCode ... is not ERROR_SUCCESS" (Learn). So a host panic or a config error restarts too. The flag "takes effect the next time the system is started" (Learn).
- A failure after the create (a `ChangeServiceConfig2W` step or the Event Log source) deletes the service this run created and reports both errors. A service that existed before the run is left registered. Install then puts `w32time` back (exit 19, existing Task 12 path).
- `DeleteService` "marks a service for deletion". The entry goes once every handle is closed and the service is not running (Learn). `ERROR_SERVICE_MARKED_FOR_DELETE` on uninstall counts as removed. On install it refuses with advice to close the Services window or reboot.
- Stop of our own service: `ControlService(STOP)` through the Task 12 wrapper, then polls every 250 ms for at most 30 s.
- Install starts our service after registering (exit 21 when that fails, the install is kept and the text names `sc.exe start ntptimeclient-winrs`). Uninstall starts it again when it stopped it and `w32time` could not be put back (R94 concern).

### Account and privileges (R104)

- LocalSystem, cut down by `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO` to `SeSystemtimePrivilege`. Learn: "If you specify privileges for a service, the SCM will remove the privileges that are not required from the process token when the process starts." The page names no account restriction. That it works for LocalSystem is inferred from that text. VM check item: `whoami /priv` from a service process, or Process Explorer.
- The list is a multi-string, each entry NUL-terminated and one more NUL at the end (Learn). Tested.
- `SeChangeNotifyPrivilege` "is never removed from a process token ... a service need not explicitly specify this privilege" (Learn). Not listed.
- Minimum set: `SeSystemtimePrivilege` for `SetSystemTimeAdjustmentPrecise` and `SetSystemTime` (Task 11). Nothing else the wrapper or host calls needs a privilege: the state directory, the registry and the Event Log are reached through DACLs, and the token keeps its groups (SYSTEM, Administrators). Guess: the 14c-A thread priority raise needs none at normal or highest thread priority. If it uses a realtime priority class it needs `SeIncreaseBasePriorityPrivilege` added here.
- Why not LocalService: the state directory DACL grants only SYSTEM and Administrators (Task 11). A low-privilege account could not write its drift, status or restore files.
- R106: LocalSystem only. `RealScm` refuses a spec with any other account, and a re-install rewrites the account to LocalSystem.
- Service SID type: `SERVICE_SID_TYPE_NONE`. R106: NONE or UNRESTRICTED, never RESTRICTED (asserted in the fake `CreateService` tests and refused by `RealScm`). A restricted SID adds the write-restricted SID and makes the token restricted (Learn, `SERVICE_SID_INFO`), so every write would also need the state directory DACL to name `NT SERVICE\ntptimeclient-winrs`. It does not today. Decide together with a change of the state directory ACL. Not now.

### Exe location check (`install_location.rs`)

- Install refuses (exit 20, nothing changed) unless the exe, its folder and every parent up to the drive root are administrators-only. The same masks as the Task 15 wrapper (`Test-LocationOrFail`): the exe and its folder must give no one else write, append, extended-attribute write, delete child, attribute write, delete, permission or owner rights, or generic write or all. A parent must give no one else delete child, delete, permission, owner, generic write or all (so `C:\` letting users create folders is fine). Owner must be SYSTEM, Administrators or TrustedInstaller. Inherit-only and deny ACEs are skipped. A null DACL, an ACE type the code cannot read, a reparse point anywhere and a non-fixed drive are refused.
- It reuses the Task 11 read wrappers (`open_no_follow`, `attribute_tag`, `read_security`, `drive_type`). No new `unsafe`.
- Measured: `System32\cmd.exe` passes, a file in the user's temp folder fails (read-only tests).

### Event Log (`event_log.rs`)

- Source key `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\ntptimeclient-winrs` with `EventMessageFile` (`REG_SZ` or `REG_EXPAND_SZ`) and `TypesSupported` (`REG_DWORD`, "Unused") (Learn, Event Sources). A source name "cannot contain the backslash character". Without a message file "the Event Viewer cannot map any event identifiers ... and will display an error" (Learn).
- Message file: `%SystemRoot%\System32\EventCreate.exe`, `TypesSupported` 7. Measured (read only): its message table maps ids 1 to 1001 to `%1`, and sources made by `eventcreate` use this file with 7. Learn only says `eventcreate /id` takes "any number from 1 to 1000". So the trick is undocumented: a guess that it keeps working. If not, the text still travels as the insertion string.
- Ids: 1 information, 2 warning, 3 error, 10 the wrapper's own lines. Debug lines never go to the Event Log.
- `ReportEventW` (Learn): types `ERROR 1`, `WARNING 2`, `INFORMATION 4`. "Each string is limited to 31,839 characters". "%n" in a string "is treated as an insertion string". Ours caps at 2,048 characters, escapes control characters again and writes `%` as `\u{25}`.
- The logger never waits on the Event Log: a 256-line queue and one writer thread. A full queue drops and counts. A failed write is counted. Neither stops the service.
- Install registers the source after the service. Uninstall removes it after the service, also when the service was already gone. A source key this run created is removed again if writing it fails.

### Config file and state

- Config: `config.toml` in the folder of the running exe. `install`, `uninstall` and `service` always use it, so they agree on `state_dir`. `run` and `status` take `--config <path>`. A missing file means the defaults. A file that exists but cannot be read or breaks a rule is an error (exit 25, service code 1), never the defaults. Read through `safe_open` (no link followed, a link refused) and capped at 64 KiB by `Config::load`. Errors in the Event Log carry no path.
- Why there: install already refuses an exe folder that non-administrators can change, so the config adds no new place to protect. The state directory cannot hold it (unknown children are refused, R68). A new folder under `ProgramData` would be a new trust root that any user could create first.
- The wrapper writes nothing in the exe folder. The service writes only in the state directory (host) and the Event Log.
- `status` reads `status.json` from the configured state directory. The DACL stays SYSTEM and Administrators only (14a review D4), so `status` needs an elevated prompt. Access denied is its own exit code (24).

### Panic policy

- No `[profile]` section in any `Cargo.toml` of the workspace or `fuzz/`, so `panic = "unwind"` holds in every profile. The host's `catch_unwind` (14a) and every FFI callback here rely on it.

### Exit codes

Process exit codes. `cli::exit` (install and uninstall) and `app::exit` (the rest). None is in 40 to 47, the Task 15 wrapper's own codes (tested).

| Code | Meaning |
|---|---|
| 0 | Done |
| 2 | Usage: no command, unknown command or argument |
| 3 | Not elevated |
| 4 | Domain joined, silent, no `--confirm-domain-joined` |
| 5 | User answered no |
| 6 | State directory or record could not be secured, read, written or removed |
| 7 | `restore.json` not valid |
| 8 | `w32time` takeover failed |
| 9 | Not ready: the host adapters are not built into this exe. Nothing changed |
| 10 | Uninstall could not restore `w32time` |
| 11 | Uninstall could not stop or remove our service |
| 12 | No record and `w32time` already disabled |
| 13 | Earlier restore record dropped to quarantine |
| 14 | `RollbackFailed` |
| 15 | Restore record carry failed |
| 16 | Bad `state_dir` path |
| 17 | Directory or record not trusted |
| 18 | Uninstall: no usable record and `w32time` disabled |
| 19 | Registering failed after the takeover |
| 20 | Exe location not administrators-only. Nothing changed |
| 21 | Installed, but our service did not start |
| 22 | `status`: no `status.json` |
| 23 | `status`: `status.json` not valid or unreadable |
| 24 | `status`: access denied, run elevated |
| 25 | Config file unreadable or invalid |
| 26 | `service` run by hand, not by the SCM |
| 27 | `run`: host adapters not built |
| 28 | `run`: the host ended with an error |
| 29 | `service`: dispatcher failed |
| 30 | `run`: our service is running, or its state cannot be read |

Service-specific exit codes (`dwServiceSpecificExitCode`, with `dwWin32ExitCode` 1066): 1 config, 2 host adapters not built, 3 host panicked, 4 stop timed out, 5 host ended unasked, 6 host thread not started, 7 building the adapters failed. 0 is a normal stop.

### Coupling with Task 14c-A

- The wrapper takes the host through `service::DepsLauncher`, one function that, on the host thread, calls `windows_deps(&cfg, sinks)` (never an empty sink list: the Event Log sink in service mode, a console sink for `run`), hands `control` and `resume` to the control handler slot through the `started` callback, and runs `host::run` on the same thread (`HostDeps` is not `Send`). `RUNNING` is reported only after the slot is filled. A STOP before that sets a flag that `started` checks, and the host is not run. A `windows_deps` error (clock, account or owner refusal) stops with service code 7 and an Event Log error.
- Deviation: the host runs on a dedicated `ntpc-host` thread, not on the `ServiceMain` thread, so `ServiceMain` can bound the stop wait. Build and run are on that one thread. `app/real.rs` has one `launcher()` function that returns `DepsLauncher::pending()` until the adapters merge. While pending, install refuses with exit 9 and `run` and `service` stop with "host not built" (27, service code 2), so no machine loses `w32time` to a service that cannot run.
- The file log sink and its names in `KNOWN_CHILDREN` are 14c-A's (R100). The service logger is the Event Log only until then.
