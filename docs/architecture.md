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
