# Preview hand test on a throwaway VM

> **THROWAWAY VM ONLY. NEVER THE HOST.**
> This installs a service, stops `w32time` and changes the system clock.
> Run it only inside a VM that has a snapshot you can revert to.
> Do not run any command below on your own machine.

Status: NOT RUN. This is the procedure for the owner. The packaging author did not run any of it.

This tests the UNSIGNED PREVIEW zip. Items marked (unverified) are guesses. The exe and the design notes own the real behaviour. Write down what you actually see.

Names used below: binary `ntptimeclient-winrs.exe`, service `ntptimeclient-winrs`, record `restore.json` and `status.json` in `C:\ProgramData\ntptimeclient-winrs`, config `config.toml` next to the exe.

## Guard

A guard on its own line can be skipped by a paste that carries on after an error. So every destructive command below is wrapped like this: `Invoke-OnVm { ... }`. The block does not run unless the guard passes, because the guard throws before it. Paste this once, first.

It needs two signals that the machine is virtual: the computer model, and the BIOS strings. It is a read-only check and a heuristic. It can refuse a real VM with odd strings. It is not proof, so the snapshot is still your safety net. If it refuses a VM you know is a VM, stop and tell the author. Do not edit the guard to get past it.

```powershell
function Invoke-OnVm {
  param([Parameter(Mandatory)][scriptblock]$Block)
  $cs = Get-CimInstance Win32_ComputerSystem
  $bios = Get-CimInstance Win32_BIOS
  $biosText = (@($bios.Manufacturer, $bios.SMBIOSBIOSVersion, $bios.Version, $bios.SerialNumber) -join ' ')
  $sig1 = $cs.Model -match 'Virtual|VMware|KVM|Hyper-V|QEMU'
  $sig2 = $biosText -match 'Hyper-V|VMware|Virtual|innotek|QEMU|Xen|SeaBIOS|Parallels|Amazon EC2|Google'
  if (-not ($sig1 -and $sig2)) { throw "STOP. Not a VM by two signals. Model='$($cs.Model)' BIOS='$biosText'. Nothing was run." }
  & $Block
}
Invoke-OnVm { 'ok: this looks like a VM' }
```

Steps 2, 3, 4 (disturbance), 6, 7, 8 and 9 contain commands in `Invoke-OnVm { }`. Run each destructive command only that way.

## 0. Set up the VM

1. Create a Windows 10 or 11 VM. Use a workgroup machine for the main run.
2. Turn off hypervisor time sync. The preview has no VM detection. Two time sources will fight.
   - Hyper-V, run on the HOST (this is the only host-side command in this document): `Disable-VMIntegrationService -VMName <name> -Name 'Time Synchronization'`
   - Other hypervisors: switch off the guest time sync option in the tools settings.
3. Check the VM has outbound UDP 123 to the internet.
4. Take a snapshot named `before-preview`.
5. Copy the zip into the VM. Compare the hash with the `.sha256` file from the release. This proves the transfer only. The hash file comes from the same place as the zip, so it does not prove the zip is genuine.
   `Get-FileHash .\ntptimeclient-winrs-*-UNSIGNED-PREVIEW-x86_64-windows.zip -Algorithm SHA256`
6. Create a new folder that only administrators can write, from the elevated shell, and extract the whole zip there.
   ```powershell
   New-Item -ItemType Directory 'C:\Program Files\ntptimeclient-preview' | Out-Null
   Expand-Archive .\ntptimeclient-winrs-*-UNSIGNED-PREVIEW-x86_64-windows.zip -DestinationPath 'C:\Program Files\ntptimeclient-preview'
   Get-ChildItem 'C:\Program Files\ntptimeclient-preview' -Force | ForEach-Object { '{0}  {1}' -f (Get-Acl $_.FullName).Owner, $_.Name }
   icacls.exe 'C:\Program Files\ntptimeclient-preview'
   ```
   The extracted folder ends up inside a folder that `Expand-Archive` created. If the zip has a top level folder, move to it. **Ownership case:** read the Owner column. Files created by an elevated shell should be owned by `BUILTIN\Administrators`. Write down what you see. If any file is owned by your user, the checks will refuse (exit 44 from the script, 20 from the exe). Record that as a finding about the extraction route. Expect no `Users` or `Authenticated Users` entry with write rights.
   Open the extracted folder in the elevated shell. All commands below run from there.
7. Expect SmartScreen, Smart App Control or antivirus to warn or block (unverified). Write down what it says and does. If the exe is blocked, `install.ps1` must exit 48 with "the exe did not run", print no rollback text, and change nothing. Check that with `sc.exe qc w32time` after.

All scripts are run as below. This changes the execution policy for that one process only. It does not change the machine policy. If a Group Policy sets the policy, `Get-ExecutionPolicy -List` shows a MachinePolicy or UserPolicy entry and the script will not run. Do not change the policy. Record it.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -AcceptPreviewRisk
```

## Exit codes

The scripts use 40 to 48. The exe uses 0 to 33. They never overlap. Full table: `README-PREVIEW.txt` in the zip.

| Code | Who | Meaning |
| --- | --- | --- |
| 40 | script | `-AcceptPreviewRisk` missing |
| 41 | script | not elevated |
| 42 | script | exe missing |
| 43 | script | hash mismatch (exe or helper) |
| 44 | script | folder not safe |
| 45 | script | answered No |
| 46 | script | exit 0 but not installed |
| 47 | script | uninstall exit 0 but service remains or unreadable |
| 48 | script | exe would not start. Nothing changed |
| 2 to 7, 12, 13, 16, 20, 31, 33 | exe | nothing changed |
| 8, 10, 11, 14, 15, 17, 18 | exe | something may have changed |
| 9, 19, 21 | exe | read the exe text. 21 means started failed, w32time put back, service set to manual |

## 1. Record the original state (read only)

Save the output. You need it in step 6.

```powershell
sc.exe qc w32time
sc.exe query w32time
Get-CimInstance Win32_Service -Filter "Name='w32time'" | Select-Object Name, StartMode, State
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\W32Time | Select-Object Start, DelayedAutostart
sc.exe qtriggerinfo w32time
(Get-CimInstance Win32_ComputerSystem).PartOfDomain
Get-Service ntptimeclient-winrs -ErrorAction SilentlyContinue
Test-Path C:\ProgramData\ntptimeclient-winrs
w32tm.exe /query /configuration
```

The registry `Start` and `DelayedAutostart` values are what `install.ps1` maps to the `sc.exe` keyword. Expect no `ntptimeclient-winrs` service and no state directory. Take a reference clock reading:

```powershell
w32tm.exe /stripchart /computer:time.cloudflare.com /samples:5 /dataonly
```

Use a reference that differs from the one the service uses (the pool). `w32tm /stripchart` works with the service stopped (unverified).

## 2. Refusal checks (nothing should change)

Each must exit with the code shown. After each, repeat `sc.exe qc w32time` and confirm nothing changed. Steps that run the install wrapper go inside `Invoke-OnVm { }` so a mis-paste on a real machine stops.

1. No risk switch: `Invoke-OnVm { powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 }`. Expect exit 40. The message shows the `-ExecutionPolicy Bypass` form.
2. Non-elevated shell: from a normal user shell run `.\install.ps1 -AcceptPreviewRisk` (same command form). Expect exit 41. The guard still goes first: `Invoke-OnVm { ... }`.
3. Dry run in an elevated shell: `Invoke-OnVm { powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -AcceptPreviewRisk -WhatIf }`. Expect the checks, the rollback line, and "WhatIf: nothing was run". No change.
4. Declined: add `-Confirm` and answer No. Expect "Declined", exit 45, not "WhatIf". No change.
5. Damage check. Copy the extracted folder to a second new admin-only folder the same way. Append one byte to the copy's `ntptimeclient-winrs.exe`. Run `install.ps1 -AcceptPreviewRisk` from the copy. Expect exit 43 and no change. This proves the accidental-damage check only. Do the same to `preview-common.ps1` and expect exit 43.
6. Writable folder. Extract a copy into `C:\Users\Public\x` or Downloads. Run from there. Expect REFUSED and exit 44 from the script with the offending principal or owner listed. This is the script's own check. Then try to defeat the script check to see the exe's: on a copy in an admin-only folder, run the exe directly: `Invoke-OnVm { .\ntptimeclient-winrs.exe install }` from the Downloads copy. Expect exit 20 and no change.
7. Loose file. In a good admin-only copy, add a stray file (`Set-Content .\stray.txt x`) and a subfolder (`New-Item -ItemType Directory sub`). Run the install each time. Expect refusal from the script (44) and, if you run the exe directly, exit 20. Remove them afterwards.
8. Hard link and junction in the folder: `Invoke-OnVm { cmd.exe /c mklink /H hard.txt LICENSE-MIT }`, expect exit 44 and exit 20 from the exe. Remove `hard.txt`. Then repeat with a junction (`mklink /J link C:\Windows`), remove it.
9. Domain joined: see step 8.

## 3. Install

```powershell
Invoke-OnVm { powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -AcceptPreviewRisk; "exit $LASTEXITCODE" }
```

Expect exit 0. If it prints exit 46 the machine does not look installed. That is the wrapper catching a stub or a failure. Stop and tell the author. For exit 12 read the message. Only pass `-AcceptDisabledOriginal` if w32time really was disabled before you started. Exit 21 (started failed) is a result to record: w32time must be back and our service set to manual.

Read the "State before the install" block and the rollback line. Check it matches step 1. Then check, read only:

```powershell
sc.exe qc w32time
sc.exe query w32time
Get-CimInstance Win32_Service -Filter "Name='w32time'" | Select-Object Name, StartMode, State
sc.exe qc ntptimeclient-winrs
sc.exe query ntptimeclient-winrs
sc.exe qfailure ntptimeclient-winrs
sc.exe qprivs ntptimeclient-winrs
Get-ChildItem C:\ProgramData\ntptimeclient-winrs -Force -Recurse
icacls.exe C:\ProgramData\ntptimeclient-winrs
.\ntptimeclient-winrs.exe status
```

Pass when:
- `w32time` is STOPPED and its start type is DISABLED.
- `ntptimeclient-winrs` exists, is RUNNING, and `START_TYPE` is `AUTO_START (DELAYED)`.
- `SERVICE_START_NAME` is `LocalSystem`. Anything else is a fail.
- `sc.exe qprivs` lists only the privileges the design says (`SeSystemtimePrivilege` and the minimum for a service). Record the list. A broad list is a finding (unverified: the design reads the privilege names from documentation).
- `sc.exe qfailure` shows restart actions (60 s, 60 s, 5 minutes).
- `BINARY_PATH_NAME` is the quoted exe path in your admin-only folder, followed by `service`. Run `icacls.exe` on its folder. Only SYSTEM, Administrators and TrustedInstaller may write there. A user-writable path here lets a user become SYSTEM. Fail the test if it is.
- The Event Log source exists (step 5).
- The state directory exists and only SYSTEM and Administrators can write.
- `restore.json` exists in the state directory. Copy it somewhere safe. It must hold the ORIGINAL w32time start type from step 1.
- Nothing else was written: no `config.toml` was created, no other service, scheduled task or firewall rule (compare with the step 1 state).

Reboot the VM now. After the reboot check: `sc.exe query ntptimeclient-winrs`, `sc.exe query w32time` (still stopped and disabled), and that the clock is still disciplined.

### Config file test

1. Copy the reference config to the real name from the elevated shell: `Copy-Item .\default-config.toml .\config.toml`. The folder must stay admin-only. Check the owner of `config.toml` is Administrators.
2. `Invoke-OnVm { Restart-Service ntptimeclient-winrs }`. Check `.\ntptimeclient-winrs.exe status`.
3. Make the config user-writable: `Invoke-OnVm { icacls.exe .\config.toml /grant 'BUILTIN\Users:(M)' }`. Restart the service. Expect it to refuse to start (service code 10, Event Log). Then `Invoke-OnVm { icacls.exe .\config.toml /remove 'BUILTIN\Users' }` and confirm it starts again.
4. A bad config makes the service fail and restart every 5 minutes. Put a bad key in, record that, then restore the file.

## 4. Run for ten minutes

1. Wait ten minutes. Do not touch the clock.
2. Read the status: `.\ntptimeclient-winrs.exe status` and `Get-Content C:\ProgramData\ntptimeclient-winrs\status.json`. Read the log in the state directory.
3. Confirm `w32time` is still stopped: `sc.exe query w32time`.
4. Offset check against the reference. The measuring scripts are in `scripts\` (see `docs\measuring.md`). Or run:
   `w32tm.exe /stripchart /computer:time.cloudflare.com /samples:10 /period:5 /dataonly`
5. Record the offsets. The preview promises no accuracy. Write down the numbers and whether they are stable.
6. Optional disturbance test. This changes the VM clock.
   ```powershell
   Invoke-OnVm { Set-Date (Get-Date).AddSeconds(2) }
   ```
   Wait. Record whether the service steps or slews it back and how long it took.

## 5. Event Log

List what is there:

```powershell
$since = (Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $since } |
  Where-Object { $_.Message -match 'ntptimeclient|Windows Time' } | Format-List TimeCreated, Id, Message
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $since } -ErrorAction SilentlyContinue |
  Where-Object { $_.ProviderName -match 'ntptimeclient' -or $_.Message -match 'ntptimeclient' } | Format-List TimeCreated, ProviderName, Id, Message
```

Expect Service Control Manager entries for the install (event 7045), the `w32time` start type change (7040) and the state changes (7036). Those ids are from memory. Record what you see. Check the service log for the join state and the active config. Check no entry contains a secret or a full config dump. After the uninstall, check whether the event source is removed or left (unverified: record it).

## 6. Uninstall

```powershell
Invoke-OnVm { powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1; "exit $LASTEXITCODE" }
```

Expect exit 0. The script prints the real state and says to verify w32time against your record. Then check, read only:

```powershell
sc.exe qc w32time
sc.exe query w32time
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\W32Time | Select-Object Start, DelayedAutostart
Get-Service ntptimeclient-winrs -ErrorAction SilentlyContinue
Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\ntptimeclient-winrs
Get-ChildItem C:\ProgramData\ntptimeclient-winrs -Force -Recurse
Get-Process ntptimeclient-winrs -ErrorAction SilentlyContinue
```

Pass when:
- `w32time` `Start` and `DelayedAutostart` equal the ORIGINAL values from step 1. Not just "something that works".
- No `ntptimeclient-winrs` service. No registry key. No running process.
- The only files left are in the state directory. Note which ones.
- The clock still runs: `w32tm.exe /stripchart /computer:time.cloudflare.com /samples:3 /dataonly`.

Reboot the VM again. After the reboot confirm `w32time` is in the original state (running or not, as step 1 says) and the service is still gone.

## 7. Delayed-auto original

The CIM start mode cannot show delayed-auto. This step proves the registry mapping.

1. Revert to `before-preview`.
2. `Invoke-OnVm { sc.exe config w32time start= delayed-auto }`. Check the registry shows `Start` 2 and `DelayedAutostart` 1.
3. Install. The script must print `sc.exe config w32time start= delayed-auto` as the rollback line.
4. Uninstall. Check `Start` 2 and `DelayedAutostart` 1 again.
5. Revert, then set `Invoke-OnVm { sc.exe config w32time start= disabled }`. Run the install. Expect exit 12 from the exe, the message about `-AcceptDisabledOriginal`, and a printed WARNING instead of a restore line. Nothing changed. Do not pass the switch unless you want to test that case. If you do, uninstall must then give the "disabled" outcome the exe's text describes.

## 8. Domain-joined case

Use a separate VM or a copy of the snapshot joined to a lab domain. Do not use a real domain. Every command below goes in `Invoke-OnVm { }`.

1. Revert to `before-preview`. Join the lab domain. Confirm `(Get-CimInstance Win32_ComputerSystem).PartOfDomain` is True. Record `sc.exe qc w32time`.
2. Run the install without the switch: `Invoke-OnVm { powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -AcceptPreviewRisk; "exit $LASTEXITCODE" }`. The wrapper pipes the exe's output, so the exe is not interactive. Per the design it aborts with exit 4 and tells you to re-run with the switch. Record what you see. Confirm w32time and services are unchanged.
   Direct run for comparison: `Invoke-OnVm { .\ntptimeclient-winrs.exe install }` from the console. This is interactive. It should warn and ask. Answer No (exit 5) and confirm no change. Do not answer Yes unless you mean to test it.
3. Run with `-ConfirmDomainJoined`. Expect the install to go ahead. Check as in step 3. Note the effect on domain time (`w32tm /query /source` before and after).
4. Uninstall and check as in step 6.
5. Entra (Azure AD) and hybrid join are not detected. Do not test them. The README says so.

## 9. Failed-install rollback check

The goal is to prove the printed manual rollback works. Run each on a reverted snapshot. Every command that changes things goes in `Invoke-OnVm { }`.

1. Second install. Install, copy `restore.json`, then run the install again. Record the exit code. Then compare `restore.json` with the copy. The ORIGINAL start type from step 1 must still be there. If it now says Disabled, the second install overwrote the original. That is a bug to report. If the exit is non-zero, check the message matches the class in the exit code table.
2. Manual rollback for real. After a successful install, do NOT run `uninstall.ps1`. Type the commands printed by the script by hand. Use the line that `install.ps1` printed before the exe ran.
   ```powershell
   Invoke-OnVm {
     sc.exe stop ntptimeclient-winrs
     sc.exe delete ntptimeclient-winrs
     sc.exe config w32time start= <the printed keyword>
     sc.exe start w32time
     w32tm.exe /resync
   }
   ```
   Check `sc.exe qc w32time` and the registry values match step 1 and no service is left. If a command fails, record it. The printed text needs fixing. Restart the VM, as the text says the clock rate may stay non-nominal until then.
3. Start failure (exit 21). Make the service unable to start in a way you can undo, for example run the install with a bad `config.toml` already in the folder (a syntax error). Expect the install to report exit 21, w32time back, and our service on manual start (`sc.exe qc` shows DEMAND_START). Fix the config. Re-run the install and check it sets auto start (delayed) again.
4. Kill test. After an install:
   ```powershell
   Invoke-OnVm { Stop-Process -Name ntptimeclient-winrs -Force }
   ```
   Wait. Record whether the service restarts and whether the clock rate was reset. Then uninstall.
5. Any non-zero exit from the exe: stop, run the step 1 checks, and write down what state the machine was left in before you do anything else.

## 10. Record the result

Revert to `before-preview` when done. Write down per step: pass or fail, what you saw, any message that was unclear. Attach the output of the step 1, 3, 5 and 6 commands. Do not claim accuracy from one ten-minute run.
