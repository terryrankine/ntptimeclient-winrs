# Preview hand test on a throwaway VM

> **THROWAWAY VM ONLY. NEVER THE HOST.**
> This installs a service, stops `w32time` and changes the system clock.
> Run it only inside a VM that has a snapshot you can revert to.
> Do not run any command below on your own machine.

Status: NOT RUN. This is the procedure for the owner. The packaging author did not run any of it.

This tests the UNSIGNED PREVIEW zip. Items marked (unverified) are guesses about the exe. Task 12 and Task 14 own the real behaviour. Write down what you actually see.

## Guard

Paste this into the elevated PowerShell in the VM first. Call `Assert-ThrowawayVm` before every destructive step below. It stops if the machine does not report itself as virtual. It is a read-only check and a heuristic, not proof. The snapshot is still your safety net.

```powershell
function Assert-ThrowawayVm {
  $m = (Get-CimInstance Win32_ComputerSystem).Model
  if ($m -notmatch 'Virtual|VMware|KVM|Hyper-V') { throw "STOP. Model is '$m'. This is not a VM." }
  "ok: model is '$m'"
}
Assert-ThrowawayVm
```

## 0. Set up the VM

1. Create a Windows 10 or 11 VM. Use a workgroup machine for the main run.
2. Turn off hypervisor time sync. The preview has no VM detection. Two time sources will fight.
   - Hyper-V, run on the HOST (this is the only host-side command in this document): `Disable-VMIntegrationService -VMName <name> -Name 'Time Synchronization'`
   - Other hypervisors: switch off the guest time sync option in the tools settings.
3. Check the VM has outbound UDP 123 to the internet.
4. Take a snapshot named `before-preview`.
5. Copy the zip into the VM. Compare the hash with the `.sha256` file from the release. This proves the transfer only. The hash file comes from the same place as the zip, so it does not prove the zip is genuine.
   `Get-FileHash .\ntptimeclient-winrs-*-UNSIGNED-PREVIEW-x86_64-windows.zip -Algorithm SHA256`
6. Create a folder that only administrators can write, from the elevated shell, and extract the whole zip there. Do not run from Downloads.
   ```powershell
   New-Item -ItemType Directory 'C:\Program Files\ntptimeclient-preview' | Out-Null
   Expand-Archive .\ntptimeclient-winrs-*-UNSIGNED-PREVIEW-x86_64-windows.zip -DestinationPath 'C:\Program Files\ntptimeclient-preview'
   icacls.exe 'C:\Program Files\ntptimeclient-preview'
   ```
   Open the extracted folder in the elevated shell. Expect no `Users` or `Authenticated Users` entry with write rights.
7. Expect SmartScreen, Smart App Control or antivirus to warn or block (unverified). Write down what it says and does.

All scripts are run as below. This changes the execution policy for that one process only. It does not change the machine policy.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -AcceptPreviewRisk
```

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

Run each. Each must exit non-zero and print REFUSED. After each, repeat `sc.exe qc w32time` and confirm nothing changed.

1. No risk switch: `.\install.ps1`. Expect exit 40. Check the message shows the `-ExecutionPolicy Bypass` form.
2. Non-elevated shell: run `.\install.ps1 -AcceptPreviewRisk` from a normal user shell. Expect exit 41.
3. Dry run in an elevated shell: add `-WhatIf`. Expect the checks, the rollback line, and "WhatIf: nothing was run". No change.
4. Declined: add `-Confirm` and answer No. Expect "Declined", exit 45, not "WhatIf". No change.
5. Damage check. Copy the extracted folder to another place the same way (admin-only folder). Append one byte to the copy's `ntptimeclient-winrs.exe`. Run `.\install.ps1 -AcceptPreviewRisk` from the copy. Expect exit 43 and no change. This proves the accidental-damage check only. Do the same to `preview-common.ps1` and expect exit 43.
6. Writable folder. Extract a copy into `C:\Users\Public\x` or Downloads. Run from there. Expect REFUSED and exit 44, with the offending principal listed.

## 3. Install

```powershell
Assert-ThrowawayVm
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -AcceptPreviewRisk
echo $LASTEXITCODE
```

Expect exit 0. If the exe is still a stub the script exits 46 and says the machine does not look installed. That is correct behaviour. Stop and tell the author.

Read the "State before the install" block and the rollback line. Check it matches step 1. Then check, read only:

```powershell
sc.exe qc w32time
sc.exe query w32time
Get-CimInstance Win32_Service -Filter "Name='w32time'" | Select-Object Name, StartMode, State
sc.exe qc ntptimeclient-winrs
sc.exe query ntptimeclient-winrs
Get-ChildItem C:\ProgramData\ntptimeclient-winrs -Force -Recurse
icacls.exe C:\ProgramData\ntptimeclient-winrs
```

Pass when:
- `w32time` is STOPPED and its start type is DISABLED.
- `ntptimeclient-winrs` exists and is RUNNING (unverified: the exe may leave it stopped. If so start it with `Start-Service ntptimeclient-winrs` and note it).
- `BINARY_PATH_NAME` from `sc.exe qc ntptimeclient-winrs` is a known path. Run `icacls.exe` on its folder. Only SYSTEM, Administrators and TrustedInstaller may write there. A user-writable path here lets a user become SYSTEM. Fail the test if it is.
- `SERVICE_START_NAME` is recorded. Write down the account. It should be the account the design says (Task 12 and 14, not decided).
- The state directory exists and only SYSTEM and Administrators can write.
- `restore.json` exists in the state directory (unverified name, from the plan). Copy it somewhere safe. It must hold the ORIGINAL w32time start type from step 1.

Reboot the VM now. After the reboot check: `sc.exe query ntptimeclient-winrs`, `sc.exe query w32time` (still stopped and disabled), and that the clock is still disciplined.

## 4. Run for ten minutes

1. Wait ten minutes. Do not touch the clock.
2. Read the status and log (paths unverified, look in the state directory):
   `Get-Content C:\ProgramData\ntptimeclient-winrs\status.json`
   `.\ntptimeclient-winrs.exe status` (unverified subcommand, from the plan)
3. Confirm `w32time` is still stopped: `sc.exe query w32time`.
4. Offset check against the reference. There is no `scripts/measure-offset.ps1` yet. Task 16 plans a PowerShell loop around `w32tm /stripchart`. Until it exists, run:
   `w32tm.exe /stripchart /computer:time.cloudflare.com /samples:10 /period:5 /dataonly`
5. Record the offsets. The preview promises no accuracy. Write down the numbers and whether they are stable.
6. Optional disturbance test. This changes the VM clock.
   ```powershell
   Assert-ThrowawayVm
   Set-Date (Get-Date).AddSeconds(2)
   ```
   Wait. Record whether the service steps or slews it back and how long it took.

## 5. Event Log

Source names for the service are unverified. List what is there:

```powershell
$since = (Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $since } |
  Where-Object { $_.Message -match 'ntptimeclient|Windows Time' } | Format-List TimeCreated, Id, Message
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $since } -ErrorAction SilentlyContinue |
  Where-Object { $_.ProviderName -match 'ntptimeclient' -or $_.Message -match 'ntptimeclient' } | Format-List TimeCreated, ProviderName, Id, Message
```

Expect Service Control Manager entries for the install (event 7045), the `w32time` start type change (7040) and the state changes (7036). Those ids are from memory. Record what you see. Check the service log file for the join state and active config lines. Check no entry contains a secret or a full config dump.

## 6. Uninstall

```powershell
Assert-ThrowawayVm
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1
echo $LASTEXITCODE
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
2. `Assert-ThrowawayVm`, then `sc.exe config w32time start= delayed-auto`. Check the registry shows `Start` 2 and `DelayedAutostart` 1.
3. Install. The script must print `sc.exe config w32time start= delayed-auto`.
4. Uninstall. Check `Start` 2 and `DelayedAutostart` 1 again.

## 8. Domain-joined case

Use a separate VM or a copy of the snapshot joined to a lab domain. Do not use a real domain.

1. Revert to `before-preview`. Join the lab domain. Confirm `(Get-CimInstance Win32_ComputerSystem).PartOfDomain` is True. Record `sc.exe qc w32time`.
2. Silent run: `.\install.ps1 -AcceptPreviewRisk` from a non-interactive context (for example a scheduled task or `psexec -s`, lab only). Per the design (spec line 186) a silent install aborts without the switch. An interactive install warns and asks. Task 12 owns the exact behaviour. Record what you see for both. Confirm w32time and services are unchanged after an abort.
3. Run with `-ConfirmDomainJoined`. Expect the install to go ahead. Check as in step 3. Note the effect on domain time (`w32tm /query /source` before and after).
4. Uninstall and check as in step 6.
5. Entra (Azure AD) and hybrid join are not detected. Do not test them. The README says so.

## 9. Failed-install rollback check

The goal is to prove the printed manual rollback works. Run each on a reverted snapshot.

1. Second install. Install, copy `restore.json`, then run `.\install.ps1 -AcceptPreviewRisk` again. Record the exit code. Then compare `restore.json` with the copy. The ORIGINAL start type from step 1 must still be there. If it now says Disabled, the second install overwrote the original. That is a bug to report. If the exit is non-zero, check the manual rollback text is shown.
2. Manual rollback for real. After a successful install, do NOT run `uninstall.ps1`. Type the commands printed by the script by hand. Use the line that `install.ps1` printed before the exe ran.
   ```powershell
   Assert-ThrowawayVm
   sc.exe stop ntptimeclient-winrs
   sc.exe delete ntptimeclient-winrs
   sc.exe config w32time start= <the printed keyword>
   sc.exe start w32time
   w32tm.exe /resync
   ```
   Check `sc.exe qc w32time` and the registry values match step 1 and no service is left. If a command fails, record it. The printed text needs fixing. Restart the VM, as the text says the clock rate may stay non-nominal until then.
3. Kill test. After an install, end the service process hard.
   ```powershell
   Assert-ThrowawayVm
   Stop-Process -Name ntptimeclient-winrs -Force
   ```
   Wait. Record whether the service restarts and whether the clock rate was reset (Review Focus 7 in the plan). Then uninstall.
4. Any non-zero exit from the exe: stop, run the step 1 checks, and write down what state the machine was left in before you do anything else.

## 10. Record the result

Revert to `before-preview` when done. Write down per step: pass or fail, what you saw, any message that was unclear. Attach the output of the step 1, 3, 5 and 6 commands. Do not claim accuracy from one ten-minute run.
