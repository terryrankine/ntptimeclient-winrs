# Preview hand test on a throwaway VM

Status: NOT RUN. This is the procedure for the owner. The packaging author did not run any of it.

This tests the UNSIGNED PREVIEW zip. It installs a service, stops `w32time` and changes the clock. Do it only on a throwaway VM with a snapshot.

Items marked (unverified) are guesses about the exe. Task 12 and Task 14 own the real behaviour. Write down what you actually see.

## 0. Set up the VM

1. Create a Windows 10 or 11 VM. Use a workgroup machine for the main run.
2. Turn off hypervisor time sync. The preview has no VM detection. Two time sources will fight.
   - Hyper-V, from the host: `Disable-VMIntegrationService -VMName <name> -Name 'Time Synchronization'`
   - Other hypervisors: switch off the guest time sync option in the tools settings.
3. Check the VM has outbound UDP 123 to the internet.
4. Take a snapshot named `before-preview`.
5. Copy the zip into the VM. Compare the hash with the `.sha256` file from the release:
   `Get-FileHash .\ntptimeclient-winrs-*-UNSIGNED-PREVIEW-x86_64-windows.zip -Algorithm SHA256`
6. Extract the whole zip. Open an elevated PowerShell in the extracted folder.
7. Expect SmartScreen to warn on the download or the exe. Write down what it says and does (unverified).

## 1. Record the original state (read only)

Save the output. You need it in step 6.

```powershell
sc.exe qc w32time
sc.exe query w32time
Get-CimInstance Win32_Service -Filter "Name='w32time'" | Select-Object Name, StartMode, State
(Get-CimInstance Win32_ComputerSystem).PartOfDomain
Get-Service ntptimeclient-winrs -ErrorAction SilentlyContinue
Test-Path C:\ProgramData\ntptimeclient-winrs
w32tm.exe /query /configuration
```

Expect `PartOfDomain` False, no `ntptimeclient-winrs` service, no state directory.

Take a reference clock reading, run from any shell:

```powershell
w32tm.exe /stripchart /computer:time.cloudflare.com /samples:5 /dataonly
```

Use a reference that differs from the one the service uses (the pool). `w32tm /stripchart` works with the service stopped (unverified).

## 2. Refusal checks (nothing should change)

Run each. Each must exit non-zero and print REFUSED. After each, repeat `sc.exe qc w32time` and confirm nothing changed.

1. Run without the risk switch: `.\install.ps1`. Expect exit 40.
2. Run from a non-elevated shell: `.\install.ps1 -AcceptPreviewRisk`. Expect exit 41.
3. Dry run in an elevated shell: `.\install.ps1 -AcceptPreviewRisk -WhatIf`. Expect the checks and "nothing was run". Expect no change.
4. Damage check. Copy the extracted folder. Append one byte to the copy's `ntptimeclient-winrs.exe`. Run `.\install.ps1 -AcceptPreviewRisk` from the copy. Expect exit 43 and no change. This only proves the accidental-damage check.

## 3. Install

```powershell
.\install.ps1 -AcceptPreviewRisk
echo $LASTEXITCODE
```

Expect exit 0. Read the printed w32time line (original StartMode). Then check, read only:

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
- `ntptimeclient-winrs` exists and is RUNNING (unverified: the exe may leave it stopped, if so start it with `Start-Service ntptimeclient-winrs` and note it).
- The state directory exists and only SYSTEM and Administrators can write.
- `restore.json` exists in the state directory (unverified file name, from the plan).

## 4. Run for ten minutes

1. Wait ten minutes. Do not touch the clock.
2. Read the status and log (the paths are unverified, look in the state directory):
   `Get-Content C:\ProgramData\ntptimeclient-winrs\status.json`
   `.\ntptimeclient-winrs.exe status` (unverified subcommand, from the plan)
3. Confirm `w32time` is still stopped: `sc.exe query w32time`.
4. Offset check against the reference. There is no `scripts/measure-offset.ps1` yet. Task 16 plans a PowerShell loop around `w32tm /stripchart`. Until it exists, run:
   `w32tm.exe /stripchart /computer:time.cloudflare.com /samples:10 /period:5 /dataonly`
5. Record the offsets. The preview promises no accuracy. Write down the numbers and whether they are stable.
6. Optional disturbance test: set the clock 2 seconds wrong with `Set-Date (Get-Date).AddSeconds(2)`. Wait. Record whether the service steps or slews it back and how long it took. This changes the clock on the VM only.

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
.\uninstall.ps1
echo $LASTEXITCODE
```

Expect exit 0. Then check, read only:

```powershell
sc.exe qc w32time
sc.exe query w32time
Get-Service ntptimeclient-winrs -ErrorAction SilentlyContinue
Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\ntptimeclient-winrs
Get-ChildItem C:\ProgramData\ntptimeclient-winrs -Force -Recurse
Get-Process ntptimeclient-winrs -ErrorAction SilentlyContinue
```

Pass when:
- `w32time` start type equals the ORIGINAL from step 1, not just "something that works".
- No `ntptimeclient-winrs` service. No registry key. No running process.
- The only files left are in the state directory. Note which ones.
- The clock still runs. Run `w32tm.exe /stripchart /computer:time.cloudflare.com /samples:3 /dataonly`.

Then, if the original `w32time` state was running, check it is running now. If it was Manual (trigger start), "stopped" may be correct. Compare with step 1, not with a guess.

## 7. Domain-joined case

Use a separate VM or a copy of the snapshot joined to a lab domain. Do not use a real domain.

1. Revert to `before-preview`. Join the lab domain. Confirm `(Get-CimInstance Win32_ComputerSystem).PartOfDomain` is True. Record `sc.exe qc w32time`.
2. Run `.\install.ps1 -AcceptPreviewRisk`. Expect the exe to abort with a clear message and a non-zero exit. Confirm w32time and services are unchanged.
3. Run `.\install.ps1 -AcceptPreviewRisk -ConfirmDomainJoined`. Expect the install to go ahead. Check as in step 3. Note the effect on domain time (`w32tm /query /source` before and after).
4. Uninstall and check as in step 6.
5. Entra (Azure AD) and hybrid join are not detected. Do not test them. The README says so.

## 8. Failed-install rollback check

The goal is to prove the printed manual rollback works. Run each on a reverted snapshot.

1. Second install. Install, then run `.\install.ps1 -AcceptPreviewRisk` again. Record the exit code and whether the message and state stay sane. If it exits non-zero the script prints the manual rollback text. Check it is shown.
2. Manual rollback for real. After a successful install, do NOT run `uninstall.ps1`. Instead type the commands printed by the script by hand, using the start type you recorded in step 1:
   ```powershell
   sc.exe stop ntptimeclient-winrs
   sc.exe delete ntptimeclient-winrs
   sc.exe config w32time start= demand
   sc.exe start w32time
   w32tm.exe /resync
   ```
   Replace `demand` with the recorded type. Check `sc.exe qc w32time` matches step 1 and no service is left. If a command fails, record it. The printed text needs fixing.
3. Kill test. After an install, end the service process hard: `Stop-Process -Name ntptimeclient-winrs -Force`. Wait. Record whether the service restarts and whether the clock rate was reset (Review Focus 7 in the plan). Then uninstall.
4. Any non-zero exit from the exe during steps 3 to 7: stop, run the step 1 checks, and write down what state the machine was left in before you do anything else.

## 9. Record the result

Revert to `before-preview` when done. Write down per step: pass or fail, what you saw, any message that was unclear. Attach the output of the step 1, 3, 5 and 6 commands. Do not claim accuracy from one ten-minute run.
