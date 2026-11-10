==========================================================================
 ntptimeclient-winrs  -  UNSIGNED PREVIEW
 NOT FOR MACHINES THAT MATTER
==========================================================================

This is a developer preview. It is not a release.

 - The binary is NOT code signed.
 - It sets the system clock and runs as a Windows service.
 - It stops and disables the Windows Time service (w32time).
 - It has not been tested on real machines yet.
 - Use it only on a throwaway virtual machine that has a snapshot.
   Never on the host, never on a production machine, a domain controller,
   or any machine you cannot rebuild.

No accuracy figure is promised. The aim is to keep the clock close to
correct. Whether it does better than the Windows default is something to
measure on your own machine, not something this preview claims.

WHAT THE SERVICE DOES
---------------------
It asks NTP servers for the time and corrects the system clock. It takes
servers from the config file first, then from DHCP, then from the global
pool (pool.ntp.org). It uses the first of those that has a usable server
and does not mix them. Even when your own servers are configured, it still
queries pool.ntp.org as a cross-check. The pool never picks the source. It
can only veto a step.
It corrects small errors by slewing (changing the clock rate gently). It
steps the clock only above a threshold (128 ms by default). It refuses a
step above 1000 seconds unless the config allows it. It writes a log file
and a status.json. It sends no alerts.

WHAT INSTALLING DOES
--------------------
install.ps1 runs "ntptimeclient-winrs.exe install". Per the project design
and its review notes, that does the following and nothing else:

 1. Stops the Windows Time service (w32time) and sets it to Disabled. The
    old state is first written to a restore record, restore.json, in the
    state directory.
 2. Registers a Windows service named ntptimeclient-winrs. It runs as
    LocalSystem with a reduced token: the only privilege it keeps for
    changing the clock is SeSystemtimePrivilege. (That the token really is
    reduced as designed is unverified until the VM test.)
 3. Sets the service to delayed automatic start, and to restart after a
    failure (after 60 s, 60 s, then 5 minutes).
 4. Creates an Event Log source for the service. The preview borrows
    EventCreate.exe as the message file. That is acceptable for a preview
    only.
 5. Starts the service and waits to see it running. If it does not start,
    the exe puts w32time back and sets our service to manual start (exit 21).
 6. Creates the state directory C:\ProgramData\ntptimeclient-winrs. Only
    SYSTEM and Administrators may write to it. It holds the saved drift
    value, restore.json, status.json and the log.

Nothing else is written. The config file is not created. The service runs
from the folder you extracted the zip into, so do not move or delete that
folder while the service is installed.

The scripts do not assume the list above. After the exe returns, install.ps1
reads the real state of w32time and of the service and prints it. If w32time
is still running or the service is missing, it says so and exits with code 46.
A state that cannot be read counts as a problem, never as success. Check the
state yourself too. The scripts themselves change nothing. They only run the
exe.

NAMES USED
----------
 - Binary:        ntptimeclient-winrs.exe
 - Service:       ntptimeclient-winrs
 - Config:        config.toml, in the SAME folder as the exe (not in the
                  state directory). default-config.toml in this zip is a
                  reference. Copy it to config.toml only from an elevated
                  shell. The folder and the file must be admin-only, like
                  the rest of the folder. The service loads this file as
                  LocalSystem at every start, so anyone who can write it
                  controls the clock.
 - State folder:  C:\ProgramData\ntptimeclient-winrs
 - Restore record: restore.json, in the state folder
 - Status:        status.json, in the state folder

WHERE TO EXTRACT THE ZIP
------------------------
Extract ONLY into a new folder that only administrators can write. Create
it from an elevated shell, for example under C:\Program Files, and extract
there. Do not run it from Downloads, the Desktop or a temp folder. A folder
under a user profile gives exit 20 and nothing is changed.

Why: the scripts run elevated and then run the exe. A program running as an
ordinary user could replace a file after the checks and before the run. The
service also runs from this folder as LocalSystem.

Checks, and who does them:
 - The exe (exit 20) checks the exe, EVERY file in its folder, every parent
   folder, and refuses subfolders, links, files with more than one hard
   link, and drives that are not fixed local drives. A stray file in the
   folder gives exit 20, so do not add files. config.toml is the one
   expected addition.
 - The scripts do a similar check first and refuse with code 44. They look
   at the folder, every file in it, each parent, subfolders, reparse points,
   link counts and the drive type. Their check is meant to be at least as
   strict as the exe's where a script can see it. It is not the control. The
   script runs from the folder it checks, so a folder that a hostile user
   could write before the run cannot be made safe by a script. Only the
   extraction into an admin-only folder does that.
 - If you extract with a tool that gives files a user owner, the check can
   refuse. Extract from an elevated shell so the new files are owned by
   Administrators.

The SHA256SUMS check is a different thing. It finds accidental damage only.
The sums file is in the same zip as the exe, so it cannot prove the zip is
genuine, and it does not stop a swap after the check.

HOW TO INSTALL
--------------
 1. Extract the whole zip as above.
 2. Open PowerShell as administrator in that folder.
 3. Read the warning, then run:

      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -AcceptPreviewRisk

    Windows blocks scripts by default, so a plain .\install.ps1 fails. The
    -ExecutionPolicy Bypass here applies to this one process only. It does
    not change the machine policy.

    -NoProfile stops PowerShell loading profile scripts. A profile that
    sits in a folder a user can write would otherwise run with
    administrator rights.

    If a Group Policy sets the execution policy, it overrides the command
    line and the script will not run. "Get-ExecutionPolicy -List" shows a
    MachinePolicy or UserPolicy entry in that case. Do not change the policy
    to get past it. Use a machine that policy does not govern.

    Add -WhatIf to run the checks and print the command without running it.

The script refuses to run without -AcceptPreviewRisk, without an elevated
shell, from an unsafe folder, or if the exe or the helper does not match
SHA256SUMS. Before it runs the exe it prints the w32time state it read from
the registry, with the exact sc.exe line to restore it. Keep it. If w32time
was already disabled, it prints a warning instead of a line, because
"restoring" disabled gives you nothing back.

If w32time is already disabled and the exe has no restore record, the exe
refuses with exit 12. A lost record must not become the new original. If
w32time really was disabled before you began, add -AcceptDisabledOriginal.
Never add it otherwise.

IF THE EXE WILL NOT START
-------------------------
Windows 11 Smart App Control, AppLocker, Windows Defender Application
Control or antivirus may refuse to run an unsigned exe (unverified for this
file). Then the script prints that the exe did not run and exits with code
48. Nothing was changed, so there is no rollback text. A bare exit code 1
from the exe is not in its table. It can mean a block too. Read the output
and the state the script prints. Do not turn protection off for this
preview. If you cannot run it, do not run it.

DOMAIN-JOINED MACHINES
----------------------
Per the design, a silent install on a domain-joined machine aborts (exit
4) unless told otherwise, and an interactive install warns and asks. Under
these scripts the exe's output is piped, so it is not interactive. It aborts
and tells you to re-run with the switch. Domain members get their time from
the domain, and w32time is how that works. If you still want to go ahead on
a test machine, add -ConfirmDomainJoined:

      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -AcceptPreviewRisk -ConfirmDomainJoined

Do that only if you understand the effect on the domain. Azure AD (Entra)
and hybrid-joined machines are not detected. The preview treats them like
any other machine.

HOW TO UNINSTALL
----------------
From an elevated PowerShell in the same folder:

      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1

This runs "ntptimeclient-winrs.exe uninstall". That should restore w32time
from restore.json and then remove the service. The script then prints the
real state. It cannot know what w32time should be, so verify it against your
record and against restore.json. The state directory is left in place.
Delete it by hand if you want it gone.

EXIT CODES
----------
Codes 40 to 48 come from the scripts. Codes 0 to 33 come from the exe. They
never overlap, so a code says who spoke.

 Scripts:
  40 -AcceptPreviewRisk not given
  41 not elevated
  42 the exe is not next to the script
  43 a hash did not match SHA256SUMS, or SHA256SUMS could not be read
  44 the folder is not safe (owner, rights, subfolder, link, drive)
  45 you answered No to the confirmation prompt
  46 install exited 0 but the machine does not look installed
  47 uninstall exited 0 but the service is still there or unreadable
  48 Windows would not start the exe. Nothing was changed

 Exe:
   0 ok                          2 usage error
   3 not elevated                4 domain joined and silent
   5 declined or timed out       6 state directory not usable
   7 restore record invalid      8 taking over w32time failed
   9 registering failed (the exe text says if anything changed)
  10 restoring w32time failed (uninstall)   11 removing the service failed
  12 w32time already disabled, no record (use -AcceptDisabledOriginal)
  13 a previous record was dropped          14 rollback failed
  15 carrying the old record failed         16 bad state path
  17 restore record not trusted             18 no record and w32time disabled
  19 registering failed AFTER takeover      20 exe location not admin-only
  21 registered but did not start (w32time put back, service set to manual)
  22 to 30 status, config and run codes (26: service run from a console)
  31 a service with our name that is not ours
  32 run: config location not safe          33 token default owner not trusted

Codes 2 to 7, 12, 13, 16, 20, 31 and 33 mean nothing was changed. The
script says so and prints no rollback text. 8, 10, 11, 14, 15, 17 and 18 mean
something may have changed. 9, 19 and 21 depend on the exe text: read it and
the state the script prints. The table is the exe's. If it differs, trust
the exe's own message.

HOW TO RESTORE w32time BY HAND
------------------------------
Use this if the exe failed halfway or you lost the folder. Run it from an
elevated prompt. The authority is restore.json in the state directory, when
it exists. The fallback is the sc.exe line install.ps1 printed before it
ran. It was built from the registry values Start and DelayedAutostart of
HKLM\SYSTEM\CurrentControlSet\Services\W32Time, so it keeps auto, delayed-auto,
demand and so on as they were. If those values could not be read, the script
prints no line and guesses nothing.

      sc.exe stop ntptimeclient-winrs
      sc.exe delete ntptimeclient-winrs
      sc.exe config w32time start= <the recorded keyword>
      sc.exe start w32time
      w32tm.exe /resync
      sc.exe qc w32time

The keywords are boot, system, auto, delayed-auto, demand and disabled.
Note the space after "start=". sc.exe requires it. A trigger start setting
is not shown by these values. The clock rate may stay non-nominal until
w32time takes over again or the machine restarts (unverified). Restart after
the rollback.

KNOWN LIMITATIONS
-----------------
 - No virtual machine detection. A hypervisor may also set the clock. Turn
   hypervisor time sync off for the test VM or the two will fight.
 - No Entra (Azure AD) or hybrid join handling. See above.
 - Unsigned. Windows SmartScreen, Smart App Control or antivirus software
   may warn about the download or the exe, or block it. How they react to
   this file has not been checked. Do not turn protection off.
 - The default pool is pool.ntp.org. The project has not yet asked the pool
   project for its own vendor zone. That is needed before any public
   release.
 - IPv4 only for DHCP-supplied servers. No NTS, no server mode, no PTP.
 - A single-server config or DHCP tier has no majority to check it. The pool
   cross-check limits the damage but does not remove the risk.
 - A bad config file makes the service fail and restart every 5 minutes.
 - The Event Log source uses EventCreate.exe as its message file. Fine for a
   preview. A public release needs its own message table.

WHERE TO REPORT PROBLEMS
------------------------
Open an issue on the Issues page of the GitHub repository this zip came
from. Say which Windows version, whether it is a VM, and attach the log file.
Do not attach anything you would not want public.

LICENCE
-------
MIT OR Apache-2.0. See LICENSE-MIT and LICENSE-APACHE in this zip.
