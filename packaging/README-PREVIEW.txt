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

WHAT INSTALLING CHANGES
-----------------------
install.ps1 runs "ntptimeclient-winrs.exe install". The design says that
should:

 1. Stop the Windows Time service (w32time).
 2. Set w32time to Disabled, after recording its previous start type.
 3. Install a Windows service named ntptimeclient-winrs. Whether the
    install also starts it is for the exe to decide.
 4. Create the state directory C:\ProgramData\ntptimeclient-winrs. Only
    SYSTEM and Administrators may write to it. It holds the saved drift
    value, the record of the old w32time state (restore.json) and the
    status file.

That list comes from the project design. The scripts do not assume it.
After the exe returns, install.ps1 reads the real state of w32time and of
the service and prints it. If w32time is still running or the service is
missing, it says so and exits with code 46. Check the state yourself too.
The scripts themselves change nothing. They only run the exe.

Not decided yet (see Tasks 12 and 14 of the project plan): where the service
binary is installed from, which account the service runs as, and where the
service reads its config file. Until Task 14, treat the config location as
unknown. default-config.toml is a reference for the keys and defaults. It
does not say where to put it.

WHERE TO EXTRACT THE ZIP
------------------------
Extract ONLY into a folder that only administrators can write. For example
create a folder under C:\Program Files from an elevated shell and extract
there. Do not run it from Downloads, the Desktop or a temp folder.

Why: the scripts run elevated and then run the exe. A program running as an
ordinary user could replace the exe or the helper script after the checks
and before the run. The service may also run from this path as SYSTEM.
The scripts check the folder, the exe, the helper and each parent folder.
They refuse (exit code 44) if anyone other than SYSTEM, Administrators or
TrustedInstaller can write there or owns it.

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
    not change the machine policy. -NoProfile stops a user profile running
    with administrator rights.

    Add -WhatIf to run the checks and print the command without running it.

The script refuses to run without -AcceptPreviewRisk, without an elevated
shell, from a folder others can write, or if the exe or the helper does not
match SHA256SUMS. Before it runs the exe it prints the w32time state it
read from the registry, with the exact sc.exe line to restore it. Keep it.

DOMAIN-JOINED MACHINES
----------------------
Per the design, a silent install on a domain-joined machine aborts unless
told otherwise, and an interactive install warns and asks. Task 12 owns
what the exe really does with the flag. Domain members get their time from
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

This runs "ntptimeclient-winrs.exe uninstall". That should remove the
service and put w32time back to the state recorded at install. The script
then prints the real state. It cannot know what w32time should be, so
verify it against your record and against restore.json. The state directory
is left in place. Delete it by hand if you want it gone.

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
is not shown by these values. The service name above is the expected one.
Check it with "sc.exe query" if it fails. The clock rate may stay
non-nominal until w32time takes over again or the machine restarts
(unverified). Restart after the rollback.

KNOWN LIMITATIONS
-----------------
 - No virtual machine detection. A hypervisor may also set the clock. Turn
   hypervisor time sync off for the test VM or the two will fight.
 - No Entra (Azure AD) or hybrid join handling. See above.
 - Unsigned. Windows SmartScreen, Smart App Control or antivirus software
   may warn about the download or the exe, or block it. How they react to
   this file has not been checked. Do not turn protection off. If the
   warning worries you, do not run the preview.
 - The default pool is pool.ntp.org. The project has not yet asked the pool
   project for its own vendor zone. That is needed before any public
   release.
 - IPv4 only for DHCP-supplied servers. No NTS, no server mode, no PTP.
 - A single-server config or DHCP tier has no majority to check it. The pool
   cross-check limits the damage but does not remove the risk.

WHERE TO REPORT PROBLEMS
------------------------
Open an issue on the Issues page of the GitHub repository this zip came
from. Say which Windows version, whether it is a VM, and attach the log file.
Do not attach anything you would not want public.

LICENCE
-------
MIT OR Apache-2.0. See LICENSE-MIT and LICENSE-APACHE in this zip.
