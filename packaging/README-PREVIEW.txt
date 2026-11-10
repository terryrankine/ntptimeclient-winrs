==========================================================================
 ntptimeclient-winrs  -  UNSIGNED PREVIEW
 NOT FOR MACHINES THAT MATTER
==========================================================================

This is a developer preview. It is not a release.

 - The binary is NOT code signed.
 - It sets the system clock and runs as a Windows service.
 - It stops and disables the Windows Time service (w32time).
 - It has not been tested on a wide range of machines.
 - Use it only on a throwaway virtual machine that has a snapshot.
 - Do not use it on a production machine, a domain controller, or any
   machine you cannot rebuild.

No accuracy figure is promised. The aim is to keep the clock close to
correct. Whether it does better than the Windows default is something to
measure on your own machine, not something this preview claims.

WHAT THE SERVICE DOES
---------------------
It asks NTP servers for the time and corrects the system clock. It takes
servers from the config file first, then from DHCP, then from the global
pool (pool.ntp.org). It uses the first of those that has a usable server
and does not mix them. It corrects small errors by slewing (changing the
clock rate gently). It steps the clock only above a threshold (128 ms by
default). It refuses a step above 1000 seconds unless the config allows it.
It writes a log file and a status.json. It sends no alerts.

WHAT INSTALLING CHANGES
-----------------------
install.ps1 runs "ntptimeclient-winrs.exe install". That is expected to:

 1. Stop the Windows Time service (w32time).
 2. Set w32time to Disabled, after recording its previous start type.
 3. Install a Windows service named ntptimeclient-winrs. Whether the
    install also starts it is for the exe to decide.
 4. Create the state directory C:\ProgramData\ntptimeclient-winrs. Only
    SYSTEM and Administrators may write to it. It holds the saved drift
    value, the record of the old w32time state (restore.json) and the
    status file.

The list above comes from the project design. The scripts do not check it.
Check it yourself (see docs/preview-vm-test.md in the source repository).
The scripts themselves change nothing. They only run the exe.

HOW TO INSTALL
--------------
 1. Extract the whole zip into a folder.
 2. Open PowerShell as administrator.
 3. Read the warning, then run:

      .\install.ps1 -AcceptPreviewRisk

    Add -WhatIf to run the checks and print the command without running it.

The script refuses to run without -AcceptPreviewRisk, without an elevated
shell, or if the exe does not match SHA256SUMS. The SHA256SUMS check finds
accidental damage only. The sums file is in the same zip as the exe, so it
cannot prove the zip is genuine.

DOMAIN-JOINED MACHINES
----------------------
On a domain-joined machine the exe aborts the install. Domain members get
their time from the domain, and w32time is how that works. If you still want
to go ahead on a test machine, add -ConfirmDomainJoined:

      .\install.ps1 -AcceptPreviewRisk -ConfirmDomainJoined

Do that only if you understand the effect on the domain. Azure AD (Entra)
and hybrid-joined machines are not detected. The preview treats them like
any other machine.

HOW TO UNINSTALL
----------------
From an elevated PowerShell in the same folder:

      .\uninstall.ps1

This runs "ntptimeclient-winrs.exe uninstall". That is expected to remove
the service and put w32time back to the state it had before the install.
The state directory is left in place. Delete it by hand if you want it gone.

HOW TO RESTORE w32time BY HAND
------------------------------
Use this if the exe failed halfway or you lost the folder. Run it from an
elevated prompt. The start type to restore is the one printed by
install.ps1 before it ran, and the one recorded in restore.json in the state
directory. On Windows 10 and 11 the default is usually Manual (trigger
start), written "demand" below. On Server it is usually Automatic ("auto").
That recollection is unverified, so prefer the recorded value.

      sc.exe stop ntptimeclient-winrs
      sc.exe delete ntptimeclient-winrs
      sc.exe config w32time start= demand
      sc.exe start w32time
      w32tm.exe /resync
      sc.exe query w32time

Note the space after "start=". It is required by sc.exe. The service name
above is the expected one. Check it with "sc.exe query" if it fails.

KNOWN LIMITATIONS
-----------------
 - No virtual machine detection. A hypervisor may also set the clock. Turn
   hypervisor time sync off for the test VM or the two will fight.
 - No Entra (Azure AD) or hybrid join handling. See above.
 - Unsigned. Windows SmartScreen or antivirus software may warn about the
   download or the exe. How SmartScreen reacts to this file has not been
   checked. Do not turn protection off. If the warning worries you, do not
   run the preview.
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
