#Requires -Version 5.1
<#
.SYNOPSIS
UNSIGNED PREVIEW. Installs the ntptimeclient-winrs service.

.DESCRIPTION
Thin wrapper. All real work (stopping and disabling w32time, creating the
service, the domain-joined rule) is done by `ntptimeclient-winrs.exe install`.
This script checks the ground, calls it, then reads back the real machine
state.

It needs an elevated shell, a folder that only administrators can write, the
exe next to it, a matching SHA256SUMS entry and the explicit
-AcceptPreviewRisk switch. It downloads nothing. It does not build code from
text or use Invoke-Expression. It does load the helper file next to it
(preview-common.ps1), after checking that file against SHA256SUMS.

.PARAMETER AcceptPreviewRisk
Required. Says you read the warning and accept that this unsigned preview
changes the system clock and stops w32time.

.PARAMETER ConfirmDomainJoined
Passes --confirm-domain-joined to the exe. Without it a silent install on a
domain-joined machine aborts, per the design. What an interactive install
does is up to the exe. Only pass this if you understand that w32time is how
the domain keeps time.

.PARAMETER AcceptDisabledOriginal
Passes --accept-disabled-original to the exe. Needed only if w32time is
already disabled and the exe has no restore record (exit 12). Use it only if
w32time really was disabled before you started. A lost record must not become
the new original. Never passed by default.

.PARAMETER WhatIf
Runs the checks and prints what would run. Calls nothing.

.NOTES
Windows blocks scripts by default (execution policy). Run it as:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -AcceptPreviewRisk
That sets the policy for this one process only. It does not change the
machine policy. -NoProfile stops a user profile from running elevated.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$AcceptPreviewRisk,
    [switch]$ConfirmDomainJoined,
    [switch]$AcceptDisabledOriginal
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Check the helper against SHA256SUMS before it is loaded and run elevated.
# This catches damage, or a helper from another release. It does not stop a
# malicious edit, and the file could still change between this hash and the
# load. PLAIN LIMIT: the folder permission check lives inside the helper, so
# it runs only after the helper is loaded. A folder that was writable by a
# hostile user before this run cannot be made safe by this script. Extracting
# into an admin-only folder, as the README says, is the only real control.
try {
    $helperPath = Join-Path -Path $PSScriptRoot -ChildPath 'preview-common.ps1'
    $sumsText = [System.IO.File]::ReadAllText((Join-Path -Path $PSScriptRoot -ChildPath 'SHA256SUMS'))
    $helperHash = (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $found = [regex]::Matches($sumsText, '(?mi)^\s*([0-9a-f]{64})\s+\*?preview-common\.ps1\s*$')
    if ($found.Count -ne 1 -or $found[0].Groups[1].Value.ToLowerInvariant() -ne $helperHash) { throw 'preview-common.ps1 does not match SHA256SUMS.' }
} catch {
    Write-Host "REFUSED: cannot trust the helper file. $($_.Exception.Message)" -ForegroundColor Red
    exit 43
}
. $helperPath

Write-Host (Get-PreviewWarningText)

if (-not $AcceptPreviewRisk) {
    Write-Host 'REFUSED: pass -AcceptPreviewRisk to confirm you read the warning above.' -ForegroundColor Red
    Write-Host (Get-ExecutionPolicyHelp -ScriptName 'install.ps1' -Extra ' -AcceptPreviewRisk')
    exit $script:ExitRiskNotAccepted
}
# A dry run needs no rights. A real run does, because the exe sets the clock
# and manages services.
if (-not $WhatIfPreference -and -not (Test-IsElevated)) {
    Write-Host 'REFUSED: run this from an elevated PowerShell (Run as administrator).' -ForegroundColor Red
    exit $script:ExitNotElevated
}

$exe = Join-Path -Path $PSScriptRoot -ChildPath $script:PreviewExeName
$sums = Join-Path -Path $PSScriptRoot -ChildPath 'SHA256SUMS'
$pre = Test-ExeOrFail -ExePath $exe -SumsPath $sums -RequireTrustedLocation
if ($pre -ne 0) { exit $pre }

$exeArgs = Get-ExeArguments -Command install -ConfirmDomainJoined:$ConfirmDomainJoined -AcceptDisabledOriginal:$AcceptDisabledOriginal

# Read before the exe runs. The exe changes w32time, and this is the only
# record of the original start type that does not depend on the exe.
$before = Get-MachineState
$rollbackKeyword = $before.W32TimeStart
Write-Host ''
Write-Host 'State before the install (read only):'
Format-MachineState -State $before | ForEach-Object { Write-Host "  $_" }
Write-Host 'Rollback line for w32time, from the registry value read just now:'
Write-Host "  $(Get-RollbackCommand -StartKeyword $rollbackKeyword)"
Write-Host 'Keep this. restore.json written by the exe is the authority when it exists.'
if ($ConfirmDomainJoined) {
    Write-Host 'WARNING: -ConfirmDomainJoined given. A domain-joined machine will not be refused.' -ForegroundColor Yellow
}
if ($AcceptDisabledOriginal) {
    Write-Host 'WARNING: -AcceptDisabledOriginal given. If w32time is disabled and there is no record, the disabled state becomes the original.' -ForegroundColor Yellow
}

if (-not $PSCmdlet.ShouldProcess("`"$exe`" $($exeArgs -join ' ')", 'Run the installer (stops and disables w32time, installs the service)')) {
    if ($WhatIfPreference) {
        Write-Host 'WhatIf: nothing was run.'
        exit 0
    }
    Write-Host 'Declined. Nothing was run.'
    exit $script:ExitDeclined
}

$code = Invoke-ExeKeepingExitCode -Path $exe -Arguments $exeArgs
if ($code -eq $script:ExitCannotStart) {
    # Windows would not start the exe (Smart App Control, AppLocker, antivirus).
    # It never ran, so nothing changed and there is no rollback to print.
    Write-Host 'Nothing was changed: the exe did not run. See README-PREVIEW.txt (blocked by Smart App Control or AppLocker).' -ForegroundColor Red
    exit $code
}
if ($code -ne 0) {
    $class = Get-ExeExitClass -Code $code -Command install
    Write-Host ''
    Write-Host $class.Message -ForegroundColor Red
    Write-Host 'State now (read only):'
    Format-MachineState -State (Get-MachineState) | ForEach-Object { Write-Host "  $_" }
    # No rollback text when the exe says it changed nothing. It would send the
    # user to undo something that never happened.
    if ($class.Class -ne 'NothingChanged') {
        Write-Host (Get-ManualRollbackText -StartKeyword $rollbackKeyword)
    }
    exit $code
}

# The exe said 0. Report what is really there, not what should be there.
$after = Get-MachineState
Write-Host ''
Write-Host 'The installer exited with code 0. State now (read only):'
Format-MachineState -State $after | ForEach-Object { Write-Host "  $_" }
$problems = @(Test-InstallOutcome -State $after)
if ($problems.Count -gt 0) {
    Write-Host ''
    Write-Host 'The exe reported success but the machine does not look installed:' -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  - $_" }
    Write-Host 'This preview may contain an exe that does not install anything yet. Do not rely on it.'
    Write-Host (Get-ManualRollbackText -StartKeyword $rollbackKeyword)
    exit $script:ExitStateMismatch
}
Write-Host ''
Write-Host 'The state looks like an install happened. Check it yourself, and see README-PREVIEW.txt.'
Write-Host 'To undo, run uninstall.ps1 from an elevated shell. Or by hand:'
Write-Host (Get-ManualRollbackText -StartKeyword $rollbackKeyword)
exit 0
