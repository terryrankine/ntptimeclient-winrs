#Requires -Version 5.1
<#
.SYNOPSIS
UNSIGNED PREVIEW. Removes the ntptimeclient-winrs service.

.DESCRIPTION
Thin wrapper. `ntptimeclient-winrs.exe uninstall` removes the service and
restores w32time to the state it recorded at install. This script checks the
ground, calls it, then prints the real machine state. It asks for no risk
switch, because leaving is always allowed. It still needs an elevated shell,
a folder that only administrators can write, and an intact exe.

.PARAMETER WhatIf
Runs the checks and prints what would run. Calls nothing.

.NOTES
Windows blocks scripts by default (execution policy). Run it as:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1
That sets the policy for this one process only. It does not change the
machine policy. -NoProfile stops a user profile from running elevated.
#>
[CmdletBinding(SupportsShouldProcess)]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Same helper check as install.ps1. See the comment there. The same plain
# limit applies: a folder writable by a hostile user before the run cannot be
# made safe by this script.
try {
    $helperPath = Join-Path -Path $PSScriptRoot -ChildPath 'preview-common.ps1'
    $sumsText = [System.IO.File]::ReadAllText((Join-Path -Path $PSScriptRoot -ChildPath 'SHA256SUMS'))
    $helperHash = (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $found = [regex]::Matches($sumsText, '(?mi)^\s*([0-9a-f]{64})\s+\*?preview-common\.ps1\s*$')
    if ($found.Count -ne 1 -or $found[0].Groups[1].Value.ToLowerInvariant() -ne $helperHash) { throw 'preview-common.ps1 does not match SHA256SUMS.' }
} catch {
    Write-Host "REFUSED: cannot trust the helper file. $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Remove the service by hand: sc.exe stop ntptimeclient-winrs, then sc.exe delete ntptimeclient-winrs. Restore w32time from restore.json in the state directory or from your own record (see README-PREVIEW.txt).'
    exit 43
}
. $helperPath

Write-Host (Get-PreviewWarningText)

if (-not $WhatIfPreference -and -not (Test-IsElevated)) {
    Write-Host 'REFUSED: run this from an elevated PowerShell (Run as administrator).' -ForegroundColor Red
    Write-Host (Get-ExecutionPolicyHelp -ScriptName 'uninstall.ps1')
    exit $script:ExitNotElevated
}

$exe = Join-Path -Path $PSScriptRoot -ChildPath $script:PreviewExeName
$sums = Join-Path -Path $PSScriptRoot -ChildPath 'SHA256SUMS'
$pre = Test-ExeOrFail -ExePath $exe -SumsPath $sums -RequireTrustedLocation
if ($pre -ne 0) {
    # The user wants out and the exe cannot be trusted to run. Give the
    # manual route instead of leaving them stuck. No start type is known here
    # (the install-time read is not kept), so none is printed.
    Write-Host 'The script will not run the exe, so remove the service by hand:'
    Write-Host (Get-ManualRollbackText -StartKeyword $null)
    exit $pre
}

$exeArgs = Get-ExeArguments -Command uninstall

Write-Host ''
Write-Host 'State before the uninstall (read only):'
Format-MachineState -State (Get-MachineState) | ForEach-Object { Write-Host "  $_" }

if (-not $PSCmdlet.ShouldProcess("`"$exe`" $($exeArgs -join ' ')", 'Run the uninstaller (removes the service, restores w32time)')) {
    if ($WhatIfPreference) {
        Write-Host 'WhatIf: nothing was run.'
        exit 0
    }
    Write-Host 'Declined. Nothing was run.'
    exit $script:ExitDeclined
}

$code = Invoke-ExeKeepingExitCode -Path $exe -Arguments $exeArgs
if ($code -eq $script:ExitCannotStart) {
    Write-Host 'Nothing was changed: the exe did not run. See README-PREVIEW.txt (blocked by Smart App Control or AppLocker).' -ForegroundColor Red
    Write-Host 'To remove by hand, use the manual steps in README-PREVIEW.txt.'
    exit $code
}
$after = Get-MachineState
Write-Host ''
Write-Host "The uninstaller exited with code $code. State now (read only):"
Format-MachineState -State $after | ForEach-Object { Write-Host "  $_" }
if ($code -ne 0) {
    $class = Get-ExeExitClass -Code $code -Command uninstall
    Write-Host $class.Message -ForegroundColor Red
    if ($class.Class -ne 'NothingChanged') {
        Write-Host (Get-ManualRollbackText -StartKeyword $null)
    }
    exit $code
}
$problems = @(Test-UninstallOutcome -State $after)
if ($problems.Count -gt 0) {
    Write-Host 'The exe reported success but:' -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  - $_" }
    exit $script:ExitUninstallStateMismatch
}
Write-Host ''
Write-Host 'The service is gone. This script cannot tell what w32time should be.'
Write-Host 'Verify w32time against your record and against restore.json in the state directory.'
Write-Host 'The state directory under C:\ProgramData is left in place.'
exit 0
