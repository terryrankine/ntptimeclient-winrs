#Requires -Version 5.1
<#
.SYNOPSIS
UNSIGNED PREVIEW. Removes the ntptimeclient-winrs service.

.DESCRIPTION
Thin wrapper. `ntptimeclient-winrs.exe uninstall` removes the service and
restores w32time to the state it recorded at install. This script checks the
ground and calls it. It asks for no risk switch, because leaving is always
allowed. It still needs an elevated shell and an intact exe.

.PARAMETER WhatIf
Runs the checks and prints what would run. Calls nothing.
#>
[CmdletBinding(SupportsShouldProcess)]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath 'preview-common.ps1')

Write-Host (Get-PreviewWarningText)

if (-not $WhatIfPreference -and -not (Test-IsElevated)) {
    Write-Host 'REFUSED: run this from an elevated PowerShell (Run as administrator).' -ForegroundColor Red
    exit $script:ExitNotElevated
}

$exe = Join-Path -Path $PSScriptRoot -ChildPath $script:PreviewExeName
$sums = Join-Path -Path $PSScriptRoot -ChildPath 'SHA256SUMS'
$pre = Test-ExeOrFail -ExePath $exe -SumsPath $sums
if ($pre -ne 0) {
    # The user wants out and the exe cannot be trusted to run. Give the
    # manual route instead of leaving them stuck.
    Write-Host 'The script will not run the exe, so remove the service by hand:'
    Write-Host (Get-ManualRollbackText)
    exit $pre
}

$exeArgs = Get-ExeArguments -Command uninstall

Write-Host ''
Write-Host (Get-W32TimeSummary)

if (-not $PSCmdlet.ShouldProcess("`"$exe`" $($exeArgs -join ' ')", 'Run the uninstaller (removes the service, restores w32time)')) {
    Write-Host 'WhatIf: nothing was run.'
    exit 0
}

& $exe @exeArgs
$code = $LASTEXITCODE
if ($code -ne 0) {
    Write-Host ''
    Write-Host "The uninstaller exited with code $code. It may have stopped halfway." -ForegroundColor Red
    Write-Host (Get-ManualRollbackText)
    exit $code
}

Write-Host ''
Write-Host 'Uninstalled. What changed:'
Write-Host "  - The $($script:PreviewServiceName) service was removed."
Write-Host '  - w32time was restored to the state recorded at install (check it below).'
Write-Host '  - The state directory under C:\ProgramData is left in place.'
Write-Host '  (These are what the exe is expected to do. Check them. See README-PREVIEW.txt.)'
Write-Host ''
Write-Host (Get-W32TimeSummary)
exit 0
