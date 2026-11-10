#Requires -Version 5.1
<#
.SYNOPSIS
UNSIGNED PREVIEW. Installs the ntptimeclient-winrs service.

.DESCRIPTION
Thin wrapper. All real work (stopping and disabling w32time, creating the
service, the domain-joined rule) is done by `ntptimeclient-winrs.exe install`.
This script only checks the ground and calls it.

It needs an elevated shell, the exe next to it, a matching SHA256SUMS entry
and the explicit -AcceptPreviewRisk switch. It never downloads anything and
never runs text as code.

.PARAMETER AcceptPreviewRisk
Required. Says you read the warning and accept that this unsigned preview
changes the system clock and stops w32time.

.PARAMETER ConfirmDomainJoined
Passes --confirm-domain-joined to the exe. Without it the exe aborts on a
domain-joined machine. Only pass it if you understand that w32time is how
the domain keeps time.

.PARAMETER WhatIf
Runs the checks and prints what would run. Calls nothing.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$AcceptPreviewRisk,
    [switch]$ConfirmDomainJoined
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath 'preview-common.ps1')

Write-Host (Get-PreviewWarningText)

if (-not $AcceptPreviewRisk) {
    Write-Host 'REFUSED: pass -AcceptPreviewRisk to confirm you read the warning above.' -ForegroundColor Red
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
$pre = Test-ExeOrFail -ExePath $exe -SumsPath $sums
if ($pre -ne 0) { exit $pre }

$exeArgs = Get-ExeArguments -Command install -ConfirmDomainJoined:$ConfirmDomainJoined

Write-Host ''
Write-Host (Get-W32TimeSummary)
Write-Host 'Note the w32time StartMode above. You need it if you restore by hand.'
if ($ConfirmDomainJoined) {
    Write-Host 'WARNING: -ConfirmDomainJoined given. A domain-joined machine will not be refused.' -ForegroundColor Yellow
}

if (-not $PSCmdlet.ShouldProcess("`"$exe`" $($exeArgs -join ' ')", 'Run the installer (stops and disables w32time, installs the service)')) {
    Write-Host 'WhatIf: nothing was run.'
    exit 0
}

& $exe @exeArgs
$code = $LASTEXITCODE
if ($code -ne 0) {
    Write-Host ''
    Write-Host "The installer exited with code $code. It may have stopped halfway." -ForegroundColor Red
    Write-Host (Get-ManualRollbackText)
    exit $code
}

Write-Host ''
Write-Host 'Installed. What changed:'
Write-Host '  - The Windows Time service (w32time) was stopped and disabled.'
Write-Host "  - The $($script:PreviewServiceName) service was installed."
Write-Host '  - A state directory was created under C:\ProgramData.'
Write-Host '  (These are what the exe is expected to do. Check them. See README-PREVIEW.txt.)'
Write-Host ''
Write-Host 'To undo, run uninstall.ps1 from an elevated shell. Or by hand:'
Write-Host (Get-ManualRollbackText)
exit 0
