<#
.SYNOPSIS
  DANGEROUS. Applies or undoes the tuned w32time profile from docs/measuring.md. Test machine only.

.DESCRIPTION
  Refuses unless MEASURE_TEST_MACHINE is 1, the session is elevated, and a second test-machine signal
  holds (a virtual machine by a model heuristic, or MEASURE_I_AM_ON_A_TEST_MACHINE=1). Supports -WhatIf.
  Apply saves the current values to -BeforeFile through a temp file, reads the file back and checks it
  before the first registry change. If any step fails it restores from the saved file and exits 1.
  -Undo restores the recorded values and removes the ones that were absent.
  Exit codes: 0 done, 1 failed (after an automatic restore), 2 refused or bad input.

.EXAMPLE
  $env:MEASURE_TEST_MACHINE = '1'; .\apply-tuned-profile.ps1 -Peers IP1,IP2,IP3 -BeforeFile .\out\w32time-before.json
  $env:MEASURE_TEST_MACHINE = '1'; .\apply-tuned-profile.ps1 -Undo -BeforeFile .\out\w32time-before.json
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$Peers,
    [string]$BeforeFile,
    [switch]$Undo
)

Set-StrictMode -Version Latest
# The guards come first. Nothing above them may change state.
if ($env:MEASURE_TEST_MACHINE -ne '1') {
    [Console]::Error.WriteLine('apply-tuned-profile: refused. Set MEASURE_TEST_MACHINE=1 on a test machine to run this.')
    exit 2
}
. (Join-Path $PSScriptRoot 'w32time-lib.ps1')
if (-not (Test-SecondTestMachineSignal)) {
    [Console]::Error.WriteLine('apply-tuned-profile: refused. No second test-machine signal: this does not look like a virtual machine. On a physical test box set MEASURE_I_AM_ON_A_TEST_MACHINE=1.')
    exit 2
}
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [Console]::Error.WriteLine('apply-tuned-profile: refused. Run elevated.')
    exit 2
}
if ([string]::IsNullOrWhiteSpace($BeforeFile)) { [Console]::Error.WriteLine('apply-tuned-profile: -BeforeFile is required.'); exit 2 }
$ErrorActionPreference = 'Stop'

if ($Undo) {
    if (-not (Test-Path -LiteralPath $BeforeFile)) { [Console]::Error.WriteLine("apply-tuned-profile: no such file $BeforeFile"); exit 2 }
    try {
        if ($PSCmdlet.ShouldProcess('w32time registry values and service', "restore from $BeforeFile")) { Invoke-TunedUndo -StateFile $BeforeFile }
    }
    catch { [Console]::Error.WriteLine("apply-tuned-profile: $($_.Exception.Message)"); exit 1 }
    exit 0
}

if (-not $Peers -or $Peers.Count -lt 1 -or @($Peers | Where-Object { $_ -notmatch '^[A-Fa-f0-9.:]{2,45}$' }).Count -gt 0) {
    [Console]::Error.WriteLine('apply-tuned-profile: -Peers must be one or more IP addresses.'); exit 2
}
if (Test-Path -LiteralPath $BeforeFile) { [Console]::Error.WriteLine("apply-tuned-profile: $BeforeFile exists. Refusing to overwrite."); exit 2 }
try {
    if ($PSCmdlet.ShouldProcess('w32time', "apply the tuned profile with peers $($Peers -join ',')")) {
        Invoke-TunedProfile -Peers $Peers -StateFile $BeforeFile
        Write-Host "applied. The values before the change are in $BeforeFile"
    }
}
catch { [Console]::Error.WriteLine("apply-tuned-profile: $($_.Exception.Message)"); exit 1 }
exit 0
