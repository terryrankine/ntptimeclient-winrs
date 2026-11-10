<#
.SYNOPSIS
  DANGEROUS. Moves the system clock by a fixed amount. Throwaway VM only.

.DESCRIPTION
  Refuses unless MEASURE_TEST_MACHINE is 1, a second test-machine signal holds (a virtual machine by a
  model heuristic, or MEASURE_I_AM_ON_A_TEST_MACHINE=1) and the session is elevated. The size is capped
  at 2000 ms. A larger value is refused when the parameters are bound. Supports -WhatIf. Prints the UTC time before the change so the event can be
  noted. Exit codes: 0 done, 2 refused or bad input.

.EXAMPLE
  $env:MEASURE_TEST_MACHINE = '1'; .\disturb-clock.ps1 -Milliseconds -2000
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param([ValidateRange(-2000, 2000)][int]$Milliseconds = -2000)

Set-StrictMode -Version Latest
# The guard comes first. Nothing above it may change state.
if ($env:MEASURE_TEST_MACHINE -ne '1') {
    [Console]::Error.WriteLine('disturb-clock: refused. Set MEASURE_TEST_MACHINE=1 on a throwaway VM to run this.')
    exit 2
}
if ($Milliseconds -eq 0) {
    [Console]::Error.WriteLine('disturb-clock: -Milliseconds must not be zero.')
    exit 2
}
. (Join-Path $PSScriptRoot 'w32time-lib.ps1')
if (-not (Test-SecondTestMachineSignal)) {
    [Console]::Error.WriteLine('disturb-clock: refused. No second test-machine signal: this does not look like a virtual machine. On a physical test box set MEASURE_I_AM_ON_A_TEST_MACHINE=1.')
    exit 2
}
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [Console]::Error.WriteLine('disturb-clock: refused. Run elevated.')
    exit 2
}
Write-Host ('before (UTC): ' + (Get-Date).ToUniversalTime().ToString('o'))
if ($PSCmdlet.ShouldProcess('system clock', "adjust by $Milliseconds ms")) {
    Set-Date -Adjust (New-TimeSpan -Milliseconds $Milliseconds) | Out-Null
    Write-Host ('after  (UTC): ' + (Get-Date).ToUniversalTime().ToString('o'))
}
exit 0
