<#
.SYNOPSIS
  DANGEROUS. Moves the system clock by a fixed amount. Throwaway VM only.

.DESCRIPTION
  Refuses unless the environment variable MEASURE_TEST_MACHINE is 1 and the session is
  elevated. Supports -WhatIf. Prints the UTC time before the change so the event can be
  noted. Exit codes: 0 done, 2 refused or bad input.

.EXAMPLE
  $env:MEASURE_TEST_MACHINE = '1'; .\disturb-clock.ps1 -Milliseconds -2000
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param([int]$Milliseconds = -2000)

Set-StrictMode -Version Latest
# The guard comes first. Nothing above it may change state.
if ($env:MEASURE_TEST_MACHINE -ne '1') {
    [Console]::Error.WriteLine('disturb-clock: refused. Set MEASURE_TEST_MACHINE=1 on a throwaway VM to run this.')
    exit 2
}
if ($Milliseconds -eq 0 -or [math]::Abs($Milliseconds) -gt 10000) {
    [Console]::Error.WriteLine('disturb-clock: -Milliseconds must be non-zero and within 10000.')
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
