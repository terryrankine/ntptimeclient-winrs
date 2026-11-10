<#
.SYNOPSIS
  Records the w32time start type and trigger info (read only), or restores them (guarded).

.DESCRIPTION
  -Record writes -File (JSON, atomic, refuses to overwrite) and -File.reg (a reg export of the W32Time
  key). It reads only, needs no admin and changes nothing. Run it before the first contender that stops
  or disables w32time. The record holds the registry Start and DelayedAutostart values, the sc.exe keyword
  derived from them (including delayed-auto), whether the service was running, and the text of
  `sc qc w32time` and `sc qtriggerinfo w32time`.

  -Restore sets the recorded start type with sc.exe, reads it back and compares the trigger info. A
  trigger difference is an error. It is never guessed. -Restore refuses unless MEASURE_TEST_MACHINE is 1,
  a second test-machine signal holds and the session is elevated. Supports -WhatIf.
  Exit codes: 0 done, 1 failed, 2 refused or bad input.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Record,
    [switch]$Restore,
    [string]$File,
    [switch]$StartIfWasRunning
)

Set-StrictMode -Version Latest
# The guard comes first. Nothing above it may change state.
if ($Restore -and $env:MEASURE_TEST_MACHINE -ne '1') {
    [Console]::Error.WriteLine('w32time-state: refused. Set MEASURE_TEST_MACHINE=1 on a test machine to run -Restore.')
    exit 2
}
if (($Record -and $Restore) -or (-not $Record -and -not $Restore) -or [string]::IsNullOrWhiteSpace($File)) {
    [Console]::Error.WriteLine('w32time-state: give exactly one of -Record or -Restore, and -File.')
    exit 2
}
. (Join-Path $PSScriptRoot 'w32time-lib.ps1')
$ErrorActionPreference = 'Stop'

if ($Record) {
    if (Test-Path -LiteralPath $File) { [Console]::Error.WriteLine("w32time-state: $File exists. Refusing to overwrite."); exit 2 }
    try {
        $state = Get-W32TimeServiceState
        $tmp = "$File.tmp"
        ($state | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $tmp -Encoding ASCII
        Move-Item -LiteralPath $tmp -Destination $File
        $back = Get-Content -LiteralPath $File -Raw | ConvertFrom-Json
        if ([int]$back.Start -ne $state.Start -or [int]$back.DelayedAutostart -ne $state.DelayedAutostart -or $back.StartKeyword -ne $state.StartKeyword) { throw 'the record read back differs' }
        & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time' "$File.reg" /y | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "reg export exited $LASTEXITCODE" }
        Write-Host "recorded start type '$($state.StartKeyword)', running=$($state.Running). Files: $File and $File.reg"
    }
    catch { [Console]::Error.WriteLine("w32time-state: $($_.Exception.Message)"); exit 1 }
    exit 0
}

if (-not (Test-SecondTestMachineSignal)) {
    [Console]::Error.WriteLine('w32time-state: refused. No second test-machine signal: this does not look like a virtual machine. On a physical test box set MEASURE_I_AM_ON_A_TEST_MACHINE=1.')
    exit 2
}
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [Console]::Error.WriteLine('w32time-state: refused. Run elevated.')
    exit 2
}
if (-not (Test-Path -LiteralPath $File)) { [Console]::Error.WriteLine("w32time-state: no such file $File"); exit 2 }
try {
    $rec = Get-Content -LiteralPath $File -Raw | ConvertFrom-Json
    if ($PSCmdlet.ShouldProcess('w32time service', "restore start type $($rec.StartKeyword)")) { Restore-W32TimeServiceState -State $rec -StartIfWasRunning:$StartIfWasRunning }
}
catch { [Console]::Error.WriteLine("w32time-state: $($_.Exception.Message)"); exit 1 }
exit 0
