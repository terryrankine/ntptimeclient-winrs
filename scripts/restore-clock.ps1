<#
.SYNOPSIS
  DANGEROUS. Steps the system clock to a reference after a disturbance block. Throwaway VM only.

.DESCRIPTION
  Refuses unless MEASURE_TEST_MACHINE is 1, a second test-machine signal holds (a virtual machine by a
  model heuristic, or MEASURE_I_AM_ON_A_TEST_MACHINE=1) and the session is elevated. Reads -Count samples
  from the reference (read only), requires more than half of them to be good, takes the median offset and
  steps the clock by it. A
  positive offset means the reference is ahead, so the clock is moved forward. Refuses a
  step larger than -MaxStepSeconds. Supports -WhatIf. Stop the contender first, then run
  wait-synced.ps1.

  Exit codes: 0 done or nothing to do, 1 could not read the reference, 2 refused or bad input.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Reference,
    [int]$Count = 5,
    [ValidateRange(0.001, 10)][double]$MaxStepSeconds = 10,
    [string]$W32tmPath = ''   # tests only
)

Set-StrictMode -Version Latest

function Get-RestoreAdjustment {
    # Median of the good offsets in seconds. Throws when there is none, when half or fewer of the requested
    # samples were good, or when it is too large.
    param([double[]]$Offsets, [double]$MaxStepSeconds, [int]$Requested = 0)
    $s = @($Offsets | Sort-Object)
    if ($s.Count -eq 0) { throw 'no good samples' }
    if ($Requested -gt 0 -and $s.Count * 2 -le $Requested) { throw "only $($s.Count) of $Requested samples were good. More than half are needed." }
    $n = $s.Count
    $m = if ($n % 2 -eq 1) { $s[($n - 1) / 2] } else { ($s[$n / 2 - 1] + $s[$n / 2]) / 2.0 }
    if ([math]::Abs($m) -gt $MaxStepSeconds) { throw "offset $m s is larger than -MaxStepSeconds" }
    return [double]$m
}

function Invoke-Restore {
    # The guard comes first. Nothing above it may change state.
    if ($env:MEASURE_TEST_MACHINE -ne '1') {
        [Console]::Error.WriteLine('restore-clock: refused. Set MEASURE_TEST_MACHINE=1 on a throwaway VM to run this.')
        return 2
    }
    if ([string]::IsNullOrWhiteSpace($Reference) -or $Reference -notmatch '^[A-Za-z0-9._:\-]{1,253}$' -or $Count -lt 1 -or $Count -gt 50 -or $MaxStepSeconds -le 0) {
        [Console]::Error.WriteLine('restore-clock: bad reference, count or limit.')
        return 2
    }
    . (Join-Path $PSScriptRoot 'w32time-lib.ps1')
    if (-not (Test-SecondTestMachineSignal)) {
        [Console]::Error.WriteLine('restore-clock: refused. No second test-machine signal: this does not look like a virtual machine. On a physical test box set MEASURE_I_AM_ON_A_TEST_MACHINE=1.')
        return 2
    }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        [Console]::Error.WriteLine('restore-clock: refused. Run elevated.')
        return 2
    }
    . (Join-Path $PSScriptRoot 'offset-lib.ps1')
    try {
        $good = @(Get-OffsetSamples -Reference $Reference -Count $Count -PeriodSeconds 1 -W32tmPath $W32tmPath | Where-Object { $_.Kind -eq 'Data' } | ForEach-Object { $_.OffsetS })
        $adj = Get-RestoreAdjustment -Offsets $good -MaxStepSeconds $MaxStepSeconds -Requested $Count
    }
    catch { [Console]::Error.WriteLine("restore-clock: $($_.Exception.Message)"); return 1 }
    Write-Host ("median offset {0:N6} s from {1} good samples" -f $adj, $good.Count)
    if ($PSCmdlet.ShouldProcess('system clock', "step by $adj s")) {
        Set-Date -Adjust ([TimeSpan]::FromSeconds($adj)) | Out-Null
        Write-Host ('stepped (UTC now): ' + (Get-Date).ToUniversalTime().ToString('o'))
    }
    return 0
}

if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-Restore) }
