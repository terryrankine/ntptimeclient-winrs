<#
.SYNOPSIS
  Read only check that the clock is synced again before the next block starts.

.DESCRIPTION
  Samples both references until -Consecutive rounds in a row have BOTH offsets below -LimitMs,
  or until -MaxWaitSeconds has passed. Changes nothing. Needs no admin.

  Exit codes: 0 synced, 3 start not clean (maximum wait reached), 2 bad input.
  On exit 3 the next block must carry the suffix -unclean on its -Block label. The summary
  flags such a block and excludes its round like a block whose references disagree.

.EXAMPLE
  .\wait-synced.ps1 -ReferenceA <REF_A_IP> -ReferenceB <REF_B_IP>
#>
[CmdletBinding()]
param(
    [string]$ReferenceA,
    [string]$ReferenceB,
    [double]$LimitMs = 10,
    [int]$Consecutive = 3,
    [int]$MaxWaitSeconds = 600,
    [int]$PeriodSeconds = 5,
    [string]$W32tmPath = ''   # tests only
)

Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'offset-lib.ps1')

function Invoke-WaitSynced {
    param([string]$ReferenceA, [string]$ReferenceB, [double]$LimitMs, [int]$Consecutive, [int]$MaxWaitSeconds, [int]$PeriodSeconds, [string]$W32tmPath)
    foreach ($r in $ReferenceA, $ReferenceB) {
        if ([string]::IsNullOrWhiteSpace($r) -or $r -notmatch '^[A-Za-z0-9._:\-]{1,253}$') { [Console]::Error.WriteLine('wait-synced: both references must be host names or IP addresses.'); return 2 }
    }
    if ($ReferenceA -eq $ReferenceB) { [Console]::Error.WriteLine('wait-synced: the two references must differ.'); return 2 }
    if ($LimitMs -le 0 -or $Consecutive -lt 1 -or $Consecutive -gt 100 -or $MaxWaitSeconds -lt 1 -or $PeriodSeconds -lt 1) { [Console]::Error.WriteLine('wait-synced: bad limit, count, wait or period.'); return 2 }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $streak = 0
    while ($true) {
        $ok = $true
        foreach ($r in $ReferenceA, $ReferenceB) {
            $s = @(Get-OffsetSamples -Reference $r -Count 1 -PeriodSeconds 1 -W32tmPath $W32tmPath)
            if ($s.Count -ne 1 -or $s[0].Kind -ne 'Data' -or [math]::Abs($s[0].OffsetS) * 1000.0 -ge $LimitMs) { $ok = $false }
        }
        if ($ok) { $streak++ } else { $streak = 0 }
        if ($streak -ge $Consecutive) { Write-Host "synced: $Consecutive consecutive rounds below $LimitMs ms on both references after $([int]$sw.Elapsed.TotalSeconds) s"; return 0 }
        if ($sw.Elapsed.TotalSeconds -ge $MaxWaitSeconds) {
            Write-Host "start not clean: not synced after $MaxWaitSeconds s. Label the next block with the suffix -unclean."
            return 3
        }
        Start-Sleep -Seconds $PeriodSeconds
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-WaitSynced -ReferenceA $ReferenceA -ReferenceB $ReferenceB -LimitMs $LimitMs -Consecutive $Consecutive -MaxWaitSeconds $MaxWaitSeconds -PeriodSeconds $PeriodSeconds -W32tmPath $W32tmPath)
}
