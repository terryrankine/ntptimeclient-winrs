<#
.SYNOPSIS
  Samples the clock offset to one NTP reference with w32tm /stripchart and writes a CSV.

.DESCRIPTION
  Read only. Needs no admin rights. Changes no system state. It runs
  `w32tm /stripchart /computer:<ref> /samples:N /period:S /dataonly /rdtsc`
  and parses each line. A failed sample is never dropped. It becomes a row with an
  error text and it counts toward the error rate.

  CSV columns: utc_iso, contender, case, reference, offset_s, delay_s, error, round, block
  Offset is as w32tm reports it: seconds, between this computer and the reference,
  seen through the network path. A POSITIVE offset means the reference is ahead, so the
  local clock is slow. It is not true UTC error.

  Priority: the sampler raises its OWN process, and the w32tm child it starts, to
  AboveNormal so that load on the host skews the timing less. No other process is touched.
  A failure to do so is a warning, not an error.

  Lines before the first data row that the parser does not know (for example a
  non-English "Tracking" line) are ignored and counted as preamble_lines. Known English
  preamble lines are not counted. After the first
  data row an unknown line becomes an error row.

  Exit codes: 0 finished, 1 run failed (w32tm missing or every sample failed), 2 bad input.

.EXAMPLE
  .\measure-offset.ps1 -Reference <REF_IP> -Contender w32time-default -Case idle -Round 1 -Block B1 -Samples 180 -PeriodSeconds 10 -OutPath .\out\r1-B1-w32time-default-idle-refA.csv
#>
[CmdletBinding()]
param(
    [string]$Reference,
    [string]$Contender,
    [string]$Case,
    [int]$Round = 0,
    [string]$Block = '',
    [int]$Samples = 0,
    [int]$PeriodSeconds = 0,
    [string]$OutPath,
    [switch]$Plain,
    [switch]$AllowPool,
    [string]$W32tmPath = ''   # tests only: a stand-in for w32tm.exe
)

Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'offset-lib.ps1')

if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-Measure -Reference $Reference -Contender $Contender -Case $Case -Round $Round -Block $Block -Samples $Samples -PeriodSeconds $PeriodSeconds -OutPath $OutPath -Plain ([bool]$Plain) -AllowPool ([bool]$AllowPool) -W32tmPath $W32tmPath)
}
