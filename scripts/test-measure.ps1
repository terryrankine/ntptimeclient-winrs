<#
  Tests for measure-offset.ps1 and summarise-offset.ps1. No network, no system change.
  Run: powershell -NoProfile -File scripts\test-measure.ps1   (exit 0 pass, 1 fail)
  Plain checks are used because the installed Pester is 3.4.0.
  Expected values in the summary tests were worked out by hand. The working is in the comments.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'offset-lib.ps1')
. (Join-Path $here 'summarise-offset.ps1')

# The helpers that change the machine must refuse without this variable. Clear it for the whole run.
$savedGuard = [Environment]::GetEnvironmentVariable('MEASURE_TEST_MACHINE', 'Process')
[Environment]::SetEnvironmentVariable('MEASURE_TEST_MACHINE', $null, 'Process')
$script:fail = 0
$script:pass = 0
function Check([string]$Name, $Actual, $Expected) {
    if ("$Actual" -ceq "$Expected") { $script:pass++ }
    else { $script:fail++; Write-Host "FAIL $Name`n  expected: $Expected`n  actual:   $Actual" }
}
function CheckNear([string]$Name, $Actual, [double]$Expected, [double]$Tol) {
    if ($null -ne $Actual -and [math]::Abs([double]$Actual - $Expected) -le $Tol) { $script:pass++ }
    else { $script:fail++; Write-Host "FAIL $Name`n  expected: $Expected +- $Tol`n  actual:   $Actual" }
}

# --- parser: canned lines. Several come from real w32tm output on 2026-11-10 ---
$cases = @(
    @{ n = 'plain positive'; l = '11:39:29, +00.0021951s'; kind = 'Data'; off = 0.0021951 },
    @{ n = 'plain negative'; l = '11:39:35, -00.0041153s'; kind = 'Data'; off = -0.0041153 },
    @{ n = 'plain timeout'; l = '18:51:59, error: 0x800705B4'; kind = 'Error'; err = 'w32tm error 0x800705B4' },
    @{ n = 'plain socket error'; l = '11:44:13, error: 0x80072733'; kind = 'Error'; err = 'w32tm error 0x80072733' },
    @{ n = 'plain comma decimal'; l = '11:39:29, +00,0021951s'; kind = 'Data'; off = 0.0021951 },
    @{ n = 'plain 12h clock with PM'; l = '6:51:59 PM, +00.0100000s'; kind = 'Data'; off = 0.01 },
    @{ n = 'plain dotted time'; l = '18.51.59, -00,0500000s'; kind = 'Data'; off = -0.05 },
    @{ n = 'plain unicode minus'; l = ('18:51:59, ' + [char]0x2212 + '00.0030000s'); kind = 'Data'; off = -0.003 },
    @{ n = 'plain d suffix flagged'; l = '18:51:59, +00.0000100d'; kind = 'Error'; err = 'unit d read as days (unverified)'; off = 0.864 },
    @{ n = 'rdtsc good'; l = '150315589625024, 150315606087988, 134387814648199712, +00.0039764, +00.1705322'; kind = 'Data'; off = 0.1705322; delay = 0.0039764 },
    @{ n = 'rdtsc negative offset'; l = '150319334177355, 150319378556113, 134387814658320078, +00.0113711, -00.0004463'; kind = 'Data'; off = -0.0004463; delay = 0.0113711 },
    @{ n = 'rdtsc timeout'; l = '150500509834930, 150504227076634, 134387815147981814, error: 0x800705B4'; kind = 'Error'; err = 'w32tm error 0x800705B4' },
    @{ n = 'rdtsc comma decimal'; l = '150315589625024, 150315606087988, 134387814648199712, +00,0039764, +00,1705322'; kind = 'Data'; off = 0.1705322; delay = 0.0039764 },
    @{ n = 'rdtsc missing offset'; l = '150315589625024, 150315606087988, 134387814648199712, +00.0039764'; kind = 'Error'; err = 'unparsed line: 150315589625024, 150315606087988, 134387814648199712, +00.0039764' },
    @{ n = 'tracking line'; l = 'Tracking time.example [192.0.2.7:123].'; kind = 'Preamble'; ip = '192.0.2.7' },
    @{ n = 'collecting line'; l = 'Collecting 3 samples.'; kind = 'Preamble' },
    @{ n = 'current time line'; l = 'The current time is 10/11/2026 6:51:04 PM.'; kind = 'Preamble' },
    @{ n = 'rdtsc header'; l = 'RdtscStart, RdtscEnd, FileTime, RoundtripDelay, NtpOffset'; kind = 'Preamble' },
    @{ n = 'blank'; l = ''; kind = 'Blank' },
    @{ n = 'fatal'; l = 'The following error occurred: No such host is known. (0x80072AF9)'; kind = 'Fatal' },
    @{ n = 'garbage is kept as error'; l = 'something unexpected'; kind = 'Unknown'; err = 'unparsed line: something unexpected' }
)
foreach ($c in $cases) {
    $p = ConvertFrom-StripchartLine -Line $c.l
    Check "$($c.n) kind" $p.Kind $c.kind
    if ($c.ContainsKey('off')) { CheckNear "$($c.n) offset" $p.OffsetS $c.off 1e-9 }
    if ($c.ContainsKey('delay')) { CheckNear "$($c.n) delay" $p.DelayS $c.delay 1e-9 }
    if ($c.ContainsKey('err')) { Check "$($c.n) error" $p.Error $c.err }
    if ($c.ContainsKey('ip')) { Check "$($c.n) ip" $p.Ip $c.ip }
}
# 134387814648199712 is 2026-11-10 10:51:04.8 UTC (18:51 local on a UTC+8 machine)
$p = ConvertFrom-StripchartLine -Line '150315589625024, 150315606087988, 134387814648199712, +00.0039764, +00.1705322'
Check 'rdtsc FileTime to UTC' $p.FileTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss', [cultureinfo]::InvariantCulture) '2026-11-10T10:51:04'

# --- CSV row formatting ---
$utc = [DateTime]::SpecifyKind([DateTime]'2026-11-10 08:51:04.8', 'Utc')
Check 'row good' (Format-SampleRow -Utc $utc -Contender 'svc' -Case 'idle' -Reference '1.2.3.4' -OffsetS 0.0021951 -DelayS 0.004 -Err '' -Round 2 -Block 'B3') '2026-11-10T08:51:04.800Z,svc,idle,1.2.3.4,0.0021951,0.004,,2,B3'
Check 'row error' (Format-SampleRow -Utc $utc -Contender 'svc' -Case 'idle' -Reference '1.2.3.4' -OffsetS $null -DelayS $null -Err 'w32tm error 0x800705B4' -Round 1) '2026-11-10T08:51:04.800Z,svc,idle,1.2.3.4,,,w32tm error 0x800705B4,1,'
Check 'row quotes comma' (Format-SampleRow -Utc $utc -Contender 'svc' -Case 'idle' -Reference 'r' -OffsetS $null -DelayS $null -Err 'a,b "c"' -Round 1) '2026-11-10T08:51:04.800Z,svc,idle,r,,,"a,b ""c""",1,'
$old = [System.Threading.Thread]::CurrentThread.CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentCulture = [cultureinfo]'de-DE'
Check 'row under de-DE' (Format-SampleRow -Utc $utc -Contender 'c' -Case 'k' -Reference 'r' -OffsetS 0.5 -DelayS $null -Err '' -Round 1) '2026-11-10T08:51:04.800Z,c,k,r,0.5,,,1,'
[System.Threading.Thread]::CurrentThread.CurrentCulture = $old

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("measure-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$ps = (Get-Process -Id $PID).Path
# Child runs. Windows PowerShell 5.1 turns native stderr into an error under Stop, so relax it here.
function Child([string[]]$ArgList) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $o = & $ps -NoProfile -File @ArgList 2>&1 | ForEach-Object { "$_" } | Out-String; @{ Out = $o; Code = $LASTEXITCODE } }
    finally { $ErrorActionPreference = $old }
}
try {
    # --- input validation ---
    $ok = Join-Path $tmp 'a.csv'
    $v = { param($r, $c, $k, $rd, $bl, $s, $pd, $o, $pool) (Test-MeasureInput -Reference $r -Contender $c -Case $k -Round $rd -Block $bl -Samples $s -PeriodSeconds $pd -OutPath $o -AllowPool $pool).Count }
    Check 'valid input' (& $v '192.0.2.7' 'svc' 'idle' 1 'B1' 5 2 $ok $false) 0
    Check 'pool refused' (& $v 'pool.ntp.org' 'svc' 'idle' 1 '' 5 2 $ok $false) 1
    Check 'pool allowed' (& $v 'au.pool.ntp.org' 'svc' 'idle' 1 '' 5 2 $ok $true) 0
    Check 'bad reference chars' (& $v 'a b;calc' 'svc' 'idle' 1 '' 5 2 $ok $false) 1
    Check 'bad label' (& $v '1.2.3.4' 'a,b' 'idle' 1 '' 5 2 $ok $false) 1
    Check 'round 0 refused' (& $v '1.2.3.4' 'svc' 'idle' 0 '' 5 2 $ok $false) 1
    Check 'bad block' (& $v '1.2.3.4' 'svc' 'idle' 1 'a,b' 5 2 $ok $false) 1
    Check 'zero samples' (& $v '1.2.3.4' 'svc' 'idle' 1 '' 0 2 $ok $false) 1
    Check 'zero period' (& $v '1.2.3.4' 'svc' 'idle' 1 '' 5 0 $ok $false) 1
    Check 'missing folder' (& $v '1.2.3.4' 'svc' 'idle' 1 '' 5 2 (Join-Path $tmp 'no\x.csv') $false) 1
    Set-Content -LiteralPath $ok -Value 'keep'
    Check 'existing file refused' (& $v '1.2.3.4' 'svc' 'idle' 1 '' 5 2 $ok $false) 1

    $c = Child @((Join-Path $here 'measure-offset.ps1'), '-Reference', '1.2.3.4', '-Contender', 'svc', '-Case', 'idle', '-Round', '1', '-Samples', '0', '-PeriodSeconds', '2', '-OutPath', (Join-Path $tmp 'b.csv'))
    Check 'exit 2 on bad samples' $c.Code 2
    $c = Child @((Join-Path $here 'measure-offset.ps1'), '-Reference', '1.2.3.4', '-Contender', 'svc', '-Case', 'idle', '-Round', '1', '-Samples', '3', '-PeriodSeconds', '2', '-OutPath', $ok)
    Check 'exit 2 on existing csv' $c.Code 2
    Check 'existing csv untouched' ((Get-Content -LiteralPath $ok -Raw).Trim()) 'keep'
    $c = Child @((Join-Path $here 'summarise-offset.ps1'))
    Check 'summarise exit 2 without path' $c.Code 2

    # --- Invoke-Measure with a stand-in for w32tm: shortfall, fatal, non-English preamble ---
    function New-Fake([string]$Name, [string[]]$Lines, [int]$Code) {
        $f = Join-Path $tmp "$Name.cmd"
        $body = @('@echo off') + ($Lines | ForEach-Object { if ($_ -eq '') { 'echo.' } else { "echo $_" } }) + "exit /b $Code"
        Set-Content -LiteralPath $f -Value $body -Encoding ASCII
        $f
    }
    function Run-Fake([string]$Name, [string[]]$Lines, [int]$Code, [int]$Samples) {
        $fake = New-Fake $Name $Lines $Code
        $out = Join-Path $tmp "$Name.csv"
        $rc = Invoke-Measure -Reference '192.0.2.7' -Contender 'svc' -Case 'idle' -Round 1 -Block 'B1' -Samples $Samples -PeriodSeconds 1 -OutPath $out -Plain $false -AllowPool $false -W32tmPath $fake 2>$null
        @{ Rc = $rc; Run = $script:LastRun; Rows = @(Import-Csv -LiteralPath $out) }
    }
    $pre = @('Tracking 192.0.2.7 [192.0.2.7:123].', 'Collecting 2 samples.', 'The current time is 10/11/2026 6:51:04 PM.', 'RdtscStart, RdtscEnd, FileTime, RoundtripDelay, NtpOffset')
    $d1 = '150315589625024, 150315606087988, 134387814648199712, +00.0039764, +00.1705322'
    $d2 = '150319334177355, 150319378556113, 134387814658320078, +00.0113711, -00.0004463'

    $r = Run-Fake 'good' ($pre + $d1 + $d2) 0 2
    Check 'good rc' $r.Rc 0
    Check 'good rows' $r.Rows.Count 2
    Check 'good errors' $r.Run.Errors 0
    Check 'good preamble_lines' $r.Run.PreambleLines 0
    Check 'good ip' $r.Run.Ip '192.0.2.7'
    Check 'good round column' $r.Rows[0].round '1'
    Check 'good block column' $r.Rows[0].block 'B1'
    Check 'good second offset' $r.Rows[1].offset_s '-0.0004463'

    $r = Run-Fake 'shortfall' ($pre + $d1) 0 3
    Check 'shortfall rc' $r.Rc 0
    Check 'shortfall rows' $r.Rows.Count 3
    Check 'shortfall errors' $r.Run.Errors 2
    Check 'shortfall text' ($r.Rows[2].error -like 'missing sample*') $true
    Check 'shortfall offset empty' $r.Rows[2].offset_s ''

    $r = Run-Fake 'fatal' @('The following error occurred: No such host is known. (0x80072AF9)') 1 2
    Check 'fatal rc' $r.Rc 1
    Check 'fatal rows' $r.Rows.Count 2
    Check 'fatal errors' $r.Run.Errors 2
    Check 'fatal text' ($r.Rows[0].error -like '*No such host*') $true

    $de = @('Verfolge 192.0.2.7 [192.0.2.7:123].', 'Sammle 2 Stichproben.', 'Die aktuelle Zeit ist 10.11.2026 18:51:04.', 'RdtscStart, RdtscEnd, FileTime, RoundtripDelay, NtpOffset')
    $r = Run-Fake 'german' ($de + $d1 + $d2) 0 2
    Check 'non-English preamble rc' $r.Rc 0
    Check 'non-English preamble rows' $r.Rows.Count 2
    Check 'non-English preamble errors' $r.Run.Errors 0
    Check 'non-English preamble_lines counted' $r.Run.PreambleLines 3

    $r = Run-Fake 'germanfatal' @('Fehler aufgetreten: Host unbekannt (0x80072AF9)') 1 2
    Check 'non-English fatal rc' $r.Rc 1
    Check 'non-English fatal counted' $r.Run.PreambleLines 1
    Check 'non-English fatal text keeps the line' ($r.Rows[0].error -like 'w32tm exited 1*Fehler aufgetreten*') $true

    $r = Run-Fake 'garbage' ($pre + $d1 + 'garbage after data') 0 2
    Check 'garbage after data rows' $r.Rows.Count 2
    Check 'garbage after data errors' $r.Run.Errors 1
    Check 'garbage after data text' $r.Rows[1].error 'unparsed line: garbage after data'
    Check 'garbage after data not preamble' $r.Run.PreambleLines 0


    # --- summary helpers ---
    $hdr = 'utc_iso,contender,case,reference,offset_s,delay_s,error,round,block'
    $base = [DateTime]::SpecifyKind([DateTime]'2026-11-10 00:00:00', 'Utc')
    function CsvRow([double]$T, [string]$C, [string]$Case, [string]$Ref, $Off, $Delay, [string]$Err, [int]$Round, [string]$Block) {
        $ts = $base.AddSeconds($T).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [cultureinfo]::InvariantCulture)
        $o = if ($null -eq $Off) { '' } else { ([double]$Off).ToString('R', [cultureinfo]::InvariantCulture) }
        $d = if ($null -eq $Delay) { '' } else { ([double]$Delay).ToString('R', [cultureinfo]::InvariantCulture) }
        "$ts,$C,$Case,$Ref,$o,$d,$Err,$Round,$Block"
    }
    function Load([string[]]$Lines) {
        $f = Join-Path $tmp ([guid]::NewGuid().ToString('N') + '.csv')
        Set-Content -LiteralPath $f -Value (@($hdr) + $Lines)
        @(ConvertTo-TypedRows -Csv @(Import-Csv -LiteralPath $f))
    }
    function Flat([double]$T0, [string]$C, [string]$Case, [string]$Ref, [double[]]$Offsets, [double]$Delay, [int]$Round, [string]$Block, [double]$Step = 60) {
        $i = 0; foreach ($o in $Offsets) { CsvRow ($T0 + $i * $Step) $C $Case $Ref $o $Delay '' $Round $Block; $i++ }
    }
    # One block per round, three rows, constant absolute offset with alternating sign.
    function Rounds([string]$C, [double[]]$Meds, [string]$Ref = 'r', [string]$Case = 'idle', [string]$Block = 'B1') {
        for ($rd = 1; $rd -le $Meds.Count; $rd++) {
            $m = $Meds[$rd - 1] / 1000.0
            Flat (($rd - 1) * 10000) $C $Case $Ref @($m, (-$m), $m) 0.004 $rd $Block
        }
    }
    function Verdict($rows, [string]$Name = 'service', [string]$Case = 'idle', [string]$Metric = 'abs', $events = @()) {
        Get-Verdict -Rows $rows -Events $events -Case $Case -Ref 'r' -Name $Name -Baseline 'w32time-default' -Metric $Metric
    }

    # median and percentile maths
    Check 'median odd' (Get-Median @(3, 1, 2)) 2
    Check 'median even is interpolated' (Get-Median @(1, 2, 3, 4)) 2.5
    Check 'nearest rank p50 of 1..4 is 2 (the bias the median avoids)' (Get-Percentile @(1, 2, 3, 4) 50) 2
    Check 'median with one infinity (middle pair)' (Get-Median @(5, 6, $script:Inf, $script:Inf)) 'Infinity'
    Check 'median with one infinity (3 of 4 finite)' (Get-Median @(5, 6, 7, $script:Inf)) 6.5

    # 11 samples 1..11 ms at 1 s steps, delay 5 ms, plus one error row.
    # median 6, p5 rank 1 -> 1, p95 rank 11 -> 11, p99 -> 11, mean 6, max 11. Slope 1000 ppm. Error rate 1 of 12 = 8.3 %.
    $ls = @()
    for ($i = 0; $i -lt 11; $i++) { $ls += (CsvRow $i 'svc' 'idle' 'r' (($i + 1) / 1000.0) 0.005 '' 1 'B1') }
    $ls += (CsvRow 11 'svc' 'idle' 'r' $null $null 'w32tm error 0x800705B4' 1 'B1')
    $b = @(Get-BlockTable -Rows (Load $ls) -Drop 0 -Which 'primary')
    Check 'known: one block row' $b.Count 1
    Check 'known: samples' $b[0].samples 12
    Check 'known: errors' $b[0].errors 1
    CheckNear 'known: error pct' $b[0].error_pct 8.3 0.05
    CheckNear 'known: median' $b[0].median_ms 6 1e-6
    CheckNear 'known: p5' $b[0].p5_ms 1 1e-6
    CheckNear 'known: p95' $b[0].p95_ms 11 1e-6
    CheckNear 'known: p99' $b[0].p99_ms 11 1e-6
    CheckNear 'known: mean' $b[0].mean_ms 6 1e-6
    CheckNear 'known: max' $b[0].max_ms 11 1e-6
    CheckNear 'known: delay median' $b[0].delay_median_ms 5 1e-6
    CheckNear 'known: delay p95' $b[0].delay_p95_ms 5 1e-6
    CheckNear 'known: slope ppm' $b[0].slope_ppm 1000 0.01

    # Delays 1..20 ms. Median (10+11)/2 = 10.5. p95 = rank ceil(19) = 19.
    $ls = @(); for ($i = 1; $i -le 20; $i++) { $ls += (CsvRow $i 'svc' 'idle' 'r' 0.001 ($i / 1000.0) '' 1 'B1') }
    $b = @(Get-BlockTable -Rows (Load $ls) -Drop 0 -Which 'primary')
    CheckNear 'delay median even n' $b[0].delay_median_ms 10.5 1e-6
    CheckNear 'delay p95' $b[0].delay_p95_ms 19 1e-6

    # Edge cases: single row, all errors.
    $b = @(Get-BlockTable -Rows (Load @((CsvRow 0 'svc' 'idle' 'r' 0.004 0.005 '' 1 'B1'))) -Drop 0 -Which 'primary')
    Check 'single row: samples' $b[0].samples 1
    CheckNear 'single row: median' $b[0].median_ms 4 1e-9
    CheckNear 'single row: p99' $b[0].p99_ms 4 1e-9
    Check 'single row: no slope' ($null -eq $b[0].slope_ppm) $true
    $b = @(Get-BlockTable -Rows (Load @((CsvRow 0 'svc' 'idle' 'r' $null $null 'w32tm error 0x800705B4' 1 'B1'), (CsvRow 1 'svc' 'idle' 'r' $null $null 'w32tm error 0x800705B4' 1 'B1'))) -Drop 0 -Which 'primary')
    Check 'all errors: error pct' $b[0].error_pct 100
    Check 'all errors: no median' ($null -eq $b[0].median_ms) $true
    Check 'all errors: no slope' ($null -eq $b[0].slope_ppm) $true

    # Two flat rounds six hours apart: 1 ms then 5 ms. Per block slope must be 0 and never mixed.
    $ls = @((Flat 0 'svc' 'idle' 'r' @(0.001, 0.001, 0.001, 0.001, 0.001) 0.004 1 'B1') + (Flat 21600 'svc' 'idle' 'r' @(0.005, 0.005, 0.005, 0.005, 0.005) 0.004 2 'B1'))
    $rep = Get-OffsetReport -Rows (Load $ls)
    Check 'two flat rounds: two block rows' $rep.Blocks.Count 2
    CheckNear 'two flat rounds: round 1 slope' $rep.Blocks[0].slope_ppm 0 1e-9
    CheckNear 'two flat rounds: round 2 slope' $rep.Blocks[1].slope_ppm 0 1e-9
    CheckNear 'two flat rounds: pooled median' $rep.Pooled[0].median_ms 3 1e-6
    CheckNear 'two flat rounds: round median min' $rep.Pooled[0].round_median_min_ms 1 1e-6
    CheckNear 'two flat rounds: round median max' $rep.Pooled[0].round_median_max_ms 5 1e-6
    CheckNear 'two flat rounds: median of block slopes' $rep.Pooled[0].slope_ppm_median_of_blocks 0 1e-9
    Check 'single reference data: nothing flagged' @($rep.Flags).Count 0

    # Wash-out: t = 0..9 s. First 3 rows are 100 ms, the rest 1 ms. Drop 3 s.
    $ls = @(); for ($i = 0; $i -lt 10; $i++) { $ls += (CsvRow $i 'svc' 'idle' 'r' $(if ($i -lt 3) { 0.1 } else { 0.001 }) 0.004 '' 1 'B1') }
    $rows = Load $ls
    $b = @(Get-BlockTable -Rows $rows -Drop 3 -Which 'primary')
    Check 'washout: primary samples' $b[0].samples 7
    Check 'washout: dropped count' $b[0].dropped 3
    CheckNear 'washout: primary median' $b[0].median_ms 1 1e-6
    $b = @(Get-BlockTable -Rows $rows -Drop 3 -Which 'washout')
    Check 'washout appendix: samples' $b[0].samples 3
    CheckNear 'washout appendix: median' $b[0].median_ms 100 1e-6
    # Event and long cases keep every row even when a drop is asked for. Their slope is not printed.
    $ls = @(); for ($i = 0; $i -lt 10; $i++) { $ls += (CsvRow $i 'svc' 'sleep' 'r' (0.001 * ($i + 1)) 0.004 '' 1 'B1') }
    $b = @(Get-BlockTable -Rows (Load $ls) -Drop 600 -Which 'primary')
    Check 'sleep case: nothing dropped' $b[0].samples 10
    Check 'sleep case: dropped 0' $b[0].dropped 0
    Check 'sleep case: slope not printed' ($null -eq $b[0].slope_ppm) $true

    # --- Verdicts. 4 rounds of 3 rows. Per-round medians (ms).
    #   default 4,5,6,5   default-aa 4.5,5,5,5   service 2,2.5,3,2.5
    # Pooled default 5, service 2.5, diff -2.5. Noise floor max(0.5,0,1,0) = 1. Threshold max(1, 0.2*5) = 1.
    # Per-round diffs -2 / -2.5 / -3 / -2.5. Four of four negative. p99 service 3 against default 6.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5)) + (Rounds 'service' @(2, 2.5, 3, 2.5)))
    $rows = Load $ls
    $v = Verdict $rows
    CheckNear 'verdict: diff' $v.diff -2.5 1e-6
    Check 'verdict: per round diffs' $v.per_round_diff '-2 / -2.5 / -3 / -2.5'
    Check 'verdict: same sign' $v.same_sign_rounds '4 of 4'
    CheckNear 'verdict: threshold' $v.threshold 1 1e-6
    CheckNear 'verdict: A/A noise floor' $v.aa_noise_floor 1 1e-6
    Check 'verdict: better' $v.verdict 'better'
    Check 'verdict: reason has numbers' ($v.reason -like '*difference -2.5 ms*noise floor 1 ms*4 of 4 rounds*') $true
    $cmp = @(Get-ComparisonTable -Rows $rows -Events @() -Primary '' -Baseline 'w32time-default')
    Check 'comparison: A/A twin labelled' (@($cmp | Where-Object { $_.contender -eq 'w32time-default-aa' })[0].verdict) 'A/A control'
    CheckNear 'comparison: A/A pooled diff is 0' (@($cmp | Where-Object { $_.contender -eq 'w32time-default-aa' })[0].diff) 0 1e-6

    # No A/A twin: no verdict, even when the difference is large.
    $rows = Load @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'service' @(2, 2.5, 3, 2.5)))
    $v = Verdict $rows
    Check 'no twin: cannot call' $v.verdict 'no noise floor, cannot call'
    Check 'no twin: reason in words' ($v.reason -like '*no*-aa twin*') $true
    # Baseline missing.
    $v = Verdict (Load @((Rounds 'service' @(2, 2.5, 3, 2.5))))
    Check 'baseline missing' $v.verdict '(baseline missing)'
    Check 'baseline missing: explains' ($v.reason -like "*baseline contender 'w32time-default' has no data*") $true
    # Contender missing.
    Check 'contender missing' (Verdict (Load @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4, 5, 6, 5))))).verdict 'no data'
    # Two rounds only.
    $v = Verdict (Load @((Rounds 'w32time-default' @(4, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5)) + (Rounds 'service' @(2, 2.5))))
    Check 'two rounds: not enough rounds' $v.verdict 'not enough rounds'
    # Difference below the threshold.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5)) + (Rounds 'service' @(4.8, 4.8, 4.8, 4.8)))
    Check 'small difference' (Verdict (Load $ls)).verdict 'no meaningful difference'
    # Difference smaller than the noise floor: default vs twin gap 3 ms, service 2.5 ms better.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(7, 5, 6, 5)) + (Rounds 'service' @(2, 2.5, 3, 2.5)))
    $v = Verdict (Load $ls)
    CheckNear 'noise floor 3' $v.aa_noise_floor 3 1e-6
    Check 'difference not above the noise floor' $v.verdict 'no meaningful difference'
    # Mixed signs: service 2,2.5,7,2.5. Diffs -2 / -2.5 / +1 / -2.5. Three of four negative.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5)) + (Rounds 'service' @(2, 2.5, 7, 2.5)))
    $rows = Load $ls
    $v = Verdict $rows
    Check 'mixed signs: three of four' $v.same_sign_rounds '3 of 4'
    Check 'mixed signs: all rounds needed' $v.verdict 'no meaningful difference'
    $MinSignRounds = 3
    Check 'mixed signs: 3 rounds enough when asked' (Verdict $rows).verdict 'better'
    $MinSignRounds = 0
    # Worse: service 8 ms flat against default median 5.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5)) + (Rounds 'service' @(8, 8, 8, 8)))
    Check 'worse' (Verdict (Load $ls)).verdict 'worse'
    # Mixed by p99: service rows 2, 2, 20 ms in every round. Median 2 (better) but p99 20 against 6.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5)))
    for ($rd = 1; $rd -le 4; $rd++) { $ls += (Flat (($rd - 1) * 10000) 'service' 'idle' 'r' @(0.002, 0.002, 0.020) 0.004 $rd 'B1') }
    $v = Verdict (Load $ls)
    Check 'p99 condition: mixed' $v.verdict 'mixed'
    Check 'p99 condition: reason' ($v.reason -like '*p99 is worse by 14 ms*') $true
    # Mixed by error rate: one error row in every service block (1 of 4 rows = 25 %), default none.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5)))
    for ($rd = 1; $rd -le 4; $rd++) {
        $m = @(2, 2.5, 3, 2.5)[$rd - 1] / 1000.0
        $ls += (Flat (($rd - 1) * 10000) 'service' 'idle' 'r' @($m, $m, $m) 0.004 $rd 'B1')
        $ls += (CsvRow (($rd - 1) * 10000 + 200) 'service' 'idle' 'r' $null $null 'w32tm error 0x800705B4' $rd 'B1')
    }
    $v = Verdict (Load $ls)
    Check 'error rate condition: mixed' $v.verdict 'mixed'
    Check 'error rate condition: reason' ($v.reason -like '*error rate is higher by 25 points*') $true
    # Load rule: service has 25 % errors in idle AND in load, the default none. Excess over the baseline rise is 0.
    $ls = @()
    foreach ($case in 'idle', 'load') {
        $ls += (Rounds 'w32time-default' @(4, 5, 6, 5) 'r' $case) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5) 'r' $case)
        for ($rd = 1; $rd -le 4; $rd++) {
            $m = @(2, 2.5, 3, 2.5)[$rd - 1] / 1000.0
            $ls += (Flat (($rd - 1) * 10000) 'service' $case 'r' @($m, $m, $m) 0.004 $rd 'B1')
            $ls += (CsvRow (($rd - 1) * 10000 + 200) 'service' $case 'r' $null $null 'w32tm error 0x800705B4' $rd 'B1')
        }
    }
    $rows = Load $ls
    Check 'load rule: plain idle comparison is mixed' (Verdict $rows 'service' 'idle').verdict 'mixed'
    $v = Verdict $rows 'service' 'load'
    Check 'load rule: rise equal to the baseline rise is a win' $v.verdict 'better'

    # --- Recovery summary. Unrecovered events are infinity, never dropped.
    function Ev([string]$C, [double[]]$Vals, [string]$Case = 'disturb2s', [string]$Type = 'step') {
        for ($i = 0; $i -lt $Vals.Count; $i++) { [pscustomobject]@{ contender = $C; case = $Case; reference = 'r'; round = ($i + 1); block = 'B1'; event = $Type; event_utc = ''; recovery_s = (R3 $Vals[$i]); recovery_value = [double]$Vals[$i] } }
    }
    $inf = $script:Inf
    $rs = @(Get-RecoverySummary @(Ev 'a' @(3, 5, 7, 9)))
    Check 'summary all recovered: events' $rs[0].events 4
    Check 'summary all recovered: recovered' $rs[0].recovered 4
    Check 'summary all recovered: fraction' $rs[0].fraction_recovered 1
    CheckNear 'summary all recovered: median' $rs[0].median_s 6 1e-9
    CheckNear 'summary all recovered: worst' $rs[0].worst_s 9 1e-9
    $rs = @(Get-RecoverySummary @(Ev 'a' @(3, 5, 7, $inf)))
    Check 'summary 3 of 4: not recovered' $rs[0].not_recovered 1
    CheckNear 'summary 3 of 4: finite median' $rs[0].median_s 6 1e-9
    Check 'summary 3 of 4: worst is not recovered' $rs[0].worst_s 'not recovered'
    $rs = @(Get-RecoverySummary @(Ev 'a' @(3, 5, $inf, $inf)))
    Check 'summary 2 of 4: median not recovered' $rs[0].median_s 'not recovered'
    Check 'summary 2 of 4: fraction' $rs[0].fraction_recovered 0.5
    $rs = @(Get-RecoverySummary @(Ev 'a' @($inf, $inf, $inf)))
    Check 'summary none recovered: median' $rs[0].median_s 'not recovered'
    Check 'summary none recovered: fraction' $rs[0].fraction_recovered 0
    $rs = @(Get-RecoverySummary @(Ev 'a' @(4)))
    Check 'summary single event: events' $rs[0].events 1
    CheckNear 'summary single event: median' $rs[0].median_s 4 1e-9
    $rs = @(Get-RecoverySummary @(Ev 'a' @($inf)))
    Check 'summary single unrecovered' $rs[0].median_s 'not recovered'

    # --- Recovery verdicts (P4 and P5 use the same function). Events built by hand, 3 rows per block at 1 s for the period.
    function EvRows([string[]]$Names, [string]$Case) {
        foreach ($n in $Names) { for ($rd = 1; $rd -le 4; $rd++) { Flat ($rd * 1000) $n $Case 'r' @(0.001, 0.001, 0.001) 0.004 $rd 'B1' 1 } }
    }
    $names = 'w32time-default', 'w32time-default-aa', 'service'
    $rows = Load @(EvRows $names 'sleep')
    # default 10,12,14,12 (pooled 12). aa 10.5,12,13,12 (noise floor 1). service 5,6,7,6 (pooled 6). Diff -6. Threshold max(2.4, 2 periods = 2) = 2.4.
    $ev = @((Ev 'w32time-default' @(10, 12, 14, 12) 'sleep' 'gap') + (Ev 'w32time-default-aa' @(10.5, 12, 13, 12) 'sleep' 'gap') + (Ev 'service' @(5, 6, 7, 6) 'sleep' 'gap'))
    $v = Verdict $rows 'service' 'sleep' 'recovery' $ev
    CheckNear 'recovery verdict: diff' $v.diff -6 1e-9
    CheckNear 'recovery verdict: threshold' $v.threshold 2.4 1e-9
    CheckNear 'recovery verdict: noise floor' $v.aa_noise_floor 1 1e-9
    Check 'recovery verdict: better' $v.verdict 'better'
    # Service fails to recover in 1 of 4 events: a loss even though the median is finite (6.5).
    $ev = @((Ev 'w32time-default' @(10, 12, 14, 12) 'sleep' 'gap') + (Ev 'w32time-default-aa' @(10.5, 12, 13, 12) 'sleep' 'gap') + (Ev 'service' @(5, 6, 7, $inf) 'sleep' 'gap'))
    $v = Verdict $rows 'service' 'sleep' 'recovery' $ev
    Check 'unrecovered event is a loss' $v.verdict 'worse'
    Check 'unrecovered event: reason' ($v.reason -like '*did not recover in 1 of 4 events*') $true
    # Both fail once: not a loss for that reason. Per-round diffs skip the inf against inf round.
    $ev = @((Ev 'w32time-default' @(10, 12, 14, $inf) 'sleep' 'gap') + (Ev 'w32time-default-aa' @(10.5, 12, 13, $inf) 'sleep' 'gap') + (Ev 'service' @(5, 6, 7, $inf) 'sleep' 'gap'))
    $v = Verdict $rows 'service' 'sleep' 'recovery' $ev
    Check 'equal unrecovered counts: compared on the rest' $v.verdict 'better'
    Check 'equal unrecovered counts: three usable rounds' $v.same_sign_rounds '3 of 3'
    # No twin for recovery.
    $ev = @((Ev 'w32time-default' @(10, 12, 14, 12) 'sleep' 'gap') + (Ev 'service' @(5, 6, 7, 6) 'sleep' 'gap'))
    Check 'recovery without twin' (Verdict $rows 'service' 'sleep' 'recovery' $ev).verdict 'no noise floor, cannot call'

    # --- Primary lines through the whole script. P1 better, P2 to P5 have no data.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5)) + (Rounds 'service' @(2, 2.5, 3, 2.5)))
    $f = Join-Path $tmp 'primary.csv'
    Set-Content -LiteralPath $f -Value (@($hdr) + $ls)
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $f)
    Check 'primary: exit 0' $c.Code 0
    Check 'primary: P1 line' ($c.Out -match 'P1 idle, median absolute offset: BETTER\. pooled 2\.5 ms') $true
    Check 'primary: P2 no data' ($c.Out -match 'P2 load, median absolute offset: NO DATA') $true
    Check 'primary: five lines' (@([regex]::Matches($c.Out, '(?m)^P[1-5] ')).Count) 5
    Check 'primary: exploratory label' ($c.Out -match 'Only these five lines are primary\. Everything below is exploratory') $true

    # --- Exclusion of flagged blocks. Four rounds, three contenders, two references, one block each.
    function TwoRefs([string]$C, [double[]]$Meds, [double[]]$B2Shift, [string]$Block = 'B1') {
        for ($rd = 1; $rd -le $Meds.Count; $rd++) {
            $m = $Meds[$rd - 1] / 1000.0
            Flat (($rd - 1) * 10000) $C 'idle' 'r1' @($m, $m, $m) 0.004 $rd $Block
            Flat (($rd - 1) * 10000) $C 'idle' 'r2' @(($m + $B2Shift[$rd - 1] / 1000.0), ($m + $B2Shift[$rd - 1] / 1000.0), ($m + $B2Shift[$rd - 1] / 1000.0)) 0.004 $rd $Block
        }
    }
    $zero = 0, 0, 0, 0
    $all = @((TwoRefs 'w32time-default' @(4, 5, 6, 5) $zero) + (TwoRefs 'w32time-default-aa' @(4.5, 5, 5, 5) $zero) + (TwoRefs 'service' @(2, 2.5, 3, 2.5) $zero))
    $rep = Get-OffsetReport -Rows (Load $all)
    Check 'all agree: no flags' @($rep.Flags).Count 0
    Check 'all agree: nothing excluded' @($rep.ExcludedRounds).Count 0
    Check 'all agree: 24 block rows' @($rep.Blocks).Count 24
    # Round 2 service block: r2 reads 3.5 ms higher. DISAGREE at 2 ms. Round 2 goes for every contender.
    $dis = @((TwoRefs 'w32time-default' @(4, 5, 6, 5) $zero) + (TwoRefs 'w32time-default-aa' @(4.5, 5, 5, 5) $zero) + (TwoRefs 'service' @(2, 2.5, 3, 2.5) @(0, 3.5, 0, 0)))
    $rep = Get-OffsetReport -Rows (Load $dis)
    Check 'disagree: one flag' @($rep.Flags).Count 1
    Check 'disagree: flag type' $rep.Flags[0].flag 'DISAGREE'
    Check 'disagree: flag names the block' ($rep.Flags[0].id -like 'idle round 2 block B1 service') $true
    Check 'disagree: round 2 excluded' ((@($rep.ExcludedRounds) -join ',')) 'idle|2'
    Check 'disagree: no round 2 rows left' @($rep.Blocks | Where-Object { $_.round -eq 2 }).Count 0
    Check 'disagree: partner blocks go too' @($rep.Blocks).Count 18
    Check 'disagree: three rounds left still call' ($rep.Primary[0].verdict) 'better'
    Check 'disagree: agreement table keeps all blocks' @($rep.Agreement).Count 12
    $IncludeFlagged = $true
    $rep = Get-OffsetReport -Rows (Load $dis)
    Check 'include flagged: flag still listed' @($rep.Flags).Count 1
    Check 'include flagged: nothing excluded' @($rep.ExcludedRounds).Count 0
    Check 'include flagged: all blocks present' @($rep.Blocks).Count 24
    $IncludeFlagged = $false
    # Block missing its second reference: flagged and excluded the same way.
    $miss = @(Load $all | Where-Object { -not ($_.Contender -eq 'w32time-default' -and $_.Round -eq 3 -and $_.Ref -eq 'r2') })
    $rep = Get-OffsetReport -Rows $miss
    Check 'missing second reference: one flag' @($rep.Flags).Count 1
    Check 'missing second reference: flag type' $rep.Flags[0].flag 'no second reference'
    Check 'missing second reference: round 3 excluded' ((@($rep.ExcludedRounds) -join ',')) 'idle|3'
    # Start not clean label.
    $unc = @((TwoRefs 'w32time-default' @(4, 5, 6, 5) $zero) + (TwoRefs 'w32time-default-aa' @(4.5, 5, 5, 5) $zero) + (TwoRefs 'service' @(2, 2.5, 3, 2.5) $zero 'B3-unclean'))
    $rep = Get-OffsetReport -Rows (Load $unc)
    Check 'start not clean: flagged' $rep.Flags[0].flag 'start not clean'
    Check 'start not clean: one flag per round' @($rep.Flags).Count 4
    Check 'start not clean: every round excluded' @($rep.ExcludedRounds).Count 4
    # The count and the list are printed.
    $f = Join-Path $tmp 'flagged.csv'
    Set-Content -LiteralPath $f -Value (@($hdr) + $dis)
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $f, '-Primary', 'r1')
    Check 'printed: count line' ($c.Out -match 'Flagged blocks: 1\. Excluded case-rounds: 1') $true
    Check 'printed: list line' ($c.Out -match 'DISAGREE') $true
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $f, '-Primary', 'r1', '-IncludeFlagged')
    Check 'printed: include flagged says none excluded' ($c.Out -match 'none excluded, -IncludeFlagged is set') $true

    # --- Reference agreement per block (table 4). r1 1.2 ms, r2 2.1 ms: diff -0.9, agree. r1 1.0, r2 4.5: -3.5 DISAGREE.
    $ls = @((Flat 0 'svc' 'idle' 'r1' @(0.0012, 0.0012, 0.0012) 0.004 1 'B1') + (Flat 0 'svc' 'idle' 'r2' @(0.0021, 0.0021, 0.0021) 0.004 1 'B1') +
        (Flat 5000 'svc' 'idle' 'r1' @(0.001, 0.001, 0.001) 0.004 2 'B1') + (Flat 5000 'svc' 'idle' 'r2' @(0.0045, 0.0045, 0.0045) 0.004 2 'B1'))
    $ag = @(Get-AgreementTable -Rows (Load $ls) -Drop 0 -Which 'primary' -AgreeMs 2)
    Check 'agreement rows' $ag.Count 2
    CheckNear 'agreement diff 1' $ag[0].diff_ms -0.9 1e-6
    Check 'agreement 1 yes' $ag[0].agree 'yes'
    CheckNear 'agreement diff 2' $ag[1].diff_ms -3.5 1e-6
    Check 'agreement 2 flagged' $ag[1].agree 'DISAGREE'

    # Free-run slope: offset = 2e-5 * t for t = 0..4 s is 20 ppm. Service flat is 0 ppm. Difference -20.
    $ls = @((Flat 0 'free-run' 'idle' 'r' @(0, 0.00002, 0.00004, 0.00006, 0.00008) 0.004 1 'B1' 1) + (Flat 0 'svc' 'idle' 'r' @(0.001, 0.001, 0.001, 0.001, 0.001) 0.004 1 'B1' 1))
    $rows = Load $ls
    $pl = @(Get-PooledTable -Rows $rows -Blocks @(Get-BlockTable -Rows $rows -Drop 0 -Which 'primary') -Drop 0 -Which 'primary')
    $fr = @($pl | Where-Object { $_.contender -eq 'free-run' })[0]
    $sv = @($pl | Where-Object { $_.contender -eq 'svc' })[0]
    CheckNear 'free-run slope' $fr.slope_ppm_median_of_blocks 20 0.01
    CheckNear 'service slope' $sv.slope_ppm_median_of_blocks 0 0.01
    CheckNear 'slope versus free-run' $sv.slope_vs_freerun_ppm -20 0.01
    Check 'free-run has no self difference' ($null -eq $fr.slope_vs_freerun_ppm) $true

    # --- Recovery detection from rows.
    # Gap: rows at 0,1,2 s (1 ms). Sleep gap. Then t=1000 0.5 s, 1001 0.2 s, 1002 5 ms, 1003 4 ms, 1004 3 ms, 1005 1 ms.
    # Event is the first row after the gap (t = 1000). First start of three rows below 10 ms is t = 1002. Recovery 2 s.
    $ls = @()
    foreach ($t in 0, 1, 2) { $ls += (CsvRow $t 'svc' 'sleep' 'r' 0.001 0.004 '' 1 'B1') }
    foreach ($pair in @(@(1000, 0.5), @(1001, 0.2), @(1002, 0.005), @(1003, 0.004), @(1004, 0.003), @(1005, 0.001))) { $ls += (CsvRow $pair[0] 'svc' 'sleep' 'r' $pair[1] 0.004 '' 1 'B1') }
    $rec = @(Get-RecoveryTable -Rows (Load $ls) -Cases @('sleep*') -LimitMs 10 -Consecutive 3 -GapSeconds 120 -StepMs 100)
    Check 'recovery gap: one event' $rec.Count 1
    Check 'recovery gap: type' $rec[0].event 'gap'
    CheckNear 'recovery gap: seconds' $rec[0].recovery_s 2 1e-6
    Check 'recovery: case filter' @(Get-RecoveryTable -Rows (Load ($ls -replace ',sleep,', ',idle,')) -Cases @('sleep*') -LimitMs 10 -Consecutive 3 -GapSeconds 120 -StepMs 100).Count 0

    # Step: t = 0..9 at 1 ms. t=10 -2 s, 11 -1.5, 12 -0.5, 13 8 ms, 14 7 ms, 15 6 ms, 16 1 ms. Event t = 10. First start t = 13. Recovery 3 s.
    function StepRows([int]$Round, [string[]]$Tail, [double]$T0) {
        # Tail items are an offset in seconds or the word error.
        $r = @(); for ($t = 0; $t -lt 10; $t++) { $r += (CsvRow ($T0 + $t) 'svc' 'disturb2s' 'r' 0.001 0.004 '' $Round 'B1') }
        for ($k = 0; $k -lt $Tail.Count; $k++) {
            if ($Tail[$k] -eq 'error') { $r += (CsvRow ($T0 + 10 + $k) 'svc' 'disturb2s' 'r' $null $null 'w32tm error 0x800705B4' $Round 'B1') }
            else { $r += (CsvRow ($T0 + 10 + $k) 'svc' 'disturb2s' 'r' ([double]::Parse($Tail[$k], [cultureinfo]::InvariantCulture)) 0.004 '' $Round 'B1') }
        }
        $r
    }
    $ls = @((StepRows 1 @('-2', '-1.5', '-0.5', '0.008', '0.007', '0.006', '0.001') 0) + (StepRows 2 @('-2', '-1.5', '-0.5', '-0.1', '-0.05', '-0.02', '0.008', '0.007', '0.006', '0.001') 1000))
    $rec = @(Get-RecoveryTable -Rows (Load $ls) -Cases @('disturb*') -LimitMs 10 -Consecutive 3 -GapSeconds 120 -StepMs 100)
    Check 'recovery step: two events' $rec.Count 2
    Check 'recovery step: type' $rec[0].event 'step'
    CheckNear 'recovery step: round 1 seconds' $rec[0].recovery_s 3 1e-6
    CheckNear 'recovery step: round 2 seconds' $rec[1].recovery_s 6 1e-6
    # The row right after the step is an error row. The step is the next good row, at t = 11. Recovery from there: starts at t = 14, 3 s.
    $ls = @(StepRows 1 @('error', '-2', '-1.5', '-0.5', '0.008', '0.007', '0.006', '0.001') 0)
    $rec = @(Get-RecoveryTable -Rows (Load $ls) -Cases @('disturb*') -LimitMs 10 -Consecutive 3 -GapSeconds 120 -StepMs 100)
    Check 'step after an error row: found' $rec.Count 1
    Check 'step after an error row: event row is the next good row' $rec[0].event_utc '2026-11-10T00:00:11.000Z'
    CheckNear 'step after an error row: seconds' $rec[0].recovery_s 3 1e-6
    # An error row inside the recovery window breaks the run. t=14 8 ms, 15 error, 16 6 ms, 17 5 ms, 18 4 ms. Event t = 10 (-2 s). Start t = 16, 6 s.
    $ls = @(StepRows 1 @('-2', '-1.5', '-0.5', '-0.1', '0.008', 'error', '0.006', '0.005', '0.004') 0)
    $rec = @(Get-RecoveryTable -Rows (Load $ls) -Cases @('disturb*') -LimitMs 10 -Consecutive 3 -GapSeconds 120 -StepMs 100)
    CheckNear 'error row breaks the run: seconds' $rec[0].recovery_s 6 1e-6
    # Never recovers.
    $ls = @(StepRows 1 @('-2', '-2', '-2', '-2') 0)
    $rec = @(Get-RecoveryTable -Rows (Load $ls) -Cases @('disturb*') -LimitMs 10 -Consecutive 3 -GapSeconds 120 -StepMs 100)
    Check 'not recovered: text' $rec[0].recovery_s 'not recovered'
    Check 'not recovered: censored value' ([double]::IsPositiveInfinity($rec[0].recovery_value)) $true
    Check 'not recovered: counted in the summary' @(Get-RecoverySummary $rec)[0].not_recovered 1

    # --- CSV edge cases through the script.
    $f = Join-Path $tmp 'empty.csv'; Set-Content -LiteralPath $f -Value $hdr
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $f)
    Check 'empty csv: exit 2' $c.Code 2
    Check 'empty csv: message' ($c.Out -match 'empty CSV') $true
    $f = Join-Path $tmp 'nocol.csv'; Set-Content -LiteralPath $f -Value @('utc_iso,contender,case,reference,delay_s,error', '2026-11-10T00:00:00.000Z,svc,idle,r,0.004,')
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $f)
    Check 'missing required column: exit 2' $c.Code 2
    Check 'missing required column: names it' ($c.Out -match 'lacks column offset_s') $true
    $f = Join-Path $tmp 'nofile.csv'
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $f)
    Check 'no such file: exit 2' $c.Code 2
    $f = Join-Path $tmp 'one.csv'; Set-Content -LiteralPath $f -Value @($hdr, (CsvRow 0 'svc' 'idle' 'r' 0.004 0.005 '' 1 'B1'))
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $f)
    Check 'single row csv: exit 0' $c.Code 0
    $f = Join-Path $tmp 'errs.csv'; Set-Content -LiteralPath $f -Value @($hdr, (CsvRow 0 'svc' 'idle' 'r' $null $null 'w32tm error 0x800705B4' 1 'B1'))
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $f)
    Check 'all errors csv: exit 0' $c.Code 0
    $old = Join-Path $tmp 'old.csv'
    Set-Content -LiteralPath $old -Value @('utc_iso,contender,case,reference,offset_s,delay_s,error', '2026-11-10T00:00:00.000Z,svc,idle,r,0.001,0.004,', '2026-11-10T00:00:01.000Z,svc,idle,r,0.002,0.004,')
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $old)
    Check 'old csv: warning' ($c.Out -match 'no round column') $true
    Check 'old csv: round 0 listed' ($c.Out -match 'svc\s+idle\s+r\s+0\s') $true
    Check 'old csv: exit 0' $c.Code 0

    # --- wait-synced.ps1 with a stand-in for w32tm.
    $okFake = New-Fake 'syncok' @('150315589625024, 150315606087988, 134387814648199712, +00.0039764, +00.0020000') 0
    $badFake = New-Fake 'syncbad' @('150315589625024, 150315606087988, 134387814648199712, +00.0039764, +00.5000000') 0
    $ws = Join-Path $here 'wait-synced.ps1'
    $c = Child @($ws, '-ReferenceA', '192.0.2.7', '-ReferenceB', '192.0.2.8', '-Consecutive', '2', '-PeriodSeconds', '1', '-MaxWaitSeconds', '30', '-W32tmPath', $okFake)
    Check 'wait-synced: synced exit 0' $c.Code 0
    Check 'wait-synced: says synced' ($c.Out -match 'synced: 2 consecutive rounds') $true
    $c = Child @($ws, '-ReferenceA', '192.0.2.7', '-ReferenceB', '192.0.2.8', '-Consecutive', '2', '-PeriodSeconds', '1', '-MaxWaitSeconds', '2', '-W32tmPath', $badFake)
    Check 'wait-synced: start not clean exit 3' $c.Code 3
    Check 'wait-synced: names the suffix' ($c.Out -match 'suffix -unclean') $true
    $c = Child @($ws, '-ReferenceA', '192.0.2.7', '-ReferenceB', '192.0.2.7', '-W32tmPath', $okFake)
    Check 'wait-synced: same reference twice is refused' $c.Code 2
    $c = Child @($ws, '-ReferenceA', 'a b', '-ReferenceB', '192.0.2.8', '-W32tmPath', $okFake)
    Check 'wait-synced: bad reference is refused' $c.Code 2
    $errFake = New-Fake 'syncerr' @('150500509834930, 150504227076634, 134387815147981814, error: 0x800705B4') 0
    $c = Child @($ws, '-ReferenceA', '192.0.2.7', '-ReferenceB', '192.0.2.8', '-Consecutive', '1', '-PeriodSeconds', '1', '-MaxWaitSeconds', '2', '-W32tmPath', $errFake)
    Check 'wait-synced: timeouts are not synced' $c.Code 3

    # --- restore-clock arithmetic and the guards of the dangerous helpers.
    . (Join-Path $here 'restore-clock.ps1')
    CheckNear 'restore: median of odd' (Get-RestoreAdjustment -Offsets @(2.01, 1.99, 2.0) -MaxStepSeconds 10) 2.0 1e-9
    CheckNear 'restore: median of even' (Get-RestoreAdjustment -Offsets @(1, 2, 3, 4) -MaxStepSeconds 10) 2.5 1e-9
    CheckNear 'restore: negative offset steps back' (Get-RestoreAdjustment -Offsets @(-0.5) -MaxStepSeconds 10) -0.5 1e-9
    $thrown = $false; try { Get-RestoreAdjustment -Offsets @() -MaxStepSeconds 10 | Out-Null } catch { $thrown = $true }
    Check 'restore: no samples throws' $thrown $true
    $thrown = $false; try { Get-RestoreAdjustment -Offsets @(25) -MaxStepSeconds 10 | Out-Null } catch { $thrown = $true }
    Check 'restore: too large throws' $thrown $true
    foreach ($h in 'disturb-clock', 'restore-clock', 'apply-tuned-profile') {
        $path = Join-Path $here "$h.ps1"
        $extra = switch ($h) { 'restore-clock' { @('-Reference', '192.0.2.7') } 'apply-tuned-profile' { @('-BeforeFile', (Join-Path $tmp 'x.json')) } default { @() } }
        $c = Child (@($path) + $extra)
        Check "$h refuses without MEASURE_TEST_MACHINE" $c.Code 2
        Check "$h says why" ($c.Out -match 'refused\. Set MEASURE_TEST_MACHINE=1') $true
        $text = Get-Content -LiteralPath $path -Raw
        $guard = $text.IndexOf('$env:MEASURE_TEST_MACHINE')
        $first = @('Set-ItemProperty', 'Remove-ItemProperty', 'Set-Date', 'Restart-Service', 'w32tm /config') | ForEach-Object { $i = $text.IndexOf($_, $text.IndexOf('Set-StrictMode')); if ($i -ge 0) { $i } } | Sort-Object | Select-Object -First 1
        Check "$h guard comes before any change" ($guard -ge 0 -and $guard -lt $first) $true
    }
}
catch { $script:fail++; Write-Host "FAIL unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)`n$($_.ScriptStackTrace)" }
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    [Environment]::SetEnvironmentVariable('MEASURE_TEST_MACHINE', $savedGuard, 'Process')
}

Write-Host "passed $script:pass, failed $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
