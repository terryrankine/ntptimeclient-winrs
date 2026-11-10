<#
  Tests for measure-offset.ps1 and summarise-offset.ps1. No network, no system change.
  Run: powershell -NoProfile -File scripts\test-measure.ps1   (exit 0 pass, 1 fail)
  Plain checks are used because the installed Pester is 3.4.0.
  Expected values in the summary tests were worked out by hand. The working is in the comments.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'measure-offset.ps1')
. (Join-Path $here 'summarise-offset.ps1')

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

    # median and percentile maths
    Check 'median odd' (Get-Median @(3, 1, 2)) 2
    Check 'median even is interpolated' (Get-Median @(1, 2, 3, 4)) 2.5
    Check 'nearest rank p50 of 1..4 is 2 (the bias the median avoids)' (Get-Percentile @(1, 2, 3, 4) 50) 2

    # 11 samples 1..11 ms at 1 s steps, delay 5 ms, plus one error row.
    # median 6, p5 = rank ceil(0.55)=1 -> 1, p95 = rank ceil(10.45)=11 -> 11, p99 -> 11, mean 6, max 11.
    # Slope: offset rises 1 ms per second = 1000 ppm. Error rate 1 of 12 = 8.3 %.
    $ls = @()
    for ($i = 0; $i -lt 11; $i++) { $ls += (CsvRow $i 'svc' 'idle' 'r' (($i + 1) / 1000.0) 0.005 '' 1 'B1') }
    $ls += (CsvRow 11 'svc' 'idle' 'r' $null $null 'w32tm error 0x800705B4' 1 'B1')
    $rows = Load $ls
    $b = @(Get-BlockTable -Rows $rows -Drop 0 -Which 'primary')
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

    # Delay percentiles: delays 1..20 ms. Median = (10+11)/2 = 10.5. p95 = rank ceil(19) = 19 -> 19.
    $ls = @(); for ($i = 1; $i -le 20; $i++) { $ls += (CsvRow $i 'svc' 'idle' 'r' 0.001 ($i / 1000.0) '' 1 'B1') }
    $b = @(Get-BlockTable -Rows (Load $ls) -Drop 0 -Which 'primary')
    CheckNear 'delay median even n' $b[0].delay_median_ms 10.5 1e-6
    CheckNear 'delay p95' $b[0].delay_p95_ms 19 1e-6

    # Two flat rounds six hours apart: 1 ms then 5 ms. Per block slope must be 0 and never mixed.
    # Pooled: ten values, five 1 and five 5. Median = (1 + 5) / 2 = 3. Round medians 1 and 5.
    $ls = @((Flat 0 'svc' 'idle' 'r' @(0.001, 0.001, 0.001, 0.001, 0.001) 0.004 1 'B1') + (Flat 21600 'svc' 'idle' 'r' @(0.005, 0.005, 0.005, 0.005, 0.005) 0.004 2 'B1'))
    $rows = Load $ls
    $rep = Get-OffsetReport -Rows $rows
    Check 'two flat rounds: two block rows' $rep.Blocks.Count 2
    CheckNear 'two flat rounds: round 1 slope' $rep.Blocks[0].slope_ppm 0 1e-9
    CheckNear 'two flat rounds: round 2 slope' $rep.Blocks[1].slope_ppm 0 1e-9
    Check 'two flat rounds: one pooled row' $rep.Pooled.Count 1
    Check 'two flat rounds: rounds' $rep.Pooled[0].rounds 2
    CheckNear 'two flat rounds: pooled median' $rep.Pooled[0].median_ms 3 1e-6
    CheckNear 'two flat rounds: round median min' $rep.Pooled[0].round_median_min_ms 1 1e-6
    CheckNear 'two flat rounds: round median max' $rep.Pooled[0].round_median_max_ms 5 1e-6
    CheckNear 'two flat rounds: pooled slope is median of block slopes' $rep.Pooled[0].slope_ppm_median_of_blocks 0 1e-9

    # Wash-out: t = 0..9 s. First 3 rows (t < 3 s) are 100 ms. The rest are 1 ms.
    $ls = @(); for ($i = 0; $i -lt 10; $i++) { $ls += (CsvRow $i 'svc' 'idle' 'r' $(if ($i -lt 3) { 0.1 } else { 0.001 }) 0.004 '' 1 'B1') }
    $rows = Load $ls
    $b = @(Get-BlockTable -Rows $rows -Drop 3 -Which 'primary')
    Check 'washout: primary samples' $b[0].samples 7
    Check 'washout: dropped count' $b[0].dropped 3
    CheckNear 'washout: primary median' $b[0].median_ms 1 1e-6
    $b = @(Get-BlockTable -Rows $rows -Drop 3 -Which 'washout')
    Check 'washout appendix: samples' $b[0].samples 3
    CheckNear 'washout appendix: median' $b[0].median_ms 100 1e-6

    # Comparison over 4 rounds with 3 rows per block, signs alternate to prove abs is used.
    # Per-round medians (ms).  default 4,5,6,5   default-aa 4.5,5,5,5   service 2,2.5,3,2.5
    # Pooled default: 4x3,5x6,6x3 -> median 5.  service: 2x3,2.5x6,3x3 -> 2.5.  Diff -2.5.
    # Noise floor = max(0.5, 0, 1, 0) = 1.  Threshold = max(1, 0.2 * 5) = 1.
    # Per-round diffs -2 / -2.5 / -3 / -2.5. Four of four negative. Verdict better.
    function Rounds([string]$C, [double[]]$Meds, [string]$Ref = 'r', [string]$Case = 'idle') {
        for ($rd = 1; $rd -le $Meds.Count; $rd++) {
            $m = $Meds[$rd - 1] / 1000.0
            Flat (($rd - 1) * 10000) $C $Case $Ref @($m, (-$m), $m) 0.004 $rd 'B1'
        }
    }
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5)) + (Rounds 'service' @(2, 2.5, 3, 2.5)))
    $rows = Load $ls
    $cmp = @(Get-ComparisonTable -Rows $rows -Drop 0 -Which 'primary' -Primary '' -Baseline 'w32time-default' -MinAbsMs 1 -MinRel 0.2 -MinSignRounds 0)
    $svc = @($cmp | Where-Object { $_.contender -eq 'service' })[0]
    $aa = @($cmp | Where-Object { $_.contender -eq 'w32time-default-aa' })[0]
    CheckNear 'compare: diff median' $svc.diff_median_ms -2.5 1e-6
    Check 'compare: per round diffs' $svc.per_round_diff_ms '-2 / -2.5 / -3 / -2.5'
    Check 'compare: same sign' $svc.same_sign_rounds '4 of 4'
    CheckNear 'compare: threshold' $svc.threshold_ms 1 1e-6
    CheckNear 'compare: A/A noise floor' $svc.aa_noise_floor_ms 1 1e-6
    Check 'compare: verdict better' $svc.verdict 'better'
    Check 'compare: A/A row labelled' $aa.verdict 'A/A control'
    CheckNear 'compare: A/A pooled diff is 0' $aa.diff_median_ms 0 1e-6

    # Difference below the threshold: service flat at 4.8 ms against default median 5. Diff -0.2.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5)) + (Rounds 'service' @(4.8, 4.8, 4.8, 4.8)))
    $cmp = @(Get-ComparisonTable -Rows (Load $ls) -Drop 0 -Which 'primary' -Primary '' -Baseline 'w32time-default' -MinAbsMs 1 -MinRel 0.2 -MinSignRounds 0)
    Check 'compare small diff' @($cmp | Where-Object { $_.contender -eq 'service' })[0].verdict 'no meaningful difference'

    # Mixed signs: service 2,2.5,7,2.5. Diffs -2 / -2.5 / +1 / -2.5. Pooled median 2.5, diff -2.5. Three of four negative.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'w32time-default-aa' @(4.5, 5, 5, 5)) + (Rounds 'service' @(2, 2.5, 7, 2.5)))
    $rows = Load $ls
    $cmp = @(Get-ComparisonTable -Rows $rows -Drop 0 -Which 'primary' -Primary '' -Baseline 'w32time-default' -MinAbsMs 1 -MinRel 0.2 -MinSignRounds 0)
    $m = @($cmp | Where-Object { $_.contender -eq 'service' })[0]
    Check 'compare mixed: three of four' $m.same_sign_rounds '3 of 4'
    Check 'compare mixed: all rounds needed' $m.verdict 'no meaningful difference'
    $cmp = @(Get-ComparisonTable -Rows $rows -Drop 0 -Which 'primary' -Primary '' -Baseline 'w32time-default' -MinAbsMs 1 -MinRel 0.2 -MinSignRounds 3)
    Check 'compare mixed: 3 rounds enough when asked' @($cmp | Where-Object { $_.contender -eq 'service' })[0].verdict 'better'

    # Worse: service 8 ms flat against default median 5. Diff +3 above threshold 1.
    $ls = @((Rounds 'w32time-default' @(4, 5, 6, 5)) + (Rounds 'service' @(8, 8, 8, 8)))
    $cmp = @(Get-ComparisonTable -Rows (Load $ls) -Drop 0 -Which 'primary' -Primary '' -Baseline 'w32time-default' -MinAbsMs 1 -MinRel 0.2 -MinSignRounds 0)
    $m = @($cmp | Where-Object { $_.contender -eq 'service' })[0]
    Check 'compare worse verdict' $m.verdict 'worse'
    Check 'compare without A/A has no noise floor' ($null -eq $m.aa_noise_floor_ms) $true

    # Reference agreement per block. r1 1.2 ms, r2 2.1 ms: diff -0.9, agree. r1 1.0, r2 4.5: diff -3.5 DISAGREE.
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
    $pl = @(Get-PooledTable -Rows (Load $ls) -Blocks @(Get-BlockTable -Rows (Load $ls) -Drop 0 -Which 'primary') -Drop 0 -Which 'primary')
    $fr = @($pl | Where-Object { $_.contender -eq 'free-run' })[0]
    $sv = @($pl | Where-Object { $_.contender -eq 'svc' })[0]
    CheckNear 'free-run slope' $fr.slope_ppm_median_of_blocks 20 0.01
    CheckNear 'service slope' $sv.slope_ppm_median_of_blocks 0 0.01
    CheckNear 'slope versus free-run' $sv.slope_vs_freerun_ppm -20 0.01
    Check 'free-run has no self difference' ($null -eq $fr.slope_vs_freerun_ppm) $true

    # Recovery after a gap. Rows at 0,1,2 s (1 ms). Sleep gap. Then t=1000 0.5 s, 1001 0.2 s, 1002 5 ms, 1003 4 ms, 1004 3 ms, 1005 1 ms.
    # Event is the first row after the gap (t = 1000). Limit 10 ms, 3 rows. First qualifying start is t = 1002. Recovery 2 s.
    $ls = @()
    $i = 0; foreach ($t in 0, 1, 2) { $ls += (CsvRow $t 'svc' 'sleep' 'r' 0.001 0.004 '' 1 'B1') }
    foreach ($pair in @(@(1000, 0.5), @(1001, 0.2), @(1002, 0.005), @(1003, 0.004), @(1004, 0.003), @(1005, 0.001))) { $ls += (CsvRow $pair[0] 'svc' 'sleep' 'r' $pair[1] 0.004 '' 1 'B1') }
    $rec = @(Get-RecoveryTable -Rows (Load $ls) -Cases @('sleep*') -LimitMs 10 -Consecutive 3 -GapSeconds 120 -StepMs 100)
    Check 'recovery gap: one event' $rec.Count 1
    Check 'recovery gap: type' $rec[0].event 'gap'
    CheckNear 'recovery gap: seconds' $rec[0].recovery_s 2 1e-6
    # The same rows under a case that is not selected give nothing.
    Check 'recovery: case filter' @(Get-RecoveryTable -Rows (Load ($ls -replace ',sleep,', ',idle,')) -Cases @('sleep*') -LimitMs 10 -Consecutive 3 -GapSeconds 120 -StepMs 100).Count 0

    # Recovery after an offset step (no gap). t = 0..9 at 1 ms. t=10 -2 s, 11 -1.5 s, 12 -0.5 s, 13 8 ms, 14 7 ms, 15 6 ms, 16 1 ms.
    # Event at t = 10. First three consecutive below 10 ms start at t = 13. Recovery 3 s.
    function StepRows([int]$Round, [double[]]$Tail, [double]$T0) {
        $r = @(); for ($t = 0; $t -lt 10; $t++) { $r += (CsvRow ($T0 + $t) 'svc' 'disturb2s' 'r' 0.001 0.004 '' $Round 'B1') }
        for ($k = 0; $k -lt $Tail.Count; $k++) { $r += (CsvRow ($T0 + 10 + $k) 'svc' 'disturb2s' 'r' $Tail[$k] 0.004 '' $Round 'B1') }
        $r
    }
    $ls = @((StepRows 1 @(-2, -1.5, -0.5, 0.008, 0.007, 0.006, 0.001) 0) + (StepRows 2 @(-2, -1.5, -0.5, -0.1, -0.05, -0.02, 0.008, 0.007, 0.006, 0.001) 1000))
    # Round 2: first three below 10 ms start at t = 16 (index 6 of the tail). Recovery 6 s. The rows at -0.02 and -0.05 are above the limit.
    $rows = Load $ls
    $rec = @(Get-RecoveryTable -Rows $rows -Cases @('disturb*') -LimitMs 10 -Consecutive 3 -GapSeconds 120 -StepMs 100)
    Check 'recovery step: two events' $rec.Count 2
    Check 'recovery step: type' $rec[0].event 'step'
    CheckNear 'recovery step: round 1 seconds' $rec[0].recovery_s 3 1e-6
    CheckNear 'recovery step: round 2 seconds' $rec[1].recovery_s 6 1e-6
    $rs = @(Get-RecoverySummary $rec)
    Check 'recovery summary: events' $rs[0].events 2
    CheckNear 'recovery summary: median (3 and 6)' $rs[0].median_s 4.5 1e-6
    CheckNear 'recovery summary: worst' $rs[0].worst_s 6 1e-6
    # An event that never recovers is reported as such.
    $ls = @(); for ($t = 0; $t -lt 5; $t++) { $ls += (CsvRow $t 'svc' 'disturb2s' 'r' 0.001 0.004 '' 1 'B1') }
    foreach ($t in 5, 6, 7, 8) { $ls += (CsvRow $t 'svc' 'disturb2s' 'r' -2.0 0.004 '' 1 'B1') }
    $rec = @(Get-RecoveryTable -Rows (Load $ls) -Cases @('disturb*') -LimitMs 10 -Consecutive 3 -GapSeconds 120 -StepMs 100)
    Check 'recovery: not recovered' $rec[0].recovery_s 'not recovered'
    Check 'recovery summary counts not recovered' @(Get-RecoverySummary $rec)[0].not_recovered 1

    # --- old CSV without the round column: read as round 0 with a warning ---
    $old = Join-Path $tmp 'old.csv'
    Set-Content -LiteralPath $old -Value @('utc_iso,contender,case,reference,offset_s,delay_s,error', '2026-11-10T00:00:00.000Z,svc,idle,r,0.001,0.004,', '2026-11-10T00:00:01.000Z,svc,idle,r,0.002,0.004,')
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $old)
    Check 'old csv: warning' ($c.Out -match 'no round column') $true
    Check 'old csv: round 0 listed' ($c.Out -match 'svc\s+idle\s+r\s+0\s') $true
    Check 'old csv: exit 0' $c.Code 0

    # whole-script run on a new CSV and -AsObject
    $new = Join-Path $tmp 'new.csv'
    Set-Content -LiteralPath $new -Value (@($hdr) + (Flat 0 'svc' 'idle' 'r' @(0.001, 0.002, 0.003) 0.004 1 'B1' 1))
    $c = Child @((Join-Path $here 'summarise-offset.ps1'), $new, '-DropSeconds', '0')
    Check 'script run: has tables' ($c.Out -match '== 1 Blocks' -and $c.Out -match '== 3 Comparison') $true
    Check 'script run: exit 0' $c.Code 0
}
catch { $script:fail++; Write-Host "FAIL unhandled error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)`n$($_.ScriptStackTrace)" }
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host "passed $script:pass, failed $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
