<#
  Tests for measure-offset.ps1 and summarise-offset.ps1. No network, no system change.
  Run: powershell -NoProfile -File scripts\test-measure.ps1   (exit 0 pass, 1 fail)
  Plain checks are used because the installed Pester is 3.4.0.
#>
Set-StrictMode -Version Latest
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
    # plain format
    @{ n = 'plain positive'; l = '11:39:29, +00.0021951s'; kind = 'Data'; off = 0.0021951 },
    @{ n = 'plain negative'; l = '11:39:35, -00.0041153s'; kind = 'Data'; off = -0.0041153 },
    @{ n = 'plain timeout'; l = '18:51:59, error: 0x800705B4'; kind = 'Error'; err = 'w32tm error 0x800705B4' },
    @{ n = 'plain socket error'; l = '11:44:13, error: 0x80072733'; kind = 'Error'; err = 'w32tm error 0x80072733' },
    @{ n = 'plain comma decimal'; l = '11:39:29, +00,0021951s'; kind = 'Data'; off = 0.0021951 },
    @{ n = 'plain 12h clock with PM'; l = '6:51:59 PM, +00.0100000s'; kind = 'Data'; off = 0.01 },
    @{ n = 'plain dotted time'; l = '18.51.59, -00,0500000s'; kind = 'Data'; off = -0.05 },
    @{ n = 'plain unicode minus'; l = ('18:51:59, ' + [char]0x2212 + '00.0030000s'); kind = 'Data'; off = -0.003 },
    @{ n = 'plain d suffix flagged'; l = '18:51:59, +00.0000100d'; kind = 'Error'; err = 'unit d read as days (unverified)'; off = 0.864 },
    # rdtsc format
    @{ n = 'rdtsc good'; l = '150315589625024, 150315606087988, 134387814648199712, +00.0039764, +00.1705322'; kind = 'Data'; off = 0.1705322; delay = 0.0039764 },
    @{ n = 'rdtsc negative offset'; l = '150319334177355, 150319378556113, 134387814658320078, +00.0113711, -00.0004463'; kind = 'Data'; off = -0.0004463; delay = 0.0113711 },
    @{ n = 'rdtsc timeout'; l = '150500509834930, 150504227076634, 134387815147981814, error: 0x800705B4'; kind = 'Error'; err = 'w32tm error 0x800705B4' },
    @{ n = 'rdtsc comma decimal'; l = '150315589625024, 150315606087988, 134387814648199712, +00,0039764, +00,1705322'; kind = 'Data'; off = 0.1705322; delay = 0.0039764 },
    @{ n = 'rdtsc missing offset'; l = '150315589625024, 150315606087988, 134387814648199712, +00.0039764'; kind = 'Error'; err = 'unparsed line: 150315589625024, 150315606087988, 134387814648199712, +00.0039764' },
    # not samples
    @{ n = 'tracking line'; l = 'Tracking time.cloudflare.com [162.159.200.1:123].'; kind = 'Preamble'; ip = '162.159.200.1' },
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
# FILETIME to UTC: 134387814648199712 is 2026-11-10 10:51:04.8 UTC (18:51 local, UTC+8)
$p = ConvertFrom-StripchartLine -Line '150315589625024, 150315606087988, 134387814648199712, +00.0039764, +00.1705322'
Check 'rdtsc FileTime to UTC' $p.FileTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss', [cultureinfo]::InvariantCulture) '2026-11-10T10:51:04'

# --- CSV row formatting ---
$utc = [DateTime]::SpecifyKind([DateTime]'2026-11-10 08:51:04.8', 'Utc')
Check 'row good' (Format-SampleRow -Utc $utc -Contender 'svc' -Case 'idle' -Reference '1.2.3.4' -OffsetS 0.0021951 -DelayS 0.004 -Err '') '2026-11-10T08:51:04.800Z,svc,idle,1.2.3.4,0.0021951,0.004,'
Check 'row error' (Format-SampleRow -Utc $utc -Contender 'svc' -Case 'idle' -Reference '1.2.3.4' -OffsetS $null -DelayS $null -Err 'w32tm error 0x800705B4') '2026-11-10T08:51:04.800Z,svc,idle,1.2.3.4,,,w32tm error 0x800705B4'
Check 'row quotes comma' (Format-SampleRow -Utc $utc -Contender 'svc' -Case 'idle' -Reference 'r' -OffsetS $null -DelayS $null -Err 'a,b "c"') '2026-11-10T08:51:04.800Z,svc,idle,r,,,"a,b ""c"""'
# a culture with comma decimals must not leak into the CSV
$old = [System.Threading.Thread]::CurrentThread.CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentCulture = [cultureinfo]'de-DE'
Check 'row under de-DE' (Format-SampleRow -Utc $utc -Contender 'c' -Case 'k' -Reference 'r' -OffsetS 0.5 -DelayS $null -Err '') '2026-11-10T08:51:04.800Z,c,k,r,0.5,,'
[System.Threading.Thread]::CurrentThread.CurrentCulture = $old

# --- input validation ---
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("measure-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $ok = Join-Path $tmp 'a.csv'
    $v = { param($r, $c, $k, $s, $pd, $o, $pool) (Test-MeasureInput -Reference $r -Contender $c -Case $k -Samples $s -PeriodSeconds $pd -OutPath $o -AllowPool $pool).Count }
    Check 'valid input' (& $v '162.159.200.1' 'svc' 'idle' 5 2 $ok $false) 0
    Check 'pool refused' (& $v 'pool.ntp.org' 'svc' 'idle' 5 2 $ok $false) 1
    Check 'pool allowed' (& $v 'au.pool.ntp.org' 'svc' 'idle' 5 2 $ok $true) 0
    Check 'bad reference chars' (& $v 'a b;calc' 'svc' 'idle' 5 2 $ok $false) 1
    Check 'bad label' (& $v '1.2.3.4' 'a,b' 'idle' 5 2 $ok $false) 1
    Check 'zero samples' (& $v '1.2.3.4' 'svc' 'idle' 0 2 $ok $false) 1
    Check 'zero period' (& $v '1.2.3.4' 'svc' 'idle' 5 0 $ok $false) 1
    Check 'missing folder' (& $v '1.2.3.4' 'svc' 'idle' 5 2 (Join-Path $tmp 'no\x.csv') $false) 1
    Set-Content -LiteralPath $ok -Value 'keep'
    Check 'existing file refused' (& $v '1.2.3.4' 'svc' 'idle' 5 2 $ok $false) 1

    # exit codes of the real script on bad input. No network: validation stops first.
    $ps = (Get-Process -Id $PID).Path
    & $ps -NoProfile -File (Join-Path $here 'measure-offset.ps1') -Reference '1.2.3.4' -Contender 'svc' -Case 'idle' -Samples 0 -PeriodSeconds 2 -OutPath (Join-Path $tmp 'b.csv') 2>$null
    Check 'exit 2 on bad samples' $LASTEXITCODE 2
    & $ps -NoProfile -File (Join-Path $here 'measure-offset.ps1') -Reference '1.2.3.4' -Contender 'svc' -Case 'idle' -Samples 3 -PeriodSeconds 2 -OutPath $ok 2>$null
    Check 'exit 2 on existing csv' $LASTEXITCODE 2
    Check 'existing csv untouched' ((Get-Content -LiteralPath $ok -Raw).Trim()) 'keep'
    & $ps -NoProfile -File (Join-Path $here 'summarise-offset.ps1') 2>$null
    Check 'summarise exit 2 without path' $LASTEXITCODE 2

    # --- summariser on a CSV with known numbers ---
    # 11 good samples, offset 1..11 ms at 1 s steps, plus 1 error row. Slope is 1 ms/s = 1000 ppm.
    $csv = Join-Path $tmp 'known.csv'
    $lines = @('utc_iso,contender,case,reference,offset_s,delay_s,error')
    for ($i = 0; $i -lt 11; $i++) {
        $lines += ('2026-11-10T00:00:{0:00}.000Z,svc,idle,1.2.3.4,{1},0.005,' -f $i, (($i + 1) / 1000.0).ToString('R', [cultureinfo]::InvariantCulture))
    }
    $lines += '2026-11-10T00:00:11.000Z,svc,idle,1.2.3.4,,,w32tm error 0x800705B4'
    Set-Content -LiteralPath $csv -Value $lines
    $s = @(Get-OffsetSummary -Rows @(Import-Csv -LiteralPath $csv))
    Check 'summary groups' $s.Count 1
    Check 'summary samples' $s[0].samples 12
    Check 'summary errors' $s[0].errors 1
    CheckNear 'summary error pct' $s[0].error_pct 8.3 0.05
    CheckNear 'summary median' $s[0].median_ms 6 1e-6
    CheckNear 'summary p5' $s[0].p5_ms 1 1e-6
    CheckNear 'summary p95' $s[0].p95_ms 11 1e-6
    CheckNear 'summary p99' $s[0].p99_ms 11 1e-6
    CheckNear 'summary mean' $s[0].mean_ms 6 1e-6
    CheckNear 'summary max' $s[0].max_ms 11 1e-6
    CheckNear 'summary drift ppm' $s[0].drift_ppm 1000 0.01

    # two contenders stay separate and an all-error group does not crash
    $csv2 = Join-Path $tmp 'two.csv'
    Set-Content -LiteralPath $csv2 -Value @(
        'utc_iso,contender,case,reference,offset_s,delay_s,error',
        '2026-11-10T00:00:00.000Z,a,idle,r,0.001,,',
        '2026-11-10T00:00:01.000Z,b,idle,r,,,w32tm error 0x800705B4')
    $s2 = @(Get-OffsetSummary -Rows @(Import-Csv -LiteralPath $csv2))
    Check 'two groups' $s2.Count 2
    Check 'all-error group error pct' $s2[1].error_pct 100
    Check 'all-error group median null' ($null -eq $s2[1].median_ms) $true
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host "passed $script:pass, failed $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
