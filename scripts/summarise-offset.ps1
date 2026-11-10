<#
.SYNOPSIS
  Summarises one or more CSVs from measure-offset.ps1, per contender and case.

.DESCRIPTION
  Read only. Prints samples, errors, error rate, and absolute offset statistics in
  milliseconds: median, p5, p95, p99, mean, max. Percentiles use the nearest-rank method.
  Drift is the least squares slope of offset against time, in ppm, over good samples.
  The slope includes any drift of the network path to the reference. It is not clock
  drift alone.

  Rows with an error text are excluded from offset statistics and counted as errors.
  Groups are keyed by contender, case and reference. Exit 0 ok, 2 bad input.

.EXAMPLE
  .\summarise-offset.ps1 .\out\*.csv
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Path,
    [switch]$AsObject
)

Set-StrictMode -Version Latest
$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture

function Get-Percentile {
    # Nearest rank on an ascending array. p in 0..100.
    param([double[]]$Sorted, [double]$P)
    if ($Sorted.Count -eq 0) { return $null }
    $rank = [math]::Ceiling($P / 100.0 * $Sorted.Count)
    if ($rank -lt 1) { $rank = 1 }
    return $Sorted[[int]$rank - 1]
}

function Get-SlopePpm {
    # Least squares slope of offset_s against elapsed seconds. Needs 3 points and a time span.
    param([double[]]$T, [double[]]$Y)
    $n = $T.Count
    if ($n -lt 3) { return $null }
    $mt = ($T | Measure-Object -Average).Average
    $my = ($Y | Measure-Object -Average).Average
    $sxx = 0.0; $sxy = 0.0
    for ($i = 0; $i -lt $n; $i++) {
        $sxx += ($T[$i] - $mt) * ($T[$i] - $mt)
        $sxy += ($T[$i] - $mt) * ($Y[$i] - $my)
    }
    if ($sxx -eq 0) { return $null }
    return ($sxy / $sxx) * 1e6
}

function Get-OffsetSummary {
    param([Parameter(Mandatory)][object[]]$Rows)
    $Rows | Group-Object { "$($_.contender)|$($_.case)|$($_.reference)" } | Sort-Object Name | ForEach-Object {
        $g = @($_.Group)
        $good = @($g | Where-Object { [string]::IsNullOrEmpty($_.error) -and -not [string]::IsNullOrEmpty($_.offset_s) })
        $errs = $g.Count - $good.Count
        $abs = @($good | ForEach-Object { [math]::Abs([double]::Parse($_.offset_s, $script:Inv)) * 1000.0 } | Sort-Object)
        $slope = $null
        if ($good.Count -ge 3) {
            $t0 = [DateTime]::Parse($good[0].utc_iso, $script:Inv, [System.Globalization.DateTimeStyles]::RoundtripKind)
            $ts = @($good | ForEach-Object { ([DateTime]::Parse($_.utc_iso, $script:Inv, [System.Globalization.DateTimeStyles]::RoundtripKind) - $t0).TotalSeconds })
            $ys = @($good | ForEach-Object { [double]::Parse($_.offset_s, $script:Inv) })
            $slope = Get-SlopePpm -T $ts -Y $ys
        }
        $first = $g[0]
        [pscustomobject][ordered]@{
            contender = $first.contender
            case      = $first.case
            reference = $first.reference
            samples   = $g.Count
            errors    = $errs
            error_pct = [math]::Round(100.0 * $errs / $g.Count, 1)
            median_ms = if ($abs.Count) { [math]::Round((Get-Percentile $abs 50), 3) } else { $null }
            p5_ms     = if ($abs.Count) { [math]::Round((Get-Percentile $abs 5), 3) } else { $null }
            p95_ms    = if ($abs.Count) { [math]::Round((Get-Percentile $abs 95), 3) } else { $null }
            p99_ms    = if ($abs.Count) { [math]::Round((Get-Percentile $abs 99), 3) } else { $null }
            mean_ms   = if ($abs.Count) { [math]::Round(($abs | Measure-Object -Average).Average, 3) } else { $null }
            max_ms    = if ($abs.Count) { [math]::Round(($abs | Measure-Object -Maximum).Maximum, 3) } else { $null }
            drift_ppm = if ($null -ne $slope) { [math]::Round($slope, 3) } else { $null }
        }
    }
}

function Format-SummaryText {
    # Own fixed-width table. Format-Table drops columns that do not fit the host width.
    param([object[]]$Summary)
    $cols = $Summary[0].PSObject.Properties.Name
    $cells = @($Summary | ForEach-Object { $row = $_; , @($cols | ForEach-Object { $v = $row.$_; if ($null -eq $v) { '-' } else { ([string]$v) } }) })
    $w = @(for ($i = 0; $i -lt $cols.Count; $i++) { $m = $cols[$i].Length; foreach ($c in $cells) { if ($c[$i].Length -gt $m) { $m = $c[$i].Length } }; $m })
    $line = { param($vals) (0..($vals.Count - 1) | ForEach-Object { $vals[$_].PadRight($w[$_]) }) -join '  ' }
    $out = @((& $line $cols).TrimEnd(), (& $line @($w | ForEach-Object { '-' * $_ })).TrimEnd())
    foreach ($c in $cells) { $out += (& $line $c).TrimEnd() }
    $out -join "`n"
}

function Invoke-Summarise {
    if (-not $Path -or $Path.Count -eq 0) { [Console]::Error.WriteLine('summarise-offset: give one or more CSV paths.'); return 2 }
    $files = @()
    foreach ($p in $Path) {
        $m = @(Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue)
        if ($m.Count -eq 0) { [Console]::Error.WriteLine("summarise-offset: no file matches $p"); return 2 }
        $files += $m
    }
    $rows = @()
    foreach ($f in $files) {
        $r = @(Import-Csv -LiteralPath $f.FullName)
        if ($r.Count -eq 0) { [Console]::Error.WriteLine("summarise-offset: empty CSV $($f.FullName)"); return 2 }
        foreach ($col in 'utc_iso', 'contender', 'case', 'reference', 'offset_s', 'delay_s', 'error') {
            if ($r[0].PSObject.Properties.Name -notcontains $col) { [Console]::Error.WriteLine("summarise-offset: $($f.Name) lacks column $col"); return 2 }
        }
        $rows += $r
    }
    $s = @(Get-OffsetSummary -Rows $rows)
    if ($AsObject) { $s } else { Format-SummaryText -Summary $s | Write-Host }
    return 0
}

if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-Summarise) }
