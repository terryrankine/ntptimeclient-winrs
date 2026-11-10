<#
.SYNOPSIS
  Summarises CSVs from measure-offset.ps1. Read only.

.DESCRIPTION
  Tables printed:
    1 Blocks      one row per contender, case, reference, round and block.
                  Samples, errors, error rate, median (interpolated), p5, p95, p99 (nearest rank),
                  mean, max of the absolute offset in ms, delay median and p95 in ms, and the
                  least squares slope of the signed offset in ppm WITHIN the block only.
    2 Pooled      one row per contender, case and reference. All rounds pooled, plus the range of
                  per-round medians and the slope compared with the free-run contender.
    3 Comparison  per case, each contender against -Baseline (default w32time-default) on the
                  primary reference: pooled difference, per-round differences, same-sign count,
                  threshold, A/A noise floor (baseline versus baseline-aa), verdict.
    4 Agreement   per block sampled against two references: signed median difference and a flag.
    5 Recovery    per event (a gap in the sample times, or an offset step). Time from the event
                  row to the first row that starts -Consecutive good rows below -LimitMs.

  Slope sign: the offset is positive when the reference is ahead. A rising offset means the
  local clock is losing time relative to the reference. Only a free-run contender has a drift
  figure. For a disciplined clock the slope is a residual trend. The slope also includes any
  drift of the path to the reference. It is never computed across rounds.

  -DropSeconds drops the first N seconds of each block from the selected part (wash-out). The
  rows stay in the CSV. -Part washout prints the dropped rows instead, as an appendix.

  Old CSVs without a round column are read as round 0 with a warning. Exit 0 ok, 2 bad input.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)][string[]]$Path,
    [switch]$AsObject,
    [double]$DropSeconds = 0,
    [ValidateSet('primary', 'washout', 'all')][string]$Part = 'primary',
    [string]$Primary = '',
    [string]$Baseline = 'w32time-default',
    [double]$MinAbsMs = 1,
    [double]$MinRel = 0.2,
    [int]$MinSignRounds = 0,
    [double]$AgreeMs = 2,
    [double]$LimitMs = 10,
    [int]$Consecutive = 3,
    [double]$GapSeconds = 120,
    [double]$StepMs = 100,
    [string[]]$RecoveryCases = @('sleep*', 'disturb*')
)

Set-StrictMode -Version Latest
$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture

function Get-Median {
    # Interpolated: the mean of the two middle values for an even count. Unbiased, unlike nearest rank.
    param([double[]]$Values)
    $s = @($Values | Sort-Object)
    $n = $s.Count
    if ($n -eq 0) { return $null }
    if ($n % 2 -eq 1) { return [double]$s[($n - 1) / 2] }
    return ([double]$s[$n / 2 - 1] + [double]$s[$n / 2]) / 2.0
}

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

function R3($v) { if ($null -eq $v) { $null } else { [math]::Round([double]$v, 3) } }

function ConvertTo-TypedRows {
    # CSV objects to typed rows. Keeps file order. Round 0 and Block '' when the columns are absent.
    param([object[]]$Csv)
    foreach ($r in $Csv) {
        $good = [string]::IsNullOrEmpty($r.error) -and -not [string]::IsNullOrEmpty($r.offset_s)
        $round = 0
        if ($r.PSObject.Properties.Name -contains 'round' -and -not [string]::IsNullOrEmpty($r.round)) { $round = [int]$r.round }
        $block = ''
        if ($r.PSObject.Properties.Name -contains 'block' -and $null -ne $r.block) { $block = [string]$r.block }
        [pscustomobject]@{
            T = [DateTimeOffset]::Parse($r.utc_iso, $script:Inv).UtcDateTime
            Contender = [string]$r.contender; Case = [string]$r.case; Ref = [string]$r.reference
            Round = $round; Block = $block; Good = $good
            Offset = if ($good) { [double]::Parse($r.offset_s, $script:Inv) } else { $null }
            Delay = if ($good -and -not [string]::IsNullOrEmpty($r.delay_s)) { [double]::Parse($r.delay_s, $script:Inv) } else { $null }
        }
    }
}

function Split-Washout {
    # Rows of one block in file order. Returns @{ Primary; Washout } by seconds since the first row.
    param([object[]]$Rows, [double]$Drop)
    if ($Drop -le 0 -or $Rows.Count -eq 0) { return @{ Primary = @($Rows); Washout = @() } }
    $t0 = $Rows[0].T
    $keep = @($Rows | Where-Object { ($_.T - $t0).TotalSeconds -ge $Drop })
    $cut = @($Rows | Where-Object { ($_.T - $t0).TotalSeconds -lt $Drop })
    return @{ Primary = $keep; Washout = $cut }
}

function Select-PartRows {
    param([object[]]$Rows, [double]$Drop, [string]$Which)
    $s = Split-Washout -Rows $Rows -Drop $Drop
    switch ($Which) {
        'primary' { return @{ Use = @($s.Primary); Other = @($s.Washout) } }
        'washout' { return @{ Use = @($s.Washout); Other = @($s.Primary) } }
        default { return @{ Use = @($Rows); Other = @() } }
    }
}

function Get-AbsMs { param([object[]]$Rows) @($Rows | Where-Object { $_.Good } | ForEach-Object { [math]::Abs($_.Offset) * 1000.0 }) }

function Get-BlockTable {
    param([object[]]$Rows, [double]$Drop, [string]$Which)
    $Rows | Group-Object { "$($_.Contender)|$($_.Case)|$($_.Ref)|$($_.Round)|$($_.Block)" } | Sort-Object Name | ForEach-Object {
        $g = @($_.Group)
        $p = Select-PartRows -Rows $g -Drop $Drop -Which $Which
        $use = $p.Use
        $good = @($use | Where-Object { $_.Good })
        $errs = $use.Count - $good.Count
        $abs = @(Get-AbsMs $use | Sort-Object)
        $dl = @($good | Where-Object { $null -ne $_.Delay } | ForEach-Object { $_.Delay * 1000.0 } | Sort-Object)
        $slope = $null
        if ($good.Count -ge 3) {
            $t0 = $good[0].T
            $slope = Get-SlopePpm -T @($good | ForEach-Object { ($_.T - $t0).TotalSeconds }) -Y @($good | ForEach-Object { $_.Offset })
        }
        $f = $g[0]
        [pscustomobject][ordered]@{
            contender = $f.Contender; case = $f.Case; reference = $f.Ref; round = $f.Round; block = $f.Block
            samples = $use.Count; dropped = $p.Other.Count; errors = $errs
            error_pct = if ($use.Count) { [math]::Round(100.0 * $errs / $use.Count, 1) } else { $null }
            median_ms = if ($abs.Count) { R3 (Get-Median $abs) } else { $null }
            p5_ms = if ($abs.Count) { R3 (Get-Percentile $abs 5) } else { $null }
            p95_ms = if ($abs.Count) { R3 (Get-Percentile $abs 95) } else { $null }
            p99_ms = if ($abs.Count) { R3 (Get-Percentile $abs 99) } else { $null }
            mean_ms = if ($abs.Count) { R3 (($abs | Measure-Object -Average).Average) } else { $null }
            max_ms = if ($abs.Count) { R3 (($abs | Measure-Object -Maximum).Maximum) } else { $null }
            delay_median_ms = if ($dl.Count) { R3 (Get-Median $dl) } else { $null }
            delay_p95_ms = if ($dl.Count) { R3 (Get-Percentile $dl 95) } else { $null }
            slope_ppm = R3 $slope
        }
    }
}

function Get-PartByBlock {
    # All rows of the selected part, as a flat list, plus the per-block slope keyed by group.
    param([object[]]$Rows, [double]$Drop, [string]$Which)
    $out = New-Object System.Collections.Generic.List[object]
    $Rows | Group-Object { "$($_.Contender)|$($_.Case)|$($_.Ref)|$($_.Round)|$($_.Block)" } | ForEach-Object {
        $p = Select-PartRows -Rows @($_.Group) -Drop $Drop -Which $Which
        foreach ($r in $p.Use) { $out.Add($r) }
    }
    , $out.ToArray()
}

function Get-PooledTable {
    param([object[]]$Rows, [object[]]$Blocks, [double]$Drop, [string]$Which)
    $sel = Get-PartByBlock -Rows $Rows -Drop $Drop -Which $Which
    $res = @($sel | Group-Object { "$($_.Contender)|$($_.Case)|$($_.Ref)" } | Sort-Object Name | ForEach-Object {
            $g = @($_.Group)
            $good = @($g | Where-Object { $_.Good })
            $abs = @(Get-AbsMs $g | Sort-Object)
            $dl = @($good | Where-Object { $null -ne $_.Delay } | ForEach-Object { $_.Delay * 1000.0 } | Sort-Object)
            $roundMeds = @($g | Group-Object Round | ForEach-Object { $a = @(Get-AbsMs @($_.Group)); if ($a.Count) { Get-Median $a } })
            $f = $g[0]
            $slopes = @($Blocks | Where-Object { $_.contender -eq $f.Contender -and $_.case -eq $f.Case -and $_.reference -eq $f.Ref -and $null -ne $_.slope_ppm } | ForEach-Object { [double]$_.slope_ppm })
            [pscustomobject][ordered]@{
                contender = $f.Contender; case = $f.Case; reference = $f.Ref
                rounds = @($g | Select-Object -ExpandProperty Round -Unique).Count
                samples = $g.Count; errors = ($g.Count - $good.Count)
                error_pct = [math]::Round(100.0 * ($g.Count - $good.Count) / $g.Count, 1)
                median_ms = if ($abs.Count) { R3 (Get-Median $abs) } else { $null }
                p99_ms = if ($abs.Count) { R3 (Get-Percentile $abs 99) } else { $null }
                max_ms = if ($abs.Count) { R3 (($abs | Measure-Object -Maximum).Maximum) } else { $null }
                delay_median_ms = if ($dl.Count) { R3 (Get-Median $dl) } else { $null }
                delay_p95_ms = if ($dl.Count) { R3 (Get-Percentile $dl 95) } else { $null }
                round_median_min_ms = if ($roundMeds.Count) { R3 (($roundMeds | Measure-Object -Minimum).Minimum) } else { $null }
                round_median_max_ms = if ($roundMeds.Count) { R3 (($roundMeds | Measure-Object -Maximum).Maximum) } else { $null }
                slope_ppm_median_of_blocks = if ($slopes.Count) { R3 (Get-Median $slopes) } else { $null }
                slope_vs_freerun_ppm = $null
            }
        })
    foreach ($r in $res) {
        $fr = @($res | Where-Object { $_.case -eq $r.case -and $_.reference -eq $r.reference -and $_.contender -like 'free-run*' -and $null -ne $_.slope_ppm_median_of_blocks })
        if ($fr.Count -gt 0 -and $null -ne $r.slope_ppm_median_of_blocks -and $r.contender -notlike 'free-run*') {
            $r.slope_vs_freerun_ppm = R3 ($r.slope_ppm_median_of_blocks - $fr[0].slope_ppm_median_of_blocks)
        }
    }
    $res
}

function Get-ComparisonTable {
    param([object[]]$Rows, [double]$Drop, [string]$Which, [string]$Primary, [string]$Baseline, [double]$MinAbsMs, [double]$MinRel, [int]$MinSignRounds)
    $sel = Get-PartByBlock -Rows $Rows -Drop $Drop -Which $Which
    $out = @()
    foreach ($case in @($sel | Select-Object -ExpandProperty Case -Unique | Sort-Object)) {
        $cr = @($sel | Where-Object { $_.Case -eq $case })
        $refs = @($cr | Select-Object -ExpandProperty Ref -Unique | Sort-Object)
        $ref = if ($Primary -and ($refs -contains $Primary)) { $Primary } else { $refs[0] }
        $cr = @($cr | Where-Object { $_.Ref -eq $ref })
        $byC = @{}
        foreach ($g in ($cr | Group-Object Contender)) { $byC[$g.Name] = @($g.Group) }
        if (-not $byC.ContainsKey($Baseline)) { continue }
        $base = $byC[$Baseline]
        $baseAbs = @(Get-AbsMs $base)
        if ($baseAbs.Count -eq 0) { continue }
        $baseMed = Get-Median $baseAbs
        $baseP99 = Get-Percentile @($baseAbs | Sort-Object) 99
        $roundMed = { param($rows, $rd) $a = @(Get-AbsMs @($rows | Where-Object { $_.Round -eq $rd })); if ($a.Count) { Get-Median $a } else { $null } }
        # A/A noise floor: the largest per-round gap between the baseline and its twin.
        $noise = $null
        $aaName = "$Baseline-aa"
        if ($byC.ContainsKey($aaName)) {
            $gaps = @()
            foreach ($rd in @($base | Select-Object -ExpandProperty Round -Unique)) {
                $a = & $roundMed $base $rd; $b = & $roundMed $byC[$aaName] $rd
                if ($null -ne $a -and $null -ne $b) { $gaps += [math]::Abs($a - $b) }
            }
            if ($gaps.Count) { $noise = ($gaps | Measure-Object -Maximum).Maximum }
        }
        foreach ($name in @($byC.Keys | Sort-Object)) {
            if ($name -eq $Baseline) { continue }
            $x = $byC[$name]
            $xAbs = @(Get-AbsMs $x)
            if ($xAbs.Count -eq 0) { continue }
            $diff = (Get-Median $xAbs) - $baseMed
            $diffP99 = (Get-Percentile @($xAbs | Sort-Object) 99) - $baseP99
            $diffs = @()
            foreach ($rd in @($x | Select-Object -ExpandProperty Round -Unique | Sort-Object)) {
                $a = & $roundMed $x $rd; $b = & $roundMed $base $rd
                if ($null -ne $a -and $null -ne $b) { $diffs += ($a - $b) }
            }
            $threshold = [math]::Max($MinAbsMs, $MinRel * $baseMed)
            $isAa = ($name -eq $aaName)
            $neg = @($diffs | Where-Object { $_ -lt 0 }).Count
            $pos = @($diffs | Where-Object { $_ -gt 0 }).Count
            $same = if ($diff -lt 0) { $neg } else { $pos }
            $need = if ($MinSignRounds -gt 0) { $MinSignRounds } else { $diffs.Count }
            $verdict = 'no meaningful difference'
            if ($isAa) { $verdict = 'A/A control' }
            elseif ([math]::Abs($diff) -ge $threshold -and ($null -eq $noise -or [math]::Abs($diff) -gt $noise) -and $diffs.Count -ge 3 -and $same -ge $need) {
                $verdict = if ($diff -lt 0) { 'better' } else { 'worse' }
            }
            $out += [pscustomobject][ordered]@{
                case = $case; reference = $ref; contender = $name; baseline = $Baseline
                rounds_compared = $diffs.Count
                diff_median_ms = R3 $diff
                diff_p99_ms = R3 $diffP99
                per_round_diff_ms = (($diffs | ForEach-Object { [string](R3 $_) }) -join ' / ')
                same_sign_rounds = "$same of $($diffs.Count)"
                threshold_ms = R3 $threshold
                aa_noise_floor_ms = R3 $noise
                verdict = $verdict
            }
        }
    }
    $out
}

function Get-AgreementTable {
    param([object[]]$Rows, [double]$Drop, [string]$Which, [double]$AgreeMs)
    $sel = Get-PartByBlock -Rows $Rows -Drop $Drop -Which $Which
    $out = @()
    foreach ($g in ($sel | Group-Object { "$($_.Contender)|$($_.Case)|$($_.Round)|$($_.Block)" } | Sort-Object Name)) {
        $refs = @($g.Group | Select-Object -ExpandProperty Ref -Unique | Sort-Object)
        if ($refs.Count -lt 2) { continue }
        $m = @{}
        foreach ($r in $refs[0..1]) {
            $v = @($g.Group | Where-Object { $_.Ref -eq $r -and $_.Good } | ForEach-Object { $_.Offset * 1000.0 })
            $m[$r] = if ($v.Count) { Get-Median $v } else { $null }
        }
        $f = $g.Group[0]
        $d = if ($null -ne $m[$refs[0]] -and $null -ne $m[$refs[1]]) { $m[$refs[0]] - $m[$refs[1]] } else { $null }
        $out += [pscustomobject][ordered]@{
            contender = $f.Contender; case = $f.Case; round = $f.Round; block = $f.Block
            ref_a = $refs[0]; ref_b = $refs[1]
            signed_median_a_ms = R3 $m[$refs[0]]; signed_median_b_ms = R3 $m[$refs[1]]
            diff_ms = R3 $d
            agree = if ($null -eq $d) { 'unknown' } elseif ([math]::Abs($d) -le $AgreeMs) { 'yes' } else { 'DISAGREE' }
        }
    }
    $out
}

function Get-RecoveryTable {
    # Events: a gap in sample times (wake from sleep) or a step in the offset (clock set wrong).
    param([object[]]$Rows, [string[]]$Cases, [double]$LimitMs, [int]$Consecutive, [double]$GapSeconds, [double]$StepMs)
    $limit = $LimitMs / 1000.0
    $step = $StepMs / 1000.0
    $out = @()
    $pick = @($Rows | Where-Object { $c = $_.Case; @($Cases | Where-Object { $c -like $_ }).Count -gt 0 })
    foreach ($g in ($pick | Group-Object { "$($_.Contender)|$($_.Case)|$($_.Ref)|$($_.Round)|$($_.Block)" } | Sort-Object Name)) {
        $r = @($g.Group)
        $n = $r.Count
        $events = @()
        $gapAt = @{}
        for ($i = 1; $i -lt $n; $i++) {
            if (($r[$i].T - $r[$i - 1].T).TotalSeconds -gt $GapSeconds) { $events += [pscustomobject]@{ Idx = $i; Type = 'gap' }; $gapAt[$i] = $true }
        }
        for ($i = 1; $i -lt $n; $i++) {
            if ($gapAt.ContainsKey($i)) { continue }
            if ($r[$i].Good -and $r[$i - 1].Good -and [math]::Abs($r[$i].Offset) -gt $step -and [math]::Abs($r[$i - 1].Offset) -le $limit) { $events += [pscustomobject]@{ Idx = $i; Type = 'step' } }
        }
        foreach ($e in @($events | Sort-Object Idx)) {
            $idx = $e.Idx
            $rec = $null
            for ($j = $idx; $j -le $n - $Consecutive; $j++) {
                $ok = $true
                for ($k = 0; $k -lt $Consecutive; $k++) {
                    if (-not ($r[$j + $k].Good -and [math]::Abs($r[$j + $k].Offset) -lt $limit)) { $ok = $false; break }
                }
                if ($ok) { $rec = ($r[$j].T - $r[$idx].T).TotalSeconds; break }
            }
            $f = $r[0]
            $out += [pscustomobject][ordered]@{
                contender = $f.Contender; case = $f.Case; reference = $f.Ref; round = $f.Round; block = $f.Block
                event = $e.Type; event_utc = $r[$idx].T.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", $script:Inv)
                recovery_s = if ($null -ne $rec) { R3 $rec } else { 'not recovered' }
            }
        }
    }
    $out
}

function Get-RecoverySummary {
    param([object[]]$Recovery)
    $out = @()
    foreach ($g in ($Recovery | Group-Object { "$($_.contender)|$($_.case)|$($_.reference)|$($_.event)" } | Sort-Object Name)) {
        $ok = @($g.Group | Where-Object { $_.recovery_s -isnot [string] } | ForEach-Object { [double]$_.recovery_s })
        $f = $g.Group[0]
        $out += [pscustomobject][ordered]@{
            contender = $f.contender; case = $f.case; reference = $f.reference; event = $f.event
            events = $g.Count; not_recovered = ($g.Count - $ok.Count)
            median_s = if ($ok.Count) { R3 (Get-Median $ok) } else { $null }
            worst_s = if ($ok.Count) { R3 (($ok | Measure-Object -Maximum).Maximum) } else { $null }
        }
    }
    $out
}

function Format-SummaryText {
    # Own fixed-width table. Format-Table drops columns that do not fit the host width.
    param([object[]]$Summary)
    if (-not $Summary -or $Summary.Count -eq 0) { return '(none)' }
    $cols = $Summary[0].PSObject.Properties.Name
    $cells = @($Summary | ForEach-Object { $row = $_; , @($cols | ForEach-Object { $v = $row.$_; if ($null -eq $v -or ([string]$v) -eq '') { '-' } else { ([string]$v) } }) })
    $w = @(for ($i = 0; $i -lt $cols.Count; $i++) { $m = $cols[$i].Length; foreach ($c in $cells) { if ($c[$i].Length -gt $m) { $m = $c[$i].Length } }; $m })
    $line = { param($vals) (0..($vals.Count - 1) | ForEach-Object { $vals[$_].PadRight($w[$_]) }) -join '  ' }
    $out = @((& $line $cols).TrimEnd(), (& $line @($w | ForEach-Object { '-' * $_ })).TrimEnd())
    foreach ($c in $cells) { $out += (& $line $c).TrimEnd() }
    $out -join "`n"
}

function Get-OffsetReport {
    param([object[]]$Rows)
    $blocks = @(Get-BlockTable -Rows $Rows -Drop $DropSeconds -Which $Part)
    [pscustomobject]@{
        Blocks = $blocks
        Pooled = @(Get-PooledTable -Rows $Rows -Blocks $blocks -Drop $DropSeconds -Which $Part)
        Comparison = @(Get-ComparisonTable -Rows $Rows -Drop $DropSeconds -Which $Part -Primary $Primary -Baseline $Baseline -MinAbsMs $MinAbsMs -MinRel $MinRel -MinSignRounds $MinSignRounds)
        Agreement = @(Get-AgreementTable -Rows $Rows -Drop $DropSeconds -Which $Part -AgreeMs $AgreeMs)
        Recovery = @(Get-RecoveryTable -Rows $Rows -Cases $RecoveryCases -LimitMs $LimitMs -Consecutive $Consecutive -GapSeconds $GapSeconds -StepMs $StepMs)
    }
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
        if ($r[0].PSObject.Properties.Name -notcontains 'round') {
            Write-Warning "summarise-offset: $($f.Name) has no round column. Read as round 0. Per-round figures are not meaningful."
        }
        $rows += @(ConvertTo-TypedRows -Csv $r)
    }
    $rep = Get-OffsetReport -Rows $rows
    $refs = @($rows | Select-Object -ExpandProperty Ref -Unique)
    if ($refs.Count -gt 1 -and -not $Primary) { Write-Warning "summarise-offset: several references and no -Primary. The comparison uses the first reference per case." }
    $script:Report = $rep
    if ($AsObject) { return 0 }
    Write-Host "== 1 Blocks (part: $Part, drop first $DropSeconds s)"; Write-Host (Format-SummaryText $rep.Blocks)
    Write-Host "`n== 2 Pooled over rounds"; Write-Host (Format-SummaryText $rep.Pooled)
    Write-Host "`n== 3 Comparison against $Baseline (primary reference)"; Write-Host (Format-SummaryText $rep.Comparison)
    Write-Host "`n== 4 Agreement between two references per block (limit $AgreeMs ms)"; Write-Host (Format-SummaryText $rep.Agreement)
    Write-Host "`n== 5 Recovery events (limit $LimitMs ms for $Consecutive rows)"; Write-Host (Format-SummaryText $rep.Recovery)
    if ($rep.Recovery.Count) { Write-Host "`n== 5b Recovery per contender"; Write-Host (Format-SummaryText @(Get-RecoverySummary $rep.Recovery)) }
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    $script:Report = $null
    $code = Invoke-Summarise
    if ($AsObject -and $script:Report) { $script:Report }
    exit $code
}
