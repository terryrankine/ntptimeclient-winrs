<#
.SYNOPSIS
  Summarises CSVs from measure-offset.ps1. Read only.

.DESCRIPTION
  Output, in order:
    Flagged blocks   blocks whose two references disagree, that lack a second reference, or whose
                     start was not clean. Their ROUND is excluded for that case, for every
                     contender, so pairs stay balanced. The count and the list are always printed.
                     -IncludeFlagged keeps them in the tables (the appendix view).
    PRIMARY          five verdict lines P1 to P5, the service against the baseline. Only these
                     five lines are primary. Everything below them is exploratory.
    Exploratory      1 Blocks, 2 Pooled, 3 Comparison, 4 Agreement, 5 Recovery, 5b Recovery summary.

  Verdict structure, the same for all five: same sign across the rounds, a threshold, a noise
  floor from the A/A twin (<baseline>-aa), a minimum number of rounds, a p99 condition (offset
  cases), an error rate condition, and for recovery cases an unrecovered event is a loss. A
  verdict is better, worse, mixed, no meaningful difference, 'no noise floor, cannot call',
  'not enough rounds', 'no data' or '(baseline missing)'.

  Unrecovered events are censored: they count as infinity in recovery medians and are never dropped.

  The offset is positive when the reference is ahead. A rising offset means the local clock is
  losing time relative to the reference. Slope is a residual trend for a disciplined clock. Only
  a free-run contender has a drift figure. Slope is not printed for event cases.

  Old CSVs without a round column are read as round 0 with a warning. Exit 0 ok, 2 bad input.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)][string[]]$Path,
    [switch]$AsObject,
    [switch]$IncludeFlagged,
    [double]$DropSeconds = 0,
    [string[]]$NoDropCases = @('sleep*', 'disturb*', 'long*'),
    [ValidateSet('primary', 'washout', 'all')][string]$Part = 'primary',
    [string]$Primary = '',
    [string]$Baseline = 'w32time-default',
    [string]$Contender = 'service',
    [double]$MinAbsMs = 1,
    [double]$MinRel = 0.2,
    [int]$MinSignRounds = 0,
    [int]$MinRounds = 3,
    [double]$ErrPp = 2,
    [double]$AgreeMs = 2,
    [double]$LimitMs = 10,
    [int]$Consecutive = 3,
    [double]$GapSeconds = 120,
    [double]$StepMs = 100,
    [double]$RecoveryMinPeriods = 2,
    [string[]]$RecoveryCases = @('sleep*', 'disturb*')
)

Set-StrictMode -Version Latest
$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture
$script:Inf = [double]::PositiveInfinity

function Get-Median {
    # Interpolated: the mean of the two middle values for an even count. Infinity is allowed.
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

function R3($v) {
    if ($null -eq $v) { return $null }
    $d = [double]$v
    if ([double]::IsPositiveInfinity($d)) { return 'not recovered' }
    if ([double]::IsNaN($d) -or [double]::IsNegativeInfinity($d)) { return $null }
    return [math]::Round($d, 3)
}

function Test-CaseLike { param([string]$Case, [string[]]$Patterns) @($Patterns | Where-Object { $Case -like $_ }).Count -gt 0 }

function ConvertTo-TypedRows {
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

function Select-PartRows {
    # Wash-out is dropped only for cases that are not in -NoDropCases (event and long cases keep every row).
    param([object[]]$Rows, [double]$Drop, [string]$Which)
    if ($Rows.Count -eq 0) { return @{ Use = @(); Other = @() } }
    $eff = if (Test-CaseLike $Rows[0].Case $NoDropCases) { 0 } else { $Drop }
    if ($Which -eq 'all') { return @{ Use = @($Rows); Other = @() } }
    $t0 = $Rows[0].T
    $keep = @($Rows | Where-Object { ($_.T - $t0).TotalSeconds -ge $eff })
    $cut = @($Rows | Where-Object { ($_.T - $t0).TotalSeconds -lt $eff })
    if ($Which -eq 'washout') { return @{ Use = $cut; Other = $keep } }
    return @{ Use = $keep; Other = $cut }
}

function Get-AbsMs { param([object[]]$Rows) @($Rows | Where-Object { $_.Good } | ForEach-Object { [math]::Abs($_.Offset) * 1000.0 }) }
function Get-GroupKey { param($r) "$($r.Contender)|$($r.Case)|$($r.Ref)|$($r.Round)|$($r.Block)" }

function Get-PartByBlock {
    param([object[]]$Rows, [double]$Drop, [string]$Which)
    $out = New-Object System.Collections.Generic.List[object]
    $Rows | Group-Object { Get-GroupKey $_ } | ForEach-Object {
        $p = Select-PartRows -Rows @($_.Group) -Drop $Drop -Which $Which
        foreach ($r in $p.Use) { $out.Add($r) }
    }
    $out.ToArray()
}

function Get-BlockFlags {
    # One row per flagged block. Uses the primary part (event and long cases use every row).
    param([object[]]$Rows, [double]$Drop, [double]$AgreeMs)
    $flags = @()
    $partRows = @(Get-PartByBlock -Rows $Rows -Drop $Drop -Which 'primary')
    $blocks = @($Rows | Group-Object { "$($_.Contender)|$($_.Case)|$($_.Round)|$($_.Block)" } | Sort-Object Name)
    $twoRef = $false
    foreach ($g in $blocks) { if (@($g.Group | Select-Object -ExpandProperty Ref -Unique).Count -ge 2) { $twoRef = $true } }
    foreach ($g in $blocks) {
        $f = $g.Group[0]
        $id = "$($f.Case) round $($f.Round) block $($f.Block) $($f.Contender)"
        $refs = @($g.Group | Select-Object -ExpandProperty Ref -Unique | Sort-Object)
        if ($f.Block -like '*-unclean') {
            $flags += [pscustomobject][ordered]@{ case = $f.Case; round = $f.Round; block = $f.Block; contender = $f.Contender; flag = 'start not clean'; detail = ''; id = $id }
        }
        if ($twoRef -and $refs.Count -lt 2) {
            $flags += [pscustomobject][ordered]@{ case = $f.Case; round = $f.Round; block = $f.Block; contender = $f.Contender; flag = 'no second reference'; detail = ''; id = $id }
        }
        elseif ($refs.Count -ge 2) {
            $pr = @($partRows | Where-Object { $_.Contender -eq $f.Contender -and $_.Case -eq $f.Case -and $_.Round -eq $f.Round -and $_.Block -eq $f.Block })
            $m = @{}
            foreach ($r in $refs[0..1]) {
                $v = @($pr | Where-Object { $_.Ref -eq $r -and $_.Good } | ForEach-Object { $_.Offset * 1000.0 })
                $m[$r] = if ($v.Count) { Get-Median $v } else { $null }
            }
            if ($null -eq $m[$refs[0]] -or $null -eq $m[$refs[1]]) {
                $flags += [pscustomobject][ordered]@{ case = $f.Case; round = $f.Round; block = $f.Block; contender = $f.Contender; flag = 'no data from a reference'; detail = ''; id = $id }
            }
            else {
                $d = $m[$refs[0]] - $m[$refs[1]]
                if ([math]::Abs($d) -gt $AgreeMs) {
                    $flags += [pscustomobject][ordered]@{ case = $f.Case; round = $f.Round; block = $f.Block; contender = $f.Contender; flag = 'DISAGREE'; detail = "$([math]::Round($d, 3)) ms"; id = $id }
                }
            }
        }
    }
    $flags
}

function Get-BlockTable {
    param([object[]]$Rows, [double]$Drop, [string]$Which)
    $Rows | Group-Object { Get-GroupKey $_ } | Sort-Object Name | ForEach-Object {
        $g = @($_.Group)
        $p = Select-PartRows -Rows $g -Drop $Drop -Which $Which
        $use = $p.Use
        $good = @($use | Where-Object { $_.Good })
        $errs = $use.Count - $good.Count
        $abs = @(Get-AbsMs $use | Sort-Object)
        $dl = @($good | Where-Object { $null -ne $_.Delay } | ForEach-Object { $_.Delay * 1000.0 } | Sort-Object)
        $slope = $null
        if ($good.Count -ge 3 -and -not (Test-CaseLike $g[0].Case $RecoveryCases)) {
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

function Get-PooledTable {
    param([object[]]$Rows, [object[]]$Blocks, [double]$Drop, [string]$Which)
    $sel = @(Get-PartByBlock -Rows $Rows -Drop $Drop -Which $Which)
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

function Get-RecoveryTable {
    # Events: a gap in sample times (wake from sleep) or a step in the offset (clock set wrong).
    # Step rule: the previous GOOD row is at or below the limit and the next GOOD row is above the
    # step size. Error rows between them are skipped. The event row is that next good row.
    # Recovery: the first row that starts Consecutive good rows below the limit. An error row breaks the run.
    param([object[]]$Rows, [string[]]$Cases, [double]$LimitMs, [int]$Consecutive, [double]$GapSeconds, [double]$StepMs)
    $limit = $LimitMs / 1000.0
    $step = $StepMs / 1000.0
    $out = @()
    $pick = @($Rows | Where-Object { Test-CaseLike $_.Case $Cases })
    foreach ($g in ($pick | Group-Object { Get-GroupKey $_ } | Sort-Object Name)) {
        $r = @($g.Group)
        $n = $r.Count
        $events = @()
        $gapAt = @{}
        for ($i = 1; $i -lt $n; $i++) {
            if (($r[$i].T - $r[$i - 1].T).TotalSeconds -gt $GapSeconds) { $events += [pscustomobject]@{ Idx = $i; Type = 'gap' }; $gapAt[$i] = $true }
        }
        $goodIdx = @(for ($i = 0; $i -lt $n; $i++) { if ($r[$i].Good) { $i } })
        for ($k = 1; $k -lt $goodIdx.Count; $k++) {
            $a = $goodIdx[$k - 1]; $b = $goodIdx[$k]
            if ($gapAt.ContainsKey($b)) { continue }
            if ([math]::Abs($r[$a].Offset) -le $limit -and [math]::Abs($r[$b].Offset) -gt $step) { $events += [pscustomobject]@{ Idx = $b; Type = 'step' } }
        }
        foreach ($e in @($events | Sort-Object Idx)) {
            $idx = $e.Idx
            $rec = $script:Inf
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
                recovery_s = R3 $rec
                recovery_value = [double]$rec
            }
        }
    }
    $out
}

function Get-RecoverySummary {
    # Unrecovered events count as infinity in the median and the worst. They are never dropped.
    # The median is finite only when more than half of the events recovered.
    param([object[]]$Recovery)
    $out = @()
    foreach ($g in ($Recovery | Group-Object { "$($_.contender)|$($_.case)|$($_.reference)|$($_.event)" } | Sort-Object Name)) {
        $vals = @($g.Group | ForEach-Object { [double]$_.recovery_value })
        $rec = @($vals | Where-Object { -not [double]::IsPositiveInfinity($_) })
        $f = $g.Group[0]
        $out += [pscustomobject][ordered]@{
            contender = $f.contender; case = $f.case; reference = $f.reference; event = $f.event
            events = $vals.Count; recovered = $rec.Count; not_recovered = ($vals.Count - $rec.Count)
            fraction_recovered = [math]::Round($rec.Count / [double]$vals.Count, 3)
            median_s = R3 (Get-Median $vals)
            worst_s = R3 (($vals | Measure-Object -Maximum).Maximum)
        }
    }
    $out
}

function Get-PeriodSeconds {
    param([object[]]$Rows)
    $d = @()
    foreach ($g in ($Rows | Group-Object { Get-GroupKey $_ })) {
        $r = @($g.Group)
        for ($i = 1; $i -lt $r.Count; $i++) { $x = ($r[$i].T - $r[$i - 1].T).TotalSeconds; if ($x -gt 0 -and $x -lt $GapSeconds) { $d += $x } }
    }
    if ($d.Count) { Get-Median $d } else { 0 }
}

function Get-Units {
    # Round -> values. Offset metric: absolute offsets in ms. Recovery metric: recovery seconds, infinity if not recovered.
    param([object[]]$Rows, [object[]]$Events, [string]$Case, [string]$Ref, [string]$Name, [string]$Metric)
    $u = @{}
    if ($Metric -eq 'abs') {
        foreach ($g in ($Rows | Where-Object { $_.Case -eq $Case -and $_.Ref -eq $Ref -and $_.Contender -eq $Name } | Group-Object Round)) {
            $a = @(Get-AbsMs @($g.Group)); if ($a.Count) { $u[[int]$g.Name] = $a }
        }
    }
    else {
        foreach ($g in ($Events | Where-Object { $_.case -eq $Case -and $_.reference -eq $Ref -and $_.contender -eq $Name } | Group-Object round)) {
            $u[[int]$g.Name] = @($g.Group | ForEach-Object { [double]$_.recovery_value })
        }
    }
    $u
}

function Get-ErrPct { param([object[]]$Rows, [string]$Case, [string]$Ref, [string]$Name)
    $x = @($Rows | Where-Object { $_.Case -eq $Case -and $_.Ref -eq $Ref -and $_.Contender -eq $Name })
    if ($x.Count -eq 0) { return $null }
    100.0 * @($x | Where-Object { -not $_.Good }).Count / $x.Count
}

function Get-Verdict {
    # One comparison of Name against Baseline for one case and one metric. All five primary
    # verdicts and every exploratory verdict come from this one function.
    param([object[]]$Rows, [object[]]$Events, [string]$Case, [string]$Ref, [string]$Name, [string]$Baseline, [string]$Metric)
    $res = [ordered]@{ case = $Case; metric = $Metric; reference = $Ref; contender = $Name; baseline = $Baseline
        rounds_compared = 0; x_pooled = $null; base_pooled = $null; diff = $null; per_round_diff = ''; same_sign_rounds = ''
        threshold = $null; aa_noise_floor = $null; diff_p99_ms = $null; error_pct_diff = $null; unrecovered = ''; verdict = ''; reason = '' }
    $fin = { param($v, $d) $res.verdict = $v; $res.reason = $d; return [pscustomobject]$res }
    $rowsC = @($Rows | Where-Object { $_.Case -eq $Case -and $_.Ref -eq $Ref })
    if (@($rowsC | Where-Object { $_.Contender -eq $Baseline }).Count -eq 0) {
        return (& $fin '(baseline missing)' "The baseline contender '$Baseline' has no data for case $Case on reference $Ref. Nothing can be compared.")
    }
    $ux = Get-Units -Rows $rowsC -Events $Events -Case $Case -Ref $Ref -Name $Name -Metric $Metric
    $ub = Get-Units -Rows $rowsC -Events $Events -Case $Case -Ref $Ref -Name $Baseline -Metric $Metric
    $ua = Get-Units -Rows $rowsC -Events $Events -Case $Case -Ref $Ref -Name "$Baseline-aa" -Metric $Metric
    if ($ux.Count -eq 0 -or $ub.Count -eq 0) { return (& $fin 'no data' "No $Metric data for $Name or for $Baseline in case $Case.") }
    $all = { param($u) @($u.Keys | ForEach-Object { $u[$_] } | ForEach-Object { $_ }) }
    $vx = @(& $all $ux); $vb = @(& $all $ub)
    $res.x_pooled = Get-Median $vx; $res.base_pooled = Get-Median $vb
    $unrX = @($vx | Where-Object { [double]::IsPositiveInfinity($_) }).Count
    $unrB = @($vb | Where-Object { [double]::IsPositiveInfinity($_) }).Count
    $res.unrecovered = "$unrX of $($vx.Count) versus $unrB of $($vb.Count)"
    if ($Metric -eq 'recovery' -and $unrX -gt $unrB) {
        return (& $fin 'worse' "$Name did not recover in $unrX of $($vx.Count) events and $Baseline did not in $unrB of $($vb.Count). An unrecovered event counts as a loss.")
    }
    if ($ua.Count -eq 0) { return (& $fin 'no noise floor, cannot call' "There is no $Baseline-aa twin in case $Case, so the noise floor is unknown. No verdict is given.") }
    $roundsXB = @($ux.Keys | Where-Object { $ub.ContainsKey($_) } | Sort-Object)
    $res.rounds_compared = $roundsXB.Count
    if ($roundsXB.Count -lt $MinRounds) { return (& $fin 'not enough rounds' "Only $($roundsXB.Count) common rounds. At least $MinRounds are needed.") }
    $diffs = @()
    foreach ($rd in $roundsXB) { $d = (Get-Median $ux[$rd]) - (Get-Median $ub[$rd]); if (-not [double]::IsNaN($d)) { $diffs += $d } }
    $res.per_round_diff = (($diffs | ForEach-Object { [string](R3 $_) }) -join ' / ')
    $gaps = @()
    foreach ($rd in @($ub.Keys | Where-Object { $ua.ContainsKey($_) })) { $g = [math]::Abs((Get-Median $ub[$rd]) - (Get-Median $ua[$rd])); if (-not [double]::IsNaN($g)) { $gaps += $g } }
    if ($gaps.Count -eq 0) { return (& $fin 'no noise floor, cannot call' "The A/A twin shares no usable round with $Baseline in case $Case. No verdict is given.") }
    $noise = ($gaps | Measure-Object -Maximum).Maximum
    $res.aa_noise_floor = $noise
    $diff = $res.x_pooled - $res.base_pooled
    $res.diff = $diff
    if ($Metric -eq 'abs') { $thr = [math]::Max($MinAbsMs, $MinRel * $res.base_pooled); $unit = 'ms' }
    else { $thr = [math]::Max($MinRel * $res.base_pooled, $RecoveryMinPeriods * (Get-PeriodSeconds $rowsC)); $unit = 's' }
    $res.threshold = $thr
    $neg = @($diffs | Where-Object { $_ -lt 0 }).Count
    $pos = @($diffs | Where-Object { $_ -gt 0 }).Count
    $same = if ($diff -lt 0) { $neg } else { $pos }
    $need = if ($MinSignRounds -gt 0) { $MinSignRounds } else { $diffs.Count }
    $res.same_sign_rounds = "$same of $($diffs.Count)"
    $why = "pooled $(R3 $res.x_pooled) $unit versus $(R3 $res.base_pooled) $unit, difference $(R3 $diff) $unit, threshold $(R3 $thr) $unit, A/A noise floor $(R3 $noise) $unit, same sign in $same of $($diffs.Count) rounds"
    $meaningful = ([math]::Abs($diff) -ge $thr) -and ([math]::Abs($diff) -gt $noise) -and ($diffs.Count -ge $MinRounds) -and ($same -ge $need)
    if (-not $meaningful) { return (& $fin 'no meaningful difference' $why) }
    if ($diff -gt 0) { return (& $fin 'worse' $why) }
    # A better median is a win only when the p99 and the error rate do not object.
    $extra = @()
    if ($Metric -eq 'abs') {
        $px = Get-Percentile @($vx | Sort-Object) 99; $pb = Get-Percentile @($vb | Sort-Object) 99
        $res.diff_p99_ms = $px - $pb
        if (($px - $pb) -gt [math]::Max($MinAbsMs, $MinRel * $pb)) { $extra += "p99 is worse by $(R3 ($px - $pb)) ms" }
    }
    $ex = Get-ErrPct $Rows $Case $Ref $Name; $eb = Get-ErrPct $Rows $Case $Ref $Baseline
    $ed = $ex - $eb
    $note = ''
    if ($Case -like 'load*') {
        $ix = Get-ErrPct $Rows 'idle' $Ref $Name; $ib = Get-ErrPct $Rows 'idle' $Ref $Baseline
        if ($null -ne $ix -and $null -ne $ib) { $ed = ($ex - $ix) - ($eb - $ib); $note = ' (rise from idle compared with the baseline rise)' } else { $note = ' (no idle data for the load rule)' }
    }
    $res.error_pct_diff = $ed
    if ($ed -gt $ErrPp) { $extra += "error rate is higher by $(R3 $ed) points$note" }
    if ($extra.Count -gt 0) { return (& $fin 'mixed' ($why + '. Median is better but ' + ($extra -join ' and '))) }
    return (& $fin 'better' $why)
}

function Get-ComparisonTable {
    # Exploratory: every contender against the baseline, every case, offset metric, plus recovery in event cases.
    param([object[]]$Rows, [object[]]$Events, [string]$Primary, [string]$Baseline)
    $out = @()
    foreach ($case in @($Rows | Select-Object -ExpandProperty Case -Unique | Sort-Object)) {
        $refs = @($Rows | Where-Object { $_.Case -eq $case } | Select-Object -ExpandProperty Ref -Unique | Sort-Object)
        $ref = if ($Primary -and ($refs -contains $Primary)) { $Primary } else { $refs[0] }
        $metrics = @('abs'); if (Test-CaseLike $case $RecoveryCases) { $metrics = @('recovery') }
        foreach ($name in @($Rows | Where-Object { $_.Case -eq $case -and $_.Ref -eq $ref } | Select-Object -ExpandProperty Contender -Unique | Sort-Object)) {
            if ($name -eq $Baseline) { continue }
            foreach ($m in $metrics) {
                $v = Get-Verdict -Rows $Rows -Events $Events -Case $case -Ref $ref -Name $name -Baseline $Baseline -Metric $m
                if ($name -eq "$Baseline-aa") { $v.verdict = 'A/A control' }
                $out += $v
            }
        }
    }
    $out
}

function Get-PrimaryVerdicts {
    param([object[]]$Rows, [object[]]$Events, [string]$Primary, [string]$Baseline, [string]$Name)
    $defs = @(
        @{ Id = 'P1'; Case = 'idle'; Metric = 'abs'; Text = 'median absolute offset' },
        @{ Id = 'P2'; Case = 'load'; Metric = 'abs'; Text = 'median absolute offset' },
        @{ Id = 'P3'; Case = 'vm'; Metric = 'abs'; Text = 'median absolute offset' },
        @{ Id = 'P4'; Case = 'sleep'; Metric = 'recovery'; Text = 'median recovery after wake' },
        @{ Id = 'P5'; Case = 'disturb2s'; Metric = 'recovery'; Text = 'median recovery after step' })
    foreach ($d in $defs) {
        $refs = @($Rows | Where-Object { $_.Case -eq $d.Case } | Select-Object -ExpandProperty Ref -Unique | Sort-Object)
        if ($refs.Count -eq 0) {
            [pscustomobject][ordered]@{ id = $d.Id; case = $d.Case; metric = $d.Text; verdict = 'no data'; reason = "No rows for case $($d.Case)." }
            continue
        }
        $ref = if ($Primary -and ($refs -contains $Primary)) { $Primary } else { $refs[0] }
        $v = Get-Verdict -Rows $Rows -Events $Events -Case $d.Case -Ref $ref -Name $Name -Baseline $Baseline -Metric $d.Metric
        [pscustomobject][ordered]@{ id = $d.Id; case = $d.Case; metric = $d.Text; verdict = $v.verdict; reason = $v.reason }
    }
}

function Get-AgreementTable {
    param([object[]]$Rows, [double]$Drop, [string]$Which, [double]$AgreeMs, [object[]]$Flags)
    $sel = @(Get-PartByBlock -Rows $Rows -Drop $Drop -Which $Which)
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

function Format-SummaryText {
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
    $flags = @(Get-BlockFlags -Rows $Rows -Drop $DropSeconds -AgreeMs $AgreeMs)
    $excl = @($flags | ForEach-Object { "$($_.case)|$($_.round)" } | Select-Object -Unique)
    $use = @($Rows | Where-Object { $IncludeFlagged -or ($excl -notcontains "$($_.Case)|$($_.Round)") })
    $blocks = @(Get-BlockTable -Rows $use -Drop $DropSeconds -Which $Part)
    $partRows = @(Get-PartByBlock -Rows $use -Drop $DropSeconds -Which $Part)
    $events = @(Get-RecoveryTable -Rows $use -Cases $RecoveryCases -LimitMs $LimitMs -Consecutive $Consecutive -GapSeconds $GapSeconds -StepMs $StepMs)
    [pscustomobject]@{
        Flags = $flags
        ExcludedRounds = $(if ($IncludeFlagged) { @() } else { $excl })
        Primary = @(Get-PrimaryVerdicts -Rows $partRows -Events $events -Primary $Primary -Baseline $Baseline -Name $Contender)
        Blocks = $blocks
        Pooled = @(Get-PooledTable -Rows $use -Blocks $blocks -Drop $DropSeconds -Which $Part)
        Comparison = @(Get-ComparisonTable -Rows $partRows -Events $events -Primary $Primary -Baseline $Baseline)
        Agreement = @(Get-AgreementTable -Rows $Rows -Drop $DropSeconds -Which $Part -AgreeMs $AgreeMs)
        Recovery = $events
        RecoverySummary = @(Get-RecoverySummary $events)
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
    $script:Report = $rep
    if ($AsObject) { return 0 }
    $refs = @($rows | Select-Object -ExpandProperty Ref -Unique)
    if ($refs.Count -gt 1 -and -not $Primary) { Write-Warning "summarise-offset: several references and no -Primary. Comparisons use the first reference per case." }
    $nEx = @($rep.ExcludedRounds).Count
    Write-Host "== Flagged blocks: $(@($rep.Flags).Count). Excluded case-rounds: $nEx$(if ($IncludeFlagged) { ' (none excluded, -IncludeFlagged is set)' })"
    if (@($rep.Flags).Count) { Write-Host (Format-SummaryText @($rep.Flags | Select-Object case, round, block, contender, flag, detail)) }
    Write-Host "`n== PRIMARY (service against $Baseline). Only these five lines are primary. Everything below is exploratory."
    foreach ($v in $rep.Primary) { Write-Host ("{0} {1}, {2}: {3}. {4}" -f $v.id, $v.case, $v.metric, $v.verdict.ToUpper(), $v.reason) }
    Write-Host "`n== EXPLORATORY 1 Blocks (part: $Part, drop first $DropSeconds s where the case allows)"; Write-Host (Format-SummaryText $rep.Blocks)
    Write-Host "`n== EXPLORATORY 2 Pooled over rounds"; Write-Host (Format-SummaryText $rep.Pooled)
    Write-Host "`n== EXPLORATORY 3 Comparison against $Baseline (primary reference)"
    Write-Host (Format-SummaryText @($rep.Comparison | Select-Object case, metric, contender, rounds_compared, @{ n = 'diff'; e = { R3 $_.diff } }, @{ n = 'diff_p99_ms'; e = { R3 $_.diff_p99_ms } }, @{ n = 'error_pct_diff'; e = { R3 $_.error_pct_diff } }, per_round_diff, same_sign_rounds, @{ n = 'threshold'; e = { R3 $_.threshold } }, @{ n = 'noise_floor'; e = { R3 $_.aa_noise_floor } }, unrecovered, verdict))
    Write-Host "`n== EXPLORATORY 4 Agreement between two references per block (limit $AgreeMs ms, all blocks)"; Write-Host (Format-SummaryText $rep.Agreement)
    Write-Host "`n== EXPLORATORY 5 Recovery events (limit $LimitMs ms for $Consecutive rows)"; Write-Host (Format-SummaryText @($rep.Recovery | Select-Object contender, case, reference, round, block, event, event_utc, recovery_s))
    if (@($rep.RecoverySummary).Count) { Write-Host "`n== EXPLORATORY 5b Recovery per contender"; Write-Host (Format-SummaryText $rep.RecoverySummary) }
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    $script:Report = $null
    $code = Invoke-Summarise
    if ($AsObject -and $script:Report) { $script:Report }
    exit $code
}
