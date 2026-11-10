<#
.SYNOPSIS
  Samples the clock offset to one NTP reference with w32tm /stripchart and writes a CSV.

.DESCRIPTION
  Read only. Needs no admin rights. Changes no system state. It runs
  `w32tm /stripchart /computer:<ref> /samples:N /period:S /dataonly /rdtsc`
  and parses each line. A failed sample is never dropped. It becomes a row with an
  error text and it counts toward the error rate.

  CSV columns: utc_iso, contender, case, reference, offset_s, delay_s, error
  Offset is as w32tm reports it: seconds, between this computer and the reference,
  seen through the network path. It is not true UTC error.

  Exit codes: 0 finished, 1 run failed (w32tm missing or every sample failed), 2 bad input.

.EXAMPLE
  .\measure-offset.ps1 -Reference 162.159.200.1 -Contender w32time-default -Case idle -Samples 450 -PeriodSeconds 16 -OutPath .\out\w32time-default-idle.csv
#>
[CmdletBinding()]
param(
    [string]$Reference,
    [string]$Contender,
    [string]$Case,
    [int]$Samples = 0,
    [int]$PeriodSeconds = 0,
    [string]$OutPath,
    [switch]$Plain,
    [switch]$AllowPool
)

Set-StrictMode -Version Latest

$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture
$script:NumRe = '[+\-' + [char]0x2212 + ']\s?\d+(?:[.,]\d+)?[sSdD]?'

function ConvertTo-StripchartNumber {
    # Returns @{ Value; Note }. Handles ',' decimals, a unicode minus and the s or d suffix.
    param([Parameter(Mandatory)][string]$Token)
    $t = $Token.Trim().Replace([string][char]0x2212, '-').Replace(' ', '').Replace(',', '.')
    $note = ''
    $mult = 1.0
    if ($t -match '[dD]$') { $mult = 86400.0; $note = 'unit d read as days (unverified)' }
    $t = $t -replace '[sSdD]$', ''
    $v = 0.0
    if (-not [double]::TryParse($t, [System.Globalization.NumberStyles]::Float, $script:Inv, [ref]$v)) {
        return @{ Value = $null; Note = "unparsable number '$Token'" }
    }
    return @{ Value = ($v * $mult); Note = $note }
}

function ConvertFrom-StripchartLine {
    <#
      Kind: Blank, Preamble, Data, Error, Fatal, Unknown.
      Data and Error rows carry OffsetS, DelayS, FileTimeUtc (rdtsc only) and Error.
    #>
    param([AllowEmptyString()][string]$Line)

    $r = [ordered]@{ Kind = 'Unknown'; OffsetS = $null; DelayS = $null; FileTimeUtc = $null; Error = ''; Ip = ''; Raw = $Line }
    $l = if ($null -eq $Line) { '' } else { $Line.Trim() }
    if ($l -eq '') { $r.Kind = 'Blank'; return [pscustomobject]$r }

    if ($l -match '^Tracking\s') {
        $r.Kind = 'Preamble'
        if ($l -match '\[([^\]]+?)(?::\d+)?\]') { $r.Ip = $Matches[1] }
        return [pscustomobject]$r
    }
    if ($l -match '^(Collecting\s|The current time|RdtscStart)') { $r.Kind = 'Preamble'; return [pscustomobject]$r }
    if ($l -match '^The following error occurred') { $r.Kind = 'Fatal'; $r.Error = $l; return [pscustomobject]$r }

    $rest = $null
    if ($l -match '^\d+\s*,\s*\d+\s*,\s*(\d+)\s*,\s*(.*)$') {
        # rdtsc: RdtscStart, RdtscEnd, FileTime, RoundtripDelay, NtpOffset
        $ft = [long]0
        if ([long]::TryParse($Matches[1], [ref]$ft) -and $ft -gt 0) {
            try { $r.FileTimeUtc = [DateTime]::FromFileTimeUtc($ft) } catch { $r.FileTimeUtc = $null }
        }
        $rest = $Matches[2]
        $isRdtsc = $true
    }
    elseif ($l -match '^\d{1,2}[:.]\d{2}[:.]\d{2}\S*\s*(?:[AaPp]\.?[Mm]\.?)?\s*,\s*(.*)$') {
        $rest = $Matches[1]
        $isRdtsc = $false
    }
    else {
        $r.Error = "unparsed line: $l"
        return [pscustomobject]$r
    }

    if ($rest -match '(?i)error') {
        $r.Kind = 'Error'
        $r.Error = if ($rest -match '(0x[0-9A-Fa-f]{1,8})') { "w32tm error $($Matches[1])" } else { "w32tm error: $rest" }
        return [pscustomobject]$r
    }

    $tokens = @([regex]::Matches($rest, $script:NumRe) | ForEach-Object { $_.Value })
    $need = if ($isRdtsc) { 2 } else { 1 }
    if ($tokens.Count -ne $need) {
        $r.Kind = 'Error'
        $r.Error = "unparsed line: $l"
        return [pscustomobject]$r
    }
    $notes = @()
    $off = ConvertTo-StripchartNumber $tokens[$need - 1]
    $r.OffsetS = $off.Value
    if ($off.Note) { $notes += $off.Note }
    if ($isRdtsc) {
        $dl = ConvertTo-StripchartNumber $tokens[0]
        $r.DelayS = $dl.Value
        if ($dl.Note) { $notes += $dl.Note }
    }
    if ($null -eq $r.OffsetS) { $r.Kind = 'Error'; $r.Error = ($notes -join '; ') }
    elseif ($notes.Count -gt 0) { $r.Kind = 'Error'; $r.Error = ($notes -join '. ') }
    else { $r.Kind = 'Data' }
    return [pscustomobject]$r
}

function ConvertTo-CsvField {
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    if ($s -match '[",\r\n]') { return '"' + $s.Replace('"', '""') + '"' }
    return $s
}

function Format-SampleRow {
    param([datetime]$Utc, [string]$Contender, [string]$Case, [string]$Reference, $OffsetS, $DelayS, [string]$Err)
    $o = if ($null -ne $OffsetS) { ([double]$OffsetS).ToString('R', $script:Inv) } else { '' }
    $d = if ($null -ne $DelayS) { ([double]$DelayS).ToString('R', $script:Inv) } else { '' }
    $ts = $Utc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", $script:Inv)
    (@($ts, $Contender, $Case, $Reference, $o, $d, $Err) | ForEach-Object { ConvertTo-CsvField $_ }) -join ','
}

function Test-MeasureInput {
    # Returns a list of problems. Empty list means the input is good.
    param([string]$Reference, [string]$Contender, [string]$Case, [int]$Samples, [int]$PeriodSeconds, [string]$OutPath, [bool]$AllowPool)
    $p = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Reference) -or $Reference -notmatch '^[A-Za-z0-9._:\-]{1,253}$') {
        $p.Add('Reference must be a host name or an IP address (letters, digits, . _ : -).')
    }
    elseif ($Reference -match '(^|\.)pool\.ntp\.org$' -and -not $AllowPool) {
        $p.Add('Reference is a pool name. It resolves to a different server on each run. Resolve one address and pass the IP, or add -AllowPool.')
    }
    if ($Contender -notmatch '^[A-Za-z0-9._\-]{1,64}$') { $p.Add('Contender must be 1 to 64 characters of letters, digits, . _ -') }
    if ($Case -notmatch '^[A-Za-z0-9._\-]{1,64}$') { $p.Add('Case must be 1 to 64 characters of letters, digits, . _ -') }
    if ($Samples -lt 1 -or $Samples -gt 1000000) { $p.Add('Samples must be 1 to 1000000.') }
    if ($PeriodSeconds -lt 1 -or $PeriodSeconds -gt 3600) { $p.Add('PeriodSeconds must be 1 to 3600.') }
    if ([string]::IsNullOrWhiteSpace($OutPath)) { $p.Add('OutPath is required.') }
    else {
        if (Test-Path -LiteralPath $OutPath) { $p.Add("OutPath exists. Refusing to overwrite: $OutPath") }
        $dir = Split-Path -Parent ([System.IO.Path]::GetFullPath($OutPath))
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { $p.Add("Folder of OutPath does not exist: $dir") }
    }
    , $p
}

function Invoke-Measure {
    $problems = Test-MeasureInput -Reference $Reference -Contender $Contender -Case $Case -Samples $Samples -PeriodSeconds $PeriodSeconds -OutPath $OutPath -AllowPool ([bool]$AllowPool)
    if ($problems.Count -gt 0) {
        $problems | ForEach-Object { [Console]::Error.WriteLine("measure-offset: $_") }
        return 2
    }
    $w32 = Get-Command w32tm.exe -ErrorAction SilentlyContinue
    if (-not $w32) { [Console]::Error.WriteLine('measure-offset: w32tm.exe not found.'); return 1 }

    $full = [System.IO.Path]::GetFullPath($OutPath)
    try {
        # CreateNew fails if the file appeared since the check above.
        $fs = New-Object System.IO.FileStream($full, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    }
    catch {
        [Console]::Error.WriteLine("measure-offset: cannot create $full : $($_.Exception.Message)")
        return 2
    }
    $sw = New-Object System.IO.StreamWriter($fs, (New-Object System.Text.UTF8Encoding($false)))
    $sw.WriteLine('utc_iso,contender,case,reference,offset_s,delay_s,error')
    $sw.Flush()

    $w32args = @('/stripchart', "/computer:$Reference", "/samples:$Samples", "/period:$PeriodSeconds", '/dataonly')
    if (-not $Plain) { $w32args += '/rdtsc' }

    $rows = 0; $bad = 0; $ip = ''; $fatal = ''
    try {
        & $w32.Source @w32args 2>&1 | ForEach-Object {
            $p = ConvertFrom-StripchartLine -Line ([string]$_)
            switch ($p.Kind) {
                'Preamble' { if ($p.Ip) { $ip = $p.Ip } }
                'Fatal' { $fatal = $p.Error }
                'Blank' { }
                default {
                    $when = if ($p.FileTimeUtc) { $p.FileTimeUtc } else { [DateTime]::UtcNow }
                    if ($p.Kind -ne 'Data') { $bad++ }
                    $sw.WriteLine((Format-SampleRow -Utc $when -Contender $Contender -Case $Case -Reference $Reference -OffsetS $p.OffsetS -DelayS $p.DelayS -Err $p.Error))
                    $sw.Flush()
                    $rows++
                }
            }
        }
        $code = $LASTEXITCODE
        # Never drop a sample silently: anything w32tm did not print is a missing-sample row.
        $why = if ($fatal) { $fatal } elseif ($code) { "w32tm exited $code before all samples" } else { 'missing sample (w32tm printed fewer rows than requested)' }
        while ($rows -lt $Samples) {
            $sw.WriteLine((Format-SampleRow -Utc ([DateTime]::UtcNow) -Contender $Contender -Case $Case -Reference $Reference -OffsetS $null -DelayS $null -Err $why))
            $rows++; $bad++
        }
        $sw.Flush()
    }
    finally { $sw.Dispose() }

    [Console]::Error.WriteLine("measure-offset: reference $Reference resolved to '$ip'. $rows rows, $bad errors. CSV: $full")
    if ($bad -ge $rows) { return 1 }
    return 0
}

# Skipped when dot-sourced, so the tests can load the functions.
if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-Measure)
}
