#Requires -Version 7
<#
Pin monitor. Checks every pinned action in .github/workflows against GitHub.
Needs the gh CLI and a token (GH_TOKEN in CI, or `gh auth login` locally).

Each pin is `uses: owner/repo@<40 hex>  # <label>`. The label is a tag such as
v7.0.1, or a branch name such as stable.

  FAIL  the commit no longer exists in that repo (force pushed or deleted)
  FAIL  the label is a tag and it now points at a different commit
        (a moved tag: the thing that pinning guards against)
  WARN  a newer release exists than the label (upgrade is due)
  INFO  the label is a branch and it has moved on (normal for a branch pin)

Exit 1 on any FAIL. WARN and INFO never fail the run. Dependabot opens the
upgrade pull requests. This script finds trouble between those runs.
#>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Join-Path $PSScriptRoot '..'
$pins = foreach ($f in Get-ChildItem (Join-Path $root '.github/workflows') -Filter *.yml -File) {
    $n = 0
    foreach ($line in Get-Content -LiteralPath $f.FullName) {
        $n++
        if ($line -match '^\s*-?\s*(?:\w+:\s*)?uses:\s*([\w.-]+/[\w.-]+)@([0-9a-f]{40})\s*#\s*(\S+)\s*$') {
            [pscustomobject]@{ File = $f.Name; Line = $n; Repo = $Matches[1]; Sha = $Matches[2]; Label = $Matches[3] }
        }
    }
}
$pins = @($pins)
if ($pins.Count -eq 0) { Write-Error 'No pins found. Is the label comment missing?'; exit 1 }

function Invoke-Gh([string]$Path) {
    $out = & gh api $Path 2>&1
    [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Text = ($out -join "`n") }
}

$fail = 0
$unique = $pins | Sort-Object Repo, Sha, Label -Unique
foreach ($p in $unique) {
    $where = "$($p.Repo)@$($p.Sha.Substring(0, 7)) ($($p.Label))"
    $exists = Invoke-Gh "repos/$($p.Repo)/commits/$($p.Sha)"
    if (-not $exists.Ok) { Write-Host "FAIL  $where : commit not found in the repo."; $fail++; continue }

    $isTag = $p.Label -match '^v?\d+(\.\d+)*'
    $now = Invoke-Gh "repos/$($p.Repo)/commits/$($p.Label)"
    if (-not $now.Ok) {
        if ($isTag) { Write-Host "FAIL  $where : label no longer resolves."; $fail++ } else { Write-Host "INFO  $where : branch label no longer resolves." }
        continue
    }
    $nowSha = ($now.Text | ConvertFrom-Json).sha
    if ($nowSha -ne $p.Sha) {
        if ($isTag) { Write-Host "FAIL  $where : tag now points at $($nowSha.Substring(0, 7)). A moved tag."; $fail++ }
        else { Write-Host "INFO  $where : branch is now at $($nowSha.Substring(0, 7))." }
    } else {
        Write-Host "ok    $where"
    }

    if ($isTag) {
        $rel = Invoke-Gh "repos/$($p.Repo)/releases/latest"
        if ($rel.Ok) {
            $latest = ($rel.Text | ConvertFrom-Json).tag_name
            if ($latest -and $latest -ne $p.Label) { Write-Host "WARN  $where : newer release $latest."; if ($env:GITHUB_ACTIONS) { Write-Host "::warning::$($p.Repo) $($p.Label) -> $latest" } }
        }
    }
}
if ($fail -gt 0) { Write-Host "$fail pin problem(s)."; exit 1 }
Write-Host "All $($unique.Count) distinct pins checked."
