#Requires -Version 7
<#
Checks the version rules in docs/releasing.md.

  - The workspace version in Cargo.toml is SemVer 2.0.
  - With -Tag, the tag is "v" plus that exact version, and CHANGELOG.md has a
    "## [version]" heading for it.
  - Prints the release channel (alpha, beta, rc or stable) and whether the
    release is a GitHub pre-release.

The version has one source: [workspace.package] version in Cargo.toml.
Every crate inherits it. Cargo.lock must agree (checked by `cargo ... --locked`).

Usage:
  pwsh scripts/check-version.ps1
  pwsh scripts/check-version.ps1 -Tag v0.1.0-alpha.1
  pwsh scripts/check-version.ps1 -Tag v0.1.0-alpha.1 -GithubOutput $env:GITHUB_OUTPUT
#>
param(
    [string]$Tag,
    [string]$CargoToml = (Join-Path $PSScriptRoot '..' 'Cargo.toml'),
    [string]$GithubOutput
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Official SemVer 2.0 pattern (semver.org), without build metadata. Build
# metadata is not used: a tag name with "+" is not a valid release.
$semver = '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?$'

$text = Get-Content -Raw -LiteralPath $CargoToml
$m = [regex]::Match($text, '(?ms)^\[workspace\.package\]\s*(.*?)(?=^\[|\z)')
if (-not $m.Success) { Write-Error 'No [workspace.package] table in Cargo.toml.'; exit 1 }
$v = [regex]::Match($m.Groups[1].Value, '(?m)^version\s*=\s*"([^"]+)"')
if (-not $v.Success) { Write-Error 'No version in [workspace.package].'; exit 1 }
$version = $v.Groups[1].Value

$parts = [regex]::Match($version, $semver)
if (-not $parts.Success) { Write-Error "Cargo version '$version' is not SemVer 2.0 without build metadata."; exit 1 }
$pre = $parts.Groups[4].Value

# Pre-release identifiers allowed: alpha.N, beta.N, rc.N. One format, so tags sort and read the same way.
$channel = 'stable'
if ($pre -ne '') {
    $c = [regex]::Match($pre, '^(alpha|beta|rc)\.(0|[1-9]\d*)$')
    if (-not $c.Success) { Write-Error "Pre-release '$pre' must be alpha.N, beta.N or rc.N."; exit 1 }
    $channel = $c.Groups[1].Value
}

# 0.x means the interface is not stable. A stable 1.0.0 is a human decision, not a script one.
if ($Tag) {
    if ($Tag -ne "v$version") { Write-Error "Tag '$Tag' does not match Cargo version 'v$version'."; exit 1 }
    # A release needs a changelog entry for its version.
    $log = Join-Path (Split-Path -Parent $CargoToml) 'CHANGELOG.md'
    if (-not (Test-Path -LiteralPath $log)) { Write-Error 'CHANGELOG.md is missing.'; exit 1 }
    if ((Get-Content -Raw -LiteralPath $log) -notmatch ('(?m)^## \[' + [regex]::Escape($version) + '\]')) {
        Write-Error "CHANGELOG.md has no '## [$version]' heading."; exit 1
    }
}

$prerelease = ($channel -ne 'stable' -or $parts.Groups[1].Value -eq '0')
Write-Host "version=$version"
Write-Host "channel=$channel"
Write-Host "prerelease=$($prerelease.ToString().ToLowerInvariant())"
if ($GithubOutput) {
    "version=$version" | Out-File -FilePath $GithubOutput -Append -Encoding utf8
    "channel=$channel" | Out-File -FilePath $GithubOutput -Append -Encoding utf8
    "prerelease=$($prerelease.ToString().ToLowerInvariant())" | Out-File -FilePath $GithubOutput -Append -Encoding utf8
}
