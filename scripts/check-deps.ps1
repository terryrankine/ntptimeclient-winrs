#Requires -Version 7
<#
Fails if ntpc-core has any normal dependency outside thiserror and its
own proc-macro chain. This keeps the core free of OS and I/O crates.
#>
$ErrorActionPreference = 'Stop'

$allowed = @(
    'ntpc-core',
    'thiserror', 'thiserror-impl',
    'proc-macro2', 'quote', 'syn', 'unicode-ident'
)

$tree = & cargo tree -p ntpc-core -e normal --prefix none 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "cargo tree failed (exit $LASTEXITCODE):`n$($tree -join "`n")"
    exit 1
}

$found = $tree | ForEach-Object { ($_ -split '\s+')[0] } | Where-Object { $_ } | Sort-Object -Unique
$bad = @($found | Where-Object { $_ -notin $allowed })

if ($bad.Count -gt 0) {
    Write-Error "ntpc-core has disallowed dependencies: $($bad -join ', ')"
    exit 1
}

Write-Host "ok: ntpc-core depends on thiserror only ($($found -join ', '))"
exit 0
