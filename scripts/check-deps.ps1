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

# Cover build deps, every target and every feature. Default tree misses them.
# stderr stays out of the package list: rustup prints info lines there.
$errFile = New-TemporaryFile
try {
    $tree = & cargo tree -p ntpc-core -e normal,build --target all --all-features --prefix none 2>$errFile
    $code = $LASTEXITCODE
    $stderr = Get-Content -Raw $errFile
} finally {
    Remove-Item $errFile -ErrorAction SilentlyContinue
}
if ($code -ne 0) {
    Write-Error "cargo tree failed (exit $code):`n$stderr"
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
