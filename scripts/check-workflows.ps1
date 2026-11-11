#Requires -Version 7
<#
Lints every workflow in .github/workflows.

  - Every "uses:" is a full 40 character commit SHA (a tag can be moved).
  - No placeholder text is left in a workflow or in packaging/.
  - No workflow expands github.event or github.head_ref text inside a run
    block (script injection). Values go through env: instead.
  - Every workflow sets a top-level permissions block.

It guards future edits. It does not replace reading a new action's code.
#>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Join-Path $PSScriptRoot '..'
$wf = @(Get-ChildItem (Join-Path $root '.github/workflows') -Filter *.yml -File)
if ($wf.Count -eq 0) { Write-Error 'No workflows found.'; exit 1 }
$fail = @()

foreach ($f in $wf) {
    $lines = Get-Content -LiteralPath $f.FullName
    $n = 0
    foreach ($line in $lines) {
        $n++
        if ($line -match '^\s*-?\s*(?:\w+:\s*)?uses:\s*(\S+)' ) {
            if ($Matches[1] -notmatch '^[^@\s]+@[0-9a-f]{40}$') { $fail += "$($f.Name):${n}: unpinned action: $($line.Trim())" }
            elseif ($line -notmatch '@[0-9a-f]{40}\s+#\s*\S+\s*$') { $fail += "$($f.Name):${n}: pin has no '# label' comment (tag or branch), which the pin monitor needs: $($line.Trim())" }
        }
        # Pattern is split so this file does not match itself.
        if ($line -match ('T' + 'ODO|FIX' + 'ME')) { $fail += "$($f.Name):${n}: placeholder: $($line.Trim())" }
        if ($line -match '\$\{\{\s*github\.(event\.|head_ref)') {
            $fail += "$($f.Name):${n}: github.event or head_ref used directly. Pass it through env: $($line.Trim())"
        }
    }
    if (-not ($lines | Where-Object { $_ -match '^permissions:' })) { $fail += "$($f.Name): no top-level permissions block" }
}

$hits = Get-ChildItem (Join-Path $root 'packaging') -Recurse -File | Select-String -Pattern ('T' + 'ODO')
foreach ($h in $hits) { $fail += "$($h.Path):$($h.LineNumber): placeholder" }

if ($fail.Count -gt 0) { $fail | ForEach-Object { Write-Host "WORKFLOW LINT: $_" }; exit 1 }
Write-Host "Workflows ok: $($wf.Name -join ', ')"
