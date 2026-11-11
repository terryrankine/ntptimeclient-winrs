#Requires -Version 7
<#
Gate for the built exe. Used by ci.yml and release.yml so both run the same probes.

A stub exe, or one whose CLI is not the one the packaging scripts call, must
never be packaged. The probes are non-mutating and a stub cannot fake them: the
exit codes come from the exe's own table.

  --help               exit 0, and the five commands listed as help lines
  (no arguments)       exit 2
  frob                 exit 2 (an unknown subcommand)
  service              exit 26 (not started by the service manager)
  status --config <a file that does not exist>   exit 22 or 24

NEVER add install, uninstall, run or a real service start here. The gate must
stay safe to run on any machine. The probes may not write to the machine.
#>
param(
    [string]$Exe
)
$ErrorActionPreference = 'Stop'

if (-not $Exe) {
    $candidates = 'target/release/ntptimeclient-winrs.exe', 'target/release/ntpc-service.exe'
    $Exe = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (-not $Exe -or -not (Test-Path -LiteralPath $Exe -PathType Leaf)) { Write-Error 'No release binary found.'; exit 1 }
$exe = (Resolve-Path -LiteralPath $Exe).Path
$tmp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$missing = Join-Path $tmp 'ntpc-gate-does-not-exist.toml'
if (Test-Path -LiteralPath $missing) { Write-Error "Probe path exists: $missing"; exit 1 }

function Invoke-Probe {
    param([string[]]$ProbeArgs)
    $out = Join-Path $tmp ('probe-out-' + [guid]::NewGuid().ToString('N') + '.txt')
    $err = Join-Path $tmp ('probe-err-' + [guid]::NewGuid().ToString('N') + '.txt')
    $sp = @{ FilePath = $exe; PassThru = $true; NoNewWindow = $true; RedirectStandardOutput = $out; RedirectStandardError = $err }
    if ($ProbeArgs.Count -gt 0) { $sp.ArgumentList = $ProbeArgs }
    $p = Start-Process @sp
    $null = $p.Handle   # keeps the exit code readable after exit
    if (-not $p.WaitForExit(30000)) { $p.Kill(); Write-Error "Probe hung: $($ProbeArgs -join ' ')"; exit 1 }
    [pscustomobject]@{ Code = $p.ExitCode; Text = ((Get-Content -Raw -LiteralPath $out -ErrorAction SilentlyContinue) + (Get-Content -Raw -LiteralPath $err -ErrorAction SilentlyContinue)) }
}

$fail = @()
$help = Invoke-Probe @('--help')
Write-Host "--help exit $($help.Code)"; Write-Host $help.Text
if ($help.Code -ne 0) { $fail += "--help exited $($help.Code), want 0" }
if ([string]::IsNullOrWhiteSpace($help.Text)) { $fail += '--help printed nothing' }
# Command-list lines only: the word at the start of a line, then space or end.
foreach ($word in 'install', 'uninstall', 'run', 'service', 'status') {
    if ($help.Text -notmatch "(?m)^\s*$word(\s|$)") { $fail += "--help has no command-list line for '$word'" }
}
$probes = @(
    @{ Name = 'no arguments'; Args = @(); Want = @(2) },
    @{ Name = 'unknown subcommand'; Args = @('frob'); Want = @(2) },
    @{ Name = 'service from a console'; Args = @('service'); Want = @(26) },
    @{ Name = 'status with a missing config'; Args = @('status', '--config', $missing); Want = @(22, 24) }
)
foreach ($pr in $probes) {
    $r = Invoke-Probe $pr.Args
    Write-Host "$($pr.Name): exit $($r.Code)"
    if ($pr.Want -notcontains $r.Code) { $fail += "$($pr.Name) exited $($r.Code), want $($pr.Want -join ' or ')" }
}
if ($fail.Count -gt 0) { $fail | ForEach-Object { Write-Host "GATE FAIL: $_" }; exit 1 }
Write-Host 'Gate passed.'
