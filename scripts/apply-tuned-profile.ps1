<#
.SYNOPSIS
  DANGEROUS. Applies or undoes the tuned w32time profile from docs/measuring.md. Test machine only.

.DESCRIPTION
  Refuses unless the environment variable MEASURE_TEST_MACHINE is 1 and the session is elevated.
  Supports -WhatIf. Apply first saves the current values to -BeforeFile (refuses to overwrite),
  then sets the peers and the registry values and restarts w32time. -Undo restores the recorded
  values and removes the ones that were absent. Exit codes: 0 done, 2 refused or bad input.

.EXAMPLE
  $env:MEASURE_TEST_MACHINE = '1'; .\apply-tuned-profile.ps1 -Peers IP1,IP2,IP3 -BeforeFile .\out\w32time-before.json
  $env:MEASURE_TEST_MACHINE = '1'; .\apply-tuned-profile.ps1 -Undo -BeforeFile .\out\w32time-before.json
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$Peers,
    [string]$BeforeFile,
    [switch]$Undo
)

Set-StrictMode -Version Latest
# The guard comes first. Nothing above it may change state.
if ($env:MEASURE_TEST_MACHINE -ne '1') {
    [Console]::Error.WriteLine('apply-tuned-profile: refused. Set MEASURE_TEST_MACHINE=1 on a test machine to run this.')
    exit 2
}
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [Console]::Error.WriteLine('apply-tuned-profile: refused. Run elevated.')
    exit 2
}
if ([string]::IsNullOrWhiteSpace($BeforeFile)) { [Console]::Error.WriteLine('apply-tuned-profile: -BeforeFile is required.'); exit 2 }

$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config'
$kp = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
$names = 'MinPollInterval', 'MaxPollInterval', 'UpdateInterval', 'PhaseCorrectRate', 'FrequencyCorrectRate'
$tuned = @{ MinPollInterval = 6; MaxPollInterval = 6; UpdateInterval = 100; PhaseCorrectRate = 1; FrequencyCorrectRate = 2 }

if ($Undo) {
    if (-not (Test-Path -LiteralPath $BeforeFile)) { [Console]::Error.WriteLine("apply-tuned-profile: no such file $BeforeFile"); exit 2 }
    $b = Get-Content -LiteralPath $BeforeFile -Raw | ConvertFrom-Json
    foreach ($n in $names) {
        $v = $b.Config.$n
        if ($null -ne $v) { if ($PSCmdlet.ShouldProcess($n, "restore $v")) { Set-ItemProperty -Path $k -Name $n -Value ([int]$v) -Type DWord } }
        elseif ($PSCmdlet.ShouldProcess($n, 'remove (was absent)')) { Remove-ItemProperty -Path $k -Name $n -ErrorAction SilentlyContinue }
    }
    if ($PSCmdlet.ShouldProcess('NtpServer and Type', 'restore')) {
        Set-ItemProperty -Path $kp -Name NtpServer -Value $b.Parameters.NtpServer
        Set-ItemProperty -Path $kp -Name Type -Value $b.Parameters.Type
    }
    if ($PSCmdlet.ShouldProcess('w32time', 'restart')) { Restart-Service w32time }
    exit 0
}

if (-not $Peers -or $Peers.Count -lt 1 -or @($Peers | Where-Object { $_ -notmatch '^[A-Fa-f0-9.:]{2,45}$' }).Count -gt 0) {
    [Console]::Error.WriteLine('apply-tuned-profile: -Peers must be one or more IP addresses.'); exit 2
}
if (Test-Path -LiteralPath $BeforeFile) { [Console]::Error.WriteLine("apply-tuned-profile: $BeforeFile exists. Refusing to overwrite."); exit 2 }

$before = @{}
$p = Get-ItemProperty -Path $k
foreach ($n in $names) { $before[$n] = if ($p.PSObject.Properties.Name -contains $n) { $p.$n } else { $null } }
$bp = Get-ItemProperty -Path $kp | Select-Object NtpServer, Type
@{ Config = $before; Parameters = $bp } | ConvertTo-Json | Set-Content -LiteralPath $BeforeFile -Encoding ASCII
Write-Host "saved the current values to $BeforeFile"

$peerList = ($Peers | ForEach-Object { "$_,0x8" }) -join ' '
if ($PSCmdlet.ShouldProcess('w32time', "manualpeerlist $peerList")) { w32tm /config "/manualpeerlist:$peerList" /syncfromflags:manual /update | Out-Null }
foreach ($n in $names) {
    if ($PSCmdlet.ShouldProcess($n, "set $($tuned[$n])")) { Set-ItemProperty -Path $k -Name $n -Value $tuned[$n] -Type DWord }
}
if ($PSCmdlet.ShouldProcess('w32time', 'restart')) { Restart-Service w32time }
exit 0
