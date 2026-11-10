#Requires -Version 5.1
<#
Shared helpers for install.ps1 and uninstall.ps1 of the UNSIGNED PREVIEW zip.

The pure functions here (hash line parsing, argument building) touch nothing
on the machine, so the Pester tests can run them anywhere. The functions that
read the machine are read only. Nothing in this file changes a service, the
registry or the clock.

This file is dot-sourced by the two scripts. It is listed in SHA256SUMS like
every other file, but the scripts cannot verify it before they load it. See
the note on Test-BinaryAgainstSums.
#>
Set-StrictMode -Version Latest

# The name the zip uses for the binary. The workflow renames the cargo output
# to this if the package binary has another name.
$script:PreviewExeName = 'ntptimeclient-winrs.exe'
# Assumed from the project name. Task 14 owns the real name. Used only in the
# printed manual rollback text, never passed to a command by these scripts.
$script:PreviewServiceName = 'ntptimeclient-winrs'

# Exit codes owned by the scripts. The exe's own codes pass through unchanged,
# so these sit well above what a small CLI normally returns. A clash is
# still possible. The printed text says which side spoke.
$script:ExitRiskNotAccepted = 40
$script:ExitNotElevated = 41
$script:ExitBinaryMissing = 42
$script:ExitHashMismatch = 43

function Get-PreviewWarningText {
    @'
==============================================================
 UNSIGNED PREVIEW. NOT FOR MACHINES THAT MATTER.
==============================================================
 This is a developer preview of ntptimeclient-winrs.
 - The binary is not code signed.
 - It sets the system clock and runs as a Windows service.
 - It stops and disables the Windows Time service (w32time).
 - It has had no real-world testing. Use a throwaway virtual
   machine with a snapshot. Do not use a production machine,
   a domain controller, or a machine you cannot rebuild.
==============================================================
'@
}

function Get-ExpectedHash {
    <#
    Finds the SHA-256 for $FileName in the text of a SHA256SUMS file.
    Line form: "<64 hex>  <name>". A "*" before the name (binary mode marker
    from sha256sum) is accepted. Returns the lower case hash.
    Throws if the file name is missing, listed twice, or the hash is not
    64 hex characters.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$SumsText,
        [Parameter(Mandatory)][string]$FileName
    )
    $hits = @()
    foreach ($line in ($SumsText -split "`r?`n")) {
        if ($line -match '^\s*([0-9A-Fa-f]{64})\s+\*?(.+?)\s*$') {
            if ($Matches[2] -ceq $FileName) { $hits += $Matches[1].ToLowerInvariant() }
        }
    }
    if ($hits.Count -eq 0) { throw "SHA256SUMS has no valid entry for $FileName." }
    if ($hits.Count -gt 1) { throw "SHA256SUMS lists $FileName more than once." }
    $hits[0]
}

function Test-HashEquals {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Actual
    )
    $Expected.Trim().ToLowerInvariant() -ceq $Actual.Trim().ToLowerInvariant()
}

function Test-BinaryAgainstSums {
    <#
    Compares the SHA-256 of $ExePath with the entry in $SumsPath.
    HONEST LIMIT: SHA256SUMS ships inside the same zip as the binary. This
    detects accidental damage (a bad download, a truncated copy). It does NOT
    detect a malicious zip, because whoever altered the exe could alter the
    sums file too. Only a code signature or a hash published through a
    separate trusted channel would. The preview has neither.
    Returns $true on a match. Throws on a missing or malformed sums file.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$ExePath,
        [Parameter(Mandatory)][string]$SumsPath
    )
    if (-not (Test-Path -LiteralPath $SumsPath -PathType Leaf)) {
        throw "SHA256SUMS is missing next to the script: $SumsPath"
    }
    $sums = [System.IO.File]::ReadAllText($SumsPath)
    $expected = Get-ExpectedHash -SumsText $sums -FileName (Split-Path -Leaf $ExePath)
    $actual = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash
    Test-HashEquals -Expected $expected -Actual $actual
}

function Get-ExeArguments {
    <#
    Builds the argument list for the exe. The domain-joined override is added
    ONLY when the caller passed -ConfirmDomainJoined. It is never a default.
    Returns an array so the caller can splat it. Each element is passed to the
    exe as one argument, so there is no quoting to get wrong.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][ValidateSet('install', 'uninstall')][string]$Command,
        [switch]$ConfirmDomainJoined
    )
    $argList = @($Command)
    if ($ConfirmDomainJoined) {
        if ($Command -ne 'install') { throw '--confirm-domain-joined only applies to install.' }
        $argList += '--confirm-domain-joined'
    }
    , $argList
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-W32TimeSummary {
    # Read only. Printed before the exe runs so the user has the original
    # start type on screen if the manual rollback is needed.
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='w32time'" -ErrorAction Stop
        if ($null -eq $svc) { return 'w32time: not found' }
        "w32time: StartMode=$($svc.StartMode) State=$($svc.State)"
    } catch {
        "w32time: could not be read ($($_.Exception.Message))"
    }
}

function Get-ManualRollbackText {
    # w32time defaults are an unverified recollection: Manual (trigger start)
    # on Windows 10 and 11, Automatic on Server and domain members. The exe
    # also records the real original in restore.json in the state directory.
    @"
Manual rollback, from an elevated prompt, if the exe failed halfway:
  1. Remove the service (ignore an error if it was never created):
       sc.exe stop $($script:PreviewServiceName)
       sc.exe delete $($script:PreviewServiceName)
  2. Restore Windows Time. Use the start type printed before the install
     (StartMode above). Commonly 'demand' on Windows 10 and 11 and 'auto'
     on Server. 'sc.exe qc w32time' shows the current one.
       sc.exe config w32time start= demand
       sc.exe start w32time
       w32tm.exe /resync
  3. Check: sc.exe query w32time
"@
}

function Test-ExeOrFail {
    <#
    Shared pre-flight for both scripts: binary present, then hash matches.
    Returns 0 when fine, otherwise the script exit code after printing why.
    #>
    param(
        [Parameter(Mandatory)][string]$ExePath,
        [Parameter(Mandatory)][string]$SumsPath
    )
    if (-not (Test-Path -LiteralPath $ExePath -PathType Leaf)) {
        Write-Host "REFUSED: $($script:PreviewExeName) is not next to this script." -ForegroundColor Red
        Write-Host "Expected: $ExePath"
        Write-Host 'Extract the whole zip first and run the script from the extracted folder.'
        return $script:ExitBinaryMissing
    }
    try {
        $ok = Test-BinaryAgainstSums -ExePath $ExePath -SumsPath $SumsPath
    } catch {
        Write-Host "REFUSED: cannot check the binary. $($_.Exception.Message)" -ForegroundColor Red
        return $script:ExitHashMismatch
    }
    if (-not $ok) {
        Write-Host "REFUSED: $($script:PreviewExeName) does not match SHA256SUMS." -ForegroundColor Red
        Write-Host 'The file may be damaged. Download the zip again.'
        return $script:ExitHashMismatch
    }
    0
}
