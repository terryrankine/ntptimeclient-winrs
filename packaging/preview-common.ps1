#Requires -Version 5.1
<#
Shared helpers for install.ps1 and uninstall.ps1 of the UNSIGNED PREVIEW zip.

The pure functions here (hash line parsing, start type mapping, ACE checks,
outcome checks, argument building) touch nothing on the machine, so the
Pester tests can run them anywhere. The functions that read the machine are
read only. Nothing in this file changes a service, the registry or the clock.
The one function that starts a process is Invoke-ExeKeepingExitCode, and the
scripts call it only for the exe, after the checks.

The two scripts verify this file against SHA256SUMS before they dot-source it.
That catches damage or a helper from another release. It does not stop a
malicious edit, and there is a short gap between that hash and the load. The
folder permission check (Test-LocationOrFail) is the control for that gap.
#>
Set-StrictMode -Version Latest

# The name the zip uses for the binary. The workflow renames the cargo output
# to this if the package binary has another name.
$script:PreviewExeName = 'ntptimeclient-winrs.exe'
# Assumed from the project name. Task 14 owns the real name. Used for the
# printed rollback text and for read-only state queries. Never passed to a
# command that changes anything.
$script:PreviewServiceName = 'ntptimeclient-winrs'

# Exit codes owned by the scripts. The exe's own codes pass through unchanged.
# These sit well above what a small CLI normally returns. A clash is still
# possible, so the printed text says which side spoke.
$script:ExitRiskNotAccepted = 40
$script:ExitNotElevated = 41
$script:ExitBinaryMissing = 42
$script:ExitHashMismatch = 43
$script:ExitUnsafeFolder = 44
$script:ExitDeclined = 45
$script:ExitStateMismatch = 46
$script:ExitUninstallStateMismatch = 47

# Principals allowed to hold write rights on the install folder.
$script:TrustedSids = @(
    'S-1-5-18',      # SYSTEM
    'S-1-5-32-544',  # Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'  # TrustedInstaller
)
# English names for hand-built ACE objects in tests. Real ACEs are turned into
# SIDs first (Get-PathSecurityInfo), so a non-English Windows is not a problem.
$script:KnownNames = @{
    'NT AUTHORITY\SYSTEM'         = 'S-1-5-18'
    'BUILTIN\Administrators'      = 'S-1-5-32-544'
    'NT SERVICE\TrustedInstaller' = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    'CREATOR OWNER'               = 'S-1-3-0'
}
# FileSystemRights bits that let a principal change the file or folder or its
# permissions: WriteData, AppendData, WriteExtendedAttributes,
# DeleteSubdirectoriesAndFiles, WriteAttributes, Delete, ChangePermissions,
# TakeOwnership, GenericAll, GenericWrite.
$script:WriteMask = [int64](0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)
# For parent folders only the rights that allow a rename or removal of the
# child folder, or a change of permissions, matter. A parent such as C:\ lets
# users create sub folders, and that is harmless here.
$script:AncestorMask = [int64](0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)

function Get-PreviewWarningText {
    @'
==============================================================
 UNSIGNED PREVIEW. NOT FOR MACHINES THAT MATTER.
==============================================================
 This is a developer preview of ntptimeclient-winrs.
 - The binary is not code signed.
 - It sets the system clock and runs as a Windows service.
 - It stops and disables the Windows Time service (w32time).
 - It has not been tested on real machines yet. Use a throwaway
   virtual machine with a snapshot. Do not use a production
   machine, a domain controller, or a machine you cannot rebuild.
==============================================================
'@
}

function Get-ExpectedHash {
    <#
    Finds the SHA-256 for $FileName in the text of a SHA256SUMS file.
    Line form: "<64 hex>  <name>". A "*" before the name (binary mode marker
    from sha256sum) is accepted. Returns the lower case hash.
    Throws if the file name is missing, listed twice, or the hash is not
    exactly 64 hex characters. A name with a path in it never matches.
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

function Get-BytesSha256 {
    [OutputType([string])]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Test-BinaryAgainstSums {
    <#
    Compares the SHA-256 of $ExePath with the entry in $SumsPath. The file is
    read once into memory and those bytes are hashed.
    HONEST LIMIT: SHA256SUMS ships inside the same zip as the binary. This
    detects accidental damage (a bad download, a truncated copy). It does NOT
    detect a malicious zip, because whoever altered the exe could alter the
    sums file too. Nor does it stop a swap after the check: the exe is run
    from its path, not from these bytes. The folder permission check is what
    covers that. The preview has no signature.
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
    $actual = Get-BytesSha256 -Bytes ([System.IO.File]::ReadAllBytes($ExePath))
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

# ---------------------------------------------------------------------------
# Running the exe
# ---------------------------------------------------------------------------

function Invoke-ExeKeepingExitCode {
    <#
    Runs the exe and returns its exit code. Its output is printed with
    Write-Host so it is not mixed into the return value.
    Why the local settings: on Windows PowerShell 5.1, when the caller
    redirects output (*> log.txt, 2>&1 | Tee-Object), the first stderr line of
    a native command becomes a terminating NativeCommandError under
    $ErrorActionPreference = 'Stop'. The script would then stop before it
    reads the exit code and prints the rollback text. So stderr is merged
    here under 'Continue', the exit code is read at once, and the caller's
    settings are put back.
    #>
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    $oldEap = $ErrorActionPreference
    $hadNative = Test-Path -Path Variable:PSNativeCommandUseErrorActionPreference
    if ($hadNative) { $oldNative = $PSNativeCommandUseErrorActionPreference }
    try {
        $ErrorActionPreference = 'Continue'
        $PSNativeCommandUseErrorActionPreference = $false
        & $Path @Arguments 2>&1 | ForEach-Object { Write-Host ([string]$_) }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldEap
        if ($hadNative) { $PSNativeCommandUseErrorActionPreference = $oldNative }
    }
    if ($null -eq $code) { return 1 }
    [int]$code
}

# ---------------------------------------------------------------------------
# w32time start type
# ---------------------------------------------------------------------------

function ConvertTo-ScStartKeyword {
    <#
    Maps the registry values Start and DelayedAutostart of a service to the
    sc.exe "start=" keyword. Returns $null when the value is missing or out
    of range, so the caller never prints a guessed default.
      Start 0 boot, 1 system, 2 auto (delayed-auto when DelayedAutostart is
      1), 3 demand, 4 disabled.
    A trigger start is not visible in these two values. It is a separate
    trigger setting, so a Manual service with triggers maps to plain demand.
    #>
    [OutputType([string])]
    param(
        [AllowNull()]$Start,
        [AllowNull()]$DelayedAutostart
    )
    if ($null -eq $Start) { return $null }
    $s = 0
    if (-not [int]::TryParse([string]$Start, [ref]$s)) { return $null }
    switch ($s) {
        0 { return 'boot' }
        1 { return 'system' }
        2 {
            $d = 0
            if ($null -ne $DelayedAutostart -and [int]::TryParse([string]$DelayedAutostart, [ref]$d) -and $d -eq 1) { return 'delayed-auto' }
            return 'auto'
        }
        3 { return 'demand' }
        4 { return 'disabled' }
        default { return $null }
    }
}

function Get-W32TimeRegistryStart {
    # Read only. Returns the sc.exe keyword, or $null if it cannot be read.
    try {
        $key = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time' -ErrorAction Stop
        $delayed = $null
        if ($key.PSObject.Properties.Name -contains 'DelayedAutostart') { $delayed = $key.DelayedAutostart }
        $start = $null
        if ($key.PSObject.Properties.Name -contains 'Start') { $start = $key.Start }
        ConvertTo-ScStartKeyword -Start $start -DelayedAutostart $delayed
    } catch {
        $null
    }
}

function Get-ServiceFacts {
    # Read only. One service by name, or $null if it does not exist.
    param([Parameter(Mandatory)][string]$Name)
    try {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        if ($null -eq $svc) { return $null }
        [pscustomobject]@{
            Name      = $Name
            State     = [string]$svc.State
            StartMode = [string]$svc.StartMode
            PathName  = [string]$svc.PathName
            StartName = [string]$svc.StartName
        }
    } catch {
        $null
    }
}

function Get-MachineState {
    # Read only snapshot used after the exe has run. It reports what is
    # really there. It never reports what the install was expected to do.
    [pscustomobject]@{
        W32Time      = Get-ServiceFacts -Name 'w32time'
        W32TimeStart = Get-W32TimeRegistryStart
        Ours         = Get-ServiceFacts -Name $script:PreviewServiceName
    }
}

function Format-MachineState {
    [OutputType([string[]])]
    param([Parameter(Mandatory)]$State)
    $lines = @()
    if ($null -eq $State.W32Time) {
        $lines += 'w32time: not found or not readable'
    } else {
        $reg = if ($State.W32TimeStart) { $State.W32TimeStart } else { 'unreadable' }
        $lines += "w32time: State=$($State.W32Time.State) StartMode=$($State.W32Time.StartMode) registry start type=$reg"
    }
    if ($null -eq $State.Ours) {
        $lines += "$($script:PreviewServiceName): no such service"
    } else {
        $lines += "$($script:PreviewServiceName): State=$($State.Ours.State) StartMode=$($State.Ours.StartMode)"
        $lines += "  binary path: $($State.Ours.PathName)"
        $lines += "  runs as: $($State.Ours.StartName)"
    }
    $lines
}

function Test-InstallOutcome {
    <#
    Pure. Returns a list of problems with the state after an install that
    exited 0. An empty list means the state looks like an install happened.
    It does not prove the install is correct.
    #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)]$State)
    $problems = @()
    if ($null -eq $State.Ours) { $problems += "the $($script:PreviewServiceName) service does not exist" }
    if ($null -ne $State.W32Time) {
        if ($State.W32Time.State -eq 'Running') { $problems += 'w32time is still running' }
        if ($State.W32TimeStart -and $State.W32TimeStart -ne 'disabled') { $problems += "w32time start type is $($State.W32TimeStart), not disabled" }
        if (-not $State.W32TimeStart -and $State.W32Time.StartMode -ne 'Disabled') { $problems += "w32time StartMode is $($State.W32Time.StartMode), not Disabled" }
    }
    $problems
}

function Test-UninstallOutcome {
    # Pure. What w32time should be after an uninstall is in the exe's record,
    # which the script does not read. So only the service is judged here.
    [OutputType([string[]])]
    param([Parameter(Mandatory)]$State)
    $problems = @()
    if ($null -ne $State.Ours) { $problems += "the $($script:PreviewServiceName) service still exists" }
    $problems
}

# ---------------------------------------------------------------------------
# Rollback text
# ---------------------------------------------------------------------------

function Get-RollbackCommand {
    # The concrete w32time restore line, or text saying none can be given.
    [OutputType([string])]
    param([AllowNull()][string]$StartKeyword)
    if ([string]::IsNullOrEmpty($StartKeyword)) {
        'The original w32time start type could not be read. No default is guessed. Read it from restore.json in the state directory, or from a record you made before the install.'
    } else {
        "sc.exe config w32time start= $StartKeyword"
    }
}

function Get-ManualRollbackText {
    # restore.json is written by the exe, so it is the authority when it
    # exists. The start type read before the install is the fallback.
    [OutputType([string])]
    param([AllowNull()][string]$StartKeyword)
    $cmd = Get-RollbackCommand -StartKeyword $StartKeyword
    @"
Manual rollback, from an elevated prompt, if the exe failed halfway:
  Authority: restore.json in the state directory (written by the exe) when it
  exists. Otherwise the start type read before the install, below.
  1. Remove the service (ignore an error if it was never created):
       sc.exe stop $($script:PreviewServiceName)
       sc.exe delete $($script:PreviewServiceName)
  2. Restore Windows Time:
       $cmd
       sc.exe start w32time
       w32tm.exe /resync
  3. Check: sc.exe qc w32time
  The clock rate may stay non-nominal until w32time takes over again or the
  machine restarts (unverified). Restart after the rollback.
"@
}

function Get-ExecutionPolicyHelp {
    param([Parameter(Mandatory)][string]$ScriptName, [string]$Extra = '')
    "Run it as: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\$ScriptName$Extra`n" +
    '(Process scope only. It does not change the machine policy. -NoProfile stops a user profile running elevated.)'
}

# ---------------------------------------------------------------------------
# Folder permission check
# ---------------------------------------------------------------------------

function Resolve-PrincipalSid {
    [OutputType([string])]
    param([AllowNull()]$Identity)
    if ($null -eq $Identity) { return $null }
    $text = [string]$Identity
    if ($text -match '^S-1-') { return $text }
    if ($script:KnownNames.ContainsKey($text)) { return $script:KnownNames[$text] }
    $null
}

function Test-OwnerTrusted {
    # Pure. The owner of an object can always rewrite its permissions.
    [OutputType([bool])]
    param([AllowNull()]$Owner)
    $sid = Resolve-PrincipalSid -Identity $Owner
    ($null -ne $sid) -and ($script:TrustedSids -contains $sid)
}

function Get-UnsafeAce {
    <#
    Pure. Takes ACE-like objects (IdentityReference as SID or English name,
    AccessControlType, FileSystemRights, PropagationFlags) and returns text
    for each allow ACE that gives a principal outside SYSTEM, Administrators
    and TrustedInstaller a right in $Mask. Not counted: deny ACEs, and
    inherit-only ACEs (they do not apply to this object, and each file is
    checked by its own ACL). An identity that cannot be resolved counts as
    untrusted.
    #>
    [OutputType([string[]])]
    param(
        [AllowEmptyCollection()][Parameter(Mandatory)]$Aces,
        [int64]$Mask = $script:WriteMask
    )
    $bad = @()
    foreach ($ace in @($Aces)) {
        if ([string]$ace.AccessControlType -ne 'Allow') { continue }
        if (([int64][int]$ace.PropagationFlags -band 2) -ne 0) { continue }
        $rights = [int64][int]$ace.FileSystemRights
        if (($rights -band $Mask) -eq 0) { continue }
        $sid = Resolve-PrincipalSid -Identity $ace.IdentityReference
        if ($null -ne $sid -and $script:TrustedSids -contains $sid) { continue }
        $bad += "$($ace.IdentityReference) has $($ace.FileSystemRights)"
    }
    $bad
}

function Get-PathSecurityInfo {
    # Read only. Real ACEs turned into plain objects with the identity as a
    # SID string, so the check does not depend on the Windows language.
    param([Parameter(Mandatory)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $toSid = {
        param($id)
        try { $id.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { [string]$id }
    }
    $aces = foreach ($a in $acl.Access) {
        [pscustomobject]@{
            IdentityReference = (& $toSid $a.IdentityReference)
            AccessControlType = [string]$a.AccessControlType
            FileSystemRights  = $a.FileSystemRights
            PropagationFlags  = $a.PropagationFlags
        }
    }
    [pscustomobject]@{ Owner = (& $toSid ([System.Security.Principal.NTAccount]$acl.Owner)); Aces = @($aces) }
}

function Test-LocationOrFail {
    <#
    Returns a list of reasons the install folder is not safe to run an
    elevated exe from. Empty means it passed. Checks, all read only:
    the folder, the exe and the helper (write rights and owner), then each
    parent folder up to the drive root (rename, delete and permission rights
    and owner). Why: a process at the user's own privilege that can write
    there could swap the exe or the helper between the hash check and the
    run, and the service may run from this path as SYSTEM.
    #>
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Paths, [Parameter(Mandatory)][string]$Folder)
    $reasons = @()
    $targets = @($Folder) + @($Paths)
    foreach ($p in $targets) {
        try { $info = Get-PathSecurityInfo -Path $p } catch { $reasons += "cannot read permissions of ${p}: $($_.Exception.Message)"; continue }
        if (-not (Test-OwnerTrusted -Owner $info.Owner)) { $reasons += "owner of $p is $($info.Owner), not SYSTEM, Administrators or TrustedInstaller" }
        foreach ($b in (Get-UnsafeAce -Aces $info.Aces)) { $reasons += "$p : $b" }
    }
    $parent = Split-Path -Parent $Folder
    while ($parent) {
        try { $info = Get-PathSecurityInfo -Path $parent } catch { $reasons += "cannot read permissions of ${parent}: $($_.Exception.Message)"; break }
        # The drive root is owned by SYSTEM or TrustedInstaller on a normal
        # install, so the same owner rule applies.
        if (-not (Test-OwnerTrusted -Owner $info.Owner)) { $reasons += "owner of parent $parent is $($info.Owner), not trusted" }
        foreach ($b in (Get-UnsafeAce -Aces $info.Aces -Mask $script:AncestorMask)) { $reasons += "parent $parent : $b" }
        $next = Split-Path -Parent $parent
        if ($next -eq $parent) { break }
        $parent = $next
    }
    $reasons
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

function Test-ExeOrFail {
    <#
    Shared pre-flight for both scripts. Order: binary present, then (with
    -RequireTrustedLocation) the folder permission check, then the hash.
    Returns 0 when fine, otherwise the script exit code after printing why.
    #>
    param(
        [Parameter(Mandatory)][string]$ExePath,
        [Parameter(Mandatory)][string]$SumsPath,
        [switch]$RequireTrustedLocation
    )
    if (-not (Test-Path -LiteralPath $ExePath -PathType Leaf)) {
        Write-Host "REFUSED: $($script:PreviewExeName) is not next to this script." -ForegroundColor Red
        Write-Host "Expected: $ExePath"
        Write-Host 'Extract the whole zip first and run the script from the extracted folder.'
        return $script:ExitBinaryMissing
    }
    if ($RequireTrustedLocation) {
        $folder = Split-Path -Parent $ExePath
        $helper = Join-Path -Path $folder -ChildPath 'preview-common.ps1'
        $reasons = @(Test-LocationOrFail -Folder $folder -Paths @($ExePath, $helper))
        if ($reasons.Count -gt 0) {
            Write-Host 'REFUSED: this folder can be changed by someone other than SYSTEM or Administrators.' -ForegroundColor Red
            $reasons | ForEach-Object { Write-Host "  $_" }
            Write-Host 'A program running as an ordinary user could replace the exe after the checks and before it runs as administrator.'
            Write-Host 'Extract the zip into a folder that only administrators can write (for example one created from an elevated shell under C:\Program Files) and run the script from there.'
            return $script:ExitUnsafeFolder
        }
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
