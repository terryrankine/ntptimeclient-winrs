# Pester tests for the pure helpers in preview-common.ps1.
# They never run install.ps1 or uninstall.ps1 and never call a service API or
# change the machine. The only process started is cmd.exe with an echo and an
# exit code, to test exit code handling.
# Legacy "Should Be" form, run with Pester 3.4 only. Pester 5 needs BeforeAll
# for the shared variables, so it is not run in CI.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\preview-common.ps1')

# "Should Throw" under Pester 3.4 on PowerShell 7 reported no exception here
# (cause not found), so the throws are asserted by hand.
function Test-Throws([scriptblock]$Block) { try { & $Block | Out-Null; $false } catch { $true } }

$h1 = ('a' * 64)
$h2 = ('B' * 64)

Describe 'Get-ExpectedHash' {
    It 'reads a two-space line' {
        Get-ExpectedHash -SumsText "$h1  ntptimeclient-winrs.exe" -FileName 'ntptimeclient-winrs.exe' | Should Be $h1
    }
    It 'accepts the binary marker, CRLF and lower-cases the hash' {
        $text = "$h2 *other.txt`r`n$h2  ntptimeclient-winrs.exe`r`n"
        Get-ExpectedHash -SumsText $text -FileName 'ntptimeclient-winrs.exe' | Should Be ('b' * 64)
    }
    It 'throws when the file is not listed' {
        (Test-Throws { Get-ExpectedHash -SumsText "$h1  other.txt" -FileName 'ntptimeclient-winrs.exe' }) | Should Be $true
    }
    It 'throws on empty text' {
        (Test-Throws { Get-ExpectedHash -SumsText '' -FileName 'x' }) | Should Be $true
    }
    It 'throws on a short hash' {
        (Test-Throws { Get-ExpectedHash -SumsText 'abc  x' -FileName 'x' }) | Should Be $true
    }
    It 'throws on a 65 character hash' {
        (Test-Throws { Get-ExpectedHash -SumsText ('a' * 65 + '  x') -FileName 'x' }) | Should Be $true
    }
    It 'throws when the name is listed twice' {
        (Test-Throws { Get-ExpectedHash -SumsText "$h1  x`n$h2  x" -FileName 'x' }) | Should Be $true
    }
    It 'matches the name exactly, case included' {
        (Test-Throws { Get-ExpectedHash -SumsText "$h1  X.EXE" -FileName 'x.exe' }) | Should Be $true
    }
    It 'does not match a line with a ..\ path' {
        (Test-Throws { Get-ExpectedHash -SumsText "$h1  ..\ntptimeclient-winrs.exe" -FileName 'ntptimeclient-winrs.exe' }) | Should Be $true
    }
    It 'does not match a line with an absolute path' {
        (Test-Throws { Get-ExpectedHash -SumsText "$h1  C:\evil\ntptimeclient-winrs.exe" -FileName 'ntptimeclient-winrs.exe' }) | Should Be $true
    }
}

Describe 'Test-HashEquals' {
    It 'ignores case and surrounding space' {
        Test-HashEquals -Expected $h2 -Actual (' ' + ('b' * 64)) | Should Be $true
    }
    It 'is false on a different hash' {
        Test-HashEquals -Expected $h1 -Actual $h2 | Should Be $false
    }
}

Describe 'Test-BinaryAgainstSums and Test-ExeOrFail (temp files only)' {
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('pv-' + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $dir | Out-Null
        $exe = Join-Path $dir 'ntptimeclient-winrs.exe'
        [System.IO.File]::WriteAllBytes($exe, [byte[]](1, 2, 3, 4))
        $real = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        $sums = Join-Path $dir 'SHA256SUMS'

        It 'is true when the sums match' {
            [System.IO.File]::WriteAllText($sums, "$real  ntptimeclient-winrs.exe`n")
            Test-BinaryAgainstSums -ExePath $exe -SumsPath $sums | Should Be $true
        }
        It 'Test-ExeOrFail returns 0 on a match' {
            $r = Test-ExeOrFail -ExePath $exe -SumsPath $sums 6>$null
            $r | Should Be 0
        }
        It 'is false when the file changed' {
            [System.IO.File]::WriteAllText($sums, "$h1  ntptimeclient-winrs.exe`n")
            Test-BinaryAgainstSums -ExePath $exe -SumsPath $sums | Should Be $false
        }
        It 'Test-ExeOrFail returns 43 on a hash mismatch' {
            $r = Test-ExeOrFail -ExePath $exe -SumsPath $sums 6>$null
            $r | Should Be 43
        }
        It 'Test-ExeOrFail returns 42 when the exe is missing' {
            $r = Test-ExeOrFail -ExePath (Join-Path $dir 'nope.exe') -SumsPath $sums 6>$null
            $r | Should Be 42
        }
        It 'throws when SHA256SUMS is missing' {
            Remove-Item -LiteralPath $sums
            (Test-Throws { Test-BinaryAgainstSums -ExePath $exe -SumsPath $sums }) | Should Be $true
        }
        It 'Test-ExeOrFail returns 43 when the sums file is missing' {
            $r = Test-ExeOrFail -ExePath $exe -SumsPath $sums 6>$null
            $r | Should Be 43
        }
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Get-ExeArguments' {
    It 'install has no domain override by default' {
        $a = Get-ExeArguments -Command install
        @($a).Count | Should Be 1
        $a[0] | Should Be 'install'
    }
    It 'install adds the override only on request' {
        $a = Get-ExeArguments -Command install -ConfirmDomainJoined
        ($a -join ' ') | Should Be 'install --confirm-domain-joined'
    }
    It 'uninstall is one argument' {
        $a = Get-ExeArguments -Command uninstall
        ($a -join ' ') | Should Be 'uninstall'
    }
    It 'uninstall refuses the domain override' {
        (Test-Throws { Get-ExeArguments -Command uninstall -ConfirmDomainJoined }) | Should Be $true
    }
    It 'rejects any other command' {
        (Test-Throws { Get-ExeArguments -Command 'run' }) | Should Be $true
    }
}

Describe 'ConvertTo-ScStartKeyword' {
    It 'maps Start 0 to boot' { ConvertTo-ScStartKeyword -Start 0 -DelayedAutostart 0 | Should Be 'boot' }
    It 'maps Start 1 to system' { ConvertTo-ScStartKeyword -Start 1 -DelayedAutostart 0 | Should Be 'system' }
    It 'maps Start 2 delayed 0 to auto' { ConvertTo-ScStartKeyword -Start 2 -DelayedAutostart 0 | Should Be 'auto' }
    It 'maps Start 2 delayed 1 to delayed-auto' { ConvertTo-ScStartKeyword -Start 2 -DelayedAutostart 1 | Should Be 'delayed-auto' }
    It 'maps Start 2 with no delayed value to auto' { ConvertTo-ScStartKeyword -Start 2 -DelayedAutostart $null | Should Be 'auto' }
    It 'maps Start 3 to demand' { ConvertTo-ScStartKeyword -Start 3 -DelayedAutostart 0 | Should Be 'demand' }
    It 'ignores delayed on Start 3' { ConvertTo-ScStartKeyword -Start 3 -DelayedAutostart 1 | Should Be 'demand' }
    It 'maps Start 4 to disabled' { ConvertTo-ScStartKeyword -Start 4 -DelayedAutostart 0 | Should Be 'disabled' }
    It 'gives null for a missing Start' { ConvertTo-ScStartKeyword -Start $null -DelayedAutostart 0 | Should BeNullOrEmpty }
    It 'gives null for Start 5' { ConvertTo-ScStartKeyword -Start 5 -DelayedAutostart 0 | Should BeNullOrEmpty }
    It 'gives null for Start -1' { ConvertTo-ScStartKeyword -Start -1 -DelayedAutostart 0 | Should BeNullOrEmpty }
    It 'gives null for text' { ConvertTo-ScStartKeyword -Start 'abc' -DelayedAutostart 0 | Should BeNullOrEmpty }
}

Describe 'Rollback text' {
    It 'prints the concrete keyword' {
        (Get-RollbackCommand -StartKeyword 'delayed-auto') | Should Be 'sc.exe config w32time start= delayed-auto'
    }
    It 'prints no command and no default when the value is unknown' {
        $t = Get-RollbackCommand -StartKeyword $null
        $t | Should Match 'No default is guessed'
        $t | Should Not Match 'sc.exe config'
    }
    It 'names restore.json as the authority and has no hard-coded demand when unknown' {
        $t = Get-ManualRollbackText -StartKeyword $null
        $t | Should Match 'restore.json'
        $t | Should Not Match 'demand'
    }
    It 'names the service and the clock rate caveat' {
        $t = Get-ManualRollbackText -StartKeyword 'auto'
        $t | Should Match 'sc.exe delete ntptimeclient-winrs'
        $t | Should Match 'non-nominal'
    }
    It 'the warning says UNSIGNED PREVIEW' {
        (Get-PreviewWarningText) | Should Match 'UNSIGNED PREVIEW'
    }
    It 'the execution policy help is process scope and uses -NoProfile' {
        $t = Get-ExecutionPolicyHelp -ScriptName 'install.ps1'
        $t | Should Match '-NoProfile -ExecutionPolicy Bypass -File'
        $t | Should Match 'does not change the machine policy'
    }
}

Describe 'Test-InstallOutcome and Test-UninstallOutcome' {
    $svc = { param($state, $start) [pscustomobject]@{ State = $state; StartMode = $start } }
    It 'flags a stub: nothing changed' {
        $s = [pscustomobject]@{ W32Time = (& $svc 'Running' 'Manual'); W32TimeStart = 'demand'; Ours = $null }
        @(Test-InstallOutcome -State $s).Count | Should Be 3
    }
    It 'passes when w32time is stopped and disabled and our service exists' {
        $s = [pscustomobject]@{ W32Time = (& $svc 'Stopped' 'Disabled'); W32TimeStart = 'disabled'; Ours = (& $svc 'Running' 'Auto') }
        @(Test-InstallOutcome -State $s).Count | Should Be 0
    }
    It 'flags a missing service' {
        $s = [pscustomobject]@{ W32Time = (& $svc 'Stopped' 'Disabled'); W32TimeStart = 'disabled'; Ours = $null }
        @(Test-InstallOutcome -State $s).Count | Should Be 1
    }
    It 'falls back to StartMode when the registry value is unreadable' {
        $s = [pscustomobject]@{ W32Time = (& $svc 'Stopped' 'Manual'); W32TimeStart = $null; Ours = (& $svc 'Running' 'Auto') }
        @(Test-InstallOutcome -State $s).Count | Should Be 1
    }
    It 'uninstall flags a service that is still there' {
        $s = [pscustomobject]@{ W32Time = $null; W32TimeStart = $null; Ours = (& $svc 'Running' 'Auto') }
        @(Test-UninstallOutcome -State $s).Count | Should Be 1
    }
    It 'uninstall passes when the service is gone' {
        $s = [pscustomobject]@{ W32Time = $null; W32TimeStart = $null; Ours = $null }
        @(Test-UninstallOutcome -State $s).Count | Should Be 0
    }
}

Describe 'Get-UnsafeAce and Test-OwnerTrusted (hand-built ACEs)' {
    function New-Ace($who, $rights, $type = 'Allow', $prop = 'None') {
        [pscustomobject]@{
            IdentityReference = $who
            AccessControlType = $type
            FileSystemRights  = [System.Security.AccessControl.FileSystemRights]$rights
            PropagationFlags  = [System.Security.AccessControl.PropagationFlags]$prop
        }
    }
    $admins = New-Ace 'BUILTIN\Administrators' 'FullControl'
    $system = New-Ace 'NT AUTHORITY\SYSTEM' 'FullControl'
    $ti = New-Ace 'NT SERVICE\TrustedInstaller' 'FullControl'

    It 'accepts an admin-only folder' {
        @(Get-UnsafeAce -Aces @($admins, $system, $ti, (New-Ace 'BUILTIN\Users' 'ReadAndExecute'))).Count | Should Be 0
    }
    It 'refuses Users with Modify' {
        @(Get-UnsafeAce -Aces @($admins, (New-Ace 'BUILTIN\Users' 'Modify'))).Count | Should Be 1
    }
    It 'refuses Authenticated Users with Write' {
        @(Get-UnsafeAce -Aces @((New-Ace 'NT AUTHORITY\Authenticated Users' 'Write'))).Count | Should Be 1
    }
    It 'refuses a SID principal with AppendData' {
        @(Get-UnsafeAce -Aces @((New-Ace 'S-1-5-21-1-2-3-1001' 'AppendData'))).Count | Should Be 1
    }
    It 'refuses Delete and WriteAttributes' {
        @(Get-UnsafeAce -Aces @((New-Ace 'BUILTIN\Users' 'Delete'), (New-Ace 'BUILTIN\Users' 'WriteAttributes'))).Count | Should Be 2
    }
    It 'refuses ChangePermissions and TakeOwnership' {
        @(Get-UnsafeAce -Aces @((New-Ace 'BUILTIN\Users' 'ChangePermissions, TakeOwnership'))).Count | Should Be 1
    }
    It 'ignores CREATOR OWNER inherit-only' {
        @(Get-UnsafeAce -Aces @((New-Ace 'CREATOR OWNER' 'FullControl' 'Allow' 'InheritOnly'))).Count | Should Be 0
    }
    It 'refuses CREATOR OWNER that applies to this object' {
        @(Get-UnsafeAce -Aces @((New-Ace 'CREATOR OWNER' 'FullControl'))).Count | Should Be 1
    }
    It 'ignores a deny ACE' {
        @(Get-UnsafeAce -Aces @((New-Ace 'BUILTIN\Users' 'FullControl' 'Deny'))).Count | Should Be 0
    }
    It 'treats an unknown name as untrusted' {
        @(Get-UnsafeAce -Aces @((New-Ace 'CONTOSO\bob' 'Modify'))).Count | Should Be 1
    }
    It 'accepts an empty ACL' {
        @(Get-UnsafeAce -Aces @()).Count | Should Be 0
    }
    It 'for a parent folder allows creating sub folders but not removal' {
        $m = $script:AncestorMask
        @(Get-UnsafeAce -Aces @((New-Ace 'BUILTIN\Users' 'AppendData')) -Mask $m).Count | Should Be 0
        @(Get-UnsafeAce -Aces @((New-Ace 'BUILTIN\Users' 'DeleteSubdirectoriesAndFiles')) -Mask $m).Count | Should Be 1
    }
    It 'owner: Administrators, SYSTEM and TrustedInstaller are trusted' {
        Test-OwnerTrusted -Owner 'BUILTIN\Administrators' | Should Be $true
        Test-OwnerTrusted -Owner 'S-1-5-18' | Should Be $true
        Test-OwnerTrusted -Owner 'NT SERVICE\TrustedInstaller' | Should Be $true
    }
    It 'owner: a user is not trusted' {
        Test-OwnerTrusted -Owner 'S-1-5-21-1-2-3-1001' | Should Be $false
        Test-OwnerTrusted -Owner 'CONTOSO\bob' | Should Be $false
        Test-OwnerTrusted -Owner $null | Should Be $false
    }
}

Describe 'Invoke-ExeKeepingExitCode' {
    # Nothing is changed here: cmd.exe echoes to stderr and exits 3.
    $cmd = $env:ComSpec
    It 'returns the exit code after stderr output under Stop' {
        $old = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        try {
            $r = Invoke-ExeKeepingExitCode -Path $cmd -Arguments @('/c', 'echo x 1>&2 & exit 3') 6>$null
        } finally { $ErrorActionPreference = $old }
        $r | Should Be 3
    }
    It 'returns the exit code when the caller redirects all streams' {
        $old = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        try {
            $r = Invoke-ExeKeepingExitCode -Path $cmd -Arguments @('/c', 'echo x 1>&2 & exit 3') *>&1
        } finally { $ErrorActionPreference = $old }
        @($r | Where-Object { $_ -is [int] })[-1] | Should Be 3
    }
    It 'returns 0 on success' {
        (Invoke-ExeKeepingExitCode -Path $cmd -Arguments @('/c', 'exit 0') 6>$null) | Should Be 0
    }
    It 'restores the caller ErrorActionPreference' {
        $old = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        try { Invoke-ExeKeepingExitCode -Path $cmd -Arguments @('/c', 'exit 0') 6>$null | Out-Null; $now = $ErrorActionPreference }
        finally { $ErrorActionPreference = $old }
        $now | Should Be 'Stop'
    }
}
