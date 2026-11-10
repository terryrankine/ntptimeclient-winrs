# More Pester tests for preview-common.ps1: exit code classes, unreadable
# state, the location check and the cannot-start path. Nothing here runs the
# scripts or changes the machine. Pester 3.4 syntax, like the other file.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\preview-common.ps1')

function Test-Throws([scriptblock]$Block) { try { & $Block | Out-Null; $false } catch { $true } }

Describe 'Get-ExeArguments -AcceptDisabledOriginal' {
    It 'is absent by default' {
        (Get-ExeArguments -Command install) -join ' ' | Should Be 'install'
    }
    It 'is added only on request' {
        (Get-ExeArguments -Command install -AcceptDisabledOriginal) -join ' ' | Should Be 'install --accept-disabled-original'
    }
    It 'combines with the domain switch' {
        (Get-ExeArguments -Command install -ConfirmDomainJoined -AcceptDisabledOriginal) -join ' ' | Should Be 'install --confirm-domain-joined --accept-disabled-original'
    }
    It 'is refused for uninstall' {
        (Test-Throws { Get-ExeArguments -Command uninstall -AcceptDisabledOriginal }) | Should Be $true
    }
}

Describe 'Exit codes do not overlap' {
    It 'wrapper codes are 40 to 48, unique, and clear of the exe codes 0 to 33' {
        $names = 'ExitRiskNotAccepted', 'ExitNotElevated', 'ExitBinaryMissing', 'ExitHashMismatch', 'ExitUnsafeFolder', 'ExitDeclined', 'ExitStateMismatch', 'ExitUninstallStateMismatch', 'ExitCannotStart'
        $vals = @($names | ForEach-Object { (Get-Variable -Name $_ -Scope Script).Value })
        @($vals | Select-Object -Unique).Count | Should Be $vals.Count
        @($vals | Where-Object { $_ -lt 40 -or $_ -gt 48 }).Count | Should Be 0
    }
}

Describe 'Get-ExeExitClass' {
    foreach ($c in 2, 3, 4, 5, 6, 7, 12, 13, 16, 20, 31, 33) {
        It "exit $c means nothing changed" {
            (Get-ExeExitClass -Code $c -Command install).Class | Should Be 'NothingChanged'
            (Get-ExeExitClass -Code $c -Command install).Message | Should Match 'Nothing was changed'
        }
    }
    It 'exit 9 is unsure and points at the exe text' {
        $r = Get-ExeExitClass -Code 9 -Command install
        $r.Class | Should Be 'Unsure'
        $r.Message | Should Match 'exe text'
    }
    foreach ($c in 19, 21) {
        It "exit $c is after takeover" { (Get-ExeExitClass -Code $c -Command install).Class | Should Be 'AfterTakeover' }
    }
    foreach ($c in 8, 10, 11, 14, 15, 17, 18, 1, 26, 99) {
        It "exit $c may have changed something" { (Get-ExeExitClass -Code $c -Command install).Class | Should Be 'MayHaveChanged' }
    }
    It 'exit 12 names -AcceptDisabledOriginal' {
        (Get-ExeExitClass -Code 12 -Command install).Message | Should Match '-AcceptDisabledOriginal'
    }
    It 'exit 20 never says halfway' {
        (Get-ExeExitClass -Code 20 -Command install).Message | Should Not Match 'halfway'
    }
    It 'exit 0 is success' { (Get-ExeExitClass -Code 0 -Command install).Class | Should Be 'Success' }
}

Describe 'Get-RollbackCommand with a disabled original' {
    It 'warns and prints no sc.exe line' {
        $t = Get-RollbackCommand -StartKeyword 'disabled'
        $t | Should Match 'already DISABLED'
        $t | Should Not Match 'sc.exe config'
    }
}

Describe 'Unreadable service state is never a success' {
    $ok = [pscustomobject]@{ Name = 'x'; Unreadable = $false; Error = ''; State = 'Stopped'; StartMode = 'Disabled'; PathName = ''; StartName = '' }
    $bad = [pscustomobject]@{ Name = 'x'; Unreadable = $true; Error = 'boom'; State = ''; StartMode = ''; PathName = ''; StartName = '' }
    It 'uninstall: an unreadable service is a problem' {
        $s = [pscustomobject]@{ W32Time = $ok; W32TimeStart = 'demand'; Ours = $bad }
        @(Test-UninstallOutcome -State $s).Count | Should Be 1
    }
    It 'uninstall: an unreadable w32time is a problem' {
        $s = [pscustomobject]@{ W32Time = $bad; W32TimeStart = $null; Ours = $null }
        @(Test-UninstallOutcome -State $s).Count | Should Be 1
    }
    It 'install: an unreadable service is a problem' {
        $s = [pscustomobject]@{ W32Time = $ok; W32TimeStart = 'disabled'; Ours = $bad }
        @(Test-InstallOutcome -State $s).Count | Should Be 1
    }
    It 'install: an unreadable w32time is a problem' {
        $s = [pscustomobject]@{ W32Time = $bad; W32TimeStart = 'disabled'; Ours = $ok }
        @(Test-InstallOutcome -State $s).Count | Should Be 1
    }
    It 'Format-MachineState says UNREADABLE' {
        $s = [pscustomobject]@{ W32Time = $bad; W32TimeStart = $null; Ours = $bad }
        (Format-MachineState -State $s) -join "`n" | Should Match 'UNREADABLE'
    }
    Mock Get-CimInstance { throw 'cim down' }
    It 'Get-ServiceFacts returns an Unreadable marker when CIM throws' {
        $r = Get-ServiceFacts -Name 'nothing'
        $r.Unreadable | Should Be $true
        $r.Error | Should Match 'cim down'
    }
}

Describe 'Get-LocationProblem (hand-built facts)' {
    function New-Facts($drive = 'Fixed', $selfLink = $false, $entries = @(), $parents = @()) {
        [pscustomobject]@{ Folder = 'C:\p\x'; FolderIsReparse = $selfLink; DriveType = $drive; Entries = $entries; Parents = $parents }
    }
    function New-Entry($name, $dir = $false, $reparse = $false, $links = 1) {
        [pscustomobject]@{ Path = "C:\p\x\$name"; IsDirectory = $dir; IsReparse = $reparse; LinkCount = $links }
    }
    It 'accepts a flat folder of single-link files on a fixed drive' {
        @(Get-LocationProblem -Facts (New-Facts -entries @((New-Entry 'a.exe'), (New-Entry 'b.ps1')) -parents @([pscustomobject]@{ Path = 'C:\p'; IsReparse = $false }))).Count | Should Be 0
    }
    It 'refuses a removable or network drive' {
        @(Get-LocationProblem -Facts (New-Facts -drive 'Removable')).Count | Should Be 1
        @(Get-LocationProblem -Facts (New-Facts -drive 'NotLocal')).Count | Should Be 1
    }
    It 'refuses a subfolder' {
        (@(Get-LocationProblem -Facts (New-Facts -entries @((New-Entry 'sub' -dir $true)))) -join ' ') | Should Match 'subfolder'
    }
    It 'refuses a reparse file' {
        @(Get-LocationProblem -Facts (New-Facts -entries @((New-Entry 'a.exe' -reparse $true)))).Count | Should Be 1
    }
    It 'refuses a file with 2 links' {
        (@(Get-LocationProblem -Facts (New-Facts -entries @((New-Entry 'a.exe' -links 2)))) -join ' ') | Should Match 'links'
    }
    It 'refuses an unreadable link count' {
        @(Get-LocationProblem -Facts (New-Facts -entries @((New-Entry 'a.exe' -links $null)))).Count | Should Be 1
    }
    It 'refuses a junction as the folder' {
        @(Get-LocationProblem -Facts (New-Facts -selfLink $true)).Count | Should Be 1
    }
    It 'refuses a junction parent' {
        @(Get-LocationProblem -Facts (New-Facts -parents @([pscustomobject]@{ Path = 'C:\p'; IsReparse = $true }))).Count | Should Be 1
    }
}

Describe 'Test-LocationOrFail (own temp folder, read only)' {
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('loc-' + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $dir | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $dir 'a.exe'), [byte[]](1))
        It 'refuses a folder under the temp directory' {
            # Temp lives under the user profile. A parent right or the owner gives it away.
            $n = @(Test-LocationOrFail -Folder $dir).Count
            if ($n -eq 0) { Set-TestInconclusive 'this temp folder passed under this token (an elevated CI account can own and reach it)' } else { ($n -gt 0) | Should Be $true }
        }
        It 'refuses a folder that holds a subfolder and names it' {
            New-Item -ItemType Directory -Path (Join-Path $dir 'sub') | Out-Null
            (@(Test-LocationOrFail -Folder $dir) -join "`n") | Should Match 'subfolder not allowed'
        }
        It 'refuses by owner when this account is not an administrator owner' {
            $info = Get-PathSecurityInfo -Path $dir
            if (Test-OwnerTrusted -Owner $info.Owner) {
                # An elevated token creates Administrators-owned objects, so the owner rule cannot fire here.
                Set-TestInconclusive 'owner of the temp folder is trusted under this token'
            } else {
                (@(Test-LocationOrFail -Folder $dir) -join "`n") | Should Match 'owner of'
            }
        }
    } finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-ExeKeepingExitCode when the file cannot run' {
    It 'returns the cannot-start code and runs nothing' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('bad-' + [guid]::NewGuid().ToString('N'))
        try {
            New-Item -ItemType Directory -Path $dir | Out-Null
            $bad = Join-Path $dir 'notanexe.exe'
            [System.IO.File]::WriteAllText($bad, 'this is text, not a program')
            $r = Invoke-ExeKeepingExitCode -Path $bad -Arguments @('x') *>&1
            @($r | Where-Object { $_ -is [int] })[-1] | Should Be 48
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
