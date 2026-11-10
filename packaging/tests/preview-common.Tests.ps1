# Pester tests for the pure helpers in preview-common.ps1.
# They never run install.ps1 or uninstall.ps1 and never call a service API.
# Written in the legacy "Should Be" form so Pester 3 and Pester 5 both run it.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\preview-common.ps1')

# "Should Throw" under Pester 3.4 on PowerShell 7 reported no exception here (cause not found),
# so the throws are asserted by hand.
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
    It 'throws when the name is listed twice' {
        (Test-Throws { Get-ExpectedHash -SumsText "$h1  x`n$h2  x" -FileName 'x' }) | Should Be $true
    }
    It 'matches the name exactly, case included' {
        (Test-Throws { Get-ExpectedHash -SumsText "$h1  X.EXE" -FileName 'x.exe' }) | Should Be $true
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

Describe 'Test-BinaryAgainstSums (temp files only)' {
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('pv-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    $exe = Join-Path $dir 'ntptimeclient-winrs.exe'
    [System.IO.File]::WriteAllBytes($exe, [byte[]](1, 2, 3, 4))
    $real = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $sums = Join-Path $dir 'SHA256SUMS'

    It 'is true when the sums match' {
        [System.IO.File]::WriteAllText($sums, "$real  ntptimeclient-winrs.exe`n")
        Test-BinaryAgainstSums -ExePath $exe -SumsPath $sums | Should Be $true
    }
    It 'is false when the file changed' {
        [System.IO.File]::WriteAllText($sums, "$h1  ntptimeclient-winrs.exe`n")
        Test-BinaryAgainstSums -ExePath $exe -SumsPath $sums | Should Be $false
    }
    It 'throws when SHA256SUMS is missing' {
        Remove-Item -LiteralPath $sums
        (Test-Throws { Test-BinaryAgainstSums -ExePath $exe -SumsPath $sums }) | Should Be $true
    }
    It 'Test-ExeOrFail returns the missing-binary code' {
        $r = Test-ExeOrFail -ExePath (Join-Path $dir 'nope.exe') -SumsPath $sums 6>$null
        $r | Should Be 42
    }
    It 'Test-ExeOrFail returns the hash code when the sums file is missing' {
        $r = Test-ExeOrFail -ExePath $exe -SumsPath $sums 6>$null
        $r | Should Be 43
    }
    Remove-Item -LiteralPath $dir -Recurse -Force
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

Describe 'Messages' {
    It 'the warning says UNSIGNED PREVIEW' {
        (Get-PreviewWarningText) | Should Match 'UNSIGNED PREVIEW'
    }
    It 'the rollback names w32time and the service' {
        $t = Get-ManualRollbackText
        $t | Should Match 'sc.exe config w32time'
        $t | Should Match 'sc.exe delete ntptimeclient-winrs'
    }
}
