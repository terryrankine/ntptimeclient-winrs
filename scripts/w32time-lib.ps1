# Functions for the guarded helpers apply-tuned-profile.ps1, w32time-state.ps1 and restore-clock.ps1.
# No parameters. Dot-source it. Loading it changes nothing.

Set-StrictMode -Version Latest

$script:W32ConfigKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config'
$script:W32ParametersKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
$script:W32ServiceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time'
$script:ProfileNames = @('MinPollInterval', 'MaxPollInterval', 'UpdateInterval', 'PhaseCorrectRate', 'FrequencyCorrectRate')
$script:ParameterNames = @('NtpServer', 'Type')
$script:TunedValues = [ordered]@{ MinPollInterval = 6; MaxPollInterval = 6; UpdateInterval = 100; PhaseCorrectRate = 1; FrequencyCorrectRate = 2 }

# --- Second test-machine signal -------------------------------------------------------------
function Test-VirtualMachineModel {
    # Heuristic on the model and manufacturer strings. It is not proof. HypervisorPresent is not used
    # because it is also true on a physical host that runs virtualisation based security.
    param([string]$Model, [string]$Manufacturer)
    if ($Model -match 'Virtual|VMware|KVM|QEMU|Hyper-V|Xen') { return $true }
    if ($Manufacturer -match 'VMware|QEMU|Xen|innotek|Parallels|Red Hat') { return $true }
    return $false
}

function Test-SecondTestMachineSignal {
    # True on a virtual machine by the heuristic above, or when MEASURE_I_AM_ON_A_TEST_MACHINE is 1
    # (for a physical test box). Read only.
    if ($env:MEASURE_I_AM_ON_A_TEST_MACHINE -eq '1') { return $true }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        return (Test-VirtualMachineModel -Model ([string]$cs.Model) -Manufacturer ([string]$cs.Manufacturer))
    }
    catch { return $false }
}

# --- Tuned profile: state, apply, undo ------------------------------------------------------
function Assert-KeyAllowed {
    # Normal use may touch the real W32Time keys only. A test run (SkipService) may touch only a
    # throwaway key under HKCU:\Software\ntptimeclient-winrs-test-.
    param([string]$Key, [bool]$TestMode, [string]$Real)
    if ($TestMode) {
        if ($Key -notlike 'HKCU:\Software\ntptimeclient-winrs-test-*') { throw "test mode refuses key $Key" }
    }
    elseif ($Key -ne $Real) { throw "refusing key $Key. Only $Real is allowed." }
}

function Get-ProfileState {
    param([string]$ConfigKey = $script:W32ConfigKey, [string]$ParametersKey = $script:W32ParametersKey)
    $p = Get-ItemProperty -Path $ConfigKey
    $cfg = [ordered]@{}
    foreach ($n in $script:ProfileNames) { $cfg[$n] = if ($p.PSObject.Properties.Name -contains $n) { $p.$n } else { $null } }
    $q = Get-ItemProperty -Path $ParametersKey
    $par = [ordered]@{}
    foreach ($n in $script:ParameterNames) { $par[$n] = if ($q.PSObject.Properties.Name -contains $n) { $q.$n } else { $null } }
    [ordered]@{ Config = $cfg; Parameters = $par }
}

function ConvertTo-StateKey {
    # Canonical text of a state, for comparing a saved file with the live values. Absent is <absent>.
    param($State)
    $parts = @()
    foreach ($n in $script:ProfileNames) { $v = $State.Config.$n; $parts += "Config.$n=$(if ($null -eq $v) { '<absent>' } else { $v })" }
    foreach ($n in $script:ParameterNames) { $v = $State.Parameters.$n; $parts += "Parameters.$n=$(if ($null -eq $v) { '<absent>' } else { $v })" }
    $parts -join "`n"
}

function Read-StateFile {
    param([string]$Path)
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Save-StateFile {
    # Atomic: write a temp file, move it into place, read it back and compare. Refuses to overwrite.
    param($State, [string]$Path)
    if (Test-Path -LiteralPath $Path) { throw "state file exists. Refusing to overwrite: $Path" }
    $tmp = "$Path.tmp"
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
    ($State | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $tmp -Encoding ASCII -ErrorAction Stop
    Move-Item -LiteralPath $tmp -Destination $Path -ErrorAction Stop
    $back = Read-StateFile -Path $Path
    if ((ConvertTo-StateKey $State) -ne (ConvertTo-StateKey $back)) { throw "state file read back differs from the live values: $Path" }
}

function Restore-ProfileState {
    # Puts back recorded values and removes those that were absent. Every item is tried. Errors are collected.
    param($State, [string]$ConfigKey = $script:W32ConfigKey, [string]$ParametersKey = $script:W32ParametersKey)
    $errs = @()
    foreach ($n in $script:ProfileNames) {
        try {
            $v = $State.Config.$n
            if ($null -ne $v) { Set-ItemProperty -Path $ConfigKey -Name $n -Value ([int]$v) -Type DWord -ErrorAction Stop }
            else { Remove-ItemProperty -Path $ConfigKey -Name $n -ErrorAction SilentlyContinue }
        }
        catch { $errs += "Config.${n}: $($_.Exception.Message)" }
    }
    foreach ($n in $script:ParameterNames) {
        try {
            $v = $State.Parameters.$n
            if ($null -ne $v) { Set-ItemProperty -Path $ParametersKey -Name $n -Value ([string]$v) -Type String -ErrorAction Stop }
            else { Remove-ItemProperty -Path $ParametersKey -Name $n -ErrorAction SilentlyContinue }
        }
        catch { $errs += "Parameters.${n}: $($_.Exception.Message)" }
    }
    if ($errs.Count) { throw ('restore had errors: ' + ($errs -join ' | ')) }
}

function Invoke-TunedProfile {
    # Saves and verifies the before state, then applies. Any failure restores from the saved file and throws.
    # SkipService and FailAt are for tests: they skip w32tm and the service restart, and inject a failure.
    param([string[]]$Peers, [string]$StateFile, [string]$ConfigKey = $script:W32ConfigKey, [string]$ParametersKey = $script:W32ParametersKey, [switch]$SkipService, [int]$FailAt = 0)
    Assert-KeyAllowed -Key $ConfigKey -TestMode ([bool]$SkipService) -Real $script:W32ConfigKey
    Assert-KeyAllowed -Key $ParametersKey -TestMode ([bool]$SkipService) -Real $script:W32ParametersKey
    $state = Get-ProfileState -ConfigKey $ConfigKey -ParametersKey $ParametersKey
    Save-StateFile -State $state -Path $StateFile    # throws before any change when it cannot be saved and verified
    $saved = Read-StateFile -Path $StateFile
    try {
        $i = 0
        if (-not $SkipService) {
            $peerList = ($Peers | ForEach-Object { "$_,0x8" }) -join ' '
            & w32tm /config "/manualpeerlist:$peerList" /syncfromflags:manual /update | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "w32tm /config exited $LASTEXITCODE" }
        }
        foreach ($n in $script:TunedValues.Keys) {
            $i++
            if ($FailAt -eq $i) { throw "injected failure at step $i" }
            Set-ItemProperty -Path $ConfigKey -Name $n -Value $script:TunedValues[$n] -Type DWord -ErrorAction Stop
        }
        if (-not $SkipService) { Restart-Service w32time -ErrorAction Stop }
    }
    catch {
        $why = $_.Exception.Message
        try { Restore-ProfileState -State $saved -ConfigKey $ConfigKey -ParametersKey $ParametersKey; if (-not $SkipService) { Restart-Service w32time -ErrorAction Stop } }
        catch { throw "apply failed ($why) and the automatic undo also failed ($($_.Exception.Message)). Restore from $StateFile by hand." }
        throw "apply failed ($why). The saved values were restored."
    }
}

function Invoke-TunedUndo {
    param([string]$StateFile, [string]$ConfigKey = $script:W32ConfigKey, [string]$ParametersKey = $script:W32ParametersKey, [switch]$SkipService)
    Assert-KeyAllowed -Key $ConfigKey -TestMode ([bool]$SkipService) -Real $script:W32ConfigKey
    Assert-KeyAllowed -Key $ParametersKey -TestMode ([bool]$SkipService) -Real $script:W32ParametersKey
    if (-not (Test-Path -LiteralPath $StateFile)) { throw "no such state file: $StateFile" }
    Restore-ProfileState -State (Read-StateFile -Path $StateFile) -ConfigKey $ConfigKey -ParametersKey $ParametersKey
    if (-not $SkipService) { Restart-Service w32time -ErrorAction Stop }
}

# --- w32time service start type -------------------------------------------------------------
function ConvertTo-ScStartKeyword {
    # Registry Start and DelayedAutostart to the sc.exe config start= keyword.
    param([int]$Start, [int]$DelayedAutostart = 0)
    switch ($Start) {
        0 { return 'boot' }
        1 { return 'system' }
        2 { if ($DelayedAutostart -eq 1) { return 'delayed-auto' } else { return 'auto' } }
        3 { return 'demand' }
        4 { return 'disabled' }
        default { throw "unknown Start value $Start" }
    }
}

function Get-W32TimeServiceState {
    # Read only. Registry Start and DelayedAutostart, plus the sc.exe query text for the record.
    param([string]$ServiceKey = $script:W32ServiceKey, [switch]$SkipSc)
    $p = Get-ItemProperty -Path $ServiceKey
    $start = [int]$p.Start
    $delayed = if ($p.PSObject.Properties.Name -contains 'DelayedAutostart') { [int]$p.DelayedAutostart } else { 0 }
    $state = [ordered]@{
        Start = $start
        DelayedAutostart = $delayed
        StartKeyword = (ConvertTo-ScStartKeyword -Start $start -DelayedAutostart $delayed)
        Running = $null
        Qc = ''
        TriggerInfo = ''
    }
    if (-not $SkipSc) {
        $state.Running = ((Get-Service -Name w32time).Status -eq 'Running')
        $state.Qc = ((& sc.exe qc w32time) -join "`n")
        $state.TriggerInfo = ((& sc.exe qtriggerinfo w32time) -join "`n")
    }
    $state
}

function Restore-W32TimeServiceState {
    # Sets the recorded start type with sc.exe, reads it back, and compares the trigger info. A trigger
    # difference is reported as an error: it is never guessed.
    param($State, [switch]$StartIfWasRunning)
    $kw = ConvertTo-ScStartKeyword -Start ([int]$State.Start) -DelayedAutostart ([int]$State.DelayedAutostart)
    & sc.exe config w32time "start=" $kw | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe config exited $LASTEXITCODE" }
    $now = Get-W32TimeServiceState
    if ($now.StartKeyword -ne $kw) { throw "start type read back as $($now.StartKeyword), recorded $kw" }
    if (($now.TriggerInfo -replace '\s+', ' ').Trim() -ne ([string]$State.TriggerInfo -replace '\s+', ' ').Trim()) {
        throw 'trigger info differs from the record. Restore the saved .reg file with reg import and reboot. Not guessed.'
    }
    if ($StartIfWasRunning -and $State.Running -eq $true -and -not $now.Running) { Start-Service -Name w32time -ErrorAction Stop }
}
