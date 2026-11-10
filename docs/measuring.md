# Measuring ntptimeclient-winrs against Windows time

Status: procedure only. No results exist yet. Every number marked "proposal" is the author's call and the owner must confirm it before the first run.

## 1. Purpose and what a measurement can show

The spec says success is measured, not promised. Success means the service beats the Windows default in each case and never makes the clock worse.

The earlier spike (`docs/superpowers/notes/ntp-proto-spike.md`) ran `w32tm /stripchart` once idle and once under load. It gave a median of +4.9 ms idle and +9.0 ms under load. The two runs used different pool servers. One run against a random pool server cannot tell clock error from path error. Nobody has yet compared a tuned `w32time`, Meinberg NTP and the service against one independent reference on one host over a long run. This procedure does that.

### What is measured

- The sampler reads the offset between this computer's clock and one reference server, as seen through the network path.
- The reading is `w32tm /stripchart` output. It uses the standard NTP offset calculation (Microsoft: [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings), `/stripchart` and `/rdtsc` rows).
- It is not true UTC error. The reference has its own error. The path adds a bias if the outbound and return delays differ.
- NTP bounds that path bias. The offset error cannot exceed half the round trip delay. The sampler records the delay so the bound is known per run. This bound comes from the NTP design and is not restated on the Microsoft page.
- The sign convention of the offset is not stated on the Microsoft page. The analysis uses absolute offsets and the slope magnitude. It never depends on the sign.

### Claims the project may make

- On this host, with this Windows build, against this reference, over this period, the service had a median absolute offset to the reference of A ms and the Windows default had B ms.
- The same host, reference and path were used for every contender, so a constant path bias applies to all of them. The difference between contenders is therefore meaningful even where the absolute offset is not.
- The service did or did not make the clock worse than the free-run control.
- The error rate of each contender, and the recovery time after a disturbance.

### Claims the project may NOT make

- "Accurate to within X ms of UTC". The method cannot show it.
- "Better than Windows in general". Only the measured host, network, reference and cases are covered.
- "Better than Meinberg" unless Meinberg was run in the same way.
- Anything about domain-joined machines, other networks, laptops on battery, or other Windows builds that were not measured.
- Any number from a run that failed the checklist in section 8.

## 2. Reference choice

Rules:

1. The reference must not be a source that any contender uses. The service defaults to `pool.ntp.org`. The Windows default is `time.windows.com`. Use a different public source, or a LAN server such as a GPS-disciplined one if the owner has it.
2. The same reference, by IP address, for every contender and every run on the host.
3. Never use a pool name. A pool name resolves to a different server each run. The sampler refuses `pool.ntp.org` names unless `-AllowPool` is given.
4. Resolve once and keep the address. Record it.

Pick it with a probe. Run this for each candidate. It reads only.

```powershell
Resolve-DnsName time.cloudflare.com -Type A | Select-Object -ExpandProperty IPAddress
w32tm /stripchart /computer:162.159.200.1 /samples:60 /period:2 /dataonly /rdtsc
```

Accept a candidate when all of these hold (proposals):

| Test | Limit | Reason |
| --- | --- | --- |
| Error rate in 60 probes | 0 | A flaky reference hides contender errors |
| Median round trip delay | 20 ms or less | Delay bounds the path bias at half of it |
| Spread of delay (p95 minus p5) | 2 ms or less | A steady path has a steady bias |
| Stratum of the reference | 1 or 2 | Fewer hops of error |

Reject a reference that disagrees with a second reference. Probe both for 30 minutes with the same sampler, one after the other, on the same free-run or default clock. Compare the median offsets. If they differ by more than 2 ms (proposal), at least one has a path bias or a fault. Pick another pair. If the difference is under 2 ms but over the delay bound of either, report the disagreement and do not claim better than that resolution.

Use a second reference for the whole study when the owner can. Section 3 uses it as a control.

## 3. Contenders and run order

### The contenders

| Label | What it is | Changes system state | Needs admin |
| --- | --- | --- | --- |
| `w32time-default` | `w32time` as shipped, no changes | No | No (sampler), yes to read config |
| `w32time-tuned` | `w32time` with the settings below | Yes: registry and service | Yes |
| `meinberg` | Meinberg NTP for Windows, optional | Yes: install, stops `w32time` | Yes |
| `service` | ntptimeclient-winrs, `install` stops and disables `w32time` | Yes | Yes |
| `free-run` | Service stopped and `w32time` stopped. No sync | Yes: stops a service | Yes |

Anything that stops `w32time` or installs a service needs a throwaway VM or a test machine. Do not run `free-run`, `meinberg` or `service` on a machine that matters. The sampler itself changes nothing and needs no admin.

### Same sources for every contender

Give `w32time-tuned`, `meinberg` and `service` the same sources. Use the three `pool.ntp.org` regional servers that `w32time-default` already shows in `w32tm /query /status` (the `ReferenceId` line gives the current one), written as IP addresses. This keeps the contender side fair. The reference stays separate (section 2).

### Tuned `w32time` profile

WARNING. These commands change the machine. Apply them only on a test machine or a throwaway VM, as administrator. Microsoft marks these registry values "don't change". Back up first: `reg export HKLM\SYSTEM\CurrentControlSet\Services\W32Time w32time-before.reg /y` (checked: runs without admin).

Source for every setting: [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings) (the registry reference tables). The values below are the author's choice for "tight sync". That they give better sync is UNVERIFIED. The study tests it.

| Setting | Value | Documented meaning | Documented default (stand-alone) |
| --- | --- | --- | --- |
| `NtpServer` flags | `,0x8` per peer | 0x8 is Client. 0x1 would use `SpecialPollInterval` | `time.windows.com,0x1` |
| `Config\MinPollInterval` | 6 (64 s) | Log base 2 seconds | 10 |
| `Config\MaxPollInterval` | 6 (64 s) | Log base 2 seconds | 15 |
| `Config\UpdateInterval` | 100 | Phase correction interval, 10 ms units, so 1 s | 360000 |
| `Config\PhaseCorrectRate` | 1 | Smaller corrects phase faster, may be unstable | 7 |
| `Config\FrequencyCorrectRate` | 2 | Smaller corrects faster, may overcorrect | 4 |

The page also notes that the stand-alone defaults in its tables and the Group Policy defaults differ. Read your machine's real values first with `w32tm /dumpreg /subkey:Config` (checked: runs without admin).

```powershell
# Administrator. Test machine only.
w32tm /config /manualpeerlist:"IP1,0x8 IP2,0x8 IP3,0x8" /syncfromflags:manual /update
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config'
Set-ItemProperty -Path $k -Name MinPollInterval -Value 6 -Type DWord
Set-ItemProperty -Path $k -Name MaxPollInterval -Value 6 -Type DWord
Set-ItemProperty -Path $k -Name UpdateInterval -Value 100 -Type DWord
Set-ItemProperty -Path $k -Name PhaseCorrectRate -Value 1 -Type DWord
Set-ItemProperty -Path $k -Name FrequencyCorrectRate -Value 2 -Type DWord
Restart-Service w32time
```

Undo: `reg import w32time-before.reg`, then `Restart-Service w32time`. Then `w32tm /dumpreg /subkey:Config` and compare with the "before" dump. `/config` flags are from `w32tm /?` on this build. The registry value names are from the Microsoft page.

### Meinberg NTP (optional)

Install it only on the test machine. Its installer stops `w32time`, which is the reason for the test machine rule. Point it at the same three IPs. Record its version and config file. The exact install and config syntax is not given here because it was not checked. Mark the contender `meinberg` and report its settings in full.

### Run order and wash-out

- One contender at a time on the same host.
- Wash-out before sampling starts: 30 minutes (proposal). The discipline needs time to converge. Check that `w32tm /query /status` shows a small `Phase Offset` for `w32time`, and that the service status shows it is synchronised.
- Rotate the contender order between rounds, for example A B C D then B C D A. This stops time of day and network load from favouring one contender.
- Run at least 3 rounds per case (proposal). Fewer rounds cannot separate a contender effect from round-to-round noise.
- Include an A/A control. Run `w32time-default` twice in the same position of two rounds. The difference between those two runs is the noise floor. Section 7 uses it.
- Include the `free-run` control once per case that is not sleep. It shows the clock error with no correction. A contender that is not clearly better than free-run is not working.
- Between contenders, restore state: stop the service with `ntptimeclient-winrs.exe uninstall`, which restores `w32time` per the design, then check `w32tm /query /status`. Do not trust it. Read the status.

### Path asymmetry checks

A constant asymmetry biases every contender equally. Detect it three ways:

1. Two references on different paths (section 2). A real clock error shows the same offset on both. A path bias shows different offsets, and the difference is at most the delay bound.
2. Compare delay. If the median delay is 5 ms, the bias cannot exceed 2.5 ms. If it is 55 ms, it could reach 27 ms.
3. `free-run` with the service stopped. The offset then moves steadily with drift. Its start value, after one manual sync, shows the bias floor. Do not read this alone, because the sync itself used a path.

During the 24 hour run (section 4) start a second sampler in another terminal against the second reference, with its own output file. Both series then share the same clock under test.

## 4. Cases

All cases run on the same host. Sampling interval and length are proposals. The reason for each is given.

| Case | Min length per run | Interval | Why this length |
| --- | --- | --- | --- |
| Idle | 4 h | 16 s | 900 samples. A p99 needs about 500 or more good samples |
| CPU load | 2 h | 10 s | 720 samples. Load effects show in minutes, not days |
| Sleep and resume | 6 cycles | 5 s | Each cycle yields one recovery time. 6 gives a median |
| VM | 4 h | 16 s | As idle, on a VM with hypervisor sync off |
| Disturbed clock | 20 min | 1 s | Recovery is fast. A 1 s interval resolves it |
| Long run | 24 h or more | 30 s | Covers a full day and night cycle. 2880 samples. Shows drift |

A 24 hour run per contender is expensive: five runs for five contenders. Do it for `w32time-default`, `service` and `free-run` as the minimum.

### Idle

- Nothing else running. Screen locked or off is fine. Sleep disabled.
- Record: sampler CSV, `w32tm /query /status` at start, middle and end for `w32time`, the service status output at the same times.

### CPU load

Use a built-in busy loop on a number of cores. No extra tools. Start the load before the wash-out ends and keep it for the whole run.

```powershell
# Load generator: N busy jobs. Stop with the cleanup lines.
$n = [Math]::Max(1, [int]([Environment]::ProcessorCount / 2))   # half the logical cores
$jobs = 1..$n | ForEach-Object {
    Start-Job -ScriptBlock {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalMinutes -lt 150) { [void][math]::Sqrt(12345.678) }
    }
}
# check the load, read only
Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 5 -MaxSamples 3
# cleanup
$jobs | Stop-Job
$jobs | Remove-Job
```

Sizing: run two levels. Half of the logical cores gives about 50 percent load. All logical cores (`$n = [Environment]::ProcessorCount`) gives about 100 percent. The spike used 24 jobs on 24 cores. Confirm the level with the `Get-Counter` line and record it. The loop stops itself after 150 minutes in case cleanup is forgotten. Do not leave it running while the machine is unattended on battery.

Record: the load level, the sampler CSV, and the service status.

### Sleep and resume

- Do the sleep by hand from the Start menu. Do not script hibernation.
- Per cycle: awake 5 minutes, asleep 10 minutes, then wake. Repeat 6 times.
- Start the sampler once. It continues after resume. A gap in `utc_iso` marks each sleep.
- Note the wake time of each cycle in a text file, in UTC: `(Get-Date).ToUniversalTime().ToString('o')`.
- Recovery time per cycle: from the wake time to the first moment when three consecutive samples are within the limit (section 7). The snippet is below.

```powershell
$inv = [cultureinfo]::InvariantCulture
$mark = [DateTimeOffset]::Parse('2026-11-10T10:54:15Z', $inv).UtcDateTime   # wake or disturbance time
$limit = 0.010                                                              # seconds, proposal
$rows = @(Import-Csv .\case.csv | Where-Object { $_.error -eq '' -and [DateTimeOffset]::Parse($_.utc_iso, $inv).UtcDateTime -ge $mark })
$hit = for ($i = 0; $i -le $rows.Count - 3; $i++) {
    $win = $rows[$i..($i + 2)]
    if (@($win | Where-Object { [math]::Abs([double]::Parse($_.offset_s, $inv)) -lt $limit }).Count -eq 3) { $rows[$i]; break }
}
if ($hit) { ([DateTimeOffset]::Parse($hit.utc_iso, $inv).UtcDateTime - $mark).TotalSeconds } else { 'not recovered' }
```

(Checked on a short canned CSV. It parses and returns a time.)

### Virtual machine

- Hypervisor time sync must be off, or documented. The spec says VM detection is out of scope and asks for measurement on a VM with hypervisor time sync off.
- Hyper-V host: `Get-VMIntegrationService -VMName NAME` shows the state (the cmdlet exists on this machine). To switch it off: `Disable-VMIntegrationService -VMName NAME -Name 'Time Synchronization'`. Run on the host as administrator. Syntax not run here because this machine has no VM to test on.
- Other hypervisors: look up the vendor setting. It is not covered here and is UNVERIFIED.
- In the guest, `w32tm /query /status` shows `Source`. If it says "VM IC Time Synchronization Provider", the hypervisor is still setting the clock. The Microsoft page shows that line in its sample output. The run is then invalid.
- Record the host load and the hypervisor version.

### Disturbed clock (throwaway VM only)

This sets the clock wrong on purpose. Never do it on a machine that matters. A step changes timestamps, Kerberos tickets and logs.

1. Contender running and converged. Sampler running with a 1 s interval.
2. Record the time, then set the clock 2 s back (administrator):

```powershell
$mark = (Get-Date).ToUniversalTime().ToString('o'); $mark
Set-Date -Adjust (New-TimeSpan -Seconds -2)
```

3. Watch for 20 minutes. Compute recovery time with the snippet above, using the `$mark` time.
4. A 2 s error is above the service step threshold of 128 ms (spec). The `w32time` default steps above its `MaxAllowedPhaseOffset` (the Microsoft page gives 1 s for stand-alone). Both should step. The test shows how fast and how clean.
5. Repeat 3 times per contender. Also repeat with a 50 ms offset (`-Milliseconds -50`) to test slewing.

### Long run

24 hours or more, idle, at 30 s. Reason: drift behaviour, temperature and the day and night path cycle. Use a stable power plan and no sleep. Run the `free-run` control for 24 hours too. The drift in ppm comes from the summary slope. The slope includes any drift of the path to the reference. Compare contenders by the slope difference to the `free-run` slope, and treat the absolute slope as indicative only.

## 5. The sampler and the summary

Files: `scripts/measure-offset.ps1`, `scripts/summarise-offset.ps1`, `scripts/test-measure.ps1`.

### Sampler

Wraps `w32tm /stripchart /computer:<ref> /samples:N /period:S /dataonly /rdtsc`. The switches were checked with `w32tm /?`. Read only. Needs no admin. Changes no state.

```powershell
.\scripts\measure-offset.ps1 -Reference 162.159.200.1 -Contender w32time-default -Case idle `
    -Samples 900 -PeriodSeconds 16 -OutPath .\out\w32time-default-idle-r1.csv
```

| Parameter | Rule |
| --- | --- |
| `-Reference` | Host name or IP. Pool names refused unless `-AllowPool` |
| `-Contender` | Label, 1 to 64 characters of letters, digits, dot, underscore, hyphen |
| `-Case` | Same label rule |
| `-Samples` | 1 to 1000000 |
| `-PeriodSeconds` | 1 to 3600 |
| `-OutPath` | Must not exist. Folder must exist |
| `-Plain` | Use the plain format instead of `/rdtsc`. Timestamps then come from the receipt time |

Exit codes: 0 finished, 1 run failed or every sample failed, 2 bad input. Nothing is overwritten.

CSV columns: `utc_iso, contender, case, reference, offset_s, delay_s, error`.

- By default the timestamp is the `FileTime` that `w32tm` prints, converted to UTC. It is the local clock at the request. This is the contender's clock under test, and so the timestamp is itself an input to the measurement. For plotting that is fine. A sudden step shows as a jump in the timestamp. Read this when analysing disturbance runs.
- A failed sample is a row with an error text and empty offset. Examples: `w32tm error 0x800705B4` (timeout) and `w32tm error 0x80072733`. A line the parser does not understand becomes a row `unparsed line: ...`. A shortfall in rows becomes `missing sample` rows. Errors count toward the error rate.
- The parser handles a decimal comma, a Unicode minus, a 12 hour time with PM, and the `s` and `d` unit suffix. The `d` suffix is read as days and flagged as an error row, because its meaning is UNVERIFIED. No real `d` line has been seen.
- The delay column is present in the default `/rdtsc` format. It is empty in `-Plain`.
- The reference is resolved once per run by `w32tm`. Pass an IP so the address cannot change. The resolved address is printed on stderr at the end.
- Run time: `samples x period`. A crash leaves the rows written so far, flushed one by one. The shortfall rows are only added when `w32tm` exits.
- Run it from an unelevated prompt. Nothing needs admin.

### Summary

```powershell
.\scripts\summarise-offset.ps1 .\out\*.csv
```

Per contender, case and reference, it prints: samples, errors, error percentage, median, p5, p95, p99, mean and max of the absolute offset in ms, and the drift slope in ppm. Percentiles use nearest rank. Errors are excluded from the offset statistics. `-AsObject` returns objects instead of text.

Drift is the least squares slope of the signed offset over time, in ppm. It includes the path to the reference. With only a few minutes of data it is noise. Use it only on long runs.

### Tests

`powershell -NoProfile -File scripts\test-measure.ps1` runs checks with no network access. It covers the parser (21 canned lines, including a timeout, a negative offset, error lines, a decimal comma, PM time and the `d` suffix), the CSV rows, the input validation, the refusal to overwrite, the exit codes and the summary maths on known numbers. Pester 3.4.0 is the only version installed here, so plain checks are used.

## 6. Comparison table and the report

### Table format

One row per case and contender. Medians over all rounds, with the round to round range in the last column. Rounding: milliseconds to 2 decimals below 10 and 1 decimal from 10. Percentages to 1 decimal. ppm to 1 decimal. Recovery times to whole seconds.

| Case | Contender | Good samples | Error rate | Median abs ms | p99 abs ms | Max abs ms | Drift ppm | Median delay ms | Range of medians across rounds |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Idle | w32time-default | N | N.N % | N.NN | N.NN | N.NN | N.N | N.NN | N.NN to N.NN |
| Idle | service | N | N.N % | N.NN | N.NN | N.NN | N.N | N.NN | N.NN to N.NN |

EXAMPLE, NOT A RESULT. The values above are placeholders. Do not read them as data.

A second table gives recovery times (wake or disturbance) per contender with the median and the worst of the repeats.

Every row needs a link to its CSV files. The CSVs go in the report folder, with the reference IP, the Windows build, the service version and config, and the `w32time` registry dump.

### One paragraph

Template:

> On HOST (Windows BUILD), against reference REF (delay median D ms, so path bias is at most D/2 ms), over R rounds, the service had a median absolute offset of A ms and the Windows default had B ms in the idle case (difference C ms, noise floor F ms). Under load the figures were A2 and B2. After a 2 s step the service recovered in S s and the Windows default in T s. The service lost in CASE by X. Error rates were E1 and E2. The free-run clock drifted at P ppm. Tuned `w32time` had A3.

EXAMPLE ONLY. The letters stand for numbers that do not exist yet.

### When the service loses

It must be reported, with numbers, in the same table and the same paragraph.

- Name the case, the contender it lost to and the size of the loss. Give median, p99 and error rate.
- Do not average a loss away across cases.
- State what was checked: the run was valid, the reference agreed with the second reference, the A/A noise floor.
- Give candidate causes as hypotheses and label them unverified. Do not change the service and re-run on the same data to remove the loss. See section 7.
- A loss against `w32time-default` and a loss against `w32time-tuned` are separate findings.

## 7. Pre-registered analysis plan

This section is written before any result exists. The owner confirms the numbers below before the first run. A change after the first result must be recorded as a change, with the date and the reason.

### What counts as better

For each case, in this order:

1. Median absolute offset to the reference, over all good samples of all rounds.
2. p99 absolute offset.
3. Error rate (errors over samples).
4. Recovery time, for the sleep and disturbance cases. Median of repeats.
5. Drift slope for the long run, as a difference from `free-run`.

The primary measure is item 1. Items 2 to 4 are reported and may veto a win.

### Minimum difference that matters (proposal, author's call)

A difference counts only when all three hold:

- It is at least 1 ms or 20 percent of the Windows default value, whichever is larger. Reason: the spike median was 4.9 ms idle, so 20 percent is about 1 ms. Below 1 ms the path bias bound (half the delay) is of the same order as the difference.
- It is larger than the A/A noise floor, which is the largest difference between the two `w32time-default` runs in the same case.
- It has the same sign in at least 3 of 3 rounds, or in all rounds if more.

A difference below this is reported as "no meaningful difference". It is not a win and not a loss.

Other proposals:

| Item | Proposal | Reason |
| --- | --- | --- |
| Reference agreement limit | 2 ms between two references | About a tenth of a 20 ms path delay bound |
| Recovery limit | 10 ms for three consecutive samples | Above sampler noise, below the claims |
| Error rate that matters | 2 percentage points | Dozens of errors out of 900 is a real fault |
| Wash-out | 30 minutes | Convergence of the discipline |
| Rounds | 3 | The least that gives a sign check |

### Freezing

- Freeze the service version (git commit) and its config before round 1. Record the commit.
- Do not tune the service after seeing results and reuse the same data. A change means a new version and a full new set of rounds. Report both sets with the tuning noted.
- Tune `w32time-tuned` once, before the rounds. The profile in section 3 is the whole profile.
- Exclude a run only for a reason listed in section 8, and list every exclusion in the report. Never exclude for being an outlier.

### What would make the owner conclude the project is NOT worth shipping (proposal)

Any one of these:

1. The service does not beat `w32time-tuned` by the minimum difference in the idle median or the load p99, across the 3 rounds. Then accuracy is not a reason to ship. Other reasons (security posture, readable code, a status log) have to carry it alone.
2. The service is worse than `free-run` in any case beyond the minimum difference. The service is then making the clock worse.
3. The service is worse than `w32time-default` by the minimum difference in two or more cases.
4. The service error rate is more than 2 percentage points above `w32time-default` in any case.
5. The disturbed clock recovery of the service is more than twice as slow as `w32time-default` after repeated runs.
6. The two references disagree by more than the limit on the final data, so no claim can be made.

The owner decides. The list only fixes the question before the answer exists.

## 8. Checklist for the person running it

Machine and system:

- [ ] Throwaway VM or a test machine for everything that stops `w32time`, installs a service or sets the clock.
- [ ] Not a domain-joined machine. Group Policy may restart `w32time` and change its settings.
- [ ] Record the Windows build: `(Get-CimInstance Win32_OperatingSystem).Version` and `winver`.
- [ ] Record the CPU, core count, RAM, and whether it is a VM.
- [ ] Power plan fixed: `powercfg /getactivescheme`. Same plan for every run. No sleep or hibernate during idle and load runs. Time zone is irrelevant because everything is UTC.
- [ ] Antivirus and updates: no scan or Windows Update running during a run. Record the policy. Pause updates if the test machine allows it.
- [ ] No other time tool installed. No VPN client that moves the route during a run.

Network:

- [ ] Wired network if possible. No Wi-Fi roaming.
- [ ] No large transfers on the same link during idle and long runs.
- [ ] UDP 123 outbound open. The sampler uses an ephemeral source port. `w32time` uses 123 (Microsoft page).
- [ ] The reference IP, its probe results and the second reference are recorded and meet section 2.

VM:

- [ ] Hypervisor time sync off, or documented. Check that the `w32tm /query /status` `Source` is not the VM provider.
- [ ] Host load and hypervisor version recorded.

Software under test:

- [ ] Service version: git commit, the config file, the build type (release), and whether it was installed by the preview zip.
- [ ] `w32time` configuration before and after each contender: `w32tm /dumpreg /subkey:Config` and `reg export HKLM\SYSTEM\CurrentControlSet\Services\W32Time before.reg /y`. Both run without admin (checked). `w32tm /query /configuration` needs admin (observed Access denied unelevated).
- [ ] The service's own view of its offset, copied at the start, middle and end of each run. The design leaves the status command and log format open (spec: "Log format and status command design"). The architecture note says only that there is a log file and a status command. Record whatever it prints, with the time, and compare its offset to the external reference column in the CSV. The comparison is meaningful only when they are close or when they diverge.
- [ ] Wash-out of 30 minutes done and recorded.
- [ ] The service logs show no panic, no refused step and no `w32time` conflict during the run. A conflict makes the run invalid.

During a run:

- [ ] Sampler started from an unelevated prompt. The output path is new.
- [ ] Note the start time, the case, the contender, the round and any event (load start, wake, step) in a text file in UTC.
- [ ] Do not use the machine for anything else.
- [ ] After the run: run the summary, check the error rate, keep the CSV.

Invalid run (exclude and say so):

- The reference changed address or went down for more than 5 percent of samples.
- Another time tool or Group Policy changed the clock.
- The machine slept when it should not have.
- A hypervisor set the clock.
- The sampler was run with a different reference or period from the others.

## Sources and unverified items

- `w32tm /?` on Windows 11 build 26300: `/stripchart`, `/rdtsc`, `/config`, `/dumpreg`, `/query` switches.
- [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings): `/stripchart` and `/rdtsc` columns, the registry settings, defaults, the 0x1 and 0x8 `NtpServer` flags, the phase correction formula, UDP 123.
- Observed by running read-only commands on the author's machine: the `/rdtsc` row format, the `error: 0x800705B4` form for a timeout, the plain `HH:MM:SS, error: 0x...` form, `w32tm /dumpreg` and `reg export` without admin, `w32tm /query /configuration` denied without admin.

Unverified:

- That the tuned profile improves sync. The study tests it.
- The sign convention of the offset.
- The meaning of a `d` suffix in stripchart output.
- Meinberg install and config steps, and hypervisor settings other than Hyper-V (the Hyper-V cmdlet exists but was not run).
- That the half-delay bound on path bias applies as stated to `w32tm` offsets. It is the NTP design bound.
- All proposal numbers: sample lengths, 30 minute wash-out, 3 rounds, 1 ms or 20 percent, 2 ms reference agreement, 10 ms recovery limit, 2 percentage points error rate.
