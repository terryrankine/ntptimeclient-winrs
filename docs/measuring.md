# Measuring ntptimeclient-winrs against Windows time

Status: procedure only. No results exist yet. Every number marked "proposal" is the author's call. The owner must confirm them and freeze them (section 8) before the first run.

## 1. Purpose and what a measurement can show

The spec says success is measured, not promised. Success means the service beats the Windows default in each case and never makes the clock worse.

The earlier spike (`docs/superpowers/notes/ntp-proto-spike.md`) ran `w32tm /stripchart` once idle and once under load. It gave a median of +4.9 ms idle and +9.0 ms under load, with 28 of 120 samples failing under load. The two runs used different pool servers. One run against a random pool server cannot tell clock error from path error. The load figure may also be partly a sampler artefact (section 5). Nobody has yet compared a tuned `w32time`, Meinberg NTP and the service against one independent reference on one host over a long run. This procedure does that.

### What is measured

- The sampler reads the offset between this computer's clock and a reference server, as seen through the network path.
- The reading is `w32tm /stripchart` output. Its columns are described in [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings) (`/stripchart` and `/rdtsc`).
- It is not true UTC error. The reference has its own error. The path adds a bias if the outbound and return delays differ.
- NTP bounds that bias. The offset error cannot exceed half the round trip delay. This is the NTP design bound. It is not restated on the Microsoft page. The sampler records the delay so the bound is known per case.
- Sign: a POSITIVE offset means the reference is AHEAD, so the local clock is SLOW. Checked by the reviewer with a raw NTP exchange. The offset formula (server transmit time minus local receive time, with the usual round trip correction) gave the same sign as `w32tm /stripchart`. A positive slope of the offset over time therefore means the local clock is losing time relative to the reference.
- `w32tm /stripchart` does not set the clock. Its help text lists no set action and it uses an ephemeral source port. In the author's smoke tests 13 samples over about 5 minutes on two references stayed inside a 5.5 ms band with no step. That shows no step. It is not proof that nothing is touched.

### Claims the project may make

- On this host, with this Windows build, against these references, over these rounds, the service had a median absolute offset of A ms and the Windows default had B ms.
- The same host, references and path were used for every contender. A constant path bias therefore applies to all of them. The difference between contenders is meaningful where the absolute offset is not.
- The service did or did not make the clock worse than the free-run control.
- The error rate of each contender and the recovery time after a disturbance.

### Claims the project may NOT make

- "Accurate to within X ms of UTC". The method cannot show it.
- "Better than Windows in general". Only the measured host, network, references and cases are covered.
- "Better than Meinberg" unless Meinberg ran in the same way.
- Anything about domain-joined machines, other networks, battery use, or other Windows builds that were not measured.
- A drift figure for a disciplined clock. Only the free-run control has a drift figure. For any other contender the slope is a residual trend.
- Any number from a run that failed the checklist in section 9.

## 2. Reference choice

The owner chooses the references and records the choice. This document does not pick one. Any server named in an example is a placeholder.

Rules:

1. A reference must not be a source that any contender uses. The service defaults to `pool.ntp.org`. The Windows default on the author's machine uses one pool server (section 3).
2. Use TWO references from different operators, sampled at the same time in every block (section 4). One is the primary reference for the comparison. The other is the check.
3. Never use a pool name. It resolves to a different server on each run. The sampler refuses `pool.ntp.org` names unless `-AllowPool` is given.
4. Pass the sampler an IP address. Be aware that an anycast address is one address served by many machines. Pinning the IP does not pin the server or the path over 24 hours.

Best option: a server on the owner's LAN that is disciplined by GPS. It has low and steady delay, no rate limit and no anycast. Second best: a national laboratory or ISP stratum 1 source near the owner, if the owner knows one. The owner must verify that it exists, is open to the public and what its policy is. Do not rely on a public name from memory.

### Measuring a candidate (read only)

Stratum, root delay and root dispersion:

```powershell
w32tm /stripchart /computer:<REF_IP> /samples:1 /packetinfo /dataonly
```

`/packetinfo` is in `w32tm /stripchart /?` on this build. Checked: it printed `Stratum`, `Root Delay`, `Root Dispersion`, `ReferenceId` and the four NTP timestamps for one public candidate. That candidate showed stratum 3, so the stratum rule below does reject some well known public servers.

Alternative: `w32tm /monitor /computers:<REF_IP> /nowarn`. Checked: it printed an ICMP delay, the NTP offset, `RefID` and `Stratum`. It also sends ICMP.

Delay and its spread over a minute:

```powershell
w32tm /stripchart /computer:<REF_IP> /samples:30 /period:2 /dataonly /rdtsc
```

### Candidate checklist

| Check | Accept when (proposal) | How |
| --- | --- | --- |
| Stratum | 1 or 2 | `/packetinfo` |
| Median round trip delay | 20 ms or less for a public server. A LAN server is far lower | `/rdtsc` column `RoundtripDelay` |
| Delay spread (p95 minus p5) | 2 ms or less | the same 30 samples |
| Error rate in the probe | 0 of 30 | the same 30 samples |
| Anycast | Known and recorded. Prefer unicast | Operator documentation. Repeat the probe hours apart. A changed `ReferenceId` or a jump in delay suggests another machine behind the address |
| Leap second smearing | Known and recorded. A smeared server disagrees with unsmeared ones by up to a fraction of a second around a leap second | Operator documentation. Owner must verify. UNVERIFIED here |
| Rate limits | Policy read. Interval and the two samplers fit inside it | Operator policy. Public servers may rate limit or send Kiss-of-Death to fast polling. This shows as error rows |
| Independence | Different operator from the contenders' sources and from the other reference | Operator documentation |

Reject a reference that disagrees with the other reference. The rule is per block (section 4): the signed medians of the two references in the same block must differ by 2 ms or less (proposal). A larger difference means at least one has a path bias or a fault. The block is flagged `DISAGREE` in the summary and is excluded from the primary analysis. Its data stays in the CSV.

## 3. Contenders

| Label | What it is | Changes system state | Needs admin |
| --- | --- | --- | --- |
| `w32time-default` | `w32time` as shipped, no changes | No | No for the sampler |
| `w32time-default-aa` | The same as `w32time-default`, a second set of blocks. The A/A control | No | No |
| `w32time-tuned` | `w32time` with the profile below | Yes: registry and service | Yes |
| `meinberg` | Meinberg NTP for Windows, optional | Yes: install, stops `w32time` | Yes |
| `service` | ntptimeclient-winrs. `install` stops and disables `w32time` | Yes | Yes |
| `free-run` | Service and `w32time` stopped. No sync. Throwaway VM only | Yes: stops a service | Yes |

Anything that stops `w32time`, installs a service or sets the clock needs a throwaway VM or a test machine. Do not run `free-run`, `meinberg` or `service` on a machine that matters. The sampler changes nothing and needs no admin.

### Sources for the contenders

The Windows default does not use the same sources as the service. On the author's machine `w32tm /query /peers` showed ONE peer, `1.au.pool.ntp.org,0x9`, and `/query /status` showed the same source. The registry `NtpServer` value was `1.au.pool.ntp.org,0x9`. So the default has one pool server and the service uses its own tier rules and a pool expansion.

Rules:

- Record the default's real source at the start of every run: `w32tm /query /status` and `w32tm /query /peers`. Both ran without admin here. Also record the service's own source list from its status output.
- Decide, and write down in the frozen plan, whether the difference between the contenders' sources is intended. A difference is intended when the question is "which shipped behaviour is better". It is not intended when the question is "which client algorithm is better".
- When the question is the client algorithm, `w32time-tuned`, `meinberg` and `service` must use the SAME manual peer list, as IP addresses. Give `w32time-default` the same list too if the owner wants a pure algorithm comparison, and say so, because that is no longer the default as shipped.
- If the owner wants the shipped behaviour as well, report both variants as separate result sets.

### Tuned `w32time` profile

WARNING. These commands change the machine. Apply them only on a test machine or a throwaway VM, as administrator. Microsoft marks these registry values as ones not to change. Back up first.

Source for every setting: [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings) (the registry reference tables). The values are the author's choice for tight sync. That they give better sync is UNVERIFIED. The study tests it.

| Setting | Value | Documented meaning | Page default (stand-alone) | Author's machine |
| --- | --- | --- | --- | --- |
| `NtpServer` flags | `,0x8` per peer | 0x8 is Client. 0x1 is SpecialInterval | `time.windows.com,0x1` | `1.au.pool.ntp.org,0x9` |
| `Config\MinPollInterval` | 6 (64 s) | Log base 2 seconds | 10 | 10 |
| `Config\MaxPollInterval` | 6 (64 s) | Log base 2 seconds | 15 | 15 |
| `Config\UpdateInterval` | 100 | Phase correction interval in 10 ms units, so 1 s | 360000 | 360000 |
| `Config\PhaseCorrectRate` | 1 | Smaller corrects phase faster, may be unstable | 7 | 1 |
| `Config\FrequencyCorrectRate` | 2 | Smaller corrects faster, may overcorrect | 4 | 4 |

The page default for `PhaseCorrectRate` (7) differs from the value on the author's machine (1). Read the real values first. They were read without admin.

Record the "before" state. Absent values matter, because `reg import` does not remove a value that was absent before. This part is read only:

```powershell
$k  = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config'
$kp = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
$names = 'MinPollInterval', 'MaxPollInterval', 'UpdateInterval', 'PhaseCorrectRate', 'FrequencyCorrectRate'
$before = @{}
$p = Get-ItemProperty -Path $k
foreach ($n in $names) { $before[$n] = if ($p.PSObject.Properties.Name -contains $n) { $p.$n } else { $null } }
$beforeParams = Get-ItemProperty -Path $kp | Select-Object NtpServer, Type
@{ Config = $before; Parameters = $beforeParams } | ConvertTo-Json | Set-Content .\out\w32time-before.json
reg export HKLM\SYSTEM\CurrentControlSet\Services\W32Time .\out\w32time-before.reg /y
```

A `null` in the JSON means the value was absent. Apply (administrator, test machine only):

```powershell
w32tm /config /manualpeerlist:"IP1,0x8 IP2,0x8 IP3,0x8" /syncfromflags:manual /update
Set-ItemProperty -Path $k -Name MinPollInterval -Value 6 -Type DWord
Set-ItemProperty -Path $k -Name MaxPollInterval -Value 6 -Type DWord
Set-ItemProperty -Path $k -Name UpdateInterval -Value 100 -Type DWord
Set-ItemProperty -Path $k -Name PhaseCorrectRate -Value 1 -Type DWord
Set-ItemProperty -Path $k -Name FrequencyCorrectRate -Value 2 -Type DWord
Restart-Service w32time
```

Undo (administrator). Restore recorded values, and remove those that were absent:

```powershell
foreach ($n in $names) {
    if ($null -ne $before[$n]) { Set-ItemProperty -Path $k -Name $n -Value $before[$n] -Type DWord }
    else { Remove-ItemProperty -Path $k -Name $n -ErrorAction SilentlyContinue }
}
Set-ItemProperty -Path $kp -Name NtpServer -Value $beforeParams.NtpServer
Set-ItemProperty -Path $kp -Name Type -Value $beforeParams.Type
Restart-Service w32time
```

Then compare `w32tm /dumpreg /subkey:Config` and `/subkey:Parameters` with the "before" dumps. The `/config` switches are from `w32tm /?` on this build. The registry value names are from the Microsoft page.

### Meinberg NTP (optional)

Install it only on the test machine. Its installer stops `w32time`, which is the reason for the test machine rule. Point it at the same IPs as the other contenders. Record its version and config file. Exact install and config steps are not given here because they were not checked. Report its settings in full.

## 4. Design: alternating blocks on one host

Sequential multi-hour runs per contender cannot separate a contender effect from time of day and network load. The design below interleaves short blocks of every contender on ONE host.

### Blocks and rounds

- A block is 30 minutes of one contender in one case. A round is one block of every contender, in a balanced order. Each case has 4 rounds (proposal).
- Each block is sampled against TWO references at the same time, by two sampler processes. Both write the same `round` and `block` labels and different CSV files.
- The A/A control is two blocks of the same contender in the balanced order: `w32time-default` and `w32time-default-aa`. Their per-round difference is the noise floor.
- `free-run` is a fixed extra block at the end of every round, VM only. It is a control, not part of the balanced order.

### Balanced order

With four contenders A = `w32time-default`, B = `w32time-default-aa`, C = `w32time-tuned`, D = `service`, use a Williams design. Every contender takes each position once, and every contender follows every other exactly once, so first-order carry-over is balanced:

| Round | Slot 1 | Slot 2 | Slot 3 | Slot 4 |
| --- | --- | --- | --- | --- |
| 1 | A | B | D | C |
| 2 | B | C | A | D |
| 3 | C | D | B | A |
| 4 | D | A | C | B |

Checked by listing the twelve ordered neighbour pairs: each appears once. Four rounds are needed to use all rows. If Meinberg is added there are five contenders and no such square. Use a fixed random order per round with a recorded seed instead, and commit the resulting schedule file before round 1. The order is then known and auditable, and it was fixed before any data. `Get-Random -SetSeed` is not guaranteed to give the same sequence on Windows PowerShell and PowerShell 7, so record the resulting order itself, not only the seed.

Block label: `B1` to `B4` for the slot. Switch contenders by hand or by an administrator script. Record the switch time.

### Wash-out

A wash-out is the part of a block that is dropped from the primary analysis because the contender is still settling. It must achieve two things for a disciplined clock:

1. The previous contender's state is gone. The service sets a clock rate, and `w32time` has its own correction state.
2. The new contender is inside its normal operating band, and the offset is not trending.

Proposal: the first 10 minutes of each 30 minute block (`-DropSeconds 600`). The rows stay in the CSV. The summary prints the dropped part as an appendix (`-Part washout`).

Check it from the data, per contender:

- Compare the median absolute offset of the dropped part with the primary part. A big gap shows the wash-out was needed.
- Compare the first and the second half of the primary part. A difference above the A/A noise floor shows the wash-out was too short.
- `w32time-default` polls slowly (1024 s on the author's machine). It may not converge inside one block. If the check fails for the default, report that finding. Do not lengthen the wash-out for the default only.
- A failed check is not fixed after the fact. It goes in the report. A longer wash-out is a new plan version (section 8) and a new set of rounds.

### Machine time (author's estimate, not measured)

| Case | Blocks per round | Length | Rounds | Hours |
| --- | --- | --- | --- | --- |
| Idle | 4 | 30 min | 4 | 8 |
| CPU load | 4 | 30 min | 4 | 8 |
| Disturbed clock (VM) | 4 | 30 min | 4 | 8 |
| Sleep and resume | 4 | 45 min | 4 | 12 |
| VM idle, with `free-run` | 5 | 30 min | 4 | 10 |
| Long run, 24 h each for default, service and free-run | 3 | 24 h | 1 | 72 |
| Switching overhead, about 10 minutes for each of 84 blocks | | | | 14 |
| Total | | | | about 132 |

That is about 5.5 days of machine time. The minimum useful set is idle, load, disturbed clock and the long run for default, service and free-run.

## 5. Cases

All cases run on the same host, sampled against both references. Each block records the contender, case, round and block.

| Case label | Block | Interval | Samples per block per reference | Primary samples after wash-out |
| --- | --- | --- | --- | --- |
| `idle` | 30 min | 10 s | 180 | 120 |
| `load` | 30 min | 10 s | 180 | 120 |
| `sleep` | 45 min, 3 cycles | 5 s | about 270 awake samples | all, events are analysed |
| `vm` | 30 min | 10 s | 180 | 120 |
| `disturb2s` | 30 min | see below | see below | events are analysed |
| `long` | 24 h | 30 s | 2880 | all |

The sampler's request count is `samples`. For a 30 minute block at 10 s, use `-Samples 180 -PeriodSeconds 10`.

Sample size, honestly: 4 rounds of 120 primary samples is 480 samples per contender per case. Samples from a disciplined clock are autocorrelated. The effective number of independent samples is far lower. A p99 from 480 autocorrelated samples rests on a handful of tail samples. Treat p99 as indicative. It is reported and it vetoes a win (section 8), but it carries less weight than the median.

### Idle

Nothing else running. Sleep disabled. Record the sampler CSVs, the state files (section 9) and the service status output at the start, the middle and the end of each block.

### CPU load

Load inflates local scheduling delay. The sampler's own timestamps and the delay column are measured on the loaded machine. The Task 1 load run with 28 of 120 failures may be partly this effect. So:

- The sampler sets its own priority, and its `w32tm` child's priority, to AboveNormal. It touches no other process. If that fails it prints a warning.
- Leave at least one core free. The primary load level is all logical cores but one.
- Report delay percentiles (median and p95) for the case. They are columns in the summary.
- Before blaming a contender for a higher error rate under load, compare the error rate of the same reference with no load. The baseline contender's rise from idle to load is the host and sampler effect. A contender is blamed only for a rise above the baseline's rise by more than 2 percentage points (proposal).

Test machine guard: the generator refuses to start unless the test machine flag is set. The jobs end themselves 30 minutes after the block would end, as a safety margin. They are also stopped by hand at the end of the block.

```powershell
if ($env:MEASURE_TEST_MACHINE -ne '1') { throw 'Set MEASURE_TEST_MACHINE=1 on a test machine to run the load generator.' }
$blockMinutes = 30
$n = [Math]::Max(1, [Environment]::ProcessorCount - 1)   # leave one core free
$jobs = 1..$n | ForEach-Object {
    Start-Job -ScriptBlock {
        param($minutes)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalMinutes -lt $minutes) { [void][math]::Sqrt(12345.678) }
    } -ArgumentList ($blockMinutes + 30)
}
# check the load, read only
Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 5 -MaxSamples 3
# cleanup at the end of the block
$jobs | Stop-Job
$jobs | Remove-Job
```

Record the job count and the measured load. A half-load level (`ProcessorCount / 2` jobs) is exploratory.

### Sleep and resume

- Sleep by hand from the Start menu. Do not script hibernation.
- Per block: 3 cycles of 5 minutes awake and 10 minutes asleep.
- Start both samplers once per block. They continue after resume. A gap in `utc_iso` marks each sleep.
- Recovery is computed by the summary: the first row after a gap longer than `-GapSeconds` (default 120) is the wake row. Recovery time is the time from that row to the first row that starts `-Consecutive` rows (default 3) all below `-LimitMs` (default 10 ms). An error row breaks a run. No hand-typed wake time is used.

### Virtual machine

- Hypervisor time sync must be off, or documented. The spec says VM detection is out of scope and asks for measurement on a VM with it off.
- Hyper-V host: `Get-VMIntegrationService -VMName NAME` shows the state (the cmdlet exists on this machine). To switch it off: `Disable-VMIntegrationService -VMName NAME -Name 'Time Synchronization'` on the host as administrator. Not run here because this machine has no VM.
- Other hypervisors: look up the vendor setting. UNVERIFIED.
- In the guest, if `w32tm /query /status` shows `Source: VM IC Time Synchronization Provider`, the hypervisor is still setting the clock. The run is invalid.
- The `free-run` block runs only here.

### Disturbed clock (throwaway VM only)

This sets the clock wrong on purpose. Never do it on a machine that matters. A step changes timestamps, tickets and logs.

1. Block of 30 minutes. The contender runs for 10 minutes (the wash-out).
2. At minute 10, set the clock 2 s back as administrator:

```powershell
Set-Date -Adjust (New-TimeSpan -Seconds -2)
```

3. Watch for the other 20 minutes. The summary finds the step by itself: the first row whose offset exceeds `-StepMs` (default 100) after a row below the limit. Recovery time is measured from that row. Sample timestamps come from the clock under test, so a second step by the contender moves them by up to the step size. Read recovery times with that error in mind.
4. A 2 s error is above the service step threshold of 128 ms (spec). `w32time` steps above its `MaxAllowedPhaseOffset` (the Microsoft page gives 1 s for stand-alone). Both should step. The test shows how fast and how clean.
5. Interval: public servers may rate limit or send Kiss-of-Death to polls every second. That shows as error rows. Use a LAN reference at 1 s. With public references use 8 s or longer and accept the coarser recovery resolution. UNVERIFIED for any given server.
6. A 50 ms disturbance (`-Milliseconds -50`) is exploratory. It tests slewing.

### Long run

24 hours, idle, at 30 s, one contender at a time, for `w32time-default`, `service` and `free-run`. Two samplers, one per reference. Reason: the day and night cycle of the path and the host. Only `free-run` gives a drift figure in ppm. For the other contenders the slope is a residual trend, reported as exploratory. The slope also includes any drift of the path to the reference. The summary reports `slope_vs_freerun_ppm` for each contender.

## 6. The sampler and the summary

Files: `scripts/measure-offset.ps1`, `scripts/summarise-offset.ps1`, `scripts/test-measure.ps1`.

### Sampler

Wraps `w32tm /stripchart /computer:<ref> /samples:N /period:S /dataonly /rdtsc`. The switches are in `w32tm /stripchart /?`. Read only. No admin. No state change. Run both samplers of a block at the same time:

```powershell
$common = @('-NoProfile', '-File', '.\scripts\measure-offset.ps1', '-Contender', 'w32time-default', '-Case', 'idle',
            '-Round', '1', '-Block', 'B1', '-Samples', '180', '-PeriodSeconds', '10')
$a = Start-Process powershell.exe -PassThru -ArgumentList ($common + @('-Reference', '<REF_A_IP>', '-OutPath', '.\out\r1-B1-default-idle-A.csv'))
$b = Start-Process powershell.exe -PassThru -ArgumentList ($common + @('-Reference', '<REF_B_IP>', '-OutPath', '.\out\r1-B1-default-idle-B.csv'))
$a, $b | Wait-Process
```

| Parameter | Rule |
| --- | --- |
| `-Reference` | Host name or IP. Pool names refused unless `-AllowPool` |
| `-Contender`, `-Case` | Label, 1 to 64 characters of letters, digits, dot, underscore, hyphen |
| `-Round` | 1 to 999 |
| `-Block` | Empty, or a label as above |
| `-Samples` | 1 to 1000000 |
| `-PeriodSeconds` | 1 to 3600 |
| `-OutPath` | Must not exist. Folder must exist |
| `-Plain` | Plain format instead of `/rdtsc`. Timestamps then come from the receipt time and there is no delay column |

Exit codes: 0 finished, 1 run failed or every sample failed, 2 bad input. Nothing is overwritten.

CSV columns: `utc_iso, contender, case, reference, offset_s, delay_s, error, round, block`.

- The timestamp is the `FileTime` that `w32tm` prints, as UTC. It is the local clock at the request. The clock under test therefore supplies the timestamp. A step shows as a jump.
- A failed sample is a row with an error text and an empty offset. Examples: `w32tm error 0x800705B4` (timeout) and `w32tm error 0x80072733`. Errors count toward the error rate.
- Never dropped: a line the parser does not understand after the first data row becomes an `unparsed line` row. A shortfall in rows becomes `missing sample` rows. If `w32tm` exits non-zero, the shortfall rows carry its message.
- Unrecognised lines before the first data row are ignored and counted. The count is printed on stderr as `preamble_lines`. The parser knows the English preamble and fatal text only. On another language `w32tm` prints different text, so those lines are ignored and counted, and the first unrecognised lines are copied into the shortfall error text when no data arrives. This is a documented limitation. It is tested.
- The parser accepts a decimal comma, a Unicode minus, a 12 hour time with PM, and the `s` suffix. The `d` suffix is read as days and flagged as an error row because its meaning is UNVERIFIED. No real `d` line has been seen.
- The reference is resolved once per run by `w32tm`. Pass an IP. The resolved address is printed on stderr.
- Priority: the sampler raises its own process and its `w32tm` child to AboveNormal. No other process is touched.
- A crash leaves the rows written so far, flushed one by one.

### Summary

```powershell
.\scripts\summarise-offset.ps1 .\out\*.csv -DropSeconds 600 -Primary <REF_A_IP>
.\scripts\summarise-offset.ps1 .\out\*.csv -DropSeconds 600 -Part washout   # the appendix
```

Tables:

1. Blocks: one row per contender, case, reference, round and block. Samples, dropped, errors, error rate, median, p5, p95, p99, mean, max of the absolute offset in ms, delay median and p95 in ms, and the least squares slope in ppm WITHIN the block. The slope is never computed across rounds.
2. Pooled: one row per contender, case and reference. All rounds pooled. The range of per-round medians. The slope median over blocks and its difference from the free-run slope.
3. Comparison: per case, each contender against `-Baseline` (default `w32time-default`) on the primary reference. Pooled difference of medians and p99, per-round differences, same-sign count, threshold, A/A noise floor, verdict `better`, `worse` or `no meaningful difference`.
4. Agreement: per block sampled against two references. Signed median difference and `DISAGREE` above `-AgreeMs` (default 2).
5. Recovery: per event, and per contender (median, worst, not recovered count).

Statistics: the median is the interpolated median (the mean of the two middle values for an even count). Nearest rank would bias it low. p5, p95 and p99 use nearest rank. A CSV without a `round` column is read as round 0 with a warning, and per-round figures are then not meaningful.

### Tests

`powershell -NoProfile -File scripts\test-measure.ps1` runs checks with no network. It covers the parser (21 canned lines), the CSV rows, validation, refusal to overwrite, exit codes, `Invoke-Measure` against a stand-in for `w32tm` (good, shortfall, fatal, a German preamble, garbage after data), and every summary statistic against hand-computed values. This includes the two-flat-rounds case that must give 0 ppm per round. Pester 3.4.0 is the only version installed here, so plain checks are used. It passes on Windows PowerShell 5.1 and PowerShell 7.

## 7. Comparison table and the report

### Table format

One row per case and contender, from Pooled and Comparison. Rounding: milliseconds to 2 decimals below 10 and 1 decimal from 10. Percentages to 1 decimal. ppm to 1 decimal. Recovery to whole seconds.

| Case | Contender | Good samples | Error rate | Median abs ms | p99 abs ms | Max abs ms | Median delay ms | p95 delay ms | Round medians, range | Verdict vs default |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Idle | w32time-default | N | N.N % | N.NN | N.NN | N.NN | N.NN | N.NN | N.NN to N.NN | baseline |
| Idle | service | N | N.N % | N.NN | N.NN | N.NN | N.NN | N.NN | N.NN to N.NN | EXAMPLE |

EXAMPLE, NOT A RESULT. The values above are placeholders.

Further tables: recovery per contender (median, worst, not recovered), the A/A noise floor per case, the agreement table, the free-run slope and the slope difference, and the wash-out appendix.

Every row links to its CSV files. The report folder holds the CSVs, the schedule file, the reference IPs and their probe results, the Windows build, the service commit and config, and the `w32time` dumps.

### One paragraph

> On HOST (Windows BUILD), against references A and B (median delay D ms, so path bias is at most D/2 ms), over R rounds of 30 minute blocks, the service had a median absolute offset of X ms and the Windows default had Y ms in the idle case (difference Z ms, A/A noise floor F ms). Under load the figures were X2 and Y2. After a 2 s step the service recovered in S s and the Windows default in T s. The service lost in CASE by W. Error rates were E1 and E2. The free-run clock drifted at P ppm. Tuned `w32time` had X3.

EXAMPLE ONLY. The letters stand for numbers that do not exist yet.

### When the service loses

It must be reported, with numbers, in the same table and the same paragraph.

- Name the case, the contender it lost to and the size of the loss. Give median, p99 and error rate.
- Do not average a loss away across cases.
- State what was checked: run validity, reference agreement, the A/A noise floor, the wash-out check.
- Give candidate causes as hypotheses and label them unverified. Do not change the service and re-run to remove the loss. Section 8 says how a change is handled.
- A loss against `w32time-default` and a loss against `w32time-tuned` are separate findings.

## 8. Pre-registered analysis plan

This section is written before any result exists. The owner confirms the numbers and freezes them.

### Freeze step

1. The owner confirms or edits every proposal in this document.
2. Commit this file, the scripts, the schedule file (order and seed) and the service commit id.
3. Tag that commit before round 1: `git tag -a measuring-plan-v1 -m "measuring plan v1, frozen before round 1"`.
4. After that, any change is a new version (`measuring-plan-v2`). The report lists every version, what changed, the date and why. Data collected under an earlier version is reported under that version. It is not mixed in.
5. Freeze the service version and config before round 1. Tune `w32time-tuned` once, before round 1. The profile in section 3 is the whole profile.
6. No tuning of the service after seeing results and re-using the same data. A tuned service is a new version and a full new set of rounds. Report both.

### Primary comparisons

There are exactly five primary comparisons. Each is the service against `w32time-default`, on the primary reference, pooled over the 4 rounds.

| ID | Case | Primary metric |
| --- | --- | --- |
| P1 | `idle` | Median absolute offset |
| P2 | `load` | Median absolute offset |
| P3 | `vm` | Median absolute offset |
| P4 | `sleep` | Median recovery time after a wake |
| P5 | `disturb2s` | Median recovery time after the step |

Everything else is exploratory: p99, the tuned and Meinberg comparisons, drift and slope, the 50 ms disturbance, the half-load level, the long run. Exploratory results are reported and labelled as such. No p-value is computed and none is hunted. With 4 rounds, four of four rounds having the same sign has a chance of 12.5 percent under no difference. That is why the threshold and the A/A conditions below also apply. It is not a significance test.

### Minimum difference that matters (proposal, author's call)

A difference in a median offset is meaningful only when all of these hold:

1. It is at least `max(1 ms, 20 percent of the default's pooled median)`. Reason: the spike median was 4.9 ms idle, so 20 percent is about 1 ms. Below 1 ms the path bias bound (half the delay) is of the same order.
2. It is larger than the A/A noise floor of that case. That is the largest per-round gap between `w32time-default` and `w32time-default-aa`.
3. It has the same sign in all 4 rounds. If one round is lost, in all remaining rounds, and at least 3.

For a recovery time the difference is meaningful when it is at least 20 percent and at least two sampling periods.

Anything smaller is "no meaningful difference". It is neither a win nor a loss.

### Definitions

- A win in a case: the primary metric is `better` (above), AND the p99 is not worse than the default by the same threshold rule applied to p99, AND the error rate is not more than 2 percentage points above the default's. If the first holds and one of the others fails the case is "mixed". It is reported and is not a win.
- A loss in a case: the primary metric is `worse`.
- "Repeated": all 4 rounds. For P4, all wake events of all 4 rounds (12 per contender). For P5, the 4 steps.
- "Two or more cases": two or more of P1 to P5.
- The claim "beats the Windows default" needs wins in all five primary comparisons and no loss. Fewer wins limit the claim to the cases won, stated by name. This is the spec's success definition applied literally.

### What would make the owner conclude the project is NOT worth shipping (proposal)

Any one of these:

1. Against `w32time-tuned` the service is not `better` in the idle median (P1 case) and not `better` in the load median (P2 case). Then accuracy is not a reason to ship. Other reasons (safety, readable code, a status log) have to carry the project alone.
2. In the VM case the service's median is not lower than `free-run` by the threshold (run the summary with `-Baseline free-run`). The service is then not improving on no sync.
3. The service has a loss in two or more of P1 to P5.
4. The service error rate is more than 2 percentage points above the default's in any case, after the load rule in section 5.
5. In P4 or P5 the service's median recovery is more than twice the default's and more than two sampling periods slower.
6. More than one of the 4 blocks flagged `DISAGREE` in three or more cases. No claim can be made then.

The owner decides. This list only fixes the question before the answer exists.

### Proposal numbers to confirm

| Item | Proposal |
| --- | --- |
| Block length, interval, wash-out | 30 min, 10 s, 10 min |
| Rounds, balanced order | 4, Williams design |
| Reference limits | stratum 1 or 2, delay 20 ms, spread 2 ms |
| Reference agreement per block | 2 ms |
| Minimum meaningful difference | max(1 ms, 20 percent) and above the A/A noise floor |
| Sign rule | same sign in all rounds, at least 3 |
| Recovery limit | 10 ms for 3 consecutive rows |
| Error rate that matters | 2 percentage points |
| Step threshold for event detection | 100 ms |
| Gap for a wake event | 120 s |
| Load level | all cores but one |

## 9. Checklist for the person running it

Machine and system:

- [ ] Throwaway VM or a test machine for everything that stops `w32time`, installs a service or sets the clock.
- [ ] Not domain-joined. Group Policy may restart `w32time` and change its settings.
- [ ] Windows build: `(Get-CimInstance Win32_OperatingSystem).Version`.
- [ ] CPU, core count, RAM, and whether it is a VM.
- [ ] Power plan fixed: `powercfg /getactivescheme`. Same plan for every run. No sleep or hibernate during blocks that should not sleep. Time zone is irrelevant because everything is UTC.
- [ ] Antivirus and updates: no scan or Windows Update during a block. Record the policy.
- [ ] No other time tool installed. No VPN that moves the route during a block.

Network:

- [ ] Wired if possible. No Wi-Fi roaming.
- [ ] No large transfers on the link during blocks.
- [ ] UDP 123 outbound open. The sampler uses an ephemeral source port. `w32time` uses 123 (Microsoft page).
- [ ] Both reference IPs, their probe results (section 2) and their operator facts (anycast, smearing, rate limits) are recorded.

VM:

- [ ] Hypervisor time sync off, or documented. `w32tm /query /status` `Source` is not the VM provider.
- [ ] Host load and hypervisor version recorded.

Software under test:

- [ ] Service version: git commit, config file, build type, how it was installed.
- [ ] At the start of every block, save the state. All of these ran without admin on the author's machine:

```powershell
w32tm /query /status   | Out-File .\out\r1-B1-state.txt
w32tm /query /peers    | Out-File .\out\r1-B1-state.txt -Append
w32tm /dumpreg /subkey:Config     | Out-File .\out\r1-B1-state.txt -Append
w32tm /dumpreg /subkey:Parameters | Out-File .\out\r1-B1-state.txt -Append
```

- [ ] The `w32time` registry before and after each tuned change (section 3). `w32tm /query /configuration` needs admin (observed Access denied unelevated).
- [ ] The service's own view of its offset and its source list, copied at the start, middle and end of each block. The design leaves the status command and log format open (spec: "Log format and status command design"). Record whatever it prints with the time. Compare its offset with the external reference columns. They should be close.
- [ ] Wash-out recorded, and the wash-out check run (section 4).
- [ ] The service log shows no panic, no refused step and no `w32time` conflict during the block. A conflict makes the block invalid.

During a block:

- [ ] Both samplers started from an unelevated prompt, new output paths.
- [ ] Event times (load start, sleep, wake, step) noted in UTC in a text file: `(Get-Date).ToUniversalTime().ToString('o')`.
- [ ] Do not use the machine for anything else.
- [ ] After the block: run the summary, check the error rate and the agreement flag, keep the CSVs.

Invalid block (exclude and say so in the report, never because it is an outlier):

- A reference changed address or went down for more than 5 percent of samples.
- Another time tool or Group Policy changed the clock.
- The machine slept when it should not have.
- A hypervisor set the clock.
- The sampler ran with a different reference, interval or priority from the others.

## Sources and unverified items

- `w32tm /?` and `w32tm /stripchart /?` on Windows 11 build 26300: `/stripchart`, `/rdtsc`, `/packetinfo`, `/config`, `/dumpreg`, `/query`, `/monitor`.
- [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings): `/stripchart` and `/rdtsc` columns, the registry settings and defaults, the 0x1 and 0x8 `NtpServer` flags, UDP 123.
- Observed by running read-only commands on the author's machine: the `/rdtsc` row format, the `error: 0x800705B4` timeout form, the plain `HH:MM:SS, error: 0x...` form, the `/packetinfo` and `/monitor` output, `w32tm /dumpreg`, `/query /status`, `/query /peers` and `reg export` without admin, `w32tm /query /configuration` denied without admin.
- Offset sign: verified by the reviewer with a raw NTP exchange.

Unverified:

- That the tuned profile improves sync. The study tests it.
- The meaning of a `d` suffix in stripchart output.
- Meinberg install and config steps, and hypervisor settings other than Hyper-V (the cmdlet exists, it was not run).
- That the half-delay bound applies as stated to `w32tm` offsets. It is the NTP design bound.
- Leap second smearing and rate limits for any given server.
- That `w32time-default` can converge inside a 30 minute block.
- All proposal numbers, listed at the end of section 8.
