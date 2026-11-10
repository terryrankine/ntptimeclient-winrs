# Measuring ntptimeclient-winrs against Windows time: procedure

This file says how to run the measurement. The rules for judging it are in [measuring-plan.md](measuring-plan.md). The plan is frozen before round 1. This procedure is not part of the freeze, but every change to it is recorded in the report.

Status: no results exist yet. Every number marked "proposal" is the author's call and the owner confirms it in the plan.

## 1. Purpose

The spec says success is measured, not promised. Success means the service beats the Windows default in each case and never makes the clock worse.

An earlier spike ran `w32tm /stripchart` once idle and once under load against two different pool servers. One run against a random pool server cannot tell clock error from path error. The load figure, with 28 of 120 samples failing, may also be partly a sampler artefact. Nobody has yet compared a tuned `w32time`, Meinberg NTP and the service against independent references on one host over a long run. This procedure does that.

### What a measurement is

- The sampler reads the offset between this computer's clock and a reference server, as seen through the network path, with `w32tm /stripchart`. The columns are described in [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings) (`/stripchart` and `/rdtsc`).
- It is not true UTC error. The reference has its own error. The path adds a bias if the outbound and return delays differ. NTP bounds that bias at half the round trip delay. This is the NTP design bound. The Microsoft page does not state it. The sampler records the delay.
- Sign: a POSITIVE offset means the reference is AHEAD, so the local clock is SLOW. This was verified independently with a raw NTP exchange. The offset formula (server transmit time minus local receive time, with the usual round trip correction) gave the same sign as `w32tm /stripchart`. A positive slope of the offset over time means the local clock is losing time relative to the reference.
- `w32tm /stripchart` does not set the clock. The Microsoft page describes it as an offset display using an ephemeral source port. Smoke tests of a few samples showed no step. That is not proof that nothing is touched.
- The `w32tm` switches used here are listed by `w32tm /?`. They were checked by running the commands. `w32tm /stripchart /?` is not a help request: it fails with `Required parameter 'computer' missing`.

What may and may not be claimed from the results is in the plan, section 1.

## 2. Safety

This is a measurement on a real Windows machine. Follow these rules.

- The sampler, the summary, `wait-synced.ps1` and every `w32tm /query`, `/dumpreg`, `/monitor` and `/stripchart` command are read only. They need no admin and change no state.
- Four scripts can change the machine: `apply-tuned-profile.ps1`, `disturb-clock.ps1`, `restore-clock.ps1` and `w32time-state.ps1 -Restore`. Each refuses unless ALL of these hold, in this order:
  1. The environment variable `MEASURE_TEST_MACHINE` is `1`. Set it only on a throwaway VM or a test machine, and only in that session.
  2. A second test-machine signal holds. It is read only. It is true when `Win32_ComputerSystem` reports a model or manufacturer that looks virtual (Virtual, VMware, KVM, QEMU, Hyper-V, Xen, innotek, Parallels, Red Hat), or when `MEASURE_I_AM_ON_A_TEST_MACHINE` is `1`. This is a heuristic. It is not proof. The `HypervisorPresent` property is not used, because it is also true on a physical host that runs virtualisation based security. Use the second variable on a physical test box.
  3. The session is elevated.
  Each supports `-WhatIf`. `disturb-clock.ps1` is capped at 2000 ms and refuses a larger value.
- Anything that stops `w32time`, installs a service, sets the clock or changes the registry needs a throwaway VM or a test machine. Never run it on a machine that matters.
- Do not run the load generator, a sleep test or a long run on a machine that must stay in use.

## 3. Reference choice

The owner chooses the references and records the choice. This document does not pick one. Any address in an example is a placeholder.

Rules:

1. A reference must not be a source that any contender uses.
2. Use TWO references from different operators, sampled at the same time in every block (section 5). One is the primary reference. The other is the check.
3. Never use a pool name. It resolves to a different server on each run. The sampler refuses `pool.ntp.org` names unless `-AllowPool` is given.
4. Pass the sampler an IP address. An anycast address is one address served by many machines. Pinning the IP does not pin the server or the path over 24 hours.

Best option: a server on the owner's LAN disciplined by GPS. It has low and steady delay, no rate limit and no anycast. Second best: a national laboratory or ISP stratum 1 source near the owner, if the owner knows one. The owner must verify that it exists, is open to the public and what its policy is. Do not rely on a public name from memory.

### Measuring a candidate (read only)

```powershell
w32tm /stripchart /computer:<REF_IP> /samples:1 /packetinfo /dataonly
w32tm /monitor /computers:<REF_IP> /nowarn
w32tm /stripchart /computer:<REF_IP> /samples:30 /period:2 /dataonly /rdtsc
```

The first prints `Stratum`, `Root Delay`, `Root Dispersion` and `ReferenceId`. The second prints an ICMP delay, the NTP offset, `RefID` and `Stratum`. It also sends ICMP. The third gives 30 delay samples. All three ran against a public candidate while this was written. That candidate showed stratum 3, so the stratum rule below does reject some well known public servers.

| Check | Accept when (proposal) | How |
| --- | --- | --- |
| Stratum | 1 or 2 | `/packetinfo` |
| Median round trip delay | 20 ms or less for a public server. A LAN server is far lower | `RoundtripDelay` column |
| Delay spread (p95 minus p5) | 2 ms or less | the 30 samples |
| Error rate | 0 of 30 | the 30 samples |
| Anycast | Known and recorded. Prefer unicast | Operator documentation. Repeat the probe hours apart. A changed `ReferenceId` or a jump in delay suggests another machine |
| Leap second smearing | Known and recorded | Operator documentation. The owner must verify. UNVERIFIED here |
| Rate limits | Policy read. The interval and two samplers fit inside it | Operator policy. Fast polling may be rate limited or get Kiss-of-Death. That shows as error rows |
| Independence | Different operator from the contenders' sources and from the other reference | Operator documentation |

The agreement rule between the two references is applied per block by the summary (plan, section 3).

## 4. Contenders

| Label | What it is | Changes state | Admin |
| --- | --- | --- | --- |
| `w32time-default` | `w32time` as shipped | No | No for the sampler |
| `w32time-default-aa` | Same as the default, second set of blocks. The A/A control | No | No |
| `w32time-tuned` | `w32time` with the profile below | Yes | Yes |
| `meinberg` | Meinberg NTP for Windows, optional | Yes | Yes |
| `service` | ntptimeclient-winrs. `install` stops and disables `w32time` | Yes | Yes |
| `free-run` | Service and `w32time` stopped. No sync. Throwaway VM only | Yes | Yes |

### Sources

The Windows default and the service do not use the same sources. The Microsoft page gives `time.windows.com,0x1` as the stand-alone default. The service uses its tier rules and a pool expansion. So:

- Record the default's real source at the start of every block: `w32tm /query /status` and `w32tm /query /peers`. Both run without admin. Record the service's own source list from its status output.
- Decide, and write down in the plan before round 1, whether the difference in sources is intended. It is intended when the question is which shipped behaviour is better. It is not when the question is which client algorithm is better.
- For the algorithm question, `w32time-tuned`, `meinberg` and `service` use the SAME manual peer list, as IP addresses. Give `w32time-default` the same list too if the owner wants a pure comparison, and say so, because that is no longer the default as shipped.
- If the owner wants the shipped behaviour as well, report both variants as separate result sets.

### Tuned `w32time` profile

WARNING. This changes the machine. Test machine only. Microsoft marks these registry values as ones not to change. Source for each: [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings) (the registry reference tables). The values are the author's choice for tight sync. That they give better sync is UNVERIFIED. The study tests it.

| Setting | Value | Documented meaning | Page default (stand-alone) |
| --- | --- | --- | --- |
| `NtpServer` flags | `,0x8` per peer | 0x8 is Client. 0x1 is SpecialInterval | `time.windows.com,0x1` |
| `Config\MinPollInterval` | 6 (64 s) | Log base 2 seconds | 10 |
| `Config\MaxPollInterval` | 6 (64 s) | Log base 2 seconds | 15 |
| `Config\UpdateInterval` | 100 | Phase correction interval, 10 ms units, so 1 s | 360000 |
| `Config\PhaseCorrectRate` | 1 | Smaller corrects phase faster, may be unstable | 7 |
| `Config\FrequencyCorrectRate` | 2 | Smaller corrects faster, may overcorrect | 4 |

Values on a real machine can differ from the page defaults. Read them first (`w32tm /dumpreg /subkey:Config`, no admin needed).

Apply and undo with the guarded script. Apply saves the current values, and the ones that were absent, to a JSON file. It writes a temp file, moves it into place, reads it back and compares it before the first registry change, and it refuses to overwrite an existing file. If any later step fails, the script restores from that file by itself and exits 1. Undo restores recorded values and removes those that were absent, including `NtpServer` or `Type` when they were absent. `reg import` cannot do that, because it does not remove a value that was absent before.

```powershell
reg export HKLM\SYSTEM\CurrentControlSet\Services\W32Time .\out\w32time-before.reg /y
$env:MEASURE_TEST_MACHINE = '1'
.\scripts\apply-tuned-profile.ps1 -Peers <IP1>,<IP2>,<IP3> -BeforeFile .\out\w32time-before.json -WhatIf
.\scripts\apply-tuned-profile.ps1 -Peers <IP1>,<IP2>,<IP3> -BeforeFile .\out\w32time-before.json
.\scripts\apply-tuned-profile.ps1 -Undo -BeforeFile .\out\w32time-before.json
```

After the undo, compare `w32tm /dumpreg /subkey:Config` and `/subkey:Parameters` with the "before" dumps.

### The w32time start type

Installing the service stops and disables `w32time`. The Meinberg installer stops it. Record the start type and the trigger info BEFORE the first contender that touches it, and restore them after each contender that stops or disables it. Never restore a guessed default: the start type may be delayed automatic, and `w32time` has service triggers.

Record (read only, no admin). It writes a JSON record and a `reg export` of the W32Time key:

```powershell
sc.exe qc w32time
sc.exe qtriggerinfo w32time
.\scripts\w32time-state.ps1 -Record -File .\out\w32time-service-state.json
```

Both `sc.exe` queries ran without admin. The record holds the registry `Start` and `DelayedAutostart` values, the `sc.exe` keyword derived from them (`boot`, `system`, `auto`, `delayed-auto`, `demand` or `disabled`), whether the service was running, and the text of both queries.

Restore (guarded, test machine only). It sets the recorded start type with `sc.exe config`, reads it back and compares the trigger info. A difference in the trigger info is an error and is never guessed. The fix is then `reg import` of the saved `.reg` file and a reboot. `-StartIfWasRunning` starts the service again when it was running.

```powershell
$env:MEASURE_TEST_MACHINE = '1'
.\scripts\w32time-state.ps1 -Restore -File .\out\w32time-service-state.json -WhatIf
.\scripts\w32time-state.ps1 -Restore -File .\out\w32time-service-state.json -StartIfWasRunning
```

### Meinberg NTP (optional)

Install it only on the test machine. Its installer stops `w32time`. Point it at the same IPs as the other contenders. Record its version and config file. Exact install and config steps are not given here because they were not checked.

## 5. Design: alternating blocks on one host

Sequential multi-hour runs per contender cannot separate a contender effect from time of day and network load. This design interleaves short blocks of every contender on one host.

- A block is 30 minutes of one contender in one case (45 minutes for sleep). A round is one block of every contender in a balanced order. Each case has 4 rounds (proposal).
- Each block is sampled against TWO references at the same time, by two sampler processes. They write the same `round` and `block` labels to different CSV files.
- The A/A control is two blocks of the same contender in the balanced order: `w32time-default` and `w32time-default-aa`.
- `free-run` is a fixed extra block at the end of every round, VM only. It is a control and not part of the balanced order. This is a known imbalance. The first block of the next round follows a free-run block, so its wash-out must also clear that state. Report free-run results as a control only.

### Balanced order

With A = `w32time-default`, B = `w32time-default-aa`, C = `w32time-tuned`, D = `service`, use a Williams design. Each contender takes each position once and follows each other contender once, so first-order carry-over is balanced. Checked by listing the twelve ordered neighbour pairs.

| Round | Slot 1 | Slot 2 | Slot 3 | Slot 4 |
| --- | --- | --- | --- | --- |
| 1 | A | B | D | C |
| 2 | B | C | A | D |
| 3 | C | D | B | A |
| 4 | D | A | C | B |

With Meinberg there are five contenders. Two options:

- A seeded random order per round, recorded as a schedule file committed before round 1. NO balance claim is made for it. The order is fixed and auditable and nothing more. `Get-Random -SetSeed` may differ between Windows PowerShell and PowerShell 7, so record the resulting order and not only the seed.
- A Williams design for an odd number of contenders needs twice as many rounds: 10 rounds of 5 blocks. A 30 minute case then takes 25 hours instead of 10. That is 15 extra hours per case.

Block labels are `B1` to `B4` for the slot. Switch contenders by hand or with an administrator script, and record the switch time.

### Wash-out

A wash-out is the part of a block dropped from the primary analysis because the contender is still settling. For a disciplined clock it must achieve two things: the previous contender's state is gone, and the new contender is inside its normal band with no trend.

Proposal: the first 10 minutes of each 30 minute block, applied by the summary with `-DropSeconds 600` to the `idle`, `load` and `vm` cases. The rows stay in the CSV. `-Part washout` prints them as an appendix. The event cases (`sleep`, `disturb2s`) and the `long` case keep every row. Recovery is measured on all rows.

Check it from the data, per contender: compare the median of the dropped part with the primary part, and compare the first and second half of the primary part. A difference above the A/A noise floor means the wash-out was too short. `w32time-default` polls slowly and may not converge in one block. If the check fails, report that finding. Do not lengthen the wash-out for the default only. A longer wash-out is a new plan version and a new set of rounds.

### Machine time (author's estimate, not measured)

| Case | Blocks per round | Length | Rounds | Hours |
| --- | --- | --- | --- | --- |
| Idle | 4 | 30 min | 4 | 8 |
| CPU load | 4 | 30 min | 4 | 8 |
| Disturbed clock (VM) | 4 | 30 min | 4 | 8 |
| Sleep and resume | 4 | 45 min | 4 | 12 |
| VM idle, with `free-run` | 5 | 30 min | 4 | 10 |
| Long run, 24 h each for default, service, free-run | 3 | 24 h | 1 | 72 |
| Switching and checks, about 10 minutes for each of 84 blocks | | | | 14 |
| Meinberg as a fifth contender (optional): one more block per round in every case, about 0.5 h x 4 rounds for idle, load, disturbance and VM, 0.75 h x 4 for sleep, plus a 24 h long run | | | | about 35 (4 rounds, seeded order) |
| Meinberg with a Williams design: 10 rounds of 5 blocks instead of 4 | | | | about 15 more per 30 minute case |
| Total | | | | about 132 |

That is about 5.5 days. The minimum useful set is idle, load, disturbed clock and the long run for default, service and free-run.

## 6. Cases and sample counts

Case labels are fixed: `idle`, `load`, `vm`, `sleep`, `disturb2s`, `long`. The plan's five primary comparisons use the first five.

The sampler `-Samples` for each case is in this table. The rule is `samples x period = awake block seconds`. Check it against the schedule file for every block before starting.

| Case | Block | Period | `-Samples` | Derivation |
| --- | --- | --- | --- | --- |
| `idle` | 30 min | 10 s | 180 | 1800 s / 10 s |
| `load` | 30 min | 10 s | 180 | 1800 s / 10 s |
| `vm` | 30 min | 10 s | 180 | 1800 s / 10 s |
| `sleep` | 45 min: 3 x (5 min awake + 10 min asleep) | 5 s | 180 | Awake time only: 3 x 300 s = 900 s, 900 s / 5 s. The process does not sample while the machine sleeps |
| `disturb2s`, LAN reference | 30 min | 1 s | 1800 | 1800 s / 1 s |
| `disturb2s`, public reference | 30 min | 8 s | 225 | 1800 s / 8 s |
| `long` | 24 h | 30 s | 2880 | 86400 s / 30 s |

A sample count that is too high makes the sampler run into the next block under the old label. A count that is too low leaves the end of the block unsampled.

Sample size, honestly: 4 rounds of 120 primary samples is 480 per contender per case. Samples from a disciplined clock are autocorrelated, so the effective number of independent samples is far lower. A p99 from 480 autocorrelated samples rests on a handful of tail samples. Treat p99 as indicative.

### Idle

Nothing else running. Sleep disabled. Record the CSVs, the state files (section 8) and the service status output at the start, middle and end of each block.

### CPU load

Load inflates local scheduling delay, so the sampler's own timestamps and delay column are measured on a loaded machine. The spike's load run with 28 of 120 failures may be partly this effect. So:

- The sampler raises its own process and its `w32tm` child to AboveNormal priority. It touches no other process. A failure to do so is a warning.
- Leave at least one core free. The primary level is all logical cores but one.
- The summary reports delay median and p95 per case.
- Before blaming a contender for a higher error rate under load, compare with no load. The verdict function does this: it compares each contender's rise from idle to load with the default's rise. Only the excess above 2 percentage points counts (plan, section 4).

Test machine guard: the generator refuses to start unless the test machine flag is set. The jobs end themselves 30 minutes after the block would end, as a safety margin. Stop them by hand at the end of the block.

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
Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 5 -MaxSamples 3   # read only
$jobs | Stop-Job    # at the end of the block
$jobs | Remove-Job
```

### Sleep and resume

- Sleep by hand from the Start menu. Do not script hibernation.
- The order inside a block is fixed. The sampler starts and takes ONE sample while awake. Then three times: sleep for 10 minutes, wake, stay awake for 5 minutes. That gives 3 wakes per block, so 12 wake events per contender over 4 rounds.
- The sample count is 180: 1 sample before the first sleep, then 179 across the three awake segments. The last awake segment ends about 5 s short of 5 minutes, and the block ends when the 180th sample is taken.
- Start both samplers once per block. They continue after resume. A gap in `utc_iso` marks each sleep.
- The summary finds each wake: the first row after a gap longer than 120 s. A network that is not up yet often gives an error row first, so the event time is the first GOOD row after the gap. Recovery time is from that row to the first row that starts 3 consecutive good rows below 10 ms. An error row breaks the run. No hand-typed wake time is used.
- Each wake has its own window. It ends at the next gap or at the end of the block. A recovery is credited only when it is seen inside its own window. A wake that does not recover inside its 5 minutes is unrecovered, and a later wake cannot rescue it. A wake with no good row at all before the next gap is unrecovered.
- Only the gap detector runs on sleep cases. The step detector does not.
- A sleep block must hold 3 wake events on each reference. The summary prints `events expected 3 found N` for every block and flags a block with another count. The flagged round is excluded and the line is printed, never dropped silently.

### Virtual machine

- Hypervisor time sync must be off, or documented. The spec asks for measurement on a VM with it off.
- Hyper-V host: `Get-VMIntegrationService -VMName NAME` shows the state (the cmdlet exists here). To switch it off, on the host as administrator: `Disable-VMIntegrationService -VMName NAME -Name 'Time Synchronization'`. Not run here because there was no VM.
- Other hypervisors: look up the vendor setting. UNVERIFIED.
- In the guest, `Source: VM IC Time Synchronization Provider` in `w32tm /query /status` means the hypervisor still sets the clock. The block is invalid.
- The `free-run` block runs only here.

### Disturbed clock (throwaway VM only)

This sets the clock wrong on purpose. A step changes timestamps, tickets and logs. Never on a machine that matters.

1. Block of 30 minutes. The contender runs 10 minutes first. Samples: see the table. Public servers may rate limit or send Kiss-of-Death to polls every second, and that shows as error rows. Use a LAN reference at 1 s, or a public one at 8 s with coarser recovery resolution. UNVERIFIED for any given server.
2. At minute 10 disturb the clock by 2 s with the guarded script. Note the printed UTC time.

```powershell
$env:MEASURE_TEST_MACHINE = '1'
.\scripts\disturb-clock.ps1 -Milliseconds -2000 -WhatIf
.\scripts\disturb-clock.ps1 -Milliseconds -2000
```

3. Watch for the other 20 minutes. The summary finds the step by itself: the first good row above 100 ms after a good row at or below 10 ms. Error rows in between are skipped. Recovery is measured from that row, and must be seen before the end of the block. Only the step detector runs on disturbance cases. A disturbance block must hold 1 step event on each reference. A block with no step seen (the contender corrected before the next sample) is flagged as `event count`, and its round is excluded and listed. Sample timestamps come from the clock under test, so a second step by the contender moves them by up to the step size.
4. A 2 s error is above the service step threshold of 128 ms (spec). `w32time` steps above its `MaxAllowedPhaseOffset` (the Microsoft page gives 1 s for stand-alone).
5. A 50 ms disturbance is exploratory. It tests slewing.

#### Reset after every disturbance block (mandatory)

A contender that has not recovered in the 20 minutes would leave the clock about 2 s off for the next block. After EVERY disturbance block:

1. Stop the contender, so it does not fight the reset.
2. Step the clock back to the first reference. The script reads 5 samples (read only), needs MORE than half of them to be good, takes the median offset, refuses a step above 10 s (a hard cap, not a parameter you can raise), and steps by it. A positive offset moves the clock forward.

```powershell
$env:MEASURE_TEST_MACHINE = '1'
.\scripts\restore-clock.ps1 -Reference <REF_A_IP> -WhatIf
.\scripts\restore-clock.ps1 -Reference <REF_A_IP>
```

3. Confirm the clock is synced again. This is read only. It needs 3 consecutive rounds with BOTH references below 10 ms, and gives up after 600 s.

```powershell
.\scripts\wait-synced.ps1 -ReferenceA <REF_A_IP> -ReferenceB <REF_B_IP>
```

Exit 0 means synced. Exit 3 means the start is not clean. The next block must then carry the suffix `-unclean` on its `-Block` label, for example `B2-unclean`. The summary flags it and excludes its round like a block whose references disagree. Start the next block only after exit 0, or after exit 3 with the label set.

### Long run

24 hours, idle, 30 s, one contender at a time, for `w32time-default`, `service` and `free-run`. Two samplers, one per reference. Only `free-run` gives a drift figure in ppm. For the other contenders the slope is a residual trend and is exploratory. The slope also includes any drift of the path to the reference.

## 7. The sampler and the summary

Files: `scripts/measure-offset.ps1`, `scripts/summarise-offset.ps1`, `scripts/wait-synced.ps1`, `scripts/offset-lib.ps1` and `scripts/w32time-lib.ps1` (shared functions), the four guarded helpers above, and `scripts/test-measure.ps1`.

### Sampler

Wraps `w32tm /stripchart /computer:<ref> /samples:N /period:S /dataonly /rdtsc`. Read only. Run both samplers of a block at the same time:

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
| `-Samples` | 1 to 1000000. See the table in section 6 |
| `-PeriodSeconds` | 1 to 3600 |
| `-OutPath` | Must not exist. Folder must exist |
| `-Plain` | Plain format instead of `/rdtsc`. No delay column. Timestamps are receipt times |

Exit codes: 0 finished, 1 run failed or every sample failed, 2 bad input. Nothing is overwritten.

CSV columns: `utc_iso, contender, case, reference, offset_s, delay_s, error, round, block`.

- The timestamp is the `FileTime` that `w32tm` prints, as UTC. It is the local clock at the request. The clock under test supplies it, so a step shows as a jump.
- A failed sample is a row with an error text and an empty offset, for example `w32tm error 0x800705B4` (timeout). Errors count toward the error rate.
- Never dropped: after the first data row, an unrecognised line becomes an `unparsed line` row. A shortfall in rows becomes `missing sample` rows. If `w32tm` exits non-zero the shortfall rows carry its message.
- Unrecognised lines before the first data row are ignored and counted. The count is printed on stderr as `preamble_lines`. The parser knows the English preamble and fatal text only. On another language those lines are ignored and counted, and the first ones are copied into the shortfall error text when no data arrives. This limitation is documented and tested.
- The parser accepts a decimal comma, a Unicode minus, a 12 hour time with PM, and the `s` suffix. The `d` suffix is read as days and flagged as an error row because its meaning is UNVERIFIED.
- The reference is resolved once per run by `w32tm`. Pass an IP.
- A crash leaves the rows written so far, flushed one by one.

### Summary

```powershell
.\scripts\summarise-offset.ps1 .\out\*.csv -DropSeconds 600 -Primary <REF_A_IP>
.\scripts\summarise-offset.ps1 .\out\*.csv -DropSeconds 600 -Part washout
.\scripts\summarise-offset.ps1 .\out\*.csv -DropSeconds 600 -Primary <REF_A_IP> -IncludeFlagged
```

It prints, in order: the flagged blocks and the excluded rounds, the five PRIMARY verdict lines, and then the exploratory tables (blocks, pooled, comparison, agreement, recovery, events per block). The `-Part washout` and `-Part all` views print `NOT PRIMARY` instead of the primary heading. The meaning of each is in the plan. Slope is not printed for event cases, because a per-block slope there is dominated by the disturbance. Medians are interpolated. p5, p95 and p99 use nearest rank. A CSV without a `round` column is read as round 0 with a warning.

Flags (each excludes the case and round for every contender, and is printed): `DISAGREE` (references differ by more than 2 ms in a block), `no second reference`, `no data from a reference`, `start not clean` (a block label ending `-unclean`), `event count` (a sleep or disturbance block with the wrong number of events), `reference errors` (the reference shows more than 5 percent errors in the baseline or A/A blocks of that case and round, which is attributed to the reference or the host and not to a contender) and `excluded by file`.

Invalid blocks are never removed by deleting CSV files. Write them in an exclusion file and pass it with `-ExcludeBlocks`. The file is a CSV with the columns `case,round,block,contender,reason`. Every entry needs a reason. The entries and reasons are printed in the output and the appendix. An entry that matches no block prints a warning.

```powershell
.\scripts\summarise-offset.ps1 .\out\*.csv -DropSeconds 600 -Primary <REF_A_IP> -ExcludeBlocks .\out\excluded-blocks.csv
```

### Tests

`powershell -NoProfile -File scripts\test-measure.ps1` runs with no network. It covers the parser, the CSV rows, validation, `Invoke-Measure` against a stand-in for `w32tm`, every summary statistic against hand-computed values, the verdict rules, the exclusion of flagged blocks, recovery with unrecovered events, `wait-synced.ps1`, the restore arithmetic, and that each dangerous helper refuses without `MEASURE_TEST_MACHINE`. Pester 3.4.0 is the only version installed here, so plain checks are used.

## 8. Checklist for the person running it

Machine, network and VM:

- [ ] Throwaway VM or a test machine for everything that stops `w32time`, installs a service or sets the clock. Not domain-joined, because Group Policy may restart `w32time`.
- [ ] Windows build (`(Get-CimInstance Win32_OperatingSystem).Version`), CPU, cores, RAM, VM or not. Host load and hypervisor version for a VM.
- [ ] Power plan fixed (`powercfg /getactivescheme`) and the same for every run. No sleep or hibernate in blocks that should not sleep. Time zone is irrelevant because everything is UTC.
- [ ] No scan or Windows Update during a block. No other time tool installed. No VPN that moves the route.
- [ ] Wired if possible, no large transfers during blocks. UDP 123 outbound open (the sampler uses an ephemeral source port, `w32time` uses 123).
- [ ] Both reference IPs, probe results and operator facts (anycast, smearing, rate limits) recorded.
- [ ] VM: hypervisor time sync off, or documented. `Source` in `w32tm /query /status` is not the VM provider.

Software under test:

- [ ] Service version: git commit, config file, build type, how it was installed.
- [ ] At the start of every block, save the state. All of these run without admin:

```powershell
w32tm /query /status   | Out-File .\out\r1-B1-state.txt
w32tm /query /peers    | Out-File .\out\r1-B1-state.txt -Append
w32tm /dumpreg /subkey:Config     | Out-File .\out\r1-B1-state.txt -Append
w32tm /dumpreg /subkey:Parameters | Out-File .\out\r1-B1-state.txt -Append
```

- [ ] The w32time start type and trigger info recorded once per machine, before the first contender that stops or disables `w32time`: `sc.exe qc w32time`, `sc.exe qtriggerinfo w32time`, `reg export HKLM\SYSTEM\CurrentControlSet\Services\W32Time .\out\w32time-before.reg /y`, and `w32time-state.ps1 -Record`. All run without admin.
- [ ] After each contender that stops or disables `w32time` (the service install, the Meinberg installer, `free-run`), restore the recorded start type with `w32time-state.ps1 -Restore` and check it with `sc.exe qc w32time`. A trigger info difference stops the run until it is fixed.
- [ ] The service's own view of its offset and source list, copied at the start, middle and end of each block. The design leaves the status command and log format open (spec). Record whatever it prints with the time and compare its offset with the external reference columns.
- [ ] Wash-out recorded and checked (section 5).
- [ ] The service log shows no panic, no refused step and no `w32time` conflict during the block. A conflict makes the block invalid.
- [ ] `-Samples` matches the table in section 6 for every block.

During a block:

- [ ] Both samplers started from an unelevated prompt with new output paths.
- [ ] Event times (load start, sleep, wake, step) noted in UTC: `(Get-Date).ToUniversalTime().ToString('o')`.
- [ ] Do not use the machine for anything else.
- [ ] After the block, run the summary, check the error rate and the flagged blocks, keep the CSVs.
- [ ] After a disturbance block, do the reset in section 6 before the next block.

Invalid block (exclude it through the exclusion file with the reason, say so in the report, never because it is an outlier and never by deleting a CSV):

- A reference changed address or was down for more than 5 percent of samples.
- Another time tool or Group Policy changed the clock.
- The machine slept when it should not have.
- A hypervisor set the clock.
- The sampler ran with a different reference, interval or priority from the others.

## Sources and unverified items

Sources: `w32tm /?` on Windows 11, checked by running each command, and [Windows Time Service Tools and Settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings). Observed by running read-only commands: the `/rdtsc` and plain row formats, the timeout form `error: 0x800705B4`, the `/packetinfo` and `/monitor` output, and that `/dumpreg`, `/query /status`, `/query /peers`, `reg export`, `sc.exe qc` and `sc.exe qtriggerinfo` run without admin. The offset sign was verified independently with a raw NTP exchange.

Unverified: that the tuned profile improves sync, the meaning of a `d` suffix, Meinberg steps, hypervisor settings other than Hyper-V, that the half-delay bound applies as stated to `w32tm` offsets, leap second smearing and rate limits for any given server, that `w32time-default` can converge inside a 30 minute block.
