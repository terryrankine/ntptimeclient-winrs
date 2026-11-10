# Measuring plan: pre-registered analysis

This file is the plan. It is written before any result exists. It says what counts as better, how big a difference has to be, what would stop the project, and how results are reported. The procedure for collecting data is in [measuring.md](measuring.md).

The numbers marked "proposal" are the author's calls. The owner confirms or edits them and then freezes this file (section 8).

## 1. What may and may not be claimed

A measurement is the offset to a reference seen through a network path. It is not true UTC error.

May claim:

- On this host, this Windows build, these references and these rounds, the service had a median absolute offset of A ms and the Windows default had B ms, in the named case.
- The same host, references and path were used for every contender, so a constant path bias applies to all. The difference between contenders is meaningful where the absolute offset is not.
- The service did or did not recover from a wake or a 2 s step, and how fast.
- The error rate of each contender.

May NOT claim:

- "Accurate to within X ms of UTC".
- "Better than Windows in general". Only the measured host, network, references and cases are covered.
- "Better than Meinberg" unless Meinberg ran the same way.
- Anything about domain-joined machines, other networks, battery use or other Windows builds that were not measured.
- A drift figure for a disciplined clock. Only the free-run control has one. For any other contender the slope is a residual trend.
- Any number from a block flagged or invalid under the procedure.

## 2. The five primary comparisons

There are exactly five. Each is the service against `w32time-default`, on the primary reference, pooled over the rounds. The summary prints one verdict line for each, with the reason in words.

| ID | Case | Primary metric |
| --- | --- | --- |
| P1 | `idle` | Median absolute offset |
| P2 | `load` | Median absolute offset |
| P3 | `vm` | Median absolute offset |
| P4 | `sleep` | Median recovery time after a wake |
| P5 | `disturb2s` | Median recovery time after the 2 s step |

Only these five lines are primary. Everything else the summary prints is exploratory. That includes p99 as a result in its own right, the tuned and Meinberg comparisons, the free-run comparison, the drift and slope figures, the 50 ms disturbance, the half-load level, the long run and every table below the five lines. Exploratory results are reported and labelled. They do not decide anything.

No p-value is computed and none is hunted. With 4 rounds, the chance that four of four rounds show the same sign under no difference is 12.5 percent. That is why the other conditions below also apply. It is not a significance test.

## 3. One verdict structure for all five

The same function produces every verdict. A verdict needs all of these, in this order:

1. The baseline `w32time-default` has data for the case. If not, the line reads `(baseline missing)` with an explanation.
2. The service has data. If not, `no data`.
3. The A/A twin `w32time-default-aa` has data. If not, the line reads `no noise floor, cannot call`. No verdict is given, however large the difference.
4. For P4 and P5 only: the unrecovered-event rule. An unrecovered event counts as infinity in every median and is never dropped. The service has a loss, and the verdict is `worse`, when its unrecovered count minus the baseline's unrecovered count is larger than the A/A pair's own difference in unrecovered counts (the noise floor for this rule). Example: baseline 1, twin 0, service 2 gives an excess of 1 and a noise of 1, so no loss on this rule.
5. At least 3 rounds are common to the service and the baseline. If not, `not enough rounds`.
6. The difference is meaningful (section 4).
7. The error rate is judged for ties and wins alike. When the service's error rate is higher than the baseline's by more than the limit in section 4, the verdict is `mixed`: for a better median ("Median is better but the error rate is higher") and for a tie ("No meaningful difference in the median, but the error rate is higher"). A meaningful `worse` stays `worse`, and the error rates are printed in its reason.
8. For a better median: the p99 condition (P1 to P3) must also hold. If not, the verdict is `mixed`, not `better`.

The error rates of both contenders are printed in the reason of every verdict.

Verdicts: `better`, `worse`, `mixed`, `no meaningful difference`, `no noise floor, cannot call`, `not enough rounds`, `no data`, `(baseline missing)`.

### Flagged blocks and exclusion

Per block, the summary compares the two references: the signed medians over the block must differ by 2 ms or less (proposal). A block is flagged when:

- the references disagree by more than 2 ms (`DISAGREE`),
- it has no second reference while other blocks in the data have two (`no second reference`),
- a reference has no good rows in it (`no data from a reference`),
- its label ends in `-unclean` (the clock was not synced at the start, procedure section 6),
- a sleep or disturbance block holds a different number of events from the expected number (`event count`, section 3a),
- the reference shows more than 5 percent errors in the baseline or the A/A blocks of that case and round (`reference errors`). That is attributed to the reference or the host and not to a contender, or
- it is listed in the exclusion file passed with `-ExcludeBlocks` (`excluded by file`). Invalid blocks are excluded this way, with a reason, and never by deleting CSV files.

A flagged block removes its whole case and round for EVERY contender, so the pairs stay balanced. The count of flagged blocks, the excluded rounds and the list of block ids are printed at the top of the output. `-IncludeFlagged` prints the tables with them included, as the appendix view. Nothing is excluded silently. If data has only one reference everywhere, agreement is not checked and nothing is flagged for that.

If exclusion leaves a case with fewer than 3 rounds, step 5 above gives `not enough rounds` for that case.

### 3a. Expected events per block

| Case | Events per block, per reference | Over 4 rounds, per contender | Detector |
| --- | --- | --- | --- |
| `sleep` | 3 wakes | 12 | gap in the sample times. Event time is the first good row after the gap |
| `disturb2s` | 1 step | 4 | first good row above 100 ms after a good row at or below 10 ms |

Only the detector for the case type runs: gaps for `sleep`, steps for `disturb2s`. Each event has its own window that ends at the next event or the end of the block. A recovery counts only when it is seen inside that window. The summary prints `events expected N found M` for every block.

## 4. Thresholds (proposals, the summary defaults)

| Item | Value | Summary parameter |
| --- | --- | --- |
| Minimum difference, offset metric | the larger of 1 ms and 20 percent of the default's pooled median | `-MinAbsMs 1 -MinRel 0.2` |
| Minimum difference, recovery metric | the larger of 20 percent and 2 sampling periods | `-MinRel 0.2 -RecoveryMinPeriods 2` |
| Noise floor | the largest per-round gap between `w32time-default` and `w32time-default-aa`. The difference must exceed it | A/A twin |
| Same sign across rounds | all common rounds, and at least 3 | `-MinRounds 3` (`-MinSignRounds` to relax) |
| p99 condition | the service p99 may not exceed the default p99 by more than the larger of 1 ms and 20 percent of the default p99 | `-MinAbsMs -MinRel` |
| Error-rate limit | the larger of 2 percentage points and the A/A twin's own error-rate gap with the default. The service error rate may not exceed the default's by more than this. For `load`, compare the rise from idle with the default's rise. Applies to ties and wins | `-ErrPp 2` |
| Unrecovered-event limit | the A/A pair's own difference in unrecovered counts | A/A twin |
| Expected events | 3 per sleep block, 1 per disturbance block | `-ExpectedSleepEvents 3 -ExpectedDisturbEvents 1` |
| Reference errors | more than 5 percent in the baseline or A/A blocks | `-RefErrPct 5` |
| Reference agreement | 2 ms per block | `-AgreeMs 2` |
| Recovery limit | 3 consecutive good rows below 10 ms | `-LimitMs 10 -Consecutive 3` |
| Step detector | first good row above 100 ms after a good row at or below the limit | `-StepMs 100` |
| Wake detector | a gap of more than 120 s between rows | `-GapSeconds 120` |

Reasons. The spike median was 4.9 ms idle, so 20 percent is about 1 ms. Below 1 ms the path bias bound (half the delay) is of the same order. The noise floor stops a difference that the same contender shows against itself from counting. Requiring all rounds to agree in sign keeps one lucky round from deciding.

Anything smaller than the threshold is `no meaningful difference`. It is neither a win nor a loss.

## 5. Definitions

- Win in a case: the verdict is `better`. That already includes the p99 and error-rate conditions.
- Mixed: the median is better and the p99 or the error rate objects, or the median is a tie and the error rate objects. Reported. Not a win.
- Loss: the verdict is `worse`. For P4 and P5 an unrecovered event is a loss when the excess over the baseline is larger than the A/A pair's own difference (section 3, step 4).
- Repeated: all rounds. For P4, every wake event of every round (3 per block, 12 per contender). For P5, the step of each round.
- Two or more cases: two or more of P1 to P5.
- Recovery medians: a median with infinity is finite only when more than half of the events recovered (3 of 4, 2 of 3, 1 of 1). Otherwise it prints `not recovered`. The summary prints events, recovered, not recovered, the fraction recovered, the median and the worst.
- The claim "beats the Windows default" needs wins in all five primary comparisons and no loss. This is the spec's success definition applied literally. Fewer wins limit the claim to the cases won, by name.

## 6. Stop rules

Stop rules use P1 to P5 and data quality only. Exploratory comparisons against `w32time-tuned`, `free-run` or Meinberg are reported. They do not decide.

The owner concludes the project is NOT worth shipping on accuracy grounds if any one of these holds (proposal):

1. The service has a loss in two or more of P1 to P5.
2. The service has no win in any of P1 to P5.
3. The error-rate limit fails for the service in any of P1 to P5, for a win or for a tie. That shows as `mixed` with an error-rate reason.

Other reasons (safety, readable code, a status log) may still carry the project. The owner decides. These rules only fix the question before the answer exists.

Data-quality rules. These make a result inconclusive. They do not count against the service:

- Q1. `no noise floor, cannot call`, `not enough rounds` or `no data` in two or more of P1 to P5. Fix the data and repeat. No claim is made.
- Q2. Per case, more than 1 of the 4 rounds excluded by flagged blocks. That case is `not enough rounds`.
- Q3. A failed wash-out check (procedure section 5) in the primary contenders. Report it. A longer wash-out is a new plan version.

## 7. Table format and reporting

One row per case and contender, from the summary's Pooled and Comparison tables. Rounding: milliseconds to 2 decimals below 10 and 1 decimal from 10. Percentages to 1 decimal. Recovery to whole seconds.

| Case | Contender | Good samples | Error rate | Median abs ms | p99 abs ms | Max abs ms | Median delay ms | p95 delay ms | Round medians, range | Verdict vs default |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Idle | w32time-default | N | N.N % | N.NN | N.NN | N.NN | N.NN | N.NN | N.NN to N.NN | baseline |
| Idle | service | N | N.N % | N.NN | N.NN | N.NN | N.NN | N.NN | N.NN to N.NN | EXAMPLE |

EXAMPLE, NOT A RESULT. The values above are placeholders.

Further tables: the five primary lines as printed, recovery per contender (events, recovered, not recovered, median, worst), the A/A noise floor per case, the flagged blocks and excluded rounds, the free-run slope and slope difference, and the wash-out appendix.

Every row links to its CSV files. The report folder holds the CSVs, the schedule file, the reference IPs and probe results, the Windows build, the service commit and config, the `w32time` dumps and the exact summary command lines.

One paragraph:

> On HOST (Windows BUILD), against references A and B (median delay D ms, so path bias is at most D/2 ms), over R rounds of 30 minute blocks, the service had a median absolute offset of X ms and the Windows default had Y ms in the idle case (difference Z ms, A/A noise floor F ms). Under load the figures were X2 and Y2. After a 2 s step the service recovered in S s and the Windows default in T s. The service lost in CASE by W. Error rates were E1 and E2. The free-run clock drifted at P ppm.

EXAMPLE ONLY. The letters stand for numbers that do not exist yet.

### When the service loses

It must be reported, with numbers, in the same table and the same paragraph.

- Name the case, the contender it lost to and the size of the loss. Give median, p99, error rate and unrecovered events.
- Do not average a loss away across cases.
- State what was checked: block validity, flagged blocks, the noise floor, the wash-out check.
- Give candidate causes as hypotheses and label them unverified. Do not change the service and re-run to remove the loss. Section 8 says how a change is handled.
- A loss against `w32time-default` and a loss against `w32time-tuned` are separate findings. Only the first is primary.

## 8. Freeze rule

1. The owner confirms or edits every proposal in this file and in the summary defaults.
2. Commit this file. The tag marks the commit that holds this plan file and covers the plan file only: `git tag -a measuring-plan-v1 -m "measuring plan v1, frozen before round 1"`.
3. The tag must exist before round 1. Do not create it before the owner has confirmed the numbers.
4. After the tag, any change to this file is a new version (`measuring-plan-v2`). The report lists every version, what changed, the date and why. Data collected under an earlier version is reported under that version and is not mixed in.
5. The procedure, the scripts and the service are not covered by the tag. The report records the commit ids of the scripts and of the service used. Any change to either after round 1 is listed in the report.
6. Freeze the service version and config before round 1. Tune `w32time-tuned` once, before round 1. The profile in the procedure is the whole profile.
7. Do not tune the service after seeing results and re-use the same data. A tuned service is a new version and a full new set of rounds. Report both.
8. Exclude a block only for a reason the procedure lists as invalid, or a flag in section 3. Never because it is an outlier. List every exclusion.

## 9. Summary command lines

The five verdict lines are made with this command line. It carries every threshold and the wash-out explicitly, so a reader sees the registered values without opening the script. The test suite checks that each value equals the script default. The one deliberate difference is `-DropSeconds`: the script default is 0, so that a bare run drops nothing, and the registered wash-out of 600 s is stated here.

```powershell
.\scripts\summarise-offset.ps1 .\out\*.csv -Primary <REF_A_IP> -Baseline w32time-default -Contender service `
    -DropSeconds 600 -MinAbsMs 1 -MinRel 0.2 -MinRounds 3 -ErrPp 2 -AgreeMs 2 -RefErrPct 5 `
    -LimitMs 10 -Consecutive 3 -StepMs 100 -GapSeconds 120 -RecoveryMinPeriods 2 `
    -ExpectedSleepEvents 3 -ExpectedDisturbEvents 1
```

Exploratory runs change `-Baseline` or `-Contender`, for example `-Baseline w32time-tuned`, and are reported as exploratory. Use `-IncludeFlagged` for the appendix view, `-Part washout` for the wash-out appendix and `-ExcludeBlocks` for the recorded exclusion file. The wash-out is applied only to `idle`, `load` and `vm`. Event cases and the long run keep every row.
