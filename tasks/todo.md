# ntptimeclient-winrs

Record of rulings and progress: `.superpowers/sdd/2026-11-10-ntptimeclient-winrs/progress.md`

## Status
- Tasks 1 to 16 are built and reviewed on branch feat/initial-build.
- Nothing has been run on a real machine.

## Not done
- Measurement runs (task 16 procedure).
- Fuzz run.
- VM runs (`docs/preview-vm-test.md`).
- Code signing.
- Vendor zone request to the NTP pool project.
- The owner's open decisions:
  - Default of `allow_panic_step` (false means a clock over 1000 s wrong is never corrected).
  - Single-server config or DHCP tier: the pool cross-check vetoes steps only.
  - Code signing route.
