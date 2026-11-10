# ntptimeclient-winrs

Plan: `docs/superpowers/plans/2026-11-10-ntptimeclient-winrs.md`
Design: `docs/superpowers/specs/2026-11-10-ntptimeclient-winrs-design.md`

## Status
- [x] Design doc written and builder-checked
- [x] Plan written, reviewed by five egm reviewers, rewritten
- [ ] Terry reviews plan and picks execution method

## Tasks
- [ ] 1 Spike on ntp-proto and w32time baseline (re-plan gate)
- [ ] 2 Repo, workspace (3 crates), architecture note, CI
- [ ] 3 Core types and ports
- [ ] 4 Source filter and selection
- [ ] 5 Tier chooser with probing
- [ ] 6 Clock discipline
- [ ] 7 Engine with feedback
- [ ] 8 Simulation scenarios
- [ ] 9 Protocol adapter
- [ ] 10 Config, resolver, drift store
- [ ] 11 Windows clock adapter
- [ ] 12 w32time takeover, monitor, domain detection
- [ ] 13 DHCP source reader (IPv4)
- [ ] 14 Service host, wiring, hardening
- [ ] 15 Developer preview packaging
- [ ] 16 Measurement procedure

## Open for Terry
- Single-source tier: add an observe-only pool cross-check, or accept the gap?
- Confirm creating the private GitHub repo (Task 2 step 9).
- Code signing: SignPath Foundation after a public release, or own certificate.
- Vendor zone request to the NTP pool project before the first public release.
