# Changelog

All notable changes are listed here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [SemVer 2.0](https://semver.org/) as set out in `docs/releasing.md`.

## [Unreleased]

## [0.1.0-alpha.1]

First alpha. Unsigned. Not for machines that matter.

- Windows service that sets the system clock from NTP.
- Server tiers in strict order: config file, then DHCP, then the global NTP pool.
- Prefers slewing over stepping. Steps once after start and once after resume.
- Pool servers cross-check the chosen tier and can veto a step.
- Stops and disables the Windows Time service (`w32time`). Restores it on a failed start.
- Install and uninstall scripts, status command and Event Log source.
- Not yet verified on a real machine: install, service run and uninstall. First use is a throwaway VM with a snapshot (`docs/preview-vm-test.md`).
- No accuracy figure against `w32time` has been measured.

[Unreleased]: https://github.com/terryrankine/ntptimeclient-winrs/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/terryrankine/ntptimeclient-winrs/releases/tag/v0.1.0-alpha.1
