# Versioning and releasing

One version. One tag. One workflow. They must agree or nothing is published.

## Version

- Scheme: [SemVer 2.0](https://semver.org/). No build metadata.
- One source: `[workspace.package] version` in `Cargo.toml`. Every crate inherits it.
- Pre-release part: `alpha.N`, `beta.N` or `rc.N` only. `N` starts at 1.
- Order: `0.1.0-alpha.1` < `0.1.0-alpha.2` < `0.1.0-beta.1` < `0.1.0-rc.1` < `0.1.0`.
- `0.x` means the interface may change in any release. `1.0.0` is a human decision. It needs signed binaries and a measured accuracy result.
- The tag is `v` plus the Cargo version. Example: `v0.1.0-alpha.1`.
- The exe logs its version at start and reports it in `status`. The zip carries it in `VERSION`.

| Channel | Example | GitHub release | Meaning |
| --- | --- | --- | --- |
| alpha | `0.1.0-alpha.1` | pre-release | Mechanics only. Throwaway VM. |
| beta | `0.1.0-beta.1` | pre-release | Install verified on real Windows. Measured against `w32time`. |
| rc | `0.1.0-rc.1` | pre-release | Signed. No known blockers. |
| stable | `0.1.0` | latest | Supported. |

A `0.x` stable tag is still marked as a pre-release.

## Pipelines

| Workflow | Runs on | Output |
| --- | --- | --- |
| `ci.yml` | push to `main`, pull requests, nightly | checks, plus a gated exe as a workflow artifact (14 days). A CI build, not a release. |
| `release.yml` | tag `vX.Y.Z[-pre.N]`, manual dry run | the zip and its hash. The tag run also makes the GitHub release. |
| `monitor.yml` | daily | pin monitor (`scripts/check-pins.ps1`) and package checker (`cargo-deny` advisories, licences, bans, sources). Changes nothing. |
| Dependabot | weekly | pull requests for action pins and Rust crates. A person merges them after `ci.yml` is green. No auto-merge. |

Checks in `ci.yml`: fmt, clippy `-D warnings`, tests, dependency rule, Pester packaging tests, minimum Rust version (1.88), `cargo-deny`, core on Linux, exe gate, version rules, workflow pin lint, nightly fuzz smoke.

`release.yml` runs the version rules first:

1. The tag equals `v` plus the Cargo version.
2. `CHANGELOG.md` has a `## [version]` heading.
3. The tag commit is on `main`.
4. Every action is pinned to a commit SHA.

It then builds with `--locked`, gates the exe, runs the packaging tests, assembles the zip, and attaches it to the release. The hash is passed from the build job and checked again before publishing.

Actions are pinned by commit SHA because a tag can be moved. Each pin ends with a `# label` comment, a tag such as `v7.0.1` or a branch such as `stable`. The pin monitor fails if a pinned commit has vanished or a tag now points elsewhere, and warns when a newer release exists. Dependabot proposes the upgrades.

## Cut a release

1. Open a branch. Set the new version in `Cargo.toml`. Run `cargo update -w` so `Cargo.lock` follows.
2. Move the `[Unreleased]` notes in `CHANGELOG.md` under a new `## [version]` heading. Update the link lines at the bottom.
3. Run `pwsh scripts/check-version.ps1 -Tag vX.Y.Z-pre.N` locally.
4. Merge to `main`. Wait for `ci.yml` to go green.
5. Tag the merge commit and push the tag.
   ```
   git tag -a vX.Y.Z-pre.N -m "vX.Y.Z-pre.N"
   git push origin vX.Y.Z-pre.N
   ```
6. Watch `release.yml`. Check the release page, the zip name and the hash.

A bad release is never edited. Mark it a pre-release or delete it, and publish the next number. Never move or reuse a tag.

## Not in place yet

- Code signing. Binaries are unsigned. SignPath Foundation is the planned route and needs a public repo.
- Build provenance attestation. Not enabled on a private repo.
- `--version` on the exe. It is rejected as an unknown argument today. The version shows in the log line at start, in `status` and in the zip `VERSION` file.
- A Rust toolchain pin. `rust-toolchain.toml` floats on `stable`. The compiler version is recorded in the zip `VERSION` file.
