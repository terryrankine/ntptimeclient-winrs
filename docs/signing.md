# Code signing

Route: [SignPath Foundation](https://signpath.org), free for open-source projects. Terms: `https://signpath.org/terms`.
Releases stay unsigned until every step here is done. `release.yml` signs only when the repo variable `SIGNPATH_ORGANIZATION_ID` is set.

## Conditions to meet before applying

- [ ] Repo public. (My guess: reputation is judged on public evidence. The terms do not say so.)
- [ ] OSI licence, no commercial dual-licensing. `MIT OR Apache-2.0`.
- [ ] A release already exists in the form that will be signed. The unsigned alpha counts.
- [ ] "Code signing policy" section on the home page. Done in `README.md`.
- [ ] Exe metadata: product name is the project name, version is the same each build. Done (`crates/ntpc-service/build.rs`).
- [ ] MFA on GitHub and on SignPath.
- [ ] Download page describes what the program does. Done in `README.md`.
- [ ] Verifiable automated build. `release.yml`.

## Apply

1. Open `https://signpath.org/apply`.
2. Fill in the project name, repo URL, licence, release URL, download page URL and a contact.
3. Wait for the decision. Acceptance is at SignPath Foundation's discretion.

## Wire up (after approval)

In SignPath: create the project with slug `ntptimeclient-winrs`, an artifact configuration for a zip with `ntptimeclient-winrs.exe` at its root, and a release signing policy that needs manual approval. Create an API token for CI and install the SignPath GitHub App or connector as its docs say.

In GitHub, repo settings, Secrets and variables, Actions:

| Kind | Name | Value |
| --- | --- | --- |
| Variable | `SIGNPATH_ORGANIZATION_ID` | the SignPath organisation id |
| Variable | `SIGNPATH_PROJECT_SLUG` | `ntptimeclient-winrs` |
| Variable | `SIGNPATH_SIGNING_POLICY_SLUG` | the release signing policy slug |
| Secret | `SIGNPATH_API_TOKEN` | the CI API token |

Then tag a release. The `sign` job submits the exe, waits for you to approve in SignPath, and `package` checks that the signature is valid before it builds the zip. A failed or rejected signing request stops the release. It never falls back to an unsigned zip.

Set the repo variable last. Setting it turns signing on for the next tag.
