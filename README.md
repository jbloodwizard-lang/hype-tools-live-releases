# HYPE TOOLS LIVE releases

Public, release-only repository for **HYPE TOOLS LIVE** installers and update metadata.
It contains no application source code. The source repository is private.

- App identity: `com.hypetools.desktop.live`
- Download: see the [Releases](../../releases) page. Only the newest two healthy releases are kept by automatic cleanup; releases that failed their post-publication checks are never removed automatically (see below).
- Updates: the LIVE app checks this repository only, when you ask it to. It asks before downloading and again before installing, and verifies a signed release statement and the installer hash.
- This is the LIVE channel. The BETA channel has its own separate repository and identity.

## Download HYPE TOOLS

**Downloads are not available yet.** The first BETA installer is being prepared. LIVE will follow after the BETA installation and update path have been validated.

| Channel | Current status | Official downloads |
|---|---|---|
| **HYPE TOOLS BETA** | Coming soon — first release is being prepared | [Open BETA Releases](https://github.com/jbloodwizard-lang/hype-tools-beta-releases/releases) |
| **HYPE TOOLS LIVE** | Coming soon — first approved stable release is not yet available | [Open LIVE Releases](https://github.com/jbloodwizard-lang/hype-tools-live-releases/releases) |

When a channel is ready, its installer and release notes will appear on that channel's Releases page above. Choose the `HYPE-TOOLS-BETA-Setup-<version>.exe` or `HYPE-TOOLS-LIVE-Setup-<version>.exe` asset matching the channel you intend to use. **Do not download or install a draft; only use a published release.**

BETA is for testing and may be unstable; LIVE is the approved stable channel. Both release repositories are public. Windows installers are initially unsigned, so Windows may display an unknown-publisher or SmartScreen warning.


## Everything here is public
Release notes, installers, update metadata, hashes, workflow files and the release ledger are visible to anyone, and copies may be kept elsewhere. Installers contain extractable application code.

## How releases are published
1. The release manager creates a **draft** release and uploads exactly three files: the installer `HYPE-TOOLS-LIVE-Setup-<version>.exe`, `latest.yml` and `release-statement.json`.
2. The `verify-and-publish` workflow checks the draft (file allowlist, sizes, hashes, metadata, Ed25519 signature, replay protection) and, when asked, publishes it as the latest release. It also opens the installer itself with 7-Zip and reads the packaged app: the app name, channel and version must match this repository and the tag, and an updater test build is refused even if it was renamed. If the installer cannot be inspected, nothing is published.
3. Releases are immutable once published. A bad release is fixed with a new, higher version, never replaced.
4. Every LIVE publication needs the repository owner's explicit approval: the publish job runs in the `live-release` environment, which requires an owner review before it starts.

## Checks after publication, and what happens when they fail
After GitHub reports the release as published, the workflow checks the published release itself rather than trusting that call: the draft flag is cleared, the prerelease flag is correct, the release is immutable, the latest release is the new one, the asset set is the one that was verified, and all three files download from their public links with the verified sizes and SHA-256 hashes (and GitHub's own digests). The installer's size and SHA-512 must also match `latest.yml` and the signed release statement, and the release must head the releases feed.

If any of these checks fails:
- The release is recorded in `ledger/releases.json` as `failed-verification`, with the failed checks and the recovery outcome. It is never counted as a healthy release.
- The workflow automatically makes the previous known-good release the latest release again and reads the latest pointer back to confirm it. If there is no previous known-good release, it marks the failed release as a prerelease so that it is no longer the latest release, and confirms that too. The job always fails and its summary says which checks failed, whether recovery was confirmed, and what still needs a person.
- **A failed release can stay publicly accessible.** Its release page, files, tag and feed entry remain reachable through direct links, its files cannot be changed, and moving the latest pointer cannot undo a download someone already made. Nothing is deleted automatically.
- Retention never deletes a failed release and never counts it among the releases it keeps.
- A failed release's tag, version and sequence number are never reused. A correction is published as a new, higher version with a tag that has never been used.
- If the ledger itself cannot be updated, the job says so, and no further release can be verified until the missing ledger entry is added.
 The only key material in this repository is the public verification key in `keys/update-public-key.txt`.
