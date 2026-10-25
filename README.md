# HYPE TOOLS LIVE releases

Public, release-only repository for **HYPE TOOLS LIVE** installers and update metadata.
It contains no application source code. The source repository is private.

- App identity: `com.hypetools.desktop.live`
- Download: see the [Releases](../../releases) page. Only the newest two releases are kept.
- Updates: the LIVE app checks this repository only, when you ask it to. It asks before downloading and again before installing, and verifies a signed release statement and the installer hash.
- This is the LIVE channel. The BETA channel has its own separate repository and identity.

## Everything here is public
Release notes, installers, update metadata, hashes, workflow files and the release ledger are visible to anyone, and copies may be kept elsewhere. Installers contain extractable application code.

## How releases are published
1. The release manager creates a **draft** release and uploads exactly three files: the installer `HYPE-TOOLS-LIVE-Setup-<version>.exe`, `latest.yml` and `release-statement.json`.
2. The `verify-and-publish` workflow checks the draft (file allowlist, sizes, hashes, metadata, Ed25519 signature, replay protection) and, when asked, publishes it as the latest release. It also opens the installer itself with 7-Zip and reads the packaged app: the app name, channel and version must match this repository and the tag, and an updater test build is refused even if it was renamed. If the installer cannot be inspected, nothing is published.
3. Releases are immutable once published. A bad release is fixed with a new, higher version, never replaced.
4. Every LIVE publication needs the repository owner's explicit approval: the publish job runs in the `live-release` environment, which requires an owner review before it starts.

No signing keys or credentials are stored here. The only key material in this repository is the public verification key in `keys/update-public-key.txt`.
