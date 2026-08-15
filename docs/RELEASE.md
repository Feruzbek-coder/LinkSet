# Release gates

A LinkSet build is releasable only when all gates pass:

1. Windows CI passes formatting, clippy, unit tests, frontend build, and production dependency audit.
2. End-to-end tests pass on clean Windows 10 and Windows 11 virtual machines in `DRY_RUN=true`.
3. Mutating smoke tests pass in a disposable Windows 11 VM with explicit confirmation.
4. The executable and installer are Authenticode-signed and signatures are verified after download.
5. The update channel has a signed manifest and rollback procedure.
6. Defender and at least one independent malware scanner report no unexpected detection.
7. Privacy export/delete controls and opt-in crash reporting are verified.
8. Winget unavailable, offline, permission-denied, timeout, and reboot-required paths are exercised.

Auto-update is enabled for updater-aware releases through signed GitHub Release artifacts. The publish workflow injects the current repository's HTTPS `latest.json` endpoint. Never commit the updater private key, code-signing certificates, or API keys to this repository.
