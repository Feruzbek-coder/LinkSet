# LinkSet updater release guide

LinkSet uses the official Tauri updater with GitHub Releases. Update packages are
verified with the public key embedded in `src-tauri/tauri.conf.json`.

## One-time GitHub setup

1. Push this project to a GitHub repository.
2. In the repository open **Settings → Secrets and variables → Actions**.
3. Create a repository secret named `TAURI_SIGNING_PRIVATE_KEY`. Its value must
   be the complete contents of:
   `C:\Users\MY COMPUTER\AppData\Local\SETWELL\LinkSet\updater.key`
4. Create `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` with an empty value if GitHub
   allows it. If it does not, omit that secret; this key was generated without a
   password.
5. Back up `updater.key` somewhere private. Never commit it. Losing it means
   installed copies cannot trust future updates.

## Publish a release

Keep these versions identical before publishing:

- `package.json`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`

Commit the change, create a matching tag and push it:

```powershell
git tag app-v0.1.2
git push origin app-v0.1.2
```

The `Publish LinkSet` workflow builds the Windows NSIS/MSI installers, signs the
updater artifacts, creates a public GitHub Release and uploads `latest.json`.
The workflow replaces the updater endpoint with the current GitHub repository,
so forks do not need to hard-code their owner name.

## First updater-enabled installation

Version 0.1.1 cannot update itself because it does not contain the updater.
Download and install version 0.1.2 once from GitHub Releases. Later releases can
be installed from **Settings → Updates** inside LinkSet.

Updater signing verifies the update package. Authenticode signing is a separate
Windows trust requirement and should be configured before public distribution.
