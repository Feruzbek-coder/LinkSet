# Security policy

LinkSet treats all AI output, user input, package metadata, process names, and Windows telemetry as untrusted data.

## Invariants

- No arbitrary PowerShell, CMD, script, URL, or executable can cross the Tauri command boundary.
- System-changing tools must exist in the Rust registry and pass typed validation.
- Level 1 and Level 2 tools require a one-time, five-minute confirmation token.
- Level 3 actions are not registered.
- Package operations use exact winget IDs. Unknown executables are never downloaded.
- The application runs without administrator rights by default.
- API keys, tokens, cookies, private keys, passwords, and file contents are not logged.
- AI can request only read-only diagnostic or package-search tools. It cannot execute mutations.

## Reporting

Do not include credentials, personal files, or raw Windows event logs in a report. Include the affected version, expected behavior, reproduction steps, and a redacted activity-log excerpt.

Before a public release, configure a private security contact and a coordinated disclosure window.

