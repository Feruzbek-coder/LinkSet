# LinkSet MVP

LinkSet is a security-first Windows PC assistant by **SETWELL**. This repository contains the first runnable vertical slice: a Tauri desktop shell, React dashboard, native Windows diagnostics, a safe action gateway, and local SQLite audit storage.

## What works

- Live CPU, RAM, disk, uptime, Windows version and process monitoring
- TCP/UDP endpoint and listening-port inspection with process mapping
- Startup apps, Windows services, installed software, adapters, IP/gateway/DNS and printers
- Windows Update/hotfix/reboot state, recent crash events and safe temp-file analysis
- Microsoft Defender, real-time protection, Firewall and Windows Update service status
- Modular system-health and security scores
- `winget` package search and exact-ID installation
- All ten requested local diagnostic workflows plus `SYSTEM_CHECK`
- Optional OpenAI Responses API provider with strict read-only tools, `store: false`, redaction and local fallback
- One-time, expiring confirmation tokens before all system-changing actions
- Verified winget install/update/uninstall, allowlisted process/service restart with one-time UAC elevation, and conservative file-by-file temp cleanup tools
- SQLite activity logs, diagnostic history, score schema and AI usage accounting
- Browser preview data when the UI runs outside Tauri

The MVP defaults to `DRY_RUN=true`. A generated AI message can never become a PowerShell/CMD command: the UI sends typed tool requests, the Rust registry validates the tool and arguments, and only fixed helpers are executed.

## Architecture

```text
React UI
  -> typed Tauri commands
  -> local orchestrator / diagnostics
  -> safety registry (risk + validation + confirmation)
  -> allowlisted Rust/PowerShell/winget adapters
  -> verification result + SQLite activity log
```

Important modules:

- `src-tauri/src/system.rs` — resource and process collection
- `src-tauri/src/windows.rs` — fixed Windows helpers and winget adapter
- `src-tauri/src/safety.rs` — whitelist, risk policy, validation, one-time approval
- `src-tauri/src/ai.rs` — replaceable `AiProvider` boundary and local intent routing
- `src-tauri/src/db.rs` — SQLite persistence abstraction
- `src/api.ts` — typed UI/native bridge with browser-preview fallback

## Requirements

- Windows 10/11 with WebView2 and `winget`
- Node.js 20+
- Rust stable (MSVC target)
- Visual Studio 2022 Build Tools with **Desktop development with C++** (MSVC linker and Windows SDK)

## Run

```powershell
npm install
Copy-Item .env.example .env
npm run tauri dev
```

For a UI-only preview (uses clearly isolated sample data):

```powershell
npm run dev
```

Production build:

```powershell
npm run build
npm run tauri build
```

## Current Windows release

The verified `0.1.1` Windows artifacts are in `release/LinkSet-0.1.1`:

- `LinkSet.exe` — standalone desktop application
- `LinkSet_0.1.1_x64-setup.exe` — NSIS installer
- `LinkSet_0.1.1_x64_en-US.msi` — MSI installer

Version `0.1.2` adds the signed Tauri updater and a **Settings → Updates** screen.
GitHub tag pushes matching `app-v*` run `.github/workflows/release.yml`, which
publishes NSIS/MSI installers, signatures, and `latest.json`. See
`docs/UPDATER.md` for the one-time signing-secret setup and release procedure.
- `SHA256SUMS.txt` — integrity hashes

The application passes 16 Rust tests, strict Clippy checks, the frontend production build, dependency audit and a native Windows launch smoke test. These local artifacts are not yet Authenticode-signed; a trusted SETWELL code-signing certificate is required before public distribution.

## Safety modes

Keep this during development:

```text
DRY_RUN=true
```

With dry run enabled, install, restart, and cleanup actions only log the exact allowed operation. To exercise mutations explicitly, start LinkSet with `DRY_RUN=false`. Level 3 operations (registry, accounts, boot configuration, partitions, reset) are not registered and cannot execute.

Service restart is limited to `Spooler`, `wuauserv`, and `Dnscache`; standard-user sessions request one-time UAC approval for that action. Package mutations require a validated exact winget package ID. Confirmation tokens expire after five minutes and are consumed once.

## AI provider

`AiProvider` is intentionally separated from tool execution. When `OPENAI_API_KEY` is configured, `OpenAiProvider` calls the Responses API with `store: false`, redacted user input and only two read-only tools. Without a key or when the request fails, the multilingual local diagnostic router remains available. Put credentials in `.env` or Windows Credential Manager—never in source control.

The database already includes `ai_usage(user_id, request_id, model, input_tokens, output_tokens, estimated_cost, timestamp)` for future AI Credits metering.

## Tests

```powershell
npm run build
npm test
npm audit --omit=dev
```

Safety tests verify that unknown tools and critical services are rejected and that approval tokens are single-use. Tests never perform real system mutations.

## MVP limitations

Remaining production work includes broader hardware temperature support, historical per-process network byte accounting, notifications, startup-at-login management, rollback, privacy export/delete controls, Authenticode signing, and clean Windows 10/11 VM certification. Signed auto-update is enabled through GitHub Releases; public distribution still requires protecting the updater key and completing Windows signing and clean-VM release checks.
