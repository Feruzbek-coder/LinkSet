# Threat model

## Trust boundaries

```text
Untrusted user/AI text
  -> React UI
  -> typed Tauri command
  -> Rust validation + risk policy
  -> one-time confirmation
  -> fixed Windows adapter
  -> post-action verification
  -> redacted SQLite audit
```

## Primary threats and controls

| Threat | Control |
|---|---|
| Prompt injection produces shell code | No shell-text command exists; AI tools are read-only and schema constrained |
| Argument command injection | Character/length validation plus narrow service/process allowlists |
| Confused-deputy elevation | App is non-admin; mutation requires a fresh user confirmation |
| Stale or replayed approval | Token expires in five minutes, is request-bound, and is consumed once |
| Malicious installer | Exact-ID winget operations from the configured winget source only |
| Silent action failure | Package/service/process/cleanup state is verified afterward |
| Credential disclosure | Local redaction, no secret logging, API key never returned to UI |
| False malware claim | Security findings are status/heuristic reports, never malware verdicts |

## Privileged helper gate

A future elevation broker must be a separate signed binary with a versioned IPC schema, caller verification, nonce, expiry, exact tool enum, argument validation, and no general process-spawn endpoint. It must not be introduced until code signing and Windows VM adversarial tests are available.

