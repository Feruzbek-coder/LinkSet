# LinkSet privacy design

LinkSet is local-first. System inventory, diagnostics, scores, activity history, and AI usage counters are stored in the local application-data SQLite database.

When OpenAI is configured, LinkSet sends only the current redacted chat message. It does not send files, cookies, passwords, authentication tokens, private keys, full event logs, process dumps, or browser history. Requests use `store: false`.

Sensitive-data redaction covers common API-token patterns, explicit secret assignments, Windows file paths, and email addresses. Redaction is defense in depth and does not replace user consent or data minimization.

Users should be given controls to export and delete local history before public release. Remote crash reporting and analytics must remain opt-in.

