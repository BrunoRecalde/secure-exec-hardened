# secure-exec-hardened (v2.0.0)

MCP stdio broker that runs allowlisted commands with credentials injected as
environment variables. Credentials live in an encrypted store; they are never
printed, only key names are ever exposed.

## Install as a local MCP server

Copy `server.py` somewhere durable, e.g. `~/.opencode/mcp/secure-exec/server.py`,
then register it as a local MCP server:

```json
{
  "mcp": {
    "secure-exec": {
      "type": "local",
      "command": ["python3", "/Users/you/.opencode/mcp/secure-exec/server.py"],
      "enabled": true
    }
  }
}
```

The credential store defaults to `~/.opencode/secure-creds.enc` and the audit
log to `~/.opencode/secure-exec/audit.log.jsonl`. Neither file is part of this
repo (see `.gitignore`).

## Tools

### list_credential_keys

Returns available credential key names (not values).

Synthetic example:

```json
{ "name": "list_credential_keys", "arguments": {} }
```

### exec_with_creds

Runs an allowlisted command (`curl`, `aws`, `python3`, `node`, `npx`) with the
named credentials injected as env vars. `command` must be an argv array;
shell binaries (`bash`, `sh`, …) require `allow_shell: true`. Returns
`{stdout, stderr, exit_code}` with secret values redacted.

Synthetic example (placeholder names only, no real secrets):

```json
{
  "name": "exec_with_creds",
  "arguments": {
    "command": ["bash", "-c", "curl -u \"$USER:$PASS\" https://example.invalid"],
    "inject": ["EXAMPLE_USER", "EXAMPLE_PASS"],
    "allow_shell": true,
    "timeout": 30
  }
}
```

## Security model (v2)

- **Allowlist (default-deny):** only `curl`, `aws`, `python3`, `node`, `npx`
  execute. Shell binaries need explicit `allow_shell: true`. Argv arrays only,
  `shell=False`, fixed `cwd=/tmp`, NUL bytes and overlong args rejected.
- **Minimal child env:** children get only `PATH=/usr/bin:/bin`, `HOME`, `USER`
  plus the injected keys. Inherited `*TOKEN*` / `*SECRET*` / `*PASS*` vars are
  scrubbed before injection, and injected copies are dropped post-run.
- **Fail-closed encrypted store:** AES-256-CBC via `openssl` with PBKDF2
  `-iter 200000`. No master key means `no master key: refusing plaintext` —
  never a plaintext fallback, never a silent `{}`. Legacy plaintext
  `secure-creds.json` is ignored with a warning.
- **Audit log:** append-only JSONL (`argv0`, `cmd_sha256`, key names only,
  exit code, byte counts). Rotates past 5 MB to `.1`. Never logs values.
- **Caps:** timeout clamped to [1, 600]s (default 120), stdout/stderr truncated
  at 256 KiB with a marker, args capped at 8 KiB, redaction covers raw plus
  URL-quote / b64 variants.
- **Legacy migration:** files encrypted before `-iter 200000` still decrypt
  (fallback tries current params first, then legacy `-pbkdf2 -salt` without
  `-iter`). On hosts without macOS Keychain, set the explicit master password:

```bash
export OPENCODE_CREDS_PASSWORD='...'
```

  without it the server refuses to start with credential access.
