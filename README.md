# secure-exec-hardened (v2.0.0)

MCP stdio broker that runs allowlisted commands with credentials injected as
environment variables. Credentials live in an encrypted store; they are never
printed, only key names are ever exposed.

## Download / Install

This repo is PRIVATE. Every path below requires access: `gh auth login`
with a token that has the `repo` scope, or an invitation as a collaborator.
Unauthenticated downloads will fail with 404.

### Option A — npm / npx (node shim around server.py)

```bash
gh auth login  # needs `repo` scope for this private repo
npx -y github:BrunoRecalde/secure-exec-hardened
# or install globally:
npm i -g github:BrunoRecalde/secure-exec-hardened
secure-exec
```

The `secure-exec` bin is a zero-dependency node shim that spawns
`python3 <package>/server.py` with stdio inherited. Requires `python3`
in `PATH`.

### Option B — pip / uvx (Python stdlib-only, no dependencies)

```bash
gh auth login  # needs `repo` scope for this private repo
pip install "git+https://github.com/BrunoRecalde/secure-exec-hardened.git@v2.0.0"
python3 -c "import server; print(server.TOOLS)"
# or run the broker directly after cloning:
python3 server.py
# uvx equivalent:
uvx --from "git+https://github.com/BrunoRecalde/secure-exec-hardened.git@v2.0.0" --help
```

`server.py` is the canonical entry point (stdlib-only). The
`bin/secure-exec` wrapper also works for pipx-style installs.

### Option C — git clone (direct)

```bash
gh auth login  # needs `repo` scope for this private repo
gh repo clone BrunoRecalde/secure-exec-hardened
python3 secure-exec-hardened/server.py
```

### opencode.json example (installed bin)

```json
{
  "mcp": {
    "secure-exec": {
      "type": "local",
      "command": ["secure-exec"],
      "enabled": true
    }
  }
}
```

If the bin is not on `PATH`, point `command` at the absolute paths
instead: `["python3", "/path/to/secure-exec-hardened/server.py"]`.

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
