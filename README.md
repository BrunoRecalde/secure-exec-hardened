# secure-exec-hardened

![version](https://img.shields.io/badge/version-v2.0.0-blue)
![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![python](https://img.shields.io/badge/python-%3E%3D3.9-green)
![deps](https://img.shields.io/badge/deps-stdlib--only-brightgreen)
![protocol](https://img.shields.io/badge/MCP-stdio-orange)

> MCP stdio broker that runs allowlisted commands with credentials injected as env vars — never printed, only key names exposed.

## Table of Contents

- [What](#what)
- [Why](#why)
- [Features](#features)
- [Quickstart](#quickstart)
- [OpenCode configuration](#opencode-configuration)
- [Tools reference](#tools-reference)
- [Security model v2](#security-model-v2)
- [Migration from legacy](#migration-from-legacy)
- [Audit log](#audit-log)
- [Limitations](#limitations)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)
- [Links](#links)

## What

`secure-exec-hardened` is a single-file, stdlib-only MCP server (`server.py`) plus a zero-dependency Node shim (`bin/secure-exec`).

It exposes two tools:

- `list_credential_keys` — list credential **names** (never values).
- `exec_with_creds` — run an allowlisted command with named credentials injected as environment variables.

Credentials live in an encrypted store (`~/.opencode/secure-creds.enc`). They are decrypted in memory per call, injected into a minimal child env, scrubbed after the run, and redacted from all output.

## Why

AI agents need to call authenticated CLIs (`curl`, `aws`) without ever seeing raw secrets in prompts, logs, or transcripts.

`secure-exec-hardened` gives you:

- a narrow execution gate (default-deny allowlist, argv arrays only, no shell by default),
- a fail-closed encrypted credential store (no plaintext fallback),
- defense-in-depth redaction and an append-only audit trail (names and hashes only).

If the master key is missing, the server refuses credential access instead of silently continuing.

## Features

- 🔒 Default-deny allowlist: `curl`, `aws`, `python3`, `node`, `npx`
- 🐚 Shell opt-in: `bash` / `sh` / `dash` / `zsh` require `allow_shell: true` (default `false`)
- 📦 Argv arrays only, `shell=False`, fixed `cwd=/tmp`, `stdin=DEVNULL`
- 🧹 Minimal child env (`PATH`, `HOME`, `USER` + injected keys), inherited secret-looking vars scrubbed
- 🔐 Fail-closed AES-256-CBC store via `openssl` with PBKDF2 `-iter 200000`; legacy plaintext `.json` ignored
- 🧽 Redaction of raw plus URL-quote / quote-plus / base64 / base64url / newline variants
- 🧾 Append-only audit log (JSONL, `0600`, rotation past 5 MB)
- ⏱️ Timeout clamped to `[1, 600]`s (default `120`), stdout/stderr truncated at `256 KiB`
- 🔑 Master key from macOS Keychain or explicit `OPENCODE_CREDS_PASSWORD`
- 📁 Atomic `0600` writes, `0600` temp password files, in-memory password cache cleared after every call

## Quickstart

Requires `python3` in `PATH` (`>= 3.9`). The repo is public — no auth needed.

### Option A — npx (no install)

```bash
npx -y github:BrunoRecalde/secure-exec-hardened
```

### Option B — npm global install

```bash
npm i -g github:BrunoRecalde/secure-exec-hardened
secure-exec
```

The `secure-exec` bin is a zero-dependency Node shim that spawns `python3 <package>/server.py` with stdio inherited.

### Option C — pip from git (stdlib-only, no dependencies)

```bash
pip install "git+https://github.com/BrunoRecalde/secure-exec-hardened.git@v2.0.0"
python3 -c "import server; print(server.TOOLS)"
# or run the broker directly after cloning:
python3 server.py
```

### Option D — git clone (direct)

```bash
gh repo clone BrunoRecalde/secure-exec-hardened
python3 secure-exec-hardened/server.py
```

> `server.py` is the canonical entry point. `bin/secure-exec` is a convenience wrapper for npm/npx and `PATH`-based setups.

## OpenCode configuration

Register the installed bin:

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

If the bin is not on `PATH`, point `command` at the script directly:

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

Default paths (not part of this repo, see `.gitignore`):

- credential store: `~/.opencode/secure-creds.enc`
- audit log: `~/.opencode/secure-exec/audit.log.jsonl`

## Tools reference

| Tool | Parameters | Returns |
| ---- | ---------- | ------- |
| `list_credential_keys` | — (no arguments) | JSON array of credential key **names**, e.g. `["EXAMPLE_API_KEY"]` |
| `exec_with_creds` | `command` (string[], required): argv array · `inject` (string[], required): credential key names · `timeout` (number, default `120`, clamped to `[1, 600]`) · `allow_shell` (boolean, default `false`) | `{stdout, stderr, exit_code}` with secret values redacted |

### `list_credential_keys`

Returns available credential key names (not values). Use it to discover what is configured.

```json
{ "name": "list_credential_keys", "arguments": {} }
```

### `exec_with_creds`

Runs an allowlisted command (`curl`, `aws`, `python3`, `node`, `npx`) with the named credentials injected as env vars. Shell binaries need `allow_shell: true`.

Synthetic example (placeholder names only, no real secrets):

```json
{
  "name": "exec_with_creds",
  "arguments": {
    "command": ["curl", "-s", "https://example.com/api"],
    "inject": ["EXAMPLE_API_KEY"],
    "timeout": 30
  }
}
```

Shell example (explicit opt-in):

```json
{
  "name": "exec_with_creds",
  "arguments": {
    "command": ["bash", "-c", "curl -u \"$EXAMPLE_USER:$EXAMPLE_PASS\" https://example.com/api"],
    "inject": ["EXAMPLE_USER", "EXAMPLE_PASS"],
    "allow_shell": true,
    "timeout": 30
  }
}
```

Notes:

- `command` must be an argv array of strings (no shell string, no NUL bytes, each arg capped at 8 KiB).
- Unknown credential keys return a generic `unknown credential key` error — `list_credential_keys` stays the only enumeration point.
- `timeout` accepts anything numeric-ish and clamps to `[1, 600]` (default `120`); `NaN` falls back to `120`.
- Child `env` is minimal: `PATH=/usr/bin:/bin`, `HOME`, `USER`, plus injected keys. Inherited `*TOKEN*` / `*SECRET*` / `*PASS*` vars and `OPENCODE_CREDS_PASSWORD` are scrubbed before injection and dropped post-run (best-effort; Python strings are immutable).

## Security model v2

Default-deny, fail-closed. The table below maps each hardened finding ID to its mitigation in `server.py` v2.0.0 (`F2` is retired and intentionally absent).

| ID | Finding | Mitigation in v2.0.0 |
| -- | ------- | -------------------- |
| F1 | Arbitrary command execution | Default-deny allowlist on `argv[0]` basename: only `curl`, `aws`, `python3`, `node`, `npx`. Non-array / empty / non-string argv, NUL bytes, and args over 8 KiB rejected. |
| F3 | Env / secret leakage into child | Minimal child env (`PATH=/usr/bin:/bin`, `HOME`, `USER` + injected keys). Inherited `*TOKEN*` / `*SECRET*` / `*PASS*` and `OPENCODE_CREDS_PASSWORD` scrubbed before injection; injected copies dropped post-run. |
| F4 | Secrets in stdout/stderr | `redact_credentials` replaces raw values plus `quote` / `quote_plus` / `base64` / `base64urlsafe` / trailing-newline variants with `***`. See [Limitations](#limitations): redaction is incomplete by design. |
| F5 | Plaintext fallback | Fail-closed store. No master key raises `no master key: refusing plaintext`. Legacy `~/.opencode/secure-creds.json` is never read — a warning is printed and it is ignored. Corrupt / non-dict stores raise instead of returning `{}`. |
| F6 | Writable server binary | `_check_self_perms` warns (only) when `server.py` is group/other-writable. It never `chmod`s itself. |
| F7 | Key enumeration oracle | Unknown `inject` keys return a generic `unknown credential key` error. `list_credential_keys` is the only enumeration point. Attempts are audit-logged with exit `-2`. |
| F8 | Master password exposure | Password travels via a `0600` temp file (`-pass file:`), never via env/argv to `openssl`. In-memory cache (`_MASTER_PW_CACHE`) is cleared after every `tools/call`. Keychain-missing hosts must set `OPENCODE_CREDS_PASSWORD` explicitly. |
| F9 | Missing / leaky audit trail | Append-only JSONL at `~/.opencode/secure-exec/audit.log.jsonl` (`0600`, `0700` dir). Logs `argv0`, `cmd_sha256`, key **names** only, exit code, byte counts. Rotates past 5 MB to `.1`. Never logs values. Failures print to stderr only. |
| F10 | Runaway / oversized output | `timeout` clamped to `[1, 600]`s (default `120`). `subprocess.run` uses `shell=False`, `stdin=DEVNULL`, `cwd=/tmp`. stdout/stderr truncated at `256 KiB` with a `[truncated N bytes]` marker. |
| F11 | Shell bypass | `bash` / `sh` / `dash` / `zsh` require explicit `allow_shell: true` (default `false`). All other non-allowlisted binaries are rejected with `command not allowed: <base>`. |
| F12 | Cached bad master password | Keychain `add-generic-password` failure raises `no master key: refusing plaintext` without caching. An unrecoverable password is never retained. |
| F13 | Partial / world-readable writes | Atomic `0600` writes (`O_EXCL` tmp + `fsync` + `rename` + dir `fsync`, 3 retries). Decrypt/parse failures raise loudly (`openssl operation failed`, `credential store corrupt: refusing to continue`). |
| F14 | (no standalone control in v2.0.0) | Folded into F1 + F10: argv validation (`ARG_RE` NUL check, 8 KiB per-arg cap) plus fixed `cwd`, `DEVNULL` stdin, and `shell=False`. Reserved for future hardening. |
| F15 | Error / env residue | `FileNotFoundError` returns `command not found` (no path echo). Generic failures return `execution failed`. Injected env copies are popped post-run (best-effort note: Python `str` is immutable, so in-memory residue cannot be fully wiped). |

Crypto parameters: `openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt`. Decrypt tries current params first, then legacy `-pbkdf2 -salt` without `-iter` (see [Migration](#migration-from-legacy)).

## Migration from legacy

Files encrypted **before** `-iter 200000` still decrypt: `_openssl_decrypt` tries current params first, then falls back to legacy `-pbkdf2 -salt` without `-iter`.

On hosts **without** macOS Keychain (`security` binary missing), set the explicit master password — otherwise the server refuses credential access:

```bash
export OPENCODE_CREDS_PASSWORD='...'
```

Without it you get `no master key: refusing plaintext` (fail-closed, never a silent `{}`).

Legacy plaintext `~/.opencode/secure-creds.json` is ignored with a warning:

```text
warning: legacy plaintext /Users/you/.opencode/secure-creds.json present; refusing to use it
```

Migrate by re-saving through the encrypted path (`encrypt_and_save` → `~/.opencode/secure-creds.enc`) and deleting the plaintext file.

## Audit log

Append-only JSONL, one object per attempt (including rejected validation and unknown-key attempts with exit `-2`). Key names only, full command hashed.

Example (names and hashes only — never values):

```json
{"ts": "2026-01-01T00:00:00Z", "argv0": "curl", "cmd_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "inject_keys": ["EXAMPLE_API_KEY"], "exit": 0, "out_bytes": 128, "err_bytes": 0}
```

Location: `~/.opencode/secure-exec/audit.log.jsonl` (`0600`). Rotates past 5 MB to `audit.log.jsonl.1`.

## Limitations

Honest constraints of v2.0.0 — read before relying on it:

- `python3 -c "..."` is **inside** the allowlist. `python3` as `argv[0]` passes the gate; the broker does not sandbox what the interpreter itself executes. Treat `python3` / `node` / `npx` as powerful primitives, not sandboxes.
- Redaction is **incomplete by design**. It covers raw values plus URL-quote / base64 / newline variants. A transformed, truncated, or hashed secret that matches no variant can still reach the caller. Never print secrets; treat broker output as untrusted.
- The Node shim requires `python3` in `PATH`. If it is missing you get `secure-exec: failed to start python3`.
- Child `PATH` is minimal (`/usr/bin:/bin`). Tools outside those dirs, user shell profiles, and inherited env are intentionally unavailable to the child.
- AES-256-CBC has no MAC; `-iter 200000` only slows brute force. The master password travels via Keychain argv during provisioning (accepted residual, noted in code).
- Python `str` immutability means credential copies cannot be fully wiped from memory; post-run env drops are best-effort.
- No `LICENSE` file ships with the repo (see [License](#license)) — check before vendoring.

## Development

Stdlib-only, no install needed for a syntax check:

```bash
python3 -m py_compile server.py
```

Smoke test the MCP handshake (stdlib-only):

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python3 server.py
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_credential_keys","arguments":{}}}' | python3 server.py
```

Expected: a `tools/list` response advertising `list_credential_keys` and `exec_with_creds` (version `2.0.0`), and a key-names array (empty when no store exists).

## Contributing

Issues and PRs are welcome. Keep the broker stdlib-only and fail-closed:

- preserve the default-deny allowlist and `allow_shell: false` default,
- never log or return secret values (names and hashes only),
- never add a plaintext fallback — loud failure over silent `{}`,
- include a smoke test (`tools/list` + one `tools/call`) in the PR description.

## License

No `LICENSE` file is shipped with v2.0.0. Both `package.json` and `pyproject.toml` declare `UNLICENSED`, so all rights are reserved by default.

If MIT is intended, the maintainer needs to add a `LICENSE` (MIT) file — it is intentionally not created here. Do not treat the absence of a license as permission.

## Links

- Repo: <https://github.com/BrunoRecalde/secure-exec-hardened>
- Release v2.0.0: <https://github.com/BrunoRecalde/secure-exec-hardened/releases/tag/v2.0.0>
