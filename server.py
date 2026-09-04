#!/usr/bin/env python3
"""MCP secure-exec server: run allowlisted commands with injected credentials.

Hardened: default-deny allowlist, arrays-only argv, minimal child env,
fail-closed encrypted store, defense-in-depth redaction, audit log.
"""
import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.parse

CRED_FILE = os.path.expanduser("~/.opencode/secure-creds.json")  # legacy, never read/written
CRED_ENC = os.path.expanduser("~/.opencode/secure-creds.enc")
AUDIT_LOG = os.path.expanduser("~/.opencode/secure-exec/audit.log.jsonl")
AUDIT_MAX_BYTES = 5 * 1024 * 1024
MASTER_SERVICE = "opencode-master"
MAX_OUT_BYTES = 256 * 1024
MAX_ARG_BYTES = 8192

# F1: default-deny allowlist. Only these argv[0] basenames may execute.
ALLOW = frozenset({"curl", "aws", "python3", "node", "npx"})
# Shell binaries: rejected unless the caller passes allow_shell:true (default false).
SHELL_BINS = frozenset({"bash", "sh", "dash", "zsh"})
# F1: per-arg regex. shell=False makes metachars inert, so this only
# rejects NUL bytes and overlong args; the real gate is the argv[0] allowlist.
ARG_RE = re.compile(r"^[^\x00]*$", re.DOTALL)

creds = {}
_MASTER_PW_CACHE = None


def _clear_master_cache():
    global _MASTER_PW_CACHE
    _MASTER_PW_CACHE = None


def _minimal_env():
    """F3: minimal child env. Never os.environ.copy() on the exec path."""
    try:
        user = os.environ.get("USER") or getpass.getuser()
    except Exception:
        user = "user"
    return {"PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~"), "USER": user or "user"}


def _scrub_env(env):
    """F3: drop inherited secret-looking vars. Runs BEFORE injecting creds."""
    for k in list(env.keys()):
        ku = k.upper()
        if k == "OPENCODE_CREDS_PASSWORD" or "TOKEN" in ku or "SECRET" in ku or "PASS" in ku:
            env.pop(k, None)


def _check_self_perms():
    """F6: warn (only) if server.py is group/other-writable. Never chmod itself."""
    try:
        if os.stat(__file__).st_mode & 0o022:
            print(f"warning: {__file__} is group/other-writable; fix permissions", file=sys.stderr)
    except OSError:
        pass


def get_master_password():
    """F5 fail-closed: raise instead of falling back to plaintext."""
    global _MASTER_PW_CACHE
    if _MASTER_PW_CACHE is not None:
        return _MASTER_PW_CACHE
    try:
        user = os.environ.get("USER") or getpass.getuser()
    except Exception:
        user = "user"
    user = user or "user"
    security_missing = False
    found = None
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-a", user, "-s", MASTER_SERVICE, "-w"],
            capture_output=True, text=True, timeout=5,
            stdin=subprocess.DEVNULL, cwd="/tmp", env=_minimal_env(),
        )
        if r.returncode == 0 and r.stdout.strip():
            found = r.stdout.strip()
    except FileNotFoundError:
        security_missing = True
    except Exception:
        pass
    if found is not None:
        _MASTER_PW_CACHE = found
        return _MASTER_PW_CACHE
    # Explicit env password is the only migration path for hosts without Keychain.
    pw_env = os.environ.get("OPENCODE_CREDS_PASSWORD")
    if pw_env:
        _MASTER_PW_CACHE = pw_env
        return _MASTER_PW_CACHE
    if security_missing:
        raise RuntimeError("no master key: refusing plaintext")
    # Keychain present but no entry: generate and store (update, no duplicates).
    gen = None
    try:
        r = subprocess.run(["openssl", "rand", "-base64", "32"], capture_output=True,
                           text=True, timeout=5, stdin=subprocess.DEVNULL,
                           cwd="/tmp", env=_minimal_env())
        if r.returncode == 0 and r.stdout.strip():
            gen = r.stdout.strip()
    except Exception:
        pass
    if not gen:
        gen = base64.b64encode(secrets.token_bytes(32)).decode()
    try:
        # NOTE: gen travels via argv (visible in process list); accepted residual.
        s = subprocess.run(
            ["security", "add-generic-password", "-U", "-a", user, "-s", MASTER_SERVICE, "-w", gen],
            capture_output=True, text=True, timeout=5,
            stdin=subprocess.DEVNULL, cwd="/tmp", env=_minimal_env(),
        )
    except FileNotFoundError:
        raise RuntimeError("no master key: refusing plaintext")
    except Exception:
        raise RuntimeError("no master key: refusing plaintext")
    if s.returncode != 0:
        # F12: loud failure, never cache an unrecoverable password.
        raise RuntimeError("no master key: refusing plaintext")
    _MASTER_PW_CACHE = gen
    return _MASTER_PW_CACHE


def _write_pw_file(pw: str) -> str:
    """F8: master password via 0600 temp file, never via env."""
    d = os.path.expanduser("~/.opencode/secure-exec")
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = os.path.join(d, ".pw." + secrets.token_hex(8))
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, pw.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    return tmp


def _destroy_file(path: str):
    try:
        try:
            with open(path, "r+b") as f:
                f.seek(0, os.SEEK_END)
                n = f.tell()
                f.seek(0)
                f.write(b"\x00" * min(n, 1 << 20))  # best-effort wipe, bounded
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _run_openssl(args, data: bytes, pw: str) -> bytes:
    pwfile = _write_pw_file(pw)
    try:
        r = subprocess.run(
            ["openssl"] + args + ["-pass", "file:" + pwfile],
            input=data, capture_output=True, timeout=15,
            cwd="/tmp", env=_minimal_env(),
        )
    finally:
        _destroy_file(pwfile)
    if r.returncode != 0:
        raise RuntimeError("openssl operation failed")
    return r.stdout


def _openssl_encrypt(plaintext: str, pw: str) -> bytes:
    # ponytail: CBC has no MAC; -iter 200000 -pbkdf2 only slows brute force.
    return _run_openssl(["enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt"],
                        plaintext.encode(), pw)


def _openssl_decrypt(cipher: bytes, pw: str) -> str:
    # Try current params first, then legacy files encrypted before -iter 200000.
    try:
        return _run_openssl(["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt"],
                            cipher, pw).decode()
    except RuntimeError:
        return _run_openssl(["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-salt"],
                            cipher, pw).decode()


def _atomic_write_bytes(path: str, data: bytes):
    """F13: atomic 0600 write: O_EXCL tmp + fsync + rename."""
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    for _ in range(3):
        tmp = f"{path}.tmp.{secrets.token_hex(8)}"
        try:
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            continue
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, path)
        try:
            dfd = os.open(d, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
        return
    raise RuntimeError("atomic write failed: refusing plaintext")


def encrypt_and_save(data: dict):
    pw = get_master_password()  # raises fail-closed, no plaintext fallback
    enc = _openssl_encrypt(json.dumps(data), pw)  # raises loud on failure
    _atomic_write_bytes(CRED_ENC, enc)


def decrypt_file() -> dict:
    # F5: legacy plaintext is never used; warn once and ignore it.
    if os.path.exists(CRED_FILE):
        print(f"warning: legacy plaintext {CRED_FILE} present; refusing to use it", file=sys.stderr)
    if os.path.exists(CRED_ENC):
        pw = get_master_password()  # raises fail-closed
        try:
            with open(CRED_ENC, "rb") as f:
                cipher = f.read()
        except OSError:
            raise RuntimeError("cannot read credential store")
        plain = _openssl_decrypt(cipher, pw)  # raises loud, never {} fallback (F13)
        try:
            data = json.loads(plain)
        except json.JSONDecodeError:
            raise RuntimeError("credential store corrupt: refusing to continue")
        if not isinstance(data, dict):
            raise RuntimeError("credential store corrupt: refusing to continue")
        return data
    return {}


def load_creds():
    global creds
    creds = decrypt_file()


def save_creds():
    # ponytail: keep for completeness — delegates to encrypt_and_save
    encrypt_and_save(creds)


def _secret_variants(v: str):
    out = {v}
    try:
        out.add(urllib.parse.quote(v, safe=""))
        out.add(urllib.parse.quote_plus(v))
        out.add(base64.b64encode(v.encode()).decode())
        out.add(base64.urlsafe_b64encode(v.encode()).decode())
    except Exception:
        pass
    for s in list(out):  # newline variant per spec
        out.add(s + "\n")
    return [s for s in out if s]


def redact_credentials(text):
    """F4: redact raw + quote/quote_plus/b64/b64urlsafe + newline variants."""
    # NOTE: still incomplete by design — a transformed/truncated/hashed secret
    # that matches no variant above can reach the LLM. Never print secrets.
    if not text:
        return text
    for v in creds.values():
        if not v:
            continue
        for var in _secret_variants(v):
            text = text.replace(var, "***")
    return text


def _audit_log(entry: dict):
    """F9: append-only audit log, 0600, names only, rotate past 5MB to .1."""
    try:
        d = os.path.dirname(AUDIT_LOG)
        os.makedirs(d, mode=0o700, exist_ok=True)
        try:
            if os.path.exists(AUDIT_LOG) and os.path.getsize(AUDIT_LOG) > AUDIT_MAX_BYTES:
                try:
                    os.rename(AUDIT_LOG, AUDIT_LOG + ".1")
                except OSError:
                    pass
        except OSError:
            pass
        fd = os.open(AUDIT_LOG, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            os.write(fd, (json.dumps(entry) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.chmod(AUDIT_LOG, 0o600)
        except OSError:
            pass
    except Exception as e:
        print(f"audit log failed: {e}", file=sys.stderr)


def _audit_attempt(cmd, inject_keys, exit_code, out_bytes, err_bytes):
    try:
        if isinstance(cmd, list):
            argv0 = cmd[0] if cmd and isinstance(cmd[0], str) else ""
            blob = json.dumps(cmd, sort_keys=True, default=str)
        else:
            argv0, blob = "", "<non-array:" + type(cmd).__name__ + ">"
    except Exception:
        argv0, blob = "", "<unserializable>"
    _audit_log({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "argv0": argv0,
        "cmd_sha256": hashlib.sha256(blob.encode()).hexdigest(),
        "inject_keys": [k for k in (inject_keys or []) if isinstance(k, str)],
        "exit": int(exit_code),
        "out_bytes": int(out_bytes),
        "err_bytes": int(err_bytes),
    })


def _validate_cmd(cmd, allow_shell):
    """F1+F11: arrays only, default-deny allowlist, bash needs explicit flag."""
    if not isinstance(cmd, list):
        return "command must be an argv array"
    if not cmd:
        return "empty command"
    if any(not isinstance(a, str) for a in cmd):
        return "command argv must be strings"
    if any("\x00" in a for a in cmd):
        return "command contains NUL byte"
    if any(len(a.encode("utf-8", errors="ignore")) > MAX_ARG_BYTES for a in cmd):
        return "command argument too long"
    base = os.path.basename(cmd[0])
    if base in SHELL_BINS:
        if allow_shell is not True:  # default false
            return "shell execution requires allow_shell:true"
        return None
    if base not in ALLOW:
        return f"command not allowed: {base}"
    for a in cmd[1:]:
        if not ARG_RE.match(a):
            return "command argument failed allowlist regex"
    return None


def _clamp_timeout(t):
    """F10: timeout = min(max(float(timeout or 120), 1), 600)."""
    try:
        f = float(t if t is not None else 120)
    except (TypeError, ValueError):
        f = 120.0
    if f != f:  # NaN
        f = 120.0
    return min(max(f, 1.0), 600.0)


def _truncate(s: str, limit: int = MAX_OUT_BYTES) -> str:
    """F10: truncate stdout/stderr to 256KiB with a marker."""
    b = s.encode("utf-8", errors="ignore")
    if len(b) <= limit:
        return s
    return b[:limit].decode("utf-8", errors="ignore") + f"\n[truncated {len(b) - limit} bytes]"


def respond(rid, result):
    d = {"jsonrpc": "2.0", "id": rid}
    if "error" in result:
        d["error"] = result["error"]
    else:
        d["result"] = result
    return json.dumps(d) + "\n"


TOOLS = [
    {
        "name": "list_credential_keys",
        "description": "Return available credential key names (not values). Use to discover what creds are configured.",
        "inputSchema": {"type": "object", "properties": {}}
    },
    {
        "name": "exec_with_creds",
        "description": "Execute an allowlisted command (curl, aws, python3, node, npx) with injected credentials via environment variables. Argv array only; shell needs allow_shell:true. Returns {stdout, stderr, exit_code}.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Command argv array, e.g. [\"curl\", \"-u\", \"$USER:$PASS\", \"https://example.com\"]"
                },
                "inject": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Credential keys to inject as environment variables."
                },
                "allow_shell": {
                    "type": "boolean",
                    "description": "Allow shell binaries (bash/sh). Default false.",
                    "default": False
                },
                "timeout": {
                    "type": "number",
                    "description": "Timeout in seconds, clamped to [1, 600] (default 120)",
                    "default": 120
                }
            },
            "required": ["command", "inject"]
        }
    },
]


def handle(msg):
    method, rid = msg.get("method"), msg.get("id")
    params = msg.get("params", {})

    if method == "initialize":
        return respond(rid, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "secure-exec", "version": "2.0.0"}
        })
    if method == "notifications/initialized" or method.startswith("$/"):
        return None
    if method == "tools/list":
        return respond(rid, {"tools": TOOLS})
    if method == "tools/call":
        try:
            try:
                load_creds()
            except RuntimeError as e:
                return respond(rid, {
                    "error": {"code": -32603, "message": redact_credentials(str(e))}
                })
            name = params.get("name")
            args = params.get("arguments", {})
            if name == "list_credential_keys":
                return respond(rid, {
                    "content": [{"type": "text", "text": json.dumps(list(creds.keys()))}]
                })
            if name == "exec_with_creds":
                return handle_exec(rid, args)
            return respond(rid, {
                "error": {"code": -32601, "message": f"Unknown tool: {name}"}
            })
        finally:
            _clear_master_cache()  # F8: never retain the master password
    return respond(rid, {
        "error": {"code": -32601, "message": f"Unknown method: {method}"}
    })


def handle_exec(rid, args):
    raw_cmd = args.get("command", [])
    allow_shell = args.get("allow_shell", False)
    inject = args.get("inject", [])

    def err_payload(msg):
        return {"content": [{"type": "text", "text": json.dumps({"error": redact_credentials(msg)})}]}

    if not isinstance(inject, list) or any(not isinstance(k, str) for k in inject):
        _audit_attempt(raw_cmd, [], -2, 0, 0)
        return respond(rid, err_payload("inject must be an array of credential key names"))
    v = _validate_cmd(raw_cmd, allow_shell)
    if v is not None:
        _audit_attempt(raw_cmd, inject, -2, 0, 0)
        return respond(rid, err_payload(v))
    cmd = raw_cmd
    if any(k not in creds for k in inject):
        # F7: generic error; list_credential_keys stays the only enumeration point.
        _audit_attempt(cmd, inject, -2, 0, 0)
        return respond(rid, err_payload("unknown credential key"))
    timeout = _clamp_timeout(args.get("timeout", 120))
    env = _minimal_env()
    _scrub_env(env)
    for k in inject:
        env[k] = creds[k]
    try:
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, env=env,
                timeout=timeout, stdin=subprocess.DEVNULL, cwd="/tmp",  # F10: no shell, fixed cwd
            )
            stdout = _truncate(redact_credentials(r.stdout or ""))
            stderr = _truncate(redact_credentials(r.stderr or ""))
            out = {"stdout": stdout, "stderr": stderr, "exit_code": int(r.returncode)}
            _audit_attempt(cmd, inject, int(r.returncode),
                           len(stdout.encode("utf-8", errors="ignore")),
                           len(stderr.encode("utf-8", errors="ignore")))
        except subprocess.TimeoutExpired:
            out = {"stdout": "", "stderr": redact_credentials(f"timeout ({timeout}s)"), "exit_code": -1}
            _audit_attempt(cmd, inject, -1, 0, 0)
        except FileNotFoundError:
            out = {"stdout": "", "stderr": "command not found", "exit_code": -1}  # F15: no path echo
            _audit_attempt(cmd, inject, -1, 0, 0)
        except Exception:
            print("exec failed", file=sys.stderr)  # never log values/paths
            out = {"stdout": "", "stderr": "execution failed", "exit_code": -1}
            _audit_attempt(cmd, inject, -1, 0, 0)
    finally:
        for k in inject:  # F15: drop credential copies post-run (best-effort; strs are immutable)
            env.pop(k, None)
    return respond(rid, {
        "content": [{"type": "text", "text": json.dumps(out)}]
    })


if __name__ == "__main__":
    _check_self_perms()
    try:
        load_creds()
    except RuntimeError as e:
        print(f"warning: {e}", file=sys.stderr)
        creds = {}
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            resp = handle(msg)
            if resp:
                sys.stdout.write(resp)
                sys.stdout.flush()
        except json.JSONDecodeError:
            pass
        except Exception as e:
            try:
                err = respond(msg.get("id"), {
                    "error": {"code": -32603, "message": redact_credentials(str(e))}})
            except Exception:
                continue
            if err:
                sys.stdout.write(err)
                sys.stdout.flush()
