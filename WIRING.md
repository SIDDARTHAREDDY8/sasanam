# WIRING — coordinator integration for keys and sandbox

Exact, copy-pasteable integration for the two TEAM ENFORCEMENT components.
`gov/log.py` and `gov/executor.py` are intentionally untouched; everything
here works through their existing seams.

## 1. Key management → tamper-evident log (`gov/keys.py` + `gov/log.py`)

`gov/log.py` reads its HMAC key from the environment on every append:

| env var              | meaning                                            |
|----------------------|----------------------------------------------------|
| `GOV_LOG_KEY`        | active HMAC key (base64/utf-8 string) — REQUIRED in production |
| `GOV_LOG_KEY_EPOCH`  | epoch label stamped on every entry (`key_epoch`)   |
| `GOV_LOG_KEY_ARCHIVE`| JSON `{epoch: key}` of retired keys (for verification only) |

The **only** supported production path to populate them:

```python
from gov.keys import KeyRing, NoKeyConfiguredError

ring = KeyRing.load("/secure/operator/keys/keyring.json")  # 0600, atomic save
ring.activate()  # sets GOV_LOG_KEY / GOV_LOG_KEY_EPOCH / GOV_LOG_KEY_ARCHIVE
```

Production startup gate (coordinator-owned, suggested):

```python
from gov.keys import require_key, NoKeyConfiguredError

try:
    require_key()   # env backend; dev key only with GOV_DEV_KEYS=1 opt-in
except NoKeyConfiguredError:
    raise SystemExit("refusing to start: no production log key configured")
```

Key facts the coordinator must respect:

- `gov/log.py`'s own verifier resolves **one** active key only. After any
  rotation, verify mixed-epoch logs with `KeyRing.verify_log(path)`, which
  selects the HMAC key per entry from the entry's `key_epoch`.
- Rotation ceremony (fail-closed): `keys.rotate_keyring(path, new_epoch,
  log_path)` verifies the existing log with the OLD ring first and refuses
  to rotate on top of a tampered log; writes `<path>.bak` (pre-rotation
  ring, 0600, atomic); persists atomically (temp + fsync + `os.replace` +
  dir fsync — a crash can never leave a truncated keyring).
- `keys.record_rotation(log, ring, new_epoch, actor=...)` appends a
  `key_rotation` audit event carrying epoch labels + key IDs only — never
  key material.
- Threat model (non-negotiable): a stolen ACTIVE key permits future forgery
  and history rewriting for that epoch; rotation limits future exposure but
  does not restore authenticity for a compromised epoch. Retaining
  historical keys preserves verification but increases custody risk. HMAC
  gives neither public verification nor non-repudiation — independent
  off-host checkpoints are still needed to detect a full rewrite by a
  key-holding attacker.

## 2. Sandbox → executor (`gov/sandbox.py` + `gov/executor.py`)

One call, no `executor.py` edits:

```python
from gov import sandbox

backend = sandbox.install(executor)
# executor._simulate is now backend.execute; call() and replay both route
# through it. Returns the SandboxedToolBackend.
```

`SandboxedToolBackend` keeps the exact `(tool, args, ctx) -> dict` contract
and result shapes; `read_file`/`write_file`/`delete_file` additionally run
inside `Sandbox` child processes. Path authority stays **parent-side**: every
path is resolved and confined under the sandbox/quarantine roots before any
child starts — the child never chooses where IO goes.

### Isolation modes

```python
from gov.sandbox import Sandbox

# Default: best-effort namespaces, honest per-call reporting.
s = Sandbox(timeout=10)

# Hostile code: FAIL CLOSED. Refuses (SandboxError) before exec when the
# PID namespace cannot be established for that call.
s = Sandbox(timeout=10, require_pidns=True)
```

- `SandboxResult.pid_isolated` / `.network_isolated` are **per-call ground
  truth** reported by the child over a status pipe — never a probe-based
  capability flag. A sporadic `unshare`/`fork` failure is reported as
  `pid_isolated=False` with a `namespace fallback` note, never silently
  mislabeled as isolated.
- Without the PID namespace the worker is a direct child: it learns the
  parent's real PID and **can `os.kill()` it** (same UID) — demonstrated
  against the dev harness. The non-strict fallback is therefore NOT a
  hostile-code boundary; hostile tool code must run with
  `require_pidns=True`.
- `require_netns=True` similarly refuses when the network namespace cannot
  be established.
- Constructor rejects contradictions: `require_pidns=True` with
  `use_pidns=False` raises `ValueError` immediately.
- Recommended: pass a strict `Sandbox` into the backend for hostile tools:
  `SandboxedToolBackend(root, quarantine, sandbox=Sandbox(require_pidns=True))`.

### What the sandbox does and does not promise

Does: `shell=False` argv only; fresh empty cwd per call; scrubbed env
(allowlist + isolated `HOME`/`TMPDIR`); new process session with
group-kill on wall-clock timeout; bounded nonblocking output capture;
POSIX rlimits (CPU/AS/fsize/fds/nproc); PID+network namespaces when the
kernel allows; 64 MiB stdin cap.

Does not: chroot the filesystem (cwd escape is contained by parent-side
path validation, not by the child); stop a double-fork+setsid escape from
the kill group; make arbitrary hostile native code safe — it is
defense-in-depth plus crash/hang/resource containment for the tool scripts
the agent system generates.
