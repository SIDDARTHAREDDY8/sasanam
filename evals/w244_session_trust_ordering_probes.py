"""Wave-244 session-startup trust-ordering battery (W244-1), red-first.

ADAPT of the GitSpawn threat model (8 flaws across 7 coding agents; a
malicious repo-local ``.git/config`` naming a command-executing key such as
``core.fsmonitor`` auto-executes attacker commands the moment tooling -- not
the agent -- runs a routine git operation, PRE-TRUST-PROMPT). The existing
``gov/git_sanitize.py`` is deny-first INSIDE its entry point, but nothing in
the tree makes the TRUST DECISION a first-class, ordering-first primitive:
this battery falsifies any shell-out path that consults the trust state
late, never, or after reading repo-supplied configuration.

Probes:
  pretrust-fsmonitor-refused -- untrusted repo whose ``.git/config``
      sets ``core.fsmonitor=<payload>`` -> ``checked_spawn`` refuses
      ``repo-hook-pretrust-refused`` and the spawn callable is never
      invoked (falsifies pre-trust execution; the payload canary file is
      never created because no subprocess is ever spawned).
  trust-then-allowed -- trust recorded as ``verified-allowed`` with a
      CLEAN config -> the spawn is invoked, argv/cwd byte-identical
      (positive control: trust is consulted, not bypassed-in-reverse).
  default-distrust-hook-executable -- an UNKNOWN repo (never recorded)
      carrying an executable ``.git/hooks/pre-commit`` -> refused
      ``repo-hook-pretrust-refused`` (falsifies prompt-bypass: distrust
      is the default, never an ask-later).
  symlink-escape-refused -- ``.git`` is a symlink escaping the repo root
      -> refused ``repo-hook-escape-refused`` (falsifies hook
      resolution following worktree-local symlinks out of the root).
  trust-ordering-first -- an UNTRUSTED repo with a HOSTILE config: the
      trust lookup fires BEFORE the config scan, the config scan NEVER
      runs, and the denial code is the trust code (falsifies ordering
      inversion via call-order recorders).
  trusted-hostile-still-denied -- a ``verified-allowed`` repo with a
      HOSTILE config -> ``gitspawn-hostile-config`` (falsifies trust
      laundering: trust is not a config bypass; deny still applies).
  denied-refused -- ``verified-denied`` repo -> refused
      ``repo-hook-trust-denied``.
  audit-redaction -- the pre-trust refusal is recorded in the audit
      sink with the refusal code, but the record contains NEITHER the
      hook path NOR any config value (falsifies secret-bearing logs).
  malformed-record-refused -- ``record_trust`` with an unknown state
      string -> refused ``session-trust-malformed`` (falsifies silent
      acceptance of invented states).

Stdlib + in-repo gov.git_sanitize only. Deterministic. No in-repo git
subprocesses (fake ``.git`` trees are plain files; the git binary is
never executed).
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_ST = False
try:
    from gov import session_trust as _st
    HAVE_ST = all(hasattr(_st, n) for n in (
        "TrustRegistry", "checked_spawn", "resolve_repo_root",
        "raise_refusal", "registered_refusals", "SessionTrustError",
        "UNTRUSTED", "ALLOWED", "DENIED"))
except ImportError:
    _st = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "pretrust-fsmonitor-refused",
    "trust-then-allowed",
    "default-distrust-hook-executable",
    "symlink-escape-refused",
    "trust-ordering-first",
    "trusted-hostile-still-denied",
    "denied-refused",
    "audit-redaction",
    "malformed-record-refused",
]

RESULTS = []
SITUATIONS = {}


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                detail = fn()
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e),
                                           "trace": traceback.format_exc(
                                               limit=5)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


def _need():
    if not HAVE_ST:
        return {"verdict": "gap", "note": "gov.session_trust missing"}
    return None


def _repo(parent, name, *, fsmonitor=None, hook_executable=False):
    root = os.path.join(parent, name)
    git = os.path.join(root, ".git")
    os.makedirs(git, exist_ok=True)
    with open(os.path.join(git, "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")
    if fsmonitor is not None:
        with open(os.path.join(git, "config"), "w") as f:
            f.write("[core]\n\tfsmonitor = %s\n" % fsmonitor)
    if hook_executable:
        hooks = os.path.join(git, "hooks")
        os.makedirs(hooks, exist_ok=True)
        hook = os.path.join(hooks, "pre-commit")
        with open(hook, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(hook, 0o755)
    return root


def _spawner(calls):
    def spawn(argv, env=None, cwd=None):
        calls.append((argv, env, cwd))
        return {"rc": 0}
    return spawn


def _assert_code(fn, code):
    try:
        fn()
    except _st.SessionTrustError as e:
        if e.code != code:
            return {"verdict": "gap",
                    "note": "wrong code: %s (wanted %s)" % (e.code, code)}
        return {"verdict": "held"}
    except Exception as e:  # noqa: BLE001
        return {"verdict": "error",
                "note": "wrong exception: %s: %s" % (type(e).__name__, e)}
    return {"verdict": "gap", "note": "no refusal raised"}


@_sit("pretrust-fsmonitor-refused")
def _p_pretrust_fsmonitor():
    """Untrusted repo + core.fsmonitor payload -> pre-trust refusal."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    root = _repo(tmp, "w244-pretrust", fsmonitor="/bin/touch CANARY")
    reg = _st.TrustRegistry()
    calls = []
    res = _assert_code(
        lambda: _st.checked_spawn(["status"], root, reg,
                                  spawn=_spawner(calls)),
        "repo-hook-pretrust-refused")
    if res["verdict"] != "held":
        return res
    if calls:
        return {"verdict": "gap",
                "note": "spawn invoked %d times pre-trust" % len(calls)}
    if os.path.exists(os.path.join(root, "CANARY")):
        return {"verdict": "gap", "note": "payload canary file exists"}
    return {"verdict": "held"}


@_sit("trust-then-allowed")
def _p_trust_then_allowed():
    """Recorded trust + clean config -> spawn runs byte-identical."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    root = _repo(tmp, "w244-trusted")
    reg = _st.TrustRegistry()
    reg.record_trust(root, _st.ALLOWED, decided_by="operator")
    calls = []
    out = _st.checked_spawn(["status"], root, reg, spawn=_spawner(calls))
    if out != {"rc": 0}:
        return {"verdict": "gap", "note": "spawn return not returned"}
    if len(calls) != 1:
        return {"verdict": "gap",
                "note": "spawn called %d times" % len(calls)}
    argv, env, cwd = calls[0]
    if argv != ["git", "status"]:
        return {"verdict": "gap", "note": "argv mutated: %r" % (argv,)}
    if os.path.abspath(cwd) != os.path.realpath(root):
        return {"verdict": "gap", "note": "cwd not the repo root"}
    if env.get("GIT_CONFIG_NOSYSTEM") != "1":
        return {"verdict": "gap", "note": "sanitized env not applied"}
    return {"verdict": "held"}


@_sit("default-distrust-hook-executable")
def _p_default_distrust():
    """Unknown repo + executable hook -> pre-trust refusal, never asked."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    root = _repo(tmp, "w244-unknown", hook_executable=True)
    reg = _st.TrustRegistry()
    calls = []
    res = _assert_code(
        lambda: _st.checked_spawn(["status"], root, reg,
                                  spawn=_spawner(calls)),
        "repo-hook-pretrust-refused")
    if res["verdict"] != "held":
        return res
    if calls:
        return {"verdict": "gap",
                "note": "spawn invoked %d times pre-trust" % len(calls)}
    return {"verdict": "held"}


@_sit("symlink-escape-refused")
def _p_symlink_escape():
    """.git symlink escaping the root -> escape refusal."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    outside = os.path.join(tmp, "w244-outside-git")
    os.makedirs(outside, exist_ok=True)
    root = _repo(tmp, "w244-escape")
    reg = _st.TrustRegistry()
    # Trust is recorded against the CLEAN layout; the attacker then
    # swaps .git for a symlink escaping the root (TOCTOU shape). The
    # spawn-time resolution must catch it even on a trusted repo.
    reg.record_trust(root, _st.ALLOWED, decided_by="operator")
    import shutil
    shutil.rmtree(os.path.join(root, ".git"))
    link = os.path.join(root, ".git")
    os.symlink(outside, link)
    calls = []
    res = _assert_code(
        lambda: _st.checked_spawn(["status"], root, reg,
                                  spawn=_spawner(calls)),
        "repo-hook-escape-refused")
    if res["verdict"] != "held":
        return res
    if calls:
        return {"verdict": "gap",
                "note": "spawn invoked %d times despite escape" % len(calls)}
    return {"verdict": "held"}


@_sit("trust-ordering-first")
def _p_trust_ordering_first():
    """Untrusted + hostile config: trust fires first, scan never runs."""
    need = _need()
    if need:
        return need
    import gov.git_sanitize as _gs
    tmp = os.environ.get("TMPDIR", "/tmp")
    root = _repo(tmp, "w244-ordering", fsmonitor="/bin/true")
    reg = _st.TrustRegistry()
    order = []
    orig_state = reg.state_of
    orig_deny = _gs.deny_config_keys

    def spy_state(path):
        order.append("trust")
        return orig_state(path)

    def spy_deny(path):
        order.append("config-scan")
        return orig_deny(path)

    reg.state_of = spy_state
    _gs.deny_config_keys = spy_deny
    try:
        res = _assert_code(
            lambda: _st.checked_spawn(["status"], root, reg,
                                      spawn=_spawner([])),
            "repo-hook-pretrust-refused")
    finally:
        reg.state_of = orig_state
        _gs.deny_config_keys = orig_deny
    if res["verdict"] != "held":
        return res
    if order != ["trust"]:
        return {"verdict": "gap",
                "note": "call order wrong (scan ran pre-trust): %r"
                % (order,)}
    return {"verdict": "held"}


@_sit("trusted-hostile-still-denied")
def _p_trusted_hostile():
    """Verified-allowed + hostile config -> config denial still fires."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    root = _repo(tmp, "w244-trusted-hostile", fsmonitor="/bin/true")
    reg = _st.TrustRegistry()
    reg.record_trust(root, _st.ALLOWED, decided_by="operator")
    calls = []
    try:
        _st.checked_spawn(["status"], root, reg, spawn=_spawner(calls))
    except Exception as e:  # noqa: BLE001 - cross-module error type
        code = getattr(e, "code", type(e).__name__)
        if code != "gitspawn-hostile-config":
            return {"verdict": "gap",
                    "note": "wrong code for trusted+hostile: %s" % code}
        if calls:
            return {"verdict": "gap",
                    "note": "spawn ran despite hostile config"}
        return {"verdict": "held"}
    return {"verdict": "gap", "note": "hostile config spawned when trusted"}


@_sit("denied-refused")
def _p_denied():
    """Verified-denied repo -> explicit denial refusal."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    root = _repo(tmp, "w244-denied")
    reg = _st.TrustRegistry()
    reg.record_trust(root, _st.DENIED, decided_by="operator")
    calls = []
    res = _assert_code(
        lambda: _st.checked_spawn(["status"], root, reg,
                                  spawn=_spawner(calls)),
        "repo-hook-trust-denied")
    if res["verdict"] != "held":
        return res
    if calls:
        return {"verdict": "gap",
                "note": "spawn invoked %d times on denied repo" % len(calls)}
    return {"verdict": "held"}


@_sit("audit-redaction")
def _p_audit_redaction():
    """Refusal is audit-logged; hook path and config values are redacted."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    secret_hook = "/bin/touch S3CR3T-hook-path"
    root = _repo(tmp, "w244-audit", fsmonitor=secret_hook)
    reg = _st.TrustRegistry()
    records = []
    try:
        _st.checked_spawn(["status"], root, reg, spawn=_spawner([]),
                          audit=records.append)
    except _st.SessionTrustError:
        pass
    if not records:
        return {"verdict": "gap", "note": "no audit record emitted"}
    blob = repr(records)
    if "repo-hook-pretrust-refused" not in blob:
        return {"verdict": "gap", "note": "code missing from audit record"}
    if "S3CR3T-hook-path" in blob or "fsmonitor" in blob:
        return {"verdict": "gap",
                "note": "hook path or config key leaked into audit"}
    return {"verdict": "held"}


@_sit("malformed-record-refused")
def _p_malformed_record():
    """Invented trust states -> session-trust-malformed."""
    need = _need()
    if need:
        return need
    tmp = os.environ.get("TMPDIR", "/tmp")
    root = _repo(tmp, "w244-malformed")
    reg = _st.TrustRegistry()
    res = _assert_code(
        lambda: reg.record_trust(root, "totally-trusted",
                                 decided_by="operator"),
        "session-trust-malformed")
    if res["verdict"] != "held":
        return res
    res = _assert_code(
        lambda: reg.record_trust(root, _st.ALLOWED, decided_by=""),
        "session-trust-malformed")
    if res["verdict"] != "held":
        return res
    if reg.state_of(root) != _st.UNTRUSTED:
        return {"verdict": "gap",
                "note": "malformed record changed the trust state"}
    return {"verdict": "held"}


def run_all():
    for sid in PROBE_NAMES:
        SITUATIONS[sid]()
    held = sum(1 for r in RESULTS if r["verdict"] == "held")
    gap = sum(1 for r in RESULTS if r["verdict"] == "gap")
    errors = sum(1 for r in RESULTS if r["verdict"] == "error")
    return held, gap, errors


def green_check_adjacent():
    """Depth-1 green check: adjacent wave-243 batteries must hold.

    Honored GOV_SKIP_GREEN: a parent's green check records a skip
    instead of spawning nested battery mains.
    """
    if GREEN_SKIP:
        return {"skipped": "GOV_SKIP_GREEN=1 (depth-1 green check)"}
    import subprocess
    repo = os.path.join(os.path.dirname(__file__), "..")
    adj = [
        "evals/w243_cosign_interop_probes.py",
        "evals/w243_finality_bound_probes.py",
        "evals/w243_transactional_tokens_probes.py",
        "evals/w243_action_bound_permits_probes.py",
        "evals/w243_attested_channel_probes.py",
        "evals/w243_outcome_vocabulary_probes.py",
        "evals/w243_verifier_failclosed_probes.py",
        "evals/w243_effect_agreement_probes.py",
        "evals/w243_threat_model_probes.py",
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    out = {}
    for rel in adj:
        path = os.path.join(repo, rel)
        if not os.path.exists(path):
            out[rel] = "missing"
            continue
        try:
            p = subprocess.run(
                [sys.executable, path], env=env, cwd=repo,
                capture_output=True, text=True, timeout=600)
            out[rel] = "rc=%d" % p.returncode
        except Exception as e:  # noqa: BLE001
            out[rel] = "error: %s" % e
    return out


def main():
    held, gap, errors = run_all()
    print("w244_session_trust_ordering: %d held / %d gap / %d errors "
          "of %d" % (held, gap, errors, len(PROBE_NAMES)))
    for r in RESULTS:
        print("  %s: %s %s" % (r["id"], r["verdict"], r["detail"]))
    green = green_check_adjacent()
    print("adjacent green check: %s" % (green,))
    bad = [k for k, v in green.items()
           if isinstance(v, str) and not v.startswith("rc=0")]
    rc = 0
    if gap or errors or bad:
        rc = 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
