"""Wave-273 lane H battery: sandbox fail-closed on real credentials.

GTG-50020 (Anthropic Sep-2026 threat report): injected instructions in an
eval sandbox caused the sandboxed agent to hand over production API keys.
Sasanam's sentinel substitution keeps real credentials out of the agent's
view (``fake_value_<uuid>`` placeholders), but the sandbox boundary itself
was fail-OPEN: any value in ``extra_env`` / ``allowed_env`` passthrough /
argv / stdin reached the (untrusted) child unexamined.

Claim under test: when a :class:`Sandbox` is constructed with a
``sentinel_vault``, any child-bound value that is byte-equal to a
vault-registered REAL credential value is refused LOUDLY before spawn
(``SandboxError`` + ``sandbox-real-credential-blocked`` refusal record);
sentinel placeholders and unregistered values pass through unchanged.

Red phase (``SANDBOXCRED_IMPL=stub``): the foil is the base behavior — a
plain :class:`Sandbox` with no vault. Attack probes MUST BREAK (the real
value reaches the child: the gap). Green phase (default): the vault-bound
sandbox MUST HOLD every attack.

Deterministic. Module-level staging default. Depth-1 green check honoring
GOV_SKIP_GREEN. No in-repo git subprocesses. Fresh /var/tmp/g273* TMPDIRs.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import sandbox as sb  # noqa: E402
from gov import sentinel_substitution as sent  # noqa: E402

TAXONOMY_PIN = 2144  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144


IMPL = os.environ.get("SANDBOXCRED_IMPL", "real")

# DLP-clean synthetic credential (registration refuses credential-shaped
# values by prototype rule); distinct from any real secret.
REAL_VALUE = "synthetic-api-token-wave273-0042"
REAL_VALUE_2 = "synthetic-api-token-wave273-0043"
BENIGN_ENTROPY = "a3f9c2e1b4d60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5"
SENTINEL_PLACEHOLDER = "fake_value_12345678-1234-1234-1234-1234567890ab"

RESULTS = []


def probe(name, fn):
    try:
        held, detail = fn()
    except Exception as e:  # noqa: BLE001
        RESULTS.append((name, "ERROR", "harness error: %r" % (e,)))
        return
    RESULTS.append((name, "HELD" if held else "BREAK", detail))


def _vault():
    v = sent.SentinelVault()
    v.register("cred-1", REAL_VALUE, ["api.example.com"],
               credential_class="api-key", release_policy="legacy-host-only")
    v.register("cred-2", REAL_VALUE_2, ["api.example.com"],
               credential_class="api-key", release_policy="legacy-host-only")
    return v


def _box(**kw):
    """Sandbox under test: vault-bound in green, plain in red (the foil)."""
    if IMPL == "stub":
        kw.pop("sentinel_vault", None)
        return sb.Sandbox(**kw)
    kw.setdefault("sentinel_vault", _vault())
    return sb.Sandbox(**kw)


_CHILD_ENV_ECHO = (
    "import os,sys;sys.stdout.write(os.environ.get('W273_PROBE','ABSENT'))")
_CHILD_ARGV_ECHO = "import sys;sys.stdout.write(sys.argv[1])"
_CHILD_STDIN_ECHO = "import sys;sys.stdout.write(sys.stdin.read())"


def _run_env_probe(box, value):
    r = box.run([sys.executable, "-I", "-c", _CHILD_ENV_ECHO],
                extra_env={"W273_PROBE": value})
    return r


# ---------------------------------------------------------------------------
# Attacks: must BREAK in red (stub), HELD in green (real)
# ---------------------------------------------------------------------------

def _attempted_crossing(box, run_fn, real_value):
    """Shared refusal verdict for the five crossing attacks.

    ``run_fn(box)`` performs the child run whose boundary value may
    carry the real credential. Returns (held, detail).
    """
    try:
        r = run_fn(box)
    except sb.SandboxError as e:
        msg = str(e)
        held = ("sandbox-real-credential-blocked" in msg
                and real_value not in msg)
        return held, "refused loud, value not in message: %s" % held
    crossed = real_value in (r.stdout or "")
    if IMPL == "stub":
        return (not crossed), "stub: credential %s the child" % (
            "CROSSED to" if crossed else "did not reach")
    return False, "GREEN FAILURE: no refusal, crossed=%s" % crossed


def a01_env_crossing():
    """Real credential in extra_env must not reach the child."""
    box = _box()
    return _attempted_crossing(
        box, lambda b: _run_env_probe(b, REAL_VALUE), REAL_VALUE)


def a02_argv_crossing():
    """Real credential as an argv element must not reach the child."""
    box = _box()
    return _attempted_crossing(
        box,
        lambda b: b.run([sys.executable, "-I", "-c", _CHILD_ARGV_ECHO,
                         REAL_VALUE]),
        REAL_VALUE)


def a03_stdin_crossing():
    """Real credential as stdin_data must not reach the child."""
    box = _box()
    return _attempted_crossing(
        box,
        lambda b: b.run([sys.executable, "-I", "-c", _CHILD_STDIN_ECHO],
                        stdin_data=REAL_VALUE.encode("utf-8")),
        REAL_VALUE)


def a04_allowed_env_passthrough():
    """Real credential via allowed_env os.environ passthrough (the
    operator-env crossing: e.g. a real key sitting in the parent env)."""
    os.environ["W273_ALLOWED_CRED"] = REAL_VALUE
    try:
        box = _box(allowed_env=["W273_ALLOWED_CRED"])

        def _run(b):
            return b.run([sys.executable, "-I", "-c",
                          "import os,sys;sys.stdout.write("
                          "os.environ.get('W273_ALLOWED_CRED','ABSENT'))"])
        return _attempted_crossing(box, _run, REAL_VALUE)
    finally:
        del os.environ["W273_ALLOWED_CRED"]


def a05_second_credential():
    """A second registered credential is caught too (not just cred-1)."""
    box = _box()
    return _attempted_crossing(
        box, lambda b: _run_env_probe(b, REAL_VALUE_2), REAL_VALUE_2)


# ---------------------------------------------------------------------------
# Controls: must be HELD in both phases
# ---------------------------------------------------------------------------

def c01_sentinel_passthrough():
    """Sentinel placeholders must pass through untouched (the legitimate
    agent-visible form)."""
    box = _box()
    r = _run_env_probe(box, SENTINEL_PLACEHOLDER)
    ok = r.ok and SENTINEL_PLACEHOLDER in (r.stdout or "")
    return ok, "placeholder reached child intact: %s" % ok


def c02_benign_entropy_passthrough():
    """Unregistered high-entropy values must NOT trip the screen (no
    false-positive refusals on session tokens / nonces)."""
    box = _box()
    r = _run_env_probe(box, BENIGN_ENTROPY)
    ok = r.ok and BENIGN_ENTROPY in (r.stdout or "")
    return ok, "benign value passed, no refusal: %s" % ok


def c03_legacy_opt_in():
    """Without a vault the sandbox behaves exactly as before (opt-in;
    no behavior change for existing deployments)."""
    box = sb.Sandbox()
    r = _run_env_probe(box, REAL_VALUE)
    crossed = REAL_VALUE in (r.stdout or "")
    return crossed, "legacy no-vault run crosses (unchanged): %s" % crossed


def c04_refusal_receipt_redacted():
    """The loud refusal leaves a structured receipt that names the
    carrier and key but NEVER the credential value."""
    import tempfile
    d = tempfile.mkdtemp(prefix="w273-receipt-")
    box = _box(refusal_receipt_dir=d)
    if IMPL == "stub":
        # No vault: no refusal is the (legacy) behavior.
        r = _run_env_probe(box, REAL_VALUE)
        return (REAL_VALUE in (r.stdout or ""),
                "stub: no refusal configured, legacy crossing stands")
    try:
        _run_env_probe(box, REAL_VALUE)
    except sb.SandboxError:
        pass
    else:
        return False, "expected SandboxError, run succeeded"
    import glob
    receipts = glob.glob(os.path.join(d, "*.jsonl"))
    if not receipts:
        return False, "no refusal receipt written"
    with open(receipts[0], encoding="utf-8") as fh:
        body = fh.read()
    has_kind = "sandbox-real-credential-blocked" in body
    no_value = REAL_VALUE not in body
    return (has_kind and no_value,
            "receipt has kind=%s, value redacted=%s" % (has_kind, no_value))


def c05_normal_run_unaffected():
    """A vault-bound sandbox still runs ordinary commands fine."""
    box = _box()
    r = box.run([sys.executable, "-I", "-c", "print('hello')"])
    return (r.ok and "hello" in (r.stdout or ""),
            "ordinary run ok: %s" % r.ok)


def c06_pin():
    import re
    with open(os.path.join(os.path.dirname(__file__), "..",
                           "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    codes = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if IMPL == "stub":
        # Red phase: the feature is absent; the tree must be untouched.
        ok = (len(codes) == 1443 and len(set(codes)) == 1443
              and "sandbox-real-credential-blocked" not in set(codes))
        return ok, "red phase: base pin 1443 intact, code absent: %s" % ok
    ok = (len(codes) == TAXONOMY_PIN and len(set(codes)) == TAXONOMY_PIN
          and "sandbox-real-credential-blocked" in set(codes))
    return ok, "pin %d/%d unique, new code present" % (
        len(codes), len(set(codes)))


def main():
    probe("a01-env-crossing", a01_env_crossing)
    probe("a02-argv-crossing", a02_argv_crossing)
    probe("a03-stdin-crossing", a03_stdin_crossing)
    probe("a04-allowed-env-passthrough", a04_allowed_env_passthrough)
    probe("a05-second-credential", a05_second_credential)
    probe("c01-sentinel-passthrough", c01_sentinel_passthrough)
    probe("c02-benign-entropy-passthrough", c02_benign_entropy_passthrough)
    probe("c03-legacy-opt-in", c03_legacy_opt_in)
    probe("c04-refusal-receipt-redacted", c04_refusal_receipt_redacted)
    probe("c05-normal-run-unaffected", c05_normal_run_unaffected)
    probe("c06-pin", c06_pin)

    if os.environ.get("GOV_SKIP_GREEN"):
        print("green check SKIPPED (GOV_SKIP_GREEN=1)")
    else:
        import subprocess
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = os.environ.get("TMPDIR", "/tmp")
        gc = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), "w35_sandbox_probes.py")],
            capture_output=True, text=True, env=env, timeout=600)
        RESULTS.append(("green:w35_sandbox_probes",
                        "HELD" if gc.returncode == 0 else "BREAK",
                        "rc=%d" % gc.returncode))

    n_held = sum(1 for _, s, _ in RESULTS if s == "HELD")
    n_break = sum(1 for _, s, _ in RESULTS if s == "BREAK")
    n_err = sum(1 for _, s, _ in RESULTS if s == "ERROR")
    for name, status, detail in RESULTS:
        print("%-32s %-6s %s" % (name, status, detail))
    print("== %d HELD / %d BREAK / %d ERROR (impl=%s) =="
          % (n_held, n_break, n_err, IMPL))
    return 0 if (n_break == 0 and n_err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
