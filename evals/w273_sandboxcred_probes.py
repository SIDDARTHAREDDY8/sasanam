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

TAXONOMY_PIN = 2121 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*)



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
