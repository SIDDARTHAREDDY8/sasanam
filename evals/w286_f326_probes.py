"""Wave-286 lane 2 red-first battery: F326 (LOW) -- rekey ceremonies
skip the bundle_scope creation-rule check.

Base: wave-285 push 76e0f24. ``seal_envelope`` refuses a bundle whose
id is outside the policy's ``bundle_scope`` (coded
``recipient-policy-invalid``), but ``update_wraps`` and
``rotate_envelope`` call ``_seal_with_key`` directly and re-seal under a
non-covering policy.

Red-first: on the pristine base the two defect probes BREAK (the
cross-scope re-seal succeeds); after the fix all probes HELD, in
staging and under env -u GOV_DEPLOYMENT_MODE. No new decision codes
are introduced -- the existing ``recipient-policy-invalid`` emission
is reused, so the taxonomy pin stays 1641.

$0 spend, synthetic/local, deterministic (secrets only for random
key material, never asserted on). Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g286-f326 && TMPDIR=/var/tmp/g286-f326 \
    ~/workspace/.gov-venv/bin/python evals/w286_f326_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g286-f326b \
    ~/workspace/.gov-venv/bin/python evals/w286_f326_probes.py
"""

import os
import re
import secrets
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w286-f326")
os.environ.setdefault("TMPDIR", "/var/tmp/g286-f326")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# F326 adds no new decision codes (reuses recipient-policy-invalid);
# pin stays at the wave-285 value 1641.
TAXONOMY_PIN = 1946 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_RESULTS = []

PLUGIN_META = ("envelope-scope", "direct", "held-vs-expected")
PROBE_METADATA = {}

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict,
                     "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs_module(probe_id):
    try:
        from gov import bundle_envelope as be
        return be
    except ImportError:
        _record(probe_id, "BREAK", "gov.bundle_envelope absent")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
            encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def _env(be, scope):
    """Seal bundle 'proj/a' under a policy scoped `scope` (offline
    recipient, so no custody provider is needed)."""
    priv = secrets.token_bytes(32)
    r = {"id": "a", "type": "offline",
         "x25519_pub": be.x25519_pub(priv).hex()}
    policy = be.make_recipient_policy([r], bundle_scope=scope)
    seed = secrets.token_bytes(32)
    env = be.seal_envelope(b"data", bundle_id="proj/a", policy=policy,
                           signer_seed=seed)
    return env, priv, seed, policy


def _narrow(be):
    """A valid policy whose scope does NOT cover 'proj/a'."""
    priv = secrets.token_bytes(32)
    r = {"id": "a", "type": "offline",
         "x25519_pub": be.x25519_pub(priv).hex()}
    return be.make_recipient_policy([r], bundle_scope="other/")


def _expect_coded_refusal(probe_id, fn, label):
    """Run fn(); HELD iff it raises with code == 'recipient-policy-invalid'.
    On base the ceremony succeeds -> BREAK."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "recipient-policy-invalid":
            _record(probe_id, "HELD",
                    "%s refused LOUD with recipient-policy-invalid" % label)
        else:
            _record(probe_id, "BREAK",
                    "%s refused but with uncoded/wrong code %r -- the "
                    "close-when demands recipient-policy-invalid" % (label,
                                                                      code))
        return
    _record(probe_id, "BREAK",
            "%s re-sealed bundle 'proj/a' under policy scoped 'other/' "
            "-- no recipient-policy-invalid refusal" % label)


def _expect_success(probe_id, fn, label):
    """Guard against over-refusal: a covering policy must still work."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(probe_id, "BREAK",
                "%s failed under a COVERING policy: %r (over-refusal)"
                % (label, e))
        return
    _record(probe_id, "HELD",
            "%s succeeds under a covering policy (no over-refusal)" % label)


# ---------------------------------------------------------------------------
# Defect probes (BREAK on base, HELD after the fix)
# ---------------------------------------------------------------------------

def p_module_present():
    be = _needs_module("module-present")
    if be is None:
        return
    _record("module-present", "HELD", "gov.bundle_envelope importable")


def p_update_wraps_scope_refused():
    be = _needs_module("update-wraps-scope-refused")
    if be is None:
        return
    env, priv, seed, _ = _env(be, "proj/")
    narrow = _narrow(be)
    _expect_coded_refusal(
        "update-wraps-scope-refused",
        lambda: be.update_wraps(env, recipient_id="a", x25519_priv=priv,
                                new_policy=narrow, signer_seed=seed),
        "update_wraps")


def p_rotate_scope_refused():
    be = _needs_module("rotate-scope-refused")
    if be is None:
        return
    env, priv, seed, _ = _env(be, "proj/")
    narrow = _narrow(be)
    _expect_coded_refusal(
        "rotate-scope-refused",
        lambda: be.rotate_envelope(env, recipient_id="a", x25519_priv=priv,
                                   policy=narrow, signer_seed=seed),
        "rotate_envelope")


def p_update_wraps_prefix_boundary():
    be = _needs_module("update-wraps-prefix-boundary")
    if be is None:
        return
    # "pro/" is not a prefix of "proj/a" under the existing creation-rule
    # semantics -- the ceremony must inherit the exact boundary.
    env, priv, seed, _ = _env(be, "proj/")
    priv2 = secrets.token_bytes(32)
    r = {"id": "a", "type": "offline",
         "x25519_pub": be.x25519_pub(priv2).hex()}
    boundary = be.make_recipient_policy([r], bundle_scope="pro/")
    _expect_coded_refusal(
        "update-wraps-prefix-boundary",
        lambda: be.update_wraps(env, recipient_id="a", x25519_priv=priv,
                                new_policy=boundary, signer_seed=seed),
        "update_wraps (prefix boundary)")


# ---------------------------------------------------------------------------
# No-over-refusal guards (HELD on base AND after the fix)
# ---------------------------------------------------------------------------

def p_update_wraps_scope_ok():
    be = _needs_module("update-wraps-scope-ok")
    if be is None:
        return
    env, priv, seed, _ = _env(be, "proj/")
    priv2 = secrets.token_bytes(32)
    r = {"id": "a", "type": "offline",
         "x25519_pub": be.x25519_pub(priv2).hex()}
    covering = be.make_recipient_policy([r], bundle_scope="proj/")
    _expect_success(
        "update-wraps-scope-ok",
        lambda: be.update_wraps(env, recipient_id="a", x25519_priv=priv,
                                new_policy=covering, signer_seed=seed),
        "update_wraps")


def p_rotate_scope_ok():
    be = _needs_module("rotate-scope-ok")
    if be is None:
        return
    env, priv, seed, _ = _env(be, "proj/")
    priv2 = secrets.token_bytes(32)
    r = {"id": "a", "type": "offline",
         "x25519_pub": be.x25519_pub(priv2).hex()}
    covering = be.make_recipient_policy([r], bundle_scope="proj/")
    _expect_success(
        "rotate-scope-ok",
        lambda: be.rotate_envelope(env, recipient_id="a", x25519_priv=priv,
                                   policy=covering, signer_seed=seed),
        "rotate_envelope")


def p_rotate_star_scope_ok():
    be = _needs_module("rotate-star-scope-ok")
    if be is None:
        return
    env, priv, seed, _ = _env(be, "proj/")
    priv2 = secrets.token_bytes(32)
    r = {"id": "a", "type": "offline",
         "x25519_pub": be.x25519_pub(priv2).hex()}
    star = be.make_recipient_policy([r], bundle_scope="*")
    _expect_success(
        "rotate-star-scope-ok",
        lambda: be.rotate_envelope(env, recipient_id="a", x25519_priv=priv,
                                   policy=star, signer_seed=seed),
        "rotate_envelope")


def p_taxonomy_pin():
    lits = _literals()
    uniq = sorted(set(lits))
    if len(lits) != TAXONOMY_PIN or len(uniq) != TAXONOMY_PIN \
            or uniq != sorted(lits):
        _record("taxonomy-pin", "BREAK",
                "taxonomy %d raw / %d unique (pin %d)"
                % (len(lits), len(uniq), TAXONOMY_PIN))
        return
    if "recipient-policy-invalid" not in uniq:
        _record("taxonomy-pin", "BREAK",
                "recipient-policy-invalid missing from taxonomy")
        return
    _record("taxonomy-pin", "HELD",
            "%d/%d/0 sorted, recipient-policy-invalid present (no new "
            "codes for F326)" % (len(lits), len(uniq)))


def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        # Adjacent: the SOPS lane battery covers bundle_envelope.py
        # end-to-end (seal/open/rotate/updatekeys).
        ("evals/w284_sops_probes.py", 0),
    ]
    for rel, expected_breaks in checks:
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), rel)
        d = tempfile.mkdtemp(prefix="w286-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=900,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r"
                    % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != expected_breaks:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)"
                    % (nbreak, expected_breaks))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % nbreak)


_PROBES = [
    p_module_present,
    p_update_wraps_scope_refused,
    p_rotate_scope_refused,
    p_update_wraps_prefix_boundary,
    p_update_wraps_scope_ok,
    p_rotate_scope_ok,
    p_rotate_star_scope_ok,
    p_taxonomy_pin,
]


def main():
    for probe in _PROBES:
        try:
            probe()
        except Exception as e:  # noqa: BLE001
            _record(probe.__name__, "ERROR", "probe raised: %r" % (e,))
    _green_checks()
    nbreak = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    nheld = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    nerr = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    print("== w286_f326_probes: %d BREAK / %d HELD / %d ERROR =="
          % (nbreak, nheld, nerr))
    for r in _RESULTS:
        if r["verdict"] != "HELD":
            print("  %s %s: %s" % (r["verdict"], r["probe_id"],
                                   r["note"]))
    return 1 if (nbreak or nerr) else 0


if __name__ == "__main__":
    sys.exit(main())
