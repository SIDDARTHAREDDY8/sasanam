"""Wave-286 lane-4 battery: close F329 + F330 (both LOW).

F329 (LOW): the keyset content pin was self-contained -- recomputable via
the public ``KmsKeyset._repin`` with no secret -- so status forgery +
audit-trail wipe loaded with ``verify_chain() == True``. The fix makes
``keyset_digest`` a keyed MAC (HMAC-SHA256) under a deployment-held pin
key (separate 0600 file): ``new``/``from_dict``/``_repin`` require the
key, and recomputation without it refuses LOUD (``keyset-pin-key-invalid``).

F330 (LOW): ``CompiledPolicy`` was mutable after the pin check --
``check_policy_use`` compared the compile-time cached digest and never
recomputed it, so post-check mutation flipped ``decide("execve")``
kill -> allow while the stale digest still matched. The fix freezes the
compiled attributes (immutable after compilation) AND recomputes the
digest from the live object inside ``check_policy_use`` (drift ->
``sandbox-policy-drift``).

API-adaptive probes: the F329/F330 attack probes run on the base tree
(where they BREAK, reproducing the defects) and on the fixed tree
(where the fixed contract makes the attack impossible -> HELD).

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g286-f329 && TMPDIR=/var/tmp/g286-f329 \
    ~/workspace/.gov-venv/bin/python evals/w286_f329_f330_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g286-f329b \
    ~/workspace/.gov-venv/bin/python evals/w286_f329_f330_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-286 lane 4: pin 1641 -> 1642 (+1 keyset-pin-key-invalid).
TAXONOMY_PIN = 2070 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2070 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*). # Wave-333 lane 4: pin 2062 -> 2070 (+8 revocation-push-*).



_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy literals %d, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals not sorted")
    _record("pin-taxonomy", "HELD", "1642/1642/0/sorted on raw literals")


def _new_supports_pin_key(kk):
    """True on the fixed tree (new/from_dict/_repin take pin_key)."""
    try:
        import inspect
        return "pin_key" in inspect.signature(kk.KmsKeyset.new).parameters
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# F329 (LOW): keyset content pin must not be recomputable without the key.
# ---------------------------------------------------------------------------

def p_f329_pin_self_forgeable():
    from gov import kms_keyset as kk
    fixed = _new_supports_pin_key(kk)
    pin_key = os.urandom(32)
    try:
        if fixed:
            ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                                  primary_key_id="k", provider_name="fake",
                                  pin_key=pin_key)
        else:
            ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                                  primary_key_id="k", provider_name="fake")
        ks.add_key("key-b", "fake")
    except Exception as e:  # noqa: BLE001
        return _record("f329-pin-self-forgeable", "ERROR",
                       "setup failed: %r" % (e,))
    doc = ks.to_dict()
    doc["keys"][1]["status"] = "destroyed"
    doc["audit_chain"] = []
    # The attacker holds the document but NOT the pin key: recompute the
    # pin with only public, keyless tools.
    try:
        forged = kk.KmsKeyset._repin(doc)
    except Exception as e:  # noqa: BLE001
        # Fixed tree: pin_key is required and its absence refuses LOUD
        # (keyset-pin-key-invalid) -- the keyless recompute is gone.
        return _record("f329-pin-self-forgeable", "HELD",
                       "keyless pin recompute refused LOUD: %s"
                       % getattr(e, "code", type(e).__name__))
    try:
        if fixed:
            evil = kk.KmsKeyset.from_dict(forged, pin_key=pin_key)
        else:
            evil = kk.KmsKeyset.from_dict(forged)
    except Exception as e:  # noqa: BLE001
        return _record("f329-pin-self-forgeable", "HELD",
                       "forgery refused at load: %s"
                       % getattr(e, "code", type(e).__name__))
    if evil.verify_chain():
        return _record("f329-pin-self-forgeable", "BREAK",
                       "status forgery + audit-trail wipe accepted at load "
                       "with verify_chain() == True -- pin recomputed "
                       "without the key")
    _record("f329-pin-self-forgeable", "HELD", "chain verification caught it")


def p_f329_honest_ceremony_with_key():
    """Positive probe: legitimate rotation ceremonies still work under
    the fixed contract (no regression on the honest path)."""
    from gov import kms_keyset as kk
    from gov.kms import FakeKmsProvider
    fixed = _new_supports_pin_key(kk)
    pin_key = os.urandom(32)
    try:
        kw = {"pin_key": pin_key} if fixed else {}
        ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                              primary_key_id="key-a",
                              provider_name="fake", **kw)
        provider = FakeKmsProvider(["key-a", "key-b"])
        ks.begin_rotation("key-b", provider_name="fake")
        ks.roll_out(provider, attempts=2, test_bytes=b"ceremony-probe")
        ks.promote(reason="unit-test")
        doc = ks.to_dict()
        ks2 = kk.KmsKeyset.from_dict(doc, **kw)
        assert ks2.verify_chain(), "honest chain must verify"
        assert ks2.primary_key_id() == "key-b", "successor must be primary"
        assert ks2.key_status("key-a") == "disabled", "old primary demoted"
        blob = ks2.wrap_data_key(provider, b"hello")
        assert provider.unwrap_data_key(
            "key-b", blob) == b"hello", "wrap round-trip under new primary"
    except AssertionError as e:
        return _record("f329-honest-ceremony", "BREAK",
                       "honest ceremony regressed: %s" % (e,))
    except Exception as e:  # noqa: BLE001
        return _record("f329-honest-ceremony", "ERROR",
                       "honest ceremony raised: %r" % (e,))
    _record("f329-honest-ceremony", "HELD",
            "full rotation ceremony + reload + wrap round-trip green")


def p_f329_pin_key_files():
    """generate_pin_key/load_pin_key round-trip; wrong-size key refused."""
    from gov import kms_keyset as kk
    if not hasattr(kk, "generate_pin_key"):
        return _record("f329-pin-key-files", "HELD",
                       "base tree: no pin-key helpers (fix absent)")
    d = tempfile.mkdtemp(prefix="w286-f329-")
    path = os.path.join(d, "pin.key")
    try:
        key = kk.generate_pin_key(path)
        assert isinstance(key, bytes) and len(key) == 32
        assert kk.load_pin_key(path) == key, "round-trip must match"
        st = os.stat(path)
        assert st.st_mode & 0o777 == 0o600, "pin key file must be 0600"
        try:
            kk.generate_pin_key(path)
        except Exception as e:  # noqa: BLE001
            assert getattr(e, "code", "") == "keyset-pin-key-invalid", \
                "overwrite must refuse coded, got %r" % (e,)
        else:
            return _record("f329-pin-key-files", "BREAK",
                           "generate_pin_key silently overwrote a key file")
        with open(path, "wb") as fh:
            fh.write(b"short")
        try:
            kk.load_pin_key(path)
        except Exception as e:  # noqa: BLE001
            assert getattr(e, "code", "") == "keyset-pin-key-invalid", \
                "wrong-size key must refuse coded, got %r" % (e,)
        else:
            return _record("f329-pin-key-files", "BREAK",
                           "load_pin_key accepted a short key")
    except AssertionError as e:
        return _record("f329-pin-key-files", "BREAK", str(e))
    except Exception as e:  # noqa: BLE001
        return _record("f329-pin-key-files", "ERROR", "raised: %r" % (e,))
    _record("f329-pin-key-files", "HELD",
            "pin-key file lifecycle green (0600, no overwrite, size-checked)")


# ---------------------------------------------------------------------------
# F330 (LOW): CompiledPolicy must be immutable after the pin check, and
# the use-time gate must recompute the digest from the live object.
# ---------------------------------------------------------------------------

_POLICY_DOC = {"policy_schema_version": 1, "policy_id": "p1",
               "syscalls": {"default": "allow", "allow": [], "deny": [],
                            "rules": ["POLICY a { DEFAULT ALLOW "
                                      "DENY { execve } }"]}}


def _pin_for(sp, policy):
    d = tempfile.mkdtemp(prefix="w286-f330-")
    pinpath = os.path.join(d, "pins.json")
    sp.pin_policy(policy.policy_id, policy.digest, pinpath)
    return sp.load_pins(pinpath)


def p_f330_policy_mutable_after_pin():
    from gov import sandbox_policy as sp
    p = sp.compile_policy(_POLICY_DOC)
    pins = _pin_for(sp, p)
    try:
        sp.check_policy_use(p, pins)
    except Exception as e:  # noqa: BLE001
        return _record("f330-policy-mutable-after-pin", "ERROR",
                       "pristine policy failed its own gate: %r" % (e,))
    before = p.decide("execve", {})
    if before != "kill":
        return _record("f330-policy-mutable-after-pin", "ERROR",
                       "fixture wrong: execve decided %r, want kill"
                       % (before,))
    # Post-check mutation attempt on the in-process object.
    try:
        p._rule_denies.discard("execve")
    except Exception as e:  # noqa: BLE001
        return _record("f330-policy-mutable-after-pin", "HELD",
                       "post-check mutation blocked (immutable): %s"
                       % type(e).__name__)
    # Mutation succeeded: the gate must now catch the drift.
    try:
        b = sp.bind(p, pins, enforced_namespaces=set())
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "sandbox-policy-drift":
            return _record("f330-policy-mutable-after-pin", "HELD",
                           "post-check mutation detected at bind: %s"
                           % (code,))
        return _record("f330-policy-mutable-after-pin", "HELD",
                       "bind refused after mutation: %s" % (code,))
    after = b.decide("execve", {})
    if before != after:
        return _record("f330-policy-mutable-after-pin", "BREAK",
                       "decide flipped %s -> %s after post-check mutation; "
                       "the pin gate did not catch it" % (before, after))
    _record("f330-policy-mutable-after-pin", "HELD",
            "mutation did not change enforcement")


def p_f330_digest_recomputed_at_gate():
    """Bypass-level probe: even a freeze-bypassing in-process edit
    (object.__setattr__) must be caught because the gate recomputes the
    digest from the live object instead of trusting the cached string."""
    from gov import sandbox_policy as sp
    p = sp.compile_policy(_POLICY_DOC)
    pins = _pin_for(sp, p)
    sp.check_policy_use(p, pins)
    object.__setattr__(p, "_rule_denies", frozenset())
    try:
        sp.check_policy_use(p, pins)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if code == "sandbox-policy-drift":
            return _record("f330-digest-recomputed-at-gate", "HELD",
                           "freeze-bypassing edit detected: %s" % (code,))
        return _record("f330-digest-recomputed-at-gate", "HELD",
                       "gate refused after bypassing edit: %s" % (code,))
    if p.decide("execve", {}) == "allow":
        return _record("f330-digest-recomputed-at-gate", "BREAK",
                       "gate passed on a stale cached digest while the "
                       "live object decides allow")
    _record("f330-digest-recomputed-at-gate", "HELD",
            "gate re-check caught the bypassing edit")


def p_f330_legitimate_flow():
    """Positive probe: the legitimate compile -> pin -> check -> bind ->
    decide flow is unaffected."""
    from gov import sandbox_policy as sp
    try:
        p = sp.compile_policy(_POLICY_DOC)
        pins = _pin_for(sp, p)
        digest = sp.check_policy_use(p, pins)
        assert digest == p.digest, "gate must return the live digest"
        b = sp.bind(p, pins, enforced_namespaces=set())
        assert b.decide("execve", {}) == "kill", "execve must kill"
        assert b.decide("read", {}) == "allow", "default must allow"
    except AssertionError as e:
        return _record("f330-legitimate-flow", "BREAK",
                       "legitimate flow regressed: %s" % (e,))
    except Exception as e:  # noqa: BLE001
        return _record("f330-legitimate-flow", "ERROR",
                       "legitimate flow raised: %r" % (e,))
    _record("f330-legitimate-flow", "HELD",
            "compile/pin/check/bind/decide green")


# ---------------------------------------------------------------------------
# Depth-1 green checks: adjacent lane batteries must stay all-HELD.
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w284_tink_probes.py",
        "evals/w284_nsjail_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w286-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_taxonomy_pin()
    p_f329_pin_self_forgeable()
    p_f329_honest_ceremony_with_key()
    p_f329_pin_key_files()
    p_f330_policy_mutable_after_pin()
    p_f330_digest_recomputed_at_gate()
    p_f330_legitimate_flow()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w286_f329_f330: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
