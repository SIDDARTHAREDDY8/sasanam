"""Break-first probes for the wave-259 identity-mesh lane.

Wave-259 lane 3 (identity-mesh: dex/SPIFFE/headscale follow-up).
Stdlib only. Deterministic across runs (staging + `env -u
GOV_DEPLOYMENT_MODE`).

Target (new in wave-259): gov/svid_issuer.py -- short-lived
SPIFFE-style workload identity documents (SVID-like:
{spiffe_id, trust_domain, issued_at, expires_at, public_key,
issuer_key_id, issuer_signature}) from a local TEST issuer, verified
at the mesh admission seam. D3 direction: headscale's identity-bound
control plane shape (namespaces as trust domains, default-deny ACL
policy as data) + cfssl's issuance layer (signing profiles as data,
parallel trust roots during rotation).

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Pre-fix (module absent) every probe reports GAP: the
capability does not exist. Post-fix each probe must report HELD:
the attack is refused with a machine code, never downgraded to a
deployment-vouched identity.

Verdicts: HELD (attack refused with the expected machine code),
BREAK (genuine defect -> file as F227+), GAP (capability absent,
pre-fix), BASELINE (known-open finding reproduced, not new).
"""

import os
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

try:
    from gov import svid_issuer as sv
    from gov import decision_codes  # noqa: E402
except ImportError:
    sv = None
    decision_codes = None

TAXONOMY_PIN = 1726  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 lane 2: pin 1723 -> 1726 (+3 toolcall-*: sequence-violated, secret-in-args, rule-compile-invalid)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _gap(detail=""):
    return ("GAP", detail)


def _break(detail=""):
    return ("BREAK", detail)


_SEED = bytes(range(32))
_OTHER_SEED = bytes([255 - b for b in range(32)])
_PUBKEY = "ab" * 32
_TD = "example.org"


def _issuer(seed=_SEED, key_id="test-issuer-1", **kw):
    return sv.TestSvidIssuer(issuer_seed=seed, key_id=key_id, **kw)


def _verifier(pubkey_seed=_SEED, key_id="test-issuer-1",
              trust_domain=_TD):
    from gov import ed25519 as _ed
    return sv.SvidVerifier(
        {"test-issuer-1" if key_id == "test-issuer-1" else key_id:
         _ed.publickey(pubkey_seed)},
        trust_domain=trust_domain)


def _expect_code(fn, code):
    """Run fn; HELD iff it raises SvidError with the exact code."""
    try:
        fn()
    except sv.SvidError as e:
        if e.code == code:
            return _held("refused %s" % code)
        return _break("wrong code %r, expected %r" % (e.code, code))
    except Exception as e:  # noqa: BLE001
        return _break("unexpected %s: %s" % (type(e).__name__, e))
    return _break("attack accepted: no refusal raised")


@probe("capability-present")
def p_capability():
    if sv is None:
        return _gap("gov/svid_issuer.py absent: no SVID primitive exists")
    return _held("module importable")


@probe("expired-svid-accepted")
def p_expired():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    doc = iss.issue("spiffe://example.org/agent/a", _PUBKEY, ttl_minutes=1,
                    now=1000.0)
    v = _verifier()
    return _expect_code(lambda: v.verify(doc, now=1000.0 + 120.0),
                        "svid-expired")


@probe("expiry-boundary")
def p_expiry_boundary():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    doc = iss.issue("spiffe://example.org/agent/a", _PUBKEY, ttl_minutes=1,
                    now=1000.0)
    v = _verifier()
    # now == expires_at refuses (now >= expires_at, same as the F224
    # short-lived-credential contract); just before accepts.
    r1 = _expect_code(lambda: v.verify(doc, now=1000.0 + 60.0),
                      "svid-expired")
    if r1[0] != "HELD":
        return r1
    try:
        v.verify(doc, now=1000.0 + 59.0)
    except Exception as e:  # noqa: BLE001
        return _break("valid SVID refused just before expiry: %s" % e)
    return _held("boundary exact: refused at, accepted before")


@probe("cross-trust-domain")
def p_cross_td():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    doc = iss.issue("spiffe://other.example/agent/a", _PUBKEY,
                    ttl_minutes=5, now=1000.0)
    v = _verifier(trust_domain="example.org")
    return _expect_code(lambda: v.verify(doc, now=1000.0),
                        "svid-trust-domain-mismatch")


@probe("trust-domain-lookalike")
def p_td_lookalike():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    # "example.org.evil" must NOT pass as trust domain "example.org":
    # exact equality, not prefix matching.
    doc = iss.issue("spiffe://example.org.evil/agent/a", _PUBKEY,
                    ttl_minutes=5, now=1000.0)
    v = _verifier(trust_domain="example.org")
    return _expect_code(lambda: v.verify(doc, now=1000.0),
                        "svid-trust-domain-mismatch")


@probe("forged-signature")
def p_forged_sig():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    doc = iss.issue("spiffe://example.org/agent/a", _PUBKEY, ttl_minutes=5,
                    now=1000.0)
    bad = dict(doc)
    sig = bytearray(bytes.fromhex(bad["issuer_signature"]))
    sig[0] ^= 0xFF
    bad["issuer_signature"] = bytes(sig).hex()
    v = _verifier()
    return _expect_code(lambda: v.verify(bad, now=1000.0),
                        "svid-signature-invalid")


@probe("signature-transplant")
def p_transplant():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    a = iss.issue("spiffe://example.org/agent/a", _PUBKEY, ttl_minutes=5,
                  now=1000.0)
    b = iss.issue("spiffe://example.org/agent/b", "cd" * 32,
                  ttl_minutes=5, now=1000.0)
    # Signature from A stapled onto B's document must not verify.
    forged = dict(b)
    forged["issuer_signature"] = a["issuer_signature"]
    v = _verifier()
    return _expect_code(lambda: v.verify(forged, now=1000.0),
                        "svid-signature-invalid")


@probe("field-tamper")
def p_field_tamper():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    doc = iss.issue("spiffe://example.org/agent/a", _PUBKEY, ttl_minutes=5,
                    now=1000.0)
    bad = dict(doc)
    bad["public_key"] = "00" * 32  # attacker's key, issuer's signature
    v = _verifier()
    return _expect_code(lambda: v.verify(bad, now=1000.0),
                        "svid-signature-invalid")


@probe("issuer-not-pinned")
def p_issuer_unknown():
    if sv is None:
        return _gap("no SVID primitive")
    rogue = _issuer(seed=_OTHER_SEED, key_id="rogue-issuer")
    doc = rogue.issue("spiffe://example.org/agent/a", _PUBKEY,
                      ttl_minutes=5, now=1000.0)
    v = _verifier()  # only pins test-issuer-1
    return _expect_code(lambda: v.verify(doc, now=1000.0),
                        "svid-issuer-unknown")


@probe("wrong-trust-root-key")
def p_wrong_root_key():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    doc = iss.issue("spiffe://example.org/agent/a", _PUBKEY, ttl_minutes=5,
                    now=1000.0)
    # Trust bundle binds test-issuer-1 to the WRONG public key: the
    # SVID must not verify (key confusion refused).
    v = _verifier(pubkey_seed=_OTHER_SEED)
    return _expect_code(lambda: v.verify(doc, now=1000.0),
                        "svid-signature-invalid")


@probe("ttl-stretched-by-caller")
def p_ttl_stretched():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()  # workload profile: max_ttl_minutes = 30
    return _expect_code(
        lambda: iss.issue("spiffe://example.org/agent/a", _PUBKEY,
                          ttl_minutes=60, now=1000.0),
        "svid-ttl-stretched")


@probe("ttl-unbounded-refused")
def p_ttl_unbounded():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    r = _expect_code(
        lambda: iss.issue("spiffe://example.org/agent/a", _PUBKEY,
                          ttl_minutes=None, now=1000.0),
        "svid-ttl-unbounded")
    if r[0] != "HELD":
        return r
    r = _expect_code(
        lambda: iss.issue("spiffe://example.org/agent/a", _PUBKEY,
                          ttl_minutes=0, now=1000.0),
        "svid-ttl-unbounded")
    if r[0] != "HELD":
        return r
    return _held("None and 0 TTL refused")


@probe("missing-svid")
def p_missing():
    if sv is None:
        return _gap("no SVID primitive")
    v = _verifier()
    return _expect_code(lambda: v.verify(None, now=1000.0),
                        "svid-missing")


@probe("malformed-now")
def p_malformed_now():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    doc = iss.issue("spiffe://example.org/agent/a", _PUBKEY, ttl_minutes=5,
                    now=1000.0)
    v = _verifier()
    import math
    for bad_now in (float("nan"), float("inf"), True, "now"):
        r = _expect_code(lambda bn=bad_now: v.verify(doc, now=bn),
                         "svid-malformed")
        if r[0] != "HELD":
            return _break("now=%r: %s" % (bad_now, r[1]))
    try:
        v.verify(doc, now=None)  # None -> time.time(); doc is long
        # expired -> the contract still validates and refuses expired.
    except sv.SvidError as e:
        if e.code != "svid-expired":
            return _break("now=None gave %r, expected svid-expired" %
                          e.code)
    return _held("NaN/inf/bool/str refused; None uses wall clock")


@probe("malformed-spiffe-id")
def p_malformed_id():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    for bad_id in ("", "not-a-uri", "spiffe://", "spiffe:///path",
                   "https://example.org/agent/a", "spiffe://ex ample/x"):
        r = _expect_code(
            lambda bi=bad_id: iss.issue(bi, _PUBKEY, ttl_minutes=5,
                                        now=1000.0),
            "svid-identity-malformed")
        if r[0] != "HELD":
            return _break("id=%r: %s" % (bad_id, r[1]))
    return _held("malformed IDs refused at issuance")


@probe("mesh-acl-default-deny")
def p_mesh_acl():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    doc = iss.issue("spiffe://example.org/agent/a", _PUBKEY, ttl_minutes=5,
                    now=1000.0)
    v = _verifier()
    gate = sv.MeshControl(v, {"allow": ["spiffe://example.org/ops/"]})
    r = _expect_code(lambda: gate.admit(doc, now=1000.0),
                     "svid-acl-denied")
    if r[0] != "HELD":
        return r
    ok_gate = sv.MeshControl(v, {"allow": ["spiffe://example.org/agent/"]})
    try:
        spiffe_id = ok_gate.admit(doc, now=1000.0)
    except Exception as e:  # noqa: BLE001
        return _break("allowlisted peer refused: %s" % e)
    if spiffe_id != "spiffe://example.org/agent/a":
        return _break("admit returned %r" % (spiffe_id,))
    return _held("default deny; allowlist prefix admits")


@probe("mesh-no-downgrade")
def p_mesh_no_downgrade():
    if sv is None:
        return _gap("no SVID primitive")
    iss = _issuer()
    doc = iss.issue("spiffe://example.org/agent/a", _PUBKEY, ttl_minutes=1,
                    now=1000.0)
    v = _verifier()
    gate = sv.MeshControl(v, {"allow": ["spiffe://example.org/agent/"]})
    # An expired SVID must refuse at the mesh seam: there is no flag,
    # env var, or fallback that admits an unverified peer.
    r = _expect_code(lambda: gate.admit(doc, now=1000.0 + 120.0),
                     "svid-expired")
    if r[0] != "HELD":
        return r
    if hasattr(gate, "insecure_skip_verify") or hasattr(
            sv.MeshControl, "insecure_skip_verify"):
        return _break("a skip-verification seam exists")
    src_attrs = [a for a in dir(gate) if "skip" in a.lower()
                 or "bypass" in a.lower() or "insecure" in a.lower()]
    if src_attrs:
        return _break("suspicious bypass attrs: %r" % (src_attrs,))
    return _held("no downgrade seam on MeshControl")


@probe("multi-root-rotation")
def p_multi_root():
    if sv is None:
        return _gap("no SVID primitive")
    from gov import ed25519 as _ed
    # Two trust roots pinned in parallel (cfssl multirootca shape):
    # an SVID from the new issuer verifies while the old root still
    # pins -- rotation without a flag day.
    new_iss = _issuer(seed=_OTHER_SEED, key_id="test-issuer-2")
    doc = new_iss.issue("spiffe://example.org/agent/a", _PUBKEY,
                        ttl_minutes=5, now=1000.0)
    v = sv.SvidVerifier({"test-issuer-1": _ed.publickey(_SEED),
                         "test-issuer-2": _ed.publickey(_OTHER_SEED)},
                        trust_domain="example.org")
    try:
        got = v.verify(doc, now=1000.0)
    except Exception as e:  # noqa: BLE001
        return _break("new-issuer SVID refused under multi-root: %s" % e)
    if got["issuer_key_id"] != "test-issuer-2":
        return _break("wrong issuer_key_id %r" % got["issuer_key_id"])
    return _held("parallel trust roots verify")


def _green_check():
    """Depth-1 green check. Honors GOV_SKIP_GREEN; never spawns another
    battery's full main."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    if sv is None:
        return [("unit tests", "SKIPPED (module absent)")]
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = tempfile.mkdtemp(prefix="w259g-", dir="/var/tmp")
    r = subprocess.run(
        [sys.executable, "-m", "tests.test_svid_issuer"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env=dict(env, TMPDIR=tmp),
        capture_output=True, text=True, timeout=300)
    tail = (r.stderr or r.stdout or "")[-200:].replace("\n", " ")
    return [("tests.test_svid_issuer",
             "rc=%d %s" % (r.returncode, tail))]


def main():
    held = breaks = gaps = baselines = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" % (type(e).__name__,
                                                    str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "GAP":
            gaps += 1
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        print("%-8s %-28s %s" % (verdict, name, detail))
    print("-" * 79)
    pin_ok = True
    if decision_codes is None:
        print("taxonomy pin: module absent (pre-fix)")
        pin_ok = False
    elif len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        pin_ok = False
    else:
        print("taxonomy pin OK: %d" % TAXONOMY_PIN)
    for name, note in _green_check():
        print("green-check %-20s %s" % (name, note))
    print("HELD %d / BREAK %d / GAP %d / BASELINE %d / ERROR %d "
          "over %d probes" % (held, breaks, gaps, baselines, errors,
                              len(_PROBES)))
    if gaps and not breaks and not errors:
        print("RED BASELINE: capability absent, all probes GAP")
        return 0
    return 1 if (breaks or errors or not pin_ok) else 0


if __name__ == "__main__":
    sys.exit(main())
