"""Break-first red-team battery for session-bound receipt presentation
(wave-269 feature lane: Oak session-layer + CoCo EHD patterns, ADAPT).

Target: gov/session_binding.py -- a session-bound presentation wraps an
existing signed artifact (e.g. a corroboration receipt) by digest and
binds it to a live session:

  1. transcript-hash binding: the presentation signature covers
     sha256(transcript); replay into another session fails;
  2. SignatureBinder: signature input is
     ``info || bound || additional`` with INFO-string domain
     separation, so a receipt presentation can never verify as an
     approval presentation;
  3. verifier-provider indirection: verification goes through a
     provider; misconfiguration fails closed;
  4. EHD: the session token binds (nonce, ephemeral pubkey) via
     ``H(nonce || pubkey)``; tokens are short-lived on an explicit
     ``now`` (never ambient clock).

The battery imports the implementation via GOV_SESSBIND_IMPL (default
"gov.session_binding"); against the permissive stub
(GOV_SESSBIND_IMPL=stub) every attack probe must BREAK, proving the
probes are real. Against the real module every probe must HELD, in
staging and under `env -u GOV_DEPLOYMENT_MODE`.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. A probe returns (ok, detail); ok=True means HELD (the seam
behaves per its contract), ok=False means BREAK (genuine defect) or
harness ERROR.

Stdlib only. Deterministic (nonce/now are explicit parameters; no
ambient time or randomness). No in-repo git subprocesses (wave-36
supply-chain probe: fail closed). Green checks are depth-1 and honor
GOV_SKIP_GREEN=1.
"""

import base64
import hashlib
import importlib
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

TAXONOMY_PIN = 2058 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*)



_IMPL = os.environ.get("GOV_SESSBIND_IMPL", "gov.session_binding")

_STUB_SRC = '''"""Permissive stub: verifies nothing, admits every
presentation. Every attack probe must BREAK against this."""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

CODES = ()


class SessionBindingError(Exception):
    def __init__(self, code, detail=""):
        super(SessionBindingError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


INFO_RECEIPT_PRESENT = "sasanam.receipt-present.v1"
INFO_APPROVAL_PRESENT = "sasanam.approval-present.v1"
INFO_DECISION_PRESENT = "sasanam.decision-present.v1"


def ehd(nonce, party_pubkey):
    return "stub"


def bind_body(info, bound_data, additional_data):
    return b"stub"


class Transcript(object):
    def __init__(self):
        self._r = []

    def append(self, role, payload):
        self._r.append((role, bytes(payload)))

    def digest(self):
        return "stub"


class VerifierProvider(object):
    def verifier_for(self, key_id):
        return None


class StaticVerifierProvider(VerifierProvider):
    def __init__(self, mapping):
        self._m = dict(mapping)

    def verifier_for(self, key_id):
        return self._m.get(key_id)


class Session(object):
    def __init__(self, session_id, signer, ephemeral_pubkey,
                 verifier_provider):
        self.session_id = session_id

    def append_record(self, role, payload):
        pass

    def transcript_digest(self):
        return "stub"

    def present(self, artifact_digest, now, ttl_s, nonce,
                info=INFO_RECEIPT_PRESENT):
        return {"format": "sasanam.session-presentation/v1",
                "session_id": self.session_id, "stub": True}

    def verify_presentation(self, presentation, artifact_digest, now,
                            info=INFO_RECEIPT_PRESENT):
        return {"ok": True, "code": "stub-ok", "checked": [],
                "out_of_scope": [], "evidence_digest": "stub"}
'''


def _load_impl():
    if _IMPL == "stub":
        mod = importlib.util.module_from_spec(
            importlib.machinery.ModuleSpec("gov_sessbind_stub", None))
        exec(compile(_STUB_SRC, "<stub>", "exec"), mod.__dict__)
        return mod
    return importlib.import_module(_IMPL)


sb = _load_impl()

_SEED_A = bytes(range(32))
_SEED_B = bytes([255 - i for i in range(32)])
_NOW = 1780000000.0
_TTL = 600.0
_NONCE = b"fixed-test-nonce-01"
_ARTIFACT = hashlib.sha256(b"artifact-under-test").hexdigest()


def _signing():
    from gov import signing
    signer = signing.Ed25519Signer(_SEED_A)
    other = signing.Ed25519Signer(_SEED_B)
    return signing, signer, other


def _session(signing, signer, provider, sid="sess-1"):
    return sb.Session(session_id=sid, signer=signer,
                      ephemeral_pubkey=signer.public_key,
                      verifier_provider=provider)


def _provider(signing, signer):
    return sb.StaticVerifierProvider(
        {signer.key_id: signing.Ed25519Verifier(signer.public_key)})


def _valid(signing, signer, now=_NOW, ttl=_TTL, nonce=_NONCE,
           artifact=_ARTIFACT, sid="sess-1",
           info=None):
    provider = _provider(signing, signer)
    presenter = _session(signing, signer, provider, sid=sid)
    verifier = _session(signing, signer, provider, sid=sid)
    for role, payload in (("agent", b"m1"), ("tool", b"m2")):
        presenter.append_record(role, payload)
        verifier.append_record(role, payload)
    pres = presenter.present(artifact, now, ttl, nonce,
                             **({"info": info} if info else {}))
    return presenter, verifier, pres

def _run(name, fn):
    try:
        held, detail = fn()
        return (name, bool(held), str(detail))
    except Exception as exc:  # harness error, never a pass
        return (name, False, "HARNESS-ERROR %r" % (exc,))


def _verdict(pres_verifier, pres, artifact, now, info):
    v = pres_verifier.verify_presentation(pres, artifact, now, info=info)
    assert isinstance(v, dict) and "ok" in v, "verdict shape"
    return v


# ---- attacks (must BREAK on stub, HELD on the real module) ----

def a01_cross_session_replay():
    signing, signer, _ = _signing()
    provider = _provider(signing, signer)
    presenter = _session(signing, signer, provider, sid="sess-A")
    verifier = _session(signing, signer, provider, sid="sess-A")
    presenter.append_record("agent", b"m1")
    presenter.append_record("tool", b"m2")
    verifier.append_record("agent", b"m1")
    verifier.append_record("tool", b"DIFFERENT")  # forked transcript
    pres = presenter.present(_ARTIFACT, _NOW, _TTL, _NONCE)
    v = _verdict(verifier, pres, _ARTIFACT, _NOW, sb.INFO_RECEIPT_PRESENT)
    held = (v["ok"] is False
            and v.get("code") == "sessbind-transcript-mismatch")
    return held, "code=%s" % v.get("code")


def a02_domain_confusion():
    signing, signer, _ = _signing()
    _, verifier, pres = _valid(signing, signer,
                               info=sb.INFO_RECEIPT_PRESENT)
    v = _verdict(verifier, pres, _ARTIFACT, _NOW,
                 sb.INFO_APPROVAL_PRESENT)
    held = (v["ok"] is False
            and v.get("code") == "sessbind-domain-mismatch")
    return held, "code=%s" % v.get("code")


def a03_token_expired():
    signing, signer, _ = _signing()
    _, verifier, pres = _valid(signing, signer)
    v = _verdict(verifier, pres, _ARTIFACT, _NOW + _TTL + 1,
                 sb.INFO_RECEIPT_PRESENT)
    held = (v["ok"] is False
            and v.get("code") == "sessbind-token-expired")
    return held, "code=%s" % v.get("code")


def a04_tampered_transcript():
    signing, signer, _ = _signing()
    provider = _provider(signing, signer)
    presenter = _session(signing, signer, provider)
    verifier = _session(signing, signer, provider)
    for r, p in (("agent", b"m1"), ("tool", b"m2")):
        presenter.append_record(r, p)
        verifier.append_record(r, p)
    pres = presenter.present(_ARTIFACT, _NOW, _TTL, _NONCE)
    verifier.append_record("tool", b"m3-sneaked-in")  # post-hoc fork
    v = _verdict(verifier, pres, _ARTIFACT, _NOW,
                 sb.INFO_RECEIPT_PRESENT)
    held = (v["ok"] is False
            and v.get("code") == "sessbind-transcript-mismatch")
    return held, "code=%s" % v.get("code")


def a05_verifier_misconfigured():
    signing, signer, _ = _signing()
    empty = sb.StaticVerifierProvider({})
    presenter = _session(signing, signer, empty)
    verifier = _session(signing, signer, empty)
    presenter.append_record("agent", b"m1")
    verifier.append_record("agent", b"m1")
    pres = presenter.present(_ARTIFACT, _NOW, _TTL, _NONCE)
    v = _verdict(verifier, pres, _ARTIFACT, _NOW,
                 sb.INFO_RECEIPT_PRESENT)
    held = (v["ok"] is False
            and v.get("code") == "sessbind-verifier-misconfigured")
    return held, "code=%s" % v.get("code")


def a06_ehd_transplant():
    # Session bound to a DIFFERENT ephemeral key than the signer:
    # the token is properly signed, but the EHD no longer matches the
    # key the verifier pins. Must refuse sessbind-ehd-mismatch.
    signing, signer, other = _signing()
    provider = _provider(signing, signer)
    presenter = sb.Session(session_id="sess-1", signer=signer,
                           ephemeral_pubkey=other.public_key,
                           verifier_provider=provider)
    verifier = _session(signing, signer, provider)
    presenter.append_record("agent", b"m1")
    verifier.append_record("agent", b"m1")
    pres = presenter.present(_ARTIFACT, _NOW, _TTL, _NONCE)
    if _IMPL == "stub":
        pres["ehd"] = "00" * 32  # stub ignores fields; must still admit
    v = _verdict(verifier, pres, _ARTIFACT, _NOW,
                 sb.INFO_RECEIPT_PRESENT)
    held = (v["ok"] is False
            and v.get("code") == "sessbind-ehd-mismatch")
    return held, "code=%s" % v.get("code")


def a07_signature_tamper():
    signing, signer, _ = _signing()
    _, verifier, pres = _valid(signing, signer)
    if isinstance(pres, dict) and "signature" in pres:
        sig = bytearray(bytes.fromhex(pres["signature"]))
        sig[0] ^= 0xFF
        pres["signature"] = bytes(sig).hex()
    v = _verdict(verifier, pres, _ARTIFACT, _NOW,
                 sb.INFO_RECEIPT_PRESENT)
    held = (v["ok"] is False
            and v.get("code") == "sessbind-signature-invalid")
    return held, "code=%s" % v.get("code")


def a08_not_yet_valid():
    signing, signer, _ = _signing()
    _, verifier, pres = _valid(signing, signer)
    v = _verdict(verifier, pres, _ARTIFACT, _NOW - 1,
                 sb.INFO_RECEIPT_PRESENT)
    held = (v["ok"] is False
            and v.get("code") == "sessbind-token-expired")
    return held, "code=%s" % v.get("code")


def a09_malformed():
    signing, signer, _ = _signing()
    _, verifier, pres = _valid(signing, signer)
    if isinstance(pres, dict):
        pres.pop("signature", None)
    v = _verdict(verifier, pres, _ARTIFACT, _NOW,
                 sb.INFO_RECEIPT_PRESENT)
    held = (v["ok"] is False
            and v.get("code") == "sessbind-malformed")
    return held, "code=%s" % v.get("code")


def a10_artifact_swap():
    signing, signer, _ = _signing()
    _, verifier, pres = _valid(signing, signer)
    other_artifact = hashlib.sha256(b"different-artifact").hexdigest()
    v = _verdict(verifier, pres, other_artifact, _NOW,
                 sb.INFO_RECEIPT_PRESENT)
    held = v["ok"] is False
    return held, "ok=%r code=%s" % (v["ok"], v.get("code"))


def a11_session_id_mismatch():
    signing, signer, _ = _signing()
    provider = _provider(signing, signer)
    presenter = _session(signing, signer, provider, sid="sess-1")
    verifier = _session(signing, signer, provider, sid="sess-2")
    presenter.append_record("agent", b"m1")
    verifier.append_record("agent", b"m1")
    pres = presenter.present(_ARTIFACT, _NOW, _TTL, _NONCE)
    v = _verdict(verifier, pres, _ARTIFACT, _NOW,
                 sb.INFO_RECEIPT_PRESENT)
    held = v["ok"] is False
    return held, "ok=%r code=%s" % (v["ok"], v.get("code"))


# ---- controls (must HELD on the real module; stub admits them too) ----

def c01_valid_round_trip():
    signing, signer, _ = _signing()
    _, verifier, pres = _valid(signing, signer)
    v = _verdict(verifier, pres, _ARTIFACT, _NOW,
                 sb.INFO_RECEIPT_PRESENT)
    held = v["ok"] is True
    return held, "ok=%r code=%s" % (v["ok"], v.get("code"))


def c02_determinism():
    signing, signer, _ = _signing()
    p1 = _valid(signing, signer)[2]
    p2 = _valid(signing, signer)[2]
    if _IMPL == "stub":
        return True, "stub deterministic by construction"
    held = (json.dumps(p1, sort_keys=True) ==
            json.dumps(p2, sort_keys=True))
    return held, "identical=%r" % held


def c03_verdict_shape():
    signing, signer, _ = _signing()
    _, verifier, pres = _valid(signing, signer)
    v = _verdict(verifier, pres, _ARTIFACT, _NOW,
                 sb.INFO_RECEIPT_PRESENT)
    if _IMPL == "stub":
        return True, "stub shape unchecked"
    held = (isinstance(v.get("checked"), list) and len(v["checked"]) > 0
            and isinstance(v.get("out_of_scope"), list)
            and len(v["out_of_scope"]) > 0
            and isinstance(v.get("evidence_digest"), str)
            and len(v["evidence_digest"]) == 64)
    return held, "checked=%d oos=%d" % (len(v.get("checked", [])),
                                        len(v.get("out_of_scope", [])))


def c04_transcript_order_matters():
    t1, t2 = sb.Transcript(), sb.Transcript()
    t1.append("agent", b"m1")
    t1.append("tool", b"m2")
    t2.append("tool", b"m2")
    t2.append("agent", b"m1")
    if _IMPL == "stub":
        return True, "stub unchecked"
    held = t1.digest() != t2.digest() and len(t1.digest()) == 64
    return held, "d1=%s d2=%s" % (t1.digest()[:8], t2.digest()[:8])


def c05_binder_domain_separation():
    b1 = sb.bind_body("sasanam.receipt-present.v1", b"X", b"Y")
    b2 = sb.bind_body("sasanam.approval-present.v1", b"X", b"Y")
    b3 = sb.bind_body("sasanam.receipt-present.v1", b"X", b"Y")
    if _IMPL == "stub":
        return True, "stub unchecked"
    held = (b1 != b2) and (b1 == b3) and isinstance(b1, bytes)
    return held, "separated=%r deterministic=%r" % (b1 != b2, b1 == b3)


def c06_ehd_unit():
    if _IMPL == "stub":
        return True, "stub unchecked"
    expect = hashlib.sha256(_NONCE + _SEED_A).hexdigest()
    held = (sb.ehd(_NONCE, _SEED_A) == expect
            and sb.ehd(b"other", _SEED_A) != expect
            and len(sb.ehd(_NONCE, _SEED_A)) == 64)
    return held, "matches-sha256=%r" % held


def c07_key_remote_verifier():
    # A verifier that never exposes its raw key (Vault-transit shape):
    # signature still verifies; the EHD check is skipped WITH
    # attribution, never silently.
    signing, signer, _ = _signing()

    class RemoteVerifier(signing.Verifier):
        def __init__(self, inner):
            self._inner = inner
            self._kid = inner.key_id

        @property
        def key_id(self):
            return self._kid

        def verify(self, data, sig):
            return self._inner.verify(data, sig)

    assert not hasattr(RemoteVerifier(
        signing.Ed25519Verifier(signer.public_key)), "public_key")
    provider = sb.StaticVerifierProvider(
        {signer.key_id: RemoteVerifier(
            signing.Ed25519Verifier(signer.public_key))})
    presenter = _session(signing, signer, provider)
    verifier = _session(signing, signer, provider)
    presenter.append_record("agent", b"m1")
    verifier.append_record("agent", b"m1")
    pres = presenter.present(_ARTIFACT, _NOW, _TTL, _NONCE)
    if _IMPL == "stub":
        return True, "stub unchecked"
    v = _verdict(verifier, pres, _ARTIFACT, _NOW,
                 sb.INFO_RECEIPT_PRESENT)
    skipped = any("ehd-check-skipped" in str(c)
                  for c in v.get("checked", []))
    held = v["ok"] is True and skipped
    return held, "ok=%r ehd-skipped-attributed=%r" % (v["ok"], skipped)


def c08_codes_live():
    codes = set(getattr(sb, "CODES", ()))
    want = {"sessbind-transcript-mismatch", "sessbind-domain-mismatch",
            "sessbind-token-expired", "sessbind-verifier-misconfigured",
            "sessbind-malformed", "sessbind-signature-invalid",
            "sessbind-ehd-mismatch"}
    if _IMPL == "stub":
        return True, "stub unchecked"
    missing = want - codes
    held = not missing
    return held, "missing=%r" % (missing,)


def p_pin():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    held = (n == TAXONOMY_PIN)
    return held, "taxonomy=%d pin=%d" % (n, TAXONOMY_PIN)


def green_check():
    """Depth-1: run the adjacent corroboration battery with
    GOV_SKIP_GREEN=1 in the child env. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", True, "skipped (GOV_SKIP_GREEN=1)")]
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = os.environ.get("TMPDIR", "/tmp")
    try:
        proc = subprocess.run(
            [sys.executable,
             os.path.join(repo, "evals", "w267_corrob_probes.py")],
            env=env, cwd=tmp, capture_output=True, text=True,
            timeout=600)
    except Exception as exc:
        return [("green-check", False, "harness error: %r" % (exc,))]
    ok = proc.returncode == 0
    tail = (proc.stdout or "")[-200:]
    return [("green-check", ok,
             "w267_corrob_probes rc=%d %s" % (proc.returncode, tail))]


PROBES = [
    a01_cross_session_replay, a02_domain_confusion, a03_token_expired,
    a04_tampered_transcript, a05_verifier_misconfigured,
    a06_ehd_transplant, a07_signature_tamper, a08_not_yet_valid,
    a09_malformed, a10_artifact_swap, a11_session_id_mismatch,
    c01_valid_round_trip, c02_determinism, c03_verdict_shape,
    c04_transcript_order_matters, c05_binder_domain_separation,
    c06_ehd_unit, c07_key_remote_verifier, c08_codes_live,
    p_pin,
]


def main():
    results = [_run(p.__name__, p) for p in PROBES]
    results.extend(green_check())
    held = sum(1 for _, h, _ in results if h)
    total = len(results)
    print("sessbind battery [%s]: %d/%d HELD" % (_IMPL, held, total))
    for name, h, detail in results:
        print("  %-28s %s  %s" % (name, "HELD" if h else "BREAK",
                                  detail))
    return 0 if held == total else 1


if __name__ == "__main__":
    sys.exit(main())
