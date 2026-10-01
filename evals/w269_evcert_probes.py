#!/usr/bin/env python3
"""Wave-269 red-first battery: short-lived evidence-cert ceremony.

14 falsifiable acceptance tests from the READY-FOR-AGENT spec
(~/workspace/teams/wave268-spec-evcert/SPEC.md).

Red phase:  GOV_EVCERT_IMPL=stub  -> permissive StubCA foil. Every
attack probe must BREAK (the stub issues when it should refuse); a
probe that HELDs on the stub is vacuous and is flagged.
Green phase: default (gov.evidence_certs) -> every probe must HELD.

Protocol constants below are pinned from the SPEC, not imported from
the module under test, so the battery is not tautological.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; depth-1 green checks honoring
GOV_SKIP_GREEN=1; fresh unique /var/tmp TMPDIRs; NO in-repo git
subprocesses.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# The audit-log HMAC chain needs an explicit key (wave-81: no dev-key
# fallback anywhere). Batteries provision their own, like w267.
import secrets  # noqa: E402

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w269-evcert")

# -- spec-pinned protocol constants (NOT imported from gov.evidence_certs)
POP_DOMAIN = b"evcert-pop-v1"
CERT_FORMAT = "sasanam-evidence-cert/v1"
CERT_EKU = "evidence-signing"
NOW = 1790860000  # fixed test clock (2026-10-01-ish)

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import ed25519 as _ed  # noqa: E402


# ---------------------------------------------------------------------------
# Requester-side helpers (spec-pinned constructions)
# ---------------------------------------------------------------------------

def _keypair(seed_byte):
    seed = bytes([seed_byte & 0xFF]) * 32
    return seed, _ed.publickey(seed)


def _pop_challenge(approval_id, pub):
    return POP_DOMAIN + approval_id.encode("utf-8") + hashlib.sha256(pub).digest()


def _pop_sig(seed, approval_id, pub):
    return _ed.sign(seed, _pop_challenge(approval_id, pub))


def _assertion(iss="https://issuer.example.com", sub="alice", exp=None):
    return {"iss": iss, "sub": sub,
            "exp": NOW + 3600 if exp is None else exp}


# ---------------------------------------------------------------------------
# Permissive stub foil (red phase): issues anything, checks nothing.
# ---------------------------------------------------------------------------

_STUB_CA_SEED = b"\x77" * 32
_STUB_CA_PUB = _ed.publickey(_STUB_CA_SEED)


class _StubIssuedError(Exception):
    pass


class StubCA(object):
    """Foil with the EvidenceCA public shape but no checks: no issuer
    allowlist, no expiry check, no approval lookup, no PoP, no reuse
    registry, no anchor check, no KMS capability check."""

    def __init__(self, **kwargs):
        self._audit_log_path = kwargs.get("audit_log_path")

    def issue(self, *, identity_assertion, ephemeral_pub, pop_sig,
              approval_id, intent_digest, lifetime_s=None):
        lifetime = lifetime_s or 600
        body = {
            "format": CERT_FORMAT,
            "subject_public_key": base64.b64encode(ephemeral_pub).decode(),
            "subject_key_id": hashlib.sha256(ephemeral_pub).hexdigest()[:16],
            "issuer_key_id": "stub-ca",
            "not_before": NOW,
            "not_after": NOW + lifetime,
            "eku": CERT_EKU,
            "extensions": {
                "approval_id": approval_id,
                "intent_digest": intent_digest,
                "principal": identity_assertion.get("sub", "?"),
                "1.3.6.1.4.1.99999.1.8": identity_assertion.get("iss", "?"),
                "1.3.6.1.4.1.99999.1.24": identity_assertion.get("sub", "?"),
            },
            "honest_limits": "stub",
        }
        canonical = json.dumps(body, sort_keys=True,
                               separators=(",", ":")).encode()
        sig = _ed.sign(_STUB_CA_SEED, canonical)
        cert = dict(body)
        cert["ca_signature"] = base64.b64encode(sig).decode()
        # SLOPPY attestation: mixes artifact-signature material into the
        # issuance record (p12 must BREAK on this).
        attestation = {"kind": "evidence-cert-issued",
                       "cert_digest": hashlib.sha256(canonical).hexdigest(),
                       "cert": cert,
                       "artifact_signature": base64.b64encode(b"SIG").decode(),
                       "approval_id": approval_id}
        return cert, attestation


def _stub_verify_cert_chain(cert, ca_public_key, now):
    return dict(cert)  # vacuous accept


def _stub_verify_evidence_signature(**kwargs):
    return {"verified": True}  # vacuous accept


def _stub_make_signature_attestation(cert, artifact_digest, signature):
    # SLOPPY: leaks issuance metadata into the artifact record.
    return {"artifact_digest": artifact_digest,
            "cert_digest": "stub",
            "signature": signature,
            "approval_id": cert["extensions"]["approval_id"],
            "principal": cert["extensions"]["principal"],
            "not_before": cert["not_before"]}


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

def _make_ca(impl, tmpdir, anchor_ok=True, now=NOW, **overrides):
    """Build a CA of the requested implementation with a standard
    fixture. Returns the CA instance."""
    if impl == "stub":
        return StubCA(audit_log_path=os.path.join(tmpdir, "audit.jsonl"))
    from gov.kms import FakeKmsProvider
    from gov import evidence_certs as ec
    fake = FakeKmsProvider(["ca-key-1"])
    params = dict(
        kms_provider=overrides.get("kms_provider", fake),
        ca_key_id="ca-key-1",
        ca_public_key=fake.test_signing_public_key("ca-key-1"),
        issuers=overrides.get("issuers", ["https://issuer.example.com"]),
        approval_lookup=overrides.get(
            "approval_lookup",
            {"a" * 32: {"decider": "alice", "state": "pending"},
             "b" * 32: {"decider": "alice", "state": "pending"},
             "c" * 32: {"decider": "alice",
                        "state": "approved"}}.get),
        audit_log_path=os.path.join(tmpdir, "audit.jsonl"),
        anchor_reachable=overrides.get("anchor_reachable",
                                       lambda: anchor_ok),
        oid_arc="1.3.6.1.4.1.99999",
        now=lambda: overrides.get("now_value", now),
    )
    params.update({k: v for k, v in overrides.items()
                   if k not in ("kms_provider", "issuers", "approval_lookup",
                                "anchor_reachable", "now_value")})
    return ec.EvidenceCA(**params)


def _good_request(seed_byte=0x01, approval_id="a" * 32,
                  intent_digest="b" * 64, lifetime_s=None, iss=None,
                  sub="alice", exp=None):
    seed, pub = _keypair(seed_byte)
    req = {"identity_assertion": _assertion(
               iss=iss or "https://issuer.example.com", sub=sub, exp=exp),
           "ephemeral_pub": pub,
           "pop_sig": _pop_sig(seed, approval_id, pub),
           "approval_id": approval_id,
           "intent_digest": intent_digest}
    if lifetime_s is not None:
        req["lifetime_s"] = lifetime_s
    return req, seed, pub


def _expect_code(fn, code):
    """Run fn; return ('HELD', detail) iff it raises with .code == code,
    ('BREAK', ...) iff it returns normally, ('ERROR', ...) otherwise."""
    try:
        out = fn()
    except Exception as e:  # noqa: BLE001 - the battery classifies everything
        got = getattr(e, "code", None)
        if got == code:
            return "HELD", "refused %s as specified" % code
        return ("ERROR", "wrong refusal: code=%r exc=%r"
                % (got, str(e)[:120]))
    return "BREAK", "issued when it must refuse %s (out=%r)" % (code, str(out)[:80])

# ---------------------------------------------------------------------------
# The 14 acceptance probes
# ---------------------------------------------------------------------------

def p01_pop_forgery(impl, tmpdir):
    """PoP signed with a DIFFERENT key than the presented ephemeral pub."""
    ca = _make_ca(impl, tmpdir)
    req, _, pub = _good_request()
    evil_seed, _ = _keypair(0xE1)
    req["pop_sig"] = _ed.sign(evil_seed, _pop_challenge(req["approval_id"], pub))
    return _expect_code(lambda: ca.issue(**req), "evcert-pop-invalid")


def p02_wrong_challenge(impl, tmpdir):
    """PoP over a different approval_id, and PoP over a client blob."""
    ca = _make_ca(impl, tmpdir)
    req, seed, pub = _good_request()
    req["pop_sig"] = _pop_sig(seed, "f" * 32, pub)  # different approval
    v1, d1 = _expect_code(lambda: ca.issue(**req), "evcert-pop-invalid")
    req2, seed2, pub2 = _good_request(seed_byte=0x02)
    blob = b"client-chosen-blob"
    req2["pop_sig"] = _ed.sign(seed2, blob)  # not the challenge at all
    v2, d2 = _expect_code(lambda: ca.issue(**req2), "evcert-pop-invalid")
    if v1 == v2 == "HELD":
        return "HELD", "both challenge mismatches refused"
    if "ERROR" in (v1, v2):
        return "ERROR", "%s / %s" % (d1, d2)
    return "BREAK", "%s / %s" % (d1, d2)


def p03_unknown_issuer(impl, tmpdir):
    """Assertion from outside the allowlist; meta-issuer anchoring."""
    ca = _make_ca(impl, tmpdir,
                  issuers=["https://issuer.example.com",
                           "https://*.dept.example.com"])
    req, _, _ = _good_request(iss="https://evil.example/")
    v1, d1 = _expect_code(lambda: ca.issue(**req), "evcert-unknown-issuer")
    # confusion: suffix-match attack must NOT pass the wildcard
    req2, _, _ = _good_request(seed_byte=0x02,
                               iss="https://dept.example.com.evil.com")
    v2, d2 = _expect_code(lambda: ca.issue(**req2), "evcert-unknown-issuer")
    # label-crossing: wildcard must not span two labels
    req3, _, _ = _good_request(seed_byte=0x03,
                               iss="https://a.b.dept.example.com")
    v3, d3 = _expect_code(lambda: ca.issue(**req3), "evcert-unknown-issuer")
    # control: single-label wildcard match MUST issue
    req4, _, _ = _good_request(seed_byte=0x04,
                               iss="https://eng.dept.example.com")
    try:
        ca.issue(**req4)
        v4, d4 = "HELD", "legit wildcard match issues"
    except Exception as e:  # noqa: BLE001
        v4, d4 = "ERROR", "legit wildcard refused: %r" % (getattr(e, "code", e),)
    vs = (v1, v2, v3, v4)
    if all(v == "HELD" for v in vs):
        return "HELD", "allowlist + anchoring exact"
    if "ERROR" in vs:
        return "ERROR", " / ".join((d1, d2, d3, d4))
    return "BREAK", " / ".join((d1, d2, d3, d4))


def p04_expired_assertion(impl, tmpdir):
    ca = _make_ca(impl, tmpdir)
    req, _, _ = _good_request(exp=NOW - 1)
    return _expect_code(lambda: ca.issue(**req), "evcert-assertion-expired")


def p05_unknown_approval(impl, tmpdir):
    ca = _make_ca(impl, tmpdir)
    req, _, _ = _good_request(approval_id="d" * 32)
    v1, d1 = _expect_code(lambda: ca.issue(**req), "evcert-unknown-approval")
    req2, _, _ = _good_request(seed_byte=0x02, approval_id="c" * 32)
    v2, d2 = _expect_code(lambda: ca.issue(**req2), "evcert-unknown-approval")
    if v1 == v2 == "HELD":
        return "HELD", "unknown + already-resolved approvals refused"
    if "ERROR" in (v1, v2):
        return "ERROR", "%s / %s" % (d1, d2)
    return "BREAK", "%s / %s" % (d1, d2)


def p06_identity_not_decider(impl, tmpdir):
    ca = _make_ca(impl, tmpdir)
    req, _, _ = _good_request(sub="mallory")  # decider is alice
    return _expect_code(lambda: ca.issue(**req), "evcert-identity-not-decider")


def p07_key_reuse(impl, tmpdir):
    """Same subject key for a second approval; across server restarts."""
    ca = _make_ca(impl, tmpdir)
    req, _, _ = _good_request(seed_byte=0x0A, approval_id="a" * 32)
    try:
        ca.issue(**req)
    except Exception as e:  # noqa: BLE001
        return "ERROR", "first issuance failed: %r" % (getattr(e, "code", e),)
    req2, _, _ = _good_request(seed_byte=0x0A, approval_id="b" * 32)
    v1, d1 = _expect_code(lambda: ca.issue(**req2), "evcert-key-reused")
    # simulated restart: brand-new CA object, same paths
    ca2 = _make_ca(impl, tmpdir)
    req3, _, _ = _good_request(seed_byte=0x0A, approval_id="b" * 32)
    v2, d2 = _expect_code(lambda: ca2.issue(**req3), "evcert-key-reused")
    # control: a FRESH key still issues after restart
    req4, _, _ = _good_request(seed_byte=0x0B, approval_id="b" * 32)
    try:
        ca2.issue(**req4)
        v3, d3 = "HELD", "fresh key issues after restart"
    except Exception as e:  # noqa: BLE001
        v3, d3 = "ERROR", "fresh key refused: %r" % (getattr(e, "code", e),)
    if v1 == v2 == v3 == "HELD":
        return "HELD", "reuse refused incl. across restarts; fresh key ok"
    if "ERROR" in (v1, v2, v3):
        return "ERROR", " / ".join((d1, d2, d3))
    return "BREAK", " / ".join((d1, d2, d3))


def p08_anchor_down(impl, tmpdir):
    """Anchor unreachable -> refuse; nothing minted; no swallowing."""
    ca = _make_ca(impl, tmpdir, anchor_ok=False)
    req, _, _ = _good_request()
    v1, d1 = _expect_code(lambda: ca.issue(**req), "evcert-anchor-unavailable")

    def _raiser():
        raise RuntimeError("anchor exploded")
    rdir = tmpdir + "-r"
    os.makedirs(rdir, exist_ok=True)
    ca2 = _make_ca(impl, rdir, anchor_reachable=_raiser)
    req2, _, _ = _good_request(seed_byte=0x02)
    try:
        ca2.issue(**req2)
        v2, d2 = "BREAK", "anchor exception swallowed and cert minted"
    except RuntimeError:
        v2, d2 = "HELD", "anchor exception propagates (no swallowing)"
    except Exception as e:  # noqa: BLE001
        v2, d2 = "ERROR", "unexpected: %r" % (getattr(e, "code", e),)
    if v1 == v2 == "HELD":
        return "HELD", "anchor-down refuses; anchor errors propagate"
    if "ERROR" in (v1, v2):
        return "ERROR", "%s / %s" % (d1, d2)
    return "BREAK", "%s / %s" % (d1, d2)


def p09_lifetime_bounds(impl, tmpdir):
    ca = _make_ca(impl, tmpdir)
    req, _, _ = _good_request(lifetime_s=7200)  # > default max 3600
    v1, d1 = _expect_code(lambda: ca.issue(**req), "evcert-lifetime-exceeded")
    req2, seed2, pub2 = _good_request(seed_byte=0x02, lifetime_s=600)
    try:
        cert, _att = ca.issue(**req2)
    except Exception as e:  # noqa: BLE001
        return "ERROR", "valid issuance failed: %r" % (getattr(e, "code", e),)
    if impl == "stub":
        verify = _stub_verify_cert_chain
        ca_pub = _STUB_CA_PUB
    else:
        from gov import evidence_certs as ec
        from gov.kms import FakeKmsProvider
        verify = ec.verify_cert_chain
        ca_pub = FakeKmsProvider(["ca-key-1"]).test_signing_public_key("ca-key-1")
    # verify after expiry
    v2, d2 = _expect_code(
        lambda: verify(cert, ca_pub, cert["not_after"] + 1),
        "evcert-cert-expired")
    # verify before not_before
    v3, d3 = _expect_code(
        lambda: verify(cert, ca_pub, cert["not_before"] - 1),
        "evcert-cert-expired")
    vs = (v1, v2, v3)
    if all(v == "HELD" for v in vs):
        return "HELD", "lifetime capped; validity window enforced"
    if "ERROR" in vs:
        return "ERROR", " / ".join((d1, d2, d3))
    return "BREAK", " / ".join((d1, d2, d3))


def p10_kms_without_sign(impl, tmpdir):
    """Envelope-only provider -> evcert-kms-cannot-sign; no local fallback."""
    if impl == "stub":
        return "BREAK", "stub never consults KMS capability"
    from gov.kms import FakeKmsProvider, KmsProvider, provider_can_sign
    from gov import evidence_certs as ec

    class EnvelopeOnlyProvider(KmsProvider):
        """Envelope-only: does NOT override sign()."""
        provider_name = "envelope-only"

        def wrap_data_key(self, key_id, plaintext):
            return b"wrapped"

        def unwrap_data_key(self, key_id, wrapped):
            return b"unwrapped"

        def describe_key(self, key_id):
            from gov.kms import KeyDescription
            return KeyDescription(key_id, self.provider_name, enabled=True)

    ep = EnvelopeOnlyProvider()
    if provider_can_sign(ep):
        return "ERROR", "capability probe wrong for envelope-only provider"
    if not provider_can_sign(FakeKmsProvider(["ca-key-1"])):
        return "ERROR", "capability probe wrong for signing provider"
    ca = _make_ca(impl, tmpdir, kms_provider=ep)
    # the CA must not hold a local fallback key: no Ed25519Signer inside
    req, _, _ = _good_request()
    return _expect_code(lambda: ca.issue(**req), "evcert-kms-cannot-sign")


def _issue_valid(impl, tmpdir, seed_byte=0x20, approval_id="a" * 32):
    ca = _make_ca(impl, tmpdir)
    req, seed, pub = _good_request(seed_byte=seed_byte,
                                   approval_id=approval_id)
    cert, att = ca.issue(**req)
    return ca, req, seed, pub, cert, att


def p11_binding_split(impl, tmpdir):
    from gov.signing import Ed25519Verifier
    ca, req, seed, pub, cert, _att = _issue_valid(impl, tmpdir)
    if impl == "stub":
        verify = _stub_verify_evidence_signature
        extra = {}
    else:
        from gov import evidence_certs as ec
        from gov.kms import FakeKmsProvider
        verify = ec.verify_evidence_signature
        extra = {"ca_public_key":
                 FakeKmsProvider(["ca-key-1"]).test_signing_public_key("ca-key-1")}
    artifact = b"decision-packet-bytes"
    good_sig = _ed.sign(seed, artifact)
    # wrong key signs the artifact
    evil_seed, evil_pub = _keypair(0xE2)
    bad_sig = _ed.sign(evil_seed, artifact)
    base = dict(approval_id=req["approval_id"],
                intent_digest=req["intent_digest"],
                verify_time=NOW + 10)
    v1, d1 = _expect_code(
        lambda: verify(cert=cert, artifact_bytes=artifact,
                       artifact_signature=bad_sig, **base, **extra),
        "evcert-binding-invalid")
    v2, d2 = _expect_code(
        lambda: verify(cert=cert, artifact_bytes=artifact,
                       artifact_signature=good_sig,
                       approval_id="f" * 32,
                       intent_digest=req["intent_digest"],
                       verify_time=NOW + 10, **extra),
        "evcert-binding-invalid")
    v3, d3 = _expect_code(
        lambda: verify(cert=cert, artifact_bytes=artifact,
                       artifact_signature=good_sig,
                       approval_id=req["approval_id"],
                       intent_digest="e" * 64,
                       verify_time=NOW + 10, **extra),
        "evcert-binding-invalid")
    try:
        out = verify(cert=cert, artifact_bytes=artifact,
                     artifact_signature=good_sig, **base, **extra)
        v4 = "HELD" if (impl == "stub" or out.get("verified")) else "ERROR"
        d4 = "valid chain+binding verifies" if v4 == "HELD" else "valid case failed"
    except Exception as e:  # noqa: BLE001
        v4, d4 = "ERROR", "valid case raised: %r" % (getattr(e, "code", e),)
    vs = (v1, v2, v3, v4)
    if all(v == "HELD" for v in vs):
        return "HELD", "chain-then-binding split exact"
    if "ERROR" in vs:
        return "ERROR", " / ".join((d1, d2, d3, d4))
    return "BREAK", " / ".join((d1, d2, d3, d4))


def p12_attestation_separation(impl, tmpdir):
    ca, req, _seed, _pub, cert, att = _issue_valid(impl, tmpdir)
    # issuance record: no artifact-signature material
    bad_keys = [k for k in ("signature", "artifact_signature", "artifact_digest")
                if k in att]
    # artifact record: no issuance metadata beyond cert_digest
    if impl == "stub":
        sig_att = _stub_make_signature_attestation(
            cert, "c" * 64, base64.b64encode(b"S").decode())
    else:
        from gov import evidence_certs as ec
        sig_att = ec.make_signature_attestation(
            cert, "c" * 64, base64.b64encode(_ed.sign(_seed, b"x")).decode())
    leak = [k for k in ("approval_id", "principal", "ca_signature",
                        "not_before", "not_after", "issuer_key_id")
            if k in sig_att]
    if not bad_keys and not leak:
        return "HELD", "issuance <-> artifact records separated"
    return "BREAK", "issuance leaks %r; artifact leaks %r" % (bad_keys, leak)


def p13_legacy_receipt_untouched(impl, tmpdir):
    """Corroboration receipt path without a cert: no cert fields, works."""
    import gov.corroboration_receipt as cr
    src = open(cr.__file__).read()
    if "evidence_certs" in src or "cert_digest" in src:
        return "BREAK", "receipt module references cert machinery"
    return "HELD", "receipt module has no cert coupling (legacy path intact)"


def p14_determinism(impl, tmpdir):
    adir, bdir = tmpdir + "-a", tmpdir + "-b"
    os.makedirs(adir, exist_ok=True)
    os.makedirs(bdir, exist_ok=True)
    ca1 = _make_ca(impl, adir)
    _r1, _s1, _p1 = _good_request(seed_byte=0x30)
    cert1, _ = ca1.issue(**_r1)
    ca2 = _make_ca(impl, bdir)
    _r2, _s2, _p2 = _good_request(seed_byte=0x30)
    cert2, _ = ca2.issue(**_r2)
    b1 = json.dumps(cert1, sort_keys=True).encode()
    b2 = json.dumps(cert2, sort_keys=True).encode()
    if b1 == b2:
        return "HELD", "identical inputs -> byte-identical certs"
    return "BREAK", "nondeterministic issuance"


PROBES = [
    ("evcert/pop-forgery", p01_pop_forgery, True),
    ("evcert/wrong-challenge", p02_wrong_challenge, True),
    ("evcert/unknown-issuer", p03_unknown_issuer, True),
    ("evcert/expired-assertion", p04_expired_assertion, True),
    ("evcert/unknown-approval", p05_unknown_approval, True),
    ("evcert/identity-not-decider", p06_identity_not_decider, True),
    ("evcert/key-reuse", p07_key_reuse, True),
    ("evcert/anchor-down", p08_anchor_down, True),
    ("evcert/lifetime-bounds", p09_lifetime_bounds, True),
    ("evcert/kms-without-sign", p10_kms_without_sign, True),
    ("evcert/binding-split", p11_binding_split, True),
    ("evcert/attestation-separation", p12_attestation_separation, True),
    ("evcert/legacy-receipt-untouched", p13_legacy_receipt_untouched, False),
    ("evcert/determinism", p14_determinism, False),
]

# ---------------------------------------------------------------------------
# Green checks (depth-1; honor GOV_SKIP_GREEN=1)
# ---------------------------------------------------------------------------

# Suites that pinned the taxonomy count pre-merge. The wave-269 merge
# repointed every taxonomy pin to 1325 (1299 + 14 evcert-* + 4
# imgscreen-* + 8 sessbind-*), so these suites must now pass cleanly;
# the green check fails them on ANY failure.
_PIN_CLEAN_SUITES = {
    "tests.test_kms_signer",
    "tests.test_signer_interop",
}

_GREEN_UNITS = [
    ("tests.test_kms", "unittest"),
    ("tests.test_kms_signer", "pin-clean"),
    ("tests.test_kms_vault", "unittest"),
    ("tests.test_transit_signer", "unittest"),
    ("tests.test_signer_interop", "pin-clean"),
    ("tests.test_corroboration_receipt", "unittest"),
    ("evals.w267_corrob_probes", "battery"),
]


def _run_green_checks():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("skipped", "GOV_SKIP_GREEN=1")]
    results = []
    py = os.environ.get("GOV_PY", sys.executable)
    for name, kind in _GREEN_UNITS:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="g269green-",
                                         dir="/var/tmp")
        os.makedirs(env["TMPDIR"], exist_ok=True)
        try:
            if kind == "unittest":
                cmd = [py, "-m", "unittest", name]
            elif kind == "pin-drift":
                cmd = [py, "-m", "unittest", name]
            else:
                cmd = [py, "-m", name]
            r = subprocess.run(cmd, cwd=_REPO, env=env,
                               capture_output=True, text=True, timeout=600)
            out = (r.stderr or "") + (r.stdout or "")
            if kind == "pin-clean":
                if r.returncode == 0:
                    results.append((name, "pass",
                                    "pin repointed to 1325 at wave-269 "
                                    "merge; suite passes cleanly"))
                else:
                    results.append((name, "FAIL", out[-400:]))
                continue
            ok = r.returncode == 0
            tail = out[-400:]
            results.append((name, "pass" if ok else "FAIL", tail))
        except Exception as e:  # noqa: BLE001
            results.append((name, "ERROR", str(e)[:200]))
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    impl = os.environ.get("GOV_EVCERT_IMPL", "real")
    if impl not in ("stub", "real"):
        print("GOV_EVCERT_IMPL must be stub or real", file=sys.stderr)
        return 2
    root = tempfile.mkdtemp(prefix="g269evcert-%s-" % impl, dir="/var/tmp")
    print("mode=%s tmpdir=%s" % (impl, root))
    held = broke = errored = 0
    for name, fn, is_attack in PROBES:
        tmpdir = os.path.join(root, name.replace("/", "-"))
        os.makedirs(tmpdir, exist_ok=True)
        try:
            verdict, detail = fn(impl, tmpdir)
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "%r" % e
        print("%-38s %-6s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
            if impl == "stub" and is_attack:
                print("  !! attack probe HELD on the stub: vacuous probe, "
                      "fix the probe")
        elif verdict == "BREAK":
            broke += 1
        else:
            errored += 1
    print("---")
    print("HELD=%d BREAK=%d ERROR=%d (mode=%s)" % (held, broke, errored, impl))
    green = _run_green_checks()
    green_fail = 0
    for item in green:
        if item[0] == "skipped":
            print("green: skipped (GOV_SKIP_GREEN=1)")
            continue
        name, status, tail = item
        print("green %-34s %s" % (name, status))
        if status != "pass":
            green_fail += 1
            print("  tail: %s" % tail.replace("\n", " | "))
    if impl == "stub":
        return 0 if errored == 0 else 1
    if errored or broke or green_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
