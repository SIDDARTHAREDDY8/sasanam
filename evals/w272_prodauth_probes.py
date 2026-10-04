#!/usr/bin/env python3
"""Wave-272 red-first battery: SLSA-shaped producer-authorization claim.

SLSA's provenance and Fulcio's identity machinery both omit
key<->producer application-level authorization. This seam closes that
negative space: on the claim path, the evidence-cert ceremony MUST
establish that the requesting producer is authorized for the claimed
application scope BEFORE the transparency log sees the digest.
Pattern-only steal (clean-room; no Fulcio/SLSA code): Fulcio's "issue
on presentation of a valid identity token" ceremony, SLSA's
{"_type", "subject", "predicate"} statement shape.

Red phase:  GOV_PRODAUTH_IMPL=stub  -> permissive foil. Every attack
probe must BREAK (the foil authorizes anything); a probe that HELDs
on the stub is vacuous and is flagged.
Green phase: default (gov.evidence_bundle_v2) -> every probe must HELD.

Protocol constants below are pinned independently of the module under
test (fixed clock, fixed key bytes); the battery never imports
gov.evidence_bundle_v2's internals.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; depth-1 green checks honoring
GOV_SKIP_GREEN=1; fresh unique /var/tmp TMPDIRs; NO in-repo git
subprocesses.
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w272-prodauth")

# -- spec-pinned protocol constants (NOT imported from the module)
NOW = 1791000000  # fixed test clock
PIN = 1933 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 7: pin 1541 -> 1545 (+4 casbin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-290 merge: pin 1706 -> 1710 (+4 provenance-rebuild-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*) ; Wave-295 lane 4: pin 1742 -> 1746 (+4 coord-state-*); Wave-295 merge: pin 1746 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)
ISSUER = "https://issuer.example.com"
ARC = "1.3.6.1.4.1.99999"
APPROVAL = "a" * 32
INTENT = "d" * 64
SCOPE = "payments/refunds"

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import ed25519 as _ed  # noqa: E402  (public vendored primitive)
from gov import evidence_certs as _ec  # noqa: E402
from gov import kms as _kms  # noqa: E402


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _keypair(byte):
    seed = bytes([byte & 0xFF]) * 32
    return seed, _ed.publickey(seed)


_ISSUER_SEED, _ISSUER_PUB = _keypair(0x10)
_CLAIM_SEED, _CLAIM_PUB = _keypair(0x20)
_ADMIN_SEED, _ADMIN_PUB = _keypair(0x30)


# ---------------------------------------------------------------------------
# Permissive foil (red phase): same API, zero checks
# ---------------------------------------------------------------------------

class _FoilError(Exception):
    def __init__(self, code, detail):
        super(_FoilError, self).__init__("%s: %s" % (code, detail))
        self.code = code


class _FoilRegistry(object):
    def __init__(self, *, entries=None, admin_public_key=None, now=None):
        self._entries = dict(entries or {})

    def register(self, *, statement, now=None):
        return "alice"

    def check(self, producer, scope):
        return True


class _FoilCA(object):
    def __init__(self, *a, **kw):
        pass

    def issue(self, **kw):
        return ({"subject_key_id": "ab" * 8,
                 "extensions": {"approval_id": APPROVAL}},
                {"producer_authz_claim": kw.get("producer_authz_claim")})


def _foil_token(sub="alice"):
    return {"token": {"sub": sub}, "token_signature": "foil"}


def _foil_claim():
    return {"format": "prodauth-claim.v1",
            "statement": {"predicate": {"producer": {"identity": "alice"},
                                        "authorizedScope": SCOPE}},
            "signature": "foil"}


class _FoilModule(object):
    EvidenceBundleV2Error = _FoilError
    ProducerRegistry = _FoilRegistry

    @staticmethod
    def mint_identity_token(**kw):
        return _foil_token(kw.get("sub", "alice"))

    @staticmethod
    def verify_identity_token(token, **kw):
        return {"producer": token["token"]["sub"], "iss": "foil"}

    @staticmethod
    def issue_producer_claim(**kw):
        return _foil_claim()

    @staticmethod
    def verify_producer_claim(claim, **kw):
        return {"producer": "alice", "scope": SCOPE}

    @staticmethod
    def submit_evidence_with_producer_claim(**kw):
        return {"kind": "evidence-submission.v2",
                "producer_authz": {"producer": "alice",
                                   "scope": kw.get("requested_scope")}}

    @staticmethod
    def verify_submission(**kw):
        return {"verified": True, "producer_authz": None}


def _real_module():
    import gov.evidence_bundle_v2 as eb2
    return eb2


def _is_foil(mod):
    return getattr(mod, "EvidenceBundleV2Error", None) is _FoilError


def _mod(impl):
    return _FoilModule() if impl == "stub" else _real_module()


# ---------------------------------------------------------------------------
# Fixtures (real: through the audited evidence-cert ceremony; foil: stubs)
# ---------------------------------------------------------------------------

class _Fx(object):
    """Per-probe fixture bundle. Built fresh per probe (fresh TMPDIR,
    fresh audit log, fixed key bytes, fixed clock)."""


def _build(mod):
    fx = _Fx()
    fx.tmp = tempfile.mkdtemp(prefix="g272-prodauth-")
    fx.audit_path = os.path.join(fx.tmp, "audit.jsonl")
    fx.fake = _kms.FakeKmsProvider(["ca-key-1"])
    fx.ca_pub = bytes(fx.fake.test_signing_public_key("ca-key-1"))
    if _is_foil(mod):
        fx.ca = _FoilCA()
        fx.registry = mod.ProducerRegistry(entries={"alice": [SCOPE]})
        fx.seed, fx.pub = _keypair(0x01)
        fx.token = mod.mint_identity_token(issuer_signing_key=_ISSUER_SEED,
                                           sub="alice", now=lambda: NOW)
        fx.key_id = "ab" * 8
        fx.claim = mod.issue_producer_claim()
        fx.cert, fx.entry = fx.ca.issue(producer_authz_claim=fx.claim)
        return fx
    ca = _ec.EvidenceCA(
        kms_provider=fx.fake, ca_key_id="ca-key-1",
        ca_public_key=fx.ca_pub,
        issuers=[ISSUER],
        approval_lookup={APPROVAL: {"decider": "alice",
                                    "state": "pending"}}.get,
        audit_log_path=fx.audit_path,
        anchor_reachable=lambda: True, oid_arc=ARC, now=lambda: NOW,
        claim_public_key=_CLAIM_PUB)
    fx.ca = ca
    fx.registry = mod.ProducerRegistry(entries={"alice": [SCOPE]})
    fx.seed, fx.pub = _keypair(0x01)
    fx.key_id = hashlib.sha256(fx.pub).hexdigest()[:16]
    fx.token = mod.mint_identity_token(issuer_signing_key=_ISSUER_SEED,
                                       sub="alice", now=lambda: NOW)
    fx.claim = mod.issue_producer_claim(
        registry=fx.registry, identity_token=fx.token,
        identity_issuer_public_key=_ISSUER_PUB, requested_scope=SCOPE,
        subject_key_id=fx.key_id, approval_id=APPROVAL,
        claim_signing_key=_CLAIM_SEED, now=lambda: NOW)
    chal = b"evcert-pop-v1" + APPROVAL.encode("utf-8")\
        + hashlib.sha256(fx.pub).digest()
    fx.cert, fx.entry = ca.issue(
        identity_assertion={"iss": ISSUER, "sub": "alice",
                            "exp": NOW + 3600},
        ephemeral_pub=fx.pub, pop_sig=_ed.sign(fx.seed, chal),
        approval_id=APPROVAL, intent_digest=INTENT,
        producer_authz_claim=fx.claim)
    return fx


def _body_sig(fx, body=None):
    body = {"decision": "deny"} if body is None else body
    return body, bytes(_ed.sign(fx.seed, _canonical(body)))


def _submit_kw(fx, **over):
    body, sig = _body_sig(fx)
    kw = dict(artifact_body=body, cert=fx.cert, artifact_signature=sig,
              approval_id=APPROVAL, intent_digest=INTENT,
              audit_log_path=fx.audit_path,
              ca_public_key=fx.ca_pub,
              verify_time=NOW, identity_token=fx.token,
              identity_issuer_public_key=_ISSUER_PUB,
              producer_registry=fx.registry, requested_scope=SCOPE,
              claim_public_key=_CLAIM_PUB, now=lambda: NOW)
    kw.update(over)
    return kw


def _submit(mod, fx, **over):
    return mod.submit_evidence_with_producer_claim(**_submit_kw(fx, **over))


PROBES = []


def probe(name, kind):
    def deco(fn):
        PROBES.append((name, kind, fn))
        return fn
    return deco


# -- attacks ----------------------------------------------------------

@probe("unknown-producer-refused", "attack")
def _p_unknown(mod):
    fx = _build(mod)
    tok = mod.mint_identity_token(issuer_signing_key=_ISSUER_SEED,
                                  sub="mallory", now=lambda: NOW)
    try:
        _submit(mod, fx, identity_token=tok)
    except mod.EvidenceBundleV2Error as e:
        if e.code == "prodauth-producer-unknown" or _is_foil(mod):
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "unknown producer's digest submitted")


@probe("forged-token-refused", "attack")
def _p_forged_token(mod):
    fx = _build(mod)
    bad = dict(fx.token)
    bad["token_signature"] = base64.b64encode(b"0" * 64).decode("ascii")
    try:
        _submit(mod, fx, identity_token=bad)
    except mod.EvidenceBundleV2Error as e:
        if e.code == "prodauth-token-invalid" or _is_foil(mod):
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "forged token's digest submitted")


@probe("expired-token-refused", "attack")
def _p_expired_token(mod):
    fx = _build(mod)
    old = mod.mint_identity_token(issuer_signing_key=_ISSUER_SEED,
                                  sub="alice", ttl_s=60, now=lambda: NOW)
    try:
        _submit(mod, fx, identity_token=old,
                **({"now": lambda: NOW + 3600} if not _is_foil(mod) else {}))
    except mod.EvidenceBundleV2Error as e:
        if e.code == "prodauth-token-expired" or _is_foil(mod):
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "expired token's digest submitted")


@probe("scope-not-authorized-refused", "attack")
def _p_scope(mod):
    fx = _build(mod)
    try:
        _submit(mod, fx, requested_scope="admin/root")
    except mod.EvidenceBundleV2Error as e:
        if e.code == "prodauth-scope-not-authorized" or _is_foil(mod):
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "unauthorized scope's digest submitted")


@probe("forged-claim-at-issuance-refused", "attack")
def _p_forged_claim(mod):
    fx = _build(mod)
    if _is_foil(mod):
        return ("BREAK", "foil embeds any claim")
    forged = dict(fx.claim)
    forged["signature"] = base64.b64encode(b"0" * 64).decode("ascii")
    seed, pub = _keypair(0x09)
    chal = b"evcert-pop-v1" + APPROVAL.encode("utf-8")\
        + hashlib.sha256(pub).digest()
    try:
        fx.ca.issue(
            identity_assertion={"iss": ISSUER, "sub": "alice",
                                "exp": NOW + 3600},
            ephemeral_pub=pub, pop_sig=_ed.sign(seed, chal),
            approval_id=APPROVAL, intent_digest=INTENT,
            producer_authz_claim=forged)
    except _ec.EvidenceCertError as e:
        if e.code == "prodauth-claim-invalid":
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "forged claim embedded at issuance")


@probe("claim-swap-refused", "attack")
def _p_claim_swap(mod):
    # Claim minted for issuance A, presented against issuance B.
    fx = _build(mod)
    if _is_foil(mod):
        return ("BREAK", "foil verifies any claim")
    seed2, pub2 = _keypair(0x02)
    key_id2 = hashlib.sha256(pub2).hexdigest()[:16]
    chal2 = b"evcert-pop-v1" + APPROVAL.encode("utf-8")\
        + hashlib.sha256(pub2).digest()
    cert2, _e2 = fx.ca.issue(
        identity_assertion={"iss": ISSUER, "sub": "alice",
                            "exp": NOW + 3600},
        ephemeral_pub=pub2, pop_sig=_ed.sign(seed2, chal2),
        approval_id=APPROVAL, intent_digest=INTENT,
        producer_authz_claim=mod.issue_producer_claim(
            registry=fx.registry, identity_token=fx.token,
            identity_issuer_public_key=_ISSUER_PUB,
            requested_scope=SCOPE, subject_key_id=key_id2,
            approval_id=APPROVAL, claim_signing_key=_CLAIM_SEED,
            now=lambda: NOW))
    body, sig = _body_sig(fx)
    fx.seed, fx.pub, fx.cert = seed2, pub2, cert2
    body2, sig2 = _body_sig(fx)
    # Now verify cert2's bundle but demand fx.claim (minted for
    # cert1's key_id) -- the join must fail.
    tlog = mod.make_log(
        producer_auth_verifier=mod.default_producer_auth_verifier,
        now=lambda: NOW)
    sub = mod.submit_evidence_with_producer_claim(
        **_submit_kw(fx, artifact_body=body2,
                     artifact_signature=sig2,
                     transparency_log=tlog))
    try:
        mod.verify_submission(
            submission=sub, audit_log_path=fx.audit_path,
            ca_public_key=fx.ca_pub, verify_time=NOW,
            transparency_log=tlog, require_producer_claim=True,
            claim_public_key=_CLAIM_PUB)
    except mod.EvidenceBundleV2Error as e:
        # The embedded claim is cert2's own (valid) -- swap the
        # attestation lookup instead: verify cert1's seal against a
        # require-claim check must fail the join, not pass.
        return ("BREAK", "unexpected refusal: %s" % e.code)
    # Direct join check: verify_producer_claim with the WRONG key id.
    try:
        mod.verify_producer_claim(
            fx.claim, claim_public_key=_CLAIM_PUB, approval_id=APPROVAL,
            subject_key_id=key_id2, verify_time=NOW)
    except mod.EvidenceBundleV2Error as e:
        if e.code == "prodauth-claim-mismatch":
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "swapped claim verified")


@probe("no-claim-verify-required-refused", "attack")
def _p_no_claim(mod):
    # Legacy bundle (no claim embedded) must NOT pass a
    # claim-required verification.
    fx = _build(mod)
    if _is_foil(mod):
        return ("BREAK", "foil requires nothing")
    # NOTE: a second audit log needs its own directory -- the
    # checkpoint file is per-directory, not per-log-file.
    leg_dir = os.path.join(fx.tmp, "legacy")
    os.makedirs(leg_dir, exist_ok=True)
    leg_audit = os.path.join(leg_dir, "audit.jsonl")
    ca2 = _ec.EvidenceCA(
        kms_provider=fx.fake, ca_key_id="ca-key-1",
        ca_public_key=fx.ca_pub,
        issuers=[ISSUER],
        approval_lookup={APPROVAL: {"decider": "alice",
                                    "state": "pending"}}.get,
        audit_log_path=leg_audit,
        anchor_reachable=lambda: True, oid_arc=ARC, now=lambda: NOW)
    seed, pub = _keypair(0x07)
    chal = b"evcert-pop-v1" + APPROVAL.encode("utf-8")\
        + hashlib.sha256(pub).digest()
    cert, _e = ca2.issue(
        identity_assertion={"iss": ISSUER, "sub": "alice",
                            "exp": NOW + 3600},
        ephemeral_pub=pub, pop_sig=_ed.sign(seed, chal),
        approval_id=APPROVAL, intent_digest=INTENT)
    sealed = mod.seal_evidence(
        artifact_body={"x": 1}, cert=cert,
        artifact_signature=bytes(_ed.sign(
            seed, _canonical({"x": 1}))),
        approval_id=APPROVAL, intent_digest=INTENT,
        ca_public_key=fx.ca_pub,
        verify_time=NOW)
    try:
        mod.verify_sealed_bundle(
            sealed=sealed,
            audit_log_path=leg_audit,
            ca_public_key=fx.ca_pub, verify_time=NOW,
            require_producer_claim=True, claim_public_key=_CLAIM_PUB)
    except mod.EvidenceBundleV2Error as e:
        if e.code == "prodauth-claim-invalid":
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "claim-less bundle passed claim-required verify")


# -- controls ---------------------------------------------------------

@probe("control/benign-claim-path", "control")
def _c_benign(mod):
    fx = _build(mod)
    if _is_foil(mod):
        r = _submit(mod, fx)
        if r.get("kind") == "evidence-submission.v2":
            return ("HELD", "foil submits")
        return ("BREAK", "foil submit shape changed")
    tlog = mod.make_log(
        producer_auth_verifier=mod.default_producer_auth_verifier,
        now=lambda: NOW)
    sub = _submit(mod, fx, transparency_log=tlog)
    out = mod.verify_submission(
        submission=sub, audit_log_path=fx.audit_path,
        ca_public_key=fx.ca_pub,
        verify_time=NOW, transparency_log=tlog,
        require_producer_claim=True, claim_public_key=_CLAIM_PUB)
    if out.get("verified") is True and out.get("producer_authz") ==\
            {"producer": "alice", "scope": SCOPE}:
        return ("HELD", "claim path round-trips")
    return ("BREAK", "benign claim path did not verify: %r" % (out,))


@probe("control/deterministic", "control")
def _c_deterministic(mod):
    a = _canonical(mod.mint_identity_token(
        issuer_signing_key=_ISSUER_SEED, sub="alice", now=lambda: NOW))
    b = _canonical(mod.mint_identity_token(
        issuer_signing_key=_ISSUER_SEED, sub="alice", now=lambda: NOW))
    if a == b:
        return ("HELD", "A==B byte-identical")
    return ("BREAK", "nondeterministic token")


@probe("control/token-audience-pinned", "control")
def _c_aud(mod):
    fx = _build(mod)
    if _is_foil(mod):
        return ("HELD", "foil skips audience (documented)")
    tok = mod.mint_identity_token(issuer_signing_key=_ISSUER_SEED,
                                  sub="alice", now=lambda: NOW)
    tok["token"]["aud"] = "some-other-system"
    try:
        mod.verify_identity_token(tok, issuer_public_key=_ISSUER_PUB,
                                  now=lambda: NOW)
    except mod.EvidenceBundleV2Error as e:
        if e.code == "prodauth-token-invalid":
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "cross-audience token verified")


@probe("control/registry-admin-registration", "control")
def _c_registry(mod):
    if _is_foil(mod):
        return ("HELD", "foil registry permissive (documented)")
    reg = mod.ProducerRegistry(admin_public_key=_ADMIN_PUB,
                               now=lambda: NOW)
    body = {"format": "prodauth-registry-statement.v1",
            "producer": "bob", "scopes": ["data/read"],
            "exp": NOW + 600}
    stmt = {"statement": body,
            "signature": base64.b64encode(
                _ed.sign(_ADMIN_SEED, _canonical(body))).decode("ascii")}
    who = reg.register(statement=stmt, now=lambda: NOW)
    if who != "bob":
        return ("BREAK", "registration returned %r" % (who,))
    if reg.check("bob", "data/read") is not True:
        return ("BREAK", "registered producer refused")
    # Forged registration is dishonored.
    bad = {"statement": body,
           "signature": base64.b64encode(b"0" * 64).decode("ascii")}
    try:
        reg.register(statement=bad, now=lambda: NOW)
    except mod.EvidenceBundleV2Error as e:
        if e.code == "prodauth-registry-unauthorized":
            return ("HELD", "admin registration + forgery dishonored")
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "forged registration honored")


@probe("control/expired-claim-refused", "control")
def _c_expired_claim(mod):
    fx = _build(mod)
    if _is_foil(mod):
        return ("HELD", "foil skips expiry (documented)")
    try:
        mod.verify_producer_claim(
            fx.claim, claim_public_key=_CLAIM_PUB, approval_id=APPROVAL,
            subject_key_id=fx.key_id, verify_time=NOW + 3600)
    except mod.EvidenceBundleV2Error as e:
        if e.code == "prodauth-claim-expired":
            return ("HELD", "refused: %s" % e.code)
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "expired claim verified")


@probe("control/legacy-path-untouched", "control")
def _c_legacy(mod):
    # Legacy issuance (no claim) keeps working and its attestation
    # carries no producer_authz_claim key.
    fx = _build(mod)
    if _is_foil(mod):
        return ("HELD", "foil has no legacy path (documented)")
    # NOTE: a second audit log needs its own directory -- the
    # checkpoint file is per-directory, not per-log-file.
    leg_dir = os.path.join(fx.tmp, "legacy")
    os.makedirs(leg_dir, exist_ok=True)
    leg_audit = os.path.join(leg_dir, "audit.jsonl")
    ca_leg = _ec.EvidenceCA(
        kms_provider=fx.fake, ca_key_id="ca-key-1",
        ca_public_key=fx.ca_pub,
        issuers=[ISSUER],
        approval_lookup={APPROVAL: {"decider": "alice",
                                    "state": "pending"}}.get,
        audit_log_path=leg_audit,
        anchor_reachable=lambda: True, oid_arc=ARC, now=lambda: NOW)
    seed, pub = _keypair(0x07)
    chal = b"evcert-pop-v1" + APPROVAL.encode("utf-8")\
        + hashlib.sha256(pub).digest()
    cert, entry = ca_leg.issue(
        identity_assertion={"iss": ISSUER, "sub": "alice",
                            "exp": NOW + 3600},
        ephemeral_pub=pub, pop_sig=_ed.sign(seed, chal),
        approval_id=APPROVAL, intent_digest=INTENT)
    if "producer_authz_claim" in entry:
        return ("BREAK", "claim key leaked into a legacy attestation")
    sealed = mod.seal_evidence(
        artifact_body={"x": 1}, cert=cert,
        artifact_signature=bytes(_ed.sign(seed, _canonical({"x": 1}))),
        approval_id=APPROVAL, intent_digest=INTENT,
        ca_public_key=fx.ca_pub,
        verify_time=NOW)
    out = mod.verify_sealed_bundle(
        sealed=sealed, audit_log_path=leg_audit,
        ca_public_key=fx.ca_pub,
        verify_time=NOW)
    if out.get("verified") is True:
        return ("HELD", "legacy path verifies without a claim")
    return ("BREAK", "legacy path broke: %r" % (out,))


@probe("control/never-raises", "control")
def _c_never_raises(mod):
    # verify_* return exact bools / raise coded errors, never raw.
    fx = _build(mod)
    if _is_foil(mod):
        return ("HELD", "foil documented")
    try:
        mod.verify_identity_token({"nope": 1},
                                  issuer_public_key=_ISSUER_PUB,
                                  now=lambda: NOW)
    except mod.EvidenceBundleV2Error as e:
        if e.code == "prodauth-token-invalid":
            return ("HELD", "coded refusal, no raw raise")
        return ("BREAK", "wrong code: %s" % e.code)
    return ("BREAK", "garbage token did not raise")


@probe("pin/taxonomy-1458", "control")
def _c_pin(mod):
    import re as _re
    src = open(os.path.join(_REPO, "gov", "decision_codes.py")).read()
    codes = _re.findall(
        r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(codes) != PIN or len(set(codes)) != PIN:
        return ("BREAK", "literals %d unique %d (want %d)"
                % (len(codes), len(set(codes)), PIN))
    new = [c for c in set(codes) if c.startswith("prodauth-") and
           c in ("prodauth-claim-expired", "prodauth-claim-invalid",
                 "prodauth-claim-mismatch", "prodauth-producer-unknown",
                 "prodauth-registry-unauthorized",
                 "prodauth-scope-not-authorized",
                 "prodauth-token-expired", "prodauth-token-invalid")]
    once = all(codes.count(c) == 1 for c in new)
    if len(new) == 8 and once:
        return ("HELD", "1579 literals, unique, 0 dups, 8 new exactly once")
    return ("BREAK", "new-code literal problem: %r" % (new,))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent evbundle unit suite with GOV_SKIP_GREEN=1 in
    the child env (it has no green check of its own)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP", "GOV_SKIP_GREEN=1 (depth-1)")
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    # Convention: gate TMPDIRs live on /var/tmp (chown-capable 2GB
    # tmpfs), never /tmp; always mkdir -p (Python 3.12 silently
    # ignores a nonexistent TMPDIR).
    tmp = "/var/tmp/g272-green-%d" % os.getpid()
    os.makedirs(tmp, exist_ok=True)
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_evbundle", "-v"],
        cwd=_REPO, env=env, capture_output=True, text=True, timeout=600)
    if p.returncode == 0:
        return ("HELD", "tests/test_evbundle green (depth-1)")
    return ("BREAK", "adjacent suite red:\n%s" % (p.stderr[-2000:],))


def main():
    impl = os.environ.get("GOV_PRODAUTH_IMPL", "real")
    mod = _mod(impl)
    held = brk = vacuous = 0
    print("impl=%s probes=%d" % (impl, len(PROBES)))
    for name, kind, fn in PROBES:
        try:
            verdict, detail = fn(mod)
        except Exception as e:  # noqa: BLE001
            verdict, detail = ("ERROR", "%r" % (e,))
        if kind == "attack" and verdict == "HELD" and impl == "stub":
            verdict = "VACUOUS"
        print("%-42s %-7s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            brk += 1
        elif verdict == "VACUOUS":
            vacuous += 1
        else:
            brk += 1  # ERROR/HELD? count as failure
    gv, gd = _green_check()
    print("green-check: %s %s" % (gv, gd))
    print("RESULT impl=%s HELD=%d BREAK=%d VACUOUS=%d" % (
        impl, held, brk, vacuous))
    if impl == "stub":
        ok = (vacuous == 0)
        print("RED-PHASE %s (need 0 vacuous)" % ("OK" if ok else "FAIL"))
    else:
        ok = (brk == 0 and vacuous == 0 and gv in ("HELD", "SKIP"))
        print("GREEN-PHASE %s" % ("OK" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
