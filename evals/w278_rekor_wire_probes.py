#!/usr/bin/env python3
"""Rekor v2 second-witness WIRING into evidence-bundle issuance: red-first probe battery.

Wave-278 lane 2 (rekorwire). Wave-277 built ``gov/rekor_v2_witness.py``
(the write path, flag OFF by default) but deliberately left it UNWIRED
-- no call from bundle issuance. This battery proves the wiring at the
issuance seam (``gov.evidence_bundle_v2.submit_evidence`` /
``submit_evidence_with_producer_claim``).

What is red on pristine (d46ad29): the issuance seam has NO witness
path at all -- no wiring kwargs, no witness attach, no ``"witnesses"``
metadata. Every wiring probe BREAKs (the seam refuses the kwargs).

What is green post-wiring:
  * flag OFF (default, env unset): the issuance return is byte-identical
    to the unwired behavior -- the exact historical key set, no
    ``"witnesses"`` slot -- and an always-on stub witness passed
    explicitly is NOT consulted.
  * flag ON (``GOV_REKOR_V2_WITNESS=1``): the same bundle digest the
    primary local anchor committed is attached as a SECOND witness;
    the witness record is filed under ``"witnesses"``; the primary
    transparency_receipt is unchanged.
  * witness failure (client outage / no signing config / missing
    material): degrades to a ``"failed"`` record -- the submission is
    still issued, nothing raises, the primary anchor is untouched.
  * witness records are digest-existence-only (evidentiary_grade +
    authority_proof=False); only the digest crosses the boundary.

Probe map:
  w_wire_params_present:      the seam exposes the wiring kwargs.
  w_flag_off_byte_identical:  env unset -> exact key set, no "witnesses";
                              always-on stub witness is not consulted.
  w_flag_on_attaches:         env=1 -> "attached"; log_generation pinned;
                              digest-existence honesty; digest-only.
  w_flag_on_failure_degrades: failing client -> "failed" record;
                              submission still issued; primary intact.
  w_flag_on_no_config_honest: env=1, no signing config -> "failed"
                              naming the cause; submission still issued.
  w_primary_anchor_unchanged: flag-on receipt == flag-off receipt.
  w_claim_path_flag_off:      claim path, env unset -> exact key set,
                              no "witnesses".
  w_broken_witness_never_breaks: non-conforming witness raising in
                              attach -> "failed" record, never raises.

Conventions: module-level staging default; fixed seeds; independent
literals; no in-repo git subprocesses; depth-1 green check honoring
GOV_SKIP_GREEN; fresh /var/tmp/g278-rekorwire TMPDIR (pre-created).
"""

import base64
import hashlib
import inspect
import json
import os
import secrets
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Audit-log HMAC chain key: setdefault covers direct-script runs.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w278-rekorwire")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import ed25519 as ed  # noqa: E402
from gov import evidence_certs as ec  # noqa: E402
from gov import evidence_bundle_v2 as eb2  # noqa: E402
from gov import kms as kms_mod  # noqa: E402
from gov import anchor_backend as ab  # noqa: E402
from gov import rekor_v2_witness as rvw  # noqa: E402

NOW = 1790860000
POP_DOMAIN = b"evcert-pop-v1"
ARC = "1.3.6.1.4.1.99999"
APPROVAL = "a" * 32
INTENT = "d" * 64
ISSUER = "https://issuer.example.com"
SCOPE = "payments/refunds"
LOG_ID = "w278-test-log"

_TEST_V2_URL = "https://rekor-v2.example.invalid"
_TEST_TSA_URL = "https://tsa.example.invalid"
_TEST_LOG_ID = "w278-test-log-id"

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("%-32s %-7s %s" % (name, verdict, detail))


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _keypair(byte):
    seed = bytes([byte & 0xFF]) * 32
    return seed, ed.publickey(seed)


# ---------------------------------------------------------------------------
# issuance harness (mirrors tests/test_evbundle.py V2Base)
# ---------------------------------------------------------------------------

class _Harness(object):
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="w278-wire-")
        self.audit_path = os.path.join(self.tmp, "audit.jsonl")
        self.fake = kms_mod.FakeKmsProvider(["ca-key-1"])
        self.ca_pub = bytes(
            self.fake.test_signing_public_key("ca-key-1"))

    def make_ca(self, claim_public_key=None):
        approvals = {APPROVAL: {"decider": "alice", "state": "pending"}}
        return ec.EvidenceCA(
            kms_provider=self.fake, ca_key_id="ca-key-1",
            ca_public_key=self.fake.test_signing_public_key("ca-key-1"),
            issuers=[ISSUER], approval_lookup=approvals.get,
            audit_log_path=self.audit_path,
            anchor_reachable=lambda: True, oid_arc=ARC,
            now=lambda: NOW, claim_public_key=claim_public_key)

    def issue_cert(self, ca, seed_byte=0x01):
        seed, pub = _keypair(seed_byte)
        chal = (POP_DOMAIN + APPROVAL.encode("utf-8")
                + hashlib.sha256(pub).digest())
        req = {"identity_assertion": {"iss": ISSUER, "sub": "alice",
                                      "exp": NOW + 3600},
               "ephemeral_pub": pub,
               "pop_sig": ed.sign(seed, chal),
               "approval_id": APPROVAL,
               "intent_digest": INTENT}
        cert, _entry = ca.issue(**req)
        return cert, seed, pub

    def submit(self, body=None, log=None, seed_byte=0x01, **extra):
        """Full issuance: cert -> seal -> submit. Returns (sub, digest)."""
        ca = self.make_ca()
        cert, seed, _pub = self.issue_cert(ca, seed_byte=seed_byte)
        if body is None:
            body = {"decision": "deny"}
        sig = ed.sign(seed, _canonical(body))
        if log is None:
            log = eb2.make_log(
                producer_auth_verifier=eb2.default_producer_auth_verifier,
                log_id=LOG_ID, now=lambda: NOW)
        sub = eb2.submit_evidence(
            artifact_body=body, cert=cert,
            artifact_signature=bytes(sig),
            approval_id=APPROVAL, intent_digest=INTENT,
            ca_public_key=bytes(self.ca_pub), verify_time=NOW,
            audit_log_path=self.audit_path, transparency_log=log,
            **extra)
        digest = sub["sealed"]["artifact"]["artifact_digest"]
        return sub, digest

    def submit_claim_path(self, **extra):
        """Claim-path issuance (mirrors tests/test_producer_authz.py)."""
        issuer_seed = bytes([0x10]) * 32
        issuer_pub = ed.publickey(issuer_seed)
        claim_seed = bytes([0x20]) * 32
        claim_pub = ed.publickey(claim_seed)
        ca = self.make_ca(claim_public_key=claim_pub)
        registry = eb2.ProducerRegistry(entries={"alice": [SCOPE]})
        tok = eb2.mint_identity_token(issuer_signing_key=issuer_seed,
                                      sub="alice", now=lambda: NOW)
        prod_seed, prod_pub = _keypair(0x01)
        key_id = hashlib.sha256(prod_pub).hexdigest()[:16]
        claim, _kid = eb2.issue_producer_claim(
            registry=registry, identity_token=tok,
            identity_issuer_public_key=issuer_pub,
            requested_scope=SCOPE, subject_key_id=key_id,
            approval_id=APPROVAL, claim_signing_key=claim_seed,
            now=lambda: NOW), key_id
        chal = (POP_DOMAIN + APPROVAL.encode("utf-8")
                + hashlib.sha256(prod_pub).digest())
        cert, _entry = ca.issue(
            identity_assertion={"iss": ISSUER, "sub": "alice",
                                "exp": NOW + 3600},
            ephemeral_pub=prod_pub,
            pop_sig=ed.sign(prod_seed, chal),
            approval_id=APPROVAL, intent_digest=INTENT,
            producer_authz_claim=claim)
        body = {"decision": "deny"}
        sig = ed.sign(prod_seed, _canonical(body))
        log = eb2.make_log(
            producer_auth_verifier=eb2.default_producer_auth_verifier,
            log_id=LOG_ID, now=lambda: NOW)
        sub = eb2.submit_evidence_with_producer_claim(
            artifact_body=body, cert=cert,
            artifact_signature=bytes(sig),
            approval_id=APPROVAL, intent_digest=INTENT,
            audit_log_path=self.audit_path,
            ca_public_key=bytes(self.ca_pub), verify_time=NOW,
            identity_token=tok,
            identity_issuer_public_key=issuer_pub,
            producer_registry=registry, requested_scope=SCOPE,
            claim_public_key=claim_pub,
            transparency_log=log, now=lambda: NOW,
            **extra)
        return sub


# ---------------------------------------------------------------------------
# witness fixtures
# ---------------------------------------------------------------------------

def _signing_config_doc():
    return {
        "rekor": [
            {"url": _TEST_V2_URL, "majorApiVersion": 2,
             "operator": "example-operator",
             "logId": _TEST_LOG_ID,
             "validFor": {"start": "2026-01-01T00:00:00Z"}},
        ],
        "tsa": [
            {"url": _TEST_TSA_URL, "majorApiVersion": 1,
             "operator": "example-operator",
             "validFor": {"start": "2021-01-01T00:00:00Z"}},
        ],
    }


def _witness_material(digest):
    """Ed25519ph witness signature material (proven recipe, wave-277)."""
    seed = bytes([0xB7]) * 32
    sig = ed.sign_ph(seed, bytes.fromhex(digest))
    pem = ab.anchor_spki_pem(ed.publickey(seed))
    return sig.hex(), pem


class _AlwaysOnStub(object):
    """Deliberate mock: always enabled, counts attach calls."""

    def __init__(self):
        self.attaches = 0
        self.enabled = True

    def attach(self, digest, *, signature_b64, pubkey_pem,
               algorithm="ed25519ph-sha512"):
        self.attaches += 1
        return {"witness": "rekor-v2-stub", "status": "attached"}


class _FailingClient(object):
    def submit_hashedrekord(self, anchor_hash, *, signature_b64,
                            pubkey_pem, algorithm="ed25519ph-sha512"):
        raise RuntimeError("simulated log outage")


class _RaisingWitness(object):
    """Non-conforming witness: attach raises (must never break issuance)."""
    enabled = True

    def attach(self, digest, **kw):
        raise RuntimeError("non-conforming witness blew up")


def _env_clean():
    saved = {}
    for var in ("GOV_REKOR_V2_WITNESS", "GOV_REKOR_V2_SIGNING_CONFIG"):
        saved[var] = os.environ.pop(var, None)
    return saved


def _env_restore(saved):
    for var, val in saved.items():
        if val is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = val


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

WIRING_PARAMS = ("rekor_v2_witness", "witness_signature_b64",
                 "witness_pubkey_pem")
BASE_SUBMIT_KEYS = frozenset(("kind", "sealed", "issuance_ref",
                              "transparency_receipt", "honest_claims"))
BASE_CLAIM_KEYS = frozenset(("kind", "sealed", "issuance_ref",
                             "transparency_receipt", "producer_authz",
                             "honest_claims"))


def w_wire_params_present():
    name = "w_wire_params_present"
    params = inspect.signature(eb2.submit_evidence).parameters
    missing = [p for p in WIRING_PARAMS if p not in params]
    if missing:
        return _record(name, "BREAK",
                       "seam lacks wiring kwargs: %s" % (missing,))
    cparams = inspect.signature(
        eb2.submit_evidence_with_producer_claim).parameters
    cmissing = [p for p in WIRING_PARAMS if p not in cparams]
    if cmissing:
        return _record(name, "BREAK",
                       "claim path lacks wiring kwargs: %s" % (cmissing,))
    _record(name, "HELD", "both issuance seams expose the wiring kwargs")


def w_flag_off_byte_identical():
    name = "w_flag_off_byte_identical"
    saved = _env_clean()
    try:
        h = _Harness()
        sub, _digest = h.submit()
        keys = frozenset(sub.keys())
        if keys != BASE_SUBMIT_KEYS:
            return _record(name, "BREAK",
                           "flag-off key set drifted: %s"
                           % sorted(keys - BASE_SUBMIT_KEYS))
        if "witnesses" in sub:
            return _record(name, "BREAK",
                           "'witnesses' slot present with flag off")
        # Deliberate mock: an always-on stub witness must NOT be
        # consulted while the flag is off. Submit the SAME sealed
        # artifact twice (identical cert, sig, log inputs) -- once
        # plain, once with the stub -- and require byte-identical
        # returns.
        stub = _AlwaysOnStub()
        ca = h.make_ca()
        cert, seed, _pub = h.issue_cert(ca, seed_byte=0x03)
        body = {"decision": "deny"}
        asig = ed.sign(seed, _canonical(body))

        def _submit_once(**kw):
            log = eb2.make_log(
                producer_auth_verifier=eb2.default_producer_auth_verifier,
                log_id=LOG_ID, now=lambda: NOW)
            return eb2.submit_evidence(
                artifact_body=body, cert=cert,
                artifact_signature=bytes(asig),
                approval_id=APPROVAL, intent_digest=INTENT,
                ca_public_key=bytes(h.ca_pub), verify_time=NOW,
                audit_log_path=h.audit_path, transparency_log=log,
                **kw)

        sub1 = _submit_once()
        sig, pem = _witness_material("ab" * 32)
        sub2 = _submit_once(rekor_v2_witness=stub,
                            witness_signature_b64=sig,
                            witness_pubkey_pem=pem)
        if stub.attaches != 0:
            return _record(name, "BREAK",
                           "stub consulted %d times with flag off"
                           % (stub.attaches,))
        if "witnesses" in sub2:
            return _record(name, "BREAK",
                           "'witnesses' filed with flag off")
        if _canonical(sub1) != _canonical(sub2):
            return _record(name, "BREAK",
                           "flag-off return not byte-identical when "
                           "always-on stub passed")
        _record(name, "HELD",
                "flag-off: exact key set, stub untouched, byte-identical")
    finally:
        _env_restore(saved)


def w_flag_on_attaches():
    name = "w_flag_on_attaches"
    saved = _env_clean()
    try:
        os.environ["GOV_REKOR_V2_WITNESS"] = "1"
        h = _Harness()
        # Seal first to learn the digest, then submit with witness
        # material for that digest.
        ca = h.make_ca()
        cert, seed, _pub = h.issue_cert(ca)
        body = {"decision": "deny"}
        asig = ed.sign(seed, _canonical(body))
        sealed = eb2.seal_evidence(
            artifact_body=body, cert=cert,
            artifact_signature=bytes(asig),
            approval_id=APPROVAL, intent_digest=INTENT,
            ca_public_key=bytes(h.ca_pub), verify_time=NOW)
        digest = sealed["artifact"]["artifact_digest"]
        sig, pem = _witness_material(digest)
        witness = rvw.RekorV2Witness(
            signing_config=_signing_config_doc())
        log = eb2.make_log(
            producer_auth_verifier=eb2.default_producer_auth_verifier,
            log_id=LOG_ID, now=lambda: NOW)
        try:
            sub = eb2.submit_evidence(
                artifact_body=body, cert=cert,
                artifact_signature=bytes(asig),
                approval_id=APPROVAL, intent_digest=INTENT,
                ca_public_key=bytes(h.ca_pub), verify_time=NOW,
                audit_log_path=h.audit_path, transparency_log=log,
                rekor_v2_witness=witness,
                witness_signature_b64=sig,
                witness_pubkey_pem=pem)
        except TypeError as e:
            return _record(name, "BREAK",
                           "seam refused wiring kwargs: %s" % (e,))
        wit = sub.get("witnesses")
        if not isinstance(wit, list) or len(wit) != 1:
            return _record(name, "BREAK",
                           "witnesses slot missing/malformed: %r" % (wit,))
        rec = wit[0]
        if rec.get("status") != "attached":
            return _record(name, "BREAK",
                           "status=%r reason=%r"
                           % (rec.get("status"), rec.get("reason")))
        gen = rec.get("log_generation") or {}
        if gen.get("log_id") != _TEST_LOG_ID \
                or gen.get("log_url") != _TEST_V2_URL:
            return _record(name, "BREAK",
                           "log generation not pinned: %r" % (gen,))
        if rec.get("evidentiary_grade") != "digest-existence-only":
            return _record(name, "BREAK",
                           "evidentiary grade overstated: %r"
                           % (rec.get("evidentiary_grade"),))
        if rec.get("authority_proof") is not False:
            return _record(name, "BREAK", "authority_proof is not False")
        receipt = rec.get("receipt") or {}
        if receipt.get("anchor_hash") != digest:
            return _record(name, "BREAK",
                           "entry does not commit the bundle digest")
        if receipt.get("verification.source") != "rekor-v2-hermetic":
            return _record(name, "BREAK",
                           "unexpected receipt source: %r"
                           % (receipt.get("verification.source"),))
        if "transparency_receipt" not in sub:
            return _record(name, "BREAK",
                           "primary anchor receipt missing")
        _record(name, "HELD",
                "attached; generation pinned; digest-only honesty kept; "
                "primary receipt intact")
    finally:
        _env_restore(saved)


def w_flag_on_failure_degrades():
    name = "w_flag_on_failure_degrades"
    saved = _env_clean()
    try:
        os.environ["GOV_REKOR_V2_WITNESS"] = "1"
        h = _Harness()
        witness = rvw.RekorV2Witness(
            signing_config=_signing_config_doc(),
            client=_FailingClient())
        sig, pem = _witness_material("ab" * 32)
        try:
            sub, digest = h.submit(rekor_v2_witness=witness,
                                   witness_signature_b64=sig,
                                   witness_pubkey_pem=pem)
        except TypeError as e:
            return _record(name, "BREAK",
                           "seam refused wiring kwargs: %s" % (e,))
        except Exception as e:
            return _record(name, "BREAK",
                           "witness outage raised through issuance: %r" % (e,))
        wit = sub.get("witnesses")
        if not isinstance(wit, list) or len(wit) != 1:
            return _record(name, "BREAK",
                           "witnesses slot missing after outage: %r" % (wit,))
        rec = wit[0]
        if rec.get("status") != "failed":
            return _record(name, "BREAK",
                           "outage status=%r, want 'failed'" % (rec.get("status"),))
        if "outage" not in (rec.get("reason") or ""):
            return _record(name, "BREAK",
                           "failure reason not honest: %r" % (rec.get("reason"),))
        if "transparency_receipt" not in sub:
            return _record(name, "BREAK",
                           "primary anchor lost on witness outage")
        _record(name, "HELD",
                "outage -> 'failed' record; issuance + primary intact")
    finally:
        _env_restore(saved)


def w_flag_on_no_config_honest():
    name = "w_flag_on_no_config_honest"
    saved = _env_clean()
    try:
        os.environ["GOV_REKOR_V2_WITNESS"] = "1"
        h = _Harness()
        try:
            sub, _digest = h.submit()
        except TypeError as e:
            return _record(name, "BREAK",
                           "seam refused wiring kwargs: %s" % (e,))
        except Exception as e:
            return _record(name, "BREAK",
                           "missing config raised through issuance: %r" % (e,))
        wit = sub.get("witnesses")
        if not isinstance(wit, list) or len(wit) != 1:
            return _record(name, "BREAK",
                           "witnesses slot missing: %r" % (wit,))
        rec = wit[0]
        if rec.get("status") != "failed":
            return _record(name, "BREAK",
                           "status=%r, want 'failed'" % (rec.get("status"),))
        reason = rec.get("reason") or ""
        if "signing config" not in reason and "ShardDiscovery" not in reason:
            return _record(name, "BREAK",
                           "reason does not name the cause: %r" % (reason,))
        _record(name, "HELD",
                "no config -> honest 'failed'; issuance unaffected")
    finally:
        _env_restore(saved)


def w_primary_anchor_unchanged():
    name = "w_primary_anchor_unchanged"
    saved = _env_clean()
    try:
        # Flag-off baseline.
        h1 = _Harness()
        sub_off, _d = h1.submit()
        r_off = sub_off["transparency_receipt"]
        # Flag-on run of the same body.
        os.environ["GOV_REKOR_V2_WITNESS"] = "1"
        h2 = _Harness()
        ca = h2.make_ca()
        cert, seed, _pub = h2.issue_cert(ca)
        body = {"decision": "deny"}
        asig = ed.sign(seed, _canonical(body))
        sealed = eb2.seal_evidence(
            artifact_body=body, cert=cert,
            artifact_signature=bytes(asig),
            approval_id=APPROVAL, intent_digest=INTENT,
            ca_public_key=bytes(h2.ca_pub), verify_time=NOW)
        digest = sealed["artifact"]["artifact_digest"]
        sig, pem = _witness_material(digest)
        witness = rvw.RekorV2Witness(
            signing_config=_signing_config_doc())
        log = eb2.make_log(
            producer_auth_verifier=eb2.default_producer_auth_verifier,
            log_id=LOG_ID, now=lambda: NOW)
        try:
            sub_on = eb2.submit_evidence(
                artifact_body=body, cert=cert,
                artifact_signature=bytes(asig),
                approval_id=APPROVAL, intent_digest=INTENT,
                ca_public_key=bytes(h2.ca_pub), verify_time=NOW,
                audit_log_path=h2.audit_path, transparency_log=log,
                rekor_v2_witness=witness,
                witness_signature_b64=sig,
                witness_pubkey_pem=pem)
        except TypeError as e:
            return _record(name, "BREAK",
                           "seam refused wiring kwargs: %s" % (e,))
        r_on = sub_on["transparency_receipt"]
        if _canonical(r_off) != _canonical(r_on):
            return _record(name, "BREAK",
                           "primary receipt changed under flag-on")
        d_off = sub_off["sealed"]["artifact"]["artifact_digest"]
        d_on = sub_on["sealed"]["artifact"]["artifact_digest"]
        if d_off != d_on:
            return _record(name, "BREAK", "bundle digest changed")
        wit = sub_on.get("witnesses") or []
        if not wit or wit[0].get("status") != "attached":
            return _record(name, "BREAK", "second witness did not attach")
        _record(name, "HELD",
                "primary receipt byte-identical; witness only adds")
    finally:
        _env_restore(saved)


def w_claim_path_flag_off():
    name = "w_claim_path_flag_off"
    saved = _env_clean()
    try:
        h = _Harness()
        try:
            sub = h.submit_claim_path()
        except TypeError as e:
            return _record(name, "BREAK",
                           "claim seam refused wiring kwargs: %s" % (e,))
        keys = frozenset(sub.keys())
        if keys != BASE_CLAIM_KEYS:
            return _record(name, "BREAK",
                           "claim-path flag-off key set drifted: %s"
                           % sorted(keys - BASE_CLAIM_KEYS))
        if "witnesses" in sub:
            return _record(name, "BREAK",
                           "'witnesses' slot present with flag off")
        _record(name, "HELD",
                "claim path flag-off: exact key set, no witnesses slot")
    finally:
        _env_restore(saved)


def w_broken_witness_never_breaks():
    name = "w_broken_witness_never_breaks"
    saved = _env_clean()
    try:
        os.environ["GOV_REKOR_V2_WITNESS"] = "1"
        h = _Harness()
        try:
            sub, _digest = h.submit(rekor_v2_witness=_RaisingWitness())
        except TypeError as e:
            return _record(name, "BREAK",
                           "seam refused wiring kwargs: %s" % (e,))
        except Exception as e:
            return _record(name, "BREAK",
                           "broken witness broke issuance: %r" % (e,))
        wit = sub.get("witnesses")
        if not isinstance(wit, list) or len(wit) != 1:
            return _record(name, "BREAK",
                           "witnesses slot missing: %r" % (wit,))
        rec = wit[0]
        if rec.get("status") != "failed":
            return _record(name, "BREAK",
                           "status=%r, want 'failed'" % (rec.get("status"),))
        if "transparency_receipt" not in sub:
            return _record(name, "BREAK",
                           "primary anchor lost on witness defect")
        _record(name, "HELD",
                "non-conforming witness -> 'failed'; issuance intact")
    finally:
        _env_restore(saved)


def _run_all():
    w_wire_params_present()
    w_flag_off_byte_identical()
    w_flag_on_attaches()
    w_flag_on_failure_degrades()
    w_flag_on_no_config_honest()
    w_primary_anchor_unchanged()
    w_claim_path_flag_off()
    w_broken_witness_never_breaks()


def green_check():
    """Depth-1 green check: adjacent unit suites, no nested batteries.

    Honors GOV_SKIP_GREEN (set in child envs by parent batteries).
    """
    if os.environ.get("GOV_SKIP_GREEN"):
        print("green_check: skipped (GOV_SKIP_GREEN set)")
        return True
    suites = ["tests.test_evbundle", "tests.test_producer_authz",
              "tests.test_rekor_v2_witness"]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for suite in suites:
        r = subprocess.run(
            [sys.executable, "-m", "unittest", suite],
            cwd=REPO_ROOT, env=env,
            capture_output=True, text=True, timeout=600)
        tail = (r.stderr.strip().splitlines() or [""])[-1]
        print("green_check %-28s %s" % (suite, tail))
        if r.returncode != 0:
            print(r.stderr[-2000:])
            return False
    return True


def main():
    _run_all()
    ok = green_check()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("w278_rekor_wire_probes: "
          "%d HELD / %d BREAK / %d ERROR / green=%s"
          % (held, brk, err, ok))
    return 1 if (brk or err or not ok) else 0


if __name__ == "__main__":
    sys.exit(main())
