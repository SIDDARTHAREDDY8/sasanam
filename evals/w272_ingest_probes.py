#!/usr/bin/env python3
"""Wave-272 red-first battery: evidence-ingest gate.

The Kyverno-verifyImages watch for evidence bundles: an admission-time
verify-analog at the bundle-INGEST seam. Before a received evidence
bundle is trusted, the gate re-verifies (a) the signature attestation
against the consumer's registered transparency log, (b) the issuance
attestation chain including the producer-authorization claim, (c)
content digests against the revision binding, and (d) a bounded-
staleness rule with freshness annotations. Background scans re-check
previously-admitted bundles against current policy and emit drift
events when a previously-admitted bundle would now be refused.

Steals (pattern, clean-room): kyverno/kyverno @ 1c002d57 (Apache-2.0) --
verifyImages admission split (enforce blocks / audit records), the
background-scan loop (per-resource ephemeral reports overwritten in
place, last-scan-time, forced-rescan interval, partial reconcile), and
the traps NOT reproduced (no FailurePolicy kill-switch, no ambient
mode downgrade, scan errors are loud, reports are operator state).

Red phase:  GOV_INGEST_IMPL=stub  -> permissive foil. Every attack
probe must BREAK (the foil admits everything); a probe that HELDs on
the stub is vacuous and is flagged.
Green phase: default (gov.evidence_ingest_gate) -> every probe HELD.

The foil fakes ONLY the gate (IngestGate); fixtures are built with the
real v2 bundle seam (gov.evidence_bundle_v2 through the audited
evidence-cert ceremony), the real policy/binding/freshness helpers.
Protocol constants below are pinned independently of the module under
test (canonical JSON form, fixed clock); the battery never imports
gov.evidence_ingest_gate's internals.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; depth-1 green checks honoring
GOV_SKIP_GREEN=1; per-probe dirs under the runner-supplied TMPDIR
(convention: fresh unique /var/tmp/g272* created with mkdir -p before
the run); NO in-repo git subprocesses.
"""

import base64
import copy
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# The audit-log HMAC chain needs an explicit key (wave-81: no dev-key
# fallback anywhere). Batteries provision their own, like w270/w271.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w272-ingest")

# -- protocol constants pinned independently of the module under test --
POP_DOMAIN = b"evcert-pop-v1"
NOW = 1790960000  # fixed test clock (2026-10-02-ish)
ARC = "1.3.6.1.4.1.99999"
ISSUER = "https://issuer.example.com"
APPROVAL = "a" * 32
INTENT = "d" * 64
REV = "ab" * 32          # audit-chain revision referenced by the bundle
REV_STALE = "cd" * 32    # an old revision
ISSUER_SEED = bytes([0xA5]) * 32  # deployment freshness-issuer key
OTHER_SEED = bytes([0x5A]) * 32   # a forger's key
PIN = 1812  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 7: pin 1541 -> 1545 (+4 casbin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-290 merge: pin 1706 -> 1710 (+4 provenance-rebuild-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*) ; Wave-295 lane 4: pin 1742 -> 1746 (+4 coord-state-*); Wave-295 merge: pin 1746 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import ed25519 as _ed  # noqa: E402
from gov import evidence_certs as _ec  # noqa: E402
from gov import kms as _kms  # noqa: E402
from gov import evidence_bundle_v2 as _v2  # noqa: E402
from gov import evidence_ingest_gate as _real_ingest  # noqa: E402


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


# ---------------------------------------------------------------------------
# Permissive foil (red phase): same gate API, zero checks
# ---------------------------------------------------------------------------

class _FoilError(Exception):
    pass


class _FoilGate(object):
    def __init__(self, **kw):
        self._kw = kw
        self._admissions = {}

    def _ok(self, bundle_id, now=None):
        return {"format": "evidence-ingest.v2",
                "bundle_id": bundle_id, "verdict": "admit",
                "code": "ingest-admit", "blocked": False,
                "policy_version": "foil",
                "evaluated_at": now or NOW,
                "evidence": {}, "out_of_scope": ()}

    def evaluate(self, *, bundle_id, submission, verify_time, now=None):
        return self._ok(bundle_id, now)

    def admit(self, *, bundle_id, submission, verify_time, now=None):
        self._admissions[bundle_id] = submission
        return self._ok(bundle_id, now)

    def scan(self, *, now=None, verify_time=None):
        return {"scanned": 0, "reevaluated": 0, "drifted": 0,
                "scanned_at": now or NOW, "policy_version": "foil"}

    def set_policy(self, policy):
        return {"event": "ingest-policy-switched"}

    def drift_events(self):
        return []

    def scan_report(self, bundle_id):
        if bundle_id in self._admissions:
            return {"verdict": "admit", "code": "ingest-admit",
                    "drift": False}
        return None


class _FoilModule(object):
    EvidenceIngestGateError = _FoilError
    IngestPolicy = _real_ingest.IngestPolicy
    IngestGate = _FoilGate
    RevisionBinding = _real_ingest.RevisionBinding
    InMemoryRevisionBinding = _real_ingest.InMemoryRevisionBinding
    make_freshness_annotation = staticmethod(
        _real_ingest.make_freshness_annotation)


def _mod(impl):
    if impl == "stub":
        return _FoilModule()
    return _real_ingest


# ---------------------------------------------------------------------------
# Real fixtures: a sealed v2 submission through the audited ceremony
# ---------------------------------------------------------------------------

def _keypair(seed_byte):
    seed = bytes([seed_byte & 0xFF]) * 32
    return seed, _ed.publickey(seed)


def _make_ca(tmpdir, audit_name="audit.jsonl", key_id="ca-key-1", **over):
    fake = _kms.FakeKmsProvider([key_id])
    approvals = {APPROVAL: {"decider": "alice", "state": "pending"}}
    kw = dict(kms_provider=fake,
              ca_key_id=key_id,
              ca_public_key=fake.test_signing_public_key(key_id),
              issuers=[ISSUER],
              approval_lookup=approvals.get,
              audit_log_path=os.path.join(tmpdir, audit_name),
              anchor_reachable=lambda: True,
              oid_arc=ARC,
              now=lambda: NOW)
    kw.update(over)
    return _ec.EvidenceCA(**kw), fake


def _issue_cert(ca, seed_byte=0x01, approval_id=APPROVAL, sub="alice"):
    seed, pub = _keypair(seed_byte)
    chal = POP_DOMAIN + approval_id.encode("utf-8")\
        + hashlib.sha256(pub).digest()
    req = {"identity_assertion": {"iss": ISSUER, "sub": sub,
                                 "exp": NOW + 3600},
           "ephemeral_pub": pub,
           "pop_sig": _ed.sign(seed, chal),
           "approval_id": approval_id,
           "intent_digest": INTENT}
    cert, _entry = ca.issue(**req)
    return cert, seed, pub


def _submission(tmpdir, *, revision=REV, body_extra=None, tamper=None,
                ca=None, seed_byte=0x01, audit_name="audit.jsonl",
                log_id="consumer-log-1"):
    """Build a genuine evidence-submission.v2 via the v2 seam."""
    if ca is None:
        ca, fake = _make_ca(tmpdir, audit_name=audit_name)
    else:
        fake = None
    cert, seed, _pub = _issue_cert(ca, seed_byte=seed_byte)
    body = {"note": "ingest-probe", "audit_revision_digest": revision}
    if revision is None:
        del body["audit_revision_digest"]
    if body_extra:
        body.update(body_extra)
    art_bytes = _canonical(body)
    sig = _ed.sign(seed, art_bytes)
    log = _v2.make_log(producer_auth_verifier=
                       _v2.default_producer_auth_verifier,
                       log_id=log_id, now=lambda: NOW)
    submission = _v2.submit_evidence(
        artifact_body=body, cert=cert, artifact_signature=sig,
        approval_id=APPROVAL, intent_digest=INTENT,
        audit_log_path=ca._audit_log_path,
        ca_public_key=(fake.test_signing_public_key("ca-key-1")
                       if fake else ca._ca_public_key),
        verify_time=NOW, transparency_log=log, now=lambda: NOW)
    if tamper == "body":
        submission = copy.deepcopy(submission)
        submission["sealed"]["artifact"]["body"]["note"] = "tampered"
    if tamper == "sig":
        submission = copy.deepcopy(submission)
        raw = bytearray(base64.b64decode(
            submission["sealed"]["signature_attestation"]["signature"]))
        raw[0] ^= 0x01
        submission["sealed"]["signature_attestation"]["signature"] =\
            base64.b64encode(bytes(raw)).decode("ascii")
    if tamper == "root":
        submission = copy.deepcopy(submission)
        root = submission["transparency_receipt"]["root"]
        submission["transparency_receipt"]["root"] =\
            ("0" if root[0] != "0" else "1") + root[1:]
    return submission, ca, log, fake


def _gate(mod, tmpdir, *, mode="enforce", horizon=3600, interval=60,
          ttl=600, log=None, audit_name="audit.jsonl", ca_pub=None,
          binding=None, registered_time=None, revision=REV,
          artifact_digest=None):
    if log is None:
        log = _v2.make_log(producer_auth_verifier=
                           _v2.default_producer_auth_verifier,
                           log_id="consumer-log-1", now=lambda: NOW)
    if ca_pub is None:
        ca, fake = _make_ca(tmpdir, audit_name=audit_name)
        ca_pub = fake.test_signing_public_key("ca-key-1")
    if binding is None:
        binding = mod.InMemoryRevisionBinding(now=lambda: NOW)
        if artifact_digest is not None:
            binding.register_revision(
                revision, [artifact_digest],
                registered_time=(NOW - 60 if registered_time is None
                                 else registered_time))
    policy = mod.IngestPolicy(
        mode=mode, max_staleness_seconds=horizon,
        force_rescan_interval_s=interval,
        freshness_annotation_ttl_s=ttl,
        freshness_issuer_pub=_ed.publickey(ISSUER_SEED),
        policy_version="ingest-policy/test-v1")
    return mod.IngestGate(
        policy=policy, transparency_log=log,
        audit_log_path=os.path.join(tmpdir, audit_name),
        ca_public_key=ca_pub, revision_binding=binding,
        now=lambda: NOW)


def _fixture(tmpdir, mod, **kw):
    """A benign, fully-bound, fresh submission plus a gate that
    should admit it."""
    submission, ca, log, _fk = _submission(tmpdir, **kw)
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    rev = kw.get("revision", REV)
    gate = _gate(mod, tmpdir, log=log,
                 artifact_digest=digest, revision=rev)
    return gate, submission, digest


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

PROBES = []


def probe(name, kind):
    def deco(fn):
        PROBES.append((name, kind, fn))
        return fn
    return deco


def _tmp():
    return tempfile.mkdtemp(prefix="g272-ingest-")


@probe("c01-benign-admitted", "control")
def p_c01(mod):
    gate, submission, _d = _fixture(_tmp(), mod)
    v = gate.admit(bundle_id="b1", submission=submission, verify_time=NOW)
    if v["verdict"] != "admit" or v["code"] != "ingest-admit"\
            or v["blocked"]:
        return ("BREAK", "benign not admitted: %r" % (v,))
    rep = gate.scan_report("b1")
    if rep is None or rep["verdict"] != "admit":
        return ("BREAK", "no ephemeral report: %r" % (rep,))
    return ("HELD", "benign admitted; ephemeral report written")


@probe("c02-stale-with-valid-annotation-admitted", "control")
def p_c02(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp, revision=REV_STALE)
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    binding = mod.InMemoryRevisionBinding(now=lambda: NOW)
    binding.register_revision(REV_STALE, [digest],
                              registered_time=NOW - 7200)
    ann = mod.make_freshness_annotation(
        revision_digest=REV_STALE, bundle_id="b2", issuer_seed=ISSUER_SEED,
        annotated_time=NOW - 100)
    submission = copy.deepcopy(submission)
    submission["freshness_annotation"] = ann
    gate = _gate(mod, tmp, log=log, binding=binding, horizon=3600)
    v = gate.admit(bundle_id="b2", submission=submission, verify_time=NOW)
    if v["verdict"] != "admit":
        return ("BREAK", "annotated stale not admitted: %r" % (v,))
    return ("HELD", "stale revision admitted with valid annotation")


@probe("c03-audit-mode-records-never-blocks", "control")
def p_c03(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp, revision=REV_STALE)
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    binding = mod.InMemoryRevisionBinding(now=lambda: NOW)
    binding.register_revision(REV_STALE, [digest],
                              registered_time=NOW - 7200)
    gate = _gate(mod, tmp, log=log, binding=binding, horizon=3600,
                 mode="audit")
    v = gate.admit(bundle_id="b3", submission=submission, verify_time=NOW)
    if v["verdict"] != "audit-recorded" or v["blocked"]\
            or v["code"] != "ingest-stale-revision":
        return ("BREAK", "audit mode misbehaved: %r" % (v,))
    return ("HELD", "audit mode recorded the would-deny, did not block")


@probe("c04-hostile-never-raises", "control")
def p_c04(mod):
    gate, _s, _d = _fixture(_tmp(), mod)
    v = gate.evaluate(bundle_id="x", submission={"garbage": 1},
                      verify_time=NOW)
    if v["verdict"] != "deny" or v["code"] != "ingest-malformed"\
            or not v["blocked"]:
        return ("BREAK", "hostile not fail-closed: %r" % (v,))
    return ("HELD", "hostile submission denied, no raise")


@probe("c05-partial-reconcile", "control")
def p_c05(mod):
    gate, submission, _d = _fixture(_tmp(), mod)
    gate.admit(bundle_id="b5", submission=submission, verify_time=NOW)
    s1 = gate.scan(now=NOW)
    s2 = gate.scan(now=NOW + 120)
    if s1["reevaluated"] != 0:
        return ("BREAK", "immediate rescan re-evaluated: %r" % (s1,))
    if s2["reevaluated"] != 1 or s2["drifted"] != 0:
        return ("BREAK", "interval rescan wrong: %r" % (s2,))
    rep = gate.scan_report("b5")
    if rep is None or rep["drift"] or rep["verdict"] != "admit":
        return ("BREAK", "report wrong after rescan: %r" % (rep,))
    return ("HELD", "unchanged policy skipped; interval forced rescan")


@probe("c06-pin-check", "control")
def p_c06(mod):
    src = open(os.path.join(_REPO, "gov", "decision_codes.py")).read()
    import re
    codes = re.findall(
        r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    from collections import Counter
    dups = [c for c, n in Counter(codes).items() if n > 1]
    if len(codes) != PIN or len(set(codes)) != PIN or dups:
        return ("BREAK", "pin %d: %d literals %d unique dups=%s"
                % (PIN, len(codes), len(set(codes)), dups))
    return ("HELD", "pin %d literals/%d unique/0 dups" % (PIN, PIN))


@probe("a01-forged-transparency-receipt-refused", "attack")
def p_a01(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp, tamper="root")
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    gate = _gate(mod, tmp, log=log, artifact_digest=digest)
    v = gate.admit(bundle_id="ba1", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "forged receipt root admitted")
    if v["code"] != "ingest-signature-unverified" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "forged transparency receipt refused")


@probe("a02-receipt-from-other-log-refused", "attack")
def p_a02(mod):
    tmp = _tmp()
    submission, ca, _log, _fk = _submission(tmp)
    other = _v2.make_log(
        producer_auth_verifier=_v2.default_producer_auth_verifier,
        log_id="attacker-log", now=lambda: NOW)
    other_receipt = other.submit(
        submission["sealed"]["artifact"]["artifact_digest"],
        producer_auth={
            "kind": "evidence-cert",
            "cert": submission["sealed"]["cert"],
            "artifact_bytes": _canonical(
                submission["sealed"]["artifact"]["body"]),
            "artifact_signature": base64.b64decode(
                submission["sealed"]["signature_attestation"][
                    "signature"]),
            "approval_id": APPROVAL,
            "intent_digest": INTENT,
            "ca_public_key": _fk.test_signing_public_key("ca-key-1"),
            "verify_time": NOW})
    submission = copy.deepcopy(submission)
    submission["transparency_receipt"] = other_receipt
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    gate = _gate(mod, tmp, log=_log, artifact_digest=digest)
    v = gate.admit(bundle_id="ba2", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "cross-log receipt admitted")
    if v["code"] != "ingest-signature-unverified" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "receipt from another log refused")


@probe("a03-tampered-attestation-signature-refused", "attack")
def p_a03(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp, tamper="sig")
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    gate = _gate(mod, tmp, log=log, artifact_digest=digest)
    v = gate.admit(bundle_id="ba3", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "tampered attestation signature admitted")
    if v["code"] != "ingest-producer-unauthorized" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "tampered signature refused as unauthorized producer")


@probe("a04-tampered-artifact-body-refused", "attack")
def p_a04(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp, tamper="body")
    digest = "ff" * 32  # original digest no longer matches
    gate = _gate(mod, tmp, log=log, artifact_digest=digest)
    v = gate.admit(bundle_id="ba4", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "tampered artifact body admitted")
    if v["code"] != "ingest-malformed" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "tampered artifact body refused")


@probe("a05-untrusted-ca-refused", "attack")
def p_a05(mod):
    tmp = _tmp()
    # A second, rogue CA under a DIFFERENT key id (FakeKmsProvider
    # derives deterministic keys per key id, so a different id is a
    # genuinely different trust root).
    rogue_ca, rogue_fake = _make_ca(tmp, audit_name="rogue-audit.jsonl",
                                    key_id="ca-key-rogue")
    submission, _c, log, _fk = _submission(tmp, ca=rogue_ca,
                                      audit_name="audit.jsonl")
    # The consumer's gate trusts only the honest CA key.
    honest_ca, honest_fake = _make_ca(tmp, audit_name="honest-audit.jsonl")
    honest_pub = honest_fake.test_signing_public_key("ca-key-1")
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    binding = _real_ingest.InMemoryRevisionBinding(now=lambda: NOW)
    binding.register_revision(REV, [digest], registered_time=NOW - 60)
    policy = _real_ingest.IngestPolicy(
        mode="enforce", max_staleness_seconds=3600,
        force_rescan_interval_s=60, freshness_annotation_ttl_s=600,
        freshness_issuer_pub=_ed.publickey(ISSUER_SEED),
        policy_version="ingest-policy/test-v1")
    # The consumer's gate trusts only the honest CA key; point it at the
    # rogue replicated log so issuance is present and only the chain
    # check fails.
    gate = mod.IngestGate(
        policy=policy, transparency_log=log,
        audit_log_path=os.path.join(tmp, "rogue-audit.jsonl"),
        ca_public_key=honest_pub, revision_binding=binding,
        now=lambda: NOW)
    v = gate.admit(bundle_id="ba5", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "rogue-CA bundle admitted")
    if v["code"] != "ingest-producer-unauthorized" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "rogue-CA bundle refused")


@probe("a06-missing-issuance-refused", "attack")
def p_a06(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp, audit_name="audit.jsonl")
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    # Consumer's replicated log has no issuance attestation for this cert.
    empty = os.path.join(tmp, "empty.jsonl")
    open(empty, "w").close()
    binding = _real_ingest.InMemoryRevisionBinding(now=lambda: NOW)
    binding.register_revision(REV, [digest], registered_time=NOW - 60)
    policy = _real_ingest.IngestPolicy(
        mode="enforce", max_staleness_seconds=3600,
        force_rescan_interval_s=60, freshness_annotation_ttl_s=600,
        freshness_issuer_pub=_ed.publickey(ISSUER_SEED),
        policy_version="ingest-policy/test-v1")
    _ca2, fake2 = _make_ca(tmp, audit_name="audit2.jsonl")
    gate = mod.IngestGate(
        policy=policy, transparency_log=log, audit_log_path=empty,
        ca_public_key=fake2.test_signing_public_key("ca-key-1"),
        revision_binding=binding, now=lambda: NOW)
    v = gate.admit(bundle_id="ba6", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "bundle without issuance admitted")
    if v["code"] != "ingest-issuance-unverifiable" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "missing issuance attestation refused")


@probe("a07-unbound-revision-refused", "attack")
def p_a07(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp)
    # Binding registers the revision but NOT this artifact digest.
    binding = mod.InMemoryRevisionBinding(now=lambda: NOW)
    binding.register_revision(REV, ["00" * 32], registered_time=NOW - 60)
    gate = _gate(mod, tmp, log=log, binding=binding)
    v = gate.admit(bundle_id="ba7", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "unbound content admitted")
    if v["code"] != "ingest-revision-unbound" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "unbound content refused")


@probe("a08-missing-revision-ref-refused", "attack")
def p_a08(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp, revision=None)
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    gate = _gate(mod, tmp, log=log, artifact_digest=digest)
    v = gate.admit(bundle_id="ba8", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "revision-less bundle admitted")
    if v["code"] != "ingest-revision-unbound" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "revision-less bundle refused")


@probe("a09-stale-revision-refused", "attack")
def p_a09(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp, revision=REV_STALE)
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    binding = mod.InMemoryRevisionBinding(now=lambda: NOW)
    binding.register_revision(REV_STALE, [digest],
                              registered_time=NOW - 7200)
    gate = _gate(mod, tmp, log=log, binding=binding, horizon=3600)
    v = gate.admit(bundle_id="ba9", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "stale revision admitted without annotation")
    if v["code"] != "ingest-stale-revision" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "stale revision refused")


@probe("a10-forged-freshness-annotation-refused", "attack")
def p_a10(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp, revision=REV_STALE)
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    binding = mod.InMemoryRevisionBinding(now=lambda: NOW)
    binding.register_revision(REV_STALE, [digest],
                              registered_time=NOW - 7200)
    ann = mod.make_freshness_annotation(
        revision_digest=REV_STALE, bundle_id="ba10",
        issuer_seed=OTHER_SEED, annotated_time=NOW - 100)
    submission = copy.deepcopy(submission)
    submission["freshness_annotation"] = ann
    gate = _gate(mod, tmp, log=log, binding=binding, horizon=3600)
    v = gate.admit(bundle_id="ba10", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "forged freshness annotation admitted")
    if v["code"] != "ingest-freshness-invalid" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "forged freshness annotation refused")


@probe("a11-expired-freshness-annotation-refused", "attack")
def p_a11(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp, revision=REV_STALE)
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    binding = mod.InMemoryRevisionBinding(now=lambda: NOW)
    binding.register_revision(REV_STALE, [digest],
                              registered_time=NOW - 7200)
    ann = mod.make_freshness_annotation(
        revision_digest=REV_STALE, bundle_id="ba11",
        issuer_seed=ISSUER_SEED, annotated_time=NOW - 1200)
    submission = copy.deepcopy(submission)
    submission["freshness_annotation"] = ann
    gate = _gate(mod, tmp, log=log, binding=binding, horizon=3600,
                 ttl=600)
    v = gate.admit(bundle_id="ba11", submission=submission,
                   verify_time=NOW)
    if v["verdict"] == "admit":
        return ("BREAK", "expired freshness annotation admitted")
    if v["code"] != "ingest-freshness-invalid" or not v["blocked"]:
        return ("BREAK", "wrong code: %r" % (v,))
    return ("HELD", "expired freshness annotation refused")


@probe("a12-policy-tightening-drift-detected", "attack")
def p_a12(mod):
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp)
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    binding = mod.InMemoryRevisionBinding(now=lambda: NOW)
    binding.register_revision(REV, [digest], registered_time=NOW - 60)
    # Admit under a lax horizon, then tighten the policy.
    gate = _gate(mod, tmp, log=log, binding=binding, horizon=10 ** 9)
    v = gate.admit(bundle_id="ba12", submission=submission,
                   verify_time=NOW)
    if v["verdict"] != "admit":
        return ("BREAK", "setup admit failed: %r" % (v,))
    tight = _real_ingest.IngestPolicy(
        mode="enforce", max_staleness_seconds=1,
        force_rescan_interval_s=60, freshness_annotation_ttl_s=600,
        freshness_issuer_pub=_ed.publickey(ISSUER_SEED),
        policy_version="ingest-policy/test-v2")
    gate.set_policy(tight)
    s = gate.scan(now=NOW + 120, verify_time=NOW + 120)
    rep = gate.scan_report("ba12")
    if s["drifted"] != 1 or rep is None or not rep["drift"]\
            or rep["code"] != "ingest-stale-revision":
        return ("BREAK", "drift not detected: %r %r" % (s, rep))
    events = gate.drift_events()
    if len(events) != 1 or events[0]["bundle_id"] != "ba12":
        return ("BREAK", "drift event missing: %r" % (events,))
    return ("HELD", "policy tightening surfaced as a drift event")


@probe("a14-audit-mode-drift-detected", "control")
def p_a14(mod):
    # Audit mode never blocks, but the Kyverno audit/watch posture
    # must still surface drift: a would-deny under a tightened policy
    # is "would now be refused". (Spec-axis finding: drift was keyed
    # on the verdict string "deny", which audit mode never returns.)
    tmp = _tmp()
    submission, ca, log, _fk = _submission(tmp)
    digest = submission["sealed"]["artifact"]["artifact_digest"]
    binding = mod.InMemoryRevisionBinding(now=lambda: NOW)
    binding.register_revision(REV, [digest], registered_time=NOW - 60)
    gate = _gate(mod, tmp, log=log, binding=binding, horizon=10 ** 9,
                 mode="audit")
    v = gate.admit(bundle_id="ba14", submission=submission,
                   verify_time=NOW)
    if v["verdict"] != "admit":
        return ("BREAK", "setup admit failed: %r" % (v,))
    tight = _real_ingest.IngestPolicy(
        mode="audit", max_staleness_seconds=1,
        force_rescan_interval_s=60, freshness_annotation_ttl_s=600,
        freshness_issuer_pub=_ed.publickey(ISSUER_SEED),
        policy_version="ingest-policy/test-v2")
    gate.set_policy(tight)
    s = gate.scan(now=NOW + 120, verify_time=NOW + 120)
    rep = gate.scan_report("ba14")
    if s["drifted"] != 1 or rep is None or not rep["drift"]\
            or rep["code"] != "ingest-stale-revision":
        return ("BREAK", "audit-mode drift not detected: %r %r" % (s, rep))
    events = gate.drift_events()
    if len(events) != 1 or events[0]["bundle_id"] != "ba14":
        return ("BREAK", "drift event missing: %r" % (events,))
    return ("HELD", "audit-mode policy tightening surfaced as drift")


@probe("a13-scan-error-is-loud", "attack")
def p_a13(mod):
    gate, submission, _d = _fixture(_tmp(), mod)
    gate.admit(bundle_id="ba13", submission=submission, verify_time=NOW)
    gate._admissions["ba13"].pop("_submission", None)  # corrupt the record
    s = gate.scan(now=NOW + 120, verify_time=NOW + 120)
    rep = gate.scan_report("ba13")
    if rep is None or rep["code"] != "ingest-scan-error":
        return ("BREAK", "scan error not loud: %r" % (rep,))
    return ("HELD", "scan error recorded loudly, no raise, no stale pass")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent v2-bundle unit suite with GOV_SKIP_GREEN=1 in
    the child env (it has no green check of its own)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP", "GOV_SKIP_GREEN=1 (depth-1)")
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = tempfile.mkdtemp(prefix="g272-green-")
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_evbundle", "-v"],
        cwd=_REPO, env=env, capture_output=True, text=True, timeout=600)
    if p.returncode == 0:
        return ("HELD", "tests/test_evbundle green (depth-1)")
    return ("BREAK", "adjacent suite red:\n%s" % (p.stderr[-2000:],))


def main():
    impl = os.environ.get("GOV_INGEST_IMPL", "real")
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
            brk += 1  # ERROR count as failure
    gv, gd = _green_check()
    print("green-check: %s %s" % (gv, gd))
    print("RESULT impl=%s HELD=%d BREAK=%d VACUOUS=%d" %
          (impl, held, brk, vacuous))
    if impl == "stub":
        ok = (vacuous == 0)
        print("RED-PHASE %s (need 0 vacuous)" % ("OK" if ok else "FAIL"))
    else:
        ok = (brk == 0 and vacuous == 0 and gv in ("HELD", "SKIP"))
        print("GREEN-PHASE %s" % ("OK" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
