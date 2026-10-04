"""Break-first battery: human-corroboration receipts (wave-267).

SB 947 ("No Robo Bosses Act", signed 2026-09-30, operative 2027-07-01)
imposes a duty of independent human corroboration of ADS output for
disciplinary decisions -- but mandates no wire format. This battery
probes the defense: approval-queue sign-off emits a dual receipt per
corroborated decision --

  * an in-toto v1 attestation (new ``human-corroboration`` predicate
    type) inside a DSSE envelope, digest-bound to the decision packet
    + evidence bundle, anchored in the audit log, and
  * a W3C VC Data Model v2.0 rendering (issuer=reviewer via did:key,
    DataIntegrityProof / eddsa-jcs-2022, credentialStatus) for
    regulator consumption.

Verification is split cosign-style: envelope-signature verification
(step 1) and statement<->decision subject binding (step 2) are two
independent, separately auditable steps.

Modes: ``GOV_CORROB_UNDER_TEST=stub`` runs the probes against a
permissive stub that issues and accepts everything (red phase: attack
probes MUST break). Default (module) runs them against
``gov.corroboration_receipt`` (green phase: attacks MUST be refused,
calibration probes MUST hold).

Honest limit under test (probe ``honest-absence``): a corroboration
receipt proves a keyholder signed a scope-bound statement at a time --
it does NOT prove independent investigation. A receipt with zero
evidence digests must still verify (honest about absence), because
anti-rubber-stamp properties belong in the approval *ceremony*, not
the receipt.

Depth-1 green check honoring ``GOV_SKIP_GREEN``; no in-repo git
subprocesses; stdlib only.
"""

import base64
import copy
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w267-corrob")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

MODE = os.environ.get("GOV_CORROB_UNDER_TEST", "module")

try:
    from gov import corroboration_receipt as _cr
    HAVE_MODULE = True
except Exception:  # red phase: module not written yet
    _cr = None
    HAVE_MODULE = False

TAXONOMY_PIN = 2012 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)


# pin 1222 -> 1231 (+9 corrob-*/corrob-vc-*).

EXPECTED_CODES = (
    "corrob-receipt-failed",
    "corrob-receipt-malformed",
    "corrob-receipt-not-approved",
    "corrob-receipt-predicate-mismatch",
    "corrob-receipt-self-corroboration",
    "corrob-receipt-signature-invalid",
    "corrob-receipt-subject-mismatch",
    "corrob-receipt-unbound-issuer",
    "corrob-vc-proof-invalid",
)

_HUMAN_CORROBORATION_PREDICATE = (
    "https://sasanam.dev/attestation/human-corroboration/v1")


# ------------------------------------------------------------------
# Permissive stub (red phase): accepts and issues everything.
# ------------------------------------------------------------------

class _StubError(Exception):
    def __init__(self, code, detail=""):
        super(_StubError, self).__init__("%s: %s" % (code, detail))
        self.code = code


class _StubSigner(object):
    def __init__(self, seed):
        self._seed = seed
        self.public_key = hashlib.sha256(b"stub-pub" + seed).digest()
        self.key_id = "stub-key"

    def sign(self, data):
        return hashlib.sha256(b"stub-sig" + self._seed + data).digest()


class _StubCorrob(object):
    """Permissive twin of the planned gov.corroboration_receipt API."""
    CorroborationReceiptError = _StubError
    HUMAN_CORROBORATION_PREDICATE = _HUMAN_CORROBORATION_PREDICATE
    DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

    def build_statement(self, reviewer_did, decision_digest,
                        evidence_digests, scope, verdict, issued_at,
                        approval_channel, statement_entry_digest):
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "decision",
                         "digest": {"sha256": decision_digest}}],
            "predicateType": self.HUMAN_CORROBORATION_PREDICATE,
            "predicate": {
                "reviewer": reviewer_did,
                "verdict": verdict,
                "issuedAt": issued_at,
                "evidenceDigests": list(evidence_digests),
                "scope": dict(scope),
                "approvalChannel": approval_channel,
                "statementEntryDigest": statement_entry_digest,
            },
        }

    def dsse_envelope(self, statement):
        raw = json.dumps(statement, sort_keys=True).encode("utf-8")
        return {"payloadType": self.DSSE_PAYLOAD_TYPE,
                "payload": base64.b64encode(raw).decode("ascii"),
                "signatures": []}

    def sign_envelope(self, envelope, signer, keyid):
        env = copy.deepcopy(envelope)
        env["signatures"] = [{"keyid": keyid,
                              "sig": "stub-signature"}]
        return env

    def verify_envelope(self, envelope, verifier):
        raw = base64.b64decode(envelope["payload"])
        return True, json.loads(raw.decode("utf-8"))

    def verify_statement_binding(self, statement, decision_digest):
        return True

    def build_vc(self, reviewer_did, statement_digest, scope, verdict,
                 valid_from, credential_id):
        return {"@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential",
                         "HumanCorroborationCredential"],
                "issuer": reviewer_did,
                "credentialSubject": {
                    "id": reviewer_did,
                    "statementDigest": statement_digest,
                    "scope": dict(scope),
                    "verdict": verdict,
                },
                "validFrom": valid_from}

    def sign_vc(self, vc, signer):
        out = copy.deepcopy(vc)
        out["proof"] = {"type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-jcs-2022",
                        "proofValue": "zstub"}
        return out

    def verify_vc(self, vc, verifier):
        return True


if MODE == "stub" or not HAVE_MODULE:
    cr = _StubCorrob()
    MODULE_MODE = False
else:
    cr = _cr
    MODULE_MODE = True


# ------------------------------------------------------------------
# Harness.
# ------------------------------------------------------------------

def _seed(i):
    return bytes([i]) * 32


def _signer(i):
    if MODULE_MODE:
        from gov.signing import Ed25519Signer
        return Ed25519Signer(_seed(i))
    return _StubSigner(_seed(i))


def _verifier_for(signer):
    if MODULE_MODE:
        from gov.signing import Ed25519Verifier
        return Ed25519Verifier(signer.public_key, key_id=signer.key_id)
    return object()


def _reviewer_did(signer):
    if MODULE_MODE:
        from gov.agent_identity import did_key_from_pubkey
        return did_key_from_pubkey(signer.public_key)
    return "did:key:zstubreviewer"


def _statement(signer, decision_digest="a" * 64, verdict="corroborated",
               evidence=("b" * 64,)):
    return cr.build_statement(
        _reviewer_did(signer), decision_digest, list(evidence),
        {"action": "tool.execute", "resource": "hr:termination-case-42"},
        verdict, "2026-10-01T13:00:00Z", "approval-queue",
        "c" * 64)


def _credential_status():
    return {
        "id": "https://example.invalid/status/7#42",
        "type": "StatusList2021Entry",
        "statusPurpose": "revocation",
        "statusListIndex": "42",
        "statusListCredential": "https://example.invalid/status/7",
    }


def _signed_envelope(signer, statement):
    env = cr.dsse_envelope(statement)
    return cr.sign_envelope(env, signer, getattr(signer, "key_id", "k"))


_RESULTS = []


def _probe(pid, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001 -- probe harness
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    _RESULTS.append((pid, verdict, note))


def _is_refused(fn, *codes):
    """True when fn() raises the module's receipt error with a code.

    In stub mode the stub never refuses -> returns False (attack BREAKs).
    """
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        err_cls = cr.CorroborationReceiptError
        if isinstance(exc, err_cls):
            if not codes or getattr(exc, "code", None) in codes:
                return True
        return False
    return False


# ------------------------------------------------------------------
# Attack probes: BREAK on the permissive stub, HELD on the module.
# ------------------------------------------------------------------

def _attack_unbound_issuer():
    # Envelope signed by the reviewer key, but the statement's
    # predicate names a DIFFERENT reviewer did:key. The signature is
    # valid; the issuer binding is not.
    reviewer = _signer(11)
    other = _signer(12)
    stmt = _statement(reviewer)
    if MODULE_MODE:
        from gov.agent_identity import did_key_from_pubkey
        stmt["predicate"]["reviewer"] = did_key_from_pubkey(other.public_key)
    else:
        stmt["predicate"]["reviewer"] = "did:key:zother"
    env = _signed_envelope(reviewer, stmt)
    refused = _is_refused(
        lambda: cr.verify_envelope(env, _verifier_for(reviewer)),
        "corrob-receipt-unbound-issuer")
    return ("HELD" if refused else "BREAK",
            "issuer binding %s" % ("refused" if refused else "accepted"))


def _attack_tampered_verdict():
    # Verdict flipped AFTER signing: envelope signature must fail.
    reviewer = _signer(21)
    stmt = _statement(reviewer)
    env = _signed_envelope(reviewer, stmt)
    tampered = copy.deepcopy(env)
    raw = json.loads(base64.b64decode(tampered["payload"]).decode("utf-8"))
    raw["predicate"]["verdict"] = "corroborated-with-notes"
    tampered["payload"] = base64.b64encode(
        json.dumps(raw, sort_keys=True).encode("utf-8")).decode("ascii")
    refused = _is_refused(
        lambda: cr.verify_envelope(tampered, _verifier_for(reviewer)),
        "corrob-receipt-signature-invalid")
    return ("HELD" if refused else "BREAK",
            "tampered payload %s" % ("refused" if refused else "accepted"))


def _attack_subject_mismatch():
    # Valid envelope, but the statement subject binds a DIFFERENT
    # decision digest than the one being corroborated (cosign
    # IntotoSubjectClaimVerifier pattern: signature alone is not
    # enough; the binding is a separate explicit step).
    reviewer = _signer(31)
    stmt = _statement(reviewer, decision_digest="d" * 64)
    env = _signed_envelope(reviewer, stmt)
    ok, parsed = cr.verify_envelope(env, _verifier_for(reviewer))
    refused = _is_refused(
        lambda: cr.verify_statement_binding(parsed, "e" * 64),
        "corrob-receipt-subject-mismatch")
    return ("HELD" if refused else "BREAK",
            "subject binding %s" % ("refused" if refused else "accepted"))


def _attack_wrong_key_envelope():
    # Attacker signs with their own key; verified against the
    # reviewer's pinned verifier.
    reviewer = _signer(41)
    attacker = _signer(42)
    stmt = _statement(reviewer)
    env = _signed_envelope(attacker, stmt)
    refused = _is_refused(
        lambda: cr.verify_envelope(env, _verifier_for(reviewer)),
        "corrob-receipt-signature-invalid")
    return ("HELD" if refused else "BREAK",
            "wrong-key envelope %s" % ("refused" if refused else "accepted"))


def _attack_malformed_statement():
    # Statement missing predicateType entirely.
    reviewer = _signer(51)
    stmt = _statement(reviewer)
    del stmt["predicateType"]
    env = _signed_envelope(reviewer, stmt)
    refused = _is_refused(
        lambda: cr.verify_envelope(env, _verifier_for(reviewer)),
        "corrob-receipt-malformed")
    return ("HELD" if refused else "BREAK",
            "malformed statement %s" % ("refused" if refused else "accepted"))


def _attack_unknown_predicate():
    # Statement carries a predicateType the verifier does not know.
    reviewer = _signer(61)
    stmt = _statement(reviewer)
    stmt["predicateType"] = "https://example.com/evil-predicate/v9"
    env = _signed_envelope(reviewer, stmt)
    refused = _is_refused(
        lambda: cr.verify_envelope(env, _verifier_for(reviewer)),
        "corrob-receipt-predicate-mismatch")
    return ("HELD" if refused else "BREAK",
            "unknown predicate %s" % ("refused" if refused else "accepted"))


def _attack_payload_type_mismatch():
    # DSSE payloadType is not the in-toto media type.
    reviewer = _signer(71)
    stmt = _statement(reviewer)
    env = _signed_envelope(reviewer, stmt)
    env["payloadType"] = "application/json"
    refused = _is_refused(
        lambda: cr.verify_envelope(env, _verifier_for(reviewer)),
        "corrob-receipt-malformed")
    return ("HELD" if refused else "BREAK",
            "payloadType mismatch %s" % ("refused" if refused else "accepted"))


def _attack_vc_wrong_key():
    # VC proof made by the attacker's key, verified against reviewer.
    reviewer = _signer(81)
    attacker = _signer(82)
    vc = cr.build_vc(_reviewer_did(reviewer), "f" * 64,
                     {"action": "tool.execute"}, "corroborated",
                     "2026-10-01T13:00:00Z", "urn:uuid:vc-1")
    signed = cr.sign_vc(vc, attacker)
    refused = _is_refused(
        lambda: cr.verify_vc(signed, _verifier_for(reviewer)),
        "corrob-vc-proof-invalid")
    return ("HELD" if refused else "BREAK",
            "VC wrong-key proof %s" % ("refused" if refused else "accepted"))


def _attack_vc_subject_unbound():
    # VC whose credentialSubject is not bound to any statement digest
    # (digest field missing) must not verify.
    reviewer = _signer(91)
    vc = cr.build_vc(_reviewer_did(reviewer), "f" * 64,
                     {"action": "tool.execute"}, "corroborated",
                     "2026-10-01T13:00:00Z", "urn:uuid:vc-2")
    del vc["credentialSubject"]["statementDigest"]
    signed = cr.sign_vc(vc, reviewer)
    refused = _is_refused(
        lambda: cr.verify_vc(signed, _verifier_for(reviewer)),
        "corrob-vc-proof-invalid")
    return ("HELD" if refused else "BREAK",
            "VC unbound subject %s" % ("refused" if refused else "accepted"))


def _attack_vc_repointed_digest():
    # A valid VC re-pointed at a DIFFERENT statement's digest and
    # re-signed (here by the reviewer key itself): verify_vc alone
    # accepts it as a well-formed signed claim, so the dual-receipt
    # ceremony must refuse the statement/VC mismatch.
    if not MODULE_MODE:
        return "BREAK", "stub has no dual verifier"
    from gov.corroboration_receipt import (
        CorroborationIssuer, statement_digest, sign_vc,
        verify_dual_receipt)
    reviewer = _signer(161)
    issuer = CorroborationIssuer(reviewer, _reviewer_did(reviewer))
    receipt = issuer.issue(
        "a" * 64, ["b" * 64],
        {"action": "tool.execute", "resource": "hr:termination-case-42"},
        "corroborated", "approval-queue", "c" * 64,
        approved=True, credential_status=_credential_status())
    other = _signer(162)
    other_stmt = cr.build_statement(
        _reviewer_did(other), "d" * 64, [],
        {"action": "tool.execute", "resource": "hr:other-case"},
        "corroborated", "2026-10-01T13:00:00Z", "approval-queue",
        "c" * 64)
    bad_vc = json.loads(json.dumps(receipt["vc"]))
    bad_vc["credentialSubject"]["statementDigest"] = statement_digest(
        other_stmt)
    del bad_vc["proof"]  # re-pointing means re-proving
    bad_vc = sign_vc(bad_vc, reviewer)
    refused = _is_refused(
        lambda: verify_dual_receipt(
            receipt["envelope"], bad_vc, _verifier_for(reviewer), "a" * 64),
        "corrob-vc-proof-invalid")
    return ("HELD" if refused else "BREAK",
            "re-pointed VC %s" % ("refused" if refused else "accepted"))


def _attack_self_corrob_queue():
    # Self-corroboration at the ceremony edge: the recorded requester
    # IS the decider. Emission must refuse loudly, never mint.
    if not MODULE_MODE:
        return "BREAK", "stub queue emits without checks"
    from gov.corroboration_receipt import (
        CorroboratingApprovalQueue, CorroborationConfig, CorroborationIssuer)
    from gov.log import ActionLog
    from gov.policy import PolicyDecision
    from gov.identity import AgentIdentity
    run_dir = tempfile.mkdtemp(prefix="gov-corrob-self-")
    log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
    reviewer = _signer(101)
    issuer = CorroborationIssuer(reviewer, _reviewer_did(reviewer))
    q = CorroboratingApprovalQueue(
        run_dir, log,
        receipt_config=CorroborationConfig(
            issuer, _reviewer_did(reviewer),
            credential_status=_credential_status()))
    q.set_identity_verifier(lambda _ident: True)
    ident = AgentIdentity("agent-1", "researcher",
                          os.path.basename(run_dir), "user-1")
    action = {"tool": "write_file",
              "args": {"path": "/tmp/x.txt", "content": "hello"},
              "agent_justification": "self corrob unit",
              "redactions": []}
    aid = q.queue(action,
                  PolicyDecision("require_approval", "self corrob unit",
                                 policy_id="corrob-unit", flag="b"),
                  "agent_direct", "preview", caller_identity=ident)
    # decided_by == the requesting agent: self-corroboration.
    refused = _is_refused(
        lambda: q.decide(aid, True, "i approve my own action",
                         decided_by="agent-1"),
        "corrob-receipt-self-corroboration")
    return ("HELD" if refused else "BREAK",
            "self-corroboration %s" % ("refused" if refused else "minted"))


def _attack_not_approved():
    # A receipt must never be minted for a REFUSED decision.
    if not MODULE_MODE:
        return "BREAK", "stub issuer mints for anything"
    from gov.corroboration_receipt import CorroborationIssuer
    reviewer = _signer(111)
    issuer = CorroborationIssuer(reviewer, _reviewer_did(reviewer))
    refused = _is_refused(
        lambda: issuer.issue("a" * 64, ["b" * 64],
                             {"action": "tool.execute"},
                             "corroborated", "approval-queue",
                             "c" * 64, approved=False),
        "corrob-receipt-not-approved")
    return ("HELD" if refused else "BREAK",
            "refused-decision receipt %s"
            % ("refused" if refused else "minted"))


# ------------------------------------------------------------------
# Calibration probes: BASELINE on the stub (it proves nothing),
# HELD on the module.
# ------------------------------------------------------------------

def _calib_happy_path():
    if not MODULE_MODE:
        return "BASELINE", "stub proves nothing"
    reviewer = _signer(121)
    verifier = _verifier_for(reviewer)
    stmt = _statement(reviewer)
    env = _signed_envelope(reviewer, stmt)
    ok, parsed = cr.verify_envelope(env, verifier)
    bound = cr.verify_statement_binding(parsed, "a" * 64)
    vc = cr.build_vc(_reviewer_did(reviewer), "f" * 64,
                     {"action": "tool.execute"}, "corroborated",
                     "2026-10-01T13:00:00Z", "urn:uuid:vc-3")
    vc_ok = cr.verify_vc(cr.sign_vc(vc, reviewer), verifier)
    held = bool(ok and bound and vc_ok)
    return ("HELD" if held else "BREAK",
            "envelope+binding+vc all verify: %s" % held)


def _calib_queue_emit():
    if not MODULE_MODE:
        return "BASELINE", "stub proves nothing"
    from gov.corroboration_receipt import (
        CorroboratingApprovalQueue, CorroborationConfig, CorroborationIssuer)
    from gov.log import ActionLog, read_entries
    from gov.policy import PolicyDecision
    from gov.identity import AgentIdentity
    run_dir = tempfile.mkdtemp(prefix="gov-corrob-emit-")
    log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
    reviewer = _signer(131)
    issuer = CorroborationIssuer(reviewer, _reviewer_did(reviewer))
    q = CorroboratingApprovalQueue(
        run_dir, log,
        receipt_config=CorroborationConfig(
            issuer, _reviewer_did(reviewer),
            credential_status=_credential_status()))
    q.set_identity_verifier(lambda _ident: True)
    ident = AgentIdentity("agent-1", "researcher",
                          os.path.basename(run_dir), "user-1")
    action = {"tool": "write_file",
              "args": {"path": "/tmp/x.txt", "content": "hello"},
              "agent_justification": "emit unit",
              "redactions": []}
    aid = q.queue(action,
                  PolicyDecision("require_approval", "emit unit",
                                 policy_id="corrob-unit", flag="b"),
                  "agent_direct", "preview", caller_identity=ident)
    target, entry = q.decide(aid, True, "verified the diff",
                             decided_by="op-rios")
    emitted = (len(q.emitted_receipts) == 1
               and "envelope" in q.emitted_receipts[0]
               and "vc" in q.emitted_receipts[0])
    events = [e for e in read_entries(os.path.join(run_dir, "actions.jsonl"))
              if isinstance(e, dict)
              and e.get("event") == "corroboration_receipt_emitted"]
    held = bool(emitted and events)
    return ("HELD" if held else "BREAK",
            "emitted=%s audit_events=%d" % (emitted, len(events)))


def _calib_evidence_carried():
    if not MODULE_MODE:
        return "BASELINE", "stub proves nothing"
    reviewer = _signer(141)
    stmt = _statement(reviewer, evidence=("b" * 64, "c" * 64))
    pred = stmt["predicate"]
    held = (pred["evidenceDigests"] == ["b" * 64, "c" * 64]
            and pred["scope"]["resource"] == "hr:termination-case-42"
            and pred["verdict"] == "corroborated"
            and stmt["subject"][0]["digest"]["sha256"] == "a" * 64)
    return ("HELD" if held else "BREAK",
            "reviewer+digests+scope+verdict+subject all carried: %s" % held)


def _calib_honest_absence():
    # The honest limit: a receipt with ZERO evidence digests still
    # verifies. The receipt proves signing, not investigation.
    if not MODULE_MODE:
        return "BASELINE", "stub proves nothing"
    reviewer = _signer(151)
    verifier = _verifier_for(reviewer)
    stmt = _statement(reviewer, evidence=())
    env = _signed_envelope(reviewer, stmt)
    ok, parsed = cr.verify_envelope(env, verifier)
    held = bool(ok and parsed["predicate"]["evidenceDigests"] == [])
    return ("HELD" if held else "BREAK",
            "empty-evidence receipt verifies honestly: %s" % held)


def _calib_legacy_quiet():
    # No corrob config -> the queue is byte-identical legacy: no
    # receipts, no receipt audit events.
    if not MODULE_MODE:
        return "HELD", "stub queue is quiet by construction"
    from gov.corroboration_receipt import CorroboratingApprovalQueue
    from gov.log import ActionLog, read_entries
    from gov.policy import PolicyDecision
    from gov.identity import AgentIdentity
    run_dir = tempfile.mkdtemp(prefix="gov-corrob-legacy-")
    log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
    q = CorroboratingApprovalQueue(run_dir, log)
    q.set_identity_verifier(lambda _ident: True)
    ident = AgentIdentity("agent-1", "researcher",
                          os.path.basename(run_dir), "user-1")
    action = {"tool": "write_file",
              "args": {"path": "/tmp/x.txt", "content": "hello"},
              "agent_justification": "legacy unit",
              "redactions": []}
    aid = q.queue(action,
                  PolicyDecision("require_approval", "legacy unit",
                                 policy_id="corrob-unit", flag="b"),
                  "agent_direct", "preview", caller_identity=ident)
    q.decide(aid, True, "ok", decided_by="op-rios")
    events = [e for e in read_entries(os.path.join(run_dir, "actions.jsonl"))
              if isinstance(e, dict)
              and str(e.get("event", "")).startswith("corroboration_")]
    held = (q.emitted_receipts == [] and events == [])
    return ("HELD" if held else "BREAK",
            "legacy quiet: receipts=%d events=%d"
            % (len(q.emitted_receipts), len(events)))


def _pin_probe():
    if not MODULE_MODE:
        return "BASELINE", "pin checked in module mode"
    from gov import decision_codes
    have = set(EXPECTED_CODES)
    missing = [c for c in have if c not in decision_codes.TAXONOMY]
    extra = [c for c in decision_codes.TAXONOMY
             if str(c).startswith("corrob-") and c not in have]
    n = len(decision_codes.TAXONOMY)
    held = (not missing and not extra and n == TAXONOMY_PIN)
    return ("HELD" if held else "BREAK",
            "pin=%d expected=%d missing=%s extra=%s"
            % (n, TAXONOMY_PIN, missing, extra))


# ------------------------------------------------------------------
# Depth-1 green check (adjacent receipt batteries).
# ------------------------------------------------------------------

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("BASELINE", "green check skipped (depth-1)")
    if not MODULE_MODE:
        return ("BASELINE", "green check runs in module mode")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = "/var/tmp/g267corrob-adj"
    os.makedirs(env["TMPDIR"], exist_ok=True)
    checks = [
        ([sys.executable, "evals/w217_receipt_probes.py"], "w217_receipt"),
        ([sys.executable, "evals/scitt_receipt_probes.py"], "scitt_receipt"),
    ]
    for cmd, label in checks:
        p = subprocess.run(cmd, cwd=REPO_ROOT, env=env,
                           capture_output=True, text=True, timeout=600)
        if p.returncode != 0:
            return ("BREAK", "%s rc=%d" % (label, p.returncode))
        out = (p.stdout or "") + (p.stderr or "")
        # Count nonzero ERROR tallies; the literal "0 ERROR" summary
        # line is not a failure.
        bad = any(int(n) > 0
                  for n in re.findall(r"(\d+)\s+ERROR", out))
        if bad:
            return ("BREAK", "%s has ERROR probes" % label)
    return ("HELD", "adjacent receipt batteries green")


_PROBES = [
    ("corrob/unbound-issuer", _attack_unbound_issuer),
    ("corrob/tampered-verdict", _attack_tampered_verdict),
    ("corrob/subject-mismatch", _attack_subject_mismatch),
    ("corrob/wrong-key-envelope", _attack_wrong_key_envelope),
    ("corrob/malformed-statement", _attack_malformed_statement),
    ("corrob/unknown-predicate", _attack_unknown_predicate),
    ("corrob/payload-type-mismatch", _attack_payload_type_mismatch),
    ("corrob/vc-wrong-key", _attack_vc_wrong_key),
    ("corrob/vc-subject-unbound", _attack_vc_subject_unbound),
    ("corrob/vc-repointed-digest", _attack_vc_repointed_digest),
    ("corrob/self-corroboration", _attack_self_corrob_queue),
    ("corrob/not-approved", _attack_not_approved),
    ("corrob/happy-path", _calib_happy_path),
    ("corrob/queue-emit", _calib_queue_emit),
    ("corrob/evidence-carried", _calib_evidence_carried),
    ("corrob/honest-absence", _calib_honest_absence),
    ("corrob/legacy-quiet", _calib_legacy_quiet),
    ("corrob/pin-1299", _pin_probe),
    ("corrob/green-check", _green_check),
]


def main():
    for pid, fn in _PROBES:
        _probe(pid, fn)
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    base = sum(1 for _, v, _ in _RESULTS if v == "BASELINE")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    for pid, v, note in _RESULTS:
        print("%-32s %-8s %s" % (pid, v, note))
    print("TOTAL: %d HELD / %d BREAK / %d BASELINE / %d ERROR"
          % (held, brk, base, err))
    return 0 if err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
