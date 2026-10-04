#!/usr/bin/env python3
"""Wave-265 independent red-team probes.

Break-first battery over the wave-264 merged seams. Every probe
attacks a public seam and classifies the outcome:

  HELD      -- attack refused / secure behavior confirmed
  RESIDUAL  -- honest residual: documented design limit, not a defect
  BREAK     -- genuine defect against a documented contract
              (each BREAK maps to a filed finding, F248+)
  ERROR     -- probe could not execute (environment / probe bug)

Seams covered: bounded_mandates (chain/replay/window), admission_policy
(key/keyless/attestation authorities, TOCTOU, refusal honesty),
trust_federation (bundle binding, expiry, de-federation, rollback),
scoped_tool_listing (ticket expiry, consent replay, cross-tool redirect),
detectors (F243/F244 residual pins), recipient_plugins (quorum unwrap),
behavioral_sigs (agent-shaped behavior: the DIVD Zammad windfall --
rapid sequential tool calls, self-commenting logs, self-interference).

Determinism: fixed logical clock, fixed seeds. The battery runs twice
(two distinct TMPDIRs) and requires an identical verdict vector.
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import hmac as hmac_std
import json
import subprocess
import sys
import tempfile
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import bounded_mandates as bm
from gov import admission_policy as ap
from gov import trust_federation as tf
from gov import scoped_tool_listing as stl
from gov import detectors as det
from gov import behavioral_sigs as bsig
from gov import ed25519

TAXONOMY_PIN = 1916 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*)

# Fixed logical clock: all probes use explicit now values, never the
# wall clock, except where the product defaults are under test.
T0 = 1_750_000_000.0

RESULTS = []


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def probe(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn
    return deco


def _run_one(name, fn):
    try:
        verdict, detail = fn()
        check(verdict in ("HELD", "RESIDUAL", "BREAK"),
              "bad verdict %r" % (verdict,))
        return (name, verdict, detail, "")
    except AssertionError as ex:
        return (name, "BREAK", "expectation violated: %s" % (ex,),
                traceback.format_exc(limit=3))
    except Exception as ex:  # noqa: BLE001 - probe bug / environment
        return (name, "ERROR", "%s: %s" % (type(ex).__name__, ex),
                traceback.format_exc(limit=3))


# ---------------------------------------------------------------------------
# Helpers: mandate fixtures
# ---------------------------------------------------------------------------

_MAC_KEY = bytes.fromhex("11" * 32)
_CONS = {"tools": ["read_file", "write_file"], "spend_cap": 100,
         "not_before": T0 - 100, "not_after": T0 + 3600,
         "data_scopes": ["fs"]}


def _mandate_pair(now=T0, cost=10, tool="read_file", args=("a.txt",)):
    issuer = bm.MandateIssuer(_MAC_KEY)
    executor = bm.MandateExecutor(_MAC_KEY)
    opened = issuer.issue_open("agent-1", _CONS, now=now)
    closed = executor.close_action(opened, tool, args, cost,
                                   executed_at=now)
    return opened, closed


def _ed_keypair():
    seed = ed25519.generate_seed()
    return seed, ed25519.publickey(seed)


def _sign_hex(seed, msg):
    return ed25519.sign(seed, msg).hex()


# ---------------------------------------------------------------------------
# Group A -- bounded_mandates
# ---------------------------------------------------------------------------

@probe("mandate/future-executed-at")
def _p_mandate_future():
    """A closed mandate sealed with executed_at in the future refuses
    mandate-tampered at audit time."""
    issuer = bm.MandateIssuer(_MAC_KEY)
    executor = bm.MandateExecutor(_MAC_KEY)
    opened = issuer.issue_open("agent-1", _CONS, now=T0)
    closed = executor.close_action(opened, "read_file", ("a.txt",), 10,
                                   executed_at=T0 + 600)
    v = bm.MandateVerifier(_MAC_KEY)
    try:
        v.verify(opened, closed, now=T0)
    except bm.MandateTampered as ex:
        check("mandate-tampered" in str(ex), "wrong code: %s" % ex)
        return ("HELD", "future executed_at refuses mandate-tampered")
    return ("BREAK", "future executed_at verified")


@probe("mandate/verify-outside-window")
def _p_mandate_window():
    """Auditing after not_after refuses mandate-expired even when the
    action itself was in-window (the audit seam must run in-window)."""
    opened, closed = _mandate_pair(now=T0)
    v = bm.MandateVerifier(_MAC_KEY)
    try:
        v.verify(opened, closed, now=T0 + 7200)
    except bm.MandateExpired as ex:
        check("mandate-expired" in str(ex), "wrong code: %s" % ex)
        return ("HELD", "post-window audit refuses mandate-expired")
    return ("BREAK", "post-window audit verified")


@probe("mandate/receipt-after-verify")
def _p_mandate_receipt_replay():
    """verify() then receipt() on the same pair: receipt refuses
    mandate-replay because receipt() verifies first. Fail-closed, but
    it makes receipts one-shot with the audit decision -- an operator
    who audits first cannot mint the dispute receipt later."""
    opened, closed = _mandate_pair()
    v = bm.MandateVerifier(_MAC_KEY)
    v.verify(opened, closed, now=T0)
    try:
        v.receipt(opened, closed, now=T0)
    except bm.MandateReplay:
        return ("RESIDUAL",
                "receipt-after-verify refuses mandate-replay: fail-closed "
                "but receipts are one-shot with the first audit; the "
                "intended flow is receipt() instead of verify()")
    return ("BREAK", "receipt minted after prior verify")


@probe("mandate/replay-across-verifier-instances")
def _p_mandate_cross_instance():
    """Replay/spend/chain state is in-memory per verifier (documented
    residual). A closed mandate verifies on a FRESH verifier instance
    even after being consumed on another."""
    opened, closed = _mandate_pair()
    v1 = bm.MandateVerifier(_MAC_KEY)
    v1.verify(opened, closed, now=T0)
    v2 = bm.MandateVerifier(_MAC_KEY)  # fresh state
    try:
        v2.verify(opened, closed, now=T0)
    except bm.MandateError as ex:
        return ("BREAK", "fresh verifier refused: %s" % ex)
    return ("RESIDUAL",
            "closed mandate verifies on a fresh verifier instance: "
            "documented in-memory replay-state residual -- a verifier "
            "restart (or a second verifier) re-accepts consumed mandates")


@probe("mandate/replay-same-verifier")
def _p_mandate_same_instance():
    """Second verify of the same pair on the same verifier refuses."""
    opened, closed = _mandate_pair()
    v = bm.MandateVerifier(_MAC_KEY)
    v.verify(opened, closed, now=T0)
    try:
        v.verify(opened, closed, now=T0)
    except bm.MandateReplay as ex:
        check("mandate-replay" in str(ex), "wrong code: %s" % ex)
        return ("HELD", "same-verifier replay refuses mandate-replay")
    return ("BREAK", "same-verifier replay verified")


@probe("mandate/tool-escape")
def _p_mandate_tool_escape():
    """A closed mandate for a tool outside the OPEN mandate's own
    tool allowlist refuses mandate-constraint-exceeded at audit."""
    issuer = bm.MandateIssuer(_MAC_KEY)
    executor = bm.MandateExecutor(_MAC_KEY)
    opened = issuer.issue_open("agent-1", _CONS, now=T0)
    closed = executor.close_action(opened, "evil_tool", ("x",), 10,
                                   executed_at=T0)
    v = bm.MandateVerifier(_MAC_KEY)
    try:
        v.verify(opened, closed, now=T0)
    except bm.MandateConstraintExceeded as ex:
        check("mandate-constraint-exceeded" in str(ex),
              "wrong code: %s" % ex)
        return ("HELD", "tool outside the open mandate's allowlist "
                "refuses mandate-constraint-exceeded")
    return ("BREAK", "tool outside the allowlist verified")


@probe("mandate/closed-open-id-mismatch")
def _p_mandate_open_mismatch():
    """A closed mandate bound to a different open mandate refuses
    mandate-unknown."""
    issuer = bm.MandateIssuer(_MAC_KEY)
    executor = bm.MandateExecutor(_MAC_KEY)
    opened_a = issuer.issue_open("agent-1", _CONS, now=T0)
    opened_b = issuer.issue_open("agent-2", _CONS, now=T0)
    check(opened_a["id"] != opened_b["id"], "test setup: ids collide")
    closed_b = executor.close_action(opened_b, "read_file", ("a",), 10,
                                     executed_at=T0)
    v = bm.MandateVerifier(_MAC_KEY)
    try:
        v.verify(opened_a, closed_b, now=T0)
    except bm.MandateUnknown as ex:
        check("mandate-unknown" in str(ex), "wrong code: %s" % ex)
        return ("HELD", "cross-open closed mandate refuses "
                "mandate-unknown")
    return ("BREAK", "cross-open closed mandate verified")


@probe("mandate/spend-cap-enforced")
def _p_mandate_spend():
    """Cost above spend_cap refuses mandate-constraint-exceeded."""
    opened, closed = _mandate_pair(cost=101)
    v = bm.MandateVerifier(_MAC_KEY)
    try:
        v.verify(opened, closed, now=T0)
    except bm.MandateConstraintExceeded as ex:
        check("mandate-constraint-exceeded" in str(ex),
              "wrong code: %s" % ex)
        return ("HELD", "overspend refuses mandate-constraint-exceeded")
    return ("BREAK", "overspend verified")

# ---------------------------------------------------------------------------
# Group B -- admission_policy
# ---------------------------------------------------------------------------

_DIGEST = "ab" * 32
_OTHER_DIGEST = "cd" * 32


def _policy_doc(entries):
    return {"version": 1, "entries": entries}


def _key_entry(key_hex, mode="any", name="tool-x"):
    return {"name": name, "patterns": [name], "mode": mode,
            "authorities": [{"type": "key", "key_id": "k1",
                             "public_key": key_hex}]}


def _keyless_entry(mode="any", name="tool-x"):
    return {"name": name, "patterns": [name], "mode": mode,
            "authorities": [{"type": "keyless", "issuer": "corp-idp",
                             "subject": "deployer-bot"}]}


def _artifact(digest=_DIGEST, name="tool-x"):
    return {"name": name, "digest": digest}


def _admit_refused(policy, artifact, evidence, resolver=None):
    """admit() raises AdmissionPolicyError on refusal. Returns
    (code, detail). Raises AssertionError if admission succeeds."""
    try:
        dec = ap.admit(policy, artifact, evidence, resolver=resolver,
                       now=T0)
    except ap.AdmissionPolicyError as ex:
        return ex.code, ex.detail
    raise AssertionError("admit succeeded unexpectedly: %r" % (dec,))


@probe("admission/keyless-self-asserted")
def _p_adm_keyless():
    """The documented keyless residual: a keyless authority admits on a
    caller-supplied identity claim. Anyone who knows the (issuer,
    subject) strings is admitted -- the deployment must SVID-verify
    keyless evidence before admission."""
    pol = ap.AdmissionPolicy.from_dict(_policy_doc([_keyless_entry()]))
    evidence = {"identity": {"issuer": "corp-idp",
                             "subject": "deployer-bot"}}
    dec = ap.admit(pol, _artifact(), evidence, now=T0)
    check(dec["verdict"] == "admitted",
          "expected admit, got %r" % (dec,))
    return ("RESIDUAL",
            "keyless authority admits on self-asserted identity claim: "
            "documented residual -- admission of keyless evidence must "
            "be preceded by deployment-side SVID verification")


@probe("admission/keyless-mismatch")
def _p_adm_keyless_mismatch():
    """A non-matching identity claim refuses."""
    pol = ap.AdmissionPolicy.from_dict(_policy_doc([_keyless_entry()]))
    evidence = {"identity": {"issuer": "corp-idp",
                             "subject": "attacker-bot"}}
    code, _detail = _admit_refused(pol, _artifact(), evidence)
    check(code == "admission-policy-identity-refused",
          "wrong code: %r" % (code,))
    return ("HELD", "mismatched identity refuses "
            "admission-policy-identity-refused")


@probe("admission/sig-for-different-digest")
def _p_adm_sig_digest():
    """A valid signature over a DIFFERENT digest is skipped, not
    accepted -- signatures are digest-bound."""
    seed, pub = _ed_keypair()
    pol = ap.AdmissionPolicy.from_dict(
        _policy_doc([_key_entry(pub.hex())]))
    evidence = {"signatures": [
        {"digest": _OTHER_DIGEST,
         "signature": _sign_hex(seed, ap.signing_bytes(_OTHER_DIGEST))}]}
    code, _detail = _admit_refused(pol, _artifact(), evidence)
    check(code == "admission-policy-signature-refused",
          "wrong code: %r" % (code,))
    return ("HELD", "signature for another digest is skipped; refusal "
            "is admission-policy-signature-refused")


@probe("admission/unsigned-key-authority")
def _p_adm_unsigned():
    """A key authority with no signatures at all refuses UNSIGNED
    (not a silent pass)."""
    _seed, pub = _ed_keypair()
    pol = ap.AdmissionPolicy.from_dict(
        _policy_doc([_key_entry(pub.hex())]))
    code, _detail = _admit_refused(pol, _artifact(),
                                     {"signatures": []})
    check(code == "admission-policy-unsigned",
          "wrong code: %r" % (code,))
    return ("HELD", "empty signatures refuse admission-policy-unsigned")


@probe("admission/attestation-predicate-confusion")
def _p_adm_att_confusion():
    """An attestation with the right predicate but signed for another
    digest is skipped."""
    seed, pub = _ed_keypair()
    pol = ap.AdmissionPolicy.from_dict(_policy_doc(
        [{"name": "tool-x", "patterns": ["tool-x"], "mode": "any",
          "authorities": [{"type": "attestation",
                           "predicate": "vuln-scan-clean",
                           "public_key": pub.hex()}]}]))
    evidence = {"attestations": [
        {"predicate": "vuln-scan-clean", "digest": _OTHER_DIGEST,
         "signature": _sign_hex(
             seed, ap.attestation_bytes("vuln-scan-clean",
                                        _OTHER_DIGEST))}]}
    code, _detail = _admit_refused(pol, _artifact(), evidence)
    check(code == "admission-policy-attestation-refused",
          "wrong code: %r" % (code,))
    return ("HELD", "cross-digest attestation skipped; "
            "admission-policy-attestation-refused")


@probe("admission/toctou-tag-move")
def _p_adm_toctou():
    """Admit on tag T resolving to D1; the tag moves to D2 before use;
    confirm_use re-resolves and refuses to confirm (digest-changed)."""
    seed, pub = _ed_keypair()
    pol = ap.AdmissionPolicy.from_dict(
        _policy_doc([_key_entry(pub.hex())]))
    evidence = {"signatures": [
        {"digest": _DIGEST,
         "signature": _sign_hex(seed, ap.signing_bytes(_DIGEST))}]}
    tag_state = {"v1.2": _DIGEST}

    def resolver(artifact):
        return tag_state.get(artifact.get("tag"))

    art = {"name": "tool-x", "tag": "v1.2"}
    dec = ap.admit(pol, art, evidence, resolver=resolver, now=T0)
    check(dec["verdict"] == "admitted",
          "expected admit, got %r" % (dec,))
    tag_state["v1.2"] = _OTHER_DIGEST  # attacker moves the tag
    try:
        confirmed = ap.confirm_use(dec, art, resolver=resolver)
    except ap.AdmissionPolicyError as ex:
        check(ex.code == "admission-policy-digest-changed",
              "wrong code: %s" % ex.code)
        return ("HELD", "confirm_use re-resolves: moved tag raises "
                "admission-policy-digest-changed")
    check(confirmed is False, "confirm_use confirmed a moved tag")
    return ("HELD", "confirm_use re-resolves: moved tag is not confirmed")


@probe("admission/refusal-names-every-authority")
def _p_adm_refusal_honesty():
    """A mode-all entry failing two authorities: the refusal DETAIL
    lists every failed authority, but the machine CODE is last-wins
    (only the last failure's code). The spec-review claimed refusals
    'name every failed authority' -- the detail does; the code does
    not."""
    _s1, pub1 = _ed_keypair()
    _s2, pub2 = _ed_keypair()
    pol = ap.AdmissionPolicy.from_dict(_policy_doc(
        [{"name": "tool-x", "patterns": ["tool-x"], "mode": "all",
          "authorities": [{"type": "key", "key_id": "k1",
                           "public_key": pub1.hex()},
                          {"type": "keyless", "issuer": "corp-idp",
                           "subject": "deployer-bot"}]}]))
    code, detail = _admit_refused(pol, _artifact(), {"signatures": []})
    check("admission-policy-unsigned" in detail and
          "admission-policy-identity-refused" in detail,
          "detail does not name every failed authority: %r" % (detail,))
    return ("RESIDUAL",
            "refusal detail names every failed authority, but the "
            "machine code %r is last-wins -- the 'name every failed "
            "authority' claim holds for the detail string, not the "
            "machine code" % (code,))


@probe("admission/honest-admit")
def _p_adm_honest():
    """Control: a correctly signed artifact is admitted."""
    seed, pub = _ed_keypair()
    pol = ap.AdmissionPolicy.from_dict(
        _policy_doc([_key_entry(pub.hex())]))
    evidence = {"signatures": [
        {"digest": _DIGEST,
         "signature": _sign_hex(seed, ap.signing_bytes(_DIGEST))}]}
    dec = ap.admit(pol, _artifact(), evidence, now=T0)
    check(dec["verdict"] == "admitted",
          "expected admit, got %r" % (dec,))
    check(dec["digest"] == _DIGEST, "decision digest not bound")
    return ("HELD", "honestly signed artifact admitted, digest bound")

# ---------------------------------------------------------------------------
# Group C -- trust_federation
# ---------------------------------------------------------------------------

_PEER = "peer.example"
_ENDPOINT = "https://peer.example/bundle"


def _fed_table():
    path = os.path.join(tempfile.gettempdir(),
                        "w265-fed-%d.jsonl" % (os.getpid(),))
    return tf.FederationTable(path)


def _fed_rel(table, domain=_PEER):
    seed, pub = _ed_keypair()
    table.add_relationship(domain, _ENDPOINT, "https_spiffe", pub.hex())
    return seed, pub


def _bundle_bytes(seed, domain=_PEER, bundle_id="b1", issued_at=None,
                  expires_at=None, roots=None, next_roots=None):
    issued_at = T0 - 100 if issued_at is None else issued_at
    expires_at = T0 + 3600 if expires_at is None else expires_at
    _s, rpub = _ed_keypair()
    roots = roots or {"root-a": rpub.hex()}
    next_roots = next_roots or {"root-b": rpub.hex()}
    body = {"trust_domain": domain, "bundle_id": bundle_id,
            "issued_at": int(issued_at), "expires_at": int(expires_at),
            "roots": roots, "next_roots": next_roots}
    doc = dict(body)
    doc["endpoint_signature"] = ed25519.sign(
        seed, tf._bundle_signing_bytes(body)).hex()
    return json.dumps(doc).encode("utf-8")


def _svid(domain=_PEER):
    return {"spiffe_id": "spiffe://%s/ns/default/sa/agent" % (domain,)}


@probe("federation/expired-bundle-verify")
def _p_fed_expired():
    """A bundle that expired since install refuses at verify time
    (federation-bundle-expired), not just at install time."""
    table = _fed_table()
    seed, _pub = _fed_rel(table)
    table.refresh_bundle(_PEER, _bundle_bytes(seed), now=T0)
    try:
        table.verify_foreign(_svid(), now=T0 + 7200)
    except tf.FederationError as ex:
        check("federation-bundle-expired" in str(ex),
              "wrong code: %s" % ex)
        return ("HELD", "stale bundle refuses federation-bundle-expired "
                "at verify time")
    return ("BREAK", "verify_foreign accepted an expired bundle")


@probe("federation/remove-then-verify")
def _p_fed_remove():
    """De-federation is deletion: after remove(), the domain is
    as-if-never-granted and SVIDs refuse federation-untrusted-domain."""
    table = _fed_table()
    seed, _pub = _fed_rel(table)
    table.refresh_bundle(_PEER, _bundle_bytes(seed), now=T0)
    table.remove(_PEER)
    try:
        table.verify_foreign(_svid(), now=T0)
    except tf.FederationError as ex:
        check("federation-untrusted-domain" in str(ex),
              "wrong code: %s" % ex)
        return ("HELD", "removed domain refuses "
                "federation-untrusted-domain")
    return ("BREAK", "verify_foreign accepted after remove()")


@probe("federation/unknown-domain")
def _p_fed_unknown():
    """An SVID from a domain with no relationship refuses."""
    table = _fed_table()
    try:
        table.verify_foreign(_svid("stranger.example"), now=T0)
    except tf.FederationError as ex:
        check("federation-untrusted-domain" in str(ex),
              "wrong code: %s" % ex)
        return ("HELD", "unfederated domain refuses "
                "federation-untrusted-domain")
    return ("BREAK", "verify_foreign accepted an unfederated domain")


@probe("federation/bundle-rollback")
def _p_fed_rollback():
    """Install bundle b2, then refresh with older-but-still-valid b1:
    accepted -- the module tracks no bundle-version monotonicity. The
    bundle must still be signed by the pinned endpoint key and the
    transport is deployment-owned, so this is a hardening gap, not a
    forgery."""
    table = _fed_table()
    seed, _pub = _fed_rel(table)
    _s, rpub = _ed_keypair()
    b2 = _bundle_bytes(seed, bundle_id="b2",
                       roots={"root-new": rpub.hex()})
    table.refresh_bundle(_PEER, b2, now=T0)
    b1 = _bundle_bytes(seed, bundle_id="b1",
                       roots={"root-old": rpub.hex()})
    table.refresh_bundle(_PEER, b1, now=T0)  # older bundle accepted
    recs = table.journal_records()
    kinds = [r.get("type") for r in recs] if recs else []
    return ("RESIDUAL",
            "older signed bundle accepted on refresh (no bundle_id "
            "monotonicity); journal shows %d records" % (len(recs),))


@probe("federation/from-bytes-raw-relationship")
def _p_fed_raw_rel():
    """from_bytes with a non-relationship (None) escapes a raw
    AttributeError, not a machine-coded refusal. Deployment-typed
    argument (programmer error), not attacker input -- the wire-input
    shapes are all machine-coded."""
    _s, rpub = _ed_keypair()
    seed = ed25519.generate_seed()
    body = {"trust_domain": _PEER, "bundle_id": "b1",
            "issued_at": int(T0 - 100), "expires_at": int(T0 + 3600),
            "roots": {"root-a": rpub.hex()},
            "next_roots": {"root-b": rpub.hex()}}
    doc = dict(body)
    doc["endpoint_signature"] = ed25519.sign(
        seed, tf._bundle_signing_bytes(body)).hex()
    raw = json.dumps(doc).encode("utf-8")
    try:
        tf.TrustBundle.from_bytes(raw, None, now=T0)
    except AttributeError:
        return ("RESIDUAL",
                "from_bytes(None) raises raw AttributeError: "
                "deployment-typed programmer-error path, not an "
                "attacker seam; the wire-input shapes are all "
                "machine-coded")
    except tf.FederationError as ex:
        return ("HELD", "machine-coded refusal even here: %s" % ex)
    return ("BREAK", "from_bytes accepted None relationship")


@probe("federation/http-endpoint-refused")
def _p_fed_http():
    """A bundle endpoint on plain http:// refuses at declaration."""
    table = _fed_table()
    _seed, pub = _ed_keypair()
    try:
        table.add_relationship(_PEER, "http://peer.example/bundle",
                               "http://", pub.hex())
    except tf.FederationError as ex:
        return ("HELD", "http endpoint refused at declaration: %s" % ex)
    return ("BREAK", "http endpoint accepted")

# ---------------------------------------------------------------------------
# Group D -- scoped_tool_listing
# ---------------------------------------------------------------------------

_SCOPE_KEY = bytes.fromhex("22" * 32)
_UNIVERSE = ["files:read", "files:write", "net:fetch"]


def _scope_issuer():
    return stl.ScopeTicketIssuer(_SCOPE_KEY, _UNIVERSE)


def _consent_issuer():
    return stl.ConsentIssuer(_SCOPE_KEY, ttl_seconds=300)


def _consent_token(approval="appr-1", tool="read_file",
                   scopes=("files:read",), sub="sub-1", now=T0):
    iss = _consent_issuer()
    url = iss.mint_consent_url(approval, tool, scopes, sub, now,
                               "https://consent.example/c")
    return url.split("ct=", 1)[1]


@probe("scopelist/ticket-no-expiry")
def _p_scope_noexp():
    """A scope ticket sealed 10 years ago still verifies today: scope
    tickets carry no expiry. Documented holder semantics make this a
    residual, not a defect -- but a leaked ticket is a permanent
    capability for as long as the issuer key stands."""
    iss = _scope_issuer()
    ticket = iss.seal("sub-1", ["files:read"], now=T0 - 10 * 365 * 86400)
    sub, scopes = iss.verify(ticket)
    check(sub == "sub-1" and scopes == frozenset({"files:read"}),
          "ticket did not verify: %r %r" % (sub, scopes))
    return ("RESIDUAL",
            "scope tickets have no expiry: a ticket sealed a decade "
            "ago verifies today. Bearer-ticket design; a leaked ticket "
            "is valid until the issuer key rotates")


@probe("scopelist/consent-replay")
def _p_scope_consent_replay():
    """The same consent token confirms twice within its TTL: no replay
    tracking. Both confirmations bind the SAME approval/tool/subject, so
    no new authority is created (duplicate audit events only)."""
    token = _consent_token()
    iss = _consent_issuer()
    events = []
    ok1 = iss.confirm_consent(token, "appr-1", "read_file", "sub-1",
                              T0 + 10, events.append)
    ok2 = iss.confirm_consent(token, "appr-1", "read_file", "sub-1",
                              T0 + 20, events.append)
    check(ok1 is True and ok2 is True, "confirmations failed")
    check(len(events) == 2, "expected 2 audit events, got %d"
          % len(events))
    return ("RESIDUAL",
            "consent token replayable within TTL (2 confirmations, 2 "
            "audit events): no replay tracking, but the binding is "
            "fixed to (approval, tool, subject) so replay grants no "
            "new authority")


@probe("scopelist/consent-cross-approval")
def _p_scope_consent_cross():
    """A token minted for approval A confirmed against approval B
    refuses scope-consent-unbound."""
    token = _consent_token(approval="appr-1")
    iss = _consent_issuer()
    try:
        iss.confirm_consent(token, "appr-2", "read_file", "sub-1",
                            T0 + 10, lambda e: None)
    except stl.ScopedListingError as ex:
        check("scope-consent-unbound" in str(ex), "wrong code: %s" % ex)
        return ("HELD", "cross-approval token refuses "
                "scope-consent-unbound")
    return ("BREAK", "cross-approval token confirmed")


@probe("scopelist/ticket-cross-tool-redirect")
def _p_scope_ticket_redirect():
    """A forged ticket on the invoke seam refuses scope-grant-tampered
    BEFORE the tool registry is consulted (F242): no unauthenticated
    caller can distinguish absent tool names from present-but-scoped
    ones, and no tool executes."""
    reg = stl.ToolRegistry(_UNIVERSE)
    reg.bind_issuer(_scope_issuer())
    reg.register("read_file", ["files:read"], "read a file")
    fired = []
    try:
        reg.invoke("not-a-ticket", "read_file",
                   lambda: fired.append(True))
    except stl.ScopedListingError as ex:
        check("scope-grant-tampered" in str(ex),
              "wrong code: %s" % ex)
        check(not fired, "action_fn executed despite forged ticket")
        return ("HELD", "forged ticket refuses scope-grant-tampered "
                "before any tool executes; no existence oracle")
    return ("BREAK", "forged ticket invoked a tool")


@probe("scopelist/consent-expired")
def _p_scope_consent_exp():
    """A consent token presented after its TTL refuses
    scope-consent-expired."""
    token = _consent_token(now=T0)
    iss = _consent_issuer()
    try:
        iss.confirm_consent(token, "appr-1", "read_file", "sub-1",
                            T0 + 301, lambda e: None)
    except stl.ScopedListingError as ex:
        check("scope-consent-expired" in str(ex), "wrong code: %s" % ex)
        return ("HELD", "expired consent refuses scope-consent-expired")
    return ("BREAK", "expired consent confirmed")

# ---------------------------------------------------------------------------
# Group E -- behavioral_sigs (agent-shaped behavior)
# ---------------------------------------------------------------------------

def _scan_map(entries, hints=None):
    return {f.signature_id: f for f in bsig.scan(entries,
                                                 credential_hints=hints)}


def _ev(ts, principal="agent-x", tool="shell", event="tool_call",
        session="s1", dest=None):
    e = {"ts": ts, "principal": principal, "tool": tool,
         "event": event, "session_id": session}
    if dest is not None:
        e["dest"] = dest
    return e


@probe("behav/divd-shaped-trajectory")
def _p_behav_divd():
    """A DIVD-Zammad-shaped trajectory -- machine-regular burst,
    fanned egress (Marimo: many IPs in seconds), parallel sessions,
    same-session establish->invalidate (the AitM/password-spray
    self-interference), and a self-commenting log trail -- trips the
    behavioral signatures. The stack catches agent-shaped behavior,
    not only signature-shaped attacks."""
    events = []
    # 14 machine-regular calls, 1s gaps (burst cadence)
    for i in range(14):
        events.append(_ev(T0 + i, dest="10.0.0.%d" % ((i % 8) + 1)
                          if i < 8 else None))
    # parallel sessions s2, s3 (2 events each, inside 300s)
    for k, s in enumerate(("s2", "s3")):
        for j in range(2):
            events.append(_ev(T0 + 20 + k * 5 + j, session=s))
    # DIVD self-interference: AitM established, then degraded by the
    # same session's own password spraying
    events.append(_ev(T0 + 40, tool="net", event="aitm_establish"))
    events.append(_ev(T0 + 45, tool="auth", event="password_spray"))
    # self-commenting log trail: 14 decision narratives, alone in
    # their 600s window (ratio 1.0)
    for i in range(14):
        events.append(_ev(T0 + 100 + i, tool="log",
                          event="decision_note"))
    found = _scan_map(events)
    want = ("burst_cadence", "fanned_egress", "parallel_sessions",
            "self_narrated_trajectory", "self_interference")
    missed = [s for s in want if not found[s].matched]
    check(not missed, "DIVD-shaped trajectory missed by: %r" % (missed,))
    return ("HELD", "DIVD-shaped trajectory trips %d behavioral "
            "signatures (%s)" % (len(want), ", ".join(want)))


@probe("behav/hyper-fast-burst-evasion")
def _p_behav_fast():
    """20 tool calls in 2s (median gap 0.1s): burst_cadence MISSES --
    the signature's min_median_gap_s=0.3 floor excludes hyper-fast
    machine bursts. An attacker operating faster than the signature's
    floor evades it by construction."""
    events = [_ev(T0 + i * 0.1) for i in range(20)]
    found = _scan_map(events)
    f = found["burst_cadence"]
    if f.matched:
        return ("HELD", "hyper-fast burst unexpectedly matched")
    return ("RESIDUAL",
            "burst_cadence misses a 20-action/2s hyper-fast burst: "
            "min_median_gap_s=0.3 excludes faster-than-floor machine "
            "cadence (detail: %r)" % (f.detail,))


@probe("behav/narrative-padding-evasion")
def _p_behav_padding():
    """12 decision narratives diluted with 20 benign calls (ratio
    12/32 = 37.5% < 40%): self_narrated_trajectory MISSES. Padding
    the trajectory with benign events defeats the ratio gate -- the
    count gate (12) is met, but the AND of count+ratio is not."""
    events = []
    for i in range(32):
        if i % 8 < 3 and sum(1 for e in events
                             if e["event"] == "decision_note") < 12:
            events.append(_ev(T0 + i, tool="log",
                              event="decision_note"))
        else:
            events.append(_ev(T0 + i))
    found = _scan_map(events)
    f = found["self_narrated_trajectory"]
    if f.matched:
        return ("HELD", "padded narration unexpectedly matched")
    return ("RESIDUAL",
            "self_narrated_trajectory misses 12 narratives padded to "
            "37.5%% ratio: the volume+ratio AND-gate is defeatable by "
            "benign-event padding (detail: %r)" % (f.detail,))


@probe("behav/cross-session-interference-evasion")
def _p_behav_xsession():
    """aitm_establish in session s1, password_spray in session s2
    (same principal): self_interference MISSES -- the matcher buckets
    by (principal, session), so splitting establish/invalidate across
    sessions evades it."""
    events = [_ev(T0, tool="net", event="aitm_establish", session="s1"),
              _ev(T0 + 5, tool="auth", event="password_spray",
                   session="s2")]
    found = _scan_map(events)
    f = found["self_interference"]
    if f.matched:
        return ("HELD", "cross-session interference unexpectedly "
                "matched")
    return ("RESIDUAL",
            "self_interference misses establish/invalidate split "
            "across sessions of the same principal: per-(principal, "
            "session) bucketing (detail: %r)" % (f.detail,))


@probe("behav/interference-vocabulary-bound")
def _p_behav_vocab():
    """aitm_establish followed by credential_stuffing (same session):
    self_interference MISSES -- the establish/invalidate vocabulary is
    a closed table with exactly one pair. Detection here is
    signature-shaped, not behavior-shaped, by versioned design."""
    events = [_ev(T0, tool="net", event="aitm_establish", session="s1"),
              _ev(T0 + 5, tool="auth", event="credential_stuffing",
                   session="s1")]
    found = _scan_map(events)
    f = found["self_interference"]
    if f.matched:
        return ("HELD", "out-of-vocabulary interference unexpectedly "
                "matched")
    return ("RESIDUAL",
            "self_interference misses out-of-vocabulary pairs: closed "
            "versioned table {(aitm_establish -> password_spray)} only; "
            "new pairs need a new signature version (detail: %r)"
            % (f.detail,))


@probe("behav/benign-quiet")
def _p_behav_benign():
    """Control: 5 slow human-paced tool calls trip nothing."""
    events = [_ev(T0 + i * 60) for i in range(5)]
    found = _scan_map(events)
    fired = [s for s, f in found.items() if f.matched]
    check(not fired, "benign control tripped: %r" % (fired,))
    return ("HELD", "benign control trips no behavioral signature")

# ---------------------------------------------------------------------------
# Group F -- detectors (F243/F244 residual pins) + quorum envelope
# ---------------------------------------------------------------------------

def _det_base(name="w265-det", **kw):
    d = {"name": name, "version": "1.0.0",
         "description": "w265 redteam probe detector",
         "event_selector": {"type": "probe_event"},
         "predicates": [{"field": "flag", "op": "eq", "value": True}],
         "produces": {"event_name": name + "_fired",
                      "event_schema_version": "1.0.0", "fields": {}},
         "subscribes": [],
         "threat": {"severity": "low", "description": "probe"}}
    d.update(kw)
    return d


def _exc_block(**kw):
    b = {"name": "allow-ci", "description": "probe exception",
         "fields": ["host"], "comps": ["startswith"],
         "values": [["ci.internal.example"]]}
    b.update(kw)
    return b


@probe("detectors/policy-rev-atomic")
def _p_det_rev():
    """A failed set_policy must not bump the policy revision: the
    revision journaled on later records must name the policy actually
    in force, never a rejected one."""
    eng = det.DetectorEngine()
    eng.register_all([_det_base(exceptions=[_exc_block()])])
    sink = det.AlertSink(eng)
    sink.set_policy({"exceptions": {}})
    rev_after_good = sink._policy_rev
    check(rev_after_good == 1, "expected rev 1, got %r"
          % (rev_after_good,))
    try:
        sink.set_policy({"exceptions": {"no-such-detector": {}}})
    except det.AlertPolicyError:
        pass
    else:
        return ("BREAK", "invalid set_policy accepted")
    check(sink._policy_rev == 1,
          "rev bumped by failed set_policy: %r" % (sink._policy_rev,))
    return ("HELD", "failed set_policy leaves policy_revision at %d" %
            (sink._policy_rev,))


@probe("detectors/accessor-deep-copy")
def _p_det_copy():
    """Mutating the dict returned by DetectorEngine.detectors (at any
    depth) must not touch the live registration (F244)."""
    eng = det.DetectorEngine()
    eng.register_all([_det_base(exceptions=[_exc_block()])])
    leaked = eng.detectors["w265-det"]
    leaked["predicates"].append({"field": "x", "op": "eq",
                                 "value": 1})
    leaked["exceptions"][0]["values"].append(["evil.example"])
    live = eng.detectors["w265-det"]
    check(live["predicates"] == [
        {"field": "flag", "op": "eq", "value": True}],
        "live predicates mutated: %r" % (live["predicates"],))
    check(live["exceptions"][0]["values"] ==
          [["ci.internal.example"]],
          "live exception values mutated")
    return ("HELD", "accessor returns deep copies at every depth")


@probe("envelope/quorum-sub-threshold-open")
def _p_quorum_sub():
    """A k=2-of-3 envelope opened with only ONE share refuses
    envelope-open-refused: the wrong reconstructed key fails the tag.
    Control: two shares open it."""
    import secrets as _secrets
    from gov import encrypted_envelopes as ee
    from gov import recipient_plugins as rp
    path = os.path.join(tempfile.gettempdir(),
                        "w265-env-%d.jsonl" % (os.getpid(),))
    vault = ee.EnvelopeVault(path)
    kms = {sid: _secrets.token_bytes(32)
           for sid in ("alice", "bob", "carol")}
    pr = rp.PluginRecipient("q", "quorum-shamir/v1",
                            {"shares": dict(kms), "quorum": 2})
    env = vault.seal_plugin(b"top-secret", [pr])
    labels = [rid.decode("utf-8")
              for rid, _w in ee._parse(env).recipients]

    def identities(*holders):
        sub = {sid: kms[sid] for sid in holders}
        return {label: {"shares": dict(sub)} for label in labels}

    try:
        vault.open_plugin(env, identities("alice"))
    except ee.EnvelopeRefusal as ex:
        check(ex.code == "envelope-open-refused",
              "wrong code: %s" % ex.code)
    else:
        return ("BREAK", "sub-threshold quorum opened the envelope")
    payload, _meta = vault.open_plugin(env, identities("alice", "bob"))
    check(payload == b"top-secret", "quorum open returned wrong payload")
    return ("HELD", "1-of-3 refuses envelope-open-refused; 2-of-3 opens")


@probe("envelope/quorum-wrong-share-poison")
def _p_quorum_poison():
    """A wrong share poisons reconstruction: the tag refuses. An
    attacker holding k-1 valid shares plus one forged share learns
    nothing and opens nothing."""
    import secrets as _secrets
    from gov import encrypted_envelopes as ee
    from gov import recipient_plugins as rp
    path = os.path.join(tempfile.gettempdir(),
                        "w265-env-%d.jsonl" % (os.getpid(),))
    vault = ee.EnvelopeVault(path)
    kms = {sid: _secrets.token_bytes(32)
           for sid in ("alice", "bob", "carol")}
    pr = rp.PluginRecipient("q", "quorum-shamir/v1",
                            {"shares": dict(kms), "quorum": 2})
    env = vault.seal_plugin(b"top-secret", [pr])
    labels = [rid.decode("utf-8")
              for rid, _w in ee._parse(env).recipients]
    bad = dict(kms)
    bad["bob"] = _secrets.token_bytes(32)  # forged share material
    identities = {label: {"shares": {"alice": bad["alice"],
                                     "bob": bad["bob"]}}
                  for label in labels}
    try:
        vault.open_plugin(env, identities)
    except ee.EnvelopeRefusal as ex:
        check(ex.code == "envelope-open-refused",
              "wrong code: %s" % ex.code)
        return ("HELD", "poisoned share refuses envelope-open-refused; "
                "the tag is the single authenticity decision")
    return ("BREAK", "poisoned shares opened the envelope")


@probe("taxonomy/pin-1177")
def _p_taxonomy_pin():
    """Merge-time pin: the decision-code taxonomy still has exactly
    1177 entries (no silent additions/removals by this lane -- this
    lane adds none)."""
    import gov.decision_codes as dc
    n = len(dc.TAXONOMY)
    check(n == TAXONOMY_PIN,
          "taxonomy has %d entries, pin is %d" % (n, TAXONOMY_PIN))
    return ("HELD", "taxonomy has %d entries = pin" % (n,))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all():
    out = [_run_one(name, fn) for name, fn in RESULTS]
    return out


def _green_check():
    """Depth-1: run the adjacent wave-264 lane batteries' mains with
    GOV_SKIP_GREEN=1 in the child env (never nested green checks)."""
    adjacent = ["evals/w264_admission_probes.py",
                "evals/w264_f240f241f242_probes.py",
                "evals/w264_f243f244_probes.py",
                "evals/w264_federation_probes.py",
                "evals/w264_mandate_probes.py"]
    # w264_redteam_probes pins the KNOWN-OPEN findings (F245/F246/F247
    # class) as BREAKs and exits 1 by design; its baseline signature
    # is checked instead of its exit code.
    redteam_baseline = ("HELD 11 / BREAK 5 / BASELINE 1 / ERROR 0 "
                        "over 17 probes")
    notes = []
    for rel in adjacent:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            notes.append((rel, "missing"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="g265rt-")
        try:
            p = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                env=env, timeout=600, cwd=REPO)
            # Classification is by exit code only: some batteries use
            # BREAK/HELD as their own probe vocabulary (e.g.
            # w264_redteam_probes re-pins the known OPEN findings
            # F245/F246/F247) while still exiting 0.
            notes.append((rel, "GREEN" if p.returncode == 0
                          else "RED rc=%d" % p.returncode))
        except Exception as ex:  # noqa: BLE001
            notes.append((rel, "ERROR: %s" % ex))
    # w264_redteam_probes: baseline-signature check (see above).
    rel = "evals/w264_redteam_probes.py"
    path = os.path.join(REPO, rel)
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="g265rt-")
    try:
        p = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            env=env, timeout=600, cwd=REPO)
        summary = [ln for ln in (p.stdout + p.stderr).splitlines()
                   if "over 17 probes" in ln]
        if summary and redteam_baseline in summary[-1]:
            notes.append((rel, "GREEN (baseline signature matches)"))
        else:
            notes.append((rel, "RED: baseline drift: %r" % (summary,)))
    except Exception as ex:  # noqa: BLE001
        notes.append((rel, "ERROR: %s" % ex))
    return notes


def main():
    tmp_a = tempfile.mkdtemp(prefix="g265rt-a-")
    tmp_b = tempfile.mkdtemp(prefix="g265rt-b-")
    vectors = {}
    for run, tmp in (("A", tmp_a), ("B", tmp_b)):
        os.environ["TMPDIR"] = tmp
        tempfile.tempdir = None
        out = run_all()
        vectors[run] = [(n, v) for n, v, _d, _e in out]
        if run == "A":
            first = out
    det_ok = vectors["A"] == vectors["B"]
    n_held = sum(1 for _n, v in vectors["A"] if v == "HELD")
    n_res = sum(1 for _n, v in vectors["A"] if v == "RESIDUAL")
    n_break = sum(1 for _n, v in vectors["A"] if v == "BREAK")
    n_err = sum(1 for _n, v in vectors["A"] if v == "ERROR")

    print("wave-265 redteam probes: %d total" % len(first))
    print("run A: %d HELD / %d RESIDUAL / %d BREAK / %d ERROR"
          % (n_held, n_res, n_break, n_err))
    print("determinism A==B: %s" % ("YES" if det_ok else "NO"))
    for name, verdict, detail, _err in first:
        if verdict in ("BREAK", "ERROR"):
            print("  [%s] %s :: %s" % (verdict, name, detail))
    if not det_ok:
        print("NON-DETERMINISTIC VECTORS:")
        for a, b in zip(vectors["A"], vectors["B"]):
            if a != b:
                print("  A=%r B=%r" % (a, b))

    green = []
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        print("green check (depth-1, adjacent batteries):")
        green = _green_check()
        for rel, note in green:
            print("  %s: %s" % (rel, note))
    else:
        print("green check skipped (GOV_SKIP_GREEN=1)")

    reds = [g for g in green if g[1] not in ("GREEN", "missing") and
            not g[1].startswith("GREEN")]
    bad = [g for g in green if g[1].startswith(("RED", "ERROR"))]
    rc = 0
    if n_break or n_err or not det_ok or bad:
        rc = 1
    print("RESULT: %s" % ("PASS" if rc == 0 else "FAIL"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
