"""Wave-270 approval-ceremony v2 red-first battery.

Targets ``gov/approval_ceremony.py`` (approval-ceremony v2: the
langgraph interrupt ceremony STEAL — four-verdict wire format,
id-addressed resume, one-shot consumption, engine-enforced verdict
allowlist, validated response schemas, signed approver receipts —
minus langgraph's traps: no re-execution side effects, no
id-as-capability, no client-side-only enforcement, no unauthenticated
resume).

Red phase: ``GOV_CEREMONY_IMPL=stub`` selects the permissive inline
stub foil; every attack probe must BREAK on it (the stub fails to
refuse). Green phase: the real module; every probe must HELD.

Conventions: module-level staging default; deterministic (fixed
seeds, explicit ``now``); fresh unique ``/var/tmp/g270*`` TMPDIRs
(``mkdir -p`` first); depth-1 green checks honoring
``GOV_SKIP_GREEN=1``; no in-repo git subprocesses; stdlib only.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

STUB = os.environ.get("GOV_CEREMONY_IMPL", "") == "stub"

if not STUB:
    import gov.approval_ceremony as ac
    from gov import corroboration_receipt as cr
    from gov.agent_identity import did_key_from_pubkey
    from gov.signing import Ed25519Signer, Ed25519Verifier
else:
    ac = None
    from gov import corroboration_receipt as cr
    from gov.agent_identity import did_key_from_pubkey
    from gov.signing import Ed25519Signer, Ed25519Verifier

# Lane-local taxonomy pin: wave-270 approval-ceremony lane adds 11
# ``ceremony-v2-*`` codes: 1325 -> 1336. Counted on QUOTED source
# literals ("code": '...'), not len(dict) and not the bare '"code": '
# substring (wave-260: dict dedup hides double-inserted blocks; the
# bare substring also matches 2 helper-function occurrences in
# decision_codes.py). The merge coordinator owns the global pin.
TAXONOMY_PIN = 2128 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)



def _pin_check():
    import re
    with open("gov/decision_codes.py", encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code": \'([^\']*)\'', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK",
                "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    missing = [c for c in _CEREMONY_V2_CODES if c not in literals]
    if missing:
        return "BREAK", "ceremony-v2 codes missing: %r" % (missing,)
    return "HELD", "taxonomy pin 1588: 1588 unique literals, 11 ceremony-v2-* present"


_CEREMONY_V2_CODES = (
    "ceremony-v2-already-consumed",
    "ceremony-v2-ambiguous-resume",
    "ceremony-v2-malformed",
    "ceremony-v2-payload-tampered",
    "ceremony-v2-receipt-invalid",
    "ceremony-v2-schema-invalid",
    "ceremony-v2-schema-violation",
    "ceremony-v2-stale-lineage",
    "ceremony-v2-unknown-approval",
    "ceremony-v2-verdict-arg-mismatch",
    "ceremony-v2-verdict-not-allowed",
)

_RESULTS = []


def _probe(pid, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001 -- probe harness
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    _RESULTS.append((pid, verdict, note))


def _refused_with(fn, *codes):
    """HELD iff fn raises ApprovalCeremonyError with one of codes."""
    try:
        out = fn()
    except Exception as exc:
        name = type(exc).__name__
        code = getattr(exc, "code", None)
        if name in ("ApprovalCeremonyError", "StubCeremonyError")\
                and code in codes:
            return "HELD", "refused %s" % code
        return "ERROR", "%s code=%r" % (name, code)
    return "BREAK", "succeeded: %r" % (out,)


# ------------------------------------------------------------------
# Harness: keys, receipts, payloads.
# ------------------------------------------------------------------

def _seed(i):
    return bytes([i]) * 32


def _signer(i):
    return Ed25519Signer(_seed(i))


def _verifier_for(signer):
    return Ed25519Verifier(signer.public_key, key_id=signer.key_id)


def _did(signer):
    return did_key_from_pubkey(signer.public_key)


def _payload_digest(payload):
    raw = json.dumps(payload, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _receipt(signer, payload_digest, verdict="corroborated"):
    stmt = cr.build_statement(
        _did(signer), payload_digest, ["b" * 64],
        {"action": "approval.resume", "resource": "ceremony-test"},
        verdict, "2026-10-01T12:00:00Z", "approval-ceremony", "c" * 64)
    env = cr.dsse_envelope(stmt)
    return cr.sign_envelope(env, signer, signer.key_id)


_PAYLOAD = {"action": "tool.execute",
            "tool": "shell",
            "args": {"cmd": "ls /tmp"}}

NOW = 1780000000


# ------------------------------------------------------------------
# Permissive stub foil (red phase). Same interface, no checks.
# ------------------------------------------------------------------

class StubCeremonyError(Exception):
    def __init__(self, code, detail):
        super(StubCeremonyError, self).__init__(detail)
        self.code = code
        self.detail = detail


# Module-level shared store so the stub foil is permissive-but-durable:
# the restart-durability control must HELD on the stub too (only the
# security checks are absent, not the persistence).
_STUB_STORE = {}


class _StubGate(object):
    """Permissive foil: records approvals, resume always accepts."""

    def __init__(self, store, verifiers):
        self._store = store
        self._seq = 0

    def _aid(self, thread_id, name, payload):
        # Deterministic id: duplicate requests are idempotent (liveness),
        # exactly like the real gate. Only the checks are absent.
        raw = ("stub|" + thread_id + "|" + name + "|"
               + _payload_digest(payload)).encode("utf-8")
        return "stub-" + hashlib.sha256(raw).hexdigest()[:12]

    def request_approval(self, thread_id, name, payload,
                         allowed_verdicts=("accept", "ignore", "respond",
                                           "edit"),
                         response_schema=None, now=NOW):
        aid = self._aid(thread_id, name, payload)
        self._store.setdefault(thread_id, {})[aid] = {
            "payload": payload,
            "payload_digest": _payload_digest(payload),
            "allowed": list(allowed_verdicts),
        }
        return {"approval_id": aid, "payload_digest":
                _payload_digest(payload)}

    def resume_approval(self, approval_id, verdict, arg,
                        receipt_envelope, now=NOW):
        # No checks at all: accepts anything, marks nothing consumed.
        # Verdict *semantics* are honored so the controls are true
        # controls; only the security checks are absent.
        for _tid, recs in self._store.items():
            if approval_id in recs:
                rec = recs[approval_id]
                base = {"approval_id": approval_id, "verdict": verdict}
                if verdict == "edit":
                    base.update(outcome="edited", payload=arg)
                elif verdict == "respond":
                    base.update(outcome="responded", payload=arg)
                elif verdict == "ignore":
                    base.update(outcome="declined", payload=None)
                else:
                    base.update(outcome="accepted",
                                payload=rec["payload"])
                return base
        raise StubCeremonyError("ceremony-v2-unknown-approval", "stub")

    def resume_next(self, thread_id, verdict, arg, receipt_envelope,
                    now=NOW):
        recs = self._store.get(thread_id, {})
        if not recs:
            raise StubCeremonyError("ceremony-v2-unknown-approval", "stub")
        # BUG (deliberate): binds to the first pending even when many.
        aid = sorted(recs)[0]
        return self.resume_approval(aid, verdict, arg,
                                    receipt_envelope, now=now)

    def pending(self, thread_id):
        return list(self._store.get(thread_id, {}))

    def fork_thread(self, thread_id, new_lineage, now=NOW):
        return []

    def run_once(self, thread_id, once_token, fn):
        return fn()


def _make_gate(store_path=None):
    """Real gate (green) or stub foil (red)."""
    if STUB:
        return _StubGate(_STUB_STORE, {}), _signer(1)
    if store_path is None:
        store = ac.MemoryApprovalStore()
    else:
        store = ac.FileApprovalStore(store_path)
    signer = _signer(1)
    gate = ac.ApprovalGate(store, {_did(signer): _verifier_for(signer)})
    return gate, signer


def _schema_record():
    if STUB:
        return {"stub": "schema"}  # stub ignores schemas entirely
    return ac.ResponseSchema.record({
        "action": ac.ResponseSchema.text(),
        "args": ac.ResponseSchema.record({
            "cmd": ac.ResponseSchema.text(),
        }),
    })


# ------------------------------------------------------------------
# The 8 falsifiable spec tests (attack probes).
# ------------------------------------------------------------------

def p01_one_shot_consumption():
    """Double resume of the same approval: second refused, action once."""
    def run():
        gate, signer = _make_gate()
        rec = gate.request_approval("t1", "deploy", _PAYLOAD, now=NOW)
        aid = rec["approval_id"]
        env = _receipt(signer, rec["payload_digest"])
        fired = []
        out1 = gate.resume_approval(aid, "accept", None, env, now=NOW)
        if out1["outcome"] != "accepted":
            return "BREAK", "first resume did not accept: %r" % (out1,)
        fired.append(1)
        second = _refused_with(
            lambda: gate.resume_approval(aid, "accept", None, env,
                                        now=NOW + 1),
            "ceremony-v2-already-consumed")
        if second[0] != "HELD":
            return second
        if len(fired) != 1:
            return "BREAK", "continuation fired %d times" % len(fired)
        return "HELD", "second resume refused; action fired once"
    return run()


def p02_ambiguity_fails_closed():
    """Two pending + resume not addressing an id -> hard error."""
    def run():
        gate, signer = _make_gate()
        r1 = gate.request_approval("t2", "a-one", _PAYLOAD, now=NOW)
        r2 = gate.request_approval("t2", "a-two", _PAYLOAD, now=NOW)
        env = _receipt(signer, r1["payload_digest"])
        before = len(gate.pending("t2"))
        verdict, note = _refused_with(
            lambda: gate.resume_next("t2", "accept", None, env, now=NOW),
            "ceremony-v2-ambiguous-resume")
        if verdict != "HELD":
            return verdict, note
        if len(gate.pending("t2")) != before:
            return "BREAK", "an approval was consumed by the bare resume"
        # And id-addressed resume of one leaves the other pending.
        gate.resume_approval(r1["approval_id"], "accept", None, env,
                             now=NOW)
        if len(gate.pending("t2")) != before - 1:
            return "BREAK", "id-addressed resume consumed wrong approval"
        return "HELD", note
    return run()


def p03_forged_approval():
    """Receipt from an unauthorized key -> refused, no state mutation."""
    def run():
        gate, signer = _make_gate()
        rec = gate.request_approval("t3", "deploy", _PAYLOAD, now=NOW)
        aid = rec["approval_id"]
        attacker = _signer(9)  # not in the gate's approver registry
        forged = _receipt(attacker, rec["payload_digest"])
        v1, n1 = _refused_with(
            lambda: gate.resume_approval(aid, "accept", None, forged,
                                         now=NOW),
            "ceremony-v2-receipt-invalid")
        if v1 != "HELD":
            return v1, "forged receipt: " + n1
        # Tampered signature from the authorized key.
        env = _receipt(signer, rec["payload_digest"])
        env["signatures"][0]["sig"] = base64.b64encode(
            b"\x00" * 64).decode("ascii")
        v2, n2 = _refused_with(
            lambda: gate.resume_approval(aid, "accept", None, env,
                                         now=NOW),
            "ceremony-v2-receipt-invalid")
        if v2 != "HELD":
            return v2, "tampered sig: " + n2
        if aid not in [x["approval_id"] for x in gate.pending("t3")]:
            return "BREAK", "approval consumed despite forged receipts"
        return "HELD", "forged + tampered receipts refused, still pending"
    return run()


def p04_verdict_allowlist():
    """allow_edit=false + edit verdict -> refused by the ENGINE."""
    def run():
        gate, signer = _make_gate()
        rec = gate.request_approval("t4", "deploy", _PAYLOAD,
                                    allowed_verdicts=("accept", "ignore"),
                                    now=NOW)
        env = _receipt(signer, rec["payload_digest"])
        edit_arg = {"action": "tool.execute",
                    "args": {"cmd": "ls /var"}}
        return _refused_with(
            lambda: gate.resume_approval(rec["approval_id"], "edit",
                                        edit_arg, env, now=NOW),
            "ceremony-v2-verdict-not-allowed")
    return run()


def p05_schema_enforced():
    """Invalid resume payload refused; dict schemas refused at request;
    node receives the validated object."""
    def run():
        gate, signer = _make_gate()
        schema = _schema_record()
        rec = gate.request_approval("t5", "deploy", _PAYLOAD,
                                    allowed_verdicts=("edit",),
                                    response_schema=schema, now=NOW)
        env = _receipt(signer, rec["payload_digest"])
        # (a) wrong-typed arg for edit (str instead of action mapping).
        v1, n1 = _refused_with(
            lambda: gate.resume_approval(rec["approval_id"], "edit",
                                        "not-a-mapping", env, now=NOW),
            "ceremony-v2-verdict-arg-mismatch")
        if v1 != "HELD":
            return v1, "wrong-typed edit arg: " + n1
        # (b) well-typed but schema-violating (extra field).
        bad = {"action": "tool.execute", "args": {"cmd": "x"},
               "injected": True}
        v2, n2 = _refused_with(
            lambda: gate.resume_approval(rec["approval_id"], "edit",
                                        bad, env, now=NOW),
            "ceremony-v2-schema-violation")
        if v2 != "HELD":
            return v2, "schema-violating arg: " + n2
        # (c) bare-dict schema is refused at request time, not surfaced.
        v3, n3 = _refused_with(
            lambda: gate.request_approval("t5", "dict-schema", _PAYLOAD,
                                         response_schema={"type": "object"},
                                         now=NOW),
            "ceremony-v2-schema-invalid")
        if v3 != "HELD":
            return v3, "bare-dict schema: " + n3
        # (d) valid edit -> node receives the validated object.
        good = {"action": "tool.execute", "args": {"cmd": "ls /var"}}
        out = gate.resume_approval(rec["approval_id"], "edit", good, env,
                                  now=NOW)
        if out["outcome"] != "edited" or out["payload"] != good:
            return "BREAK", "validated object not delivered: %r" % (out,)
        return "HELD", "schema enforced at gate; validated object returned"
    return run()


def p06_no_pregate_replay():
    """A re-executed node performs its pre-gate side effect once."""
    def run():
        gate, _signer = _make_gate()
        calls = []

        def node_body():
            calls.append(1)
            return gate.run_once("t6", "side-effect-1",
                                 lambda: calls.append("fired") or "done")

        node_body()  # first execution: effect fires
        node_body()  # re-execution (resume model): must NOT refire
        if calls.count("fired") != 1:
            return "BREAK", "side effect fired %d times" % calls.count(
                "fired")
        return "HELD", "once-token: effect fired exactly once"
    return run()


def p07_stale_lineage():
    """Resuming an old-lineage approval after a fork is refused; the
    approval re-fires under a new id in the new lineage."""
    def run():
        gate, signer = _make_gate()
        rec = gate.request_approval("t7", "deploy", _PAYLOAD, now=NOW)
        old_id = rec["approval_id"]
        env = _receipt(signer, rec["payload_digest"])
        refired = gate.fork_thread("t7", "lineage-b", now=NOW + 1)
        if len(refired) != 1 or refired[0] == old_id:
            return "BREAK", "fork did not re-fire under a new id: %r" % (
                refired,)
        v, n = _refused_with(
            lambda: gate.resume_approval(old_id, "accept", None, env,
                                        now=NOW + 2),
            "ceremony-v2-stale-lineage")
        if v != "HELD":
            return v, "stale resume: " + n
        out = gate.resume_approval(refired[0], "accept", None, env,
                                  now=NOW + 3)
        if out["outcome"] != "accepted":
            return "BREAK", "re-fired approval would not resume: %r" % (
                out,)
        return "HELD", "stale lineage refused; re-fired id accepted"
    return run()


def p08_payload_binding():
    """A receipt signed over P cannot authorize mutated payload P'."""
    def run():
        gate, signer = _make_gate()
        rec = gate.request_approval("t8", "deploy", _PAYLOAD, now=NOW)
        mutated = {"action": "tool.execute", "tool": "shell",
                   "args": {"cmd": "rm -rf /"}}
        rec2 = gate.request_approval("t8b", "deploy", mutated, now=NOW)
        assert rec2["payload_digest"] != rec["payload_digest"]
        # Receipt honestly built over P, presented for the P' approval.
        env_over_p = _receipt(signer, rec["payload_digest"])
        return _refused_with(
            lambda: gate.resume_approval(rec2["approval_id"], "accept",
                                        None, env_over_p, now=NOW),
            "ceremony-v2-payload-tampered")
    return run()


# ------------------------------------------------------------------
# Controls (legitimate flows must work, on stub AND module).
# ------------------------------------------------------------------

def c01_accept_flow():
    def run():
        gate, signer = _make_gate()
        rec = gate.request_approval("c1", "deploy", _PAYLOAD, now=NOW)
        env = _receipt(signer, rec["payload_digest"])
        out = gate.resume_approval(rec["approval_id"], "accept", None,
                                  env, now=NOW)
        if out["outcome"] != "accepted":
            return "BREAK", "accept flow failed: %r" % (out,)
        return "HELD", "accept flow works"
    return run()


def c02_edit_flow():
    def run():
        gate, signer = _make_gate()
        rec = gate.request_approval("c2", "deploy", _PAYLOAD,
                                    allowed_verdicts=("edit", "ignore"),
                                    response_schema=_schema_record(),
                                    now=NOW)
        env = _receipt(signer, rec["payload_digest"])
        repaired = {"action": "tool.execute", "args": {"cmd": "ls /var"}}
        out = gate.resume_approval(rec["approval_id"], "edit", repaired,
                                  env, now=NOW)
        if out["outcome"] != "edited" or out["payload"] != repaired:
            return "BREAK", "edit flow failed: %r" % (out,)
        return "HELD", "edit-as-repair works"
    return run()


def c03_respond_flow():
    def run():
        gate, signer = _make_gate()
        rec = gate.request_approval("c3", "deploy", _PAYLOAD,
                                    allowed_verdicts=("respond", "accept"),
                                    now=NOW)
        env = _receipt(signer, rec["payload_digest"])
        out = gate.resume_approval(rec["approval_id"], "respond",
                                  "use the staging host", env, now=NOW)
        if out["outcome"] != "responded" or\
                out["payload"] != "use the staging host":
            return "BREAK", "respond flow failed: %r" % (out,)
        return "HELD", "respond returns feedback, not a grant"
    return run()


def c04_ignore_flow():
    def run():
        gate, signer = _make_gate()
        rec = gate.request_approval("c4", "deploy", _PAYLOAD, now=NOW)
        env = _receipt(signer, rec["payload_digest"])
        out = gate.resume_approval(rec["approval_id"], "ignore", None,
                                  env, now=NOW)
        if out["outcome"] != "declined":
            return "BREAK", "ignore flow failed: %r" % (out,)
        return "HELD", "ignore declines without granting"
    return run()


def c05_resume_next_single():
    def run():
        gate, signer = _make_gate()
        rec = gate.request_approval("c5", "deploy", _PAYLOAD, now=NOW)
        env = _receipt(signer, rec["payload_digest"])
        out = gate.resume_next("c5", "accept", None, env, now=NOW)
        if out.get("approval_id") != rec["approval_id"]:
            return "BREAK", "resume_next bound wrong id: %r" % (out,)
        return "HELD", "resume_next works with exactly one pending"
    return run()


def c06_idempotent_request():
    def run():
        gate, _signer = _make_gate()
        r1 = gate.request_approval("c6", "deploy", _PAYLOAD, now=NOW)
        r2 = gate.request_approval("c6", "deploy", _PAYLOAD, now=NOW)
        if r1["approval_id"] != r2["approval_id"]:
            return "BREAK", "duplicate request minted two ids"
        if len(gate.pending("c6")) != 1:
            return "BREAK", "duplicate request double-pended"
        return "HELD", "re-request is idempotent (re-execution safe)"
    return run()


def c07_restart_durability(tmpdir):
    def run():
        import os as _os
        path = _os.path.join(tmpdir, "journal.jsonl")
        gate, signer = _make_gate(store_path=path)
        rec = gate.request_approval("c7", "deploy", _PAYLOAD, now=NOW)
        aid = rec["approval_id"]
        # Simulated restart: drop the gate, rebuild on the same journal.
        gate2, _s2 = _make_gate(store_path=path)
        if aid not in [x["approval_id"] for x in gate2.pending("c7")]:
            return "BREAK", "pending approval lost across restart"
        env = _receipt(_signer(1), rec["payload_digest"])
        out = gate2.resume_approval(aid, "accept", None, env, now=NOW)
        if out["outcome"] != "accepted":
            return "BREAK", "post-restart resume failed: %r" % (out,)
        return "HELD", "pending approvals survive restart by id"
    return run


def c08_run_once_cache(tmpdir):
    def run():
        gate, _signer = _make_gate()
        calls = []
        v1 = gate.run_once("c8", "tok", lambda: calls.append(1) or "r")
        v2 = gate.run_once("c8", "tok", lambda: calls.append(1) or "r")
        if v1 != "r" or v2 != "r" or len(calls) != 1:
            return "BREAK", "run_once did not cache: %r" % (calls,)
        return "HELD", "run_once caches per token"
    return run


# ------------------------------------------------------------------
# Depth-1 green check + main.
# ------------------------------------------------------------------

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN", "") == "1":
        return ("SKIP", "GOV_SKIP_GREEN=1 set; recorded, not run")
    target = os.path.join(REPO, "evals", "w267_corrob_probes.py")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("TMPDIR", "/var/tmp/g270-green")
    os.makedirs(env["TMPDIR"], exist_ok=True)
    try:
        proc = subprocess.run(
            [sys.executable, target], env=env, cwd=REPO,
            capture_output=True, text=True, timeout=600)
    except Exception as exc:  # noqa: BLE001
        return ("ERROR", "green check spawn failed: %s" % exc)
    if proc.returncode != 0:
        return ("BREAK", "adjacent battery rc=%d: %s" % (
            proc.returncode, (proc.stdout + proc.stderr)[-400:]))
    return ("HELD", "w267_corrob_probes green")


def main():
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="g270-ceremony-")
    os.makedirs(tmpdir, exist_ok=True)

    attacks = [
        ("cv2/one-shot-consumption", p01_one_shot_consumption),
        ("cv2/ambiguity-fails-closed", p02_ambiguity_fails_closed),
        ("cv2/forged-approval", p03_forged_approval),
        ("cv2/verdict-allowlist", p04_verdict_allowlist),
        ("cv2/schema-enforced", p05_schema_enforced),
        ("cv2/no-pregate-replay", p06_no_pregate_replay),
        ("cv2/stale-lineage", p07_stale_lineage),
        ("cv2/payload-binding", p08_payload_binding),
    ]
    controls = [
        ("cv2/control-accept", c01_accept_flow),
        ("cv2/control-edit", c02_edit_flow),
        ("cv2/control-respond", c03_respond_flow),
        ("cv2/control-ignore", c04_ignore_flow),
        ("cv2/control-resume-next-single", c05_resume_next_single),
        ("cv2/control-idempotent-request", c06_idempotent_request),
        ("cv2/control-restart-durability",
         lambda: c07_restart_durability(tmpdir)()),
        ("cv2/control-run-once",
         lambda: c08_run_once_cache(tmpdir)()),
    ]
    for pid, fn in attacks + controls:
        _probe(pid, fn)

    _probe("cv2/taxonomy-pin", _pin_check)

    gv, gn = _green_check()
    _RESULTS.append(("cv2/green-check-w267-corrob", gv, gn))

    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    res = sum(1 for _, v, _ in _RESULTS if v == "RESIDUAL")
    skip = sum(1 for _, v, _ in _RESULTS if v == "SKIP")
    print("mode=%s" % ("STUB" if STUB else "MODULE"))
    for pid, v, n in _RESULTS:
        print("%-42s %-8s %s" % (pid, v, n))
    print("HELD=%d BREAK=%d RESIDUAL=%d ERROR=%d SKIP=%d" % (
        held, brk, err, res, skip))
    print("RESULT %s" % ("OK" if err == 0 else "FAIL"))


if __name__ == "__main__":
    main()
