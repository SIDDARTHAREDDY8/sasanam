#!/usr/bin/env python3
"""Wave-233 lane A: evaluation-function with frozen call records.

Re-derived shape (STEAL of the evaluation-function direction from the
wave-232 prospectus, draft-jackson-wimse-evaluation-02 as pattern only;
all prose and code written fresh): an authorization evaluation is a
FROZEN CALL. The input (every authorization_details entry) is digested
BEFORE evaluation; the verdict re-references that digest; the freezing
key and the adjudicating key are role-separated; replay re-runs the
PINNED policy revision against the frozen input. A verdict whose
call_digest does not match the recomputed frozen input refuses
``evaluation-input-swapped``; a replay under a changed current policy
refuses ``evaluation-policy-drift``; a non-reproducible replay refuses
``evaluation-non-reproducible``.

Seams under test (public seams only):
* gov/evaluation_function.py -- freeze_call / evaluate_call /
  verify_call / replay_evaluation / deny_authority_use.
* gov/policy_revisions.py -- RevisionRegistry pinned-revision
  composition (additive; policy_revisions.py untouched).

Attack shapes: skip an authorization_details entry (never evaluated,
no digest); freeze with the adjudicating key (role conflation);
surgically swap the frozen input post-freeze; flip the recorded
verdict and re-pin the digest; replay under a mutated live policy;
present the record as authority; half-pin the policy revision.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-232 HEAD
4ac83e2da908db2ec28b947bb8a2423f9dba20f6.

Verdicts: HELD / GAP / BREAK / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g233a
  TMPDIR=/var/tmp/g233a ~/workspace/.gov-venv/bin/python evals/w233_evalfn_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import sys
import time
import traceback
from copy import deepcopy

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_MODULE = False
try:
    from gov import evaluation_function as _ev
    from gov import policy_revisions as _pr
    from gov import policy as _pol
    HAVE_MODULE = all(hasattr(_ev, n) for n in (
        "freeze_call", "evaluate_call", "verify_call",
        "replay_evaluation", "deny_authority_use"))
except ImportError:
    _ev = _pr = _pol = None

PROBE_NAMES = [
    "evalfn-all-entries-evaluated",
    "evalfn-key-role-conflation-refused",
    "evalfn-input-swapped-refused",
    "evalfn-non-reproducible-refused",
    "evalfn-policy-drift-refused",
    "evalfn-tampered-frozen-record-refused",
    "evalfn-half-pinned-refused",
    "evalfn-empty-details-refused",
    "evalfn-not-authorization",
    "evalfn-replay-round-trip",
]

POLICY_V1 = """\
version: "1"
policies:
  - id: allow-send
    effect: allow
    match:
      tool: send_email
"""

POLICY_V2 = """\
version: "2"
policies:
  - id: deny-send
    effect: deny
    match:
      tool: send_email
"""


def _entry(tool="send_email", agent="agent-1"):
    return {"action": {"tool": tool, "agent": agent, "role": "member",
                       "args": {"to": "bob@example.com"}},
            "context": {"counters": {tool: 1}}}


def _setup():
    """Registry pinned to POLICY_V1 under 'policy:1', plus live engines."""
    reg = _pr.RevisionRegistry()
    rev = reg.register("policy:1", POLICY_V1.encode("utf-8"))
    live_v1 = _pol.PolicyEngine.from_text(POLICY_V1, source_label="<probe>")
    live_v2 = _pol.PolicyEngine.from_text(POLICY_V2, source_label="<probe>")
    assert rev.digest == live_v1.policy_hash, "pin/self-hash mismatch"
    return reg, rev, live_v1, live_v2


def _run_all():
    results = {}
    reg, rev, live_v1, live_v2 = _setup()
    ek, ak = "evidence-key-1", "adjudication-key-1"

    # 1. every entry evaluated: two entries, per-entry digests cover all
    #    and the combined verdict is deny-dominates.
    try:
        frozen = _ev.freeze_call(
            [_entry("send_email"), _entry("send_email", "agent-2")],
            evidence_key_id=ek, policy_rev_id="policy:1",
            policy_digest=rev.digest, instant="2026-09-30T10:00:00Z")
        rec = _ev.evaluate_call(frozen, reg, adjudication_key_id=ak)
        evs = rec["entry_verdicts"]
        assert len(evs) == 2, "entry verdicts missing: %d" % len(evs)
        assert [e["index"] for e in evs] == [0, 1]
        assert rec["verdict"] == "allow"
        # deny dominates: one deny entry forces the combined verdict
        frozen_d = _ev.freeze_call(
            [_entry("send_email"), _entry("send_sms")],
            evidence_key_id=ek, policy_rev_id="policy:1",
            policy_digest=rev.digest, instant="2026-09-30T10:00:01Z")
        rec_d = _ev.evaluate_call(frozen_d, reg, adjudication_key_id=ak)
        assert rec_d["verdict"] == "deny", rec_d["verdict"]
        assert [e["index"] for e in rec_d["entry_verdicts"]] == [0, 1]
        results["evalfn-all-entries-evaluated"] = "HELD"
    except Exception:
        results["evalfn-all-entries-evaluated"] = \
            "BREAK\n" + traceback.format_exc(limit=2)

    # 2. key-role conflation refused (same key freezes and adjudicates)
    try:
        frozen = _ev.freeze_call(
            [_entry()], evidence_key_id=ek, policy_rev_id="policy:1",
            policy_digest=rev.digest, instant="2026-09-30T10:00:02Z")
        _ev.evaluate_call(frozen, reg, adjudication_key_id=ek)
        results["evalfn-key-role-conflation-refused"] = "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", None) or str(exc)
        code = getattr(exc, "code", "")
        if "evaluation-key-role-conflation" in (code + reason):
            results["evalfn-key-role-conflation-refused"] = "HELD"
        else:
            results["evalfn-key-role-conflation-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 3. swapped input refused: mutate the frozen details post-freeze,
    #    keeping every recorded digest untouched.
    try:
        frozen = _ev.freeze_call(
            [_entry()], evidence_key_id=ek, policy_rev_id="policy:1",
            policy_digest=rev.digest, instant="2026-09-30T10:00:03Z")
        rec = _ev.evaluate_call(frozen, reg, adjudication_key_id=ak)
        swapped = deepcopy(rec)
        swapped["authorization_details"][0]["action"]["args"][
            "to"] = "mallory@example.com"
        _ev.verify_call(swapped, reg)
        results["evalfn-input-swapped-refused"] = "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", None) or str(exc)
        code = getattr(exc, "code", "")
        if "evaluation-input-swapped" in (code + reason):
            results["evalfn-input-swapped-refused"] = "HELD"
        else:
            results["evalfn-input-swapped-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 4. non-reproducible refused: flip the recorded verdict and re-pin
    #    the verdict digest consistently -- the digest check alone must
    #    NOT be the only guard; replay re-runs the frozen input.
    try:
        frozen = _ev.freeze_call(
            [_entry("send_sms")], evidence_key_id=ek,
            policy_rev_id="policy:1", policy_digest=rev.digest,
            instant="2026-09-30T10:00:04Z")
        rec = _ev.evaluate_call(frozen, reg, adjudication_key_id=ak)
        assert rec["verdict"] == "deny"
        forged = deepcopy(rec)
        forged["verdict"] = "allow"
        forged["verdict_digest"] = _ev.verdict_digest_of(forged)
        _ev.replay_evaluation(forged, reg)
        results["evalfn-non-reproducible-refused"] = "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", None) or str(exc)
        code = getattr(exc, "code", "")
        if "evaluation-non-reproducible" in (code + reason):
            results["evalfn-non-reproducible-refused"] = "HELD"
        else:
            results["evalfn-non-reproducible-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 5. policy drift refused: replay against a CURRENT engine whose
    #    policy changed the verdict.
    try:
        frozen = _ev.freeze_call(
            [_entry()], evidence_key_id=ek, policy_rev_id="policy:1",
            policy_digest=rev.digest, instant="2026-09-30T10:00:05Z")
        rec = _ev.evaluate_call(frozen, reg, adjudication_key_id=ak)
        assert rec["verdict"] == "allow"
        _ev.replay_evaluation(rec, reg, current_engine=live_v2)
        results["evalfn-policy-drift-refused"] = "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", None) or str(exc)
        code = getattr(exc, "code", "")
        if "evaluation-policy-drift" in (code + reason):
            results["evalfn-policy-drift-refused"] = "HELD"
        else:
            results["evalfn-policy-drift-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 6. tampered frozen record refused (missing adjudication key id,
    #    dangling entry digest)
    try:
        frozen = _ev.freeze_call(
            [_entry()], evidence_key_id=ek, policy_rev_id="policy:1",
            policy_digest=rev.digest, instant="2026-09-30T10:00:06Z")
        rec = _ev.evaluate_call(frozen, reg, adjudication_key_id=ak)
        tampered = deepcopy(rec)
        tampered["entry_verdicts"] = tampered["entry_verdicts"][:0]
        _ev.verify_call(tampered, reg)
        results["evalfn-tampered-frozen-record-refused"] = \
            "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", None) or str(exc)
        code = getattr(exc, "code", "")
        if "evaluation-input-swapped" in (code + reason) or \
                "evaluation-incomplete-details" in (code + reason):
            results["evalfn-tampered-frozen-record-refused"] = "HELD"
        else:
            results["evalfn-tampered-frozen-record-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 7. half-pinned revision refused at freeze
    try:
        _ev.freeze_call([_entry()], evidence_key_id=ek,
                        policy_rev_id="policy:1", policy_digest=None,
                        instant="2026-09-30T10:00:07Z")
        results["evalfn-half-pinned-refused"] = "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", None) or str(exc)
        code = getattr(exc, "code", "")
        if "evaluation-malformed" in (code + reason):
            results["evalfn-half-pinned-refused"] = "HELD"
        else:
            results["evalfn-half-pinned-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 8. empty authorization_details refused at freeze
    try:
        _ev.freeze_call([], evidence_key_id=ek, policy_rev_id="policy:1",
                        policy_digest=rev.digest,
                        instant="2026-09-30T10:00:08Z")
        results["evalfn-empty-details-refused"] = "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", None) or str(exc)
        code = getattr(exc, "code", "")
        if "evaluation-malformed" in (code + reason):
            results["evalfn-empty-details-refused"] = "HELD"
        else:
            results["evalfn-empty-details-refused"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 9. an evaluation record is evidence, never authority
    try:
        frozen = _ev.freeze_call(
            [_entry()], evidence_key_id=ek, policy_rev_id="policy:1",
            policy_digest=rev.digest, instant="2026-09-30T10:00:09Z")
        rec = _ev.evaluate_call(frozen, reg, adjudication_key_id=ak)
        _ev.deny_authority_use(rec)
        results["evalfn-not-authorization"] = "BREAK: no refusal"
    except Exception as exc:
        reason = getattr(exc, "reason", None) or str(exc)
        code = getattr(exc, "code", "")
        if "evaluation-not-authorization" in (code + reason):
            results["evalfn-not-authorization"] = "HELD"
        else:
            results["evalfn-not-authorization"] = \
                "BREAK: wrong refusal %r" % (reason,)

    # 10. full round trip: freeze -> evaluate -> verify -> replay,
    #     digests recomputed independently.
    try:
        frozen = _ev.freeze_call(
            [_entry("send_email"), _entry("send_sms")],
            evidence_key_id=ek, policy_rev_id="policy:1",
            policy_digest=rev.digest, instant="2026-09-30T10:00:10Z")
        assert len(frozen["call_digest"]) == 64
        rec = _ev.evaluate_call(frozen, reg, adjudication_key_id=ak)
        assert rec["verdict"] == "deny"  # deny dominates
        ok = _ev.verify_call(rec, reg)
        assert ok["call_digest"] == frozen["call_digest"]
        out = _ev.replay_evaluation(rec, reg)
        assert out["replayed"] is True and out["verdict"] == "deny"
        out2 = _ev.replay_evaluation(rec, reg, current_engine=live_v1)
        assert out2["drift_checked"] is True
        assert out2["verdict"] == "deny"
        results["evalfn-replay-round-trip"] = "HELD"
    except Exception:
        results["evalfn-replay-round-trip"] = \
            "BREAK\n" + traceback.format_exc(limit=2)

    return results


def main():
    t0 = time.time()
    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            print("%-42s GAP (evaluation_function absent)" % name)
        print("summary: 0 HELD / %d GAP / 0 BREAK / 0 ERROR" % len(PROBE_NAMES))
        return 2
    results = _run_all()
    held = sum(1 for v in results.values() if v == "HELD")
    gap = sum(1 for v in results.values() if v.startswith("GAP"))
    brk = sum(1 for v in results.values() if v.startswith("BREAK"))
    err = sum(1 for v in results.values() if v.startswith("ERROR"))
    for name in PROBE_NAMES:
        verdict = results.get(name, "ERROR: missing")
        first = verdict.split("\n")[0]
        print("%-42s %s" % (name, first))
        if "\n" in verdict:
            print(verdict.split("\n", 1)[1])
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR (%.1fs)"
          % (held, gap, brk, err, time.time() - t0))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
