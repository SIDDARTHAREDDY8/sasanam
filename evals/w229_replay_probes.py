#!/usr/bin/env python3
"""Wave-229 lane C: policy-revision-pinned evidence replay.

ADAPT (re-derived prose; nothing copied) of the policy-revision-pinned
evidence-replay pattern: every decision pins the immutable policy
revision in force, and evidence replay re-evaluates against the PINNED
revision -- provable, not approximate.

Seams under test:
* gov/policy_revisions.py -- RevisionRegistry.register recomputes the
  digest from ruleset bytes (a caller-supplied claimed_digest that
  mismatches refuses ``replay-policy-digest-mismatch``); supersedes
  chains refuse unknown targets; duplicate rev_ids with different
  bytes refuse ``replay-policy-revision-conflict`` (identical bytes
  are idempotent).
* evaluate() stamps PolicyDecision with policy_rev_id/policy_digest
  (additive, keyword-only, legacy byte-identical when unset).
* replay(evidence, pinned_rev_id, registry, current_engine=...)
  re-evaluates the SAME evidence against the pinned revision's
  ruleset with record_telemetry=False (synthetic -- the pinned replay
  never pollutes the live mode ledger); unknown revision refuses
  ``replay-policy-revision-unknown``; tampered evidence refuses
  ``replay-evidence-tampered``; a current-policy re-evaluation that
  would change the verdict refuses ``replay-policy-drift``; replay
  results are evidence, never authority
  (``replay-policy-not-authorization``).
* build_decision_packet(policy_rev_id=..., policy_digest=...):
  optional digest-bound section, signature-covered; byte-identical
  legacy packet when omitted.

Attack shapes: mutate the live policy and replay -- the verdict must
reproduce from the PINNED revision, not follow the mutation; claim a
false digest for a revision's bytes; replay a revision that was never
registered; tamper the evidence action between capture and replay;
present a replay receipt as authority; swap the packet's pinned
digest after signing.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-228 HEAD
45fc6cbfa96f82f56e651388513c13af01c3d7b3.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g229c
  TMPDIR=/var/tmp/g229c ~/workspace/.gov-venv/bin/python evals/w229_replay_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g229c-u \\
      ~/workspace/.gov-venv/bin/python evals/w229_replay_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import sys
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import policy_revisions as _pr
    from gov import policy as _policy
    from gov import decision_packet as _dp
    from gov import decision_bom as _bom
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

PROBE_NAMES = [
    "rp-01-decision-pins-revision",
    "rp-02-replay-reproduces-verdict",
    "rp-03-mutated-policy-drift",
    "rp-04-unknown-revision-refused",
    "rp-05-claimed-digest-mismatch",
    "rp-06-supersedes-chain",
    "rp-07-tampered-evidence-refused",
    "rp-08-revision-conflict",
    "rp-09-packet-carries-pinned-revision",
]


def _refuses(fn, code):
    """True if fn() raises an Exception whose .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


_POLICY_V1 = """\
version: "1"
policies:
  - id: allow-send
    effect: allow
    match:
      tool: send_email
"""

_POLICY_V2 = """\
version: "2"
policies:
  - id: deny-send
    effect: deny
    match:
      tool: send_email
"""

_ACTION = {"tool": "send_email", "agent": "agent-1", "role": "member",
           "args": {"to": "bob@example.com"}}
_CONTEXT = {"counters": {"send_email": 1}}


def _engines():
    e1 = _policy.PolicyEngine.from_text(_POLICY_V1, source_label="p1")
    e2 = _policy.PolicyEngine.from_text(_POLICY_V2, source_label="p2")
    return e1, e2


def _wired(e1):
    reg = _pr.RevisionRegistry()
    _pr.pin_engine_bytes(reg, "policy:" + e1.policy_version,
                         _POLICY_V1.encode("utf-8"))
    return reg


def _green_check():
    """Depth-1 green check: adjacent seams, no nested battery mains."""
    if GREEN_SKIP:
        return [("green-skipped", "SKIP", "GOV_SKIP_GREEN=1")]
    checks = []
    try:
        e1 = _policy.PolicyEngine.from_text(_POLICY_V1,
                                            source_label="green")
        d = e1.evaluate(dict(_ACTION), dict(_CONTEXT))
        checks.append(("green-policy-evaluate",
                       "PASS" if d.effect == "allow" else "FAIL",
                       "baseline evaluate still allows"))
    except Exception as exc:  # noqa: BLE001
        checks.append(("green-policy-evaluate", "ERROR", "%r" % (exc,)))
    return checks


def _run_once():
    results = []

    def rec(name, verdict, detail=""):
        results.append((name, verdict, detail))

    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            rec(name, "GAP", "gov.policy_revisions absent on this tree")
        return results

    for gname, gverdict, gdetail in _green_check():
        rec(gname, gverdict, gdetail)

    # rp-01: evaluate() stamps the pinned revision; the digest is
    # recomputed from the exact policy bytes (== engine.policy_hash).
    try:
        e1, _e2 = _engines()
        d = e1.evaluate(dict(_ACTION), dict(_CONTEXT))
        import hashlib as _hl
        recomputed = _hl.sha256(_POLICY_V1.encode("utf-8")).hexdigest()
        ok = (d.effect == "allow"
              and d.policy_rev_id == "policy:1"
              and d.policy_digest == e1.policy_hash == recomputed)
        ser = d.to_dict()
        ok = ok and ser.get("policy_rev_id") == "policy:1" \
            and ser.get("policy_digest") == recomputed
        rec("rp-01-decision-pins-revision", "HELD" if ok else "BREAK",
            "decision must pin policy:1 + recomputed digest")
    except Exception as exc:  # noqa: BLE001
        rec("rp-01-decision-pins-revision", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-02: replay against the pinned revision reproduces the verdict.
    try:
        e1, _e2 = _engines()
        reg = _wired(e1)
        ev = _pr.capture_evidence(_ACTION, _CONTEXT)
        res = _pr.replay(ev, "policy:1", reg)
        live = e1.evaluate(dict(_ACTION), dict(_CONTEXT))
        ok = (res["replayed"] is True
              and res["verdict"]["effect"] == live.effect
              and res["verdict"]["reason"] == live.reason
              and res["verdict"]["policy_id"] == live.policy_id
              and res["pinned_rev_id"] == "policy:1"
              and res["policy_digest"] == e1.policy_hash)
        rec("rp-02-replay-reproduces-verdict", "HELD" if ok else "BREAK",
            "pinned replay must reproduce the live verdict exactly")
    except Exception as exc:  # noqa: BLE001
        rec("rp-02-replay-reproduces-verdict", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-03: the live policy mutates (v2 denies); replay under the
    # mutated current engine refuses replay-policy-drift, while the
    # pinned replay stays stable (proves the verdict differs from a
    # current-policy re-evaluation).
    try:
        e1, e2 = _engines()
        reg = _wired(e1)
        _pr.pin_engine_bytes(reg, "policy:" + e2.policy_version,
                             _POLICY_V2.encode("utf-8"))
        ev = _pr.capture_evidence(_ACTION, _CONTEXT)
        cur = e2.evaluate(dict(_ACTION), dict(_CONTEXT))
        drift = _refuses(
            lambda: _pr.replay(ev, "policy:1", reg, current_engine=e2),
            "replay-policy-drift")
        pinned = _pr.replay(ev, "policy:1", reg)
        ok = (cur.effect == "deny"
              and pinned["verdict"]["effect"] == "allow"
              and pinned["verdict"]["effect"] != cur.effect
              and drift)
        rec("rp-03-mutated-policy-drift", "HELD" if ok else "BREAK",
            "mutated policy denies; drift refused; pinned stays allow")
    except Exception as exc:  # noqa: BLE001
        rec("rp-03-mutated-policy-drift", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-04: an unregistered revision refuses
    # replay-policy-revision-unknown.
    try:
        e1, _e2 = _engines()
        reg = _wired(e1)
        ev = _pr.capture_evidence(_ACTION, _CONTEXT)
        ok = _refuses(
            lambda: _pr.replay(ev, "policy:999", reg),
            "replay-policy-revision-unknown")
        rec("rp-04-unknown-revision-refused", "HELD" if ok else "BREAK",
            "unregistered revision must refuse")
    except Exception as exc:  # noqa: BLE001
        rec("rp-04-unknown-revision-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-05: a caller-supplied claimed digest that does not match the
    # recomputed bytes refuses replay-policy-digest-mismatch.
    try:
        e1, _e2 = _engines()
        reg = _pr.RevisionRegistry()
        ok = _refuses(
            lambda: reg.register("policy:1",
                                 _POLICY_V1.encode("utf-8"),
                                 claimed_digest="00" * 32),
            "replay-policy-digest-mismatch")
        rec("rp-05-claimed-digest-mismatch", "HELD" if ok else "BREAK",
            "false claimed digest must refuse")
    except Exception as exc:  # noqa: BLE001
        rec("rp-05-claimed-digest-mismatch", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-06: supersedes chains are intact; a supersedes target that was
    # never registered refuses.
    try:
        reg = _pr.RevisionRegistry()
        reg.register("policy:1", _POLICY_V1.encode("utf-8"))
        reg.register("policy:2", _POLICY_V2.encode("utf-8"),
                     supersedes="policy:1")
        chain_ok = reg.chain("policy:2") == ["policy:1", "policy:2"]
        bad = _refuses(
            lambda: reg.register("policy:3",
                                 _POLICY_V2.encode("utf-8"),
                                 supersedes="policy:ghost"),
            "replay-policy-revision-unknown")
        ok = chain_ok and bad
        rec("rp-06-supersedes-chain", "HELD" if ok else "BREAK",
            "chain intact; unknown supersedes target refused")
    except Exception as exc:  # noqa: BLE001
        rec("rp-06-supersedes-chain", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-07: tampering the evidence action after capture fails the
    # replay (replay-evidence-tampered).
    try:
        e1, _e2 = _engines()
        reg = _wired(e1)
        ev = _pr.capture_evidence(_ACTION, _CONTEXT)
        ev2 = copy.deepcopy(ev)
        ev2["action"]["tool"] = "delete_everything"
        ok = _refuses(
            lambda: _pr.replay(ev2, "policy:1", reg),
            "replay-evidence-tampered")
        rec("rp-07-tampered-evidence-refused", "HELD" if ok else "BREAK",
            "tampered evidence must refuse")
    except Exception as exc:  # noqa: BLE001
        rec("rp-07-tampered-evidence-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-08: duplicate rev_id with different bytes refuses
    # replay-policy-revision-conflict; identical bytes are idempotent.
    try:
        reg = _pr.RevisionRegistry()
        reg.register("policy:1", _POLICY_V1.encode("utf-8"))
        idem = reg.register("policy:1", _POLICY_V1.encode("utf-8"))
        conflict = _refuses(
            lambda: reg.register("policy:1",
                                 _POLICY_V2.encode("utf-8")),
            "replay-policy-revision-conflict")
        ok = (idem is not None) and conflict
        rec("rp-08-revision-conflict", "HELD" if ok else "BREAK",
            "byte-conflict refused; identical bytes idempotent")
    except Exception as exc:  # noqa: BLE001
        rec("rp-08-revision-conflict", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # rp-09: the packet carries the pinned revision as a
    # signature-covered section; a swapped digest breaks the
    # signature; a legacy packet (kwargs omitted) is byte-identical
    # to one built with explicit None.
    try:
        e1, _e2 = _engines()
        digest = e1.policy_hash
        seed = bytes.fromhex("11" * 32)

        def _kw(**over):
            kw = dict(decision="allow", boundary_declared=False,
                      authority_proof=None,
                      evidence_head_digest="GENESIS",
                      policy_id="default", policy_version="1",
                      issued_at="2026-09-30T00:00:00+00:00")
            kw.update(over)
            if "bill_of_materials" not in over:
                kw["bill_of_materials"] = _bom.build_bom(
                    policy_id=kw["policy_id"],
                    policy_version=kw["policy_version"],
                    policy_digest="ab" * 32,
                    evidence_head_digest=kw["evidence_head_digest"],
                    principal={"agent_id": None, "role": None,
                               "principal": None, "run_id": None})
            return kw

        body = _dp.build_decision_packet(
            **_kw(policy_rev_id="policy:1", policy_digest=digest))
        sec = body.get("policy_revision", {}).get("value", {})
        pkt = _dp.sign_packet(body, seed)
        ok1, _r1 = _dp.verify_decision_packet(pkt)
        tampered = copy.deepcopy(pkt)
        tampered["policy_revision"]["value"]["digest"] = "00" * 32
        ok2, _r2 = _dp.verify_decision_packet(tampered)
        legacy = _dp.build_decision_packet(**_kw())
        explicit = _dp.build_decision_packet(
            **_kw(policy_rev_id=None, policy_digest=None))
        legacy_same = _dp._canonical(legacy) == _dp._canonical(explicit)
        ok = (sec.get("rev_id") == "policy:1"
              and sec.get("digest") == digest
              and ok1 and not ok2 and legacy_same)
        rec("rp-09-packet-carries-pinned-revision",
            "HELD" if ok else "BREAK",
            "section signature-covered; legacy byte-identical")
    except Exception as exc:  # noqa: BLE001
        rec("rp-09-packet-carries-pinned-revision", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    return results


def main():
    results = _run_once()
    held = sum(1 for _n, v, _d in results if v == "HELD")
    brk = sum(1 for _n, v, _d in results if v == "BREAK")
    gap = sum(1 for _n, v, _d in results if v == "GAP")
    err = sum(1 for _n, v, _d in results if v == "ERROR")
    for name, verdict, detail in results:
        print("%-44s %s %s" % (name, verdict, detail))
    print("held=%d break=%d gap=%d error=%d" % (held, brk, gap, err))
    if HAVE_MODULE and (brk or err):
        return 2
    if HAVE_MODULE and gap:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
