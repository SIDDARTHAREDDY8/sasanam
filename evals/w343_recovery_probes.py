#!/usr/bin/env python3
"""Wave-343 lane 6 battery: recovery-as-product post-block UX.

Steal target: Archestra OpenAPPA recovery-as-product (MIT engine repo;
ADAPT patterns only). Product surface: gov/recovery_guide.py -- turns a
coded refusal into a structured, human-readable RecoveryGuide (what was
blocked, why in the policy's own language, exact lawful next steps) plus
a BlockJournal with blocked-mark semantics (retries distinguishable from
fresh requests; marks permanent; guide can never authorize).

$0 SPEND BY CONSTRUCTION: this battery makes NO model calls. Every probe
uses canned inputs and local records -- never a live provider. Do NOT add
ModelDriver/SpendLedger usage here.

Red-first note: the unliftable probes assert the CURRENT fail-closed
behavior (empty remedy plan -> unliftable notice, never invented steps).
If a future change makes an unliftable probe produce steps, that probe
goes BREAK by design -- the tripwire working, not a false alarm.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w343_recovery_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import dataclasses
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2135  # Wave-342 merge: pin stays 2131, no new codes; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)

from gov import recovery_guide as rg  # noqa: E402
from gov import trajectory_labels as tl  # noqa: E402
from gov import decision_contract as dc  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# ---------------------------------------------------------------- fixtures

_CANARY = "sk-canary-9f8e7d6c5b4a"  # oracle probe: must never surface


def _egress_refusal():
    """A real R40 refusal: DLP-flagged bytes folded, public dispatch."""
    traj = tl.Trajectory()
    traj = tl.fold(traj, tool="slack_reader",
                   output=b"token xoxb-abc123def456 here",
                   declared=tl.TOP, strict=False)
    ref = tl.check_dispatch(traj, recipient={"public-channel"},
                            action="send_slack")
    assert ref is not None
    return ref


def _blocked_refusal():
    """A real absolute-deny refusal: trajectory carries the blocked mark."""
    traj = tl.mark_blocked(tl.Trajectory())
    ref = tl.check_dispatch(traj, recipient={"x"}, action="send_slack")
    assert ref is not None
    return ref


def _decision_fixtures(effect):
    req = dc.Request(principal="agent-7", action="send_email",
                     resource="smtp://ext.example.com", role=None,
                     args={"to": "ext@example.com"}, context={})
    hit = dc.RuleHit(rule_id="no-external-mail", effect="deny",
                     reason="external mail disabled by policy",
                     flag=None, declaration_index=0, deciding=True)
    diag = dc.Diagnostics(deciding_rule=hit, forbid_hits=(hit,),
                          policy_ids=frozenset({"mail-policy"}))
    dec = dc.Decision(effect=effect, allowed=(effect == "allow"),
                      reason="decided", policy_id="mail-policy",
                      flag=None, diagnostics=diag, request=req)
    return req, dec, diag


# ------------------------------------------------------------------ probes

def test_p1_pin_taxonomy():
    ok = (isinstance(TAXONOMY, dict) and len(TAXONOMY) == TAXONOMY_PIN)
    return ("HELD" if ok else "BREAK",
            "taxonomy pin 2131 (no new codes): %d codes" % len(TAXONOMY))


def test_p2_footer_state():
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(path) as f:
        last = "".join(f.readlines()[-3:])
    ok = ("Next free finding: **F503**" in last
          and "Open findings: F496, F497, F498, F499, F500, F501, F502." in last)
    return ("HELD" if ok else "BREAK",
            "footer must read open F429 / next F430")


def test_p3_guide_from_refusal_steps():
    ref = _egress_refusal()
    guide = rg.build_guide(rg.view_from_refusal(
        ref, principal="agent-7", resource="slack://public-channel"))
    rec = guide.to_record()
    steps = rec["requester"]["steps"]
    plan_names = sorted(r.value for r in ref.plan.remedies)
    step_names = sorted(s["remedy"] for s in steps)
    ok = (guide.code == "label-egress-refused"
          and not guide.unliftable
          and step_names == plan_names
          and all(s["kind"] == "remedy" for s in steps)
          and all(s["title"] and s["detail"] and s["prerequisite"]
                  for s in steps))
    return ("HELD" if ok else "BREAK",
            "guide carries the plan's remedies verbatim: %s" % step_names)


def test_p4_guide_determinism():
    ref = _egress_refusal()
    mk = lambda: rg.build_guide(rg.view_from_refusal(
        ref, principal="agent-7", resource="slack://public-channel"))
    g1, g2 = mk(), mk()
    ok = (g1.record_digest() == g2.record_digest()
          and g1.guide_digest == g2.guide_digest)
    return ("HELD" if ok else "BREAK",
            "identical input -> identical digests")


def test_p5_unliftable_never_invents():
    ref = _blocked_refusal()
    guide = rg.build_guide(rg.view_from_refusal(ref, principal="agent-7"))
    rec = guide.to_record()
    ok = (guide.unliftable
          and rec["requester"]["steps"] == []
          and guide.notice is not None
          and "v1" in guide.notice
          and "Escalate to a human operator" in guide.notice)
    return ("HELD" if ok else "BREAK",
            "empty plan -> unliftable notice, zero invented steps")


def test_p6_guide_never_authorizes():
    # The guide is records-in/records-out: building one must not change
    # the enforcement outcome, and the guide must expose no allow/permit
    # surface.
    traj = tl.mark_blocked(tl.Trajectory())
    ref = tl.check_dispatch(traj, recipient={"x"}, action="send_slack")
    guide = rg.build_guide(rg.view_from_refusal(ref, principal="a"))
    still_refused = tl.check_dispatch(traj, recipient={"x"},
                                      action="send_slack")
    ok = (still_refused is not None
          and still_refused.code == "label-remedy-empty-unliftable"
          and not hasattr(guide, "allow") and not hasattr(guide, "permit")
          and not hasattr(guide, "authorize"))
    return ("HELD" if ok else "BREAK",
            "guide issuance leaves the refusal standing; no auth surface")


def test_p7_journal_initial_vs_retry():
    j = rg.BlockJournal()
    d = rg.canonical_request_digest("agent-7", "send_slack",
                                    "slack://public-channel")
    m1 = j.mark(d, "label-egress-refused", noted_at="2026-10-05T00:00:00Z")
    m2 = j.mark(d, "label-egress-refused", noted_at="2026-10-05T00:00:01Z")
    d2 = rg.canonical_request_digest("agent-7", "send_email", None)
    m3 = j.mark(d2, "label-egress-refused")
    ok = (m1.attempt_kind == "initial" and m1.attempt_no == 1
          and m1.retry_of is None
          and m2.attempt_kind == "retry" and m2.attempt_no == 2
          and m2.retry_of == m1.mark_id
          and m3.attempt_kind == "initial" and m3.attempt_no == 1
          and len(j) == 3)
    return ("HELD" if ok else "BREAK",
            "same digest -> retry (retry_of linked); new digest -> initial")


def test_p8_journal_chain_verify_and_tamper():
    j = rg.BlockJournal()
    d = rg.canonical_request_digest("a", "act", "res")
    j.mark(d, "label-egress-refused")
    j.mark(d, "label-egress-refused")
    ok_chain = j.verify_chain()
    # Adversarial: forge one entry's mark_id, chain must fail.
    bad = dataclasses.replace(j._entries[0], mark_id="0" * 64)
    j2 = rg.BlockJournal()
    j2._entries = [bad, j._entries[1]]
    j2._head = j._head
    ok = ok_chain and not j2.verify_chain()
    return ("HELD" if ok else "BREAK",
            "honest chain verifies; forged mark_id fails")


def test_p9_retry_storm_advisory():
    j = rg.BlockJournal()
    d = rg.canonical_request_digest("a", "act", "res")
    marks = [j.mark(d, "label-egress-refused") for _ in range(6)]
    ok = (all(m.advisory is None for m in marks[:4])
          and marks[4].advisory is not None
          and marks[5].advisory is not None
          and "escalate to a human" in marks[4].advisory
          and rg.retry_advisory(marks[0]) is None)
    return ("HELD" if ok else "BREAK",
            "storm advisory appears at attempt 5+, never before")


def test_p10_no_unmark_api():
    j = rg.BlockJournal()
    ok = not any(hasattr(j, name) for name in
                 ("unmark", "clear", "remove", "reset", "delete"))
    return ("HELD" if ok else "BREAK",
            "block marks are permanent: no unmark/clear API")


def test_p11_absolute_mark_flag():
    j = rg.BlockJournal()
    d1 = rg.canonical_request_digest("a", "act1", None)
    d2 = rg.canonical_request_digest("a", "act2", None)
    m_abs = j.mark(d1, "label-remedy-empty-unliftable")
    m_plain = j.mark(d2, "label-egress-refused")
    ok = m_abs.absolute and not m_plain.absolute
    return ("HELD" if ok else "BREAK",
            "absolute-deny code -> absolute mark; others do not")


def test_p12_diagnostics_deny_adapter():
    req, dec, diag = _decision_fixtures("deny")
    view = rg.view_from_diagnostics(req, dec, diag,
                                    code="mail-egress-refused")
    guide = rg.build_guide(view)
    kinds = [s.kind for s in guide.steps]
    ok = (not guide.unliftable
          and kinds == ["procedural", "procedural"]
          and "deciding_rule" not in guide.to_record()["requester"]
          and guide.audit["deciding_rule"] == "no-external-mail"
          and guide.audit["policy_id"] == "mail-policy"
          and "no-external-mail" in guide.steps[0].detail)
    return ("HELD" if ok else "BREAK",
            "deny -> procedural re-scope + policy-owner, rule named")


def test_p13_diagnostics_approval_adapter():
    req, dec, diag = _decision_fixtures("require_approval")
    view = rg.view_from_diagnostics(req, dec, diag)
    guide = rg.build_guide(view)
    ok = (len(guide.steps) == 1
          and guide.steps[0].remedy == "procedural-authorize"
          and guide.steps[0].kind == "procedural"
          and "approval_request.issue" in guide.steps[0].detail)
    return ("HELD" if ok else "BREAK",
            "require_approval -> single procedural authorize step")


def test_p14_diagnostics_allow_raises():
    req, dec, diag = _decision_fixtures("allow")
    try:
        rg.view_from_diagnostics(req, dec, diag)
    except rg.RecoveryGuideError:
        return ("HELD", "guide for an allowed action raises loud")
    return ("BREAK", "allowed action must not yield a guide")


def test_p15_record_adapter_roundtrip():
    record = {"code": "label-egress-refused", "action": "send_slack",
              "principal": "agent-7", "resource": "slack://c",
              "reason": "recipient outside audience",
              "deciding_rule": "r1", "policy_id": "p1",
              "policy_version": "3",
              "remedies": ["withhold", "derive"],
              "remedy_vocab_version": 1,
              "trajectory_digest": "ab" * 32,
              "refusal_digest": "cd" * 32}
    view = rg.view_from_record(record)
    guide = rg.build_guide(view)
    rec = guide.to_record()
    ok = (guide.code == "label-egress-refused"
          and sorted(s["remedy"] for s in rec["requester"]["steps"])
          == ["derive", "withhold"]
          and rec["audit"]["deciding_rule"] == "r1"
          and rec["audit"]["policy_id"] == "p1"
          and rec["audit"]["refusal_digest"] == "cd" * 32)
    return ("HELD" if ok else "BREAK",
            "dict adapter preserves every field into the guide")


def test_p16_oracle_clean_requester_section():
    # The reason carries a canary secret: it may live in the audit
    # section, but must never appear in the requester-visible text.
    # The view also carries no raw args at all (nothing to echo).
    record = {"code": "label-egress-refused", "action": "send_slack",
              "principal": "agent-7", "reason": "saw " + _CANARY,
              "remedies": ["withhold"]}
    guide = rg.build_guide(rg.view_from_record(record))
    req_text = (guide.what + guide.why
                + "".join(s.title + s.detail for s in guide.steps)
                + (guide.notice or ""))
    ok = (_CANARY not in req_text
          and _CANARY in guide.audit["reason"]
          and not hasattr(rg.RefusalView, "args"))
    return ("HELD" if ok else "BREAK",
            "canary in audit only; requester section oracle-clean")


def test_p17_canonical_digest_properties():
    d1 = rg.canonical_request_digest("a", "act", "res", {"k": "v"})
    d2 = rg.canonical_request_digest("a", "act", "res", {"k": "v"})
    d3 = rg.canonical_request_digest("b", "act", "res", {"k": "v"})
    ok = (d1 == d2 and d1 != d3 and len(d1) == 64
          and all(c in "0123456789abcdef" for c in d1))
    return ("HELD" if ok else "BREAK",
            "digest deterministic, principal-sensitive, hex-shaped")


def test_p18_bad_inputs_raise_loud():
    bad = 0
    try:
        rg.RefusalView(code="", action="x")
    except rg.RecoveryGuideError:
        bad += 1
    try:
        rg.RefusalView(code="c", action="")
    except rg.RecoveryGuideError:
        bad += 1
    try:
        rg.RefusalView(code="c", action="x", remedies={"bribe"})
    except rg.RecoveryGuideError:
        bad += 1
    try:
        rg.build_guide("not-a-view")
    except rg.RecoveryGuideError:
        bad += 1
    try:
        rg.view_from_record("not-a-mapping")
    except rg.RecoveryGuideError:
        bad += 1
    try:
        rg.BlockJournal().mark("", "label-egress-refused")
    except rg.RecoveryGuideError:
        bad += 1
    ok = bad == 6
    return ("HELD" if ok else "BREAK",
            "6/6 malformed inputs raise RecoveryGuideError (got %d)" % bad)


def test_p19_guide_record_shape():
    ref = _egress_refusal()
    guide = rg.build_guide(rg.view_from_refusal(ref, principal="a"))
    rec = guide.to_record()
    ok = (set(rec.keys()) == {"requester", "audit"}
          and set(rec["requester"].keys()) == {
              "code", "guide_digest", "notice", "remedy_vocab_version",
              "request_digest", "steps", "unliftable", "what", "why"}
          and rec["requester"]["guide_digest"] == guide.guide_digest
          and guide.record_digest() == guide.record_digest())
    return ("HELD" if ok else "BREAK",
            "record has requester+audit sections, digest-bound")


def test_p20_vocab_scan_clean():
    # This module must not introduce unregistered machine codes: the
    # tree-wide vocabulary scanner only picks up code-shaped literals
    # in gov/; assert none of this module's identifiers look like one.
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "recovery_guide.py"),
               encoding="utf-8").read()
    const_re = re.compile(
        r'(?m)^\s*([A-Z][A-Z0-9_]*)\s*=\s*["\']([a-z0-9][a-z0-9_.-]*)["\']')
    hits = [(m.group(1), m.group(2)) for m in const_re.finditer(src)]
    ok = hits == []
    return ("HELD" if ok else "BREAK",
            "no ALL-CAPS code-shaped constants in gov/recovery_guide.py: %r"
            % (hits,))


TESTS = [
    test_p1_pin_taxonomy, test_p2_footer_state,
    test_p3_guide_from_refusal_steps, test_p4_guide_determinism,
    test_p5_unliftable_never_invents, test_p6_guide_never_authorizes,
    test_p7_journal_initial_vs_retry, test_p8_journal_chain_verify_and_tamper,
    test_p9_retry_storm_advisory, test_p10_no_unmark_api,
    test_p11_absolute_mark_flag, test_p12_diagnostics_deny_adapter,
    test_p13_diagnostics_approval_adapter, test_p14_diagnostics_allow_raises,
    test_p15_record_adapter_roundtrip, test_p16_oracle_clean_requester_section,
    test_p17_canonical_digest_properties, test_p18_bad_inputs_raise_loud,
    test_p19_guide_record_shape, test_p20_vocab_scan_clean,
]

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere


def _green_check():
    """Depth-1 green check: the adjacent R40 battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w342_r40_label_probes.py",):
        tmp = "/var/tmp/g343-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        tail = (r.stdout + r.stderr)[-300:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    n_break = n_held = n_err = 0
    probe_breaks = set()
    for fn in TESTS:
        if args.only and fn.__name__ != args.only:
            continue
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - loud, never a skip
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%-6s %-42s %s" % (verdict, fn.__name__, detail))
        if verdict == "BREAK":
            n_break += 1
            probe_breaks.add(fn.__name__)
        elif verdict == "HELD":
            n_held += 1
        else:
            n_err += 1
    print("result: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held,
                                                    n_err))
    if probe_breaks ^ _EXPECTED_BREAKS:
        raise SystemExit("BREAK set mismatch: got %s, expected %s"
                         % (sorted(probe_breaks),
                            sorted(_EXPECTED_BREAKS)))
    if n_err:
        raise SystemExit("ERRORs present")
    if n_break:
        raise SystemExit("BREAKs present")


if __name__ == "__main__":
    main()
