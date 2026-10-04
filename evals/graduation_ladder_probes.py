#!/usr/bin/env python3
"""Red-first break battery for wave-198: Gatekeeper graduation ladder.

The gap (pristine tree): policy rules have no rollout mode. A new rule
is deny-on-day-one or it does not exist -- there is no observe (record
violations, carry no authority), no warn (nominal verdict, enforced
allow, operator telemetry), no per-rule violation ledger, no
evidence-gated graduation, and no quorum-wired demotion. The spike
(wave-196 lane E, SPIKE.md) concluded ADAPT: take Gatekeeper's rollout
discipline (observe -> warn -> deny), not its K8s machinery.

Probes (each run twice; any disagreement is ERROR):
  P0 fresh-deny-blocks:  a newly added deny rule blocks on day one
                         (baseline the ladder must preserve; HELD on
                         both trees).
  P1 warn-fatigue (R1):  1000 warn-mode hits -> ONE operator digest,
                         all requests admitted, no agent interrupts.
  P2 dryrun-blindness(R2): 200 evaluations / 0 violations -> graduation
                         refused; heartbeat distinguishes no-traffic
                         from broken-rule.
  P3 demotion-abuse (R3): unilateral demotion refused; pinned-rule
                         demotion refused at any quorum; non-eligible
                         (agent) approvers refused.
  P4 observe-cannot-weaken (R4): observe hits are named but carry no
                         authority; existing deny rules and the
                         implicit default deny decide as before.
  P5 happy-path (R5):    observe -> warn -> deny on evidence
                         (>=100 evaluated, >=10 violations, >=20
                         reviewed, FP <5% / <1%, 2 distinct human
                         approvers, warning acks).
  P6 high-fp-refused (R6): 35% FP refused despite 5 approvers.
  P7 invalid-modes (R7): unknown mode and pinned+non-deny fail LOUD
                         at policy load.
  P8 byte-identical:     mode-absent policies produce byte-identical
                         verdicts (golden 5-tuples; on ladder trees
                         additionally: no ladder keys in to_dict()).

Pristine expectation: P0 HELD, P8 HELD, P1-P7 BREAK (7/9 BREAK).
Fixed expectation: 9/9 HELD.

Stdlib only. Deterministic (no randomness; fixed synthetic traffic).
Sets GOV_DEPLOYMENT_MODE=staging at module level; verify standalone
under ``env -u GOV_DEPLOYMENT_MODE``. Honors GOV_SKIP_GREEN=1 (green
check is depth-1: the adjacent unit suite only, never nested battery
mains).
"""

import importlib.util
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import secrets  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402

# The warn-digest probe (P1) chains entries through a real ActionLog,
# which fails closed without an explicit key (F73: no dev fallback).
# Ephemeral synthetic key, setdefault so a real deployment key wins.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "graduation-ladder-battery")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov.policy import PolicyEngine  # noqa: E402
from gov.decision_contract import Request  # noqa: E402
import probe_lines  # noqa: E402  (canonical probe-line form)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

_HAS_LADDER = importlib.util.find_spec("gov.mode_ledger") is not None
if _HAS_LADDER:
    from gov import mode_ledger as ml  # noqa: E402


def _req(tool):
    return Request.from_action({"tool": tool, "args": {}})


def _QUORUM_BLOCK():
    # Wave-198: graduation/demotion seams fail closed without a
    # configured approvals.quorum (human attestation, §3.4).
    return ("approvals:\n"
            "  quorum:\n"
            "    min_approvals: 2\n"
            "    eligible_principals: [op1, op2]\n")


def _ladder_policy():
    return PolicyEngine.from_text(
        "version: 1\n" + _QUORUM_BLOCK() +
        "policies:\n"
        "  - id: fresh-deny\n"
        "    effect: deny\n"
        "    match:\n"
        "      tool: send_email\n"
        "    reason: fresh deny blocks day one\n"
        "  - id: observe-rule\n"
        "    effect: deny\n"
        "    mode: observe\n"
        "    match:\n"
        "      tool: write_file\n"
        "    reason: observing write rule\n"
        "  - id: warn-rule\n"
        "    effect: deny\n"
        "    mode: warn\n"
        "    match:\n"
        "      tool: delete_file\n"
        "    reason: warning delete rule\n"
        "  - id: pinned-exfil\n"
        "    effect: deny\n"
        "    pinned: true\n"
        "    match:\n"
        "      tool: api_call\n"
        "    reason: pinned exfil forbid\n")


def _executor_for(engine):
    """Minimal real ToolExecutor for the warn-digest seam (P1)."""
    from gov.executor import ToolExecutor
    from gov.log import ActionLog, read_entries
    from gov.approvals import ApprovalQueue
    run_dir = tempfile.mkdtemp(prefix="gov-grad-")
    log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
    queue = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, engine, log, queue,
                      ungoverned_ack=("synthetic wave-198 battery: raw "
                                      "pipeline by design"))
    return ex, lambda: read_entries(os.path.join(run_dir,
                                                 "actions.jsonl"))


# ------------------------------------------------------------------ probes

def _p0_fresh_deny_blocks():
    eng = PolicyEngine.from_text(
        "version: 1\npolicies:\n"
        "  - id: brand-new\n"
        "    effect: deny\n"
        "    match:\n"
        "      tool: send_email\n"
        "    reason: new rule blocks day one\n")
    d = eng.decide(_req("send_email"))
    if (d.effect, d.allowed) != ("deny", False):
        return "BREAK", "fresh deny rule did not block: %r" % (d.effect,)
    if d.policy_id != "brand-new":
        return "BREAK", "wrong decider: %r" % (d.policy_id,)
    return "HELD", "fresh deny rule blocks day one (mode-absent)"


def _p1_warn_fatigue():
    if not _HAS_LADDER:
        return "BREAK", "no ladder: gov.mode_ledger absent (R1 unhandled)"
    eng = _ladder_policy()
    ex, read_log = _executor_for(eng)
    n = 1000
    admitted = 0
    for _ in range(n):
        d = eng.decide(_req("delete_file"))
        if d.effect != "allow" or not d.allowed:
            return "BREAK", "warn-mode hit not admitted: %r" % (d.effect,)
        if d.nominal_effect != "deny" or not d.warnings:
            return "BREAK", "warn decision lost nominal/warnings"
        admitted += 1
        ex._surface_warn_digest(d.to_policy_decision())
    digests = ex.flush_warn_digests()
    if len(digests) != 1:
        return "BREAK", "%d digests for %d warnings (want 1)" % (
            len(digests), n)
    if digests[0]["count"] != n or digests[0]["rule_id"] != "warn-rule":
        return "BREAK", "digest miscounted: %r" % (digests[0],)
    chained = [e for e in read_log() if e.get("event") == "warn_digest"]
    if len(chained) != 1:
        return "BREAK", "%d chained warn_digest entries (want 1)" % (
            len(chained),)
    return "HELD", ("%d warn hits -> 1 operator digest, %d admitted, "
                    "0 agent interrupts" % (n, admitted))


def _p2_dryrun_blindness():
    if not _HAS_LADDER:
        return "BREAK", "no ladder: gov.mode_ledger absent (R2 unhandled)"
    eng = _ladder_policy()
    for _ in range(200):
        eng.decide(_req("read_file"))  # never matches observe-rule
    eng.mode_ledger.heartbeat("observe-rule", exercised=False,
                              detail="canary: no write_file traffic seen")
    eng.mode_ledger.heartbeat("observe-rule", exercised=True,
                              detail="canary: synthetic write_file matched")
    ok, reasons = eng.evaluate_graduation(
        "observe-rule", "warn", approvers=["op1", "op2"])
    if ok:
        return "BREAK", "graduated on zero violations (dryrun-blind)"
    if not any("zero violations" in r for r in reasons):
        return "BREAK", "refused but not for zero data: %r" % (reasons,)
    ok_chain, _ = eng.mode_ledger.verify_chain()
    if not ok_chain:
        return "ERROR", "ledger chain failed to verify"
    return "HELD", ("zero-violation graduation refused; heartbeats "
                    "distinguish no-traffic from broken-rule")


def _p3_demotion_abuse():
    if not _HAS_LADDER:
        return "BREAK", "no ladder: gov.mode_ledger absent (R3 unhandled)"
    eng = _ladder_policy()
    # Graduate warn-rule to deny first so there is something to demote.
    # §3.4 "longer window": warn->deny needs >=200 evaluated.
    for _ in range(200):
        eng.decide(_req("delete_file"))
    for _ in range(25):
        eng.mode_ledger.record_review("warn-rule", correct=True,
                                      reviewer="op1")
    for _ in range(6):
        eng.mode_ledger.record_warning_ack("warn-rule", operator="op1")
    ok, _ = eng.apply_graduation("warn-rule", "deny",
                                 approvers=["op1", "op2"])
    if not ok:
        return "ERROR", "setup graduation failed"
    # (a) unilateral demotion: one approver is not a quorum.
    pid = eng.propose_demotion("warn-rule", "warn",
                               reason="FP spike reported",
                               requested_by="op1")
    ok, reasons = eng.approve_demotion(pid, approvers=["op1"])
    if ok:
        return "BREAK", "unilateral demotion applied (R3)"
    if not any("quorum" in r for r in reasons):
        return "BREAK", "refused but not on quorum: %r" % (reasons,)
    # (b) pinned rule: demotion refused at ANY quorum.
    try:
        eng.propose_demotion("pinned-exfil", "warn",
                             reason="operator wants warn",
                             requested_by="op1")
        return "BREAK", "pinned-rule demotion proposal accepted"
    except ml.ModeLedgerError as e:
        if "pinned" not in str(e).lower():
            return "BREAK", "pinned refused for wrong reason: %s" % (e,)
    # (c) agent principals are not eligible human approvers: the
    # ladder's quorum check runs against the policy's approvals
    # quorum eligible set, and ineligible principals are refused.
    # (Separate warn-mode engine: warn-rule above already graduated.)
    eng3 = PolicyEngine.from_text(
        "version: 1\npolicies:\n"
        "  - id: wr\n"
        "    effect: deny\n"
        "    mode: warn\n"
        "    match:\n"
        "      tool: delete_file\n"
        "    reason: warn rule\n")
    for i in range(100):
        eng3.decide(_req("delete_file" if i % 10 == 0 else "read_file"))
    for _ in range(25):
        eng3.mode_ledger.record_review("wr", correct=True,
                                       reviewer="op1")
    for _ in range(6):
        eng3.mode_ledger.record_warning_ack("wr", operator="op1")
    quorum_cfg = {"eligible_principals": ("op1", "op2"),
                  "min_approvals": 2, "deny_veto": True}
    ok, reasons = eng3.mode_ledger.evaluate_graduation(
        "wr", "deny",
        approvers=["agent:mallory", "op1"], quorum_cfg=quorum_cfg)
    if ok:
        return "BREAK", "agent principal passed an eligible-set quorum"
    if not any("eligible" in r for r in reasons):
        return "BREAK", "refused but not on eligibility: %r" % (reasons,)
    # (c2) reviews require an attested (non-empty) reviewer: anonymous
    # reviews are refused loudly, never silently counted.
    try:
        eng.mode_ledger.record_review("warn-rule", correct=True,
                                      reviewer="   ")
        return "BREAK", "anonymous review counted toward FP stats"
    except ml.ModeLedgerError:
        pass
    # (d) emergency demotion: allowed for one operator, but mandates
    # post-hoc review within 24h.
    rec = eng.emergency_demote("warn-rule", "warn", operator="op1",
                               reason="blocking prod NOW")
    if eng.mode_ledger.stats("warn-rule")["mode"] != "warn":
        return "BREAK", "emergency demotion did not apply"
    overdue = eng.mode_ledger.check_emergency_reviews(
        now=rec["deadline"] + 1)
    if len(overdue) != 1:
        return "BREAK", "emergency review deadline not tracked"
    return "HELD", ("unilateral demotion refused; pinned demotion "
                    "refused at any quorum; agent approvers excludable; "
                    "anonymous reviews refused; emergency demotion "
                    "mandates 24h post-hoc review")


def _p4_observe_cannot_weaken():
    if not _HAS_LADDER:
        return "BREAK", "no ladder: gov.mode_ledger absent (R4 unhandled)"
    eng = _ladder_policy()
    # Case 1: only the observe rule matches -> implicit default deny
    # still decides; the observe hit is named but powerless.
    d = eng.decide(_req("write_file"))
    if d.effect != "deny" or d.policy_id is not None:
        return "BREAK", ("observe hit weakened the verdict: %r %r"
                         % (d.effect, d.policy_id))
    observed = [h.rule_id for h in d.diagnostics.observed_hits]
    if observed != ["observe-rule"]:
        return "BREAK", "observe hit not named: %r" % (observed,)
    if d.diagnostics.deciding_rule is not None:
        return "BREAK", "observe hit became the decider"
    # Case 2: an existing deny rule matches the same request as the
    # observe rule -> the existing rule decides, unchanged.
    eng2 = PolicyEngine.from_text(
        "version: 1\npolicies:\n"
        "  - id: legacy-deny\n"
        "    effect: deny\n"
        "    match:\n"
        "      tool: write_file\n"
        "    reason: legacy deny\n"
        "  - id: observe-rule\n"
        "    effect: deny\n"
        "    mode: observe\n"
        "    match:\n"
        "      tool: write_file\n"
        "    reason: observing\n")
    d2 = eng2.decide(_req("write_file"))
    if d2.policy_id != "legacy-deny" or d2.effect != "deny":
        return "BREAK", "legacy deny displaced: %r" % (d2.policy_id,)
    return "HELD", ("observe hits named in observed_hits, zero "
                    "authority: default deny and legacy deny unchanged")


def _p5_happy_path():
    if not _HAS_LADDER:
        return "BREAK", "no ladder: gov.mode_ledger absent (R5 unhandled)"
    eng = PolicyEngine.from_text(
        "version: 1\n" + _QUORUM_BLOCK() +
        "policies:\n"
        "  - id: candidate\n"
        "    effect: deny\n"
        "    mode: observe\n"
        "    match:\n"
        "      tool: http_post\n"
        "    reason: candidate egress rule\n")
    for i in range(100):
        eng.decide(_req("http_post" if i % 10 == 0 else "read_file"))
    st = eng.mode_ledger.stats("candidate")
    if st["evaluated"] < 100 or st["violations"] < 10:
        return "ERROR", "telemetry short: %r" % (st,)
    for _ in range(25):
        eng.mode_ledger.record_review("candidate", correct=True,
                                      reviewer="op1")
    ok, reasons = eng.apply_graduation("candidate", "warn",
                                       approvers=["op1", "op2"])
    if not ok:
        return "BREAK", "observe->warn refused on good evidence: %r" % (
            reasons,)
    if eng.mode_ledger.stats("candidate")["mode"] != "warn":
        return "BREAK", "graduation did not change the mode"
    # Warn phase: decisions admitted, warnings flow, operators ack.
    # §3.4 "longer window": warn->deny needs >=200 evaluated, so the
    # warn phase runs 100 decisions (100 observe + 100 warn).
    for _ in range(100):
        d = eng.decide(_req("http_post"))
        if d.effect != "allow" or d.nominal_effect != "deny":
            return "BREAK", "warn phase misbehaving: %r %r" % (
                d.effect, d.nominal_effect)
    for _ in range(6):
        eng.mode_ledger.record_warning_ack("candidate", operator="op2")
    ok, reasons = eng.apply_graduation("candidate", "deny",
                                       approvers=["op1", "op2"])
    if not ok:
        return "BREAK", "warn->deny refused on good evidence: %r" % (
            reasons,)
    d = eng.decide(_req("http_post"))
    if d.effect != "deny" or d.policy_id != "candidate":
        return "BREAK", "graduated rule does not deny: %r" % (d.effect,)
    hist = eng.mode_ledger.mode_history("candidate")
    if [h["new_mode"] for h in hist] != ["warn", "deny"]:
        return "BREAK", "mode history not chained: %r" % (hist,)
    if any(len(h["approvers"]) < 2 for h in hist):
        return "BREAK", "graduation applied without two approvers"
    # §3.5: every mode-change record carries the FP stats snapshot
    # the quorum acted on.
    for h in hist:
        snap = h.get("stats")
        if not isinstance(snap, dict) or snap.get("evaluated", 0) < 100:
            return "BREAK", "mode-change record missing FP stats: %r" % (
                h,)
    ok_chain, _ = eng.mode_ledger.verify_chain()
    if not ok_chain:
        return "ERROR", "ledger chain failed to verify"
    return "HELD", ("observe->warn->deny on evidence, one rung at a "
                    "time, two approvers per rung, history chained")


def _p6_high_fp_refused():
    if not _HAS_LADDER:
        return "BREAK", "no ladder: gov.mode_ledger absent (R6 unhandled)"
    eng = PolicyEngine.from_text(
        "version: 1\n" + _QUORUM_BLOCK() +
        "policies:\n"
        "  - id: noisy\n"
        "    effect: deny\n"
        "    mode: observe\n"
        "    match:\n"
        "      tool: http_post\n"
        "    reason: noisy candidate\n")
    for i in range(100):
        eng.decide(_req("http_post" if i % 10 == 0 else "read_file"))
    for _ in range(13):
        eng.mode_ledger.record_review("noisy", correct=True,
                                      reviewer="op1")
    for _ in range(7):
        eng.mode_ledger.record_review("noisy", correct=False,
                                      reviewer="op2")
    ok, reasons = eng.evaluate_graduation(
        "noisy", "warn",
        approvers=["op1", "op2", "op3", "op4", "op5"])
    if ok:
        return "BREAK", "35% FP graduated despite 5 approvers (R6)"
    if not any("FP" in r for r in reasons):
        return "BREAK", "refused but not on FP: %r" % (reasons,)
    return "HELD", "35% FP refused despite 5 approvers (numbers gate)"


def _p7_invalid_modes():
    base = ("version: 1\npolicies:\n"
            "  - id: r\n"
            "    effect: deny\n"
            "    match:\n"
            "      tool: read_file\n"
            "    reason: x\n")
    if not _HAS_LADDER:
        # Pristine: even a VALID ladder mode is an unknown field --
        # the capability is absent.
        try:
            PolicyEngine.from_text(base + "    mode: observe\n")
            return "ERROR", "pristine accepted mode: observe?!"
        except ValueError:
            return "BREAK", ("no ladder: 'mode' is an unknown field on "
                             "pristine (R7 unhandled)")
    try:
        PolicyEngine.from_text(base + "    mode: bogus\n")
        return "BREAK", "unknown mode 'bogus' loaded silently"
    except ValueError as e:
        if "unknown mode" not in str(e):
            return "BREAK", "refused for the wrong reason: %s" % (e,)
    try:
        PolicyEngine.from_text(base + "    mode: observe\n"
                               "    pinned: true\n")
        return "BREAK", "pinned+observe loaded silently"
    except ValueError as e:
        if "pinned" not in str(e).lower():
            return "BREAK", "refused for the wrong reason: %s" % (e,)
    try:
        PolicyEngine.from_text(base + "    pinned: yes-please\n")
        return "BREAK", "non-bool pinned loaded silently"
    except ValueError:
        pass
    return "HELD", ("unknown mode / pinned+non-deny / non-bool pinned "
                    "all fail loud at load")


def _p8_byte_identical():
    pol = ("version: 1\npolicies:\n"
           "  - id: r-deny\n"
           "    effect: deny\n"
           "    match:\n"
           "      tool: send_email\n"
           "    reason: no mail\n"
           "  - id: r-allow\n"
           "    effect: allow\n"
           "    match:\n"
           "      tool: read_file\n"
           "    reason: reads ok\n")
    eng = PolicyEngine.from_text(pol)
    golden = [
        ("send_email", ("deny", False, "no mail", "r-deny", None)),
        ("read_file", ("allow", True, "reads ok", "r-allow", None)),
        ("write_file", ("deny", False,
                        "No policy matched; denied by default "
                        "(fail-closed).", None, "default_deny")),
    ]
    for tool, want in golden:
        d = eng.decide(_req(tool))
        got = (d.effect, d.allowed, d.reason, d.policy_id, d.flag)
        if got != want:
            return "BREAK", "verdict drift for %s: %r != %r" % (
                tool, got, want)
        if _HAS_LADDER:
            # The ladder must be invisible in serialization when no
            # rule uses it.
            ser = d.to_dict()
            for key in ("nominal_effect", "mode", "warnings"):
                if key in ser:
                    return "BREAK", "ladder key %r leaked into %s" % (
                        key, tool)
            dser = d.diagnostics.to_dict()
            if "observed_hits" in dser:
                return "BREAK", "observed_hits leaked for %s" % (tool,)
            for h in (dser["forbid_hits"] + dser["approval_hits"]
                      + dser["permit_hits"]):
                if "mode" in h:
                    return "BREAK", "hit mode leaked for %s" % (tool,)
            pd = d.to_policy_decision().to_dict()
            for key in ("nominal_effect", "mode", "warnings"):
                if key in pd:
                    return "BREAK", "ladder key %r leaked into legacy %s" % (
                        key, tool)
    return "HELD", ("mode-absent verdicts byte-identical to the golden "
                    "set; no ladder keys serialized")


def _p9_unattested_quorum_refused():
    if not _HAS_LADDER:
        return "BREAK", "no ladder: gov.mode_ledger absent (R9 unhandled)"
    # A policy WITHOUT approvals.quorum: the engine must refuse every
    # enforcement-changing ladder seam, because "two distinct human
    # approvers" is unattested without the eligible-principals set
    # (§3.4). Self-attested names must never graduate a rule.
    eng = PolicyEngine.from_text(
        "version: 1\npolicies:\n"
        "  - id: candidate\n"
        "    effect: deny\n"
        "    mode: observe\n"
        "    match:\n"
        "      tool: http_post\n"
        "    reason: candidate egress rule\n")
    for i in range(100):
        eng.decide(_req("http_post" if i % 10 == 0 else "read_file"))
    for _ in range(25):
        eng.mode_ledger.record_review("candidate", correct=True,
                                      reviewer="op1")
    ok, reasons = eng.apply_graduation("candidate", "warn",
                                       approvers=["op1", "op2"])
    if ok:
        return "BREAK", "graduation applied with unattested approvers"
    if not any("quorum" in r for r in reasons):
        return "BREAK", "refused but not on quorum: %r" % (reasons,)
    # Demotion approval and emergency demotion are enforcement
    # changes too: same refusal (on a warn-mode rule, where demotion
    # has a rung to go to).
    eng2 = PolicyEngine.from_text(
        "version: 1\npolicies:\n"
        "  - id: wr\n"
        "    effect: deny\n"
        "    mode: warn\n"
        "    match:\n"
        "      tool: delete_file\n"
        "    reason: warn rule\n")
    pid = eng2.propose_demotion("wr", "observe",
                                reason="test", requested_by="op1")
    ok, reasons = eng2.approve_demotion(pid, approvers=["op1", "op2"])
    if ok or not any("quorum" in r for r in reasons):
        return "BREAK", "demotion approved with unattested approvers"
    try:
        eng2.emergency_demote("wr", "observe", operator="op1",
                              reason="test")
        return "BREAK", "emergency demotion with unattested operator"
    except Exception as e:
        if "quorum" not in str(e).lower():
            return "BREAK", "emergency refused for wrong reason: %s" % (e,)
    return "HELD", ("ladder seams fail closed without approvals.quorum: "
                    "no self-attested graduation/demotion")


def _p10_warn_stale_escalates():
    if not _HAS_LADDER:
        return "BREAK", "no ladder: gov.mode_ledger absent (R10 unhandled)"
    # A warn rule past the max dwell must reach the operator audit
    # trail at the executor seam (§3.4), not sit in a query-only
    # method.
    eng = _ladder_policy()
    eng.mode_ledger.register_rule("stale-warn", mode="warn")
    eng.mode_ledger._stats("stale-warn")["warn_since"] = (
        eng.mode_ledger._now() - 31 * 24 * 3600)
    ex, read_log = _executor_for(eng)
    ex._check_ladder_escalations()
    events = [e.get("event") for e in read_log()]
    if "warn_stale" not in events:
        return "BREAK", "stale warn rule never reached the audit trail"
    # Second sweep: no duplicate escalation for the same episode.
    ex._check_ladder_escalations()
    events2 = [e.get("event") for e in read_log()]
    if events2.count("warn_stale") != 1:
        return "BREAK", "stale escalation duplicated: %r" % (events2,)
    return "HELD", "warn-stale chains exactly one audit entry per episode"


def _p11_overdue_review_reescalates():
    if not _HAS_LADDER:
        return "BREAK", "no ladder: gov.mode_ledger absent (R11 unhandled)"
    # An emergency demotion whose 24h post-hoc review deadline passed
    # must re-escalate to the operator audit trail (§3.5).
    eng = _ladder_policy()
    for _ in range(200):
        eng.decide(_req("delete_file"))
    for _ in range(25):
        eng.mode_ledger.record_review("warn-rule", correct=True,
                                      reviewer="op1")
    for _ in range(6):
        eng.mode_ledger.record_warning_ack("warn-rule", operator="op1")
    ok, _ = eng.apply_graduation("warn-rule", "deny",
                                 approvers=["op1", "op2"])
    if not ok:
        return "ERROR", "setup graduation failed"
    eng.emergency_demote("warn-rule", "warn", operator="op1",
                         reason="blocking prod NOW")
    # Fast-forward past the 24h deadline.
    st = eng.mode_ledger._stats("warn-rule")
    st["pending_emergency_review"]["deadline"] = (
        eng.mode_ledger._now() - 1)
    ex, read_log = _executor_for(eng)
    ex._check_ladder_escalations()
    events = [e.get("event") for e in read_log()]
    if "emergency_review_overdue" not in events:
        return "BREAK", "overdue post-hoc review never re-escalated"
    ex._check_ladder_escalations()
    events2 = [e.get("event") for e in read_log()]
    if events2.count("emergency_review_overdue") != 1:
        return "BREAK", "overdue escalation duplicated: %r" % (events2,)
    return "HELD", "overdue emergency review re-escalates exactly once"


def _p12_longer_window():
    if not _HAS_LADDER:
        return "BREAK", "no ladder: gov.mode_ledger absent (R12 unhandled)"
    # §3.4: warn->deny runs a LONGER window than observe->warn. 150
    # evaluated / 15 violations clears the observe bar but not the
    # warn->deny bar (200/20).
    eng = PolicyEngine.from_text(
        "version: 1\n" + _QUORUM_BLOCK() +
        "policies:\n"
        "  - id: wr\n"
        "    effect: deny\n"
        "    mode: warn\n"
        "    match:\n"
        "      tool: delete_file\n"
        "    reason: warn rule\n")
    for i in range(150):
        eng.decide(_req("delete_file" if i % 10 == 0 else "read_file"))
    for _ in range(25):
        eng.mode_ledger.record_review("wr", correct=True,
                                      reviewer="op1")
    for _ in range(6):
        eng.mode_ledger.record_warning_ack("wr", operator="op1")
    ok, reasons = eng.evaluate_graduation("wr", "deny",
                                          approvers=["op1", "op2"])
    if ok:
        return "BREAK", "warn->deny graduated on the short window"
    if not any("longer window" in r for r in reasons):
        return "BREAK", "refused but not on the longer window: %r" % (
            reasons,)
    return "HELD", "warn->deny refused below the longer-window minimums"


_PROBES = [
    ("P0", _p0_fresh_deny_blocks),
    ("P1", _p1_warn_fatigue),
    ("P2", _p2_dryrun_blindness),
    ("P3", _p3_demotion_abuse),
    ("P4", _p4_observe_cannot_weaken),
    ("P5", _p5_happy_path),
    ("P6", _p6_high_fp_refused),
    ("P7", _p7_invalid_modes),
    ("P8", _p8_byte_identical),
    ("P9", _p9_unattested_quorum_refused),
    ("P10", _p10_warn_stale_escalates),
    ("P11", _p11_overdue_review_reescalates),
    ("P12", _p12_longer_window),
]


def _run_once():
    out = []
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # harness error, never a probe pass
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        out.append((name, verdict, detail))
    return out


def main():
    # Wave-316 lane-3 correction: this battery records no "FP" verdict
    # (its probes return BREAK/HELD/ERROR only; "FP" appears solely in
    # prose about false-positive *rates*). Verdicts are already
    # canonical -- the migration is the print loop only.
    first = _run_once()
    second = _run_once()
    results = []
    for (name, v1, d1), (_n2, v2, _d2) in zip(first, second):
        if v1 != v2:
            v1, d1 = "ERROR", \
                "%s nondeterministic: %r then %r" % (name, v1, v2)
        results.append((name, v1, d1))
    probe_lines.emit(results)
    breaks = sum(1 for _, v, _ in results if v == "BREAK")
    held = sum(1 for _, v, _ in results if v == "HELD")
    errors = sum(1 for _, v, _ in results if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        results, breaks, held, errors)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    print("breaks=%d held=%d errors=%d" % (breaks, held, errors))
    if breaks:
        print("BREAK: %s" % ", ".join(n for n, v, _ in first
                                      if v == "BREAK"))
    green_ok = _green_check()
    if errors or not green_ok:
        return 1
    return 0


def _green_check():
    """Depth-1 green check: the adjacent unit suite only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip; skips
    gracefully on trees where the wave-198 suite does not exist."""
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    if importlib.util.find_spec("tests.test_graduation_ladder") is None:
        print("GREEN CHECK: skipped (tests.test_graduation_ladder absent "
              "on this tree)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_graduation_ladder"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
    print("GREEN CHECK unit suite: rc=%d %s"
          % (r.returncode, " | ".join(tail)))
    return r.returncode == 0


if __name__ == "__main__":
    sys.exit(main())
