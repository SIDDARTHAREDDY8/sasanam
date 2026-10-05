#!/usr/bin/env python3
"""Wave-343 lane 5: per-policy observe->enforce rollout lifecycle (Kontext steal #2).

Steal verdict (deepdive-kontext/STEAL-BRIEF.md): every policy starts in
Observing mode with would-block counters, then flips to Enforced.
Adapted for Sasanam with our fail-closed guarantee intact:

  * Observe mode is an explicit, declared, auditable deployment choice
    per policy -- never a silent fail-open (Kontext's documented
    fail-open-on-policy-errors is DROPPED, not copied).
  * Every decision record in observe mode declares policy_mode="observe".
  * Flips (observe->enforce and back) require an attested human quorum
    (mirrors wave-198: refuses without a configured approvals.quorum).
  * Pinned rules (deny-only, e.g. credential-exfil forbids) refuse
    per-policy observe -- the ladder's pinned invariant is not weakened.
  * Would-block counters are chained into the observation ledger and
    ride the flip record, so the quorum acts on evidence.

$0 SPEND BY CONSTRUCTION: canned policies/requests only, no model calls.
Do NOT add ModelDriver/SpendLedger usage here.

Probes:
  P1  observe declares itself: decision to_dict carries policy_mode
      "observe"; effect allow; nominal_effect deny; would_deny=1.
  P2  no enforcement in observe: a deny-matching request is allowed in
      observe, denied in enforce.
  P3  flip needs attested human quorum: 1 approver refused; no
      approvals.quorum configured refused; 2 eligible approvers ok.
  P4  pinned rules refuse observe: policy with a pinned deny rule
      cannot deploy in observe.
  P5  would-block counters: mixed traffic accumulates would_deny /
      would_require_approval / would_allow; the enforce flip record
      carries the final snapshot.
  P6  tamper evidence: mutating an observation record breaks
      verify_chain().
  P7  evaluation errors propagate in observe mode: a raising engine
      does not become a silent allow (anti fail-open).
  P8  evaluate() path stamps policy_mode too; enforce-mode decisions
      are byte-identical (no policy_mode key in to_dict).
  P9  pin + footer: taxonomy 2131, footer open F429 / next F430.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w343_observe_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2134  # Wave-342 merge: pin 2131 (no new codes in wave-343 lane 5); Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)
FOOTER_OPEN = "F430, F431"
FOOTER_NEXT = "F432"

from gov import policy_observe  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402
from gov.decision_contract import Request  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

_POLICY = """\
version: 2
roles:
  analyst: [read_file, send_email]
approvals:
  quorum:
    min_approvals: 2
    eligible_principals: [alice, bob, carol]
policies:
  - id: forbid-secret-reads
    effect: deny
    match:
      tool: [read_file]
      path_contains_any: [secret]
    reason: secret reads are forbidden.
  - id: approval-external-mail
    effect: require_approval
    match:
      tool: [send_email]
    reason: external mail needs a human.
  - id: permit-reads
    effect: allow
    match:
      tool: [read_file]
    reason: ordinary reads permitted.
"""

_POLICY_NO_QUORUM = """\
version: 2
roles:
  analyst: [read_file]
policies:
  - id: forbid-secret-reads
    effect: deny
    match:
      tool: [read_file]
      path_contains_any: [secret]
    reason: secret reads are forbidden.
"""

_POLICY_PINNED = """\
version: 2
roles:
  analyst: [read_file]
approvals:
  quorum:
    min_approvals: 2
    eligible_principals: [alice, bob]
policies:
  - id: forbid-exfil
    effect: deny
    mode: deny
    pinned: true
    match:
      tool: [read_file]
      path_contains_any: [secret]
    reason: pinned forbid.
"""


def _engine(text=_POLICY):
    return PolicyEngine.from_text(text, source_label="<observe probe>")


def _req(tool, **args):
    return Request.from_action({"tool": tool, "args": args,
                               "agent_id": "probe-agent"},
                              {"role": "analyst"})


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return cond


# ------------------------------------------------- P1: observe declares itself
def p1_observe_declares_mode():
    dep = policy_observe.PolicyObserveDeployment(_engine())
    ok, _ = dep.deploy_observe(approvers=["alice", "bob"])
    assert ok, "deploy_observe should succeed with quorum"
    dec = dep.decide(_req("read_file", path="/data/secret/keys.txt"))
    d = dec.to_dict()
    ok = True
    ok = _check("P1a effect allow in observe", dec.effect == "allow",
                "effect=%s" % dec.effect) and ok
    ok = _check("P1b nominal_effect deny preserved",
                dec.nominal_effect == "deny",
                "nominal=%s" % dec.nominal_effect) and ok
    ok = _check("P1c to_dict declares policy_mode observe",
                d.get("policy_mode") == "observe",
                "keys=%s" % sorted(d)) and ok
    st = dep.stats()
    ok = _check("P1d would_deny counter = 1",
                st["would_deny"] == 1 and st["evaluated"] == 1,
                "stats=%s" % st) and ok
    return ok


# -------------------------------------------- P2: no enforcement in observe
def p2_no_enforcement_in_observe():
    dep = policy_observe.PolicyObserveDeployment(_engine())
    req = _req("read_file", path="/data/secret/keys.txt")
    enforced = dep.decide(req)
    ok = _check("P2a enforce mode denies",
                enforced.effect == "deny" and not enforced.allowed,
                "effect=%s" % enforced.effect)
    ok2, _ = dep.deploy_observe(approvers=["alice", "bob"])
    assert ok2
    observed = dep.decide(req)
    ok = _check("P2b observe mode allows (no enforcement)",
                observed.effect == "allow" and observed.allowed,
                "effect=%s" % observed.effect) and ok
    ok2, _ = dep.enforce(approvers=["alice", "carol"])
    assert ok2
    back = dep.decide(req)
    ok = _check("P2c flip back to enforce denies again",
                back.effect == "deny",
                "effect=%s" % back.effect) and ok
    return ok


# --------------------------------------- P3: flip needs attested human quorum
def p3_flip_needs_quorum():
    dep = policy_observe.PolicyObserveDeployment(_engine())
    ok1, reasons = dep.deploy_observe(approvers=["alice"])
    ok = _check("P3a single approver refused", not ok1,
                "; ".join(reasons))
    ok2, reasons = dep.deploy_observe(approvers=["mallory", "trudy"])
    ok = _check("P3b ineligible approvers refused", not ok2,
                "; ".join(reasons)) and ok
    ok3, reasons = dep.deploy_observe(approvers=["alice", ("bob", False)])
    ok = _check("P3c dissent vetoes", not ok3,
                "; ".join(reasons)) and ok
    dep2 = policy_observe.PolicyObserveDeployment(_engine(_POLICY_NO_QUORUM))
    ok4, reasons = dep2.deploy_observe(approvers=["alice", "bob"])
    ok = _check("P3d no approvals.quorum configured refuses", not ok4,
                "; ".join(reasons)) and ok
    ok5, _ = dep.deploy_observe(approvers=["alice", "bob"])
    ok = _check("P3e eligible quorum succeeds", ok5
                and dep.policy_mode == "observe") and ok
    return ok


# -------------------------------------------- P4: pinned rules refuse observe
def p4_pinned_rules_refuse_observe():
    dep = policy_observe.PolicyObserveDeployment(_engine(_POLICY_PINNED))
    ok1, reasons = dep.deploy_observe(approvers=["alice", "bob"])
    ok = _check("P4a pinned rule blocks observe deployment", not ok1
                and dep.policy_mode == "enforce",
                "; ".join(reasons))
    return ok


# --------------------------------------------- P5: would-block counters ride
def p5_would_block_counters():
    dep = policy_observe.PolicyObserveDeployment(_engine())
    ok, _ = dep.deploy_observe(approvers=["alice", "bob"])
    assert ok
    dep.decide(_req("read_file", path="/data/secret/a.txt"))   # would deny
    dep.decide(_req("read_file", path="/data/secret/b.txt"))   # would deny
    dep.decide(_req("send_email", to="x@y.z"))                 # would approval
    dep.decide(_req("read_file", path="/data/public/c.txt"))   # would allow
    st = dep.stats()
    ok = _check("P5a counters accumulate",
                st["evaluated"] == 4 and st["would_deny"] == 2
                and st["would_require_approval"] == 1
                and st["would_allow"] == 1,
                "stats=%s" % st)
    ok2, reasons = dep.enforce(approvers=["alice", "bob"])
    assert ok2, reasons
    recs = [r for r in dep.records() if r["kind"] == "mode_change"
            and r["new_mode"] == "enforce"]
    snap = recs[-1]["counters"] if recs else {}
    ok = _check("P5b flip record carries counter snapshot",
                snap.get("would_deny") == 2
                and snap.get("would_require_approval") == 1
                and snap.get("evaluated") == 4,
                "snapshot=%s" % snap) and ok
    return ok


# ---------------------------------------------------- P6: tamper evidence
def p6_tamper_evidence():
    dep = policy_observe.PolicyObserveDeployment(_engine())
    ok, _ = dep.deploy_observe(approvers=["alice", "bob"])
    assert ok
    dep.decide(_req("read_file", path="/data/secret/a.txt"))
    okc, reason = dep.verify_chain()
    ok = _check("P6a chain verifies clean", okc, reason)
    dep._chain[1]["nominal_effect"] = "allow"  # tamper with a record
    okc2, reason2 = dep.verify_chain()
    ok = _check("P6b tampered chain fails", not okc2, reason2) and ok
    return ok


# --------------------------------- P7: eval errors propagate (anti fail-open)
def p7_eval_errors_propagate():
    dep = policy_observe.PolicyObserveDeployment(_engine())
    ok, _ = dep.deploy_observe(approvers=["alice", "bob"])
    assert ok
    try:
        dep.decide("not-a-request")
    except TypeError:
        raised = True
    except Exception as e:  # noqa: BLE001
        raised = False
        print("P7 unexpected exception type: %r" % e)
    else:
        raised = False
    ok = _check("P7a engine error propagates in observe (no silent allow)",
                raised)
    st = dep.stats()
    ok = _check("P7b failed evaluation not counted",
                st["evaluated"] == 0, "stats=%s" % st) and ok
    return ok


# ------------------------------- P8: evaluate path + enforce byte-identical
def p8_evaluate_path_and_enforce_shape():
    dep = policy_observe.PolicyObserveDeployment(_engine())
    d0 = dep.decide(_req("read_file", path="/data/public/c.txt")).to_dict()
    ok = _check("P8a enforce-mode to_dict has no policy_mode key",
                "policy_mode" not in d0, "keys=%s" % sorted(d0))
    ok2, _ = dep.deploy_observe(approvers=["alice", "bob"])
    assert ok2
    pd = dep.evaluate({"tool": "read_file",
                       "args": {"path": "/data/secret/a.txt"},
                       "agent_id": "probe-agent"}, {"role": "analyst"})
    d = pd.to_dict()
    ok = _check("P8b evaluate() stamps policy_mode observe",
                d.get("policy_mode") == "observe"
                and pd.effect == "allow"
                and pd.nominal_effect == "deny",
                "effect=%s nominal=%s" % (pd.effect, pd.nominal_effect)) and ok
    ok = _check("P8c evaluate() stamps policy revision",
                pd.policy_rev_id is not None
                and pd.policy_digest is not None) and ok
    return ok


# ---------------------------------------------------------- P9: pin + footer
def p9_pin_and_footer():
    ok = _check("P9a pin-taxonomy-2134",
                len(TAXONOMY) == TAXONOMY_PIN
                and len(set(TAXONOMY)) == TAXONOMY_PIN,
                "%d/%d" % (len(TAXONOMY), len(set(TAXONOMY))))
    last = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
                ).read().splitlines()[-1]
    ok = _check("P9b footer open F429/next F430",
                ("Next free finding: **%s**." % FOOTER_NEXT) in last
                and ("Open findings: %s." % FOOTER_OPEN) in last,
                last[:60]) and ok
    return ok


def _green_check():
    """Depth-1 green check: adjacent mode-ladder + contract batteries."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("graduation_ladder_probes.py",
                   "cedar_contract_probes.py",
                   "decision_diagnostics_probes.py"):
        path = os.path.join(REPO_ROOT, "evals", script)
        if not os.path.exists(path):
            notes.append("%s absent (skipped)" % script)
            continue
        tmp = "/var/tmp/g343-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, path],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        tail = (r.stdout + r.stderr)[-200:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = []
    for fn in (p1_observe_declares_mode, p2_no_enforcement_in_observe,
               p3_flip_needs_quorum, p4_pinned_rules_refuse_observe,
               p5_would_block_counters, p6_tamper_evidence,
               p7_eval_errors_propagate, p8_evaluate_path_and_enforce_shape,
               p9_pin_and_footer):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-46s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
