"""F442 closure: the policy-delta risk gate now models ladder mode changes
(wave-347 lane 6).

F442 (LOW, OPEN): gov/policy_delta_gate.analyze_policy_delta did not
model per-rule ladder `mode` changes -- a deny rule flipped to
`mode: observe` genuinely weakens enforcement (the observe-mode deny
carries no authority: the secret read goes deny -> allow) but the
delta analysis reported verdict "pass" with zero findings.

Closure: _analyze_rules models the observe < warn < deny ladder via
_MODE_AUTHORITY (gov/mode_ledger.LADDER_MODES). A rule moved DOWN the
ladder on a deny/require_approval rule emits the new centrally-
registered decision code `policy-delta-mode-weakened`:

  P1  RED: the F442 red-first script now prints HELD (was BREAK on base).
  P2  deny -> warn on a deny rule: high severity, verdict refuse (the
      enforced verdict flips deny -> allow -- verified against the
      real PolicyEngine).
  P3  warn -> observe on a deny rule: medium severity, verdict pass
      (enforced verdict was already allow; only operator warnings are
      lost -- flagged, not refused).
  P4  require_approval -> observe: high, verdict refuse (human check
      evaporates).
  P5  discrimination: allow-rule mode changes carry no finding;
      tightening moves (observe -> warn, observe -> deny, warn -> deny)
      carry no finding.
  P6  fail-closed: an unknown ladder mode raises PolicyDeltaError
      (policy-delta-malformed), never a vacuous pass.
  P7  combined effect + mode weakening fires both
      policy-delta-effect-weakened and policy-delta-mode-weakened.
  P8  engine ground truth: the deny -> observe flip flips the real
      PolicyEngine verdict deny -> allow (the genuine-weakening leg of
      the red-first), and warn likewise.
  P9  determinism: same delta twice -> byte-identical report + digest.
  P10 pin 2143, raw-literal taxonomy uniqueness, central registration  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
      of policy-delta-mode-weakened, footer open F437-F441 / next F442.

$0 spend. No network. Scratch files live under /var/tmp only.
"""

import os

# Wave-95 lesson: deployment mode must be set at module level so the
# battery runs standalone under `env -u GOV_DEPLOYMENT_MODE`.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json
import re
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import policy_delta_gate as _pdg  # noqa: E402
from gov import decision_codes as _dc  # noqa: E402
from gov.policy_delta_gate import PolicyDeltaError  # noqa: E402

VENV_PYTHON = os.path.expanduser("~/workspace/.gov-venv/bin/python")
FOOTER_OPEN = "F700, F701, F702, F703, F704, F705, F706, F707, F708, F709, F710, F711, F712"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-352 merge (3/5): F454-F457 CLOSED; F458-F460 OPEN (next F461)  # wave-350 lane 3: F449+F450 CLOSED; wave-347 lane 6: F442 closed; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444) Wave-348: F443 closed (open none).; wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 lane 1: F444 CLOSED (open F445); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # wave-352 lane 3: F457 CLOSED locally (merge finalizes tree-wide)  # wave-350 lane 3: F449+F450 CLOSED; wave-347 lane 6: F442 closed; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444) Wave-348: F443 closed (open none).; wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 lane 1: F444 CLOSED (open F445); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461); wave-352 lane 1: F454+F455 CLOSED locally  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)


FOOTER_NEXT = "F713"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)


TAXONOMY_PIN = 2143  # Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
EXPECTED_PIN_MSG = "2143/2143/0 sorted"  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return bool(cond)


BASE_POLICY = open(os.path.join(REPO_ROOT, "policies", "default.yaml")).read()


def _set_mode(text, rule_id, old_effect, new_mode):
    pat = re.compile(r"(  - id: %s\n(?:.*\n)*?    effect: %s\n)"
                     % (re.escape(rule_id), old_effect))
    out, n = pat.subn(lambda m: m.group(1) + "    mode: %s\n" % new_mode,
                      text, count=1)
    assert n == 1, "rule block not found: %s" % rule_id
    return out


def _set_effect(text, rule_id, old_effect, new_effect):
    pat = re.compile(r"(  - id: %s\n(?:.*\n)*?    effect: )%s\n"
                     % (re.escape(rule_id), old_effect))
    out, n = pat.subn(lambda m: m.group(1) + new_effect + "\n",
                      text, count=1)
    assert n == 1, "rule block not found: %s" % rule_id
    return out


def _mode_findings(report):
    return [f for f in report["risk_findings"]
            if f["risk_class"] == "policy-delta-mode-weakened"]


# -------------------------------------------------------------------------- P1
def p1_red_first_held():
    """RED: the F442 red-first script BREAKs on the open tree and must
    now print HELD on the closed tree."""
    tmp = tempfile.mkdtemp(prefix="g347-f442-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    env["TMPDIR"] = tmp
    r = subprocess.run(
        [VENV_PYTHON, os.path.join(REPO_ROOT, "evals",
                                   "w346_f442_redfirst.py")],
        capture_output=True, text=True, env=env, timeout=600,
        cwd=REPO_ROOT)
    ok = (r.returncode == 0 and "F442 HELD" in r.stdout)
    return _check("p1 RED: red-first now HELD", ok,
                  "rc=%d out=%s" % (r.returncode,
                                     (r.stdout + r.stderr)[-160:].strip()))


# -------------------------------------------------------------------------- P2
def p2_deny_to_warn_refused():
    """deny -> warn on a deny rule: high severity, verdict refuse."""
    new = _set_mode(BASE_POLICY, "deny-secret-reads", "deny", "warn")
    report = _pdg.analyze_policy_delta(BASE_POLICY, new)
    mf = _mode_findings(report)
    ok = (report["verdict"] == "refuse"
          and len(mf) == 1
          and mf[0]["severity"] == "high"
          and mf[0]["rule_id"] == "deny-secret-reads"
          and mf[0]["before"] == "deny" and mf[0]["after"] == "warn")
    return _check("p2: deny->warn high/refuse", ok,
                  "verdict=%s findings=%d" % (report["verdict"], len(mf)))


# -------------------------------------------------------------------------- P3
def p3_warn_to_observe_flagged():
    """warn -> observe on a deny rule: medium flag, verdict pass (the
    enforced verdict was already allow; only operator warnings lost)."""
    warn = _set_mode(BASE_POLICY, "deny-secret-reads", "deny", "warn")
    new = _set_mode(BASE_POLICY, "deny-secret-reads", "deny", "observe")
    report = _pdg.analyze_policy_delta(warn, new)
    mf = _mode_findings(report)
    ok = (report["verdict"] == "pass"
          and len(mf) == 1
          and mf[0]["severity"] == "medium"
          and mf[0]["before"] == "warn" and mf[0]["after"] == "observe")
    return _check("p3: warn->observe medium/flag", ok,
                  "verdict=%s findings=%d" % (report["verdict"], len(mf)))


# -------------------------------------------------------------------------- P4
def p4_require_approval_weakened():
    """require_approval -> observe: high, verdict refuse (human check
    evaporates)."""
    parsed = json.loads(__import__(
        "gov.policy_change", fromlist=["canonical_policy_bytes"])
        .canonical_policy_bytes(BASE_POLICY).decode("utf-8"))
    ra = [r["id"] for r in parsed["policies"]
          if r["effect"] == "require_approval"][0]
    new = _set_mode(BASE_POLICY, ra, "require_approval", "observe")
    report = _pdg.analyze_policy_delta(BASE_POLICY, new)
    mf = _mode_findings(report)
    ok = (report["verdict"] == "refuse"
          and len(mf) == 1 and mf[0]["severity"] == "high"
          and mf[0]["rule_id"] == ra)
    return _check("p4: require_approval->observe high/refuse", ok,
                  "rule=%s" % ra)


# -------------------------------------------------------------------------- P5
def p5_discrimination():
    """Allow-rule mode changes and tightening moves carry no finding."""
    parsed = json.loads(__import__(
        "gov.policy_change", fromlist=["canonical_policy_bytes"])
        .canonical_policy_bytes(BASE_POLICY).decode("utf-8"))
    allow = [r["id"] for r in parsed["policies"]
             if r["effect"] == "allow"][0]
    ok = True
    # allow rule down the ladder: enforced verdict unchanged.
    r = _pdg.analyze_policy_delta(
        BASE_POLICY, _set_mode(BASE_POLICY, allow, "allow", "observe"))
    ok = ok and not _mode_findings(r)
    # tightening moves: no finding.
    obs = _set_mode(BASE_POLICY, "deny-secret-reads", "deny", "observe")
    warn = _set_mode(BASE_POLICY, "deny-secret-reads", "deny", "warn")
    for old_t, new_t, label in ((obs, warn, "observe->warn"),
                                (obs, BASE_POLICY, "observe->deny"),
                                (warn, BASE_POLICY, "warn->deny")):
        r = _pdg.analyze_policy_delta(old_t, new_t)
        ok = ok and not _mode_findings(r) and r["verdict"] == "pass"
    return _check("p5: allow-mode/tightening quiet", ok)


# -------------------------------------------------------------------------- P6
def p6_unknown_mode_fail_closed():
    """An unknown ladder mode fails closed (malformed), never a vacuous
    pass."""
    try:
        _pdg.analyze_policy_delta(
            BASE_POLICY,
            _set_mode(BASE_POLICY, "deny-secret-reads", "deny", "bogus"))
    except PolicyDeltaError as e:
        ok = (e.code == "policy-delta-malformed")
        return _check("p6: unknown mode malformed", ok, e.code)
    return _check("p6: unknown mode malformed", False, "no error raised")


# -------------------------------------------------------------------------- P7
def p7_effect_plus_mode_both_fire():
    """A combined effect + mode weakening fires both codes."""
    new = _set_effect(BASE_POLICY, "deny-secret-reads", "deny", "allow")
    new = _set_mode(new, "deny-secret-reads", "allow", "observe")
    report = _pdg.analyze_policy_delta(BASE_POLICY, new)
    classes = {f["risk_class"] for f in report["risk_findings"]}
    ok = ({"policy-delta-effect-weakened",
           "policy-delta-mode-weakened"} <= classes
          and report["verdict"] == "refuse")
    return _check("p7: effect+mode both fire", ok, sorted(classes))


# -------------------------------------------------------------------------- P8
def p8_engine_ground_truth():
    """The flips the gate refuses genuinely weaken the real engine."""
    from gov.policy import PolicyEngine  # noqa: E402
    probe = {"tool": "read_file", "role": "researcher",
             "args": {"path": "config/.env"}}
    before = PolicyEngine(
        os.path.join(REPO_ROOT, "policies", "default.yaml")).evaluate(probe)
    ok = before.effect == "deny"
    for mode in ("observe", "warn"):
        tmp = tempfile.mkdtemp(prefix="g347-f442-eng-", dir="/var/tmp")
        p = os.path.join(tmp, "weak.yaml")
        open(p, "w").write(
            _set_mode(BASE_POLICY, "deny-secret-reads", "deny", mode))
        after = PolicyEngine(p).evaluate(probe)
        ok = ok and after.effect == "allow"
    return _check("p8: engine deny->allow on both rungs", ok)


# -------------------------------------------------------------------------- P9
def p9_determinism():
    """Same delta twice -> byte-identical report and digest."""
    new = _set_mode(BASE_POLICY, "deny-secret-reads", "deny", "observe")
    r1 = _pdg.analyze_policy_delta(BASE_POLICY, new)
    r2 = _pdg.analyze_policy_delta(BASE_POLICY, new)
    ok = (r1 == r2 and r1["delta_digest"] == r2["delta_digest"])
    return _check("p9: deterministic reports", ok,
                  r1["delta_digest"][:16])


# -------------------------------------------------------------------------- P10
def p10_pin_footer_registration():
    """Pin 2143, raw-literal taxonomy uniqueness, central registration  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    of the new code, footer open F437-F441 / next F442."""
    codes = sorted(_dc.TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    ok = ok and ("policy-delta-mode-weakened" in _dc.TAXONOMY)
    entry = _dc.TAXONOMY["policy-delta-mode-weakened"]
    ok = (ok and entry["code"] == "policy-delta-mode-weakened"
          and entry["domain"] == "policy-delta")
    cov = json.load(open(os.path.join(
        REPO_ROOT, "docs", "decision-code-coverage.json")))
    ok = ok and cov.get("pin") == TAXONOMY_PIN == len(codes)
    src = open(os.path.join(REPO_ROOT, "gov", "decision_codes.py")).read()
    lits = re.findall(r"""['"]code['"]\s*:\s*['"]([^'"]+)['"]""", src)
    ok = ok and len(lits) == len(set(lits)) == TAXONOMY_PIN
    footer = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    return _check("p10: pin 2143, footer F437-F441/next F442", ok,  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
                  footer[-60:])


# --------------------------------------------------------------- green check
def _green_check():
    """Depth-1 green check: the delta-gate battery (the analyzer this
    closure builds on) must stay green."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    notes = []
    for script in ("w246_policy_delta_probes.py",):
        # Fresh unique TMPDIR per gate run (wave-173 lesson).
        tmp = "/var/tmp/g347-green-%s-%d-%d" % (
            script.replace(".py", ""), os.getpid(),
            int(__import__("time").time() * 1000) % 100000)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [VENV_PYTHON, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        tail = (r.stdout + r.stderr)[-200:].strip().replace("\n", " | ")
        notes.append("%s rc=%d %s" % (script, r.returncode, tail))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = __import__("argparse").ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    results = []
    for fn in (p1_red_first_held,
               p2_deny_to_warn_refused,
               p3_warn_to_observe_flagged,
               p4_require_approval_weakened,
               p5_discrimination,
               p6_unknown_mode_fail_closed,
               p7_effect_plus_mode_both_fire,
               p8_engine_ground_truth,
               p9_determinism,
               p10_pin_footer_registration):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-46s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("w347_f442close: %d HELD / %d BREAK / %d ERROR"
          % (n_held, n_break, n_err))
    sys.exit(0 if (n_break == 0 and n_err == 0) else 1)


if __name__ == "__main__":
    main()
