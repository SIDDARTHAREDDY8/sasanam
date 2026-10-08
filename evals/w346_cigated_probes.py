"""CI-gated policy testing: gate analyzer, selection, and red-first
gate semantics (wave-346 lane 3).

STEAL (mechanism only) from Archestra's CI-gated policy testing
(describe --check / replay as required CI): a policy change must pass
the evidence tests that pin its affected decision signals BEFORE it
lands. gov/policy_gate.py does the static half (impact analysis +
battery selection); scripts/policy_ci_gate.py does the running half
(executes the selected batteries, fails closed).

  P1  analyzer: effect-weakening flip is detected (modified rule, flag,
      delta-gate policy-delta-effect-weakened).
  P2  analyzer: rule removal is detected (removed rule, flag, delta
      verdict refuse / policy-delta-forbid-removed).
  P3  analyzer: malformed policy text fails closed (PolicyGateError,
      never a vacuous pass).
  P4  selection: deny-secret-reads removal selects the batteries that
      pin its flag/rule id (adaptive_adversary.py among them); nothing
      unpinned.
  P5  RED (spec-mandated): the gate FAILs on an intentionally
      weakened policy -- one deny rule flipped to observe-only in a
      scratch tree (the observe-mode deny carries no authority, so the
      secret read is allowed and the pinning battery breaks).
  P6  control: the gate PASSes on the unweakened policy (battery held).
  P7  discrimination: a weakening that defense-in-depth still catches
      (effect deny->allow, approval rule backs it) does NOT fail the
      gate -- no false positives.
  P10 RED (second mechanism): removing a forbid rule outright also
      fails the gate (delta: policy-delta-forbid-removed).
  P8  observe-lifecycle + pin-registry impact units.
  P9  pin 2143, footer open F437-F441 / next F442 (no new decision  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
      codes -- F437 is filed, not closed).

$0 spend. No network. Scratch files live under /var/tmp only.
"""

import os

# Wave-95 lesson: deployment mode must be set at module level so the
# battery runs standalone under `env -u GOV_DEPLOYMENT_MODE`.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import importlib.util
import re
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import policy_gate as _pg  # noqa: E402
from gov.policy_gate import PolicyGateError  # noqa: E402

VENV_PYTHON = os.path.expanduser("~/workspace/.gov-venv/bin/python")
FOOTER_OPEN = "F713, F714, F715, F716, F717, F718, F719, F720, F721, F722, F723, F724, F725, F726, F727, F728, F729, F730, F731, F732, F733, F734, F735, F736, F737"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # wave-346 merge final; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)


FOOTER_NEXT = "F738"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)


TAXONOMY_PIN = 2143  #Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)


def _load_gate_script():
    path = os.path.join(REPO_ROOT, "scripts", "policy_ci_gate.py")
    spec = importlib.util.spec_from_file_location("policy_ci_gate", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_GATE = _load_gate_script()

BASE_POLICY = open(os.path.join(REPO_ROOT, "policies", "default.yaml")).read()


def _remove_rule(text, rule_id):
    pat = re.compile(r"  - id: %s\n(?:    .*\n|\n)*?(?=  - id: |\Z)"
                     % re.escape(rule_id))
    out, n = pat.subn("", text, count=1)
    assert n == 1, "rule block not found: %s" % rule_id
    assert rule_id not in out
    return out


def _flip_effect(text, rule_id, new_effect="allow"):
    pat = re.compile(r"(  - id: %s\n(?:.*\n)*?    effect: )deny\n"
                     % re.escape(rule_id))
    out, n = pat.subn(lambda m: m.group(1) + new_effect + "\n",
                      text, count=1)
    assert n == 1, "rule effect not found: %s" % rule_id
    return out


def _flip_mode_observe(text, rule_id):
    """The spec's mandated weakening: a deny rule flipped to
    observe-only (ladder `mode: observe`). Empirically verified: the
    observe-mode deny carries no authority, so the secret read is
    allowed (F437 notes the delta gate does not model this)."""
    pat = re.compile(r"(  - id: %s\n(?:.*\n)*?    effect: deny\n)"
                     % re.escape(rule_id))
    out, n = pat.subn(lambda m: m.group(1) + "    mode: observe\n",
                      text, count=1)
    assert n == 1, "rule not found: %s" % rule_id
    return out


def _scratch(text, name):
    # Explicit /var/tmp dir: tempfile's default honors $TMPDIR and falls
    # back to /tmp, the stale-shared-dir surface the wave-112/173
    # lessons guard against.
    d = tempfile.mkdtemp(prefix="g346-gate-", dir="/var/tmp")
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(text)
    return p


def _check(name, cond, detail=""):
    print("%-46s %s %s" % (name, "HELD" if cond else "BREAK", detail))
    return bool(cond)


# --------------------------------------------------------------------------
# P1-P3: analyzer units
# --------------------------------------------------------------------------

def p1_effect_flip_detected():
    new = _flip_effect(BASE_POLICY, "deny-egress-unallowlisted")
    imp = _pg.policy_yaml_impact(BASE_POLICY, new)
    classes = [f["risk_class"] for f in imp["delta_findings"]]
    ok = (imp["modified"] == ["deny-egress-unallowlisted"]
          and "egress_violation" in imp["flags"]
          and "policy-delta-effect-weakened" in classes)
    return _check("p1: effect flip detected + delta-flagged", ok,
                  "modified=%s flags=%s" % (imp["modified"], imp["flags"]))


def p2_rule_removal_detected():
    new = _remove_rule(BASE_POLICY, "deny-secret-reads")
    imp = _pg.policy_yaml_impact(BASE_POLICY, new)
    classes = [f["risk_class"] for f in imp["delta_findings"]]
    ok = (imp["removed"] == ["deny-secret-reads"]
          and "secret_access_attempt" in imp["flags"]
          and imp["delta_verdict"] == "refuse"
          and "policy-delta-forbid-removed" in classes)
    return _check("p2: rule removal detected, delta refuses", ok,
                  "removed=%s verdict=%s" % (imp["removed"],
                                             imp["delta_verdict"]))


def p3_malformed_fails_closed():
    try:
        _pg.policy_yaml_impact("[1, 2, 3]", BASE_POLICY)
    except PolicyGateError:
        return _check("p3: malformed policy fails closed", True)
    return _check("p3: malformed policy fails closed", False,
                  "no exception raised")


# --------------------------------------------------------------------------
# P4: selection
# --------------------------------------------------------------------------

def p4_selection_picks_pinning_batteries():
    new = _remove_rule(BASE_POLICY, "deny-secret-reads")
    imp = _pg.policy_yaml_impact(BASE_POLICY, new)
    idx = _pg.build_battery_index(REPO_ROOT)
    sel = _pg.select_batteries([imp], idx)
    # The affected decision code (policy-delta-forbid-removed) is
    # enumerated and its pinning batteries selected alongside the
    # flag/rule-id pinners.
    ok = ("adaptive_adversary.py" in sel["batteries"]
          and "policy-delta-forbid-removed" in imp["codes"]
          and any("w246" in b or "w247" in b for b in sel["batteries"])
          and sel["unpinned"] == [])
    return _check("p4: selection picks pinning batteries", ok,
                  "codes=%s selected=%s unpinned=%s"
                  % (imp["codes"], sel["batteries"], sel["unpinned"]))


# --------------------------------------------------------------------------
# P5-P7: gate semantics (red-first + controls)
# --------------------------------------------------------------------------

def _gate_on_policy(new_text, only):
    weak_path = _scratch(new_text, "policy.yaml")
    return _GATE.gate_policy_texts(
        REPO_ROOT,
        [("policies/default.yaml", BASE_POLICY, new_text)],
        python=VENV_PYTHON, timeout=300, only=only,
        extra_env={"ADAPTIVE_ADVERSARY_POLICY": weak_path,
                   "ADAPTIVE_ADVERSARY_ROUNDS": "2"})


def p5_red_observe_flip_fails_gate():
    """RED (spec-mandated): flip one deny rule to observe-only in a
    scratch tree, run the gate, confirm FAIL."""
    new = _flip_mode_observe(BASE_POLICY, "deny-secret-reads")
    report = _gate_on_policy(new, ["adaptive_adversary.py"])
    res = report["results"][0] if report["results"] else {}
    brk = res.get("break")
    ok = (report["verdict"] == "FAIL"
          and res.get("passed") is False
          and isinstance(brk, int) and brk > 0)
    return _check("p5 RED: observe-only flip fails the gate", ok,
                  "verdict=%s break=%s note=%s" % (report["verdict"], brk,
                                                   res.get("note")))


def p6_control_unweakened_policy_passes():
    report = _gate_on_policy(BASE_POLICY, ["adaptive_adversary.py"])
    ok = (report["verdict"] == "PASS"
          and report["reason"] == "no policy surfaces changed")
    return _check("p6 control: unweakened policy passes", ok,
                  "verdict=%s" % report["verdict"])


def p7_no_false_positive_on_held_weakening():
    """Effect deny->allow is flagged by the analyzer, but the pinning
    battery still holds (approval rule backs it) -> gate must PASS."""
    new = _flip_effect(BASE_POLICY, "deny-egress-unallowlisted")
    report = _gate_on_policy(new, ["adaptive_adversary.py"])
    res = report["results"][0] if report["results"] else {}
    ok = (report["verdict"] == "PASS" and res.get("passed")
          and "deny-egress-unallowlisted" in
          _pg.policy_yaml_impact(BASE_POLICY, new)["modified"])
    return _check("p7: held weakening does not fail the gate", ok,
                  "verdict=%s" % report["verdict"])


# --------------------------------------------------------------------------
# P8: other surfaces
# --------------------------------------------------------------------------

def p10_red_rule_removal_fails_gate():
    """RED (second mechanism): removing a forbid rule outright opens a
    real hole -> the gate must FAIL (delta: policy-delta-forbid-removed)."""
    new = _remove_rule(BASE_POLICY, "deny-secret-reads")
    report = _gate_on_policy(new, ["adaptive_adversary.py"])
    res = report["results"][0] if report["results"] else {}
    brk = res.get("break")
    ok = (report["verdict"] == "FAIL"
          and res.get("passed") is False
          and isinstance(brk, int) and brk > 0)
    return _check("p10 RED: rule removal fails the gate", ok,
                  "verdict=%s break=%s" % (report["verdict"], brk))


def p8_observe_and_pin_impacts():
    old_obs = "def deploy_observe(self):\n    pass\n"
    new_obs = "def deploy_observe(self):\n    pass\ndef promote(self):\n    pass\n"
    oi = _pg.observe_module_impact(old_obs, new_obs)
    ok = (oi["changed"] and oi["defs_added"] == ["promote"]
          and "policy_mode" in oi["keywords"])
    oi2 = _pg.observe_module_impact(old_obs, old_obs)
    ok = ok and not oi2["changed"]
    pi = _pg.pin_registry_impact("a", "b")
    pi2 = _pg.pin_registry_impact("a", "a")
    ok = ok and pi["changed"] and not pi2["changed"]
    return _check("p8: observe/pin impact units", ok)


# --------------------------------------------------------------------------
# P9: pin + footer (no new decision codes in this lane)
# --------------------------------------------------------------------------

def p9_pin_and_footer():
    from gov import decision_codes as _dc
    codes = sorted(_dc.TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN
          and codes == sorted(set(codes))
          and all(c == c.strip() for c in codes))
    # Independent cross-check (wave-302-lane-5 class): the coverage
    # artifact generated by a different lane must agree on the pin,
    # so a lockstep-stale constant can't pass vacuously.
    cov = __import__("json").load(
        open(os.path.join(REPO_ROOT, "docs", "decision-code-coverage.json")))
    ok = ok and cov.get("pin") == TAXONOMY_PIN == len(codes)
    # raw-literal uniqueness (wave-260 lesson): no duplicate "code" literals
    import re as _re
    src = open(os.path.join(REPO_ROOT, "gov", "decision_codes.py")).read()
    lits = _re.findall(r"""['"]code['"]\s*:\s*['"]([^'"]+)['"]""", src)
    ok = ok and len(lits) == len(set(lits))
    footer = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **%s**" % FOOTER_NEXT) in footer
    ok = ok and ("Open findings: %s." % FOOTER_OPEN) in footer
    return _check("p9: pin 2143, footer open F437-F441 / next F442", ok,  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
                  footer[-60:])


# --------------------------------------------------------------- green check
def _green_check():
    """Depth-1 green check: the delta-gate battery (the analyzer this
    gate builds on) plus this battery's own analyzer import surface."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    notes = []
    for script in ("w246_policy_delta_probes.py",):
        # Fresh unique TMPDIR per gate run (wave-173 lesson: never reuse
        # a fixed path; stale state collides across runs).
        tmp = "/var/tmp/g346-green-%s-%d-%d" % (
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
    for fn in (p1_effect_flip_detected,
               p2_rule_removal_detected,
               p3_malformed_fails_closed,
               p4_selection_picks_pinning_batteries,
               p5_red_observe_flip_fails_gate,
               p6_control_unweakened_policy_passes,
               p7_no_false_positive_on_held_weakening,
               p10_red_rule_removal_fails_gate,
               p8_observe_and_pin_impacts,
               p9_pin_and_footer):
        try:
            results.append(fn())
        except Exception as e:  # noqa: BLE001 - battery harness reports
            print("%-46s ERROR %s: %s" % (fn.__name__, type(e).__name__, e))
            results.append(None)
    n_held = sum(1 for r in results if r is True)
    n_break = sum(1 for r in results if r is False)
    n_err = sum(1 for r in results if r is None)
    print("w346_cigated: %d HELD / %d BREAK / %d ERROR"
          % (n_held, n_break, n_err))
    sys.exit(0 if (n_break == 0 and n_err == 0) else 1)


if __name__ == "__main__":
    main()
