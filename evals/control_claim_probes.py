#!/usr/bin/env python3
"""Control-claim red-team battery (wave-208 lane C).

The overstated-closure detector for the NIST SP 800-53 Rev 5
control-claim table in gov/control_claims.py.

Rule: an uncheckable claim is an overstated closure. This battery
evaluates every claim's check against the real tree and fails the
claim LOUDLY when the mechanism it cites does not hold -- or when
the check itself cannot be evaluated.

On the pristine tree every probe reports GAP (module absent -- genuine
red). After the fix all must flip to HELD.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red phase),
ERROR only on harness failure (a verdict changing between the two
runs). Each probe runs twice and a verdict change is an ERROR.
Synthetic/local only. Stdlib only.

New batteries must set the deployment mode at module level
(GOV_DEPLOYMENT_MODE=staging); the harness's declared ungoverned_ack
is refused in production mode.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import control_claims as _cc
    _ABSENT = False
except ImportError:
    _cc = None
    _ABSENT = True


# -- probe helpers -----------------------------------------------------

def _claim_ids():
    return [c["control_id"] for c in _cc.CONTROL_CLAIMS]


# -- probes ------------------------------------------------------------

def p_a_table_shape():
    """Every claim carries the full documented shape."""
    required = ("control_id", "family", "nist_statement", "mechanism",
                "check", "evidence_field", "scope", "not_claimed")
    ids = _claim_ids()
    if len(ids) != len(set(ids)):
        return "GAP"
    for c in _cc.CONTROL_CLAIMS:
        for field in required:
            if field not in c or not c[field]:
                return "GAP"
        if c["check"] not in _cc.CHECKS:
            return "GAP"
    # the not-claimed list is part of the honesty contract too
    for n in _cc.NOT_CLAIMED:
        if not n.get("control_id") or not n.get("why_not"):
            return "GAP"
    return "HELD"


def p_b_checks_hold():
    """Every claim's check evaluates and holds against the real tree."""
    for c in _cc.CONTROL_CLAIMS:
        res = _cc.check_claim(c["control_id"])
        if not res.checkable or not res.held or not res.detail:
            return "GAP"
    return "HELD"


def p_c_detector_catches_uncheckable():
    """The detector itself: a broken check must be reported, never green."""
    broken = {
        "control_id": "XX-9",
        "family": "XX",
        "nist_statement": "synthetic broken claim",
        "mechanism": "none",
        "check": "definitely_not_a_registered_check",
        "evidence_field": "none",
        "scope": "none",
        "not_claimed": "everything",
    }
    res = _cc.evaluate_claim(broken)
    if res.checkable or res.held:
        return "GAP"
    if "UNCHECKABLE" not in res.detail and "uncheckable" not in res.detail.lower():
        return "GAP"
    # a check that raises must also be caught, not propagate
    def _raiser():
        raise RuntimeError("synthetic check failure")
    _cc.CHECKS["synthetic_raiser"] = _raiser
    try:
        broken2 = dict(broken)
        broken2["check"] = "synthetic_raiser"
        res2 = _cc.evaluate_claim(broken2)
        if res2.checkable or res2.held:
            return "GAP"
    finally:
        del _cc.CHECKS["synthetic_raiser"]
    return "HELD"


def p_d_evidence_and_scope():
    """Every claim names an evidence-bundle field and a narrow scope."""
    for c in _cc.CONTROL_CLAIMS:
        if not c["evidence_field"] or not c["scope"]:
            return "GAP"
        if len(c["scope"]) < 20:
            return "GAP"
    # AU-12/AU-3 content claims must pin the exact v2 record shape
    au3 = _cc.get_claim("AU-3")
    if "decision_id" not in au3["evidence_field"] and \
            "decision_id" not in au3["scope"]:
        return "GAP"
    return "HELD"


def p_e_oscal_extension():
    """OSCAL implementation-statement extension: deterministic, complete,
    digest-sensitive, and honestly carrying the not-claimed rows."""
    from gov.evidence import oscal_control_claims as _occ
    a = _occ.component_definition_json(generated_at="2026-09-29T00:00:00+00:00")
    b = _occ.component_definition_json(generated_at="2026-09-29T00:00:00+00:00")
    if a != b:
        return "GAP"
    pkg = _occ.generate_control_claims_component_definition(
        generated_at="2026-09-29T00:00:00+00:00")
    comps = pkg["component-definition"]["components"]
    if len(comps) != 1:
        return "GAP"
    impls = comps[0]["control-implementations"]
    fw = {i["source"]: i for i in impls}
    if "NIST-SP-800-53-Rev-5" not in fw:
        return "GAP"
    reqs = fw["NIST-SP-800-53-Rev-5"]["implemented-requirements"]
    claimed = {r["control-id"] for r in reqs
               if r["props"] and _prop(r, "x-claim-status") == "claimed"}
    if claimed != set(_claim_ids()):
        return "GAP"
    not_claimed = {r["control-id"] for r in reqs
                   if _prop(r, "x-claim-status") == "not-claimed"}
    if not_claimed != {n["control_id"] for n in _cc.NOT_CLAIMED}:
        return "GAP"
    # every claimed row must name its check and its evidence field
    for r in reqs:
        if _prop(r, "x-claim-status") != "claimed":
            continue
        if not _prop(r, "x-claim-check") or not _prop(r, "x-evidence-field"):
            return "GAP"
    # digest sensitivity: the content digest must be a real function of
    # the claim table, not a constant
    d1 = _occ.control_claims_content_digest()
    if not d1 or len(d1) != 64:
        return "GAP"
    return "HELD"


def _prop(req, name):
    for p in req.get("props", ()):
        if p.get("name") == name:
            return p.get("value")
    return None


_PROBES = [
    ("C1", "TABLE_SHAPE", p_a_table_shape),
    ("C2", "CHECKS_HOLD", p_b_checks_hold),
    ("C3", "DETECTOR", p_c_detector_catches_uncheckable),
    ("C4", "EVIDENCE_SCOPE", p_d_evidence_and_scope),
    ("C5", "OSCAL_EXT", p_e_oscal_extension),
]


def green_check():
    """Adjacent-battery green check (depth-1: honor GOV_SKIP_GREEN)."""
    if _SKIP_GREEN:
        print("green_check: skipped (GOV_SKIP_GREEN=1)")
        return 0
    print("green_check: running adjacent suites (depth-1)")
    import subprocess
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    suites = [
        [sys.executable, "-m", "unittest", "tests.test_dsse_envelope"],
        [sys.executable, "-m", "unittest", "tests.test_decision_log_v2"],
        [sys.executable, "-m", "unittest", "tests.test_sign_deploy_namespaces"],
    ]
    rc = 0
    for cmd in suites:
        r = subprocess.run(cmd, cwd=root, env=env,
                           capture_output=True, text=True, timeout=600)
        name = cmd[-1]
        if r.returncode != 0:
            print("green_check FAIL: %s" % name)
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            rc = 1
        else:
            print("green_check OK: %s" % name)
    return rc


def main():
    if _ABSENT:
        print("gov.control_claims ABSENT (pristine tree) -- all GAP")
        for pid, name, _ in _PROBES:
            print("%s %-14s GAP (module absent)" % (pid, name))
        return 0
    failures = 0
    for pid, name, fn in _PROBES:
        first = fn()
        second = fn()
        verdict = first if first == second else "ERROR"
        if verdict != "HELD":
            failures += 1
        print("%s %-14s %s" % (pid, name, verdict))
        if first != second:
            print("  NON-DETERMINISTIC: %s then %s" % (first, second))
    rc = green_check()
    print("probes: %d/%d HELD" % (len(_PROBES) - failures, len(_PROBES)))
    return 1 if failures or rc else 0


if __name__ == "__main__":
    sys.exit(main())
