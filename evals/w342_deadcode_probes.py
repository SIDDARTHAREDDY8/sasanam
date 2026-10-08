#!/usr/bin/env python3
"""Wave-342 dead-code registry-hygiene battery (lane 6).

Two registry-hygiene actions, verified behaviorally (break-first, at the
public seams):

A. ``admission-at-risk-accepted`` now EMITS: ``admit_at_risk()`` in
   ``gov/evidence_admission.py`` stamps the returned ADMIT-AT-RISK
   decision record with ``"code": AT_RISK_ACCEPTED``. The constant was
   defined and the registry entry written, but the emission was never
   wired -- this lane wired it. Probes A1-A4 drive the governed-exception
   path for real and pin the discrimination boundaries:
     - the at-risk code appears ONLY on the accepted record (never on
       the REFUSE record itself);
     - no live exception -> admission-exception-refused, no code;
     - floor-failed refusals can NEVER be accepted at risk.

B. Four family-fallback base-class codes are REMOVED from the taxonomy:
   ``single-use-refused``, ``evidence-refused``, ``key-identity-refused``,
   ``spiffe-refused``. Audit result: every raise site in the tree raises
   the concrete subclass (which overrides ``code``); no test, battery,
   or production path ever emits the base-class value, and the w228
   VOCAB never contained them. They were implementation vocabulary
   (defensive ``code`` defaults on exception base classes), not evidence
   vocabulary. Probe A5 pins their absence; probe A6 pins that the
   concrete subclass codes still emit (the families are unaffected).

Pin: 2131 -> 2127. Footer: open F429 / next F430.

$0 SPEND BY CONSTRUCTION: no model calls, canned inputs only. Do NOT
add ModelDriver/SpendLedger usage here.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w342_deadcode_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import re
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes); Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

from gov import evidence_admission as ap  # noqa: E402
from gov import governed_exceptions as ge  # noqa: E402
from gov.decision_codes import TAXONOMY, code_for, DecisionCodeError  # noqa: E402
from gov import single_use as _su  # noqa: E402


# ---------------------------------------------------------------- fixtures
def _doc(**kw):
    d = {
        "format": "admission-policy/1",
        "policy_id": "adm-u",
        "scopes": [
            {"scope": "provenance", "level": "strict"},
            {"scope": "checkpoint", "level": "permissive"},
        ],
    }
    d.update(kw)
    return d


def _full(fails=()):
    return dict((c, c not in fails) for c in (
        "signature-valid", "digest-binds", "provenance-present",
        "builder-allowlisted", "endorsement-independent",
        "witness-quorum", "freshness"))


def _ev(kind):
    return {"kind": kind, "artifact_digest": "d" * 64, "envelope": None}


def _store(grant=False, policy_id="adm-u"):
    reg = ge.CheckRegistry()
    reg.register(ap.ACCEPT_RISK_CHECK_ID, "admission accept risk",
                 "admission", "medium", "accept at operator risk",
                 ["admission-policy"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["ops"])
    if grant:
        now = time.time()
        store.grant(ap.ACCEPT_RISK_CHECK_ID, ("policy", policy_id),
                    "accepting at risk for this test run",
                    "ops", now + 3600, now)
    return store


def _refuse_err(fails=("provenance-present",)):
    pol = ap.compile_policy(_doc())
    try:
        ap.admit(_ev("provenance"), pol, _full(fails=fails))
    except ap.AdmissionError as e:
        return e
    raise AssertionError("admit() did not refuse")


def _is_hex64(s):
    return (isinstance(s, str) and len(s) == 64
            and all(c in "0123456789abcdef" for c in s))


# ---------------------------------------------------------------- probes
def test_a1_at_risk_emits_code():
    """The ADMIT-AT-RISK record carries machine code
    'admission-at-risk-accepted', bound to the refuse record and the
    live exception."""
    err = _refuse_err()
    assert err.code == "admission-refused", err.code
    rec = ap.admit_at_risk(err, _store(grant=True), now=time.time())
    if rec.get("code") != "admission-at-risk-accepted":
        return "BREAK", "record code: %r" % (rec.get("code"),)
    if rec.get("verdict") != "ADMIT-AT-RISK":
        return "BREAK", "verdict: %r" % (rec.get("verdict"),)
    if not _is_hex64(rec.get("refused_decision_digest", "")):
        return "BREAK", "refused_decision_digest not digest-shaped"
    if rec["refused_decision_digest"] != err.decision["decision_digest"]:
        return "BREAK", "refused digest does not bind the REFUSE record"
    if not _is_hex64(rec.get("exception_digest", "")):
        return "BREAK", "exception_digest not digest-shaped"
    if not _is_hex64(rec.get("decision_digest", "")):
        return "BREAK", "record decision_digest not digest-shaped"
    if rec.get("floor_failed") != []:
        return "BREAK", "floor_failed: %r" % (rec.get("floor_failed"),)
    return "HELD", "at-risk code emitted and bound"


def test_a2_refuse_record_carries_no_at_risk_code():
    """Discrimination: the REFUSE record itself never carries the at-risk
    code -- the code exists only on the accepted record."""
    err = _refuse_err()
    if "code" in err.decision:
        return "BREAK", "REFUSE record carries code: %r" % (
            err.decision["code"],)
    return "HELD", "REFUSE record has no at-risk code"


def test_a3_no_live_exception_no_code():
    """Discrimination: without a live governed exception there is no
    accepted record at all -- LOUD refusal, no at-risk code emitted."""
    err = _refuse_err()
    try:
        ap.admit_at_risk(err, _store(), now=time.time())
    except ap.AdmissionError as e:
        if e.code != "admission-exception-refused":
            return "BREAK", "wrong refusal code: %r" % (e.code,)
        return "HELD", "refused loud, no at-risk code"
    return "BREAK", "admit_at_risk accepted without a live exception"


def test_a4_floor_never_accepted_at_risk():
    """Discrimination: a floor-failed refusal refuses LOUD even with a
    live exception -- the at-risk code is never emitted past the floor."""
    err = _refuse_err(fails=("signature-valid",))
    assert err.code == "admission-integrity-floor-violated", err.code
    try:
        ap.admit_at_risk(err, _store(grant=True), now=time.time())
    except ap.AdmissionError as e:
        if e.code != "admission-exception-refused":
            return "BREAK", "wrong refusal code: %r" % (e.code,)
        return "HELD", "floor refusal never accepted at risk"
    return "BREAK", "floor-failed refusal was accepted at risk"


def test_a5_removed_family_codes_unregistered():
    """The four family-fallback base-class codes are gone from the
    taxonomy; code_for() fails closed on them."""
    removed = ("single-use-refused", "evidence-refused",
               "key-identity-refused", "spiffe-refused")
    for c in removed:
        if c in TAXONOMY:
            return "BREAK", "%r still registered" % (c,)
        try:
            code_for(c)
        except DecisionCodeError as e:
            if e.code != "decision-code-unmapped":
                return "BREAK", "%r failed closed with %r, not unmapped" % (
                    c, e.code)
        else:
            return "BREAK", "code_for(%r) did not raise" % (c,)
    return "HELD", "4 family-fallback codes unregistered, fail closed"


def test_a6_concrete_subclass_codes_still_emit():
    """The families are unaffected: concrete subclass codes still emit
    (single-use replay -> 'single-use-replay-refused')."""
    reg = _su.SingleUseRegistry()
    att = reg.issue("ab" * 32, "issuer-1", "nonce-1")
    try:
        reg.consume(att)
        reg.consume(att)
    except Exception as e:  # noqa: BLE001 - any error must carry the code
        if getattr(e, "code", None) != "single-use-replay-refused":
            return "BREAK", "replay code: %r" % (getattr(e, "code", None),)
        return "HELD", "subclass code still emits"
    return "BREAK", "double consume did not refuse"


def test_a7_family_fallback_premise():
    """The w228 VOCAB exclusion's premise: none of the four base
    classes is ever raised or instantiated directly in gov/ -- every
    raise site uses a concrete subclass that overrides ``code``. If a
    direct raise appears, the exclusion is wrong and must be revisited."""
    bases = ("SingleUseError", "EvidenceError",
             "KeyIdentityError", "SpiffeError")
    govdir = os.path.join(REPO_ROOT, "gov")
    hits = []
    for fname in sorted(os.listdir(govdir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(govdir, fname), encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                s = line.strip()
                if s.startswith("#") or s.startswith('"""'):
                    continue
                if re.match(r"\s*class\s+\w+", line):
                    # class definition lines (incl. ``class _X(Base):``)
                    # are not raises.
                    continue
                for base in bases:
                    if re.search(r"\b%s\s*\(" % base, line):
                        hits.append("%s:%d:%s" % (fname, i, s[:80]))
    if hits:
        return "BREAK", "direct base-class use: %r" % (hits[:4],)
    return "HELD", "no direct raise/instantiation of the 4 base classes"


def test_pin_taxonomy_2127():
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return "BREAK", "battery pin drifted: %r" % (TAXONOMY_PIN,)
    if len(TAXONOMY) != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return "BREAK", "registry holds %d codes, want 2140" % len(TAXONOMY)
    keys = list(TAXONOMY)
    if keys != sorted(keys):
        return "BREAK", "taxonomy not sorted"
    if len(set(keys)) != len(keys):
        return "BREAK", "duplicate code literals"
    return "HELD", "2140/2140/0 sorted, raw-literal unique"


def test_footer_state():
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    footer = ([ln for ln in lines if "Next free finding:" in ln] or [""])[-1]  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531) (footer is not the last line; entries follow)
    ok = ("Next free finding: **F606**" in footer  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
          and "Open findings: F597, F598, F599, F600, F601, F602, F603, F604, F605." in footer)  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
    return ("HELD" if ok else "BREAK",
            "footer line: %r" % (footer[:120],))


TESTS = [test_a1_at_risk_emits_code,
         test_a2_refuse_record_carries_no_at_risk_code,
         test_a3_no_live_exception_no_code,
         test_a4_floor_never_accepted_at_risk,
         test_a5_removed_family_codes_unregistered,
         test_a6_concrete_subclass_codes_still_emit,
         test_a7_family_fallback_premise,
         test_pin_taxonomy_2127,
         test_footer_state]

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere


def _green_check():
    """Depth-1 green check: adjacent unit suites only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for mod in ("tests.test_evidence_admission", "tests.test_decision_codes"):
        tmp = "/var/tmp/g342-green-%s" % mod.replace(".", "-")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        env["GOV_RUN_ROOT"] = tmp + "-run"
        r = subprocess.run(
            [venv_python, "-m", mod],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        tail = (r.stdout + r.stderr)[-300:]
        notes.append("%s rc=%d %s" % (mod, r.returncode, tail.strip()))
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
        print("%s: %s -- %s" % (fn.__name__, verdict, detail[:200]))
        if verdict == "BREAK":
            n_break += 1
            probe_breaks.add(fn.__name__)
        elif verdict == "HELD":
            n_held += 1
        else:
            n_err += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    if probe_breaks ^ _EXPECTED_BREAKS:
        print("MISMATCH: breaks=%s expected=%s"
              % (sorted(probe_breaks), sorted(_EXPECTED_BREAKS)))
        sys.exit(2)
    sys.exit(1 if n_break or n_err else 0)


if __name__ == "__main__":
    main()
