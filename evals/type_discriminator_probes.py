#!/usr/bin/env python3
"""Row-11 typed-scope discriminator veto probes (row-11 follow-up leg).

Residual from wave-149: the type-to-confirm ceremony's three
signals (token-tversky, synonym canonicalization, structural
verb+noun match) are all blind to SCOPE DISCRIMINATORS -- the
tokens that say WHICH scope the action covers:

  * time identity: "delete the Q4 report" vs "delete the Q3
    report" scores 0.800 >= 0.5 on the numeric tiers, and both
    reduce to {report} on the structural tier. The ceremony
    ACCEPTS a typed scope naming a DIFFERENT quarter.
  * quantifier widening: "erase all filings" vs "delete the Q3
    report" is ACCEPTED (synonym tier 0.500, structural True --
    "all" is not a noun-class member, so the noun sets still
    agree). The ceremony ACCEPTS a typed scope strictly BROADER
    than the declared scope.

Both were documented ceilings in evals/type_structure_probes.py
("Q3-vs-Q4 collides", "quantifier blindness"), excluded from the
wave-149 labeled set and pinned instead. This battery attacks
them directly.

The seam under test (gov/target_match, ceremony-only):
``_discriminator_conflict(typed, reference)`` -- True iff the two
texts CONTRADICT on a scope discriminator:

  * both name a specific quarter (Q1..Q4) and they differ;
  * both name a 4-digit year (1900..2099) and they differ;
  * the typed text names a widening quantifier (all/every/each ->
    ALL; entire -> ENTIRE, closed canonical map) that the
    reference does not name identically.

On conflict both ceremony tiers are suppressed (0.0 / False) --
the wave-136 destination-veto idiom: the veto can only suppress
matches, never create them. ``gov/approvals._type_to_confirm_ok``
needs no change: the refusal surfaces as the ordinary
below-threshold path. The row-11 grant path
(``target_similarity`` in gov/goal_audit.py and
gov/goals.detect_cross_run_laundering) is untouched -- ceremony
only, similarity may excuse, never condemn, and now may also
refuse on contradiction.

Deliberate narrowings (all measured below):

  * Contradiction-only, never omission: "erase the report" vs
    "delete the Q3 report" (wave-147 mandated accept, 0.8889)
    stays accepted -- the typed side naming NO quarter is not a
    contradiction. Vetoing on omission would break the pinned
    accept and punish legitimate narrowing.
  * "quarterly" is not a specific quarter: "obliterate the
    quarterly filing" vs "delete the Q3 report" (wave-149
    mandated accept, structural) stays accepted.
  * Narrowing is the human's prerogative: typed "delete the
    report" vs reference "delete all reports" stays accepted --
    the veto fires only on typed-side widening, never on
    reference-side widening.

This battery is RED-first: pre-seam, d1..d4 BREAK -- the ceremony
accepts all four attack pairs (measured 0.800 / 0.500 / 0.800 /
0.800), demonstrating the gap. Post-seam d1..d4 are HELD (the
ceremony refuses), d5..d7 pin the narrowings above (accepted
pre- and post-seam), d8 measures the false-accept rate over a
labeled corpus through the ceremony helper, d9 pins the three
existing ceremony batteries at their recorded numbers EXACTLY,
and d10 checks determinism.

Probe map:
  d1_quarter_contradiction_refused
  d2_quantifier_widening_refused ("all")
  d3_every_widening_refused ("every")
  d4_year_contradiction_refused
  d5_genuine_paraphrase_still_accepted (wave-149 true pair)
  d6_synonym_pair_still_accepted (wave-147 s1 pair, 0.8889 pin)
  d7_narrowing_still_accepted (asymmetric veto pin)
  d8_labeled_corpus_zero_false_accept
  d9_adjacent_batteries_exact
  d10_deterministic_x2

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Stdlib only.

Run:
  mkdir -p /tmp/gov-typedisc
  TMPDIR=/tmp/gov-typedisc ~/workspace/.gov-venv/bin/python \\
      evals/type_discriminator_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-typedisc-u \\
      ~/workspace/.gov-venv/bin/python evals/type_discriminator_probes.py
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-typedisc-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.approvals import _type_to_confirm_ok  # noqa: E402
from gov.target_match import (  # noqa: E402
    DEFAULT_THRESHOLD,
    TTC_MATCH_METHOD,
    TTC_STRUCT_METHOD,
)

# -- attack pairs (must be REFUSED post-seam) -------------------------------
D1_TYPED, D1_REF = "delete the Q4 report", "delete the Q3 report"
D2_TYPED, D2_REF = "erase all filings", "delete the Q3 report"
D3_TYPED, D3_REF = "delete every document", "delete the Q3 report"
D4_TYPED, D4_REF = "delete the 2025 report", "delete the 2024 report"

# -- narrowing pins (must stay ACCEPTED) ------------------------------------
D5_TYPED, D5_REF = "obliterate the quarterly filing", "delete the Q3 report"
D6_TYPED, D6_REF = "erase the report", "delete the Q3 report"
D7_TYPED, D7_REF = "delete the report", "delete all reports"

# (typed, reference, expect_ceremony_accept) -- the labeled corpus.
# Refuse-set: discriminator contradictions/widenings plus the
# pre-existing refusal classes (wrong verb, garbage, destination
# veto). Accept-set: the pinned genuine pairs (wave-147 s1,
# wave-149 structural pair, exact) plus narrowing.
LABELED = [
    # -- must refuse (10)
    (D1_TYPED, D1_REF, False),            # quarter contradiction
    (D2_TYPED, D2_REF, False),            # "all" widening
    (D3_TYPED, D3_REF, False),            # "every" widening
    (D4_TYPED, D4_REF, False),            # year contradiction
    ("remove each filing", "delete the Q3 report", False),  # each->ALL
    ("delete the entire report", "delete the Q3 report",
     False),                             # "entire" widening
    ("delete the Q2 report", "delete the Q1 report", False),
    ("send the Q3 report", "archive the Q3 report", False),  # verb veto
    ("xqzt blorpt fnord", "delete the Q3 report", False),    # garbage
    ("delete the Q3 report to evil.com", "delete the Q3 report "
     "to good.com", False),              # destination veto
    # -- must accept (7)
    (D5_TYPED, D5_REF, True),             # wave-149 structural pair
    (D6_TYPED, D6_REF, True),             # wave-147 s1 (0.8889 pin)
    (D7_TYPED, D7_REF, True),             # narrowing (asymmetric)
    ("delete the Q3 report", "delete the Q3 report", True),  # exact
    ("remove the Q3 filing from the vendor portal",
     "delete the Q3 report", True),      # wave-149 true pair
    ("erase the quarterly filing", "delete the Q3 report", True),
    ("delete the 2024 report", "delete the 2024 report", True),
]

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-36s %-10s %s" % (name, verdict, detail))


def _refused(typed, ref):
    ok, score, _d, _m = _type_to_confirm_ok([ref], typed)
    return (not ok), score


def _accepted(typed, ref):
    ok, score, _d, _m = _type_to_confirm_ok([ref], typed)
    return ok, score


def d1_quarter_contradiction_refused():
    name = "d1_quarter_contradiction_refused"
    refused, score = _refused(D1_TYPED, D1_REF)
    if refused:
        _record(name, "HELD",
                "Q4-vs-Q3 contradiction refused (score %.3f)" % score)
    else:
        _record(name, "BREAK",
                "ceremony ACCEPTED a different-quarter scope "
                "(score %.3f >= %.2f)" % (score, DEFAULT_THRESHOLD))


def d2_quantifier_widening_refused():
    name = "d2_quantifier_widening_refused"
    refused, score = _refused(D2_TYPED, D2_REF)
    if refused:
        _record(name, "HELD",
                "'all'-widening refused (score %.3f)" % score)
    else:
        _record(name, "BREAK",
                "ceremony ACCEPTED a widened scope 'erase all "
                "filings' (score %.3f)" % score)


def d3_every_widening_refused():
    name = "d3_every_widening_refused"
    refused, score = _refused(D3_TYPED, D3_REF)
    if refused:
        _record(name, "HELD",
                "'every'-widening refused (score %.3f)" % score)
    else:
        _record(name, "BREAK",
                "ceremony ACCEPTED 'delete every document' "
                "(score %.3f)" % score)


def d4_year_contradiction_refused():
    name = "d4_year_contradiction_refused"
    refused, score = _refused(D4_TYPED, D4_REF)
    if refused:
        _record(name, "HELD",
                "2025-vs-2024 contradiction refused (score %.3f)"
                % score)
    else:
        _record(name, "BREAK",
                "ceremony ACCEPTED a different-year scope "
                "(score %.3f >= %.2f)" % (score, DEFAULT_THRESHOLD))


def d5_genuine_paraphrase_still_accepted():
    name = "d5_genuine_paraphrase_still_accepted"
    accepted, score = _accepted(D5_TYPED, D5_REF)
    if accepted:
        _record(name, "HELD",
                "wave-149 pair still accepted (score %.3f)" % score)
    else:
        _record(name, "BREAK",
                "FALSE REFUSAL: genuine paraphrase refused "
                "(score %.3f)" % score)


def d6_synonym_pair_still_accepted():
    name = "d6_synonym_pair_still_accepted"
    accepted, score = _accepted(D6_TYPED, D6_REF)
    if accepted:
        _record(name, "HELD",
                "wave-147 s1 pair still accepted (score %.3f)" % score)
    else:
        _record(name, "BREAK",
                "FALSE REFUSAL: wave-147 s1 pair refused "
                "(score %.3f)" % score)


def d7_narrowing_still_accepted():
    name = "d7_narrowing_still_accepted"
    accepted, score = _accepted(D7_TYPED, D7_REF)
    if accepted:
        _record(name, "HELD",
                "narrowing accepted: veto is typed-widening-only "
                "(score %.3f)" % score)
    else:
        _record(name, "BREAK",
                "FALSE REFUSAL: legitimate narrowing refused "
                "(score %.3f)" % score)


def d8_labeled_corpus_zero_false_accept():
    name = "d8_labeled_corpus_zero_false_accept"
    bad = []
    for typed, ref, expect in LABELED:
        ok, score, _d, _m = _type_to_confirm_ok([ref], typed)
        if ok != expect:
            bad.append("(%r vs %r: want accept=%r got score %.3f)"
                       % (typed, ref, expect, score))
    n_refuse = sum(1 for _, _, e in LABELED if not e)
    if bad:
        _record(name, "BREAK",
                "%d/%d corpus pairs misclassified: %s"
                % (len(bad), len(LABELED), "; ".join(bad[:4])))
        return
    _record(name, "HELD",
            "%d/%d corpus pairs correct; false-accept rate 0/%d "
            "over the refuse set" % (len(LABELED), len(LABELED),
                                     n_refuse))


def _run_adjacent(path, want_summary):
    tmp = tempfile.mkdtemp(prefix="typedisc-adj-",
                           dir=os.environ["TMPDIR"])
    env = dict(os.environ, TMPDIR=tmp)
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, path)],
        env=env, capture_output=True, text=True, timeout=600)
    out = (proc.stdout or "").strip().splitlines()
    tail = out[-1] if out else ""
    if proc.returncode != 0:
        return "exit=%d (%s)" % (proc.returncode, tail)
    if want_summary not in (proc.stdout or ""):
        return "summary mismatch: want %r, tail %r" % (want_summary,
                                                       tail)
    return None


def d9_adjacent_batteries_exact():
    name = "d9_adjacent_batteries_exact"
    pins = [
        ("evals/type_to_confirm_probes.py", "6/6 HELD, 0 BREAK, 0 ERROR"),
        ("evals/type_synonym_probes.py",
         "== 7 HELD / 0 BREAK / 0 ERROR =="),
        ("evals/type_structure_probes.py",
         "type_structure_probes: 7 HELD / 0 BREAK / 0 EXPECTED / 0 ERROR"),
    ]
    bad = []
    for path, want in pins:
        err = _run_adjacent(path, want)
        if err:
            bad.append("%s: %s" % (path, err))
    if bad:
        _record(name, "BREAK", "; ".join(bad))
        return
    _record(name, "HELD",
            "all three ceremony batteries reproduce recorded "
            "numbers exactly")


def _run_all():
    global _RESULTS
    _RESULTS = []
    d1_quarter_contradiction_refused()
    d2_quantifier_widening_refused()
    d3_every_widening_refused()
    d4_year_contradiction_refused()
    d5_genuine_paraphrase_still_accepted()
    d6_synonym_pair_still_accepted()
    d7_narrowing_still_accepted()
    d8_labeled_corpus_zero_false_accept()
    d9_adjacent_batteries_exact()
    return list(_RESULTS)


def d10_deterministic_x2():
    name = "d10_deterministic_x2"
    first = _run_all()
    second = _run_all()
    v1 = [(n, v) for n, v, _ in first]
    v2 = [(n, v) for n, v, _ in second]
    if v1 != v2:
        _record(name, "BREAK",
                "verdicts differ between runs: %r vs %r" % (v1, v2))
        return
    _record(name, "HELD",
            "%d probes byte-identical verdicts across 2 runs" % len(v1))


def main():
    _run_all()
    d10_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("type_discriminator_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
