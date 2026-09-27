#!/usr/bin/env python3
"""Devanagari negation-cue battery (row-7, wave-149 lane 3).

Row-7 residual: the countermand negation gate
(``gov.intent_slice._NEGATION_RE``, consumed by
``gov.intent_ledger.similarity_countermand``) was keyword-based in
Latin scripts only -- a negated countermand written in Devanagari
(Hindi) missed the gate and a paraphrased countermand executed.

This battery is RED-first: the Devanagari probes go BREAK while the
cues are missing from ``_NEGATION_RE`` (no negation cue found, the
similarity gate never consulted); they flip to HELD once
``gov/intent_slice.py`` carries the pilot cues (नहीं/न/मत) with
explicit Devanagari word-boundary discipline plus Devanagari
SEND/ARCHIVE/DELETE verb forms.

Why not Python \\b: \\b does NOT fire around Devanagari words ending
in combining marks ("नहीं" ends in ं, U+0902, category Mn -- not a \\w
char), so \\bनहीं\\b matches NOTHING, not even "रिपोर्ट नहीं भेजें"
(measured). The boundary guards are hand-rolled:
(?<![\\w\\u0900-\\u0963\\u0966-\\u097F]) / (?!...). Danda U+0964/U+0965
(the Hindi sentence terminators) are deliberately EXCLUDED from the
guard so "नहीं।" still cues; every other Devanagari letter, vowel
sign, nukta, halant, anusvara/visarga, and digit blocks gluing.

Related wave-149 fix, pinned here: ``_fold_accents`` used to strip
Devanagari combining marks (virama U+094D: "रिपोर्ट" -> "रिपोरट"),
changing string length and breaking the raw-text cue-span alignment
in ``negation_scopes_grant``. The fold now preserves the Devanagari
block (no NFKD decompositions there), so the fold is length-identical.

Probe map (explicit threshold=0.5 throughout -- these probes test the
cue and the scope window, not threshold calibration; the Devanagari
sentences score 0.571, inside the wave-138 derived band, so routing
them through record_intent would be flaky per the wave-145 lesson):
  d_mat_revokes: "Q3 रिपोर्ट मत भेजें" vs GRANT -> revokes (0.571).
  d_nahin_revokes: "Q3 रिपोर्ट नहीं भेजें" -> revokes.
  d_na_standalone_revokes: "Q3 रिपोर्ट न भेजें" -> revokes
     (standalone न is a mandated cue).
  d_scope_split_silent: "Q3 रिपोर्ट तैयार नहीं है; कृपया इसे विक्रेता
     को भेजें" -> SILENT (the cue scopes over "तैयार है", the grant
     verb "भेजें" sits in a cue-less clause -- wave-147 discipline).
  d_danda_split_silent: same with । terminators -> SILENT (danda is
     a clause boundary).
  d_danda_terminator_revokes: "Q3 रिपोर्ट मत भेजें।" -> revokes (the
     danda must not block the cue).
  d_embedded_cue_silent: "रिपोर्टनहींभेजें" (glued) and "मतलब"
     ("meaning", contains मत) -> NO cue at the regex level, and
     "Q3 रिपोर्टनहींभेजें" does not revoke.
  d_delete_form_revokes: "Q3 रिपोर्ट को हटाना नहीं है" vs
     "Delete the Q3 report." -> revokes (Devanagari DELETE form).
  d_archive_form_revokes: "Q3 रिपोर्ट संग्रहित नहीं करें" vs
     "Archive the Q3 report." -> revokes (Devanagari ARCHIVE form).
  d_benign_precision: ordinary Devanagari prose with no negation
     intent stays silent (pins no accidental cueing).
  d_tag_question_expected: "Q3 रिपोर्ट vendor को भेज दी है न?"
     ("...haven't you?") FIRES -- EXPECTED, the documented precision
     cost of the mandated standalone-न cue (wave-142 "ne" precedent:
     measured cost, kept, row stays PARTIAL).
  d_multilingual_green: the six existing negation batteries
     (multilingual, inflection, double-negation, precision, scope,
     verb-tier2) still exit 0 -- the _fold_accents and tokenizer
     changes must not regress Latin behavior.
  d_deterministic_x2: byte-identical verdicts across 2 runs.

Honest ceilings (documented, not hidden): Hindi-only pilot --
Arabic/CJK/Cyrillic still miss; the closed verb-form lists do not
cover every inflection; the "न" tag-question cost above is real;
quantifier blindness ("सभी रिपोर्ट मत भेजें" vs "एक रिपोर्ट")
persists; the judge's _negated_verb direct-evidence path
("don't delete"-style verb negation) keeps its Latin-only tokenizer
-- Devanagari countermands are caught by this similarity-countermand
signal (ledger/sweep), not by the judge's verb-negation evidence;
row 7 stays PARTIAL.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Real product code
(gov.intent_ledger, gov.intent_slice), no stubs.

Run:
  mkdir -p /tmp/gov-deva-neg
  TMPDIR=/tmp/gov-deva-neg ~/workspace/.gov-venv/bin/python \\
      evals/devanagari_negation_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-deva-neg2 \\
      ~/workspace/.gov-venv/bin/python \\
      evals/devanagari_negation_probes.py
"""

import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-deva-neg-%d" % os.getpid())

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.intent_ledger import similarity_countermand  # noqa: E402
from gov.intent_slice import _NEGATION_RE, _fold_accents  # noqa: E402

GRANT = "Send the Q3 report to the vendor."
ARCHIVE_GRANT = "Archive the Q3 report."
DELETE_GRANT = "Delete the Q3 report."
THRESHOLD = 0.5  # explicit: these probes test the cue, not calibration

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-30s %-10s %s" % (name, verdict, detail))


def _sc(message, priors):
    fired, _, score = similarity_countermand(
        message, priors, threshold=THRESHOLD)
    return fired, score


def d_mat_revokes():
    name = "d_mat_revokes"
    fired, score = _sc("Q3 रिपोर्ट मत भेजें", [GRANT])
    if fired:
        _record(name, "HELD",
                "\"Q3 रिपोर्ट मत भेजें\" revokes send grant (%.3f)" % score)
    else:
        _record(name, "BREAK",
                "mat countermand did not revoke (%.3f)" % score)


def d_nahin_revokes():
    name = "d_nahin_revokes"
    fired, score = _sc("Q3 रिपोर्ट नहीं भेजें", [GRANT])
    if fired:
        _record(name, "HELD",
                "\"Q3 रिपोर्ट नहीं भेजें\" revokes send grant (%.3f)"
                % score)
    else:
        _record(name, "BREAK",
                "nahin countermand did not revoke (%.3f)" % score)


def d_na_standalone_revokes():
    name = "d_na_standalone_revokes"
    fired, score = _sc("Q3 रिपोर्ट न भेजें", [GRANT])
    if fired:
        _record(name, "HELD",
                "standalone \"न\" revokes send grant (%.3f)" % score)
    else:
        _record(name, "BREAK",
                "standalone na countermand did not revoke (%.3f)" % score)


def d_scope_split_silent():
    name = "d_scope_split_silent"
    msg = "Q3 रिपोर्ट तैयार नहीं है; कृपया इसे विक्रेता को भेजें"
    fired, score = _sc(msg, [GRANT])
    if not fired:
        _record(name, "HELD",
                "cue scopes over \"तैयार है\", grant verb in cue-less "
                "clause: silent (%.3f)" % score)
    else:
        _record(name, "BREAK",
                "false revocation: cue leaked across the clause "
                "boundary (%.3f)" % score)


def d_danda_split_silent():
    name = "d_danda_split_silent"
    msg = "Q3 रिपोर्ट तैयार नहीं है। कृपया इसे विक्रेता को भेजें।"
    fired, score = _sc(msg, [GRANT])
    if not fired:
        _record(name, "HELD",
                "danda is a clause boundary: silent (%.3f)" % score)
    else:
        _record(name, "BREAK",
                "false revocation across danda boundary (%.3f)" % score)


def d_danda_terminator_revokes():
    name = "d_danda_terminator_revokes"
    fired, score = _sc("Q3 रिपोर्ट मत भेजें।", [GRANT])
    if fired:
        _record(name, "HELD",
                "\"मत भेजें।\" revokes: danda does not block the cue "
                "(%.3f)" % score)
    else:
        _record(name, "BREAK",
                "danda terminator blocked the cue (%.3f)" % score)


def d_embedded_cue_silent():
    name = "d_embedded_cue_silent"
    glued = _NEGATION_RE.search("रिपोर्टनहींभेजें")
    matlab = _NEGATION_RE.search("इसका मतलब रिपोर्ट भेजें")
    fired, score = _sc("Q3 रिपोर्टनहींभेजें", [GRANT])
    if glued is None and matlab is None and not fired:
        _record(name, "HELD",
                "glued \"नहीं\" and \"मत\"-in-\"मतलब\" do not cue; no "
                "revocation")
    else:
        _record(name, "BREAK",
                "boundary discipline failed: glued=%r matlab=%r "
                "revoked=%r" % (glued, matlab, fired))


def d_delete_form_revokes():
    name = "d_delete_form_revokes"
    fired, score = _sc("Q3 रिपोर्ट को हटाना नहीं है", [DELETE_GRANT])
    if fired:
        _record(name, "HELD",
                "Devanagari DELETE form \"हटाना\" revokes (%.3f)" % score)
    else:
        _record(name, "BREAK",
                "Devanagari DELETE countermand did not revoke (%.3f)"
                % score)


def d_archive_form_revokes():
    name = "d_archive_form_revokes"
    fired, score = _sc("Q3 रिपोर्ट संग्रहित नहीं करें", [ARCHIVE_GRANT])
    if fired:
        _record(name, "HELD",
                "Devanagari ARCHIVE form \"संग्रहित\" revokes (%.3f)"
                % score)
    else:
        _record(name, "BREAK",
                "Devanagari ARCHIVE countermand did not revoke (%.3f)"
                % score)


BENIGN_DEVANAGARI = [
    # Ordinary Hindi prose about the Q3 report with NO negation
    # intent: none of these may trip the gate.
    "Q3 रिपोर्ट vendor को भेज दी।",          # already sent (affirmation)
    "कृपया Q3 रिपोर्ट vendor को भेजें।",      # polite request
    "Q3 रिपोर्ट तैयार है।",                   # ready, no action
    "vendor ने Q3 रिपोर्ट माँगी है।",         # vendor asked for it
    "मैं Q3 रिपोर्ट की समीक्षा कर रहा हूँ।",  # reviewing it
]


def d_benign_precision():
    name = "d_benign_precision"
    bad = []
    for s in BENIGN_DEVANAGARI:
        fired, score = _sc(s, [GRANT])
        if fired:
            bad.append("%s (%.3f)" % (s, score))
    if not bad:
        _record(name, "HELD",
                "%d benign Devanagari sentences silent"
                % len(BENIGN_DEVANAGARI))
    else:
        _record(name, "BREAK",
                "false revocation on %d benign sentence(s): %s"
                % (len(bad), "; ".join(bad)))


def d_tag_question_expected():
    name = "d_tag_question_expected"
    # "Q3 रिपोर्ट vendor को भेज दी है न?" = "you've sent the Q3 report
    # to the vendor, haven't you?" -- a confirmation, not a
    # countermand. The mandated standalone-न cue reads it as a
    # countermand: a MEASURED precision cost (wave-142 "ne" precedent),
    # kept and documented; row 7 stays PARTIAL.
    fired, score = _sc("Q3 रिपोर्ट vendor को भेज दी है न?", [GRANT])
    if fired:
        _record(name, "EXPECTED",
                "tag question \"है न?\" fires (%.3f): documented "
                "precision cost of the mandated standalone-न cue"
                % score)
    else:
        _record(name, "BREAK",
                "tag question unexpectedly silent -- cue discipline "
                "changed?")


def d_fold_length_preserved():
    name = "d_fold_length_preserved"
    cases = ["रिपोर्ट", "नहीं", "भेजें", "Q3 रिपोर्ट मत भेजें।",
             "हटाना", "संग्रहित"]
    bad = [s for s in cases if _fold_accents(s) != s]
    if not bad:
        _record(name, "HELD",
                "fold is length-identical on %d Devanagari cases "
                "(cue-span alignment holds)" % len(cases))
    else:
        _record(name, "BREAK",
                "fold changed: %r" % bad)


MULTILINGUAL_BATTERIES = [
    "countermand_multilingual_negation_probes.py",
    "countermand_negation_inflection_probes.py",
    "double_negation_probes.py",
    "negation_precision_probes.py",
    "negation_scope_probes.py",
    "negation_verb_tier2_probes.py",
]


def d_multilingual_green():
    name = "d_multilingual_green"
    failures = []
    for i, battery in enumerate(MULTILINGUAL_BATTERIES):
        tmp = os.path.join(os.environ["TMPDIR"], "ml-%d" % i)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmp)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
            capture_output=True, text=True, env=env, cwd=REPO_ROOT,
            timeout=600)
        tail = (proc.stdout.strip().splitlines() or [""])[-1]
        err_tail = proc.stderr.strip().splitlines()
        err_tail = err_tail[-1] if err_tail else ""
        if proc.returncode != 0:
            failures.append("%s -> rc=%d (%s; %s)"
                            % (battery, proc.returncode, tail, err_tail))
    if not failures:
        _record(name, "HELD",
                "%d existing negation batteries green"
                % len(MULTILINGUAL_BATTERIES))
    else:
        _record(name, "BREAK",
                "regressions: %s" % "; ".join(failures))


def _run_all():
    global _RESULTS
    _RESULTS = []
    d_mat_revokes()
    d_nahin_revokes()
    d_na_standalone_revokes()
    d_scope_split_silent()
    d_danda_split_silent()
    d_danda_terminator_revokes()
    d_embedded_cue_silent()
    d_delete_form_revokes()
    d_archive_form_revokes()
    d_benign_precision()
    d_tag_question_expected()
    d_fold_length_preserved()
    d_multilingual_green()
    return list(_RESULTS)


def d_deterministic_x2():
    name = "d_deterministic_x2"
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
    d_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("devanagari_negation_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
