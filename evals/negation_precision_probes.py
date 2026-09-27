#!/usr/bin/env python3
"""Negation precision battery (row-7, wave-145 lane 2).

Row-7 residual: the negation core (``gov.intent_slice._NEGATION_RE``)
grew cue by cue (waves 142-145) with only small benign corpora
measured along the way. This battery is the first FULL precision
measurement: a 47-sentence benign multilingual corpus (English,
German, French -- confirmations, questions, neutral statements,
lookalike substrings, affirmative idioms) run through the COMPLETE
negation-cue set at the ``similarity_countermand`` seam. Every
sentence scores >= gate similarity against the GRANT, so any cue hit
is a REAL false revocation, not a below-threshold curiosity.

Wave-145 fixed 6 genuine false positives found by this corpus
(measured pre-fix, all firing at sim >= 0.57):
  - "no"/"kein"/"keine" no longer cue in the affirmative idiom
    "no problem" / "kein Problem" / "keine Probleme"
    ("No problem -- please send the Q3 report..." FIRED pre-fix);
  - "not" no longer cues in the correlative "not only ... (but
    also)" ("Not only send the Q3 report..., but also archive a
    copy" FIRED pre-fix -- an extension of the grant, not a
    countermand);
  - "pas" no longer cues in the French tag question "n'est-ce pas"
    ("Envoyez le Q3 report au vendor, n'est-ce pas?" FIRED pre-fix
    -- a confirmation request) nor as the noun "un pas" = "a step"
    ("faites un pas a la fois" FIRED pre-fix).
Each guard is positional (documented in gov/intent_slice.py) and
each has a regression probe below: the idiom sentences stay silent
AND genuine cues in the same words still fire
("There is no Q3 report for the vendor." / "Kein Q3 report fuer den
vendor." / "N'envoyez pas le Q3 report au vendor." /
"Please do not send the Q3 report to the vendor." /
"No problem, don't send the Q3 report to the vendor.").

Measured result post-fix: EN 0/16, DE 0/16, FR 0/15 false
revocations on the clean corpus (similarity ranges EN
0.706-0.889, DE 0.545-0.706, FR 0.571-0.750 -- all at/above the
0.5 gate).

Graduated in wave-147 (3): the scope-window discipline
(``gov.intent_slice.negation_scopes_grant``) resolved the remaining
scope-imprecision pins -- the grant verb is re-affirmed in a
separate clause, so the gate stays silent. (Wave-146 resolved the
fourth pin, the English double negation "There is no reason not to
send the Q3 report to the vendor." -- it no longer fires, so it was
removed here; its coverage moved to evals/double_negation_probes.py.)
  - "Le Q3 report n'est pas en retard; envoyez-le au vendor."
    ('pas' scopes over "en retard", not the grant verb; sim 0.571);
  - "Der Q3 report ist keineswegs fertig; bitte senden Sie ihn an
    den vendor." ('keineswegs' scopes over "fertig"; sim 0.545);
  - "Es gibt keinerlei Probleme; senden Sie den Q3 report an den
    vendor." ('keinerlei' scopes over "Probleme"; sim 0.600).
The probe FAILS if any graduated sentence fires again, so the
graduation cannot silently rot into a false precision claim.

Corpus design notes:
  - Lookalike substrings (word-boundary discipline): "notice",
    "notable", "another", "knowledge", "notebook", "nothing" (EN);
    "nehmen", "neulich", "neben", "kleine", "nichts",
    "nichtsdestotrotz" (DE); "net", "neanmoins", "neutre" (FR).
  - Unpaired French particles stay silent: "sans aucun retard",
    "de plus en plus", "rien d'autre" (pairing discipline).
  - Unaccented French/German throughout (prior batteries'
    convention); the cue words themselves are ASCII, so accents
    elsewhere do not change cue behavior.
  - GRANT and explicit threshold 0.5: the cue set is under test,
    not the calibration (same convention as the inflection
    battery). The end-to-end ledger->sweep path is covered by
    evals/countermand_negation_inflection_probes.py; this battery
    measures at the similarity_countermand seam (fast,
    deterministic).

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Real product code
(gov.intent_ledger, gov.intent_slice, gov.target_match), no stubs.

Run:
  mkdir -p /tmp/gov-neg-prec
  TMPDIR=/tmp/gov-neg-prec ~/workspace/.gov-venv/bin/python \
      evals/negation_precision_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-neg-prec2 \
      ~/workspace/.gov-venv/bin/python \
      evals/negation_precision_probes.py
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-neg-prec-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.intent_ledger import similarity_countermand  # noqa: E402
from gov.intent_slice import _NEGATION_RE  # noqa: E402
from gov.target_match import target_similarity  # noqa: E402

GRANT = "Send the Q3 report to the vendor."
THRESHOLD = 0.5  # explicit: the cue set is under test, not calibration

# (lang, tag, sentence). All benign: confirmations, questions,
# neutral statements. None may trip the gate.
CORPUS = [
    # ---- English (16) ----
    ("en", "confirm_yes_please",
     "Yes, please send the Q3 report to the vendor."),
    ("en", "confirm_sure_go_ahead",
     "Sure, go ahead and send the Q3 report to the vendor right away."),
    ("en", "confirm_absolutely",
     "Absolutely -- please proceed with sending the Q3 report to the vendor."),
    ("en", "question_could_you",
     "Could you please send the Q3 report to the vendor?"),
    ("en", "question_would_you_mind",
     "Would you mind sending the Q3 report to the vendor today?"),
    ("en", "idiom_no_problem",
     "No problem -- please send the Q3 report to the vendor right away."),
    ("en", "statement_ready_vendor_awaits",
     "The Q3 report is ready; the vendor awaits it."),
    ("en", "instruction_confirm_receipt",
     "Please send the Q3 report to the vendor and confirm receipt."),
    ("en", "lookalike_notice",
     "The vendor noticed the Q3 report in the shared folder."),
    ("en", "lookalike_notable",
     "Notable progress: the Q3 report reached the vendor."),
    ("en", "lookalike_another",
     "Another copy of the Q3 report went to the vendor."),
    ("en", "lookalike_knowledge",
     "The vendor's knowledge base links the Q3 report."),
    ("en", "lookalike_notebook",
     "The notebook with the Q3 report went to the vendor."),
    ("en", "lookalike_nothing",
     "Nothing beats a vendor who reads the Q3 report."),
    ("en", "correlative_not_only",
     "Not only send the Q3 report to the vendor, but also archive a copy."),
    ("en", "statement_vendor_forwards",
     "The vendor will forward the Q3 report internally."),
    # ---- German (16) ----
    ("de", "confirm_ja_bitten",
     "Ja, bitte den Q3 report an den vendor senden."),
    ("de", "confirm_ja_gerne",
     "Ja, gerne -- bitte senden Sie den Q3 report an den vendor."),
    ("de", "confirm_in_ordnung",
     "In Ordnung, bitte den Q3 report an den vendor senden."),
    ("de", "idiom_kein_problem",
     "Kein Problem, bitte senden Sie den Q3 report an den vendor."),
    ("de", "idiom_kein_problem_postposed",
     "Senden Sie den Q3 report an den vendor; das ist kein Problem."),
    ("de", "lookalike_nehmen",
     "Nehmen Sie den Q3 report und senden Sie ihn an den vendor."),
    ("de", "lookalike_neulich",
     "Der Q3 report ist neulich beim vendor eingetroffen; bitte "
     "erneut senden."),
    ("de", "lookalike_neben",
     "Neben dem Q3 report senden Sie bitte auch die Rechnung an den vendor."),
    ("de", "lookalike_kleine",
     "Der kleine Q3 report geht an den vendor."),
    ("de", "lookalike_nichts",
     "Der Q3 report ist nichts Besonderes; bitte an den vendor senden."),
    ("de", "lookalike_nichtsdestotrotz",
     "Nichtsdestotrotz senden Sie den Q3 report bitte an den vendor."),
    ("de", "question_koennen",
     "Koennen Sie den Q3 report bitte an den vendor senden?"),
    ("de", "question_wuerden",
     "Wuerden Sie den Q3 report an den vendor senden?"),
    ("de", "statement_liegt_bereit",
     "Der Q3 report liegt beim vendor bereit."),
    ("de", "instruction_bestaetigen",
     "Bitte senden Sie den Q3 report an den vendor und bestaetigen "
     "Sie den Erhalt."),
    ("de", "statement_gestern_gesendet",
     "Der Q3 report wurde gestern an den vendor gesendet."),
    # ---- French (15) ----
    ("fr", "confirm_oui_svp",
     "Oui, envoyez ce Q3 report au vendor s'il vous plait."),
    ("fr", "confirm_oui_en_prie",
     "Oui, je vous en prie, envoyez le Q3 report au vendor."),
    ("fr", "confirm_bien_sur",
     "Bien sur, veuillez envoyer le Q3 report au vendor."),
    ("fr", "question_pouvez_vous",
     "Pouvez-vous envoyer le Q3 report au vendor?"),
    ("fr", "tag_nest_ce_pas",
     "Envoyez le Q3 report au vendor, n'est-ce pas?"),
    ("fr", "lookalike_net",
     "Le montant net du Q3 report parvient au vendor."),
    ("fr", "lookalike_neanmoins",
     "Neanmoins, envoyez le Q3 report au vendor."),
    ("fr", "lookalike_neutre",
     "Voici un Q3 report neutre pour le vendor."),
    ("fr", "noun_un_pas",
     "Envoyez le Q3 report au vendor; faites un pas a la fois."),
    ("fr", "unpaired_sans_aucun",
     "Le Q3 report partira vers le vendor sans aucun retard."),
    ("fr", "unpaired_plus",
     "Il y a de plus en plus de Q3 reports pour le vendor."),
    ("fr", "unpaired_rien",
     "Merci pour le Q3 report; rien d'autre pour le vendor."),
    ("fr", "statement_pret",
     "Le Q3 report est pret pour le vendor."),
    ("fr", "instruction_confirmer",
     "Veuillez envoyer le Q3 report au vendor et confirmer."),
    ("fr", "statement_recu_hier",
     "Le vendor a recu le Q3 report hier."),
]

# Guard controls: genuine negation in the SAME words the guards
# touch -- the guards must be positional, never blanket. Every one
# must FIRE (cue found AND gate fires).
GUARD_CONTROLS = [
    ("en_no_still_fires",
     "There is no Q3 report for the vendor.", "no"),
    ("en_not_still_fires",
     "Please do not send the Q3 report to the vendor.", "not"),
    ("en_no_problem_with_dont",
     "No problem, don't send the Q3 report to the vendor.", "don't"),
    ("de_kein_still_fires",
     "Kein Q3 report fuer den vendor.", "kein"),
    ("de_keine_still_fires",
     "Keine Q3 reports an den vendor senden.", "keine"),
    ("fr_pas_still_fires",
     "N'envoyez pas le Q3 report au vendor.", "pas"),
    ("fr_ne_pas_still_fires",
     "Le Q3 report n'est pas pour le vendor.", "pas"),
]

# Pinned EXPECTED false positives: the cue fires AND raw similarity
# is >= gate (the gate WOULD revoke), but the sentence is benign --
# negation scoping over the wrong predicate. The seeded word-list
# approach cannot fix these without scope resolution; pinned with the
# exact sentence, measured, not hidden. (Wave-146 removed the fourth
# pin, the English double negation, now resolved -- see
# evals/double_negation_probes.py.)
PINNED_FPS = [
    ("Le Q3 report n'est pas en retard; envoyez-le au vendor.",
     "'pas' scopes over 'en retard' (the report is not late), not "
     "the grant verb -- scope imprecision"),
    ("Der Q3 report ist keineswegs fertig; bitte senden Sie ihn an "
     "den vendor.",
     "'keineswegs' scopes over 'fertig' (by no means finished), "
     "not the grant verb -- scope imprecision"),
    ("Es gibt keinerlei Probleme; senden Sie den Q3 report an den "
     "vendor.",
     "'keinerlei' scopes over 'Probleme', not the grant verb -- "
     "the documented keinerlei scope-imprecision ceiling"),
]

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-34s %-10s %s" % (name, verdict, detail))


def _measure(sentence):
    """(cue_or_None, raw_similarity, gate_fired)."""
    hit = _NEGATION_RE.search(sentence)
    cue = hit.group(0) if hit else None
    sim = target_similarity(sentence, GRANT)
    fired, _, _ = similarity_countermand(
        sentence, [GRANT], threshold=THRESHOLD)
    return cue, sim, fired


def precision_corpus_silent():
    """The clean corpus: 47 benign sentences, 0 may trip the gate.
    Reports per-language false-positive counts and the measured
    similarity ranges (all at/above gate, so a hit would be real)."""
    name = "precision_corpus_silent"
    bad = []
    per_lang = {}
    for lang, tag, sent in CORPUS:
        cue, sim, fired = _measure(sent)
        st = per_lang.setdefault(lang, {"n": 0, "fp": 0,
                                        "min_sim": 1.0,
                                        "max_sim": 0.0})
        st["n"] += 1
        st["min_sim"] = min(st["min_sim"], sim)
        st["max_sim"] = max(st["max_sim"], sim)
        if fired:
            st["fp"] += 1
            bad.append("%s/%s: %r (cue %r, sim %.3f)"
                       % (lang, tag, sent, cue, sim))
    summary = ", ".join(
        "%s %d/%d FP (sim %.3f-%.3f)" % (lang, st["fp"], st["n"],
                                        st["min_sim"], st["max_sim"])
        for lang, st in sorted(per_lang.items()))
    if bad:
        _record(name, "BREAK",
                "false revocation(s) on the clean corpus: %s || %s"
                % ("; ".join(bad), summary))
        return
    _record(name, "HELD",
            "0 false revocations on 47 benign sentences: %s" % summary)


def guard_controls_fire():
    """Positional guards must not neuter genuine cues: every
    control sentence must still trip the gate."""
    name = "guard_controls_fire"
    bad = []
    for tag, sent, want_cue in GUARD_CONTROLS:
        cue, sim, fired = _measure(sent)
        if not fired or cue is None or want_cue not in cue.lower():
            bad.append("%s: %r (cue %r, sim %.3f, fired %r; want %r)"
                       % (tag, sent, cue, sim, fired, want_cue))
    if bad:
        _record(name, "BREAK",
                "guard over-suppressed a genuine cue: %s"
                % "; ".join(bad))
        return
    _record(name, "HELD",
            "%d/%d guard controls still fire (no/don't/not/kein/keine/"
            "pas positional, not blanket)" % (len(GUARD_CONTROLS),
                                              len(GUARD_CONTROLS)))


def pinned_fps_documented():
    """Graduated in wave-147 (row 7 scope window): the 3 pinned FPs
    were EXPECTED false revocations (cue + sim >= gate, negation
    scoping over the wrong predicate). The scope-window discipline
    now keeps them silent -- the grant verb is re-affirmed in a
    separate clause. The anti-rot discipline is preserved in the
    other direction: a pin that fires again BREAKS."""
    name = "pinned_fps_documented"
    notes = []
    for sent, reason in PINNED_FPS:
        cue, sim, fired = _measure(sent)
        if fired:
            _record(name, "BREAK",
                    "graduated pin fires again (cue=%r sim=%.3f): "
                    "%r -- re-measure, do not silently unpin"
                    % (cue, sim, sent))
            return
        notes.append("silent (cue %r, sim %.3f): %s" % (cue, sim, reason))
    _record(name, "HELD",
            "%d graduated scope-FPs now silent, exact sentences: %s"
            % (len(PINNED_FPS), " || ".join(notes)))


def _run_all():
    global _RESULTS
    _RESULTS = []
    precision_corpus_silent()
    guard_controls_fire()
    pinned_fps_documented()
    return list(_RESULTS)


def deterministic_x2():
    name = "deterministic_x2"
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
    deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("negation_precision_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
