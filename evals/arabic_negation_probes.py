#!/usr/bin/env python3
"""Arabic negation-cue battery (row-7, wave-152 lane 3).

Row-7 residual: the countermand negation gate
(``gov.intent_slice._NEGATION_RE``, consumed by
``gov.intent_ledger.similarity_countermand``) was keyword-based in
Latin scripts plus Devanagari (wave-149/150) and Cyrillic
(wave-151) pilots -- a negated countermand written in Arabic missed
the gate and a paraphrased countermand executed.

This battery is RED-first: the Arabic probes go BREAK while the
cues are missing from ``_NEGATION_RE`` (no negation cue found, the
similarity gate never consulted; the judge's tokenizer never sees
the verbs). They flip to HELD once ``gov/intent_slice.py`` carries
the pilot cues (لا/لم/لن/ما/ليس, with the attached و/ب/ل prefixes
before لا and و before the rest) with Arabic word-boundary
discipline plus Arabic SEND/DELETE/SHARE verb forms.

Why plain \\b suffices here (like Cyrillic, unlike Devanagari):
Arabic letters ARE \\w, so \\b fires correctly around Arabic
words -- \\bلا\\b matches "لا ترسل" and does NOT match "بلاد",
"سلام", or "كلام" (measured, pinned in c_lookalike_boundaries).
The attached prefixes (و/ب/ل before لا, و before لم/لن/ما/ليس)
are part of the cue alternative itself: "ولا ترسل" (and do not
send) and "بلا إرسال" (without sending) cue; "بلاد" (country)
does not, because the trailing \\b still guards the word end.

Arabic under _fold_accents: standard Arabic letters have no NFKD
decomposition, and wave-152 preserves the whole Arabic block
(U+0600-U+06FF, tashkeel included) exactly like the Devanagari
block -- so the fold is length-identical on Arabic and cue-span
alignment holds (pinned in c_fold_length_preserved). No
dual-spelling class table is needed (unlike Cyrillic ё/й).
The Arabic question mark ؟ (U+061F) and Arabic semicolon ؛ (U+061B)
are clause boundaries in _CLAUSE_SPLIT_RE (parallel to the
Devanagari danda and Latin ?/;); the Arabic comma ، is not
(parallel to the Latin comma).

Probe map (explicit threshold=0.5 throughout -- these probes test
the cue and the scope window, not threshold calibration, per the
wave-145 derived-band lesson):
  c_<class>_<cue> (15 probes): each cue (لا/لم/لن/ما/ليس) x each
     covered verb class (SEND/DELETE/SHARE) -> revokes on the
     similarity-countermand path. Pre-seam: 15 BREAK (no cue found).
  c_prefix_<p> (3 probes): attached prefixes -- ولا (و+لا),
     ولم (و+لم), بلا (ب+لا) -- revoke. Pre-seam BREAK.
  c_judge_native_countermands: genuine Arabic countermands through
     the native _negated_verb judge -> all fire (incl. a و+لا
     prefixed cue). Pre-seam BREAK (no Arabic verbs/cues).
  c_judge_wrong_predicate_silent: negated verb that is not the
     action's verb, affirmations -> judge silent.
  c_scope_split_silent / c_scope_period_silent /
  c_scope_question_silent: "لم يصدر تقرير Q3؛/؟/. أرسل التقرير"
     -> SILENT (cue scopes over "يصدر", the SEND verb sits in a
     cue-less clause -- wave-147 discipline). Pre-seam these BREAK
     the other way: the verb is invisible, so the scope function
     conservatively returns True; post-seam the verb is visible
     AND the clause discipline holds.
  c_scope_class_fires: in-window cue + class verb -> revokes
     natively (pre-seam HELD-vacuous via the conservative no-verb
     path; post-seam HELD-sharp).
  c_scope_delete_split_silent: DELETE analogue of the split
     silence.
  c_lookalike_boundaries: regex-level scan of word-internal
     lookalikes (بلاد/سلام/كلام/مال/ألم/لندن) -> 0 cue hits; the
     FP count is reported.
  c_benign_precision: 8 realistic Arabic sentences (affirmations,
     requests, lookalikes) each scoring >= 0.5, all silent; the FP
     count is reported.
  c_maa_ambiguity_documented: EXPECTED -- ما as interrogative
     ("ما رأيك في تقرير Q3؟" = "what do you think of the Q3
     report?") or relative pronoun ("أرسل ما طلبت" = "send what
     you requested") fires the cue. Documented precision boundary
     of the seed pilot: negation-ما is always followed by a
     past-tense verb, but the pilot carries no tense guard, so
     the interrogative/relative uses are indistinguishable at
     this layer. A positional past-tense guard is follow-up work;
     row 7 stays PARTIAL.
  c_fold_length_preserved: fold is length-identical on Arabic
     (incl. a vocalized/tashkeel case), motivating no
     dual-spelling table.
  c_multilingual_green: the seven existing negation batteries plus
     tests/test_intent_slice.py and tests/test_intent_ledger.py
     still pass -- the scope-tokenizer, fold, clause-split, and
     cue additions must not regress Latin/Cyrillic/Devanagari
     behavior byte-identically.
  c_deterministic_x2: byte-identical verdicts across 2 runs.

Honest ceilings (documented, not hidden): Arabic MSA pilot only --
CJK and other non-romanized scripts still miss; closed cue list
(لا/لم/لن/ما/ليس; ليس has no inflection coverage -- "ليست"
does not cue); dialectal forms untouched (Egyptian ما...ش,
Levantine ما عم, etc.); verb-class coverage is SEND/DELETE/SHARE
ONLY -- ARCHIVE/REDACT/PUBLISH/FORWARD/UPLOAD have no Arabic forms
(documented residual); hamza spelling variants beyond the carried
forms (أرسل/ارسل, إرسال/ارسال) are a closed-list boundary;
quantifier blindness persists; the judge has no share tool (SHARE
Arabic forms live in the similarity-countermand scope path only
-- same as Latin/Cyrillic/Devanagari); the ما interrogative/
relative ambiguity is a known FP (c_maa_ambiguity_documented);
row 7 stays PARTIAL.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Real product code
(gov.intent_ledger, gov.intent_slice), no stubs.

Run:
  mkdir -p /tmp/gov-ar-neg
  TMPDIR=/tmp/gov-ar-neg ~/workspace/.gov-venv/bin/python \\
      evals/arabic_negation_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-ar-neg2 \\
      ~/workspace/.gov-venv/bin/python \\
      evals/arabic_negation_probes.py
"""

import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-ar-neg-%d" % os.getpid())

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.intent_ledger import similarity_countermand  # noqa: E402
from gov.intent_slice import (  # noqa: E402
    _NEGATION_RE, _fold_accents, _negated_verb, negation_scopes_grant)
from gov.target_match import target_similarity  # noqa: E402

SEND_GRANT = "Send the Q3 report to the vendor."
DELETE_GRANT = "Delete the Q3 report."
SHARE_GRANT = "Share the Q3 report with the vendor."
THRESHOLD = 0.5  # explicit: these probes test the cue, not calibration

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-32s %-10s %s" % (name, verdict, detail))


def _sc(message, priors):
    fired, _, score = similarity_countermand(
        message, priors, threshold=THRESHOLD)
    return fired, score


# ------------------------------------------------- fire matrix: 5 cues x 3 classes
# Each cue x each covered verb class -> must revoke on the
# similarity-countermand path. Pre-seam: all BREAK (no cue found,
# the gate never consults similarity).
_FIRE_MATRIX = [
    # (probe suffix, message, grant)
    ("send_laa", "لا ترسل تقرير Q3", SEND_GRANT),
    ("send_lam", "لم يتم إرسال تقرير Q3", SEND_GRANT),
    ("send_lan", "لن ترسل تقرير Q3", SEND_GRANT),
    ("send_maa", "ما تم إرسال تقرير Q3", SEND_GRANT),
    ("send_laysa", "ليس هناك إرسال لتقرير Q3", SEND_GRANT),
    ("delete_laa", "لا تحذف تقرير Q3", DELETE_GRANT),
    ("delete_lam", "لم يتم حذف تقرير Q3", DELETE_GRANT),
    ("delete_lan", "لن تحذف تقرير Q3", DELETE_GRANT),
    ("delete_maa", "ما تم حذف تقرير Q3", DELETE_GRANT),
    ("delete_laysa", "ليس هناك حذف لتقرير Q3", DELETE_GRANT),
    ("share_laa", "لا تشارك تقرير Q3", SHARE_GRANT),
    ("share_lam", "لم تتم مشاركة تقرير Q3", SHARE_GRANT),
    ("share_lan", "لن تشارك تقرير Q3", SHARE_GRANT),
    ("share_maa", "ما تمت مشاركة تقرير Q3", SHARE_GRANT),
    ("share_laysa", "ليس هناك مشاركة لتقرير Q3", SHARE_GRANT),
]

_PREFIX_MATRIX = [
    # Attached prefixes before the cue (the و/ب/ل pilot discipline).
    ("prefix_wa_laa", "ولا ترسل تقرير Q3", SEND_GRANT),     # و+لا
    ("prefix_wa_lam", "ولم يتم إرسال تقرير Q3", SEND_GRANT),  # و+لم
    ("prefix_ba_laa", "بلا إرسال لتقرير Q3", SEND_GRANT),   # ب+لا
]


def c_fire_matrix():
    for suffix, msg, grant in _FIRE_MATRIX + _PREFIX_MATRIX:
        name = "c_%s_revokes" % suffix
        fired, score = _sc(msg, [grant])
        if fired:
            _record(name, "HELD", "%r revokes (%.3f)" % (msg, score))
        else:
            _record(name, "BREAK",
                    "countermand did not revoke: %r (%.3f)"
                    % (msg, score))


# ------------------------------------------------- native judge
_JUDGE_COUNTERMANDS = [
    ("لا ترسل تقرير Q3", "send_email"),        # SEND + لا
    ("لم يتم إرسال تقرير Q3", "send_email"),  # SEND + لم
    ("لن ترسل تقرير Q3", "send_email"),       # SEND + لن
    ("ولا تحذف تقرير Q3", "delete_file"),     # DELETE + و+لا prefix
    ("لا تحذف تقرير Q3", "delete_file"),      # DELETE + لا
    ("لم يتم حذف تقرير Q3", "delete_file"),   # DELETE + لم
    ("ليس هناك حذف لتقرير Q3", "delete_file"),  # DELETE + ليس
]

_JUDGE_SILENCES = [
    ("لا ترسل تقرير Q3", "delete_file"),   # negated SEND, tool DELETE
    ("لا تحذف تقرير Q3", "send_email"),    # negated DELETE, tool SEND
    ("تم إرسال تقرير Q3", "send_email"),   # affirmation
    ("أرسل تقرير Q3 من فضلك", "send_email"),  # request
]


def c_judge_native_countermands():
    name = "c_judge_native_countermands"
    bad = [(t, tool) for t, tool in _JUDGE_COUNTERMANDS
           if not _negated_verb(t, tool)]
    if not bad:
        _record(name, "HELD",
                "%d genuine Arabic countermands fire the native "
                "judge (SEND/DELETE x لا/لم/لن/ليس, incl. a و+لا "
                "prefix)" % len(_JUDGE_COUNTERMANDS))
    else:
        _record(name, "BREAK",
                "judge silent on %d countermand(s): %s"
                % (len(bad), "; ".join("%s/%s" % b for b in bad)))


def c_judge_wrong_predicate_silent():
    name = "c_judge_wrong_predicate_silent"
    bad = [(t, tool) for t, tool in _JUDGE_SILENCES
           if _negated_verb(t, tool)]
    if not bad:
        _record(name, "HELD",
                "%d wrong-predicate/affirmation cases silent in the "
                "judge" % len(_JUDGE_SILENCES))
    else:
        _record(name, "BREAK",
                "judge fired on %d non-countermand(s): %s"
                % (len(bad), "; ".join("%s/%s" % b for b in bad)))


# ------------------------------------------------- scope window
def c_scope_split_silent():
    name = "c_scope_split_silent"
    msg = "لم يصدر تقرير Q3؛ أرسل التقرير"
    if not negation_scopes_grant(msg, SEND_GRANT):
        _record(name, "HELD",
                "cue scopes over \"يصدر\", SEND verb in a cue-less "
                "clause: silent")
    else:
        _record(name, "BREAK",
                "false revocation: cue leaked across the clause "
                "boundary")


def c_scope_period_silent():
    name = "c_scope_period_silent"
    msg = "لم يصدر تقرير Q3. أرسل التقرير"
    if not negation_scopes_grant(msg, SEND_GRANT):
        _record(name, "HELD", "period is a clause boundary: silent")
    else:
        _record(name, "BREAK",
                "false revocation across the period boundary")


def c_scope_question_silent():
    name = "c_scope_question_silent"
    # The Arabic question mark ؟ (U+061F) is a clause boundary
    # (wave-152, parallel to the Devanagari danda).
    msg = "لم يصدر تقرير Q3؟ أرسل التقرير"
    if not negation_scopes_grant(msg, SEND_GRANT):
        _record(name, "HELD",
                "Arabic ؟ is a clause boundary: silent")
    else:
        _record(name, "BREAK",
                "false revocation across the ؟ boundary")


def c_scope_delete_split_silent():
    name = "c_scope_delete_split_silent"
    msg = "لم يصدر تقرير Q3؛ احذف المسودة"
    if not negation_scopes_grant(msg, DELETE_GRANT):
        _record(name, "HELD", "DELETE clause-split cue stays silent")
    else:
        _record(name, "BREAK",
                "false revocation: DELETE cue leaked across clauses")


def c_scope_class_fires():
    name = "c_scope_class_fires"
    cases = [
        ("لا ترسل تقرير Q3", SEND_GRANT, True),
        ("لا تحذف تقرير Q3", DELETE_GRANT, True),
        ("لا تشارك تقرير Q3", SHARE_GRANT, True),
        ("ولا ترسل تقرير Q3", SEND_GRANT, True),  # و+لا prefix
    ]
    bad = [(m, a) for m, a, w in cases
           if negation_scopes_grant(m, a) != w]
    if not bad:
        _record(name, "HELD",
                "%d in-window cue+verb cases revoke natively "
                "(SEND/DELETE/SHARE)" % len(cases))
    else:
        _record(name, "BREAK",
                "scope discipline failed: %s"
                % "; ".join("%s <- %s" % b for b in bad))


# ------------------------------------------------- boundaries, benign
_LOOKALIKES = [
    # Word-internal occurrences of cue substrings: the \b guards
    # must hold on every one.
    "بلاد",    # country: ب+لا inside a word
    "سلام",    # peace: لا inside
    "كلام",    # speech: لا inside
    "مال",     # money: ما inside
    "ألم",     # pain: لم inside
    "لندن",    # London: لن inside
]


def c_lookalike_boundaries():
    name = "c_lookalike_boundaries"
    hits = [(w, _NEGATION_RE.search(w).group(0))
            for w in _LOOKALIKES if _NEGATION_RE.search(w)]
    if not hits:
        _record(name, "HELD",
                "0 cue hits on %d word-internal lookalikes "
                "(بلاد/سلام/كلام/مال/ألم/لندن)" % len(_LOOKALIKES))
    else:
        _record(name, "BREAK",
                "%d FP cue hit(s): %s"
                % (len(hits), "; ".join("%s->%s" % h for h in hits)))


_BENIGN_ARABIC = [
    # Ordinary Arabic prose about the Q3 report with NO negation
    # intent. Every sentence scores >= 0.5 against the grant, so a
    # cue hit here would be a REAL false revocation.
    "أرسل تقرير Q3 من فضلك",          # request (affirmation)
    "تم إرسال تقرير Q3",              # affirmation
    "تقرير Q3 جاهز للإرسال",          # ready for sending
    "سلام، هل أرسلت تقرير Q3؟",       # سلام-lookalike + question
    "تقرير Q3 عن بلاد الشام جاهز",    # بلاد-lookalike
    "لندن توافق على تقرير Q3",        # لندن-lookalike
    "كلام جميل عن تقرير Q3",          # كلام-lookalike
    "تم حذف مسودة تقرير Q3",          # affirmation (DELETE)
]


def c_benign_precision():
    name = "c_benign_precision"
    bad = []
    low_sim = []
    min_score = 1.0
    for s in _BENIGN_ARABIC:
        # The raw similarity (not the gated 0.0): a cue hit here
        # would be a REAL false revocation only if sim >= 0.5.
        sim = target_similarity(s, SEND_GRANT)
        min_score = min(min_score, sim)
        if sim < THRESHOLD:
            low_sim.append("%s (%.3f)" % (s, sim))
        fired, _ = _sc(s, [SEND_GRANT])
        if fired:
            bad.append(s)
    if low_sim:
        _record(name, "BREAK",
                "benign sentence(s) below the similarity bar "
                "(silence would be vacuous): %s"
                % "; ".join(low_sim))
    elif not bad:
        _record(name, "HELD",
                "%d benign Arabic sentences silent (0 FPs; min "
                "raw similarity %.3f >= 0.5)" % (len(_BENIGN_ARABIC),
                                                 min_score))
    else:
        _record(name, "BREAK",
                "%d false revocation(s): %s"
                % (len(bad), "; ".join(bad)))


def c_maa_ambiguity_documented():
    name = "c_maa_ambiguity_documented"
    if _NEGATION_RE.search("ما") is None:
        # Pre-seam: the ما cue is absent, so the boundary is not
        # demonstrable -- a valid red signal, not a discipline
        # change.
        _record(name, "BREAK", "pre-seam: ما cue absent, boundary "
                "not demonstrable")
        return
    # EXPECTED: ما as interrogative ("what") or relative pronoun
    # fires the cue -- the pilot carries no tense guard, so the
    # interrogative/relative uses are indistinguishable from
    # negation-ما at this layer. Documented precision boundary of
    # the seed pilot (a positional past-tense guard is follow-up
    # work); the benign corpus above stays ما-free so its 0-FP
    # pin is honest.
    cases = [
        ("ما رأيك في تقرير Q3؟", SEND_GRANT),   # "what do you think?"
        ("أرسل ما طلبت في تقرير Q3", SEND_GRANT),  # "send what you asked"
    ]
    fired = [(m, "%.3f" % _sc(m, [g])[1]) for m, g in cases
             if _sc(m, [g])[0]]
    if len(fired) == len(cases):
        _record(name, "EXPECTED",
                "ما interrogative/relative fires (%s) -- documented "
                "precision boundary; negation-ما is always followed "
                "by a past-tense verb, but the pilot carries no "
                "tense guard" % ", ".join(s for _, s in fired))
    elif not fired:
        _record(name, "BREAK",
                "ما ambiguity unexpectedly silent -- cue discipline "
                "changed?")
    else:
        _record(name, "BREAK",
                "inconsistent ما behavior: %r" % (fired,))


def c_fold_length_preserved():
    name = "c_fold_length_preserved"
    cases = ["لا ترسل", "لم", "لن", "ما", "ليس", "أرسل", "إرسال",
             "مشاركة", "لا ترسل تقرير Q3",
             "مُرسَل",  # vocalized (tashkeel): must not shrink
             ]
    bad = [s for s in cases if len(_fold_accents(s)) != len(s)]
    # Pin the no-op: standard Arabic has no NFKD decomposition, so
    # no dual-spelling class table is needed (unlike Cyrillic ё/й).
    norm_ok = (_fold_accents("أرسل") == "أرسل"
               and _fold_accents("إرسال") == "إرسال")
    if not bad and norm_ok:
        _record(name, "HELD",
                "fold length-identical on %d Arabic cases "
                "(tashkeel preserved; cue-span alignment holds)" %
                len(cases))
    else:
        _record(name, "BREAK",
                "fold broke length or normalization: %r norm_ok=%r"
                % (bad, norm_ok))


MULTILINGUAL_BATTERIES = [
    "countermand_multilingual_negation_probes.py",
    "countermand_negation_inflection_probes.py",
    "cyrillic_negation_probes.py",
    "double_negation_probes.py",
    "negation_precision_probes.py",
    "negation_scope_probes.py",
    "negation_verb_tier2_probes.py",
]

UNIT_TESTS = [
    "tests.test_intent_slice",
    "tests.test_intent_ledger",
]


def c_multilingual_green():
    name = "c_multilingual_green"
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 nesting discipline (2026-09-28): skip our own adjacency
        # green check when running as a nested child; the parent already
        # ran our red probes. Standalone runs still execute the full check.
        _record(name, "HELD",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); "
                "run standalone for full depth-1 adjacency")
        return
    failures = []
    for i, battery in enumerate(MULTILINGUAL_BATTERIES):
        tmp = os.path.join(os.environ["TMPDIR"], "ml-%d" % i)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmp)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        # Depth-1 nesting discipline (2026-09-28): children run their red
        # probes but skip their own green checks.
        env["GOV_SKIP_GREEN"] = "1"
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
    for i, mod in enumerate(UNIT_TESTS):
        tmp = os.path.join(os.environ["TMPDIR"], "ut-%d" % i)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmp)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", mod],
            capture_output=True, text=True, env=env, cwd=REPO_ROOT,
            timeout=600)
        if proc.returncode != 0:
            err_tail = proc.stderr.strip().splitlines()
            err_tail = err_tail[-1] if err_tail else ""
            failures.append("%s -> rc=%d (%s)"
                            % (mod, proc.returncode, err_tail))
    if not failures:
        _record(name, "HELD",
                "%d existing negation batteries + %d unit suites green"
                % (len(MULTILINGUAL_BATTERIES), len(UNIT_TESTS)))
    else:
        _record(name, "BREAK",
                "regressions: %s" % "; ".join(failures))


def _run_all():
    global _RESULTS
    _RESULTS = []
    c_fire_matrix()
    c_judge_native_countermands()
    c_judge_wrong_predicate_silent()
    c_scope_split_silent()
    c_scope_period_silent()
    c_scope_question_silent()
    c_scope_delete_split_silent()
    c_scope_class_fires()
    c_lookalike_boundaries()
    c_benign_precision()
    c_maa_ambiguity_documented()
    c_fold_length_preserved()
    c_multilingual_green()
    return list(_RESULTS)


def c_deterministic_x2():
    name = "c_deterministic_x2"
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
    c_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("arabic_negation_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
