#!/usr/bin/env python3
"""Row-7 native negation-cue expansion battery (wave-165 lane).

Row-7 residual: the negation cue list (``gov.intent_slice._NEGATION_RE``)
was Latin-centric plus pilots for Devanagari (w149), Russian Cyrillic
(w151), Arabic MSA (w152), and CJK Mandarin/Japanese/Korean (w153). A
countermand written with a native cue from Spanish, Portuguese,
Italian, Ukrainian, formal Mandarin (请勿), Japanese plain prohibitive
(送るな), Arabic ليست, or colloquial Hindi ना carried NO recognizable
cue: the similarity-countermand gate never opened and the countermand
executed silently.

This battery is RED-first: pre-fix every fire probe below is BREAK (no
cue found -> gate returns (False, None, 0.0)). Post-fix they are HELD.

New cues (wave-165):
  Spanish:      nunca, jamás/jamas, tampoco
  Portuguese:   não, nem, tampouco (+ nunca/jamás shared)
  Italian:      niente, nessuno, né, nemmeno, neppure
  Ukrainian:    ні (U+0456), заборонено (не already covered by Russian)
  Mandarin:     请勿 (formal "please do not")
  Japanese:     るな plain prohibitive, narrowed to るな-not-followed-
                by-kana/kanji (the はるなに/Haruna FP)
  Arabic:       ليست (feminine "is not")
  Hindi:        ना (colloquial "don't"; नहीं|ना|न|मत alternation order)

Measured exclusions (wave-142 "non"/"mat" precedent -- each suppressed
hit below was a REAL false revocation at the gate):
  - Italian "mai" DROPPED: "Mai sent the Q3 report to the vendor."
    scores 0.800 with a cue hit (Mai is a personal name; German "Mai"
    = May is the same shape).
  - "ni" DROPPED (ES/FR "neither/nor"): "Ni from compliance approved"
    scores 0.842 (Ni is a romanized surname).
  - Italian "non" stays DROPPED (wave-142 "non-profit" measurement).
  - Unaccented "nao" DROPPED (the "NAO" robot reads as a cue).
  - Bare るな substring NARROWED (see above).

Documented residuals (pinned EXPECTED, not claimed):
  - Reverse glue (native cue glued to a native verb with zero
    whitespace: "неотправляйте", "لاترسل"): the F188 fix is
    one-directional by design (Latin cue -> non-Latin verb).
  - Emphatic 送るなよ (な followed by hiragana): residual of the るな
    narrowing.
  - Vocalized Arabic, dialectal Arabic, Mandarin 没, paraphrase-level
    evasion: untouched.

Probe map (explicit threshold=0.5 throughout -- these probes test the
cue, not threshold calibration, per the wave-145 derived-band lesson):
  n_<lang>_<cue>_revokes: fire matrix -- each new cue x a covered verb
     class -> revokes on the similarity-countermand path.
  n_scope_<lang>: cue within the scope window of the anchor's verb ->
     negation_scopes_grant True; cue in a separate clause -> silent.
  n_judge_wiring: new Latin cues fullmatch in the judge's pre-verb
     window when a Latin-stem verb is present ("Nunca send ...").
  n_judge_runa: "Q3レポートを送るな" negates send_email in the judge
     via the form-anchored るな branch; "はるなに..." stays silent.
  n_glued_latin_cue: "nunca发送" fires via the inherited F188 end
     boundary (Latin cue glued to a non-Latin verb).
  n_lookalikes: word-internal lookalikes stay silent (0 cue hits).
  n_benign_precision: realistic benign sentences (incl. the Mai/Ni/
     Haruna/NAO shapes) scoring >= 0.5 stay silent.
  n_dropped_silent: mai/ni/non/nao carry no cue (exclusions pinned).
  n_reverse_glue_expected: EXPECTED -- reverse glue still misses.
  n_multilingual_green: all prior negation batteries + unit suites.
  n_deterministic_x2.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Real product code
(gov.intent_ledger, gov.intent_slice), no stubs.

Run:
  mkdir -p /tmp/gov-nat-cue
  TMPDIR=/tmp/gov-nat-cue ~/workspace/.gov-venv/bin/python \\
      evals/row7_native_cue_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-nat-cue2 \\
      ~/workspace/.gov-venv/bin/python evals/row7_native_cue_probes.py
"""

import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-nat-cue-%d" % os.getpid())

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.intent_ledger import similarity_countermand  # noqa: E402
from gov.intent_slice import (  # noqa: E402
    _NEGATION_RE, _negated_verb, negation_scopes_grant)
from gov.target_match import target_similarity  # noqa: E402

SEND_GRANT = "Send the Q3 report to the vendor."
DELETE_GRANT = "Delete the Q3 report."
ARCHIVE_GRANT = "Archive the Q3 report."
THRESHOLD = 0.5  # explicit: these probes test the cue, not calibration

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-34s %-10s %s" % (name, verdict, detail))


def _sc(message, priors):
    fired, _, score = similarity_countermand(
        message, priors, threshold=THRESHOLD)
    return fired, score


# ------------------------------------------------- fire matrix
# Each new cue x a covered verb class -> must revoke on the
# similarity-countermand path. Pre-fix: all BREAK (no cue found, the
# gate never consults similarity). Similarity-validity of every probe
# was measured pre-battery via gov.target_match.target_similarity
# (all >= 0.5); the gate short-circuits the score to 0.0 when no cue
# is found, so a post-fix fire proves the cue opened the gate.
_FIRE_MATRIX = [
    # Spanish (tuned for token overlap: report/vendor shared)
    ("es_nunca", "Nunca env\u00edes el Q3 report al vendor", SEND_GRANT),
    ("es_jamas", "Jam\u00e1s env\u00edes el Q3 report al vendor", SEND_GRANT),
    ("es_jamas_unacc", "Jamas envies el Q3 report al vendor", SEND_GRANT),
    ("es_tampoco", "Tampoco env\u00edes el Q3 report al vendor",
     SEND_GRANT),
    ("es_tampoco_del", "Tampoco elimines el Q3 report", DELETE_GRANT),
    # Portuguese
    ("pt_nao", "Q3 relat\u00f3rio n\u00e3o envies ao vendor", SEND_GRANT),
    ("pt_nem", "Q3 relat\u00f3rio nem envies ao vendor", SEND_GRANT),
    ("pt_tampouco", "Q3 relat\u00f3rio tampouco envies ao vendor",
     SEND_GRANT),
    # Italian
    ("it_niente", "Q3 report niente invio", SEND_GRANT),
    ("it_nessuno", "Q3 report nessuno invii", SEND_GRANT),
    ("it_ne", "Q3 report n\u00e9 inviare n\u00e9 archiviare", SEND_GRANT),
    ("it_nemmeno", "Q3 report nemmeno inviare", SEND_GRANT),
    ("it_neppure", "Q3 report neppure archiviare", ARCHIVE_GRANT),
    # Ukrainian
    ("uk_ni", "Q3 зв\u0456т н\u0456 в якому раз\u0456", SEND_GRANT),
    ("uk_zabor", "Q3 зв\u0456т в\u0456дправляти заборонено", SEND_GRANT),
    # Mandarin
    ("zh_qingwu", "Q3\u62a5\u544a\u8bf7\u52ff\u53d1\u9001", SEND_GRANT),
    # Japanese plain prohibitive
    ("ja_runa_send", "Q3\u30ec\u30dd\u30fc\u30c8\u3092\u9001\u308b\u306a",
     SEND_GRANT),
    ("ja_runa_del", "Q3\u30ec\u30dd\u30fc\u30c8\u3092\u524a\u9664\u3059\u308b\u306a",
     DELETE_GRANT),
    # Arabic
    ("ar_laystat", "Q3 \u0627\u0644\u062a\u0642\u0631\u064a\u0631 \u0644\u064a\u0633\u062a \u062c\u0627\u0647\u0632\u0629",
     SEND_GRANT),
    # Hindi
    ("hi_naa", "Q3 \u0930\u093f\u092a\u094b\u0930\u094d\u091f \u0928\u093e \u092d\u0947\u091c\u0947\u0902",
     SEND_GRANT),
]


def n_fire_matrix():
    for suffix, msg, grant in _FIRE_MATRIX:
        name = "n_%s_revokes" % suffix
        fired, score = _sc(msg, [grant])
        if fired:
            _record(name, "HELD", "%r revokes (%.3f)" % (msg, score))
        else:
            _record(name, "BREAK",
                    "countermand did not revoke: %r (%.3f)" % (msg, score))


# ------------------------------------------------- scope discipline
def n_scope_window():
    # Cue within the window of the anchor's verb -> revokes.
    msg = "Nunca env\u00edes el Q3 report al vendor"
    if negation_scopes_grant(msg, SEND_GRANT):
        _record("n_scope_es_window", "HELD", "cue scopes the grant verb")
    else:
        _record("n_scope_es_window", "BREAK", "in-window cue missed")
    # Cue in a separate clause from the grant verb -> silent.
    # "env\u00eda" folds to "envia" (SEND class); the nunca clause
    # carries no grant verb.
    msg2 = "Nunca hay problema; env\u00eda el Q3 report al vendor"
    if not negation_scopes_grant(msg2, SEND_GRANT):
        _record("n_scope_es_split_silent", "HELD",
                "cross-clause cue stays silent")
    else:
        _record("n_scope_es_split_silent", "BREAK",
                "cue leaked across the clause boundary: %r" % msg2)
    # Ukrainian split-clause silence: the ні cue sits in its own
    # clause while a Russian SEND-class verb (отправьте) carries the
    # grant in another clause. (Ukrainian verb forms are not in the
    # class table -- Russian-only per wave-151 -- so the probe uses
    # the Russian form to test that the new cue participates in
    # scope discipline.)
    msg3 = "Ні! Q3 отчёт готов; отправьте его vendor."
    if not negation_scopes_grant(msg3, SEND_GRANT):
        _record("n_scope_uk_split_silent", "HELD",
                "cross-clause cue stays silent")
    else:
        _record("n_scope_uk_split_silent", "BREAK",
                "cue leaked across the clause boundary")


# ------------------------------------------------- judge wiring
def n_judge_wiring():
    # New Latin cues fullmatch in the judge's pre-verb window when a
    # Latin-stem verb is present (wiring check, not a realism claim).
    if _negated_verb("Nunca send the Q3 report", "send_email"):
        _record("n_judge_latin_cue_window", "HELD",
                "nunca fullmatches in the pre-verb window")
    else:
        _record("n_judge_latin_cue_window", "BREAK",
                "new Latin cue missed the judge window")
    # Japanese るな: form-anchored branch fires the judge...
    if _negated_verb("Q3\u30ec\u30dd\u30fc\u30c8\u3092\u9001\u308b\u306a",
                      "send_email"):
        _record("n_judge_runa_fires", "HELD",
                "送るな negates send_email in the judge")
    else:
        _record("n_judge_runa_fires", "BREAK", "るな missed the judge")
    # ...while the Haruna sentence stays silent in the judge too.
    if not _negated_verb(
            "Q3\u30ec\u30dd\u30fc\u30c8\u3092\u306f\u308b\u306a\u306b"
            "\u9001\u3063\u3066\u304f\u3060\u3055\u3044", "send_email"):
        _record("n_judge_haruna_silent", "HELD",
                "はるなに stays silent in the judge")
    else:
        _record("n_judge_haruna_silent", "BREAK",
                "Haruna FP in the judge")


# ------------------------------------------------- F188 inheritance
def n_glued_latin_cue():
    # New Latin cues inherit the F188 script-transition end boundary:
    # a Spanish cue glued to a non-Latin verb cues on the search path.
    msg = "nunca\u53d1\u9001Q3\u62a5\u544a"
    hits = [m.group(0) for m in _NEGATION_RE.finditer(msg)]
    if hits:
        _record("n_glued_nunca_fasong", "HELD",
                "nunca glued to 发送 cues: %r" % hits[0])
    else:
        _record("n_glued_nunca_fasong", "BREAK",
                "new Latin cue missed the glued boundary")


# ------------------------------------------------- lookalike boundaries
_LOOKALIKES = [
    # (text, must_have_zero_cue_hits, note)
    ("pyjamas", True, "jamas inside pyjamas"),
    ("Jamason", True, "Jamas as name prefix"),
    ("nemo", True, "nem inside nemo"),
    ("anemone", True, "nem inside anemone"),
    ("niente affatto", False, "genuine niente fires"),
    ("\u043d\u0456\u0431\u0438", True, "Ukrainian ніби (as if)"),
    ("Q3 \u043d\u0456\u0447\u043d\u0438\u0439 \u0437\u0432\u0456\u0442", True,
     "нічний (night) -- no cue"),
    ("\u0644\u064a\u0633\u062a\u0627\u0646", True, "Arabic lookalike"),
    ("\u0905\u092a\u0928\u093e", True, "अपना (own) -- ना guarded"),
    ("\u0928\u093e\u0924\u093e", True, "नाता (relation) -- ना guarded"),
    ("\u092e\u0924\u0932\u092c", True, "मतलब (meaning) -- मत guarded"),
    ("Q3\u62a5\u544a\u8bf7\u52ff\u53d1\u9001", False, "genuine 请勿 fires"),
]


def n_lookalike_boundaries():
    fps = 0
    for text, silent, note in _LOOKALIKES:
        hits = [m.group(0) for m in _NEGATION_RE.finditer(text)]
        if silent and hits:
            fps += 1
            _record("n_lookalike_fp", "BREAK",
                    "%r cued (%s): %r" % (text, note, hits[0]))
        elif not silent and not hits:
            fps += 1
            _record("n_lookalike_miss", "BREAK",
                    "genuine cue missed: %r (%s)" % (text, note))
    if fps == 0:
        _record("n_lookalike_boundaries", "HELD",
                "0 FP on %d lookalikes; genuine cues fire" % len(_LOOKALIKES))


# ------------------------------------------------- benign precision
# Every sentence scores >= 0.5 against the grant, so a cue hit would
# be a REAL false revocation (wave-145 discipline).
_BENIGN = [
    ("Mai sent the Q3 report to the vendor.", SEND_GRANT,
     "Mai name vs dropped mai"),
    ("Mai, please send the Q3 report to the vendor.", SEND_GRANT,
     "vocative Mai"),
    ("Send the Q3 report to the vendor in May.", SEND_GRANT,
     "May vs dropped mai"),
    ("The nickel vendor sent the Q3 report.", SEND_GRANT,
     "nickel vs dropped ni"),
    ("Q3\u30ec\u30dd\u30fc\u30c8\u3092\u306f\u308b\u306a\u306b"
     "\u9001\u3063\u3066\u304f\u3060\u3055\u3044", SEND_GRANT,
     "Haruna recipient vs narrowed るな"),
    ("\u306f\u308b\u306a\u3055\u3093\u304cQ3\u30ec\u30dd\u30fc\u30c8\u3092"
     "\u9001\u308a\u307e\u3057\u305f", SEND_GRANT,
     "Haruna subject vs narrowed るな"),
    ("The NAO robot sent the Q3 report.", SEND_GRANT,
     "NAO robot vs dropped nao"),
    ("Our non-profit partner sent the Q3 report.", SEND_GRANT,
     "non-profit vs dropped non"),
    ("No problem -- send the Q3 report to the vendor.", SEND_GRANT,
     "wave-145 no-problem guard"),
    ("Not only send the Q3 report, but archive it.", SEND_GRANT,
     "wave-145 not-only guard"),
    ("Q3 \u0930\u093f\u092a\u094b\u0930\u094d\u091f \u092d\u0947\u091c\u0928\u093e "
     "\u092e\u0924\u0932\u092c \u0938\u092e\u091d\u093e\u090f\u0901", SEND_GRANT,
     "मतलब inside benign Hindi"),
]


def n_benign_precision():
    fps = 0
    for msg, grant, note in _BENIGN:
        sim = target_similarity(msg, grant)
        fired, _ = _sc(msg, [grant])
        if sim < THRESHOLD:
            _record("n_benign_lowsim", "ERROR",
                    "benign probe below gate: %r (%.3f)" % (msg, sim))
            fps += 1
        elif fired:
            fps += 1
            _record("n_benign_fp", "BREAK",
                    "FALSE revocation (%.3f): %r [%s]" % (sim, msg, note))
    if fps == 0:
        _record("n_benign_precision", "HELD",
                "0 FP on %d benign sentences (all >= 0.5)" % len(_BENIGN))


# ------------------------------------------------- dropped exclusions pinned
def n_dropped_silent():
    for cue_word, note in [("mai", "Mai-name FP"), ("ni", "Ni-surname FP"),
                           ("non", "wave-142 non-profit"),
                           ("nao", "NAO-robot FP")]:
        hits = [m.group(0) for m in
                _NEGATION_RE.finditer("x %s x" % cue_word)]
        # "ne" is a pre-existing French cue and WILL hit inside "ne";
        # check the exact word only.
        exact = [h for h in hits if h.lower() == cue_word]
        if cue_word == "ne":
            continue
        if not exact:
            _record("n_dropped_%s_silent" % cue_word, "HELD",
                    "%s carries no cue (%s)" % (cue_word, note))
        else:
            _record("n_dropped_%s_silent" % cue_word, "BREAK",
                    "dropped cue %r fires!" % cue_word)


# ------------------------------------------------- documented residuals
def n_reverse_glue_expected():
    # EXPECTED: reverse glue (native cue glued to a native verb) is
    # not the F188 shape; the F188 fix is one-directional by design.
    for msg, grant in [
            ("Q3 \u043e\u0442\u0447\u0451\u0442 \u043d\u0435\u043e\u0442\u043f\u0440\u0430\u0432\u043b\u044f\u0439\u0442\u0435",
             SEND_GRANT),
            ("Q3 \u0644\u0627\u062a\u0631\u0633\u0644 \u0627\u0644\u062a\u0642\u0631\u064a\u0631",
             SEND_GRANT)]:
        fired, score = _sc(msg, [grant])
        if not fired:
            _record("n_reverse_glue_expected", "EXPECTED",
                    "still silent (%.3f): %r" % (score, msg[:24]))
        else:
            _record("n_reverse_glue_expected", "BREAK",
                    "reverse glue unexpectedly fires: %r" % msg[:24])
    # EXPECTED: emphatic 送るなよ (な followed by hiragana) is the
    # documented residual of the るな narrowing.
    msg = "Q3\u30ec\u30dd\u30fc\u30c8\u3092\u9001\u308b\u306a\u3088"
    fired, score = _sc(msg, [SEND_GRANT])
    if not fired:
        _record("n_runa_yo_expected", "EXPECTED",
                "送るなよ still silent (%.3f)" % score)
    else:
        _record("n_runa_yo_expected", "BREAK",
                "送るなよ unexpectedly fires")


# ------------------------------------------------- multilingual green
def n_multilingual_green():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 nesting discipline (2026-09-28): when this battery runs
        # as a nested child, skip our own adjacency green check -- the
        # parent already ran our red probes. Standalone runs (var unset)
        # still execute the full check below.
        _record("n_multilingual_green", "HELD",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); "
                "run standalone for full depth-1 adjacency")
        return
    batteries = [
        "evals/countermand_multilingual_negation_probes.py",
        "evals/cyrillic_negation_probes.py",
        "evals/arabic_negation_probes.py",
        "evals/cjk_negation_probes.py",
        "evals/devanagari_negation_probes.py",
        "evals/f188_glued_cue_probes.py",
        "evals/negation_precision_probes.py",
        "evals/negation_scope_probes.py",
        "evals/row7_verb_expansion_probes.py",
        "evals/row7_archive_redact_probes.py",
    ]
    bad = []
    for b in batteries:
        # Every battery exits 1 on any BREAK/ERROR (their docstrings
        # mention "BREAK", so a substring check would false-positive).
        # Wave-112/134 discipline: the per-battery TMPDIR must EXIST
        # (mkdir -p) -- Python 3.12 silently falls back to /tmp for a
        # nonexistent TMPDIR, which shares /tmp/egress_ledger.jsonl
        # across suites and flakes with LedgerUnverifiableError.
        child_tmp = "/tmp/gov-nat-cue-%d-%s" % (
            os.getpid(), os.path.basename(b)[:8])
        os.makedirs(child_tmp, exist_ok=True)
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, b)],
            capture_output=True, text=True,
            env={**os.environ, "TMPDIR": child_tmp,
                 # Depth-1 nesting discipline (2026-09-28): children run
                 # their red probes but skip their own green checks.
                 "GOV_SKIP_GREEN": "1"},
            cwd=REPO_ROOT, timeout=600)
        if p.returncode != 0:
            tail = (p.stdout.strip().splitlines() or [""])[-1]
            bad.append("%s (tail: %s)" % (b, tail[:120]))
    for t in ["tests/test_intent_slice.py", "tests/test_intent_ledger.py"]:
        p = subprocess.run(
            [sys.executable, "-m", "unittest",
             t.replace("/", ".").replace(".py", "")],
            capture_output=True, text=True, cwd=REPO_ROOT, timeout=600)
        if p.returncode != 0:
            bad.append(t)
    if not bad:
        _record("n_multilingual_green", "HELD",
                "%d batteries + 2 unit suites green" % (len(batteries)))
    else:
        _record("n_multilingual_green", "BREAK",
                "regressions: %s" % bad)


def n_deterministic_x2():
    sig1 = [(n_, v) for n_, v, _ in _RESULTS]
    # re-run the fire matrix only (cheap determinism pin)
    sig2 = []
    for suffix, msg, grant in _FIRE_MATRIX:
        fired, _ = _sc(msg, [grant])
        sig2.append(("n_%s_revokes" % suffix, "HELD" if fired else "BREAK"))
    ok = all(s1 == s2 for s1, s2 in zip(sig1[:len(sig2)], sig2))
    _record("n_deterministic_x2", "HELD" if ok else "BREAK",
            "fire matrix byte-identical across runs" if ok
            else "NONDETERMINISM in fire matrix")


def main():
    print("row-7 native negation-cue battery (wave-165 lane)")
    n_fire_matrix()
    n_scope_window()
    n_judge_wiring()
    n_glued_latin_cue()
    n_lookalike_boundaries()
    n_benign_precision()
    n_dropped_silent()
    n_reverse_glue_expected()
    n_multilingual_green()
    n_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("TOTAL: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
