#!/usr/bin/env python3
"""F188: Latin negation cue glued to a non-Latin verb form (zero-
whitespace script boundary) misses the cue search and the native
judge.

F188 (LOW, filed wave-156): ``do not发送Q3报告`` (Latin "do not" +
CJK SEND form 发送, no whitespace) is missed by BOTH countermand
layers -- ``_negated_verb`` returns False AND the scope-path cue
search ``_NEGATION_RE.search`` finds no cue -- so the human-
unambiguous "do not send" never revokes. Verified cross-script
(Cyrillic ``do notотправляйте``, Arabic ``do notأرسل`` identical),
NOT CJK-specific, NOT a lane regression.

Mechanism (two independent misses):
  (1) Scope path: ``_NEGATION_RE``'s Latin alternatives require a
      trailing ``\\b``, but CJK/Cyrillic/Arabic chars are ``\\w`` in
      Unicode regex, so the boundary fails at the Latin->non-Latin
      transition and the cue is never found.
  (2) Judge path: the tokenizer fuses the glued run into one token
      ("not发送"); the Latin branch needs an exact verb-form token
      match (fails) and ``_cjk_token_negates`` only knows CJK cues
      (fails: "not" is Latin).

This battery is RED-first: the glued probes go BREAK while the
cue search misses and the judge stays silent. They flip to HELD
once (1) the trailing ``\\b`` of the Latin cue alternatives also
accepts a Latin->non-Latin script transition, and (2) the judge
gains a glued-cue branch (a Latin cue abutting a non-ASCII native
verb form's left edge).

Explicit threshold=0.5 throughout (wave-145 derived-band lesson:
these probes test the cue/judge, not threshold calibration).

Scope note: ``similarity_countermand`` end-to-end still does NOT
revoke on these garbled inputs -- the measured similarity is
~0.000, below threshold, and similarity alone never countermands
by design (finding severity rationale #3). The fix restores the
cue/judge layers; the stale-intent rubric consumes ``_negated_verb``
directly ("don't delete" -> STALE). The end-to-end similarity
observation is pinned, not a BREAK.

$0 spend, synthetic/local, deterministic. Real product code
(gov.intent_slice, gov.intent_ledger), no stubs.

Run:
  mkdir -p /tmp/gov-f188
  TMPDIR=/tmp/gov-f188 ~/workspace/.gov-venv/bin/python \\
      evals/f188_glued_cue_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-f188b \\
      ~/workspace/.gov-venv/bin/python \\
      evals/f188_glued_cue_probes.py
"""

import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-f188-%d" % os.getpid())

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.intent_ledger import similarity_countermand  # noqa: E402
from gov.intent_slice import (  # noqa: E402
    _NEGATION_RE, _negated_verb, negation_scopes_grant)

SEND_GRANT = "Send the Q3 report to the vendor."
DELETE_GRANT = "Delete the Q3 report."
THRESHOLD = 0.5  # explicit: these probes test the cue/judge, not calibration

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-34s %-10s %s" % (name, verdict, detail))


def _cue_found(text):
    m = _NEGATION_RE.search(text)
    return m.group(0) if m else None


# ------------------------------------------------- cue search: glued
# The scope-path cue gate (_NEGATION_RE.search). Pre-fix every one
# of these returns None: the trailing \b fails at the
# Latin->non-Latin boundary.
_GLUED_CUES = [
    # (probe suffix, message, expected cue text)
    ("cjk_do_not", "do not发送Q3报告", "do not"),
    ("cjk_dont", "don't发送Q3报告", "don't"),
    ("cjk_never", "never删除Q3报告", "never"),
    ("cjk_stop", "stop发送Q3报告", "stop"),
    ("cyrillic_do_not", "do notотправляйте Q3 отчёт", "do not"),
    ("arabic_do_not", "do notأرسل Q3 التقرير", "do not"),
]


def f_cue_glued():
    for suffix, msg, cue in _GLUED_CUES:
        name = "f_cue_glued_%s" % suffix
        found = _cue_found(msg)
        if found is not None and cue in found:
            _record(name, "HELD",
                    "cue %r found in %r" % (found, msg))
        else:
            _record(name, "BREAK",
                    "no cue in %r (found=%r)" % (msg, found))


# ------------------------------------------------- judge: glued
# _negated_verb must fire: the Latin cue abuts a non-ASCII native
# verb form of the tool's class. Pre-fix all False.
_GLUED_JUDGE = [
    # (probe suffix, message, tool)
    ("cjk_do_not", "do not发送Q3报告", "send_email"),
    ("cjk_dont", "don't发送Q3报告", "send_email"),
    ("cjk_never", "never删除Q3报告", "delete_file"),
    ("cjk_stop", "stop发送Q3报告", "send_email"),
    ("cyrillic_do_not", "do notотправляйте Q3 отчёт", "send_email"),
    ("arabic_do_not", "do notأرسل Q3 التقرير", "send_email"),
]


def f_judge_glued():
    for suffix, msg, tool in _GLUED_JUDGE:
        name = "f_judge_glued_%s" % suffix
        if _negated_verb(msg, tool):
            _record(name, "HELD",
                    "judge fires on %r/%s" % (msg, tool))
        else:
            _record(name, "BREAK",
                    "judge silent on %r/%s" % (msg, tool))


# ------------------------------------------------- scope: glued, via a REAL cue
# negation_scopes_grant must return True because the cue is found
# AND the verb is attributed -- not merely via the conservative
# no-verb path. (Pre-fix the CJK case returns False outright; the
# Cyrillic/Arabic cases return True only conservatively, with no
# cue found -- both are BREAK here.)
def f_scope_glued_real_cue():
    cases = [
        ("do not发送Q3报告", SEND_GRANT),
        ("never删除Q3报告", DELETE_GRANT),
    ]
    bad = []
    for msg, grant in cases:
        cue = _cue_found(msg)
        scope = negation_scopes_grant(msg, grant)
        if cue is None or not scope:
            bad.append("%r (cue=%r scope=%r)" % (msg, cue, scope))
    name = "f_scope_glued_real_cue"
    if not bad:
        _record(name, "HELD",
                "%d glued CJK cases: cue found + scope revokes"
                % len(cases))
    else:
        _record(name, "BREAK",
                "scope misses: %s" % "; ".join(bad))


# ------------------------------------------------- guard at the script boundary
# "not only" must NOT cue, even glued to non-Latin text -- the
# wave-145 guard's intent is script-independent. (Pre-fix the
# guard's own \b fails at the boundary and "not" leaks through;
# pinned here so the fix carries the guard across.)
def f_guard_not_only_glued():
    name = "f_guard_not_only_glued"
    found = _cue_found("not only发送Q3报告")
    if found is None:
        _record(name, "HELD",
                "\"not only\" guard holds at the script boundary")
    else:
        _record(name, "BREAK",
                "guard leaked: cue %r found in \"not only发送\""
                % found)


def f_guard_no_problem_glued():
    name = "f_guard_no_problem_glued"
    found = _cue_found("no problem发送Q3报告")
    if found is None:
        _record(name, "HELD",
                "\"no problem\" guard holds at the script boundary")
    else:
        _record(name, "BREAK",
                "guard leaked: cue %r found in \"no problem发送\""
                % found)


# ------------------------------------------------- precision: benign glued text
# Glued Latin+non-Latin WITHOUT negation intent must stay silent.
def f_precision_benign_glued():
    name = "f_precision_benign_glued"
    cases = [
        # (message, tool, why silent)
        ("cannot发送Q3报告", "send_email",
         "\"cannot\" is not a cue (consistent with \"cannot send\")"),
        ("donot发送Q3报告", "send_email",
         "\"donot\" is not a cue (consistent with \"donot send\")"),
        ("do not担心", "send_email",
         "cue present but no SEND verb form"),
        ("do not发送Q3报告", "delete_file",
         "negated SEND, tool DELETE (wrong predicate)"),
        ("Q3报告已发送", "send_email",
         "affirmation, no cue at all"),
    ]
    bad = []
    for msg, tool, why in cases:
        if _negated_verb(msg, tool):
            bad.append("%r/%s fired (%s)" % (msg, tool, why))
    if not bad:
        _record(name, "HELD",
                "%d benign glued cases silent in the judge"
                % len(cases))
    else:
        _record(name, "BREAK",
                "false judge fire: %s" % "; ".join(bad))


def f_precision_benign_cue_search():
    name = "f_precision_benign_cue_search"
    cases = [
        "cannot发送Q3报告",
        "donot发送Q3报告",
        "Q3报告已发送",
        "the vendor通知了",  # no cue word at all
    ]
    bad = [(m, _cue_found(m)) for m in cases
           if _cue_found(m) is not None]
    if not bad:
        _record(name, "HELD",
                "%d benign glued cases yield no cue" % len(cases))
    else:
        _record(name, "BREAK",
                "spurious cue: %s"
                % "; ".join("%r->%r" % b for b in bad))


# ------------------------------------------------- reverse glue + spaced controls
def f_reverse_glue_keeps_firing():
    name = "f_reverse_glue_keeps_firing"
    # CJK cue in a Latin-context token -- fired pre-fix, must keep
    # firing (the finding's documented working direction).
    if _negated_verb("email不要发送", "send_email"):
        _record(name, "HELD", "\"email不要发送\" still fires the judge")
    else:
        _record(name, "BREAK",
                "REGRESSION: \"email不要发送\" went silent")


def f_spaced_controls():
    name = "f_spaced_controls"
    cases = [
        ("do not 发送Q3报告", SEND_GRANT),
        ("do not отправляйте Q3 отчёт", SEND_GRANT),
    ]
    bad = []
    for msg, grant in cases:
        if _cue_found(msg) is None or \
                not negation_scopes_grant(msg, grant):
            bad.append(msg)
    if not bad:
        _record(name, "HELD",
                "%d spaced controls: cue found + scope revokes"
                % len(cases))
    else:
        _record(name, "BREAK",
                "spaced control broke: %s" % "; ".join(bad))


# ------------------------------------------------- end-to-end similarity: pinned
def f_similarity_observability():
    name = "f_similarity_observability"
    # The cue gate must now PASS (fired, score measured) while the
    # similarity threshold still -- correctly -- blocks revocation
    # on the ~0.000-similarity garbled input. This is the finding's
    # severity rationale #3, pinned as designed behavior, NOT a
    # BREAK: the cue/judge layers are restored; similarity alone
    # never countermands.
    fired, _, score = similarity_countermand(
        "do not发送Q3报告", [SEND_GRANT], threshold=THRESHOLD)
    cue = _cue_found("do not发送Q3报告")
    if cue is not None and not fired and score < THRESHOLD:
        _record(name, "HELD",
                "cue gate passes (%r), similarity %.3f < %.2f "
                "correctly blocks: layers restored, no bypass"
                % (cue, score, THRESHOLD))
    else:
        _record(name, "BREAK",
                "unexpected end-to-end state: cue=%r fired=%r "
                "score=%.3f" % (cue, fired, score))


# ------------------------------------------------- invisible-format discipline
def f_zero_width_still_stripped():
    name = "f_zero_width_still_stripped"
    # F183: a zero-width char inside the glued cue must not break
    # the fix -- stripping restores the visible text.
    msg = "do not\u200b发送Q3报告"
    if _negated_verb(msg, "send_email"):
        _record(name, "HELD",
                "zero-width inside glued cue still fires the judge")
    else:
        _record(name, "BREAK",
                "judge silent with zero-width in the glued cue")


ADJACENT_BATTERIES = [
    "zw_negation_probes.py",
    "bidi_negation_probes.py",
    "arabic_negation_probes.py",
    "cyrillic_negation_probes.py",
    "cjk_negation_probes.py",
    "countermand_multilingual_negation_probes.py",
    "countermand_negation_inflection_probes.py",
    "double_negation_probes.py",
    "negation_precision_probes.py",
    "negation_scope_probes.py",
    "negation_verb_tier2_probes.py",
]

UNIT_TESTS = [
    "tests.test_intent_slice",
    "tests.test_intent_ledger",
]


def f_multilingual_green():
    name = "f_multilingual_green"
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 nesting discipline (2026-09-28): skip our own adjacency
        # green check when running as a nested child; the parent already
        # ran our red probes. Standalone runs still execute the full check.
        _record(name, "HELD",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); "
                "run standalone for full depth-1 adjacency")
        return
    failures = []
    for i, battery in enumerate(ADJACENT_BATTERIES):
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
        if proc.returncode != 0:
            err_tail = proc.stderr.strip().splitlines()
            err_tail = err_tail[-1] if err_tail else ""
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
                "%d adjacent batteries + %d unit suites green"
                % (len(ADJACENT_BATTERIES), len(UNIT_TESTS)))
    else:
        _record(name, "BREAK",
                "regressions: %s" % "; ".join(failures))


def _run_all():
    global _RESULTS
    _RESULTS = []
    f_cue_glued()
    f_judge_glued()
    f_scope_glued_real_cue()
    f_guard_not_only_glued()
    f_guard_no_problem_glued()
    f_precision_benign_glued()
    f_precision_benign_cue_search()
    f_reverse_glue_keeps_firing()
    f_spaced_controls()
    f_similarity_observability()
    f_zero_width_still_stripped()
    f_multilingual_green()
    return list(_RESULTS)


def f_deterministic_x2():
    name = "f_deterministic_x2"
    first = _run_all()
    second = _run_all()
    v1 = [(n, v) for n, v, _ in first]
    v2 = [(n, v) for n, v, _ in second]
    if v1 != v2:
        _record(name, "BREAK",
                "verdicts differ between runs")
        return
    _record(name, "HELD",
            "%d probes byte-identical verdicts across 2 runs" % len(v1))


def main():
    _run_all()
    f_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("f188_glued_cue_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
