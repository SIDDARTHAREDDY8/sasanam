#!/usr/bin/env python3
"""Row-7 verb-list expansion: high-risk exfiltration/destruction verbs
beyond SEND/DELETE/SHARE.

Row 7 stays PARTIAL for closed verb/cue lists and SEND/DELETE/SHARE-only
coverage (wave-151/152/153 pilots). This battery is RED-first: every
section-A/B probe goes BREAK on the current tree and flips to HELD once
the verb table carries the missing forms:

  A. Judge path (F188 pattern): a Latin negation cue glued to (or a
     CJK cue preceding) a non-Latin PUBLISH/UPLOAD verb form is silent
     in ``_negated_verb`` for the http_post tool, whose classes are
     (PUBLISH, UPLOAD). FORWARD has no tool mapping (SHARE precedent,
     wave-151: scope-path only), so it is covered in section B.
  B. Scope attribution (F188 strictness): the cue is found AND the
     anchor's verb is attributed to the expected class -- not merely
     the conservative no-verb path. Covers FORWARD/GRANT/REVOKE/LEAK
     (new classes) and the new non-Latin PUBLISH/UPLOAD forms.
  C. No-regression controls: covered verbs keep firing.
  D. Benign guards: the wave-158 guard set (not only / no problem /
     cannot / donot / knot) must not false-positive on the new verbs,
     and non-negated / wrong-predicate / affirmation cases stay silent.

Explicit threshold=0.5 throughout (wave-145 derived-band lesson: these
probes test the cue/judge/scope, not threshold calibration).

$0 spend, synthetic/local, deterministic. Real product code
(gov.intent_slice, gov.intent_ledger), no stubs.

Run:
  mkdir -p /tmp/gov-r7verb
  TMPDIR=/tmp/gov-r7verb ~/workspace/.gov-venv/bin/python \
      evals/row7_verb_expansion_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-r7verb2 \
      ~/workspace/.gov-venv/bin/python \
      evals/row7_verb_expansion_probes.py
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-r7verb-%d" % os.getpid())

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.intent_slice import (  # noqa: E402
    _NEGATION_RE, _anchor_verb_classes, _negated_verb,
    negation_scopes_grant)

THRESHOLD = 0.5  # explicit: these probes test the cue/judge/scope

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-34s %-10s %s" % (name, verdict, detail))


def _cue_found(text):
    m = _NEGATION_RE.search(text)
    return m.group(0) if m else None


# ------------------------------------------------- A. judge: F188 pattern
# _negated_verb must fire for the http_post tool (classes PUBLISH,
# UPLOAD). Pre-fix every gap probe is False: the non-Latin forms are
# absent from the class table, so neither the exact-match branch, the
# CJK in-token branch, nor the glued-cue branch can see them.
_JUDGE_GAPS = [
    # (probe suffix, message, tool)
    ("publish_cjk_glued", "do not发布Q3报告", "http_post"),
    ("publish_cjk_cue", "不要发布Q3报告", "http_post"),
    ("publish_cyrillic_glued", "do notопубликуйте Q3 отчёт", "http_post"),
    ("publish_arabic_glued", "do notانشر Q3 التقرير", "http_post"),
    ("upload_cjk_glued", "do not上传文件", "http_post"),
    ("upload_cyrillic_glued", "do notзагрузите файл", "http_post"),
    ("upload_arabic_glued", "do notارفع الملف", "http_post"),
]


def f_judge_gaps():
    for suffix, msg, tool in _JUDGE_GAPS:
        name = "f_judge_gap_%s" % suffix
        if _negated_verb(msg, tool):
            _record(name, "HELD",
                    "judge fires on %r/%s" % (msg, tool))
        else:
            _record(name, "BREAK",
                    "judge silent on %r/%s" % (msg, tool))


def f_judge_controls():
    name = "f_judge_controls"
    cases = [
        ("do not post the report", "http_post"),      # Latin stem (pre-existing)
        ("do not publish the report", "http_post"),   # Latin tier-2 (wave-148)
        ("do not upload the file", "http_post"),      # Latin tier-2 (wave-148)
        ("do not send the report", "send_email"),     # tier-1 control
        ("do not发送Q3报告", "send_email"),            # wave-158 control
    ]
    bad = ["%r/%s" % (m, t) for m, t in cases
           if not _negated_verb(m, t)]
    if not bad:
        _record(name, "HELD",
                "%d covered-verb controls still fire" % len(cases))
    else:
        _record(name, "BREAK",
                "REGRESSION: judge went silent on %s" % "; ".join(bad))


# ------------------------------------------------- B. scope attribution
# Strict: the cue must be FOUND and the anchor's verb ATTRIBUTED to
# the expected class (cls in _anchor_verb_classes(anchor)) and the
# scope must revoke. The conservative no-verb path (True without
# attribution) counts as BREAK here -- it is the pre-fix behavior.
_SCOPE_GAPS = [
    # (probe suffix, message, anchor, expected class)
    ("forward_cjk", "do not转发Q3报告", "把Q3报告转发给vendor", "FORWARD"),
    ("forward_cyrillic", "do not перешлите отчёт",
     "Перешлите отчёт коллеге", "FORWARD"),
    ("forward_arabic", "do not وجّه التقرير",
     "وجّه التقرير إلى المدير", "FORWARD"),
    ("grant_latin", "do not grant the contractor access",
     "Grant the contractor access.", "GRANT"),
    ("grant_cyrillic", "do not предоставьте доступ",
     "Предоставьте подрядчику доступ", "GRANT"),
    ("grant_arabic", "do not تمنح الوصول",
     "امنح المقاول الوصول", "GRANT"),
    ("grant_cjk", "do not授予访问权限",
     "把访问权限授予承包商", "GRANT"),
    ("revoke_latin", "do not revoke my access",
     "Revoke my access.", "REVOKE"),
    ("revoke_cyrillic", "do not отзовите доступ",
     "Отзовите его доступ", "REVOKE"),
    ("revoke_arabic", "do not تلغي الوصول",
     "ألغ وصوله", "REVOKE"),
    ("revoke_cjk", "do not撤销访问权限",
     "撤销他的访问权限", "REVOKE"),
    ("leak_latin", "do not leak the document",
     "Leak the document to the press.", "LEAK"),
    ("leak_cyrillic", "do not слейте данные",
     "Слейте данные прессе", "LEAK"),
    ("leak_arabic", "do not تسرّب المستند",
     "سرّب المستند للصحافة", "LEAK"),
    ("leak_cjk", "do not泄露文件",
     "把文件泄露出去", "LEAK"),
    ("publish_cjk_scope", "do not发布Q3报告",
     "把Q3报告发布到博客", "PUBLISH"),
    ("upload_cjk_scope", "do not上传文件",
     "把文件上传到服务器", "UPLOAD"),
]


def f_scope_attribution():
    for suffix, msg, anchor, cls in _SCOPE_GAPS:
        name = "f_scope_attr_%s" % suffix
        cue = _cue_found(msg)
        classes = _anchor_verb_classes(anchor)
        scope = negation_scopes_grant(msg, anchor)
        if cue is not None and cls in classes and scope:
            _record(name, "HELD",
                    "cue %r + %s attributed + scope revokes" % (cue, cls))
        else:
            _record(name, "BREAK",
                    "%r/%r: cue=%r classes=%r scope=%r (want %s)"
                    % (msg, anchor, cue, sorted(classes), scope, cls))


# ------------------------------------------------- C. scope no-regression controls
def f_scope_controls():
    name = "f_scope_controls"
    cases = [
        ("do not发送Q3报告", "Send the Q3 report to the vendor."),
        ("never删除Q3报告", "Delete the Q3 report."),
        ("do not publish the report", "Publish the report to the blog."),
    ]
    bad = []
    for msg, grant in cases:
        if _cue_found(msg) is None or \
                not negation_scopes_grant(msg, grant):
            bad.append("%r/%r" % (msg, grant))
    if not bad:
        _record(name, "HELD",
                "%d covered-verb scope controls still revoke" % len(cases))
    else:
        _record(name, "BREAK",
                "REGRESSION: scope broke on %s" % "; ".join(bad))


# ------------------------------------------------- D. benign guards on new verbs
def f_guard_cue_search_new_verbs():
    name = "f_guard_cue_search_new_verbs"
    # The wave-158 guard set must not leak a cue glued to the NEW
    # verb forms, in any newly covered script.
    cases = [
        "not only发布Q3报告",
        "no problem发布Q3报告",
        "cannot上传文件",
        "donot转发报告",
        "knot发布",
        "not only授予访问权限",
        "no problem撤销访问",
        "cannot泄露文件",
        "not onlyопубликуйте",
        "no problemانشر",
    ]
    bad = [(m, _cue_found(m)) for m in cases
           if _cue_found(m) is not None]
    if not bad:
        _record(name, "HELD",
                "%d guard cases yield no cue on new verbs" % len(cases))
    else:
        _record(name, "BREAK",
                "guard leaked: %s"
                % "; ".join("%r->%r" % b for b in bad))


def f_precision_judge_new_verbs():
    name = "f_precision_judge_new_verbs"
    cases = [
        # (message, tool, why silent)
        ("do not担心", "http_post",
         "cue present but no PUBLISH/UPLOAD verb form"),
        ("Q3报告已发布", "http_post",
         "affirmation, no cue at all"),
        ("do not发布Q3报告", "send_email",
         "negated PUBLISH, tool SEND (wrong predicate)"),
        ("Please grant the contractor access.", "http_post",
         "no negation cue"),
        ("Grant access to the team.", "http_post",
         "no negation cue (bare grant)"),
        ("do not read the post", "delete_file",
         "negated READ, tool DELETE (wrong predicate)"),
    ]
    bad = []
    for msg, tool, why in cases:
        if _negated_verb(msg, tool):
            bad.append("%r/%s fired (%s)" % (msg, tool, why))
        if _cue_found(msg) is not None and "no negation cue" in why:
            bad.append("%r yielded cue %r (%s)"
                       % (msg, _cue_found(msg), why))
    if not bad:
        _record(name, "HELD",
                "%d benign new-verb cases silent in cue+judge"
                % len(cases))
    else:
        _record(name, "BREAK",
                "false fire: %s" % "; ".join(bad))


# ------------------------------------------------- scorecard
def main():
    print("row-7 verb expansion probes (pre-fix: A/B BREAK, C/D HELD)")
    f_judge_gaps()
    f_judge_controls()
    f_scope_attribution()
    f_scope_controls()
    f_guard_cue_search_new_verbs()
    f_precision_judge_new_verbs()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    broken = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    print("SCORECARD: %d HELD / %d BREAK / %d total"
          % (held, broken, len(_RESULTS)))


if __name__ == "__main__":
    main()
