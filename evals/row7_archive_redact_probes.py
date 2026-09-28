#!/usr/bin/env python3
"""Row-7 archive/redact multilingual: native Cyrillic/Arabic/CJK forms for
the ARCHIVE and REDACT verb classes.

Row 7 stays PARTIAL partly because ARCHIVE and REDACT carry no
Cyrillic/Arabic/CJK forms (wave-151/152/153 pilots covered
SEND/DELETE/SHARE; wave-163 extended PUBLISH/UPLOAD/FORWARD and added
GRANT/REVOKE/LEAK). This battery is RED-first: every section-A probe goes
BREAK on the current tree and flips to HELD once the verb table carries
the missing forms.

ARCHIVE/REDACT have no product-tool mapping in _TOOL_VERB_CLASSES
(SHARE precedent, wave-151), so they are scope/cue-path only -- there
is no judge-path section (contrast row7_verb_expansion_probes.py):

  A. Scope attribution (F188 strictness): the cue must be FOUND and the
     anchor's verb ATTRIBUTED to the expected class (cls in
     _anchor_verb_classes(anchor)) and the scope must revoke. The
     conservative no-verb path (True without attribution) counts as
     BREAK here -- it is the pre-fix behavior.
  B. No-regression controls: covered verbs keep firing.
  C. Benign guards: the wave-158 guard set (not only / no problem /
     cannot / donot / knot) must not false-positive on the new forms,
     and non-negated messages must not revoke.
  D. Attribution precision: new forms attribute to exactly the right
     class, no cross-class leakage.

$0 spend, synthetic/local, deterministic. Real product code
(gov.intent_slice), no stubs.

Run:
  mkdir -p /tmp/gov-r7ar
  TMPDIR=/tmp/gov-r7ar ~/workspace/.gov-venv/bin/python \
      evals/row7_archive_redact_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-r7ar2 \
      ~/workspace/.gov-venv/bin/python \
      evals/row7_archive_redact_probes.py
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-r7ar-%d" % os.getpid())

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.intent_slice import (  # noqa: E402
    _NEGATION_RE, _anchor_verb_classes, negation_scopes_grant)

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-34s %-10s %s" % (name, verdict, detail))


def _cue_found(text):
    m = _NEGATION_RE.search(text)
    return m.group(0) if m else None


# ------------------------------------------------- A. scope attribution gaps
# Pre-fix every gap probe is BREAK: the non-Latin forms are absent from
# the class table, so _anchor_verb_classes(anchor) is empty (the
# conservative no-verb path) and the class is never attributed.
_SCOPE_GAPS = [
    # (probe suffix, message, anchor, expected class)
    ("archive_cyrillic_glued", "do not архивируйте отчёт",
     "Архивируйте отчёт в хранилище", "ARCHIVE"),
    ("archive_cyrillic_cue", "не архивируйте отчёт",
     "Архивируйте отчёт в хранилище", "ARCHIVE"),
    ("archive_arabic_glued", "do not أرشف التقرير",
     "أرشف التقرير في المخزن", "ARCHIVE"),
    ("archive_arabic_cue", "لا ترشف التقرير",
     "أرشف التقرير في المخزن", "ARCHIVE"),
    ("archive_cjk_glued", "do not归档Q3报告",
     "把Q3报告归档到仓库", "ARCHIVE"),
    ("archive_cjk_cue", "不要归档Q3报告",
     "把Q3报告归档到仓库", "ARCHIVE"),
    ("redact_cyrillic_glued", "do not вымарайте данные",
     "Вымарайте секретные данные", "REDACT"),
    ("redact_cyrillic_cue", "не вымарайте данные",
     "Вымарайте секретные данные", "REDACT"),
    ("redact_arabic_glued", "do not اشطب البيانات",
     "اشطب البيانات السرية", "REDACT"),
    ("redact_arabic_cue", "لا تشطب البيانات",
     "اشطب البيانات السرية", "REDACT"),
    ("redact_cjk_glued", "do not涂黑敏感信息",
     "把敏感信息涂黑", "REDACT"),
    ("redact_cjk_cue", "不要涂黑敏感信息",
     "把敏感信息涂黑", "REDACT"),
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


# ------------------------------------------------- B. scope no-regression controls
def f_scope_controls():
    name = "f_scope_controls"
    cases = [
        ("do not发送Q3报告", "Send the Q3 report to the vendor."),
        ("never删除Q3报告", "Delete the Q3 report."),
        ("do not发布Q3报告", "把Q3报告发布到博客"),      # wave-163
        ("do not archive the report", "Archive the report to cold storage."),
        ("do not redact the document", "Redact the secret passages."),
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


# ------------------------------------------------- C. benign guards on new forms
def f_guard_cue_search_new_forms():
    name = "f_guard_cue_search_new_forms"
    # The wave-158 guard set must not leak a cue glued to the NEW
    # verb forms, in any newly covered script.
    cases = [
        "not only归档Q3报告",
        "no problem归档报告",
        "cannot涂黑信息",
        "donot归档报告",
        "knot涂黑",
        "not onlyархивируйте",
        "no problemأرشف",
        "cannotвымарайте",
        "donotاشطب",
        "not onlyアーカイブ",
    ]
    bad = [(m, _cue_found(m)) for m in cases
           if _cue_found(m) is not None]
    if not bad:
        _record(name, "HELD",
                "%d guard cases yield no cue on new forms" % len(cases))
    else:
        _record(name, "BREAK",
                "guard leaked: %s"
                % "; ".join("%r->%r" % b for b in bad))


def f_no_cue_no_revoke():
    name = "f_no_cue_no_revoke"
    # Affirmations naming the new verbs must not revoke.
    cases = [
        ("Please archive the quarterly report.",
         "Archive the report to cold storage."),
        ("Kindly redact the secret passages.",
         "Redact the secret passages."),
        ("请把Q3报告归档到仓库", "把Q3报告归档到仓库"),
        ("Архивируйте отчёт в хранилище", "Архивируйте отчёт в хранилище"),
    ]
    bad = ["%r/%r" % (m, g) for m, g in cases
           if negation_scopes_grant(m, g)]
    if not bad:
        _record(name, "HELD",
                "%d affirmation cases stay non-revoking" % len(cases))
    else:
        _record(name, "BREAK",
                "false revoke: %s" % "; ".join(bad))


# ------------------------------------------------- D. attribution precision
def f_attribution_precision():
    name = "f_attribution_precision"
    cases = [
        # (anchor, expected exact class set)
        ("把Q3报告归档到仓库", {"ARCHIVE"}),
        ("把敏感信息涂黑", {"REDACT"}),
        ("Архивируйте отчёт в хранилище", {"ARCHIVE"}),
        ("Вымарайте секретные данные", {"REDACT"}),
        ("أرشف التقرير في المخزن", {"ARCHIVE"}),
        ("اشطب البيانات السرية", {"REDACT"}),
        ("Archive the report to cold storage.", {"ARCHIVE"}),
        ("Redact the secret passages.", {"REDACT"}),
    ]
    bad = []
    for anchor, want in cases:
        got = _anchor_verb_classes(anchor)
        if got != want:
            bad.append("%r -> %r (want %r)" % (anchor, sorted(got),
                                               sorted(want)))
    if not bad:
        _record(name, "HELD",
                "%d anchors attribute to exactly the right class"
                % len(cases))
    else:
        _record(name, "BREAK",
                "misattribution: %s" % "; ".join(bad))


# ------------------------------------------------- scorecard
def main():
    print("row-7 archive/redact probes (pre-fix: A BREAK, B/C/D HELD)")
    f_scope_attribution()
    f_scope_controls()
    f_guard_cue_search_new_forms()
    f_no_cue_no_revoke()
    f_attribution_precision()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    broken = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    print("SCORECARD: %d HELD / %d BREAK / %d total"
          % (held, broken, len(_RESULTS)))


if __name__ == "__main__":
    main()
