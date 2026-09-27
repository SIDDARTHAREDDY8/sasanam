#!/usr/bin/env python3
"""Row-11 type-to-confirm synonym resilience (wave-147 lane 1).

Residual from wave-145/146: the type-to-confirm ceremony's
token-tversky check is paraphrase-tolerant but synonym-blind in a
specific way -- and, worse, synonym-INDIFFERENT in the other
direction:

  s1_synonym_verb_matches: typed "erase the report" vs reference
     "delete the Q3 report" -> MATCH (score >= 0.5). "erase" is a
     synonym of "delete"; the meaning matches. Measured raw
     token-tversky: 0.5714 -- the shared noun "report" already
     carries it over the threshold, so this probe is HELD pre- and
     post-fix (documented, not claimed as a fix).
  s2_wrong_verb_no_match: typed "send the report" vs reference
     "archive the Q3 report" -> NO MATCH (fail-closed). "send" is
     NOT a synonym of "archive": a different action. Measured raw
     token-tversky: 0.5714 -- ALSO over the threshold, so raw
     matching BREAKS pre-fix (the ceremony would let a mismatched
     action through). Post-fix the synonym-aware check refuses it
     via the verb-agreement veto.
  s3_garbage_no_match: garbage typed scope -> NO match.
  s4_exact_match: exact typed scope -> MATCH (no regression).
  s5_destination_veto_preserved: "send invoices to
     accounting@vendor.com" vs "send invoices to evil.com" -> NO
     match (the wave-136 destination veto must survive synonym
     canonicalization).
  s6_ceremony_synonym_ok: the ceremony helper
     (gov.approvals._type_to_confirm_ok) accepts the s1 pair.
  s7_ceremony_wrong_verb_refused: the ceremony helper refuses the
     s2 pair.

Design note (deviation from the wave-147 sketch, measured): the
sketch said "expand synonyms additively, take max(raw,
expanded)". That provably cannot satisfy s2: additive expansion
only ADDS token overlap, and s2 already scores 0.5714 >= 0.5 raw,
so max(raw, expanded) >= 0.5714 always -- s2 can never be refused.
The shipped design is synonym CANONICALIZATION (each token maps to
its canonical form: erase/remove/destroy -> DELETE, etc.) PLUS a
verb-agreement veto: when BOTH sides name an action verb from the
curated verb classes and the canonical verbs differ, similarity is
forced to 0.0 -- the same veto idiom as the wave-136 destination
veto (conservative: it can only suppress matches, never create
them). max(raw, canonical) is taken only when the veto does not
fire. The curated map is bounded and documented in
gov/target_match.py (delete/erase/remove/destroy;
report/document/file; send/transmit/dispatch; archive/store/backup;
Q3 is identity -- deliberately NOT expanded). The synonym-aware
path is used ONLY by the type-to-confirm ceremony
(gov/approvals._type_to_confirm_ok); the row-11 paraphrase tier
(gov/goal_audit.py, gov/goals.py detect_cross_run_laundering) keeps
raw token-tversky -- the grant path is NOT widened.

Verdicts:
- HELD  = the ceremony behaved as specified above.
- BREAK = the ceremony misbehaved (pre-fix: s2 BREAKS -- raw
          matching lets the wrong verb through).
- ERROR = probe/instrumentation problem.

$0 spend, synthetic/local, deterministic. Stdlib only.

Run:
  mkdir -p /tmp/gov-typesynonym
  TMPDIR=/tmp/gov-typesynonym ~/workspace/.gov-venv/bin/python \\
      evals/type_synonym_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-tsyn-u \\
      ~/workspace/.gov-venv/bin/python evals/type_synonym_probes.py
"""

import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "typesynonym-break")
os.environ.setdefault("TMPDIR", "/tmp/gov-typesynonym")
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    # Post-fix seam (wave-147 lane 1): synonym-aware typed-scope
    # similarity, used only by the type-to-confirm ceremony.
    from gov.target_match import (  # noqa: E402
        typed_scope_similarity,
        DEFAULT_THRESHOLD,
    )
    _SEAM = "typed_scope_similarity"
except ImportError:  # pre-fix: the ceremony uses raw token-tversky
    from gov.target_match import (  # noqa: E402
        target_similarity as typed_scope_similarity,
        DEFAULT_THRESHOLD,
    )
    _SEAM = "target_similarity (pre-fix fallback)"
from gov.approvals import _type_to_confirm_ok  # noqa: E402

# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

S1_TYPED, S1_REF = "erase the report", "delete the Q3 report"
S2_TYPED, S2_REF = "send the report", "archive the Q3 report"
S3_TYPED, S3_REF = "xqzt blorp wobble fnord", "delete the Q3 report"
S4_TYPED, S4_REF = "delete the Q3 report", "delete the Q3 report"
S5_TYPED, S5_REF = ("send invoices to accounting@vendor.com",
                    "send invoices to evil.com")


def s1_synonym_verb_matches():
    """Typed verb is a synonym of the reference verb -> match."""
    score = typed_scope_similarity(S1_TYPED, S1_REF)
    if score >= DEFAULT_THRESHOLD:
        return ("HELD", "score %.4f >= %.2f" % (score,
                                                DEFAULT_THRESHOLD))
    return ("BREAK", "synonym pair refused: score %.4f < %.2f"
            % (score, DEFAULT_THRESHOLD))


def s2_wrong_verb_no_match():
    """Typed verb is NOT a synonym of the reference verb -> NO match
    (fail-closed). Pre-fix this BREAKS: raw token-tversky scores the
    pair 0.5714 >= 0.5 (the shared noun "report" carries it), so the
    ceremony would accept a mismatched action."""
    score = typed_scope_similarity(S2_TYPED, S2_REF)
    if score < DEFAULT_THRESHOLD:
        return ("HELD", "score %.4f < %.2f (refused)" % (score,
                                                        DEFAULT_THRESHOLD))
    return ("BREAK", "wrong-verb pair ACCEPTED: score %.4f >= %.2f"
            % (score, DEFAULT_THRESHOLD))


def s3_garbage_no_match():
    score = typed_scope_similarity(S3_TYPED, S3_REF)
    if score < DEFAULT_THRESHOLD:
        return ("HELD", "score %.4f < %.2f" % (score, DEFAULT_THRESHOLD))
    return ("BREAK", "garbage accepted: %.4f" % score)


def s4_exact_match():
    score = typed_scope_similarity(S4_TYPED, S4_REF)
    if score >= DEFAULT_THRESHOLD:
        return ("HELD", "score %.4f >= %.2f" % (score,
                                                DEFAULT_THRESHOLD))
    return ("BREAK", "exact pair refused: %.4f" % score)


def s5_destination_veto_preserved():
    """The wave-136 destination veto must survive synonym
    canonicalization: differing explicit destinations force 0.0."""
    score = typed_scope_similarity(S5_TYPED, S5_REF)
    if score == 0.0:
        return ("HELD", "destination veto held (0.0)")
    return ("BREAK", "destination veto broken: %.4f" % score)


def s6_ceremony_synonym_ok():
    ok, score, _detail, _method = _type_to_confirm_ok([S1_REF], S1_TYPED)
    if ok:
        return ("HELD", "ceremony accepted synonym pair (%.4f)" % score)
    return ("BREAK", "ceremony refused synonym pair (%.4f)" % score)


def s7_ceremony_wrong_verb_refused():
    ok, score, _detail, _method = _type_to_confirm_ok([S2_REF], S2_TYPED)
    if not ok:
        return ("HELD", "ceremony refused wrong-verb pair (%.4f)" % score)
    return ("BREAK", "ceremony ACCEPTED wrong-verb pair (%.4f)" % score)


PROBES = [
    ("s1_synonym_verb_matches", s1_synonym_verb_matches),
    ("s2_wrong_verb_no_match", s2_wrong_verb_no_match),
    ("s3_garbage_no_match", s3_garbage_no_match),
    ("s4_exact_match", s4_exact_match),
    ("s5_destination_veto_preserved", s5_destination_veto_preserved),
    ("s6_ceremony_synonym_ok", s6_ceremony_synonym_ok),
    ("s7_ceremony_wrong_verb_refused", s7_ceremony_wrong_verb_refused),
]


def main():
    print("seam under test: %s" % _SEAM)
    held = broke = errored = 0
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001
            verdict, detail = "ERROR", "%r" % (exc,)
        print("%-36s %-6s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broke += 1
        else:
            errored += 1
    print("== %d HELD / %d BREAK / %d ERROR ==" % (held, broke, errored))
    return 0 if (broke == 0 and errored == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
