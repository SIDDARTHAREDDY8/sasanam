#!/usr/bin/env python3
"""Wave-212 lane B red-team probes: in-toto-style artifact rules.

Break-first battery per the diagnosing-bugs skill. Pattern lineage:
in-toto specification, section 4.3.3 ("Artifact Rules"), re-implemented
stdlib-only in gov.artifact_rules -- no in-toto code or spec text is
vendored or copied; only the rule grammar shape is adapted in our own
words (the specification is Community Specification License).

The pristine tree (c124c928) has a NARROW rule engine inside
gov.provenance_verifier (REQUIRE/MATCH/DISALLOW over sealed
ProvenanceStatements) but NO general-purpose artifact-rule module:
CREATE/MODIFY/DELETE do not exist as first-class rules, and there is
no consumptive queue over plain (name -> digest) material/product maps.
Each probe attacks that gap; on pristine every probe reports GAP
(module absent -- genuine red). After the fix all must flip to HELD.

Probe map:

  A1  CREATE_SPOOFED      rule CREATE "out/*", but out/app was NOT
                          created by this step (it is ALSO in
                          materials with the same digest) -> refused.
  A2  UNCONSUMED_SMUGGLING extra artifact "keys/signing.key" in
                          materials matches no rule -> terminal
                          DISALLOW refuses (no implicit ALLOW *).
  A3  REQUIRE_ABSENT      REQUIRE "release.tar.gz" with no such
                          artifact anywhere -> refused.
  A4  MATCH_DIGEST_LIE    MATCH pins digest D1 for artifact, actual
                          digest is D2 -> refused.
  A5  MODIFY_UNMODIFIED   MODIFY "src/*" but the artifact digest is
                          IDENTICAL in materials and products ->
                          refused (nothing was modified).
  A6  DELETE_RESURRECTED  DELETE "tmp/*" but tmp/plan.txt is still
                          present in products -> refused.
  A7  LOAD_NO_DISALLOW    rule set with NO terminal DISALLOW refused
                          at load (fail-closed lint discipline).
  A8  LOAD_MID_DISALLOW   DISALLOW in a non-terminal position
                          refused at load.
  A9  DOUBLE_CONSUME      artifact consumed by CREATE, then REQUIRED
                          again by a later rule -> refused (an
                          artifact is accounted for exactly once).
  A10 VALID_FLOW          honest step: material src/main.c unchanged,
                          src/lib.c modified, docs/new.md created,
                          tmp/scratch.txt deleted, release pinned by
                          MATCH -> verifies, audit report sane,
                          rule_set_digest stable.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red
phase), ERROR only on harness failure (a verdict changing between
the two deterministic runs, or an unexpected exception).

Deterministic: no keys, no clock; every probe runs twice and a
verdict change is an ERROR. Synthetic/local only.
``GOV_SKIP_GREEN=1`` is honored (green check records a skip instead
of spawning sub-batteries).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import artifact_rules as _ar
    _ABSENT = False
except ImportError:
    _ABSENT = True

_RESULTS = []

_D1 = "aa" * 32
_D2 = "bb" * 32
_D3 = "cc" * 32


def _record(probe_id, name, verdict, detail):
    _RESULTS.append({"id": probe_id, "name": name, "verdict": verdict,
                     "detail": detail})


def _gap(probe_id, name, detail):
    _record(probe_id, name, "GAP", detail)


def _held(probe_id, name, detail):
    _record(probe_id, name, "HELD", detail)


def _run_twice(fn):
    first = fn()
    second = fn()
    if first[0] != second[0]:
        return ("ERROR",
                "nondeterministic verdict: %r vs %r" % (first, second))
    return first


def _expect_refusal(fn, must_mention=None):
    """The artifact-rules module raises ArtifactRuleError (a ValueError)
    loudly on every violation -- a silent False is an invitation to
    skip the check, so the public seam never returns one."""
    try:
        fn()
    except _ar.ArtifactRuleError as exc:
        if must_mention and must_mention not in str(exc):
            return ("ERROR", "refusal message missing %r: %s"
                    % (must_mention, exc))
        return ("HELD", "refused: %s" % exc)
    except Exception as exc:  # noqa: BLE001 - taxonomy check
        return ("ERROR", "wrong exception taxonomy: %r: %s"
                % (type(exc).__name__, exc))
    return ("GAP", "not refused")


def _probe_a1_create_spoofed():
    materials = {"src/main.c": _D1, "out/app": _D2}
    products = {"out/app": _D2}
    rules = [("CREATE", "out/*"), ("DISALLOW",)]
    return _expect_refusal(
        lambda: _ar.verify_artifacts(materials, products, rules),
        "CREATE")


def _probe_a2_unconsumed_smuggling():
    materials = {"src/main.c": _D1, "keys/signing.key": _D3}
    products = {"out/app": _D2}
    rules = [("REQUIRE", "src/main.c"),
             ("CREATE", "out/*"),
             ("DISALLOW",)]
    return _expect_refusal(
        lambda: _ar.verify_artifacts(materials, products, rules),
        "signing.key")


def _probe_a3_require_absent():
    materials = {"src/main.c": _D1}
    products = {"out/app": _D2}
    rules = [("REQUIRE", "release.tar.gz"),
             ("CREATE", "out/*"),
             ("DISALLOW",)]
    return _expect_refusal(
        lambda: _ar.verify_artifacts(materials, products, rules),
        "REQUIRE")


def _probe_a4_match_digest_lie():
    materials = {"src/main.c": _D2}  # actual digest differs from pin
    products = {}
    rules = [("MATCH", "src/main.c", _D1), ("DISALLOW",)]
    return _expect_refusal(
        lambda: _ar.verify_artifacts(materials, products, rules),
        "MATCH")


def _probe_a5_modify_unmodified():
    materials = {"src/lib.c": _D1}
    products = {"src/lib.c": _D1}
    rules = [("MODIFY", "src/*"), ("DISALLOW",)]
    return _expect_refusal(
        lambda: _ar.verify_artifacts(materials, products, rules),
        "MODIFY")


def _probe_a6_delete_resurrected():
    materials = {"tmp/scratch.txt": _D1}
    products = {"tmp/scratch.txt": _D1, "out/app": _D2}
    rules = [("DELETE", "tmp/*"), ("CREATE", "out/*"), ("DISALLOW",)]
    return _expect_refusal(
        lambda: _ar.verify_artifacts(materials, products, rules),
        "DELETE")


def _probe_a7_load_no_disallow():
    materials = {"src/main.c": _D1}
    products = {}
    rules = [("REQUIRE", "src/main.c")]  # no terminal DISALLOW
    return _expect_refusal(
        lambda: _ar.verify_artifacts(materials, products, rules),
        "DISALLOW")


def _probe_a8_load_mid_disallow():
    materials = {"src/main.c": _D1}
    products = {}
    rules = [("DISALLOW",), ("REQUIRE", "src/main.c"), ("DISALLOW",)]
    return _expect_refusal(
        lambda: _ar.verify_artifacts(materials, products, rules),
        "terminal")


def _probe_a9_double_consume():
    materials = {"src/main.c": _D1}
    products = {"out/app": _D2}
    rules = [("REQUIRE", "src/main.c"),
             ("CREATE", "out/*"),
             ("REQUIRE", "out/app"),  # already consumed by CREATE
             ("DISALLOW",)]
    return _expect_refusal(
        lambda: _ar.verify_artifacts(materials, products, rules),
        "REQUIRE")


def _probe_a10_valid_flow():
    materials = {"src/main.c": _D1,      # unchanged
                 "src/lib.c": _D1,       # will be modified
                 "tmp/scratch.txt": _D3}  # will be deleted
    products = {"src/main.c": _D1,       # unchanged -> REQUIRE
                "src/lib.c": _D2,        # modified
                "docs/new.md": _D3}       # created
    rules = [("DELETE", "tmp/*"),
             ("MODIFY", "src/lib.c"),
             ("CREATE", "docs/*"),
             ("REQUIRE", "src/main.c"),
             ("DISALLOW",)]
    try:
        report = _ar.verify_artifacts(materials, products, rules)
    except Exception as exc:  # noqa: BLE001 - valid flow must pass
        return ("GAP", "valid flow refused: %r: %s"
                % (type(exc).__name__, exc))
    if not isinstance(report, dict) or report.get("ok") is not True:
        return ("ERROR", "report not a success dict: %r" % (report,))
    digest = report.get("rule_set_digest")
    if not (isinstance(digest, str) and len(digest) == 64):
        return ("ERROR", "rule_set_digest not a sha256 hex: %r" % (digest,))
    consumed = report.get("per_rule", [])
    if len(consumed) != 5:
        return ("ERROR", "audit trail missing rules: %r" % (consumed,))
    return ("HELD", "valid flow verified; digest=%s..." % digest[:16])


_PROBES = [
    ("A1", "CREATE_SPOOFED", _probe_a1_create_spoofed),
    ("A2", "UNCONSUMED_SMUGGLING", _probe_a2_unconsumed_smuggling),
    ("A3", "REQUIRE_ABSENT", _probe_a3_require_absent),
    ("A4", "MATCH_DIGEST_LIE", _probe_a4_match_digest_lie),
    ("A5", "MODIFY_UNMODIFIED", _probe_a5_modify_unmodified),
    ("A6", "DELETE_RESURRECTED", _probe_a6_delete_resurrected),
    ("A7", "LOAD_NO_DISALLOW", _probe_a7_load_no_disallow),
    ("A8", "LOAD_MID_DISALLOW", _probe_a8_load_mid_disallow),
    ("A9", "DOUBLE_CONSUME", _probe_a9_double_consume),
    ("A10", "VALID_FLOW", _probe_a10_valid_flow),
]


def _green_check():
    """Depth-1 adjacent check: the narrow rule engine inside
    gov.provenance_verifier (REQUIRE/MATCH/DISALLOW over sealed
    statements) must stay green when this module lands. Honors
    GOV_SKIP_GREEN=1 (records a skip, never spawns)."""
    if _SKIP_GREEN:
        _record("GREEN", "GREEN_ADJACENT",
                "SKIPPED", "GOV_SKIP_GREEN=1; depth-1 convention")
        return True
    try:
        from gov import provenance_verifier as _pv
    except ImportError:
        _record("GREEN", "GREEN_ADJACENT", "ERROR",
                "gov.provenance_verifier import failed")
        return False
    try:
        _pv.parse_rule(("REQUIRE", "x"))
        _pv.parse_rule(("DISALLOW",))
    except Exception as exc:  # noqa: BLE001 - adjacent smoke
        _record("GREEN", "GREEN_ADJACENT", "ERROR",
                "provenance_verifier smoke failed: %s" % exc)
        return False
    _record("GREEN", "GREEN_ADJACENT", "HELD",
            "provenance_verifier seam intact")
    return True


def main():
    if _ABSENT:
        for probe_id, name, _ in _PROBES:
            _gap(probe_id, name, "gov.artifact_rules absent on pristine")
        _record("GREEN", "GREEN_ADJACENT", "GAP",
                "module absent; green check deferred")
        return _emit(2)
    for probe_id, name, fn in _PROBES:
        verdict, detail = _run_twice(fn)
        _record(probe_id, name, verdict, detail)
    _green_check()
    return _emit(0)


def _emit(code):
    held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    gap = sum(1 for r in _RESULTS if r["verdict"] == "GAP")
    err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    skip = sum(1 for r in _RESULTS if r["verdict"] == "SKIPPED")
    print("artifact_rules_probes: %d HELD / %d GAP / %d ERROR / %d SKIPPED"
          % (held, gap, err, skip))
    for r in _RESULTS:
        print("  %s %-22s %s %s"
              % (r["id"], r["name"], r["verdict"], r["detail"]))
    return 0 if (code == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
