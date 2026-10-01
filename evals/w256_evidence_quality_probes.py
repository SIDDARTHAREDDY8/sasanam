"""Break-first battery for gov/evidence_quality.py (wave-256 lane 3).

great-expectations ADAPT (pattern only; Apache-2.0): a declarative
evidence-quality expectation vocabulary (named assertion -> typed
result -> validation record) evaluated between the evidence pipeline
stages (collection -> signing -> bundling), with a quality gate in
front of the compliance emitter.

Red-first discipline: every probe is GAP on a pristine base (module
absent), HELD when the implementation holds, BREAK when a break
attempt succeeds. A genuine BREAK against the final implementation
would file a finding; this battery must be all HELD on the shipped
module.

Related prospectus gap: W255-2 (wave-255 prospectus). Next free: F219.
"""

import copy
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PIN = 1080  # Wave-258 merge: pin -> 1080.

try:
    from gov import decision_codes
    from gov import evidence_quality as eq
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

if HAVE_MODULE:
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, \
        "taxonomy drift: %d != %d" % (len(decision_codes.TAXONOMY),  # Wave-258 merge: pin -> 1080.
                                      TAXONOMY_PIN)

PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


def _mono_items(n=3, start=1):
    return [{"seq": start + i, "note": "e%d" % i} for i in range(n)]


def _chain_items(n=3):
    import hashlib
    import json
    items, prev = [], None
    for i in range(n):
        body = {"seq": i + 1, "payload": "p%d" % i}
        digest = hashlib.sha256(
            json.dumps(body, sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest()
        items.append(dict(body, digest=digest, prev_digest=prev))
        prev = digest
    return items


def _control_source():
    return {
        "id": "SAS-EQ-001",
        "title": "Evidence quality gate",
        "description": "Quality expectations hold over the evidence "
                       "before emission.",
        "mappings": [
            {"kind": "code", "ref": "evidence-quality-gate-failed",
             "rationale": "gate refusal path"},
        ],
    }


@probe
def p_monotonic_gap_caught():
    """A sequence-number gap/regression must fail the monotonic
    expectation -- a sloppy collector must not pass silently."""
    items = _mono_items()
    items[1]["seq"] = 1  # regression: 1,1,3
    res = eq.evaluate(
        [{"expectation_type": "expect_evidence_monotonic",
          "kwargs": {}}], items)
    if res["success"]:
        return "BREAK"
    if len(res["results"]) != 1:
        return "BREAK"
    return "HELD"


@probe
def p_broken_chain_caught():
    """A tampered chain link must fail expect_chain_intact."""
    items = _chain_items()
    items[1]["payload"] = "tampered"
    res = eq.evaluate(
        [{"expectation_type": "expect_chain_intact", "kwargs": {}}],
        items)
    return "HELD" if not res["success"] else "BREAK"


@probe
def p_missing_artifact_caught():
    """A bundle referencing an absent artifact must fail
    expect_bundle_complete -- no dangling refs."""
    bundle = {"items": [{"artifact_ref": "a1"},
                        {"artifact_ref": "a-missing"}]}
    res = eq.evaluate(
        [{"expectation_type": "expect_bundle_complete",
          "kwargs": {"artifacts": {"a1": {"bytes": b"x"}}}}],
        bundle)
    if res["success"]:
        return "BREAK"
    missing = res["results"][0]["result"]["details"].get(
        "missing_refs", [])
    return "HELD" if "a-missing" in missing else "BREAK"


@probe
def p_unknown_expectation_refuses():
    """An unknown expectation_type must refuse fail-closed
    (evidence-quality-unknown-expectation), never silently skip."""
    try:
        eq.evaluate(
            [{"expectation_type": "expect_nonexistent_thing",
              "kwargs": {}}], _mono_items())
    except eq.EvidenceQualityError as exc:
        return "HELD" if exc.code == \
            "evidence-quality-unknown-expectation" else "BREAK"
    except Exception:
        return "BREAK"
    return "BREAK"


@probe
def p_malformed_expectation_refuses():
    """A malformed expectation shape must refuse
    (evidence-quality-malformed)."""
    for bad in ({"kwargs": {}}, {"expectation_type": 42},
                "not-a-dict"):
        try:
            eq.evaluate([bad], _mono_items())
        except eq.EvidenceQualityError as exc:
            if exc.code != "evidence-quality-malformed":
                return "BREAK"
        except Exception:
            return "BREAK"
        else:
            return "BREAK"
    return "HELD"


@probe
def p_malformed_evidence_refuses():
    """Non-list evidence / non-dict items must refuse
    (evidence-quality-evidence-malformed)."""
    for bad in ("nope", None, [{"seq": 1}, "not-a-dict"]):
        try:
            eq.evaluate(
                [{"expectation_type": "expect_evidence_monotonic",
                  "kwargs": {}}], bad)
        except eq.EvidenceQualityError as exc:
            if exc.code != "evidence-quality-evidence-malformed":
                return "BREAK"
        except Exception:
            return "BREAK"
        else:
            return "BREAK"
    return "HELD"


@probe
def p_gate_refuses_emission_on_failure():
    """emit_with_quality_gate must refuse with
    evidence-quality-gate-failed when any expectation fails."""
    items = _mono_items()
    items[0]["seq"] = 99  # break monotonicity
    try:
        eq.emit_with_quality_gate(
            _control_source(), "json",
            [{"expectation_type": "expect_evidence_monotonic",
              "kwargs": {}}], items)
    except eq.EvidenceQualityError as exc:
        return "HELD" if exc.code == \
            "evidence-quality-gate-failed" else "BREAK"
    except Exception:
        return "BREAK"
    return "BREAK"


@probe
def p_gate_emits_on_clean():
    """Clean evidence passes the gate and the emitter artifact is
    produced."""
    out = eq.emit_with_quality_gate(
        _control_source(), "json",
        [{"expectation_type": "expect_evidence_monotonic",
          "kwargs": {}}], _mono_items())
    return "HELD" if '"id": "SAS-EQ-001"' in out or \
        '"id":"SAS-EQ-001"' in out or "SAS-EQ-001" in out else "BREAK"


@probe
def p_no_silent_skip():
    """Every expectation yields exactly one result record, in order --
    nothing is ever silently skipped."""
    exps = [
        {"expectation_type": "expect_evidence_monotonic",
         "kwargs": {}},
        {"expectation_type": "expect_fields_present",
         "kwargs": {"required_fields": ["seq"]}},
        {"expectation_type": "expect_timestamps_ordered",
         "kwargs": {}},
    ]
    items = [{"seq": 1, "issued_at": "2026-10-01T00:00:00Z"},
             {"seq": 2, "issued_at": "2026-10-01T00:00:01Z"}]
    res = eq.evaluate(exps, items)
    if len(res["results"]) != 3:
        return "BREAK"
    types = [r["expectation_type"] for r in res["results"]]
    if types != [e["expectation_type"] for e in exps]:
        return "BREAK"
    stats = res["statistics"]
    if stats["evaluated_expectations"] != 3:
        return "BREAK"
    if stats["successful_expectations"] + \
            stats["unsuccessful_expectations"] != 3:
        return "BREAK"
    return "HELD" if res["success"] else "BREAK"


@probe
def p_evaluate_does_not_mutate():
    """evaluate() must not mutate caller-held expectations or evidence
    (F212 lesson)."""
    exps = [{"expectation_type": "expect_evidence_monotonic",
             "kwargs": {}}]
    items = _mono_items()
    exps_before = copy.deepcopy(exps)
    items_before = copy.deepcopy(items)
    eq.evaluate(exps, items)
    if exps != exps_before or items != items_before:
        return "BREAK"
    return "HELD"


@probe
def p_timestamps_ordered_caught():
    """Out-of-order timestamps must fail expect_timestamps_ordered."""
    items = [{"issued_at": "2026-10-01T00:00:02Z"},
             {"issued_at": "2026-10-01T00:00:01Z"}]
    res = eq.evaluate(
        [{"expectation_type": "expect_timestamps_ordered",
          "kwargs": {}}], items)
    return "HELD" if not res["success"] else "BREAK"


@probe
def p_fields_present_caught():
    """An item missing a required field must fail
    expect_fields_present."""
    items = [{"seq": 1}, {"note": "no seq"}]
    res = eq.evaluate(
        [{"expectation_type": "expect_fields_present",
          "kwargs": {"required_fields": ["seq"]}}], items)
    return "HELD" if not res["success"] else "BREAK"


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = [
        [sys.executable, "-m", "unittest", "tests.test_compliance_emitter",
         "-v"],
        [sys.executable, "-m", "unittest", "tests.test_decision_codes",
         "-v"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    td = "/var/tmp/g256-eq-green"
    os.makedirs(td, exist_ok=True)
    env["TMPDIR"] = td
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: compliance_emitter + decision_codes green")
    return True


def main():
    results = []
    if not HAVE_MODULE:
        for p in PROBES:
            results.append((p.__name__, "GAP"))
    else:
        for p in PROBES:
            try:
                results.append((p.__name__, p()))
            except Exception as exc:  # never mask a crash
                results.append((p.__name__, "BREAK(%r)" % (exc,)))
    held = sum(1 for _, v in results if v == "HELD")
    brk = sum(1 for _, v in results if v.startswith("BREAK"))
    gap = sum(1 for _, v in results if v == "GAP")
    for name, verdict in results:
        print("%-38s %s" % (name, verdict))
    print("HELD %d / BREAK %d / GAP %d of %d" % (held, brk, gap,
                                                 len(results)))
    ok = green_check()
    return held, brk, gap, ok


if __name__ == "__main__":
    held, brk, gap, ok = main()
    sys.exit(0 if (gap or (held, brk, gap) == (len(PROBES), 0, 0)) and ok
             else 1)
