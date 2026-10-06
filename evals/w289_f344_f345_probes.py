"""Wave-289 lane 2 red-first battery: close F344 + F345.

F344 (LOW): non-JSON-serializable claim values nested inside list/dict
claims escape as an uncoded TypeError from submit_evidence / endorse /
_grade_dimension. Close-when: refuse LOUD with coded
``trustvec-evidence-invalid``.
F345 (LOW): gov/evidence_provenance.py's ``_emit`` calls the installed
audit sink without isolation, so a raising sink escapes
``verify_provenance`` / ``record_provenance_in_graph`` as the sink's own
uncoded exception type. Close-when: sink failures are isolated (swallowed
with a recorded failure mode, or recorded and refused coded) -- never the
sink's raw exception type.

Base: wave-288 push 18beb4044a26cba48bd895d95b505d7adc327422
(pin 1700; next free F346).

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g289-f344f345 && TMPDIR=/var/tmp/g289-f344f345 \\
    ~/workspace/.gov-venv/bin/python evals/w289_f344_f345_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g289-f344f345b \\
    ~/workspace/.gov-venv/bin/python evals/w289_f344_f345_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# No new decision codes: F344 reuses trustvec-evidence-invalid, F345
# swallows per the timestamp_authority precedent.
TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals not sorted")
    _record("pin-taxonomy", "HELD", "taxonomy %d unique/sorted" % len(lits))


_SCHEME = "w289.f344"


def _scheme():
    from gov import trust_vector as tv
    if _SCHEME not in tv.registered_schemes():
        tv.register_scheme(tv.SchemeDescriptor(
            _SCHEME, {"items": "list"}, []))


# ---------------------------------------------------------------------------
# F344: non-JSON-serializable claim values must refuse LOUD and coded.
# ---------------------------------------------------------------------------

def p_f344_submit_set():
    from gov import trust_vector as tv
    _scheme()
    try:
        tv.submit_evidence(_SCHEME, {"items": [{"s": {1, 2}}]}, "prodA")
    except TypeError as e:
        if getattr(e, "code", None) is None:
            return _record("f344-submit-set", "BREAK",
                           "raw TypeError escapes submit_evidence for a "
                           "set nested in a list claim -- expected coded "
                           "trustvec-evidence-invalid")
        return _record("f344-submit-set", "HELD",
                       "coded refusal: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == tv.EVIDENCE_INVALID:
            return _record("f344-submit-set", "HELD",
                           "coded refusal: %s" % (code,))
        return _record("f344-submit-set", "BREAK",
                       "unexpected failure type %s (code=%r)"
                       % (type(e).__name__, code))
    _record("f344-submit-set", "BREAK",
            "non-JSON claim silently accepted")


def p_f344_endorse_set():
    from gov import trust_vector as tv
    _scheme()
    ev = tv.submit_evidence(_SCHEME, {"items": ["ok"]}, "prodA")
    try:
        tv.endorse(ev, "items", {1, 2}, "srcB")
    except TypeError as e:
        if getattr(e, "code", None) is None:
            return _record("f344-endorse-set", "BREAK",
                           "raw TypeError escapes endorse for a set "
                           "expected_value -- expected coded "
                           "trustvec-evidence-invalid")
        return _record("f344-endorse-set", "HELD",
                       "coded refusal: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == tv.EVIDENCE_INVALID:
            return _record("f344-endorse-set", "HELD",
                           "coded refusal: %s" % (code,))
        return _record("f344-endorse-set", "BREAK",
                       "unexpected failure type %s (code=%r)"
                       % (type(e).__name__, code))
    _record("f344-endorse-set", "BREAK",
            "non-JSON endorsement value silently accepted")


def p_f344_grade_set():
    from gov import trust_vector as tv
    _scheme()
    # Build the evidence object directly (bypassing submit_evidence's
    # own digest computation) so the grade path is reached; the set
    # must still refuse coded inside _grade_dimension's _digest_value.
    ev = tv.Evidence(_SCHEME, {"items": [{"s": {1, 2}}]},
                     "prodA", "00" * 32)
    dim = {"name": "d", "rule": tv.RULE_ENDORSED_MATCH,
           "claims": ["items"]}
    end = tv.Endorsement(ev.digest, "items", "ff" * 32, "srcB", "00" * 32)
    try:
        tv._grade_dimension(ev, [end], None, dim)
    except TypeError as e:
        if getattr(e, "code", None) is None:
            return _record("f344-grade-set", "BREAK",
                           "raw TypeError escapes _grade_dimension for a "
                           "set nested in a claim -- expected coded "
                           "trustvec-evidence-invalid")
        return _record("f344-grade-set", "HELD",
                       "coded refusal: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == tv.EVIDENCE_INVALID:
            return _record("f344-grade-set", "HELD",
                           "coded refusal: %s" % (code,))
        return _record("f344-grade-set", "BREAK",
                       "unexpected failure type %s (code=%r)"
                       % (type(e).__name__, code))
    _record("f344-grade-set", "BREAK",
            "non-JSON claim graded instead of refused")


def p_f344_valid_json_still_accepted():
    from gov import trust_vector as tv
    _scheme()
    # Anti-over-refusal: ordinary nested JSON must keep working.
    try:
        ev = tv.submit_evidence(
            _SCHEME,
            {"items": ["a", 1, True, None, {"k": [1, 2]}, [3, 4]]},
            "prodA")
    except Exception as e:  # noqa: BLE001
        return _record("f344-valid-json", "BREAK",
                       "legit nested JSON refused: %s (code=%r)"
                       % (type(e).__name__, getattr(e, "code", None)))
    if not ev.digest:
        return _record("f344-valid-json", "BREAK", "digest missing")
    _record("f344-valid-json", "HELD",
            "nested JSON claims still accepted and digested")


# ---------------------------------------------------------------------------
# F345: audit-sink failures must be isolated from verification.
# ---------------------------------------------------------------------------

def _make_envelope():
    from gov import evidence_provenance as ep
    from gov import ed25519
    seed = ed25519.generate_seed()
    pub = ed25519.publickey(seed).hex()
    pol = ep.BuilderPolicy("w289pol", {"b1": pub})
    digest = "ab" * 32
    claim = ep.make_provenance_claim(
        "b1", "k1", digest,
        [{"uri": "u", "digest": digest, "completeness": "verified"}])
    envelope = ep.seal_provenance(claim, seed)
    return ep, pol, envelope


def p_f345_sink_raises_runtimeerror():
    from gov import evidence_provenance as ep
    ep, pol, envelope = _make_envelope()

    def bad_sink(evt):
        raise RuntimeError("sink is down")

    ep.set_emit(bad_sink)
    try:
        ok = ep.verify_provenance(envelope, pol)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f345-sink-runtimeerror", "BREAK",
                           "uncoded %s escapes verify_provenance -- sink "
                           "failure must be isolated from verification"
                           % type(e).__name__)
        return _record("f345-sink-runtimeerror", "BREAK",
                       "sink failure refused coded %r: a broken audit "
                       "sink must never break verification "
                       "(timestamp_authority precedent)"
                       % (code,))
    finally:
        ep.set_emit(None)
    if ok is not True:
        return _record("f345-sink-runtimeerror", "BREAK",
                       "verify returned %r" % (ok,))
    _record("f345-sink-runtimeerror", "HELD",
            "raising sink isolated: verification completed")


def p_f345_sink_raises_other_type():
    from gov import evidence_provenance as ep
    ep, pol, envelope = _make_envelope()

    def bad_sink(evt):
        raise ValueError("different sink failure shape")

    ep.set_emit(bad_sink)
    try:
        ok = ep.verify_provenance(envelope, pol)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("f345-sink-valueerror", "BREAK",
                           "uncoded %s escapes verify_provenance"
                           % type(e).__name__)
        return _record("f345-sink-valueerror", "BREAK",
                       "sink failure refused coded %r -- must not break "
                       "verification" % (getattr(e, "code", None),))
    finally:
        ep.set_emit(None)
    if ok is not True:
        return _record("f345-sink-valueerror", "BREAK",
                       "verify returned %r" % (ok,))
    _record("f345-sink-valueerror", "HELD",
            "arbitrary sink exception type isolated")


def p_f345_graphed_sink():
    from gov import evidence_provenance as ep
    from gov import guac_graph as gg
    ep, pol, envelope = _make_envelope()
    graph = gg.GuacGraph()

    def bad_sink(evt):
        raise KeyError("sink down")

    ep.set_emit(bad_sink)
    try:
        rec = ep.record_provenance_in_graph(graph, envelope, pol)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record("f345-sink-graphed", "BREAK",
                           "uncoded %s escapes record_provenance_in_graph"
                           % type(e).__name__)
        return _record("f345-sink-graphed", "BREAK",
                       "sink failure refused coded %r -- must not break "
                       "graph recording" % (getattr(e, "code", None),))
    finally:
        ep.set_emit(None)
    if not isinstance(rec, dict) or "evidence_node" not in rec:
        return _record("f345-sink-graphed", "BREAK",
                       "bad record: %r" % (rec,))
    _record("f345-sink-graphed", "HELD",
            "raising sink isolated from graph recording")


def p_f345_working_sink_still_emits():
    from gov import evidence_provenance as ep
    ep, pol, envelope = _make_envelope()
    seen = []

    def good_sink(evt):
        seen.append(evt)

    ep.set_emit(good_sink)
    try:
        ok = ep.verify_provenance(envelope, pol)
    finally:
        ep.set_emit(None)
    if ok is not True:
        return _record("f345-sink-working", "BREAK",
                       "verify returned %r" % (ok,))
    if not seen or seen[0].get("event") != "provenance-verified":
        return _record("f345-sink-working", "BREAK",
                       "working sink received no provenance-verified event")
    _record("f345-sink-working", "HELD",
            "working sink still receives audit events")


# ---------------------------------------------------------------------------
# Depth-1 green checks: adjacent batteries must stay green. The
# w288_redteam battery re-pins F344/F345, so after this fix it should
# show 1 BREAK expected-open (F343 only).
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        _record("green-checks", "HELD",
                "skipped via GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    checks = [
        ("evals/w287_provenance_probes.py", 0),
        # Merge-time (wave-289): F343 is also closed on the composed
        # tree (it was expected-open at lane time).
        ("evals/w288_redteam_probes.py", 0),
    ]
    for rel, expected_breaks in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w289-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR",
                    "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak != expected_breaks:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)"
                    % (nbreak, expected_breaks))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % nbreak)


def main():
    p_taxonomy_pin()
    p_f344_submit_set()
    p_f344_endorse_set()
    p_f344_grade_set()
    p_f344_valid_json_still_accepted()
    p_f345_sink_raises_runtimeerror()
    p_f345_sink_raises_other_type()
    p_f345_graphed_sink()
    p_f345_working_sink_still_emits()
    _green_checks()
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    helds = sum(1 for _, v, _ in _results if v == "HELD")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w289_f344_f345: %d BREAK / %d HELD / %d ERROR" %
          (breaks, helds, errors))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, breaks, helds, errors)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
