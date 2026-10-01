"""Break-first red battery: single-source compliance emitter
(wave-254 lane 3; ComplianceAsCode/content ADAPT -- the single control
source emitting multi-format regulator artifacts only, never
ComplianceAsCode code or its content model).

The gap under test: regulator artifacts today come only from the
hand-mapped evidence crosswalk. A deployment that needs to claim a
control must be able to define ONE control source (id, title,
description, mappings to Sasanam controls/findings/codes) and emit it
in multiple formats (OSCAL component-definition, Markdown summary,
canonical JSON mapping) -- with every emitted claim traceable to
live Sasanam evidence. A mapping that dangles (unknown code,
finding, mechanism, or track) must refuse fail-closed, and a claim
with no evidence link must never be emitted.

On the pristine wave-253 base every probe reports GAP (the module
does not exist). After the build, every probe must report HELD under
both staging and a clean environment.

Synthetic/local only. Deterministic: fixed fixtures, sorted
assertions, no wall clock in asserted values. Stdlib only, no
in-repo git subprocesses. Fresh TMPDIR per process is the caller's
concern; this battery writes only inside the stdlib tempdir.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Repo root (this file lives in evals/) so `gov` is importable when the
# battery is run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# ------------------------------------------------------------------
# probe harness
# ------------------------------------------------------------------

RESULTS = []


def _record(name, verdict, detail=""):
    RESULTS.append({"probe": name, "verdict": verdict, "detail": detail})
    return verdict


def load_emitter_module():
    """Return (gov.compliance_emitter, None) or (None, reason)."""
    try:
        from gov import compliance_emitter
        return compliance_emitter, None
    except ImportError as exc:  # noqa: BLE001 - importability is the gap
        return None, str(exc)


def _gap_all(reason):
    for name in ("dangling-code-ref", "dangling-finding-ref",
                 "dangling-mechanism-ref", "dangling-track-ref",
                 "unlinked-claim", "malformed-source", "unknown-format",
                 "finding-ref-without-index", "valid-all-formats",
                 "malformed-findings-index"):
        _record(name, "GAP", reason)


# --- valid fixtures -------------------------------------------------

def _valid_source():
    return {
        "id": "SAS-COMP-001",
        "title": "Permit lifecycle evidence is tamper-evident",
        "description": "Bound permits are journaled in a hash-chained "
                       "journal and exportable as auditor evidence.",
        "mappings": [
            {"kind": "code", "ref": "permit-journal-misuse",
             "rationale": "refusal path for malformed journal events"},
            {"kind": "mechanism", "ref": "chained-audit-log",
             "rationale": "hash-chained append-only log"},
            {"kind": "posture_track", "ref": "durability",
             "rationale": "durability track covers journal health"},
        ],
    }


def _finding_source():
    src = _valid_source()
    src["id"] = "SAS-COMP-002"
    src["mappings"] = [
        {"kind": "finding", "ref": "F214",
         "rationale": "linked red-team finding"},
    ]
    return src


def _expect_refusal(probe_name, fn, code):
    """Run fn; HELD iff it raises the emitter error with `code`."""
    emitter, reason = load_emitter_module()
    if emitter is None:
        return _record(probe_name, "GAP", reason)
    try:
        fn(emitter)
    except emitter.ComplianceEmitterError as exc:
        if exc.code == code:
            return _record(probe_name, "HELD",
                           "refused with %s" % (code,))
        return _record(probe_name, "BREAK",
                       "wrong code: %s (want %s)" % (exc.code, code))
    except Exception as exc:  # noqa: BLE001 - a raw escape is a BREAK
        return _record(probe_name, "BREAK",
                       "escaped %r instead of %s" % (exc, code))
    return _record(probe_name, "BREAK",
                   "no refusal (want %s)" % (code,))


# --- probes ---------------------------------------------------------

def probe_dangling_code_ref():
    src = _valid_source()
    src["mappings"] = [{"kind": "code", "ref": "no-such-code-xyz",
                        "rationale": "dangling"}]
    _expect_refusal("dangling-code-ref",
                    lambda e: e.emit_json(src),
                    "compliance-emitter-unknown-code")


def probe_dangling_finding_ref():
    src = _finding_source()
    findings = {"F215": "open"}  # F214 absent -> dangling
    _expect_refusal("dangling-finding-ref",
                    lambda e: e.emit_json(src, findings=findings),
                    "compliance-emitter-unknown-finding")


def probe_dangling_mechanism_ref():
    src = _valid_source()
    src["mappings"] = [{"kind": "mechanism", "ref": "no-such-mech",
                        "rationale": "dangling"}]
    _expect_refusal("dangling-mechanism-ref",
                    lambda e: e.emit_json(src),
                    "compliance-emitter-unknown-mechanism")


def probe_dangling_track_ref():
    src = _valid_source()
    src["mappings"] = [{"kind": "posture_track", "ref": "no-such-track",
                        "rationale": "dangling"}]
    _expect_refusal("dangling-track-ref",
                    lambda e: e.emit_json(src),
                    "compliance-emitter-unknown-track")


def probe_unlinked_claim():
    src = _valid_source()
    src["mappings"] = []  # a claim with no evidence link must not emit
    _expect_refusal("unlinked-claim",
                    lambda e: e.emit_json(src),
                    "compliance-emitter-unlinked-claim")


def probe_malformed_source():
    src = _valid_source()
    del src["id"]
    _expect_refusal("malformed-source",
                    lambda e: e.emit_json(src),
                    "compliance-emitter-malformed")


def probe_unknown_format():
    src = _valid_source()
    _expect_refusal("unknown-format",
                    lambda e: e.emit(src, fmt="yaml"),
                    "compliance-emitter-unknown-format")


def probe_finding_ref_without_index():
    # A finding mapping with no deployment findings index supplied must
    # fail closed: the emitter cannot confirm the finding exists.
    src = _finding_source()
    _expect_refusal("finding-ref-without-index",
                    lambda e: e.emit_json(src),
                    "compliance-emitter-unknown-finding")


def probe_valid_all_formats():
    name = "valid-all-formats"
    emitter, reason = load_emitter_module()
    if emitter is None:
        return _record(name, "GAP", reason)
    src = _valid_source()
    try:
        oscal_a = emitter.emit_oscal(src, generated_at="2026-10-01T00:00:00Z")
        oscal_b = emitter.emit_oscal(src, generated_at="2026-10-01T00:00:00Z")
        md = emitter.emit_markdown(src)
        js_a = emitter.emit_json(src)
        js_b = emitter.emit_json(src)
        if oscal_a != oscal_b:
            return _record(name, "BREAK", "oscal not deterministic")
        if js_a != js_b:
            return _record(name, "BREAK", "json not deterministic")
        digest = emitter.source_content_digest(src)
        props = oscal_a["component-definition"]["metadata"]["props"]
        got = {p["name"]: p["value"] for p in props}.get(
            "x-compliance-source-sha256")
        if got != digest:
            return _record(name, "BREAK",
                           "oscal digest %r != module digest %r"
                           % (got, digest))
        # Traceability: the control id and every evidence ref must appear
        # in all three artifacts.
        blob = repr(oscal_a) + md + js_a
        for token in ("SAS-COMP-001", "permit-journal-misuse",
                      "chained-audit-log", "durability"):
            if token not in blob:
                return _record(name, "BREAK",
                               "token %r missing from artifacts" % (token,))
        return _record(name, "HELD",
                       "oscal+markdown+json deterministic, digest-bound")
    except Exception as exc:  # noqa: BLE001
        return _record(name, "BREAK", "%r" % (exc,))


def probe_malformed_findings_index():
    src = _finding_source()
    findings = {"F214": "bogus-status"}
    _expect_refusal("malformed-findings-index",
                    lambda e: e.emit_json(src, findings=findings),
                    "compliance-emitter-malformed")


# --- green checks (depth-1) -------------------------------------------

def _green():
    if SKIP_GREEN:
        return ["green-checks skipped (GOV_SKIP_GREEN=1)"]
    import subprocess
    notes = []
    for bat in ("evals/oscal_export_battery.py",
                "evals/w251_posture_probes.py"):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), bat)
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
        out = (proc.stdout or "") + (proc.stderr or "")
        bad = ("BREAK" in out and "0 BREAK" not in out) or \
              ("ERROR" in out and "0 ERROR" not in out)
        if proc.returncode != 0 or bad:
            raise AssertionError(
                "%s green check failed (rc=%d): %s"
                % (bat, proc.returncode, out[-2000:]))
        notes.append("%s: green" % bat)
    return notes


# --- main ---------------------------------------------------------------

def main():
    probes = [
        probe_dangling_code_ref,
        probe_dangling_finding_ref,
        probe_dangling_mechanism_ref,
        probe_dangling_track_ref,
        probe_unlinked_claim,
        probe_malformed_source,
        probe_unknown_format,
        probe_finding_ref_without_index,
        probe_valid_all_formats,
        probe_malformed_findings_index,
    ]
    for probe in probes:
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 - one bad probe
            # must not mask the rest.
            _record(probe.__name__, "ERROR", "%r" % (exc,))
    try:
        notes = _green()
    except Exception as exc:  # noqa: BLE001
        _record("green-checks", "ERROR", "%r" % (exc,))
        notes = []
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    gap = sum(1 for r in RESULTS if r["verdict"] == "GAP")
    brk = sum(1 for r in RESULTS if r["verdict"] == "BREAK")
    err = sum(1 for r in RESULTS if r["verdict"] == "ERROR")
    total = len(RESULTS)
    print("w254_compliance_probes: %d/%d HELD (%d GAP, %d BREAK, "
          "%d ERROR)" % (held, total, gap, brk, err))
    for r in RESULTS:
        print("  [%s] %s %s" % (r["verdict"], r["probe"],
                                r["detail"]))
    if notes:
        print("  green: %s" % ("; ".join(notes),))
    # Non-zero unless every probe HELD: GAP (pristine base) and any
    # BREAK/ERROR fail the battery.
    return 0 if (held == total and gap == 0 and brk == 0
                 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
