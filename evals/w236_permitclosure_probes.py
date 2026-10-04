#!/usr/bin/env python3
"""Wave-236 lane C: permit/closure pre/post attestation split.

Attack shapes at the public seams (break-first, red-first on base):
* a signed Permit binds the decision to the canonical REQUEST bytes
  pre-dispatch; dispatch with different actual bytes refuses with the
  named ``permit-binding-mismatch``;
* dispatch without any Permit refuses ``dispatch-without-permit``;
* a signed Closure record post-execution binds to the Permit's digest;
  a Closure presented without its matching Permit refuses
  ``closure-permit-absent``; a Closure whose bound permit digest does
  not match refuses ``closure-permit-mismatch``;
* the verifier lineage vocabulary enforces narrowing: a Closure may
  narrow (a subset of the permitted effects) but never widen the
  Permit's scope; widening refuses ``closure-scope-widened``;
* tampered permit or closure records refuse via the existing
  ``permit-malformed`` / ``permit-tampered`` codes.

Seams under test:
* gov/permit_closure.py -- issue_permit, verify_permit, dispatch,
  issue_closure, verify_closure.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-235 HEAD 3a5c97f6b421c89791b0c7811efe804252701dff.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g236c
  TMPDIR=/var/tmp/g236c ~/workspace/.gov-venv/bin/python evals/w236_permitclosure_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_NEW_API = False
try:
    from gov import permit_closure as _pc
    HAVE_NEW_API = all(hasattr(_pc, n) for n in (
        "PermitClosureError", "issue_permit", "verify_permit", "dispatch",
        "issue_closure", "verify_closure"))
except ImportError:
    _pc = None

PROBE_NAMES = [
    "permitclosure-happy-path",
    "permitclosure-dispatch-without-permit",
    "permitclosure-binding-mismatch",
    "permitclosure-closure-without-permit",
    "permitclosure-closure-permit-mismatch",
    "permitclosure-closure-widened-refused",
    "permitclosure-tampered-permit-refused",
]


def _decision():
    return {"action": "deploy", "target": "prod", "decision": "permit"}


def _request_json():
    return b'{"action":"deploy","params":{"tag":"v1.2.3"},"target":"prod"}'


def _scope():
    return ["deploy:prod", "deploy:staging", "logs:read"]


def _issue():
    return _pc.issue_permit(_decision(), _request_json(), _scope())


def _expect_code(fn, code):
    """Run fn; return ("HELD", detail) iff an exception with the
    exact machine code is raised, else ("BREAK"/"ERROR", detail)."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - battery records, never masks
        got = getattr(exc, "code", None)
        if got is None:
            got = type(exc).__name__
        if got == code:
            return ("HELD", "raised %r" % (got,))
        return ("BREAK", "wrong code: %r (want %r): %s"
                % (got, code, str(exc)[:160]))
    return ("BREAK", "no refusal raised (want %r)" % (code,))


def _rec(results, name, verdict, detail=""):
    results[name] = verdict if not detail else "%s\n  %s" % (verdict, detail)


def _p1_happy(results):
    try:
        permit = _issue()
        assert permit["version"] == 1, permit
        assert len(permit["permit_digest"]) == 64, permit
        assert len(permit["request_digest"]) == 64, permit
        assert _pc.verify_permit(permit) is True
        # Byte-different but semantically identical wire shape binds.
        other = b'{"target":"prod","action":"deploy","params":{"tag":"v1.2.3"}}'
        assert _pc.dispatch(permit, other) is True
        # Narrowing closure: subset of the permitted effects.
        closure = _pc.issue_closure(
            permit, "ab" * 32, ["deploy:prod", "logs:read"])
        assert _pc.verify_closure(closure, permit) is True
        _rec(results, PROBE_NAMES[0], "HELD",
             "permit_digest=%s..." % permit["permit_digest"][:16])
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[0], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[0], "ERROR", traceback.format_exc(limit=2))


def _p2_dispatch_without_permit(results):
    try:
        v, detail = _expect_code(
            lambda: _pc.dispatch(None, _request_json()),
            "dispatch-without-permit")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[1], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[1], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[1], "ERROR", traceback.format_exc(limit=2))


def _p3_binding_mismatch(results):
    try:
        permit = _issue()
        other = b'{"action":"deploy","target":"prod","params":{"tag":"v9.9.9"}}'
        v, detail = _expect_code(
            lambda: _pc.dispatch(permit, other), "permit-binding-mismatch")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[2], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[2], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[2], "ERROR", traceback.format_exc(limit=2))


def _p4_closure_without_permit(results):
    try:
        permit = _issue()
        closure = _pc.issue_closure(permit, "ab" * 32, ["deploy:prod"])
        v, detail = _expect_code(
            lambda: _pc.verify_closure(closure, None),
            "closure-permit-absent")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[3], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[3], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[3], "ERROR", traceback.format_exc(limit=2))


def _p5_closure_permit_mismatch(results):
    try:
        permit = _issue()
        # A closure legitimately issued against a DIFFERENT permit:
        # the record is untampered, the two halves disagree.
        other = _pc.issue_permit(_decision(), _request_json(), _scope(),
                                 permit_id="permit-other")
        closure = _pc.issue_closure(other, "ab" * 32, ["deploy:prod"])
        v, detail = _expect_code(
            lambda: _pc.verify_closure(closure, permit),
            "closure-permit-mismatch")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[4], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[4], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[4], "ERROR", traceback.format_exc(limit=2))


def _p6_closure_widened(results):
    try:
        permit = _issue()
        # Closure claims an effect outside the permitted scope.
        closure = _pc.issue_closure(
            permit, "ab" * 32, ["deploy:prod", "secrets:read"])
        v, detail = _expect_code(
            lambda: _pc.verify_closure(closure, permit),
            "closure-scope-widened")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[5], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[5], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[5], "ERROR", traceback.format_exc(limit=2))


def _p7_tampered_permit(results):
    try:
        permit = _issue()
        tampered = dict(permit)
        tampered["scope"] = ["*"]
        v, detail = _expect_code(
            lambda: _pc.verify_permit(tampered), "permit-tampered")
        assert v == "HELD", detail
        # A tampered permit never reaches dispatch.
        v, detail = _expect_code(
            lambda: _pc.dispatch(tampered, _request_json()),
            "permit-tampered")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[6], "HELD",
             "edited permit refused permit-tampered; dispatch unreachable")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[6], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[6], "ERROR", traceback.format_exc(limit=2))


def _run_all():
    results = {}
    _p1_happy(results)
    _p2_dispatch_without_permit(results)
    _p3_binding_mismatch(results)
    _p4_closure_without_permit(results)
    _p5_closure_permit_mismatch(results)
    _p6_closure_widened(results)
    _p7_tampered_permit(results)
    return results


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: GAP -> BREAK.
# The verdict token is the first word of the recorded verdict string; the
# original first line is kept verbatim as the note (evidence preserved), with
# any multi-line detail collapsed to its first line (" // "-joined).
# Unknown tokens fail closed as ERROR (loud, never silent). Raw results keep
# the battery's own vocabulary (count code and exit contract untouched); the
# mapping happens at emission.
_VERDICT_TOKEN_MAP = {"HELD": "HELD", "GAP": "BREAK", "BREAK": "BREAK",
                      "ERROR": "ERROR"}


def _split_row(name, v):
    first = probe_lines.first_line(v)
    tok = (first.split(":")[0].split() or [""])[0]
    mapped = _VERDICT_TOKEN_MAP.get(tok)
    if mapped is None:
        return {"probe_id": name, "verdict": "ERROR",
                "note": "unparseable verdict string: %r" % (first,)}
    _, _, rest = v.partition("\n")
    rest_first = probe_lines.first_line(rest).strip()
    note = first if not rest_first else first + " // " + rest_first
    return {"probe_id": name, "verdict": mapped, "note": note}

def main():
    t0 = time.time()
    if not HAVE_NEW_API:
        rows = [{"probe_id": name, "verdict": "BREAK",
                 "note": "GAP (permit-closure module absent)"} for name in PROBE_NAMES]
        probe_lines.emit_dicts(rows)
        print("%d BREAK / %d HELD / %d ERROR" % (len(PROBE_NAMES), 0, 0))
        return 2
    results = _run_all()

    def _v(name):
        return results.get(name, "ERROR: missing").split("\n")[0]
    held = sum(1 for name in PROBE_NAMES if _v(name) == "HELD")
    gap = sum(1 for name in PROBE_NAMES if _v(name).startswith("GAP"))
    brk = sum(1 for name in PROBE_NAMES if _v(name).startswith("BREAK"))
    err = sum(1 for name in PROBE_NAMES if _v(name).startswith("ERROR"))
    rows = [_split_row(name, results.get(name, "ERROR: missing"))
            for name in PROBE_NAMES]
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(r["probe_id"], r["verdict"], r["note"]) for r in rows],
        brk + gap, held, err)
    probe_lines.emit_dicts(rows)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR (%.1fs)"
          % (brk + gap, held, err, time.time() - t0))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
