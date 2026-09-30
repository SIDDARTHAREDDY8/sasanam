#!/usr/bin/env python3
"""Wave-237 lane B: edited-approval refusal + re-propose (fissible ADR-0040).

Attack shapes at the public seam (break-first, red-first on base):
* approve-with-edits is refused at the adapter boundary: an approval
  whose action bytes differ from the proposal's canonical action bytes
  refuses with the named ``approval-edited`` -- never "close enough";
* a rebinding attempt -- an approval referencing proposal id X but
  carrying action bytes matching proposal Y -- refuses with the named
  ``approval-rebinding`` (IDOR-shaped); id/action consistency is
  verified, never assumed from the id alone;
* the honest path: the edited action is re-proposed as a NEW proposal
  (fresh id, fresh digest, no link to the old approval); a subsequent
  clean approval consumes normally;
* byte-identical approvals pass; semantically-identical-but-byte-
  different JSON wire shapes pass (JCS canonicalization, same idiom as
  gov/permit_closure.py); opaque non-JSON bytes bind byte-exact.

Seams under test:
* gov/approval_edit_guard.py -- propose, check_approval, repropose.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-236 HEAD 9a725ce5fac37b95a2502eaebebfc33e7a8fb0d0.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g237b
  TMPDIR=/var/tmp/g237b ~/workspace/.gov-venv/bin/python evals/w237_editedapproval_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_NEW_API = False
try:
    from gov import approval_edit_guard as _aeg
    HAVE_NEW_API = all(hasattr(_aeg, n) for n in (
        "ApprovalEditGuardError", "propose", "check_approval", "repropose"))
except ImportError:
    _aeg = None

PROBE_NAMES = [
    "editedapproval-happy-path",
    "editedapproval-edited-refused",
    "editedapproval-rebinding-refused",
    "editedapproval-repropose-clean",
    "editedapproval-single-bit-tamper",
    "editedapproval-canonical-wire-shape",
    "editedapproval-malformed-refused",
]


def _action_json():
    return b'{"action":"deploy","params":{"tag":"v1.2.3"},"target":"prod"}'


def _propose(action_bytes=None, proposal_id="proposal-A"):
    return _aeg.propose(
        action_bytes if action_bytes is not None else _action_json(),
        proposal_id=proposal_id)


def _approve(proposal, action_bytes, proposal_id=None):
    return {
        "proposal_id": proposal_id if proposal_id is not None
        else proposal["proposal_id"],
        "action_bytes": action_bytes,
    }


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
        proposal = _propose()
        approval = _approve(proposal, _action_json())
        assert _aeg.check_approval(proposal, approval) is True
        assert len(proposal["action_digest"]) == 64, proposal
        _rec(results, PROBE_NAMES[0], "HELD",
             "proposal_id=%s digest=%s..."
             % (proposal["proposal_id"], proposal["action_digest"][:16]))
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[0], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[0], "ERROR", traceback.format_exc(limit=2))


def _p2_edited_refused(results):
    try:
        proposal = _propose()
        edited = b'{"action":"deploy","params":{"tag":"v9.9.9"},"target":"prod"}'
        approval = _approve(proposal, edited)
        v, detail = _expect_code(
            lambda: _aeg.check_approval(proposal, approval),
            "approval-edited")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[1], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[1], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[1], "ERROR", traceback.format_exc(limit=2))


def _p3_rebinding_refused(results):
    try:
        prop_x = _propose(_action_json(), proposal_id="proposal-X")
        bytes_y = b'{"action":"wipe","params":{"tag":"v1.2.3"},"target":"prod"}'
        prop_y = _propose(bytes_y, proposal_id="proposal-Y")
        # Approval genuinely bound to proposal-Y (its bytes match Y),
        # but presented in proposal-X's context.
        approval = _approve(prop_y, bytes_y)
        v, detail = _expect_code(
            lambda: _aeg.check_approval(prop_x, approval),
            "approval-rebinding")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[2], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[2], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[2], "ERROR", traceback.format_exc(limit=2))


def _p4_repropose_clean(results):
    try:
        proposal = _propose()
        edited = b'{"action":"deploy","params":{"tag":"v2.0.0"},"target":"prod"}'
        # The edited approval is refused at the boundary...
        v, detail = _expect_code(
            lambda: _aeg.check_approval(
                proposal, _approve(proposal, edited)),
            "approval-edited")
        assert v == "HELD", detail
        # ...so the edited action is re-proposed as a NEW proposal.
        fresh = _aeg.repropose(edited)
        assert fresh["proposal_id"] != proposal["proposal_id"], fresh
        assert fresh["action_digest"] != proposal["action_digest"], fresh
        assert "supersedes" not in fresh and "approval" not in fresh, fresh
        # A subsequent clean approval against the fresh proposal consumes.
        assert _aeg.check_approval(
            fresh, _approve(fresh, edited)) is True
        _rec(results, PROBE_NAMES[3], "HELD",
             "fresh proposal_id=%s" % fresh["proposal_id"])
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[3], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[3], "ERROR", traceback.format_exc(limit=2))


def _p5_single_bit_tamper(results):
    try:
        proposal = _propose()
        tampered = bytearray(_action_json())
        tampered[20] ^= 0x01
        approval = _approve(proposal, bytes(tampered))
        v, detail = _expect_code(
            lambda: _aeg.check_approval(proposal, approval),
            "approval-edited")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[4], "HELD", detail)
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[4], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[4], "ERROR", traceback.format_exc(limit=2))


def _p6_canonical_wire_shape(results):
    try:
        proposal = _propose()
        # Byte-different but semantically identical wire shape: key order
        # and whitespace changed. JCS canonicalization must bind it.
        other = (b'{ "target" : "prod" , "action" : "deploy" , '
                 b'"params" : { "tag" : "v1.2.3" } }')
        assert other != _action_json(), "fixture must be byte-different"
        approval = _approve(proposal, other)
        assert _aeg.check_approval(proposal, approval) is True
        # Opaque (non-JSON) bytes bind byte-exact: a reordered payload
        # that is NOT parseable JSON must refuse.
        opaque = _aeg.propose(b"\x00\x01opaque-payload",
                              proposal_id="proposal-opaque")
        v, detail = _expect_code(
            lambda: _aeg.check_approval(
                opaque, _approve(opaque, b"\x01\x00opaque-payload")),
            "approval-edited")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[5], "HELD",
             "JCS binds; opaque binds byte-exact")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[5], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[5], "ERROR", traceback.format_exc(limit=2))


def _p7_malformed_refused(results):
    try:
        proposal = _propose()
        # A proposal that is not a record at all.
        v, detail = _expect_code(
            lambda: _aeg.check_approval("not-a-proposal",
                                        _approve(proposal, _action_json())),
            "approval-malformed")
        assert v == "HELD", detail
        # An approval missing its action bytes.
        v, detail = _expect_code(
            lambda: _aeg.check_approval(
                proposal, {"proposal_id": proposal["proposal_id"]}),
            "approval-malformed")
        assert v == "HELD", detail
        # A proposal whose digest is not a bare digest.
        bad = dict(proposal)
        bad["action_digest"] = "not-a-digest"
        v, detail = _expect_code(
            lambda: _aeg.check_approval(
                bad, _approve(proposal, _action_json())),
            "approval-malformed")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[6], "HELD",
             "non-record, missing action_bytes, bad digest all refused")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[6], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[6], "ERROR", traceback.format_exc(limit=2))


def _run_all():
    results = {}
    _p1_happy(results)
    _p2_edited_refused(results)
    _p3_rebinding_refused(results)
    _p4_repropose_clean(results)
    _p5_single_bit_tamper(results)
    _p6_canonical_wire_shape(results)
    _p7_malformed_refused(results)
    return results


def main():
    t0 = time.time()
    if not HAVE_NEW_API:
        for name in PROBE_NAMES:
            print("%-42s GAP (approval-edit-guard module absent)" % name)
        print("summary: 0 HELD / %d GAP / 0 BREAK / 0 ERROR"
              % len(PROBE_NAMES))
        return 2
    results = _run_all()

    def _v(name):
        return results.get(name, "ERROR: missing").split("\n")[0]
    held = sum(1 for name in PROBE_NAMES if _v(name) == "HELD")
    gap = sum(1 for name in PROBE_NAMES if _v(name).startswith("GAP"))
    brk = sum(1 for name in PROBE_NAMES if _v(name).startswith("BREAK"))
    err = sum(1 for name in PROBE_NAMES if _v(name).startswith("ERROR"))
    for name in PROBE_NAMES:
        verdict = results.get(name, "ERROR: missing")
        first = verdict.split("\n")[0]
        print("%-42s %s" % (name, first))
        if "\n" in verdict:
            print(verdict.split("\n", 1)[1])
    print("summary: %d HELD / %d GAP / %d BREAK / %d ERROR (%.1fs)"
          % (held, gap, brk, err, time.time() - t0))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
