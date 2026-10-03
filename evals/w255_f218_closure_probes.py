"""F218 closure battery: deep-nesting payload must refuse with
permit-journal-misuse instead of escaping raw RecursionError.

Wave-255 lane 3 (F218 closure). Stdlib only. Red-first: on the pristine
wave-254 base, `journal/deep-nesting-misuse` BREAKs (raw RecursionError
escapes grant()); on fixed code it HELDs (PermitJournalRefusal with
permit-journal-misuse, no partial write). Deterministic across runs
(staging + `env -u GOV_DEPLOYMENT_MODE`).

Related finding: F218 (LOW, OPEN on base). Next free: F219.
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import permit_journal as pj  # noqa: E402

TAXONOMY_PIN = 1828  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*)

assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN,\
    "taxonomy drift: %d != %d" % (len(decision_codes.TAXONOMY),  # Wave-258 merge: pin -> 1080.
                                  TAXONOMY_PIN)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w255f218-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _journal():
    return pj.PermitJournal(os.path.join(_tmpdir(), "j.jsonl"),
                            key=os.urandom(32))


def _nested(depth=3000):
    nested, cur = {}, None
    cur = nested
    for _ in range(depth):
        cur["x"] = {}
        cur = cur["x"]
    return nested


def _misuse_expected(fn, label):
    try:
        fn()
    except pj.PermitJournalRefusal as exc:
        if exc.code == "permit-journal-misuse":
            return _held(label)
        return _break("%s: wrong code %s" % (label, exc.code))
    except Exception as exc:
        return _break("%s: raw %s escaped" % (label,
                                              type(exc).__name__))
    return _break("%s: misuse accepted" % label)


# ---------------------------------------------------------------------------
# F218: the defect probe
# ---------------------------------------------------------------------------

@probe("journal/deep-nesting-misuse")
def _p_deep_nesting():
    # Deeply nested payload must refuse with permit-journal-misuse,
    # not escape a raw RecursionError from json.dumps. Refusal must
    # happen before any durable write (no partial write).
    j = _journal()
    try:
        j.grant("P1", payload={"nested": _nested()})
    except pj.PermitJournalRefusal as exc:
        if exc.code != "permit-journal-misuse":
            return _break("deep nesting: wrong code %s" % exc.code)
    except RecursionError:
        return _break("F218: raw RecursionError escaped "
                      "permit-journal-misuse")
    except Exception as exc:
        return _break("deep nesting: raw %s escaped"
                      % type(exc).__name__)
    else:
        return _break("deep nesting: granted without error")
    # No partial write: the journal must still be empty of P1,
    # even on a fresh reload from disk.
    if j.permit_ids():
        return _break("deep nesting: partial write on refusal")
    j2 = pj.PermitJournal(j._path, key=j._key)
    if j2.permit_ids():
        return _break("deep nesting: durable partial write on refusal")
    return _held("deep nesting refused permit-journal-misuse, "
                 "no partial write")


@probe("journal/deep-nesting-record-use")
def _p_deep_nesting_record_use():
    # All public append paths share _build_body's guard: record_use
    # with a deeply nested payload must hit the same refusal.
    j = _journal()
    j.grant("P1", payload={"ok": True})
    return _misuse_expected(
        lambda: j.record_use("P1", payload={"nested": _nested()}),
        "deep nesting on record_use")


@probe("journal/depth-bound-pins")
def _p_depth_bound_pins():
    # The depth bound must not over-refuse: a payload at depth 150 is
    # accepted, a payload at depth 201 is refused with misuse.
    j = _journal()
    try:
        j.grant("P150", payload={"nested": _nested(150)})
    except Exception as exc:  # noqa: BLE001
        return _break("depth 150 refused: %s" % type(exc).__name__)
    if "P150" not in j.permit_ids():
        return _break("depth 150 grant not recorded")
    return _misuse_expected(
        lambda: j.grant("P201", payload={"nested": _nested(201)}),
        "depth 201")


# ---------------------------------------------------------------------------
# Regression pins (F214 class + adjacent misuse shapes)
# ---------------------------------------------------------------------------

@probe("journal/set-payload-misuse")
def _p_set_payload():
    # F214 regression pin: non-serializable payload -> misuse code.
    return _misuse_expected(
        lambda: _journal().grant("P1", payload={"s": {1, 2}}),
        "set payload")


@probe("journal/payload-non-dict-misuse")
def _p_payload_nondict():
    return _misuse_expected(
        lambda: _journal().grant("P1", payload=["not", "a", "dict"]),
        "non-dict payload")


@probe("journal/empty-permit-id-misuse")
def _p_empty_permit_id():
    return _misuse_expected(
        lambda: _journal().grant("", payload={"ok": True}),
        "empty permit_id")


@probe("journal/empty-event-id-misuse")
def _p_empty_event_id():
    return _misuse_expected(
        lambda: _journal().grant("P1", payload={"ok": True},
                                 event_id=""),
        "empty event_id")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_battery(verbose=True):
    held, broken, errors = 0, 0, []
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001
            verdict, detail = "ERROR", "%r" % (exc,)
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broken += 1
        else:
            errors.append(name)
        if verbose:
            print("%s  %s  %s" % (verdict.ljust(5), name, detail))
    print("HELD=%d BREAK=%d ERROR=%d (%d probes)" %
          (held, broken, len(errors), len(_PROBES)))
    return held, broken, errors


def _green_check():
    # Depth-1 green check: honors GOV_SKIP_GREEN, spawns nothing.
    skip = os.environ.get("GOV_SKIP_GREEN") == "1"
    if skip:
        return {"skipped": "GOV_SKIP_GREEN=1 (parent gate runs suites)"}
    return {}


def main():
    notes = _green_check()
    if notes.get("skipped"):
        print("green check skipped:", notes["skipped"])
    held, broken, errors = run_battery(verbose=True)
    if broken or errors:
        print("RED: %d BREAK, %d ERROR" % (broken, len(errors)))
        return 1
    print("GREEN: %d HELD, 0 BREAK, 0 ERROR" % held)
    return 0


if __name__ == "__main__":
    sys.exit(main())
