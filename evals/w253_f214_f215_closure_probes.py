"""Break-first closure battery for F214 + F215.

Wave-253 lane 1 (closure). Stdlib only. Deterministic across runs
(staging + `env -u GOV_DEPLOYMENT_MODE`).

F214: PermitJournal._build_body must refuse non-serializable
payloads with PermitJournalRefusal carrying "permit-journal-misuse"
-- no raw TypeError escapes a public append path. The refusal still
writes nothing: the journal must verify cleanly afterwards.

F215: posture_cards.issue_summary / track_level must refuse
non-dict cards with PostureCardError carrying
"posture-card-malformed" -- no raw AttributeError escapes a public
path. Valid cards still sign and verify (no over-refusal).
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import permit_journal as pj  # noqa: E402
from gov import posture_cards as pc  # noqa: E402

TAXONOMY_PIN = 1951 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w253c-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


# ---------------------------------------------------------------------------
# F214: permit-journal non-serializable payload
# ---------------------------------------------------------------------------

@probe("f214/non-serializable-payload")
def _p_f214():
    # grant() with a set inside the payload: on the pristine base this
    # escaped as a raw TypeError from json.dumps inside event_mac.
    # Fixed code must refuse PermitJournalRefusal(misuse).
    path = os.path.join(_tmpdir(), "j.jsonl")
    journal = pj.PermitJournal(path, key=b"k" * 32)
    try:
        journal.grant("p1", {"bad": {1, 2, 3}})
    except pj.PermitJournalError as exc:
        assert exc.code == pj.MISUSE_CODE, exc.code
        return _held("non-serializable payload -> misuse code")
    except TypeError:
        return _break("F214: raw TypeError escapes grant()")
    return _break("F214: non-serializable payload silently accepted")


@probe("f214/no-partial-write")
def _p_f214_nowrite():
    # The refusal must leave the journal untouched: no event for p1
    # may exist and a fresh journal over the same file verifies.
    path = os.path.join(_tmpdir(), "j.jsonl")
    journal = pj.PermitJournal(path, key=b"k" * 32)
    try:
        journal.grant("p1", {"bad": {1, 2, 3}})
    except Exception:  # noqa: BLE001 -- either error shape refuses
        pass
    st = journal.permit_state("p1")
    assert st["n_events"] == 0, st
    reloaded = pj.PermitJournal(path, key=b"k" * 32)
    assert reloaded.permit_ids() == [], reloaded.permit_ids()
    return _held("refused grant wrote nothing; journal verifies")


@probe("f214/serializable-still-works")
def _p_f214_sane():
    # Regression guard: the wrap must not refuse honest payloads.
    path = os.path.join(_tmpdir(), "j.jsonl")
    journal = pj.PermitJournal(path, key=b"k" * 32)
    body = journal.grant("p1", {"scope": "read", "n": 3})
    assert body["permit_id"] == "p1", body
    assert journal.permit_state("p1")["state"] == "granted"
    return _held("honest payload grants normally")


# ---------------------------------------------------------------------------
# F215: posture_cards non-dict cards
# ---------------------------------------------------------------------------

def _valid_cards():
    return [
        {"check": "a", "track": "supply-chain", "probe": "pass",
         "score": 10, "reason": "r", "remediation": "none"},
        {"check": "b", "track": "identity", "probe": "fail",
         "score": 0, "reason": "r", "remediation": "x"},
    ]


@probe("f215/non-dict-cards-issue-summary")
def _p_f215_issue():
    # On the pristine base this escaped as AttributeError from
    # c.get("track") inside track_level. Fixed code must refuse
    # PostureCardError(malformed).
    seed = bytes(range(32))
    try:
        pc.issue_summary("s", ["not-a-dict"], seed, issuer="me")
    except pc.PostureCardError as exc:
        assert exc.code == pc.MALFORMED, exc.code
        return _held("non-dict cards -> posture-card-malformed")
    except AttributeError:
        return _break("F215: raw AttributeError escapes issue_summary")
    return _break("F215: non-dict cards silently accepted")


@probe("f215/non-dict-cards-track-level")
def _p_f215_track():
    # track_level is the shared read path; it must validate too.
    try:
        pc.track_level(["not-a-dict"], "supply-chain")
    except pc.PostureCardError as exc:
        assert exc.code == pc.MALFORMED, exc.code
        return _held("non-dict cards -> posture-card-malformed")
    except AttributeError:
        return _break("F215: raw AttributeError escapes track_level")
    return _break("F215: non-dict cards silently accepted")


@probe("f215/valid-cards-still-work")
def _p_f215_sane():
    # Regression guard: valid cards still sign and verify.
    seed = bytes(range(32))
    summary = pc.issue_summary("s", _valid_cards(), seed, issuer="me")
    record = pc.verify_summary(summary)
    assert record["subject"] == "s", record
    assert pc.track_level(_valid_cards(), "supply-chain") == "full"
    assert pc.track_level(_valid_cards(), "identity") == "absent"
    return _held("valid cards sign/verify; levels compute")


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

def main():
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (  # Wave-258 merge: pin -> 1080.
        "taxonomy pin: expected %d, got %d"
        % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))  # Wave-258 merge: pin -> 1080.
    held, broken, errors = 0, 0, 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = ("ERROR", "%r" % (exc,))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broken += 1
        else:
            errors += 1
        print("%-42s %-6s %s" % (name, verdict, detail))
    print("probes=%d held=%d break=%d error=%d"
          % (len(_PROBES), held, broken, errors))
    return 0 if (broken == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
