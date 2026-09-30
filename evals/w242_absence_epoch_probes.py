"""Wave-242 TACET signed-absence-epoch mechanism probes (W242-9, red-first).

ADAPT, pattern only, prose re-derived: beacon-opened hourly epochs,
signed observations-of-absence, sparse Merkle map, offline-verifiable
portable format -- the shape for our non-exfiltration absence story.
NOT the Bitcoin anchor. No upstream code is read, imported, or
vendored.

Probes:
  absence-epoch-open-observe-verify -- happy path: open epoch, observe
      absence for a scope, close, verify_absence returns True.
  absence-forged-claim-rejected -- a disclosure exists for (epoch,
      scope); an attacker's absence observation for the same cell
      refuses absence-disclosure-recorded (the committed root, not
      the attacker's claim, is the authority).
  absence-backdated-claim-rejected -- an observation whose observed_at
      is after the epoch close refuses absence-backdated.
  absence-observation-after-close-refused -- observing into a closed
      epoch refuses absence-epoch-closed.
  absence-tampered-root-rejected -- a bundle whose ledger no longer
      matches the closed root refuses absence-root-mismatch.
  absence-unsigned-beacon-rejected -- a beacon with a corrupted
      signature refuses absence-epoch-beacon-unsigned.
  absence-offline-portable -- the bundle survives a JSON round-trip
      and verifies with no network dependency: the module imports no
      socket/urllib/requests/http, and verification runs in a fresh
      subprocess importing only this module.

Stdlib only (plus in-repo gov.ed25519, pure-Python, per wave-241
precedent). Deterministic: fixed epoch numbers and injected times.
No in-repo git subprocesses.
"""

import io
import copy
import json
import os
import subprocess
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_NEW_API = False
try:
    from gov import absence_epoch as _ax
    HAVE_NEW_API = all(hasattr(_ax, n) for n in (
        "EPOCH_SECONDS", "epoch_of", "open_epoch", "observe_absence",
        "record_disclosure", "close_epoch", "make_bundle",
        "verify_absence", "AbsenceEpochError"))
except ImportError:
    _ax = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

EPOCH = 41000                      # fixed, deterministic epoch
T_OPEN = EPOCH * 3600               # epoch start (seconds)
T_MID = T_OPEN + 1800              # mid-epoch
T_CLOSE = T_OPEN + 3600            # epoch end / close time
SCOPE = "egress:corp-net"

PROBE_NAMES = [
    "absence-epoch-open-observe-verify",
    "absence-forged-claim-rejected",
    "absence-backdated-claim-rejected",
    "absence-observation-after-close-refused",
    "absence-tampered-root-rejected",
    "absence-unsigned-beacon-rejected",
    "absence-offline-portable",
]


def _run_probe(name, fn):
    if not HAVE_NEW_API:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    """fn must raise AbsenceEpochError with .code == code; returns note."""
    try:
        fn()
    except _ax.AbsenceEpochError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


def _keys():
    beacon_seed = bytes(range(32))
    observer_seed = bytes([200]) * 32
    return beacon_seed, observer_seed


def _setup_closed():
    """A closed epoch with one honest absence observation."""
    beacon_seed, observer_seed = _keys()
    beacon = _ax.open_epoch(beacon_seed, EPOCH, "00" * 32, T_OPEN)
    ledger = {}
    obs = _ax.observe_absence(observer_seed, beacon, SCOPE, T_MID)
    ledger[SCOPE] = obs
    close = _ax.close_epoch(beacon_seed, EPOCH, ledger, "00" * 32,
                            T_CLOSE)
    bundle = _ax.make_bundle([beacon], [close],
                             {str(EPOCH): ledger},
                             {"beacon": _ax.pub_of(beacon_seed),
                              "observer": _ax.pub_of(observer_seed)})
    return beacon_seed, observer_seed, beacon, ledger, close, bundle


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_open_observe_verify():
    beacon_seed, observer_seed, _b, _l, _c, bundle = _setup_closed()
    ok = _ax.verify_absence(bundle, EPOCH, SCOPE,
                            _ax.pub_of(observer_seed), T_CLOSE + 10)
    assert ok is True, "verify_absence did not return True"
    return "happy path verifies"


def _probe_forged_claim_rejected():
    beacon_seed, observer_seed = _keys()
    attacker_seed = bytes([7]) * 32
    beacon = _ax.open_epoch(beacon_seed, EPOCH, "00" * 32, T_OPEN)
    # The deployment's honest ledger records a DISCLOSURE for SCOPE.
    ledger = {}
    ledger[SCOPE] = _ax.record_disclosure(bytes([9]) * 32, beacon, SCOPE,
                                          T_MID, "deadbeef" * 8)
    close = _ax.close_epoch(beacon_seed, EPOCH, ledger, "00" * 32,
                            T_CLOSE)
    bundle = _ax.make_bundle([beacon], [close],
                             {str(EPOCH): ledger},
                             {"beacon": _ax.pub_of(beacon_seed),
                              "attacker": _ax.pub_of(attacker_seed)})
    # Snapshot the honest ledger BEFORE the attacker's swap (make_bundle
    # copies the outer dict but shares the inner ledger dict).
    honest_ledger = copy.deepcopy(ledger)
    # Attacker forges an absence observation for the same cell. The
    # committed root (which commits the disclosure) is the authority.
    forged = _ax.observe_absence(attacker_seed, beacon, SCOPE, T_MID)
    bundle["ledgers"][str(EPOCH)][SCOPE] = forged  # attacker swaps leaf
    # Recompute happens inside verify: root no longer matches close.
    note = _expect_refusal(
        lambda: _ax.verify_absence(bundle, EPOCH, SCOPE,
                                   _ax.pub_of(attacker_seed), T_CLOSE + 10),
        "absence-root-mismatch")
    # And the honest bundle (no swap) refuses the attacker's claim as
    # a disclosure cell, not an absence cell.
    honest = _ax.make_bundle([beacon], [close],
                             {str(EPOCH): honest_ledger},
                             {"beacon": _ax.pub_of(beacon_seed),
                              "attacker": _ax.pub_of(attacker_seed)})
    note2 = _expect_refusal(
        lambda: _ax.verify_absence(honest, EPOCH, SCOPE,
                                   _ax.pub_of(attacker_seed), T_CLOSE + 10),
        "absence-disclosure-recorded")
    return "%s; %s" % (note, note2)


def _probe_backdated_claim_rejected():
    beacon_seed, observer_seed = _keys()
    beacon = _ax.open_epoch(beacon_seed, EPOCH, "00" * 32, T_OPEN)
    ledger = {}
    close = _ax.close_epoch(beacon_seed, EPOCH, ledger, "00" * 32,
                            T_CLOSE)
    # Observation minted AFTER the close, claiming mid-epoch time.
    late = _ax.observe_absence(observer_seed, beacon, SCOPE, T_MID)
    late = dict(late)
    late["observed_at"] = T_CLOSE + 500  # backdated into a closed epoch
    late = _ax.resign_observation(observer_seed, late)
    ledger2 = {SCOPE: late}
    bundle = _ax.make_bundle([beacon], [close],
                             {str(EPOCH): ledger2},
                             {"beacon": _ax.pub_of(beacon_seed),
                              "observer": _ax.pub_of(observer_seed)})
    return _expect_refusal(
        lambda: _ax.verify_absence(bundle, EPOCH, SCOPE,
                                   _ax.pub_of(observer_seed), T_CLOSE + 600),
        "absence-backdated")


def _probe_observation_after_close_refused():
    beacon_seed, observer_seed, beacon, _l, close, _b = _setup_closed()
    closed = {str(EPOCH): close}
    return _expect_refusal(
        lambda: _ax.observe_absence(observer_seed, beacon, SCOPE, T_MID,
                                    closed_epochs=closed),
        "absence-epoch-closed")


def _probe_tampered_root_rejected():
    beacon_seed, observer_seed, _b, ledger, close, bundle = \
        _setup_closed()
    tampered = json.loads(json.dumps(bundle))
    cell = tampered["ledgers"][str(EPOCH)][SCOPE]
    # Mutate a signed field and re-sign: the cell still verifies on its
    # own, but the ledger no longer matches the closed root.
    cell["observed_at"] = T_MID + 1
    tampered["ledgers"][str(EPOCH)][SCOPE] = _ax.resign_observation(
        observer_seed, cell)
    return _expect_refusal(
        lambda: _ax.verify_absence(tampered, EPOCH, SCOPE,
                                   _ax.pub_of(observer_seed), T_CLOSE + 10),
        "absence-root-mismatch")


def _probe_unsigned_beacon_rejected():
    beacon_seed, observer_seed, _b, ledger, close, bundle = \
        _setup_closed()
    bad = json.loads(json.dumps(bundle))
    bad["beacons"][0]["sig"] = "00" * 64  # corrupt the beacon signature
    return _expect_refusal(
        lambda: _ax.verify_absence(bad, EPOCH, SCOPE,
                                   _ax.pub_of(observer_seed), T_CLOSE + 10),
        "absence-epoch-beacon-unsigned")


def _probe_offline_portable():
    # 1. The module must not depend on the network stack.
    src_path = os.path.join(os.path.dirname(__file__), "..", "gov",
                            "absence_epoch.py")
    with io.open(src_path, "r", encoding="utf-8") as handle:
        src = handle.read()
    for banned in ("import socket", "import urllib", "import requests",
                   "import http", "from socket", "from urllib"):
        assert banned not in src, "network import %r in module" % banned
    # 2. A JSON-serialized bundle verifies in a FRESH interpreter that
    #    imports only this module (no trusted-server dependency).
    _b_seed, observer_seed, _b, _l, _c, bundle = _setup_closed()
    wire = json.dumps(bundle)
    script = (
        "import json, os, sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE', 'staging');"
        "sys.path.insert(0, %r);"
        "from gov import absence_epoch as ax;"
        "bundle = json.loads(sys.stdin.read());"
        "ok = ax.verify_absence(bundle, %d, %r, %r, %d);"
        "print('VERIFY_OK' if ok else 'VERIFY_FALSE')"
    ) % (os.path.join(os.path.dirname(__file__), ".."), EPOCH, SCOPE,
         _ax.pub_of(observer_seed), T_CLOSE + 10)
    proc = subprocess.run(
        [sys.executable, "-c", script], input=wire, capture_output=True,
        text=True, timeout=120, cwd=os.path.join(
            os.path.dirname(__file__), ".."))
    assert proc.returncode == 0, "fresh-interpreter verify failed: %s" % (
        proc.stderr[-500:],)
    assert "VERIFY_OK" in proc.stdout, "verify did not return True: %s" % (
        proc.stdout[-200:],)
    return "json round-trip verifies in fresh interpreter; no net imports"


_PROBES = {
    "absence-epoch-open-observe-verify": _probe_open_observe_verify,
    "absence-forged-claim-rejected": _probe_forged_claim_rejected,
    "absence-backdated-claim-rejected": _probe_backdated_claim_rejected,
    "absence-observation-after-close-refused":
        _probe_observation_after_close_refused,
    "absence-tampered-root-rejected": _probe_tampered_root_rejected,
    "absence-unsigned-beacon-rejected": _probe_unsigned_beacon_rejected,
    "absence-offline-portable": _probe_offline_portable,
}


def _run_green_checks():
    """Adjacent-seam sanity: no product-code regression. Depth-1 only;
    honors GOV_SKIP_GREEN=1 (never spawns another battery's main)."""
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    try:
        from gov import decision_codes as _dc
        for code in ("absence-epoch-beacon-unsigned",
                     "absence-epoch-not-open",
                     "absence-epoch-closed",
                     "absence-backdated",
                     "absence-root-mismatch",
                     "absence-disclosure-recorded",
                     "absence-not-observed"):
            _dc.code_for(code)
        notes.append("new refusal codes mapped in taxonomy")
    except Exception as exc:  # noqa: BLE001
        notes.append("taxonomy mapping check FAILED: %r" % (exc,))
    return notes


def main():
    print("wave-242 absence-epoch probes (new API: %s)" % HAVE_NEW_API)
    results = []
    for name in PROBE_NAMES:
        results.append(_run_probe(name, _PROBES[name]))
    held = sum(1 for r in results if r[1] == "HELD")
    gap = sum(1 for r in results if r[1] == "GAP")
    bad = sum(1 for r in results if r[1] in ("BREAK", "ERROR"))
    for name, verdict, note in results:
        print("  [%s] %s: %s" % (verdict, name, note.split("\n")[0]))
    for note in _run_green_checks():
        print("  green: %s" % note)
    print("HELD=%d GAP=%d BREAK/ERROR=%d" % (held, gap, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
