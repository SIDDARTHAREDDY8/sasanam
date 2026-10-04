"""Wave-295 F366 closure battery: advance(record=...) must be atomic.

F366 (LOW): ``KeySuccession.advance(record=...)`` called ``_apply_record``
(phase -> "completing") BEFORE ``_check_window(window)``, so a well-signed
advance record with a missing/out-of-bounds window refused coded
``keysuccession-window-missing`` but left the ceremony poisoned at
"completing" with ``_overlap_window = None`` -- a state unreachable via the
seed path or ``from_records`` (which checks the window before mutating).

Close-when: a malformed advance record leaves the ceremony at "prepared";
``advance(record)`` and ``from_records`` agree on the same input.

Base: wave-294 merge 5a88d9fa. Pin 1742 (no new codes; F366 closure only).
Next free F367.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g295-f366 && TMPDIR=/var/tmp/g295-f366 \
    ~/workspace/.gov-venv/bin/python evals/w295_f366_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g295-f366b \
    ~/workspace/.gov-venv/bin/python evals/w295_f366_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"
TAXONOMY_PIN = 2045 # Wave-294 merge (no new codes for F366 closure); Wave-295 merge: pin 1742 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



_RESULTS = []


def _record(pid, verdict, note):
    _RESULTS.append((pid, verdict, note))
    return (pid, verdict, note)


def _safe(pid, fn):
    try:
        fn()
    except Exception:  # noqa: BLE001 -- a probe crash is data
        _record(pid, "ERROR", traceback.format_exc(limit=3).strip())


def _literals():
    src = open("gov/decision_codes.py").read()
    return re.findall(r'''[\"']code[\"']\s*:\s*[\"']([^\"']+)[\"']''', src)


def p_taxonomy_pin():
    codes = _literals()
    if len(codes) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "raw literals %d, want %d"
                       % (len(codes), TAXONOMY_PIN))
    if len(set(codes)) != len(codes):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if codes != sorted(codes):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    import gov.decision_codes as dc
    if len(dc.TAXONOMY) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "live dict %d, want %d"
                       % (len(dc.TAXONOMY), TAXONOMY_PIN))
    _record("pin-taxonomy", "HELD",
            "raw literals %d unique sorted; live dict matches" % len(codes))


# -- F366 probes -------------------------------------------------------

from gov import ed25519  # noqa: E402
from gov.key_succession import (  # noqa: E402
    KeySuccession, KeySuccessionError,
)

SEED_A = bytes(range(1, 33))
SEED_B = bytes(range(33, 65))

WINDOW_MISSING = "keysuccession-window-missing"


def _pub(seed):
    return ed25519.publickey(seed).hex()


def _prepared():
    c = KeySuccession("authority-1", _pub(SEED_A))
    c.begin(_pub(SEED_B), old_seed=SEED_A)
    c.announce(old_seed=SEED_A)
    return c


def _craft_advance(c, window):
    """A well-signed prepared->completing record with the given window
    (or no window at all when window is None)."""
    if window is None:
        record = c._build_record("prepared", "completing", 1700000000)
    else:
        record = c._build_record("prepared", "completing", 1700000000,
                                 overlap_window_seconds=window)
    return {"record": record,
            "signature": c._sign_old(record, SEED_A),
            "keyid": "old-authority"}


def p_f366_missing_window_refused_coded():
    c = _prepared()
    bad = _craft_advance(c, None)
    try:
        c.advance(record=bad)
    except KeySuccessionError as e:
        if e.code == WINDOW_MISSING:
            return _record("f366-missing-window-coded", "HELD",
                           "refuses coded %s" % e.code)
        return _record("f366-missing-window-coded", "BREAK",
                       "wrong code %r" % (e.code,))
    _record("f366-missing-window-coded", "BREAK", "no refusal at all")


def p_f366_not_poisoned_missing_window():
    c = _prepared()
    bad = _craft_advance(c, None)
    try:
        c.advance(record=bad)
    except KeySuccessionError:
        pass
    if c.phase != "prepared":
        return _record("f366-no-poison", "BREAK",
                       "ceremony at %r after failed advance" % (c.phase,))
    if c._overlap_window is not None or c.overlap_window_seconds is not None:
        return _record("f366-no-poison", "BREAK",
                       "window stashed despite failed advance")
    if c.advance_record is not None:
        return _record("f366-no-poison", "BREAK",
                       "advance_record stashed despite failed advance")
    _record("f366-no-poison", "HELD",
            "ceremony still at prepared; no state leaked")


def p_f366_not_poisoned_bounds_window():
    c = _prepared()
    bad = _craft_advance(c, 10 ** 12)  # well-signed, out of bounds
    try:
        c.advance(record=bad)
    except KeySuccessionError as e:
        if e.code != WINDOW_MISSING:
            return _record("f366-bounds-no-poison", "BREAK",
                           "wrong code %r" % (e.code,))
    else:
        return _record("f366-bounds-no-poison", "BREAK", "no refusal at all")
    if c.phase != "prepared" or c.advance_record is not None:
        return _record("f366-bounds-no-poison", "BREAK",
                       "poisoned: phase=%r" % (c.phase,))
    _record("f366-bounds-no-poison", "HELD",
            "out-of-bounds window leaves ceremony at prepared")


def p_f366_paths_agree():
    c = _prepared()
    records = [c.begin_record, c.announce_record, _craft_advance(c, None)]
    try:
        KeySuccession.from_records("authority-1", _pub(SEED_A), records)
    except KeySuccessionError as e:
        if e.code != WINDOW_MISSING:
            return _record("f366-paths-agree", "BREAK",
                           "from_records wrong code %r" % (e.code,))
    else:
        return _record("f366-paths-agree", "BREAK",
                       "from_records accepted a windowless chain")
    _record("f366-paths-agree", "HELD",
            "from_records refuses the same chain coded; paths agree")


def p_f366_seed_path_still_clean():
    c = _prepared()
    try:
        c.advance(old_seed=SEED_A, overlap_window_seconds=None)
    except KeySuccessionError as e:
        if e.code != WINDOW_MISSING:
            return _record("f366-seed-path", "BREAK",
                           "wrong code %r" % (e.code,))
    else:
        return _record("f366-seed-path", "BREAK", "no refusal at all")
    if c.phase != "prepared":
        return _record("f366-seed-path", "BREAK",
                       "seed path poisoned too: %r" % (c.phase,))
    _record("f366-seed-path", "HELD",
            "seed path refuses clean, ceremony at prepared")


def p_f366_valid_record_still_advances():
    c = _prepared()
    good = _craft_advance(c, 3600)
    c.advance(record=good)
    if c.phase != "completing":
        return _record("f366-valid-record", "BREAK",
                       "valid record did not advance: %r" % (c.phase,))
    if c._overlap_window != 3600 or c.overlap_window_seconds != 3600:
        return _record("f366-valid-record", "BREAK",
                       "window not applied on the happy path")
    _record("f366-valid-record", "HELD",
            "valid advance record applies window, phase=completing")


def p_f366_after_failure_ceremony_reusable():
    c = _prepared()
    try:
        c.advance(record=_craft_advance(c, None))
    except KeySuccessionError:
        pass
    # The ceremony must still accept a valid advance afterwards.
    try:
        c.advance(old_seed=SEED_A, overlap_window_seconds=3600)
    except KeySuccessionError as e:
        return _record("f366-reusable", "BREAK",
                       "valid advance after failure refused: %s" % (e.code,))
    if c.phase != "completing":
        return _record("f366-reusable", "BREAK",
                       "did not reach completing: %r" % (c.phase,))
    _record("f366-reusable", "HELD",
            "failed advance leaves a usable ceremony")


# -- depth-1 green checks (adjacent batteries, no recursive green) -----


def _green(name):
    if SKIP_GREEN:
        return _record("green-%s" % name, "HELD",
                       "skipped (GOV_SKIP_GREEN=1)")
    path = os.path.join(REPO, "evals", name)
    td = tempfile.mkdtemp(prefix="g295-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = td
    env.pop("GOV_DEPLOYMENT_MODE", None)
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    try:
        r = subprocess.run([sys.executable, path], env=env, cwd=REPO,
                           capture_output=True, text=True, timeout=600)
    except Exception as e:  # noqa: BLE001
        return _record("green-%s" % name, "ERROR", "spawn failed: %s" % e)
    tail = (r.stdout or "") + (r.stderr or "")
    if name == "w294_redteam_probes.py":
        # F366 open at this battery's base expectation: 3 BREAK (F365 depth-5
        # nesting + F365 64KB budget + F366 ks-advance-record-not-atomic)
        # until F366 is closed; after closure 2 BREAK (F365 still OPEN).
        # The runner sets F366_OPEN=1 for the red-first run; the post-fix
        # run leaves it unset.
        want_breaks = 3 if os.environ.get("F366_OPEN") == "1" else 2
    else:
        want_breaks = 0
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", tail)
    if not m:
        return _record("green-%s" % name, "ERROR",
                       "no summary line; rc=%d" % r.returncode)
    br, he, er = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if br != want_breaks or er != 0:
        return _record("green-%s" % name, "BREAK",
                       "saw %d BREAK / %d HELD / %d ERROR, want %d BREAK / 0 ERROR"
                       % (br, he, er, want_breaks))
    _record("green-%s" % name, "HELD",
            "%d BREAK / %d HELD / %d ERROR" % (br, he, er))


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("f366-missing-window-coded", p_f366_missing_window_refused_coded)
    _safe("f366-no-poison", p_f366_not_poisoned_missing_window)
    _safe("f366-bounds-no-poison", p_f366_not_poisoned_bounds_window)
    _safe("f366-paths-agree", p_f366_paths_agree)
    _safe("f366-seed-path", p_f366_seed_path_still_clean)
    _safe("f366-valid-record", p_f366_valid_record_still_advances)
    _safe("f366-reusable", p_f366_after_failure_ceremony_reusable)
    _safe("green-w294_redteam", lambda: _green("w294_redteam_probes.py"))
    _safe("green-w293_key_succession",
          lambda: _green("w293_key_succession_probes.py"))
    breaks = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    errors = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    probe_lines.emit(_RESULTS)
    print("w295_f366: %d BREAK / %d HELD / %d ERROR"
          % (breaks, held, errors))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _RESULTS, breaks, held, errors)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    return 1 if breaks or errors else 0


if __name__ == "__main__":
    sys.exit(main())
