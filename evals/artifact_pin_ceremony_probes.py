#!/usr/bin/env python3
"""Row-12 pin-ceremony audit battery (wave-142 lane 1).

Residual after wave-141: a compromised executor WITH deployment-key
access can still pin a malicious inventory -- the ceremony (who pins,
when, audited) is the control, not the MAC. Wave-141 bound the pin to
the inventory; this battery pins the CEREMONY:

  - ``pin_inventory`` records the key epoch the pin was made under
    (``gov.keyprovider.resolve_active_key()`` epoch, MAC-bound into
    the pin body) and emits a chained ``artifact_sweep_inventory_pinned``
    ceremony event carrying the inventory digest, key epoch, and
    timestamp.
  - ``verify_inventory_pin`` / the gap report surface the pin's age
    and key epoch; a pin made under a rotated-out key epoch (or older
    than an operator TTL) verifies as ``stale_pin_epoch`` -- LOUD,
    fail-closed, treated as unverifiable (full-gap).

This battery is RED-first: probes c1/c3/c4 go BREAK while the
ceremony seam is missing (no ``key_epoch`` in the pin, no
``artifact_sweep_inventory_pinned`` event, no TTL enforcement);
they flip to HELD once ``gov.artifact_sweep`` implements it.

Probes:
  c1_epoch_rotation_stale_loud: pin under key epoch A; rotate the
     epoch LABEL to B (same key bytes -- the operator rotated the
     epoch); present the epoch-A pin -> LOUD
     ``artifact_sweep_inventory_unverifiable``, fail-closed full-gap,
     reason names ``stale_pin_epoch``. A pre-rotation control shows
     the same pin verified (verdict "pinned") before the rotation --
     the rotation alone made it stale.
  c2_fresh_pin_verifies_with_epoch_surfaced: fresh pin under the
     current epoch -> verifies; the gap report carries the pin's
     ``key_epoch`` and ``pin_age_seconds`` (and the summary event
     carries them too).
  c3_ceremony_event_chained: ``pin_inventory(..., audit=log.append)``
     lands one ``artifact_sweep_inventory_pinned`` event in the
     chained audit log carrying ``inventory_digest`` (recomputable
     from the pinned dict), ``key_epoch``, and ``pinned_at``;
     ``verify_chain`` stays OK.
  c4_ttl_expired_pin_stale: pin made "long ago" (pinned_at backdated
     via a monkeypatched clock -- the MAC still verifies because the
     pin was genuinely made then) presented with
     ``pin_ttl_seconds`` smaller than its age -> LOUD unverifiable,
     reason names ``stale_pin_epoch``.
  c5_deterministic_x2: the whole battery runs twice; verdicts must
     be identical.

Honest ceilings (documented, not hidden): the ceremony audit proves
WHEN and WHAT was pinned and under WHICH key epoch -- it does not
prove the pinned list was WISE. A malicious-but-fresh pin made by a
key-holder verifies cleanly; that is the operator's problem, and
this battery does not claim otherwise. The control is the ceremony,
stated plainly.

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic (no RNG in verdicts;
secrets.token_hex is used only for the deployment key and temp-dir
isolation). Stdlib only.

Run:
  mkdir -p /tmp/gov-pinceremony
  TMPDIR=/tmp/gov-pinceremony ~/workspace/.gov-venv/bin/python \
      evals/artifact_pin_ceremony_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-pinceremonyb \
      ~/workspace/.gov-venv/bin/python evals/artifact_pin_ceremony_probes.py
"""

import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "ceremony-A")
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-pinceremony-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import artifact_sweep as _sweep  # noqa: E402
from gov.log import ActionLog, verify_chain  # noqa: E402

_RESULTS = []

CEREMONY_EVENT = "artifact_sweep_inventory_pinned"
_HAVE_CEREMONY = hasattr(_sweep, "INVENTORY_PINNED_EVENT")


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-36s %-10s %s" % (name, verdict, detail))


# ------------------------------------------------------------ fixtures

def _data_root(name):
    root = Path(tempfile.mkdtemp(prefix="govpincer-%s-" % name,
                                 dir=os.environ["TMPDIR"]))
    (root / "keep.txt").write_text("deployed baseline file\n",
                                   encoding="utf-8")
    return root


def _set_epoch(epoch):
    os.environ["GOV_LOG_KEY_EPOCH"] = epoch


def _report(pinned_or_list, watch_roots, **kw):
    events = []
    rep = _sweep.report_coverage_gaps(
        pinned_or_list, watch_roots, audit=events.append, run_id="pincer",
        **kw)
    return rep, events


def _stale_loud_ok(rep, events, roots):
    """Shared assertion: LOUD unverifiable + full-gap, reason names
    stale_pin_epoch."""
    evs = [e for e in events
           if e.get("event") == _sweep.INVENTORY_UNVERIFIABLE_EVENT]
    if len(evs) != 1:
        return (False, "expected exactly 1 %s event, got %d"
                % (_sweep.INVENTORY_UNVERIFIABLE_EVENT, len(evs)))
    ev = evs[0]
    if ev.get("severity") != "LOUD":
        return (False, "unverifiable event not LOUD: %r" % (ev,))
    if "stale_pin_epoch" not in str(ev.get("reason", "")):
        return (False, "reason does not name stale_pin_epoch: %r"
                % (ev.get("reason"),))
    if rep.get("verdict") != "unverifiable":
        return (False, "report verdict is %r, want 'unverifiable'"
                % (rep.get("verdict"),))
    want = {os.path.realpath(str(r)) for r in roots}
    if set(rep.get("gaps", [])) != want or rep.get("covered"):
        return (False, "not full-gap: gaps=%r covered=%r"
                % (rep.get("gaps"), rep.get("covered")))
    return (True, "LOUD stale_pin_epoch; fail-closed full-gap over "
            "%d declared" % len(want))


# ---------------------------------------------------------------- probes

def c1_epoch_rotation_stale_loud():
    name = "c1_epoch_rotation_stale_loud"
    rootA = _data_root("a")
    rootB = _data_root("b")
    _set_epoch("ceremony-A")
    pinned = _sweep.pin_inventory([str(rootA), str(rootB)])
    if "key_epoch" not in pinned:
        _record(name, "BREAK",
                "pin carries no key_epoch -- the ceremony seam is "
                "MISSING (not implemented)")
        return
    if pinned.get("key_epoch") != "ceremony-A":
        _record(name, "BREAK",
                "pin key_epoch is %r, want the pinning epoch "
                "'ceremony-A'" % (pinned.get("key_epoch"),))
        return
    # Control: before rotation the same pin verifies (verdict pinned).
    rep0, _ = _report(pinned, [])
    if rep0.get("verdict") != "pinned":
        _record(name, "ERROR",
                "pre-rotation control did not verify: %r"
                % (rep0.get("verdict"),))
        _set_epoch("ceremony-A")
        return
    # Rotate the epoch LABEL (same key bytes -- the operator rotated
    # the epoch; the pin's MAC still verifies, the ceremony must not).
    _set_epoch("ceremony-B")
    try:
        rep, events = _report(pinned, [])
    finally:
        _set_epoch("ceremony-A")
    ok, detail = _stale_loud_ok(rep, events, [rootA, rootB])
    _record(name, "HELD" if ok else "BREAK", detail)


def c2_fresh_pin_verifies_with_epoch_surfaced():
    name = "c2_fresh_pin_verifies_with_epoch_surfaced"
    if not _HAVE_CEREMONY:
        _record(name, "BREAK",
                "ceremony seam MISSING (not implemented)")
        return
    rootA = _data_root("c")
    rootB = _data_root("d")
    _set_epoch("ceremony-A")
    pinned = _sweep.pin_inventory([str(rootA), str(rootB)])
    rep, events = _report(pinned, [])
    if rep.get("verdict") != "pinned":
        _record(name, "BREAK",
                "fresh pin under the current epoch did not verify: "
                "%r" % (rep.get("verdict"),))
        return
    if rep.get("key_epoch") != "ceremony-A":
        _record(name, "BREAK",
                "report does not surface the pin's key epoch: %r"
                % (rep.get("key_epoch"),))
        return
    age = rep.get("pin_age_seconds")
    if not isinstance(age, (int, float)) or age < 0:
        _record(name, "BREAK",
                "report does not surface the pin's age: %r" % (age,))
        return
    comps = [e for e in events
             if e.get("event") == _sweep.COVERAGE_COMPLETE_EVENT]
    if (not comps or comps[0].get("key_epoch") != "ceremony-A"
            or not isinstance(comps[0].get("pin_age_seconds"),
                             (int, float))):
        _record(name, "BREAK",
                "summary event missing key_epoch/pin_age_seconds: %r"
                % (comps,))
        return
    _record(name, "HELD",
            "fresh pin verifies; report + summary surface key_epoch "
            "'ceremony-A' and pin_age_seconds=%.1f" % (age,))


def c3_ceremony_event_chained():
    name = "c3_ceremony_event_chained"
    if not _HAVE_CEREMONY:
        _record(name, "BREAK",
                "ceremony event seam MISSING (not implemented)")
        return
    rootA = _data_root("e")
    run_dir = Path(tempfile.mkdtemp(prefix="govpincer-log-",
                                    dir=os.environ["TMPDIR"]))
    log = ActionLog(str(run_dir / "actions.jsonl"))
    _set_epoch("ceremony-A")
    pinned = _sweep.pin_inventory([str(rootA)], audit=log.append,
                                  run_id="ceremony-test")
    lines = [e for e in _sweep_chain_events(log)
             if isinstance(e, dict)
             and e.get("event") == CEREMONY_EVENT]
    if len(lines) != 1:
        _record(name, "BREAK",
                "expected exactly 1 %s event in the chained log, got %d"
                % (CEREMONY_EVENT, len(lines)))
        return
    ev = lines[0]
    want_digest = _sweep.inventory_digest(pinned)
    if ev.get("inventory_digest") != want_digest:
        _record(name, "BREAK",
                "ceremony event inventory_digest %r != recomputed %r"
                % (ev.get("inventory_digest"), want_digest))
        return
    if ev.get("key_epoch") != "ceremony-A":
        _record(name, "BREAK",
                "ceremony event key_epoch is %r, want 'ceremony-A'"
                % (ev.get("key_epoch"),))
        return
    if ev.get("pinned_at") != pinned.get("pinned_at"):
        _record(name, "BREAK",
                "ceremony event pinned_at does not match the pin")
        return
    if not verify_chain(str(run_dir / "actions.jsonl")):
        _record(name, "BREAK",
                "audit chain broken after the ceremony event")
        return
    _record(name, "HELD",
            "ceremony event chained with inventory_digest=%s..., "
            "key_epoch, pinned_at; chain verifies"
            % (want_digest[:12],))


def _sweep_chain_events(log):
    # ActionLog has no public read-all; read the raw file.
    import json as _json
    out = []
    for line in Path(log.path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(_json.loads(line))
    return out


def c4_ttl_expired_pin_stale():
    name = "c4_ttl_expired_pin_stale"
    if not _HAVE_CEREMONY:
        _record(name, "BREAK",
                "ceremony seam MISSING (not implemented)")
        return
    rootA = _data_root("f")
    _set_epoch("ceremony-A")
    # A genuinely old pin: backdate the ceremony clock, pin, restore.
    # The MAC still verifies -- only the age is old.
    old_ts = (datetime.now(timezone.utc)
              - timedelta(days=90)).isoformat()
    real_now = _sweep._utcnow_iso
    _sweep._utcnow_iso = lambda: old_ts
    try:
        pinned = _sweep.pin_inventory([str(rootA)])
    finally:
        _sweep._utcnow_iso = real_now
    if "key_epoch" not in pinned:
        _record(name, "BREAK",
                "pin carries no key_epoch -- ceremony seam MISSING")
        return
    # Sanity: with no TTL the old pin still verifies (TTL is an
    # operator opt-in, not a default).
    rep0, _ = _report(pinned, [])
    if rep0.get("verdict") != "pinned":
        _record(name, "ERROR",
                "old pin without TTL did not verify: %r"
                % (rep0.get("verdict"),))
        return
    rep, events = _report(pinned, [], pin_ttl_seconds=30 * 86400)
    ok, detail = _stale_loud_ok(rep, events, [rootA])
    _record(name, "HELD" if ok else "BREAK", detail)


def _run_all():
    global _RESULTS
    _RESULTS = []
    c1_epoch_rotation_stale_loud()
    c2_fresh_pin_verifies_with_epoch_surfaced()
    c3_ceremony_event_chained()
    c4_ttl_expired_pin_stale()
    return list(_RESULTS)


def c5_deterministic_x2():
    name = "c5_deterministic_x2"
    first = _run_all()
    second = _run_all()
    v1 = [(n, v) for n, v, _ in first]
    v2 = [(n, v) for n, v, _ in second]
    if v1 != v2:
        _record(name, "BREAK",
                "verdicts differ between runs: %r vs %r" % (v1, v2))
        return
    _record(name, "HELD",
            "%d probes byte-identical verdicts across 2 runs" % len(v1))


def main():
    _run_all()
    c5_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("artifact_pin_ceremony_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
