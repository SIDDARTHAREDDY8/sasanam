"""Wave-20 red-team probes (2026-09-22): gate-green overrides.

- sit48: F73 strict-resolver world (see below).
- sit115/sit118: R17 `full_in` revert maintenance — the countdown keys
  went falsy (no `full_in` in tips or verdicts anymore); re-derived at
  the F72 replay shape the revert preserved (saved valid tip still
  accepted — the MAC binds integrity, not freshness). F72 stays OPEN.

The product changed under the wave-9 F32 forgery probe: the F73 strict
key resolver (``gov/log.py::_active_key``) rejects the PUBLIC dev key on
the production path EVEN WHEN EXPLICITLY CONFIGURED (``GOV_LOG_KEY`` set
to the dev bytes, or ``GOV_LOG_KEY_EPOCH=dev`` -> ``NoKeyConfiguredError``).
The w9a forge probe's documented dev flow (configure the dev key, then
``_verify`` the 'production'-labeled forgery) can no longer reach the
label-binding check — the forgery fails closed one layer earlier, at the
resolver. That is the intended F73 design (red-team verified F73 CLOSED
via sit47), not a regression: the F32 control claim ("the forgery fails
closed") holds, enforced strictly earlier.

Per the r9/r11/w19 precedent, ``evals/w9_probes.py`` stays UNCHANGED as
the historical record; its playbook entry is superseded here. Old keys
retired: ``forge_fails_single_key``, ``forge_typed_api_raises``,
``forge_closed_realkey``, ``forge_closed_keyring``,
``forge_report_stays_dev`` (the first two asserted pre-F73 behavior;
the last three keep their meaning in the double-opt-in world).

Strict-world assertions (wave-81: the F73 strict resolver is deleted
with the dev key — explicit material is used verbatim):

- ``explicit_bytes_used_verbatim``: ``GOV_LOG_KEY``=<retired dev bytes>
  explicitly configured -> the resolver uses them as-is (no screening);
  the forgery still fails closed at label binding, never misread.
- ``label_binding_survives_with_explicit_key``: under legitimate
  explicit provisioning, ``_verify`` still returns ``ok=False`` with a
  "key_epoch label mismatch" error — the F32 label-binding check is
  intact.
- ``typed_api_raises_with_explicit_key``: ``require_verified`` raises
  the typed ``LogUnverifiableError`` under explicit provisioning.
- ``other_key_still_closed``: a different explicitly configured key
  still closes on the insider-MAC'd forgery.
- ``keyring_still_closed``: the KeyRing path is unchanged (label
  selects the verifying key).
- ``report_flags_mismatch``: ``key_status`` renders the forgery with
  the 'production' label mismatch flagged, never a production banner.

Env hygiene (sit47 lesson): every mutation of ``os.environ`` is saved
and restored in a finally — nothing leaks into later cells.
"""

import contextlib
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from gov import log as _logmod  # noqa: E402
from gov.keys import KeyRing, KeyMaterial, NoKeyConfiguredError  # noqa: E402
from evals.w9_probes import (  # noqa: E402
    _forge_production_labeled_log, _tmp)
from demo.make_report import key_status  # noqa: E402

_KEY_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH")


@contextlib.contextmanager
def _key_env(key=None, epoch=None):
    """Set GOV_LOG_KEY[/GOV_LOG_KEY_EPOCH], restoring all afterwards.
    None means 'unset'."""
    old = {k: os.environ.get(k) for k in _KEY_VARS}
    for k, v in (("GOV_LOG_KEY", key), ("GOV_LOG_KEY_EPOCH", epoch)):
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextlib.contextmanager
def _explicit_world():
    """Wave-81: the legitimate explicit-provisioning posture — an
    explicitly configured key/epoch, everything restored afterwards."""
    import secrets as _secrets
    with _key_env(key=_secrets.token_hex(32), epoch="epoch-9"):
        yield


def _w20_sit48_strict_forge():
    """sit48 override: F32 forgery in the wave-81 explicit-key world."""
    o = {}
    with _tmp("w20f-") as d:
        lp, entries = _forge_production_labeled_log(d)
        # 1. Explicitly configuring the retired public dev bytes: used
        #    verbatim (no screening anymore) — and the forgery still
        #    fails closed at label binding, never misread as verifiable.
        retired = "retired-public-dev-bytes-v1"
        with _key_env(key=retired, epoch="epoch-9"):
            v = _logmod._verify(lp)
            o["explicit_bytes_used_verbatim"] = (
                not v["ok"]
                and "key_epoch label mismatch" in (v["error"] or ""))
        # 2-4, 6. Under legitimate explicit provisioning the F32 claims
        # hold.
        with _explicit_world():
            v = _logmod._verify(lp)
            o["label_binding_survives_with_explicit_key"] = (
                not v["ok"]
                and "key_epoch label mismatch" in (v["error"] or ""))
            try:
                _logmod.require_verified(lp)
                o["typed_api_raises_with_explicit_key"] = False
            except _logmod.LogUnverifiableError:
                o["typed_api_raises_with_explicit_key"] = True
            from demo.make_report import key_status as _ks
            ks = _ks(entries, v["key_epoch"])
            o["report_flags_mismatch"] = (
                ks["verified_epoch"] == v["key_epoch"]
                and ks["label_mismatch"] == ["production"]
                and "LABEL MISMATCH" in ks["banner_line"]
                and "verified epoch `production`" not in ks["banner_line"])
        # A different explicitly configured key: still closed.
        with _key_env(key="other-explicit-key", epoch="epoch-2"):
            o["other_key_still_closed"] = not _logmod._verify(lp)["ok"]
        # The KeyRing path: the label selects the verifying key —
        # unchanged behavior.
        ring = KeyRing()
        ring._keys["production"] = KeyMaterial(
            "production", b"other-explicit-key", status="active")
        ring._keys["epoch-9"] = KeyMaterial(
            "epoch-9", b"w9-insider-holds-this-key", status="active")
        ring._active_epoch = "epoch-9"
        o["keyring_still_closed"] = not ring.verify_log(lp)["ok"]
    return o


# ---------------------------------------------------------------------------
# Wave-25 probe maintenance (2026-09-22): F72 CLOSED re-derivation.
#
# F72 CLOSED 2026-09-22 (R18, wave-23 crypto/log): every tip write
# bumps a MAC'd generation counter and appends a generation pin
# (separate "checkpoint-tipgen" MAC domain) to the checkpoint sidecar
# BEFORE the tip file lands (gov/log.py: _append_tip_gen_pin,
# _max_pinned_tip_gen); _read_tip_cache rejects a tip older than the
# newest pinned generation, so a replayed older tip degrades to full
# re-verification (self-healing) instead of silent staleness. No
# wall-clock involved — freshness is purely log-anchored.
#
# The Wave-20 re-derivations below (which pinned the OPEN shape:
# "saved valid tip restored -> ACCEPTED") are therefore inverted at
# the closed mechanism, following the 2026-09-22 03:26 UTC Wave-20
# precedent (re-derive at the landed mechanism, discriminating
# honesty pair, old keys confirmed falsy, finding entry dated).
# ---------------------------------------------------------------------------

def _w20_sit118_replay_shape():
    """sit118 re-derived: F72 CLOSED pin (generation freshness).

    A run-dir writer saves the validly MACed tip (gen g0), lets sweeps
    advance it (gen g1 > g0, pinned in the sidecar), then restores the
    saved tip: the restore is REJECTED as stale by _read_tip_cache
    (newest pinned gen > tip gen), verify_chain_tip returns None (no
    silent incremental acceptance), and a full verification of the
    genuine bytes succeeds and reseeds the tip to the live tail at a
    still-newer generation (self-healing). All keys truthy PINS the
    closure; the old "replay_accepted_ok" key is now asserted False.
    """
    o = {}
    with _key_env(key="w25f72", epoch="w25a"):
        with _tmp("w25f72-") as d:
            from gov.log import (
                ActionLog, write_chain_tip_from_tail, _tip_cache_path,
                verify_chain_tip, verify_chain, _read_tip_cache,
                read_entries)
            lp = d / "actions.jsonl"
            log = ActionLog(lp)
            for i in range(300):
                log.append({"event": "w25f72", "i": i})
            write_chain_tip_from_tail(lp, {})
            saved = _tip_cache_path(lp).read_bytes()
            tip0 = _read_tip_cache(lp)
            o["seeded_tip_gen_positive"] = (
                tip0 is not None and tip0.get("gen", 0) >= 1)
            gen0 = tip0["gen"] if tip0 else -1
            for i in range(300, 305):
                log.append({"event": "w25f72", "i": i})
            v = verify_chain_tip(lp)
            tip1 = _read_tip_cache(lp)
            o["advance_tip_gen_bumped"] = (
                v is not None and v.get("ok") is True
                and tip1 is not None and tip1["gen"] > gen0)
            # Attacker restores the saved valid tip (moves it backwards).
            _tip_cache_path(lp).write_bytes(saved)
            o["replay_rejected_stale"] = (
                _read_tip_cache(lp) is None)
            o["replay_no_incremental_verify"] = (
                verify_chain_tip(lp) is None)
            o["replay_not_silently_accepted"] = bool(
                o["replay_rejected_stale"]
                and o["replay_no_incremental_verify"])
            # Full verification of the genuine bytes succeeds (loud if
            # tampered) and reseeds the tip to the live tail.
            # verify_chain returns (ok, broken_seq_or_None, count).
            vf = verify_chain(lp)
            o["full_verify_genuine_ok"] = (
                vf is not None and vf[0] is True)
            write_chain_tip_from_tail(lp, {})
            tip_h = _read_tip_cache(lp)
            live = len(read_entries(lp))
            o["tip_self_healed_to_tail"] = (
                tip_h is not None and tip_h.get("seq") == live
                and tip_h.get("gen", 0) > gen0)
            o["f72_closed_pinned"] = all([
                o["seeded_tip_gen_positive"],
                o["advance_tip_gen_bumped"],
                o["replay_rejected_stale"],
                o["replay_no_incremental_verify"],
                o["full_verify_genuine_ok"],
                o["tip_self_healed_to_tail"],
            ])
    return o


def _w20_sit115_replay_honesty():
    """sit115 re-derived: honesty of the F72 CLOSED pin.

    Discriminating triple at the closed mechanism:
      - control: the CURRENT valid tip is ACCEPTED (incremental
        verify ok) — the pin must not break the honest path;
      - stale: a valid-but-OLDER tip (lower generation than the
        newest sidecar pin) is REJECTED for freshness;
      - corrupt: a tip with a corrupted MAC is REJECTED for integrity.
    The generation comparison is pinned in source
    (_max_pinned_tip_gen vs tip gen in _read_tip_cache). The stale and
    corrupt keys must flip relative to the control; keys that hold on
    all three are safety invariants. Proves the re-derived sit118 pin
    is discriminating, not vacuous.

    The anchor is scoped to _read_tip_cache's own source (not the whole
    file) and checks for the comparison's presence, not its exact
    argument text: the Wave-112 F69 hardening legitimately changed the
    scan window from the whole sidecar to cp_bytes[tip["pin_off"]:]
    (a sound, reviewed optimization — any pin that could stale this tip
    sits at or past pin_off), which broke the old exact-string match.
    """
    o = {}
    import inspect as _inspect
    from gov.log import _read_tip_cache as _rtc_fn
    fn_src = _inspect.getsource(_rtc_fn)
    o["anchor_gen_check_in_source"] = (
        "_max_pinned_tip_gen(" in fn_src
        and '> tip["gen"]' in fn_src)
    with _key_env(key="w25f72h", epoch="w25a"):
        with _tmp("w25f72h-") as d:
            from gov.log import (
                ActionLog, write_chain_tip_from_tail, _tip_cache_path,
                verify_chain_tip, _read_tip_cache)
            lp = d / "actions.jsonl"
            log = ActionLog(lp)
            for i in range(300):
                log.append({"event": "w25f72h", "i": i})
            write_chain_tip_from_tail(lp, {})
            saved = _tip_cache_path(lp).read_bytes()
            # Control: current valid tip accepted.
            v_cur = verify_chain_tip(lp)
            o["control_current_tip_accepted"] = (
                v_cur is not None and v_cur.get("ok") is True)
            # Stale arm: advance the tip, then restore the saved valid
            # (older-generation) tip.
            for i in range(300, 303):
                log.append({"event": "w25f72h", "i": i})
            verify_chain_tip(lp)
            _tip_cache_path(lp).write_bytes(saved)
            o["stale_valid_tip_rejected"] = (
                _read_tip_cache(lp) is None
                and verify_chain_tip(lp) is None)
            # Corrupt arm: same JSON shape, corrupted MAC -> rejected.
            tip_json = json.loads(saved)
            mac = tip_json["mac"]
            tip_json["mac"] = ("0" if mac[0] != "0" else "1") + mac[1:]
            _tip_cache_path(lp).write_bytes(
                json.dumps(tip_json).encode("utf-8"))
            o["corrupt_mac_tip_rejected"] = (
                _read_tip_cache(lp) is None)
            o["discriminating_keys_flip"] = (
                o["control_current_tip_accepted"]
                and o["stale_valid_tip_rejected"]
                and o["corrupt_mac_tip_rejected"])
    return o


PROBES = {
    "sit48_strict_forge": _w20_sit48_strict_forge,
    "sit115_replay_honesty": _w20_sit115_replay_honesty,
    "sit118_replay_shape": _w20_sit118_replay_shape,
}

# Gate-green overrides: supersede the w9a playbook entry for sit48 and
# the w19 R17-countdown entries for sit115/sit118 (the full_in revert
# removed the countdown from tips and verdicts; the probes are
# re-derived at the F72 replay shape the revert preserved).
W20_OVERRIDES = (
    ("sit48", "w20-forge", "sit48_strict_forge", "fg_"),
    ("sit115", "w20-f72honesty", "sit115_replay_honesty", "f72hon_"),
    ("sit118", "w20-f72shape", "sit118_replay_shape", "f72shape_"),
)


def register_w20(playbooks, w7_playbook):
    """Wire the wave-20 probes into run_evals.PLAYBOOKS.

    Registered AFTER register_w19: sit48's playbook entry is superseded
    by the post-F73 probe, and sit115/sit118 are superseded by the
    post-R17-revert re-derivations (countdown keys dropped, F72 replay
    shape pinned). The old probe files stay UNCHANGED as the historical
    record.
    """
    for sid, key, pk, pre in W20_OVERRIDES:
        fn = PROBES[pk]
        playbooks[sid] = (
            lambda s, p, _k=key, _f=fn, _r=pre:
                w7_playbook(s, p, _k, _f, _r))
