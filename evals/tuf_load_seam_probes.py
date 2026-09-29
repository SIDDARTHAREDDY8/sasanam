"""Wave-194 lane A — red-first battery: TUF freshness steal for the load seam.

The wave-193 python-tuf spike showed the load layer (``gov/load_gate.py``)
has no freshness binding: ``ArtifactPinset`` / ``verify_and_load`` /
``load_skill_content`` carry no version and no expiry, while the watch
layer (``gov/skill_watch.py``, wave-179 lane D) refuses both stale pins
(``pin-expired``) and rolled-back pin manifests (``pin-manifest-rollback``).
Attack shapes (TUF A1/A2/A5 adapted to the load seam):

- P1 freeze/expiry: a pin whose ``not_after`` has passed must be refused at
  the FORCED entry point (``load_skill_content``) — today it loads.
- P2 rollback: a replayed older pin statement (valid old authorship, lower
  version) must not displace a newer pin — today it does.
- P3 unpin-replay: a replayed older unpin statement must not delete a newer
  pin — today it does (fail-closed into ``artifact_unpinned``, but still a
  rollback of governed state).
- P4 fail-closed parsing: naive / malformed ``not_after`` and bad versions
  are refused at ``pin()`` time, never silently coerced.
- P5 default TTL: a pin with no explicit ``not_after`` gets the 90-day
  default (mirrors ``skill_watch._PIN_NOT_AFTER_TTL_SECONDS``).
- P6 legitimate renewal: re-pin at a HIGHER version with fresh authorship
  is accepted (the update path must keep working).
- P7 ordering: expiry is checked BEFORE the digest (mirrors the watch
  layer, which refuses stale pins before attesting content).

Controls: C0 fresh pin loads on both trees (no blanket refusal); C1 the
canonical body binds version+not_after under authorship (tampering either
breaks the signature).

Protocol generations: pristine trees have no version/not_after in the pin
protocol, so the attack shapes are demonstrated in their pristine form
(old pin loads; re-pin of an older digest displaces the newer one) and the
battery exits RED with GAP verdicts. On the new protocol the full battery
runs. Each probe runs x2 internally with a determinism check.

Hermetic: synthetic keys/content, no network. Deterministic except
wall-clock "now" (only used for expiry comparison, never asserted on).

Deployment mode is set at module level per the wave-95 lesson; verify
standalone under ``env -u GOV_DEPLOYMENT_MODE``.
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import inspect
import secrets
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import load_gate as _lg  # noqa: E402
from gov.delegation_tokens import DelegationTrust  # noqa: E402
from gov.ed25519 import publickey as _pubkey  # noqa: E402
from gov.ed25519 import sign as _edsign  # noqa: E402

_TS = "2026-09-23T00:00:00+00:00"
_PAST = "2020-01-01T00:00:00+00:00"      # long-expired bound
_FUTURE = "2030-01-01T00:00:00+00:00"    # safely-unexpired bound

NEW_PROTOCOL = "not_after" in inspect.signature(
    _lg.ArtifactPinset.pin).parameters


def _world():
    s1, s2 = secrets.token_bytes(32), secrets.token_bytes(32)
    ax = secrets.token_bytes(32)
    trust = DelegationTrust(
        human_keys={"op:alice": _pubkey(s1), "op:bob": _pubkey(s2)},
        authority_keys={"ax": _pubkey(ax)},
        user_issuer_keys={"idp": _pubkey(secrets.token_bytes(32))},
    )
    return trust, s1, s2


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Pristine-generation demonstrations (the genuine red).
# ---------------------------------------------------------------------------

def _pin_old_protocol(pinset, artifact_id, digest, seed,
                      key_id="op:alice", ts=_TS, tier="dev"):
    """The only pin shape the pristine protocol can express."""
    body = _lg._canonical_pin_body(tier, artifact_id, digest, ts)
    return pinset.pin(artifact_id, digest, key_id, _edsign(seed, body).hex(),
                      ts=ts, tier=tier)


def demonstrate_pristine_gap():
    """Run the two attack shapes against the pristine tree.

    Returns a list of (probe, verdict, detail) with verdict GAP SHOWN when
    the attack succeeds (the seam is unguarded).
    """
    out = []
    trust, s1, _s2 = _world()

    # D1: a pin from 2020 (any age — the seam has no expiry concept) loads
    # through the FORCED entry point.
    pinset = _lg.ArtifactPinset(trust)
    data = b"skill-bytes-v1"
    _pin_old_protocol(pinset, "skill:old", _digest(data), s1, ts=_PAST)
    try:
        _lg.load_skill_content(pinset, {"old": data}, "old")
        out.append(("D1 expired-pin loads at forced entry",
                    "GAP SHOWN", "load_skill_content ACCEPTED a pin from 2020"))
    except _lg.ArtifactRefused as e:
        out.append(("D1 expired-pin loads at forced entry",
                    "UNEXPECTEDLY HELD", str(e)))

    # D2: re-pinning an OLDER digest (replayed old pin statement, valid
    # authorship) displaces the newer pin — no monotonic floor.
    pinset2 = _lg.ArtifactPinset(trust)
    new_data, old_data = b"skill-bytes-v2-fixed", b"skill-bytes-v1-vuln"
    _pin_old_protocol(pinset2, "skill:x", _digest(new_data), s1)
    _pin_old_protocol(pinset2, "skill:x", _digest(old_data), s1)
    current = pinset2.pin_for("skill:x")["digest"]
    if current == _digest(old_data):
        out.append(("D2 replayed older pin displaces newer",
                    "GAP SHOWN",
                    "older digest displaced the newer pin (no version floor)"))
    else:
        out.append(("D2 replayed older pin displaces newer",
                    "UNEXPECTEDLY HELD", "newer pin survived"))

    return out


# ---------------------------------------------------------------------------
# New-protocol battery.
# ---------------------------------------------------------------------------

def _na(ts, explicit=None):
    return _lg._resolve_pin_not_after(ts, explicit)


def _pin_new(pinset, artifact_id, digest, seed, key_id="op:alice", ts=_TS,
             tier="dev", version=1, not_after=None):
    na = _na(ts, not_after)
    body = _lg._canonical_pin_body(tier, artifact_id, digest, ts,
                                   version=version, not_after=na)
    return pinset.pin(artifact_id, digest, key_id, _edsign(seed, body).hex(),
                      ts=ts, tier=tier, version=version, not_after=na)


def _unpin_new(pinset, artifact_id, seed, key_id="op:alice", ts=_TS,
               tier="dev", version=2):
    body = _lg._canonical_unpin_body(tier, artifact_id, ts, version=version)
    return pinset.unpin(artifact_id, key_id, _edsign(seed, body).hex(),
                        ts=ts, tier=tier, version=version)


def _expect_refused(fn, needle, label):
    """Run fn twice (determinism); expect ArtifactRefused mentioning needle."""
    seen = []
    for _ in range(2):
        try:
            fn()
            seen.append("ACCEPTED")
        except _lg.ArtifactRefused as e:
            seen.append("REFUSED:" + str(e))
        except Exception as e:  # noqa: BLE001 — any other error is a failure
            seen.append("ERROR:" + type(e).__name__ + ":" + str(e))
    if seen[0] != seen[1]:
        return (label, "FLAKY", " != ".join(seen))
    if seen[0].startswith("REFUSED:") and needle in seen[0]:
        return (label, "HELD", seen[0])
    return (label, "BREAK", seen[0])


def _expect_ok(fn, label):
    seen = []
    for _ in range(2):
        try:
            fn()
            seen.append("OK")
        except Exception as e:  # noqa: BLE001
            seen.append("ERROR:" + type(e).__name__ + ":" + str(e))
    if seen[0] != seen[1]:
        return (label, "FLAKY", " != ".join(seen))
    if seen[0] == "OK":
        return (label, "HELD", "ok x2")
    return (label, "BREAK", seen[0])


def run_new_protocol_battery():
    out = []
    trust, s1, _s2 = _world()

    # P1: expired pin refused at the forced entry point.
    def p1():
        pinset = _lg.ArtifactPinset(trust)
        data = b"skill-bytes-expired"
        _pin_new(pinset, "skill:e", _digest(data), s1, not_after=_PAST)
        _lg.load_skill_content(pinset, {"e": data}, "e")
    out.append(_expect_refused(p1, "pin_expired", "P1 expired pin refused"))

    # P1b: expired pin refused at verify_and_load directly.
    def p1b():
        pinset = _lg.ArtifactPinset(trust)
        data = b"skill-bytes-expired"
        _pin_new(pinset, "skill:e", _digest(data), s1, not_after=_PAST)
        _lg.verify_and_load(pinset, "skill:e", data)
    out.append(_expect_refused(p1b, "pin_expired", "P1b verify_and_load refuses"))

    # P2: replayed older pin statement cannot displace a newer pin.
    def p2():
        pinset = _lg.ArtifactPinset(trust)
        new_data, old_data = b"skill-bytes-v2-fixed", b"skill-bytes-v1-vuln"
        _pin_new(pinset, "skill:x", _digest(new_data), s1, version=2)
        _pin_new(pinset, "skill:x", _digest(old_data), s1, version=1)
    out.append(_expect_refused(p2, "pin_version_not_monotonic",
                               "P2 rollback re-pin refused"))
    # ... and the newer pin is still the one that loads.
    def p2b():
        pinset = _lg.ArtifactPinset(trust)
        new_data, old_data = b"skill-bytes-v2-fixed", b"skill-bytes-v1-vuln"
        _pin_new(pinset, "skill:x", _digest(new_data), s1, version=2)
        try:
            _pin_new(pinset, "skill:x", _digest(old_data), s1, version=1)
        except _lg.ArtifactRefused:
            pass
        got = _lg.verify_and_load(pinset, "skill:x", new_data)
        assert got.digest == _digest(new_data), "newer pin must survive"
    out.append(_expect_ok(p2b, "P2b newer pin survives rollback attempt"))

    # P2c: same-version re-pin is also refused (versions move strictly up).
    def p2c():
        pinset = _lg.ArtifactPinset(trust)
        _pin_new(pinset, "skill:x", _digest(b"a"), s1, version=3)
        _pin_new(pinset, "skill:x", _digest(b"b"), s1, version=3)
    out.append(_expect_refused(p2c, "pin_version_not_monotonic",
                               "P2c same-version re-pin refused"))

    # P3: replayed older unpin cannot delete a newer pin.
    def p3():
        pinset = _lg.ArtifactPinset(trust)
        _pin_new(pinset, "skill:x", _digest(b"data"), s1, version=2)
        _unpin_new(pinset, "skill:x", s1, version=1)
    out.append(_expect_refused(p3, "unpin_version_not_monotonic",
                               "P3 unpin-replay refused"))
    def p3b():
        pinset = _lg.ArtifactPinset(trust)
        _pin_new(pinset, "skill:x", _digest(b"data"), s1, version=2)
        try:
            _unpin_new(pinset, "skill:x", s1, version=1)
        except _lg.ArtifactRefused:
            pass
        assert pinset.pin_for("skill:x") is not None, "pin must survive"
    out.append(_expect_ok(p3b, "P3b pin survives unpin-replay"))

    # P4: fail-closed parsing at pin() time.
    def p4a():
        pinset = _lg.ArtifactPinset(trust)
        _pin_new(pinset, "skill:x", _digest(b"d"), s1,
                 not_after="2026-09-29 00:00:00")  # naive: no timezone
    out.append(_expect_refused(p4a, "not_after", "P4a naive not_after refused"))

    def p4b():
        pinset = _lg.ArtifactPinset(trust)
        _pin_new(pinset, "skill:x", _digest(b"d"), s1, not_after="not-a-date")
    out.append(_expect_refused(p4b, "not_after", "P4b malformed not_after refused"))

    def p4c():
        pinset = _lg.ArtifactPinset(trust)
        _pin_new(pinset, "skill:x", _digest(b"d"), s1, version=0)
    out.append(_expect_refused(p4c, "version", "P4c version 0 refused"))

    def p4d():
        pinset = _lg.ArtifactPinset(trust)
        _pin_new(pinset, "skill:x", _digest(b"d"), s1, version=True)
    out.append(_expect_refused(p4d, "version", "P4d bool version refused"))

    # P5: default TTL is pinned_at + 90 days (mirrors skill_watch).
    def p5():
        pinset = _lg.ArtifactPinset(trust)
        rec = _pin_new(pinset, "skill:x", _digest(b"d"), s1)
        assert rec["not_after"] == "2026-12-22T00:00:00+00:00", rec["not_after"]
        assert rec["version"] == 1, rec["version"]
    out.append(_expect_ok(p5, "P5 default 90-day TTL bound"))

    # P6: legitimate renewal at a higher version is accepted.
    def p6():
        pinset = _lg.ArtifactPinset(trust)
        _pin_new(pinset, "skill:x", _digest(b"v1"), s1, version=1)
        _pin_new(pinset, "skill:x", _digest(b"v2"), s1, version=2)
        got = _lg.verify_and_load(pinset, "skill:x", b"v2")
        assert got.digest == _digest(b"v2")
    out.append(_expect_ok(p6, "P6 higher-version renewal accepted"))

    # P6b: legitimate unpin at a higher version works.
    def p6b():
        pinset = _lg.ArtifactPinset(trust)
        _pin_new(pinset, "skill:x", _digest(b"d"), s1, version=1)
        _unpin_new(pinset, "skill:x", s1, version=2)
        assert pinset.pin_for("skill:x") is None
    out.append(_expect_ok(p6b, "P6b higher-version unpin accepted"))

    # P7: expiry is checked before the digest (watch-layer parity: stale
    # pins are refused before any content is attested).
    def p7():
        pinset = _lg.ArtifactPinset(trust)
        _pin_new(pinset, "skill:x", _digest(b"right-bytes"), s1,
                 not_after=_PAST)
        _lg.verify_and_load(pinset, "skill:x", b"wrong-bytes")
    out.append(_expect_refused(p7, "pin_expired", "P7 expiry before digest"))

    # C0: a fresh pin loads through the forced entry point (no blanket
    # refusal).
    def c0():
        pinset = _lg.ArtifactPinset(trust)
        data = b"skill-bytes-fresh"
        _pin_new(pinset, "skill:f", _digest(data), s1, not_after=_FUTURE)
        m = _lg.load_skill_content(pinset, {"f": data}, "f")
        from gov.sterile import Unvetted
        assert isinstance(m, Unvetted)
    out.append(_expect_ok(c0, "C0 fresh pin loads (control)"))

    # C1: tampering with version/not_after after signing breaks authorship.
    def c1():
        pinset = _lg.ArtifactPinset(trust)
        data = b"skill-bytes-tamper"
        digest = _digest(data)
        na = _na(_TS, _FUTURE)
        body = _lg._canonical_pin_body("dev", "skill:t", digest, _TS,
                                       version=1, not_after=na)
        sig = _edsign(s1, body).hex()
        # attacker rewrites the expiry but replays the old signature
        pinset.pin("skill:t", digest, "op:alice", sig, ts=_TS, tier="dev",
                   version=1, not_after="2031-01-01T00:00:00+00:00")
    out.append(_expect_refused(c1, "pin_authorship_invalid",
                               "C1 expiry tamper breaks authorship"))

    return out


def main():
    print("protocol generation: %s"
          % ("NEW (version/not_after bound)" if NEW_PROTOCOL else "PRISTINE"))
    if not NEW_PROTOCOL:
        results = demonstrate_pristine_gap()
    else:
        results = run_new_protocol_battery()
    held = sum(1 for _, v, _ in results if v == "HELD")
    gaps = sum(1 for _, v, _ in results if v == "GAP SHOWN")
    breaks = sum(1 for _, v, _ in results if v in ("BREAK", "FLAKY",
                                                  "UNEXPECTEDLY HELD"))
    for name, verdict, detail in results:
        print("[%s] %s -- %s" % (verdict, name, detail))
    print("held=%d gaps=%d breaks/flaky=%d" % (held, gaps, breaks))
    if not NEW_PROTOCOL:
        print("GAP SHOWN: load seam has no freshness binding")
        return 1
    return 0 if breaks == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
