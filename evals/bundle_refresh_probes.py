#!/usr/bin/env python3
"""Wave-206 lane B red-team probes: TUF-style skill-bundle refresh.

Break-first battery per the diagnosing-bugs skill. Pattern lineage:
python-tuf client refresh workflow (ADAPT: root N->N+1 dual-threshold
chaining with no best-effort path, expiry != suspension, per-role
max_length byte caps, write-through cache re-verified from the pinned
root -- re-implemented stdlib-only, nothing vendored).

The pristine tree has skill-bundle loading (gov.load_gate) but NO
refresh workflow: gov.bundle_refresh is absent. Each probe attacks
that gap:

  R1  VALID_CHAIN        complete root->timestamp->snapshot->targets
                         chain refreshes; target digests served
  R2a EXPIRED_ROOT       pinned root expired -> cached metadata still
                         served + retry (stale, loud warning), NOT
                         suspended
  R2b STALE_ONLY_REFUSED expired timestamp with no cache -> refresh
                         cannot complete; loads refused loudly
  R3  ROLLBACK_REFUSED   timestamp version < cached -> chain break ->
                         suspended
  R4  BYTE_CAP           targets envelope over the per-role cap ->
                         refused (byte-cap DoS closed on this seam)
  R5  ROOT_THRESHOLD     root N+1 without old-root threshold (and
                         without new-root threshold) -> suspended
  R6  KEYID_OPAQUE       declared key IDs are honored even when they
                         differ from the derived key id (the `tough`
                         recompute-and-reject trap is NOT repeated);
                         unknown keyid -> refused
  R7  CANON_MISMATCH     properly-signed but non-canonical payload
                         (JCS-style short escapes) -> refused on the
                         canonicalization pin, not the signature
  R8  CACHE_TAMPER       tampered write-through cache is never trusted
                         blindly; re-verification fails closed and a
                         fresh refresh recovers
  R9  BINDING_MISMATCH   snapshot bytes != timestamp's declared digest
                         -> refused (MATCH-by-digest discipline)

On the pristine tree every probe reports GAP (module absent -- genuine
red). After the fix all must flip to HELD.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red
phase), ERROR only on harness failure (a verdict changing between the
two deterministic runs, an unexpected exception).

Deterministic: fixed seeds for Ed25519 signers, fixed clock; every
probe runs twice and a verdict change is an ERROR. Synthetic/local
only. ``GOV_SKIP_GREEN=1`` is honored (green check records a skip
instead of spawning sub-batteries).
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import bundle_refresh as br
    from gov.signing import Ed25519Signer, Ed25519Verifier
    _ABSENT = False
except ImportError:
    _ABSENT = True

_RESULTS = []


def _record(probe_id, name, verdict, detail):
    _RESULTS.append({"id": probe_id, "name": name, "verdict": verdict,
                     "detail": detail})


def _gap(probe_id, name, detail):
    _record(probe_id, name, "GAP", detail)


def _held(probe_id, name, detail):
    _record(probe_id, name, "HELD", detail)


def _run_twice(fn):
    """Run a probe twice; a verdict change between runs is an ERROR."""
    first = fn()
    second = fn()
    if first[0] != second[0]:
        return ("ERROR",
                "nondeterministic verdict: %r vs %r" % (first, second))
    return first


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

_FIXED_CLOCK = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _keys():
    seeds = {
        "root-a": b"\x11" * 32,
        "root-b": b"\x22" * 32,
        "ts-a": b"\x33" * 32,
        "snap-a": b"\x44" * 32,
        "tgt-a": b"\x55" * 32,
        "evil": b"\xee" * 32,
    }
    return {kid: Ed25519Signer(seed) for kid, seed in seeds.items()}


# Declared key IDs are OPAQUE producer-chosen strings -- deliberately
# different from the derived ed25519_key_id(pub). A refresher that
# recomputes-and-rejects (the `tough` trap) fails R1, not just R6.
DECLARED = {
    "root-a": "opaque-root-alpha",
    "root-b": "opaque-root-beta",
    "ts-a": "opaque-ts-alpha",
    "snap-a": "opaque-snap-alpha",
    "tgt-a": "opaque-tgt-alpha",
    "evil": "opaque-evil",
}

ALPHA_DIGEST = "aa" * 32
BETA_DIGEST = "bb" * 32


class _FixtureRepo(object):
    """Builds a signed four-role repository in memory.

    files: (role, version) -> envelope wire bytes. fetch(role, version)
    is the transport the BundleRefresher consumes; it raises
    br.FetchNotFound for absent files (the normal rollover stop).
    """

    def __init__(self, keys, declared):
        self.keys = keys
        self.declared = declared
        self.files = {}
        self.root_version = 0

    def _signers(self, *kids):
        return [(self.declared[k], self.keys[k]) for k in kids]

    def _pub_hex(self, kid):
        return self.keys[kid].public_key.hex()

    def _role_keys(self, kids):
        return {self.declared[k]: {"keytype": "ed25519",
                                   "keyval": {"public": self._pub_hex(k)}}
                for k in kids}

    def build_root(self, version, kids, threshold, expires):
        doc = {
            "_type": "root",
            "version": version,
            "expires": _iso(expires),
            "keys": self._role_keys(
                ["root-a", "root-b", "ts-a", "snap-a", "tgt-a"]),
            "roles": {
                "root": {"keyids": [self.declared[k] for k in kids],
                         "threshold": threshold},
                "timestamp": {"keyids": [self.declared["ts-a"]],
                              "threshold": 1},
                "snapshot": {"keyids": [self.declared["snap-a"]],
                             "threshold": 1},
                "targets": {"keyids": [self.declared["tgt-a"]],
                            "threshold": 1},
            },
        }
        wire = br.seal_role("root", doc, self._signers(*kids))
        self.files[("root", version)] = wire
        self.root_version = max(self.root_version, version)
        return wire

    def build_targets(self, version, expires, extra_targets=None):
        targets = {
            "skill:alpha": {"length": 128,
                            "hashes": {"sha256": ALPHA_DIGEST}},
            "skill:beta": {"length": 256,
                           "hashes": {"sha256": BETA_DIGEST}},
        }
        if extra_targets:
            targets.update(extra_targets)
        doc = {"_type": "targets", "version": version,
               "expires": _iso(expires), "targets": targets}
        wire = br.seal_role("targets", doc,
                            self._signers("tgt-a"))
        self.files[("targets", version)] = wire
        return wire

    def build_snapshot(self, version, expires, targets_version):
        twire = self.files[("targets", targets_version)]
        doc = {
            "_type": "snapshot",
            "version": version,
            "expires": _iso(expires),
            "meta": {"targets.json": {
                "version": targets_version,
                "length": len(twire),
                "hashes": {"sha256": hashlib.sha256(twire).hexdigest()}}},
        }
        wire = br.seal_role("snapshot", doc, self._signers("snap-a"))
        self.files[("snapshot", version)] = wire
        return wire

    def build_timestamp(self, version, expires, snapshot_version):
        swire = self.files[("snapshot", snapshot_version)]
        doc = {
            "_type": "timestamp",
            "version": version,
            "expires": _iso(expires),
            "snapshot": {
                "version": snapshot_version,
                "length": len(swire),
                "hashes": {"sha256": hashlib.sha256(swire).hexdigest()}},
        }
        wire = br.seal_role("timestamp", doc, self._signers("ts-a"))
        self.files[("timestamp", version)] = wire
        return wire

    def fetch(self, role, version):
        key = (role, version)
        if key not in self.files:
            raise br.FetchNotFound("no %s version %s" % (role, version))
        return self.files[key]

    def anchored_refresher(self, root_version=1, **kw):
        kw.setdefault("clock", lambda: _FIXED_CLOCK)
        return br.BundleRefresher(
            trusted_root_wire=self.files[("root", root_version)],
            fetch=self.fetch, **kw)


def _fresh_repo(expires_year=2030):
    keys = _keys()
    repo = _FixtureRepo(keys, DECLARED)
    exp = datetime(expires_year, 1, 1, tzinfo=timezone.utc)
    repo.build_root(1, ["root-a", "root-b"], 2, exp)
    repo.build_targets(1, exp)
    repo.build_snapshot(1, exp, 1)
    repo.build_timestamp(1, exp, 1)
    return repo


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def _p_r1():
    """R1 VALID_CHAIN: a complete valid chain refreshes to trusted."""
    if _ABSENT:
        return ("GAP", "gov.bundle_refresh absent")
    try:
        repo = _fresh_repo()
        import tempfile
        with tempfile.TemporaryDirectory() as cache:
            r = repo.anchored_refresher(cache_dir=cache)
            report = r.refresh()
            if report.state != "trusted":
                return ("GAP", "valid chain did not reach trusted: %r %r"
                        % (report.state, report.warnings))
            digest, length = r.target_digest("skill:alpha")
            if digest != ALPHA_DIGEST or length != 128:
                return ("GAP", "target digest wrong: %r %r"
                        % (digest, length))
            # write-through cache populated
            names = sorted(os.listdir(cache))
            if not any(n.startswith("root.") for n in names):
                return ("GAP", "root chain not written through: %r" % names)
            for n in ("timestamp.json", "snapshot.json", "targets.json"):
                if n not in names:
                    return ("GAP", "cache missing %s: %r" % (n, names))
        return ("HELD", "valid chain -> trusted; digests served; cache "
                "written through")
    except Exception as e:  # noqa: BLE001 -- harness reports, never throws
        return ("ERROR", "%s: %s" % (type(e).__name__, e))


def _p_r2a():
    """R2a EXPIRED_ROOT: expired pinned root -> cached + retry, not suspend."""
    if _ABSENT:
        return ("GAP", "gov.bundle_refresh absent")
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as cache:
            repo = _fresh_repo(expires_year=2030)
            r1 = repo.anchored_refresher(cache_dir=cache)
            rep1 = r1.refresh()
            if rep1.state != "trusted":
                return ("ERROR", "phase-1 refresh not trusted: %r"
                        % (rep1.state,))
            # Phase 2: same keys, same version, but the PINNED root is
            # expired. The cache holds verified metadata; the refresher
            # must serve it (stale, loud warning) and retry -- never
            # suspend on expiry alone.
            expired = datetime(2020, 1, 1, tzinfo=timezone.utc)
            anchor_wire = repo.build_root(1, ["root-a", "root-b"], 2,
                                          expired)
            r2 = br.BundleRefresher(
                trusted_root_wire=anchor_wire, fetch=repo.fetch,
                cache_dir=cache, clock=lambda: _FIXED_CLOCK)
            report = r2.refresh()
            if report.state == "suspended":
                return ("GAP", "expired root suspended the refresher: %r"
                        % (report.reason,))
            if report.state != "stale":
                return ("GAP", "expired root should be stale, got %r"
                        % (report.state,))
            if not any("expir" in w.lower() for w in report.warnings):
                return ("GAP", "no loud expiry warning: %r"
                        % (report.warnings,))
            digest, _ = r2.target_digest("skill:alpha")
            if digest != ALPHA_DIGEST:
                return ("GAP", "stale root stopped serving cached digests")
        return ("HELD", "expired root -> stale + cached served + warning; "
                "no suspension")
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(e).__name__, e))


def _p_r2b():
    """R2b STALE_ONLY_REFUSED: expired timestamp, no cache -> loud refusal."""
    if _ABSENT:
        return ("GAP", "gov.bundle_refresh absent")
    try:
        import tempfile
        keys = _keys()
        repo = _FixtureRepo(keys, DECLARED)
        fresh = datetime(2030, 1, 1, tzinfo=timezone.utc)
        stale = datetime(2020, 1, 1, tzinfo=timezone.utc)
        repo.build_root(1, ["root-a", "root-b"], 2, fresh)
        repo.build_targets(1, fresh)
        repo.build_snapshot(1, fresh, 1)
        repo.build_timestamp(1, stale, 1)  # expired, and nothing cached
        with tempfile.TemporaryDirectory() as cache:
            r = repo.anchored_refresher(cache_dir=cache)
            report = r.refresh()
            if report.state != "suspended":
                return ("GAP", "stale-only refresh should suspend, got %r"
                        % (report.state,))
            try:
                r.target_digest("skill:alpha")
                return ("GAP", "suspended refresher served a digest")
            except br.SuspendedError:
                pass
        return ("HELD", "expired timestamp with no cache -> suspended; "
                "target_digest raises SuspendedError loudly")
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(e).__name__, e))


def _p_r3():
    """R3 ROLLBACK_REFUSED: older timestamp version -> chain break."""
    if _ABSENT:
        return ("GAP", "gov.bundle_refresh absent")
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as cache:
            repo = _fresh_repo()
            r1 = repo.anchored_refresher(cache_dir=cache)
            if r1.refresh().state != "trusted":
                return ("ERROR", "phase-1 refresh not trusted")
            # Attacker replays an older-but-validly-signed timestamp.
            keys, fresh = _keys(), datetime(2030, 1, 1, tzinfo=timezone.utc)
            repo2 = _FixtureRepo(keys, DECLARED)
            repo2.build_root(1, ["root-a", "root-b"], 2, fresh)
            repo2.build_targets(1, fresh)
            repo2.build_snapshot(1, fresh, 1)
            old_wire = repo2.build_timestamp(0, fresh, 1)
            repo2.files[("timestamp", 1)] = old_wire  # serve v0 as "v1"
            r2 = br.BundleRefresher(
                trusted_root_wire=repo.files[("root", 1)],
                fetch=repo2.fetch, cache_dir=cache,
                clock=lambda: _FIXED_CLOCK)
            report = r2.refresh()
            if report.state != "suspended":
                return ("GAP", "rollback accepted, state=%r" % (report.state,))
            try:
                r2.target_digest("skill:alpha")
                return ("GAP", "suspended refresher served a digest")
            except br.SuspendedError:
                pass
        return ("HELD", "timestamp rollback (v1->v0) -> suspended; "
                "no digests served")
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(e).__name__, e))


def _p_r4():
    """R4 BYTE_CAP: oversized targets envelope -> refused before parsing."""
    if _ABSENT:
        return ("GAP", "gov.bundle_refresh absent")
    try:
        import tempfile
        keys = _keys()
        repo = _FixtureRepo(keys, DECLARED)
        fresh = datetime(2030, 1, 1, tzinfo=timezone.utc)
        repo.build_root(1, ["root-a", "root-b"], 2, fresh)
        # Bloated but otherwise valid targets: 200 extra entries.
        extra = {"skill:pad-%03d" % i: {"length": i, "hashes": {
            "sha256": "%064x" % i}} for i in range(200)}
        repo.build_targets(1, fresh, extra_targets=extra)
        repo.build_snapshot(1, fresh, 1)
        repo.build_timestamp(1, fresh, 1)
        wire = repo.files[("targets", 1)]
        with tempfile.TemporaryDirectory() as cache:
            r = repo.anchored_refresher(
                cache_dir=cache, max_length={"targets": 512})
            assert len(wire) > 512, "fixture too small to trip the cap"
            report = r.refresh()
            if report.state != "suspended":
                return ("GAP", "oversized targets accepted, state=%r"
                        % (report.state,))
            if not isinstance(report.reason, str) or \
                    "cap" not in report.reason.lower():
                return ("GAP", "suspension reason does not name the cap: %r"
                        % (report.reason,))
        return ("HELD", "targets envelope %d bytes over 512 cap -> "
                "refused; refresher suspended" % len(wire))
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(e).__name__, e))


def _p_r5():
    """R5 ROOT_THRESHOLD: root N+1 without dual threshold -> suspended."""
    if _ABSENT:
        return ("GAP", "gov.bundle_refresh absent")
    try:
        import tempfile
        keys = _keys()
        fresh = datetime(2030, 1, 1, tzinfo=timezone.utc)

        def _case(sign_kids, label):
            repo = _FixtureRepo(keys, DECLARED)
            repo.build_root(1, ["root-a", "root-b"], 2, fresh)
            repo.build_targets(1, fresh)
            repo.build_snapshot(1, fresh, 1)
            repo.build_timestamp(1, fresh, 1)
            # Rogue v2: threshold-2 role, but only the given kids sign.
            doc = {
                "_type": "root", "version": 2,
                "expires": _iso(fresh),
                "keys": repo._role_keys(
                    ["root-a", "root-b", "ts-a", "snap-a", "tgt-a"]),
                "roles": {
                    "root": {"keyids": [DECLARED["root-a"],
                                        DECLARED["root-b"]],
                             "threshold": 2},
                    "timestamp": {"keyids": [DECLARED["ts-a"]],
                                  "threshold": 1},
                    "snapshot": {"keyids": [DECLARED["snap-a"]],
                                 "threshold": 1},
                    "targets": {"keyids": [DECLARED["tgt-a"]],
                                "threshold": 1}},
            }
            repo.files[("root", 2)] = br.seal_role(
                "root", doc, repo._signers(*sign_kids))
            with tempfile.TemporaryDirectory() as cache:
                r = repo.anchored_refresher(cache_dir=cache)
                report = r.refresh()
                if report.state != "suspended":
                    return ("GAP", "%s: root v2 adopted without dual "
                            "threshold (state=%r)" % (label, report.state))
            return None

        # Case 1: only one of two required old-root keys signs.
        miss = _case(["root-a"], "single-signer")
        if miss:
            return miss
        # Case 2: two signatures, but from keys the old root never
        # authorized (new-root-only) -- old-root threshold unmet.
        miss = _case(["evil", "root-a"], "unauthorized-key")
        if miss:
            return miss
        return ("HELD", "root v2 without old-root threshold (1-of-2) and "
                "with unauthorized keys both -> suspended")
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(e).__name__, e))


def _p_r6():
    """R6 KEYID_OPAQUE: declared IDs honored; unknown keyid refused."""
    if _ABSENT:
        return ("GAP", "gov.bundle_refresh absent")
    try:
        import tempfile
        # Positive: every declared id in the fixtures is opaque (differs
        # from the derived ed25519 key id); the valid chain in R1 already
        # proves declared IDs are honored, not recomputed-and-rejected.
        keys = _keys()
        derived = {k: Ed25519Verifier(
            keys[k].public_key).key_id for k in DECLARED}
        if all(DECLARED[k] == derived[k] for k in DECLARED):
            return ("ERROR", "fixture error: declared ids not opaque")
        # Negative: a signature attributed to an undeclared keyid must
        # not verify, even when the underlying key is legitimate.
        repo = _fresh_repo()
        fresh = datetime(2030, 1, 1, tzinfo=timezone.utc)
        ts_doc = {"_type": "timestamp", "version": 2,
                  "expires": _iso(fresh),
                  "snapshot": {"version": 1,
                               "length": len(repo.files[("snapshot", 1)]),
                               "hashes": {"sha256": hashlib.sha256(
                                   repo.files[("snapshot", 1)]).hexdigest()}}}
        payload = br.tuf_canonical_json(ts_doc)
        from gov.dsse_envelope import pae
        import base64
        pae_bytes = pae(br.PAYLOAD_TYPES["timestamp"], payload)
        sig = keys["ts-a"].sign(pae_bytes).hex()
        rogue = {"payload": base64.b64encode(payload).decode("ascii"),
                 "payloadType": br.PAYLOAD_TYPES["timestamp"],
                 "signatures": [{"keyid": "ghost-key-undeclared",
                                 "sig": sig}]}
        with tempfile.TemporaryDirectory() as cache:
            r = repo.anchored_refresher(cache_dir=cache)
            # Phase 1: a good refresh to populate the cache at v1...
            rep = r.refresh()
            if rep.state != "trusted":
                return ("ERROR", "phase-1 refresh not trusted: %r"
                        % (rep.state,))
            # ...then the rogue v2 timestamp (planted after phase 1)
            # must break the chain: the signature is real but its keyid
            # is undeclared, so it must not attribute.
            repo.files[("timestamp", 2)] = br.tuf_canonical_json(rogue)
            rep2 = r.refresh()
            if rep2.state != "suspended":
                return ("GAP", "undeclared keyid signature accepted "
                        "(state=%r)" % (rep2.state,))
        return ("HELD", "opaque declared IDs honored end-to-end; "
                "undeclared 'ghost-key-undeclared' signature -> suspended")
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(e).__name__, e))


def _p_r7():
    """R7 CANON_MISMATCH: signed-but-non-canonical payload -> refused."""
    if _ABSENT:
        return ("GAP", "gov.bundle_refresh absent")
    try:
        import tempfile
        import base64
        from gov.dsse_envelope import pae
        repo = _fresh_repo()
        keys = _keys()
        fresh = datetime(2030, 1, 1, tzinfo=timezone.utc)
        # A targets doc containing a newline, encoded JCS-style (short
        # \n escape) instead of OLPC canonical (\u000a), then signed by
        # the legitimate targets key. Same dict, different bytes.
        tsnap = repo.files[("snapshot", 1)]
        doc = {"_type": "targets", "version": 2,
               "expires": _iso(fresh),
               "targets": {"skill:alpha": {"length": 128, "hashes": {
                   "sha256": ALPHA_DIGEST}},
                           "skill:note": {"length": 5, "hashes": {
                               "sha256": "cc" * 32},
                               "comment": "line1\nline2"}},
               }
        jcs_like = json.dumps(doc, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        assert b"\\n" in jcs_like and b"\\u000a" not in jcs_like, \
            "fixture does not exercise the escape difference"
        assert br.tuf_canonical_json(doc) != jcs_like, \
            "canonical form unexpectedly equals the JCS form"
        pae_bytes = pae(br.PAYLOAD_TYPES["targets"], jcs_like)
        sig = keys["tgt-a"].sign(pae_bytes).hex()
        rogue_env = {"payload": base64.b64encode(jcs_like).decode("ascii"),
                     "payloadType": br.PAYLOAD_TYPES["targets"],
                     "signatures": [{"keyid": DECLARED["tgt-a"],
                                     "sig": sig}]}
        rogue_wire = br.tuf_canonical_json(rogue_env)
        with tempfile.TemporaryDirectory() as cache:
            r = repo.anchored_refresher(cache_dir=cache)
            if r.refresh().state != "trusted":
                return ("ERROR", "phase-1 refresh not trusted")
            # Plant the attack AFTER phase 1: bind the non-canonical
            # targets properly (new snapshot + timestamp, all
            # legitimately signed). The ONLY defect is the
            # non-canonical payload encoding.
            snap_doc = {"_type": "snapshot", "version": 2,
                        "expires": _iso(fresh),
                        "meta": {"targets.json": {
                            "version": 2, "length": len(rogue_wire),
                            "hashes": {"sha256": hashlib.sha256(
                                rogue_wire).hexdigest()}}}}
            repo.files[("targets", 2)] = rogue_wire
            repo.files[("snapshot", 2)] = br.seal_role(
                "snapshot", snap_doc, [(
                    DECLARED["snap-a"], keys["snap-a"])])
            ts_doc = {"_type": "timestamp", "version": 2,
                      "expires": _iso(fresh),
                      "snapshot": {"version": 2,
                                   "length": len(repo.files[("snapshot", 2)]),
                                   "hashes": {"sha256": hashlib.sha256(
                                       repo.files[("snapshot", 2)]
                                   ).hexdigest()}}}
            repo.files[("timestamp", 2)] = br.seal_role(
                "timestamp", ts_doc, [(DECLARED["ts-a"], keys["ts-a"])])
            report = r.refresh()
            if report.state != "suspended":
                return ("GAP", "non-canonical payload accepted (state=%r)"
                        % (report.state,))
            if "canon" not in (report.reason or "").lower():
                return ("GAP", "suspension reason does not name "
                        "canonicalization: %r" % (report.reason,))
            try:
                r.target_digest("skill:alpha")
                return ("GAP", "suspended refresher served a digest")
            except br.SuspendedError:
                pass
        return ("HELD", "JCS-escaped payload (signed by the real key) "
                "refused on the canonicalization pin before the "
                "signature could bless it")
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(e).__name__, e))


def _p_r8():
    """R8 CACHE_TAMPER: a tampered write-through cache is never trusted."""
    if _ABSENT:
        return ("GAP", "gov.bundle_refresh absent")
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as cache:
            repo = _fresh_repo()
            r1 = repo.anchored_refresher(cache_dir=cache)
            if r1.refresh().state != "trusted":
                return ("ERROR", "phase-1 refresh not trusted")
            # Tamper with the cached targets envelope on disk.
            path = os.path.join(cache, "targets.json")
            with open(path, "rb") as f:
                data = bytearray(f.read())
            data[len(data) // 2] ^= 0x01
            with open(path, "wb") as f:
                f.write(bytes(data))
            # A new refresher must NOT trust the tampered cache: the
            # tampered file fails re-verification and is discarded.
            r2 = repo.anchored_refresher(cache_dir=cache)
            try:
                r2.target_digest("skill:alpha")
                return ("GAP", "tampered cache was trusted blindly")
            except br.SuspendedError:
                pass
            # A fresh refresh over the live repo recovers cleanly.
            report = r2.refresh()
            if report.state != "trusted":
                return ("GAP", "recovery refresh failed: %r %r"
                        % (report.state, report.reason))
            digest, _ = r2.target_digest("skill:alpha")
            if digest != ALPHA_DIGEST:
                return ("GAP", "recovered digest wrong")
        return ("HELD", "tampered cache refused at init; fresh refresh "
                "recovers to trusted")
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(e).__name__, e))


def _p_r9():
    """R9 BINDING_MISMATCH: snapshot bytes != timestamp digest -> refused."""
    if _ABSENT:
        return ("GAP", "gov.bundle_refresh absent")
    try:
        import tempfile
        keys = _keys()
        repo = _fresh_repo()
        fresh = datetime(2030, 1, 1, tzinfo=timezone.utc)
        # A second, validly-signed snapshot whose bytes the timestamp
        # does NOT bind: the timestamp still binds v1's digest.
        repo.build_targets(9, fresh)
        with tempfile.TemporaryDirectory() as cache:
            r = repo.anchored_refresher(cache_dir=cache)
            if r.refresh().state != "trusted":
                return ("ERROR", "phase-1 refresh not trusted")
            # Plant the attack AFTER phase 1: a second, validly-signed
            # snapshot whose bytes the new timestamp does NOT bind (it
            # still binds v1's digest).
            rogue_snap = repo.build_snapshot(9, fresh, 9)
            repo.files[("snapshot", 2)] = rogue_snap  # served as v2...
            ts_doc = {"_type": "timestamp", "version": 2,
                      "expires": _iso(fresh),
                      "snapshot": {"version": 2,
                                   "length": len(rogue_snap),
                                   # ...but bound to v1's digest.
                                   "hashes": {"sha256": hashlib.sha256(
                                       repo.files[("snapshot", 1)]
                                   ).hexdigest()}}}
            repo.files[("timestamp", 2)] = br.seal_role(
                "timestamp", ts_doc, [(DECLARED["ts-a"], keys["ts-a"])])
            report = r.refresh()
            if report.state != "suspended":
                return ("GAP", "digest-mismatched snapshot accepted "
                        "(state=%r)" % (report.state,))
        return ("HELD", "snapshot bytes != timestamp-bound digest -> "
                "BindingError -> suspended")
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(e).__name__, e))


_PROBES = [
    ("R1", "VALID_CHAIN", _p_r1),
    ("R2a", "EXPIRED_ROOT", _p_r2a),
    ("R2b", "STALE_ONLY_REFUSED", _p_r2b),
    ("R3", "ROLLBACK_REFUSED", _p_r3),
    ("R4", "BYTE_CAP", _p_r4),
    ("R5", "ROOT_THRESHOLD", _p_r5),
    ("R6", "KEYID_OPAQUE", _p_r6),
    ("R7", "CANON_MISMATCH", _p_r7),
    ("R8", "CACHE_TAMPER", _p_r8),
    ("R9", "BINDING_MISMATCH", _p_r9),
]


def _green_check():
    """Depth-1 green check: adjacent unit suite, no recursive spawning."""
    import subprocess
    if _SKIP_GREEN:
        return "SKIP (GOV_SKIP_GREEN=1): adjacent unit suite not re-run"
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    test_file = os.path.join(REPO, "tests", "test_bundle_refresh.py")
    if not os.path.exists(test_file):
        return "SKIP: tests/test_bundle_refresh.py absent"
    tmp = os.environ.get("TMPDIR", "/tmp")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", test_file, "-q"], env=env,
            cwd=REPO, capture_output=True, text=True, timeout=600)
        if proc.returncode != 0 and "No module named pytest" in (
                proc.stderr + proc.stdout):
            raise FileNotFoundError("pytest not installed")
    except FileNotFoundError:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest",
             "tests.test_bundle_refresh", "-v"], env=env,
            cwd=REPO, capture_output=True, text=True, timeout=600)
    tail = (proc.stdout + proc.stderr)[-1500:]
    status = "PASS" if proc.returncode == 0 else "FAIL"
    return "adjacent test_bundle_refresh: %s\n%s" % (status, tail)


def main():
    for probe_id, name, fn in _PROBES:
        verdict, detail = _run_twice(fn)
        if verdict == "HELD":
            _held(probe_id, name, detail)
        elif verdict == "GAP":
            _gap(probe_id, name, detail)
        else:
            _record(probe_id, name, "ERROR", detail)
    held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    gap = sum(1 for r in _RESULTS if r["verdict"] == "GAP")
    errors = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    print("bundle_refresh probes: %d HELD / %d GAP / %d ERROR "
          "of %d" % (held, gap, errors, len(_RESULTS)))
    for r in _RESULTS:
        print("  [%s] %s %s: %s" % (r["verdict"], r["id"], r["name"],
                                    r["detail"]))
    print("--- green check ---")
    print(_green_check())
    if errors:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
