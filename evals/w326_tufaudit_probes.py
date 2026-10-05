#!/usr/bin/env python3
"""Wave-326 Lane 4: TUF section-5 client-workflow audit probes for
``gov/bundle_refresh.py``.

Break-first probes, one per audit target. Each probe ATTACKS the refresh
path and asserts the coded refusal:

  Target 1 -- root rotation is exactly N+1 (skip -> RootChainError,
              rollback -> RollbackError, single-threshold -> refuse).
  Target 2 -- freeze attacks: the update-start time is fixed per cycle,
              so a clock that advances mid-cycle cannot flip verdicts;
              replayed old-but-valid timestamps are refused by rollback.
  Target 3 -- rollback protection on every role (root, timestamp,
              snapshot, targets).
  Target 4 -- fast-forward recovery after a trust-changing root rotation
              (re-bootstrap under the new root, pre-rotation floor).
  Target 5 -- mix-and-match: snapshot/targets version+digest bindings
              checked against the parent.
  Target 6 -- arbitrary-update vs rollback boundary: a compromised role
              key publishing *newer* valid versions is inside the TUF
              trust model (documented, not a finding).

Probe outcome vocabulary: HELD (the coded refusal fired -- conformant),
BREAK (the attack succeeded -- genuine gap), ERROR (harness failure).

Battery rules: GOV_DEPLOYMENT_MODE=staging at module level; clean under
``env -u GOV_DEPLOYMENT_MODE``; green checks are depth-1 and honor
GOV_SKIP_GREEN; no in-repo git subprocesses.
"""

import hashlib
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import bundle_refresh as br  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

TAXONOMY_PIN = 2127  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).

# ---------------------------------------------------------------------------
# Fixture: a miniature TUF repository in memory.
# ---------------------------------------------------------------------------

def _mk_repo():
    keys = {
        "a": Ed25519Signer(b"\x11" * 32),
        "b": Ed25519Signer(b"\x22" * 32),
        "ts": Ed25519Signer(b"\x33" * 32),
        "tk2": Ed25519Signer(b"\x55" * 32),   # rotated timestamp key
        "rk3": Ed25519Signer(b"\x44" * 32),   # rotated root key
    }
    kids = {"a": "kid-a", "b": "kid-b", "ts": "kid-ts",
            "tk2": "kid-tk2", "rk3": "kid-rk3"}
    return keys, kids


class Repo(object):
    """In-memory versioned repository. ``drop(role, version)`` simulates
    the repository no longer serving that slot (prune / gap)."""

    def __init__(self, now):
        self.keys, self.kids = _mk_repo()
        self.now = now
        self.expires = (now + timedelta(days=365)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        self.files = {}

    def _keys_doc(self, names):
        return {self.kids[n]: {"keytype": "ed25519", "keyval": {
            "public": self.keys[n].public_key.hex()}} for n in names}

    def root(self, version, root_kids, ts_kid, old_signers, new_signers):
        doc = {
            "_type": "root", "version": version, "expires": self.expires,
            "keys": self._keys_doc(["a", "b", "ts", "tk2", "rk3"]),
            "roles": {
                "root": {"keyids": [self.kids[k] for k in root_kids],
                         "threshold": 2},
                "timestamp": {"keyids": [self.kids[ts_kid]], "threshold": 1},
                "snapshot": {"keyids": [self.kids[ts_kid]], "threshold": 1},
                "targets": {"keyids": [self.kids[ts_kid]], "threshold": 1}},
        }
        self.files[("root", version)] = br.seal_role(
            "root", doc, [(self.kids[k], self.keys[k])
                          for k in old_signers + new_signers])

    def targets(self, version, kid):
        doc = {"_type": "targets", "version": version,
               "expires": self.expires,
               "targets": {"skill:x": {
                   "length": 10, "hashes": {"sha256": "ab" * 32}}}}
        self.files[("targets", version)] = br.seal_role(
            "targets", doc, [(self.kids[kid], self.keys[kid])])

    def snapshot(self, version, tgt_version, kid):
        twire = self.files[("targets", tgt_version)]
        doc = {"_type": "snapshot", "version": version,
               "expires": self.expires,
               "meta": {"targets.json": {
                   "version": tgt_version,
                   "length": len(twire),
                   "hashes": {"sha256": hashlib.sha256(
                       twire).hexdigest()}}}}
        self.files[("snapshot", version)] = br.seal_role(
            "snapshot", doc, [(self.kids[kid], self.keys[kid])])

    def timestamp(self, version, snap_version, kid):
        swire = self.files[("snapshot", snap_version)]
        doc = {"_type": "timestamp", "version": version,
               "expires": self.expires,
               "snapshot": {
                   "version": snap_version,
                   "length": len(swire),
                   "hashes": {"sha256": hashlib.sha256(
                       swire).hexdigest()}}}
        self.files[("timestamp", version)] = br.seal_role(
            "timestamp", doc, [(self.kids[kid], self.keys[kid])])

    def drop(self, role, version):
        self.files.pop((role, version), None)

    def fetch(self, role, version):
        key = (role, version)
        if key not in self.files:
            raise br.FetchNotFound("no %s v%s" % (role, version))
        return self.files[key]


def _refresher(repo, clock, tmpdir=None):
    if tmpdir is None:
        tmpdir = tempfile.mkdtemp(prefix="w326tuf-")
    return br.BundleRefresher(
        trusted_root_wire=repo.files[("root", 1)],
        fetch=repo.fetch, cache_dir=tmpdir, clock=clock), tmpdir


def _base_repo(now):
    """Root v1 (a,b 2-of-2; ts for subordinates), targets/snapshot v1,
    timestamp v1..v3 under the old key."""
    repo = Repo(now)
    repo.root(1, ["a", "b"], "ts", ["a", "b"], [])
    repo.targets(1, "ts")
    repo.snapshot(1, 1, "ts")
    for v in (1, 2, 3):
        repo.timestamp(v, 1, "ts")
    return repo


PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


# ---------------------------------------------------------------------------
# Target 1: root rotation is exactly N+1.
# ---------------------------------------------------------------------------

@probe("T1a-root-skip-Nplus2-refused")
def _p1a():
    """The repository serves a root v3 document AT slot v2 while the
    client trusts v1 (v2 skipped). The exact N+1 rule must refuse with
    RootChainError; the client suspends."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    # Craft the v3 doc, but serve it at slot 2 (the probed N+1 slot).
    repo.root(3, ["b", "rk3"], "ts", ["a", "b"], ["b", "rk3"])
    repo.files[("root", 2)] = repo.files.pop(("root", 3))
    rep = r.refresh()
    if rep.state == "suspended" and "skips versions" in (rep.reason or ""):
        return "HELD", "skip v1->v3 refused: %s" % rep.reason
    return "BREAK", "skip not refused: state=%s reason=%s" % (
        rep.state, rep.reason)


@probe("T1b-root-rollback-refused")
def _p1b():
    """After adopting root v2, serve the older root v1 at the v2 slot.
    Rollback must raise; the client suspends."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    repo.root(2, ["b", "rk3"], "ts", ["a", "b"], ["b", "rk3"])
    assert r.refresh().state == "trusted"
    assert r._root_version == 2
    # Attacker rewinds the v2 slot to the v1 bytes.
    repo.files[("root", 2)] = repo.files[("root", 1)]
    rep = r.refresh()
    if rep.state == "suspended" and "older than trusted" in (
            rep.reason or ""):
        return "HELD", "root rollback refused: %s" % rep.reason
    return "BREAK", "rollback not refused: state=%s reason=%s" % (
        rep.state, rep.reason)


@probe("T1c-root-single-threshold-refused")
def _p1c():
    """Root v2 signed only by the OLD keys (a,b) -- the new root role
    (b,rk3) threshold is not met. Dual-threshold chaining must refuse."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    # v2 declares new root role (b,rk3) but carries only old (a,b) sigs.
    repo.root(2, ["b", "rk3"], "ts", ["a", "b"], [])
    rep = r.refresh()
    if rep.state == "suspended" and "threshold" in (rep.reason or "").lower():
        return "HELD", "single-threshold v2 refused: %s" % rep.reason
    return "BREAK", "single-threshold accepted: state=%s reason=%s" % (
        rep.state, rep.reason)


@probe("T1d-root-valid-Nplus1-adopted")
def _p1d():
    """Positive control: a dual-signed v2 (old 2-of-2 AND new 2-of-2)
    is adopted and the version advances."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    repo.root(2, ["b", "rk3"], "ts", ["a", "b"], ["b", "rk3"])
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    rep = r.refresh()
    if rep.state == "trusted" and r._root_version == 2:
        return "HELD", "valid N+1 adopted, root v2"
    return "BREAK", "valid N+1 not adopted: state=%s root=v%s" % (
        rep.state, r._root_version)


# ---------------------------------------------------------------------------
# Target 2: freeze attacks -- fixed update-start time.
# ---------------------------------------------------------------------------

@probe("T2a-update-start-time-pinned")
def _p2a():
    """The clock returns pre-expiry at cycle start, then post-expiry on
    every later read. The per-cycle pinned reference time must keep the
    whole cycle pre-expiry: state stays trusted. (If expiry were sampled
    per-check, the later reads would flip the cycle to stale.)"""
    start = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = Repo(start)
    repo.expires = (start + timedelta(minutes=30)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    repo.root(1, ["a", "b"], "ts", ["a", "b"], [])
    repo.targets(1, "ts")
    repo.snapshot(1, 1, "ts")
    repo.timestamp(1, 1, "ts")
    calls = []

    def clock():
        calls.append(1)
        # First two reads (pinned-root check at init, cycle sample at
        # refresh start) see pre-expiry; every later read is post-expiry.
        if len(calls) <= 2:
            return start
        return start + timedelta(hours=2)

    r, _ = _refresher(repo, clock)
    rep = r.refresh()
    if rep.state == "trusted":
        return "HELD", "cycle pinned at start; %d clock reads" % len(calls)
    return "BREAK", "mid-cycle clock advance flipped verdict: state=%s" % (
        rep.state,)


@probe("T2b-replayed-old-timestamp-refused")
def _p2b():
    """Freeze via replay: the attacker re-serves timestamp v2 (still
    unexpired, validly signed) after the client reached v3. The
    timestamp rollback floor must refuse."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    assert r._chain["timestamp"]["doc"]["version"] == 3
    old_v2 = repo.files[("timestamp", 2)]
    # Attacker rewinds every newer slot to the v2 bytes.
    for v in (3, 4, 5, 6):
        repo.files[("timestamp", v)] = old_v2
    rep = r.refresh()
    if rep.state == "suspended" and "older than trusted" in (
            rep.reason or ""):
        return "HELD", "replayed timestamp refused: %s" % rep.reason
    return "BREAK", "freeze replay accepted: state=%s reason=%s" % (
        rep.state, rep.reason)


# ---------------------------------------------------------------------------
# Target 3: rollback protection on every role.
# ---------------------------------------------------------------------------

@probe("T3a-timestamp-rollback-refused")
def _p3a():
    """Serve timestamp v2 at slot v4 while the client trusts v3."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    repo.files[("timestamp", 4)] = repo.files[("timestamp", 2)]
    rep = r.refresh()
    if rep.state == "suspended" and "older than trusted" in (
            rep.reason or ""):
        return "HELD", "timestamp rollback refused"
    return "BREAK", "timestamp rollback accepted: state=%s" % rep.state


@probe("T3b-snapshot-rollback-via-timestamp-refused")
def _p3b():
    """A valid newer timestamp (v4) binds snapshot v1 while the client
    trusts snapshot v2: the bound-role rollback floor must refuse even
    though the timestamp itself is newer and validly signed."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    # Advance snapshot to v2 under the old key first.
    repo.targets(2, "ts")
    repo.snapshot(2, 2, "ts")
    repo.timestamp(4, 2, "ts")
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    assert r._chain["snapshot"]["doc"]["version"] == 2
    # Evil but validly-signed timestamp v5 binds the OLD snapshot v1.
    repo.timestamp(5, 1, "ts")
    repo.drop("timestamp", 6)
    rep = r.refresh()
    if rep.state == "suspended" and "older than trusted" in (
            rep.reason or "").lower():
        return "HELD", "snapshot rollback via timestamp refused: %s" % (
            rep.reason,)
    return "BREAK", "snapshot rollback accepted: state=%s reason=%s" % (
        rep.state, rep.reason)


@probe("T3c-targets-rollback-via-snapshot-refused")
def _p3c():
    """A valid newer snapshot binds targets v1 while the client trusts
    targets v2: refused."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    repo.targets(2, "ts")
    repo.snapshot(2, 2, "ts")
    repo.timestamp(4, 2, "ts")
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    assert r._chain["targets"]["doc"]["version"] == 2
    # Snapshot v3 binds the OLD targets v1; timestamp v5 binds snap v3.
    repo.snapshot(3, 1, "ts")
    repo.timestamp(5, 3, "ts")
    rep = r.refresh()
    if rep.state == "suspended" and "older than trusted" in (
            rep.reason or "").lower():
        return "HELD", "targets rollback via snapshot refused: %s" % (
            rep.reason,)
    return "BREAK", "targets rollback accepted: state=%s reason=%s" % (
        rep.state, rep.reason)


# ---------------------------------------------------------------------------
# Target 4: fast-forward recovery after a trust-changing root rotation.
# ---------------------------------------------------------------------------

def _rotated_repo(now, ts_versions, drop_old_ts=()):
    """Root v1 -> v2 rotating root key a->rk3 AND timestamp key ts->tk2.
    New timestamp versions ``ts_versions`` are published under tk2;
    old timestamp slots in ``drop_old_ts`` are removed (pruned repo)."""
    repo = _base_repo(now)
    repo.root(2, ["b", "rk3"], "tk2", ["a", "b"], ["b", "rk3"])
    repo.targets(2, "tk2")
    repo.snapshot(2, 2, "tk2")
    for v in ts_versions:
        repo.timestamp(v, 2, "tk2")
    for v in drop_old_ts:
        repo.drop("timestamp", v)
    return repo


@probe("T4a-post-rotation-recovers-contiguous")
def _p4a():
    """Positive control: old versions retained (contiguous from v1), new
    timestamp v4 under the rotated key. Client re-bootstraps and trusts."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _rotated_repo(now, [4])
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    rep = r.refresh()
    if (rep.state == "trusted" and r._root_version == 2
            and rep.versions.get("timestamp") == 4
            and any("re-bootstrap" in w for w in r.warnings)):
        return "HELD", "re-bootstrap recovered to timestamp v4"
    return "BREAK", "recovery failed: state=%s versions=%s" % (
        rep.state, rep.versions)


@probe("T4b-post-rotation-floor-enforced")
def _p4b():
    """Attacker plants a new-key-signed timestamp v1 (below the
    pre-rotation floor v3) at the v1 slot BEFORE the rotation refresh:
    the bootstrap's floor check must refuse."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    # Publish the rotation (root v2 + timestamp v4 under the new key).
    repo.root(2, ["b", "rk3"], "tk2", ["a", "b"], ["b", "rk3"])
    repo.targets(2, "tk2")
    repo.snapshot(2, 2, "tk2")
    repo.timestamp(4, 2, "tk2")
    # Plant: valid tk2-signed timestamp with version 1 at slot 1.
    _env, doc, _payload = br._parse_envelope(
        "timestamp", repo.files[("timestamp", 4)], "plant",
        br.DEFAULT_MAX_LENGTH)
    evil = dict(doc)
    evil["version"] = 1
    repo.files[("timestamp", 1)] = br.seal_role(
        "timestamp", evil,
        [(repo.kids["tk2"], repo.keys["tk2"])])
    rep = r.refresh()
    if rep.state == "suspended" and "pre-rotation" in (
            rep.reason or "").lower():
        return "HELD", "sub-floor timestamp refused: %s" % rep.reason
    return "BREAK", "sub-floor timestamp accepted: state=%s reason=%s" % (
        rep.state, rep.reason)


@probe("T4c-post-rotation-pruned-v1-wedges")
def _p4c():
    """The repository continues versioning under the new key (v4, v5)
    and prunes the old v1..v3 slots. The bootstrap scans from v1 and
    breaks on the first miss -- the client suspends on EVERY refresh
    and can never recover (F410)."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    # Rotation: root v2 (new timestamp key), v4+v5 under the new key,
    # old v1..v3 slots pruned by the repository.
    repo.root(2, ["b", "rk3"], "tk2", ["a", "b"], ["b", "rk3"])
    repo.targets(2, "tk2")
    repo.snapshot(2, 2, "tk2")
    for v in (4, 5):
        repo.timestamp(v, 2, "tk2")
    for v in (1, 2, 3):
        repo.drop("timestamp", v)
    rep = r.refresh()
    rep2 = r.refresh()  # a second cycle must not self-heal
    if rep.state == "suspended" and rep2.state == "suspended":
        return "BREAK", (
            "F410: pruned pre-rotation slots wedge the client forever: "
            "state=%s reason=%s" % (rep.state, rep.reason))
    if rep.state == "trusted" and rep.versions.get("timestamp") == 5:
        return "HELD", "bootstrap skipped pruned slots and recovered"
    return "ERROR", "unexpected: %s/%s" % (rep.state, rep2.state)


@probe("T4d-post-rotation-gap-wedges")
def _p4d():
    """Same root cause as T4c via a single gap: v1, v2 (old key), v3
    missing, v4, v5 (new key). The first miss breaks the scan even
    though valid newer versions exist (F410)."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    repo.root(2, ["b", "rk3"], "tk2", ["a", "b"], ["b", "rk3"])
    repo.targets(2, "tk2")
    repo.snapshot(2, 2, "tk2")
    for v in (4, 5):
        repo.timestamp(v, 2, "tk2")
    repo.drop("timestamp", 3)
    rep = r.refresh()
    if rep.state == "suspended":
        return "BREAK", (
            "F410: a single pruned slot wedges the client: state=%s "
            "reason=%s" % (rep.state, rep.reason))
    if rep.state == "trusted" and rep.versions.get("timestamp") == 5:
        return "HELD", "bootstrap skipped the gap and recovered"
    return "ERROR", "unexpected: %s" % rep.state


# ---------------------------------------------------------------------------
# Target 5: mix-and-match -- parent version+digest bindings.
# ---------------------------------------------------------------------------

@probe("T5a-snapshot-digest-mismatch-refused")
def _p5a():
    """Timestamp v4 binds snapshot v2 with a forged digest: the binding
    check must refuse before signature verification."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    repo.targets(2, "ts")
    repo.snapshot(2, 2, "ts")
    # Timestamp v4 claims snapshot v2 but with a wrong digest.
    swire = repo.files[("snapshot", 2)]
    doc = {"_type": "timestamp", "version": 4, "expires": repo.expires,
           "snapshot": {"version": 2, "length": len(swire),
                        "hashes": {"sha256": "ff" * 32}}}
    repo.files[("timestamp", 4)] = br.seal_role(
        "timestamp", doc, [(repo.kids["ts"], repo.keys["ts"])])
    rep = r.refresh()
    if rep.state == "suspended" and "digest" in (rep.reason or "").lower():
        return "HELD", "snapshot digest mismatch refused: %s" % rep.reason
    return "BREAK", "digest mismatch accepted: state=%s reason=%s" % (
        rep.state, rep.reason)


@probe("T5b-snapshot-version-mismatch-refused")
def _p5b():
    """Timestamp v4 binds snapshot v2, but the served bytes at the v2
    slot are really snapshot v3 (mix-and-match across versions)."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    repo.targets(2, "ts")
    repo.snapshot(2, 2, "ts")
    repo.targets(3, "ts")
    repo.snapshot(3, 3, "ts")
    repo.timestamp(4, 2, "ts")
    # Swap the v2 slot to serve v3 bytes (version mismatch).
    repo.files[("snapshot", 2)] = repo.files[("snapshot", 3)]
    rep = r.refresh()
    if rep.state == "suspended" and "parent-bound" in (
            rep.reason or "").lower():
        return "HELD", "version mismatch refused: %s" % rep.reason
    return "BREAK", "mix-and-match accepted: state=%s reason=%s" % (
        rep.state, rep.reason)


@probe("T5c-targets-digest-mismatch-refused")
def _p5c():
    """Snapshot binds targets v2 with a forged digest: refused."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    repo.targets(2, "ts")
    twire = repo.files[("targets", 2)]
    doc = {"_type": "snapshot", "version": 2, "expires": repo.expires,
           "meta": {"targets.json": {
               "version": 2, "length": len(twire),
               "hashes": {"sha256": "00" * 32}}}}
    repo.files[("snapshot", 2)] = br.seal_role(
        "snapshot", doc, [(repo.kids["ts"], repo.keys["ts"])])
    repo.timestamp(4, 2, "ts")
    rep = r.refresh()
    if rep.state == "suspended" and "digest" in (rep.reason or "").lower():
        return "HELD", "targets digest mismatch refused"
    return "BREAK", "targets mix-and-match accepted: state=%s reason=%s" % (
        rep.state, rep.reason)


@probe("T5d-targets-swap-across-snapshots-refused")
def _p5d():
    """Snapshot v2 binds targets v2, but the served v2 bytes are really
    targets v3 (different skill bytes, validly signed): the digest
    binding must catch the swap."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    repo.targets(2, "ts")
    # A *different* targets v2' with attacker-chosen content.
    doc = {"_type": "targets", "version": 2, "expires": repo.expires,
           "targets": {"skill:evil": {
               "length": 3, "hashes": {"sha256": "cc" * 32}}}}
    evil = br.seal_role("targets", doc,
                        [(repo.kids["ts"], repo.keys["ts"])])
    repo.snapshot(2, 2, "ts")   # binds the GOOD targets v2
    repo.timestamp(4, 2, "ts")
    repo.files[("targets", 2)] = evil  # swap in the evil v2
    rep = r.refresh()
    if rep.state == "suspended" and "digest" in (rep.reason or "").lower():
        return "HELD", "targets swap refused by digest binding"
    return "BREAK", "targets swap accepted: state=%s reason=%s" % (
        rep.state, rep.reason)


# ---------------------------------------------------------------------------
# Target 6: arbitrary-update vs rollback boundary.
# ---------------------------------------------------------------------------

@probe("T6a-compromised-key-newer-version-is-trust-model")
def _p6a():
    """A compromised timestamp key publishing NEWER valid versions
    (v4 with evil snapshot) is accepted -- this is inside the TUF trust
    model (the key is trusted), not a rollback. Documents the boundary;
    HELD means the code behaves as the model dictates."""
    now = datetime(2026, 6, 1, 12, tzinfo=timezone.utc)
    repo = _base_repo(now)
    r, _ = _refresher(repo, lambda: now)
    assert r.refresh().state == "trusted"
    # Attacker holds the ts key: publishes newer timestamp v4 -> snap v2
    # -> targets v2 with evil content, all validly signed.
    doc = {"_type": "targets", "version": 2, "expires": repo.expires,
           "targets": {"skill:evil": {
               "length": 3, "hashes": {"sha256": "cc" * 32}}}}
    repo.files[("targets", 2)] = br.seal_role(
        "targets", doc, [(repo.kids["ts"], repo.keys["ts"])])
    repo.snapshot(2, 2, "ts")
    repo.timestamp(4, 2, "ts")
    rep = r.refresh()
    # The trust model says this MUST be accepted (the key is trusted).
    if rep.state == "trusted" and rep.versions.get("timestamp") == 4:
        return "HELD", (
            "boundary documented: newer valid versions under a trusted "
            "(compromised) key are accepted -- key compromise is outside "
            "the rollback defense")
    return "ERROR", "unexpected: state=%s" % rep.state


# ---------------------------------------------------------------------------
# Runner.
# ---------------------------------------------------------------------------

def run_all():
    results = []
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except AssertionError as exc:
            verdict, detail = "ERROR", "harness assertion: %s" % exc
        except Exception as exc:  # noqa: BLE001
            verdict, detail = "ERROR", "%s: %s" % (
                type(exc).__name__, exc)
        results.append((name, verdict, detail))
    return results


def main():
    results = run_all()
    held = sum(1 for _, v, _ in results if v == "HELD")
    broken = sum(1 for _, v, _ in results if v == "BREAK")
    errors = sum(1 for _, v, _ in results if v == "ERROR")
    print("w326 TUF section-5 audit probes: %d/%d/%d held/break/error" % (
        held, broken, errors))
    for name, verdict, detail in results:
        print("  [%s] %s: %s" % (verdict, name, detail))
    # Expected BREAKs are the filed findings; anything else is a failure.
    # (F410 closed wave-327 lane 2: the post-rotation bootstrap now
    # tolerates pruned slots, so T4c/T4d hold.)
    expected_breaks = set()
    actual_breaks = {n for n, v, _ in results if v == "BREAK"}
    ok = (errors == 0 and actual_breaks == expected_breaks)
    if not ok:
        print("MISMATCH: expected breaks %s, got %s, errors %d" % (
            sorted(expected_breaks), sorted(actual_breaks), errors))
        return 1
    print("all probes match expectations (0 expected BREAKs: F410 closed)")
    return 0


def _green_check():
    """Depth-1 green check: run the existing bundle_refresh unit tests
    with green checks skipped in the child. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("green check: skipped (GOV_SKIP_GREEN set)")
        return 0
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cmd = [sys.executable, "-m", "unittest",
           "tests.test_bundle_refresh", "-v"]
    proc = subprocess.run(cmd, cwd=repo_root, env=env,
                          capture_output=True, text=True, timeout=600)
    tail = "\n".join(proc.stdout.splitlines()[-5:])
    print("green check: unittest tests.test_bundle_refresh -> rc=%d" % (
        proc.returncode,))
    print(tail)
    return proc.returncode


if __name__ == "__main__":
    if "--green-check" in sys.argv:
        sys.exit(_green_check())
    sys.exit(main())
