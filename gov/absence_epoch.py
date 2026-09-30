"""Signed absence epochs (W242-9, ADAPT -- pattern only, prose re-derived).

TACET's signed-absence-epoch mechanism gives us the shape for a
non-exfiltration *absence* story: beacon-opened hourly epochs, signed
observations-of-absence, a sparse Merkle map committing the epoch
ledger, and an offline-verifiable portable bundle. NOT the Bitcoin
anchor. No upstream code is read, imported, or vendored; the pattern
is re-derived in prose from the wave-241 prospectus description.

Protocol
--------
An epoch is one hour: ``epoch_of(ts) == ts // 3600``. A deployment
beacon opens each epoch with a signed beacon record. During the epoch,
observers sign observations-of-absence per scope (e.g.
``"egress:corp-net"``); the deployment also records disclosures into
the same epoch ledger. The beacon then closes the epoch by signing the
sparse-Merkle root over the whole ledger. Verification recomputes the
root from the ledger in the bundle and compares it with the closed
root -- the committed root, not any single claim, is the authority.

Refusal vocabulary (domain ``absence-epoch``, all fail-closed):

* ``absence-epoch-beacon-unsigned`` -- beacon (or close) signature does
  not verify, or the close is not signed by the epoch's beacon key.
* ``absence-epoch-not-open`` -- no beacon for the claimed epoch.
* ``absence-epoch-not-closed`` -- no close record; an unclosed epoch
  has no committed authority, so nothing verifies.
* ``absence-epoch-closed`` -- a new observation for a closed epoch is
  refused (epochs are append-only while open, frozen after close).
* ``absence-epoch-malformed`` -- the bundle/record is not the shape
  this module speaks.
* ``absence-backdated`` -- the observation's ``observed_at`` is before
  the epoch start or after the epoch close (backdating into a closed
  epoch fails).
* ``absence-root-mismatch`` -- the ledger in the bundle does not
  recompute to the closed root (tampering, or a swapped leaf).
* ``absence-disclosure-recorded`` -- the cell for (epoch, scope)
  commits a disclosure; an absence claim for that cell is forged.
* ``absence-not-observed`` -- no absence observation for the cell.
* ``absence-observation-unsigned`` -- the observation signature does
  not verify, names the wrong observer, or is not bound to the epoch
  beacon.

Honest boundaries
-----------------
* Signatures prove *who claimed what*, not that nothing happened: an
  absence observation is only as honest as its observer. The mechanism
  makes absence claims *checkable* (bound to a closed epoch root); it
  cannot make the observer honest.
* The beacon is the deployment's trusted epoch opener. A dishonest
  beacon can open epochs arbitrarily; beacon key custody is
  deployment-owned.
* Tail truncation (epochs the beacon never opened) is not detectable
  by this module: coverage is a deployment declaration, not a proof.
* This module never touches the network: ``verify_absence`` takes only
  the portable bundle dict. Offline verification is structural, not a
  configuration flag.

Stdlib only, plus in-repo ``gov.ed25519`` (pure-Python, the same
checker-primitive precedent wave-241's ``recompute_check`` set).
Deterministic: every clock is injected.
"""

import hashlib
import json

try:
    from .ed25519 import generate_seed as _generate_seed
    from .ed25519 import publickey as _publickey
    from .ed25519 import sign as _sign
    from .ed25519 import verify as _verify
except ImportError:  # pragma: no cover - importable in-repo by construction
    _generate_seed = _publickey = _sign = _verify = None


EPOCH_SECONDS = 3600

_DOMAIN = b"absence-epoch-v1:"

BEACON_UNSIGNED = "absence-epoch-beacon-unsigned"
NOT_OPEN = "absence-epoch-not-open"
NOT_CLOSED = "absence-epoch-not-closed"
EPOCH_CLOSED = "absence-epoch-closed"
MALFORMED = "absence-epoch-malformed"
BACKDATED = "absence-backdated"
ROOT_MISMATCH = "absence-root-mismatch"
DISCLOSURE_RECORDED = "absence-disclosure-recorded"
NOT_OBSERVED = "absence-not-observed"
OBSERVATION_UNSIGNED = "absence-observation-unsigned"


class AbsenceEpochError(Exception):
    """Fail-closed absence-epoch refusal. ``code`` is the vocabulary."""

    def __init__(self, code, detail=""):
        super(AbsenceEpochError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


def epoch_of(ts):
    """Hour index for a unix timestamp (int)."""
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        raise AbsenceEpochError(MALFORMED, "ts must be a number")
    return int(ts) // EPOCH_SECONDS


def _h(data):
    return hashlib.sha256(_DOMAIN + data).digest()


_EMPTY_LEAF = _h(b"empty")


def _leaf_hash(key, value_digest):
    return _h(b"\x00" + key + value_digest)


def _node_hash(left, right):
    return _h(b"\x01" + left + right)


def _cell_key(epoch, scope):
    if isinstance(scope, bool) or not isinstance(scope, str) or not scope:
        raise AbsenceEpochError(MALFORMED, "scope must be a non-empty str")
    return _h(b"epoch:" + int(epoch).to_bytes(8, "big")
              + b"\x00scope:" + scope.encode("utf-8"))


def smt_root(pairs):
    """Sparse-Merkle root over (key_bytes, value_digest) pairs.

    Deterministic; empty map roots to the empty-leaf constant.
    """
    if not pairs:
        return _EMPTY_LEAF
    cur = {}
    for key, value_digest in pairs:
        path = int.from_bytes(key, "big")
        cur[path] = _leaf_hash(key, value_digest)
    for _depth in range(256):
        groups = {}
        for path, node in cur.items():
            parent = path >> 1
            groups.setdefault(parent, {})[path & 1] = node
        nxt = {}
        for parent, kids in groups.items():
            nxt[parent] = _node_hash(kids.get(0, _EMPTY_LEAF),
                                     kids.get(1, _EMPTY_LEAF))
        cur = nxt
        if len(cur) == 1 and 0 in cur:
            break
    return cur.get(0, _EMPTY_LEAF)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest_hex(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _require_ed25519():
    if _sign is None:
        raise AbsenceEpochError(
            MALFORMED, "gov.ed25519 unavailable; cannot sign or verify")
    return True


def pub_of(seed):
    """Hex public key for a 32-byte seed."""
    _require_ed25519()
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise AbsenceEpochError(MALFORMED, "seed must be 32 bytes")
    return _publickey(bytes(seed)).hex()


def _sign_record(seed, record):
    _require_ed25519()
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise AbsenceEpochError(MALFORMED, "seed must be 32 bytes")
    body = {k: v for k, v in record.items() if k != "sig"}
    sig = _sign(bytes(seed), _canonical(body))
    out = dict(body)
    out["sig"] = sig.hex()
    return out


def _verify_record(record, pub_hex, code):
    _require_ed25519()
    try:
        pub = bytes.fromhex(pub_hex)
        sig = bytes.fromhex(record["sig"])
    except (KeyError, ValueError, TypeError):
        raise AbsenceEpochError(code, "unparseable key or signature")
    body = {k: v for k, v in record.items() if k != "sig"}
    ok = _verify(pub, _canonical(body), sig)
    if not ok:
        raise AbsenceEpochError(code, "signature does not verify")
    return True


def _check_epoch_int(epoch):
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise AbsenceEpochError(MALFORMED, "epoch must be a non-negative int")
    return epoch


def open_epoch(beacon_seed, epoch, prev_root, opened_at):
    """Beacon-opens an epoch. Returns the signed beacon record."""
    _check_epoch_int(epoch)
    if not isinstance(prev_root, str):
        raise AbsenceEpochError(MALFORMED, "prev_root must be a hex str")
    if not isinstance(opened_at, (int, float)) or isinstance(opened_at,
                                                             bool):
        raise AbsenceEpochError(MALFORMED, "opened_at must be a number")
    record = {
        "type": "absence-epoch-beacon",
        "v": 1,
        "epoch": epoch,
        "opened_at": opened_at,
        "prev_root": prev_root,
        "beacon_pub": pub_of(beacon_seed),
    }
    return _sign_record(beacon_seed, record)


def observe_absence(observer_seed, beacon, scope, observed_at,
                    closed_epochs=None):
    """Sign an observation-of-absence for (epoch, scope).

    Refuses ``absence-epoch-closed`` when the epoch already has a
    close record (epochs freeze at close), and
    ``absence-epoch-malformed`` when the beacon is not a beacon record.
    """
    if not isinstance(beacon, dict) or \
            beacon.get("type") != "absence-epoch-beacon":
        raise AbsenceEpochError(MALFORMED, "beacon must be a beacon record")
    epoch = _check_epoch_int(beacon.get("epoch"))
    if closed_epochs and str(epoch) in closed_epochs:
        raise AbsenceEpochError(
            EPOCH_CLOSED,
            "epoch %d is closed; observations are append-only while open"
            % epoch)
    if not isinstance(observed_at, (int, float)) or isinstance(
            observed_at, bool):
        raise AbsenceEpochError(MALFORMED, "observed_at must be a number")
    start = epoch * EPOCH_SECONDS
    if not (start <= observed_at < start + EPOCH_SECONDS):
        raise AbsenceEpochError(
            BACKDATED,
            "observed_at %r is outside epoch %d [%d, %d)" % (
                observed_at, epoch, start, start + EPOCH_SECONDS))
    record = {
        "type": "absence-observation",
        "v": 1,
        "epoch": epoch,
        "scope": scope,
        "observed_at": observed_at,
        "beacon_digest": _digest_hex(
            {k: v for k, v in beacon.items() if k != "sig"}),
        "observer_pub": pub_of(observer_seed),
    }
    return _sign_record(observer_seed, record)


def resign_observation(observer_seed, observation):
    """Re-sign an observation after field mutation (test/rotation use).

    The signature covers the current fields; this is the honest way to
    amend a record, as opposed to silently editing a signed blob.
    """
    if not isinstance(observation, dict) or \
            observation.get("type") != "absence-observation":
        raise AbsenceEpochError(MALFORMED, "not an absence observation")
    return _sign_record(observer_seed, observation)


def record_disclosure(signer_seed, beacon, scope, disclosed_at,
                      detail_digest):
    """Record a disclosure for (epoch, scope) into the epoch ledger.

    A disclosure occupies the cell: any later absence claim for the
    same cell is forged. The disclosure is signed by the deployment's
    disclosure key; its authority at verification time comes from the
    beacon-signed close root committing the ledger.
    """
    if not isinstance(beacon, dict) or \
            beacon.get("type") != "absence-epoch-beacon":
        raise AbsenceEpochError(MALFORMED, "beacon must be a beacon record")
    epoch = _check_epoch_int(beacon.get("epoch"))
    if not isinstance(disclosed_at, (int, float)) or isinstance(
            disclosed_at, bool):
        raise AbsenceEpochError(MALFORMED, "disclosed_at must be a number")
    if not isinstance(detail_digest, str) or not detail_digest:
        raise AbsenceEpochError(MALFORMED, "detail_digest must be a hex str")
    record = {
        "type": "absence-disclosure",
        "v": 1,
        "epoch": epoch,
        "scope": scope,
        "disclosed_at": disclosed_at,
        "detail_digest": detail_digest,
        "signer_pub": pub_of(signer_seed),
    }
    return _sign_record(signer_seed, record)


def close_epoch(beacon_seed, epoch, ledger, prev_root, closed_at):
    """Beacon-closes an epoch, committing the sparse-Merkle root."""
    _check_epoch_int(epoch)
    if not isinstance(ledger, dict):
        raise AbsenceEpochError(MALFORMED, "ledger must be a dict")
    if not isinstance(closed_at, (int, float)) or isinstance(closed_at,
                                                              bool):
        raise AbsenceEpochError(MALFORMED, "closed_at must be a number")
    pairs = []
    for scope, cell in ledger.items():
        if not isinstance(cell, dict):
            raise AbsenceEpochError(MALFORMED, "ledger cell must be a dict")
        key = _cell_key(epoch, scope)
        value = bytes.fromhex(_digest_hex(cell))
        pairs.append((key, value))
    root = smt_root(pairs).hex()
    record = {
        "type": "absence-epoch-close",
        "v": 1,
        "epoch": epoch,
        "root": root,
        "closed_at": closed_at,
        "prev_root": prev_root,
        "beacon_pub": pub_of(beacon_seed),
    }
    return _sign_record(beacon_seed, record)


def make_bundle(beacons, closes, ledgers, pubs):
    """Assemble the portable offline-verifiable bundle (plain dict)."""
    for name, seq in (("beacons", beacons), ("closes", closes)):
        if not isinstance(seq, (list, tuple)) or \
                not all(isinstance(r, dict) for r in seq):
            raise AbsenceEpochError(MALFORMED, "%s must be a list of dicts"
                                    % name)
    if not isinstance(ledgers, dict):
        raise AbsenceEpochError(MALFORMED, "ledgers must be a dict")
    if not isinstance(pubs, dict):
        raise AbsenceEpochError(MALFORMED, "pubs must be a dict")
    return {
        "type": "absence-epoch-bundle",
        "v": 1,
        "beacons": list(beacons),
        "closes": list(closes),
        "ledgers": dict(ledgers),
        "pubs": dict(pubs),
    }


def _find(records, rtype, epoch):
    for record in records:
        if isinstance(record, dict) and record.get("type") == rtype \
                and record.get("epoch") == epoch:
            return record
    return None


def verify_absence(bundle, epoch, scope, observer_pub, now=None):
    """Verify an absence claim offline from the bundle alone.

    Returns True. Refuses with the named vocabulary on any failure;
    in particular a disclosure cell refuses
    ``absence-disclosure-recorded`` and a backdated claim refuses
    ``absence-backdated``. ``now`` is accepted for API symmetry and
    ignored: verification is over the closed epoch, not the clock.
    """
    _check_epoch_int(epoch)
    if not isinstance(bundle, dict):
        raise AbsenceEpochError(MALFORMED, "bundle must be a dict")
    if not isinstance(observer_pub, str):
        raise AbsenceEpochError(MALFORMED, "observer_pub must be hex")

    beacon = _find(bundle.get("beacons", []), "absence-epoch-beacon", epoch)
    if beacon is None:
        raise AbsenceEpochError(NOT_OPEN, "no beacon for epoch %d" % epoch)
    _verify_record(beacon, beacon["beacon_pub"], BEACON_UNSIGNED)

    close = _find(bundle.get("closes", []), "absence-epoch-close", epoch)
    if close is None:
        raise AbsenceEpochError(
            NOT_CLOSED,
            "epoch %d has no close record; unclosed epochs verify nothing"
            % epoch)
    if close.get("beacon_pub") != beacon.get("beacon_pub"):
        raise AbsenceEpochError(
            BEACON_UNSIGNED,
            "close is not signed by the epoch beacon key")
    _verify_record(close, close["beacon_pub"], BEACON_UNSIGNED)

    ledgers = bundle.get("ledgers")
    if not isinstance(ledgers, dict):
        raise AbsenceEpochError(MALFORMED, "bundle ledgers malformed")
    ledger = ledgers.get(str(epoch))
    if not isinstance(ledger, dict):
        raise AbsenceEpochError(NOT_OBSERVED,
                                "no ledger for epoch %d" % epoch)
    claim = ledger.get(scope)
    if claim is None:
        raise AbsenceEpochError(
            NOT_OBSERVED,
            "no observation for scope %r in epoch %d" % (scope, epoch))
    if not isinstance(claim, dict):
        raise AbsenceEpochError(MALFORMED, "ledger cell malformed")
    if claim.get("type") == "absence-disclosure":
        raise AbsenceEpochError(
            DISCLOSURE_RECORDED,
            "a disclosure is recorded for scope %r in epoch %d; "
            "an absence claim for this cell is forged" % (scope, epoch))
    if claim.get("type") != "absence-observation":
        raise AbsenceEpochError(NOT_OBSERVED,
                                "cell is not an absence observation")

    _verify_record(claim, observer_pub, OBSERVATION_UNSIGNED)
    if claim.get("observer_pub") != observer_pub:
        raise AbsenceEpochError(
            OBSERVATION_UNSIGNED,
            "observation names a different observer")
    beacon_digest = _digest_hex(
        {k: v for k, v in beacon.items() if k != "sig"})
    if claim.get("beacon_digest") != beacon_digest:
        raise AbsenceEpochError(
            OBSERVATION_UNSIGNED,
            "observation is not bound to this epoch's beacon")

    start = epoch * EPOCH_SECONDS
    observed_at = claim.get("observed_at")
    closed_at = close.get("closed_at")
    if not isinstance(observed_at, (int, float)) or isinstance(
            observed_at, bool) or not (start <= observed_at <= closed_at):
        raise AbsenceEpochError(
            BACKDATED,
            "observed_at %r is outside the closed epoch window "
            "[%d, %r]" % (observed_at, start, closed_at))

    pairs = []
    for cell_scope, cell in ledger.items():
        if not isinstance(cell, dict):
            raise AbsenceEpochError(MALFORMED, "ledger cell malformed")
        pairs.append((_cell_key(epoch, cell_scope),
                      bytes.fromhex(_digest_hex(cell))))
    recomputed = smt_root(pairs).hex()
    if recomputed != close.get("root"):
        raise AbsenceEpochError(
            ROOT_MISMATCH,
            "ledger does not recompute to the closed root")
    return True


__all__ = [
    "EPOCH_SECONDS",
    "AbsenceEpochError",
    "BEACON_UNSIGNED",
    "NOT_OPEN",
    "NOT_CLOSED",
    "EPOCH_CLOSED",
    "MALFORMED",
    "BACKDATED",
    "ROOT_MISMATCH",
    "DISCLOSURE_RECORDED",
    "NOT_OBSERVED",
    "OBSERVATION_UNSIGNED",
    "epoch_of",
    "pub_of",
    "open_epoch",
    "observe_absence",
    "resign_observation",
    "record_disclosure",
    "close_epoch",
    "smt_root",
    "make_bundle",
    "verify_absence",
]
