"""Delegation revocation propagation (power-of-attorney pattern).

Mechanism lineage: wave-298 prospecting, delegation & authority-transfer
governance -- the power-of-attorney rule (revocation binds ALL downstream
copies; a revoked grant is void everywhere, not just at the issuer),
cap'n Proto attenuation discipline, and Kerberos-style epoch semantics.
Mechanisms only; stdlib only.

A delegator issues signed, chained, attenuated receipts. THIS module
answers "what happens when authority is taken back":

* **Delegation epochs:** every receipt carries ``epoch`` (monotonic per
  delegator). A revocation names ``(target_receipt_id, target_epoch)``
  and is itself a signed record.
* **Revocation propagation:** revoking receipt R invalidates R AND every
  receipt descended from R. ``is_live`` walks the whole presented chain
  and refuses coded ``delegation-revoked`` if ANY ancestor-or-self is
  revoked -- the descendant is dead because its ancestor is dead, so
  checking each chain member's own id suffices.
* **Monotonic revocation:** there is no un-revoke. Re-delegation after
  a revocation requires a NEW receipt (a new ``receipt_id``); the
  revoked id is never resurrected. This module exposes no rescind /
  unrevoke / remove API at all (``AttributeError``, not a coded
  refusal -- the operation does not exist).
* **Revocation list:** append-only, bounded (4096 entries per
  delegator; overflow refuses loud ``delegation-revocation-list-full``),
  every entry signed, list digest chained -- independently verifiable
  offline with ``verify_list``.
* **Revocation beats expiry:** a revoked-but-unexpired receipt refuses
  ``delegation-revoked``, never ``delegation-expired``; the revocation
  check runs before the expiry check in ``is_live``.

This module is a DECISION layer (like ``gov/supervision.py`` and
``gov/coordination_lease.py``): ``is_live`` returns the live leaf id
or raises a coded ``RevocationError`` (the F351 contract -- every
refusal is coded). The actual enforcement (refusing the delegated
action) is deployment-owned. In-memory per verifier (wave-292 decay
precedent): two verifiers do not share revocation state.

Receipt-shape contract (defined LOCALLY -- lane 2 of wave-299 builds
``gov/delegation.py`` in parallel; the merge seam is documented in
REPORT.md and in this module's ``MERGE_SEAM`` note below)::

    delegation-receipt/v1 =
      {schema, receipt_id, delegator_id, delegate_id,
       parent_receipt_id, epoch, capabilities, not_before,
       not_after, signature}

``receipt_id`` is sha256 of the canonical unsigned body;
``signature`` is the delegator's ed25519 signature over the same
canonical body. ``parent_receipt_id`` is None for roots.

Composition points (documented here; this lane is self-contained and
changes no existing API):

* ``gov/delegation.py`` (wave-299 lane 2): the CANONICAL native receipt
  issuer. Its receipts are the authority records; this module's local
  ``delegation-receipt/v1`` shape is retained for standalone use and
  tests. Composition (wired at the wave-299 merge):
  ``DelegationRevoker.revoke`` accepts any 64-hex ``receipt_id`` --
  including native ``gov/delegation.py`` receipt ids -- and
  ``assert_live_native`` composes native chain verification
  (``gov.delegation.verify_chain``) with this list's revocation check.
* ``gov/coordination_lease.py``: when a lease grant is issued as a
  delegation receipt (the receipt binds the fencing token), revoking
  the grant kills the token's authority. The wiring point is
  ``check_write``: it should call ``is_live([receipt], revocations,
  at)`` and map a ``delegation-revoked`` refusal onto
  ``coord-lease-fencing``. The merge coordinator wires this; lease
  semantics are NOT changed by this lane.

THREAT MODEL:

* The delegator key is the trust anchor (signs revocations). A
  compromised delegator key can revoke arbitrarily -- including
  revoking legitimate receipts (denial of authority) -- the
  compromised-host class; the revocation record proves WHAT was
  revoked, by the key, and when.
* ``revoked_at`` / ``at`` are freshness markers, not a clock. Callers
  pass explicit instants; this module orders events, it does not run
  a clock.
* The revocation list is per-verifier; a presenter can withhold a
  revocation list, but a verifier that demands the list and finds the
  receipt revoked refuses -- list distribution is deployment-owned.
"""

import hashlib
import json
from collections.abc import Mapping

from gov import ed25519

# ---------------------------------------------------------------------------
# Codes (F351: every refusal carries one). Three are minted by this lane;
# two pre-existing codes are reused so the taxonomy pin moves only by 3.
# ---------------------------------------------------------------------------

RV_REVOKED = "delegation-revoked"
RV_INVALID = "delegation-revocation-invalid"
RV_LIST_FULL = "delegation-revocation-list-full"
SIG_INVALID = "delegation-signature-invalid"  # reused, pre-existing
EXP = "delegation-expired"  # reused, pre-existing

SCHEMA_RECEIPT = "delegation-receipt/v1"
SCHEMA_REVOCATION = "delegation-revocation/v1"

MAX_REVOCATIONS = 4096

_RECEIPT_UNSIGNED_FIELDS = (
    "schema", "delegator_id", "delegate_id",
    "parent_receipt_id", "epoch", "capabilities", "not_before",
    "not_after",
)
# receipt_id is the digest of exactly these fields; the signature covers
# the same set. Neither covers itself.
_REVOCATION_UNSIGNED_FIELDS = (
    "schema", "delegator_id", "target_receipt_id",
    "target_epoch", "revoked_at",
)


class RevocationError(Exception):
    """Base class; carries the machine ``code`` so every refusal is
    coded -- the F351 contract."""

    code = RV_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise RevocationError(detail, code=code)


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _shahex(data):
    return hashlib.sha256(data).hexdigest()


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# The sink never breaks the module (F345-class).
# ---------------------------------------------------------------------------

_sink = None


def set_sink(fn):
    """Install an audit-sink callable; ``None`` clears it."""
    global _sink
    _sink = fn


def _emit(event):
    if _sink is None:
        return
    try:
        _sink(dict(event))
    except Exception:  # noqa: BLE001 -- the sink must never break us
        pass


class DelegationRevoker:
    """Holds one delegator's key and its append-only revocation list."""

    def __init__(self, seed, delegator_id):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            _fail(RV_INVALID, "delegator seed must be 32 bytes")
        if not isinstance(delegator_id, str) or not delegator_id:
            _fail(RV_INVALID, "delegator_id must be a non-empty string")
        self._seed = bytes(seed)
        self._pub = ed25519.publickey(self._seed)
        self.delegator_id = delegator_id
        self._revocations = []  # append-only, in-memory per verifier
        self._by_id = {}
        self._by_target = {}

    # -- introspection ----------------------------------------------------

    @property
    def pubkey_hex(self):
        return self._pub.hex()

    def __len__(self):
        return len(self._revocations)

    # -- revocation issuance ----------------------------------------------

    def revoke(self, target_receipt_id, at, target_epoch=0):
        """Issue a signed revocation for ``target_receipt_id``.

        Idempotent: revoking an already-revoked receipt returns the
        existing record (no error, no duplicate entry).
        """
        if not _is_hex64(target_receipt_id):
            _fail(RV_INVALID, "target_receipt_id must be 64 lowercase hex")
        if not isinstance(at, int) or at < 0:
            _fail(RV_INVALID, "revoked_at must be a non-negative int")
        if not isinstance(target_epoch, int) or target_epoch < 0:
            _fail(RV_INVALID, "target_epoch must be a non-negative int")
        existing = self._by_target.get(target_receipt_id)
        if existing is not None:
            return dict(existing)
        if len(self._revocations) >= MAX_REVOCATIONS:
            _fail(RV_LIST_FULL,
                  "revocation list full (%d entries)" % MAX_REVOCATIONS)
        if self._revocations and at < self._revocations[-1]["revoked_at"]:
            _fail(RV_INVALID,
                  "revoked_at moves backwards: list is append-only")
        body = {
            "schema": SCHEMA_REVOCATION,
            "delegator_id": self.delegator_id,
            "target_receipt_id": target_receipt_id,
            "target_epoch": target_epoch,
            "revoked_at": at,
        }
        body["revocation_id"] = _shahex(_canon(body))
        sig = ed25519.sign(self._seed, _canon(
            {k: body[k] for k in _REVOCATION_UNSIGNED_FIELDS}))
        record = dict(body)
        record["signature"] = sig.hex()
        self._append_validated(record)
        _emit({"event": "revocation-issued",
               "revocation_id": record["revocation_id"],
               "target_receipt_id": target_receipt_id,
               "delegator_id": self.delegator_id})
        return dict(record)

    def revoke_epoch(self, epoch, receipt_ids, at):
        """Revoke every receipt id in ``receipt_ids`` at ``epoch``.

        Epoch-wide revocation: the caller names the receipts (this
        module is a decision layer; receipt storage is deployment- or
        lane-2-owned).
        """
        if not isinstance(epoch, int) or epoch < 0:
            _fail(RV_INVALID, "epoch must be a non-negative int")
        ids = list(receipt_ids)
        if not ids or not all(_is_hex64(i) for i in ids):
            _fail(RV_INVALID, "receipt_ids must be a non-empty list of "
                              "64 lowercase hex ids")
        return [self.revoke(rid, at, target_epoch=epoch) for rid in ids]

    def _append_validated(self, record):
        self._verify_record_shape(record)
        if ed25519.verify(self._pub, _canon(
                {k: record[k] for k in _REVOCATION_UNSIGNED_FIELDS}),
                bytes.fromhex(record["signature"])) is not True:
            _fail(SIG_INVALID, "revocation signature does not verify")
        if record["revocation_id"] in self._by_id:
            return  # idempotent re-append
        self._revocations.append(dict(record))
        self._by_id[record["revocation_id"]] = record
        self._by_target.setdefault(record["target_receipt_id"], record)

    # -- offline verification ---------------------------------------------

    @staticmethod
    def _verify_record_shape(record):
        if not isinstance(record, dict):
            _fail(RV_INVALID, "revocation record must be a dict")
        for field in _REVOCATION_UNSIGNED_FIELDS:
            if field not in record:
                _fail(RV_INVALID, "revocation record missing %r" % field)
        if record.get("schema") != SCHEMA_REVOCATION:
            _fail(RV_INVALID, "unexpected revocation schema")
        if not isinstance(record.get("delegator_id"), str) \
                or not record["delegator_id"]:
            _fail(RV_INVALID, "delegator_id must be a non-empty string")
        if not _is_hex64(record.get("target_receipt_id")):
            _fail(RV_INVALID, "target_receipt_id must be 64 lowercase hex")
        if not _is_hex64(record.get("revocation_id")):
            _fail(RV_INVALID, "revocation_id must be 64 lowercase hex")
        if not isinstance(record.get("target_epoch"), int) \
                or record["target_epoch"] < 0:
            _fail(RV_INVALID, "target_epoch must be a non-negative int")
        if not isinstance(record.get("revoked_at"), int) \
                or record["revoked_at"] < 0:
            _fail(RV_INVALID, "revoked_at must be a non-negative int")
        if not isinstance(record.get("signature"), str):
            _fail(RV_INVALID, "signature must be a hex string")
        expect = _shahex(_canon(
            {k: record[k] for k in _REVOCATION_UNSIGNED_FIELDS}))
        if record["revocation_id"] != expect:
            _fail(RV_INVALID, "revocation_id does not match body digest")

    def verify_revocation(self, record, pubkey_hex=None):
        """Verify one revocation record offline; raises coded on any
        defect, returns True when valid."""
        self._verify_record_shape(record)
        pub = bytes.fromhex(pubkey_hex) if pubkey_hex else self._pub
        try:
            pub_b = bytes(pub)
        except (ValueError, TypeError):
            _fail(RV_INVALID, "pubkey_hex is not valid hex")
        if ed25519.verify(pub_b, _canon(
                {k: record[k] for k in _REVOCATION_UNSIGNED_FIELDS}),
                bytes.fromhex(record["signature"])) is not True:
            _fail(SIG_INVALID, "revocation signature does not verify")
        return True

    def verify_list(self, records=None, pubkey_hex=None):
        """Verify a whole revocation list offline: every entry valid,
        ids unique, ``revoked_at`` non-decreasing (append-only order)."""
        recs = self.export_list() if records is None else list(records)
        seen = set()
        last_at = -1
        for record in recs:
            self.verify_revocation(record, pubkey_hex=pubkey_hex)
            if record["revocation_id"] in seen:
                _fail(RV_INVALID, "duplicate revocation_id in list")
            seen.add(record["revocation_id"])
            if record["revoked_at"] < last_at:
                _fail(RV_INVALID, "revocation list is not append-ordered")
            last_at = record["revoked_at"]
        return True

    def list_digest(self):
        """Chained digest over the revocation ids (empty list digests
        the empty string)."""
        h = hashlib.sha256()
        for record in self._revocations:
            h.update(record["revocation_id"].encode("ascii"))
        return h.hexdigest()

    def export_list(self):
        return [dict(r) for r in self._revocations]

    def revoked_targets(self):
        return sorted(self._by_target.keys())

    # -- liveness ----------------------------------------------------------

    @staticmethod
    def _check_receipt_shape(receipt):
        if not isinstance(receipt, dict):
            _fail(RV_INVALID, "receipt must be a dict")
        for field in _RECEIPT_UNSIGNED_FIELDS:
            if field not in receipt:
                _fail(RV_INVALID, "receipt missing %r" % field)
        if receipt.get("schema") != SCHEMA_RECEIPT:
            _fail(RV_INVALID, "unexpected receipt schema")
        if not _is_hex64(receipt.get("receipt_id")):
            _fail(RV_INVALID, "receipt_id must be 64 lowercase hex")
        if not isinstance(receipt.get("delegator_id"), str) \
                or not receipt["delegator_id"]:
            _fail(RV_INVALID, "delegator_id must be a non-empty string")
        if not isinstance(receipt.get("delegate_id"), str) \
                or not receipt["delegate_id"]:
            _fail(RV_INVALID, "delegate_id must be a non-empty string")
        parent = receipt.get("parent_receipt_id")
        if parent is not None and not _is_hex64(parent):
            _fail(RV_INVALID, "parent_receipt_id must be 64 hex or None")
        if not isinstance(receipt.get("epoch"), int) or receipt["epoch"] < 0:
            _fail(RV_INVALID, "epoch must be a non-negative int")
        caps = receipt.get("capabilities")
        if not isinstance(caps, list) or not caps \
                or not all(isinstance(c, str) and c for c in caps):
            _fail(RV_INVALID, "capabilities must be a non-empty string list")
        for bound in ("not_before", "not_after"):
            if not isinstance(receipt.get(bound), int) or receipt[bound] < 0:
                _fail(RV_INVALID, "%s must be a non-negative int" % bound)
        if receipt["not_after"] <= receipt["not_before"]:
            _fail(RV_INVALID, "not_after must exceed not_before")
        if not isinstance(receipt.get("signature"), str):
            _fail(RV_INVALID, "signature must be a hex string")
        expect = _shahex(_canon(
            {k: receipt[k] for k in _RECEIPT_UNSIGNED_FIELDS}))
        if receipt["receipt_id"] != expect:
            _fail(RV_INVALID, "receipt_id does not match body digest")

    def is_live(self, chain, at, keyring):
        """Decide whether a delegation chain is live at instant ``at``.

        ``chain`` is root-first [root, ..., leaf]. ``keyring`` maps
        delegator_id -> ed25519 pubkey hex. Returns the leaf
        ``receipt_id`` when live; raises coded otherwise. Refusal
        order: shape -> signature -> revocation -> expiry, so a
        revoked-but-unexpired receipt refuses ``delegation-revoked``
        (revocation beats expiry).
        """
        if not isinstance(chain, list) or not chain:
            _fail(RV_INVALID, "chain must be a non-empty list")
        if not isinstance(at, int) or at < 0:
            _fail(RV_INVALID, "at must be a non-negative int")
        if not isinstance(keyring, dict):
            _fail(RV_INVALID, "keyring must be a dict")
        for i, receipt in enumerate(chain):
            self._check_receipt_shape(receipt)
            if i == 0:
                if receipt["parent_receipt_id"] is not None:
                    _fail(RV_INVALID, "root receipt must have no parent")
            elif receipt["parent_receipt_id"] != chain[i - 1]["receipt_id"]:
                _fail(RV_INVALID, "chain linkage broken at hop %d" % i)
            pub_hex = keyring.get(receipt["delegator_id"])
            if not isinstance(pub_hex, str):
                _fail(RV_INVALID, "no key for delegator %r"
                                 % receipt["delegator_id"])
            try:
                pub = bytes.fromhex(pub_hex)
            except (ValueError, TypeError):
                _fail(RV_INVALID, "keyring pubkey is not valid hex")
            try:
                sig = bytes.fromhex(receipt["signature"])
            except (ValueError, TypeError):
                _fail(SIG_INVALID, "receipt signature is not valid hex")
            if ed25519.verify(pub, _canon(
                    {k: receipt[k] for k in _RECEIPT_UNSIGNED_FIELDS}),
                    sig) is not True:
                _fail(SIG_INVALID, "receipt signature does not verify")
            # Revocation BEFORE expiry: revocation beats expiry.
            if receipt["receipt_id"] in self._by_target:
                _fail(RV_REVOKED,
                      "receipt %s revoked by %s"
                      % (receipt["receipt_id"][:16],
                         receipt["delegator_id"]))
            if not (receipt["not_before"] <= at < receipt["not_after"]):
                _fail(EXP, "receipt %s outside its validity window"
                           % receipt["receipt_id"][:16])
        leaf = chain[-1]["receipt_id"]
        _emit({"event": "chain-live", "leaf": leaf,
               "hops": len(chain), "at": at})
        return leaf

    def assert_live_native(self, chain, at, trust_roots):
        """Decide liveness for a ``gov/delegation.py`` NATIVE receipt chain.

        ``chain`` is root-first [root, ..., leaf] of native receipts as
        issued by ``gov/delegation.issue``. ``trust_roots`` are the
        accepted root delegator pubkeys (hex), as for
        ``gov.delegation.verify_chain``. Returns the leaf
        ``receipt_id`` when live.

        Refusal order: revocation -> chain verification. A revoked
        receipt refuses ``delegation-revoked`` even if its chain would
        otherwise verify (revocation beats expiry, same as ``is_live``);
        any chain defect refuses with ``gov/delegation.py``'s own coded
        error (signature, linkage, rights-narrowing, expiry).

        ``revoke`` targets 64-hex receipt ids and is shape-agnostic, so
        revoking a native receipt id and then presenting its chain here
        refuses ``delegation-revoked`` -- including every DESCENDANT of
        the revoked receipt, since each chain member's own id is
        checked.
        """
        if not isinstance(chain, list) or not chain:
            _fail(RV_INVALID, "chain must be a non-empty list")
        if not isinstance(at, int) or at < 0:
            _fail(RV_INVALID, "at must be a non-negative int")
        # Revocation BEFORE chain verification: revocation beats expiry.
        # (Native receipts are frozen MappingProxyTypes, not dicts.)
        for receipt in chain:
            rid = receipt.get("receipt_id") \
                if isinstance(receipt, Mapping) else None
            if not _is_hex64(rid):
                _fail(RV_INVALID,
                      "chain member has no 64-hex receipt_id")
            if rid in self._by_target:
                _fail(RV_REVOKED,
                      "native receipt %s revoked" % rid[:16])
        from gov import delegation as _dg  # lazy: delegation never imports this module
        _dg.verify_chain(chain[-1], chain, at=at, trust_roots=trust_roots)
        leaf = chain[-1]["receipt_id"]
        _emit({"event": "chain-live-native", "leaf": leaf,
               "hops": len(chain), "at": at})
        return leaf


def make_receipt(seed, delegator_id, delegate_id, parent_receipt_id,
                 epoch, capabilities, not_before, not_after):
    """Test/issuance helper: build and sign a receipt-shaped dict.

    (Lane 2's ``gov/delegation.py`` is the native issuer; this helper
    exists so revocation can be exercised and tested without it.)
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        _fail(RV_INVALID, "seed must be 32 bytes")
    unsigned = {
        "schema": SCHEMA_RECEIPT,
        "delegator_id": delegator_id,
        "delegate_id": delegate_id,
        "parent_receipt_id": parent_receipt_id,
        "epoch": epoch,
        "capabilities": list(capabilities),
        "not_before": not_before,
        "not_after": not_after,
    }
    receipt_id = _shahex(_canon(unsigned))
    sig = ed25519.sign(bytes(seed), _canon(unsigned))
    receipt = dict(unsigned)
    receipt["receipt_id"] = receipt_id
    receipt["signature"] = sig.hex()
    DelegationRevoker._check_receipt_shape(receipt)
    return receipt
