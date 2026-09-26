"""Anchor adapter interface (H24): the v2 seam for transparency-log anchoring.

The interface is ``anchor(bundle) -> receipt``:

* ``bundle``: an evidence-bundle dict (as produced by ``gov.evidence_bundle``).
* ``receipt``: a dict proving the bundle was committed to a transparency log.
  The receipt is self-describing (``adapter`` names the implementation) so an
  auditor can select the right verifier.

Two implementations ship:

* ``FakeLogAdapter``: in-process deterministic test double (same role as
  ``FakeTransparencyLog`` in ``gov/anchor.py`` and ``FakeKmsProvider``).
  Proves the adapter FORMAT and the verification PATH, not a remote service.
* ``RekorStubAdapter``: Rekor-shaped, backed by an offline mock transport.
  The ``proposedEntry`` / ``verification`` shapes mirror Rekor's
  ``/api/v1/log/entries`` API; the transport is injectable so the conformance
  battery exercises it with zero network.

A production Rekor adapter implements this same interface against the live
Rekor API. Nothing here performs network I/O. Live anchoring is a v2
decision (spec section 7.4); this module is the seam that makes v2 cheap.
"""

import hashlib
import json

from . import ed25519 as _ed
from . import merkle as _merkle

STATEMENT_VERSION = 1
_STATEMENT_DOMAIN = b"gov-bundle-anchor/v1\x00"
_FAKE_SET_DOMAIN = b"gov-fake-anchor-set/v1\x00"


class AnchorAdapter:
    """Transparency-log anchor adapter.

    ``anchor(bundle)`` submits the bundle and returns a receipt dict.
    ``verify_receipt(receipt, bundle)`` returns ``(ok, error)``; it never
    raises on malformed input.
    """

    name = "base"

    def anchor(self, bundle):
        """Anchor ``bundle``; return a receipt dict. Raises ValueError on a
        malformed bundle; raises AnchorError (or a subclass) on log refusal."""
        raise NotImplementedError

    def verify_receipt(self, receipt, bundle):
        """Return ``(True, None)`` if ``receipt`` proves ``bundle`` was
        committed, else ``(False, reason)``. Never raises."""
        raise NotImplementedError


class AnchorError(Exception):
    """The transparency log refused the submission (not a malformed bundle)."""


class EquivocationError(AnchorError):
    """A conflicting bundle was submitted for an already-anchored id."""


def bundle_statement(bundle):
    """Canonical anchor statement for a bundle: its content hash.

    The statement is deliberately minimal -- the log commits to the hash,
    and the bundle itself travels with the receipt for audit. Raises
    ValueError on a non-dict bundle.
    """
    if not isinstance(bundle, dict):
        raise ValueError("bundle must be a dict")
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, default=str).encode("utf-8")
    return {
        "statement_version": STATEMENT_VERSION,
        "bundle_hash": hashlib.sha256(
            _STATEMENT_DOMAIN + canonical).hexdigest(),
    }


def _statement_hash(statement):
    return hashlib.sha256(
        _STATEMENT_DOMAIN
        + json.dumps(statement, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("utf-8")).hexdigest()


class FakeLogAdapter(AnchorAdapter):
    """In-process deterministic transparency log -- TEST DOUBLE.

    Owns an Ed25519 key and an append-only Merkle tree over statement
    hashes. ``anchor`` is idempotent on the identical bundle (returns the
    original receipt); anchoring a DIFFERENT bundle under an explicitly
    supplied ``bundle_id`` that is already anchored is equivocation and
    raises ``EquivocationError``.

    This is NOT a network service and MUST NOT be mistaken for one.
    """

    name = "fake-log"

    def __init__(self, seed):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self._seed = bytes(seed)
        self._pub = _ed.publickey(self._seed)
        self._leaves = []
        self._receipts = []
        self._by_id = {}

    @property
    def public_key(self):
        return self._pub

    @property
    def log_id(self):
        return hashlib.sha256(self._pub).hexdigest()

    def _set_body(self, log_index, log_root_hex, stmt_hash):
        return (_FAKE_SET_DOMAIN
                + ("%d|%s|%s" % (log_index, log_root_hex,
                                 stmt_hash)).encode("utf-8"))

    def anchor(self, bundle):
        statement = bundle_statement(bundle)  # ValueError on malformed
        bundle_id = bundle.get("bundle_id")
        stmt_hash = _statement_hash(statement)
        if bundle_id is not None and bundle_id in self._by_id:
            first = self._by_id[bundle_id]
            if first["statement"] == statement:
                return first["receipt"]
            raise EquivocationError(
                "conflicting bundle already anchored for bundle_id %r"
                % (bundle_id,))
        log_index = len(self._receipts)
        self._leaves.append(bytes.fromhex(stmt_hash))
        proof = _merkle.inclusion_proof(self._leaves, log_index)
        root_hex = _merkle.tree_root(self._leaves).hex()
        sig = _ed.sign(
            self._seed, self._set_body(log_index, root_hex,
                                       stmt_hash)).hex()
        receipt = {
            "adapter": self.name,
            "log_id": self.log_id,
            "statement": statement,
            "statement_hash": stmt_hash,
            "log_index": log_index,
            "tree_size": log_index + 1,
            "inclusion_proof": [p.hex() for p in proof],
            "log_root": root_hex,
            "log_sig": sig,
        }
        self._receipts.append(receipt)
        if bundle_id is not None:
            self._by_id[bundle_id] = {"statement": statement,
                                      "receipt": receipt}
        return receipt

    def verify_receipt(self, receipt, bundle):
        try:
            if not isinstance(receipt, dict):
                return False, "receipt is not an object"
            if receipt.get("adapter") != self.name:
                return False, "receipt is for a different adapter"
            if receipt.get("log_id") != self.log_id:
                return False, "receipt is from a different log"
            statement = bundle_statement(bundle)
            if receipt.get("statement") != statement:
                return False, "receipt statement does not match bundle"
            stmt_hash = _statement_hash(statement)
            if receipt.get("statement_hash") != stmt_hash:
                return False, "statement_hash mismatch"
            proof = [bytes.fromhex(p)
                     for p in receipt["inclusion_proof"]]
            root = bytes.fromhex(receipt["log_root"])
            if not _merkle.verify_inclusion(
                    bytes.fromhex(stmt_hash), receipt["log_index"],
                    proof, root, receipt["tree_size"]):
                return False, "inclusion proof does not verify"
            sig = bytes.fromhex(receipt["log_sig"])
            body = self._set_body(receipt["log_index"],
                                  receipt["log_root"], stmt_hash)
            if not _ed.verify(self._pub, body, sig):
                return False, "log signature invalid"
            return True, None
        except (KeyError, TypeError, ValueError) as e:
            return False, "malformed receipt: %s" % (e,)


class RekorStubAdapter(AnchorAdapter):
    """Rekor-shaped anchor adapter over an offline mock transport.

    The request shape mirrors Rekor ``POST /api/v1/log/entries`` (a
    ``proposedEntry`` with ``kind``/``apiVersion``/``spec``); the receipt
    mirrors Rekor's ``verification`` block (``signedEntryTimestamp``,
    ``inclusionProof`` with ``logIndex``/``hashes``/``rootHash``/
    ``treeSize``). The transport is any callable
    ``transport(proposed_entry) -> rekor_response``; the conformance
    battery supplies an in-process mock. No network is performed here.
    """

    name = "rekor-stub"

    def __init__(self, transport):
        if not callable(transport):
            raise ValueError("transport must be callable")
        self._transport = transport

    def _proposed_entry(self, statement):
        return {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "data": {"hash": {"algorithm": "sha256",
                                  "value": statement["bundle_hash"]}},
                "signature": {"format": "x509",
                              "publicKey": {"content": ""}},
            },
        }

    def anchor(self, bundle):
        statement = bundle_statement(bundle)  # ValueError on malformed
        proposed = self._proposed_entry(statement)
        try:
            resp = self._transport(proposed)
        except Exception as e:
            raise AnchorError("transport failed: %s" % (e,))
        if not isinstance(resp, dict):
            raise AnchorError("transport returned a non-dict response")
        verification = resp.get("verification")
        if not isinstance(verification, dict):
            raise AnchorError("transport response has no verification block")
        return {
            "adapter": self.name,
            "statement": statement,
            "proposed_entry": proposed,
            "verification": verification,
        }

    def verify_receipt(self, receipt, bundle):
        try:
            if not isinstance(receipt, dict):
                return False, "receipt is not an object"
            if receipt.get("adapter") != self.name:
                return False, "receipt is for a different adapter"
            statement = bundle_statement(bundle)
            if receipt.get("statement") != statement:
                return False, "receipt statement does not match bundle"
            verification = receipt.get("verification")
            if not isinstance(verification, dict):
                return False, "receipt has no verification block"
            proof = verification.get("inclusionProof")
            if not isinstance(proof, dict):
                return False, "receipt has no inclusionProof"
            # The stub trusts the mock transport's proof shape; a live
            # Rekor adapter would verify the SET signature and the
            # inclusion proof against Rekor's public key here.
            for field in ("logIndex", "rootHash", "treeSize", "hashes"):
                if field not in proof:
                    return False, (
                        "inclusionProof missing %r" % (field,))
            if "signedEntryTimestamp" not in verification:
                return False, "receipt has no signedEntryTimestamp"
            return True, None
        except (KeyError, TypeError, ValueError) as e:
            return False, "malformed receipt: %s" % (e,)


def mock_rekor_transport():
    """Offline mock Rekor transport for tests: deterministic, no network.

    Returns a ``transport`` callable plus the mock's public state, so tests
    can assert the proposed entry was well-formed.
    """
    entries = []

    def transport(proposed_entry):
        idx = len(entries)
        entries.append(proposed_entry)
        spec_hash = proposed_entry["spec"]["data"]["hash"]["value"]
        return {
            "logIndex": idx,
            "verification": {
                "signedEntryTimestamp": "mock-set-%d" % idx,
                "inclusionProof": {
                    "logIndex": idx,
                    "rootHash": hashlib.sha256(
                        ("mock-root-%d|" % idx).encode()
                        + spec_hash.encode()).hexdigest(),
                    "treeSize": idx + 1,
                    "hashes": ["mock-hash-%d" % idx],
                },
            },
        }

    transport.entries = entries
    return transport
