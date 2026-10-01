"""Sybil-resistant peer identity attestation (wave-267 lane).

An ADAPT of SPIFFE/SPIRE's node-attestation patterns (pattern only --
no SPIRE code or spec text is read, copied, imported, or vendored).
The recombination target: ``gov/trust_federation.py`` covers
cross-trust-domain bundle trust (endpoint pinning, SVID verification)
but says nothing about the *strength* of a peer's identity claims;
attested peer identity is deployment-vouched with no Sybil
resistance. This module adds the six adapted primitives:

* **Tiered claim classes** (:data:`CLAIM_ANCHOR_SIGNED` /
  :data:`CLAIM_SELF_ASSERTABLE`): claims backed by signature-verified
  evidence vs claims from operator-writable state (tags, labels, role
  attachments -- the Unit42 2026-09 selector-spoofing classes).
  Self-assertable claim keys are **default-deny**: only keys on the
  deployment's ``allowlisted_claim_keys`` are honored (the SPIRE
  ``AllowedLabelKeys`` pattern); everything else refuses
  ``federation-claim-class-denied``. Anchor-signed claims require a
  valid signature under the peer's bound anchor key.
* **TOFU + loud double-join**: the first registration binds a peer id
  to its anchor key. A second registration for an already-bound peer
  id -- or a different peer id reusing a bound anchor key -- refuses
  ``federation-double-join`` AND journals a LOUD
  ``peer-double-join-incident`` to the hash-chained durable journal
  (SPIRE's contract: both sides log the double-join as a security
  incident). Rotation is explicit: ``remove_peer`` unbinds, then a
  fresh registration succeeds. Bindings, identity mappings, and bans
  are rebuilt from the journal on ``__init__`` (F251): the TOFU
  guarantee survives restarts, not just the process lifetime.
* **Centrally-authored identity mapping**: the deployment authors
  which identities each anchor-bound peer may claim
  (:meth:`PeerAttestationTable.author_identity`). Attestation
  *selects* from that mapping; a peer presenting a valid anchor and
  possession proof for an identity it was never mapped to gets
  ``federation-identity-unmapped``. Agents never mint their own
  identities.
* **Per-peer ban** (:meth:`PeerAttestationTable.ban_peer`): a banned
  peer refuses ``federation-peer-banned`` on registration,
  challenge, and attestation. Bans survive pruning (SPIRE: banned
  nodes are excluded from pruning).
* **Challenge-response possession proofs**: the server issues a
  32-byte nonce; the peer signs
  ``b"sasanam-peer-possession/v1:" || nonce || peer_id`` under the
  anchor key. Bearer presentation is never accepted -- a garbage or
  wrong-key signature refuses ``federation-possession-failed``.
  Challenges are single-use (consumed on success AND on failure);
  a response for an old challenge never verifies against a new one
  (anti-replay binding).
* **Pinned cross-domain bundle endpoints**: a foreign-domain identity
  is admitted only through a declared relationship in the caller's
  ``trust_federation.FederationTable`` whose bundle endpoint EXACTLY
  matches the presented endpoint URL. No relationship refuses the
  existing ``federation-untrusted-domain``; a substituted endpoint
  refuses ``federation-endpoint-unpinned``. There is no
  auto-discovery of peer domains.

Composition (never duplication):

* Clock handling reuses ``gov.svid_issuer._validate_now`` (the F224
  contract: a bad clock is machine-coded, never ``time.time()``
  fallback surprises).
* Cross-domain trust defers to ``gov.trust_federation``'s
  relationship vocabulary; the endpoint transport itself stays
  deployment-supplied.
* Possession proofs use the repo's ``gov.ed25519`` (``verify`` returns
  exact ``True``/``False`` -- checked with ``is True``/``is False``).

Machine codes (domain ``federation``, registered in
``gov/decision_codes.py``):
``federation-attestation-malformed`` /
``federation-claim-class-denied`` / ``federation-double-join`` /
``federation-endpoint-unpinned`` / ``federation-identity-unmapped`` /
``federation-peer-banned`` / ``federation-possession-failed``.
The existing ``federation-untrusted-domain`` is reused for
never-declared foreign domains.

Fail-closed: every refusal is machine-coded; nothing attests on a
partial check.

Honest boundaries
-----------------
* The anchor keys are deployment-provisioned trust material -- this
  module does not solve first-contact trust, exactly like SVID trust
  roots.
* Challenge-response proves *key possession*, not that the key is
  hardware-bound. TPM DevID-grade hardware attestation (the only
  attestor surviving node-root compromise per Unit42) is post-v1.
* Node/host integrity is axiomatic: a claim is only as strong as the
  peer host it was issued from.
* Cross-domain trust is transitive: pinning a foreign bundle trusts
  that domain's attestation policy, same as ``trust_federation``.
* The journal is local/single-node (``durable_journal`` scope);
  incident delivery to a SIEM is deployment-owned.

Stdlib only. Deterministic: injectable clock, no I/O except the
required journal path, no network, no in-repo git subprocesses.
"""

import os
import re

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from . import durable_journal as _durable_journal
from . import ed25519 as _ed25519
from .svid_issuer import _validate_now

__all__ = [
    "PeerAttestationError",
    "PeerAttestationTable",
    "CLAIM_ANCHOR_SIGNED",
    "CLAIM_SELF_ASSERTABLE",
    "CODES",
    "ATTESTATION_MALFORMED_CODE",
    "CLAIM_CLASS_DENIED_CODE",
    "DOUBLE_JOIN_CODE",
    "ENDPOINT_UNPINNED_CODE",
    "IDENTITY_UNMAPPED_CODE",
    "PEER_BANNED_CODE",
    "POSSESSION_FAILED_CODE",
]

#: Tiered claim classes (the SPIRE selector-class partition).
CLAIM_ANCHOR_SIGNED = "anchor_signed"
CLAIM_SELF_ASSERTABLE = "self_assertable"
_CLAIM_CLASSES = frozenset([CLAIM_ANCHOR_SIGNED, CLAIM_SELF_ASSERTABLE])

#: Machine codes (registered in gov/decision_codes.py, domain
#: "federation"). "federation-untrusted-domain" (existing) is reused
#: for never-declared foreign domains.
ATTESTATION_MALFORMED_CODE = "federation-attestation-malformed"
CLAIM_CLASS_DENIED_CODE = "federation-claim-class-denied"
DOUBLE_JOIN_CODE = "federation-double-join"
ENDPOINT_UNPINNED_CODE = "federation-endpoint-unpinned"
IDENTITY_UNMAPPED_CODE = "federation-identity-unmapped"
PEER_BANNED_CODE = "federation-peer-banned"
POSSESSION_FAILED_CODE = "federation-possession-failed"

CODES = (
    ATTESTATION_MALFORMED_CODE,
    CLAIM_CLASS_DENIED_CODE,
    DOUBLE_JOIN_CODE,
    ENDPOINT_UNPINNED_CODE,
    IDENTITY_UNMAPPED_CODE,
    PEER_BANNED_CODE,
    POSSESSION_FAILED_CODE,
)

#: Domain separation for possession proofs and claim evidence.
_POSSESSION_DOMAIN = b"sasanam-peer-possession/v1:"
_CLAIM_DOMAIN = b"sasanam-peer-claim/v1:"

_PEER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_ANCHOR_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.\-_]*[a-z0-9])?$")
_IDENTITY_RE = re.compile(
    r"^spiffe://([a-z0-9](?:[a-z0-9.\-_]*[a-z0-9])?)/(.{1,256})$")
_CLAIM_KEY_RE = re.compile(r"^[A-Za-z0-9:._-]{1,128}$")

_MAX_CLAIM_VALUE_LEN = 1024
_MAX_BAN_REASON_LEN = 512


class PeerAttestationError(Exception):
    """Machine-coded refusal. ``code`` is a decision-code taxonomy key."""

    def __init__(self, code, detail=""):
        super(PeerAttestationError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _malformed(what):
    return PeerAttestationError(ATTESTATION_MALFORMED_CODE, what)


def _check_peer_id(value):
    if not isinstance(value, str) or not _PEER_ID_RE.match(value):
        raise _malformed("bad peer id %r" % (value,))
    return value


def _check_anchor(value):
    if not isinstance(value, str) or not _ANCHOR_RE.match(value):
        raise _malformed("bad anchor public key %r" % (value,))
    return value


def _check_nonce(value):
    if not isinstance(value, str) or not _NONCE_RE.match(value):
        raise _malformed("bad challenge nonce")
    return value


def _check_domain(value):
    if not isinstance(value, str) or not _TRUST_DOMAIN_RE.match(value):
        raise _malformed("bad trust domain %r" % (value,))
    return value


def _check_identity(value):
    if not isinstance(value, str):
        raise _malformed("bad identity (not a string)")
    m = _IDENTITY_RE.match(value)
    if not m:
        raise _malformed("bad identity syntax %r" % (value,))
    return m.group(1), m.group(2)


def _check_claims(peer_id, anchor_pub, claims, allowlisted):
    """Validate claim shapes and class discipline.

    Returns the normalized claim record ``{key: {value, class}}``.
    Refuses machine-coded; never a bare TypeError.
    """
    if claims is None:
        return {}
    if not isinstance(claims, dict):
        raise _malformed("claims must be a dict")
    out = {}
    for key, shape in claims.items():
        if (not isinstance(key, str) or not _CLAIM_KEY_RE.match(key)):
            raise _malformed("bad claim key %r" % (key,))
        if not isinstance(shape, (tuple, list)):
            raise _malformed("bad claim shape for %r" % (key,))
        if len(shape) == 2:
            value, cls = shape
            sig = None
        elif len(shape) == 3:
            value, cls, sig = shape
        else:
            raise _malformed("bad claim shape for %r" % (key,))
        if not isinstance(value, str) or len(value) > _MAX_CLAIM_VALUE_LEN:
            raise _malformed("bad claim value for %r" % (key,))
        if cls not in _CLAIM_CLASSES:
            raise _malformed("unknown claim class %r" % (cls,))
        if cls == CLAIM_ANCHOR_SIGNED:
            # Anchor-signed claims carry signature-verified evidence:
            # the signature must verify under the peer's bound anchor
            # key over the domain-separated claim binding.
            if not isinstance(sig, (bytes, bytearray)):
                raise PeerAttestationError(
                    CLAIM_CLASS_DENIED_CODE,
                    "anchor-signed claim %r lacks signature evidence"
                    % (key,))
            msg = (_CLAIM_DOMAIN + peer_id.encode("utf-8") + b":"
                   + key.encode("utf-8") + b":"
                   + value.encode("utf-8"))
            if _ed25519.verify(bytes.fromhex(anchor_pub), msg,
                               bytes(sig)) is not True:
                raise PeerAttestationError(
                    CLAIM_CLASS_DENIED_CODE,
                    "anchor-signed claim %r signature invalid" % (key,))
        else:
            # Self-assertable claims: default-deny, deployment
            # allowlist by key name (the AllowedLabelKeys pattern).
            if key not in allowlisted:
                raise PeerAttestationError(
                    CLAIM_CLASS_DENIED_CODE,
                    "self-assertable claim key %r not allowlisted"
                    % (key,))
        out[key] = {"value": value, "class": cls}
    return out


def _possession_message(nonce_hex, peer_id):
    return (_POSSESSION_DOMAIN + bytes.fromhex(nonce_hex)
            + b":" + peer_id.encode("utf-8"))


class PeerAttestationTable(object):
    """Sybil-resistant peer identity attestation within a trust domain.

    ``journal_path`` (required): a ``durable_journal.Journal`` path.
    Control-plane events (registration, identity authorization, ban,
    removal, double-join incidents) are journaled; the audit trail is
    not optional, so a table without a journal cannot exist.

    ``local_domain``: this trust domain's name. ``allowlisted_claim_keys``:
    the deployment-authored set of self-assertable claim keys honored
    at attestation (default-deny otherwise).
    """

    def __init__(self, journal_path, local_domain,
                 allowlisted_claim_keys=()):
        self._local_domain = _check_domain(local_domain)
        if allowlisted_claim_keys is None:
            raise _malformed("allowlisted_claim_keys must be iterable")
        allowed = set()
        for key in allowlisted_claim_keys:
            if not isinstance(key, str) or not _CLAIM_KEY_RE.match(key):
                raise _malformed("bad allowlisted claim key %r" % (key,))
            allowed.add(key)
        self._allowlisted = frozenset(allowed)
        self._journal = _durable_journal.Journal(journal_path)
        self._peers = {}        # peer_id -> record
        self._anchor_index = {}  # anchor_pub_hex -> peer_id
        self._mapping = {}      # peer_id -> frozenset(identities)
        # F251 fix: rebuild control-plane state from the durable
        # journal. Without this, TOFU bindings, identity mappings,
        # and bans were in-memory-only and a restart silently voided
        # them (an attacker's post-restart registration succeeded
        # while the legitimate owner's later re-registration was the
        # one refused, with confused attribution).
        self._replay_journal()

    # -- journal ----------------------------------------------------

    def _journal_append(self, rtype, body):
        self._journal.append(rtype, body)

    # -- journal replay (F251) ---------------------------------------

    def _replay_journal(self):
        """Rebuild in-memory control-plane state from the journal.

        Applies, in order, the control-plane record types this class
        journals: ``peer-registered``, ``peer-identity-authorized``,
        ``peer-banned``, ``peer-removed``. Incident records
        (``peer-double-join-incident``), snapshot anchors, and unknown
        types carry no peer state and are ignored. Replay is
        read-only: it never appends to the journal.

        Records are hash-chain-verified at journal load, but replay
        still validates shapes and raises
        ``durable_journal.JournalCorrupted`` on a shape-invalid known
        record: silently skipping a binding would reintroduce F251.
        A registration for an already-bound peer id or anchor key is
        a journal anomaly (the live path refuses double-join before
        journaling); first record wins, the anomaly is left in the
        audit trail rather than rebound.

        Claim payloads are NOT restored: the journal records
        ``claim_keys`` for audit; claim evidence is re-attested at
        each attestation, so replay rebuilds an empty claim set.

        Note: operator-invoked ``Journal.compact()`` drops folded
        pre-snapshot history by design; replay covers the records the
        journal still holds.
        """
        for rec in self._journal.records:
            rtype = rec.get("type")
            body = rec.get("body") or {}
            if rtype == "peer-registered":
                self._replay_registered(body)
            elif rtype == "peer-identity-authorized":
                self._replay_authorized(body)
            elif rtype == "peer-banned":
                self._replay_banned(body)
            elif rtype == "peer-removed":
                self._replay_removed(body)
            # else: incidents, snapshot anchors, unknown types --
            # no control-plane state.

    def _replay_registered(self, body):
        try:
            peer_id = _check_peer_id(body["peer_id"])
            anchor = _check_anchor(body["anchor_public_key"])
        except (KeyError, TypeError, PeerAttestationError) as exc:
            raise _durable_journal.JournalCorrupted(
                "peer-registered record malformed: %r" % (exc,))
        if peer_id in self._peers or anchor in self._anchor_index:
            # Journal anomaly: first record wins (see _replay_journal).
            return
        self._peers[peer_id] = {
            "peer_id": peer_id,
            "anchor_public_key": anchor,
            "claims": {},
            "registered_at": body.get("registered_at"),
            "banned": False,
            "challenge": None,
            "last_attested_identity": None,
        }
        self._anchor_index[anchor] = peer_id

    def _replay_authorized(self, body):
        try:
            peer_id = _check_peer_id(body["peer_id"])
            identities = body["identities"]
            if (not isinstance(identities, (list, tuple))
                    or not identities):
                raise _malformed("identities malformed")
            seen = set()
            for ident in identities:
                _check_identity(ident)
                seen.add(ident)
        except (KeyError, TypeError, PeerAttestationError) as exc:
            raise _durable_journal.JournalCorrupted(
                "peer-identity-authorized record malformed: %r" % (exc,))
        self._mapping[peer_id] = frozenset(sorted(seen))

    def _replay_banned(self, body):
        try:
            peer_id = _check_peer_id(body["peer_id"])
        except (KeyError, TypeError, PeerAttestationError) as exc:
            raise _durable_journal.JournalCorrupted(
                "peer-banned record malformed: %r" % (exc,))
        rec = self._peers.get(peer_id)
        if rec is None:
            # Cannot happen through the public API (ban_peer refuses
            # unknown peers); fail closed by keeping the ban.
            rec = {
                "peer_id": peer_id,
                "anchor_public_key": None,
                "claims": {},
                "registered_at": None,
                "banned": True,
                "challenge": None,
                "last_attested_identity": None,
            }
            self._peers[peer_id] = rec
        else:
            rec["banned"] = True
            rec["challenge"] = None

    def _replay_removed(self, body):
        try:
            peer_id = _check_peer_id(body["peer_id"])
        except (KeyError, TypeError, PeerAttestationError) as exc:
            raise _durable_journal.JournalCorrupted(
                "peer-removed record malformed: %r" % (exc,))
        # Mirror remove_peer exactly (it does not clear _mapping).
        rec = self._peers.pop(peer_id, None)
        if rec is not None and rec.get("anchor_public_key") is not None:
            self._anchor_index.pop(rec["anchor_public_key"], None)

    # -- centrally-authored identity mapping -------------------------

    def author_identity(self, peer_id, identities):
        """Deployment-authored mapping: the identities ``peer_id`` may
        claim. Attestation selects from this mapping; it never mints.
        Journaled (``peer-identity-authorized``).
        """
        peer_id = _check_peer_id(peer_id)
        if (not isinstance(identities, (list, tuple))
                or not identities):
            raise _malformed("identities must be a non-empty list")
        seen = set()
        for ident in identities:
            _check_identity(ident)
            seen.add(ident)
        self._mapping[peer_id] = frozenset(sorted(seen))
        self._journal_append("peer-identity-authorized",
                             {"peer_id": peer_id,
                              "identities": sorted(seen)})
        return {"peer_id": peer_id, "identities": sorted(seen)}

    # -- registration (TOFU) ------------------------------------------

    def register_peer(self, peer_id, anchor_pub_hex, claims=None,
                      now=None):
        """First-contact registration: binds ``peer_id`` to its anchor
        key. A second registration for an already-bound peer id, or a
        different peer id reusing a bound anchor key, refuses
        ``federation-double-join`` and journals a LOUD
        ``peer-double-join-incident``.
        """
        now = _validate_now(now)
        peer_id = _check_peer_id(peer_id)
        anchor_pub_hex = _check_anchor(anchor_pub_hex)
        if self._peers.get(peer_id, {}).get("banned"):
            raise PeerAttestationError(
                PEER_BANNED_CODE,
                "peer %r is banned" % (peer_id,))
        if peer_id in self._peers:
            self._double_join_incident(peer_id, anchor_pub_hex, now,
                                       "peer-id-rebind")
            raise PeerAttestationError(
                DOUBLE_JOIN_CODE,
                "peer id %r already bound (TOFU)" % (peer_id,))
        holder = self._anchor_index.get(anchor_pub_hex)
        if holder is not None:
            self._double_join_incident(holder, anchor_pub_hex, now,
                                       "anchor-key-reuse")
            raise PeerAttestationError(
                DOUBLE_JOIN_CODE,
                "anchor key already bound to %r (TOFU)" % (holder,))
        normalized = _check_claims(peer_id, anchor_pub_hex, claims,
                                   self._allowlisted)
        self._peers[peer_id] = {
            "peer_id": peer_id,
            "anchor_public_key": anchor_pub_hex,
            "claims": normalized,
            "registered_at": now,
            "banned": False,
            "challenge": None,
            "last_attested_identity": None,
        }
        self._anchor_index[anchor_pub_hex] = peer_id
        self._journal_append("peer-registered",
                             {"peer_id": peer_id,
                              "anchor_public_key": anchor_pub_hex,
                              "claim_keys": sorted(normalized),
                              "registered_at": now})
        return {"peer_id": peer_id, "registered": True}

    def _double_join_incident(self, bound_peer_id, presented_anchor,
                              now, kind):
        """LOUD incident record for a double-join attempt (SPIRE's
        "both sides log" contract). Anchor keys are public material."""
        self._journal_append("peer-double-join-incident",
                             {"security_incident": True,
                              "kind": kind,
                              "bound_peer_id": bound_peer_id,
                              "presented_anchor": presented_anchor,
                              "now": now})

    # -- challenge-response possession proofs --------------------------

    def issue_challenge(self, peer_id, now=None):
        """Issue a server-chosen 32-byte nonce challenge. The peer
        proves possession by signing the domain-separated binding.
        """
        now = _validate_now(now)
        peer_id = _check_peer_id(peer_id)
        rec = self._peers.get(peer_id)
        if rec is None:
            raise _malformed("unknown peer %r" % (peer_id,))
        if rec["banned"]:
            raise PeerAttestationError(
                PEER_BANNED_CODE,
                "peer %r is banned" % (peer_id,))
        nonce = os.urandom(32).hex()
        rec["challenge"] = {"nonce": nonce, "issued_at": now}
        return {"peer_id": peer_id, "nonce": nonce, "issued_at": now}

    def _verify_possession(self, rec, peer_id, nonce, response_sig):
        pending = rec.get("challenge")
        # Single-use challenges: consumed on success AND on failure,
        # so a response is never a replayable oracle.
        rec["challenge"] = None
        if pending is None or pending.get("nonce") != nonce:
            raise PeerAttestationError(
                POSSESSION_FAILED_CODE,
                "no matching pending challenge")
        if not isinstance(response_sig, (bytes, bytearray)):
            raise PeerAttestationError(
                POSSESSION_FAILED_CODE,
                "possession response is not bytes")
        msg = _possession_message(nonce, peer_id)
        pub = bytes.fromhex(rec["anchor_public_key"])
        if _ed25519.verify(pub, msg, bytes(response_sig)) is not True:
            raise PeerAttestationError(
                POSSESSION_FAILED_CODE,
                "possession proof does not verify")

    # -- attestation ----------------------------------------------------

    def attest(self, peer_id, claimed_identity, nonce, response_sig,
               claims=None, federation_table=None, endpoint_url=None,
               now=None):
        """Attest ``claimed_identity`` for ``peer_id``.

        Checks, in fixed order: registered, not banned, possession
        proof, identity in the deployment-authored mapping, claim
        classes, and (for foreign domains) the pinned bundle endpoint.
        Returns the attested record on success.
        """
        now = _validate_now(now)
        peer_id = _check_peer_id(peer_id)
        domain, _path = _check_identity(claimed_identity)
        _check_nonce(nonce)
        rec = self._peers.get(peer_id)
        if rec is None:
            raise _malformed("unknown peer %r" % (peer_id,))
        if rec["banned"]:
            raise PeerAttestationError(
                PEER_BANNED_CODE,
                "peer %r is banned" % (peer_id,))
        self._verify_possession(rec, peer_id, nonce, response_sig)
        allowed = self._mapping.get(peer_id, frozenset())
        if claimed_identity not in allowed:
            raise PeerAttestationError(
                IDENTITY_UNMAPPED_CODE,
                "peer %r was never mapped to %r"
                % (peer_id, claimed_identity))
        normalized = _check_claims(peer_id, rec["anchor_public_key"],
                                   claims, self._allowlisted)
        if domain != self._local_domain:
            self._check_pinned_endpoint(domain, endpoint_url,
                                        federation_table)
        rec["claims"] = normalized
        rec["last_attested_identity"] = claimed_identity
        return {"peer_id": peer_id, "identity": claimed_identity,
                "attested": True, "trust_domain": domain,
                "claims": normalized}

    def _check_pinned_endpoint(self, domain, endpoint_url,
                               federation_table):
        """Cross-domain endpoint pinning: the presented endpoint must
        EXACTLY match the relationship-pinned endpoint. No
        auto-discovery: a domain with no declared relationship refuses
        the existing ``federation-untrusted-domain``.
        """
        if (not isinstance(endpoint_url, str) or not endpoint_url
                or len(endpoint_url) > 2048):
            raise PeerAttestationError(
                ENDPOINT_UNPINNED_CODE,
                "no bundle endpoint presented for %r" % (domain,))
        if federation_table is None:
            raise PeerAttestationError(
                ENDPOINT_UNPINNED_CODE,
                "no federation table for cross-domain attestation")
        relationships = federation_table.relationships()
        rel = relationships.get(domain)
        if rel is None:
            raise PeerAttestationError(
                "federation-untrusted-domain",
                "no federation relationship for %r" % (domain,))
        if rel.get("bundle_endpoint") != endpoint_url:
            raise PeerAttestationError(
                ENDPOINT_UNPINNED_CODE,
                "endpoint %r does not match the pinned endpoint for %r"
                % (endpoint_url, domain))

    # -- ban / remove / prune --------------------------------------------

    def ban_peer(self, peer_id, reason, now=None):
        """Ban a peer (per-peer revocation). Journaled
        (``peer-banned``); bans survive pruning."""
        now = _validate_now(now)
        peer_id = _check_peer_id(peer_id)
        if (not isinstance(reason, str) or not reason
                or len(reason) > _MAX_BAN_REASON_LEN):
            raise _malformed("bad ban reason")
        rec = self._peers.get(peer_id)
        if rec is None:
            raise _malformed("unknown peer %r" % (peer_id,))
        rec["banned"] = True
        rec["challenge"] = None
        self._journal_append("peer-banned",
                             {"peer_id": peer_id, "reason": reason,
                              "now": now})
        return {"peer_id": peer_id, "banned": True}

    def remove_peer(self, peer_id, now=None):
        """Remove a peer record (explicit TOFU reset): unbinds the peer
        id and its anchor key, clearing any ban. Journaled
        (``peer-removed``)."""
        now = _validate_now(now)
        peer_id = _check_peer_id(peer_id)
        rec = self._peers.pop(peer_id, None)
        if rec is not None:
            self._anchor_index.pop(rec["anchor_public_key"], None)
        self._journal_append("peer-removed",
                             {"peer_id": peer_id,
                              "had_record": rec is not None,
                              "now": now})
        return {"peer_id": peer_id, "removed": True}

    def prune(self, now, ttl_seconds):
        """Drop stale peer records (registered_at + ttl < now).
        Banned peers are excluded from pruning (they must stay banned
        until explicitly removed)."""
        now = _validate_now(now)
        if (not isinstance(ttl_seconds, (int, float))
                or ttl_seconds < 0):
            raise _malformed("bad ttl_seconds")
        pruned = 0
        for peer_id in list(self._peers):
            rec = self._peers[peer_id]
            if rec["banned"]:
                continue
            registered_at = rec.get("registered_at")
            if registered_at is None:
                # F251 replay: journals written before registered_at
                # was journaled carry no timestamp. Staleness cannot
                # be computed -- fail safe by keeping the peer.
                continue
            if registered_at + ttl_seconds < now:
                self._anchor_index.pop(rec["anchor_public_key"], None)
                del self._peers[peer_id]
                pruned += 1
        return {"pruned": pruned}

    # -- reads -------------------------------------------------------------

    def peer_record(self, peer_id):
        """The peer record (JSON-safe copy) or None."""
        peer_id = _check_peer_id(peer_id)
        rec = self._peers.get(peer_id)
        if rec is None:
            return None
        return {
            "peer_id": rec["peer_id"],
            "anchor_public_key": rec["anchor_public_key"],
            "claims": {k: dict(v)
                       for k, v in rec["claims"].items()},
            "registered_at": rec["registered_at"],
            "banned": rec["banned"],
            "identities": sorted(self._mapping.get(peer_id, ())),
            "last_attested_identity":
                rec["last_attested_identity"],
        }

    def is_banned(self, peer_id):
        peer_id = _check_peer_id(peer_id)
        rec = self._peers.get(peer_id)
        return rec is not None and rec["banned"] is True
