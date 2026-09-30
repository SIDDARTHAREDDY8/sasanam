#!/usr/bin/env python3
"""Hybrid family gate + verifier-pinned suite acceptance.

Two primitives, re-derived (nothing copied):

1. ``FamilyPolicy`` — a verifier-pinned acceptance set: ``{v,
   accepted_suites: {suite_id: {declared_entries: [{key_id, key_type,
   role}]}}}``, where ``role`` is ``"classical"`` or ``"pqc"``. The
   policy is DIGEST-PINNED at construction: the canonical encoding is
   deep-copied and hashed, and ``FamilyGate.admit`` re-derives the pin
   on every call. A mutated policy (shared-object tampering between
   construction and admit) refuses ``hybrid-policy-tampered``.

2. ``FamilyGate(policy, key_registry)`` — ``admit(suite_id,
   presented_entries, message, signatures)``:

   Check order (deliberate):
     1. shape validation -> ``hybrid-gate-malformed``;
     2. policy pin re-derivation -> ``hybrid-policy-tampered``
        (verifier integrity before any trust decision);
     3. suite_id must be verifier-pinned ->
        ``hybrid-suite-not-accepted`` (suite acceptance is pinned by
        verifier policy, never token-selected);
     4. presented entries must be declared for this suite ->
        ``hybrid-entry-mismatch`` (no smuggled keys);
     5. if the policy declares any PQC entry but the presented set
        contains NO declared PQC entry ->
        ``hybrid-classical-fallback-refused`` (the named downgrade:
        a valid classical set presented while every quantum leg is
        dropped is never a generic incompleteness);
     6. every declared entry must have presented material ->
        ``hybrid-incomplete`` (reserved for material that never
        arrived — a PRESENTED bundle with empty/missing signature
        parts is a failing leg, step 7);
     7. per entry: presented key_type must equal the registered
        record's key_type -> ``hybrid-entry-mismatch``; registered
        resolution (``key-identity-unknown`` / ``key-identity-revoked``
        propagate); MAC-tier entries refuse ``hybrid-leg-invalid`` (a
        family gate is signature-only); the presented pubkey must
        digest-bind to the registered ``pubkey_digest`` ->
        ``hybrid-leg-invalid``; the signature must verify ->
        ``hybrid-leg-failed`` (including presented-but-empty
        material).

   Role semantics: ``role`` labels each declared entry
   ``"classical"`` or ``"pqc"`` and drives the named downgrade check
   (step 5). The cryptographic mandate is: EVERY declared entry
   verifies under its registered record, and hybrid records delegate
   to ``verify_hybrid``. Suite design is verifier-pinned — the gate
   enforces the declared family, it does not second-guess the
   verifier's suite composition. Residual: a single-entry suite
   labelled ``"pqc"`` whose registered record declares no
   ``hybrid_of`` admits on one signature leg. That is a verifier
   authoring choice, visible in the pinned policy, not a silent
   fallback — and dropping a declared PQC entry always refuses
   ``hybrid-classical-fallback-refused``.

   Hybrid-record delegation: when a declared entry's registered
   record declares ``hybrid_of``, the entry is verified through
   ``gov/key_identity.py`` ``verify_hybrid`` — both legs required,
   never a single-leg fallback (``hybrid-leg-invalid`` /
   ``hybrid-leg-failed`` carry the key_identity codes). This is the
   verify_hybrid mandate discipline reused, not re-derived.

   Success returns an admission record ``{v, suite_id,
   message_digest, admitted_entries, policy_digest, admitted_at}`` —
   digest-bound evidence. Admission records are evidence, never
   authority: ``deny_authority_use(record)`` refuses
   ``hybrid-gate-not-authorization``.

Stdlib only. No network. $0.
"""

import hashlib
import json
import math
import time

from .alg_registry import default_registry

# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class HybridGateError(Exception):
    """Base class for all family-gate refusals. ``code`` is
    machine-readable."""

    code = "hybrid-gate-refused"


class _Malformed(HybridGateError):
    code = "hybrid-gate-malformed"


class _SuiteNotAccepted(HybridGateError):
    code = "hybrid-suite-not-accepted"


class _Incomplete(HybridGateError):
    code = "hybrid-incomplete"


class _LegFailed(HybridGateError):
    code = "hybrid-leg-failed"


class _LegInvalid(HybridGateError):
    code = "hybrid-leg-invalid"


class _ClassicalFallback(HybridGateError):
    code = "hybrid-classical-fallback-refused"


class _PolicyTampered(HybridGateError):
    code = "hybrid-policy-tampered"


class _EntryMismatch(HybridGateError):
    code = "hybrid-entry-mismatch"


class _NotAuthorization(HybridGateError):
    code = "hybrid-gate-not-authorization"


_ROLES = ("classical", "pqc")


def _canonical(obj):
    """JCS-style canonical encoding for digest pinning."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _non_empty_str(value, field):
    if not isinstance(value, str) or not value:
        raise _Malformed(
            "hybrid-gate-malformed: %s must be a non-empty string"
            % (field,))
    return value


class FamilyPolicy:
    """A verifier-pinned suite acceptance set, digest-pinned.

    ``policy`` is ``{"v": 1, "accepted_suites": {suite_id:
    {"declared_entries": [{"key_id", "key_type", "role"}]}}}``. The
    input is deep-copied through the canonical encoding, so later
    mutation of the caller's dict cannot move the pin; ``digest()``
    returns the pin, and any admit-time re-derivation mismatch
    refuses ``hybrid-policy-tampered``.
    """

    def __init__(self, policy):
        if not isinstance(policy, dict):
            raise _Malformed(
                "hybrid-gate-malformed: policy must be a dict")
        if policy.get("v") != 1:
            raise _Malformed(
                "hybrid-gate-malformed: policy.v must be 1")
        suites = policy.get("accepted_suites")
        if not isinstance(suites, dict) or not suites:
            raise _Malformed(
                "hybrid-gate-malformed: policy.accepted_suites must be a "
                "non-empty dict")
        for suite_id, suite in suites.items():
            _non_empty_str(suite_id, "suite_id")
            if not isinstance(suite, dict):
                raise _Malformed(
                    "hybrid-gate-malformed: suite %r must be a dict"
                    % (suite_id,))
            entries = suite.get("declared_entries")
            if not isinstance(entries, list) or not entries:
                raise _Malformed(
                    "hybrid-gate-malformed: suite %r declared_entries "
                    "must be a non-empty list" % (suite_id,))
            seen = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise _Malformed(
                        "hybrid-gate-malformed: suite %r entries must be "
                        "dicts" % (suite_id,))
                key_id = _non_empty_str(entry.get("key_id"), "key_id")
                _non_empty_str(entry.get("key_type"), "key_type")
                role = entry.get("role")
                if role not in _ROLES:
                    raise _Malformed(
                        "hybrid-gate-malformed: suite %r entry %r role "
                        "must be one of %r" % (suite_id, key_id, _ROLES))
                if key_id in seen:
                    raise _Malformed(
                        "hybrid-gate-malformed: suite %r declares key_id "
                        "%r twice" % (suite_id, key_id))
                seen.add(key_id)
        # Deep-copy through the canonical encoding: the caller's dict
        # cannot move the pin after construction.
        self._suites = json.loads(_canonical(suites).decode("utf-8"))
        self._pin = hashlib.sha256(_canonical(self._suites)).hexdigest()

    def digest(self):
        """The policy pin: SHA-256 of the canonical accepted_suites."""
        return self._pin

    def suites(self):
        """The verifier-pinned suite ids."""
        return tuple(self._suites)

    def declared(self, suite_id):
        """The declared entries for a pinned suite (deep copy)."""
        return json.loads(json.dumps(self._suites[suite_id]
                                     ["declared_entries"]))

    def _rederive_pin(self):
        return hashlib.sha256(_canonical(self._suites)).hexdigest()

    def verify_pin(self):
        """Re-derive the pin from live state. A mutated policy
        refuses ``hybrid-policy-tampered``. Called on every admit."""
        if self._rederive_pin() != self._pin:
            raise _PolicyTampered(
                "hybrid-policy-tampered: the verifier-pinned policy was "
                "mutated after construction")


class FamilyGate:
    """Admit signature material against a verifier-pinned family policy.

    ``key_registry`` is a ``gov/key_identity.py`` ``KeyRegistry``;
    resolution and revocation semantics are reused from it, never
    re-derived.
    """

    def __init__(self, policy, key_registry):
        if not isinstance(policy, FamilyPolicy):
            raise _Malformed(
                "hybrid-gate-malformed: policy must be a FamilyPolicy")
        self._policy = policy
        self._kreg = key_registry
        self._areg = default_registry()

    @property
    def policy(self):
        return self._policy

    def admit(self, suite_id, presented_entries, message, signatures,
              admitted_at=None):
        """Admit presented signatures under a pinned suite.

        ``presented_entries`` is ``[{"key_id", "key_type"}]`` — the
        caller's claim of what is presented. ``signatures`` maps
        ``key_id`` to ``{"signature", "pubkey"}`` (leaf entries) or to
        ``{"sig_a", "pubkey_a", "sig_b", "pubkey_b"}`` when the entry's
        registered record declares ``hybrid_of`` (delegated to
        ``verify_hybrid``). Returns the digest-bound admission record.
        """
        # 1. shape validation — malformed inputs fail before any trust
        #    decision.
        _non_empty_str(suite_id, "suite_id")
        if not isinstance(message, (bytes, bytearray)):
            raise _Malformed(
                "hybrid-gate-malformed: message must be bytes")
        if not isinstance(presented_entries, list) or not presented_entries:
            raise _Malformed(
                "hybrid-gate-malformed: presented_entries must be a "
                "non-empty list")
        claimed = {}
        for entry in presented_entries:
            if not isinstance(entry, dict):
                raise _Malformed(
                    "hybrid-gate-malformed: presented entries must be "
                    "dicts")
            key_id = _non_empty_str(entry.get("key_id"), "key_id")
            key_type = _non_empty_str(entry.get("key_type"), "key_type")
            if key_id in claimed:
                raise _Malformed(
                    "hybrid-gate-malformed: key_id %r presented twice"
                    % (key_id,))
            claimed[key_id] = key_type
        if not isinstance(signatures, dict) or not signatures:
            raise _Malformed(
                "hybrid-gate-malformed: signatures must be a non-empty "
                "dict")
        for key_id, bundle in signatures.items():
            if not isinstance(bundle, dict):
                raise _Malformed(
                    "hybrid-gate-malformed: signature bundle for %r must "
                    "be a dict" % (key_id,))
        if admitted_at is None:
            admitted_at = time.time()
        if not isinstance(admitted_at, (int, float)) \
                or isinstance(admitted_at, bool) \
                or not math.isfinite(admitted_at) \
                or admitted_at < 0:
            raise _Malformed(
                "hybrid-gate-malformed: admitted_at must be a finite "
                "non-negative seconds-since-epoch")

        # 2. verifier integrity: the pin is re-derived on every call,
        # through the policy's public method — the gate never reaches
        # into policy privates.
        self._policy.verify_pin()

        # 3. suite acceptance is pinned by verifier policy — never
        #    token-selected.
        if suite_id not in self._policy.suites():
            raise _SuiteNotAccepted(
                "hybrid-suite-not-accepted: suite %r is not in the "
                "verifier-pinned policy" % (suite_id,))
        declared = {e["key_id"]: e
                    for e in self._policy.declared(suite_id)}

        # 4. no smuggled keys: every presented entry must be declared.
        for key_id in claimed:
            if key_id not in declared:
                raise _EntryMismatch(
                    "hybrid-entry-mismatch: key_id %r is not declared for "
                    "suite %r" % (key_id, suite_id,))

        # 5. the named downgrade: the policy declares PQC entries but
        #    the presented set drops every one of them. This is
        #    checked BEFORE generic completeness so a valid-looking
        #    classical-only set is never mistaken for a partial one.
        pqc_ids = {kid for kid, e in declared.items()
                   if e["role"] == "pqc"}
        if pqc_ids and not (pqc_ids & set(claimed)):
            raise _ClassicalFallback(
                "hybrid-classical-fallback-refused: suite %r declares "
                "PQC entries but only classical material was presented"
                % (suite_id,))

        # 6. completeness: every declared entry must have material.
        for key_id in declared:
            if key_id not in claimed or key_id not in signatures:
                raise _Incomplete(
                    "hybrid-incomplete: suite %r declares key_id %r but "
                    "no material was presented" % (suite_id, key_id))

        # 7. per-entry verification — every declared leg must verify.
        admitted_entries = []
        for key_id, entry in declared.items():
            record = self._kreg.resolve(key_id)  # key-identity codes
            if claimed[key_id] != record["key_type"]:
                raise _EntryMismatch(
                    "hybrid-entry-mismatch: presented key_type %r for "
                    "key_id %r does not match the registered %r"
                    % (claimed[key_id], key_id, record["key_type"]))
            if not self._areg.info(record["key_type"])["non_repudiation"]:
                raise _LegInvalid(
                    "hybrid-leg-invalid: entry %r uses MAC-tier %r — a "
                    "MAC is not a signature and a family gate is "
                    "signature-only" % (key_id, record["key_type"]))
            bundle = signatures[key_id]
            if record.get("hybrid_of") is not None:
                # Hybrid-record entry: delegate to the key_identity
                # mandate — both legs required, never single-leg.
                self._hybrid_entry(key_id, record, bundle, message)
            else:
                self._leaf_entry(key_id, record, bundle, message)
            admitted_entries.append(
                {"key_id": key_id, "key_type": record["key_type"],
                 "role": entry["role"]})

        return {"v": 1,
                "suite_id": suite_id,
                "message_digest": hashlib.sha256(
                    bytes(message)).hexdigest(),
                "admitted_entries": admitted_entries,
                "policy_digest": self._policy.digest(),
                "admitted_at": admitted_at}

    def _leaf_entry(self, key_id, record, bundle, message):
        sig = bundle.get("signature")
        pubkey = bundle.get("pubkey")
        # A presented entry whose bundle material is absent or empty is
        # a FAILING LEG, not a missing entry: the entry was declared
        # and presented, but its proof does not exist.
        # ``hybrid-incomplete`` is reserved for material that never
        # arrived (step 6, which runs before any leg is verified).
        for name, blob in (("signature", sig), ("pubkey", pubkey)):
            if not isinstance(blob, (bytes, bytearray)) or not blob:
                raise _LegFailed(
                    "hybrid-leg-failed: entry %r presented an "
                    "empty/missing %s" % (key_id, name))
        # Digest-bind the presented pubkey to the registered record —
        # the same binding key_identity enforces for hybrid legs.
        recomputed = hashlib.new(
            record["digest_alg"], bytes(pubkey)).hexdigest()
        if recomputed != record["pubkey_digest"]:
            raise _LegInvalid(
                "hybrid-leg-invalid: entry %r presented pubkey does not "
                "match the registered pubkey_digest" % (key_id,))
        if not self._areg.verify(record["key_type"], bytes(message),
                                 bytes(sig), bytes(pubkey)):
            raise _LegFailed(
                "hybrid-leg-failed: entry %r signature did not verify"
                % (key_id,))

    def _hybrid_entry(self, key_id, record, bundle, message):
        parts = {}
        for name in ("sig_a", "pubkey_a", "sig_b", "pubkey_b"):
            blob = bundle.get(name)
            # Same taxonomy as leaf entries: an absent leg part in a
            # presented bundle is a failing leg, not an incompleteness.
            if not isinstance(blob, (bytes, bytearray)) or not blob:
                raise _LegFailed(
                    "hybrid-leg-failed: hybrid entry %r presented an "
                    "empty/missing %s" % (key_id, name))
            parts[name] = bytes(blob)
        # Delegated to gov/key_identity.verify_hybrid: both legs
        # required, dead legs checked before any signature is touched.
        self._kreg.verify_hybrid(key_id, bytes(message), parts["sig_a"],
                                 parts["sig_b"], parts["pubkey_a"],
                                 parts["pubkey_b"])

    def deny_authority_use(self, admission):
        """An admission record is evidence, never authority."""
        if not isinstance(admission, dict) \
                or "suite_id" not in admission \
                or "policy_digest" not in admission:
            raise _Malformed(
                "hybrid-gate-malformed: deny_authority_use takes an "
                "admission record")
        raise _NotAuthorization(
            "hybrid-gate-not-authorization: admission records are "
            "evidence of verified signatures, never authorization")
