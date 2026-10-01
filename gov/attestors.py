"""Attestor-plugin interface at cert issuance (SPIFFE ADAPT, principle
only -- no SPIFFE dependency, no JWT SVIDs, no bearer-token flows).

The certified producer identity stays in the wave-272 OIDC
``(iss, sub)`` ceremony. Attestors add an environment binding on top:
a pluggable :class:`Attestor` collects environment facts at issuance
time, and the CA matches those facts against declared registration
entries in an :class:`AttestedRegistry`. On a match, the entry's id
and the attested facts feed the cert's claim set (a ``<oid_arc>.1.41``
extension) and the issuance attestation.

Registration entries are crown jewels: ``register_entry`` requires a
claim-level ceremony -- an Ed25519 signature over the canonical entry
by an authorized ceremony key. Entry writes without a valid ceremony
refuse ``attestor-ceremony-invalid``.

Selector-spoofing trap (Unit42): in-process facts are attestations
of the LOCAL environment, not remote proof. Facts that are cheap to
spoof from inside the host (cgroup paths, argv, environment
variables) are documented as such and the collectors prefer
kernel/platform facts (boot_id, machine-id, uname) that are harder
to fake. The security value is binding + ceremony + auditability:
a cert minted for environment E carries E's facts in its claim set,
so a verifier can check them against the declared entry -- not
unspoofability of collection from inside the same host.

Honest limits:
- ``PlatformAttestor`` runs in-process: it binds the local
  environment, it does not remotely attest it.
- ``StaticAttestor`` is a test double: it asserts facts, it does
  not collect them. Never configure it in production.
- Facts are scalar-only (str/int/bool); anything else is dropped at
  collection shaping, never coerced.

Refusals are the ``attestor-*`` machine codes (global taxonomy):

- ``attestor-entry-malformed``: a registration entry fails shape
  validation (or a duplicate entry_id is registered).
- ``attestor-facts-malformed``: an attestor returned a malformed
  collection (missing attestor_id, non-dict facts).
- ``attestor-ceremony-invalid``: an entry write without a valid
  claim-level ceremony (missing, unknown signer, bad signature).
- ``attestor-entry-unmatched``: collected facts match no registered
  entry (or the matched entry's producer is not the assertion sub).
- ``attestor-entry-ambiguous``: collected facts match more than one
  entry -- fail closed, never pick one.
"""

import copy
import json
import os
import platform

__all__ = [
    "AttestorError",
    "Attestor",
    "PlatformAttestor",
    "StaticAttestor",
    "AttestedRegistry",
    "EXPECTED_CODES",
]

EXPECTED_CODES = (
    "attestor-entry-malformed",
    "attestor-facts-malformed",
    "attestor-ceremony-invalid",
    "attestor-entry-unmatched",
    "attestor-entry-ambiguous",
)

_ENTRY_FIELDS = frozenset({"entry_id", "attestor_id", "selector",
                           "producer_sub", "scopes"})


class AttestorError(Exception):
    """Coded refusal from the attestor seam."""

    def __init__(self, code, detail):
        if code not in EXPECTED_CODES:
            raise ValueError("unknown attestor code %r" % (code,))
        super(AttestorError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _shape_facts(raw):
    """Shape a collected facts dict: scalar-only, fail-closed."""
    if not isinstance(raw, dict):
        raise AttestorError(
            "attestor-facts-malformed",
            "attestor facts must be a dict, not %s"
            % type(raw).__name__)
    shaped = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key:
            raise AttestorError(
                "attestor-facts-malformed",
                "attestor fact keys must be non-empty strings")
        # Non-scalars are dropped, never coerced: a fact the
        # collector cannot render as a scalar is not a fact.
        if isinstance(value, bool):
            shaped[key] = value
        elif isinstance(value, int):
            shaped[key] = value
        elif isinstance(value, str):
            shaped[key] = value
        # else: dropped
    if not shaped:
        raise AttestorError(
            "attestor-facts-malformed",
            "attestor returned no scalar facts")
    return shaped


class Attestor(object):
    """Plugin interface: collect environment facts at issuance time.

    ``collect()`` returns ``{"attestor_id": str, "facts": {str:
    str|int|bool}}``. Implementations must be deterministic for a
    fixed environment (the battery asserts A==B across runs).
    """

    attestor_id = "base"

    def collect(self):
        raise NotImplementedError


class PlatformAttestor(Attestor):
    """Stdlib environment-fact collector (no new dependencies).

    Prefers kernel/platform facts (boot_id, machine-id, uname)
    over cheaply-spoofed process facts (cgroup paths, argv, env
    vars are deliberately NOT collected -- see the module docstring
    on the selector-spoofing trap). process.pid is deliberately NOT
    collected either: pids recycle, so a pid is not a selector-grade
    fact (audit correlation for the minting process comes from the
    issuance attestation itself). In-process collection binds the
    LOCAL environment; it is not remote attestation.
    """

    attestor_id = "platform"

    def collect(self):
        facts = {
            "os.name": os.name,
            "platform.system": platform.system(),
            "platform.release": platform.release(),
            "platform.machine": platform.machine(),
        }
        # Kernel boot id: changes every boot, not settable from
        # inside the host without privileges. Best-effort: absent
        # on non-Linux, never fatal.
        try:
            with open("/proc/sys/kernel/random/boot_id", "r",
                       encoding="utf-8") as f:
                boot_id = f.read().strip()
            if boot_id:
                facts["kernel.boot_id"] = boot_id
        except OSError:
            pass
        # Stable machine id: identifies the host across boots.
        # Best-effort and read-only.
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    machine_id = f.read().strip()
                if machine_id:
                    facts["host.machine_id"] = machine_id
                    break
            except OSError:
                continue
        return {"attestor_id": self.attestor_id,
                "facts": _shape_facts(facts)}


class StaticAttestor(Attestor):
    """Test-double attestor: asserts configured facts.

    NEVER configure in production: it collects nothing and proves
    nothing. Exists so the ceremony, matching, and binding logic
    are testable without a real platform.
    """

    attestor_id = "static-test"

    def __init__(self, facts):
        self._facts = _shape_facts(dict(facts))

    def collect(self):
        return {"attestor_id": self.attestor_id,
                "facts": dict(self._facts)}


def _canonical_entry(entry):
    body = {k: v for k, v in entry.items() if k != "ceremony"}
    return json.dumps(body, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


class AttestedRegistry(object):
    """Declared registration entries: environment selectors bound to
    producer identities.

    ``ceremony_keys`` maps ceremony key id -> 32-byte Ed25519 public
    key. Every ``register_entry`` requires a claim-level ceremony: a
    signature over the canonical entry (without the ceremony
    envelope) by an authorized ceremony key. Entries are matched by
    exact selector subset: an entry matches when every
    ``selector`` key/value equals the collected fact.
    """

    def __init__(self, *, ceremony_keys):
        if not isinstance(ceremony_keys, dict) or not ceremony_keys:
            raise ValueError(
                "ceremony_keys must be a non-empty dict of "
                "key_id -> 32-byte public key")
        for kid, pub in ceremony_keys.items():
            if not isinstance(kid, str) or not kid:
                raise ValueError("ceremony key ids must be non-empty "
                                 "strings")
            if not isinstance(pub, (bytes, bytearray)) \
                    or len(pub) != 32:
                raise ValueError("ceremony key %r must be 32 bytes"
                                 % (kid,))
        self._ceremony_keys = {k: bytes(v)
                               for k, v in ceremony_keys.items()}
        self._entries = {}

    def _check_entry_shape(self, entry):
        if not isinstance(entry, dict):
            raise AttestorError(
                "attestor-entry-malformed",
                "registration entry must be a dict, not %s"
                % type(entry).__name__)
        if set(entry.keys()) - _ENTRY_FIELDS - {"ceremony"}:
            raise AttestorError(
                "attestor-entry-malformed",
                "registration entry has unknown fields: %r"
                % sorted(set(entry.keys())
                         - _ENTRY_FIELDS - {"ceremony"}))
        for field in ("entry_id", "attestor_id", "producer_sub"):
            if not isinstance(entry.get(field), str) \
                    or not entry.get(field):
                raise AttestorError(
                    "attestor-entry-malformed",
                    "registration entry %r must be a non-empty str"
                    % field)
        selector = entry.get("selector")
        if not isinstance(selector, dict) or not selector:
            raise AttestorError(
                "attestor-entry-malformed",
                "registration entry selector must be a non-empty "
                "dict")
        for key, value in selector.items():
            if not isinstance(key, str) or not key \
                    or not isinstance(value, (str, int, bool)):
                raise AttestorError(
                    "attestor-entry-malformed",
                    "registration entry selector must be str -> "
                    "scalar")
        scopes = entry.get("scopes")
        if not isinstance(scopes, list) or not scopes \
                or not all(isinstance(s, str) and s for s in scopes):
            raise AttestorError(
                "attestor-entry-malformed",
                "registration entry scopes must be a non-empty list "
                "of strings")

    def register_entry(self, entry, *, ceremony):
        """Register a declaration. ``ceremony`` is ``{"signer":
        key_id, "signature": base64}`` over the canonical entry.
        Crown jewels: any missing/invalid ceremony refuses
        ``attestor-ceremony-invalid`` -- the write never lands.
        """
        self._check_entry_shape(entry)
        if not isinstance(ceremony, dict):
            raise AttestorError(
                "attestor-ceremony-invalid",
                "registration entry %r: entry writes require a "
                "claim-level ceremony (none presented)"
                % (entry.get("entry_id"),))
        signer = ceremony.get("signer")
        signature = ceremony.get("signature")
        pub = self._ceremony_keys.get(signer)
        if pub is None:
            raise AttestorError(
                "attestor-ceremony-invalid",
                "registration entry %r: unknown ceremony signer %r"
                % (entry.get("entry_id"), signer))
        from gov.ed25519 import verify as _verify
        import base64 as _b64
        try:
            sig = _b64.b64decode(signature, validate=True)
        except Exception:
            raise AttestorError(
                "attestor-ceremony-invalid",
                "registration entry %r: ceremony signature is not "
                "valid base64" % (entry.get("entry_id"),))
        if _verify(pub, _canonical_entry(entry), sig) is not True:
            raise AttestorError(
                "attestor-ceremony-invalid",
                "registration entry %r: ceremony signature does not "
                "verify against signer %r"
                % (entry.get("entry_id"), signer))
        entry_id = entry["entry_id"]
        if entry_id in self._entries:
            raise AttestorError(
                "attestor-entry-malformed",
                "registration entry %r already registered"
                % (entry_id,))
        stored = {k: v for k, v in entry.items() if k != "ceremony"}
        self._entries[entry_id] = stored
        return entry_id

    def match(self, facts, *, attestor_id):
        """Match collected facts against registered entries.

        Returns the single matching entry. Zero matches ->
        ``attestor-entry-unmatched``; more than one ->
        ``attestor-entry-ambiguous`` (fail closed).
        """
        if not isinstance(attestor_id, str) or not attestor_id:
            raise AttestorError(
                "attestor-facts-malformed",
                "attestor_id must be a non-empty str")
        facts = _shape_facts(facts)
        hits = []
        for entry in self._entries.values():
            if entry["attestor_id"] != attestor_id:
                continue
            if all(facts.get(k) == v
                   for k, v in entry["selector"].items()):
                hits.append(entry)
        if not hits:
            raise AttestorError(
                "attestor-entry-unmatched",
                "no registration entry matches the collected facts "
                "for attestor %r" % (attestor_id,))
        if len(hits) > 1:
            raise AttestorError(
                "attestor-entry-ambiguous",
                "%d registration entries match the collected facts "
                "for attestor %r; refusing rather than picking one"
                % (len(hits), attestor_id))
        # Deep copy: the nested selector/scopes are shared references
        # into registry state, and a caller must never be able to
        # corrupt a registered entry's selector through the returned
        # handle (spec review, wave-274 lane 3).
        return copy.deepcopy(hits[0])

    def entry_ids(self):
        return sorted(self._entries.keys())
