"""Denied actions as first-class sealed evidence with selective disclosure.

Wave-236 lane B. Stdlib only.

A denied action is sealed into a DENIAL CAPSULE with the same
evidentiary weight as a permit: the capsule binds the taxonomy
refusal code, the denying authority, the denied action's digest, and
a timestamp, and is sealed under a domain-separated signature input
(``gov-denial-capsule/v1`` + canonical JSON of the sealed body) so
the seal can never be repurposed as another record's signature.

Selective disclosure (re-derived, nothing copied from the external
sel-disc literature):

* The sealed body carries NO raw field values -- only salted-hash
  commitments ``sha256(salt || canonical_field_bytes)``, one per
  committed field, plus decoy digests.
* ``disclose_fields`` reveals only the named fields (values + salts);
  ``verify_disclosure`` recomputes every commitment, so a tampered
  disclosed value refuses ``denial-disclosure-mismatch``.
* Decoy digests are 64-char lowercase hex digests like real
  commitments; they are format-identical and indistinguishable
  without the salt. Indistinguishability is shape-level only -- a
  verifier holding a salt can tell -- never a semantic guarantee.

A silent-drop denial is refused: ``emit_denial`` without a sealed
capsule refuses ``denial-unsealed`` -- a denial must be sealed or the
action never ran.

Composition: ``gov.deny_receipts.emit`` accepts an optional
keyword-only ``denial_capsule=``; the attached capsule is
shape-checked and signature-covered by the receipt. The default
receipt path (no capsule) is byte-identical to the legacy path.

Honest boundary: a sealed denial capsule proves the emitter's signed
claim about a denial, not that the denial was correct or that the
described action would have occurred. Salts are deployment-custodied:
whoever holds the salts can disclose; whoever holds the values can
recompute commitments. The in-repo default refuses spawning and has
no custody half (same standing boundary as the rest of the
evidence tree).

Design rules (re-derived):

1. Commitments, never values: the sealed body is values-free, so a
   capsule can travel where the raw values must not.
2. Domain separation: the signature input is prefixed with
   ``gov-denial-capsule/v1`` + canonical bytes; a capsule seal can
   never validate as another record type's signature.
3. Refusal codes are vocabulary-bound: the committed refusal code
   must already be a mapped taxonomy code (``gov.decision_codes``);
   an unmapped code refuses ``denial-capsule-malformed`` at seal
   time, never at verify time.
4. Recompute, never trust: ``verify_capsule`` re-derives the
   signature input from the presented capsule; a tampered capsule
   refuses ``denial-capsule-signature-invalid``.
5. MAC tiers honestly labeled: an ``hmac-sha256-mac`` capsule
   verifies but carries ``non_repudiation=False`` (per
   gov/alg_registry.py); only ``ed25519-rfc8032`` capsules are
   non-repudiation evidence.
6. Honest-claim discipline: the sealed body is asserted through
   ``gov.honest_claims`` before signing -- a reserved claim token in
   operator-controlled body strings (``key_id``; the values live only
   as salted commitments) refuses ``honest-claim-reserved-token``,
   never ships silently.

Registries are in-memory; persistence and distribution are
deployment-owned. The revocation story is the same as the capsules
this composes with: a capsule proves a sealed claim, not a live
authorization state.
"""

import hashlib
import json
import os
import time

DENIAL_CAPSULE_VERSION = 1

_CAPSULE_KIND = "denial-capsule"
_SIGNATURE_DOMAIN = b"gov-denial-capsule/v1"

# Fields committed (salted-hash) by every sealed capsule, in order.
_COMMITTED_FIELDS = ("refusal_code", "authority", "action_digest",
                     "timestamp")

_SALT_BYTES = 32

_EXPECTED_FIELDS = frozenset({
    "v", "kind", "commitments", "decoys", "alg", "key_id",
    "non_repudiation", "signature"})


class DenialCapsuleError(Exception):
    """Base denial-capsule failure. ``code`` is machine-readable and
    registered in gov/decision_codes.py (domain ``denial``)."""
    code = "denial-capsule-malformed"


class DenialCapsuleMalformed(DenialCapsuleError):
    """The capsule, disclosure, or seal-time input is not well-formed."""
    code = "denial-capsule-malformed"


class DenialCapsuleInvalid(DenialCapsuleError):
    """The capsule seal does not verify."""
    code = "denial-capsule-signature-invalid"


class DenialCapsuleUnsealed(DenialCapsuleError):
    """A denial was emitted without a sealed denial capsule."""
    code = "denial-unsealed"


class DenialCapsuleDisclosure(DenialCapsuleError):
    """A disclosed field does not match its sealed commitment."""
    code = "denial-disclosure-mismatch"


# -- internals ----------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _signing_input(body):
    return _SIGNATURE_DOMAIN + _canonical(body)


def _is_hex64(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


def _decision_codes():
    try:
        from . import decision_codes as mod
    except ImportError:  # standalone: module beside this file
        import decision_codes as mod  # noqa: N812
    return mod


def _registry(registry):
    if registry is not None:
        return registry
    try:
        from . import alg_registry as mod
    except ImportError:  # standalone: registry beside this file
        import alg_registry as mod  # noqa: N812
    return mod.default_registry()


def _honest_claims():
    try:
        from . import honest_claims as mod
    except ImportError:  # standalone: module beside this file
        import honest_claims as mod  # noqa: N812
    return mod


def _field_commitment(value, salt):
    """Salted commitment: sha256(salt || canonical_field_bytes)."""
    return hashlib.sha256(salt + _canonical(value)).hexdigest()


def _check_signer(signer):
    for attr in ("alg", "secret", "key_id"):
        if not hasattr(signer, attr):
            raise DenialCapsuleMalformed(
                "denial-capsule-malformed: signer needs .%s" % attr)
    if not isinstance(signer.alg, str) or not signer.alg:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: signer alg must be a non-empty "
            "string")
    if not isinstance(signer.secret, (bytes, bytearray)) or \
            not signer.secret:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: signer secret must be non-empty "
            "bytes")
    if not isinstance(signer.key_id, str) or not signer.key_id:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: signer key_id must be a "
            "non-empty string")


def check_capsule_shape(capsule):
    """Public shape check (also used by gov.deny_receipts attach)."""
    if not isinstance(capsule, dict):
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: capsule must be a dict")
    unknown = set(capsule) - _EXPECTED_FIELDS
    if unknown:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: unknown capsule fields: %s"
            % ",".join(sorted(unknown)))
    missing = _EXPECTED_FIELDS - set(capsule)
    if missing:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: missing capsule fields: %s"
            % ",".join(sorted(missing)))
    if capsule.get("v") != DENIAL_CAPSULE_VERSION:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: bad capsule version")
    if capsule.get("kind") != _CAPSULE_KIND:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: capsule kind mismatch")
    commitments = capsule.get("commitments")
    if not isinstance(commitments, dict) or not commitments:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: commitments must be a non-empty "
            "dict")
    for name, digest in commitments.items():
        if not isinstance(name, str) or not name:
            raise DenialCapsuleMalformed(
                "denial-capsule-malformed: commitment name must be a "
                "non-empty string")
        if not _is_hex64(digest):
            raise DenialCapsuleMalformed(
                "denial-capsule-malformed: commitment %r is not "
                "64-char lowercase hex" % (name,))
    decoys = capsule.get("decoys")
    if not isinstance(decoys, list):
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: decoys must be a list")
    for digest in decoys:
        if not _is_hex64(digest):
            raise DenialCapsuleMalformed(
                "denial-capsule-malformed: decoy digest is not 64-char "
                "lowercase hex")
    if not isinstance(capsule.get("alg"), str) or not capsule["alg"]:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: alg must be a non-empty string")
    if not isinstance(capsule.get("key_id"), str) or not capsule["key_id"]:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: key_id must be a non-empty "
            "string")
    sig = capsule.get("signature")
    if not isinstance(sig, str) or not sig:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: signature malformed")
    return capsule


def _capsule_digest(capsule):
    """Digest binding a disclosure to its capsule: sha256 over the
    signature input of the seal body (signature excluded)."""
    body = {k: v for k, v in capsule.items() if k != "signature"}
    return hashlib.sha256(_signing_input(body)).hexdigest()


def _check_salt(salt, field_name):
    if not isinstance(salt, (bytes, bytearray)) or not salt:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: salt for %r must be non-empty "
            "bytes" % (field_name,))
    return bytes(salt)


# -- public API ---------------------------------------------------------

def seal_denial(refusal_code, authority, action_digest, *, signer,
                registry=None, timestamp=None, salts=None,
                extra_fields=None, decoy_count=0):
    """Seal a denied action into a denial capsule.

    Commits (salted-hash) ``refusal_code``, ``authority``,
    ``action_digest``, and ``timestamp`` -- plus any ``extra_fields``
    -- into a sealed, values-free body. Returns
    ``(capsule, material)``: the sealed capsule travels anywhere; the
    material (field values + salts) stays producer-custodied and is
    what ``disclose_fields`` later reveals selectively.

    ``refusal_code`` must already be a mapped taxonomy refusal code;
    ``action_digest`` must be 64-char lowercase hex. ``salts`` maps
    field names to salt bytes (generated with ``os.urandom`` when
    absent). ``decoy_count`` adds that many format-identical decoy
    digests.
    """
    # Vocabulary-bound refusal: unmapped codes refuse at seal time.
    if not isinstance(refusal_code, str) or not refusal_code:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: refusal_code must be a "
            "non-empty string")
    try:
        _decision_codes().code_for(refusal_code)
    except Exception as exc:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: refusal_code %r is not a "
            "mapped taxonomy code: %s" % (refusal_code, exc)) from exc
    if not isinstance(authority, str) or not authority.strip():
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: authority must be a non-empty "
            "string")
    if not _is_hex64(action_digest):
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: action_digest must be 64-char "
            "lowercase hex")
    if timestamp is None:
        timestamp = int(time.time())
    if not isinstance(timestamp, int) or timestamp < 0:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: timestamp must be a non-negative "
            "int")
    _check_signer(signer)
    if salts is not None and not isinstance(salts, dict):
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: salts must be a dict")
    if extra_fields is not None and not isinstance(extra_fields, dict):
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: extra_fields must be a dict")
    if not isinstance(decoy_count, int) or decoy_count < 0:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: decoy_count must be a "
            "non-negative int")

    fields = {"refusal_code": refusal_code,
              "authority": authority,
              "action_digest": action_digest,
              "timestamp": timestamp}
    if extra_fields:
        for name, value in extra_fields.items():
            if not isinstance(name, str) or not name:
                raise DenialCapsuleMalformed(
                    "denial-capsule-malformed: extra field name must be "
                    "a non-empty string")
            if name in fields:
                raise DenialCapsuleMalformed(
                    "denial-capsule-malformed: extra field %r "
                    "collides with a committed field" % (name,))
            fields[name] = value

    provided = salts or {}
    salts_out = {}
    commitments = {}
    for name, value in fields.items():
        raw = provided.get(name)
        salt = _check_salt(raw, name) if raw is not None \
            else os.urandom(_SALT_BYTES)
        salts_out[name] = salt.hex()
        commitments[name] = _field_commitment(value, salt)

    decoys = [hashlib.sha256(os.urandom(_SALT_BYTES)).hexdigest()
              for _ in range(decoy_count)]

    reg = _registry(registry)
    try:
        entry_alg = reg._entry(signer.alg)  # fail closed on unregistered
    except Exception as exc:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: capsule alg %r unusable: %s"
            % (signer.alg, exc)) from exc
    body = {
        "v": DENIAL_CAPSULE_VERSION,
        "kind": _CAPSULE_KIND,
        "commitments": commitments,
        "decoys": decoys,
        "alg": signer.alg,
        "key_id": signer.key_id,
        "non_repudiation": bool(entry_alg["non_repudiation"]),
    }
    # Honest-claim discipline: the sealed body is a rendered
    # evidence artifact; operator-supplied strings (key_id) must not
    # carry reserved claim tokens.
    _honest_claims().assert_no_reserved_claims(body)
    sig = reg.sign(signer.alg, _signing_input(body),
                   bytes(signer.secret))
    capsule = dict(body)
    capsule["signature"] = sig.hex()
    material = {"fields": fields, "salts": salts_out}
    return capsule, material


def verify_capsule(capsule, *, key, expect_alg=None, registry=None):
    """Verify a presented denial capsule.

    Shape violations refuse ``denial-capsule-malformed``; a seal that
    does not verify refuses ``denial-capsule-signature-invalid``.
    On success returns the verified claim (commitments, key id,
    non_repudiation). A capsule proves the emitter's signed claim
    about a denial, never authority.
    """
    check_capsule_shape(capsule)
    reg = _registry(registry)
    try:
        reg._entry(capsule["alg"])  # fail closed on unregistered
    except Exception:
        raise DenialCapsuleInvalid(
            "denial-capsule-signature-invalid: capsule alg %r is "
            "unregistered" % (capsule.get("alg"),))
    if expect_alg is not None and capsule["alg"] != expect_alg:
        raise DenialCapsuleInvalid(
            "denial-capsule-signature-invalid: alg %r != pinned %r"
            % (capsule["alg"], expect_alg))
    try:
        sig = bytes.fromhex(capsule["signature"])
    except ValueError:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: capsule signature is not hex")
    body = {k: v for k, v in capsule.items() if k != "signature"}
    if not reg.verify(capsule["alg"], _signing_input(body), sig,
                      bytes(key)):
        raise DenialCapsuleInvalid(
            "denial-capsule-signature-invalid: capsule seal does not "
            "verify")
    return {
        "ok": True,
        "commitments": dict(capsule["commitments"]),
        "key_id": capsule["key_id"],
        "non_repudiation": bool(capsule["non_repudiation"]),
    }


def disclose_fields(capsule, material, field_names):
    """Reveal only the named fields from the capsule material.

    Returns a disclosure record ``{capsule_digest, disclosed, salts}``
    that ``verify_disclosure`` checks against the sealed commitments.
    Undisclosed fields and their salts never appear in the record.
    """
    check_capsule_shape(capsule)
    if not isinstance(material, dict) or \
            not isinstance(material.get("fields"), dict) or \
            not isinstance(material.get("salts"), dict):
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: material must carry "
            "'fields' and 'salts' dicts")
    if not isinstance(field_names, (list, tuple)) or not field_names:
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: field_names must be a "
            "non-empty list")
    fields = material["fields"]
    salts = material["salts"]
    disclosed = {}
    salt_hexes = {}
    for name in field_names:
        if not isinstance(name, str):
            raise DenialCapsuleMalformed(
                "denial-capsule-malformed: field name must be a string")
        if name not in fields:
            raise DenialCapsuleMalformed(
                "denial-capsule-malformed: field %r is not committed "
                "by this capsule" % (name,))
        if name not in salts:
            raise DenialCapsuleMalformed(
                "denial-capsule-malformed: no salt for field %r"
                % (name,))
        disclosed[name] = fields[name]
        salt_hexes[name] = salts[name]
    return {
        "capsule_digest": _capsule_digest(capsule),
        "disclosed": disclosed,
        "salts": salt_hexes,
    }


def verify_disclosure(capsule, disclosure, *, key, registry=None):
    """Verify a disclosure record against the sealed capsule.

    Fail-closed order: the capsule SEAL is verified first (a
    self-consistent forged capsule with its own disclosure refuses
    ``denial-capsule-signature-invalid`` -- commitments mean nothing
    without the seal), then every salted commitment is recomputed; a
    tampered value, wrong salt, or uncommitted field refuses
    ``denial-disclosure-mismatch``. Also refuses when the disclosure
    binds a different capsule digest. ``key`` is mandatory: there is
    no anonymous disclosure verification.
    """
    # Seal first: authenticate the commitments before trusting them.
    verify_capsule(capsule, key=key, registry=registry)
    if not isinstance(disclosure, dict) or \
            not isinstance(disclosure.get("disclosed"), dict) or \
            not isinstance(disclosure.get("salts"), dict):
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: disclosure must carry "
            "'disclosed' and 'salts' dicts")
    expected_digest = _capsule_digest(capsule)
    if disclosure.get("capsule_digest") != expected_digest:
        raise DenialCapsuleDisclosure(
            "denial-disclosure-mismatch: disclosure binds a different "
            "capsule")
    commitments = capsule["commitments"]
    for name, value in disclosure["disclosed"].items():
        committed = commitments.get(name)
        salt_hex = disclosure["salts"].get(name)
        if committed is None or not isinstance(salt_hex, str):
            raise DenialCapsuleDisclosure(
                "denial-disclosure-mismatch: field %r is not "
                "committed by this capsule" % (name,))
        try:
            salt = bytes.fromhex(salt_hex)
        except ValueError:
            raise DenialCapsuleDisclosure(
                "denial-disclosure-mismatch: salt for %r is not hex"
                % (name,))
        if _field_commitment(value, salt) != committed:
            raise DenialCapsuleDisclosure(
                "denial-disclosure-mismatch: disclosed field %r does "
                "not match its sealed commitment" % (name,))
    return {"ok": True,
            "disclosed": sorted(disclosure["disclosed"])}


def emit_denial(action_record, *, capsule=None):
    """Emit a denial record for a denied action.

    ``capsule`` must be a sealed denial capsule from ``seal_denial``;
    without one the path refuses ``denial-unsealed`` -- a denial must
    be sealed or the action never ran. The record carries the sealed
    capsule alongside the action record; the cryptographic binding
    between the action and the capsule is the ``action_digest``
    commitment, which verifiers confirm through ``verify_disclosure``
    -- this function nests them, it does not re-prove the link. The
    record carries no authority semantics.
    """
    if capsule is None:
        raise DenialCapsuleUnsealed(
            "denial-unsealed: a denial was emitted without a sealed "
            "denial capsule; a denial must be sealed or the action "
            "never ran")
    check_capsule_shape(capsule)
    if not isinstance(action_record, dict):
        raise DenialCapsuleMalformed(
            "denial-capsule-malformed: action_record must be a dict")
    return {
        "v": 1,
        "kind": "denial",
        "action": dict(action_record),
        "capsule": capsule,
    }
