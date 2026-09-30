#!/usr/bin/env python3
"""Supply-chain verification records (SVR) with mandatory reproduction
pointers.

ADAPT of the in-toto v1.2.0 SVR v0.2 direction (re-derived prose;
nothing copied): a verification record is only honest if it names
WHERE its claim can be reproduced. A record with no reproduction
pointer is an unverifiable assertion, not verification — this module
refuses it fail-closed with ``svr-no-reproduction-pointer``.

A record is::

    {v, artifact_digest, build_instructions_digest,
     reproduction_pointers, verifier_results, svr_digest}

``svr_digest`` is SHA-256 of the canonical JSON bytes of the record
minus itself, so the record is self-describing and replayable.

Key properties, enforced in code:

* Mandatory reproduction pointers. :func:`build_svr` refuses
  ``svr-no-reproduction-pointer`` for an empty or missing pointer
  list. Each pointer is syntactically validated as a ``scheme:path``
  locator (``oci://...``, ``git+https://...``, ``file:///...``);
  a malformed pointer refuses ``svr-pointer-malformed``.
* Digest-shape discipline. Both digests must be 64 lowercase hex
  chars; otherwise ``svr-digest-malformed``.
* Replayable. :func:`verify_svr` recomputes the digest and
  re-validates every field; tampering refuses
  ``svr-digest-mismatch``.
* Evidence, never authority. An SVR records a verification; it
  never grants one. :func:`svr_carries_no_authority` refuses
  ``svr-not-authorization`` on authority-shaped fields.
* Digest-linked composition. :func:`attach_svr_to_capsule`
  re-seals an action capsule with the recomputed ``svr_digest`` in
  the effect; :func:`verify_capsule_svr` re-derives the link and
  refuses ``svr-digest-mismatch`` when the record no longer matches
  it. This is additive: ``gov/action_capsule.py`` is not modified.

Stdlib only. No network. $0.
"""

import hashlib
import json
import re

from .action_capsule import (
    seal_capsule,
    verify_capsule,
)


# ----------------------------------------------------------------------
# Error vocabulary.
# ----------------------------------------------------------------------


class SVRError(Exception):
    """Base class for all SVR refusals. ``code`` is
    machine-readable."""

    code = "svr-refused"


class _NoReproductionPointer(SVRError):
    code = "svr-no-reproduction-pointer"


class _PointerMalformed(SVRError):
    code = "svr-pointer-malformed"


class _DigestMalformed(SVRError):
    code = "svr-digest-malformed"


class _DigestMismatch(SVRError):
    code = "svr-digest-mismatch"


class _NotAuthorization(SVRError):
    code = "svr-not-authorization"


class _Malformed(SVRError):
    code = "svr-malformed"


# ----------------------------------------------------------------------
# Constants.
# ----------------------------------------------------------------------

SVR_VERSION = 1

_HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")

# Top-level fields that would smuggle authority into evidence.
_AUTHORITY_FIELDS = frozenset(
    {"grant", "authorization", "authority", "permit", "capability",
     "scope", "delegation", "token"}
)

# A reproduction pointer is a scheme:path locator. The scheme names
# the reproduction channel (oci, git+https, file, ...); the path is
# the opaque locator inside that channel. No whitespace is allowed:
# whitespace in a locator is a copy-paste fracture, not a pointer.
_POINTER_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:[^\s]+\Z")

_MAX_POINTER_LEN = 2048


# ----------------------------------------------------------------------
# Field gates.
# ----------------------------------------------------------------------


def _check_digest(value, field):
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        raise _DigestMalformed(
            "%s must be 64 lowercase hex chars" % field)
    return value


def _check_pointer(pointer):
    if not isinstance(pointer, str) or not pointer:
        raise _PointerMalformed(
            "reproduction pointer must be a non-empty string")
    if len(pointer) > _MAX_POINTER_LEN:
        raise _PointerMalformed("reproduction pointer too long")
    if not _POINTER_RE.match(pointer):
        raise _PointerMalformed(
            "reproduction pointer is not a scheme:path locator: %r"
            % (pointer,))
    return pointer


def _check_pointers(pointers):
    if not isinstance(pointers, (list, tuple)) or not pointers:
        raise _NoReproductionPointer(
            "an SVR without reproduction pointers is an unverifiable "
            "assertion, not a verification record")
    return [_check_pointer(pointer) for pointer in pointers]


def _check_verifier_results(results):
    if results is None:
        return {}
    if not isinstance(results, dict):
        raise _Malformed("verifier_results must be an object")
    for key, value in results.items():
        if not isinstance(key, str) or not key:
            raise _Malformed(
                "verifier_results keys must be non-empty strings")
        if isinstance(value, float) \
                or not isinstance(value, (str, int, bool)):
            raise _Malformed(
                "verifier_results values must be JSON scalars")
    return dict(results)


def svr_carries_no_authority(record):
    """Refuse ``svr-not-authorization`` if the record smuggles
    authority-shaped fields into the evidence.

    An SVR records a verification; it never grants one.
    """
    if not isinstance(record, dict):
        raise _Malformed("record must be a dict")
    smuggled = _AUTHORITY_FIELDS.intersection(record.keys())
    if smuggled:
        raise _NotAuthorization(
            "SVR carries authority-shaped fields: %s"
            % sorted(smuggled))
    return True


# ----------------------------------------------------------------------
# Building and verification.
# ----------------------------------------------------------------------


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def build_svr(artifact_digest, build_instructions_digest,
              reproduction_pointers, verifier_results=None):
    """Build a supply-chain verification record.

    ``reproduction_pointers`` MUST be a non-empty list of
    ``scheme:path`` locators; empty refuses
    ``svr-no-reproduction-pointer``. Both digests must be 64
    lowercase hex chars. Returns the record with ``svr_digest``
    committed over the canonical body.
    """
    record = {
        "v": SVR_VERSION,
        "artifact_digest": _check_digest(artifact_digest,
                                         "artifact_digest"),
        "build_instructions_digest": _check_digest(
            build_instructions_digest, "build_instructions_digest"),
        "reproduction_pointers": _check_pointers(reproduction_pointers),
        "verifier_results": _check_verifier_results(verifier_results),
    }
    svr_carries_no_authority(record)
    record["svr_digest"] = _digest(_canonical_bytes(record))
    return record


def verify_svr(record):
    """Replay an SVR: recompute the digest, re-validate every
    field. Returns the record. Tampering refuses
    ``svr-digest-mismatch``; malformed records refuse with the
    field-specific codes.
    """
    if not isinstance(record, dict):
        raise _Malformed("record must be a dict")
    unknown = set(record.keys()) - {"v", "artifact_digest",
                                    "build_instructions_digest",
                                    "reproduction_pointers",
                                    "verifier_results", "svr_digest"}
    if unknown:
        raise _Malformed("unknown SVR fields: %s" % sorted(unknown))
    if record.get("v") != SVR_VERSION:
        raise _Malformed("unsupported SVR version")
    body = {
        "v": SVR_VERSION,
        "artifact_digest": _check_digest(record.get("artifact_digest"),
                                         "artifact_digest"),
        "build_instructions_digest": _check_digest(
            record.get("build_instructions_digest"),
            "build_instructions_digest"),
        "reproduction_pointers": _check_pointers(
            record.get("reproduction_pointers")),
        "verifier_results": _check_verifier_results(
            record.get("verifier_results")),
    }
    svr_carries_no_authority(body)
    claimed = record.get("svr_digest")
    if not isinstance(claimed, str) or not _HEX64_RE.match(claimed):
        raise _DigestMalformed("svr_digest malformed")
    if claimed != _digest(_canonical_bytes(body)):
        raise _DigestMismatch(
            "svr_digest does not recompute from the record body")
    return dict(record)


# ----------------------------------------------------------------------
# Digest-linked composition with action capsules.
# ----------------------------------------------------------------------


def attach_svr_to_capsule(capsule, svr_record):
    """Attach an SVR to a sealed action capsule as digest-linked
    evidence.

    Replays the capsule and the SVR, then seals a NEW capsule whose
    effect carries ``svr_digest`` (recomputed, never asserted).
    Additive: ``gov/action_capsule.py`` is not modified.
    """
    if not isinstance(capsule, dict):
        raise _Malformed("capsule must be a dict")
    body = verify_capsule(capsule)  # replay; tampering refuses here
    verified = verify_svr(svr_record)
    new_effect = dict(body["effect"])
    new_effect["svr_digest"] = verified["svr_digest"]
    return seal_capsule({"attempt": dict(body["attempt"]),
                         "effect": new_effect})


def verify_capsule_svr(capsule, svr_record):
    """Verify the digest link between a capsule and an SVR.

    Replays the capsule, re-verifies the SVR (recomputing its
    digest), and checks the effect's ``svr_digest`` against the
    recomputed digest. Returns the linked digest. A mismatch
    refuses ``svr-digest-mismatch``; a capsule with no SVR link
    refuses ``svr-malformed``.
    """
    if not isinstance(capsule, dict):
        raise _Malformed("capsule must be a dict")
    body = verify_capsule(capsule)  # replay; tampering refuses here
    verified = verify_svr(svr_record)  # recompute; tampering refuses
    linked = body["effect"].get("svr_digest")
    if not isinstance(linked, str):
        raise _Malformed("capsule effect carries no SVR link")
    if linked != verified["svr_digest"]:
        raise _DigestMismatch(
            "capsule SVR link does not match the SVR's digest")
    return linked
