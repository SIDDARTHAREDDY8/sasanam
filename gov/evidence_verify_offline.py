"""Standalone offline verifier for evidence bundles (wave-311 lane E).

Build-order step 4 (after Sigstore-bundle distribution), implementing the
wave-310 lane B steal verdicts
(``research/prospecting/w310_offline_verifier_auditor_ux.md``):

* **registystack offline-verifier pattern** (steal): the verifier is
  pinned exactly (``VERIFIER_ID``/``VERIFIER_VERSION``), offers no
  options to skip checks, takes narrow inputs only (the canonical
  artifact bytes + an inline verification bundle + a compiled-in trust
  root pinned by SHA-256), and performs zero network I/O by
  construction (this module imports no socket/urllib/http/ssl; proven
  by ``evals/w311_offline_verifier_probes.py`` static + dynamic).
* **DepGuard failure taxonomy** (steal the taxonomy, not the
  dependency): 11 typed failure codes in fixed verification order
  (parse -> crypto -> unsupported -> consistency -> policy/temporal)
  with typed exit codes 40-44, machine + human output on every run.
* **cosign air-gap UX contract** (steal): ``--offline`` /
  ``--trusted-root`` / ``--rfc3161-timestamp`` flag surface. There is
  deliberately no ``--private-infrastructure`` (that flag is an alias
  for skipping transparency checks -- a degradation, not a pattern).
* **SLSA v1.2 VSA consumer procedure** (steal): the verifier emits a
  VSA-shaped verification summary, and the transcript states plainly
  that ``verificationResult: PASSED`` is evidence input, not an
  authorization decision (PASSED != ALLOW).
* **Witness policy binding** (steal): trust roots travel inside the
  SIGNED policy; the compiled-in anchor pins only the policy-signing
  key(s). An expired policy always fails.
* **GUAC metadata discipline** (steal): every claim in the summary
  carries collector (verifier id), origin (trust-root / policy
  digests), and timestamp.
* **Timestamp-authority isolation** (steal, sigstore-rust PR #166):
  each observer timestamp is verified against ONLY its named
  authority's key and ONLY that authority's ``validFor`` window.
* **Rekor v2 CLIENTS.md offline contract** (adapt): no network, no
  online lookup; the witness-entry slot exists in the bundle but any
  entry is refused coded until the witness step lands (the seam).
* **TUF rotation ceremony** (adapt): there is no TUF client in this
  verifier. Trust-root refresh is a reviewed ceremony outside the
  verifier: the new root's SHA-256 is pinned here. The verifier never
  silently falls back to embedded metadata -- a pin mismatch refuses
  to run at all.
* **Clock as inspectable control** (adapt): the caller supplies a
  NAMED time source; the transcript names it with the observed time.
  No time source -> fail closed (no trusted time).

The 9-step pipeline (``verify``), in order:

    parse -> payloadType -> signature -> statement -> predicate ->
    digest -> subject -> policy -> transcript

Trust flow note: the policy is authenticated (signature + expiry)
BEFORE its trust material is used -- authentication precedes use --
then the 9 steps run in canonical order with the authenticated
material. The transcript lists the steps in canonical order; the
policy step's detail records that the policy was authenticated first.

Same-bytes discipline: the bundle JSON is parsed exactly once; the
DSSE envelope is parsed exactly once; signatures are verified over
the exact parsed payload bytes; the statement's canonical bytes must
equal those payload bytes; the subject digest must equal the sha256
of the exact artifact bytes. ``keyid`` is an unauthenticated hint.

The compiled-in trust root below is a SYNTHETIC test anchor. The
deployment's key ceremony replaces it (and re-pins
``COMPILED_TRUST_ROOT_SHA256``) -- trust-root pinning is a
trust-policy decision, not code.

Stdlib only (+ the vendored pure-Python RFC 8032 Ed25519 primitive
already in the tree -- hashlib/secrets only -- loaded by file path so
``gov/__init__.py`` never executes and the import closure stays
socket-free). $0 spend.
Synthetic/local testing.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone


def _load_ed25519():
    """Load the vendored Ed25519 by file path.

    ``from gov import ed25519`` would execute ``gov/__init__.py``,
    whose transitive imports include ``urllib`` (via executor) --
    network-capable code in the import closure of a verifier whose
    contract is zero network. Loading ``gov/ed25519.py`` directly
    keeps the true import closure socket-free (it imports only
    hashlib+secrets). Fail-closed: a missing/unreadable file is an
    InternalError, never a silent fallback.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "ed25519.py")
    try:
        spec = importlib.util.spec_from_file_location(
            "sasanam_standalone_ed25519", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise InternalError("cannot load vendored Ed25519 from %r: %s"
                            % (path, exc))
    return module


# Loaded after the exception classes below (the loader raises
# InternalError on failure, so it must exist first).
_ed25519 = None


def _init_ed25519():
    global _ed25519
    if _ed25519 is None:
        _ed25519 = _load_ed25519()
    return _ed25519

__all__ = [
    "VERIFIER_ID",
    "VERIFIER_VERSION",
    "BUNDLE_VERSION",
    "POLICY_VERSION",
    "TRUST_ROOT_VERSION",
    "ENVELOPE_PAYLOAD_TYPE",
    "POLICY_PAYLOAD_TYPE",
    "INTOTO_STATEMENT_TYPE",
    "COMPILED_TRUST_ROOT",
    "COMPILED_TRUST_ROOT_SHA256",
    "FAILURE_CODES",
    "EXIT_OK",
    "EXIT_PARSE",
    "EXIT_CRYPTO",
    "EXIT_UNSUPPORTED",
    "EXIT_BINDING",
    "EXIT_POLICY",
    "EXIT_INTERNAL",
    "EXIT_USAGE",
    "VerificationError",
    "InternalError",
    "FixedClock",
    "SystemClock",
    "canonical",
    "pae",
    "seal_envelope",
    "build_verification_bundle",
    "compiled_trust_root",
    "verify",
    "render_transcript",
    "machine_report",
    "main",
]

VERIFIER_ID = "sasanam-offline-verifier"
VERIFIER_VERSION = "1.0.0"

BUNDLE_VERSION = "sasanam-offline-verify-bundle/v1"
POLICY_VERSION = "sasanam-verification-policy/v1"
TRUST_ROOT_VERSION = "sasanam-offline-trust-root/v1"

#: DSSE payloadType for the sealed in-toto statement (bound inside the
#: PAE signature; bound again at step 2 of the pipeline).
ENVELOPE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

#: DSSE payloadType for the sealed verification policy.
POLICY_PAYLOAD_TYPE = "application/vnd.sasanam.verification-policy+json"

#: in-toto Statement v1 type URI.
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# ---------------------------------------------------------------------------
# Compiled-in trust root (synthetic test anchor -- see module docstring).
# Only the POLICY-SIGNING key is pinned here; every other trust root
# (evidence keys, timestamp authorities) travels inside the SIGNED
# policy (Witness pattern). Pin = sha256 of the canonical JSON below.
# ---------------------------------------------------------------------------

COMPILED_TRUST_ROOT = {
    "version": TRUST_ROOT_VERSION,
    "policy_keys": [
        {
            "keyid": "bc628a3a02edab86",
            "pubkey_hex": "72a730cfdb526c0369aff6e1e2e08270bc5fd7eab157fafba0323b17bf543502",
        },
    ],
}
COMPILED_TRUST_ROOT_SHA256 = (
    "642eaff7c5b5c73a5152fb963bd7fa83bd02321595924e1cf57d169b581e8768")

# ---------------------------------------------------------------------------
# Failure taxonomy (DepGuard-shaped): 11 typed codes, fixed order
# parse -> crypto -> unsupported -> binding -> policy/temporal, typed
# exit codes 40-44. Every code carries a human reason template and a
# remedy hint (cosign failure-message pattern: expected-vs-actual +
# remedy on every failure).
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_PARSE = 40
EXIT_CRYPTO = 41
EXIT_UNSUPPORTED = 42
EXIT_BINDING = 43
EXIT_POLICY = 44
#: A crash must never emit a success signal (CVE-2026-44310): internal
#: failures exit 1 with a typed INTERNAL_ERROR machine report.
EXIT_INTERNAL = 1
#: CLI usage errors (argparse).
EXIT_USAGE = 2

FAILURE_CODES = {
    # -- parse (40) --
    "BUNDLE_MALFORMED": {
        "exit": EXIT_PARSE, "category": "parse",
        "reason": "the verification bundle is not valid JSON or is "
                  "missing required fields",
        "remedy": "re-export the bundle with build_verification_bundle; "
                  "do not hand-edit bundle JSON",
    },
    "POLICY_MALFORMED": {
        "exit": EXIT_PARSE, "category": "parse",
        "reason": "the signed policy envelope or policy document is "
                  "malformed",
        "remedy": "re-issue the policy with the policy-signing key; "
                  "check version, expires, and required sections",
    },
    # -- crypto (41) --
    "ENVELOPE_SIGNATURE_INVALID": {
        "exit": EXIT_CRYPTO, "category": "crypto",
        "reason": "the statement envelope's signatures do not meet the "
                  "policy threshold (keyid is a hint only; unknown keys "
                  "verify against nothing)",
        "remedy": "seal the statement with a policy-trusted evidence "
                  "key; check the threshold and keyids in the policy",
    },
    "POLICY_SIGNATURE_INVALID": {
        "exit": EXIT_CRYPTO, "category": "crypto",
        "reason": "the policy envelope is not signed by a trust-root "
                  "policy key",
        "remedy": "sign the policy with the deployment's policy-signing "
                  "key pinned in the trust root; a policy signed by any "
                  "other key is not a policy",
    },
    "TIMESTAMP_SIGNATURE_INVALID": {
        "exit": EXIT_CRYPTO, "category": "crypto",
        "reason": "an observer timestamp failed authority-isolated "
                  "verification (unknown authority, bad signature, "
                  "outside the authority's validFor window at the "
                  "timestamp's time, or not bound to this artifact)",
        "remedy": "obtain the timestamp from a policy-listed authority "
                  "inside its validFor window, bound to the artifact "
                  "digest",
    },
    # -- unsupported (42) --
    "UNSUPPORTED_PAYLOAD_TYPE": {
        "exit": EXIT_UNSUPPORTED, "category": "unsupported",
        "reason": "the envelope payloadType is not the bound in-toto "
                  "statement type",
        "remedy": "seal an in-toto Statement v1; the payloadType is "
                  "bound inside the signature and cannot be swapped",
    },
    "UNSUPPORTED_PREDICATE_TYPE": {
        "exit": EXIT_UNSUPPORTED, "category": "unsupported",
        "reason": "the statement predicateType is not the policy's "
                  "required predicate type (content checks are always "
                  "on; there is no flag to disable them)",
        "remedy": "attest with the predicate type the policy requires; "
                  "a signature over the wrong predicate type proves "
                  "nothing about the expected claims",
    },
    "UNSUPPORTED_BUNDLE_VERSION": {
        "exit": EXIT_UNSUPPORTED, "category": "unsupported",
        "reason": "the bundle version is not understood, or the bundle "
                  "carries witness entries this verifier build does not "
                  "verify (witness step not landed)",
        "remedy": "use a v1 bundle; witness entries are refused until "
                  "the Rekor-pattern witness step lands (see the seam "
                  "note in the module docstring)",
    },
    # -- binding / consistency (43) --
    "STATEMENT_SHAPE_INVALID": {
        "exit": EXIT_BINDING, "category": "consistency",
        "reason": "the statement is not a well-shaped in-toto "
                  "Statement v1 or is missing a policy-required "
                  "predicate claim",
        "remedy": "build the statement with the 4-field shape and "
                  "include every claim the policy requires",
    },
    "SUBJECT_DIGEST_MISMATCH": {
        "exit": EXIT_BINDING, "category": "consistency",
        "reason": "the statement's canonical bytes differ from the "
                  "signed payload bytes, or the subject digest does not "
                  "match the artifact bytes",
        "remedy": "verify the exact artifact bytes the statement was "
                  "built over; never re-serialize the statement",
    },
    # -- policy / temporal (44) --
    "TEMPORAL_UNSATISFIED": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "a temporal policy requirement is unsatisfied: the "
                  "signed policy is expired at the observed time "
                  "(expired policy always fails; there is no grace), no "
                  "trusted time source, a timestamp in the future or "
                  "older than the policy's max age, or fewer verified "
                  "observer timestamps than the policy minimum",
        "remedy": "re-issue the policy with the policy-signing key; "
                  "supply a named time source; refresh observer "
                  "timestamps within the policy's max age",
    },
}


class VerificationError(Exception):
    """A typed, coded verification failure.

    Attributes: ``code`` (one of FAILURE_CODES), ``exit_code``,
    ``reason``, ``remedy``, ``expected``, ``actual``, ``checks``
    (the pipeline steps completed before the failure).
    """

    def __init__(self, code, expected=None, actual=None, detail="",
                 checks=()):
        try:
            spec = FAILURE_CODES[code]
        except KeyError:
            raise InternalError("unknown failure code %r "
                                "(verifier bug)" % (code,))
        self.code = code
        self.exit_code = spec["exit"]
        self.category = spec["category"]
        self.reason = spec["reason"] + (": " + detail if detail else "")
        self.remedy = spec["remedy"]
        self.expected = expected
        self.actual = actual
        self.checks = list(checks)
        super().__init__("[%s] %s" % (code, self.reason))


class InternalError(Exception):
    """The verifier itself is broken or misbuilt (never a bundle
    verdict). Always exits non-zero; never emits success."""


_init_ed25519()


# ---------------------------------------------------------------------------
# Clocks: the time source is NAMED and inspectable. No ambient default:
# verify() without a time source fails closed.
# ---------------------------------------------------------------------------

class FixedClock:
    """A named clock pinned to one instant (tests, reproducible runs)."""

    def __init__(self, name, instant):
        if not isinstance(name, str) or not name:
            raise InternalError("clock needs a non-empty name")
        if (not isinstance(instant, datetime)
                or instant.tzinfo is None):
            raise InternalError("clock instant must be tz-aware")
        self._name = name
        self._instant = instant

    @property
    def name(self):
        return self._name

    def now(self):
        return self._instant


class SystemClock:
    """The machine's UTC clock, explicitly named."""

    def __init__(self, name="system-utc-clock"):
        if not isinstance(name, str) or not name:
            raise InternalError("clock needs a non-empty name")
        self._name = name

    @property
    def name(self):
        return self._name

    def now(self):
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Primitives.
# ---------------------------------------------------------------------------

def canonical(obj):
    """Canonical JSON bytes: sort_keys, no whitespace, ASCII.

    The same canonical form as ``gov/evidence_bundle.py::canonical``:
    deterministic bytes for signing so every signer and verifier
    agrees on the payload. Raises InternalError if not serializable
    (never silently degrades).
    """
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InternalError("not JSON-serializable: %s" % (exc,))


def pae(payload_type, payload):
    """DSSE Pre-Authentication Encoding (spec algorithm).

    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
    The payloadType rides inside the signed bytes, so a signature
    cannot be transplanted onto a differently-typed payload.
    """
    if not isinstance(payload_type, str) or not payload_type:
        raise InternalError("pae needs a non-empty payloadType")
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        raise InternalError("pae needs non-empty payload bytes")
    t = payload_type.encode("utf-8")
    b = bytes(payload)
    return (b"DSSEv1 " + str(len(t)).encode("ascii") + b" " + t + b" "
            + str(len(b)).encode("ascii") + b" " + b)


def _b64decode(data, where):
    if not isinstance(data, str):
        raise InternalError("%s: base64 field must be str" % where)
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise InternalError("%s: invalid base64: %s" % (where, exc))


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdefABCDEF" for c in value))


def _parse_time(value, where, malformed_code):
    """Parse an ISO-8601 instant; must be timezone-aware.

    ``malformed_code`` is the VerificationError code for a bad time
    (POLICY_MALFORMED for policy times, TIMESTAMP_SIGNATURE_INVALID
    for token times).
    """
    def _bad(detail):
        raise VerificationError(malformed_code, detail=detail)
    if not isinstance(value, str):
        _bad("%s: time must be a string" % where)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        _bad("%s: bad time %r" % (where, value))
    if dt.tzinfo is None:
        _bad("%s: naive time refused %r" % (where, value))
    return dt


def compiled_trust_root():
    """Return the compiled-in trust root iff it matches its SHA-256 pin.

    A pin mismatch means the verifier binary is corrupt or misbuilt:
    refuse to run at all (InternalError -> exit 1), never a bundle
    verdict.
    """
    doc = COMPILED_TRUST_ROOT
    digest = hashlib.sha256(canonical(doc)).hexdigest()
    if digest != COMPILED_TRUST_ROOT_SHA256:
        raise InternalError(
            "compiled trust root does not match its SHA-256 pin "
            "(got %s, want %s): refusing to run"
            % (digest, COMPILED_TRUST_ROOT_SHA256))
    return doc


# ---------------------------------------------------------------------------
# Bundle assembly (producer side; used by the distribution step and tests).
# ---------------------------------------------------------------------------

def seal_envelope(payload_bytes, payload_type, signers):
    """Seal ``payload_bytes`` in a DSSE envelope dict.

    ``signers``: objects with ``.key_id`` and ``.sign(bytes)`` (the
    ``gov.signing`` signers qualify). Each signer signs
    ``pae(payload_type, payload_bytes)``; threshold is policy at verify
    time. Returns ``{payload, payloadType, signatures}`` with base64
    fields. Raises InternalError on bad inputs (producer bug, loud).
    """
    if not isinstance(payload_bytes, (bytes, bytearray)) \
            or not payload_bytes:
        raise InternalError("seal_envelope needs non-empty payload bytes")
    if not isinstance(payload_type, str) or not payload_type:
        raise InternalError("seal_envelope needs a payloadType")
    signers = list(signers)
    if not signers:
        raise InternalError("seal_envelope needs at least one signer")
    body = bytes(payload_bytes)
    sigs = []
    for s in signers:
        kid = getattr(s, "key_id", None)
        sign = getattr(s, "sign", None)
        if not isinstance(kid, str) or not callable(sign):
            raise InternalError("signer needs .key_id and .sign")
        sigs.append({"keyid": kid,
                     "sig": base64.b64encode(sign(pae(payload_type,
                                                      body))).decode("ascii")})
    return {"payload": base64.b64encode(body).decode("ascii"),
            "payloadType": payload_type,
            "signatures": sigs}


def build_verification_bundle(envelope, policy_envelope, timestamps=(),
                              witness_entries=()):
    """Assemble the inline verification bundle (the narrow input).

    ``envelope``: DSSE envelope over the in-toto statement.
    ``policy_envelope``: DSSE envelope over the signed policy.
    ``timestamps``: observer-timestamp tokens (may be empty).
    ``witness_entries``: reserved for the witness step -- any entry is
    refused coded by the verifier until that step lands.
    """
    for name, doc in (("envelope", envelope),
                      ("policy_envelope", policy_envelope)):
        if not isinstance(doc, dict):
            raise InternalError("%s must be a dict" % name)
    return {
        "version": BUNDLE_VERSION,
        "envelope": envelope,
        "policy": policy_envelope,
        "timestamps": list(timestamps),
        "witness_entries": list(witness_entries),
    }


# ---------------------------------------------------------------------------
# Verification internals. Every failure raises the typed
# VerificationError; unexpected breakage raises InternalError.
# ---------------------------------------------------------------------------

def _check_pubkey_hex(value, where, malformed_code="POLICY_MALFORMED"):
    """Validate a 64-hex-char Ed25519 pubkey.

    Bad key material in the POLICY is POLICY_MALFORMED (untrusted
    input); bad material in the TRUST ROOT is InternalError (the
    verifier's own config is corrupt -- pass malformed_code=None to
    select that).
    """
    if not _is_hex64(value):
        if malformed_code is None:
            raise InternalError("%s: pubkey_hex must be 64 hex chars"
                                % where)
        raise VerificationError(malformed_code,
                                detail="%s: pubkey_hex must be 64 hex chars"
                                % where)
    return bytes.fromhex(value)


def _check_trust_root_shape(doc):
    if not isinstance(doc, dict):
        raise InternalError("trust root must be a dict")
    if doc.get("version") != TRUST_ROOT_VERSION:
        raise InternalError("unsupported trust root version %r"
                            % (doc.get("version"),))
    keys = doc.get("policy_keys")
    if not isinstance(keys, list) or not keys:
        raise InternalError("trust root needs a non-empty policy_keys list")
    out = {}
    for k in keys:
        if not isinstance(k, dict):
            raise InternalError("trust root policy key must be an object")
        kid = k.get("keyid")
        if not isinstance(kid, str) or not kid:
            raise InternalError("trust root policy key needs a keyid")
        if kid in out:
            raise InternalError("duplicate trust root policy keyid %r"
                                % (kid,))
        out[kid] = _check_pubkey_hex(k.get("pubkey_hex"),
                                     "trust root policy key",
                                     malformed_code=None)
    return out


def _parse_envelope(doc, where, malformed_code):
    """Strict single parse of a DSSE envelope dict.

    Returns ``(payload_bytes, payload_type, [(keyid, sig_bytes)])``.
    """
    if not isinstance(doc, dict):
        raise VerificationError(malformed_code,
                                detail="%s: envelope must be an object"
                                % where)
    for field in ("payload", "payloadType", "signatures"):
        if field not in doc:
            raise VerificationError(
                malformed_code,
                detail="%s: envelope missing %r" % (where, field))
    payload = _b64decode(doc["payload"], where + ".payload")
    ptype = doc["payloadType"]
    if not isinstance(ptype, str) or not ptype:
        raise VerificationError(malformed_code,
                                detail="%s: payloadType must be a string"
                                % where)
    sigs = doc["signatures"]
    if not isinstance(sigs, list):
        raise VerificationError(malformed_code,
                                detail="%s: signatures must be a list"
                                % where)
    entries = []
    for i, e in enumerate(sigs):
        if not isinstance(e, dict):
            raise VerificationError(
                malformed_code,
                detail="%s: signature %d must be an object" % (where, i))
        kid = e.get("keyid")
        if kid is not None and not isinstance(kid, str):
            raise VerificationError(
                malformed_code,
                detail="%s: signature %d keyid must be str" % (where, i))
        entries.append((kid, _b64decode(e.get("sig"),
                                       "%s.signatures[%d].sig" % (where, i))))
    if not payload:
        raise VerificationError(malformed_code,
                                detail="%s: empty payload refused" % where)
    return payload, ptype, entries


def _verify_threshold(payload, ptype, entries, pubkeys, threshold,
                      sig_code):
    """Verify ``threshold`` DISTINCT keys over pae(ptype, payload).

    ``pubkeys``: keyid -> 32-byte pubkey. ``keyid`` is a hint only: an
    entry naming an unknown key falls back to try-all; authentication
    is never weakened (an untrusted key verifies against nothing).
    Returns the list of verifying keyids. Raises ``sig_code`` when the
    threshold is unmet.
    """
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or threshold < 1):
        raise InternalError("threshold must be a positive int")
    msg = pae(ptype, payload)
    verified = []
    for kid, sig in entries:
        candidates = []
        if kid is not None and kid in pubkeys:
            candidates = [(kid, pubkeys[kid])]
        else:
            # Hint miss (or absent): try all -- grants an attacker
            # nothing new, avoids spurious refusals from mislabeled
            # keyids.
            candidates = list(pubkeys.items())
        for ckid, pub in candidates:
            if ckid in verified:
                continue
            try:
                ok = _ed25519.verify(pub, msg, sig)
            except Exception:  # noqa: BLE001 -- malformed is False
                ok = False
            if ok is True:
                verified.append(ckid)
                break
    if len(verified) < threshold:
        raise VerificationError(
            sig_code, expected="threshold %d distinct trusted key(s)"
            % threshold,
            actual="%d verified (%s)" % (len(verified),
                                         ",".join(verified) or "none"))
    return verified


def _check_policy_shape(doc):
    """Shape-check the parsed policy document. Returns a normalized dict."""
    if not isinstance(doc, dict):
        raise VerificationError("POLICY_MALFORMED",
                                detail="policy must be a JSON object")
    if doc.get("version") != POLICY_VERSION:
        raise VerificationError("POLICY_MALFORMED",
                                detail="unsupported policy version %r"
                                % (doc.get("version"),))
    pid = doc.get("policy_id")
    if not isinstance(pid, str) or not pid:
        raise VerificationError("POLICY_MALFORMED",
                                detail="policy needs a policy_id")
    expires = _parse_time(doc.get("expires"), "policy.expires",
                                "POLICY_MALFORMED")
    es = doc.get("evidence_signing")
    if not isinstance(es, dict):
        raise VerificationError("POLICY_MALFORMED",
                                detail="policy needs evidence_signing")
    threshold = es.get("threshold")
    if (isinstance(threshold, bool) or not isinstance(threshold, int)
            or threshold < 1):
        raise VerificationError("POLICY_MALFORMED",
                                detail="evidence_signing.threshold must be "
                                "a positive int")
    ev_keys = {}
    keys = es.get("keys")
    if not isinstance(keys, list) or not keys:
        raise VerificationError("POLICY_MALFORMED",
                                detail="evidence_signing needs keys")
    for k in keys:
        if not isinstance(k, dict):
            raise VerificationError("POLICY_MALFORMED",
                                    detail="evidence key must be an object")
        kid = k.get("keyid")
        if not isinstance(kid, str) or not kid:
            raise VerificationError("POLICY_MALFORMED",
                                    detail="evidence key needs a keyid")
        if kid in ev_keys:
            raise VerificationError("POLICY_MALFORMED",
                                    detail="duplicate evidence keyid %r"
                                           % (kid,))
        ev_keys[kid] = _check_pubkey_hex(k.get("pubkey_hex"),
                                         "policy evidence key")
    if threshold > len(ev_keys):
        raise VerificationError("POLICY_MALFORMED",
                                detail="threshold %d exceeds %d keys"
                                % (threshold, len(ev_keys)))
    authorities = {}
    tas = doc.get("timestamp_authorities", [])
    if not isinstance(tas, list):
        raise VerificationError("POLICY_MALFORMED",
                                detail="timestamp_authorities must be a list")
    for ta in tas:
        if not isinstance(ta, dict):
            raise VerificationError("POLICY_MALFORMED",
                                    detail="authority must be an object")
        aid = ta.get("authority_id")
        if not isinstance(aid, str) or not aid:
            raise VerificationError("POLICY_MALFORMED",
                                    detail="authority needs authority_id")
        if aid in authorities:
            raise VerificationError("POLICY_MALFORMED",
                                    detail="duplicate authority_id %r" % aid)
        vf = ta.get("valid_for") if isinstance(ta.get("valid_for"), dict) \
            else {}
        authorities[aid] = {
            "pubkey": _check_pubkey_hex(ta.get("pubkey_hex"),
                                        "authority %s" % aid),
            "not_before": _parse_time(vf.get("not_before"),
                                      "policy.authority.valid_for",
                                      "POLICY_MALFORMED"),
            "not_after": _parse_time(vf.get("not_after"),
                                     "policy.authority.valid_for",
                                     "POLICY_MALFORMED"),
        }
    rpt = doc.get("required_predicate_type")
    if not isinstance(rpt, str) or not rpt:
        raise VerificationError("POLICY_MALFORMED",
                                detail="policy needs required_predicate_type")
    rpc = doc.get("required_predicate_claims", [])
    if (not isinstance(rpc, list)
            or not all(isinstance(c, str) and c for c in rpc)):
        raise VerificationError("POLICY_MALFORMED",
                                detail="required_predicate_claims must be "
                                "a list of strings")
    ots = doc.get("observer_timestamps", {})
    if not isinstance(ots, dict):
        raise VerificationError("POLICY_MALFORMED",
                                detail="observer_timestamps must be an object")
    min_ts = ots.get("min", 0)
    max_age = ots.get("max_age_hours", 168)
    if (isinstance(min_ts, bool) or not isinstance(min_ts, int)
            or min_ts < 0):
        raise VerificationError("POLICY_MALFORMED",
                                detail="observer_timestamps.min must be "
                                "a non-negative int")
    if (isinstance(max_age, bool) or not isinstance(max_age, (int, float))
            or max_age <= 0):
        raise VerificationError("POLICY_MALFORMED",
                                detail="observer_timestamps.max_age_hours "
                                "must be positive")
    wr = doc.get("witness_required", False)
    if not isinstance(wr, bool):
        raise VerificationError("POLICY_MALFORMED",
                                detail="witness_required must be a bool")
    return {
        "policy_id": pid,
        "expires": expires,
        "threshold": threshold,
        "evidence_keys": ev_keys,
        "authorities": authorities,
        "required_predicate_type": rpt,
        "required_predicate_claims": list(rpc),
        "min_timestamps": min_ts,
        "max_age_hours": max_age,
        "witness_required": wr,
        "canonical": canonical(doc),
    }


def _authenticate_policy(policy_envelope, trust_root_keys, now):
    """Verify the policy envelope and return the normalized policy.

    Authentication precedes use: nothing from the policy is trusted
    until its signature verifies against the trust root and its expiry
    is checked against the observed time.
    """
    payload, ptype, entries = _parse_envelope(
        policy_envelope, "policy", "POLICY_MALFORMED")
    if ptype != POLICY_PAYLOAD_TYPE:
        raise VerificationError("POLICY_MALFORMED",
                                expected=POLICY_PAYLOAD_TYPE, actual=ptype,
                                detail="policy envelope payloadType")
    _verify_threshold(payload, ptype, entries, trust_root_keys, 1,
                      "POLICY_SIGNATURE_INVALID")
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise VerificationError("POLICY_MALFORMED",
                                detail="policy payload not JSON: %s" % exc)
    policy = _check_policy_shape(doc)
    if policy["expires"] <= now:
        raise VerificationError(
            "TEMPORAL_UNSATISFIED",
            expected="policy valid at observed time",
            actual="expired %s (observed %s)"
                   % (policy["expires"].isoformat(), now.isoformat()),
            detail="the signed policy is expired")
    return policy


def _check_statement_shape(statement):
    """Fail-fast shape check for the parsed in-toto statement."""
    if not isinstance(statement, dict):
        raise VerificationError("STATEMENT_SHAPE_INVALID",
                                detail="statement must be a JSON object")
    if statement.get("_type") != INTOTO_STATEMENT_TYPE:
        raise VerificationError("STATEMENT_SHAPE_INVALID",
                                expected=INTOTO_STATEMENT_TYPE,
                                actual=statement.get("_type"))
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise VerificationError("STATEMENT_SHAPE_INVALID",
                                detail="subject must be a non-empty list")
    first = subjects[0]
    digest = first.get("digest") if isinstance(first, dict) else None
    if not isinstance(digest, dict) or not _is_hex64(digest.get("sha256")):
        raise VerificationError("STATEMENT_SHAPE_INVALID",
                                detail="subject[0].digest.sha256 must be "
                                "a hex sha256")
    if not isinstance(statement.get("predicateType"), str):
        raise VerificationError("STATEMENT_SHAPE_INVALID",
                                detail="predicateType must be a string")
    if not isinstance(statement.get("predicate"), dict):
        raise VerificationError("STATEMENT_SHAPE_INVALID",
                                detail="predicate must be an object")
    return digest["sha256"]


def _verify_timestamps(tokens, policy, bundle_hexdigest, now):
    """Verify observer timestamps with authority isolation.

    Each token is verified against ONLY its named authority's key and
    ONLY that authority's validFor window, checked at the TOKEN's time
    (CVE-2026-24122). The token binds the artifact digest inside the
    signed body (CVE-2026-22703). Returns the count verified.
    """
    if not isinstance(tokens, list):
        raise VerificationError("BUNDLE_MALFORMED",
                                detail="timestamps must be a list")
    verified = 0
    for i, tok in enumerate(tokens):
        where = "timestamps[%d]" % i
        if not isinstance(tok, dict):
            raise VerificationError("TIMESTAMP_SIGNATURE_INVALID",
                                    detail="%s: token must be an object"
                                    % where)
        aid = tok.get("authority_id")
        auth = policy["authorities"].get(aid) \
            if isinstance(aid, str) else None
        if auth is None:
            raise VerificationError(
                "TIMESTAMP_SIGNATURE_INVALID",
                expected="policy-listed authority",
                actual="authority_id %r" % (aid,),
                detail="%s: unknown authority" % where)
        when = _parse_time(tok.get("time"), "timestamp.time",
                          "TIMESTAMP_SIGNATURE_INVALID")
        # Isolation: the window belongs to THIS authority, checked at
        # the token's time -- never the pooled window, never "now".
        if not (auth["not_before"] <= when <= auth["not_after"]):
            raise VerificationError(
                "TIMESTAMP_SIGNATURE_INVALID",
                expected="token time inside %s validFor [%s, %s]"
                         % (aid, auth["not_before"].isoformat(),
                            auth["not_after"].isoformat()),
                actual=when.isoformat(),
                detail="%s: outside authority window at token time"
                       % where)
        ev_digest = tok.get("evidence_digest")
        if not isinstance(ev_digest, str) \
                or ev_digest.lower() != bundle_hexdigest.lower():
            raise VerificationError(
                "TIMESTAMP_SIGNATURE_INVALID",
                expected="evidence_digest %s" % bundle_hexdigest,
                actual=ev_digest,
                detail="%s: not bound to this artifact" % where)
        body = {"authority_id": aid,
                "time": tok["time"],
                "evidence_digest": tok["evidence_digest"]}
        sig = _b64decode(tok.get("sig"), where + ".sig")
        try:
            ok = _ed25519.verify(auth["pubkey"], canonical(body), sig)
        except Exception:  # noqa: BLE001
            ok = False
        if ok is not True:
            raise VerificationError(
                "TIMESTAMP_SIGNATURE_INVALID",
                detail="%s: bad signature for authority %s (isolated)"
                       % (where, aid))
        # Temporal policy on present tokens: no future timestamps, and
        # none older than the policy's max age.
        if when > now:
            raise VerificationError(
                "TEMPORAL_UNSATISFIED",
                expected="timestamp <= observed time",
                actual=when.isoformat(),
                detail="%s: timestamp in the future" % where)
        age_h = (now - when).total_seconds() / 3600.0
        if age_h > policy["max_age_hours"]:
            raise VerificationError(
                "TEMPORAL_UNSATISFIED",
                expected="age <= %.1f hours" % policy["max_age_hours"],
                actual="%.1f hours" % age_h,
                detail="%s: stale observer timestamp" % where)
        verified += 1
    if verified < policy["min_timestamps"]:
        raise VerificationError(
            "TEMPORAL_UNSATISFIED",
            expected=">= %d verified observer timestamp(s)"
                     % policy["min_timestamps"],
            actual="%d verified" % verified)
    return verified


# ---------------------------------------------------------------------------
# The 9-step pipeline.
# ---------------------------------------------------------------------------

def _fmt_time(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify(bundle_bytes, verification_bundle, trust_root=None,
           time_source=None, existence_only=False):
    """Verify an evidence bundle offline; return the verification report.

    Narrow inputs: ``bundle_bytes`` (the canonical artifact bytes),
    ``verification_bundle`` (the inline bundle dict, or its JSON
    bytes), ``trust_root`` (None -> the compiled-in, SHA-256-pinned
    root; a dict -> caller-supplied, recorded in the transcript),
    ``time_source`` (a NAMED clock -- None fails closed: no trusted
    time), ``existence_only`` (labeled mode; never defaulted).

    Returns the VSA-shaped report dict on success. Raises the typed
    :class:`VerificationError` on any check failure, or
    :class:`InternalError` when the verifier itself is broken.
    Zero network I/O on this path by construction.
    """
    checks = []

    def _pass(step, detail):
        checks.append({"step": step, "result": "pass", "detail": detail})

    def _fail(code, **kw):
        raise VerificationError(code, checks=checks, **kw)

    # -- verifier integrity first: the pin on the compiled-in root --
    if trust_root is None:
        root_doc = compiled_trust_root()
        root_source = "compiled-in"
    else:
        if not isinstance(trust_root, dict):
            raise InternalError("trust_root must be a dict or None")
        root_doc = trust_root
        root_source = "caller-supplied"
    root_keys = _check_trust_root_shape(root_doc)
    root_digest = hashlib.sha256(canonical(root_doc)).hexdigest()

    # -- clock as inspectable control: fail closed with no trusted time --
    if time_source is None:
        _fail("TEMPORAL_UNSATISFIED",
              detail="no trusted time source supplied")
    name = getattr(time_source, "name", None)
    now_fn = getattr(time_source, "now", None)
    if not isinstance(name, str) or not name or not callable(now_fn):
        raise InternalError("time_source needs .name and .now()")
    now = now_fn()
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise InternalError("time_source.now() must return tz-aware time")

    # -- step 1: parse --
    if not isinstance(bundle_bytes, (bytes, bytearray)) \
            or not bundle_bytes:
        _fail("BUNDLE_MALFORMED", detail="bundle_bytes must be non-empty bytes")
    bundle_bytes = bytes(bundle_bytes)
    bundle_hex = hashlib.sha256(bundle_bytes).hexdigest()
    if isinstance(verification_bundle, (bytes, bytearray)):
        try:
            verification_bundle = json.loads(bytes(verification_bundle)
                                             .decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            _fail("BUNDLE_MALFORMED", detail="bundle JSON invalid: %s" % exc)
    if not isinstance(verification_bundle, dict):
        _fail("BUNDLE_MALFORMED", detail="bundle must be a JSON object")
    vb = verification_bundle
    if "version" not in vb:
        _fail("BUNDLE_MALFORMED", detail="bundle missing 'version'")
    if vb.get("version") != BUNDLE_VERSION:
        _fail("UNSUPPORTED_BUNDLE_VERSION",
              expected=BUNDLE_VERSION, actual=vb.get("version"))
    for field in ("envelope", "policy"):
        if field not in vb:
            _fail("BUNDLE_MALFORMED",
                  detail="bundle missing %r" % field)
    witness_entries = vb.get("witness_entries", [])
    if not isinstance(witness_entries, list):
        _fail("BUNDLE_MALFORMED", detail="witness_entries must be a list")
    if witness_entries:
        # The seam: the witness step has not landed. Entries are
        # refused coded, never silently ignored.
        _fail("UNSUPPORTED_BUNDLE_VERSION",
              detail="%d witness entr(ies) present; this verifier build "
                     "does not verify witness entries" % len(witness_entries))
    _pass("parse", "bundle %s parsed (envelope + signed policy)" % BUNDLE_VERSION)

    # -- policy pre-pass: authentication precedes use --
    # The policy is verified (signature + expiry) BEFORE its trust
    # material feeds the envelope checks below.
    policy = _authenticate_policy(vb["policy"], root_keys, now)
    policy_digest = hashlib.sha256(policy["canonical"]).hexdigest()

    # -- step 2: payloadType --
    payload, ptype, entries = _parse_envelope(
        vb["envelope"], "envelope", "BUNDLE_MALFORMED")
    if ptype != ENVELOPE_PAYLOAD_TYPE:
        _fail("UNSUPPORTED_PAYLOAD_TYPE",
              expected=ENVELOPE_PAYLOAD_TYPE, actual=ptype)
    _pass("payloadType", "%s (bound inside the PAE signature)" % ptype)

    # -- step 3: signature --
    verified_keyids = _verify_threshold(
        payload, ptype, entries, policy["evidence_keys"],
        policy["threshold"], "ENVELOPE_SIGNATURE_INVALID")
    _pass("signature",
          "%d/%d threshold over pae(%s, payload) -- key(s) %s"
          % (len(verified_keyids), policy["threshold"], ptype,
             ",".join(verified_keyids)))

    # -- step 4: statement --
    try:
        statement = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        _fail("STATEMENT_SHAPE_INVALID",
              detail="statement payload not JSON: %s" % exc)
    subject_hex = _check_statement_shape(statement)
    _pass("statement", "in-toto Statement v1, well-shaped")

    # -- step 5: predicate --
    if statement["predicateType"] != policy["required_predicate_type"]:
        _fail("UNSUPPORTED_PREDICATE_TYPE",
              expected=policy["required_predicate_type"],
              actual=statement["predicateType"])
    missing = [c for c in policy["required_predicate_claims"]
               if c not in statement["predicate"]]
    # existence-only mode: the crypto core still runs; the
    # predicate-CONTENT evaluation is skipped but LABELED (never
    # defaulted).
    if missing and not existence_only:
        _fail("STATEMENT_SHAPE_INVALID",
              expected="predicate claims %r"
                       % (policy["required_predicate_claims"],),
              actual="missing %r" % (missing,))
    _pass("predicate",
          "%s%s" % (policy["required_predicate_type"],
                    " (existence-only: content not evaluated)"
                    if existence_only else
                    " + %d required claim(s)"
                    % len(policy["required_predicate_claims"])))

    # -- step 6: digest (same-bytes) --
    if canonical(statement) != payload:
        _fail("SUBJECT_DIGEST_MISMATCH",
              expected="statement canonical bytes == signed payload bytes",
              actual="canonical(statement) != payload "
                     "(%d vs %d bytes)" % (len(canonical(statement)),
                                           len(payload)))
    payload_hex = hashlib.sha256(payload).hexdigest()
    _pass("digest", "statement canonical bytes == signed payload bytes "
                    "(sha256:%s)" % payload_hex)

    # -- step 7: subject (digest-first binding) --
    if subject_hex.lower() != bundle_hex.lower():
        _fail("SUBJECT_DIGEST_MISMATCH",
              expected="subject sha256 %s" % bundle_hex,
              actual="statement attests %s" % subject_hex)
    _pass("subject", "subject digest == sha256(artifact bytes)")

    # -- step 8: policy --
    n_ts = _verify_timestamps(vb.get("timestamps", []), policy,
                              bundle_hex, now)
    _pass("policy",
          "policy %s authenticated before use; signed by trust-root "
          "key; expires %s; %d observer timestamp(s) verified "
          "(authority-isolated)"
          % (policy["policy_id"], _fmt_time(policy["expires"]), n_ts))

    # -- step 9: transcript --
    report = {
        "status": "VALID",
        "verificationResult": "PASSED",
        "verifier": {"id": VERIFIER_ID, "version": VERIFIER_VERSION},
        "timeVerified": _fmt_time(now),
        "timeSource": {"name": name, "observed": _fmt_time(now)},
        "resourceUri": "sha256:" + bundle_hex,
        "policy": {
            "uri": policy["policy_id"],
            "digest": {"sha256": policy_digest},
            "expires": _fmt_time(policy["expires"]),
        },
        "trustRoot": {"source": root_source, "sha256": root_digest},
        "inputAttestations": [
            {"uri": "dsse-envelope", "digest": {"sha256": payload_hex}},
        ],
        "evidenceKeys": {"threshold": policy["threshold"],
                         "verifiedKeyids": verified_keyids},
        "observerTimestamps": {"required": policy["min_timestamps"],
                               "verified": n_ts},
        "existenceOnly": bool(existence_only),
        "checks": checks,
    }
    _pass("transcript", "report assembled (see below)")
    return report


# ---------------------------------------------------------------------------
# Output: cosign-shaped human transcript + DepGuard-shaped machine JSON.
# ---------------------------------------------------------------------------

def render_transcript(report):
    """Render the cosign-shaped human transcript for a VALID report."""
    if not isinstance(report, dict) or report.get("status") != "VALID":
        raise InternalError("render_transcript needs a VALID report")
    lines = []
    lines.append("Verification for %s -- %s"
                 % (report["resourceUri"], report["verificationResult"]))
    lines.append("  verifier: %s %s"
                 % (report["verifier"]["id"], report["verifier"]["version"]))
    lines.append("  time source: %s  observed: %s"
                 % (report["timeSource"]["name"],
                    report["timeSource"]["observed"]))
    lines.append("  trust root: %s  sha256:%s"
                 % (report["trustRoot"]["source"],
                    report["trustRoot"]["sha256"]))
    lines.append("  policy: %s  expires: %s  sha256:%s"
                 % (report["policy"]["uri"], report["policy"]["expires"],
                    report["policy"]["digest"]["sha256"]))
    if report.get("existenceOnly"):
        lines.append("  NOTE: existence-only verification -- signature and "
                     "binding verified; predicate content NOT evaluated")
    lines.append("The following checks were performed:")
    for c in report["checks"]:
        lines.append("  [pass] %s: %s" % (c["step"], c["detail"]))
    lines.append("NOTE: verificationResult PASSED is evidence input, not "
                 "an authorization decision (PASSED != ALLOW).")
    return "\n".join(lines) + "\n"


def render_failure(error):
    """Render the failure transcript: expected-vs-actual + remedy."""
    lines = []
    lines.append("Verification -- FAILED [%s]" % error.code)
    lines.append("  category: %s  exit: %d"
                 % (error.category, error.exit_code))
    if error.expected is not None:
        lines.append("  expected: %s" % (error.expected,))
    if error.actual is not None:
        lines.append("  actual:   %s" % (error.actual,))
    lines.append("  reason:   %s" % (error.reason,))
    lines.append("  remedy:   %s" % (error.remedy,))
    done = [c["step"] for c in error.checks]
    if done:
        lines.append("  checks completed before failure: %s"
                     % (", ".join(done),))
    return "\n".join(lines) + "\n"


def machine_report(report_or_error):
    """DepGuard-shaped machine output (JSON-serializable)."""
    if isinstance(report_or_error, VerificationError):
        e = report_or_error
        return {
            "status": "INVALID",
            "code": e.code,
            "category": e.category,
            "exit_code": e.exit_code,
            "reason": e.reason,
            "remedy": e.remedy,
            "expected": e.expected,
            "actual": e.actual,
            "checks": e.checks,
        }
    if isinstance(report_or_error, dict):
        return dict(report_or_error)
    raise InternalError("machine_report needs a report or VerificationError")


# ---------------------------------------------------------------------------
# CLI: the cosign air-gap UX contract.
# ---------------------------------------------------------------------------

def _parse_clock_arg(value):
    if value == "system":
        return SystemClock()
    if value.startswith("test:"):
        return FixedClock("test-clock",
                          _parse_time(value[len("test:"):], "clock",
                                      "TEMPORAL_UNSATISFIED"))
    raise InternalError("--clock must be 'system' or 'test:<ISO-8601>'")


def main(argv=None):
    """CLI entry point. Returns the process exit code (never 0 on failure).

    Flags: --bundle PATH (required), --artifact PATH (required),
    --trusted-root PATH (caller-supplied trust root JSON; the transcript
    records its digest and source), --rfc3161-timestamp PATH (repeatable;
    extra observer-timestamp tokens in the bundle's JSON token shape),
    --clock system|test:<ISO> (default: system), --existence-only
    (labeled mode), --offline (accepted; offline is the only mode --
    this verifier has no network path), --json (machine output).
    There is deliberately no --private-infrastructure.
    """
    ap = argparse.ArgumentParser(
        prog="evidence-verify-offline",
        description="Standalone offline verifier for Sasanam evidence "
                    "bundles (zero network by construction).")
    ap.add_argument("--bundle", required=True,
                    help="verification bundle JSON file")
    ap.add_argument("--artifact", required=True,
                    help="artifact bytes file (the evidence bundle bytes)")
    ap.add_argument("--trusted-root", default=None,
                    help="caller-supplied trust root JSON file")
    ap.add_argument("--rfc3161-timestamp", action="append", default=[],
                    metavar="PATH",
                    help="extra observer-timestamp token JSON file "
                         "(repeatable)")
    ap.add_argument("--clock", default="system",
                    help="'system' or 'test:<ISO-8601 instant>'")
    ap.add_argument("--existence-only", action="store_true",
                    help="labeled existence-only mode (never the default)")
    ap.add_argument("--offline", action="store_true", default=True,
                    help="air-gap contract flag: offline is the only mode")
    ap.add_argument("--json", action="store_true",
                    help="emit the machine JSON report instead of the "
                         "human transcript")
    args = ap.parse_args(argv)

    def _load_json(path, what):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError) as exc:
            raise InternalError("%s %r unreadable: %s" % (what, path, exc))

    def _emit_failure(code, reason, remedy, exit_code):
        doc = {"status": "INVALID", "code": code, "reason": reason,
               "remedy": remedy, "exit_code": exit_code}
        sys.stdout.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        return exit_code

    try:
        vb = _load_json(args.bundle, "bundle")
        if not isinstance(vb, dict):
            raise InternalError("bundle JSON must be an object")
        try:
            with open(args.artifact, "rb") as fh:
                artifact = fh.read()
        except OSError as exc:
            raise InternalError("artifact %r unreadable: %s"
                                % (args.artifact, exc))
        trust_root = (_load_json(args.trusted_root, "trust root")
                      if args.trusted_root else None)
        extra_ts = [_load_json(p, "timestamp token")
                    for p in args.rfc3161_timestamp]
        if extra_ts:
            vb = dict(vb)
            vb["timestamps"] = list(vb.get("timestamps", [])) + extra_ts
        clock = _parse_clock_arg(args.clock)
        report = verify(artifact, vb, trust_root=trust_root,
                        time_source=clock,
                        existence_only=args.existence_only)
    except VerificationError as e:
        sys.stdout.write(json.dumps(machine_report(e), indent=2,
                                    sort_keys=True) + "\n")
        return e.exit_code
    except InternalError as e:
        return _emit_failure("INTERNAL_ERROR", str(e),
                             "the verifier is misbuilt or misconfigured; "
                             "do not trust this installation", EXIT_INTERNAL)
    except Exception as e:  # noqa: BLE001 -- crash path (CVE-2026-44310)
        return _emit_failure("INTERNAL_ERROR",
                             "unexpected %s: %s"
                             % (type(e).__name__, e),
                             "the verifier crashed; a crash is never "
                             "success", EXIT_INTERNAL)

    if args.json:
        sys.stdout.write(json.dumps(machine_report(report), indent=2,
                                    sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_transcript(report))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
