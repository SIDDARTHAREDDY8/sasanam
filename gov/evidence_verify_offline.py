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
  online lookup; log-backed witness entries (``sasanam-witness-log/v1``)
  are verified checkpoint-first -- the checkpoint signature is checked
  before any size/hash is parsed, root hash and tree size come ONLY
  from the verified checkpoint, duplicated copies elsewhere are
  ignored (sigstore-python#248), and the witness key travels inside
  the SIGNED policy. Unknown witness entry kinds are still refused
  coded.
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

plus a conditional witness step between policy and transcript: it runs
only when the bundle carries witness entries or the signed policy sets
``witness_required``. Bundles without witness evidence keep the exact
9-step transcript (existing verifiers and batteries are untouched).

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
_wl = None
_trr = None
_wc = None


def _init_ed25519():
    global _ed25519
    if _ed25519 is None:
        _ed25519 = _load_ed25519()
    return _ed25519


def _load_witness_log():
    """Load gov/witness_log.py by file path (same reason as above:
    ``from gov import witness_log`` would execute ``gov/__init__.py``
    and pull urllib into the import closure). witness_log is stdlib-only
    (hashlib/json/base64), so the closure stays socket-free."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "witness_log.py")
    try:
        spec = importlib.util.spec_from_file_location(
            "sasanam_standalone_witness_log", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise InternalError("cannot load witness_log from %r: %s"
                            % (path, exc))
    return module


def _witness_log():
    global _wl
    if _wl is None:
        _wl = _load_witness_log()
    return _wl


def _load_trust_root_refresh():
    """Load gov/trust_root_refresh.py by file path (same reason as the
    ed25519/witness_log loaders above: ``from gov import trust_root_refresh``
    would execute ``gov/__init__.py`` and pull urllib into the import
    closure of a verifier whose contract is zero network)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "trust_root_refresh.py")
    try:
        spec = importlib.util.spec_from_file_location(
            "sasanam_standalone_trust_root_refresh", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise InternalError("cannot load trust_root_refresh from %r: %s"
                            % (path, exc))
    return module


def _trust_root_refresh():
    global _trr
    if _trr is None:
        _trr = _load_trust_root_refresh()
    return _trr


def _load_witness_consistency():
    """Load gov/witness_consistency.py by file path (same reason as the
    ed25519/witness_log/trust_root_refresh loaders above: ``from gov
    import witness_consistency`` would execute ``gov/__init__.py`` and
    pull urllib into the import closure of a verifier whose contract is
    zero network)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "witness_consistency.py")
    try:
        spec = importlib.util.spec_from_file_location(
            "sasanam_standalone_witness_consistency", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise InternalError("cannot load witness_consistency from %r: %s"
                            % (path, exc))
    return module


def _witness_consistency():
    global _wc
    if _wc is None:
        _wc = _load_witness_consistency()
    return _wc


def _load_schema_v2():
    """Load gov/evidence_schema_v2.py by file path (same reason as the
    ed25519/witness-log loaders: ``from gov import evidence_schema_v2``
    would execute ``gov/__init__.py`` and pull urllib into the import
    closure). evidence_schema_v2 is stdlib-only, so the closure stays
    socket-free."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "evidence_schema_v2.py")
    try:
        spec = importlib.util.spec_from_file_location(
            "sasanam_standalone_evidence_schema_v2", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise InternalError("cannot load evidence_schema_v2 from %r: %s"
                            % (path, exc))
    return module


_sv2 = None


def _schema_v2():
    global _sv2
    if _sv2 is None:
        _sv2 = _load_schema_v2()
    return _sv2

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
    "seal_witness_entry",
    "build_verification_bundle",
    "compiled_trust_root",
    "verify",
    "render_transcript",
    "machine_report",
    "main",
    "WITNESS_ENTRY_KIND",
    "WITNESS_ENTRY_BODY_KIND",
    "WITNESS_ENTRY_API_VERSION",
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

#: Wire kind of a log-backed witness entry in the verification bundle.
WITNESS_ENTRY_KIND = "sasanam-witness-log/v1"

#: Kind marker inside the witness entry body (the leaf preimage).
WITNESS_ENTRY_BODY_KIND = "sasanam-witness-log"

#: Entry body API version.
WITNESS_ENTRY_API_VERSION = "0.0.1"

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
    # -- witness consistency (wave-319 lane 3; parse) --
    "witness-note-malformed": {
        "exit": EXIT_PARSE, "category": "parse",
        "reason": "the checkpoint note is not a valid C2SP signed note",
        "remedy": "re-issue the checkpoint note from the witness log; do "
                  "not hand-edit note bytes",
    },
    "witness-policy-malformed": {
        "exit": EXIT_PARSE, "category": "parse",
        "reason": "the witness_consistency policy section or the gossip "
                  "input is malformed",
        "remedy": "re-issue the policy with a well-formed "
                  "witness_consistency section; malformed policy is never "
                  "defaulted",
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
    "WITNESS_CHECKPOINT_INVALID": {
        "exit": EXIT_CRYPTO, "category": "crypto",
        "reason": "a witness checkpoint failed verification: bad "
                  "signature (checked FIRST, before any field is parsed), "
                  "malformed checkpoint, logId not naming a policy "
                  "witness key, or checkpoint time outside the key's "
                  "validFor window at the checkpoint's time",
        "remedy": "fetch the checkpoint from the pinned witness log; "
                  "check that the policy's witness_log_keys pin the "
                  "log's key with a covering validFor window",
    },
    "WITNESS_KEY_UNAVAILABLE": {
        "exit": EXIT_CRYPTO, "category": "crypto",
        "reason": "the bundle carries witness entries but the signed "
                  "policy names no witness_log_keys to verify them "
                  "against",
        "remedy": "add the witness log's key (with its validFor "
                  "window) to the signed policy's witness_log_keys; a "
                  "witness entry without a policy-pinned key is not "
                  "verifiable",
    },
    # -- witness consistency (wave-319 lane 3; crypto) --
    "witness-cosignature-invalid": {
        "exit": EXIT_CRYPTO, "category": "crypto",
        "reason": "a signature from a configured witness key failed "
                  "verification (cosignature line or gossip view)",
        "remedy": "re-fetch the witness's signature; a known key's bad "
                  "signature is a refusal, never an accept",
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
                  "carries a witness entry kind this verifier does not "
                  "support",
        "remedy": "use a v1 bundle with sasanam-witness-log/v1 witness "
                  "entries; unknown entry kinds are refused, never "
                  "skipped",
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
    # Wave-318 lane 2: schema-2.0 extension (AU-3 record fields + CC8.1
    # decision-maker versioning). The claim says 2.0 but the extension
    # fields are missing, malformed, or the change log has a gap.
    "EXTENSION_SCHEMA_INVALID": {
        "exit": EXIT_BINDING, "category": "consistency",
        "reason": "the statement claims evidence-schema/2.0 but the "
                  "extension claims (au3_records, decision_maker) are "
                  "missing, malformed, or the decision-maker change log "
                  "has a gap",
        "remedy": "attach well-shaped au3_records and decision_maker "
                  "claims, and change-log every model/prompt/config "
                  "change; or ship a schema-1.0 bundle",
    },
    "SUBJECT_DIGEST_MISMATCH": {
        "exit": EXIT_BINDING, "category": "consistency",
        "reason": "the statement's canonical bytes differ from the "
                  "signed payload bytes, or the subject digest does not "
                  "match the artifact bytes",
        "remedy": "verify the exact artifact bytes the statement was "
                  "built over; never re-serialize the statement",
    },
    "WITNESS_INCLUSION_INVALID": {
        "exit": EXIT_BINDING, "category": "consistency",
        "reason": "the witness inclusion proof does not verify the "
                  "entry against the checkpoint's root hash (the root "
                  "hash and tree size come ONLY from the verified "
                  "checkpoint; duplicates elsewhere are ignored), or "
                  "log_index is outside the checkpoint tree_size",
        "remedy": "fetch a fresh inclusion proof from the witness log "
                  "against a current signed checkpoint",
    },
    "WITNESS_ENTRY_UNBOUND": {
        "exit": EXIT_BINDING, "category": "consistency",
        "reason": "the witness entry's body does not bind this bundle: "
                  "artifact digest, exact wire signatures, verified "
                  "keyids, or policy digest mismatch, or the entry's "
                  "integratedTime is incoherent with its checkpoint "
                  "(CVE-2026-22703: never accept 'a valid entry' alone)",
        "remedy": "witness the exact bundle being verified; an entry "
                  "for another artifact cannot be transplanted",
    },
    # -- witness consistency (wave-319 lane 3; consistency) --
    "witness-consistency-fork-detected": {
        "exit": EXIT_BINDING, "category": "consistency",
        "reason": "two checkpoint notes from one log key at the same tree "
                  "size name different roots: cryptographic proof of log "
                  "misbehavior",
        "remedy": "treat the log as compromised; rotate to a new log and "
                  "investigate the fork before trusting any checkpoint",
    },
    "witness-consistency-invalid": {
        "exit": EXIT_BINDING, "category": "consistency",
        "reason": "the consistency proof does not recompute both "
                  "checkpoint roots, the old checkpoint does not match the "
                  "anchored receipt checkpoint, or the note does not verify "
                  "under the log key",
        "remedy": "fetch a valid consistency proof from the witness log "
                  "between the two checkpoints; a valid proof alone is "
                  "never enough (it must bind the receipt's checkpoint)",
    },
    "witness-gossip-conflict": {
        "exit": EXIT_BINDING, "category": "consistency",
        "reason": "witnesses report conflicting signed tree heads for one "
                  "log (same tree size, different roots): cryptographic "
                  "proof of log misbehavior",
        "remedy": "treat the log as compromised; do not accept either head "
                  "until the fork is investigated",
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
    "WITNESS_REQUIRED_UNMET": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "the signed policy requires witness evidence "
                  "(witness_required) but the bundle carries no witness "
                  "entry",
        "remedy": "witness the bundle with the policy-pinned witness "
                  "log, or re-issue the policy without "
                  "witness_required; the requirement is never silently "
                  "dropped",
    },
    "witness-consistency-missing": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "the signed policy configures the witness-consistency "
                  "mode but the bundle carries no consistency evidence",
        "remedy": "attach the cosigned head note and the consistency proof "
                  "from the accepted head, or re-issue the policy without "
                  "the witness_consistency section; configured means "
                  "required",
    },
    "witness-quorum-unmet": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "fewer than quorum_k distinct configured witnesses "
                  "cosigned the log head",
        "remedy": "collect cosignatures from the policy-pinned witnesses "
                  "until the quorum is met; the head is accepted only with "
                  "the policy's witness quorum",
    },
    "witness-unreachable": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "a configured witness reported no view during gossip",
        "remedy": "retry once the witness is reachable; silence refuses, "
                  "never passes",
    },
    "witness-checkpoint-stale": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "the checkpoint note is older than the freshness window, "
                  "is dated in the future vs the observed time, or carries "
                  "no issuance timestamp",
        "remedy": "fetch a fresh checkpoint from the witness log within "
                  "the policy's max_checkpoint_age",
    },
    # -- trust-root chain (45; wave-318) --
    "trust-root-chain-malformed": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "the versioned trust-root chain is structurally invalid: "
                  "empty, versions not strictly consecutive from v1, content "
                  "hash mismatch, or bad pin fields",
        "remedy": "re-export the chain from the rotation ceremony records; "
                  "never hand-edit chain JSON",
    },
    "trust-root-rotation-invalid": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "the rotation ceremony record is invalid: bad version "
                  "link, hash mismatch, future review date, reviewed "
                  "outside the signing root's window, or not signed by the "
                  "old root's keys",
        "remedy": "re-run the rotation ceremony with the old root's keys; "
                  "rotation is a policy ceremony, never a silent swap",
    },
    "trust-root-silent-swap": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "a chain link was adopted without a rotation record",
        "remedy": "adopt the new root through a signed rotation record; "
                  "silent root swaps are refused",
    },
    "trust-root-stale-freshness": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "the trust-root freshness signal is missing, stale, "
                  "future-dated, for the wrong chain version, or not signed "
                  "by the tip root's keys",
        "remedy": "re-issue the freshness statement with the tip root's "
                  "keys within the freshness window",
    },
    "trust-root-expired": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "the chain tip was not valid at the bundle timestamp's "
                  "time (expiry is evaluated at the timestamp's time, "
                  "chain-wide)",
        "remedy": "rotate the trust root through the ceremony and "
                  "re-verify; bundles timestamped outside the root's "
                  "window are refused",
    },
    "trust-root-receipt-unbound": {
        "exit": EXIT_POLICY, "category": "policy",
        "reason": "a witness receipt does not bind the artifact digest, "
                  "signature, and signer key (CVE-2026-22703: never accept "
                  "'a valid receipt' alone)",
        "remedy": "present the receipt issued for this exact "
                  "artifact/signature/key triple",
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
_witness_log()


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
                              witness_entries=(),
                              consistency_evidence=None):
    """Assemble the inline verification bundle (the narrow input).

    ``envelope``: DSSE envelope over the in-toto statement.
    ``policy_envelope``: DSSE envelope over the signed policy.
    ``timestamps``: observer-timestamp tokens (may be empty).
    ``witness_entries``: log-backed witness entries
    (``sasanam-witness-log/v1``, see :func:`seal_witness_entry`); each
    is verified checkpoint-first by :func:`verify`. Unknown entry kinds
    are refused coded, never skipped.
    ``consistency_evidence``: optional ``{"head_note_b64": str,
    "consistency_proof": [hex, ...]}`` for the witness-consistency
    stage (wave-319 lane 3); omitted entirely when None so legacy
    bundles are byte-identical.
    """
    for name, doc in (("envelope", envelope),
                      ("policy_envelope", policy_envelope)):
        if not isinstance(doc, dict):
            raise InternalError("%s must be a dict" % name)
    bundle = {
        "version": BUNDLE_VERSION,
        "envelope": envelope,
        "policy": policy_envelope,
        "timestamps": list(timestamps),
        "witness_entries": list(witness_entries),
    }
    if consistency_evidence is not None:
        if not isinstance(consistency_evidence, dict):
            raise InternalError("consistency_evidence must be a dict")
        bundle["consistency_evidence"] = dict(consistency_evidence)
    return bundle


def seal_witness_entry(witness_log, witness_signer, *, artifact_digest,
                       signatures, verified_keyids, policy_digest,
                       integrated_time=None):
    """Append a witness entry for a verified bundle to the log.

    Producer-side helper (the sealer that feeds :func:`verify`'s
    witness stage). The caller must have ALREADY verified the envelope
    (threshold signatures over the exact payload bytes): this function
    binds the GIVEN values into the entry body, it does not re-verify
    them.

    ``witness_log``: a ``gov.witness_log.WitnessLog`` (loaded here by
    file path, like the Ed25519 primitive). ``witness_signer``: the
    log's witness key (``.public_key`` 32 bytes, ``.sign(bytes)``).
    ``artifact_digest``: hex sha256 of the exact artifact bytes.
    ``signatures``: the envelope's EXACT wire signature entries
    (``[{"keyid", "sig"}, ...]`` as delivered). ``verified_keyids``:
    the keyids that met the policy threshold. ``policy_digest``: hex
    sha256 of the canonical policy document that authorized the keys
    (binds WHICH policy). ``integrated_time``: unix seconds (default:
    now, UTC).

    The entry body (the Merkle leaf preimage) binds artifact digest +
    exact wire signatures + verified keyids + policy digest
    (CVE-2026-22703: artifact + signature + key, never "a valid entry"
    alone). Returns the wire entry dict: kind, log_index, entry_body,
    checkpoint, checkpoint_signature, inclusion_path.

    Raises InternalError on bad inputs (producer bug, loud).
    """
    wl = _witness_log()
    if witness_log.__class__.__name__ != "WitnessLog":
        raise InternalError("witness_log must be a WitnessLog")
    pub = getattr(witness_signer, "public_key", None)
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        raise InternalError("witness_signer public_key must be 32 bytes")
    if not callable(getattr(witness_signer, "sign", None)):
        raise InternalError("witness_signer needs .sign(bytes)")
    if (not isinstance(artifact_digest, str) or len(artifact_digest) != 64
            or any(c not in "0123456789abcdefABCDEF"
                   for c in artifact_digest)):
        raise InternalError("artifact_digest must be 64 hex chars")
    if (not isinstance(signatures, list) or not signatures
            or not all(isinstance(e, dict) for e in signatures)):
        raise InternalError("signatures must be a non-empty list of "
                            "wire entries")
    if (not isinstance(verified_keyids, (list, tuple))
            or not verified_keyids
            or not all(isinstance(k, str) and k for k in verified_keyids)):
        raise InternalError("verified_keyids must be a non-empty list "
                            "of str")
    if (not isinstance(policy_digest, str) or len(policy_digest) != 64
            or any(c not in "0123456789abcdefABCDEF"
                   for c in policy_digest)):
        raise InternalError("policy_digest must be 64 hex chars")
    if integrated_time is None:
        integrated_time = int(datetime.now(timezone.utc).timestamp())
    if (isinstance(integrated_time, bool)
            or not isinstance(integrated_time, int)
            or integrated_time < 0):
        raise InternalError("integrated_time must be a non-negative int")
    body = {
        "apiVersion": WITNESS_ENTRY_API_VERSION,
        "kind": WITNESS_ENTRY_BODY_KIND,
        "spec": {
            "artifactDigest": artifact_digest.lower(),
            "signatures": signatures,
            "verifiedKeyids": sorted(set(verified_keyids)),
            "policyDigest": policy_digest.lower(),
            "integratedTime": integrated_time,
        },
    }
    leaf = wl.canonical_bytes(body)
    index = witness_log.append(leaf)
    sealed = witness_log.sealed_checkpoint(integrated_time, witness_signer)
    proof = witness_log.inclusion_proof(index)
    return {
        "kind": WITNESS_ENTRY_KIND,
        "log_index": index,
        "entry_body": body,
        "checkpoint": sealed["checkpoint"],
        "checkpoint_signature": sealed["signature"],
        "inclusion_path": proof["path"],
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
    # Witness-log keys (optional section; the Rekor-pattern witness
    # step). Each key carries a validFor window, and the checkpoint's
    # time is checked against the SIGNING key's window at the
    # checkpoint's time (CVE-2026-24122 analogue; sigstore-rust PR #166
    # authority isolation). A bundle carrying witness entries with no
    # key pinned here refuses WITNESS_KEY_UNAVAILABLE.
    witness_log_keys = {}
    wlks = doc.get("witness_log_keys", [])
    if not isinstance(wlks, list):
        raise VerificationError("POLICY_MALFORMED",
                                detail="witness_log_keys must be a list")
    for wk in wlks:
        if not isinstance(wk, dict):
            raise VerificationError("POLICY_MALFORMED",
                                    detail="witness log key must be an object")
        kid = wk.get("keyid")
        if not isinstance(kid, str) or not kid:
            raise VerificationError("POLICY_MALFORMED",
                                    detail="witness log key needs a keyid")
        if kid in witness_log_keys:
            raise VerificationError("POLICY_MALFORMED",
                                    detail="duplicate witness log keyid %r"
                                           % (kid,))
        vf = wk.get("valid_for") if isinstance(wk.get("valid_for"), dict) \
            else {}
        witness_log_keys[kid] = {
            "pubkey": _check_pubkey_hex(wk.get("pubkey_hex"),
                                        "witness log key %s" % kid),
            "not_before": _parse_time(vf.get("not_before"),
                                      "policy.witness_log_key.valid_for",
                                      "POLICY_MALFORMED"),
            "not_after": _parse_time(vf.get("not_after"),
                                     "policy.witness_log_key.valid_for",
                                     "POLICY_MALFORMED"),
        }
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
    # Witness-consistency mode (optional section; wave-319 lane 3).
    # When present, the verifier runs the witness-consistency stage
    # fail-closed: quorum cosignatures + freshness + growth from the
    # accepted head. The note bytes travel as base64 (the policy is
    # JSON); the module gets raw bytes.
    wc_section = doc.get("witness_consistency")
    wc_policy = None
    if wc_section is not None:
        if not isinstance(wc_section, dict):
            raise VerificationError("POLICY_MALFORMED",
                                    detail="witness_consistency must be "
                                           "an object")
        op_vkeys = wc_section.get("operator_vkeys")
        if (not isinstance(op_vkeys, list) or not op_vkeys
                or not all(isinstance(v, str) and v for v in op_vkeys)):
            raise VerificationError("POLICY_MALFORMED",
                                    detail="witness_consistency."
                                           "operator_vkeys must be a "
                                           "non-empty list of str")
        wit_vkeys = wc_section.get("witness_vkeys")
        if (not isinstance(wit_vkeys, dict) or not wit_vkeys
                or not all(isinstance(k, str) and k
                           and isinstance(v, str) and v
                           for k, v in wit_vkeys.items())):
            raise VerificationError("POLICY_MALFORMED",
                                    detail="witness_consistency."
                                           "witness_vkeys must be a "
                                           "non-empty {name: vkey} map")
        quorum_k = wc_section.get("quorum_k")
        if (isinstance(quorum_k, bool) or not isinstance(quorum_k, int)
                or quorum_k < 1):
            raise VerificationError("POLICY_MALFORMED",
                                    detail="witness_consistency.quorum_k "
                                           "must be a positive int")
        max_age = wc_section.get("max_checkpoint_age")
        if (isinstance(max_age, bool) or not isinstance(max_age, int)
                or max_age <= 0):
            raise VerificationError("POLICY_MALFORMED",
                                    detail="witness_consistency."
                                           "max_checkpoint_age must be "
                                           "a positive int")
        head = wc_section.get("accepted_head")
        # accepted_head is OPTIONAL (spec): the pinned previous checkpoint
        # for growth proofs. Absent -> quorum + freshness still enforced,
        # but there is no growth to prove.
        accepted_head = None
        if head is not None:
            if not isinstance(head, dict):
                raise VerificationError("POLICY_MALFORMED",
                                        detail="witness_consistency."
                                               "accepted_head must be an "
                                               "object")
            head_b64 = head.get("note_b64")
            if not isinstance(head_b64, str):
                raise VerificationError("POLICY_MALFORMED",
                                        detail="witness_consistency."
                                               "accepted_head.note_b64 must "
                                               "be a str")
            try:
                head_note = base64.b64decode(head_b64.encode("ascii"),
                                             validate=True)
            except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
                raise VerificationError("POLICY_MALFORMED",
                                        detail="witness_consistency."
                                               "accepted_head.note_b64 is "
                                               "not valid base64: %s" % (exc,))
            if not head_note:
                raise VerificationError("POLICY_MALFORMED",
                                        detail="witness_consistency."
                                               "accepted_head.note_b64 must "
                                               "decode to non-empty bytes")
            accepted_head = {"note": head_note}
        wc_policy = {"operator_vkeys": list(op_vkeys),
                     "witness_vkeys": dict(wit_vkeys),
                     "quorum_k": quorum_k,
                     "max_checkpoint_age": max_age,
                     "accepted_head": accepted_head}
    return {
        "policy_id": pid,
        "expires": expires,
        "threshold": threshold,
        "evidence_keys": ev_keys,
        "authorities": authorities,
        "witness_log_keys": witness_log_keys,
        "required_predicate_type": rpt,
        "required_predicate_claims": list(rpc),
        "min_timestamps": min_ts,
        "max_age_hours": max_age,
        "witness_required": wr,
        "witness_consistency": wc_policy,
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
# Witness stage: checkpoint-first verification of log-backed entries.
# ---------------------------------------------------------------------------

def _verify_witness_entries(witness_entries, policy, bundle_hex,
                            wire_signatures, verified_keyids,
                            policy_digest, now, checks):
    """Verify the bundle's log-backed witness entries.

    The checkpoint-first contract, in order:

    1. entry kind pin -- unknown kinds refuse UNSUPPORTED_BUNDLE_VERSION
       (never silently skipped);
    2. the signed policy must pin a witness key -- else
       WITNESS_KEY_UNAVAILABLE;
    3. the checkpoint SIGNATURE is verified FIRST, against the
       policy-pinned key named by the checkpoint's logId;
    4. tree_size/root_hash/timestamp are parsed ONLY from the verified
       checkpoint -- duplicated copies anywhere else are IGNORED
       (sigstore-python#248: an unpinned root hash verifies against any
       log);
    5. the checkpoint time is inside the signing key's validFor window
       at the checkpoint's time (CVE-2026-24122 analogue) and not in
       the future vs the observed time;
    6. log_index bounds + Merkle inclusion proof against the
       checkpoint's root hash;
    7. entry-body binding: artifact digest + exact wire signatures +
       verified keyids + policy digest (CVE-2026-22703: never accept "a
       valid entry" alone).

    Returns the witness info dict for the VSA-shaped report. Every
    failure raises the typed VerificationError with the checks done so
    far.
    """
    wl = _witness_log()

    def _fail(code, **kw):
        raise VerificationError(code, checks=checks, **kw)

    if not witness_entries:
        _fail("WITNESS_REQUIRED_UNMET",
              expected=">= 1 witness entry (policy witness_required)",
              actual="bundle carries no witness entries")
    if len(witness_entries) != 1:
        _fail("BUNDLE_MALFORMED",
              detail="witness_entries: exactly one entry supported "
                     "(multi-entry bundles are a documented residual), "
                     "got %d" % len(witness_entries))
    entry = witness_entries[0]
    if not isinstance(entry, dict) or entry.get("kind") != WITNESS_ENTRY_KIND:
        _fail("UNSUPPORTED_BUNDLE_VERSION",
              expected=WITNESS_ENTRY_KIND,
              actual=(entry.get("kind") if isinstance(entry, dict)
                      else type(entry).__name__),
              detail="unknown witness entry kind refused")

    keys = policy["witness_log_keys"]
    if not keys:
        _fail("WITNESS_KEY_UNAVAILABLE",
              detail="the bundle carries a witness entry but the signed "
                     "policy names no witness_log_keys")
    cp = entry.get("checkpoint")
    log_id = cp.get("logId") if isinstance(cp, dict) else None
    matched = None
    for kid, key in keys.items():
        if hashlib.sha256(key["pubkey"]).hexdigest() == log_id:
            matched = (kid, key)
            break
    if matched is None:
        _fail("WITNESS_CHECKPOINT_INVALID",
              detail="checkpoint logId %r names no policy witness key"
                     % (log_id,))
    keyid, key = matched

    # --- checkpoint signature FIRST, before parsing anything ---
    try:
        verified_cp = wl.verify_checkpoint(
            {"checkpoint": cp,
             "signature": entry.get("checkpoint_signature")},
            key["pubkey"])
    except wl.WitnessError as exc:
        _fail("WITNESS_CHECKPOINT_INVALID",
              detail="checkpoint rejected: [%s] %s" % (exc.code,
                                                      exc.detail))
    # --- sizes/hashes ONLY from the verified checkpoint ---
    tree_size = verified_cp["treeSize"]
    root_hash = bytes.fromhex(verified_cp["rootHash"])
    cp_time = datetime.fromtimestamp(verified_cp["timestamp"],
                                     tz=timezone.utc)
    # Authority isolation (sigstore-rust PR #166): the window belongs
    # to THIS key, checked at the checkpoint's time -- never "now".
    if not (key["not_before"] <= cp_time <= key["not_after"]):
        _fail("WITNESS_CHECKPOINT_INVALID",
              expected="checkpoint time inside witness key validFor "
                       "[%s, %s]" % (key["not_before"].isoformat(),
                                     key["not_after"].isoformat()),
              actual=cp_time.isoformat(),
              detail="checkpoint outside the signing key's window at "
                     "checkpoint time (CVE-2026-24122 analogue)")
    if cp_time > now:
        _fail("TEMPORAL_UNSATISFIED",
              expected="checkpoint time <= observed time",
              actual=cp_time.isoformat(),
              detail="witness checkpoint timestamp in the future")

    log_index = entry.get("log_index")
    if (isinstance(log_index, bool) or not isinstance(log_index, int)
            or log_index < 0 or log_index >= tree_size):
        _fail("WITNESS_INCLUSION_INVALID",
              expected="0 <= log_index < tree_size (%d)" % tree_size,
              actual=repr(log_index))

    body = entry.get("entry_body")
    if not isinstance(body, dict):
        _fail("WITNESS_ENTRY_UNBOUND",
              detail="entry_body must be an object")
    try:
        leaf = wl.canonical_bytes(body)
    except wl.WitnessError as exc:
        _fail("WITNESS_ENTRY_UNBOUND",
              detail="entry_body not canonical-serializable: [%s] %s"
                     % (exc.code, exc.detail))
    try:
        wl.verify_inclusion(leaf, log_index, entry.get("inclusion_path"),
                            tree_size, root_hash)
    except wl.WitnessError as exc:
        _fail("WITNESS_INCLUSION_INVALID",
              detail="inclusion proof rejected: [%s] %s" % (exc.code,
                                                            exc.detail))

    # --- entry-body binding (CVE-2026-22703) ---
    spec = body.get("spec")
    if not isinstance(spec, dict):
        _fail("WITNESS_ENTRY_UNBOUND", detail="entry_body.spec missing")
    if (body.get("kind") != WITNESS_ENTRY_BODY_KIND
            or body.get("apiVersion") != WITNESS_ENTRY_API_VERSION):
        _fail("WITNESS_ENTRY_UNBOUND",
              expected="%s/%s" % (WITNESS_ENTRY_BODY_KIND,
                                  WITNESS_ENTRY_API_VERSION),
              actual="%r/%r" % (body.get("kind"),
                                body.get("apiVersion")))
    if (not isinstance(spec.get("artifactDigest"), str)
            or spec["artifactDigest"].lower() != bundle_hex.lower()):
        _fail("WITNESS_ENTRY_UNBOUND",
              expected="artifactDigest %s" % bundle_hex,
              actual=repr(spec.get("artifactDigest")),
              detail="entry does not bind this bundle's artifact digest")
    try:
        sig_match = (wl.canonical_bytes(spec.get("signatures"))
                     == wl.canonical_bytes(wire_signatures))
    except wl.WitnessError:
        sig_match = False
    if not sig_match:
        _fail("WITNESS_ENTRY_UNBOUND",
              detail="entry does not bind this bundle's exact wire "
                     "signatures")
    vk = spec.get("verifiedKeyids")
    vk_ok = (isinstance(vk, list)
             and all(isinstance(k, str) for k in vk)
             and sorted(vk) == sorted(verified_keyids))
    if not vk_ok:
        _fail("WITNESS_ENTRY_UNBOUND",
              expected="verifiedKeyids %r" % (sorted(verified_keyids),),
              actual=repr(vk),
              detail="entry does not bind the threshold-verified keys")
    if (not isinstance(spec.get("policyDigest"), str)
            or spec["policyDigest"].lower() != policy_digest.lower()):
        _fail("WITNESS_ENTRY_UNBOUND",
              expected="policyDigest %s" % policy_digest,
              actual=repr(spec.get("policyDigest")),
              detail="entry does not bind the authorizing policy")
    it = spec.get("integratedTime")
    if (isinstance(it, bool) or not isinstance(it, int) or it < 0
            or it > verified_cp["timestamp"]):
        _fail("WITNESS_ENTRY_UNBOUND",
              expected="integratedTime <= checkpoint timestamp (%d)"
                       % verified_cp["timestamp"],
              actual=repr(it),
              detail="entry time incoherent with its checkpoint "
                     "(backdated)")

    return {
        "entries": 1,
        "kind": WITNESS_ENTRY_KIND,
        "log_id": verified_cp["logId"],
        "witness_keyid": keyid,
        "tree_size": tree_size,
        "root_hash": verified_cp["rootHash"].lower(),
        "log_index": log_index,
        "integrated_time": _fmt_time(cp_time),
        "time_source": "witness checkpoint (signed)",
    }


# ---------------------------------------------------------------------------
# The pipeline (9 steps + conditional witness step).
# ---------------------------------------------------------------------------

def _fmt_time(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify(bundle_bytes, verification_bundle, trust_root=None,
           time_source=None, existence_only=False, trust_chain=None,
           chain_freshness=None, chain_max_age_seconds=86400):
    """Verify an evidence bundle offline; return the verification report.

    Narrow inputs: ``bundle_bytes`` (the canonical artifact bytes),
    ``verification_bundle`` (the inline bundle dict, or its JSON
    bytes), ``trust_root`` (None -> the compiled-in, SHA-256-pinned
    root; a dict -> caller-supplied, recorded in the transcript),
    ``time_source`` (a NAMED clock -- None fails closed: no trusted
    time), ``existence_only`` (labeled mode; never defaulted).

    Optional trust-root chain discipline (additive; when ``trust_chain``
    is None the pipeline is unchanged): ``trust_chain`` (a versioned
    chain as built by ``gov.trust_root_refresh``), ``chain_freshness``
    (its freshness statement), ``chain_max_age_seconds`` (freshness
    window). The chain tip becomes the authority: rotation records are
    checked, freshness must hold at verification time, and the tip's
    validity window must cover the bundle timestamp's time (checked at
    the timestamp's time, per CVE-2026-24122 -- a bundle timestamped
    inside the window still verifies after the root expired). Any chain
    failure raises a coded ``trust-root-*`` VerificationError.
    ``trust_root`` and ``trust_chain`` together are an InternalError
    (ambiguous anchor): the chain tip is the authority, never silently
    preferred over an explicit root.

    Returns the VSA-shaped report dict on success. Raises the typed
    :class:`VerificationError` on any check failure, or
    :class:`InternalError` when the verifier itself is broken.
    Zero network I/O on this path by construction.

    Wave-338 (R15): the report carries ``notVerified`` -- the stages
    the pipeline did NOT evaluate this run (trust-chain, witness,
    witness-consistency, predicate content under existence-only, the
    schema-2.0 extension gate on legacy bundles), each with its
    bypass reason. The human transcript prints them after the pass
    list. PASSED stays evidence input (PASSED != ALLOW); the blind
    spots are part of the verdict, not footnotes.
    """
    checks = []

    # Wave-338 (R15, Bernstein #5069 "the panel lists what a run did not
    # cover"): stages the pipeline did NOT evaluate are recorded as
    # machine-readable blind spots on the VSA summary alongside the
    # passes -- verificationResult PASSED is evidence input, and the
    # report must name its own coverage honestly.
    not_verified = []

    def _skip(stage, reason):
        not_verified.append({"stage": stage, "reason": reason})

    def _pass(step, detail):
        checks.append({"step": step, "result": "pass", "detail": detail})

    def _fail(code, **kw):
        raise VerificationError(code, checks=checks, **kw)

    # -- verifier integrity first: the pin on the compiled-in root --
    if trust_chain is not None:
        if trust_root is not None:
            raise InternalError(
                "trust_root and trust_chain are mutually exclusive: "
                "the chain tip is the authority")
        root_doc = None  # resolved from the chain after the clock check
        root_source = "trust-chain"
    elif trust_root is None:
        root_doc = compiled_trust_root()
        root_source = "compiled-in"
    else:
        if not isinstance(trust_root, dict):
            raise InternalError("trust_root must be a dict or None")
        root_doc = trust_root
        root_source = "caller-supplied"
    if root_doc is not None:
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

    # -- trust-root chain (optional, additive): versioned rotation --
    # Structure + freshness are checked here (they need the clock); the
    # tip's validity at the bundle timestamp's time is checked after the
    # timestamps step (step 8), when the bundle's attested time is known.
    chain_tip = None
    if trust_chain is not None:
        trr = _trust_root_refresh()
        try:
            chain_tip = trr.verify_chain_structure(
                trust_chain, freshness=chain_freshness, now=now,
                max_age_seconds=chain_max_age_seconds)
        except trr.TrustRootError as exc:
            _fail(exc.code, detail=exc.detail)
        root_doc = chain_tip["root_doc"]
        root_source = "trust-chain v%d" % chain_tip["chain_version"]
        root_keys = _check_trust_root_shape(root_doc)
        root_digest = hashlib.sha256(canonical(root_doc)).hexdigest()
        _pass("trust-chain",
              "v1..v%d valid; freshness fresh at %s; authority is the "
              "tip root (content %s)"
              % (chain_tip["chain_version"], _fmt_time(now),
                 chain_tip["content_hash"][:16]))
    else:
        # R15: no versioned chain supplied -- rotation + freshness are
        # NOT evaluated; the compiled-in or caller-supplied root was
        # used as-is.
        _skip("trust-chain",
              "no versioned trust-root chain supplied: rotation and "
              "freshness not evaluated (root used as-is)")
        _skip("trust-chain-expiry",
              "no versioned trust-root chain supplied: tip validity at "
              "bundle time not evaluated")

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
    # The witness stage runs after the policy is authenticated (its
    # keys come from the signed policy); unknown entry kinds are
    # refused coded there, never silently skipped.
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
    # Schema-2.0 extension gate (wave-318 lane 2): when the statement
    # claims evidence-schema/2.0, the AU-3 + CC8.1 extension claims are
    # validated strictly -- missing/malformed fields or a change-log gap
    # refuse coded EXTENSION_SCHEMA_INVALID. Bundles without the 2.0
    # claim take the legacy path unchanged (backward compat). Skipped in
    # existence-only mode like all other predicate-CONTENT evaluation.
    v2_note = ""
    if not existence_only and statement["predicate"].get(
            "evidence_schema_version") == \
            _schema_v2().EVIDENCE_SCHEMA_V2:
        try:
            _schema_v2().validate_v2_claims(statement["predicate"])
        except _schema_v2().SchemaV2Error as exc:
            _fail("EXTENSION_SCHEMA_INVALID", detail=str(exc))
        v2_note = (" + schema-2.0 extension "
                   "(au3_records, decision_maker_versions, "
                   "change-log consistent)")
    _pass("predicate",
          "%s%s%s" % (policy["required_predicate_type"],
                    " (existence-only: content not evaluated)"
                    if existence_only else
                    " + %d required claim(s)"
                    % len(policy["required_predicate_claims"]),
                    v2_note))
    # R15: predicate content not evaluated in existence-only mode, and
    # the schema-2.0 extension gate not evaluated on legacy bundles --
    # the report names both blind spots.
    if existence_only:
        _skip("predicate-content",
              "existence-only mode: signature and binding verified; "
              "predicate content NOT evaluated")
    elif statement["predicate"].get("evidence_schema_version") != \
            _schema_v2().EVIDENCE_SCHEMA_V2:
        _skip("schema-2.0-extension",
              "statement does not claim evidence-schema/2.0: legacy "
              "predicate rules applied; AU-3/CC8.1 extension claims not "
              "validated")

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

    # -- trust-chain expiry (conditional): at the timestamp's time --
    # The bundle's attested time is the earliest verified observer
    # timestamp when present, else the trusted now (tokens were verified
    # in the step above, so re-parsing their times here is safe).
    # CVE-2026-24122: the tip's validity window is evaluated at the
    # TIMESTAMP's time -- a bundle timestamped inside the window still
    # verifies after the root expired (designed grace); a bundle
    # timestamped outside it is refused.
    if trust_chain is not None:
        ts_times = []
        for tok in vb.get("timestamps", []):
            ts_times.append(_parse_time(tok["time"], "timestamp.time",
                                        "TIMESTAMP_SIGNATURE_INVALID"))
        bundle_ts = min(ts_times) if ts_times else now
        trr = _trust_root_refresh()
        try:
            trr.check_expiry(chain_tip, bundle_ts)
        except trr.TrustRootError as exc:
            _fail(exc.code, detail=exc.detail)
        _pass("trust-chain-expiry",
              "tip root v%d valid at bundle time %s (expiry evaluated at "
              "the timestamp's time)"
              % (chain_tip["chain_version"], _fmt_time(bundle_ts)))

    # -- witness step (conditional): runs only when the bundle carries
    # witness entries or the signed policy requires them. The 9 base
    # steps above are unchanged otherwise.
    witness_info = None
    if witness_entries or policy["witness_required"]:
        witness_info = _verify_witness_entries(
            witness_entries, policy, bundle_hex,
            vb["envelope"]["signatures"], verified_keyids,
            policy_digest, now, checks)
        _pass("witness",
              "log-backed entry verified checkpoint-first: checkpoint "
              "signature, inclusion proof vs checkpoint root, entry "
              "bound to artifact digest + signatures + keys (log %s, "
              "tree_size %d, index %d)"
              % (witness_info["log_id"][:16], witness_info["tree_size"],
                 witness_info["log_index"]))
    else:
        # R15: no witness anchoring evaluated for this run.
        _skip("witness",
              "bundle carries no witness entries and the signed policy "
              "does not require witness anchoring: log-backed "
              "consistency not evaluated")

    # -- witness-consistency stage (conditional, wave-319 lane 3):
    # runs only when the signed policy configures the
    # witness_consistency mode. Optional-but-fail-closed: a configured
    # mode with missing evidence refuses coded (never silently
    # skipped). Bundles without the policy section keep the exact
    # legacy behavior above.
    wc_info = None
    if policy["witness_consistency"] is None:
        # R15: witness-consistency mode not evaluated for this run.
        _skip("witness-consistency",
              "signed policy configures no witness-consistency mode: "
              "witness cosignature quorum and log-growth proof not "
              "evaluated")
    if policy["witness_consistency"] is not None:
        wc = _witness_consistency()
        raw_ev = vb.get("consistency_evidence")
        ev = {}
        if isinstance(raw_ev, dict):
            ev = dict(raw_ev)
            head_b64 = ev.get("head_note_b64")
            if isinstance(head_b64, str):
                try:
                    ev["head_note"] = base64.b64decode(
                        head_b64.encode("ascii"), validate=True)
                except (binascii.Error, ValueError,
                        UnicodeEncodeError) as exc:
                    _fail("WITNESS_NOTE_MALFORMED",
                          detail="consistency_evidence.head_note_b64 is "
                                 "not valid base64: %s" % (exc,))
        try:
            # CVE-2026-22703: bind the growth proof to the checkpoint the
            # bundle's inclusion receipt proved (witness_info carries the
            # VERIFIED checkpoint sizes/hashes from the witness stage).
            receipt_cp = None
            if isinstance(witness_info, dict):
                try:
                    receipt_cp = {
                        "treeSize": witness_info["tree_size"],
                        "rootHash": witness_info["root_hash"],
                    }
                except KeyError:
                    receipt_cp = None
            wc_info = wc.verify_witness_policy(
                policy["witness_consistency"], ev,
                now=int(now.timestamp()),
                receipt_checkpoint=receipt_cp)
        except wc.WitnessConsistencyError as exc:
            _fail(exc.code, detail=exc.detail)
        if wc_info["growth"] is None:
            _pass("witness-consistency",
                  "quorum %d/%d witness cosignatures, head fresh (age %ds), "
                  "no pinned accepted_head (steady state, no growth proof "
                  "needed)"
                  % (wc_info["cosignatures"],
                     policy["witness_consistency"]["quorum_k"],
                     wc_info["head"]["age"]))
        else:
            _pass("witness-consistency",
                  "quorum %d/%d witness cosignatures, head fresh (age %ds), "
                  "log grew %d->%d with a valid consistency proof"
                  % (wc_info["cosignatures"],
                     policy["witness_consistency"]["quorum_k"],
                     wc_info["head"]["age"],
                     wc_info["growth"]["old_size"],
                     wc_info["growth"]["new_size"]))

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
        "witness": witness_info,
        "witness_consistency": wc_info,
        # R15 (Bernstein #5069 "the panel lists what a run did not
        # cover"): stages the pipeline did NOT evaluate, each with the
        # reason it was bypassed. Empty when every conditional stage
        # ran -- a PASSED report with an empty list claims full
        # coverage honestly.
        "notVerified": not_verified,
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
    if report.get("witness"):
        w = report["witness"]
        lines.append("  witness: log %s  tree_size %d  index %d  root %s  "
                     "integrated %s"
                     % (w["log_id"][:16], w["tree_size"], w["log_index"],
                        w["root_hash"][:16], w["integrated_time"]))
    if report.get("existenceOnly"):
        lines.append("  NOTE: existence-only verification -- signature and "
                     "binding verified; predicate content NOT evaluated")
    lines.append("The following checks were performed:")
    for c in report["checks"]:
        lines.append("  [pass] %s: %s" % (c["step"], c["detail"]))
    # R15: the panel lists what the run did NOT cover -- blind spots
    # are part of the transcript, not hidden behind PASSED.
    not_verified = report.get("notVerified") or []
    if not_verified:
        lines.append("The following were NOT verified by this run:")
        for s in not_verified:
            lines.append("  [skip] %s: %s" % (s["stage"], s["reason"]))
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
