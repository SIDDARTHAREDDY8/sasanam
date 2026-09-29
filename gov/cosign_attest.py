"""Keyset-attested cosign signing for evidence bundles.

The distribution-signature half of the ORAS evidence-distribution story
(``gov.evidence_distribute`` moves bytes; this module answers *whose key*
signed them). A cosign ECDSA-P256 public key is bound to the product's
versioned keyset ceremony by a signed attestation statement
(``sasanam-cosign-key-attestation/v1``), so the cosign key behaves exactly
like every other signing key: attested by the keyset, rotating with it
(verify-only versions keep old attestations verifiable), revocable through
it (revoked versions refuse on the authorization path).

cosign itself stays a CLI dependency -- never vendored code. This module
shells to it for ``sign-blob`` / ``verify-blob`` only. The product's trust
story is the keyset, not cosign.

Attestation layout (canonical JSON, UTF-8, sorted keys, no trailing
whitespace)::

    {"format": "sasanam-cosign-key-attestation/v1",
     "cosign_public_key_pem": "-----BEGIN PUBLIC KEY-----\\n...\\n",
     "cosign_key_fingerprint": "sha256:<hex of sha256(DER of the SPKI)>",
     "attested_by": {"purpose": "cosign-key-attestation",
                     "keyset_key_id": "<8-byte hex>",
                     "keyset_version": 1,
                     "keyset_hash": "<sha256 of the keyset document as of
                                    the attesting version>"},
     "at": <unix seconds, int>,
     "envelope": {"sig_key_id": ..., "sig_key_version": 1,
                  "sig": "<hex ed25519 signature>"}}

The envelope signature covers the domain
``b"sasanam-cosign-key-attestation/v1\\0"`` plus the canonical statement
(everything except ``envelope``). The verifying key is resolved via
``Keyset.find_verifying_key`` on the envelope -- revoked versions refuse
on the standard path, verify-only versions verify; the forensics path
(``attribute_bundle_signature``) resolves revoked versions for
attribution only.

``attested_by.keyset_hash`` pins the keyset document hash
(``Keyset.keyset_hash()``) *as of the attesting version*. The spec
requires rotation to keep attestations verifiable (R1a/R1b), but the
live document hash changes on every rotation -- so after rotation the
expected value is recovered from the rotation lineage, whose records
preserve each pre-rotation ``prev_keyset_hash`` (versions are dense
from 1, so the record retiring version ``v`` sits at lineage index
``v-1``). The lineage is hash-chained and checked by
``Keyset.verify()`` before the pin is consulted, so history cannot be
rewritten without breaking the chain. This keeps the field literal --
it is the keyset's hash, not a derived value -- while staying
rotation-stable. Silent keyset substitution still fails at this pin.

Heterogeneity (per the spec): cosign keys are ECDSA-P256 -- cosign's
``generate-key-pair`` offers no Ed25519 option. The verifier refuses any
PEM whose SPKI algorithm is not ECDSA-P256; the repo's product
signatures stay Ed25519. The cosign signature is the *transport*
signature over the bundle tar; the keyset's Ed25519 signatures are the
*product attestations* naming that transport key.

Offline-signing contract: ``sign_bundle_blob`` always passes
``--use-signing-config=false`` (hardcoded in the argv, never a
parameter) so the TUF-provided service-URL config (RFC3161 timestamp
authority etc.) is disabled -- no TSA timestamp authority is silently
depended on. KNOWN LIMITATION (verified 2026-09-29, cosign v3.1.3):
the flag does NOT stop ``sign-blob`` from attempting a Rekor
transparency-log upload (goroutine stack: ``sigstore-go`` transparency
-> Rekor client); where Rekor is unreachable the CLI hangs until the
timeout below fires and the call fails LOUD and closed. "Offline"
therefore means "no hosted-service trust dependency", not "zero
packets". The disclosed consequence: there is no independent
timestamp authority on the signature; long-term verifiability rests
on the bundle signature plus the product's transparency-log
anchoring.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time

from . import ed25519 as _ed
from .keyset import (
    Keyset,
    KeysetError,
    keyset_signer_for_version,
)

__all__ = [
    "ATTESTATION_FORMAT",
    "ATTESTATION_DOMAIN",
    "ATTESTATION_PURPOSE",
    "CosignAttestationError",
    "pem_to_der",
    "cosign_key_fingerprint",
    "keyset_hash_at_version",
    "attest_cosign_key",
    "verify_attestation",
    "sign_bundle_blob",
    "verify_bundle_blob",
    "authorize_bundle_signature",
    "attribute_bundle_signature",
]

ATTESTATION_FORMAT = "sasanam-cosign-key-attestation/v1"
ATTESTATION_DOMAIN = b"sasanam-cosign-key-attestation/v1\x00"
ATTESTATION_PURPOSE = "cosign-key-attestation"

_STATEMENT_FIELDS = frozenset({
    "format", "cosign_public_key_pem", "cosign_key_fingerprint",
    "attested_by", "at", "envelope",
})
_ATTESTED_BY_FIELDS = frozenset({
    "purpose", "keyset_key_id", "keyset_version", "keyset_hash",
})
_ENVELOPE_FIELDS = frozenset({"sig_key_id", "sig_key_version", "sig"})

# DER prefix of an ECDSA-P256 SubjectPublicKeyInfo:
#   SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING }
# (27 bytes) followed by 0x04 + 64 bytes of uncompressed point.
_P256_SPKI_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004")
_P256_SPKI_LEN = 91

# The offline flag is part of the product contract, not a caller option.
_OFFLINE_FLAG = "--use-signing-config=false"

_DEFAULT_TIMEOUT_S = 120


class CosignAttestationError(Exception):
    """Any attestation, pipeline, or cosign-CLI failure (all fail closed)."""


def _canonical(obj):
    """Deterministic JSON for signing (same recipe as gov/keyset)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _require_int(value, what):
    if isinstance(value, bool) or not isinstance(value, int) \
            or value < 0:
        raise CosignAttestationError("%s must be an integer >= 0" % what)
    return value


def pem_to_der(pem_text):
    """Strict PEM -> DER for one ``PUBLIC KEY`` block (fail-closed).

    Refuses anything that is not exactly one SubjectPublicKeyInfo PEM
    block: missing armor, extra blocks, or undecodable base64.
    """
    if not isinstance(pem_text, str):
        raise CosignAttestationError("cosign public key must be PEM text")
    lines = [ln.strip() for ln in pem_text.strip().splitlines()
             if ln.strip()]
    if len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----" \
            or lines[-1] != "-----END PUBLIC KEY-----":
        raise CosignAttestationError(
            "cosign public key is not a single PUBLIC KEY PEM block")
    for ln in lines[1:-1]:
        if ln.startswith("-----"):
            raise CosignAttestationError(
                "cosign public key carries more than one PEM block")
    try:
        return base64.b64decode("".join(lines[1:-1]), validate=True)
    except (ValueError, base64.binascii.Error) as e:
        raise CosignAttestationError(
            "cosign public key PEM is not valid base64: %s" % e)


def _check_p256_spki(der):
    """Refuse any SPKI whose algorithm is not ECDSA-P256 (spec: no
    algorithm agility -- the spike verified one algorithm)."""
    if len(der) != _P256_SPKI_LEN or \
            der[:len(_P256_SPKI_PREFIX)] != _P256_SPKI_PREFIX:
        raise CosignAttestationError(
            "cosign public key is not ECDSA-P256 (refusing non-P-256 "
            "key material)")


def cosign_key_fingerprint(pem_text):
    """``sha256:<hex>`` of the DER-encoded SubjectPublicKeyInfo.

    The fingerprint is *derived* from the PEM, never the other way
    around: verifiers re-derive it and compare.
    """
    der = pem_to_der(pem_text)
    _check_p256_spki(der)
    return "sha256:" + hashlib.sha256(der).hexdigest()


def keyset_hash_at_version(keyset, version):
    """The keyset's full-document hash as of ``version``.

    At mint time this is the live ``Keyset.keyset_hash()`` (minting
    requires the version to be active, hence latest). After later
    rotations the historical value is recovered from the rotation
    lineage: each record preserves the pre-rotation
    ``prev_keyset_hash``, and versions are dense from 1, so the record
    retiring version ``v`` is at lineage index ``v-1``. Callers must
    run ``Keyset.verify()`` on the document first -- the lineage is
    hash-chained, so history cannot be rewritten without breaking it.

    Raises :class:`gov.keyset.KeysetError` for an unknown version.
    """
    kv = keyset.version(version)  # KeysetError when unknown
    latest = keyset.primary_version
    if kv.version == latest:
        return keyset.keyset_hash()
    lineage = keyset.to_dict().get("rotation_lineage", [])
    idx = kv.version - 1
    if idx < 0 or idx >= len(lineage):
        raise KeysetError(
            "no rotation record retires keyset version %d" % kv.version)
    rec = lineage[idx]
    prev = rec.get("prev_keyset_hash")
    if not isinstance(prev, str) or len(prev) != 64:
        raise KeysetError(
            "rotation record %d has a malformed prev_keyset_hash" % idx)
    return prev


def attest_cosign_key(keyset, cosign_public_key_pem, seed, *,
                      version=None, at=None):
    """Mint an attestation statement for a cosign public key.

    The signing handle is minted via
    ``keyset_signer_for_version`` -- a revoked or verify-only
    version's seed is refused here (retired material cannot mint new
    attestations), as is a seed that does not match the version's key.
    The keyset's purpose must be ``cosign-key-attestation``.

    Returns the attestation statement as a dict (public material).
    """
    if not isinstance(keyset, Keyset):
        raise CosignAttestationError("keyset must be a gov.keyset.Keyset")
    if keyset.purpose != ATTESTATION_PURPOSE:
        raise CosignAttestationError(
            "keyset purpose %r cannot attest cosign keys (need %r)"
            % (keyset.purpose, ATTESTATION_PURPOSE))
    # Strict PEM + P-256 + fingerprint, before any signing happens.
    fingerprint = cosign_key_fingerprint(cosign_public_key_pem)
    if version is None:
        version = keyset.primary_version
    try:
        signer = keyset_signer_for_version(keyset, version, seed)
    except KeysetError as e:
        raise CosignAttestationError(
            "cannot mint an attestation signing handle: %s" % e)
    stamp = int(time.time()) if at is None else _require_int(at, "'at'")
    body = {
        "format": ATTESTATION_FORMAT,
        "cosign_public_key_pem": cosign_public_key_pem,
        "cosign_key_fingerprint": fingerprint,
        "attested_by": {
            "purpose": keyset.purpose,
            "keyset_key_id": signer.key_id,
            "keyset_version": signer.key_version,
            "keyset_hash": keyset_hash_at_version(keyset,
                                                  signer.key_version),
        },
        "at": stamp,
    }
    sig = signer.sign(ATTESTATION_DOMAIN + _canonical(body)).hex()
    body["envelope"] = {
        "sig_key_id": signer.key_id,
        "sig_key_version": signer.key_version,
        "sig": sig,
    }
    return body


def _statement_error(reason):
    return False, reason


def verify_attestation(attestation, keyset_doc, *, forensics=False):
    """Verify an attestation statement against a keyset document.

    Steps: structure (exact fields, exact format match) -> keyset
    parse + purpose + lineage -> attested_by/envelope consistency ->
    keyset-hash pin (historical document hash; see module docstring) ->
    envelope key resolution (``find_verifying_key``; revoked refuses
    unless ``forensics``) -> Ed25519 signature over domain + canonical
    statement -> PEM is ECDSA-P256 -> fingerprint re-derivation matches.

    Returns ``(True, details)`` or ``(False, reason)``; never raises.
    """
    # -- structure -----------------------------------------------------
    if not isinstance(attestation, dict):
        return _statement_error("attestation is not a mapping")
    unknown = set(attestation) - _STATEMENT_FIELDS
    if unknown:
        return _statement_error("attestation carries unknown fields: %s"
                                % sorted(unknown))
    if set(attestation) != _STATEMENT_FIELDS:
        return _statement_error(
            "attestation missing fields: %s"
            % sorted(_STATEMENT_FIELDS - set(attestation)))
    if attestation["format"] != ATTESTATION_FORMAT:
        return _statement_error(
            "attestation format %r is not %r (exact match required)"
            % (attestation.get("format"), ATTESTATION_FORMAT))
    pem = attestation["cosign_public_key_pem"]
    claimed_fp = attestation["cosign_key_fingerprint"]
    if not isinstance(pem, str):
        return _statement_error("cosign_public_key_pem is not text")
    if not isinstance(claimed_fp, str) or not claimed_fp.startswith(
            "sha256:") or len(claimed_fp) != 71:
        return _statement_error("cosign_key_fingerprint is malformed")
    try:
        _require_int(attestation["at"], "'at'")
    except CosignAttestationError as e:
        return _statement_error(str(e))

    att_by = attestation["attested_by"]
    if not isinstance(att_by, dict):
        return _statement_error("attested_by is not a mapping")
    unknown = set(att_by) - _ATTESTED_BY_FIELDS
    if unknown:
        return _statement_error("attested_by carries unknown fields: %s"
                                % sorted(unknown))
    if set(att_by) != _ATTESTED_BY_FIELDS:
        return _statement_error(
            "attested_by missing fields: %s"
            % sorted(_ATTESTED_BY_FIELDS - set(att_by)))
    if att_by["purpose"] != ATTESTATION_PURPOSE:
        return _statement_error(
            "attested_by purpose %r is not %r"
            % (att_by.get("purpose"), ATTESTATION_PURPOSE))
    if not isinstance(att_by["keyset_key_id"], str) \
            or not att_by["keyset_key_id"]:
        return _statement_error("attested_by.keyset_key_id is not text")
    av = att_by["keyset_version"]
    if isinstance(av, bool) or not isinstance(av, int) or av < 1:
        return _statement_error("attested_by.keyset_version is not a "
                                "positive integer")
    kh = att_by["keyset_hash"]
    if not isinstance(kh, str) or len(kh) != 64:
        return _statement_error("attested_by.keyset_hash is malformed")

    env = attestation["envelope"]
    if not isinstance(env, dict):
        return _statement_error("attestation envelope is not a mapping")
    unknown = set(env) - _ENVELOPE_FIELDS
    if unknown:
        return _statement_error("envelope carries unknown fields: %s"
                                % sorted(unknown))
    if set(env) != _ENVELOPE_FIELDS:
        return _statement_error(
            "envelope missing fields: %s"
            % sorted(_ENVELOPE_FIELDS - set(env)))
    if env["sig_key_id"] != att_by["keyset_key_id"] \
            or env["sig_key_version"] != av:
        return _statement_error("envelope does not name the attested_by "
                                "key (key id / version mismatch)")

    # -- keyset ---------------------------------------------------------
    try:
        ks = Keyset.from_dict(keyset_doc)
    except KeysetError as e:
        return _statement_error("keyset document invalid: %s" % e)
    if ks.purpose != ATTESTATION_PURPOSE:
        return _statement_error(
            "keyset purpose %r cannot attest cosign keys" % ks.purpose)
    ok, err = ks.verify()
    if not ok:
        return _statement_error("keyset lineage invalid: %s" % err)

    # -- keyset-hash pin (rotation-stable via lineage; see module docstring)
    try:
        pinned = keyset_hash_at_version(ks, av)
    except KeysetError as e:
        return _statement_error("attested keyset version not in keyset: %s"
                                % e)
    if pinned != kh:
        return _statement_error(
            "attested_by.keyset_hash does not match the keyset document "
            "as of version %d (silent keyset substitution)" % av)

    # -- envelope key resolution ----------------------------------------
    if forensics:
        kv, lookup = ks.find_verifying_key_for_forensics(env)
    else:
        kv, lookup = ks.find_verifying_key(env)
    if kv is None:
        return _statement_error("envelope key lookup failed: %s" % lookup)
    if kv.version != av or kv.key_id != att_by["keyset_key_id"]:
        return _statement_error("resolved key does not match attested_by")

    # -- signature -------------------------------------------------------
    stmt = {k: v for k, v in attestation.items() if k != "envelope"}
    try:
        sig = bytes.fromhex(env["sig"])
    except (ValueError, TypeError):
        return _statement_error("envelope sig is not valid hex")
    if len(sig) != 64:
        return _statement_error("envelope sig is not 64 bytes")
    if not _ed.verify(kv.public_key, ATTESTATION_DOMAIN + _canonical(stmt),
                      sig):
        return _statement_error("attestation signature does not verify")

    # -- fingerprint binding ---------------------------------------------
    try:
        derived = cosign_key_fingerprint(pem)
    except CosignAttestationError as e:
        return _statement_error("bad cosign key material: %s" % e)
    if derived != claimed_fp:
        return _statement_error(
            "fingerprint does not match the named PEM "
            "(stale or recomputed attacker fingerprint)")

    return True, {"keyset_version": kv.version, "status": kv.status,
                  "keyset_key_id": kv.key_id, "lookup": lookup,
                  "fingerprint": claimed_fp}


# ---------------------------------------------------------------------------
# cosign CLI surface (cosign stays a CLI dependency -- never vendored)
# ---------------------------------------------------------------------------

def _cosign_bin(cosign_bin):
    if not cosign_bin or not isinstance(cosign_bin, str):
        raise CosignAttestationError("cosign binary path is not text")
    if os.path.sep in cosign_bin or (
            os.path.altsep and os.path.altsep in cosign_bin):
        if not (os.path.isfile(cosign_bin)
                and os.access(cosign_bin, os.X_OK)):
            raise CosignAttestationError(
                "cosign binary not executable: %r" % (cosign_bin,))
        return cosign_bin
    found = shutil.which(cosign_bin)
    if not found:
        raise CosignAttestationError(
            "cosign binary %r not found on PATH" % (cosign_bin,))
    return found


def _temp_file(data, suffix):
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def _run_cosign(argv, *, env_extra=None, timeout=_DEFAULT_TIMEOUT_S):
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout,
                              env=env_extra)
    except FileNotFoundError:
        raise CosignAttestationError(
            "cosign binary not found: %r" % (argv[0],))
    except subprocess.TimeoutExpired:
        raise CosignAttestationError("cosign timed out after %ds" % timeout)
    except OSError as e:
        raise CosignAttestationError("cosign failed to launch: %s" % e)
    return proc.returncode, proc.stdout, proc.stderr


def sign_bundle_blob(tar_bytes, cosign_key_path, *, password=None,
                     cosign_bin="cosign", timeout=_DEFAULT_TIMEOUT_S):
    """Sign a bundle tar with the cosign CLI (offline contract).

    ``--use-signing-config=false`` is hardcoded into the argv -- the
    product never signs with the default (online, TSA-calling) config.
    Returns the sigstore bundle bytes (v0.3 bundle JSON).

    Raises :class:`CosignAttestationError` on any failure.
    """
    if not isinstance(tar_bytes, (bytes, bytearray)) or not tar_bytes:
        raise CosignAttestationError("bundle tar bytes are empty")
    if not isinstance(cosign_key_path, str) \
            or not os.path.isfile(cosign_key_path):
        raise CosignAttestationError(
            "cosign key file not found: %r" % (cosign_key_path,))
    exe = _cosign_bin(cosign_bin)
    tar_path = _temp_file(bytes(tar_bytes), ".tar")
    bundle_path = _temp_file(b"", ".sigstore.json")
    try:
        argv = [exe, "sign-blob",
                "--key", cosign_key_path,
                "--bundle", bundle_path,
                _OFFLINE_FLAG,  # offline contract: never a caller option
                "--yes",
                tar_path]
        env = dict(os.environ)
        if password is not None:
            if not isinstance(password, str):
                raise CosignAttestationError("password must be text")
            env["COSIGN_PASSWORD"] = password
        rc, _out, err = _run_cosign(argv, env_extra=env, timeout=timeout)
        if rc != 0:
            raise CosignAttestationError(
                "cosign sign-blob failed (rc=%d): %s"
                % (rc, err.decode("utf-8", "replace")[:500]))
        with open(bundle_path, "rb") as f:
            bundle = f.read()
        if not bundle:
            raise CosignAttestationError("cosign wrote an empty bundle")
        try:
            json.loads(bundle.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise CosignAttestationError(
                "cosign bundle is not JSON: %s" % e)
        return bundle
    finally:
        for p in (tar_path, bundle_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def verify_bundle_blob(tar_bytes, sigstore_bundle_bytes,
                       cosign_public_key_pem, *, cosign_bin="cosign",
                       timeout=_DEFAULT_TIMEOUT_S):
    """Verify a bundle tar against a sigstore bundle with a cosign key.

    The PEM is parsed strictly (ECDSA-P256 only) *before* shelling --
    garbage never reaches the CLI. Returns ``(True, reason)`` or
    ``(False, reason)``; never raises.
    """
    if not isinstance(tar_bytes, (bytes, bytearray)) or not tar_bytes:
        return False, "bundle tar bytes are empty"
    if not isinstance(sigstore_bundle_bytes, (bytes, bytearray)) \
            or not sigstore_bundle_bytes:
        return False, "sigstore bundle bytes are empty"
    try:
        # The key comes from a *verified* attestation on the pipeline
        # path; parsing it strictly here too keeps the direct entry
        # point honest.
        cosign_key_fingerprint(cosign_public_key_pem)
    except CosignAttestationError as e:
        return False, "bad cosign public key: %s" % e
    try:
        exe = _cosign_bin(cosign_bin)
    except CosignAttestationError as e:
        return False, str(e)
    tar_path = _temp_file(bytes(tar_bytes), ".tar")
    bundle_path = _temp_file(bytes(sigstore_bundle_bytes),
                             ".sigstore.json")
    pub_path = _temp_file(cosign_public_key_pem.encode("utf-8"), ".pub")
    try:
        rc, _out, err = _run_cosign(
            [exe, "verify-blob", "--bundle", bundle_path,
             "--key", pub_path, tar_path],
            timeout=timeout)
        if rc != 0:
            return False, "cosign refused the bundle (rc=%d): %s" % (
                rc, err.decode("utf-8", "replace")[:300])
        return True, "cosign verified the bundle"
    finally:
        for p in (tar_path, bundle_path, pub_path):
            try:
                os.unlink(p)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Auditor pipeline (five-step contract)
# ---------------------------------------------------------------------------

def _audit_failed(reason):
    return CosignAttestationError("AUDIT FAILED: %s" % reason)


def _pipeline(tar_bytes, sigstore_bundle_bytes, attestation, keyset_doc,
              genesis_key_id, *, cosign_bin, forensics,
              timeout=_DEFAULT_TIMEOUT_S):
    # Step 1: pin the genesis key id out-of-band. The pipeline refuses
    # to start without a pin -- a self-pinning bundle is a
    # self-attesting claim.
    if not isinstance(genesis_key_id, str) or not genesis_key_id:
        raise _audit_failed("no genesis key id pin supplied -- refusing "
                            "to start")
    if not isinstance(keyset_doc, dict):
        raise _audit_failed("keyset document is not a mapping")
    versions = keyset_doc.get("versions")
    if not isinstance(versions, list):
        raise _audit_failed("keyset document has no versions list")
    genesis = next((v for v in versions
                    if isinstance(v, dict) and v.get("version") == 1), None)
    if genesis is None or genesis.get("key_id") != genesis_key_id:
        raise _audit_failed("presented keyset does not chain from the "
                            "pinned genesis key")

    # Steps 2-4: keyset lineage, attestation signature, fingerprint
    # binding (revoked refuses here unless forensics).
    ok, info = verify_attestation(attestation, keyset_doc,
                                 forensics=forensics)
    if not ok:
        raise _audit_failed("attestation: %s" % info)

    # Step 5: the cosign public key is extracted FROM THE VERIFIED
    # ATTESTATION -- never a side channel -- and cosign verify-blob
    # runs against the bundle tar.
    ok, reason = verify_bundle_blob(tar_bytes, sigstore_bundle_bytes,
                                    attestation["cosign_public_key_pem"],
                                    cosign_bin=cosign_bin,
                                    timeout=timeout)
    if not ok:
        raise _audit_failed(reason)
    return {"verdict": "VERIFIED",
            "genesis_key_id": genesis_key_id,
            "keyset_version": info["keyset_version"],
            "keyset_status": info["status"],
            "keyset_key_id": info["keyset_key_id"],
            "fingerprint": info["fingerprint"],
            "forensics": forensics}


def authorize_bundle_signature(tar_bytes, sigstore_bundle_bytes,
                               attestation, keyset_doc, genesis_key_id,
                               *, cosign_bin="cosign",
                               timeout=_DEFAULT_TIMEOUT_S):
    """Five-step auditor pipeline on the *authorization* path.

    A revoked attesting key refuses here. Returns a verdict dict on
    success; raises :class:`CosignAttestationError` (``AUDIT FAILED:
    <reason>``) on any failure -- fail-closed, loud.
    """
    return _pipeline(tar_bytes, sigstore_bundle_bytes, attestation,
                     keyset_doc, genesis_key_id, cosign_bin=cosign_bin,
                     forensics=False, timeout=timeout)


def attribute_bundle_signature(tar_bytes, sigstore_bundle_bytes,
                               attestation, keyset_doc, genesis_key_id,
                               *, cosign_bin="cosign",
                               timeout=_DEFAULT_TIMEOUT_S):
    """Five-step pipeline on the *forensics* path (attribution only).

    A revoked attesting key still verifies here -- by design, so that
    attribution survives revocation. This answers "was this bundle
    signed by the now-revoked key?"; it never authorizes. The two
    entry points are deliberately distinct callables with distinct
    names: conflating them is how revoked keys keep authorizing.
    """
    return _pipeline(tar_bytes, sigstore_bundle_bytes, attestation,
                     keyset_doc, genesis_key_id, cosign_bin=cosign_bin,
                     forensics=True, timeout=timeout)
