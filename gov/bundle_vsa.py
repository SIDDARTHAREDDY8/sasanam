"""Per-bundle Verification Summary Attestations (wave-279).

The "sell evidence, not the engine" unit: one signed VSA per sealed
evidence bundle. The VSA shape itself (``sasanam-vsa/1``) and the
Ed25519 issuer live in ``gov.provenance_policy`` (``VSAIssuer``);
the admission-time consumer is
``ProvenancePolicy.admit_vsa``. This module is the SEAL-TIME wiring:

* :func:`issue_bundle_vsa` -- issue the signed VSA for one bundle:
  names the bundle digest, the verifier identity, the policy /
  evaluation it passed, and the verification time; the bundle's
  receipts ride as trust-labeled ``input_attestations``
  (agent-supplied vs platform-supplied -- nothing unlabeled).
* :func:`verify_bundle_vsa` -- the standalone verifier: refuses
  forged / tampered VSAs (wrong signature, wrong digest, expired
  verification) with coded fail-closed verdicts
  (``provenance-vsa-refused`` / ``provenance-subject-refused``).
  Hostile shapes refuse machine-coded (F245 discipline), never as
  raw TypeError/ValueError/KeyError.
* :func:`attach_bundle_vsa` -- file exactly one VSA onto a sealed
  bundle record (a second attach refuses; the seal ceremony signs
  one summary per bundle).
* :func:`bundle_input_attestations` -- the default receipt list for
  a seal: the seal ceremony's own signature attestation, labeled
  platform-supplied (the sealer generated it).

License posture: the VSA FORMAT is adapted from the SLSA
Verification Summary field definitions (slsa-framework/slsa;
spec text under CSL 1.0 -- shapes only, no spec prose copied).
Signatures use the repo's existing Ed25519 machinery
(``gov.ed25519`` via ``gov.provenance_policy``). Refusal codes are
the existing registered vocabulary: no new decision codes, the
taxonomy pin does not move.

Key custody: the issuer holds the sealer seed; this module never
mints or stores keys.
"""

import hashlib
import hmac
import time

from gov import ed25519 as _ed25519
from gov import provenance_policy as _pp

# The signature domain is shared with gov.provenance_policy -- one
# source of truth so issuer and verifier can never drift.
_VSA_DOMAIN = _pp._VSA_DOMAIN  # noqa: SLF001 -- same product, shared seam
_canonical_bytes = _pp.canonical_bytes

#: The VSA format this module issues and verifies.
VSA_FORMAT = _pp.VSA_FORMAT

#: Default verification policy named on seal-issued VSAs: the
#: seal-time verification the sealer actually ran (chain-then-bind
#: signature check + evidence-cert ceremony re-verification).
DEFAULT_POLICY_ID = "sasanam-evidence-seal/v1"

#: Default verification level for seal-issued VSAs: the sealer
#: performed the named verification itself (ranked vocabulary shared
#: with ``ProvenancePolicy.admit_vsa``).
DEFAULT_VERIFIED_LEVEL = "SLSA_BUILD_LEVEL_1"

#: Default credential lifetime for seal-issued VSAs (24h); the
#: admitting policy additionally caps age (``vsa_max_age_seconds``).
DEFAULT_TTL_SECONDS = 86400

_HEX64 = set("0123456789abcdef")

#: Closed refusal vocabulary for this seam (all registered codes).
_VERDICTS = frozenset(("provenance-vsa-refused",
                       "provenance-subject-refused",
                       "evbundle-malformed"))


class BundleVSAError(Exception):
    """Fail-closed refusal. ``code`` is a closed-vocabulary member."""

    def __init__(self, code, detail=""):
        if code not in _VERDICTS:
            raise ValueError("unknown BundleVSA code %r" % (code,))
        super(BundleVSAError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise BundleVSAError(code, detail)


def _as_hex64(value):
    if not isinstance(value, str) or len(value) != 64:
        return None
    low = value.lower()
    if any(c not in _HEX64 for c in low):
        return None
    return low


def _issuer_now(issued_at):
    """Issuer-side clock (F228 shape): None resolves to time.time();
    a bool/non-numeric/non-finite value refuses as ValueError -- the
    issuer validates ITS inputs; the verifier refuses coded."""
    if issued_at is None:
        return float(time.time())
    if isinstance(issued_at, bool) \
            or not isinstance(issued_at, (int, float)):
        raise ValueError("issued_at must be a finite number or None")
    if issued_at != issued_at \
            or issued_at in (float("inf"), float("-inf")):
        raise ValueError("issued_at must be finite")
    return float(issued_at)


def _verifier_now(now):
    """Verifier-side clock (F228 shape, coded): None resolves to
    time.time(); a bool/non-numeric/non-finite value refuses
    ``provenance-vsa-refused`` BEFORE any refusal decision."""
    if now is None:
        return float(time.time())
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        _refuse("provenance-vsa-refused",
                "now must be a finite number or None")
    if now != now or now in (float("inf"), float("-inf")):
        _refuse("provenance-vsa-refused",
                "now must be finite (got NaN/inf)")
    return float(now)


def _subject_digest(vsa):
    """Extract the VSA's subject sha256 without letting hostile
    shapes escape as raw exceptions (F245): a truthy non-dict
    ``subject`` (or ``digest``) carries no digest and is therefore
    unmatchable -- treated as missing so the caller refuses
    machine-coded."""
    subject = vsa.get("subject")
    if not isinstance(subject, dict):
        return None
    digest_field = subject.get("digest")
    if not isinstance(digest_field, dict):
        return None
    return digest_field.get("sha256")


def issue_bundle_vsa(*, issuer, bundle_digest, policy_id,
                     verified_level, input_attestations=None,
                     issued_at=None, ttl_seconds=DEFAULT_TTL_SECONDS):
    """Issue the signed VSA for one sealed evidence bundle.

    ``issuer`` is a ``gov.provenance_policy.VSAIssuer`` (the sealer
    identity; key custody stays with the caller). ``bundle_digest``
    is the 64-hex digest the VSA names as its subject.
    ``policy_id`` names the verification the sealer ran
    (default: the seal-time ceremony); ``verified_level`` is the
    ranked evaluation outcome. ``input_attestations`` is the
    bundle's receipts as trust-labeled ``{"kind", "digest",
    "trust"}`` entries -- validated (nothing unlabeled is ever
    signed). Returns the signed VSA dict.
    """
    if not isinstance(issuer, _pp.VSAIssuer):
        raise ValueError("issuer must be a provenance_policy.VSAIssuer")
    now = _issuer_now(issued_at)
    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive int")
    return issuer.issue(bundle_digest, policy_id, verified_level,
                        now, ttl_seconds,
                        input_attestations=input_attestations)


def bundle_input_attestations(signature_attestation):
    """Default receipt list for a seal-time VSA: the seal ceremony's
    own signature attestation, labeled platform-supplied (the sealer
    generated it -- never agent-supplied).
    """
    if not isinstance(signature_attestation, dict):
        raise ValueError("signature_attestation must be a dict")
    digest = hashlib.sha256(
        _canonical_bytes(signature_attestation)).hexdigest()
    return [{"kind": "signature-attestation",
             "digest": digest,
             "trust": "platform-supplied"}]


def attach_bundle_vsa(sealed, vsa):
    """File exactly one VSA onto a sealed bundle record.

    Returns a copy of ``sealed`` with the VSA filed under ``"vsa"``.
    Refuses ``evbundle-malformed`` when the sealed record is not a
    dict or already carries a VSA (one summary per bundle), and
    ``provenance-vsa-refused`` when the VSA is not structurally a
    ``sasanam-vsa/1`` attestation. Signature checking is
    :func:`verify_bundle_vsa`'s job, not the filing step's.
    """
    if not isinstance(sealed, dict):
        _refuse("evbundle-malformed",
                "sealed bundle must be a dict")
    if "vsa" in sealed:
        _refuse("evbundle-malformed",
                "sealed bundle already carries a VSA")
    if not isinstance(vsa, dict) or vsa.get("format") != VSA_FORMAT:
        _refuse("provenance-vsa-refused",
                "not a sasanam VSA")
    if not isinstance(vsa.get("signature"), dict):
        _refuse("provenance-vsa-refused",
                "VSA carries no signature block")
    filed = dict(sealed)
    filed["vsa"] = vsa
    return filed


def verify_bundle_vsa(vsa, *, verifier_pubkey_hex,
                      expected_bundle_digest, now=None):
    """Verify a per-bundle VSA against the pinned verifier key.

    Checks, in order: VSA shape, Ed25519 signature under the pinned
    key (the ``verify`` contract returns True/False and never
    raises -- the False return is checked here, wave-243 lesson),
    the validity window (expired or not-yet-valid refuses), the
    subject digest against ``expected_bundle_digest``
    (``provenance-subject-refused`` on mismatch), and that the
    verification level is a known rank. Returns the VSA dict on
    success. Every failure is a closed-vocabulary refusal; hostile
    shapes never escape as raw exceptions.
    """
    now = _verifier_now(now)
    if not isinstance(vsa, dict) or vsa.get("format") != VSA_FORMAT:
        _refuse("provenance-vsa-refused",
                "not a sasanam VSA")
    try:
        pub = bytes.fromhex(verifier_pubkey_hex)
    except (ValueError, TypeError, AttributeError):
        _refuse("provenance-vsa-refused",
                "pinned verifier key malformed")
    if len(pub) != 32:
        _refuse("provenance-vsa-refused",
                "pinned verifier key is not 32 bytes")
    sig_entry = vsa.get("signature")
    if not isinstance(sig_entry, dict):
        # F245: a truthy non-dict signature block has no usable sig
        # -- refuse machine-coded instead of AttributeError.
        _refuse("provenance-vsa-refused",
                "VSA carries no signature block")
    try:
        sig = bytes.fromhex(sig_entry.get("sig", ""))
    except (ValueError, TypeError, AttributeError):
        _refuse("provenance-vsa-refused",
                "VSA signature malformed")
    if len(sig) != 64:
        _refuse("provenance-vsa-refused",
                "VSA signature is not 64 bytes")
    body = {k: v for k, v in vsa.items() if k != "signature"}
    msg = _VSA_DOMAIN + _canonical_bytes(body)
    # verify() returns True/False, never raises -- check the False.
    if _ed25519.verify(pub, msg, sig) is not True:
        _refuse("provenance-vsa-refused",
                "VSA signature does not verify under pinned key")
    issued_at = vsa.get("issued_at")
    expires_at = vsa.get("expires_at")
    if not isinstance(issued_at, (int, float)) \
            or isinstance(issued_at, bool) \
            or not isinstance(expires_at, (int, float)) \
            or isinstance(expires_at, bool):
        _refuse("provenance-vsa-refused",
                "VSA carries no well-formed validity window")
    if not (issued_at <= now < expires_at):
        _refuse("provenance-vsa-refused",
                "VSA outside its validity window (expired or "
                "not yet valid)")
    digest = _as_hex64(_subject_digest(vsa))
    want = _as_hex64(expected_bundle_digest)
    if digest is None or want is None \
            or not hmac.compare_digest(digest, want):
        _refuse("provenance-subject-refused",
                "VSA subject digest does not match the bundle")
    level = vsa.get("verified_level")
    if not isinstance(level, str) \
            or _pp._VSA_LEVEL_RANK.get(level) is None:  # noqa: SLF001
        # F245: a non-string (possibly unhashable) level can never
        # be a valid rank -- refuse machine-coded instead of a raw
        # TypeError from the dict lookup.
        _refuse("provenance-vsa-refused",
                "VSA verification level %r is not a known rank"
                % (level,))
    return vsa
