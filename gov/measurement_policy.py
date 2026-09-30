"""Named, versioned measurement policies for attested identity.

Design input (ADAPT, not vendored): Keylime's verifier-side policy
discipline -- named, versioned measurement policies served from the
verifier, where the agent record binds policy *name and version*, and
unknown or stale policy is a refusal, never "verify against whatever
the agent sent". Keylime's TPM plumbing is explicitly DROPPED here:
our attestation posture is synthetic/fixture-based and Keylime is
Apache-2.0, so no Keylime source appears in this repo (none is needed;
the idea is re-implemented natively below). ``keylime/keylime``
LICENSE at HEAD: Apache-2.0 (verified wave-212 prospecting).

What this module provides, stdlib-only:

* A **measurement policy** as explicit data: ``policy_name``,
  ``version``, ``required_measurements`` (a list of
  ``{component, expected_digest}``), a validity window
  (``not_before`` / ``not_after``, integer epoch seconds), and an
  identity-only ``signer.kid``. The policy is signed (Ed25519) by the
  **policy-issuer keyset, pinned out-of-band** -- a policy document
  never carries a usable signing key, so self-signed policies verify
  False against the pinned key by construction.
* :class:`MeasurementPolicyRegistry`: the activation point. Policies
  activate per (policy_name, version). Activation verifies the
  signature, the strict shape, and a monotonic version floor --
  activating an older version than one already activated for the same
  name is a refusal (no silent downgrade). An already-expired policy
  cannot activate (stale at birth).
* :class:`MeasurementPolicyRegistry.evaluate`: attestation evaluation
  binds BOTH name and version explicitly -- there is no "latest" and
  no implicit upgrade. On every evaluation the registry checks, in
  order: the (name, version) is known, the stored policy signature
  still verifies against the pinned key (a policy swapped or edited
  after activation fails the re-check), the policy is within its
  validity window (stale = refused), and every required measurement
  matches with constant-time comparison. Missing required components,
  digest mismatches, and *unlisted extra components* all refuse --
  "which measurements must match" is the policy, and anything outside
  it is unexpected software.
* The policies WRAP the existing synthetic verifiers; they do not
  replace them. ``gov.attested_identity`` / ``gov.tee_attest`` /
  ``gov.eat_claims`` keep verifying evidence their own way; this
  module answers the Keylime question they never asked: *which named,
  versioned measurement set is this attestation evaluated against?*

Fail-closed: every refusal raises :class:`MeasurementPolicyError`
with a machine-readable ``code``.

$0 spend, synthetic/local deterministic only. No network.
"""

import hashlib
import hmac
import json
import re
import time

from . import ed25519 as _ed

__all__ = [
    "MEASUREMENT_POLICY_FORMAT",
    "POLICY_SIGN_DOMAIN",
    "MeasurementPolicyError",
    "canonical_policy_json",
    "policy_signing_bytes",
    "validate_policy_body",
    "make_policy_body",
    "sign_policy",
    "MeasurementPolicyRegistry",
]

#: Format tag of the policy document (exact match at verify).
MEASUREMENT_POLICY_FORMAT = "sasanam-measurement-policy/v1"

#: Domain separation for policy signatures.
POLICY_SIGN_DOMAIN = b"sasanam-measurement-policy-sign/v1:"

_POLICY_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
#: Digest hex accepted in policies and measurements: any
#: even-length lowercase hex of at least 32 bytes.
_DIGEST_HEX_RE = re.compile(r"^([0-9a-f]{2}){32,}$")


class MeasurementPolicyError(Exception):
    """Fail-closed measurement-policy violation. ``code`` is the
    machine-readable failure mode."""

    def __init__(self, code, detail=""):
        super(MeasurementPolicyError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def canonical_policy_json(body):
    """Canonical bytes of a policy body (sorted keys, no whitespace,
    ASCII). Signatures cover exactly these bytes."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def policy_signing_bytes(body):
    """Bytes the issuer signs: domain || sha256(canonical(body))."""
    digest = hashlib.sha256(canonical_policy_json(body)).hexdigest()
    return POLICY_SIGN_DOMAIN + digest.encode("ascii")


def _check_component(component, where):
    if not isinstance(component, str) or not _POLICY_NAME_RE.match(
            component):
        raise MeasurementPolicyError(
            "policy-body-malformed",
            "%s.component must match %s"
            % (where, _POLICY_NAME_RE.pattern))


def _check_digest_hex(value, where):
    if not isinstance(value, str) or not _DIGEST_HEX_RE.match(value):
        raise MeasurementPolicyError(
            "policy-body-malformed",
            "%s must be even-length lowercase hex of >= 32 bytes "
            "(a measurement digest)" % (where,))


def validate_policy_body(body):
    """Strictly validate a measurement-policy body mapping.

    Refuses unknown fields (never ignored), empty measurement sets,
    duplicate components, bad digest hex, inverted validity windows,
    and non-integer versions. Returns the body unchanged on success.
    """
    if not isinstance(body, dict):
        raise MeasurementPolicyError("policy-body-malformed",
                                     "policy body must be a mapping")
    allowed = {"document", "policy_name", "version",
               "required_measurements", "not_before", "not_after",
               "signer"}
    if set(body) - allowed:
        raise MeasurementPolicyError(
            "policy-body-malformed",
            "policy body carries unknown fields: %s"
            % sorted(set(body) - allowed))
    if body.get("document") != MEASUREMENT_POLICY_FORMAT:
        raise MeasurementPolicyError("policy-body-malformed",
                                     "document must be %r"
                                     % (MEASUREMENT_POLICY_FORMAT,))
    name = body.get("policy_name")
    if not isinstance(name, str) or not _POLICY_NAME_RE.match(name):
        raise MeasurementPolicyError(
            "policy-body-malformed",
            "policy_name must match %s" % (_POLICY_NAME_RE.pattern,))
    version = body.get("version")
    if isinstance(version, bool) or not isinstance(version, int) \
            or version < 1:
        raise MeasurementPolicyError("policy-body-malformed",
                                     "version must be an int >= 1")
    measurements = body.get("required_measurements")
    if not isinstance(measurements, list) or not measurements:
        raise MeasurementPolicyError(
            "policy-body-malformed",
            "required_measurements must be a non-empty list")
    seen = set()
    for i, entry in enumerate(measurements):
        where = "required_measurements[%d]" % (i,)
        if not isinstance(entry, dict) \
                or set(entry) != {"component", "expected_digest"}:
            raise MeasurementPolicyError(
                "policy-body-malformed",
                "%s must carry exactly {component, expected_digest}"
                % (where,))
        _check_component(entry["component"], where)
        if entry["component"] in seen:
            raise MeasurementPolicyError(
                "policy-body-malformed",
                "%s.component %r is duplicated"
                % (where, entry["component"]))
        seen.add(entry["component"])
        _check_digest_hex(entry["expected_digest"],
                          where + ".expected_digest")
    for key in ("not_before", "not_after"):
        value = body.get(key)
        if isinstance(value, bool) or not isinstance(value, int) \
                or value < 0:
            raise MeasurementPolicyError(
                "policy-body-malformed",
                "%s must be a non-negative int epoch" % (key,))
    if body["not_after"] <= body["not_before"]:
        raise MeasurementPolicyError("policy-body-malformed",
                                     "not_after must be after not_before")
    signer = body.get("signer")
    if not isinstance(signer, dict) or set(signer) != {"kid"}:
        raise MeasurementPolicyError("policy-body-malformed",
                                     "signer must carry exactly {kid}")
    if not isinstance(signer["kid"], str) or not signer["kid"]:
        raise MeasurementPolicyError("policy-body-malformed",
                                     "signer.kid must be a non-empty "
                                     "string")
    return body


def make_policy_body(*, policy_name, version, required_measurements,
                     not_before, not_after, signer_kid):
    """Assemble a policy body mapping, strictly validated.

    ``required_measurements``: iterable of (component, digest_hex)."""
    body = {
        "document": MEASUREMENT_POLICY_FORMAT,
        "policy_name": policy_name,
        "version": version,
        "required_measurements": [
            {"component": component, "expected_digest": digest}
            for component, digest in required_measurements
        ],
        "not_before": not_before,
        "not_after": not_after,
        "signer": {"kid": signer_kid},
    }
    return validate_policy_body(body)


def sign_policy(seed, body):
    """Sign a validated policy body with an Ed25519 seed.

    ``seed`` is 32 raw bytes (fixture/operator-side). Returns the
    64-byte signature over :func:`policy_signing_bytes`. The seed is
    never embedded in the body -- the registry verifies against its
    pinned public key only.
    """
    validate_policy_body(body)
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise MeasurementPolicyError("bad-seed",
                                     "seed must be 32 bytes")
    return _ed.sign(bytes(seed), policy_signing_bytes(body))


class MeasurementPolicyRegistry(object):
    """Activation point and evaluation seam for measurement policies.

    ``issuer_public_key`` is the PINNED 32-byte Ed25519 policy-issuer
    key (never fetched, never read from a policy document). Policies
    activate per (policy_name, version); each activation is signature-
    checked, shape-checked, and version-floor-checked. Evaluation binds
    the (name, version) explicitly -- no implicit "latest", no silent
    upgrade -- and re-checks the stored signature and the validity
    window on every call, so a policy swapped or edited after
    activation refuses mid-evaluation.
    """

    def __init__(self, issuer_public_key):
        if not isinstance(issuer_public_key, (bytes, bytearray)) \
                or len(issuer_public_key) != 32:
            raise MeasurementPolicyError(
                "bad-issuer-key",
                "issuer_public_key must be a 32-byte Ed25519 public key")
        self._issuer = bytes(issuer_public_key)
        self._policies = {}   # (name, version) -> {"body", "sig"}
        self._floor = {}      # name -> highest activated version
        self._failures = []

    @property
    def activation_failures(self):
        """Bounded telemetry for refused policy activations."""
        return list(self._failures)

    def _record_failure(self, code, detail):
        self._failures.append({"code": code, "detail": detail})
        del self._failures[:-64]

    def _fail(self, code, detail=""):
        self._record_failure(code, detail)
        raise MeasurementPolicyError(code, detail)

    def _verify_sig(self, body, sig):
        try:
            return bool(_ed.verify(self._issuer, policy_signing_bytes(body),
                                   bytes(sig)))
        except Exception:
            return False

    def activate(self, body, signature, *, now=None, rollback_guard=None):
        """Verify and activate a policy.

        Raises :class:`MeasurementPolicyError` (fail-closed) when the
        body is malformed (``policy-body-malformed``), the signature
        does not verify against the pinned issuer key
        (``policy-signature-invalid`` -- self-signed policies land
        here), the policy is already expired (``policy-stale``), or
        the version is not newer than the highest activated version
        for this name (``policy-version-downgrade``). A failed
        candidate never displaces anything already activated.

        When ``rollback_guard`` (a
        ``gov.version_manifest.SeenVersionRegistry``) is supplied, the
        candidate is additionally authorized against the durable
        seen-version history AFTER the signature check (so attacker
        probes cannot poison history). Guard refusals surface with the
        guard's own distinct codes (``rollback-detected``,
        ``policy-expired``, ``policy-unknown``, ``digest-mismatch``,
        ``bootstrap-required``). With ``rollback_guard=None`` (the
        default) the legacy path is byte-identical.
        """
        moment = int(now) if now is not None else int(time.time())
        if not isinstance(signature, (bytes, bytearray)) \
                or len(signature) != 64:
            self._fail("policy-signature-invalid",
                       "signature must be 64 bytes")
        try:
            validate_policy_body(body)
        except MeasurementPolicyError as exc:
            self._fail(exc.code, exc.detail)
        if not self._verify_sig(body, signature):
            self._fail("policy-signature-invalid",
                       "policy is not signed by the pinned issuer key")
        if rollback_guard is not None:
            # Tighten-only opt-in: durable anti-rollback beyond the
            # in-memory floor. Guard codes surface unchanged.
            from gov import version_manifest as _vm
            if not isinstance(rollback_guard, _vm.SeenVersionRegistry):
                self._fail("registry-malformed",
                           "rollback_guard must be a "
                           "gov.version_manifest.SeenVersionRegistry")
            _digest = "sha256:" + hashlib.sha256(
                policy_signing_bytes(body)).hexdigest()
            try:
                rollback_guard.authorize_activation(
                    body["policy_name"], body["version"], digest=_digest,
                    not_after=body["not_after"], now=moment)
            except _vm.VersionManifestError as exc:
                self._fail(exc.code, exc.detail)
        if moment >= body["not_after"]:
            self._fail("policy-stale",
                       "policy already expired at %d (not_after)"
                       % (body["not_after"],))
        if moment < body["not_before"]:
            self._fail("policy-not-yet-valid",
                       "policy not_before %d is in the future"
                       % (body["not_before"],))
        name = body["policy_name"]
        version = body["version"]
        if version <= self._floor.get(name, 0):
            self._fail("policy-version-downgrade",
                       "version %d is not newer than the activated "
                       "version %d for policy %r (downgrade refused)"
                       % (version, self._floor[name], name))
        self._policies[(name, version)] = {"body": dict(body),
                                           "sig": bytes(signature)}
        self._floor[name] = version
        return (name, version)

    def known_policies(self):
        """Sorted list of activated (policy_name, version) pairs."""
        return sorted(self._policies)

    def evaluate(self, policy_name, version, measurements, *, now=None):
        """Evaluate attested measurements against a named policy
        version. ``measurements`` maps component -> 64-hex digest.

        Refusal order (fail-closed): unknown (name, version)
        (``policy-unknown``); stored signature no longer verifies
        against the pinned key (``policy-signature-invalid`` -- a
        policy swapped or edited after activation); policy outside
        its validity window (``policy-stale``); missing required
        component (``measurement-missing``); digest mismatch,
        constant-time (``measurement-mismatch``); measured component
        not listed in the policy (``measurement-unlisted``).

        Returns the (policy_name, version) on success.
        """
        moment = int(now) if now is not None else int(time.time())
        entry = self._policies.get((policy_name, version))
        if entry is None:
            raise MeasurementPolicyError(
                "policy-unknown",
                "no activated policy (%r, version %r): policy must be "
                "activated before evaluation" % (policy_name, version))
        body = entry["body"]
        if not self._verify_sig(body, entry["sig"]):
            raise MeasurementPolicyError(
                "policy-signature-invalid",
                "stored policy (%r, v%d) no longer verifies against "
                "the pinned issuer key (policy was swapped or edited "
                "after activation)" % (policy_name, version))
        if moment < body["not_before"] or moment >= body["not_after"]:
            raise MeasurementPolicyError(
                "policy-stale",
                "policy (%r, v%d) is outside its validity window "
                "[%d, %d)" % (policy_name, version, body["not_before"],
                              body["not_after"]))
        if not isinstance(measurements, dict):
            raise MeasurementPolicyError("bad-measurements",
                                         "measurements must be a mapping")
        wanted = {m["component"]: m["expected_digest"]
                  for m in body["required_measurements"]}
        for component, expected in sorted(wanted.items()):
            got = measurements.get(component)
            if got is None:
                raise MeasurementPolicyError(
                    "measurement-missing",
                    "required component %r not measured" % (component,))
            # Malformed digests verify False rather than raising: the
            # comparison stays constant-time on every plausible input.
            if not isinstance(got, str) or not _DIGEST_HEX_RE.match(got):
                raise MeasurementPolicyError(
                    "measurement-mismatch",
                    "component %r digest is malformed" % (component,))
            if not hmac.compare_digest(got, expected):
                raise MeasurementPolicyError(
                    "measurement-mismatch",
                    "component %r digest does not match the policy"
                    % (component,))
        for component in measurements:
            if component not in wanted:
                raise MeasurementPolicyError(
                    "measurement-unlisted",
                    "measured component %r is not listed in policy "
                    "(%r, v%d): unexpected software refuses"
                    % (component, policy_name, version))
        return (policy_name, version)
