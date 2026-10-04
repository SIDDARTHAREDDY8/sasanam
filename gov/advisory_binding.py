"""Advisory-bound verifier inputs (W244-6, ADAPT -- pattern only).

Attacker shapes from treeship's published security advisories, verified
2026-09-30 against the zerkerlabs/treeship repo-level advisory API
(repo advisories, not global GHSAs -- the global API 404s them by
design; IDs were fetched, never carried on trust):
- GHSA-w356-2hw3-x2v2 (high): agent-card verification could accept a
  trusted party's key as another agent's; revocations forgeable/hidden.
- GHSA-qhv9-h5vq-hw6r (medium): Rekor anchoring never succeeded;
  verify --max-unwitnessed trusted unsigned local records.
- GHSA-29hj-wmwv-7hx8 (medium): package verify accepted fabricated
  sealed sets without checking signatures.
- GHSA-pmp9-x698-fh4v (high): keystore documented as AES-256-GCM was a
  broken SHA-256-CTR+HMAC construction (claimed-vs-actual crypto).
- GHSA-p367-33qm-pwv7 (high): package verify could report a rewritten
  receipt as verified.

No treeship code is vendored or imported; the attack *shapes* above are
the probe classes. The Sasanam answer: a verifier that consumes
advisory data must bind the advisory INPUT, not just the verdict:

- ``grade_agent_pin(pin)``: an unscoped ``agent_cert`` pin grades
  ASSERTED at most, never key-bound (treeship v0.31.12 discipline);
  presenting an asserted pin as verification evidence refuses
  ``pin-scope-insufficient`` -- re-pin with agent scope.
- ``bind_advisory_input(policy, snapshot, now)``: pins an advisory
  snapshot under a named advisory policy -- canonical-byte digest
  rechecked (tamper-evident), Ed25519 signatures verified against the
  policy's trusted keys (distinct keys only, no double-count), version
  recorded.
- ``supersede(pinned_list)``: newest version wins; an older allow never
  resurrects a newer flag.
- ``check_package(pinned, package_id, now)`` evaluates, in order:
  availability (``chain-source-unavailable``, fail closed) -> staleness
  (``chain-source-stale``, explicit stale verdict, never silent) ->
  advisory signature threshold (``registry-threshold-unmet``: flags
  from an untrusted advisory are untrusted) -> advisory flag
  (``package-advisory-flagged``: a package whose signature VERIFIES but
  which the advisory flags is still refused -- a signature proves who
  signed, never that the package is safe).

Reuses (never redefines): ``chain-source-unavailable``,
``chain-source-stale``, ``registry-threshold-unmet``,
``verifier-input-malformed`` from the existing taxonomy.

Honest residuals:
- Advisory content is caller-supplied; this module checks binding,
  freshness, supersession, and flags -- it cannot make an advisory
  honest. A lying advisory source is an attestation problem upstream.
- Pin grading is about the pin's scope, not signature genuineness;
  signature verification belongs to the caller's verifier seam
  (verifier_failclosed / signer_interop).
- Supersession is evaluated over the presented set; the deployment must
  present the current set (the freshness bound catches a stale feed).
- ``now`` is caller-supplied; no clock.

Stdlib only (+ in-repo gov.ed25519, pure-Python). Deterministic.
"""

import base64
import hashlib
import json

from gov import ed25519 as _ed25519

PACKAGE_ADVISORY_FLAGGED = "package-advisory-flagged"
PIN_SCOPE_INSUFFICIENT = "pin-scope-insufficient"

# Reused from the existing taxonomy (not redefined here):
#   "chain-source-unavailable", "chain-source-stale",
#   "registry-threshold-unmet", "verifier-input-malformed"
_CHAIN_SOURCE_UNAVAILABLE = "chain-source-unavailable"
_CHAIN_SOURCE_STALE = "chain-source-stale"
_REGISTRY_THRESHOLD_UNMET = "registry-threshold-unmet"
_VERIFIER_INPUT_MALFORMED = "verifier-input-malformed"
# New in wave-328 (registered in gov/decision_codes.py):
#   "advisory-version-tie", "advisory-input-unpinned"
_ADVISORY_VERSION_TIE = "advisory-version-tie"
_ADVISORY_INPUT_UNPINNED = "advisory-input-unpinned"

_ASSERTED = "asserted"
_KEY_BOUND = "key-bound"

_FLAG_VALUES = ("flagged", "allow")


class AdvisoryBindingError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail):
        super(AdvisoryBindingError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    raise AdvisoryBindingError(code, detail)


def _malformed(detail):
    _refuse(_VERIFIER_INPUT_MALFORMED, detail)


class PinnedAdvisory(dict):
    """Sealed advisory input: only ``bind_advisory_input`` builds these.

    ``check_package`` accepts ONLY this type. A plain dict -- even one
    with all the right fields -- is refused LOUD
    (``advisory-input-unpinned``): the deployment must pin through
    ``bind_advisory_input`` (shape + canonical digest + signature
    threshold checks), never hand-build the pinned record. Dict
    subclassing keeps every existing consumer working unchanged.

    Convention-grade seal (stated honestly): the constructor is public,
    so this stops accidental hand-built dicts -- the observed gap --
    not a determined direct construction. A caller that deliberately
    builds one is attacking its own check.
    """


def _num(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _malformed("%s must be a number" % name)
    return value


def _nonneg_int(value, name):
    if isinstance(value, bool) or not isinstance(value, int) \
            or value < 0:
        _malformed("%s must be a non-negative int" % name)
    return value


def _nonempty_str(value, name):
    if isinstance(value, bool) or not isinstance(value, str) \
            or not value:
        _malformed("%s must be a non-empty str" % name)
    return value


# ---------------------------------------------------------------------------
# Pin grading (treeship v0.31.12 discipline)
# ---------------------------------------------------------------------------

def grade_agent_pin(pin):
    """Grade an agent_cert pin: ``asserted`` or ``key-bound``.

    An unscoped pin (no ``agent`` scope) grades ASSERTED at most --
    it asserts a binding without proving it. Only a pin scoped to an
    agent (``agent://name``) grades key-bound. The grade is about the
    pin's scope, not signature genuineness.
    """
    if not isinstance(pin, dict):
        _malformed("pin must be a dict")
    if pin.get("kind") != "agent_cert":
        _malformed("pin kind must be 'agent_cert', got %r"
                   % (pin.get("kind"),))
    agent = pin.get("agent")
    if agent is None:
        return _ASSERTED
    if isinstance(agent, bool) or not isinstance(agent, str) \
            or not agent:
        _malformed("pin agent scope must be a non-empty str when present")
    return _KEY_BOUND


def assert_pin_for_verification(pin):
    """Present a pin as verification evidence, or refuse.

    An asserted-grade (unscoped) pin presented as verification evidence
    refuses ``pin-scope-insufficient``: re-pin with agent scope. Only a
    key-bound pin may proceed to the verifier's signature checks.
    """
    grade = grade_agent_pin(pin)
    if grade == _ASSERTED:
        _refuse(PIN_SCOPE_INSUFFICIENT,
                "unscoped agent_cert pin grades asserted at most; "
                "re-pin with agent scope for verification evidence")
    return _KEY_BOUND


# ---------------------------------------------------------------------------
# Advisory input binding
# ---------------------------------------------------------------------------

def _canonical_bytes(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _malformed("not JSON-canonicalizable: %s" % (exc,))


def _check_policy(policy):
    if not isinstance(policy, dict):
        _malformed("policy must be a dict")
    policy_input = _nonempty_str(
        policy.get("advisory_policy_input"), "advisory_policy_input")
    freshness = _nonneg_int(
        policy.get("freshness_seconds"), "freshness_seconds")
    if freshness <= 0:
        _malformed("freshness_seconds must be positive")
    threshold = _nonneg_int(
        policy.get("signature_threshold"), "signature_threshold")
    if threshold < 1:
        _malformed("signature_threshold must be >= 1")
    trusted = policy.get("trusted_keys")
    if not isinstance(trusted, list) or not trusted:
        _malformed("trusted_keys must be a non-empty list")
    for key in trusted:
        _nonempty_str(key, "trusted_keys entry")
    return policy_input, freshness, threshold, list(trusted)


def _count_valid_signatures(canon, signatures, trusted_keys):
    """Verify advisory signatures; count DISTINCT trusted keys.

    A signature counts only if it verifies (bool return checked, never
    assumed) AND its key is in the policy trust list. The same key
    twice counts once -- no double-counting.
    """
    if not isinstance(signatures, list) or not signatures:
        _malformed("signatures must be a non-empty list")
    seen = set()
    for entry in signatures:
        if not isinstance(entry, dict):
            _malformed("signature entry must be a dict")
        key_b64 = entry.get("key")
        sig_b64 = entry.get("sig")
        if not isinstance(key_b64, str) or not isinstance(sig_b64, str):
            _malformed("signature entry needs str key and sig")
        if key_b64 not in trusted_keys or key_b64 in seen:
            continue
        try:
            pub = base64.b64decode(key_b64, validate=True)
            sig = base64.b64decode(sig_b64, validate=True)
        except Exception:
            continue
        if len(pub) != 32 or len(sig) != 64:
            continue
        if _ed25519.verify(pub, canon, sig) is True:
            seen.add(key_b64)
    return len(seen)


def bind_advisory_input(policy, snapshot, now):
    """Pin an advisory snapshot under a named advisory policy.

    Checks, in order: policy shape -> snapshot shape -> canonical-byte
    digest (tamper-evident) -> signature verification against the
    policy trust list. Returns the pinned record as a ``PinnedAdvisory``
    (sealed: only ``check_package`` accepts it, and only this function
    builds it); refuses fail-closed.
    """
    policy_input, freshness, threshold, trusted = _check_policy(policy)
    _num(now, "now")
    if not isinstance(snapshot, dict):
        _malformed("snapshot must be a dict")
    advisory_id = _nonempty_str(
        snapshot.get("advisory_id"), "advisory_id")
    version = _nonneg_int(snapshot.get("version"), "version")
    issuer = _nonempty_str(snapshot.get("issuer"), "issuer")
    fetched_at = _num(snapshot.get("fetched_at"), "fetched_at")
    flags = snapshot.get("flags")
    if not isinstance(flags, dict):
        _malformed("flags must be a dict")
    for package_id, flag in flags.items():
        if not isinstance(package_id, str) or not package_id:
            _malformed("flags keys must be non-empty strings")
        if flag not in _FLAG_VALUES:
            _malformed("flag for %r must be one of %r, got %r"
                       % (package_id, _FLAG_VALUES, flag))
    canon = snapshot.get("canonical_bytes")
    if not isinstance(canon, (bytes, bytearray)):
        _malformed("canonical_bytes must be bytes")
    canon = bytes(canon)
    digest = snapshot.get("digest")
    if not isinstance(digest, str):
        _malformed("digest must be a hex string")
    if hashlib.sha256(canon).hexdigest() != digest:
        _malformed("advisory snapshot digest mismatch: the canonical "
                   "bytes do not digest to the claimed digest "
                   "(possible tampering)")
    valid = _count_valid_signatures(
        canon, snapshot.get("signatures"), trusted)
    return PinnedAdvisory({
        "advisory_policy_input": policy_input,
        "advisory_id": advisory_id,
        "version": version,
        "issuer": issuer,
        "fetched_at": float(fetched_at),
        "freshness_seconds": freshness,
        "signature_threshold": threshold,
        "valid_signatures": valid,
        "flags": dict(flags),
        "digest": digest,
    })


def supersede(pinned_list):
    """Newest advisory wins; an older allow never resurrects.

    Evaluated over the presented set: the deployment must present the
    current set (the freshness bound on ``bind_advisory_input`` catches
    a stale feed). An empty set means no advisory source at all ->
    ``chain-source-unavailable`` (fail closed).

    An exact version tie between two DIFFERENT presented records is
    refused LOUD (``advisory-version-tie``): first-wins would make the
    survivor order-dependent, and same-version conflicts must not exist
    in a well-formed feed -- the feed, not the tie-break, is fixed.
    """
    if not isinstance(pinned_list, list):
        _malformed("pinned_list must be a list")
    if not pinned_list:
        _refuse(_CHAIN_SOURCE_UNAVAILABLE,
                "no advisory snapshots presented")
    best = None
    for pinned in pinned_list:
        if not isinstance(pinned, dict):
            _malformed("pinned advisory must be a dict")
        version = pinned.get("version")
        if isinstance(version, bool) or not isinstance(version, int):
            _malformed("pinned advisory version must be an int")
        if best is None or version > best["version"]:
            best = pinned
        elif version == best["version"] and pinned is not best:
            _refuse(_ADVISORY_VERSION_TIE,
                    "two presented advisories share version %d (%r vs "
                    "%r); the survivor would be order-dependent -- the "
                    "feed must not contain same-version conflicts"
                    % (version, best.get("advisory_id"),
                       pinned.get("advisory_id")))
    return best


def check_package(pinned, package_id, now):
    """Evaluate one package against a pinned advisory, or refuse.

    Order: shape -> availability (fail closed) -> staleness (explicit
    stale verdict) -> advisory signature threshold (untrusted flags are
    untrusted) -> advisory flag. A flagged package is refused even
    though its own signature may verify: a signature proves who signed,
    never that the package is safe.
    """
    if pinned is None:
        _refuse(_CHAIN_SOURCE_UNAVAILABLE,
                "no pinned advisory input for this check")
    if not isinstance(pinned, PinnedAdvisory):
        # The pinned record is caller-trusted ONLY when it came out of
        # bind_advisory_input (shape + canonical digest + signature
        # threshold verified there). A hand-built dict -- even with all
        # the right fields -- is refused LOUD: the deployment must pin
        # through bind_advisory_input, never assemble the record itself.
        _refuse(_ADVISORY_INPUT_UNPINNED,
                "pinned advisory must be a bind_advisory_input-sealed "
                "PinnedAdvisory, got %s" % (type(pinned).__name__,))
    for field in ("advisory_policy_input", "advisory_id", "version",
                  "fetched_at", "freshness_seconds",
                  "signature_threshold", "valid_signatures", "flags"):
        if field not in pinned:
            _malformed("pinned advisory is missing %r" % (field,))
    _nonempty_str(package_id, "package_id")
    now = _num(now, "now")
    fetched_at = _num(pinned["fetched_at"], "fetched_at")
    freshness = _nonneg_int(
        pinned["freshness_seconds"], "freshness_seconds")
    if now > fetched_at + freshness:
        _refuse(_CHAIN_SOURCE_STALE,
                "advisory snapshot %r is older than its %d-second "
                "freshness bound (explicit stale, never a silent pass)"
                % (pinned["advisory_id"], freshness))
    threshold = _nonneg_int(
        pinned["signature_threshold"], "signature_threshold")
    valid = _nonneg_int(pinned["valid_signatures"], "valid_signatures")
    if valid < threshold:
        _refuse(_REGISTRY_THRESHOLD_UNMET,
                "%d valid advisory signatures, policy requires %d; "
                "flags from an untrusted advisory are untrusted"
                % (valid, threshold))
    flags = pinned["flags"]
    if not isinstance(flags, dict):
        _malformed("pinned advisory flags must be a dict")
    if flags.get(package_id) == "flagged":
        _refuse(PACKAGE_ADVISORY_FLAGGED,
                "advisory %r flags package %r: refused even though "
                "its signature may verify (a signature proves who "
                "signed, never that the package is safe)"
                % (pinned["advisory_id"], package_id))
    return {
        "verdict": "advisory-clear",
        "advisory_policy_input": pinned["advisory_policy_input"],
        "advisory_id": pinned["advisory_id"],
        "version": pinned["version"],
    }
