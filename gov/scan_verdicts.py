"""Signed scan-verdict promotion gate (NIST SP 800-190 ADAPT, narrow).

PATTERN LINEAGE: NIST SP 800-190, *Application Container Security
Guide* (DOI 10.6028/NIST.SP.800-190), sections 4.1/4.2 and the
vulnerability-management guidance: "only trusted images run", "scan
images", and "restrict deployment based on acceptable vulnerability
rules/thresholds". NIST Special Publications are U.S. federal
government works -- PUBLIC DOMAIN. No specification text is copied;
only the control rationale is adapted, in our own words, to the
promotion seam: deployment gated on a NAMED, SIGNED,
FRESHNESS-BOUNDED scan verdict.

What this module is and is not:

* It is a SIGNED-VERDICT primitive: a scanner emits a verdict record,
  signs it, and the promotion gate consults the record. The policy --
  which scanner names are required -- is caller-owned
  (:class:`ScanPolicy`); the module only enforces what the policy
  declares. Default policy requires NOTHING: the feature is opt-in and
  can never become silently mandatory for deployments that have not
  adopted it.
* It is NOT a scanner. Building our own scanner would be
  self-attestation and is explicitly out of scope (wave-211
  prospecting). The scanner is a trusted third party; its compromise,
  misconfiguration, database lag, or blind spots are OUTSIDE this
  module's verification boundary -- named in the claim bounds, not
  absorbed.
* A scan verdict proves "scanner S scanned digest D at time T with
  ruleset R and recorded verdict V" -- NOT "D has no vulnerabilities".
  The evidence bundle carries the ruleset digest and scan time so a
  verifier can judge staleness itself.

Wire shape (DSSE, via gov.dsse_envelope)::

    {"payloadType": "application/vnd.sasanam.scan-verdict+json",
     "payload": base64(canonical JSON statement),
     "signatures": [{"keyid": ..., "sig": ...}]}

Statement (canonical JSON, unknown fields refused)::

    {"scanner_name": "trivy",            # required, non-empty
     "scanner_version": "0.58.2",        # required, non-empty
     "scan_target_digest": "sha256:...",# required, the scanned bytes
     "verdict": "pass|fail|error",      # required, closed vocabulary
     "ruleset_digest": "sha256:...",   # required, scanner DB/ruleset
     "severity_counts": {"critical": 0, "high": 1},  # optional, default {}
     "scanned_at": 1700000000,          # required, unix seconds
     "expires_at": 1700086400,          # required, unix seconds
     "claim_bounds": {...}}             # required, four-field bounds

Freshness discipline (the "no eternal verdicts" wire rule):

* ``expires_at`` is MANDATORY -- a verdict without an expiry cannot be
  emitted, and one without an expiry on the wire cannot verify.
* Emission refuses a validity window longer than
  ``MAX_VERDICT_TTL_SECONDS`` (90 days, pinned): no verdict may claim
  validity beyond that, however the scanner feels.
* Emission refuses a verdict born stale (``expires_at <= now``) and a
  scan from the future (``scanned_at > now``).
* Verification refuses a verdict whose ``scanned_at`` is in the future
  or whose ``expires_at`` has passed, against the verifier's clock
  (the clock is a named verifier assumption in the claim bounds).

Gate semantics (:class:`ScanGate.check`):

* Every presented envelope is verified against the PINNED keyset for
  its claimed scanner name; a verdict from a name with no pinned
  keyset is refused LOUDLY (``scan_verdict_unknown_scanner``) -- never
  silently ignored, or an attacker could dodge a required scan by
  inventing a scanner name.
* Wrong-target verdicts refuse (``scan_verdict_target_mismatch``): a
  clean verdict for bundle A cannot be transplanted onto bundle B.
* For every policy-required scanner name there must be a verified
  ``pass`` verdict for the target; missing -> ``scan_verdict_missing``.
* A verified ``fail``/``error`` verdict BLOCKS promotion
  (``scan_verdict_negative``) -- negative evidence dominates: a ``pass``
  for the same name+target does not erase a ``fail``. Severity
  thresholds ("no CRITICAL unexpired-unexcepted") and exception grants
  (approver + compensating control + expiry) are policy-side
  adjudication, deliberately NOT wire fields: the verdict's
  ``pass``/``fail`` IS the scanner's threshold adjudication, and a
  ``fail`` blocks unconditionally. A deployment that needs exception
  workflows adjudicates them outside the gate -- the gate only ever
  sees pass/fail/error.

Integration: ``gov.load_gate.SkillLoader`` accepts an optional
``scan_gate`` (a :class:`ScanGate`) and ``load_skill`` accepts optional
``scan_verdicts`` envelopes -- the same optional-wiring shape as the
wave-194 corpus, wave-206 bundle-refresh, and wave-209 namespace
seams. Unwired callers see byte-identical behavior.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import hashlib
import json
import time

from . import claim_bounds as _cb
from . import dsse_envelope as _dsse
from .signing import Verifier

__all__ = [
    "SCAN_VERDICT_PAYLOAD_TYPE",
    "VERDICT_PASS",
    "VERDICT_FAIL",
    "VERDICT_ERROR",
    "VERDICTS",
    "MAX_VERDICT_TTL_SECONDS",
    "ScanVerdictError",
    "default_scan_bounds",
    "digest_of_bytes",
    "emit_scan_verdict",
    "verify_scan_verdict",
    "peek_scan_verdict",
    "ScanPolicy",
    "ScanGate",
]

#: Pinned DSSE payload type for scan-verdict statements. The type rides
#: inside the signed PAE bytes (gov.dsse_envelope), so a signature
#: cannot be transplanted onto a different statement kind.
SCAN_VERDICT_PAYLOAD_TYPE = "application/vnd.sasanam.scan-verdict+json"

VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_ERROR = "error"
#: Closed verdict vocabulary. "fail"/"error" are both negative at the
#: gate; "error" (scanner could not complete) fails closed like "fail".
VERDICTS = frozenset({VERDICT_PASS, VERDICT_FAIL, VERDICT_ERROR})

#: No verdict may claim a validity window longer than 90 days. This is
#: a module-pinned wire contract ("no eternal verdicts"), not policy:
#: a scanner that needs longer re-emits. Policy cannot widen it.
MAX_VERDICT_TTL_SECONDS = 90 * 86400

_STATEMENT_FIELDS = frozenset({
    "scanner_name", "scanner_version", "scan_target_digest", "verdict",
    "ruleset_digest", "severity_counts", "scanned_at", "expires_at",
    "claim_bounds",
})
_REQUIRED_STATEMENT_FIELDS = frozenset({
    "scanner_name", "scanner_version", "scan_target_digest", "verdict",
    "ruleset_digest", "scanned_at", "expires_at", "claim_bounds",
})


class ScanVerdictError(ValueError):
    """Any scan-verdict emission, verification, policy, or gate failure.

    Raised loudly -- never a silent False. The message names the
    refusal code (scan_verdict_stale, scan_verdict_target_mismatch,
    ...) so callers and audit trails can distinguish attack classes.
    """


def _now():
    return int(time.time())


def digest_of_bytes(data):
    """The canonical digest pin for exact bytes: ``sha256:`` + the
    64-char lowercase hex SHA-256 digest (stdlib hashlib, no third
    party).

    This is the digest-binding primitive (wave-216, npm/PyPI
    attestation DIGEST-BINDING steal -- idea only): a scan verdict
    binds to the digest of the bytes the scanner actually scanned, and
    a consumer binds to the digest of the bytes it is actually about
    to promote. A digest CLAIM from a manifest is never hashed here --
    only bytes the caller holds. Non-bytes-like input (str, None,
    int) is refused LOUDLY, never coerced: a digest string passed
    where bytes belong would silently re-bind the verdict to the
    claim.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    else:
        raise ScanVerdictError(
            "scan_verdict_bad_bytes: digest_of_bytes requires a "
            "bytes-like object, got %s -- digest strings are never "
            "accepted where bytes belong" % type(data).__name__)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


# ---------------------------------------------------------------------------
# Field checkers (shared by emission and verification)
# ---------------------------------------------------------------------------

def _check_name(value, where):
    if not isinstance(value, str) or not value:
        raise ScanVerdictError("scan_verdict_bad_scanner_name: %s must "
                               "be a non-empty str" % where)
    if len(value) > 128:
        raise ScanVerdictError("scan_verdict_bad_scanner_name: %s longer "
                               "than 128 chars" % where)
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ScanVerdictError("scan_verdict_bad_scanner_name: %s "
                               "control characters refused" % where)
    return value


def _check_version(value, where):
    if not isinstance(value, str) or not value:
        raise ScanVerdictError("scan_verdict_bad_scanner_version: %s "
                               "must be a non-empty str" % where)
    if len(value) > 64:
        raise ScanVerdictError("scan_verdict_bad_scanner_version: %s "
                               "longer than 64 chars" % where)
    return value


def _check_pin(value, where):
    # Canonical digest-pin shape, matching gov.load_gate.is_digest_pin:
    # "sha256:" + 64 lowercase hex chars. Refused, never coerced.
    if not isinstance(value, str):
        raise ScanVerdictError("scan_verdict_bad_digest: %s digest pin "
                               "must be a str, got %s"
                               % (where, type(value).__name__))
    if not value.startswith("sha256:") or len(value) != 71:
        raise ScanVerdictError("scan_verdict_bad_digest: %s not a sha256 "
                               "digest pin: %r" % (where, value))
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise ScanVerdictError("scan_verdict_bad_digest: %s not a sha256 "
                               "digest pin: %r" % (where, value))
    return value


def _check_verdict(value, where):
    if value not in VERDICTS:
        raise ScanVerdictError("scan_verdict_bad_verdict: %s must be one "
                               "of %s, got %r"
                               % (where, sorted(VERDICTS), value))
    return value


def _check_severity_counts(value, where):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ScanVerdictError("scan_verdict_bad_severity_counts: %s "
                               "must be a dict or absent" % where)
    out = {}
    for k, v in value.items():
        if not isinstance(k, str) or not k or len(k) > 32:
            raise ScanVerdictError("scan_verdict_bad_severity_counts: "
                                   "%s bad severity key %r" % (where, k))
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ScanVerdictError("scan_verdict_bad_severity_counts: "
                                   "%s count for %r must be an int >= 0"
                                   % (where, k))
        out[k] = v
    return out


def _check_ts(value, where):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScanVerdictError("scan_verdict_bad_timestamp: %s must be "
                               "an int unix timestamp, got %r"
                               % (where, value))
    if value < 0:
        raise ScanVerdictError("scan_verdict_bad_timestamp: %s negative "
                               "timestamp refused" % where)
    return value


def default_scan_bounds():
    """The pinned narrow claim bounds every scan verdict carries.

    Honest about the seam: a verdict proves the scanner RECORDED this
    verdict, not that the target is clean, the scanner is correct, or
    the ruleset database is complete. Validated by
    gov.claim_bounds.validate_bounds at emission and verification.
    """
    return _cb.validate_bounds({
        "proves": ["named-scanner-recorded-this-verdict"],
        "does_not_prove": [
            "target-is-vulnerability-free",
            "scanner-is-correct",
            "ruleset-database-is-complete",
            "target-runtime-behavior",
        ],
        "verifier_assumptions": [
            "scanner-keyset-pinned-correctly",
            "verdict-target-digest-binds-the-promoted-bytes",
            "verifier-clock-is-sane",
        ],
        "scope_limits": [
            "scan-time-evidence-only",
            "freshness-expires-at-bound",
        ],
    }, where="scan_verdict_bounds")


def _statement_dict(scanner_name, scanner_version, scan_target_digest,
                    verdict, ruleset_digest, severity_counts,
                    scanned_at, expires_at, claim_bounds):
    """Structurally validate and normalize a statement (emission and
    verification share this; time-relative rules are applied by the
    caller)."""
    stmt = {
        "scanner_name": _check_name(scanner_name, "scanner_name"),
        "scanner_version": _check_version(scanner_version,
                                          "scanner_version"),
        "scan_target_digest": _check_pin(scan_target_digest,
                                         "scan_target_digest"),
        "verdict": _check_verdict(verdict, "verdict"),
        "ruleset_digest": _check_pin(ruleset_digest, "ruleset_digest"),
        "severity_counts": _check_severity_counts(severity_counts,
                                                  "severity_counts"),
        "scanned_at": _check_ts(scanned_at, "scanned_at"),
        "expires_at": _check_ts(expires_at, "expires_at"),
    }
    if claim_bounds is None:
        claim_bounds = default_scan_bounds()
    try:
        stmt["claim_bounds"] = _cb.validate_bounds(
            claim_bounds, where="scan_verdict.claim_bounds")
    except _cb.ClaimBoundsError as e:
        raise ScanVerdictError("claim_bounds invalid: %s" % e)
    return stmt


def _statement_bytes(stmt):
    return _canonical_json(stmt).encode("utf-8")


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------

def emit_scan_verdict(*, scanner_name, scanner_version,
                      scan_target_digest, verdict, ruleset_digest,
                      scanned_at, expires_at, signer,
                      severity_counts=None, claim_bounds=None, now=None):
    """Emit a signed scan-verdict DSSE envelope (the scanner's act).

    ``signer`` is a gov.signing.Signer for the scanner's key. ``now``
    is an optional int unix timestamp for determinism (tests); it
    defaults to the wall clock.

    Emission-time fail-closed rules (the "no eternal verdicts" wire
    rule): ``expires_at`` is mandatory; the validity window
    ``expires_at - scanned_at`` must be positive and no longer than
    ``MAX_VERDICT_TTL_SECONDS``; the verdict must not be born stale
    (``expires_at > now``) and the scan must not be from the future
    (``scanned_at <= now``).

    Returns the DSSE envelope dict.
    """
    now = _now() if now is None else _check_ts(now, "now")
    stmt = _statement_dict(scanner_name, scanner_version,
                           scan_target_digest, verdict, ruleset_digest,
                           severity_counts, scanned_at, expires_at,
                           claim_bounds)
    if stmt["expires_at"] <= stmt["scanned_at"]:
        raise ScanVerdictError(
            "scan_verdict_empty_window: expires_at (%d) must be after "
            "scanned_at (%d)" % (stmt["expires_at"], stmt["scanned_at"]))
    window = stmt["expires_at"] - stmt["scanned_at"]
    if window > MAX_VERDICT_TTL_SECONDS:
        raise ScanVerdictError(
            "scan_verdict_window_too_long: validity window %d s exceeds "
            "the pinned maximum %d s -- no eternal verdicts"
            % (window, MAX_VERDICT_TTL_SECONDS))
    if stmt["scanned_at"] > now:
        raise ScanVerdictError(
            "scan_verdict_future_scan: scanned_at (%d) is after now (%d)"
            % (stmt["scanned_at"], now))
    if stmt["expires_at"] <= now:
        raise ScanVerdictError(
            "scan_verdict_born_stale: expires_at (%d) is not after now "
            "(%d)" % (stmt["expires_at"], now))
    if not hasattr(signer, "sign"):
        raise ScanVerdictError("scan_verdict_no_signer: signer must "
                               "expose sign()")
    return _dsse.seal(_statement_bytes(stmt), SCAN_VERDICT_PAYLOAD_TYPE,
                      [signer])


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _parse_envelope_strict(envelope):
    """Strict-parse a scan-verdict DSSE envelope (shared by peek and
    verify -- one parse per envelope, never two).

    Returns ``(payload_bytes, payload_type, sig_entries)``. Raises
    ScanVerdictError on any structural violation or payload-type
    mismatch.
    """
    try:
        payload, payload_type, sig_entries = _dsse.parse_envelope(envelope)
    except _dsse.EnvelopeError as e:
        raise ScanVerdictError("scan_verdict_malformed_envelope: %s" % e)
    if payload_type != SCAN_VERDICT_PAYLOAD_TYPE:
        raise ScanVerdictError(
            "scan_verdict_payload_type: envelope carries %r, expected %r"
            % (payload_type, SCAN_VERDICT_PAYLOAD_TYPE))
    return payload, payload_type, sig_entries


def _statement_from_payload(payload):
    """Strict-validate parsed payload bytes into the canonical
    statement dict (shared by peek and verify). Unknown fields are
    refused; the wire bytes must equal the canonical re-derivation."""
    try:
        stmt = json.loads(bytes(payload).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ScanVerdictError("scan_verdict_bad_json: %s" % e)
    if not isinstance(stmt, dict):
        raise ScanVerdictError("scan_verdict_bad_json: statement is not "
                               "a JSON object")
    extra = set(stmt) - _STATEMENT_FIELDS
    if extra:
        raise ScanVerdictError("scan_verdict_unknown_fields: refused: %s"
                               % sorted(extra))
    missing = _REQUIRED_STATEMENT_FIELDS - set(stmt)
    if missing:
        raise ScanVerdictError("scan_verdict_missing_fields: %s"
                               % sorted(missing))
    # Structural validation only (no time-relative rules here).
    normalized = _statement_dict(
        stmt["scanner_name"], stmt["scanner_version"],
        stmt["scan_target_digest"], stmt["verdict"], stmt["ruleset_digest"],
        stmt.get("severity_counts"), stmt["scanned_at"], stmt["expires_at"],
        stmt["claim_bounds"])
    # Pin the canonical shape: the wire bytes must equal the canonical
    # re-derivation, so a non-canonical-but-equivalent JSON cannot slip
    # through (same discipline as gov.dsse_envelope.open_statement).
    if _statement_bytes(normalized) != bytes(payload):
        raise ScanVerdictError("scan_verdict_not_canonical: statement is "
                               "not in canonical form")
    return normalized


def peek_scan_verdict(envelope):
    """Structurally parse a scan-verdict envelope WITHOUT verifying its
    signature.

    Returns the canonical statement dict. Raises ScanVerdictError on
    any structural violation. This is how the gate learns a verdict's
    claimed scanner name (to find the pinned keyset) before signature
    verification -- it authenticates NOTHING and must never be used to
    admit anything.
    """
    payload, _payload_type, _sigs = _parse_envelope_strict(envelope)
    return _statement_from_payload(payload)


def _verify_threshold(payload, payload_type, sig_entries, verifiers,
                      threshold):
    """Distinct-key DSSE signature check over the pinned verifiers."""
    verifiers = list(verifiers)
    if not verifiers:
        raise ScanVerdictError("scan_verdict_no_verifiers: at least one "
                               "pinned verifier is required")
    if not all(isinstance(v, Verifier) for v in verifiers):
        raise ScanVerdictError("scan_verdict_bad_verifiers: verifiers "
                               "must be gov.signing.Verifier instances")
    if not isinstance(threshold, int) or isinstance(threshold, bool) \
            or threshold < 1:
        raise ScanVerdictError("threshold must be a positive int")
    pae_bytes = _dsse.pae(payload_type, payload)
    good = set()
    for keyid, sig in sig_entries:
        if keyid is None:
            matches = [v for v in verifiers if v.verify(pae_bytes, sig)]
        else:
            cand = [v for v in verifiers if v.key_id == keyid]
            if not cand:
                continue
            matches = [cand[0]] if cand[0].verify(pae_bytes, sig) else []
        for m in matches:
            good.add(m.key_id)
    if len(good) < threshold:
        raise ScanVerdictError(
            "scan_verdict_signature_invalid: %d of %d distinct pinned "
            "key(s) verified" % (len(good), threshold))
    return sorted(good)


def verify_scan_verdict(envelope, *, verifiers, scanner_name,
                        scan_target_digest, now=None, threshold=1):
    """Verify a scan-verdict envelope against the pinned scanner keyset.

    Checks, in order: strict envelope parse; payloadType binding;
    ``threshold`` distinct-key signatures over the PAE bytes against
    ``verifiers`` (the PINNED scanner keyset -- caller-owned);
    canonical statement shape; ``scanner_name`` match (a verdict for
    another scanner is not this scanner's verdict);
    ``scan_target_digest`` match (transplant refused); claim-bounds
    validation; freshness (``scanned_at <= now < expires_at``).

    Returns ``{"statement": <canonical statement dict>,
    "verified_key_ids": [...]}`` -- the authentication metadata rides
    BESIDE the signed statement, never mixed into it. Raises
    ScanVerdictError loudly on any violation -- including a stale
    verdict (``scan_verdict_stale``) and a not-yet-valid one
    (``scan_verdict_future_scan``).
    """
    now = _now() if now is None else _check_ts(now, "now")
    _check_name(scanner_name, "expected scanner_name")
    _check_pin(scan_target_digest, "expected scan_target_digest")
    payload, payload_type, sig_entries = _parse_envelope_strict(envelope)
    key_ids = _verify_threshold(payload, payload_type, sig_entries,
                                verifiers, threshold)
    stmt = _statement_from_payload(payload)  # strict shape + canonical pin
    if stmt["scanner_name"] != scanner_name:
        raise ScanVerdictError(
            "scan_verdict_scanner_mismatch: verdict names scanner %r, "
            "expected %r" % (stmt["scanner_name"], scanner_name))
    if stmt["scan_target_digest"] != scan_target_digest:
        raise ScanVerdictError(
            "scan_verdict_target_mismatch: verdict is bound to %s, "
            "presented for %s"
            % (stmt["scan_target_digest"], scan_target_digest))
    if stmt["scanned_at"] > now:
        raise ScanVerdictError(
            "scan_verdict_future_scan: scanned_at (%d) is after now (%d)"
            % (stmt["scanned_at"], now))
    if stmt["expires_at"] <= now:
        raise ScanVerdictError(
            "scan_verdict_stale: expires_at (%d) is not after now (%d) "
            "-- a stale verdict never admits"
            % (stmt["expires_at"], now))
    return {"statement": stmt, "verified_key_ids": key_ids}


# ---------------------------------------------------------------------------
# Policy: which scanner names are required (caller-owned, opt-in)
# ---------------------------------------------------------------------------

class ScanPolicy:
    """The promotion scan policy: which scanner names are REQUIRED.

    Fail-closed parsing: unknown fields, empty/duplicate names, and
    non-list shapes are refused. The DEFAULT policy requires nothing --
    the feature is opt-in and can never become silently mandatory for
    deployments that have not adopted scan gating.
    """

    _FIELDS = frozenset({"required_scans"})

    def __init__(self, required_scans=()):
        names = list(required_scans)
        for n in names:
            _check_name(n, "required_scans entry")
        if len(set(names)) != len(names):
            raise ScanVerdictError("scan_policy_duplicates: "
                                   "required_scans has duplicates")
        self._required = tuple(names)

    @property
    def required_scans(self):
        return self._required

    @classmethod
    def from_dict(cls, doc):
        if not isinstance(doc, dict):
            raise ScanVerdictError("scan_policy: must be a dict")
        extra = set(doc) - cls._FIELDS
        if extra:
            raise ScanVerdictError("scan_policy: unknown field(s) "
                                   "refused: %s" % sorted(extra))
        required = doc.get("required_scans", [])
        if not isinstance(required, (list, tuple)):
            raise ScanVerdictError("scan_policy: required_scans must be "
                                   "a list")
        return cls(required)

    def to_dict(self):
        return {"required_scans": list(self._required)}

    def __repr__(self):
        return "ScanPolicy(required_scans=%r)" % (list(self._required),)


# ---------------------------------------------------------------------------
# Gate: the promotion-seam check
# ---------------------------------------------------------------------------

class ScanGate:
    """The load-side holder of scan policy + pinned scanner keysets.

    ``keysets`` maps scanner name -> list of gov.signing.Verifier (the
    PINNED scanner keyset -- caller-owned, like the corpus-signing
    keyset in gov.load_gate). :meth:`check` is the promotion-seam
    consult: every presented envelope is verified, and every
    policy-required scanner name must have a verified ``pass`` verdict
    for the target digest.
    """

    def __init__(self, policy, keysets):
        if not isinstance(policy, ScanPolicy):
            raise ScanVerdictError("ScanGate policy must be a ScanPolicy")
        if not isinstance(keysets, dict):
            raise ScanVerdictError("ScanGate keysets must be a dict of "
                                   "scanner name -> [verifiers]")
        checked = {}
        for name, verifiers in keysets.items():
            _check_name(name, "keysets scanner name")
            verifiers = list(verifiers)
            if not verifiers:
                raise ScanVerdictError(
                    "ScanGate: keyset for %r has no verifiers" % name)
            if not all(isinstance(v, Verifier) for v in verifiers):
                raise ScanVerdictError(
                    "ScanGate: keyset for %r must hold gov.signing."
                    "Verifier instances" % name)
            checked[name] = verifiers
        self._policy = policy
        self._keysets = checked

    @property
    def policy(self):
        return self._policy

    def verifiers_for(self, scanner_name):
        """The pinned verifiers for ``scanner_name`` (None when
        unpinned)."""
        return self._keysets.get(scanner_name)

    def check(self, scan_target_digest, verdicts, *, now=None):
        """Consult the gate for promoting ``scan_target_digest``.

        ``verdicts`` is a list of presented scan-verdict DSSE envelopes.
        Returns ``{"ok": True, "checked": [...], "required": [...]}``.

        Refusals (all ScanVerdictError, all fail-closed):

        * a verdict from a scanner name with NO pinned keyset ->
          ``scan_verdict_unknown_scanner`` (loud, never silently
          ignored -- otherwise an attacker dodges a required scan by
          inventing a scanner name);
        * any envelope that fails verification (bad signature, wrong
          target, stale, malformed) -> the underlying refusal;
        * a policy-required scanner name with no verified verdict ->
          ``scan_verdict_missing``;
        * a verified ``fail``/``error`` verdict for a required name ->
          ``scan_verdict_negative`` (negative evidence dominates: a
          ``pass`` for the same name+target does not erase a ``fail``).
        """
        now = _now() if now is None else _check_ts(now, "now")
        _check_pin(scan_target_digest, "scan_target_digest")
        if not isinstance(verdicts, (list, tuple)):
            raise ScanVerdictError("scan_gate: verdicts must be a list "
                                   "of envelopes")
        verified_by_name = {}
        for i, envelope in enumerate(verdicts):
            try:
                claimed = peek_scan_verdict(envelope)["scanner_name"]
            except ScanVerdictError as e:
                raise ScanVerdictError(
                    "scan_gate: verdicts[%d] malformed: %s" % (i, e))
            keyset = self._keysets.get(claimed)
            if keyset is None:
                raise ScanVerdictError(
                    "scan_verdict_unknown_scanner: verdicts[%d] names "
                    "scanner %r, which has no pinned keyset -- refused, "
                    "never silently ignored" % (i, claimed))
            got = verify_scan_verdict(
                envelope, verifiers=keyset, scanner_name=claimed,
                scan_target_digest=scan_target_digest, now=now)
            verified_by_name.setdefault(claimed, []).append(got)
        for name in self._policy.required_scans:
            got_list = verified_by_name.get(name, [])
            if not got_list:
                raise ScanVerdictError(
                    "scan_verdict_missing: policy requires scanner %r "
                    "but no verified verdict for %s was presented"
                    % (name, scan_target_digest))
            bad = [g for g in got_list
                   if g["statement"]["verdict"] != VERDICT_PASS]
            if bad:
                raise ScanVerdictError(
                    "scan_verdict_negative: scanner %r recorded verdict "
                    "%r for %s -- promotion blocked"
                    % (name, bad[0]["statement"]["verdict"],
                       scan_target_digest))
        checked = sorted(n for n, gs in verified_by_name.items()
                         if all(g["statement"]["verdict"] == VERDICT_PASS
                                for g in gs))
        return {"ok": True,
                "checked": checked,
                "required": list(self._policy.required_scans)}

    def check_bytes(self, scan_bytes, verdicts, *, now=None):
        """Consult the gate for promoting the exact BYTES held.

        The digest context is derived here, from the bytes themselves,
        via :func:`digest_of_bytes` -- never from a caller-supplied
        digest string. This is the digest-binding consumption seam
        (wave-216): a deployment that hashes the claimant's manifest
        digest claim instead of the promoted bytes collapses the
        verdict binding (the npm/PyPI lesson -- "an attestation for one
        file must not verify for a different file in the same
        release"). Callers that hold the bytes promote through here;
        callers that only hold a digest claim they did not hash must
        not use :meth:`check` with it.

        Tighten-only and purely additive: this delegates to
        :meth:`check` with the computed digest, so every refusal code
        and the legacy string API are unchanged.
        """
        return self.check(digest_of_bytes(scan_bytes), verdicts, now=now)
