"""SLSA v1.2 decision VSAs: signed verification summaries for decisions (wave-315).

The evidence-envelope build order's last step: in-toto re-enveloping (wave-310)
-> Sigstore-bundle distribution (wave-311) -> offline verifier (wave-311) ->
Rekor-pattern witness (wave-314) -> **VSA decision packets (this module)**.

A VSA decision packet is a signed statement by a verifier: "I ran the offline
verification pipeline over the evidence chain for decision D (named by its
decision-packet digest) against policy P at time T with result R." It is
wrapped in the SLSA v1.2 ``verification_summary`` shape
(``predicateType: https://slsa.dev/verification_summary/v1``) inside a DSSE
envelope with the vendored payloadType
``application/vnd.sasanam.vsa-decision.v1+json``, so third-party policy
tooling can consume it as an in-toto statement.

What this module does NOT do (honest boundaries):
- It does not re-verify evidence. The offline pipeline
  (``gov.evidence_verify_offline.verify``) is the verifier; this module only
  *packages and consumes its report*. The consumer trusts the report's
  input-attestation digests as pins; re-verifying the underlying evidence is
  the offline verifier's job (layering, not a gap).
- It does not authorize. ``consume_vsa`` returns the verified claims and
  **never an authorization verdict**: ``verificationResult == PASSED`` is
  evidence input, not ``ALLOW`` (the PULSEmech principle from the prospectus).
  Admission stays the caller's explicit policy call; there is deliberately no
  ``admit()`` helper.
- A VSA does not protect against compromise of the verifier (SLSA's own
  warning). The pinned (signer, verifier) registry cannot detect a
  lying-but-pinned verifier.
- Freshness is consumer policy (``max_age_seconds``), not a credential
  property: the predicate carries no expiry field (SLSA parity).

Key custody: the signer holds the seed; this module never mints or stores
keys. Decision VSAs reuse the decision-packet signing key
(``gov.decision_packet.resolve_packet_key``: explicit seed > env > 0600 file,
no dev-key fallback). Sharing that key across statement types is explicit and
documented; the (signer, verifier) registry makes each pairing auditable, and
the envelope-domain registration refuses cross-type transplants.

Stdlib only. Deterministic: canonical JSON, no clock reads on the issue path
(time comes from the verification report), no randomness, no I/O, no env
reads in issue/consume (the signer helper reads env only when no explicit
seed is given, exactly like ``resolve_packet_key``).
"""

import base64
import binascii
import hashlib
import json
import time
from datetime import datetime, timezone

try:
    from . import ed25519 as _ed
except ImportError:  # standalone/offline: ed25519.py beside this file
    import ed25519 as _ed


def _trr():
    """Lazy handle on gov/trust_root_refresh (the _dsse() pattern above).

    trust_root_refresh is stdlib-only and loads ed25519 by file path,
    so either import route keeps the closure socket-free.
    """
    try:
        from . import trust_root_refresh as mod
    except ImportError:  # standalone/offline: trust_root_refresh.py beside
        import trust_root_refresh as mod  # this file
    return mod


def _dsse():
    """Lazy handle on gov/dsse_envelope (the decision_packet.py pattern).

    Registers the vsa_packet envelope domain (idempotent): a
    decision_packet envelope presented as a VSA refuses at the
    payloadType binding instead of verifying as the wrong kind.
    """
    try:
        from . import dsse_envelope as mod
    except ImportError:  # standalone/offline: dsse_envelope.py beside
        import dsse_envelope as mod  # this file
    mod.register_envelope_domain(VSA_DOMAIN, VSA_PAYLOAD_TYPE)
    return mod


def _decision_packet():
    """Lazy handle on gov/decision_packet (key ceremony only)."""
    try:
        from . import decision_packet as mod
    except ImportError:  # standalone/offline: decision_packet.py beside
        import decision_packet as mod  # this file
    return mod


#: SLSA v1.2 verification_summary predicate (the shape third-party
#: tooling consumes).
SLSA_VSA_PREDICATE = "https://slsa.dev/verification_summary/v1"

#: in-toto statement type wrapping the predicate.
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: Vendored DSSE payloadType (the repo's ``application/vnd.sasanam.*+json``
#: namespace; ``check_payload_type_namespace`` refuses anything else).
VSA_PAYLOAD_TYPE = "application/vnd.sasanam.vsa-decision.v1+json"

#: Envelope domain for transplant protection.
VSA_DOMAIN = "vsa_packet"

#: Closed vocabulary of asserted verification levels. The SLSA ranks are
#: reused; ``sasanam/evidence-chain/witnessed`` names the additional
#: evidence-chain property (witness inclusion) this product's verifier
#: can assert.
DECISION_VERIFIED_LEVELS = (
    "SLSA_BUILD_LEVEL_1",
    "SLSA_BUILD_LEVEL_2",
    "SLSA_BUILD_LEVEL_3",
    "sasanam/evidence-chain/witnessed",
)

#: decision identity scheme for resourceUri / attestation uris.
DECISION_URI_SCHEME = "sasanam:decision-packet/"

_HEX = frozenset("0123456789abcdef")

#: Closed refusal vocabulary for this seam (all registered decision codes).
_VERDICTS = frozenset((
    "vsa-packet-malformed",
    "vsa-packet-signature-invalid",
    "vsa-packet-signer-unpinned",
    "vsa-packet-subject-mismatch",
    "vsa-packet-predicate-mismatch",
    "vsa-packet-verifier-mismatch",
    "vsa-packet-resource-mismatch",
    "vsa-packet-result-not-passed",
    "vsa-packet-levels-missing",
    "vsa-packet-window-invalid",
    # trust-root chain discipline (wave-318): emitted when expected
    # carries a trust_chain and the chain fails (all registered in the
    # decision taxonomy).
    "trust-root-chain-malformed",
    "trust-root-rotation-invalid",
    "trust-root-silent-swap",
    "trust-root-stale-freshness",
    "trust-root-expired",
    "trust-root-receipt-unbound",
))


class VSAPacketError(Exception):
    """Fail-closed refusal. ``code`` is a closed-vocabulary member."""

    def __init__(self, code, detail=""):
        if code not in _VERDICTS:
            raise ValueError("unknown VSAPacket code %r" % (code,))
        super(VSAPacketError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _refuse(code, detail=""):
    raise VSAPacketError(code, detail)


def _canonical(obj):
    """Deterministic canonical JSON bytes (sort_keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def _as_hex64(value):
    """Lowercased 64-hex string, or None when ``value`` is not one."""
    if not isinstance(value, str) or len(value) != 64:
        return None
    low = value.lower()
    if any(c not in _HEX for c in low):
        return None
    return low


def _parse_rfc3339(value):
    """Parse ``YYYY-MM-DDTHH:MM:SSZ`` to epoch seconds; None on failure.

    The shape gate matches exactly what the offline pipeline emits
    (``evidence_verify_offline._fmt_time``); calendar validity is
    delegated to ``datetime.fromisoformat`` (the
    ``gov.rekor_v2_witness._parse_rfc3339`` precedent), so impossible
    dates like 2026-02-31 refuse instead of normalizing.
    """
    if not isinstance(value, str) or len(value) != 20:
        return None
    if value[4] != "-" or value[7] != "-" or value[10] != "T" \
            or value[13] != ":" or value[16] != ":" or value[19] != "Z":
        return None
    try:
        dt = datetime.fromisoformat(value[:19] + "+00:00")
    except ValueError:
        return None
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def _kid_of_pubkey(pubkey_hex):
    """Key id for the registry: ``sha256(pubkey)[:16]`` hex (the
    invocation-receipt / decision-packet convention). None when the
    pubkey is not 32 bytes hex."""
    try:
        pub = bytes.fromhex(pubkey_hex)
    except (ValueError, TypeError, AttributeError):
        return None
    if len(pub) != 32:
        return None
    return hashlib.sha256(pub).digest()[:16].hex()


class _PacketKeySigner(object):
    """DSSE signer over the decision-packet signing key (duck-typed for
    ``dsse_envelope.seal``: ``sign(bytes) -> bytes`` and ``key_id``)."""

    __slots__ = ("_seed", "key_id")

    def __init__(self, seed, key_id):
        self._seed = bytes(seed)
        self.key_id = key_id

    def sign(self, msg):
        return _ed.sign(self._seed, bytes(msg))


def packet_key_signer(seed_hex=None):
    """Resolve the packet-signing key into a DSSE signer.

    ``seed_hex`` (explicit 64-hex) wins; otherwise the
    ``GOV_DECISION_PACKET_KEY`` / ``GOV_DECISION_PACKET_KEY_FILE``
    idiom via ``decision_packet.resolve_packet_key``. No dev-key
    fallback, ever. ``key_id`` follows the invocation-receipt /
    decision-packet convention (``sha256(pubkey)[:16]`` hex).
    """
    if seed_hex is not None and not isinstance(seed_hex, str):
        raise ValueError("seed_hex must be a 64-hex string or None")
    resolved = _decision_packet().resolve_packet_key(seed_hex)
    return _PacketKeySigner(resolved["seed"], resolved["key_id"])


def _report_claims(report):
    """Extract the VSA claims from an offline-verification report.

    Issuer-side: malformed inputs are the ISSUER's error -> ValueError
    (the ``issue_bundle_vsa`` precedent). In particular a report that is
    not VALID/PASSED can never be minted into a PASSED VSA.
    """
    if not isinstance(report, dict):
        raise ValueError("report must be a dict")
    if report.get("status") != "VALID":
        raise ValueError("only a VALID report can back a VSA "
                         "(got status %r)" % (report.get("status"),))
    if report.get("verificationResult") != "PASSED":
        raise ValueError("only a PASSED report can back a VSA "
                         "(got %r)" % (report.get("verificationResult"),))
    verifier = report.get("verifier")
    if not isinstance(verifier, dict) \
            or not isinstance(verifier.get("id"), str) \
            or not verifier["id"] \
            or not isinstance(verifier.get("version"), str) \
            or not verifier["version"]:
        raise ValueError("report.verifier must name {id, version}")
    time_verified = report.get("timeVerified")
    if _parse_rfc3339(time_verified) is None:
        raise ValueError("report.timeVerified must be RFC3339 UTC")
    time_source = report.get("timeSource")
    if not isinstance(time_source, dict):
        raise ValueError("report.timeSource must be an object")
    clock_name = time_source.get("name")
    if not isinstance(clock_name, str) or not clock_name:
        raise ValueError("report.timeSource.name must be a non-empty string")
    policy = report.get("policy")
    if not isinstance(policy, dict) \
            or not isinstance(policy.get("uri"), str) \
            or not policy["uri"]:
        raise ValueError("report.policy.uri must be a non-empty string")
    policy_digest_raw = policy.get("digest")
    if not isinstance(policy_digest_raw, dict):
        raise ValueError("report.policy.digest must be an object")
    policy_digest = _as_hex64(policy_digest_raw.get("sha256"))
    if policy_digest is None:
        raise ValueError("report.policy.digest.sha256 must be 64 hex")
    attestations = []
    raw_atts = report.get("inputAttestations") or []
    if not isinstance(raw_atts, (list, tuple)):
        raise ValueError("report.inputAttestations must be a list")
    for entry in raw_atts:
        if not isinstance(entry, dict) \
                or not isinstance(entry.get("uri"), str) \
                or not entry["uri"]:
            raise ValueError("inputAttestation entries need a uri")
        entry_digest = entry.get("digest")
        if not isinstance(entry_digest, dict):
            raise ValueError("inputAttestation entries need a digest object")
        digest = _as_hex64(entry_digest.get("sha256"))
        if digest is None:
            raise ValueError("inputAttestation entries need a 64-hex digest")
        attestations.append({"uri": entry["uri"],
                             "digest": {"sha256": digest}})
    witnessed = report.get("witness") is not None
    return {
        "verifier": {"id": verifier["id"], "version": verifier["version"]},
        "time_verified": time_verified,
        "clock_name": clock_name,
        "policy_uri": policy["uri"],
        "policy_digest": policy_digest,
        "input_attestations": attestations,
        "witnessed": witnessed,
        "witness_info": report.get("witness"),
    }


def levels_for_report(report):
    """Convenience mapping from a VALID report to asserted levels.

    Base ``SLSA_BUILD_LEVEL_1`` (the pipeline ran); plus
    ``sasanam/evidence-chain/witnessed`` when the report carries witness
    info. The issuer passes levels explicitly; this helper only suggests.
    """
    claims = _report_claims(report)  # validates VALID/PASSED too
    levels = ["SLSA_BUILD_LEVEL_1"]
    if claims["witnessed"]:
        levels.append("sasanam/evidence-chain/witnessed")
    return levels


def _check_levels(levels):
    """Closed-vocabulary assertion; issuer-side errors are ValueError."""
    if not isinstance(levels, (list, tuple)) or not levels:
        raise ValueError("verified_levels must be a non-empty list")
    for level in levels:
        if level not in DECISION_VERIFIED_LEVELS:
            raise ValueError("unknown verified level %r" % (level,))
    return list(levels)


def issue_decision_vsa(*, decision_digest, report, verified_levels, signer):
    """Issue the signed VSA decision packet for one decision.

    ``decision_digest`` is the decision-packet digest the VSA names as its
    subject. ``report`` is the VALID offline-verification report over the
    decision's evidence chain. ``verified_levels`` is the explicit closed
    vocabulary assertion (see :func:`levels_for_report`). ``signer`` is a
    DSSE signer (``sign(bytes) -> bytes``, ``key_id`` str); see
    :func:`packet_key_signer`.

    Returns the DSSE envelope dict. Issuer-side input errors raise
    ``ValueError``; the envelope is only ever sealed over VALID/PASSED
    evidence, so a PASSED VSA cannot be minted over failed evidence.
    """
    digest = _as_hex64(decision_digest)
    if digest is None:
        raise ValueError("decision_digest must be 64 hex chars")
    claims = _report_claims(report)
    levels = _check_levels(verified_levels)
    if signer is None or not callable(getattr(signer, "sign", None)) \
            or not isinstance(getattr(signer, "key_id", None), str):
        raise ValueError("signer must expose sign(bytes) and key_id str")
    try:
        report_digest = hashlib.sha256(_canonical(report)).hexdigest()
    except (TypeError, ValueError) as exc:
        raise ValueError("report is not JSON-serializable: %s" % (exc,))
    attestations = list(claims["input_attestations"])
    attestations.append({"uri": DECISION_URI_SCHEME + digest,
                         "digest": {"sha256": digest}})
    if claims["witnessed"]:
        try:
            witness_digest = hashlib.sha256(
                _canonical(claims["witness_info"])).hexdigest()
        except (TypeError, ValueError) as exc:
            raise ValueError("report.witness is not JSON-serializable: %s"
                             % (exc,))
        attestations.append({"uri": "sasanam:witness-info",
                             "digest": {"sha256": witness_digest}})
    statement = {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [{"name": "sasanam-decision-packet",
                     "digest": {"sha256": digest}}],
        "predicateType": SLSA_VSA_PREDICATE,
        "predicate": {
            "verifier": claims["verifier"],
            "timeVerified": claims["time_verified"],
            "timeSource": {"name": claims["clock_name"]},
            "resourceUri": DECISION_URI_SCHEME + digest,
            "policy": {"uri": claims["policy_uri"],
                       "digest": {"sha256": claims["policy_digest"]}},
            "inputAttestations": attestations,
            "verificationResult": "PASSED",
            "verifiedLevels": levels,
            "sasanamExtensions": {
                "reportDigest": report_digest,
                "witnessed": claims["witnessed"],
            },
        },
    }
    return _dsse().seal(_canonical(statement), VSA_PAYLOAD_TYPE, [signer])


def _expected_claims(expected):
    """Validate the consumer's expectations (caller errors -> ValueError)."""
    if not isinstance(expected, dict):
        raise ValueError("expected must be a dict")
    for key in ("subject_digest", "resource_uri", "verifier_id",
                "required_level", "signer_registry", "max_age_seconds"):
        if key not in expected:
            raise ValueError("expected is missing %r" % (key,))
    subject = _as_hex64(expected["subject_digest"])
    if subject is None:
        raise ValueError("expected subject_digest must be 64 hex")
    if not isinstance(expected["resource_uri"], str) \
            or not expected["resource_uri"]:
        raise ValueError("expected resource_uri must be a non-empty string")
    if not isinstance(expected["verifier_id"], str) \
            or not expected["verifier_id"]:
        raise ValueError("expected verifier_id must be a non-empty string")
    if expected["required_level"] not in DECISION_VERIFIED_LEVELS:
        raise ValueError("expected required_level %r is not a known level"
                         % (expected["required_level"],))
    registry = expected["signer_registry"]
    if not isinstance(registry, dict) or not registry:
        raise ValueError("expected signer_registry must be a non-empty dict")
    for vid, keys in registry.items():
        if not isinstance(vid, str) or not vid:
            raise ValueError("signer_registry verifier ids must be strings")
        if not isinstance(keys, (list, tuple)) or not keys:
            raise ValueError("signer_registry entries must be non-empty lists")
        for pub in keys:
            if _kid_of_pubkey(pub) is None:
                raise ValueError("signer_registry holds a malformed pubkey")
    max_age = expected["max_age_seconds"]
    if isinstance(max_age, bool) or not isinstance(max_age, (int, float)) \
            or not (max_age == max_age) \
            or max_age in (float("inf"), float("-inf")) or max_age <= 0:
        raise ValueError("expected max_age_seconds must be a positive "
                         "finite number")
    now = expected.get("now")
    if now is None:
        now = time.time()  # the wave-279 verifier precedent
    if isinstance(now, bool) or not isinstance(now, (int, float)) \
            or not (now == now) \
            or now in (float("inf"), float("-inf")):
        raise ValueError("expected now must be a finite number or None")
    tc = expected.get("trust_chain")
    if tc is not None:
        # Optional trust-root chain discipline (wave-318): the VSA is
        # consumed only under a live, fresh trust root. Validated here
        # (caller errors -> ValueError); enforced in consume_vsa after
        # the signature check, with the VSA's timeVerified as the bundle
        # timestamp (expiry evaluated at the timestamp's time).
        if not isinstance(tc, dict):
            raise ValueError("expected trust_chain must be a dict")
        if not isinstance(tc.get("chain"), list) or not tc["chain"]:
            raise ValueError("expected trust_chain.chain must be a "
                             "non-empty list")
        freshness = tc.get("freshness")
        if freshness is not None and not isinstance(freshness, dict):
            raise ValueError("expected trust_chain.freshness must be a "
                             "dict or None")
        tc_max_age = tc.get("max_age_seconds", 86400)
        if isinstance(tc_max_age, bool) \
                or not isinstance(tc_max_age, (int, float)) \
                or not (tc_max_age == tc_max_age) \
                or tc_max_age in (float("inf"), float("-inf")) \
                or tc_max_age <= 0:
            raise ValueError("expected trust_chain.max_age_seconds must be "
                             "a positive finite number")
        tc = {"chain": tc["chain"], "freshness": freshness,
              "max_age_seconds": float(tc_max_age)}
    return {
        "subject_digest": subject,
        "resource_uri": expected["resource_uri"],
        "verifier_id": expected["verifier_id"],
        "required_level": expected["required_level"],
        "signer_registry": registry,
        "max_age_seconds": float(max_age),
        "now": float(now),
        "trust_chain": tc,
    }


def _open_envelope(envelope):
    """Strict envelope open (shape only); signature comes later."""
    if not isinstance(envelope, dict):
        _refuse("vsa-packet-malformed",
                "envelope must be a dict")
    fields = set(envelope)
    if fields != {"payload", "payloadType", "signatures"}:
        _refuse("vsa-packet-malformed",
                "envelope fields must be exactly "
                "{payload, payloadType, signatures}")
    if envelope["payloadType"] != VSA_PAYLOAD_TYPE:
        _refuse("vsa-packet-malformed",
                "payloadType %r is not a VSA decision packet"
                % (envelope["payloadType"],))
    sigs = envelope["signatures"]
    if not isinstance(sigs, list) or len(sigs) != 1 \
            or not isinstance(sigs[0], dict):
        _refuse("vsa-packet-malformed",
                "envelope must carry exactly one signature")
    entry = sigs[0]
    keyid = entry.get("keyid")
    sig_hex = entry.get("sig")
    if not isinstance(keyid, str) or not keyid:
        _refuse("vsa-packet-malformed",
                "signature entry needs a keyid")
    try:
        sig = bytes.fromhex(sig_hex) if isinstance(sig_hex, str) else None
    except (ValueError, TypeError):
        sig = None
    if sig is None or len(sig) != 64:
        _refuse("vsa-packet-malformed",
                "signature is not 64 bytes hex")
    try:
        payload_bytes = base64.b64decode(envelope["payload"], validate=True)
    except (binascii.Error, ValueError, TypeError):
        _refuse("vsa-packet-malformed",
                "payload is not valid base64")
    try:
        statement = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        _refuse("vsa-packet-malformed",
                "payload is not JSON")
    if not isinstance(statement, dict):
        _refuse("vsa-packet-malformed",
                "statement must be a JSON object")
    return payload_bytes, statement, keyid, sig


def _predicate_claims(statement):
    """Extract the predicate claims; hostile shapes refuse machine-coded."""
    if statement.get("_type") != IN_TOTO_STATEMENT_TYPE:
        _refuse("vsa-packet-malformed",
                "statement _type is not the in-toto statement type")
    if statement.get("predicateType") != SLSA_VSA_PREDICATE:
        _refuse("vsa-packet-predicate-mismatch",
                "predicateType %r is not the SLSA verification_summary"
                % (statement.get("predicateType"),))
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1 \
            or not isinstance(subjects[0], dict):
        _refuse("vsa-packet-malformed",
                "subject must be a single-element list")
    subject_digest_raw = subjects[0].get("digest")
    if not isinstance(subject_digest_raw, dict):
        _refuse("vsa-packet-malformed",
                "subject digest must be an object")
    subject_digest = _as_hex64(subject_digest_raw.get("sha256"))
    if subject_digest is None:
        _refuse("vsa-packet-malformed",
                "subject carries no 64-hex sha256 digest")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        _refuse("vsa-packet-malformed",
                "predicate must be an object")
    verifier = predicate.get("verifier")
    verifier_id = verifier.get("id") if isinstance(verifier, dict) else None
    if not isinstance(verifier_id, str) or not verifier_id:
        _refuse("vsa-packet-malformed",
                "predicate.verifier.id must be a non-empty string")
    resource_uri = predicate.get("resourceUri")
    if not isinstance(resource_uri, str) or not resource_uri:
        _refuse("vsa-packet-malformed",
                "predicate.resourceUri must be a non-empty string")
    result = predicate.get("verificationResult")
    levels = predicate.get("verifiedLevels")
    if not isinstance(levels, list):
        _refuse("vsa-packet-malformed",
                "predicate.verifiedLevels must be a list")
    time_verified = predicate.get("timeVerified")
    policy = predicate.get("policy") or {}
    attestations = predicate.get("inputAttestations")
    if not isinstance(attestations, list):
        _refuse("vsa-packet-malformed",
                "predicate.inputAttestations must be a list")
    return {
        "subject_digest": subject_digest,
        "verifier_id": verifier_id,
        "verifier": verifier,
        "resource_uri": resource_uri,
        "verification_result": result,
        "verified_levels": levels,
        "time_verified": time_verified,
        "policy": policy,
        "input_attestations": attestations,
    }


def consume_vsa(envelope, *, expected):
    """Run the SLSA v1.2 VSA consumer procedure (the seven mandatory steps,
    plus the envelope-shape binding and the consumer freshness window).

    ``expected`` names what the consumer requires::

        {"subject_digest", "resource_uri", "verifier_id", "required_level",
         "signer_registry": {verifier_id: [pubkey_hex, ...]},
         "now" (None -> wall clock), "max_age_seconds"}

    Optional ``trust_chain``: ``{"chain": [...], "freshness": {...},
    "max_age_seconds": N}`` -- when present, the VSA is consumed only
    under a live, fresh trust root (the wave-318 trust-root chain
    discipline); a stale, exhausted, or silently-swapped root refuses
    with a coded ``trust-root-*`` error.

    Checks, in order, fail-closed: (0) envelope shape and the VSA
    payloadType binding; (1) the expected verifier id is pinned, the
    envelope keyid is pinned for that id -- "consumers MUST accept only
    specific (signer, verifier) pairs" -- and the signature verifies;
    (2) in-toto statement type; (3) the SLSA verification_summary
    predicateType; (4) subject digest matches; (5) the statement's
    verifier id equals the expected verifier id; (6) resourceUri matches;
    (7) verificationResult is PASSED; (8) verifiedLevels contains the
    required level; (9) timeVerified parses and ``now`` falls inside
    ``[timeVerified, timeVerified + max_age_seconds]``.

    Returns the verified claims ``{"ok": True, "subject_digest",
    "verifier", "policy", "time_verified", "verified_levels",
    "input_attestations"}``. **There is no authorization verdict in the
    return value**: ``PASSED`` is evidence input, not ``ALLOW``. Admission
    is the caller's separate, explicit policy decision.
    """
    exp = _expected_claims(expected)
    payload_bytes, statement, keyid, sig = _open_envelope(envelope)
    registry = exp["signer_registry"]
    pinned_keys = registry.get(exp["verifier_id"])
    if not pinned_keys:
        # The consumer expects a verifier it has not pinned: no pair to
        # check against. (SLSA: accept only specific (signer, verifier)
        # pairs.)
        _refuse("vsa-packet-verifier-mismatch",
                "verifier %r is not pinned" % (exp["verifier_id"],))
    pinned_kids = {_kid_of_pubkey(pub) for pub in pinned_keys}
    if keyid not in pinned_kids:
        _refuse("vsa-packet-signer-unpinned",
                "signing key %r is not pinned for verifier %r"
                % (keyid, exp["verifier_id"]))
    pub_hex = next(pub for pub in pinned_keys
                   if _kid_of_pubkey(pub) == keyid)
    pae_bytes = _dsse().pae(VSA_PAYLOAD_TYPE, payload_bytes)
    # verify() returns True/False and never raises -- check the False
    # (the wave-243 lesson).
    if _ed.verify(bytes.fromhex(pub_hex), pae_bytes, sig) is not True:
        _refuse("vsa-packet-signature-invalid",
                "envelope signature does not verify under the pinned key")
    claims = _predicate_claims(statement)
    if claims["subject_digest"] != exp["subject_digest"]:
        _refuse("vsa-packet-subject-mismatch",
                "VSA subject does not match the expected decision")
    if claims["verifier_id"] != exp["verifier_id"]:
        _refuse("vsa-packet-verifier-mismatch",
                "statement verifier %r is not the expected verifier %r"
                % (claims["verifier_id"], exp["verifier_id"]))
    if claims["resource_uri"] != exp["resource_uri"]:
        _refuse("vsa-packet-resource-mismatch",
                "resourceUri %r does not match" % (claims["resource_uri"],))
    if claims["verification_result"] != "PASSED":
        _refuse("vsa-packet-result-not-passed",
                "verificationResult is %r, not PASSED"
                % (claims["verification_result"],))
    if exp["required_level"] not in claims["verified_levels"]:
        _refuse("vsa-packet-levels-missing",
                "required level %r not in verifiedLevels"
                % (exp["required_level"],))
    verified_at = _parse_rfc3339(claims["time_verified"])
    if verified_at is None:
        _refuse("vsa-packet-window-invalid",
                "timeVerified is not RFC3339 UTC")
    if not (verified_at <= exp["now"]
            <= verified_at + exp["max_age_seconds"]):
        _refuse("vsa-packet-window-invalid",
                "timeVerified is outside the consumer window")
    tc = exp["trust_chain"]
    if tc is not None:
        # Trust-root chain discipline: the chain must be structurally
        # valid with a fresh signal at consumption time, and the tip
        # must have been valid at the VSA's timeVerified (expiry at the
        # timestamp's time, per CVE-2026-24122). A stale, exhausted, or
        # silently-swapped root refuses with a coded trust-root-* error.
        trr = _trr()
        try:
            tip = trr.verify_chain(
                tc["chain"], freshness=tc["freshness"],
                bundle_timestamp=datetime.fromtimestamp(
                    verified_at, tz=timezone.utc),
                now=datetime.fromtimestamp(exp["now"], tz=timezone.utc),
                max_age_seconds=tc["max_age_seconds"])
        except trr.TrustRootError as exc:
            _refuse(exc.code, exc.detail)
    return {
        "ok": True,
        "subject_digest": claims["subject_digest"],
        "verifier": claims["verifier"],
        "policy": claims["policy"],
        "time_verified": claims["time_verified"],
        "verified_levels": list(claims["verified_levels"]),
        "input_attestations": claims["input_attestations"],
    }
