"""Multi-verifier threshold VSA decision packets (wave-324).

The wave-315 ``gov/vsa_packet.py`` is a complete SINGLE-verifier SLSA v1.2
decision VSA: one verifier, one signature, one pinned (signer, verifier)
pair. This module is the genuinely missing piece: a THRESHOLD VSA, where
k-of-n independent verifiers co-sign one statement over a decision-packet
digest and the consumer enforces the quorum.

A threshold VSA is a quorum statement: "k of these n named verifiers each
ran verification over decision D against policy P at their stated time
with result R, and they all agree on D, P, R, and the verified inputs."
Every verifier signs the SAME canonical statement plus their own
identity descriptor, so decision-digest binding and input-digest binding
hold for every co-signature: transplanting the VSA to another decision,
substituting the verified inputs, or replaying a signature under another
verifier's name all break verification.

Packet shape (``sasanam-threshold-vsa/1``)::

    {
      "type": "sasanam-threshold-vsa/1",
      "subject": {"decision_digest": "<64 hex>"},
      "verdict": "PASSED",
      "verified_levels": ["decision-evidence-complete", ...],
      "inputs": {
        "policy": {"uri": str, "digest": "<64 hex>",
                   "policy_id": str, "version": int},
        "artifact_digests": {"<name>": "<64 hex>"},
        "evidence_references": ["<str>", ...],
      },
      "threshold": 2,
      "attestations": [
        {"verifier_id": str, "key_id": str,
         "time_verified": "<RFC3339 UTC>", "signature": "<128 hex>"}
      ],
    }

Each attestation signature is Ed25519 over::

    SIGN_DOMAIN || canonical(statement) || 0x00 ||
        canonical({"verifier_id", "key_id", "time_verified"})

where ``statement`` is the packet without the ``attestations`` list. The
attestation roster itself is deliberately NOT part of the signed
statement: the packet is a bag of independent attestations over one
common statement, and dropping an attestation can only LOWER the valid
count (the fail-closed direction) -- it can never manufacture quorum.
The per-attestation identity descriptor binds each signature to its
verifier, so a signature cannot be replayed across verifiers or across
decisions.

``issue_vsa(decision, verifications, signers, threshold)`` builds the
packet. All verifications must AGREE (same verdict, levels, inputs) --
disagreement is a ceremony/coordinator caller error (``ValueError``),
never a silently-issued packet.

``verify_vsa(packet, trust)`` runs the threshold consumer procedure,
fail-closed, with coded ``VSAThresholdError`` refusals (never a soft
False):

1. shape (unknown fields refuse) -- ``vsa-packet-malformed``
2. threshold sanity (1 <= k <= n) -- ``vsa-packet-malformed``
3. verdict PASSED -- ``vsa-threshold-verdict-not-passed``
4. required level asserted -- ``vsa-packet-levels-missing``
5. per-attestation: verifier pinned, key pinned for that verifier
   (``vsa-threshold-signer-unpinned``), signature verifies
   (``vsa-threshold-signature-invalid``); distinct verifier ids counted
   once -- no double-count
6. distinct valid >= threshold -- ``vsa-threshold-below-quorum``
   (the consumer may also demand ``min_threshold`` >= the packet's)
7. subject binding -- ``vsa-packet-subject-mismatch``
8. freshness per attestation -- ``vsa-packet-window-invalid``
9. policy-version currency -- ``vsa-threshold-policy-stale``

Honest boundaries (shared with ``gov/vsa_packet.py``):
- ``verify_vsa`` returns the verified CLAIMS, never an authorization
  verdict: ``verdict == "PASSED"`` is evidence input, not ``ALLOW``.
  Admission stays the caller's explicit policy call.
- A threshold VSA does not protect against compromise of the verifiers
  (SLSA's own warning). The pinned registry cannot detect
  lying-but-pinned verifiers; the threshold only bounds how many must
  collude.
- Key custody: signers hold the seeds; this module never mints keys.

Stdlib only. Deterministic: canonical JSON, no randomness, no I/O, no
env reads. Times are caller-supplied; ``trust["now"]`` defaults to the
wall clock only when the caller passes None (the wave-279 verifier
precedent, same as ``gov/vsa_packet.py``) -- pass an explicit ``now``
for deterministic verification.
"""

import hashlib
import json

try:
    from . import ed25519 as _ed
except ImportError:  # standalone/offline: ed25519.py beside this file
    import ed25519 as _ed


PACKET_TYPE = "sasanam-threshold-vsa/1"
SIGN_DOMAIN = b"sasanam-threshold-vsa/1\x00"

_VSA_PACKET_MALFORMED = "vsa-packet-malformed"
_VSA_PACKET_SUBJECT_MISMATCH = "vsa-packet-subject-mismatch"
_VSA_PACKET_LEVELS_MISSING = "vsa-packet-levels-missing"
_VSA_PACKET_WINDOW_INVALID = "vsa-packet-window-invalid"
_VSA_THRESHOLD_BELOW_QUORUM = "vsa-threshold-below-quorum"
_VSA_THRESHOLD_POLICY_STALE = "vsa-threshold-policy-stale"
_VSA_THRESHOLD_SIGNATURE_INVALID = "vsa-threshold-signature-invalid"
_VSA_THRESHOLD_SIGNER_UNPINNED = "vsa-threshold-signer-unpinned"
_VSA_THRESHOLD_VERDICT_NOT_PASSED = "vsa-threshold-verdict-not-passed"

_TOP_FIELDS = frozenset(
    ["type", "subject", "verdict", "verified_levels", "inputs",
     "threshold", "attestations"])
_SUBJECT_FIELDS = frozenset(["decision_digest"])
_INPUTS_FIELDS = frozenset(["policy", "artifact_digests",
                            "evidence_references"])
_POLICY_FIELDS = frozenset(["uri", "digest", "policy_id", "version"])
_ATTESTATION_FIELDS = frozenset(["verifier_id", "key_id", "time_verified",
                                 "signature"])
_DESCRIPTOR_FIELDS = frozenset(["verifier_id", "key_id", "time_verified"])


class VSAThresholdError(Exception):
    """Coded refusal from the threshold-VSA consumer (fail-closed)."""

    def __init__(self, code, detail=""):
        super(VSAThresholdError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail=""):
    raise VSAThresholdError(code, detail)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _is_hex(value, length):
    return (isinstance(value, str) and len(value) == length
            and all(c in "0123456789abcdefABCDEF" for c in value))


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_rfc3339(value):
    """Epoch seconds for a strict RFC3339 UTC timestamp, else None."""
    if not isinstance(value, str) or len(value) != 20:
        return None
    if not (value[4] == "-" and value[7] == "-" and value[10] == "T"
            and value[13] == ":" and value[16] == ":" and value.endswith("Z")):
        return None
    digits = value[0:4] + value[5:7] + value[8:10] + value[11:13] \
        + value[14:16] + value[17:19]
    if not digits.isdigit():
        return None
    import calendar
    try:
        return calendar.timegm((
            int(value[0:4]), int(value[5:7]), int(value[8:10]),
            int(value[11:13]), int(value[14:16]), int(value[17:19]),
            0, 0, 0))
    except (ValueError, OverflowError):
        return None


def _decision_packet():
    try:
        from . import decision_packet as mod
    except ImportError:
        import decision_packet as mod
    return mod


def _statement(packet):
    """The common signed statement: the packet without attestations."""
    return {k: v for k, v in packet.items() if k != "attestations"}


def attestation_signing_input(packet, attestation):
    """Domain-separated signing input for one attestation.

    ``SIGN_DOMAIN || canonical(statement) || 0x00 ||
    canonical({verifier_id, key_id, time_verified})`` -- the signature
    binds the common statement AND the signer's identity descriptor, so
    it cannot be replayed across verifiers or decisions.
    """
    statement = _statement(packet)
    descriptor = {k: attestation[k] for k in _DESCRIPTOR_FIELDS}
    return (SIGN_DOMAIN + _canonical(statement) + b"\x00"
            + _canonical(descriptor))


def _normalize_verification(verification):
    """Validated (verdict, levels, inputs, time) or ValueError."""
    if not isinstance(verification, dict):
        raise ValueError("verification must be a dict")
    for key in ("verifier_id", "verdict", "verified_levels", "inputs",
                "time_verified"):
        if key not in verification:
            raise ValueError("verification is missing %r" % (key,))
    vid = verification["verifier_id"]
    if not isinstance(vid, str) or not vid:
        raise ValueError("verifier_id must be a non-empty string")
    verdict = verification["verdict"]
    if verdict not in ("PASSED", "FAILED"):
        raise ValueError("verdict must be PASSED or FAILED")
    levels = verification["verified_levels"]
    if (not isinstance(levels, (list, tuple)) or not levels
            or any(not isinstance(l, str) or not l for l in levels)):
        raise ValueError("verified_levels must be a non-empty list of str")
    inputs = verification["inputs"]
    _check_inputs_shape(inputs)
    if _parse_rfc3339(verification["time_verified"]) is None:
        raise ValueError("time_verified must be RFC3339 UTC")
    return {
        "verifier_id": vid,
        "verdict": verdict,
        "verified_levels": list(levels),
        "inputs": json.loads(_canonical(inputs)),
        "time_verified": verification["time_verified"],
    }


def _check_inputs_shape(inputs):
    if not isinstance(inputs, dict):
        raise ValueError("inputs must be a dict")
    if set(inputs.keys()) != _INPUTS_FIELDS:
        raise ValueError("inputs must have exactly %s"
                         % (sorted(_INPUTS_FIELDS),))
    policy = inputs["policy"]
    if not isinstance(policy, dict) or set(policy.keys()) != _POLICY_FIELDS:
        raise ValueError("inputs.policy must have exactly %s"
                         % (sorted(_POLICY_FIELDS),))
    if not isinstance(policy["uri"], str) or not policy["uri"]:
        raise ValueError("inputs.policy.uri must be a non-empty string")
    if not _is_hex(policy["digest"], 64):
        raise ValueError("inputs.policy.digest must be 64 hex")
    if not isinstance(policy["policy_id"], str) or not policy["policy_id"]:
        raise ValueError("inputs.policy.policy_id must be non-empty")
    if not _is_int(policy["version"]):
        raise ValueError("inputs.policy.version must be an int")
    digests = inputs["artifact_digests"]
    if (not isinstance(digests, dict)
            or any(not isinstance(k, str) or not k for k in digests)
            or any(not _is_hex(v, 64) for v in digests.values())):
        raise ValueError("inputs.artifact_digests must map names to 64 hex")
    refs = inputs["evidence_references"]
    if (not isinstance(refs, (list, tuple))
            or any(not isinstance(r, str) for r in refs)):
        raise ValueError("inputs.evidence_references must be a list of str")


def issue_vsa(decision, verifications, signers, threshold):
    """Issue the threshold VSA packet for one decision.

    ``decision`` is a decision-packet dict (its digest is computed via
    ``gov.decision_packet.packet_digest``) or a 64-hex digest string.
    ``verifications`` is one dict per co-signing verifier:
    ``{verifier_id, verdict, verified_levels, inputs, time_verified}``.
    ``signers`` is one ``{verifier_id, key_id, sign}`` per verifier, in
    the same order. ``threshold`` k: 1 <= k <= len(signers).

    Every verification must AGREE on the verdict, levels, and inputs --
    a threshold VSA is a quorum statement, and disagreement is a
    ceremony caller error (``ValueError``), never a silently-issued
    packet. Each signer signs the common statement plus their own
    identity descriptor.

    Returns the packet dict. Issuer-side input errors raise
    ``ValueError``.
    """
    if isinstance(decision, dict):
        digest = _decision_packet().packet_digest(decision)
    elif _is_hex(decision, 64):
        digest = decision.lower()
    else:
        raise ValueError("decision must be a decision-packet dict or 64 hex")
    if not isinstance(verifications, (list, tuple)) or not verifications:
        raise ValueError("verifications must be a non-empty list")
    if not isinstance(signers, (list, tuple)) or not signers:
        raise ValueError("signers must be a non-empty list")
    if len(verifications) != len(signers):
        raise ValueError("verifications and signers must align 1:1")
    if not _is_int(threshold) or not 1 <= threshold <= len(signers):
        raise ValueError("threshold must satisfy 1 <= k <= %d"
                         % (len(signers),))
    normed = [_normalize_verification(v) for v in verifications]
    first = normed[0]
    for other in normed[1:]:
        for key in ("verdict", "verified_levels", "inputs"):
            if other[key] != first[key]:
                raise ValueError(
                    "verifier %r disagrees on %s: threshold VSAs require "
                    "unanimous verifications" % (other["verifier_id"], key))
    seen_ids = set()
    for signer in signers:
        if not isinstance(signer, dict):
            raise ValueError("signer must be a dict")
        key_id = signer.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("signer key_id must be a non-empty string")
        if not callable(signer.get("sign")):
            raise ValueError("signer sign must be callable")
    packet = {
        "type": PACKET_TYPE,
        "subject": {"decision_digest": digest},
        "verdict": first["verdict"],
        "verified_levels": first["verified_levels"],
        "inputs": first["inputs"],
        "threshold": threshold,
        "attestations": [],
    }
    for verification, signer in zip(normed, signers):
        vid = verification["verifier_id"]
        if signer.get("verifier_id") != vid:
            raise ValueError("signer/verifier alignment mismatch")
        if vid in seen_ids:
            raise ValueError("duplicate verifier_id %r in issuance" % (vid,))
        seen_ids.add(vid)
        packet["attestations"].append({
            "verifier_id": vid,
            "key_id": signer["key_id"],
            "time_verified": verification["time_verified"],
            "signature": None,
        })
    for attestation, signer in zip(packet["attestations"], signers):
        msg = attestation_signing_input(packet, attestation)
        sig = signer["sign"](msg)
        if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
            raise ValueError("signer must return 64 signature bytes")
        attestation["signature"] = bytes(sig).hex()
    return packet


def _check_packet_shape(packet):
    """Structural validation; refuses vsa-packet-malformed."""
    if not isinstance(packet, dict):
        _refuse(_VSA_PACKET_MALFORMED, "packet must be a dict")
    if set(packet.keys()) != _TOP_FIELDS:
        _refuse(_VSA_PACKET_MALFORMED,
                "packet must have exactly %s" % (sorted(_TOP_FIELDS),))
    if packet["type"] != PACKET_TYPE:
        _refuse(_VSA_PACKET_MALFORMED,
                "packet type %r is not %r" % (packet["type"], PACKET_TYPE))
    subject = packet["subject"]
    if not isinstance(subject, dict) or set(subject.keys()) != _SUBJECT_FIELDS:
        _refuse(_VSA_PACKET_MALFORMED, "subject must name a decision_digest")
    if not _is_hex(subject["decision_digest"], 64):
        _refuse(_VSA_PACKET_MALFORMED, "decision_digest must be 64 hex")
    if packet["verdict"] not in ("PASSED", "FAILED"):
        _refuse(_VSA_PACKET_MALFORMED, "verdict must be PASSED or FAILED")
    levels = packet["verified_levels"]
    if (not isinstance(levels, list) or not levels
            or any(not isinstance(l, str) or not l for l in levels)):
        _refuse(_VSA_PACKET_MALFORMED,
                "verified_levels must be a non-empty list of str")
    try:
        _check_inputs_shape(packet["inputs"])
    except ValueError as exc:
        _refuse(_VSA_PACKET_MALFORMED, "inputs: %s" % (exc,))
    threshold = packet["threshold"]
    attestations = packet["attestations"]
    if not isinstance(attestations, list) or not attestations:
        _refuse(_VSA_PACKET_MALFORMED,
                "attestations must be a non-empty list")
    # Only positivity is a shape property: a threshold larger than the
    # attestation count is not malformed, it is an unmet quorum (the
    # roster is not part of the signed statement, so k > n can arrive
    # when attestations are dropped -- and refuses below-quorum).
    if not _is_int(threshold) or threshold < 1:
        _refuse(_VSA_PACKET_MALFORMED,
                "threshold must be a positive int")
    for attestation in attestations:
        if not isinstance(attestation, dict) \
                or set(attestation.keys()) != _ATTESTATION_FIELDS:
            _refuse(_VSA_PACKET_MALFORMED,
                    "attestations must have exactly %s"
                    % (sorted(_ATTESTATION_FIELDS),))
        if not isinstance(attestation["verifier_id"], str) \
                or not attestation["verifier_id"]:
            _refuse(_VSA_PACKET_MALFORMED, "verifier_id must be non-empty")
        if not isinstance(attestation["key_id"], str) \
                or not attestation["key_id"]:
            _refuse(_VSA_PACKET_MALFORMED, "key_id must be non-empty")
        if _parse_rfc3339(attestation["time_verified"]) is None:
            _refuse(_VSA_PACKET_MALFORMED,
                    "time_verified must be RFC3339 UTC")
        if not _is_hex(attestation["signature"], 128):
            _refuse(_VSA_PACKET_MALFORMED,
                    "signature must be 128 hex chars")


def _check_trust(trust):
    """Validate the consumer's trust expectations (caller errors)."""
    if not isinstance(trust, dict):
        raise ValueError("trust must be a dict")
    for key in ("verifier_registry", "expected_subject_digest",
                "required_level", "max_age_seconds"):
        if key not in trust:
            raise ValueError("trust is missing %r" % (key,))
    registry = trust["verifier_registry"]
    if not isinstance(registry, dict) or not registry:
        raise ValueError("verifier_registry must be a non-empty dict")
    for vid, keys in registry.items():
        if not isinstance(vid, str) or not vid:
            raise ValueError("verifier ids must be non-empty strings")
        if not isinstance(keys, (list, tuple)) or not keys:
            raise ValueError("registry entries must be non-empty lists")
        for pub in keys:
            if not _is_hex(pub, 64):
                raise ValueError("registry holds a malformed pubkey")
    if not _is_hex(trust["expected_subject_digest"], 64):
        raise ValueError("expected_subject_digest must be 64 hex")
    if not isinstance(trust["required_level"], str) \
            or not trust["required_level"]:
        raise ValueError("required_level must be a non-empty string")
    max_age = trust["max_age_seconds"]
    if isinstance(max_age, bool) or not isinstance(max_age, (int, float)) \
            or not (max_age == max_age) or max_age <= 0:
        raise ValueError("max_age_seconds must be a positive finite number")
    now = trust.get("now")
    if now is None:
        import time
        now = time.time()
    if isinstance(now, bool) or not isinstance(now, (int, float)) \
            or not (now == now):
        raise ValueError("now must be a finite number or None")
    min_threshold = trust.get("min_threshold")
    if min_threshold is not None and (
            not _is_int(min_threshold) or min_threshold < 1):
        raise ValueError("min_threshold must be a positive int or None")
    currency = trust.get("policy_currency")
    if not isinstance(currency, dict):
        raise ValueError("policy_currency is required: "
                         "pass {policy_id, min_version} explicitly -- "
                         "a consumer that does not name its currency "
                         "floor must not silently accept stale policy")
    if not isinstance(currency.get("policy_id"), str) \
            or not currency["policy_id"]:
        raise ValueError("policy_currency.policy_id must be non-empty")
    if not _is_int(currency.get("min_version")):
        raise ValueError("policy_currency.min_version must be an int")
    return {
        "verifier_registry": registry,
        "expected_subject_digest": trust["expected_subject_digest"].lower(),
        "required_level": trust["required_level"],
        "max_age_seconds": float(max_age),
        "now": float(now),
        "min_threshold": min_threshold,
        "policy_currency": currency,
    }


def _key_id_of(pubkey_hex):
    """Key-id convention: sha256(pub) hexdigest [:16] (gov/signing)."""
    return hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()[:16]


def verify_vsa(packet, trust):
    """Run the threshold-VSA consumer procedure (fail-closed, coded).

    ``trust`` names what the consumer requires::

        {"verifier_registry": {verifier_id: [pubkey_hex, ...]},
         "expected_subject_digest", "required_level", "max_age_seconds",
         "now" (None -> wall clock), "min_threshold" (optional),
         "policy_currency": {"policy_id", "min_version"} (REQUIRED --
         the consumer must name its currency floor explicitly; there
         is no silent accept of stale policy)}

    Checks, in order: shape; threshold sanity; verdict PASSED; required
    level asserted; every attestation pinned (specific (signer, verifier)
    pairs) and verifying over the common statement plus its identity
    descriptor -- distinct verifier ids counted once; quorum met;
    subject binding; per-attestation freshness; policy-version currency.

    Returns the verified claims ``{"ok": True, "subject_digest",
    "verifier_ids", "policy", "threshold", "verified_levels",
    "inputs"}``. **No authorization verdict**: PASSED is evidence input,
    not ALLOW. Raises :class:`VSAThresholdError` (coded) on any failure.
    """
    tr = _check_trust(trust)
    _check_packet_shape(packet)
    if packet["verdict"] != "PASSED":
        _refuse(_VSA_THRESHOLD_VERDICT_NOT_PASSED,
                "verdict is %r, not PASSED" % (packet["verdict"],))
    if tr["required_level"] not in packet["verified_levels"]:
        _refuse(_VSA_PACKET_LEVELS_MISSING,
                "required level %r not asserted"
                % (tr["required_level"],))
    registry = tr["verifier_registry"]
    valid_ids = set()
    for attestation in packet["attestations"]:
        vid = attestation["verifier_id"]
        pinned = registry.get(vid)
        if not pinned:
            _refuse(_VSA_THRESHOLD_SIGNER_UNPINNED,
                    "verifier %r is not pinned" % (vid,))
        pub_hex = None
        for candidate in pinned:
            if _key_id_of(candidate) == attestation["key_id"]:
                pub_hex = candidate
                break
        if pub_hex is None:
            _refuse(_VSA_THRESHOLD_SIGNER_UNPINNED,
                    "key %r is not pinned for verifier %r"
                    % (attestation["key_id"], vid))
        msg = attestation_signing_input(packet, attestation)
        sig = bytes.fromhex(attestation["signature"])
        # verify() returns True/False and never raises -- check the False
        # (the wave-243 lesson).
        if _ed.verify(bytes.fromhex(pub_hex), msg, sig) is not True:
            _refuse(_VSA_THRESHOLD_SIGNATURE_INVALID,
                    "signature from verifier %r does not verify" % (vid,))
        valid_ids.add(vid)
    if len(valid_ids) < packet["threshold"]:
        _refuse(_VSA_THRESHOLD_BELOW_QUORUM,
                "%d distinct valid verifier(s), need %d"
                % (len(valid_ids), packet["threshold"]))
    if tr["min_threshold"] is not None \
            and packet["threshold"] < tr["min_threshold"]:
        _refuse(_VSA_THRESHOLD_BELOW_QUORUM,
                "packet threshold %d is below the consumer minimum %d"
                % (packet["threshold"], tr["min_threshold"]))
    if packet["subject"]["decision_digest"].lower() \
            != tr["expected_subject_digest"]:
        _refuse(_VSA_PACKET_SUBJECT_MISMATCH,
                "VSA subject does not match the expected decision")
    for attestation in packet["attestations"]:
        verified_at = _parse_rfc3339(attestation["time_verified"])
        if not (verified_at <= tr["now"]
                <= verified_at + tr["max_age_seconds"]):
            _refuse(_VSA_PACKET_WINDOW_INVALID,
                    "verifier %r time_verified is outside the window"
                    % (attestation["verifier_id"],))
    currency = tr["policy_currency"]
    if currency is not None:
        policy = packet["inputs"]["policy"]
        if policy["policy_id"] != currency["policy_id"] \
                or policy["version"] < currency["min_version"]:
            _refuse(_VSA_THRESHOLD_POLICY_STALE,
                    "policy %r v%d is below the required v%d"
                    % (policy["policy_id"], policy["version"],
                       currency["min_version"]))
    return {
        "ok": True,
        "subject_digest": packet["subject"]["decision_digest"].lower(),
        "verifier_ids": sorted(valid_ids),
        "policy": dict(packet["inputs"]["policy"]),
        "threshold": packet["threshold"],
        "verified_levels": list(packet["verified_levels"]),
        "inputs": json.loads(_canonical(packet["inputs"])),
    }
