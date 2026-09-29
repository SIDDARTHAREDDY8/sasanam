"""Decision Bill-of-Materials (wave-180 lane A).

Microsoft agent-governance-toolkit steal verdict (STEAL, pattern only --
no vendored code): a Decision BOM -- a reconstructible view of every
factor behind a governance decision, assembled on demand from existing
signals instead of storing pre-built explanations. Cheaper to build,
harder to tamper with. Design principle kept: "non-invasive over
complete."

The BOM rides the signed decision packet as a producer-attributed
section (see gov/decision_packet.py). It binds, BY DIGEST, every input
artifact that informed the decision:

  policy    -- the policy bundle: id + version + sha256 of the EXACT
               bytes the engine parsed (the F53 one-buffer rule makes
               this the enforced bytes, not a re-read).
  evidence  -- the audit-chain head digest the packet was built under.
  principal -- the agent identity the decision was rendered for.
               Optionally carries token_digest (sha256 of the raw OIDC
               identity token the identity was minted from, wave-191);
               the packet verifier cross-checks it against the packet's
               identity_token section when both record one.
  pins      -- skill/MCP pin digests {skill_id: attested digest}.
  approval  -- the approval id + approval-record digest, when the
               decision answered an approval. An approval id whose
               record digest cannot be resolved fails CLOSED at build
               time -- the BOM never silently drops approval provenance.
               On the audit path, verify_bom re-derives the digest
               against auditor-supplied approval_records (F200); when
               the auditor supplies none, the approval leg is reported
               UNVERIFIED rather than silently passed.

An auditor re-derives the digests ON DEMAND (verify_bom) from the
actual artifacts instead of trusting the packet's pointers -- the same
"references, not re-bindings" philosophy as the packet itself, with
teeth: a swapped or missing input digest fails closed. A tampered
policy version is caught by the BOM<->packet version agreement check
in the packet verifier; note the version string is a caller-supplied
label and the binding between a label and specific bytes is external
to the BOM (re-derivation validates the DIGEST against supplied
bytes only).

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env
reads in the build/verify path. No gov imports: like decision_packet.py
this module is standalone-verifiable (the offline story copies
decision_packet.py + decision_bom.py + ed25519.py).

Schema note (wave-180 prospectus, SLSA v1 provenance predicate --
STEAL, shape only, no spec prose copied): the BOM mirrors the
predicate's two halves. Caller-supplied inputs (evidence head,
principal, approval) are the externalParameters; governor
configuration (policy bundle, pin digests) are the
internalParameters -- recorded separately so the two can never be
conflated. Pins are digest-bound dependency descriptors; a future
export may widen them to multi-algorithm ResourceDescriptor maps,
but nothing in the tree produces non-sha256 digests today, so the
BOM keeps the compact single-algorithm form.
"""

import hashlib
import json


BOM_VERSION = 1


class BomError(Exception):
    """The BOM could not be built (loud, fail-closed for builders)."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def build_bom(*, policy_id, policy_version, policy_digest,
              evidence_head_digest, principal, pin_digests=None,
              approval_id=None, approval_record_digest=None):
    """Assemble the bill of materials for one policy decision.

    ``policy_digest`` is sha256 hex over the exact policy-bundle bytes
    the engine parsed (``PolicyEngine.policy_hash``). ``principal`` is
    the identity dict (agent_id/role/principal/run_id), optionally
    carrying ``token_digest`` -- the sha256 of the raw OIDC identity
    token the identity was minted from (wave-191), recorded only when
    supplied. ``pin_digests``
    maps skill/MCP ids to their attested digests; empty when the
    decision used no pinned skills. ``approval_id`` /
    ``approval_record_digest`` are None when the decision answered no
    approval (direct allow/deny) -- honest, not a gap. But an
    approval_id WITHOUT a resolvable record digest raises BomError:
    the BOM must never silently drop approval provenance.

    Every required input is validated LOUD: a missing or malformed
    digest, an empty policy id/version, or a non-dict principal raises
    BomError. A BOM must never silently record a weaker claim than the
    decision actually rested on.
    """
    if not isinstance(policy_id, str) or not policy_id:
        raise BomError("policy_id must be a non-empty string")
    if not isinstance(policy_version, str) or not policy_version:
        raise BomError("policy_version must be a non-empty string")
    if not _is_hex64(policy_digest):
        raise BomError("policy_digest must be 64-char lowercase hex")
    if (not isinstance(evidence_head_digest, str)
            or not evidence_head_digest):
        raise BomError("evidence_head_digest must be a non-empty string")
    if not isinstance(principal, dict):
        raise BomError("principal must be a dict")
    # Wave-191: the optional identity-token binding. Recorded only when
    # supplied, so BOMs built without it are byte-identical to before.
    token_digest = principal.get("token_digest")
    if token_digest is not None and not _is_hex64(token_digest):
        raise BomError(
            "principal token_digest must be 64-char lowercase hex or None")
    # F201: the mapping guard must run BEFORE the dict() conversion --
    # dict(["x"]) raises bare ValueError and dict(5) raises bare
    # TypeError, which would escape as undocumented builtins instead of
    # the documented BomError.
    if pin_digests is not None and not isinstance(pin_digests, dict):
        raise BomError("pin_digests must be a dict or None")
    pins = dict(pin_digests) if pin_digests is not None else {}
    for skill_id, digest in pins.items():
        if not isinstance(skill_id, str) or not skill_id:
            raise BomError("pin skill_id must be a non-empty string")
        if not _is_hex64(digest):
            raise BomError(
                "pin digest for %r must be 64-char lowercase hex"
                % (skill_id,))
    if approval_id is not None and (
            not isinstance(approval_id, str) or not approval_id):
        raise BomError("approval_id must be a non-empty string or None")
    if approval_record_digest is not None and not _is_hex64(
            approval_record_digest):
        raise BomError(
            "approval_record_digest must be 64-char lowercase hex or None")
    if approval_id is not None and approval_record_digest is None:
        # Fail closed: an approval id without a resolvable record
        # digest would silently drop the approval's provenance. The
        # caller must resolve the record or omit the approval.
        raise BomError(
            "approval_id %r has no record digest; refusing to build a "
            "BOM that drops approval provenance" % (approval_id,))
    principal_inputs = {
        "agent_id": principal.get("agent_id"),
        "role": principal.get("role"),
        "principal": principal.get("principal"),
        "run_id": principal.get("run_id"),
    }
    if token_digest is not None:
        principal_inputs["token_digest"] = token_digest
    return {
        "bom_version": BOM_VERSION,
        "inputs": {
            "policy": {
                "policy_id": policy_id,
                "policy_version": policy_version,
                "digest": policy_digest,
            },
            "evidence": {
                "head_digest": evidence_head_digest,
            },
            "principal": principal_inputs,
            "pins": pins,
            "approval": {
                "approval_id": approval_id,
                "record_digest": approval_record_digest,
            },
        },
    }


def bom_digest(bom):
    """sha256 over the canonical BOM -- the tamper-evident binding of
    the whole input list. A swapped entry changes this digest."""
    return hashlib.sha256(_canonical(bom)).hexdigest()


def check_bom_shape(bom):
    """Validate a BOM dict. Returns (ok, reason); never raises."""
    if not isinstance(bom, dict):
        return False, "bom is not a dict"
    if bom.get("bom_version") != BOM_VERSION:
        return False, "unsupported bom_version %r" % (bom.get("bom_version"),)
    inputs = bom.get("inputs")
    if not isinstance(inputs, dict):
        return False, "bom.inputs is not a dict"
    policy = inputs.get("policy")
    if not isinstance(policy, dict):
        return False, "bom.inputs.policy is not a dict"
    if not policy.get("policy_id") or not isinstance(
            policy.get("policy_id"), str):
        return False, "bom.inputs.policy.policy_id missing"
    if not policy.get("policy_version") or not isinstance(
            policy.get("policy_version"), str):
        return False, "bom.inputs.policy.policy_version missing"
    if not _is_hex64(policy.get("digest")):
        return False, "bom.inputs.policy.digest is not 64-char hex"
    evidence = inputs.get("evidence")
    if not isinstance(evidence, dict) or not evidence.get("head_digest"):
        return False, "bom.inputs.evidence.head_digest missing"
    principal = inputs.get("principal")
    if not isinstance(principal, dict):
        return False, "bom.inputs.principal is not a dict"
    # Wave-191: the optional token_digest, when present, must be a
    # well-formed sha256 hex digest.
    _ptd = principal.get("token_digest")
    if _ptd is not None and not _is_hex64(_ptd):
        return False, "bom.inputs.principal.token_digest is not 64-char hex"
    pins = inputs.get("pins")
    if not isinstance(pins, dict):
        return False, "bom.inputs.pins is not a dict"
    for skill_id, digest in pins.items():
        if not isinstance(skill_id, str) or not _is_hex64(digest):
            return False, "bom.inputs.pins has a malformed entry"
    approval = inputs.get("approval")
    if not isinstance(approval, dict):
        return False, "bom.inputs.approval is not a dict"
    aid = approval.get("approval_id")
    if aid is not None and (not isinstance(aid, str) or not aid):
        return False, "bom.inputs.approval.approval_id malformed"
    rd = approval.get("record_digest")
    if rd is not None and not _is_hex64(rd):
        return False, "bom.inputs.approval.record_digest malformed"
    return True, "ok"


def verify_bom(bom, *, policy_bundle_bytes=None, pin_digests=None,
               approval_records=None):
    """On-demand reconstruction check (stdlib only).

    Returns ``(True, "ok")`` or ``(False, reason)``. Never raises on
    malformed input (fail-closed for verifiers).

    The auditor supplies the ACTUAL artifacts and the BOM's digests are
    re-derived from them -- this is the "assembled on demand" half of
    the steal: the packet stores cheap digests, the auditor does the
    expensive re-hashing only when reconstructing a decision.

    ``policy_bundle_bytes``: the exact policy-bundle bytes; sha256 must
    equal the BOM's policy digest. ``pin_digests``: {skill_id: attested
    digest} from the pin registry; each BOM pin entry must match.
    ``approval_records``: {approval_id: record_digest} resolved by the
    auditor from the approval store; the BOM's
    ``inputs.approval.record_digest`` must match the supplied digest
    for the BOM's approval_id, failing closed on mismatch -- the MATCH
    rule for the BOM->approval edge, symmetric with the policy and pins
    legs. The digest map (rather than raw records) is deliberate: the
    approval record digest is HMAC-keyed under the log key (see
    gov/approvals.approval_record_digest), so the auditor re-resolves
    it through their trusted store/key instead of re-hashing bytes --
    exactly as the pins leg compares registry digests rather than
    re-attesting skills.

    A BOM checked with NO artifacts supplied returns (False, ...): its
    shape is valid but its provenance is UNVERIFIED, and no caller may
    mistake that for a verified BOM. When approval_records is not
    supplied but the BOM names an approval, the approval leg is
    reported as UNVERIFIED in the reason -- never silently passed.
    Pass the artifacts for the full check.
    """
    try:
        return _verify(bom,
                       policy_bundle_bytes=policy_bundle_bytes,
                       pin_digests=pin_digests,
                       approval_records=approval_records)
    except Exception as e:  # noqa: BLE001 - verifiers never raise
        return False, "verifier exception (fail-closed): %s: %s" % (
            type(e).__name__, e)


def _verify(bom, *, policy_bundle_bytes, pin_digests, approval_records):
    ok, reason = check_bom_shape(bom)
    if not ok:
        return False, reason
    inputs = bom["inputs"]
    checked = []
    unverified = []
    if policy_bundle_bytes is not None:
        if not isinstance(policy_bundle_bytes, (bytes, bytearray)):
            return False, "policy_bundle_bytes is not bytes"
        rederived = hashlib.sha256(bytes(policy_bundle_bytes)).hexdigest()
        claimed = inputs["policy"]["digest"]
        if rederived != claimed:
            return False, (
                "policy digest does not re-derive from the supplied "
                "bundle bytes (swapped or tampered policy)")
        checked.append("policy")
    if pin_digests is not None:
        if not isinstance(pin_digests, dict):
            return False, "pin_digests is not a dict"
        for skill_id, digest in inputs["pins"].items():
            expected = pin_digests.get(skill_id)
            if expected != digest:
                return False, (
                    "pin digest for %r does not match the registry "
                    "(swapped or tampered pin)" % (skill_id,))
        checked.append("pins")
    # F200: the approval leg. The record digest is HMAC-keyed, so the
    # auditor supplies their own resolution ({approval_id:
    # record_digest}); the BOM's digest must MATCH it. Without the
    # auditor's input the leg is UNVERIFIED -- reported, never passed
    # silently.
    approval_id = inputs["approval"]["approval_id"]
    if approval_records is not None:
        if not isinstance(approval_records, dict):
            return False, "approval_records is not a dict"
        if approval_id is not None:
            if approval_id not in approval_records:
                return False, (
                    "approval_id %r not present in the supplied "
                    "approval_records; cannot re-derive record_digest "
                    "(fail-closed)" % (approval_id,))
            expected = approval_records[approval_id]
            if not _is_hex64(expected):
                return False, (
                    "approval_records[%r] is not 64-char hex"
                    % (approval_id,))
            claimed = inputs["approval"]["record_digest"]
            if expected != claimed:
                return False, (
                    "approval record_digest for %r does not match the "
                    "supplied approval records (swapped or tampered "
                    "approval provenance)" % (approval_id,))
            checked.append("approval")
    elif approval_id is not None:
        unverified.append("approval")
    if not checked:
        return False, ("no artifacts supplied for re-derivation: BOM "
                       "shape ok, provenance UNVERIFIED")
    reason = "ok (shape + re-derived: %s)" % ",".join(checked)
    if unverified:
        reason += "; unverified: %s" % ",".join(unverified)
    return True, reason
