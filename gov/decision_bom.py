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
  pins      -- skill/MCP pin digests {skill_id: attested digest}.
  approval  -- the approval id + approval-record digest, when the
               decision answered an approval. An approval id whose
               record digest cannot be resolved fails CLOSED at build
               time -- the BOM never silently drops approval provenance.

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
    the identity dict (agent_id/role/principal/run_id). ``pin_digests``
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
    pins = dict(pin_digests) if pin_digests is not None else {}
    if not isinstance(pins, dict):
        raise BomError("pin_digests must be a dict")
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
            "principal": {
                "agent_id": principal.get("agent_id"),
                "role": principal.get("role"),
                "principal": principal.get("principal"),
                "run_id": principal.get("run_id"),
            },
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


def verify_bom(bom, *, policy_bundle_bytes=None, pin_digests=None):
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
    A BOM checked with NO artifacts supplied returns (False, ...): its
    shape is valid but its provenance is UNVERIFIED, and no caller may
    mistake that for a verified BOM. Pass the artifacts for the full
    check.
    """
    try:
        return _verify(bom,
                       policy_bundle_bytes=policy_bundle_bytes,
                       pin_digests=pin_digests)
    except Exception as e:  # noqa: BLE001 - verifiers never raise
        return False, "verifier exception (fail-closed): %s: %s" % (
            type(e).__name__, e)


def _verify(bom, *, policy_bundle_bytes, pin_digests):
    ok, reason = check_bom_shape(bom)
    if not ok:
        return False, reason
    inputs = bom["inputs"]
    checked = []
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
    if not checked:
        return False, ("no artifacts supplied for re-derivation: BOM "
                       "shape ok, provenance UNVERIFIED")
    return True, "ok (shape + re-derived: %s)" % ",".join(checked)
