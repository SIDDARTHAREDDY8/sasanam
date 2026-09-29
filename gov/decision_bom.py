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
# Wave-198: the ladder mode vocabulary (stdlib-only, no
# import cycle).
from .mode_ledger import LADDER_MODES


BOM_VERSION = 1


class BomError(Exception):
    """The BOM could not be built (loud, fail-closed for builders)."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


# Wave-198: one shared mode-history entry validator. build_bom
# raises BomError (fail closed) while check_bom_shape returns
# (False, reason); the shape test is the same at both boundaries.
def _mode_history_entry_ok(h):
    if not isinstance(h, dict):
        return False
    for key in ("old_mode", "new_mode", "at", "approvers"):
        if key not in h:
            return False
    if h["old_mode"] not in LADDER_MODES \
            or h["new_mode"] not in LADDER_MODES:
        return False
    return (isinstance(h["at"], (int, float))
            and isinstance(h["approvers"], list))


def build_bom(*, policy_id, policy_version, policy_digest,
              evidence_head_digest, principal, pin_digests=None,
              approval_id=None, approval_record_digest=None,
              decision_mode=None, nominal_effect=None,
              decision_warnings=None, rule_mode_history=None,
              perm_model=None, decision_event_v2=None, tool_grants=None,
              attested_identity=None):
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

    Wave-198 (graduation ladder): ``decision_mode`` ("observe" |
    "warn" | "deny"), ``nominal_effect`` (what the rule asked for vs
    the enforced verdict), ``decision_warnings`` (operator telemetry
    strings), and ``rule_mode_history`` (the deciding rule's chained
    mode-change history) ride an optional ``inputs.ladder`` section.
    All four default to None and the section is omitted when none is
    supplied -- BOMs built without ladder telemetry are
    byte-identical to before (the wave-191 token_digest precedent).
    When any is supplied, all four are required and validated loudly:
    a BOM must never silently record a weaker claim than the decision
    actually rested on.

    Wave-200 (PERM model-as-data): ``perm_model`` is an optional
    all-or-none dict ``{"model_digest": hex64, "policy_digest":
    hex64, "composition_digest": hex64, "function_set_digest":
    hex64}`` -- the signed PERM model + policy documents the decision
    ran under (``gov.perm_loader``), the screen-composition order +
    verdict mapping, and the matcher function-set digest (the model
    names functions; the engine provides them -- the digest makes the
    coupling auditable). Supplied as
    ``PermModel.bom_perm_section()``. Omitted when the decision did
    not run under a PERM model, and BOMs built without it are
    byte-identical to before (the wave-191 token_digest and wave-198
    ladder precedents). A partial dict raises BomError: the BOM never
    silently records a weaker claim than the decision actually rested
    on.

    Wave-202 (capability grants): ``tool_grants`` is an optional
    all-or-none dict ``{"grant_digest": hex64, "decision_id": str,
    "capability_count": int}`` -- the grant set a tool call ran under
    (``gov.capability_grants.bom_grants_section()``). Omitted when the
    decision dispatched no tool call, and BOMs built without it are
    byte-identical to before. A partial dict raises BomError.

    Every required input is validated LOUD: a missing or malformed
    digest, an empty policy id/version, or a non-dict principal raises
    BomError. A BOM must never silently record a weaker claim than the
    decision actually rested on.

    Wave-202 (decision-log v2): ``decision_event_v2`` is an optional
    verified v2 decision event (``gov.decision_log_v2``). When supplied
    it is fully verified here (fail-closed: BomError on any verification
    failure) and bound BY DIGEST under ``inputs.decision_event`` as
    ``{"decision_id", "event_digest"}`` -- the event_digest excludes the
    ``audit`` chain bookkeeping so an auditor holding only the chained
    log entry can re-derive it. Omitted when the decision carries no v2
    event, and BOMs built without it are byte-identical to before.

    Wave-204 (attested identity): ``attested_identity`` is an optional
    all-or-none dict ``{"tier": 1, "credential_digest": hex64,
    "evidence_digest": hex64}`` -- the attested identity the deciding
    agent bootstrapped under (``gov.attested_identity.
    bom_identity_section()``). The credential digest binds the exact
    issued credential; the evidence digest binds the consumed
    attestation evidence. Tier-1 only: tier-2 carries no attested
    evidence, and binding an empty digest would be a vacuous proof, so
    ``bom_identity_section()`` refuses tier-2 loudly. Omitted when the
    decision did not run under an attested identity, and BOMs built
    without it are byte-identical to before (the wave-191
    token_digest precedent). A partial dict raises BomError.
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
    # Wave-198 (graduation ladder): the optional ladder section. When
    # none of the four inputs is supplied the section is omitted --
    # byte-identical BOMs for mode-absent decisions. When any is
    # supplied, all four are required and validated loudly.
    ladder_inputs = None
    if (decision_mode is not None or nominal_effect is not None
            or decision_warnings is not None
            or rule_mode_history is not None):
        if decision_mode not in LADDER_MODES:
            raise BomError(
                "decision_mode must be observe/warn/deny, got %r"
                % (decision_mode,))
        if nominal_effect not in ("allow", "require_approval", "deny"):
            raise BomError(
                "nominal_effect must be allow/require_approval/deny, "
                "got %r" % (nominal_effect,))
        warnings = list(decision_warnings or ())
        for w in warnings:
            if not isinstance(w, str) or not w:
                raise BomError(
                    "decision_warnings entries must be non-empty strings, "
                    "got %r" % (w,))
        history = list(rule_mode_history or ())
        for h in history:
            if not _mode_history_entry_ok(h):
                raise BomError(
                    "rule_mode_history entry malformed or has a bad mode "
                    "transition: %r" % (h,))
        ladder_inputs = {
            "mode": decision_mode,
            "nominal_effect": nominal_effect,
            "warnings": warnings,
            "rule_mode_history": history,
        }
    # Wave-200 (PERM model-as-data): the optional perm section.
    # All-or-none: a partial dict is refused loud, and absence keeps
    # the BOM byte-identical to before.
    perm_inputs = None
    if perm_model is not None:
        if not isinstance(perm_model, dict):
            raise BomError("perm_model must be a dict or None")
        for key in ("model_digest", "policy_digest",
                    "composition_digest", "function_set_digest"):
            value = perm_model.get(key)
            if not _is_hex64(value):
                raise BomError(
                    "perm_model %r must be 64-char lowercase hex"
                    % (key,))
        unknown_perm = set(perm_model) - {
            "model_digest", "policy_digest", "composition_digest",
            "function_set_digest"}
        if unknown_perm:
            raise BomError(
                "perm_model carries unknown keys: %s"
                % sorted(unknown_perm))
        perm_inputs = {
            "model_digest": perm_model["model_digest"],
            "policy_digest": perm_model["policy_digest"],
            "composition_digest": perm_model["composition_digest"],
            "function_set_digest": perm_model["function_set_digest"],
        }
    # Wave-202 (capability grants): the optional grants section.
    # All-or-none: a partial dict is refused loud, and absence keeps
    # the BOM byte-identical to before.
    grant_inputs = None
    if tool_grants is not None:
        if not isinstance(tool_grants, dict):
            raise BomError("tool_grants must be a dict or None")
        grant_digest = tool_grants.get("grant_digest")
        if not _is_hex64(grant_digest):
            raise BomError(
                "tool_grants grant_digest must be 64-char lowercase hex")
        decision_id = tool_grants.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            raise BomError(
                "tool_grants decision_id must be a non-empty string")
        capability_count = tool_grants.get("capability_count")
        if (not isinstance(capability_count, int)
                or capability_count < 0):
            raise BomError(
                "tool_grants capability_count must be a non-negative int")
        unknown_grants = set(tool_grants) - {
            "grant_digest", "decision_id", "capability_count"}
        if unknown_grants:
            raise BomError(
                "tool_grants carries unknown keys: %s"
                % sorted(unknown_grants))
        grant_inputs = {
            "grant_digest": grant_digest,
            "decision_id": decision_id,
            "capability_count": capability_count,
        }
    inputs = {
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
    }
    if ladder_inputs is not None:
        inputs["ladder"] = ladder_inputs
    if perm_inputs is not None:
        inputs["perm"] = perm_inputs
    # Wave-202 (decision-log v2): the optional decision-event section.
    # Binds the v2 decision event BY DIGEST so evidence bundles carry a
    # reference an auditor can resolve against the chained audit log.
    # The event is fully verified here (fail-closed); absence keeps the
    # BOM byte-identical to before.
    if decision_event_v2 is not None:
        from . import decision_log_v2 as _dlv
        try:
            _dlv.verify_event(decision_event_v2)
        except _dlv.DecisionEventError as e:
            raise BomError("decision_event_v2 failed verification: %s"
                           % (e,))
        inputs["decision_event"] = {
            "decision_id": decision_event_v2["decision_id"],
            "event_digest": _dlv.event_digest(decision_event_v2),
        }
    if grant_inputs is not None:
        inputs["grants"] = grant_inputs
    # Wave-204 (attested identity): the optional attested_identity
    # section. All-or-none: a partial dict is refused loud, and absence
    # keeps the BOM byte-identical to before.
    if attested_identity is not None:
        if not isinstance(attested_identity, dict):
            raise BomError("attested_identity must be a dict or None")
        ident_tier = attested_identity.get("tier")
        # bool rejected explicitly: True == 1 in Python, so a bare
        # ``!= 1`` check would silently accept tier=True as tier-1.
        if isinstance(ident_tier, bool) or ident_tier != 1:
            raise BomError(
                "attested_identity tier must be 1 (tier-1 attested); "
                "tier-2 carries no attested evidence to bind, got %r"
                % (ident_tier,))
        ident_cred = attested_identity.get("credential_digest")
        if not _is_hex64(ident_cred):
            raise BomError("attested_identity credential_digest must be "
                           "64-char lowercase hex")
        ident_ev = attested_identity.get("evidence_digest")
        if not _is_hex64(ident_ev):
            raise BomError("attested_identity evidence_digest must be "
                           "64-char lowercase hex")
        unknown_ident = set(attested_identity) - {
            "tier", "credential_digest", "evidence_digest"}
        if unknown_ident:
            raise BomError("attested_identity carries unknown keys: %s"
                           % sorted(unknown_ident))
        inputs["attested_identity"] = {
            "tier": ident_tier,
            "credential_digest": ident_cred,
            "evidence_digest": ident_ev,
        }
    return {
        "bom_version": BOM_VERSION,
        "inputs": inputs,
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
    # Wave-198 (graduation ladder): the optional ladder section, when
    # present, must be well-formed. Absent is fine (mode-absent
    # decisions omit it).
    ladder = inputs.get("ladder")
    if ladder is not None:
        if not isinstance(ladder, dict):
            return False, "bom.inputs.ladder is not a dict"
        if ladder.get("mode") not in LADDER_MODES:
            return False, "bom.inputs.ladder.mode malformed"
        if ladder.get("nominal_effect") not in ("allow",
                                                "require_approval",
                                                "deny"):
            return False, "bom.inputs.ladder.nominal_effect malformed"
        warnings = ladder.get("warnings")
        if not isinstance(warnings, list) or not all(
                isinstance(w, str) and w for w in warnings):
            return False, "bom.inputs.ladder.warnings malformed"
        history = ladder.get("rule_mode_history")
        if not isinstance(history, list) or not all(
                _mode_history_entry_ok(h) for h in history):
            return False, "bom.inputs.ladder.rule_mode_history malformed"
    # Wave-200 (PERM model-as-data): the optional perm section, when
    # present, must carry all three digests well-formed. Absent is
    # fine (non-PERM decisions omit it).
    perm = inputs.get("perm")
    if perm is not None:
        if not isinstance(perm, dict):
            return False, "bom.inputs.perm is not a dict"
        for key in ("model_digest", "policy_digest",
                    "composition_digest", "function_set_digest"):
            if not _is_hex64(perm.get(key)):
                return False, (
                    "bom.inputs.perm.%s is not 64-char hex" % (key,))
        if set(perm) - {"model_digest", "policy_digest",
                        "composition_digest", "function_set_digest"}:
            return False, "bom.inputs.perm carries unknown keys"
    # Wave-202 (decision-log v2): the optional decision_event section,
    # when present, must bind a decision_id and an event digest.
    # Absent is fine (decisions without a v2 event omit it).
    devt = inputs.get("decision_event")
    if devt is not None:
        if not isinstance(devt, dict):
            return False, "bom.inputs.decision_event is not a dict"
        if not _is_hex64(devt.get("decision_id")):
            return False, ("bom.inputs.decision_event.decision_id is not "
                           "64-char hex")
        if not _is_hex64(devt.get("event_digest")):
            return False, ("bom.inputs.decision_event.event_digest is not "
                           "64-char hex")
        if set(devt) - {"decision_id", "event_digest"}:
            return False, "bom.inputs.decision_event carries unknown keys"
    # Wave-202 (capability grants): the optional grants section, when
    # present, must be well-formed. Absent is fine (decisions that
    # dispatched no tool call omit it).
    grants = inputs.get("grants")
    if grants is not None:
        if not isinstance(grants, dict):
            return False, "bom.inputs.grants is not a dict"
        if not _is_hex64(grants.get("grant_digest")):
            return False, "bom.inputs.grants.grant_digest is not 64-char hex"
        did = grants.get("decision_id")
        if not isinstance(did, str) or not did:
            return False, "bom.inputs.grants.decision_id malformed"
        cc = grants.get("capability_count")
        if not isinstance(cc, int) or cc < 0:
            return False, "bom.inputs.grants.capability_count malformed"
        if set(grants) - {"grant_digest", "decision_id",
                           "capability_count"}:
            return False, "bom.inputs.grants carries unknown keys"
    # Wave-204 (attested identity): the optional attested_identity
    # section, when present, must bind a tier-1 credential and its
    # evidence by digest. Absent is fine (decisions that did not run
    # under an attested identity omit it).
    ident = inputs.get("attested_identity")
    if ident is not None:
        if not isinstance(ident, dict):
            return False, "bom.inputs.attested_identity is not a dict"
        # bool rejected explicitly: True == 1 in Python, so a bare
        # ``!= 1`` check would silently accept tier=True as tier-1.
        ident_tier = ident.get("tier")
        if isinstance(ident_tier, bool) or ident_tier != 1:
            return False, ("bom.inputs.attested_identity.tier must be 1 "
                           "(tier-1 attested)")
        if not _is_hex64(ident.get("credential_digest")):
            return False, ("bom.inputs.attested_identity.credential_digest "
                           "is not 64-char hex")
        if not _is_hex64(ident.get("evidence_digest")):
            return False, ("bom.inputs.attested_identity.evidence_digest "
                           "is not 64-char hex")
        if set(ident) - {"tier", "credential_digest", "evidence_digest"}:
            return False, ("bom.inputs.attested_identity carries unknown "
                           "keys")
    return True, "ok"


def verify_bom(bom, *, policy_bundle_bytes=None, pin_digests=None,
               approval_records=None, perm_model_bytes=None,
               perm_policy_bytes=None, grant_capability_specs=None,
               identity_credential_body=None):
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

    Wave-200 (PERM): ``perm_model_bytes`` / ``perm_policy_bytes`` are
    the exact signed model/policy document bytes; their sha256 must
    equal the BOM's ``inputs.perm`` digests. The composition and
    function-set digests are shape-checked only here -- full
    re-derivation needs the model compiler (``gov.perm_loader``),
    which the standalone offline verifier deliberately does not
    import; an auditor with the engine re-derives them via
    ``PermModel.composition_digest`` / ``function_set_digest``.
    Wave-202 (capability grants): ``grant_capability_specs`` is the
    auditor's canonical capability description list for the dispatched
    grant set (the ``describe()`` shape: [{kind, resource,
    rights:[...]}, ...], any order) resolved from the parent's
    dispatch records. The BOM's ``inputs.grants.grant_digest`` and
    ``capability_count`` re-derive from it; without it the grants leg
    is reported UNVERIFIED, never silently passed.
    Wave-204 (attested identity): ``identity_credential_body`` is the
    presented attested-identity credential body dict (the unsigned
    ``{"domain", "tier", "claims", "expires_at"}`` the attester signed).
    The BOM's ``inputs.attested_identity.credential_digest`` must
    re-derive from it via ``gov.attested_identity.credential_digest_of``,
    and the body's tier must match the section's tier -- a relabelled
    credential is caught here. Without the body the leg is UNVERIFIED,
    named, never silently passed -- exactly like the approval leg.
    """
    try:
        return _verify(bom,
                       policy_bundle_bytes=policy_bundle_bytes,
                       pin_digests=pin_digests,
                       approval_records=approval_records,
                       perm_model_bytes=perm_model_bytes,
                       perm_policy_bytes=perm_policy_bytes,
                       grant_capability_specs=grant_capability_specs,
                       identity_credential_body=identity_credential_body)
    except Exception as e:  # noqa: BLE001 - verifiers never raise
        return False, "verifier exception (fail-closed): %s: %s" % (
            type(e).__name__, e)


def _verify(bom, *, policy_bundle_bytes, pin_digests, approval_records,
            perm_model_bytes, perm_policy_bytes,
            grant_capability_specs, identity_credential_body):
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
    # Wave-200 (PERM): re-derive the model/policy digests from the
    # exact document bytes. The composition and function-set digests
    # need the compiler; they are shape-checked only (see docstring).
    perm = inputs.get("perm")
    if perm is not None:
        # Partial verification must never return an overbroad "ok":
        # every PERM leg that cannot be re-derived is NAMED in the
        # unverified list, exactly like the approval leg above.
        if perm_model_bytes is None:
            unverified.append("perm-model")
        else:
            if not isinstance(perm_model_bytes, (bytes, bytearray)):
                return False, "perm_model_bytes is not bytes"
            rederived = hashlib.sha256(
                bytes(perm_model_bytes)).hexdigest()
            if rederived != perm["model_digest"]:
                return False, (
                    "perm model digest does not re-derive from the "
                    "supplied model bytes (swapped or tampered model)")
            checked.append("perm-model")
        if perm_policy_bytes is None:
            unverified.append("perm-policy")
        else:
            if not isinstance(perm_policy_bytes, (bytes, bytearray)):
                return False, "perm_policy_bytes is not bytes"
            rederived = hashlib.sha256(
                bytes(perm_policy_bytes)).hexdigest()
            if rederived != perm["policy_digest"]:
                return False, (
                    "perm policy digest does not re-derive from the "
                    "supplied policy bytes (swapped or tampered "
                    "policy)")
            checked.append("perm-policy")
    # Wave-202 (capability grants): the auditor re-derives the grant
    # digest from their own dispatch records. Without the specs the
    # leg is UNVERIFIED -- named, never silently passed -- exactly
    # like the approval leg above.
    grants = inputs.get("grants")
    if grants is not None:
        if grant_capability_specs is None:
            unverified.append("grants")
        else:
            from gov import capability_grants as _cg
            if not isinstance(grant_capability_specs, (list, tuple)):
                return False, "grant_capability_specs is not a list"
            if not _cg.verify_grant_digest(grants["grant_digest"],
                                           grant_capability_specs):
                return False, (
                    "grant digest does not re-derive from the supplied "
                    "capability specs (swapped or tampered grants)")
            if len(grant_capability_specs) != grants["capability_count"]:
                return False, (
                    "grant capability_count does not match the supplied "
                    "capability specs")
            checked.append("grants")
    # Wave-204 (attested identity): the auditor re-derives the
    # credential digest from the presented credential body. Without the
    # body the leg is UNVERIFIED -- named, never silently passed --
    # exactly like the approval leg above. A swapped or relabelled
    # credential fails closed here.
    ident = inputs.get("attested_identity")
    if ident is not None:
        if identity_credential_body is None:
            unverified.append("attested-identity")
        else:
            from gov import attested_identity as _ai
            if not isinstance(identity_credential_body, dict):
                return False, "identity_credential_body is not a dict"
            rederived = _ai.credential_digest_of(identity_credential_body)
            if rederived != ident["credential_digest"]:
                return False, (
                    "attested_identity credential_digest does not "
                    "re-derive from the supplied credential body "
                    "(swapped or tampered identity)")
            if identity_credential_body.get("tier") != ident["tier"]:
                return False, (
                    "attested_identity tier in the credential body does "
                    "not match the BOM section (relabelled identity)")
            checked.append("attested-identity")
    if not checked:
        return False, ("no artifacts supplied for re-derivation: BOM "
                       "shape ok, provenance UNVERIFIED")
    reason = "ok (shape + re-derived: %s)" % ",".join(checked)
    if unverified:
        reason += "; unverified: %s" % ",".join(unverified)
    return True, reason
