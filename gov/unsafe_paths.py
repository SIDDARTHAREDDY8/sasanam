"""Named unsafe-path warning codes: the warning code IS the disclosure.

evidentia ADAPT (idea only -- no evidentia source is vendored and no
conformance is claimed): evidentia documents ``verify_signature_unsafe_noop``
as a NAMED warning code, so the unsafe path is only ever reachable through
an explicitly-named, greppable, auditable code, never silently. This module
is Sasanam's central registry of every such path in the tree.

Rules:
  * Every code is ``gov.<module>.<unsafe_noop_name>`` and greppable: it
    appears both in its defining module and in this registry.
  * ``emit`` refuses unregistered codes (fail-closed registry): a typo or
    an unregistered path can never slip through quietly.
  * Every execution of a registered path emits its code through the audit
    path (an audit list/callable) AND as a loud ``UnsafePathWarning``.
  * Postures:
      FAIL_CLOSED       -- refuses by default; the code rides on the refusal.
      EXPLICIT_OPT_IN   -- reachable only through a named deployment opt-in
                           (constructor/flag/ack); the code fires on EVERY
                           execution, opt-in or not.
      LEGACY_ADVISORY   -- documented legacy behavior, retained byte-identical;
                           the code fires on EVERY execution so it is never
                           silent.
      CONSULT_TELEMETRY -- defense-in-depth consult that never admits anything
                           on its own; fail-open-on-unreadable is the
                           documented discipline; the code fires on EVERY
                           execution.
"""

import warnings


class UnsafePathWarning(UserWarning):
    """Loud warning carrying a registered unsafe-path code."""


class UnknownUnsafePathError(Exception):
    """Raised when ``emit`` is asked for a code the registry never saw."""


#: code -> {module, posture, description, emission}
UNSAFE_PATHS = {
    # -- consult telemetry: fail-open-on-unreadable discipline -------------
    "gov.artifacts.egress_unreadable_tamper_check_skipped": {
        "module": "gov.artifacts",
        "posture": "CONSULT_TELEMETRY",
        "description": ("ArtifactInventory.check_egress with sha256_now=None "
                        "(file unreadable): the tamper comparison is "
                        "skipped and the verdict falls back to the label "
                        "signal. Mirrors the lineage hook's discipline."),
        "emission": "audit event on every execution (audit= kwarg)",
    },
    "gov.artifact_inventory_manifest.manifest_unreadable_failopen": {
        "module": "gov.artifact_inventory_manifest",
        "posture": "CONSULT_TELEMETRY",
        "description": ("check_manifest with sha256_now=None: the "
                        "deployment-pin comparison is skipped "
                        "(manifest_unreadable), fail-open on unreadable."),
        "emission": "audit event on every execution (audit= kwarg)",
    },
    "gov.artifact_sweep.unreadable_file_skipped": {
        "module": "gov.artifact_sweep",
        "posture": "CONSULT_TELEMETRY",
        "description": ("The sweep skips unreadable files/directories "
                        "fail-open per file, counted in stats. A blind "
                        "spot is only acceptable when it is counted AND "
                        "named."),
        "emission": "aggregated audit event per sweep call (audit= kwarg)",
    },
    # -- explicit opt-ins ----------------------------------------------------
    "gov.identity_policy.unsafe_allow_vacuous_pass": {
        "module": "gov.identity_policy",
        "posture": "EXPLICIT_OPT_IN",
        "description": ("UnsafeAllow: the named deployment opt-in that "
                        "passes vacuously. Requires a non-empty reason at "
                        "construction; warns loudly on EVERY use."),
        "emission": ("UnsafePathWarning on every verify + audit event at "
                     "the check_admission seam (audit= kwarg)"),
    },
    "gov.attested_identity.tier2_only_degradation": {
        "module": "gov.attested_identity",
        "posture": "EXPLICIT_OPT_IN",
        "description": ("degraded_attester(): explicit constructor for "
                        "hosts with no TPM/cloud verifier. Tier-1 stays "
                        "unreachable; tier-2 credentials carry the "
                        "TIER_2_NOT_ATTESTED_WARNING."),
        "emission": ("audit event at attester construction (attester.audit) "
                     "AND on EVERY tier-2 credential registration "
                     "(register_kernel_fact_identity); loud UnsafePathWarning "
                     "on each."),
    },
    # -- legacy advisory: retained byte-identical, never silent --------------
    "gov.capability_manifests.no_store_advisory": {
        "module": "gov.capability_manifests",
        "posture": "LEGACY_ADVISORY",
        "description": ("verify_skill_manifest with store=None returns "
                        "(True, 'no-store'): today's behavior when the "
                        "trust registry is unwired. Advisory only."),
        "emission": "audit event on every execution (audit= kwarg)",
    },
    "gov.capability_manifests.manifest_absent_advisory": {
        "module": "gov.capability_manifests",
        "posture": "LEGACY_ADVISORY",
        "description": ("verify_skill_manifest with no manifest for the "
                        "skill returns (True, 'manifest-absent'). The "
                        "caller emits the canonical "
                        "capability_manifest_absent event; this registry "
                        "code is its greppable alias."),
        "emission": "capability_manifest_absent (caller) + registry alias",
    },
    "gov.credential_manifest.no_session_identity_binding_skipped": {
        "module": "gov.credential_manifest",
        "posture": "LEGACY_ADVISORY",
        "description": ("check_egress with session_principal=None returns "
                        "True: the rule requires a provisioned session "
                        "identity, so there is nothing to bind to. "
                        "Documented, not a bypass of a configured check."),
        "emission": "audit event on every execution (audit= kwarg)",
    },
    "gov.scan_verdicts.empty_policy_no_scans_required": {
        "module": "gov.scan_verdicts",
        "posture": "LEGACY_ADVISORY",
        "description": ("ScanGate.check with a ScanPolicy whose "
                        "required_scans is empty: nothing is required, so "
                        "the gate passes vacuously. Scan gating is opt-in; "
                        "the vacuity is now named, not implicit."),
        "emission": "audit event on every execution (audit= kwarg)",
    },
    "gov.authority_proof.no_boundary_advisory": {
        "module": "gov.authority_proof",
        "posture": "LEGACY_ADVISORY",
        "description": ("check() with boundary=None: the operator declared "
                        "no authority boundary, so coverage cannot be "
                        "proven -- verdict INCONCLUSIVE, advisory only, "
                        "never a refusal and never a proof."),
        "emission": "the proof itself (verdict=inconclusive); pure fn",
    },
    "gov.evidence_verify.unpinned_self_consistent": {
        "module": "gov.evidence_verify",
        "posture": "LEGACY_ADVISORY",
        "description": ("verify_bundle with no pins: checks pass but "
                        "authorship is unproven -- verdict SELF_CONSISTENT "
                        "(exit 2), never VERIFIED (exit 0). The "
                        "distinction is the disclosure."),
        "emission": "verdict + exit code (public seam)",
    },
    "gov.executor.invocation_receipts_disabled": {
        "module": "gov.executor",
        "posture": "LEGACY_ADVISORY",
        "description": ("No receipt-signing key configured: consequential "
                        "invocations execute WITHOUT a countersigned "
                        "invocation receipt. Loud chained audit event."),
        "emission": "invocation_receipts_disabled (chained audit log)",
    },
    "gov.executor.decision_packet_disabled": {
        "module": "gov.executor",
        "posture": "LEGACY_ADVISORY",
        "description": ("No decision-packet key configured: executions run "
                        "without decision packets. Loud chained audit "
                        "event."),
        "emission": "decision_packet_disabled (chained audit log)",
    },
    "gov.decision_packet.packets_disabled_no_key": {
        "module": "gov.decision_packet",
        "posture": "LEGACY_ADVISORY",
        "description": ("Decision packets cannot be built/verified without "
                        "a configured key: the seam declares the absence "
                        "instead of minting packets."),
        "emission": "loud declaration at the seam (no silent packets)",
    },
    # -- fail-closed: the refusal carries the code ---------------------------
    "gov.executor.capability_gate_unconfigured_refused": {
        "module": "gov.executor",
        "posture": "FAIL_CLOSED",
        "description": ("Governed-core executor with no capability gate "
                        "binding and no explicit ungoverned ack: REFUSED "
                        "(no_binding_no_ack). The explicit ack is the "
                        "named opt-in, chained into the audit log and "
                        "refused outright in production."),
        "emission": "refusal no_binding_no_ack (loud)",
    },
    "gov.anchorer.unconfigured_anchoring_disabled": {
        "module": "gov.anchorer",
        "posture": "FAIL_CLOSED",
        "description": ("No anchor key configured: resolve_anchor_key "
                        "raises NoAnchorKeyError loudly; the chain "
                        "continues operator-attested-only, never silently "
                        "unanchored."),
        "emission": "NoAnchorKeyError (loud)",
    },
    "gov.policy_compile.post_compile_mutation_refused": {
        "module": "gov.policy_compile",
        "posture": "FAIL_CLOSED",
        "description": ("A compiled policy/ruleset whose live inputs were "
                        "mutated after compilation is REFUSED at "
                        "evaluation: the evaluation-time frozen snapshot "
                        "no longer matches. Closes the wave-217 residual."),
        "emission": "refusal carrying the code (loud)",
    },
}


def registered(code):
    """True when ``code`` is in the registry."""
    return code in UNSAFE_PATHS


def codes_for_posture(posture):
    """All registered codes with the given posture, in registry order."""
    return [c for c, m in UNSAFE_PATHS.items()
            if m["posture"] == posture]


def emit(code, *, audit=None, detail="", run_id=""):
    """Emit a registered unsafe-path code, loudly, on the audit path.

    Raises :class:`UnknownUnsafePathError` for unregistered codes --
    the registry fails closed. ``audit`` is an optional list (appended
    to) or a callable taking one event dict. A loud
    :class:`UnsafePathWarning` is always issued so the path can never
    execute silently, even when no audit handle is threaded through.
    """
    meta = UNSAFE_PATHS.get(code)
    if meta is None:
        raise UnknownUnsafePathError(
            "unsafe path %r is not registered: refusing to emit it "
            "silently" % (code,))
    event = {"event": "unsafe_path_executed",
             "code": code,
             "posture": meta["posture"],
             "module": meta["module"],
             "detail": detail,
             "run_id": run_id}
    if audit is not None:
        if callable(audit):
            audit(event)
        else:
            audit.append(event)
    warnings.warn("%s: %s" % (code, detail or meta["description"]),
                  UnsafePathWarning, stacklevel=3)
    return event
