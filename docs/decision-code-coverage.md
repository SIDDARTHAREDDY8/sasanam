# Decision-code coverage table (generated)

Generated: 2026-10-05T10:41:49Z UTC · registry pin: 2130 · base: wave-339 lane 2

Rule (Bernstein #5569, ADAPT): no row claims coverage without a test. A code counts as covered when its literal string appears quoted in at least one ``.py`` file under ``tests/`` or ``evals/``. Production ``emit()`` call sites do not count.

**Covered: 1919 / 2130** · **Gaps: 211**

| code | domain | severity | covered | asserted in |
| ---- | ------ | -------- | ------- | ----------- |
| `aauth-aud-mismatch` | aauth | high | yes | evals/w241_aauth_egress_probes.py, evals/w242_ir8587_conformance_probes.py, tests/test_aauth_egress.py |
| `aauth-egress-blocked` | aauth | high | yes | evals/w241_aauth_egress_probes.py, tests/test_aauth_egress.py |
| `aauth-iss-mismatch` | aauth | high | yes | evals/w241_aauth_egress_probes.py, tests/test_aauth_egress.py |
| `aauth-scheme-not-allowed` | aauth | high | yes | evals/w241_aauth_egress_probes.py, tests/test_aauth_egress.py |
| `aauth-stale-created` | aauth | high | yes | evals/w241_aauth_egress_probes.py, tests/test_aauth_egress.py |
| `absence-advertised-but-missing` | absence | medium | yes | evals/w222_revoke_probes.py, tests/test_absence_revocation.py |
| `absence-backdated` | absence-epoch | high | yes | evals/w242_absence_epoch_probes.py, tests/test_absence_epoch.py |
| `absence-disclosure-recorded` | absence-epoch | high | yes | evals/w242_absence_epoch_probes.py, tests/test_absence_epoch.py |
| `absence-epoch-beacon-unsigned` | absence-epoch | high | yes | evals/w242_absence_epoch_probes.py, tests/test_absence_epoch.py |
| `absence-epoch-closed` | absence-epoch | medium | yes | evals/w242_absence_epoch_probes.py, tests/test_absence_epoch.py |
| `absence-epoch-malformed` | absence-epoch | medium | yes | tests/test_absence_epoch.py |
| `absence-epoch-not-closed` | absence-epoch | high | yes | evals/w244_treeship_advisory_probes.py, tests/test_absence_epoch.py |
| `absence-epoch-not-open` | absence-epoch | high | yes | evals/w242_absence_epoch_probes.py, tests/test_absence_epoch.py |
| `absence-never-advertised` | absence | medium | yes | evals/w222_revoke_probes.py, tests/test_absence_revocation.py |
| `absence-not-observed` | absence-epoch | medium | yes | evals/w242_absence_epoch_probes.py, tests/test_absence_epoch.py |
| `absence-observation-unsigned` | absence-epoch | high | yes | tests/test_absence_epoch.py |
| `absence-refused` | absence | medium | **NO** |  |
| `absence-revoked` | absence | high | yes | evals/w222_revoke_probes.py |
| `absence-root-mismatch` | absence-epoch | high | yes | evals/w242_absence_epoch_probes.py, tests/test_absence_epoch.py |
| `absence-unverifiable` | absence | medium | yes | evals/w222_revoke_probes.py, evals/w224_agile_probes.py, tests/test_absence_revocation.py |
| `access-request-duplicate-review-refused` | access-request | medium | yes | evals/w281_teleport_probes.py |
| `access-request-grant-refused` | access-request | high | yes | evals/w281_teleport_probes.py, tests/test_access_requests.py |
| `access-request-reviewer-ineligible` | access-request | medium | yes | evals/w281_teleport_probes.py |
| `access-request-self-review-refused` | access-request | high | yes | evals/w281_teleport_probes.py, tests/test_access_requests.py |
| `access-request-terminal-refused` | access-request | medium | yes | evals/w281_teleport_probes.py, tests/test_access_requests.py |
| `action-binding-tampered` | typed_action | critical | yes | evals/w228_typed_probes.py, evals/w230_defsha_probes.py, tests/test_typed_actions.py |
| `action-depth-exceeded` | typed_action | medium | yes | evals/w230_defsha_probes.py, tests/test_typed_actions.py |
| `action-duplicate-key` | typed_action | high | yes | evals/w230_defsha_probes.py, tests/test_typed_actions.py |
| `action-material-missing` | typed_action | medium | yes | evals/w228_typed_probes.py, tests/test_typed_actions.py |
| `action-material-type-mismatch` | typed_action | medium | yes | evals/w230_defsha_probes.py, tests/test_typed_actions.py |
| `action-semantics-drift` | typed_action | critical | yes | evals/w230_defsha_probes.py, tests/test_typed_actions.py |
| `action-type-drift` | typed_action | critical | yes | evals/w228_typed_probes.py, tests/test_typed_actions.py |
| `action-type-unknown` | typed_action | medium | yes | evals/w228_typed_probes.py, tests/test_typed_actions.py |
| `action-value-count-exceeded` | typed_action | medium | yes | evals/w230_defsha_probes.py, tests/test_typed_actions.py |
| `action-value-too-long` | typed_action | medium | yes | evals/w230_defsha_probes.py, tests/test_typed_actions.py |
| `admission-at-risk-accepted` | admission | low | **NO** |  |
| `admission-check-failed` | admission | medium | yes | evals/w288_admission_probes.py, evals/w291_redteam_probes.py, tests/test_evidence_admission.py |
| `admission-conjunction-refused` | admission | medium | yes | evals/w223_gatealg_probes.py, evals/w224_quar_probes.py, tests/test_gate_algebra.py |
| `admission-digest-mismatch` | admission | critical | yes | evals/w221_admission_probes.py, evals/w223_gatealg_probes.py, evals/w223_set_probes.py (+4) |
| `admission-exception-refused` | admission | medium | yes | evals/w288_admission_probes.py, evals/w289_redteam_probes.py, evals/w290_f348_f349_probes.py (+2) |
| `admission-format-unknown` | admission | medium | yes | evals/w221_admission_probes.py, evals/w224_quar_probes.py, tests/test_admission.py (+1) |
| `admission-inspection-bundle-mismatch` | admission | critical | yes | evals/w221_admission_probes.py, tests/test_admission.py |
| `admission-inspection-missing` | admission | medium | yes | evals/w221_admission_probes.py, tests/test_admission.py |
| `admission-integrity-floor-violated` | admission | high | yes | evals/w288_admission_probes.py, evals/w289_redteam_probes.py, evals/w290_f348_f349_probes.py (+2) |
| `admission-issuer-untrusted` | admission | medium | yes | evals/w221_admission_probes.py, evals/w224_quar_probes.py, tests/test_admission.py (+2) |
| `admission-malformed` | admission | medium | yes | tests/test_admission.py, tests/test_gate_algebra.py |
| `admission-no-applicable-policy` | admission | medium | yes | evals/w288_admission_probes.py, tests/test_evidence_admission.py |
| `admission-policy-attestation-refused` | admission-policy | medium | yes | evals/w264_admission_probes.py, evals/w265_redteam_probes.py |
| `admission-policy-authority-unknown` | admission-policy | medium | yes | evals/w264_admission_probes.py |
| `admission-policy-digest-changed` | admission-policy | critical | yes | evals/w264_admission_probes.py, evals/w265_redteam_probes.py |
| `admission-policy-identity-refused` | admission-policy | high | yes | evals/w264_admission_probes.py, evals/w265_redteam_probes.py |
| `admission-policy-invalid` | admission | medium | yes | evals/w288_admission_probes.py, evals/w290_redteam_probes.py, evals/w291_f354_probes.py (+1) |
| `admission-policy-malformed` | admission-policy | medium | yes | evals/w264_admission_probes.py |
| `admission-policy-not-covered` | admission-policy | medium | yes | evals/w264_admission_probes.py |
| `admission-policy-signature-refused` | admission-policy | high | yes | evals/w264_admission_probes.py, evals/w265_redteam_probes.py |
| `admission-policy-transparency-refused` | admission-policy | medium | yes | evals/w264_admission_probes.py |
| `admission-policy-unresolvable` | admission-policy | medium | yes | evals/w264_admission_probes.py |
| `admission-policy-unsigned` | admission-policy | high | yes | evals/w264_admission_probes.py, evals/w265_redteam_probes.py |
| `admission-policy-vacuous` | admission-policy | medium | yes | evals/w264_admission_probes.py |
| `admission-refused` | admission | medium | yes | evals/w288_admission_probes.py, evals/w290_f348_f349_probes.py, evals/w291_redteam_probes.py (+1) |
| `admission-severity-exceeded` | admission | medium | yes | evals/w223_gatealg_probes.py, evals/w224_quar_probes.py, tests/test_gate_algebra.py |
| `admission-severity-unverifiable` | admission | medium | yes | evals/w223_gatealg_probes.py, evals/w224_quar_probes.py, tests/test_gate_algebra.py |
| `admission-tag-mutated` | admission | medium | yes | evals/w223_gatealg_probes.py, tests/test_gate_algebra.py |
| `admission-unverifiable` | admission | medium | yes | evals/w221_admission_probes.py, evals/w224_quar_probes.py, tests/test_admission.py (+1) |
| `advisory-input-malformed` | advisory | high | yes | evals/w246_advisory_state_probes.py, tests/test_advisory_state.py |
| `advisory-input-unpinned` | authority | high | yes | evals/w326_redteam_probes.py, evals/w328_resid_probes.py, evals/w329_redteam_probes.py (+1) |
| `advisory-version-tie` | authority | medium | yes | evals/w326_redteam_probes.py, evals/w328_resid_probes.py, evals/w329_redteam_probes.py (+1) |
| `aggregate-budget-already-charged` | budget | high | yes | evals/w242_aggregate_budget_probes.py, tests/test_aggregate_budget.py |
| `aggregate-budget-exhausted` | budget | high | yes | evals/w242_aggregate_budget_probes.py, tests/test_aggregate_budget.py |
| `aggregate-budget-malformed` | budget | medium | yes | evals/w242_aggregate_budget_probes.py, tests/test_aggregate_budget.py |
| `aggregate-budget-scope-undeclared` | budget | medium | yes | evals/w242_aggregate_budget_probes.py, tests/test_aggregate_budget.py |
| `agreement-input-unmapped` | reconcile_agreement | medium | yes | evals/w231_wimse_probes.py, tests/test_reconcile_agreement.py |
| `agreement-not-authorization` | reconcile_agreement | high | yes | evals/w231_wimse_probes.py, tests/test_reconcile_agreement.py |
| `alg-mismatch` | alg | critical | yes | evals/w224_agile_probes.py, tests/test_alg_registry.py |
| `alg-no-mutual` | alg | medium | yes | evals/w224_agile_probes.py, tests/test_alg_registry.py |
| `alg-non-repudiation-refused` | alg | high | yes | evals/w224_agile_probes.py, tests/test_alg_registry.py |
| `alg-refused` | alg | medium | **NO** |  |
| `alg-registration-refused` | alg | medium | yes | evals/w224_agile_probes.py, tests/test_alg_registry.py, tests/test_kms_signer.py |
| `alg-unregistered` | alg | medium | yes | evals/w224_agile_probes.py, evals/w226_kms_probes.py, tests/test_alg_registry.py (+1) |
| `already-bootstrapped` | manifest | medium | yes | evals/w219_rollback_probes.py, tests/test_version_manifest.py |
| `already_finalized` | approval | medium | yes | evals/w22_probes.py, tests/test_approvals_d1.py |
| `anchor-checkpoint-invalid` | anchor | high | yes | evals/w285_tessera_probes.py, evals/w287_f331_probes.py, tests/test_evidence_anchor.py |
| `anchor-inclusion-mismatch` | anchor | high | yes | evals/w285_tessera_probes.py, evals/w287_f331_probes.py, tests/test_evidence_anchor.py |
| `anchor-index-unpublished` | anchor | medium | yes | evals/w285_tessera_probes.py, tests/test_evidence_anchor.py |
| `anchor-leaf-mismatch` | anchor | medium | yes | evals/w285_tessera_probes.py, tests/test_evidence_anchor.py |
| `anchor-log-corrupt` | anchor | medium | yes | evals/w285_tessera_probes.py, evals/w287_f331_probes.py, tests/test_evidence_anchor.py |
| `anchor-no-signer` | anchor | medium | yes | evals/w285_tessera_probes.py, tests/test_evidence_anchor.py |
| `anchor-witness-quorum-failed` | anchor | high | yes | evals/w285_tessera_probes.py, evals/w287_f333_probes.py, tests/test_evidence_anchor.py |
| `approval-capability-dead` | scoped | high | yes | evals/w237_closescoped_probes.py, tests/test_closure_scoped_approvals.py |
| `approval-digest-diverged` | digest_link | critical | yes | evals/w222_digestlink_probes.py, evals/w223_set_probes.py, tests/test_digest_link.py (+1) |
| `approval-edited` | approval | high | yes | evals/w237_editedapproval_probes.py, tests/test_approval_edit_guard.py |
| `approval-malformed` | approval | medium | yes | evals/w237_editedapproval_probes.py, tests/test_approval_edit_guard.py |
| `approval-policy-audit-failed` | approval-policy | high | yes | evals/w254_approval_policy_probes.py, tests/test_approval_policy.py |
| `approval-policy-disapproval-defaulted` | approval-policy | high | yes | tests/test_approval_policy.py |
| `approval-policy-malformed` | approval-policy | medium | yes | evals/w254_approval_policy_probes.py, tests/test_approval_policy.py |
| `approval-policy-no-audit-sink` | approval-policy | high | yes | evals/w254_approval_policy_probes.py, tests/test_approval_policy.py |
| `approval-policy-seam-unavailable` | approval-policy | medium | yes | evals/w254_approval_policy_probes.py, tests/test_approval_policy.py |
| `approval-quorum-invalid` | approval | medium | yes | evals/w297_approval_quorum_probes.py, evals/w298_redteam_probes.py, tests/test_approval_quorum.py (+1) |
| `approval-quorum-self-vote` | approval | high | yes | evals/w297_approval_quorum_probes.py, tests/test_approval_quorum.py, tests/test_approval_request_quorum_integration.py |
| `approval-quorum-unmet` | approval | medium | yes | evals/w297_approval_quorum_probes.py, tests/test_approval_quorum.py |
| `approval-quorum-vetoed` | approval | high | yes | evals/w297_approval_quorum_probes.py, tests/test_approval_quorum.py |
| `approval-rebinding` | approval | high | yes | evals/w237_editedapproval_probes.py, tests/test_approval_edit_guard.py |
| `approval-record-digest-mismatch` | capability | critical | yes | tests/test_capability_grants.py |
| `approval-record-undigestible` | capability | medium | **NO** |  |
| `approval-record-unresolvable` | capability | medium | yes | tests/test_capability_grants.py |
| `approval-request-digest-missing` | approval | high | yes | evals/w297_approval_request_probes.py, tests/test_approval_request.py |
| `approval-request-expired` | approval | high | yes | evals/w297_approval_quorum_probes.py, evals/w297_approval_request_probes.py, evals/w300_delegation_approval_probes.py (+6) |
| `approval-request-forgery` | approval | critical | yes | evals/w297_approval_request_probes.py, evals/w300_delegation_approval_probes.py, evals/w301_redteam_probes.py (+1) |
| `approval-request-invalid` | approval | high | yes | evals/w297_approval_request_probes.py, evals/w298_redteam_probes.py, evals/w301_redteam_probes.py (+3) |
| `approval-route-mismatch` | scoped | high | yes | evals/w237_closescoped_probes.py, tests/test_closure_scoped_approvals.py |
| `approval-run-mismatch` | scoped | high | yes | evals/w237_closescoped_probes.py, tests/test_closure_scoped_approvals.py |
| `approval-sandbox-mismatch` | scoped | high | yes | evals/w237_closescoped_probes.py, tests/test_closure_scoped_approvals.py |
| `approval-state-stale` | scoped | high | yes | evals/w237_closescoped_probes.py, tests/test_closure_scoped_approvals.py |
| `approval-token-argument-mismatch` | approval | high | yes | evals/w313_aptokens_probes.py, evals/w314_redteam_probes.py, evals/w333_captoken_probes.py (+1) |
| `approval-token-capability-mismatch` | approval | high | yes | evals/w313_aptokens_probes.py, evals/w314_redteam_probes.py, evals/w333_captoken_probes.py (+1) |
| `approval-token-expired` | approval | medium | yes | evals/w313_aptokens_probes.py, evals/w314_redteam_probes.py, tests/test_approval_tokens.py |
| `approval-token-malformed` | approval | medium | yes | evals/w314_redteam_probes.py, tests/test_approval_tokens.py |
| `approval-token-replayed` | approval | high | yes | evals/w313_aptokens_probes.py, evals/w314_redteam_probes.py, tests/test_approval_tokens.py |
| `approval-token-tampered` | approval | critical | yes | evals/w313_aptokens_probes.py, evals/w314_redteam_probes.py, tests/test_approval_tokens.py |
| `arap-error` | arap | medium | **NO** |  |
| `arg_constraint_violated` | approval | medium | yes | tests/test_delegation_primitive.py |
| `artifact-blob-extra` | artifact-pack | high | yes | evals/w248_artifact_pack_probes.py, evals/w249_redteam_probes.py, tests/test_artifact_pack.py |
| `artifact-blob-missing` | artifact-pack | high | yes | evals/w248_artifact_pack_probes.py, tests/test_artifact_pack.py |
| `artifact-blob-tampered` | artifact-pack | high | yes | evals/w248_artifact_pack_probes.py, evals/w249_redteam_probes.py, tests/test_artifact_pack.py |
| `artifact-gate-refused` | namespace | medium | yes | evals/w213b_promotion_gate_probes.py, tests/test_promotion_artifact_gate.py |
| `artifact-manifest-malformed` | artifact-pack | medium | yes | evals/w248_artifact_pack_probes.py, tests/test_artifact_pack.py |
| `artifact-manifest-tampered` | artifact-pack | high | yes | evals/w248_artifact_pack_probes.py, tests/test_artifact_pack.py |
| `artifact-size-mismatch` | artifact-pack | high | yes | evals/w248_artifact_pack_probes.py, tests/test_artifact_pack.py |
| `artifact-type-unknown` | artifact-pack | medium | yes | evals/w248_artifact_pack_probes.py, tests/test_artifact_pack.py |
| `artifact_unpinned` | load_gate | medium | yes | evals/w78_probes.py, evals/w80_probes.py, tests/test_w194_tuf_load_seam.py (+2) |
| `artifact_unreadable` | load_gate | high | **NO** |  |
| `assessment_from_future` | capability | medium | yes | tests/test_capgate_wiring.py |
| `assessment_malformed` | capability | medium | **NO** |  |
| `assessment_report_digest_mismatch` | capability | medium | yes | tests/test_capgate_wiring.py |
| `assessment_signature_invalid` | capability | high | yes | evals/capgate_break.py, tests/test_capgate_wiring.py |
| `assessment_unsealed` | capability | medium | yes | tests/test_capgate_wiring.py |
| `assessment_untrusted_key` | capability | medium | yes | tests/test_capgate_wiring.py |
| `atomic-arg-refused` | atomic | medium | yes | evals/w282_atomicredteam_probes.py |
| `atomic-cleanup-failed` | atomic | high | yes | evals/w282_atomicredteam_probes.py |
| `atomic-dependency-refused` | atomic | medium | yes | evals/w282_atomicredteam_probes.py |
| `atomic-elevation-required` | atomic | medium | yes | evals/w282_atomicredteam_probes.py |
| `atomic-guid-collision` | atomic | high | yes | evals/w282_atomicredteam_probes.py |
| `atomic-spec-invalid` | atomic | high | yes | evals/w282_atomicredteam_probes.py, evals/w283_caldera_probes.py, evals/w284_f312_315_probes.py |
| `attackpath-duplicate-node` | policy | low | yes | evals/w282_bloodhound_probes.py, tests/test_attack_paths.py |
| `attackpath-unknown-edge-type` | policy | medium | yes | evals/w282_bloodhound_probes.py, tests/test_attack_paths.py |
| `attackpath-unknown-node` | policy | medium | yes | evals/w282_bloodhound_probes.py, tests/test_attack_paths.py |
| `attenuation-expired` | attenuation | medium | yes | evals/w223_atten_probes.py, tests/test_attenuation.py |
| `attenuation-lease-mismatch` | attenuation | critical | yes | evals/w223_atten_probes.py, tests/test_attenuation.py |
| `attenuation-missing` | attenuation | medium | yes | evals/w223_atten_probes.py, tests/test_attenuation.py |
| `attenuation-refused` | attenuation | medium | **NO** |  |
| `attenuation-ttl-refused` | attenuation | medium | yes | evals/w223_atten_probes.py, tests/test_attenuation.py |
| `attenuation-unverifiable` | attenuation | medium | yes | evals/w223_atten_probes.py, tests/test_attenuation.py |
| `attenuation-widening-refused` | attenuation | high | yes | evals/w223_atten_probes.py, tests/test_attenuation.py |
| `attest_absence` | absence | medium | **NO** |  |
| `attestation-class-inflation` | attested | high | yes | tests/test_attestation_column.py |
| `attestation-class-unlabeled` | attested | medium | yes | tests/test_attestation_column.py |
| `attestation-outcome-misread` | attested | high | yes | tests/test_attestation_column.py |
| `attestation-record-malformed` | attested | medium | yes | tests/test_attestation_column.py |
| `attestor-ceremony-invalid` | attested | high | yes | evals/w274_attestor_probes.py, tests/test_attestors.py |
| `attestor-entry-ambiguous` | attested | high | yes | evals/w274_attestor_probes.py, tests/test_attestors.py |
| `attestor-entry-malformed` | attested | medium | yes | tests/test_attestors.py |
| `attestor-entry-unmatched` | attested | high | yes | evals/w274_attestor_probes.py, tests/test_attestors.py |
| `attestor-facts-malformed` | attested | medium | yes | tests/test_attestors.py |
| `authority-lifecycle-expired` | authority-lifecycle | high | yes | evals/w303_authority_lifecycle_probes.py, evals/w304_redteam_probes.py, tests/test_authority_lifecycle.py |
| `authority-lifecycle-heartbeat-lapsed` | authority-lifecycle | high | yes | evals/w303_authority_lifecycle_probes.py, evals/w303_heartbeat_schedule_probes.py, evals/w304_redteam_probes.py (+2) |
| `authority-lifecycle-revoked` | authority-lifecycle | high | yes | evals/w303_authority_lifecycle_probes.py, tests/test_authority_lifecycle.py |
| `authority-stale` | authority | high | yes | evals/w243_verifier_failclosed_probes.py, tests/test_verifier_failclosed.py |
| `authority-unavailable` | authority | high | yes | evals/w243_verifier_failclosed_probes.py |
| `authorized_builders` | slsa | medium | yes | evals/slsa_predicate_probes.py, tests/test_slsa_predicate.py |
| `authz-allow` | authz | low | yes | evals/w268_authzcombine_probes.py, evals/w269_redteam_probes.py, tests/test_authorization_combine.py |
| `authz-audit-hit` | authz | low | yes | evals/w268_authzcombine_probes.py, tests/test_authorization_combine.py |
| `authz-default-deny` | authz | high | yes | evals/w268_authzcombine_probes.py, tests/test_authorization_combine.py |
| `authz-deny` | authz | high | yes | evals/w268_authzcombine_probes.py, evals/w269_redteam_probes.py, tests/test_authorization_combine.py |
| `authz-malformed-bundle` | authz | medium | yes | evals/w268_authzcombine_probes.py, evals/w269_redteam_probes.py, tests/test_authorization_combine.py |
| `authz-malformed-rule` | authz | medium | yes | evals/w268_authzcombine_probes.py, evals/w269_redteam_probes.py, tests/test_authorization_combine.py |
| `authz-partial-attributes` | authz | high | yes | evals/w268_authzcombine_probes.py, evals/w269_redteam_probes.py, tests/test_authorization_combine.py |
| `authz-provider-misconfigured` | authz | high | yes | evals/w268_authzcombine_probes.py, evals/w269_redteam_probes.py, tests/test_authorization_combine.py |
| `authz-shadow-evaluated` | authz | low | yes | evals/w269_redteam_probes.py, tests/test_authorization_combine.py |
| `authz-uncheckable` | authz | medium | yes | evals/w268_authzcombine_probes.py, tests/test_authorization_combine.py |
| `axis-ceiling-hit` | axis | medium | **NO** |  |
| `axis-indeterminate` | axis | medium | **NO** |  |
| `axis-invalid` | axis | high | **NO** |  |
| `axis-unestablished` | axis | medium | **NO** |  |
| `bad-artifacts` | corpus | medium | yes | tests/test_corpus_manifest.py |
| `bad-assertion-shape` | c2pa | medium | yes | evals/w215_c2pa24_probes.py, tests/test_c2pa24_conformance.py |
| `bad-enforcement-mode` | pack | medium | yes | tests/test_pack_lint.py |
| `bad-expiry` | corpus | medium | yes | tests/test_corpus_manifest.py |
| `bad-files` | deploy | medium | **NO** |  |
| `bad-format` | corpus | medium | yes | evals/w280_batterylang_probes.py, tests/test_audit_detect.py, tests/test_corpus_manifest.py (+2) |
| `bad-handoff` | deploy | medium | **NO** |  |
| `bad-identity-policy` | namespace | medium | **NO** |  |
| `bad-issuer-key` | measurement | medium | **NO** |  |
| `bad-measurements` | measurement | medium | **NO** |  |
| `bad-namespace` | namespace | medium | yes | evals/sign_deploy_namespace_probes.py, tests/test_sign_deploy_namespaces.py |
| `bad-now` | deploy | medium | **NO** |  |
| `bad-operator` | deploy | medium | **NO** |  |
| `bad-operator-ceremony` | pack | medium | **NO** |  |
| `bad-operators` | deploy | medium | yes | tests/test_deploy_trust_config.py |
| `bad-pack-class` | deploy | medium | **NO** |  |
| `bad-pack-id` | pack | medium | **NO** |  |
| `bad-pin` | c2pa | medium | yes | evals/w215_c2pa24_probes.py, tests/test_c2pa24_conformance.py |
| `bad-quorum-policy` | namespace | medium | yes | tests/test_quorum_policy.py |
| `bad-quorum-rollback-guard` | namespace | medium | yes | tests/test_version_manifest.py |
| `bad-rule` | audit | medium | yes | tests/test_audit_detect.py |
| `bad-rules` | pack | medium | **NO** |  |
| `bad-ruleset` | namespace | medium | yes | tests/test_promotion_artifact_gate.py |
| `bad-seed` | measurement | medium | **NO** |  |
| `bad-signature` | signature | high | yes | evals/sign_deploy_namespace_probes.py, tests/test_audit_detect.py, tests/test_corpus_manifest.py (+1) |
| `bad-statement-signature` | scitt | high | yes | tests/test_scitt_receipt.py |
| `bad-threshold` | quorum | medium | yes | tests/test_corpus_manifest.py |
| `bad-trust-record` | c2pa | medium | **NO** |  |
| `bad-trust-signature` | c2pa | high | yes | evals/w215_c2pa24_probes.py, tests/test_c2pa24_conformance.py |
| `bad-version` | corpus | medium | yes | evals/w261_detector_probes.py, evals/w269_redteam_probes.py |
| `bad_delegatee` | approval | high | **NO** |  |
| `bad_key` | drift | high | yes | evals/w245_packet_conformance_verifier.py |
| `bad_mac` | drift | high | yes | evals/w35_probes.py, tests/test_drift_budget.py, tests/test_f110_platform_egress.py (+1) |
| `bad_scope` | approval | high | yes | tests/test_delegation_primitive.py |
| `bad_signature` | lease | high | yes | evals/f152_hunt_break.py, evals/identity_covert_break.py, evals/w78_probes.py |
| `ballot-bad-signature` | ballot | high | yes | evals/w261_ballot_probes.py, evals/w262_ceremony_probes.py, evals/w262_redteam_probes.py |
| `ballot-double-vote` | ballot | medium | yes | evals/w261_ballot_probes.py, evals/w262_redteam_probes.py |
| `ballot-late-vote` | ballot | medium | yes | evals/w261_ballot_probes.py, evals/w262_redteam_probes.py |
| `ballot-malformed-proposal` | ballot | medium | **NO** |  |
| `ballot-not-member` | ballot | high | yes | evals/w261_ballot_probes.py |
| `ballot-quorum-not-reached` | ballot | medium | yes | evals/w261_ballot_probes.py |
| `ballot-unknown-ballot` | ballot | medium | yes | evals/w261_ballot_probes.py |
| `ballot-unknown-ballot-type` | ballot | medium | **NO** |  |
| `ballot-vote-hook-failed` | ballot | medium | yes | evals/w261_ballot_probes.py, evals/w262_redteam_probes.py |
| `battery-lang-bad-manifest` | battery | medium | yes | evals/w280_batterylang_probes.py |
| `battery-lang-bad-metadata` | battery | medium | **NO** |  |
| `battery-lang-bad-module` | battery | medium | **NO** |  |
| `battery-lang-bad-probe` | battery | medium | yes | evals/w280_batterylang_probes.py |
| `battery-lang-bad-probe-entry` | battery | medium | **NO** |  |
| `battery-lang-expected-drift` | battery | medium | yes | evals/w280_batterylang_probes.py, evals/w281_redteam_probes.py |
| `battery-lang-no-metadata` | battery | medium | yes | evals/w280_batterylang_probes.py |
| `battery-lang-no-probes` | battery | medium | **NO** |  |
| `battery-lang-probe-missing` | battery | medium | **NO** |  |
| `battery-lang-unannotated` | battery | medium | yes | evals/w280_batterylang_probes.py |
| `battery-lang-unknown-grader` | battery | medium | yes | evals/w280_batterylang_probes.py |
| `battery-lang-unknown-plugin` | battery | medium | yes | evals/w280_batterylang_probes.py, evals/w281_redteam_probes.py |
| `battery-lang-unknown-strategy` | battery | medium | yes | evals/w280_batterylang_probes.py |
| `behsig-correlator-advisory` | behsig | medium | yes | evals/w267_behsig_probes.py |
| `behsig-pack-malformed` | behsig | high | yes | evals/w267_behsig_probes.py, tests/test_behavioral_sig_packs.py |
| `behsig-pack-untrusted` | behsig | high | yes | evals/w267_behsig_probes.py, evals/w268_redteam_probes.py, tests/test_behavioral_sig_packs.py |
| `behsig-rule-disabled` | behsig | medium | yes | evals/w267_behsig_probes.py |
| `behsig-rule-eval-failed` | behsig | medium | yes | evals/w267_behsig_probes.py |
| `behsig-tuning-applied` | behsig | low | yes | evals/w267_behsig_probes.py, tests/test_behavioral_sig_packs.py |
| `behsig-tuning-rejected` | behsig | medium | yes | evals/w267_behsig_probes.py, evals/w268_redteam_probes.py, tests/test_behavioral_sig_packs.py |
| `binding_mismatch` | lease | high | yes | evals/w78_probes.py, tests/test_w78_supplychain.py |
| `blank_ack` | deployment | medium | yes | tests/test_w85_legacy_seam.py |
| `bootstrap-required` | manifest | medium | yes | evals/w219_rollback_probes.py, tests/test_version_manifest.py |
| `breach-boundary-budget-exceeded` | breach-boundary | high | yes | evals/w246_incident_replay_probes.py, tests/test_breach_boundary.py |
| `breach-boundary-circuit-tripped` | breach-boundary | high | yes | evals/w246_incident_replay_probes.py, tests/test_breach_boundary.py |
| `breach-boundary-compromised-source` | breach-boundary | high | yes | evals/w246_incident_replay_probes.py, tests/test_breach_boundary.py |
| `breach-boundary-external-untrusted` | breach-boundary | high | yes | tests/test_breach_boundary.py |
| `breach-boundary-quarantined` | breach-boundary | low | yes | evals/w246_incident_replay_probes.py, tests/test_breach_boundary.py, tests/test_breach_boundary_f210.py |
| `breach-boundary-record-malformed` | breach-boundary | medium | yes | evals/w246_incident_replay_probes.py, tests/test_breach_boundary.py, tests/test_breach_boundary_f210.py |
| `breach-boundary-reset-unvouched` | breach-boundary | medium | yes | evals/w246_incident_replay_probes.py, tests/test_breach_boundary.py |
| `breach-boundary-rotation-unvouched` | breach-boundary | medium | yes | evals/w246_incident_replay_probes.py, tests/test_breach_boundary.py |
| `breach-boundary-seal-invalid` | breach-boundary | high | yes | evals/w248_f210_closure_probes.py, evals/w249_redteam_probes.py, tests/test_breach_boundary.py (+1) |
| `breach-boundary-unknown-component` | breach-boundary | medium | yes | evals/w246_incident_replay_probes.py, tests/test_breach_boundary.py |
| `breach-boundary-unverified-use-refused` | breach-boundary | high | yes | evals/w246_incident_replay_probes.py, evals/w248_f210_closure_probes.py, tests/test_breach_boundary.py (+1) |
| `breach-boundary-verifier-unvouched` | breach-boundary | medium | yes | tests/test_breach_boundary.py |
| `bundle-delivery-cache-locked` | bundle | medium | yes | evals/w273_tuf_probes.py, tests/test_bundle_delivery.py |
| `bundle-delivery-delegation-cap-exceeded` | bundle | medium | yes | evals/w273_tuf_probes.py, tests/test_bundle_delivery.py |
| `bundle-delivery-delegation-cycle` | bundle | high | yes | evals/w273_tuf_probes.py, evals/w274_redteam_probes.py, tests/test_bundle_delivery.py |
| `bundle-delivery-delegation-malformed` | bundle | medium | yes | evals/w273_tuf_probes.py, evals/w274_redteam_probes.py, tests/test_bundle_delivery.py |
| `bundle-delivery-delegation-unverified` | bundle | high | yes | evals/w273_tuf_probes.py, tests/test_bundle_delivery.py |
| `bundle-delivery-expired-authority-refused` | bundle | high | yes | evals/w273_tuf_probes.py, tests/test_bundle_delivery.py |
| `bundle-delivery-expired-bootstrap-refused` | bundle | high | yes | evals/w273_tuf_probes.py, evals/w274_redteam_probes.py, tests/test_bundle_delivery.py |
| `bundle-delivery-mirror-stale` | bundle | high | yes | evals/w273_tuf_probes.py, tests/test_bundle_delivery.py |
| `bundle-delivery-shadowed-delegation` | bundle | high | yes | evals/w273_tuf_probes.py, evals/w274_redteam_probes.py, tests/test_bundle_delivery.py |
| `bundle-delivery-target-not-found` | bundle | medium | yes | evals/w273_tuf_probes.py, tests/test_bundle_delivery.py |
| `bundle-inspection-malformed` | bundle | medium | **NO** |  |
| `bundle-link-unverifiable` | bundle | medium | yes | evals/w221_admission_probes.py, tests/test_admission.py |
| `bundle_refresh_mismatch` | load_gate | high | yes | tests/test_bundle_refresh.py |
| `bundle_refresh_suspended` | load_gate | medium | yes | tests/test_bundle_refresh.py |
| `bundle_refresh_unbound` | load_gate | medium | yes | tests/test_bundle_refresh.py |
| `bundlescan-malformed` | bundle | high | yes | evals/w270_bundlescan_probes.py, evals/w271_redteam_probes.py, evals/w272_f255_probes.py (+2) |
| `bundlescan-odd-packaging` | bundle | low | yes | evals/w270_bundlescan_probes.py, tests/test_bundle_scan.py |
| `bundlescan-oversized` | bundle | high | yes | evals/w270_bundlescan_probes.py, tests/test_bundle_scan.py |
| `bundlescan-rce-global` | bundle | critical | yes | evals/w270_bundlescan_probes.py, evals/w271_redteam_probes.py, evals/w272_f255_probes.py (+2) |
| `bundlescan-suspicious-global` | bundle | high | yes | evals/w270_bundlescan_probes.py, tests/test_bundle_scan.py, tests/test_bundle_scan_f255.py |
| `bundlescan-unknown-global` | bundle | medium | yes | evals/w270_bundlescan_probes.py, evals/w272_f255_probes.py, tests/test_bundle_scan.py (+1) |
| `callauthz-check-error` | callauthz | high | **NO** |  |
| `callauthz-denied` | callauthz | high | yes | evals/w260_callauthz_probes.py |
| `callauthz-not-configured` | callauthz | high | **NO** |  |
| `callback-approval-denied` | callback | medium | yes | evals/w265_callback_probes.py |
| `callback-approval-expired` | callback | medium | yes | evals/w265_callback_probes.py |
| `callback-approval-requested` | callback | low | yes | evals/w265_callback_probes.py, tests/test_agent_callbacks.py |
| `callback-blocked` | callback | medium | yes | evals/w265_callback_probes.py, tests/test_agent_callbacks.py |
| `callback-cannot-widen` | callback | high | yes | evals/w265_callback_probes.py |
| `callback-faulted` | callback | medium | yes | evals/w265_callback_probes.py, tests/test_agent_callbacks.py |
| `callback-finding-escalated` | callback | low | yes | evals/w265_callback_probes.py |
| `callback-malformed-verdict` | callback | medium | yes | evals/w265_callback_probes.py, tests/test_agent_callbacks.py |
| `callback-unknown-approval` | callback | medium | yes | evals/w265_callback_probes.py, evals/w266_redteam_probes.py, tests/test_agent_callbacks.py |
| `campaign-produces-suppressed` | campaign | low | yes | evals/w284_redteam_probes.py, evals/w285_f324_f316_probes.py |
| `cancellation-unauthorized` | arap | high | yes | evals/w218_arap_probes.py, tests/test_arap.py |
| `canonical_link_body` | quorum | medium | **NO** |  |
| `canonicalization-failure` | agent_card | medium | yes | evals/a2a_card_verifier_probes.py, evals/w215_redteam_probes.py, tests/test_capability_manifests.py |
| `capability-token-agent-mismatch` | capability | high | yes | evals/w333_captoken_probes.py, evals/w334_attack_probes.py, evals/w334_redteam_probes.py |
| `capability-token-expired` | capability | medium | yes | evals/w333_captoken_probes.py, evals/w334_redteam_probes.py |
| `capability-token-malformed` | capability | medium | yes | evals/w333_captoken_probes.py, evals/w334_redteam_probes.py |
| `capability-token-mission-mismatch` | capability | high | yes | evals/w333_captoken_probes.py, evals/w334_redteam_probes.py |
| `capability-token-policy-stale` | capability | high | yes | evals/w333_captoken_probes.py, evals/w334_redteam_probes.py |
| `capability-token-tampered` | capability | critical | yes | evals/w333_captoken_probes.py, evals/w334_redteam_probes.py |
| `capability-token-tools-mismatch` | capability | high | yes | evals/w333_captoken_probes.py, evals/w334_redteam_probes.py |
| `capability_assessment_expired` | capability | medium | yes | evals/capgate_break.py, tests/test_capgate_wiring.py, tests/test_f152_sweep_capability_gate.py |
| `capability_assessment_insufficient` | capability | medium | yes | tests/test_capgate_wiring.py, tests/test_f152_sweep_capability_gate.py |
| `capability_assessment_missing` | capability | medium | yes | evals/capgate_break.py, tests/test_capgate_wiring.py, tests/test_f152_sweep_capability_gate.py |
| `capsule-attempt-effect-diverged` | capsule | critical | yes | evals/w224_capsule_probes.py, tests/test_action_capsule.py |
| `capsule-closestate-mismatch` | capsule | critical | yes | evals/w225_recompute_probes.py, tests/test_capsule_batch.py |
| `capsule-count-mismatch` | capsule | critical | yes | evals/w225_recompute_probes.py, evals/w228_codes_probes.py, tests/test_capsule_batch.py |
| `capsule-digest-mismatch` | capsule | critical | yes | evals/w224_capsule_probes.py, evals/w225_recompute_probes.py, tests/test_action_capsule.py (+2) |
| `capsule-malformed` | capsule | medium | yes | evals/w225_recompute_probes.py, evals/w229_reconcile_probes.py, tests/test_action_capsule.py (+1) |
| `capsule-noncanonical` | capsule | medium | yes | evals/w224_capsule_probes.py, tests/test_action_capsule.py, tests/test_decision_effect_agreement.py |
| `capsule-not-authorization` | capsule | high | yes | evals/w224_capsule_probes.py, evals/w227_pairs_probes.py, evals/w229_reconcile_probes.py (+2) |
| `capsule-refused` | capsule | medium | **NO** |  |
| `capsule-unknown-field` | capsule | medium | yes | evals/w224_capsule_probes.py, evals/w225_recompute_probes.py, tests/test_action_capsule.py (+1) |
| `card-version` | agent_card | medium | yes | evals/w214_agentcard_probes.py, tests/test_agent_cards_v1.py |
| `carrier_mismatch` | memory | medium | yes | evals/w228_codes_probes.py, tests/test_audio_carrier.py |
| `casbin-conf-invalid` | policy | medium | yes | evals/w281_casbin_probes.py, tests/test_casbin_perm.py |
| `casbin-enforce-error-fail-closed` | policy | medium | yes | evals/w282_redteam_probes.py, tests/test_casbin_perm.py |
| `casbin-policy-shadowed` | policy | medium | yes | evals/w281_casbin_probes.py, tests/test_casbin_perm.py |
| `casbin-unknown-matcher-function` | policy | medium | yes | evals/w281_casbin_probes.py, tests/test_casbin_perm.py |
| `ceremony-bad-signature` | ceremony | medium | yes | evals/w262_ceremony_probes.py |
| `ceremony-digest-mismatch` | ceremony | high | yes | evals/w262_ceremony_probes.py |
| `ceremony-double-review` | ceremony | medium | yes | evals/w262_ceremony_probes.py |
| `ceremony-malformed-proposal` | ceremony | medium | **NO** |  |
| `ceremony-not-keyholder` | ceremony | medium | **NO** |  |
| `ceremony-phase-violation` | ceremony | medium | yes | evals/w262_ceremony_probes.py |
| `ceremony-private-key-material` | ceremony | high | yes | evals/w262_ceremony_probes.py |
| `ceremony-quorum-not-reached` | ceremony | high | yes | evals/w262_ceremony_probes.py |
| `ceremony-refused` | namespace | high | yes | evals/sign_deploy_namespace_probes.py, evals/w213b_promotion_gate_probes.py, tests/test_promotion_artifact_gate.py (+1) |
| `ceremony-rehearsal-forged` | ceremony | high | yes | evals/w262_ceremony_probes.py |
| `ceremony-rehearsal-missing` | ceremony | high | yes | evals/w262_ceremony_probes.py |
| `ceremony-replayed` | ceremony | high | yes | evals/w262_ceremony_probes.py |
| `ceremony-routine-path-refused` | ceremony | high | yes | evals/w262_ceremony_probes.py |
| `ceremony-unknown-ceremony` | ceremony | medium | **NO** |  |
| `ceremony-v2-already-consumed` | ceremony | medium | yes | evals/w270_ceremony_probes.py, evals/w271_redteam_probes.py, tests/test_approval_ceremony.py |
| `ceremony-v2-ambiguous-resume` | ceremony | medium | yes | evals/w270_ceremony_probes.py, evals/w271_redteam_probes.py, tests/test_approval_ceremony.py |
| `ceremony-v2-malformed` | ceremony | medium | yes | evals/w270_ceremony_probes.py, tests/test_approval_ceremony.py |
| `ceremony-v2-payload-tampered` | ceremony | high | yes | evals/w270_ceremony_probes.py, evals/w271_redteam_probes.py, tests/test_approval_ceremony.py |
| `ceremony-v2-receipt-invalid` | ceremony | high | yes | evals/w270_ceremony_probes.py, evals/w271_redteam_probes.py, tests/test_approval_ceremony.py |
| `ceremony-v2-schema-invalid` | ceremony | medium | yes | evals/w270_ceremony_probes.py, evals/w271_redteam_probes.py, tests/test_approval_ceremony.py |
| `ceremony-v2-schema-violation` | ceremony | medium | yes | evals/w270_ceremony_probes.py, tests/test_approval_ceremony.py |
| `ceremony-v2-stale-lineage` | ceremony | medium | yes | evals/w270_ceremony_probes.py, evals/w271_redteam_probes.py, tests/test_approval_ceremony.py |
| `ceremony-v2-unknown-approval` | ceremony | medium | yes | evals/w270_ceremony_probes.py, evals/w271_redteam_probes.py, tests/test_approval_ceremony.py |
| `ceremony-v2-verdict-arg-mismatch` | ceremony | medium | yes | evals/w270_ceremony_probes.py, tests/test_approval_ceremony.py |
| `ceremony-v2-verdict-not-allowed` | ceremony | medium | yes | evals/w270_ceremony_probes.py, evals/w271_redteam_probes.py, tests/test_approval_ceremony.py |
| `chain-octet-digest-absent` | audit | high | yes | evals/w234_octetchain_probes.py, tests/test_log_octet_chain.py |
| `chain-octet-digest-mismatch` | audit | high | yes | evals/w234_octetchain_probes.py, tests/test_log_octet_chain.py |
| `chain-record-truncated` | audit | high | yes | evals/w234_octetchain_probes.py |
| `chain-source-stale` | authority | high | yes | evals/w243_verifier_failclosed_probes.py, evals/w244_treeship_advisory_probes.py, evals/w246_advisory_state_probes.py (+3) |
| `chain-source-unavailable` | authority | high | yes | evals/w243_verifier_failclosed_probes.py, tests/test_advisory_binding.py |
| `chain_broken` | approval | medium | yes | tests/test_delegation_primitive.py |
| `challenge-anchor-mismatch` | challenge | high | yes | evals/w289_ceremony_probes.py, tests/test_ceremony_binding.py |
| `challenge-invalid-shape` | challenge | medium | yes | tests/test_ceremony_binding.py |
| `challenge-nonce-invalid` | challenge | medium | yes | evals/w289_ceremony_probes.py, evals/w290_redteam_probes.py, tests/test_ceremony_binding.py |
| `challenge-nonce-mismatch` | challenge | high | yes | evals/w289_ceremony_probes.py, evals/w290_redteam_probes.py, tests/test_ceremony_binding.py |
| `challenge-purpose-mismatch` | challenge | high | yes | evals/w289_ceremony_probes.py, evals/w290_redteam_probes.py, tests/test_ceremony_binding.py |
| `challenge-signature-invalid` | challenge | high | yes | evals/w289_ceremony_probes.py, evals/w290_redteam_probes.py, evals/w291_f353_f355_probes.py (+1) |
| `channel-identity-unattested` | attested-channel | high | yes | evals/w243_attested_channel_probes.py, evals/w260_identity2_probes.py, tests/test_attested_channel.py (+1) |
| `channel-peer-mismatch` | attested-channel | high | yes | evals/w243_attested_channel_probes.py, evals/w244_treeship_advisory_probes.py, tests/test_attested_channel.py |
| `channel-record-malformed` | attested-channel | high | yes | evals/w243_attested_channel_probes.py, tests/test_attested_channel.py, tests/test_mesh_admission.py |
| `channel-sequence-break` | attested-channel | high | yes | evals/w243_attested_channel_probes.py, tests/test_attested_channel.py |
| `channel-timestamp-divergence` | attested-channel | high | yes | evals/w243_attested_channel_probes.py, tests/test_attested_channel.py |
| `checkpoint-chain-broken` | checkpoints | critical | yes | evals/w229_mmr_probes.py, tests/test_checkpoints.py |
| `checkpoint-count-mismatch` | checkpoints | critical | yes | evals/w229_mmr_probes.py |
| `checkpoint-evidence-not-authorization` | checkpoints | high | yes | evals/w229_mmr_probes.py, tests/test_checkpoints.py |
| `checkpoint-extension-empty` | checkpoint | low | yes | evals/w238_checkpoint_probes.py, tests/test_checkpoint_note.py |
| `checkpoint-inconsistent` | checkpoint | high | yes | evals/w238_checkpoint_probes.py, tests/test_checkpoint_note.py |
| `checkpoint-known-signature-invalid` | checkpoint | high | yes | evals/w238_checkpoint_probes.py |
| `checkpoint-log-empty` | checkpoint | medium | yes | evals/w238_checkpoint_probes.py, tests/test_checkpoint_note.py |
| `checkpoint-log-incomplete` | checkpoints | critical | yes | evals/w229_mmr_probes.py |
| `checkpoint-log-reordered` | checkpoints | critical | yes | evals/w229_mmr_probes.py, tests/test_checkpoints.py |
| `checkpoint-malformed` | checkpoints | medium | yes | tests/test_checkpoints.py |
| `checkpoint-no-trusted-signature` | checkpoint | high | yes | evals/w238_checkpoint_probes.py |
| `checkpoint-not-c2sp` | checkpoint | high | yes | evals/w238_checkpoint_probes.py, tests/test_checkpoint_note.py |
| `checkpoint-note-malformed` | checkpoint | high | yes | evals/w238_checkpoint_probes.py, tests/test_checkpoint_note.py |
| `checkpoint-origin-empty` | checkpoint | medium | yes | evals/w238_checkpoint_probes.py, tests/test_checkpoint_note.py |
| `checkpoint-refused` | checkpoints | medium | **NO** |  |
| `checkpoint-root-malformed` | checkpoint | medium | yes | evals/w238_checkpoint_probes.py, tests/test_checkpoint_note.py |
| `checkpoint-signature-invalid` | checkpoints | critical | yes | evals/w229_mmr_probes.py |
| `checkpoint-size-malformed` | checkpoint | medium | yes | evals/w238_checkpoint_probes.py, tests/test_checkpoint_note.py |
| `child-refused-op` | capability | medium | **NO** |  |
| `claim-invalid-grant` | claim | high | yes | evals/w239_claim_dispatch_probes.py, tests/test_claim_at_dispatch.py |
| `claim-lease-expired` | claim | medium | yes | evals/w239_claim_dispatch_probes.py, tests/test_claim_at_dispatch.py |
| `claim-malformed` | claim | medium | yes | tests/test_claim_at_dispatch.py |
| `claim-not-presented` | claim | high | yes | evals/w239_claim_dispatch_probes.py, tests/test_claim_at_dispatch.py |
| `claim-not-releasable` | claim | high | yes | evals/w239_claim_dispatch_probes.py, tests/test_claim_at_dispatch.py |
| `claim-replay` | claim | high | yes | evals/w239_claim_dispatch_probes.py, tests/test_claim_at_dispatch.py |
| `clear_cross_run_lineage` | lineage | medium | **NO** |  |
| `close-chain-digest-mismatch` | close | high | yes | evals/w236_closebind_probes.py, tests/test_close_signer_binding.py |
| `close-record-malformed` | close | medium | yes | tests/test_close_signer_binding.py |
| `close-signature-invalid` | close | high | yes | evals/w236_closebind_probes.py, tests/test_close_signer_binding.py |
| `close-signer-absent` | close | medium | yes | evals/w236_closebind_probes.py, tests/test_close_signer_binding.py |
| `close-signer-mismatch` | close | high | yes | evals/w236_closebind_probes.py, tests/test_close_signer_binding.py |
| `close-trust-repointed` | close | high | yes | evals/w236_closebind_probes.py, tests/test_close_signer_binding.py |
| `close-unsigned-scope` | close | high | yes | evals/w236_closebind_probes.py, tests/test_close_signer_binding.py |
| `closure-permit-absent` | permit | high | yes | evals/w236_permitclosure_probes.py, tests/test_permit_closure.py |
| `closure-permit-mismatch` | permit | high | yes | evals/w236_permitclosure_probes.py, tests/test_permit_closure.py |
| `closure-scope-widened` | permit | high | yes | evals/w236_permitclosure_probes.py, tests/test_permit_closure.py |
| `combine-default-deny` | policy-combine | high | yes | evals/w248_policy_combine_probes.py, evals/w249_redteam_probes.py, tests/test_policy_combine.py |
| `combine-forbid-overrides` | policy-combine | high | yes | evals/w248_policy_combine_probes.py, evals/w249_redteam_probes.py, evals/w251_harness_probes.py (+3) |
| `combine-misuse` | policy-combine | medium | yes | evals/w248_policy_combine_probes.py, tests/test_policy_combine.py |
| `commit-path-escape` | capability | medium | **NO** |  |
| `commit-right-missing` | capability | medium | **NO** |  |
| `commit-unknown-token` | capability | medium | yes | evals/capability_grant_probes.py |
| `compliance-emitter-malformed` | compliance-emitter | medium | yes | evals/w254_compliance_probes.py, tests/test_compliance_emitter.py |
| `compliance-emitter-unknown-code` | compliance-emitter | medium | yes | evals/w254_compliance_probes.py, tests/test_compliance_emitter.py |
| `compliance-emitter-unknown-finding` | compliance-emitter | medium | yes | evals/w254_compliance_probes.py, tests/test_compliance_emitter.py |
| `compliance-emitter-unknown-format` | compliance-emitter | medium | yes | evals/w254_compliance_probes.py, tests/test_compliance_emitter.py |
| `compliance-emitter-unknown-mechanism` | compliance-emitter | medium | yes | evals/w254_compliance_probes.py, tests/test_compliance_emitter.py |
| `compliance-emitter-unknown-track` | compliance-emitter | medium | yes | evals/w254_compliance_probes.py, tests/test_compliance_emitter.py |
| `compliance-emitter-unlinked-claim` | compliance-emitter | medium | yes | evals/w254_compliance_probes.py, tests/test_compliance_emitter.py |
| `component_tampered` | platform | high | yes | evals/f81launcher_privileged.py, evals/s7egress_break.py, tests/test_s7_egress_launcher.py |
| `compute_candidate` | release | medium | **NO** |  |
| `config-authority-claim-refused` | config | medium | yes | evals/w244_config_trust_probes.py, tests/test_config_trust.py |
| `config-body-malformed` | deploy | medium | yes | evals/w228_codes_probes.py, tests/test_deploy_trust_config.py |
| `config-malformed` | authorization_receipt | medium | **NO** |  |
| `config-provenance-agent-asserted` | config | medium | yes | evals/w244_config_trust_probes.py, evals/w245_spawn_context_probes.py, tests/test_config_trust.py (+1) |
| `config-provenance-untrusted` | config | medium | yes | evals/w244_config_trust_probes.py, evals/w245_spawn_context_probes.py, tests/test_spawn_context_guard.py |
| `config-record-malformed` | config | medium | yes | evals/w244_config_trust_probes.py, tests/test_config_trust.py |
| `config-rewritten-privilege` | config | medium | yes | evals/w244_config_trust_probes.py, tests/test_config_trust.py |
| `config-version-mismatch` | deploy | medium | yes | tests/test_deploy_trust_config.py |
| `consent_expired` | platform | medium | **NO** |  |
| `consent_invalid` | platform | high | **NO** |  |
| `consent_key_required` | platform | medium | yes | tests/test_f110_platform_egress.py |
| `consent_required` | platform | medium | **NO** |  |
| `consumption-idempotency-reused` | consumption | high | yes | evals/w234_consumed_probes.py, tests/test_consumption_ledger.py |
| `consumption-instance-malformed` | consumption | medium | yes | evals/w234_consumed_probes.py, tests/test_consumption_ledger.py |
| `consumption-journal-unusable` | consumption | high | yes | tests/test_consumption_ledger.py |
| `consumption-journal-write-failed` | consumption | high | **NO** |  |
| `consumption-key-malformed` | consumption | medium | yes | evals/w234_consumed_probes.py, tests/test_consumption_ledger.py |
| `consumption-receipt-malformed` | consumption | medium | yes | evals/w234_consumed_probes.py, tests/test_consumption_ledger.py |
| `consumption-receipt-tampered` | consumption | high | yes | evals/w234_consumed_probes.py, tests/test_consumption_ledger.py |
| `content-type-not-allowlisted` | scitt | medium | yes | tests/test_scitt_receipt.py |
| `context-binding-mismatch` | arap | high | yes | evals/w218_arap_probes.py, tests/test_arap.py |
| `context-key-mismatch` | policy | high | yes | tests/test_policy_registration_compile.py |
| `context-not-declared` | arap | high | yes | evals/w218_arap_probes.py, tests/test_arap.py |
| `contradictory_declaration` | deployment | medium | **NO** |  |
| `control-profile-check-passed` | control-profile | low | yes | evals/w257_profiles_probes.py, evals/w259_f226_probes.py, tests/test_control_profiles.py |
| `control-profile-duplicate-control-id` | control-profile | medium | yes | evals/w257_profiles_probes.py, tests/test_control_profiles.py |
| `control-profile-empty` | control-profile | medium | yes | evals/w257_profiles_probes.py, tests/test_control_profiles.py |
| `control-profile-evidence-malformed` | control-profile | medium | yes | evals/w257_profiles_probes.py, evals/w259_redteam_probes.py, tests/test_control_profiles.py |
| `control-profile-gate-failed` | control-profile | medium | yes | evals/w257_profiles_probes.py, evals/w258_redteam_probes.py, evals/w259_f226_probes.py (+2) |
| `control-profile-invalid-impact` | control-profile | medium | yes | evals/w257_profiles_probes.py, tests/test_control_profiles.py |
| `control-profile-malformed` | control-profile | medium | yes | evals/w260_f227_probes.py, tests/test_control_profiles.py |
| `control-profile-non-callable-check` | control-profile | medium | yes | evals/w257_profiles_probes.py, tests/test_control_profiles.py |
| `control-profile-unknown-key` | control-profile | medium | yes | evals/w257_profiles_probes.py, tests/test_control_profiles.py |
| `coord-lease-denied` | coord-lease | medium | yes | evals/w294_coord_lease_probes.py, evals/w296_f367_probes.py, evals/w297_redteam_probes.py (+1) |
| `coord-lease-expired` | coord-lease | high | yes | evals/w294_coord_lease_probes.py, evals/w297_redteam_probes.py, evals/w300_revoke_lease_probes.py (+9) |
| `coord-lease-fencing` | coord-lease | high | yes | evals/w294_coord_lease_probes.py, evals/w297_redteam_probes.py, evals/w298_supervision_lease_probes.py (+12) |
| `coord-lease-invalid` | coord-lease | high | yes | evals/w294_coord_lease_probes.py, evals/w297_redteam_probes.py, evals/w300_revoke_lease_probes.py (+4) |
| `coord-lease-manager-mismatch` | coord-lease | high | yes | evals/w307_redteam_probes.py, evals/w308_f391_probes.py, evals/w308_redteam_probes.py (+6) |
| `coord-state-bound` | coord-state | medium | yes | evals/w295_crdt_state_probes.py, tests/test_coordination_state.py |
| `coord-state-forgery` | coord-state | high | yes | evals/w295_crdt_state_probes.py, tests/test_coordination_state.py |
| `coord-state-invalid` | coord-state | high | yes | evals/w295_crdt_state_probes.py, tests/test_coordination_state.py |
| `coord-state-overwrite` | coord-state | high | yes | evals/w295_crdt_state_probes.py, tests/test_coordination_state.py |
| `corpus-expired` | corpus | medium | yes | tests/test_corpus_manifest.py |
| `corpus_manifest_mismatch` | load_gate | high | yes | evals/tuf_corpus_probes.py, tests/test_corpus_manifest.py |
| `corpus_manifest_stale` | load_gate | medium | yes | evals/tuf_corpus_probes.py, tests/test_corpus_manifest.py |
| `corpus_manifest_unbound` | load_gate | medium | yes | evals/tuf_corpus_probes.py, tests/test_corpus_manifest.py |
| `corpus_manifest_unpresented` | load_gate | medium | yes | evals/tuf_corpus_probes.py, tests/test_corpus_manifest.py |
| `corrob-receipt-failed` | corroboration | medium | yes | evals/w267_corrob_probes.py, tests/test_corroboration_receipt.py |
| `corrob-receipt-malformed` | corroboration | medium | yes | evals/w267_corrob_probes.py, tests/test_corroboration_receipt.py |
| `corrob-receipt-not-approved` | corroboration | medium | yes | evals/w267_corrob_probes.py, tests/test_corroboration_receipt.py |
| `corrob-receipt-predicate-mismatch` | corroboration | medium | yes | evals/w267_corrob_probes.py, tests/test_corroboration_receipt.py |
| `corrob-receipt-self-corroboration` | corroboration | high | yes | evals/w267_corrob_probes.py, tests/test_corroboration_receipt.py |
| `corrob-receipt-signature-invalid` | corroboration | high | yes | evals/w267_corrob_probes.py, evals/w268_redteam_probes.py, tests/test_corroboration_receipt.py |
| `corrob-receipt-subject-mismatch` | corroboration | high | yes | evals/w267_corrob_probes.py, evals/w268_redteam_probes.py, tests/test_corroboration_receipt.py |
| `corrob-receipt-unbound-issuer` | corroboration | high | yes | evals/w267_corrob_probes.py, evals/w268_redteam_probes.py, tests/test_corroboration_receipt.py |
| `corrob-vc-proof-invalid` | corroboration | high | yes | evals/w267_corrob_probes.py, tests/test_corroboration_receipt.py |
| `corroboration-key-inequality` | corroboration | high | yes | evals/w339_covgap1_probes.py |
| `corroboration-malformed` | corroboration | medium | yes | evals/w339_covgap1_probes.py |
| `corroboration-signature-invalid` | corroboration | high | yes | evals/w339_covgap1_probes.py |
| `corroboration-unattested` | corroboration | high | yes | evals/w339_covgap1_probes.py |
| `corroboration-uncorroborated` | corroboration | high | yes | evals/w339_covgap1_probes.py |
| `corroboration-untrusted-source` | corroboration | medium | yes | evals/w339_covgap1_probes.py |
| `coverage-logbook-chain-broken` | coverage | high | yes | evals/w275_coverage_probes.py, evals/w276_redteam_probes.py, tests/test_coverage_ledger.py |
| `coverage-refused-backdated-entry` | coverage | medium | yes | evals/w275_coverage_probes.py, evals/w276_redteam_probes.py, evals/w277_f298_probes.py (+2) |
| `coverage-refused-future-dated-entry` | coverage | medium | yes | evals/w277_f298_probes.py, evals/w278_redteam_probes.py |
| `coverage-refused-monitor-implies-prevention` | coverage | medium | yes | evals/w275_coverage_probes.py, evals/w276_redteam_probes.py, tests/test_coverage_ledger.py |
| `coverage-refused-no-denominator` | coverage | medium | yes | evals/w275_coverage_probes.py, tests/test_coverage_ledger.py |
| `coverage-refused-no-proof-method` | coverage | medium | yes | evals/w275_coverage_probes.py, tests/test_coverage_ledger.py |
| `credential-strict-config-invalid` | credential | high | yes | evals/w266_credstrict_probes.py, tests/test_credential_strict.py |
| `credential-strict-host-denied` | credential | high | yes | evals/w266_credstrict_probes.py, evals/w267_redteam_probes.py, tests/test_credential_strict.py |
| `credential-strict-refused` | credential | high | yes | evals/w266_credstrict_probes.py, evals/w267_redteam_probes.py, tests/test_credential_strict.py |
| `credential-strict-unapproved` | credential | high | yes | evals/w266_credstrict_probes.py, evals/w267_redteam_probes.py, tests/test_credential_strict.py |
| `cross_run_denied` | approval | high | yes | tests/test_delegation_primitive.py |
| `custody-shamir-bad-params` | custody | medium | yes | evals/w328_shamir_probes.py, evals/w329_redteam_probes.py, tests/test_shamir_custody.py |
| `custody-shamir-ceremony-mismatch` | custody | high | yes | evals/w328_shamir_probes.py, evals/w329_redteam_probes.py, tests/test_shamir_custody.py |
| `custody-shamir-commitment-mismatch` | custody | high | yes | evals/w328_shamir_probes.py, evals/w329_redteam_probes.py |
| `custody-shamir-distribute-refused` | custody | medium | yes | evals/w328_shamir_probes.py, evals/w329_redteam_probes.py, evals/w331_redteam_probes.py (+2) |
| `custody-shamir-duplicate-share` | custody | high | yes | evals/w328_shamir_probes.py, evals/w329_redteam_probes.py |
| `custody-shamir-insufficient-shares` | custody | medium | yes | evals/w328_shamir_probes.py, evals/w329_redteam_probes.py, tests/test_shamir_custody.py |
| `custody-shamir-share-malformed` | custody | medium | yes | evals/w328_shamir_probes.py, evals/w329_redteam_probes.py |
| `custody-shamir-transcript-corrupt` | custody | high | yes | evals/w328_shamir_probes.py, evals/w329_redteam_probes.py, tests/test_shamir_custody.py |
| `decision-code-digest-malformed` | decision_codes | high | yes | evals/w228_codes_probes.py, tests/test_decision_codes.py |
| `decision-code-digest-mismatch` | decision_codes | high | yes | evals/w228_codes_probes.py, tests/test_decision_codes.py |
| `decision-code-malformed` | decision_codes | medium | yes | evals/w228_codes_probes.py, evals/w303_f385_probes.py, tests/test_decision_codes.py (+4) |
| `decision-code-not-authorization` | decision_codes | critical | yes | evals/w228_codes_probes.py, tests/test_decision_codes.py |
| `decision-code-unmapped` | decision_codes | medium | yes | evals/w228_codes_probes.py, tests/test_decision_codes.py |
| `decision-effect-decision-drift` | decision_effect | critical | yes | evals/w230_agree_probes.py, tests/test_decision_effect_agreement.py |
| `decision-effect-disagreement` | decision_effect | critical | yes | evals/w230_agree_probes.py, tests/test_decision_effect_agreement.py |
| `decision-effect-effect-absent` | decision_effect | high | yes | evals/w230_agree_probes.py, tests/test_decision_effect_agreement.py |
| `decision-effect-effect-drift` | decision_effect | critical | yes | tests/test_decision_effect_agreement.py |
| `decision-effect-extra-effect` | decision_effect | critical | yes | evals/w230_agree_probes.py, tests/test_decision_effect_agreement.py |
| `decision-effect-malformed` | decision_effect | medium | yes | evals/w230_agree_probes.py, tests/test_decision_effect_agreement.py |
| `decision-effect-not-authorization` | decision_effect | high | yes | evals/w230_agree_probes.py, tests/test_decision_effect_agreement.py |
| `decision-effect-refused` | decision_effect | medium | yes | tests/test_decision_effect_agreement.py |
| `decision-effect-time-inversion` | decision_effect | medium | yes | evals/w230_agree_probes.py, tests/test_decision_effect_agreement.py |
| `decision-labels-invalid` | decision | medium | yes | evals/w225_effect_probes.py, evals/w228_codes_probes.py, tests/test_effect_status.py |
| `decision-log-equivocation` | decision-log | high | yes | evals/w250_decision_log_probes.py, tests/test_decision_log.py |
| `decision-log-malformed` | decision-log | medium | yes | evals/w250_decision_log_probes.py, tests/test_decision_log.py |
| `decision-log-proof-invalid` | decision-log | high | yes | evals/w250_decision_log_probes.py, evals/w251_redteam_probes.py, tests/test_decision_log.py |
| `decision-log-request-mismatch` | decision-log | high | yes | evals/w250_decision_log_probes.py, evals/w251_redteam_probes.py, evals/w252_redteam_probes.py (+1) |
| `decision-trace-forgery` | decision-trace | high | yes | evals/w297_redteam_probes.py, tests/test_decision_trace_f371.py |
| `decision-trace-invalid` | decision-trace | medium | yes | evals/w297_redteam_probes.py, evals/w298_redteam_probes.py, tests/test_decision_trace_f371.py |
| `decision-trace-replay-mismatch` | decision-trace | critical | yes | evals/w297_redteam_probes.py, tests/test_decision_trace_f371.py |
| `decodetrust-binding-mismatch` | evcert | high | yes | evals/w274_decode_trust_probes.py, evals/w276_f292_probes.py, tests/test_decode_trust.py |
| `decodetrust-malformed-evidence` | evcert | medium | yes | tests/test_decode_trust.py |
| `decodetrust-no-evidence` | evcert | high | yes | evals/w274_decode_trust_probes.py, evals/w275_redteam_probes.py, evals/w276_f292_probes.py (+1) |
| `decommission_refused` | recovery | medium | yes | tests/test_w77_recovery.py |
| `decoy-grant-not-issuable` | tool_grant | high | yes | evals/w277_redteam_probes.py |
| `decoy-grant-tripped` | tool_grant | critical | yes | evals/w276_decoy_probes.py, evals/w277_redteam_probes.py, tests/test_decoy_grants.py |
| `delegatee_mismatch` | approval | high | yes | evals/w26rt_probes.py, tests/test_delegation_executor_wiring.py, tests/test_delegation_primitive.py |
| `delegation-action-refused` | delegation | high | yes | evals/w265_delegation_probes.py, evals/w291_delegation_probes.py, tests/test_delegation_chain.py (+1) |
| `delegation-approval-chain-mismatch` | delegation | high | yes | evals/w300_delegation_approval_probes.py, evals/w301_redteam_probes.py, tests/test_delegation_approval.py |
| `delegation-approval-right-mismatch` | delegation | high | yes | evals/w300_delegation_approval_probes.py, evals/w301_redteam_probes.py, tests/test_delegation_approval.py |
| `delegation-attenuation-inverted` | delegation | high | yes | evals/w265_delegation_probes.py, evals/w266_redteam_probes.py, evals/w267_f249_probes.py (+4) |
| `delegation-attestation-malformed` | delegation-freshness | medium | yes | evals/w245_delegation_freshness_probes.py, tests/test_delegation_freshness.py |
| `delegation-ceremony-mismatch` | delegation | high | yes | evals/w291_delegation_probes.py, tests/test_delegation_narrowing.py |
| `delegation-chain-broken` | delegation-freshness | high | yes | evals/w245_delegation_freshness_probes.py, evals/w299_delegation_identity_probes.py, evals/w299_delegation_probes.py (+6) |
| `delegation-containment-violated` | containment | high | yes | evals/w242_containment_probes.py, tests/test_wave242_containment.py |
| `delegation-custody-splice` | delegation | high | yes | evals/w267_f249_probes.py, tests/test_delegation_custody.py |
| `delegation-decision-mismatch` | capability | critical | **NO** |  |
| `delegation-depth-exceeded` | delegation | high | yes | evals/w299_delegation_probes.py |
| `delegation-ephemeral-grant-refused` | delegation | high | yes | evals/w280_fga_probes.py, evals/w281_teleport_probes.py, tests/test_ephemeral_grants.py |
| `delegation-escrow-violated` | delegation | high | yes | evals/w299_delegation_probes.py, tests/test_delegation.py |
| `delegation-expired` | delegation | medium | yes | evals/w265_delegation_probes.py, evals/w292_delegation_decay_probes.py, evals/w293_redteam_probes.py (+10) |
| `delegation-freshness-expired` | delegation-freshness | high | yes | evals/w245_delegation_freshness_probes.py, tests/test_delegation_freshness.py |
| `delegation-identity-false-hardware-claim` | delegation-identity | high | yes | evals/w299_delegation_identity_probes.py, evals/w300_redteam_probes.py, tests/test_delegation_identity.py |
| `delegation-identity-invalid` | delegation-identity | high | yes | evals/w299_delegation_identity_probes.py, evals/w300_redteam_probes.py, tests/test_delegation_identity.py |
| `delegation-identity-unauthorized-key` | delegation-identity | high | yes | evals/w299_delegation_identity_probes.py, tests/test_delegation_compose.py, tests/test_delegation_identity.py |
| `delegation-invalid` | delegation | high | yes | evals/w299_delegation_probes.py, evals/w300_delegation_approval_probes.py, evals/w300_redteam_probes.py (+3) |
| `delegation-invocation-audience-mismatch` | delegation | high | yes | evals/w291_delegation_probes.py, tests/test_delegation_narrowing.py |
| `delegation-invocation-not-proven` | delegation | high | yes | evals/w291_delegation_probes.py, tests/test_delegation_narrowing.py |
| `delegation-lineage-overflow` | delegation | medium | yes | evals/w292_delegation_decay_probes.py, evals/w293_redteam_probes.py, tests/test_delegation_decay.py |
| `delegation-malformed` | delegation | medium | yes | evals/w265_delegation_probes.py, evals/w291_delegation_probes.py, evals/w292_delegation_decay_probes.py (+3) |
| `delegation-monotonicity-violated` | delegation-freshness | high | yes | evals/w245_delegation_freshness_probes.py, tests/test_delegation_freshness.py |
| `delegation-not-allowlisted` | capability | medium | yes | evals/capability_grant_probes.py |
| `delegation-orphaned-branch` | delegation | high | yes | evals/w292_delegation_decay_probes.py, evals/w293_redteam_probes.py, tests/test_delegation_decay.py |
| `delegation-parent-mismatch` | delegation | high | yes | evals/w265_delegation_probes.py, tests/test_delegation_chain.py |
| `delegation-pop-signature-invalid` | delegation | high | yes | evals/w291_delegation_probes.py, evals/w292_redteam_probes.py, tests/test_delegation_narrowing.py |
| `delegation-replay` | delegation | high | yes | evals/w265_delegation_probes.py, evals/w267_f249_probes.py, tests/test_delegation_chain.py (+1) |
| `delegation-retired-reuse` | delegation | high | yes | evals/w292_delegation_decay_probes.py, evals/w293_redteam_probes.py, tests/test_delegation_decay.py |
| `delegation-revocation-invalid` | delegation | high | yes | evals/w299_delegation_revoke_probes.py, evals/w300_redteam_probes.py, tests/test_delegation_revoke.py |
| `delegation-revocation-list-full` | delegation | medium | yes | evals/w299_delegation_revoke_probes.py, tests/test_delegation_revoke.py |
| `delegation-revoked` | delegation | high | yes | evals/w299_delegation_revoke_probes.py, evals/w300_delegation_approval_probes.py, evals/w300_redteam_probes.py (+7) |
| `delegation-root-exceeds-policy` | delegation | high | yes | evals/w291_delegation_probes.py, evals/w292_redteam_probes.py, tests/test_delegation_narrowing.py |
| `delegation-root-untrusted` | delegation | high | yes | evals/w265_delegation_probes.py, evals/w267_f249_probes.py, evals/w299_delegation_probes.py (+3) |
| `delegation-signature-invalid` | delegation | high | yes | evals/w265_delegation_probes.py, evals/w267_f249_probes.py, evals/w291_delegation_probes.py (+7) |
| `delegation-stale-lineage` | delegation | high | yes | evals/w292_delegation_decay_probes.py, evals/w293_redteam_probes.py, tests/test_delegation_decay.py |
| `delegation-state-mismatch` | delegation-freshness | high | yes | evals/w245_delegation_freshness_probes.py, tests/test_delegation_freshness.py |
| `delegation-ticket-expired` | delegation | medium | yes | evals/w299_delegation_tickets_probes.py |
| `delegation-ticket-invalid` | delegation | high | yes | evals/w299_delegation_tickets_probes.py, evals/w300_redteam_probes.py, tests/test_delegation_compose.py (+1) |
| `delegation-ticket-not-opted-in` | delegation | medium | yes | evals/w299_delegation_tickets_probes.py |
| `delegation-ticket-type-violated` | delegation | high | yes | evals/w299_delegation_tickets_probes.py, tests/test_delegation_compose.py, tests/test_delegation_tickets.py |
| `delegation-ttl-excessive` | delegation-freshness | medium | yes | evals/w245_delegation_freshness_probes.py, tests/test_delegation_freshness.py |
| `delegation-ttl-missing` | delegation-freshness | high | yes | evals/w245_delegation_freshness_probes.py, tests/test_delegation_freshness.py |
| `delegation-unknown-parent` | capability | medium | **NO** |  |
| `delegation-version-mismatch` | delegation | medium | yes | evals/w265_delegation_probes.py, tests/test_delegation_chain.py |
| `delegation-widened` | delegation | critical | yes | evals/w299_delegation_probes.py, tests/test_delegation.py |
| `delegation-would-widen` | capability | high | yes | evals/capability_grant_probes.py, evals/w265_delegation_probes.py, evals/w292_delegation_decay_probes.py (+2) |
| `delegation_disabled` | approval | high | yes | tests/test_approval_web_d1.py, tests/test_approvals_d1.py, tests/test_delegation_primitive.py |
| `delegation_loop` | approval | high | yes | evals/w22_probes.py, tests/test_approvals_d1.py |
| `denial-anchored-in-denied-transaction` | seeded_denial | high | yes | evals/w231_seed_probes.py, tests/test_seeded_denials.py |
| `denial-capsule-malformed` | denial | high | yes | evals/w236_denialcap_probes.py, tests/test_denial_capsule.py |
| `denial-capsule-signature-invalid` | denial | high | yes | evals/w236_denialcap_probes.py, evals/w246_jwt_alg_confusion_probes.py, tests/test_denial_capsule.py |
| `denial-disclosure-mismatch` | denial | high | yes | evals/w236_denialcap_probes.py, tests/test_denial_capsule.py |
| `denial-evidence-lost` | seeded_denial | critical | yes | evals/w231_seed_probes.py, tests/test_seeded_denials.py |
| `denial-unsealed` | denial | high | yes | evals/w236_denialcap_probes.py, tests/test_denial_capsule.py |
| `deny-receipt-malformed` | receipts | medium | yes | evals/w230_deny_probes.py, tests/test_deny_receipts.py |
| `deny-receipt-not-authorization` | receipts | high | yes | evals/w230_deny_probes.py, tests/test_deny_receipts.py |
| `deny-receipt-refused` | receipts | medium | yes | evals/w236_denialcap_probes.py, evals/w246_jwt_alg_confusion_probes.py, tests/test_denial_capsule.py |
| `deny-receipt-signature-invalid` | receipts | critical | yes | evals/w230_deny_probes.py, tests/test_deny_receipts.py |
| `deny-receipt-unavailable-as-permit` | receipts | high | yes | evals/w230_deny_probes.py, tests/test_deny_receipts.py |
| `deny_first_rules` | decision_log | medium | yes | evals/decision_diagnostics_probes.py, evals/decision_log_v2_probes.py, tests/test_decision_diagnostics.py (+1) |
| `deprecated-assertion-version` | c2pa | medium | yes | evals/w215_c2pa24_probes.py, tests/test_c2pa24_conformance.py |
| `depth_exceeded` | approval | medium | yes | tests/test_delegation_primitive.py |
| `detector-cycle` | detector | medium | yes | evals/w261_detector_probes.py, evals/w262_redteam_probes.py |
| `detector-deprecated` | detector | medium | yes | evals/w261_detector_probes.py, evals/w262_alert_probes.py |
| `detector-duplicate-name` | detector | medium | yes | evals/w261_detector_probes.py |
| `detector-exception-malformed` | detector | medium | yes | evals/w261_detector_probes.py, evals/w262_alert_probes.py |
| `detector-malformed` | detector | medium | yes | evals/w261_detector_probes.py, evals/w262_redteam_probes.py |
| `detector-unknown-maturity` | detector | medium | yes | evals/w261_detector_probes.py, evals/w262_alert_probes.py |
| `detector-unknown-predicate` | detector | medium | yes | evals/w261_detector_probes.py, evals/w262_redteam_probes.py |
| `detector-unknown-priority` | detector | medium | yes | evals/w261_detector_probes.py, evals/w262_alert_probes.py |
| `device-pin-malformed` | jail | medium | yes | evals/w220_jailinspect_probes.py, tests/test_jail_pci.py |
| `did-key-binding-invalid` | identity | high | yes | evals/w246_agent_identity_probes.py, evals/w247_redteam_probes.py, tests/test_agent_identity.py |
| `did-key-malformed` | identity | medium | yes | evals/w246_agent_identity_probes.py, tests/test_agent_identity.py |
| `did-key-method-unsupported` | identity | medium | yes | evals/w246_agent_identity_probes.py, tests/test_agent_identity.py |
| `digest-bad-input` | authorization_receipt | medium | yes | tests/test_authorization_receipts.py |
| `digest-linkage-malformed` | digest_link | medium | yes | evals/w222_digestlink_probes.py, tests/test_digest_link.py |
| `digest-linkage-mismatch` | digest_link | critical | yes | evals/w222_digestlink_probes.py, tests/test_digest_link.py |
| `digest-linkage-refused` | digest_link | medium | **NO** |  |
| `digest-malformed` | authorization_receipt | medium | yes | evals/w217_receipt_probes.py, tests/test_authorization_receipts.py |
| `digest-mismatch` | digest_link | critical | yes | evals/sign_deploy_namespace_probes.py, evals/w219_rollback_probes.py, evals/w220_lease_probes.py (+3) |
| `digest-role-mismatch` | authorization_receipt | critical | yes | evals/w217_receipt_probes.py, tests/test_authorization_receipts.py |
| `digest-role-missing` | authorization_receipt | medium | **NO** |  |
| `digest_mismatch` | load_gate | high | yes | evals/chapman_row1_coverage.py, evals/w78_probes.py, evals/w80_probes.py (+4) |
| `discipline-inhibitor-malformed` | discipline | medium | yes | evals/w265_discipline_probes.py |
| `discipline-inhibitor-unverifiable` | discipline | medium | yes | evals/w265_discipline_probes.py |
| `discipline-prompt-coalesced` | discipline | low | yes | evals/w265_discipline_probes.py |
| `discipline-prompt-inhibited` | discipline | low | yes | evals/w265_discipline_probes.py |
| `discipline-prompt-silenced` | discipline | low | yes | evals/w265_discipline_probes.py |
| `discipline-request-malformed` | discipline | medium | yes | evals/w265_discipline_probes.py |
| `discipline-silence-forbidden-class` | discipline | medium | yes | evals/w265_discipline_probes.py |
| `discipline-silence-malformed` | discipline | medium | yes | evals/w265_discipline_probes.py |
| `discipline-silence-unjournaled` | discipline | medium | yes | evals/w265_discipline_probes.py |
| `discovery-definition-drift` | discovery-scan | high | yes | evals/w282_agentscan_probes.py |
| `discovery-definition-unregistered` | discovery-scan | medium | yes | evals/w282_agentscan_probes.py |
| `discovery-emit-failed` | discovery-scan | high | yes | evals/w283_redteam_probes.py, evals/w284_f312_315_probes.py |
| `discovery-identity-mismatch` | mcp-discovery | high | yes | evals/w246_mcp_dns_discovery_probes.py, evals/w247_redteam_probes.py, tests/test_mcp_discovery_trust.py |
| `discovery-result-malformed` | mcp-discovery | medium | yes | evals/w246_mcp_dns_discovery_probes.py, evals/w283_redteam_probes.py, evals/w284_f312_315_probes.py (+1) |
| `discovery-scope-unknown` | discovery-scan | medium | yes | evals/w282_agentscan_probes.py |
| `discovery-unpinned` | mcp-discovery | high | yes | evals/w246_mcp_dns_discovery_probes.py, evals/w247_redteam_probes.py, tests/test_mcp_discovery_trust.py |
| `dispatch-without-permit` | permit | high | yes | evals/w236_permitclosure_probes.py, tests/test_permit_closure.py |
| `display-attestation-error` | display | medium | **NO** |  |
| `display-hash-mismatch` | presentation | high | yes | evals/w220_faith_probes.py, evals/w221_rendercommit_probes.py, tests/test_presentation_faith.py (+1) |
| `display-no-render-commitment` | display | medium | yes | evals/w222_display_probes.py, tests/test_display_attest.py |
| `display-policy-unknown` | display | medium | yes | evals/w222_display_probes.py, tests/test_display_attest.py |
| `display-rederivation-failed` | display | high | yes | evals/w222_display_probes.py, tests/test_display_attest.py |
| `downgrade-refused` | presentation | high | yes | evals/w220_faith_probes.py, tests/test_presentation_faith.py |
| `drift-baseline-updated` | drift | low | yes | evals/w272_driftrev_probes.py, tests/test_drift_report.py |
| `drift-detected` | drift | medium | yes | evals/w272_driftrev_probes.py, evals/w282_agentscan_probes.py, tests/test_drift_report.py |
| `drift-log-corrupt` | drift | high | yes | evals/w272_driftrev_probes.py, tests/test_drift_report.py |
| `drift-malformed` | drift | medium | yes | evals/w272_driftrev_probes.py, tests/test_drift_report.py |
| `dsse-envelope-malformed` | dsse | high | yes | evals/w232_dsse_probes.py, tests/test_decision_packet.py, tests/test_dsse_envelope.py (+1) |
| `dsse-envelope-multi-signature` | dsse | high | yes | evals/w233_dsseone_probes.py, evals/w248_dsse_envelope_probes.py, evals/w249_redteam_probes.py (+2) |
| `dsse-envelope-no-signature` | dsse | high | yes | evals/w233_dsseone_probes.py, tests/test_dsse_envelope.py, tests/test_evidence_envelope.py |
| `dsse-envelope-transplant` | dsse | high | yes | evals/w233_dsseone_probes.py, tests/test_decision_packet.py, tests/test_deny_receipts.py (+1) |
| `dsse-payload-type-refused` | dsse | high | yes | evals/w232_dsse_probes.py, tests/test_deny_receipts.py, tests/test_dsse_envelope.py |
| `dsse-payloadtype-mismatch` | dsse | high | yes | evals/w233_dsseone_probes.py, tests/test_dsse_envelope.py |
| `dsse-signature-invalid` | dsse | critical | yes | evals/w232_dsse_probes.py, evals/w233_dsseone_probes.py, evals/w248_dsse_envelope_probes.py (+4) |
| `duplicate-trust-record` | c2pa | medium | yes | evals/w215_c2pa24_probes.py, tests/test_c2pa24_conformance.py |
| `duplicate_request` | arap | medium | yes | evals/w218_arap_probes.py, tests/test_arap.py |
| `duplicate_vote` | approval | medium | yes | evals/w22_probes.py, tests/test_approvals_d1.py |
| `effect-decision-contradicted` | effect-agreement | high | yes | evals/w243_effect_agreement_probes.py, tests/test_wave243_effect_agreement.py |
| `effect-decision-missing` | effect-agreement | medium | yes | evals/w243_effect_agreement_probes.py, tests/test_wave243_effect_agreement.py |
| `effect-not-bound` | effect-agreement | high | yes | evals/w243_effect_agreement_probes.py, tests/test_wave243_effect_agreement.py |
| `effect-status-ambiguous-refused` | effect | medium | yes | evals/w225_effect_probes.py, tests/test_effect_status.py, tests/test_receipt_pairs.py |
| `effect-status-invalid` | effect | medium | yes | evals/w225_effect_probes.py, tests/test_effect_status.py |
| `effect-status-refused` | effect | medium | yes | evals/w228_codes_probes.py |
| `egress-destination-exemption-refused` | spawn-context | medium | yes | evals/w245_spawn_context_probes.py, tests/test_spawn_context_guard.py |
| `egress-injection-propagation` | egress | high | yes | evals/w245_egress_propagation_probes.py, tests/test_egress_propagation_guard.py |
| `egress-propagation-malformed` | egress | medium | yes | evals/w245_egress_propagation_probes.py, tests/test_egress_propagation_guard.py |
| `egress-ref-data-exfil` | egress | high | yes | evals/w273_egress_probes.py, evals/w274_redteam_probes.py, evals/w275_egress_close_probes.py (+6) |
| `egress-refs-malformed` | egress | medium | yes | tests/test_egress_refs.py |
| `egress-refs-oversized` | egress | medium | yes | tests/test_egress_refs.py |
| `egress-relay-exfil` | egress | high | yes | evals/w273_egress_probes.py, evals/w274_redteam_probes.py, evals/w275_egress_close_probes.py (+1) |
| `elicitation_budget_exhausted` | elicitation | medium | yes | evals/w278_approvalv2_probes.py, evals/w279_remediation_probes.py |
| `elicitation_refused` | elicitation | medium | yes | evals/w278_approvalv2_probes.py, evals/w279_remediation_probes.py, tests/test_elicitation_contract.py |
| `elicitation_secret_detected` | elicitation | high | yes | evals/w278_approvalv2_probes.py, evals/w279_remediation_probes.py |
| `empty_reason` | approval | medium | **NO** |  |
| `envelope-aad-mismatch` | envelope | high | yes | evals/w284_sops_probes.py |
| `envelope-bad-header` | envelope | medium | **NO** |  |
| `envelope-bad-sample` | envelope | medium | **NO** |  |
| `envelope-custody-unavailable` | envelope | medium | yes | evals/w284_sops_probes.py |
| `envelope-mac-failed` | envelope | high | yes | evals/w284_sops_probes.py, tests/test_bundle_envelope.py |
| `envelope-malformed` | envelope | high | yes | evals/w257_envelopes_probes.py, evals/w258_redteam_probes.py, evals/w284_sops_probes.py (+1) |
| `envelope-open-refused` | envelope | high | yes | evals/w257_envelopes_probes.py, evals/w258_redteam_probes.py, evals/w263_recipient_probes.py (+3) |
| `envelope-recipient-refused` | envelope | medium | yes | evals/w257_envelopes_probes.py, evals/w258_redteam_probes.py, tests/test_encrypted_envelopes.py |
| `envelope-recipient-unknown` | envelope | medium | yes | evals/w284_sops_probes.py, tests/test_bundle_envelope.py |
| `envelope-rekey-refused` | envelope | medium | yes | evals/w284_sops_probes.py |
| `envelope-sample-too-large` | envelope | medium | **NO** |  |
| `envelope-seal-refused` | envelope | medium | yes | evals/w257_envelopes_probes.py, evals/w284_sops_probes.py, tests/test_bundle_envelope.py (+2) |
| `envelope-signature-invalid` | envelope | high | yes | evals/w284_sops_probes.py, tests/test_bundle_envelope.py |
| `envelope-too-many-samples` | envelope | medium | **NO** |  |
| `envelope-unwrap-failed` | envelope | high | yes | evals/w284_sops_probes.py |
| `envelope-version-unknown` | envelope | high | yes | evals/w257_envelopes_probes.py, evals/w258_redteam_probes.py, tests/test_encrypted_envelopes.py |
| `escalation-action-mismatch` | escalation | critical | yes | evals/w227_escalate_probes.py, tests/test_escalation_svr.py |
| `escalation-already-bound` | escalation | medium | yes | evals/w227_escalate_probes.py, tests/test_escalation_svr.py |
| `escalation-approval-digest-mismatch` | escalation | critical | yes | evals/w227_escalate_probes.py, tests/test_escalation_svr.py |
| `escalation-bind-refused` | escalation | medium | **NO** |  |
| `escalation-malformed` | escalation | medium | yes | tests/test_escalation_svr.py |
| `escalation-not-bound` | escalation | medium | yes | evals/w227_escalate_probes.py, tests/test_escalation_svr.py |
| `evaltask-bad-dataset-id` | evidence | medium | **NO** |  |
| `evaltask-bad-sample` | evidence | medium | **NO** |  |
| `evaltask-bad-samples` | evidence | medium | **NO** |  |
| `evaltask-bad-score` | evidence | medium | yes | evals/w281_redteam_probes.py |
| `evaltask-bad-scoring-id` | evidence | medium | **NO** |  |
| `evaltask-bad-scoring-refs` | evidence | medium | **NO** |  |
| `evaltask-bad-target` | evidence | medium | **NO** |  |
| `evaltask-bad-task-id` | evidence | medium | **NO** |  |
| `evaltask-dataset-changed` | evidence | high | **NO** |  |
| `evaltask-duplicate-dataset` | evidence | medium | yes | evals/w281_redteam_probes.py, tests/test_eval_tasks.py |
| `evaltask-duplicate-scoring-function` | evidence | medium | **NO** |  |
| `evaltask-duplicate-task` | evidence | medium | **NO** |  |
| `evaltask-grader-changed` | evidence | high | **NO** |  |
| `evaltask-grader-crashed` | evidence | high | yes | tests/test_eval_tasks.py |
| `evaltask-not-json` | evidence | medium | **NO** |  |
| `evaltask-scoring-not-callable` | evidence | medium | **NO** |  |
| `evaltask-scoring-source-unavailable` | evidence | medium | **NO** |  |
| `evaltask-target-crashed` | evidence | high | **NO** |  |
| `evaltask-unknown-dataset` | evidence | medium | yes | tests/test_eval_tasks.py |
| `evaltask-unknown-scoring-function` | evidence | medium | **NO** |  |
| `evaltask-unknown-task` | evidence | medium | yes | tests/test_eval_tasks.py |
| `evaltask-unverifiable` | evidence | high | **NO** |  |
| `evaluation-incomplete-details` | evaluation | high | yes | evals/w233_evalfn_probes.py, evals/w235_boundpermit_probes.py, tests/test_bound_permit.py (+1) |
| `evaluation-input-swapped` | evaluation | critical | yes | evals/w233_evalfn_probes.py, tests/test_evaluation_function.py |
| `evaluation-key-role-conflation` | evaluation | high | yes | evals/w233_evalfn_probes.py, tests/test_evaluation_function.py |
| `evaluation-malformed` | evaluation | medium | yes | evals/w233_evalfn_probes.py, tests/test_evaluation_function.py |
| `evaluation-non-reproducible` | evaluation | critical | yes | evals/w233_evalfn_probes.py, tests/test_evaluation_function.py |
| `evaluation-not-authorization` | evaluation | high | yes | evals/w233_evalfn_probes.py, tests/test_evaluation_function.py |
| `evaluation-policy-digest-mismatch` | evaluation | high | yes | tests/test_evaluation_function.py |
| `evaluation-policy-drift` | evaluation | high | yes | evals/w233_evalfn_probes.py, tests/test_evaluation_function.py |
| `evaluation-revision-unknown` | evaluation | medium | yes | tests/test_evaluation_function.py |
| `evbundle-checkpoint-invalid` | evbundle | medium | yes | evals/w270_evbundle_probes.py, tests/test_evbundle.py |
| `evbundle-consistency-invalid` | evbundle | medium | yes | evals/w270_evbundle_probes.py, evals/w271_redteam_probes.py, tests/test_evbundle.py |
| `evbundle-contract-refused` | evbundle | medium | yes | evals/w279_sealer_probes.py, evals/w280_redteam_probes.py, evals/w281_redteam_probes.py (+1) |
| `evbundle-inclusion-unverified` | evbundle | medium | yes | evals/w270_evbundle_probes.py, evals/w271_redteam_probes.py, evals/w273_rslreplay_probes.py (+1) |
| `evbundle-issuance-unverifiable` | evbundle | high | yes | evals/w270_evbundle_probes.py, evals/w271_redteam_probes.py, tests/test_evbundle.py |
| `evbundle-join-mismatch` | evbundle | high | yes | evals/w270_evbundle_probes.py, evals/w271_redteam_probes.py, tests/test_evbundle.py |
| `evbundle-malformed` | evbundle | medium | yes | tests/test_bundle_vsa.py, tests/test_evbundle.py |
| `evbundle-transparency-unavailable` | evbundle | medium | yes | evals/w270_evbundle_probes.py, tests/test_evbundle.py |
| `evbundle-unauthorized-producer` | evbundle | high | yes | evals/w270_evbundle_probes.py, evals/w271_redteam_probes.py, tests/test_evbundle.py |
| `evcert-anchor-unavailable` | evcert | medium | yes | evals/w269_evcert_probes.py, evals/w270_redteam_probes.py, tests/test_evcert.py |
| `evcert-assertion-expired` | evcert | medium | yes | evals/w269_evcert_probes.py, tests/test_evcert.py |
| `evcert-binding-invalid` | evcert | high | yes | evals/w269_evcert_probes.py, tests/test_evbundle.py, tests/test_evcert.py |
| `evcert-cert-expired` | evcert | medium | yes | evals/w269_evcert_probes.py, tests/test_evcert.py |
| `evcert-chain-invalid` | evcert | high | yes | tests/test_evcert.py |
| `evcert-identity-not-decider` | evcert | high | yes | evals/w269_evcert_probes.py, evals/w270_redteam_probes.py, tests/test_evcert.py |
| `evcert-key-reused` | evcert | high | yes | evals/w269_evcert_probes.py, evals/w270_redteam_probes.py, tests/test_evcert.py |
| `evcert-kms-cannot-sign` | evcert | medium | yes | evals/w269_evcert_probes.py, evals/w270_redteam_probes.py, tests/test_evcert.py |
| `evcert-lifetime-exceeded` | evcert | medium | yes | evals/w269_evcert_probes.py, evals/w270_evcert_provisioner_probes.py, evals/w270_redteam_probes.py (+1) |
| `evcert-malformed-cert` | evcert | medium | yes | evals/w270_evcert_provisioner_probes.py, tests/test_evcert.py |
| `evcert-malformed-request` | evcert | medium | yes | evals/w270_evcert_provisioner_probes.py, evals/w271_redteam_probes.py, evals/w272_oidc_probes.py (+2) |
| `evcert-pop-invalid` | evcert | high | yes | evals/w269_evcert_probes.py, evals/w270_redteam_probes.py, tests/test_evcert.py |
| `evcert-provisioner-policy-violated` | evcert | medium | yes | evals/w270_evcert_provisioner_probes.py, evals/w271_redteam_probes.py, tests/test_evcert.py |
| `evcert-unknown-approval` | evcert | medium | yes | evals/w269_evcert_probes.py, evals/w270_redteam_probes.py, tests/test_evcert.py |
| `evcert-unknown-issuer` | evcert | medium | yes | evals/w269_evcert_probes.py, evals/w270_redteam_probes.py, tests/test_evcert.py |
| `evidence-bundle-hint-mismatch` | evbundle | medium | yes | evals/w329_sigb_probes.py, evals/w330_redteam_probes.py, tests/test_evidence_sigstore.py |
| `evidence-bundle-malformed` | evbundle | medium | yes | evals/w312_redteam_probes.py, evals/w313_redteam_probes.py, tests/test_evidence_sigstore.py |
| `evidence-bundle-payload-type-refused` | evbundle | medium | **NO** |  |
| `evidence-bundle-predicate-refused` | evbundle | medium | yes | tests/test_evidence_sigstore.py |
| `evidence-bundle-signature-invalid` | evbundle | medium | yes | evals/w312_redteam_probes.py, evals/w313_redteam_probes.py, evals/w330_redteam_probes.py (+1) |
| `evidence-bundle-subject-mismatch` | evbundle | medium | yes | tests/test_evidence_sigstore.py |
| `evidence-bundle-timestamp-malformed` | evbundle | medium | yes | evals/w312_redteam_probes.py, evals/w313_redteam_probes.py, tests/test_evidence_sigstore.py |
| `evidence-bundle-verification-material` | evbundle | medium | yes | evals/w329_sigb_probes.py, evals/w330_redteam_probes.py, tests/test_evidence_sigstore.py |
| `evidence-bundle-witness-checkpoint-invalid` | evbundle | medium | yes | evals/w312_witness_log_probes.py, tests/test_evidence_sigstore.py |
| `evidence-bundle-witness-expired` | evbundle | medium | yes | evals/w329_sigb_probes.py, tests/test_evidence_sigstore.py |
| `evidence-bundle-witness-inclusion-invalid` | evbundle | medium | yes | evals/w312_witness_log_probes.py, tests/test_evidence_sigstore.py |
| `evidence-bundle-witness-key-unavailable` | evbundle | medium | **NO** |  |
| `evidence-bundle-witness-missing` | evbundle | medium | yes | tests/test_evidence_sigstore.py |
| `evidence-bundle-witness-signature-invalid` | evbundle | medium | yes | evals/w329_sigb_probes.py, tests/test_evidence_sigstore.py |
| `evidence-bundle-witness-unbound` | evbundle | medium | yes | evals/w312_redteam_probes.py, evals/w313_redteam_probes.py, evals/w329_sigb_probes.py (+1) |
| `evidence-bundle-witness-unsupported` | evbundle | medium | yes | tests/test_evidence_sigstore.py |
| `evidence-envelope-record-limit` | evidence | medium | yes | evals/w248_dsse_envelope_probes.py, tests/test_evidence_envelope.py |
| `evidence-envelope-record-too-large` | evidence | medium | yes | evals/w248_dsse_envelope_probes.py, tests/test_evidence_envelope.py |
| `evidence-graph-ambiguous-link` | evidence-graph | medium | yes | evals/w250_evidence_graph_probes.py, evals/w251_redteam_probes.py, tests/test_evidence_graph.py |
| `evidence-graph-malformed` | evidence-graph | medium | yes | tests/test_evidence_graph.py |
| `evidence-graph-overflow` | evidence-graph | medium | yes | evals/w250_evidence_graph_probes.py, evals/w251_redteam_probes.py, tests/test_evidence_graph.py |
| `evidence-graph-unlinked` | evidence-graph | medium | yes | evals/w251_redteam_probes.py, tests/test_evidence_graph.py |
| `evidence-incomplete` | evidence | medium | yes | evals/w226_singleuse_probes.py, evals/w242_three_outcome_conformance_probes.py, tests/test_gate_outcomes.py (+3) |
| `evidence-pq-not-enabled` | evbundle | medium | yes | evals/w335_pqslot_probes.py, evals/w336_attack_probes.py, evals/w336_redteam_probes.py (+1) |
| `evidence-pq-unknown-alg` | evbundle | medium | yes | evals/w335_pqslot_probes.py, evals/w336_attack_probes.py, evals/w336_redteam_probes.py (+1) |
| `evidence-quality-empty-evidence` | evidence-quality | medium | yes | evals/w258_f222_probes.py, evals/w259_f226_probes.py, evals/w259_redteam_probes.py (+3) |
| `evidence-quality-evidence-malformed` | evidence-quality | medium | yes | evals/w256_evidence_quality_probes.py, evals/w257_redteam_probes.py, evals/w258_f222_probes.py (+3) |
| `evidence-quality-gate-failed` | evidence-quality | medium | yes | evals/w256_evidence_quality_probes.py, evals/w258_f222_probes.py, evals/w261_failaction_probes.py (+2) |
| `evidence-quality-malformed` | evidence-quality | medium | yes | evals/w256_evidence_quality_probes.py, evals/w258_f222_probes.py, evals/w261_failaction_probes.py (+2) |
| `evidence-quality-unknown-expectation` | evidence-quality | medium | yes | evals/w256_evidence_quality_probes.py, evals/w257_redteam_probes.py, evals/w259_f226_probes.py (+2) |
| `evidence-refused` | evidence | medium | **NO** |  |
| `evidence-unverifiable-item` | evidence | medium | yes | evals/w226_singleuse_probes.py, tests/test_single_use.py |
| `exception-baseline-drift` | exception | high | yes | evals/w285_exceptions_probes.py, tests/test_governed_exceptions.py |
| `exception-close-refused` | exception | high | yes | evals/w285_exceptions_probes.py, tests/test_governed_exceptions.py |
| `exception-compensating-validation-failed` | exception | medium | yes | evals/w268_exception_probes.py, evals/w269_redteam_probes.py, tests/test_policy_exception.py |
| `exception-declaration-invalid` | exception | medium | yes | evals/w285_exceptions_probes.py, tests/test_governed_exceptions.py |
| `exception-duplicate` | exception | low | yes | evals/w285_exceptions_probes.py, tests/test_governed_exceptions.py |
| `exception-duplicate-check` | exception | low | yes | evals/w285_exceptions_probes.py, tests/test_governed_exceptions.py |
| `exception-expired` | exception | medium | yes | evals/w268_exception_probes.py, evals/w269_redteam_probes.py, evals/w285_exceptions_probes.py (+2) |
| `exception-expiry-invalid` | exception | medium | yes | evals/w285_exceptions_probes.py |
| `exception-granted-with-attribution` | exception | low | yes | evals/w268_exception_probes.py, evals/w269_poldelta_skip_probes.py, evals/w269_redteam_probes.py (+1) |
| `exception-justification-missing` | exception | medium | yes | evals/w285_exceptions_probes.py, evals/w287_f332_probes.py |
| `exception-malformed` | exception | medium | yes | evals/w268_exception_probes.py, evals/w269_redteam_probes.py, tests/test_policy_exception.py |
| `exception-rule-skipped` | exception | low | yes | evals/w268_exception_probes.py, tests/test_policy_exception.py |
| `exception-scope-mismatch` | exception | high | yes | evals/w285_exceptions_probes.py, tests/test_governed_exceptions.py |
| `exception-unapproved-approver` | exception | high | yes | evals/w285_exceptions_probes.py, tests/test_governed_exceptions.py |
| `exception-unauthorized-authorship` | exception | high | yes | evals/w268_exception_probes.py, evals/w269_redteam_probes.py, tests/test_policy_exception.py |
| `exception-unknown-check` | exception | medium | yes | evals/w285_exceptions_probes.py, tests/test_governed_exceptions.py |
| `exception-unknown-digest` | exception | low | yes | tests/test_governed_exceptions.py |
| `expected-participant-missing` | participants | high | yes | evals/w241_probe_classes_probes.py, evals/w243_verifier_failclosed_probes.py, tests/test_wave241_probe_classes.py |
| `expected-participants-malformed` | participants | medium | yes | tests/test_wave241_probe_classes.py |
| `expected-participants-undeclared` | participants | medium | yes | tests/test_wave241_probe_classes.py |
| `expired-card` | agent_card | medium | yes | evals/w214_agentcard_probes.py, evals/w215_redteam_probes.py, tests/test_agent_cards_v1.py |
| `export-witness-bundle-mismatch` | witness | high | yes | evals/w323_exwitness_probes.py, evals/w324_redteam_probes.py |
| `export-witness-carrier-oversize` | witness | low | yes | evals/w323_exwitness_probes.py, evals/w324_redteam_probes.py, tests/test_export_witness.py |
| `export-witness-checkpoint-invalid` | witness | high | yes | evals/w323_exwitness_probes.py |
| `export-witness-malformed` | witness | medium | yes | evals/w323_exwitness_probes.py, evals/w324_redteam_probes.py, evals/w325_resid_probes.py (+1) |
| `export-witness-policy-invalid` | witness | high | yes | evals/w323_exwitness_probes.py |
| `export-witness-policy-version-below-minimum` | witness | medium | yes | evals/w325_resid_probes.py, tests/test_export_witness.py |
| `export-witness-proof-mismatch` | witness | high | yes | evals/w323_exwitness_probes.py, evals/w324_redteam_probes.py |
| `export-witness-stale` | witness | medium | yes | evals/w323_exwitness_probes.py, evals/w324_redteam_probes.py |
| `export-witness-vkey-mismatch` | witness | high | yes | evals/w323_exwitness_probes.py, evals/w324_redteam_probes.py |
| `faithfulness-error` | presentation | medium | **NO** |  |
| `federation-attestation-malformed` | federation | medium | yes | evals/w267_peerattest_probes.py, tests/test_peer_attestation.py |
| `federation-bundle-confusion` | federation | high | yes | evals/w264_federation_probes.py, tests/test_trust_federation.py |
| `federation-bundle-expired` | federation | medium | yes | evals/w264_federation_probes.py, evals/w265_redteam_probes.py, tests/test_trust_federation.py |
| `federation-bundle-malformed` | federation | medium | yes | evals/w264_federation_probes.py, tests/test_trust_federation.py |
| `federation-bundle-missing` | federation | medium | yes | evals/w264_federation_probes.py, tests/test_trust_federation.py |
| `federation-bundle-signature-invalid` | federation | high | yes | evals/w264_federation_probes.py, tests/test_trust_federation.py |
| `federation-claim-class-denied` | federation | high | yes | evals/w267_peerattest_probes.py, tests/test_peer_attestation.py |
| `federation-double-join` | federation | high | yes | evals/w267_peerattest_probes.py, evals/w268_redteam_probes.py, evals/w269_f251_probes.py (+3) |
| `federation-endpoint-unpinned` | federation | high | yes | evals/w267_peerattest_probes.py, tests/test_peer_attestation.py |
| `federation-identity-unmapped` | federation | high | yes | evals/w267_peerattest_probes.py, evals/w268_redteam_probes.py, tests/test_peer_attestation.py |
| `federation-peer-banned` | federation | high | yes | evals/w267_peerattest_probes.py, evals/w268_redteam_probes.py, evals/w269_f251_probes.py (+1) |
| `federation-possession-failed` | federation | high | yes | evals/w267_peerattest_probes.py, evals/w268_redteam_probes.py, tests/test_peer_attestation.py |
| `federation-relationship-malformed` | federation | medium | yes | evals/w264_federation_probes.py, tests/test_trust_federation.py |
| `federation-untrusted-domain` | federation | medium | yes | evals/w264_federation_probes.py, evals/w265_redteam_probes.py, evals/w267_peerattest_probes.py (+2) |
| `finding-illegal-transition` | policy | low | yes | evals/w283_defectdojo_probes.py, evals/w284_redteam_probes.py, tests/test_finding_lifecycle.py |
| `finding-sla-breached` | policy | medium | yes | evals/w283_defectdojo_probes.py, tests/test_finding_lifecycle.py |
| `gate-exception-malformed` | gate | high | yes | evals/w242_exception_ttl_probes.py, tests/test_exception_ttl.py |
| `gate-tampered` | gate | high | yes | evals/w237_gateoutcomes_probes.py, evals/w242_exception_ttl_probes.py, evals/w242_three_outcome_conformance_probes.py (+4) |
| `gate-undecidable` | gate | high | yes | evals/w237_gateoutcomes_probes.py, evals/w240_axis_result_probes.py, evals/w242_exception_ttl_probes.py (+6) |
| `gate-undecidable-allowed` | gate | high | yes | evals/w237_gateoutcomes_probes.py, tests/test_gate_outcomes.py |
| `gate-verdict-unreasoned` | gate | high | yes | evals/w237_gateoutcomes_probes.py, tests/test_gate_outcomes.py |
| `gatehard-breakglass-invalid` | gatehard | high | yes | evals/w271_gatehard_probes.py, tests/test_gate_hardening.py, tests/test_gatehard_closures_w273.py |
| `gatehard-breakglass-used` | gatehard | medium | yes | evals/w271_gatehard_probes.py, tests/test_gate_hardening.py, tests/test_gatehard_closures_w273.py |
| `gatehard-gate-error` | gatehard | high | yes | evals/w271_gatehard_probes.py, evals/w272_isolation_probes.py, evals/w273_monitor_accounting_probes.py (+5) |
| `gatehard-gate-timeout` | gatehard | high | yes | evals/w271_gatehard_probes.py, evals/w272_isolation_probes.py, evals/w273_monitor_accounting_probes.py (+1) |
| `gatehard-global-deadline-unset` | gatehard | high | yes | evals/w271_gatehard_probes.py, tests/test_gate_hardening.py |
| `gatehard-host-callback-denied` | gatehard | medium | yes | evals/w271_gatehard_probes.py, evals/w272_isolation_probes.py, evals/w273_monitor_accounting_probes.py (+2) |
| `gatehard-host-callback-wildcard` | gatehard | high | yes | evals/w271_gatehard_probes.py, tests/test_gate_hardening.py |
| `gatehard-ignore-exception-invalid` | gatehard | high | yes | evals/w271_gatehard_probes.py, tests/test_gate_hardening.py, tests/test_gatehard_closures_w273.py |
| `gatehard-ignore-exception-used` | gatehard | medium | yes | evals/w271_gatehard_probes.py, evals/w272_redteam_probes.py, tests/test_gate_hardening.py (+1) |
| `gatehard-monitor-would-deny` | gatehard | low | yes | evals/w271_gatehard_probes.py, evals/w273_monitor_accounting_probes.py, evals/w274_redteam_probes.py (+2) |
| `gatehard-per-policy-deadline-exceeds-global` | gatehard | medium | yes | evals/w271_gatehard_probes.py, tests/test_gate_hardening.py |
| `gatehard-policy-denied` | gatehard | medium | yes | evals/w271_gatehard_probes.py, evals/w272_driftrev_probes.py, evals/w272_isolation_probes.py (+6) |
| `gatehard-policy-malformed` | gatehard | medium | yes | evals/w271_gatehard_probes.py, evals/w272_redteam_probes.py, tests/test_gate_hardening.py (+1) |
| `gatehard-unknown-mode` | gatehard | high | yes | evals/w271_gatehard_probes.py, tests/test_gate_hardening.py |
| `gitspawn-config-unparseable` | gitspawn | medium | yes | evals/w226_gitsan_probes.py, tests/test_git_sanitize.py |
| `gitspawn-hostile-config` | gitspawn | medium | yes | evals/w226_gitsan_probes.py, evals/w228_codes_probes.py, evals/w244_session_trust_ordering_probes.py (+2) |
| `gitspawn-in-repo-git-refused` | gitspawn | medium | yes | evals/w226_gitsan_probes.py, tests/test_git_sanitize.py |
| `gov.capability_manifests.manifest_absent_advisory` | skill | medium | yes | evals/w219_unsafe_paths_probes.py |
| `gov.executor.capability_gate_unconfigured_refused` | deployment | medium | yes | evals/w219_unsafe_paths_probes.py |
| `gov.policy_compile.post_compile_mutation_refused` | policy | medium | yes | evals/w219_unsafe_paths_probes.py, tests/test_unsafe_paths.py |
| `grant-already-consumed` | capability | medium | yes | evals/capability_grant_probes.py, tests/test_capability_grants.py |
| `grant-attenuation-gap` | grants | high | yes | evals/w235_antiwiden_probes.py, tests/test_grant_attenuation.py |
| `grant-chain-required` | grants | high | yes | evals/w235_antiwiden_probes.py, tests/test_grant_attenuation.py |
| `grant-decision-mismatch` | capability | critical | **NO** |  |
| `grant-malformed` | authorization_receipt | medium | yes | tests/test_grant_attenuation.py |
| `grant-not-minted` | capability | medium | yes | evals/capability_grant_probes.py |
| `grant-revoked` | authorization_receipt | high | yes | evals/w217_receipt_probes.py, evals/w235_antiwiden_probes.py, tests/test_authorization_receipts.py (+1) |
| `grant-widened` | grants | high | yes | evals/w235_antiwiden_probes.py, tests/test_grant_attenuation.py |
| `grant_consumed` | approval | medium | yes | evals/w26rt_probes.py, tests/test_delegation_primitive.py |
| `grant_expired` | approval | medium | yes | tests/test_delegation_primitive.py |
| `grant_integrity_violation` | approval | critical | yes | evals/w26rt_probes.py, tests/test_delegation_primitive.py |
| `grant_revoked` | approval | medium | yes | evals/w26rt_probes.py, tests/test_delegation_primitive.py |
| `grantneg-anchor-untrusted` | grantneg | high | yes | evals/w319_grant_probes.py, tests/test_grant_negotiation.py |
| `grantneg-audience-mismatch` | grantneg | high | yes | evals/w319_grant_probes.py, evals/w320_grantwiring_probes.py, evals/w321_redteam_probes.py (+2) |
| `grantneg-chain-unverifiable` | grantneg | high | yes | evals/w319_grant_probes.py, tests/test_grant_negotiation.py |
| `grantneg-chain-widened` | grantneg | high | yes | evals/w319_grant_probes.py, tests/test_grant_negotiation.py |
| `grantneg-expired` | grantneg | medium | yes | evals/w319_grant_probes.py, evals/w320_grantwiring_probes.py, evals/w321_redteam_probes.py (+2) |
| `grantneg-malformed` | grantneg | medium | yes | evals/w319_grant_probes.py, tests/test_grant_negotiation.py |
| `grantneg-product-of-fields` | grantneg | high | yes | evals/w319_grant_probes.py, tests/test_grant_negotiation.py |
| `grantneg-registry-withdrawn` | grantneg | high | **NO** |  |
| `grantneg-scope-mismatch` | grantneg | high | yes | evals/w319_grant_probes.py, evals/w320_grantwiring_probes.py, evals/w320_redteam_probes.py (+3) |
| `grantneg-widening-refused` | grantneg | medium | yes | evals/w319_grant_probes.py, tests/test_grant_negotiation.py |
| `guac-graph-ambiguous-link` | guac-graph | medium | yes | tests/test_guac_graph.py |
| `guac-graph-bad-spec` | guac-graph | low | yes | evals/w284_guac_probes.py, tests/test_guac_graph.py |
| `guac-graph-claim-conflict` | guac-graph | medium | yes | evals/w284_guac_probes.py, tests/test_guac_graph.py |
| `guac-graph-envelope-refused` | guac-graph | medium | yes | evals/w284_guac_probes.py, tests/test_guac_graph.py |
| `guac-graph-malformed` | guac-graph | medium | yes | evals/w284_guac_probes.py, tests/test_guac_graph.py |
| `guac-graph-overflow` | guac-graph | medium | yes | evals/w284_guac_probes.py, tests/test_guac_graph.py |
| `guac-graph-unlinked` | guac-graph | medium | yes | evals/w284_guac_probes.py, tests/test_guac_graph.py |
| `guardplugin-bad-hook` | guardplugin | low | yes | evals/w281_portkey_probes.py, tests/test_guard_plugins.py |
| `guardplugin-bad-id` | guardplugin | low | yes | tests/test_guard_plugins.py |
| `guardplugin-bad-params` | guardplugin | low | yes | evals/w281_portkey_probes.py, tests/test_guard_plugins.py |
| `guardplugin-bad-run` | guardplugin | low | yes | tests/test_guard_plugins.py |
| `guardplugin-bad-transform` | guardplugin | high | yes | tests/test_guard_plugins.py |
| `guardplugin-bad-verdict` | guardplugin | high | yes | tests/test_guard_plugins.py |
| `guardplugin-denied` | guardplugin | medium | yes | tests/test_guard_plugins.py |
| `guardplugin-duplicate-id` | guardplugin | low | yes | evals/w281_portkey_probes.py, tests/test_guard_plugins.py |
| `guardplugin-error-refused` | guardplugin | high | yes | evals/w283_f311_probes.py, tests/test_guard_plugins.py |
| `guardplugin-unknown-id` | guardplugin | medium | yes | evals/w281_portkey_probes.py, tests/test_guard_plugins.py |
| `guest-budget-amplified` | guest-budget | high | yes | evals/w244_guest_host_budget_probes.py, tests/test_guest_budget_guard.py |
| `guest-budget-deadline-fired` | guest-budget | high | yes | evals/w244_guest_host_budget_probes.py, tests/test_guest_budget_guard.py |
| `guest-budget-envelope-malformed` | guest-budget | medium | yes | evals/w244_guest_host_budget_probes.py, tests/test_guest_budget_guard.py |
| `guest-budget-scope-undeclared` | guest-budget | medium | yes | evals/w244_guest_host_budget_probes.py, tests/test_guest_budget_guard.py |
| `halt_refused` | recovery | medium | yes | evals/w77_probes.py, tests/test_w77_recovery.py |
| `handle-not-authority` | handle | high | yes | evals/w218_arap_probes.py, tests/test_arap.py |
| `handle-unknown` | handle | medium | yes | evals/w218_arap_probes.py, tests/test_arap.py |
| `handoff-invalid` | deploy | medium | yes | tests/test_deploy_trust_config.py |
| `harness_config_digest_mismatch` | capability | medium | yes | evals/capgate_break.py, tests/test_capgate_wiring.py |
| `harness_id_mismatch` | capability | high | yes | tests/test_capgate_wiring.py |
| `helper_not_configured` | platform | medium | yes | tests/test_s7_egress_launcher.py |
| `honest-claim-reserved-token` | honest_claims | high | yes | evals/w233_nonclaims_probes.py, tests/test_honest_claims.py |
| `honesty-baseline-tampered` | honesty | high | yes | evals/w240_forcing_honesty_probes.py, tests/test_forcing_honesty.py |
| `honesty-baseline-unforced` | honesty | high | yes | evals/w240_forcing_honesty_probes.py, tests/test_forcing_honesty.py |
| `honesty-condition-silent` | honesty | medium | yes | evals/w240_forcing_honesty_probes.py, tests/test_forcing_honesty.py |
| `honesty-mutant-inconclusive` | honesty | low | yes | evals/w240_forcing_honesty_probes.py, evals/w338_deadctrl_probes.py, tests/test_forcing_honesty.py |
| `honesty-mutant-invalid` | honesty | low | yes | evals/w240_forcing_honesty_probes.py, tests/test_forcing_honesty.py |
| `honesty-tautology-suspect` | honesty | low | yes | evals/w240_forcing_honesty_probes.py, tests/test_forcing_honesty.py |
| `hop_token_refs` | delegation | medium | **NO** |  |
| `hostid-hostname-digest-not-identity` | hostid | high | yes | evals/w241_host_identity_probes.py, tests/test_host_identity.py |
| `hostid-hostname-not-identity` | hostid | high | yes | evals/w241_host_identity_probes.py, tests/test_host_identity.py |
| `hostid-id-file-corrupt` | hostid | high | yes | evals/w241_host_identity_probes.py, tests/test_host_identity.py |
| `hostid-malformed-identity` | hostid | medium | yes | evals/w241_host_identity_probes.py, tests/test_host_identity.py |
| `hostid-symlink-at-id-path` | hostid | critical | yes | evals/w241_host_identity_probes.py, tests/test_host_identity.py |
| `hybrid-classical-fallback-refused` | hybrid_gate | high | yes | evals/w228_hybrid_probes.py |
| `hybrid-entry-mismatch` | hybrid_gate | high | yes | evals/w228_hybrid_probes.py, tests/test_hybrid_gate.py |
| `hybrid-gate-malformed` | hybrid_gate | medium | yes | tests/test_hybrid_gate.py |
| `hybrid-gate-not-authorization` | hybrid_gate | low | yes | evals/w228_hybrid_probes.py, tests/test_hybrid_gate.py |
| `hybrid-gate-refused` | hybrid_gate | medium | **NO** |  |
| `hybrid-incomplete` | hybrid_gate | medium | yes | evals/w228_hybrid_probes.py |
| `hybrid-leg-failed` | key_identity | medium | yes | evals/w227_keys_probes.py, evals/w228_hybrid_probes.py, tests/test_hybrid_gate.py (+1) |
| `hybrid-leg-invalid` | key_identity | medium | yes | evals/w227_keys_probes.py, tests/test_hybrid_gate.py, tests/test_key_identity.py |
| `hybrid-policy-tampered` | hybrid_gate | critical | yes | evals/w228_hybrid_probes.py |
| `hybrid-suite-not-accepted` | hybrid_gate | high | yes | evals/w228_hybrid_probes.py, evals/w231_seed_probes.py, tests/test_hybrid_gate.py (+1) |
| `identity-anchor-unknown` | attested-identity | high | yes | evals/w246_attested_identity_probes.py, tests/test_identity_crosscheck.py |
| `identity-attestation-malformed` | attested-identity | medium | yes | evals/w246_attested_identity_probes.py, tests/test_identity_crosscheck.py |
| `identity-attestation-unverifiable` | attested-identity | high | yes | evals/w246_attested_identity_probes.py, evals/w247_redteam_probes.py, tests/test_identity_crosscheck.py |
| `identity-attested` | attested-identity | low | yes | evals/w319_identity_probes.py, tests/test_workload_identity.py |
| `identity-audience-mismatch` | attested-identity | high | yes | evals/w319_identity_probes.py, evals/w320_redteam_probes.py, tests/test_workload_identity.py |
| `identity-claim-mismatch` | attested-identity | high | yes | evals/w246_attested_identity_probes.py, evals/w247_redteam_probes.py, tests/test_identity_crosscheck.py |
| `identity-claims-ambiguous` | identity | high | yes | evals/w248_dex_identity_probes.py, tests/test_dex_identity.py |
| `identity-claims-malformed` | identity | medium | yes | tests/test_dex_identity.py |
| `identity-claims-missing-subject` | identity | high | yes | evals/w248_dex_identity_probes.py, tests/test_dex_identity.py |
| `identity-connector-unsupported` | identity | high | yes | evals/w248_dex_identity_probes.py, tests/test_dex_identity.py |
| `identity-expired` | attested-identity | medium | yes | evals/w319_identity_probes.py, evals/w320_redteam_probes.py, tests/test_workload_identity.py |
| `identity-forged` | attested-identity | high | yes | evals/w319_identity_probes.py, evals/w320_redteam_probes.py, tests/test_workload_identity.py |
| `identity-issuer-key-retired` | identity | medium | yes | evals/w325_dexid_probes.py, evals/w326_redteam_probes.py, tests/test_federated_identity.py |
| `identity-mint-refused` | attested-identity | medium | yes | evals/w319_identity_probes.py, tests/test_workload_identity.py |
| `identity-mismatch` | agent_card | critical | yes | evals/a2a_card_verifier_probes.py, evals/w214_agentcard_probes.py, evals/w215_redteam_probes.py (+1) |
| `identity-not-yet-valid` | attested-identity | medium | yes | evals/w319_identity_probes.py, tests/test_workload_identity.py |
| `identity-policy-refused` | namespace | medium | yes | evals/w215_identity_policy_probes.py |
| `identity-refresh-expired` | identity | medium | yes | tests/test_dex_identity.py |
| `identity-refresh-lock-unavailable` | identity | medium | yes | evals/w335_rtlock_probes.py, evals/w336_attack_probes.py, evals/w336_redteam_probes.py (+2) |
| `identity-refresh-reuse-detected` | identity | high | yes | evals/w248_dex_identity_probes.py, evals/w249_redteam_probes.py, evals/w335_rtlock_probes.py (+4) |
| `identity-refresh-revoked` | identity | high | yes | evals/w248_dex_identity_probes.py, evals/w249_redteam_probes.py, evals/w335_rtlock_probes.py (+1) |
| `identity-refresh-unknown` | identity | medium | yes | tests/test_dex_identity.py |
| `identity-selector-mismatch` | attested-identity | high | yes | evals/w319_identity_probes.py, evals/w320_redteam_probes.py, tests/test_workload_identity.py |
| `identity-token-audience-mismatch` | identity | high | yes | evals/w248_dex_identity_probes.py, evals/w325_dexid_probes.py, evals/w326_redteam_probes.py (+2) |
| `identity-token-expired` | identity | medium | yes | evals/w248_dex_identity_probes.py, evals/w325_dexid_probes.py, evals/w326_redteam_probes.py (+2) |
| `identity-token-issuer-unknown` | identity | high | yes | evals/w325_dexid_probes.py, evals/w326_redteam_probes.py, tests/test_federated_identity.py |
| `identity-token-key-binding-mismatch` | identity | high | yes | evals/w325_dexid_probes.py, evals/w326_redteam_probes.py, tests/test_federated_identity.py |
| `identity-token-malformed` | identity | medium | yes | evals/w325_dexid_probes.py, tests/test_dex_identity.py, tests/test_federated_identity.py |
| `identity-token-not-yet-valid` | identity | high | yes | evals/w325_dexid_probes.py, tests/test_dex_identity.py, tests/test_federated_identity.py |
| `identity-token-replayed` | identity | high | yes | evals/w325_dexid_probes.py, evals/w326_redteam_probes.py, tests/test_federated_identity.py |
| `identity-token-required` | identity | medium | yes | evals/w325_dexid_probes.py, evals/w326_redteam_probes.py, tests/test_federated_identity.py |
| `identity-token-tampered` | identity | high | yes | evals/w248_dex_identity_probes.py, evals/w249_redteam_probes.py, evals/w325_dexid_probes.py (+3) |
| `identity-token-ttl-exceeded` | identity | medium | yes | evals/w325_dexid_probes.py, evals/w326_redteam_probes.py, tests/test_federated_identity.py |
| `identity-untrusted-domain` | attested-identity | high | yes | evals/w319_identity_probes.py, evals/w320_redteam_probes.py, tests/test_workload_identity.py |
| `identity_key_of` | detection | medium | **NO** |  |
| `ifc-audit-required` | ifc | medium | yes | evals/w268_ifc_probes.py, evals/w269_redteam_probes.py, evals/w270_f252_probes.py (+1) |
| `ifc-grant-unissued` | ifc | high | yes | evals/w270_f252_probes.py, evals/w271_redteam_probes.py, evals/w272_redteam_probes.py (+1) |
| `ifc-integrity-flow-denied` | ifc | high | yes | evals/w268_ifc_probes.py, evals/w270_f252_probes.py, tests/test_output_ifc.py |
| `ifc-label-malformed` | ifc | medium | yes | evals/w268_ifc_probes.py, evals/w269_redteam_probes.py, evals/w270_f252_probes.py (+2) |
| `ifc-privilege-denied` | ifc | high | yes | evals/w268_ifc_probes.py, evals/w269_redteam_probes.py, tests/test_output_ifc.py |
| `ifc-privilege-expired` | ifc | medium | yes | evals/w268_ifc_probes.py, evals/w269_redteam_probes.py, evals/w270_f252_probes.py (+1) |
| `ifc-privilege-scope-denied` | ifc | high | yes | evals/w268_ifc_probes.py, evals/w269_redteam_probes.py, evals/w270_f252_probes.py (+1) |
| `ifc-privilege-unauthorized` | ifc | high | yes | evals/w268_ifc_probes.py, evals/w269_redteam_probes.py, evals/w270_f252_probes.py (+2) |
| `ifc-registry-corrupt` | ifc | high | yes | evals/w270_f252_probes.py, tests/test_ifc_grants.py |
| `ifc-secrecy-flow-denied` | ifc | high | yes | evals/w268_ifc_probes.py, evals/w269_redteam_probes.py, tests/test_output_ifc.py |
| `ifc-sink-unmapped` | ifc | medium | yes | evals/w268_ifc_probes.py, tests/test_output_ifc.py |
| `imgscreen-instruction-detected` | imgscreen | high | yes | evals/w269_imgscreen_probes.py, evals/w270_redteam_probes.py, evals/w271_imgtext_probes.py (+1) |
| `imgscreen-malformed` | imgscreen | medium | yes | evals/w269_imgscreen_probes.py, evals/w270_redteam_probes.py, tests/test_image_screen.py |
| `imgscreen-oversized` | imgscreen | medium | yes | evals/w269_imgscreen_probes.py, evals/w270_redteam_probes.py, tests/test_image_screen.py |
| `imgscreen-stego-suspect` | imgscreen | low | yes | evals/w269_imgscreen_probes.py |
| `imgtext-extraction-failed` | imgtext | medium | yes | evals/w271_imgtext_probes.py, tests/test_image_text.py |
| `imgtext-malformed` | imgtext | medium | yes | evals/w271_imgtext_probes.py, tests/test_image_text.py |
| `imgtext-oversized` | imgtext | medium | yes | evals/w271_imgtext_probes.py, tests/test_image_text.py |
| `imgtext-reassembled-instruction-detected` | imgtext | high | yes | evals/w271_imgtext_probes.py, evals/w274_rail_probes.py, evals/w275_redteam_probes.py (+7) |
| `incident-gpai9-final-overdue` | incident | medium | yes | evals/w334_gpai9_probes.py, evals/w335_redteam_probes.py |
| `incident-gpai9-incomplete` | incident | medium | yes | evals/w334_gpai9_probes.py, evals/w335_attack_probes.py, evals/w335_redteam_probes.py |
| `incident-gpai9-initial-overdue` | incident | medium | yes | evals/w334_gpai9_probes.py, evals/w335_redteam_probes.py |
| `incident-gpai9-intermediate-overdue` | incident | medium | yes | evals/w334_gpai9_probes.py, evals/w335_redteam_probes.py |
| `incident-gpai9-malformed` | incident | medium | yes | evals/w334_gpai9_probes.py, evals/w335_redteam_probes.py |
| `incident-gpai9-retention-violation` | incident | medium | yes | evals/w334_gpai9_probes.py, evals/w335_redteam_probes.py |
| `incident-illegal-transition` | incident | medium | yes | evals/w253_incident_probes.py, evals/w255_f216_closure_probes.py, evals/w256_redteam_probes.py (+1) |
| `incident-malformed` | incident | medium | yes | evals/w253_incident_probes.py, tests/test_incident.py |
| `incident-open-findings` | incident | medium | yes | evals/w253_incident_probes.py, evals/w254_redteam_probes.py, evals/w255_f216_closure_probes.py (+1) |
| `incident-open-tasks` | incident | medium | yes | evals/w253_incident_probes.py, evals/w254_redteam_probes.py, evals/w255_f216_closure_probes.py (+1) |
| `incident-premature-postmortem` | incident | medium | yes | evals/w253_incident_probes.py, tests/test_incident.py |
| `incident-unknown` | incident | medium | yes | evals/w253_incident_probes.py, evals/w256_redteam_probes.py, tests/test_incident.py |
| `inclusion-receipt-malformed` | receipt | high | yes | evals/w286_receipts_probes.py, tests/test_evidence_receipt.py |
| `ingest-admit` | ingest | low | yes | evals/w272_ingest_probes.py, tests/test_evidence_ingest_gate.py |
| `ingest-freshness-invalid` | ingest | high | yes | evals/w272_ingest_probes.py, tests/test_evidence_ingest_gate.py |
| `ingest-issuance-unverifiable` | ingest | high | yes | evals/w272_ingest_probes.py |
| `ingest-malformed` | ingest | medium | yes | evals/w272_ingest_probes.py, tests/test_evidence_ingest_gate.py |
| `ingest-producer-unauthorized` | ingest | critical | yes | evals/w272_ingest_probes.py |
| `ingest-revision-unbound` | ingest | high | yes | evals/w272_ingest_probes.py, tests/test_evidence_ingest_gate.py |
| `ingest-scan-error` | ingest | high | yes | evals/w272_ingest_probes.py |
| `ingest-signature-unverified` | ingest | critical | yes | evals/w272_ingest_probes.py |
| `ingest-stale-revision` | ingest | high | yes | evals/w272_ingest_probes.py |
| `input_closure_digest` | provenance | medium | **NO** |  |
| `inspection-failed` | inspection | medium | yes | evals/w220_jailinspect_probes.py, tests/test_admission.py, tests/test_jail_pci.py |
| `inspection-link-unverifiable` | inspection | medium | yes | evals/w220_jailinspect_probes.py, tests/test_jail_pci.py |
| `inspection-malformed` | inspection | medium | yes | tests/test_jail_pci.py |
| `inspection-script-digest-mismatch` | inspection | critical | yes | evals/w220_jailinspect_probes.py, tests/test_jail_pci.py |
| `instruction-provenance-public-channel` | egress | high | yes | evals/w245_egress_propagation_probes.py, tests/test_egress_propagation_guard.py |
| `instruction-provenance-untrusted` | egress | medium | yes | tests/test_egress_propagation_guard.py |
| `insufficient_data` | evidence | medium | yes | evals/s4eval_battery.py, tests/test_drift.py, tests/test_drift_budget.py (+2) |
| `integrity_violation` | sweep | critical | **NO** |  |
| `invalid-signature` | agent_card | high | yes | evals/a2a_card_verifier_probes.py, evals/w214_agentcard_probes.py, tests/test_agent_cards_v1.py |
| `invalid_target` | approval | medium | **NO** |  |
| `inventory-catalog-card-malformed` | inventory-catalog | low | yes | evals/w255_inventory_probes.py, tests/test_inventory_catalog.py |
| `inventory-catalog-dangling-reference` | inventory-catalog | medium | yes | evals/w255_inventory_probes.py, tests/test_inventory_catalog.py |
| `inventory-catalog-duplicate-entry` | inventory-catalog | low | yes | evals/w255_inventory_probes.py, tests/test_inventory_catalog.py |
| `inventory-catalog-entry-malformed` | inventory-catalog | low | yes | evals/w255_inventory_probes.py, tests/test_inventory_catalog.py |
| `inventory-catalog-grant-unresolved` | inventory-catalog | medium | yes | evals/w255_inventory_probes.py, tests/test_inventory_catalog.py |
| `inventory-catalog-seam-unavailable` | inventory-catalog | medium | yes | evals/w255_inventory_probes.py, tests/test_inventory_catalog.py |
| `inventory-catalog-unknown-entry` | inventory-catalog | low | yes | evals/w255_inventory_probes.py, tests/test_inventory_catalog.py |
| `inventory-identity-collision` | inventory-query | medium | **NO** |  |
| `inventory-pack-drift` | inventory-query | high | yes | evals/w283_osquery_probes.py, tests/test_inventory_query.py |
| `inventory-pack-unpinned` | inventory-query | high | yes | tests/test_inventory_query.py |
| `inventory-provider-failed` | inventory-query | medium | yes | evals/w284_redteam_probes.py, tests/test_inventory_query.py |
| `inventory-row-malformed` | inventory-query | low | yes | tests/test_inventory_query.py |
| `inventory-schema-mismatch` | inventory-query | medium | yes | tests/test_inventory_query.py |
| `inventory-unregistered` | inventory-query | medium | yes | evals/w283_osquery_probes.py, tests/test_inventory_query.py |
| `invocation-malformed` | jail | medium | yes | tests/test_jail_policy.py |
| `invocation-network-request-refused` | jail | medium | yes | evals/w216_jail_policy_probes.py |
| `invocation-timeout-exceeds-policy` | jail | medium | yes | evals/w216_jail_policy_probes.py |
| `invocation-writable-dir-mismatch` | jail | critical | yes | evals/w216_jail_policy_probes.py, tests/test_jail_policy.py |
| `ip_not_found` | platform | medium | yes | tests/test_s7_egress_launcher.py |
| `issuance-monitor-misissuance` | issuance | high | yes | evals/w292_revocation_probes.py, evals/w293_redteam_probes.py, evals/w293_sweep_probes.py (+2) |
| `issuer-malformed` | authorization_receipt | medium | **NO** |  |
| `issuer-not-allowlisted` | scitt | medium | yes | tests/test_scitt_receipt.py |
| `jku-not-allowed` | capability | high | **NO** |  |
| `jwks-issuer-unpinned` | jwks | medium | yes | evals/w245_jwks_fetch_probes.py, tests/test_jwks_fetch.py |
| `jwks-origin-mismatch` | jwks | high | yes | evals/w245_jwks_fetch_probes.py, tests/test_jwks_fetch.py |
| `jwks-redirect-refused` | jwks | high | yes | evals/w245_jwks_fetch_probes.py, tests/test_jwks_fetch.py |
| `jwks-transport-failed` | jwks | medium | yes | evals/w245_jwks_fetch_probes.py, tests/test_jwks_fetch.py |
| `jwks-url-malformed` | jwks | medium | yes | evals/w245_jwks_fetch_probes.py, tests/test_jwks_fetch.py |
| `keep_evidence_types` | vc | medium | **NO** |  |
| `keep_subject_fields` | vc | medium | **NO** |  |
| `key-identity-malformed` | key_identity | medium | yes | tests/test_key_identity.py |
| `key-identity-refused` | key_identity | medium | **NO** |  |
| `key-identity-revoked` | key_identity | high | yes | evals/w227_keys_probes.py, evals/w228_codes_probes.py, tests/test_hybrid_gate.py (+1) |
| `key-identity-unknown` | key_identity | medium | yes | evals/w227_keys_probes.py, tests/test_key_identity.py |
| `key-identity-unregistered` | key_identity | medium | yes | evals/w227_keys_probes.py, tests/test_key_identity.py |
| `key-in-agent-process` | attested-channel | high | yes | evals/w243_attested_channel_probes.py, tests/test_attested_channel.py |
| `key-swap-refused` | authorization_receipt | critical | yes | evals/w217_receipt_probes.py, tests/test_authorization_receipts.py |
| `keygroup-malformed` | envelope | high | yes | evals/w259_keygroups_probes.py, tests/test_key_groups.py |
| `keygroup-open-refused` | envelope | high | yes | evals/w259_keygroups_probes.py, evals/w260_redteam_probes.py, tests/test_key_groups.py |
| `keygroup-scope-mismatch` | envelope | medium | yes | evals/w259_keygroups_probes.py, tests/test_key_groups.py |
| `keygroup-seal-refused` | envelope | medium | yes | evals/w259_keygroups_probes.py, tests/test_key_groups.py |
| `keygroup-unknown-key-id` | envelope | medium | yes | evals/w259_keygroups_probes.py, tests/test_key_groups.py |
| `keygroup-version-unknown` | envelope | high | yes | evals/w259_keygroups_probes.py, tests/test_key_groups.py |
| `keyset-bad-template` | kms | low | yes | evals/w284_tink_probes.py, tests/test_kms_keyset.py |
| `keyset-ceremony-incomplete` | kms | medium | yes | evals/w284_tink_probes.py, tests/test_kms_keyset.py |
| `keyset-duplicate-key` | kms | medium | yes | tests/test_kms_keyset.py |
| `keyset-key-destroyed` | kms | high | yes | evals/w284_tink_probes.py, tests/test_kms_keyset.py |
| `keyset-key-disabled` | kms | medium | yes | evals/w284_tink_probes.py, tests/test_kms_keyset.py |
| `keyset-pin-key-invalid` | kms | low | yes | evals/w286_f329_f330_probes.py, tests/test_kms_keyset.py |
| `keyset-primary-not-enabled` | kms | high | yes | evals/w284_tink_probes.py, tests/test_kms_keyset.py |
| `keyset-unknown-key` | kms | medium | yes | tests/test_kms_keyset.py |
| `keyset-verify-failed` | kms | medium | yes | tests/test_kms_keyset.py |
| `keysuccession-invalid-transition` | keysuccession | high | yes | evals/w293_key_succession_probes.py, tests/test_key_succession.py |
| `keysuccession-phase-skipped` | keysuccession | high | yes | evals/w293_key_succession_probes.py, tests/test_key_succession.py |
| `keysuccession-retired-reuse` | keysuccession | high | yes | evals/w293_key_succession_probes.py, tests/test_key_succession.py |
| `keysuccession-window-missing` | keysuccession | high | yes | evals/w293_key_succession_probes.py, evals/w295_f366_probes.py, tests/test_key_succession.py |
| `kid-ambiguity` | agent_card | high | yes | evals/a2a_card_verifier_probes.py, evals/w214_agentcard_probes.py, evals/w215_redteam_probes.py |
| `kms-signer-algorithm-refused` | kms | medium | yes | evals/w226_kms_probes.py, tests/test_kms_signer.py |
| `kms-signer-keyref-invalid` | kms | medium | yes | tests/test_kms_signer.py |
| `kms-signer-message-too-large` | kms | medium | yes | evals/w226_kms_probes.py, tests/test_kms_signer.py |
| `kms-signer-refused` | kms | medium | yes | tests/test_kms_signer.py |
| `lease_expired` | lease | medium | yes | evals/w78_probes.py, tests/test_decision_codes.py, tests/test_w78_supplychain.py |
| `lease_missing` | lease | medium | yes | evals/w78_probes.py, tests/test_w78_supplychain.py |
| `lease_not_yet_valid` | lease | medium | **NO** |  |
| `lease_revoked` | lease | medium | yes | tests/test_w78_supplychain.py |
| `lineage-gap` | evaluation | high | yes | evals/w243_outcome_vocabulary_probes.py, tests/test_outcome_vocabulary.py |
| `lock_unavailable` | platform | medium | yes | evals/s7egress_break.py |
| `make_link_record` | quorum | medium | **NO** |  |
| `malformed-card` | agent_card | medium | yes | evals/a2a_card_verifier_probes.py, evals/w214_agentcard_probes.py, tests/test_agent_cards_v1.py |
| `malformed-context` | mcp | medium | **NO** |  |
| `malformed-message` | mcp | medium | **NO** |  |
| `malformed-permit` | mcp | medium | **NO** |  |
| `malformed-signature-entry` | signature | high | **NO** |  |
| `malformed-statement` | scitt | medium | yes | tests/test_scitt_receipt.py |
| `malformed_binding` | deployment | medium | **NO** |  |
| `malformed_lease` | lease | medium | **NO** |  |
| `mandate-constraint-exceeded` | mandate | high | yes | evals/w264_mandate_probes.py, evals/w265_redteam_probes.py |
| `mandate-expired` | mandate | medium | yes | evals/w264_mandate_probes.py, evals/w265_redteam_probes.py |
| `mandate-malformed` | mandate | medium | yes | evals/w264_mandate_probes.py |
| `mandate-replay` | mandate | high | yes | evals/w264_mandate_probes.py, evals/w265_redteam_probes.py |
| `mandate-tampered` | mandate | high | yes | evals/w264_mandate_probes.py, evals/w265_redteam_probes.py |
| `mandate-unknown` | mandate | medium | yes | evals/w264_mandate_probes.py, evals/w265_redteam_probes.py |
| `mandate-version-mismatch` | mandate | medium | yes | evals/w264_mandate_probes.py |
| `manifest-downgrade-refused` | manifest | high | yes | evals/w219_rollback_probes.py, tests/test_version_manifest.py |
| `manifest-refused` | manifest | medium | yes | evals/w219_rollback_probes.py, tests/test_version_manifest.py |
| `manifest-regex-unsafe` | manifest | low | yes | evals/w286_f325_probes.py |
| `manifest-selection-invalid` | manifest | low | yes | evals/w284_nuclei_probes.py, tests/test_attack_manifest.py |
| `manifest-signature-invalid` | manifest | high | yes | evals/w284_nuclei_probes.py, tests/test_attack_manifest.py |
| `manifest-template-malformed` | manifest | low | yes | evals/w284_nuclei_probes.py, tests/test_attack_manifest.py |
| `manifest-template-unsigned` | manifest | medium | yes | evals/w284_nuclei_probes.py, tests/test_attack_manifest.py |
| `mapping-drift` | mcp | critical | **NO** |  |
| `max_hops_exceeded` | approval | medium | yes | evals/w22_probes.py, tests/test_approvals_d1.py |
| `mcp-oauth-binding-tampered` | mcp-oauth | high | yes | evals/w245_mcp_oauth_binding_probes.py, evals/w332_mcpoauth_probes.py, evals/w334_prm_probes.py (+1) |
| `mcp-oauth-cimd-binding-mismatch` | mcp-oauth | high | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-credential-present` | mcp-oauth | critical | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-document-malformed` | mcp-oauth | high | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-fetch-non200` | mcp-oauth | high | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-fetch-redirect` | mcp-oauth | high | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-fetch-ssrf-range` | mcp-oauth | critical | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-fetch-timeout` | mcp-oauth | medium | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-fetch-too-large` | mcp-oauth | medium | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-redirect-origin-mismatch` | mcp-oauth | high | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-url-dot-segment` | mcp-oauth | high | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-url-fragment` | mcp-oauth | medium | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-url-not-https` | mcp-oauth | high | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-url-query` | mcp-oauth | medium | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-url-root-path` | mcp-oauth | medium | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-cimd-url-userinfo` | mcp-oauth | high | yes | evals/w339_covgap1_probes.py |
| `mcp-oauth-credential-misbound` | mcp-oauth | high | yes | evals/w245_mcp_oauth_binding_probes.py, tests/test_mcp_oauth_binding.py |
| `mcp-oauth-fix-gap-refused` | mcp-oauth | high | yes | evals/w245_mcp_oauth_binding_probes.py, tests/test_mcp_oauth_binding.py |
| `mcp-oauth-iss-mismatched` | mcp-oauth | high | yes | evals/w331_redteam_probes.py, evals/w332_mcpoauth_probes.py, tests/test_mcp_oauth_binding.py |
| `mcp-oauth-iss-missing` | mcp-oauth | high | yes | evals/w331_redteam_probes.py, evals/w332_mcpoauth_probes.py, tests/test_mcp_oauth_binding.py |
| `mcp-oauth-issuer-unbound` | mcp-oauth | high | yes | evals/w245_mcp_oauth_binding_probes.py, tests/test_mcp_oauth_binding.py |
| `mcp-oauth-issuer-unverified` | mcp-oauth | high | yes | evals/w245_mcp_oauth_binding_probes.py, tests/test_mcp_oauth_binding.py |
| `mcp-oauth-key-missing` | mcp-oauth | medium | yes | tests/test_mcp_oauth_binding.py |
| `mcp-oauth-metadata-malformed` | mcp-oauth | medium | yes | evals/w245_mcp_oauth_binding_probes.py, evals/w334_prm_probes.py, evals/w334_redteam_probes.py (+3) |
| `mcp-oauth-prm-challenge-malformed` | mcp-oauth | medium | yes | evals/w334_prm_probes.py, evals/w335_attack_probes.py, evals/w335_redteam_probes.py |
| `mcp-oauth-prm-cross-origin` | mcp-oauth | high | yes | evals/w334_prm_probes.py, evals/w335_redteam_probes.py |
| `mcp-oauth-prm-fetch-refused` | mcp-oauth | medium | yes | evals/w334_prm_probes.py, evals/w335_redteam_probes.py |
| `mcp-oauth-prm-issuer-unlisted` | mcp-oauth | high | yes | evals/w334_prm_probes.py, evals/w335_attack_probes.py, evals/w335_redteam_probes.py |
| `mcp-oauth-prm-malformed` | mcp-oauth | medium | yes | evals/w334_prm_probes.py, evals/w335_redteam_probes.py, evals/w336_attack_probes.py (+2) |
| `mcp-oauth-prm-resource-mismatched` | mcp-oauth | high | yes | evals/w334_prm_probes.py, evals/w335_attack_probes.py, evals/w335_redteam_probes.py |
| `mcp-oauth-resource-misbound` | mcp-oauth | high | yes | evals/w331_redteam_probes.py, evals/w332_mcpoauth_probes.py, tests/test_mcp_oauth_binding.py |
| `mcp-oauth-resource-missing` | mcp-oauth | high | yes | evals/w331_redteam_probes.py, evals/w332_mcpoauth_probes.py, tests/test_mcp_oauth_binding.py |
| `mcp-oauth-verdict-mismatched` | mcp-oauth | medium | yes | evals/w245_mcp_oauth_binding_probes.py, tests/test_mcp_oauth_binding.py |
| `mcp-server-auth-insufficient-scope` | mcp-server-auth | medium | yes | evals/w335_redteam_probes.py |
| `mcp-server-auth-issuer-mismatched` | mcp-server-auth | high | yes | evals/w335_redteam_probes.py |
| `mcp-server-auth-issuer-missing` | mcp-server-auth | high | yes | evals/w335_redteam_probes.py |
| `mcp-server-auth-malformed` | mcp-server-auth | medium | yes | evals/w335_redteam_probes.py |
| `mcp-server-auth-missing-token` | mcp-server-auth | medium | yes | evals/w335_redteam_probes.py |
| `mcp-server-auth-resource-misbound` | mcp-server-auth | high | yes | evals/w334_mcpsrvauthz_probes.py, evals/w335_attack_probes.py, evals/w335_redteam_probes.py (+1) |
| `mcp-server-auth-resource-missing` | mcp-server-auth | high | yes | evals/w335_redteam_probes.py |
| `mcp-server-auth-token-expired` | mcp-server-auth | medium | yes | evals/w335_redteam_probes.py |
| `mcp-server-auth-token-in-query` | mcp-server-auth | medium | yes | evals/w335_redteam_probes.py |
| `mcp-server-auth-token-invalid` | mcp-server-auth | high | yes | evals/w335_attack_probes.py, evals/w335_redteam_probes.py |
| `mcp-server-auth-token-not-yet-valid` | mcp-server-auth | medium | yes | evals/w335_redteam_probes.py |
| `measurement-mismatch` | measurement | critical | yes | evals/w214_measurement_policy_probes.py, evals/w215_redteam_probes.py |
| `measurement-missing` | measurement | medium | yes | evals/w214_measurement_policy_probes.py |
| `measurement-unlisted` | measurement | medium | yes | evals/w214_measurement_policy_probes.py |
| `memory-composed-divergent` | memory_composed | critical | yes | evals/w300_memory_composed_probes.py, evals/w301_redteam_probes.py, tests/test_memory_composed.py |
| `memory-composed-key-invalid` | memory_composed | high | **NO** |  |
| `memory-composed-key-too-long` | memory_composed | high | yes | evals/w300_memory_composed_probes.py, tests/test_memory_composed.py |
| `memory-reconcile-conflict-unresolved` | memory_reconcile | medium | yes | evals/w298_memory_reconcile_probes.py, evals/w299_redteam_probes.py, tests/test_memory_reconcile.py |
| `memory-reconcile-invalid` | memory_reconcile | high | yes | evals/w298_memory_reconcile_probes.py, evals/w299_redteam_probes.py, evals/w300_memory_composed_probes.py (+3) |
| `memory-reconcile-poison-refused` | memory_reconcile | critical | yes | evals/w298_memory_reconcile_probes.py, tests/test_memory_reconcile.py |
| `memory-reconcile-scope-missing` | memory_reconcile | high | yes | evals/w298_memory_reconcile_probes.py, evals/w299_redteam_probes.py, tests/test_memory_reconcile.py |
| `memory-reconcile-unauthorized-namespace` | memory_reconcile | high | yes | evals/w298_memory_reconcile_probes.py, evals/w299_redteam_probes.py, evals/w300_memory_composed_probes.py (+3) |
| `memory-store-expired` | memory_store | medium | yes | evals/w298_memory_store_probes.py, evals/w300_memory_composed_probes.py, evals/w301_redteam_probes.py (+1) |
| `memory-store-invalid` | memory_store | high | yes | evals/w298_memory_store_probes.py, evals/w299_redteam_probes.py, evals/w301_redteam_probes.py |
| `memory-store-retention-lapsed` | memory_store | medium | yes | evals/w298_memory_store_probes.py, evals/w300_memory_composed_probes.py, tests/test_memory_composed.py |
| `memory-store-tombstoned` | memory_store | medium | yes | evals/w298_memory_store_probes.py, evals/w299_redteam_probes.py |
| `memory-store-unsigned-retraction` | memory_store | high | yes | evals/w298_memory_store_probes.py, evals/w299_redteam_probes.py |
| `mesh-auth-envelope-missing` | mesh-auth | medium | yes | evals/w263_meshauth_probes.py, tests/test_mesh_auth.py |
| `mesh-auth-escalation-bypass` | mesh-auth | high | yes | evals/w263_meshauth_probes.py, tests/test_mesh_auth.py |
| `mesh-auth-malformed` | mesh-auth | medium | yes | evals/w263_meshauth_probes.py, tests/test_mesh_auth.py |
| `mesh-auth-not-owner` | mesh-auth | high | yes | evals/w264_redteam_probes.py, evals/w265_f245f246f247_probes.py, tests/test_mesh_auth.py |
| `mesh-auth-scheme-confusion` | mesh-auth | high | yes | evals/w263_meshauth_probes.py, tests/test_mesh_auth.py |
| `mesh-auth-scope-uncovered` | mesh-auth | medium | yes | evals/w263_meshauth_probes.py, tests/test_mesh_auth.py |
| `mesh-auth-subject-mismatch` | mesh-auth | high | yes | evals/w263_meshauth_probes.py, evals/w265_f245f246f247_probes.py, tests/test_mesh_auth.py |
| `mesh-auth-task-paused` | mesh-auth | medium | yes | evals/w263_meshauth_probes.py, tests/test_mesh_auth.py |
| `mesh-auth-undeclared-scheme` | mesh-auth | high | yes | evals/w263_meshauth_probes.py, tests/test_mesh_auth.py |
| `missing-digest` | authorization_receipt | medium | yes | evals/w217_receipt_probes.py |
| `missing-signatures` | signature | medium | yes | evals/a2a_card_verifier_probes.py, evals/w215_redteam_probes.py, tests/test_capability_manifests.py |
| `missing-skill-id` | capability | medium | **NO** |  |
| `mission-binding-mismatch` | presentation | critical | yes | evals/w220_faith_probes.py, tests/test_presentation_faith.py |
| `namespace_admission_refused` | load_gate | medium | yes | evals/admit_deploy_wiring_probes.py, tests/test_admit_deploy_wiring.py |
| `never_registered` | sweep | medium | yes | tests/test_scoped_tool_listing.py |
| `no-active-pack` | pack | medium | yes | tests/test_pack_lint.py |
| `no-effect-asserted-and-ignored` | permit | medium | yes | evals/w242_no_effect_branch_probes.py, tests/test_no_effect_branch.py |
| `no-trust-config` | deploy | medium | yes | evals/deploy_trust_probes.py |
| `no_ack` | deployment | medium | yes | tests/test_w85_legacy_seam.py |
| `no_amplification_oracle` | approval | medium | yes | tests/test_delegation_primitive.py |
| `no_binding_no_ack` | deployment | medium | yes | evals/w219_unsafe_paths_probes.py, tests/test_capgate_wiring.py |
| `no_common_algorithm` | platform | high | yes | evals/s7egress_break.py |
| `no_drift_store` | deployment | medium | yes | tests/test_drift.py |
| `no_framing_store` | deployment | medium | **NO** |  |
| `no_resolved_target` | deployment | medium | **NO** |  |
| `non_delegable_power` | approval | high | yes | tests/test_delegation_primitive.py |
| `not-yet-valid` | agent_card | medium | yes | evals/w214_agentcard_probes.py, tests/test_agent_cards_v1.py |
| `not_eligible` | approval | medium | yes | evals/w22_probes.py, tests/test_approval_web_d1.py, tests/test_approvals_d1.py |
| `not_parent_delegatee` | approval | high | yes | tests/test_delegation_primitive.py |
| `not_pending` | approval | medium | yes | tests/test_approvals_d1.py |
| `not_quorum` | approval | medium | yes | tests/test_approvals_d1.py |
| `obligation-malformed` | obligation | medium | yes | tests/test_wave241_probe_classes.py |
| `obligation-unfulfilled` | obligation | high | yes | evals/w241_probe_classes_probes.py, tests/test_wave241_probe_classes.py |
| `oci-artifact-type-mismatch` | oci | medium | yes | evals/w321_oci_probes.py, evals/w322_redteam_probes.py, tests/test_oci_distribution.py |
| `oci-blob-digest-mismatch` | oci | critical | yes | evals/w321_oci_probes.py, evals/w322_redteam_probes.py, evals/w338_oci_probes.py (+2) |
| `oci-bundle-not-verifiable` | oci | medium | yes | evals/w338_oci_probes.py, evals/w339_verifiable_probes.py |
| `oci-layer-media-type-mismatch` | oci | medium | yes | evals/w338_oci_probes.py, tests/test_oci_referrer.py |
| `oci-manifest-malformed` | oci | medium | yes | evals/w322_redteam_probes.py, tests/test_oci_distribution.py |
| `oci-referrers-malformed` | oci | low | yes | evals/w322_redteam_probes.py, evals/w323_redteam_probes.py, evals/w324_redteam_probes.py (+2) |
| `oci-referrers-unavailable` | oci | medium | yes | evals/w321_oci_probes.py, evals/w324_redteam_probes.py, evals/w338_oci_probes.py (+2) |
| `oci-registry-onboarding-refused` | oci | medium | yes | evals/w338_oci_probes.py, evals/w339_oci_gate_probes.py |
| `oci-subject-mismatch` | oci | high | yes | evals/w321_oci_probes.py, evals/w322_redteam_probes.py, evals/w338_oci_probes.py (+3) |
| `oci-tag-refused` | oci | medium | yes | evals/w338_oci_probes.py, tests/test_oci_referrer.py |
| `offline-verify-anchor-invalid` | witness | high | yes | evals/w324_offver_probes.py, evals/w325_redteam_probes.py |
| `offline-verify-anchor-key-mismatch` | witness | high | yes | evals/w324_offver_probes.py, evals/w325_redteam_probes.py |
| `offline-verify-anchor-unsupported` | witness | medium | **NO** |  |
| `offline-verify-bundle-digest-mismatch` | witness | high | yes | evals/w324_offver_probes.py, evals/w325_redteam_probes.py |
| `offline-verify-chain-broken` | witness | high | yes | evals/w324_offver_probes.py |
| `offline-verify-containment` | witness | high | yes | evals/w324_offver_probes.py |
| `offline-verify-entry-signature-invalid` | witness | high | yes | evals/w324_offver_probes.py |
| `offline-verify-internal` | witness | medium | **NO** |  |
| `offline-verify-malformed` | witness | medium | yes | evals/w324_offver_probes.py, tests/test_offline_verify.py |
| `offline-verify-monotonicity` | witness | high | yes | evals/w324_offver_probes.py |
| `offline-verify-policy-window` | witness | high | yes | evals/w324_offver_probes.py, evals/w325_redteam_probes.py |
| `offline-verify-redaction-undisclosed` | witness | high | yes | evals/w324_offver_probes.py, evals/w325_redteam_probes.py |
| `offline-verify-trust-root-invalid` | witness | medium | yes | evals/w324_offver_probes.py, evals/w325_resid_probes.py, tests/test_offline_verify.py |
| `offline-verify-version-skew` | witness | medium | yes | evals/w324_offver_probes.py, tests/test_offline_verify.py |
| `offline-verify-witness-layer-invalid` | witness | high | yes | evals/w324_offver_probes.py, evals/w325_redteam_probes.py, evals/w325_resid_probes.py |
| `offline-verify-witness-layer-missing` | witness | medium | yes | evals/w324_offver_probes.py, evals/w325_redteam_probes.py |
| `oidc-ambiguous-subject` | oidc | high | yes | evals/w272_oidc_probes.py, tests/test_oidc_gate.py |
| `oidc-audience-mismatch` | oidc | high | yes | evals/w272_oidc_probes.py, tests/test_oidc_gate.py |
| `oidc-issuer-mismatch` | oidc | high | yes | evals/w215_identity_policy_probes.py, evals/w272_oidc_probes.py, tests/test_identity_policy.py (+2) |
| `oidc-malformed-token` | oidc | medium | yes | evals/w272_oidc_probes.py, tests/test_oidc_gate.py |
| `oidc-missing-claim` | oidc | medium | yes | evals/w272_oidc_probes.py, tests/test_oidc_gate.py |
| `oidc-signature-invalid` | oidc | high | yes | evals/w272_oidc_probes.py, tests/test_oidc_gate.py |
| `oidc-token-expired` | oidc | medium | yes | evals/w272_oidc_probes.py, tests/test_oidc_gate.py |
| `oidc-token-required` | oidc | medium | yes | evals/w272_oidc_probes.py, tests/test_oidc_gate.py |
| `opt-out-consumed` | deploy | medium | yes | tests/test_deploy_trust_config.py |
| `opt-out-quorum-unmet` | deploy | medium | yes | evals/deploy_trust_probes.py, tests/test_deploy_trust_config.py |
| `opt-out-self-ack` | deploy | medium | yes | evals/deploy_trust_probes.py |
| `opt-out-unknown-proposal` | deploy | medium | yes | tests/test_deploy_trust_config.py |
| `oracle-could-not-evaluate` | oracle | medium | yes | tests/test_refusal_oracle_guard.py |
| `oracle-evaluated-and-refused` | oracle | medium | yes | tests/test_refusal_oracle_guard.py |
| `oracle-verifier-misconfigured` | oracle | high | yes | tests/test_refusal_oracle_guard.py |
| `outside_sandbox` | deployment | medium | **NO** |  |
| `pack-expired` | pack | medium | yes | tests/test_audit_detect.py |
| `pack-invalid` | audit | medium | yes | evals/sigma_detection_probes.py |
| `pack-lint-failed` | pack | medium | yes | evals/pack_lint_probes.py, tests/test_pack_lint.py |
| `package-advisory-flagged` | advisory | high | yes | evals/w244_treeship_advisory_probes.py, tests/test_advisory_binding.py, tests/test_residual_hardening_w328.py |
| `package-digest-first-seen-mismatch` | registry-acceptance | critical | yes | evals/w245_registry_adversary_probes.py, tests/test_registry_adversary.py |
| `package-digest-mismatch` | registry-acceptance | critical | yes | evals/w243_threat_model_probes.py, evals/w244_treeship_advisory_probes.py, tests/test_wave243_effect_agreement.py |
| `package-identity-name-untrusted` | registry-acceptance | high | yes | evals/w245_registry_adversary_probes.py, tests/test_registry_adversary.py |
| `package-manifest-malformed` | registry-acceptance | medium | yes | tests/test_wave243_effect_agreement.py |
| `package-signature-invalid` | registry-acceptance | high | yes | evals/w243_threat_model_probes.py, evals/w244_treeship_advisory_probes.py, evals/w245_registry_adversary_probes.py (+2) |
| `package-signer-compromised` | registry-acceptance | critical | yes | evals/w245_registry_adversary_probes.py, tests/test_registry_adversary.py |
| `package-stale` | registry-acceptance | medium | yes | evals/w243_threat_model_probes.py, tests/test_wave243_effect_agreement.py |
| `parameter-malformed` | parameter | medium | yes | tests/test_wave241_probe_classes.py |
| `parameter-obfuscation` | parameter | high | yes | evals/w241_probe_classes_probes.py, tests/test_wave241_probe_classes.py |
| `pass-vacuous` | identity | low | yes | evals/w215_identity_policy_probes.py, tests/test_identity_policy.py, tests/test_policy_compile.py |
| `pci-allowlist-widening-refused` | jail | high | yes | evals/w220_jailinspect_probes.py, tests/test_jail_pci.py |
| `pci-attach-refused` | jail | medium | yes | evals/w220_jailinspect_probes.py, tests/test_jail_pci.py |
| `pci-attach-request-malformed` | jail | medium | yes | tests/test_jail_pci.py |
| `pending-approval-resume-refused` | approval | medium | yes | evals/w281_langgraph_probes.py, tests/test_pending_approvals.py |
| `pending-approval-snapshot-tampered` | approval | critical | yes | evals/w281_langgraph_probes.py, tests/test_pending_approvals.py |
| `permit-binding-mismatch` | permit | high | yes | evals/w236_permitclosure_probes.py, tests/test_permit_closure.py |
| `permit-consume-store-not-durable` | permit | high | yes | evals/w240_boundpermit_followthrough_probes.py, tests/test_bound_permit.py |
| `permit-consume-store-unavailable` | permit | high | yes | evals/w240_boundpermit_followthrough_probes.py, tests/test_bound_permit.py |
| `permit-containment-malformed` | containment | medium | yes | tests/test_wave242_containment.py |
| `permit-currentness-could-not-check` | containment | medium | yes | evals/w242_containment_probes.py, tests/test_wave242_containment.py |
| `permit-currentness-violated` | permit | medium | yes | evals/w243_action_bound_permits_probes.py, tests/test_action_bound_permits.py |
| `permit-decision-absent` | permit | high | yes | tests/test_bound_permit.py |
| `permit-digest-mismatch` | permit | critical | yes | evals/w220_lease_probes.py, evals/w221_rendercommit_probes.py, evals/w222_display_probes.py (+3) |
| `permit-downgrade-refused` | permit | high | yes | evals/w220_lease_probes.py, tests/test_permit_leases.py |
| `permit-expired` | permit | medium | yes | evals/w220_lease_probes.py, tests/test_permit_leases.py |
| `permit-idempotency-conflict` | permit | high | yes | evals/w240_boundpermit_followthrough_probes.py, evals/w301_idempotency_probes.py, evals/w302_redteam_probes.py (+6) |
| `permit-in-progress` | permit | medium | yes | evals/w240_boundpermit_followthrough_probes.py, tests/test_bound_permit.py |
| `permit-instance-replay` | permit | high | yes | evals/w243_action_bound_permits_probes.py, tests/test_action_bound_permits.py |
| `permit-journal-chain-broken` | permit-journal | high | yes | evals/w250_permit_journal_probes.py, evals/w251_redteam_probes.py, tests/test_permit_journal.py |
| `permit-journal-corrupted` | permit-journal | high | yes | evals/w250_permit_journal_probes.py, tests/test_permit_journal.py |
| `permit-journal-duplicate-event` | permit-journal | medium | yes | evals/w250_permit_journal_probes.py, evals/w251_redteam_probes.py, tests/test_permit_journal.py |
| `permit-journal-key-weak` | permit-journal | medium | yes | evals/w250_permit_journal_probes.py, tests/test_permit_journal.py |
| `permit-journal-misuse` | permit-journal | medium | yes | evals/w253_f214_f215_closure_probes.py, evals/w254_compliance_probes.py, evals/w254_redteam_probes.py (+4) |
| `permit-journal-snapshot-tampered` | permit-journal | high | yes | evals/w250_permit_journal_probes.py, evals/w251_redteam_probes.py, tests/test_permit_journal.py |
| `permit-journal-transition-illegal` | permit-journal | medium | yes | evals/w250_permit_journal_probes.py, evals/w251_redteam_probes.py, tests/test_permit_journal.py |
| `permit-journal-unknown-permit` | permit-journal | medium | yes | evals/w250_permit_journal_probes.py, tests/test_permit_journal.py |
| `permit-journal-write-conflict` | permit-journal | medium | yes | tests/test_permit_journal.py |
| `permit-jti-duplicate` | permit | high | yes | evals/w235_boundpermit_probes.py, evals/w240_boundpermit_followthrough_probes.py, tests/test_bound_permit.py |
| `permit-leg-refusal-unmapped` | permit | high | yes | tests/test_bound_permit.py |
| `permit-malformed` | permit | medium | yes | evals/w240_boundpermit_followthrough_probes.py, evals/w242_no_effect_branch_probes.py, evals/w243_action_bound_permits_probes.py (+4) |
| `permit-mandate-absent` | permit | high | yes | evals/w235_boundpermit_probes.py, tests/test_bound_permit.py |
| `permit-message-mismatch` | mcp | critical | yes | evals/w243_threat_model_probes.py |
| `permit-no-effect-unattested` | permit | medium | yes | evals/w240_boundpermit_followthrough_probes.py, evals/w242_no_effect_branch_probes.py, tests/test_bound_permit.py (+1) |
| `permit-no-fallback` | permit | high | yes | evals/w240_boundpermit_followthrough_probes.py, tests/test_bound_permit.py |
| `permit-parent-named` | containment | high | yes | evals/w242_containment_probes.py, tests/test_wave242_containment.py |
| `permit-policy-absent` | permit | high | yes | evals/w235_boundpermit_probes.py, tests/test_bound_permit.py |
| `permit-presenter-mismatch` | permit | high | yes | evals/w243_action_bound_permits_probes.py, tests/test_action_bound_permits.py |
| `permit-rate-budget-unreleasable` | permit | medium | yes | evals/w240_boundpermit_followthrough_probes.py, tests/test_bound_permit.py |
| `permit-refusal-vocabulary-invalid` | permit | medium | yes | evals/w243_action_bound_permits_probes.py, tests/test_action_bound_permits.py |
| `permit-refused` | permit | medium | **NO** |  |
| `permit-registry-unavailable` | permit | high | yes | evals/w240_boundpermit_followthrough_probes.py, tests/test_bound_permit.py |
| `permit-reused` | permit | high | yes | evals/w220_faith_probes.py, evals/w220_lease_probes.py, tests/test_absence_revocation.py (+3) |
| `permit-revoked` | permit | high | yes | evals/w222_revoke_probes.py, evals/w223_set_probes.py, evals/w224_capsule_probes.py (+9) |
| `permit-tampered` | permit | high | yes | evals/w235_boundpermit_probes.py, evals/w236_permitclosure_probes.py, evals/w240_boundpermit_followthrough_probes.py (+4) |
| `permit-unknown` | permit | medium | yes | evals/w220_lease_probes.py, tests/test_permit_leases.py |
| `persistence-modification-refused` | spawn-context | high | yes | evals/w245_spawn_context_probes.py, tests/test_spawn_context_guard.py |
| `pin-scope-insufficient` | advisory | medium | yes | evals/w244_treeship_advisory_probes.py, tests/test_advisory_binding.py |
| `pin_authorship_invalid` | platform | high | yes | evals/f138_break.py, evals/f138_closure.py, evals/f81launcher_privileged.py (+7) |
| `pin_chain_broken` | platform | high | yes | evals/f138_closure.py, tests/test_s7_egress_launcher.py |
| `pin_expired` | load_gate | medium | yes | evals/tuf_load_seam_probes.py, tests/test_w194_tuf_load_seam.py |
| `pin_version_not_monotonic` | load_gate | medium | yes | evals/tuf_load_seam_probes.py, tests/test_w194_tuf_load_seam.py |
| `plan-policy-capability` | workflow | high | yes | evals/w313_plancheck_probes.py, evals/w314_redteam_probes.py, tests/test_plan_policy.py |
| `plan-policy-data-flow` | workflow | high | yes | evals/w313_plancheck_probes.py, evals/w314_redteam_probes.py, tests/test_plan_policy.py |
| `plan-policy-manifest-missing` | workflow | medium | yes | evals/w314_redteam_probes.py, tests/test_plan_policy.py |
| `plan-policy-not-admitted` | workflow | high | yes | evals/w313_plancheck_probes.py, evals/w314_redteam_probes.py, tests/test_plan_policy.py |
| `plan-policy-trust-mixing` | workflow | high | yes | evals/w313_plancheck_probes.py, evals/w314_redteam_probes.py, tests/test_plan_policy.py |
| `plan-policy-unknown-tool` | workflow | medium | yes | evals/w313_plancheck_probes.py, evals/w314_redteam_probes.py, tests/test_plan_policy.py |
| `poldist-bundle-malformed` | poldist | medium | yes | evals/w260_poldist_probes.py, evals/w262_poldist2_probes.py, tests/test_policy_distribution.py |
| `poldist-signature-mismatch` | poldist | high | yes | evals/w260_poldist_probes.py, evals/w261_redteam_probes.py, evals/w262_poldist2_probes.py (+1) |
| `poldist-signature-missing` | poldist | high | yes | evals/w260_poldist_probes.py, tests/test_policy_distribution.py |
| `poldist-topic-cross` | poldist | medium | yes | evals/w260_poldist_probes.py, evals/w261_redteam_probes.py, tests/test_policy_distribution.py |
| `poldist-version-rollback` | poldist | high | yes | evals/w260_poldist_probes.py, evals/w261_redteam_probes.py, tests/test_policy_distribution.py |
| `policy-authoring-compile-refused` | policy-authoring | medium | yes | tests/test_policy_authoring.py |
| `policy-authoring-conflicting-filters` | policy-authoring | medium | yes | evals/w253_authoring_probes.py, tests/test_policy_authoring.py |
| `policy-authoring-empty` | policy-authoring | medium | yes | tests/test_policy_authoring.py |
| `policy-authoring-malformed` | policy-authoring | medium | yes | tests/test_policy_authoring.py |
| `policy-authoring-unknown-action` | policy-authoring | medium | yes | evals/w253_authoring_probes.py, tests/test_policy_authoring.py |
| `policy-authoring-unknown-filter` | policy-authoring | medium | yes | evals/w253_authoring_probes.py, evals/w254_redteam_probes.py, tests/test_policy_authoring.py |
| `policy-authoring-unknown-op` | policy-authoring | medium | yes | evals/w253_authoring_probes.py, tests/test_policy_authoring.py |
| `policy-body-malformed` | policy | medium | yes | evals/w214_measurement_policy_probes.py, evals/w216_jail_policy_probes.py, tests/test_jail_policy.py (+1) |
| `policy-boundary-exceeded` | policy | high | yes | evals/w266_policyprove_probes.py, evals/w267_poldelta_probes.py, evals/w267_redteam_probes.py (+1) |
| `policy-change-capability-expansion` | policy | high | yes | evals/w266_policyprove_probes.py, tests/test_policy_change_containment.py |
| `policy-change-credential-reach-expansion` | policy | high | yes | evals/w266_policyprove_probes.py, evals/w267_poldelta_probes.py, tests/test_policy_change_containment.py |
| `policy-change-l7-bypass-credentialed` | policy | high | yes | evals/w266_policyprove_probes.py, evals/w267_poldelta_probes.py, tests/test_policy_change_containment.py |
| `policy-change-link-local-reach` | policy | high | yes | evals/w266_policyprove_probes.py, evals/w267_poldelta_probes.py, tests/test_policy_change_containment.py |
| `policy-change-malformed` | policy | medium | yes | evals/w266_policyprove_probes.py, tests/test_policy_change_containment.py |
| `policy-change-uncheckable` | policy | medium | yes | evals/w266_policyprove_probes.py, evals/w267_redteam_probes.py, tests/test_policy_change_containment.py |
| `policy-channel-activation-failed` | policy | medium | yes | evals/w327_polchan_probes.py, tests/test_policy_channel.py |
| `policy-channel-feed-escape` | policy | high | yes | evals/w327_polchan_probes.py, evals/w328_redteam_probes.py, tests/test_policy_channel.py |
| `policy-channel-malformed` | policy | medium | yes | evals/w327_polchan_probes.py, evals/w328_redteam_probes.py, evals/w332_redteam_probes.py (+1) |
| `policy-channel-rollback` | policy | high | yes | evals/w327_polchan_probes.py, evals/w328_redteam_probes.py, tests/test_policy_channel.py |
| `policy-channel-stale` | policy | medium | yes | evals/w327_polchan_probes.py, tests/test_policy_channel.py |
| `policy-channel-superseded` | policy | high | yes | evals/w327_polchan_probes.py, tests/test_policy_channel.py |
| `policy-channel-unknown-policy` | policy | medium | yes | evals/w327_polchan_probes.py, tests/test_policy_channel.py |
| `policy-channel-unsigned` | policy | high | yes | evals/w327_polchan_probes.py, evals/w328_redteam_probes.py, tests/test_policy_channel.py |
| `policy-channel-version-skip` | policy | high | yes | evals/w327_polchan_probes.py, evals/w328_redteam_probes.py, tests/test_policy_channel.py |
| `policy-ci-companion-missing` | policy | medium | yes | evals/w297_policy_ci_probes.py, tests/test_policy_ci.py |
| `policy-ci-derived-tampered` | policy | high | yes | evals/w297_policy_ci_probes.py, evals/w298_redteam_probes.py, tests/test_policy_ci.py |
| `policy-ci-dryrun-skipped` | policy | high | yes | evals/w297_policy_ci_probes.py, evals/w298_redteam_probes.py, tests/test_policy_ci.py |
| `policy-ci-invalid` | policy | medium | yes | evals/w297_policy_ci_probes.py, evals/w298_redteam_probes.py, tests/test_policy_ci.py |
| `policy-compile-refused` | policy | medium | yes | evals/w219_regcompile_probes.py, tests/test_policy_registration_compile.py |
| `policy-delta-allow-modified` | policy-delta | medium | yes | evals/w247_redteam_probes.py, tests/test_policy_delta_gate.py |
| `policy-delta-allow-unforbidden` | policy-delta | medium | yes | evals/w246_policy_delta_probes.py, tests/test_policy_delta_gate.py |
| `policy-delta-check-removed` | policy-delta | medium | yes | tests/test_policy_delta_gate.py |
| `policy-delta-counterexample-raised` | policy-delta | medium | yes | evals/w267_poldelta_probes.py, tests/test_policy_delta.py |
| `policy-delta-default-deny` | policy-delta | medium | yes | evals/w268_redteam_probes.py, evals/w269_poldelta_skip_probes.py, tests/test_policy_delta.py |
| `policy-delta-effect-weakened` | policy-delta | high | yes | evals/w246_policy_delta_probes.py, evals/w247_redteam_probes.py, tests/test_policy_delta_gate.py |
| `policy-delta-evaluation-error` | policy-delta | medium | **NO** |  |
| `policy-delta-forbid` | policy-delta | high | yes | evals/w268_redteam_probes.py, evals/w269_poldelta_skip_probes.py, evals/w270_redteam_probes.py (+1) |
| `policy-delta-forbid-modified` | policy-delta | medium | yes | tests/test_policy_delta_gate.py |
| `policy-delta-forbid-narrowed` | policy-delta | high | yes | evals/w246_policy_delta_probes.py, tests/test_policy_delta_gate.py |
| `policy-delta-forbid-removed` | policy-delta | high | yes | evals/w246_policy_delta_probes.py, evals/w247_redteam_probes.py, tests/test_policy_delta_gate.py |
| `policy-delta-forbid-residual` | policy-delta | high | yes | evals/w267_poldelta_probes.py, evals/w268_redteam_probes.py, evals/w269_poldelta_skip_probes.py (+1) |
| `policy-delta-malformed` | policy-delta | high | yes | evals/w246_policy_delta_probes.py, evals/w267_poldelta_probes.py, evals/w269_poldelta_skip_probes.py (+3) |
| `policy-delta-role-added` | policy-delta | medium | yes | tests/test_policy_delta_gate.py |
| `policy-delta-section-changed` | policy-delta | medium | yes | tests/test_policy_delta_gate.py |
| `policy-delta-unknown` | policy-delta | medium | yes | evals/w267_poldelta_probes.py, tests/test_policy_delta.py |
| `policy-delta-widening` | policy-delta | high | yes | evals/w246_policy_delta_probes.py, evals/w247_redteam_probes.py, tests/test_policy_delta_gate.py |
| `policy-envelope-malformed` | jail | medium | **NO** |  |
| `policy-expired` | manifest | medium | yes | evals/w219_rollback_probes.py, tests/test_version_manifest.py |
| `policy-harness-malformed` | policy-harness | medium | yes | evals/w251_harness_probes.py, tests/test_policy_harness.py |
| `policy-harness-missing-expected` | policy-harness | medium | yes | evals/w251_harness_probes.py, tests/test_policy_harness.py |
| `policy-harness-no-policies` | policy-harness | medium | yes | tests/test_policy_harness.py |
| `policy-harness-unknown-format` | policy-harness | medium | yes | tests/test_policy_harness.py |
| `policy-needs-unimplemented-feature` | jail | medium | yes | evals/w216_jail_policy_probes.py, tests/test_jail_policy.py, tests/test_policy_registration_compile.py |
| `policy-signature-invalid` | signature | high | yes | evals/w214_measurement_policy_probes.py, evals/w215_redteam_probes.py, evals/w216_jail_policy_probes.py (+2) |
| `policy-stale` | policy | medium | yes | evals/w214_measurement_policy_probes.py, evals/w215_redteam_probes.py, evals/w216_jail_policy_probes.py (+3) |
| `policy-unknown` | policy | medium | yes | evals/w214_measurement_policy_probes.py, evals/w215_redteam_probes.py, evals/w216_jail_policy_probes.py (+4) |
| `policy-version-downgrade` | jail | high | yes | evals/w214_measurement_policy_probes.py, evals/w215_redteam_probes.py, evals/w216_jail_policy_probes.py (+2) |
| `post-rotation` | bundle | medium | **NO** |  |
| `posture-card-malformed` | posture-card | medium | yes | evals/w253_f214_f215_closure_probes.py, evals/w254_redteam_probes.py, tests/test_posture_cards.py |
| `posture-card-unknown-track` | posture-card | medium | yes | evals/w251_posture_probes.py, tests/test_posture_cards.py |
| `posture-card-unverifiable` | posture-card | high | yes | evals/w251_posture_probes.py, tests/test_posture_cards.py |
| `posture-endorsement-missing` | posture | medium | yes | tests/test_runtime_posture.py |
| `posture-endorsement-not-independent` | posture | medium | yes | evals/w289_redteam_probes.py, evals/w290_f350_f351_probes.py, evals/w291_redteam_probes.py (+1) |
| `posture-invalid-shape` | posture | medium | yes | evals/w291_redteam_probes.py, tests/test_runtime_posture.py |
| `posture-nonce-invalid` | posture | medium | yes | tests/test_runtime_posture.py |
| `posture-refused` | posture | medium | **NO** |  |
| `posture-signature-invalid` | posture | high | yes | evals/w290_f350_f351_probes.py, evals/w290_redteam_probes.py, evals/w291_f353_f355_probes.py (+2) |
| `posture-submod-invalid` | posture | medium | yes | tests/test_runtime_posture.py |
| `precommit_refused` | precommit | medium | **NO** |  |
| `preexec_chain_failed` | platform | high | yes | evals/f149chain_break.py, evals/f150chainexit_break.py, tests/test_s7_egress_launcher.py |
| `preexec_child_died` | platform | medium | **NO** |  |
| `preexec_recheck_failed` | platform | medium | yes | evals/f81launcher_privileged.py, evals/s7egress_break.py, tests/test_s7_egress_launcher.py |
| `preexec_recheck_timeout` | platform | high | **NO** |  |
| `presentation-missing` | presentation | medium | yes | evals/w220_faith_probes.py, tests/test_presentation_faith.py |
| `previously-consumed` | consumption | medium | yes | evals/w234_consumed_probes.py, tests/test_bound_permit.py, tests/test_consumption_ledger.py |
| `prodauth-claim-expired` | prodauth | medium | yes | evals/w272_prodauth_probes.py, tests/test_producer_authz.py |
| `prodauth-claim-invalid` | prodauth | high | yes | evals/w272_prodauth_probes.py, tests/test_producer_authz.py |
| `prodauth-claim-mismatch` | prodauth | high | yes | evals/w272_prodauth_probes.py, tests/test_producer_authz.py |
| `prodauth-producer-unknown` | prodauth | high | yes | evals/w272_prodauth_probes.py, tests/test_producer_authz.py |
| `prodauth-registry-unauthorized` | prodauth | medium | yes | evals/w272_prodauth_probes.py, tests/test_producer_authz.py |
| `prodauth-scope-not-authorized` | prodauth | high | yes | evals/w272_prodauth_probes.py, tests/test_producer_authz.py |
| `prodauth-token-expired` | prodauth | medium | yes | evals/w272_prodauth_probes.py, tests/test_producer_authz.py |
| `prodauth-token-invalid` | prodauth | high | yes | evals/w272_prodauth_probes.py, tests/test_producer_authz.py |
| `production` | deployment | medium | yes | evals/f138_closure.py, evals/manifest_default_on_probes.py, evals/matrix.py (+31) |
| `production_credential_rejected` | credential | high | yes | tests/test_f111_credential_manifest.py |
| `proof.envelope` | vc | medium | **NO** |  |
| `proof.type` | vc | medium | **NO** |  |
| `propose_release` | release | medium | **NO** |  |
| `provenance-artifact-mismatch` | evidence-provenance | medium | yes | evals/w287_provenance_probes.py, tests/test_evidence_provenance.py |
| `provenance-builder-refused` | provenance-policy | high | yes | evals/w263_provenance_probes.py, tests/test_provenance_policy.py |
| `provenance-builder-untrusted` | evidence-provenance | medium | yes | evals/w287_provenance_probes.py, tests/test_evidence_provenance.py |
| `provenance-chain-class-mismatch` | provenance | high | yes | evals/w239_provenance_probes.py, tests/test_provenance_nonupgrade.py |
| `provenance-class-missing` | provenance | high | yes | evals/w239_provenance_probes.py, tests/test_provenance_nonupgrade.py |
| `provenance-class-unknown` | provenance | high | yes | evals/w239_provenance_probes.py, tests/test_provenance_nonupgrade.py |
| `provenance-critical-arg-refused` | provenance | high | yes | evals/w314_provsink_probes.py, evals/w315_redteam_probes.py, evals/w317_producer_probes.py (+7) |
| `provenance-declassify-invalid` | provenance | medium | yes | evals/w314_provsink_probes.py, evals/w315_redteam_probes.py |
| `provenance-digest-mismatch` | provenance | high | yes | evals/w239_provenance_probes.py, tests/test_provenance_nonupgrade.py |
| `provenance-envelope-malformed` | evidence-provenance | low | yes | evals/w293_redteam_probes.py, tests/test_evidence_provenance.py, tests/test_rebuild_receipts.py (+1) |
| `provenance-label-tampered` | provenance | high | yes | evals/w314_provsink_probes.py, evals/w315_redteam_probes.py |
| `provenance-label-unverifiable` | provenance | medium | yes | evals/w314_provsink_probes.py |
| `provenance-material-unmarked` | evidence-provenance | low | yes | evals/w287_provenance_probes.py, tests/test_evidence_provenance.py |
| `provenance-material-unverified` | evidence-provenance | low | yes | evals/w287_provenance_probes.py, tests/test_evidence_provenance.py |
| `provenance-missing` | evidence-provenance | medium | yes | evals/w287_provenance_probes.py, tests/test_evidence_provenance.py |
| `provenance-policy-vacuous` | provenance-policy | high | yes | evals/w263_provenance_probes.py, tests/test_provenance_policy.py |
| `provenance-quarantine-terminal` | provenance | medium | yes | evals/w314_provsink_probes.py, evals/w315_redteam_probes.py, evals/w317_producer_probes.py (+3) |
| `provenance-rebuild-invalid` | evidence-provenance | medium | yes | evals/w290_rebuild_probes.py, evals/w291_redteam_probes.py, evals/w292_f356_probes.py (+3) |
| `provenance-rebuild-mismatch` | evidence-provenance | critical | yes | evals/w290_rebuild_probes.py, evals/w291_redteam_probes.py, tests/test_rebuild_receipts.py |
| `provenance-rebuild-missing` | evidence-provenance | medium | yes | evals/w290_rebuild_probes.py, evals/w291_redteam_probes.py, tests/test_rebuild_receipts.py |
| `provenance-rebuild-transform-unknown` | evidence-provenance | medium | yes | evals/w290_rebuild_probes.py, evals/w291_redteam_probes.py, evals/w292_f356_probes.py (+2) |
| `provenance-signature-invalid` | evidence-provenance | medium | yes | evals/w287_provenance_probes.py, evals/w290_rebuild_probes.py, evals/w291_redteam_probes.py (+2) |
| `provenance-sink-escalated` | provenance | medium | yes | evals/w314_provsink_probes.py, tests/test_provenance_sink.py |
| `provenance-sink-redacted` | provenance | low | yes | evals/w314_provsink_probes.py |
| `provenance-sink-refused` | provenance | high | yes | evals/w314_provsink_probes.py |
| `provenance-sink-unknown-tool` | provenance | medium | yes | evals/w314_provsink_probes.py, evals/w315_redteam_probes.py |
| `provenance-source-refused` | provenance-policy | high | yes | evals/w263_provenance_probes.py, tests/test_provenance_policy.py |
| `provenance-statement-unverified` | provenance-policy | high | yes | evals/w263_provenance_probes.py, evals/w265_f245f246f247_probes.py, tests/test_provenance_policy.py |
| `provenance-step-break` | provenance | high | yes | evals/w239_provenance_probes.py, tests/test_provenance_nonupgrade.py |
| `provenance-subject-refused` | provenance-policy | high | yes | evals/w263_provenance_probes.py, evals/w265_f245f246f247_probes.py, evals/w279_vsa_probes.py (+2) |
| `provenance-tag-refused` | provenance-policy | high | yes | evals/w263_provenance_probes.py, tests/test_provenance_policy.py |
| `provenance-upgraded` | provenance | critical | yes | evals/w239_provenance_probes.py, tests/test_provenance_nonupgrade.py |
| `provenance-vsa-refused` | provenance-policy | high | yes | evals/w263_provenance_probes.py, evals/w265_f245f246f247_probes.py, evals/w279_vsa_probes.py (+2) |
| `provisioned_required` | approval | medium | **NO** |  |
| `provlabel-approval-required` | provlabel | medium | yes | evals/w274_provenance_probes.py, evals/w276_f294_probes.py, evals/w277_conflict_probes.py (+3) |
| `provlabel-malformed` | provlabel | medium | yes | evals/w279_f300_probes.py, evals/w281_f307_probes.py, tests/test_instruction_provenance.py |
| `provlabel-mixed-provenance` | provlabel | medium | yes | evals/w275_redteam_probes.py, evals/w276_f294_probes.py, evals/w277_conflict_probes.py (+4) |
| `provlabel-omitted-driver` | provlabel | medium | yes | evals/w279_f300_probes.py, evals/w281_f307_probes.py, evals/w282_redteam_probes.py |
| `provlabel-unresolvable-driver` | provlabel | medium | yes | evals/w274_provenance_probes.py, evals/w277_conflict_probes.py, evals/w279_f300_probes.py (+4) |
| `ptgrant-arg-attribute-missing` | tool_grant | high | yes | evals/w271_ptgrantv2_probes.py, evals/w272_redteam_probes.py, tests/test_tool_grant_v2.py |
| `ptgrant-arg-bound-violated` | tool_grant | high | yes | evals/w270_ptgrant_probes.py, evals/w271_ptgrantv2_probes.py, evals/w272_redteam_probes.py (+2) |
| `ptgrant-attenuation-invalid` | tool_grant | high | **NO** |  |
| `ptgrant-audience-mismatch` | tool_grant | high | yes | evals/w270_ptgrant_probes.py, tests/test_tool_grant.py |
| `ptgrant-batch-tool-cap-exceeded` | tool_grant | medium | yes | evals/w271_ptgrantv2_probes.py, tests/test_tool_grant_v2.py |
| `ptgrant-caller-unauthorized` | tool_grant | high | yes | evals/w271_ptgrantv2_probes.py, tests/test_tool_grant_v2.py |
| `ptgrant-cnf-missing` | tool_grant | high | **NO** |  |
| `ptgrant-context-oversize` | tool_grant | medium | yes | evals/w271_ptgrantv2_probes.py, tests/test_tool_grant_v2.py |
| `ptgrant-grant-expired` | tool_grant | medium | yes | evals/w270_ptgrant_probes.py, tests/test_tool_grant.py |
| `ptgrant-grant-malformed` | tool_grant | medium | yes | tests/test_tool_grant.py, tests/test_tool_grant_v2.py |
| `ptgrant-grant-not-yet-valid` | tool_grant | medium | **NO** |  |
| `ptgrant-invalid-target` | tool_grant | medium | yes | tests/test_tool_grant.py |
| `ptgrant-issuer-unknown` | tool_grant | high | **NO** |  |
| `ptgrant-jti-reused` | tool_grant | high | yes | evals/w271_redteam_probes.py, evals/w272_f253f254_probes.py, evals/w272_redteam_probes.py (+2) |
| `ptgrant-link-unverifiable` | tool_grant | medium | yes | tests/test_tool_grant.py |
| `ptgrant-mandate-drift` | tool_grant | high | yes | evals/w270_ptgrant_probes.py, evals/w271_ptgrantv2_probes.py, evals/w271_redteam_probes.py (+3) |
| `ptgrant-mandate-unreachable` | tool_grant | high | yes | evals/w271_ptgrantv2_probes.py, evals/w272_redteam_probes.py, tests/test_gatehard_closures_w273.py (+1) |
| `ptgrant-max-calls-exhausted` | tool_grant | medium | yes | evals/w270_ptgrant_probes.py, evals/w271_redteam_probes.py, tests/test_tool_grant.py |
| `ptgrant-ok` | tool_grant | medium | yes | evals/w270_ptgrant_probes.py, evals/w271_ptgrantv2_probes.py, evals/w271_redteam_probes.py (+5) |
| `ptgrant-pop-invalid` | tool_grant | high | yes | evals/w270_ptgrant_probes.py, evals/w271_redteam_probes.py, evals/w272_f253f254_probes.py (+3) |
| `ptgrant-predicate-hash-mismatch` | tool_grant | high | yes | evals/w271_ptgrantv2_probes.py, tests/test_tool_grant_v2.py |
| `ptgrant-predicate-unknown` | tool_grant | medium | yes | evals/w270_ptgrant_probes.py, evals/w271_redteam_probes.py, tests/test_tool_grant.py |
| `ptgrant-signature-invalid` | tool_grant | high | yes | evals/w270_ptgrant_probes.py, tests/test_tool_grant.py |
| `ptgrant-supply-chain-failed` | tool_grant | high | yes | evals/w270_ptgrant_probes.py, evals/w271_redteam_probes.py, tests/test_tool_grant.py |
| `ptgrant-tool-not-covered` | tool_grant | high | yes | evals/w270_ptgrant_probes.py, evals/w271_ptgrantv2_probes.py, evals/w276_decoy_probes.py (+2) |
| `quarantine-bypass-refused` | quarantine | high | yes | evals/w224_quar_probes.py, tests/test_quarantine.py |
| `quarantine-digest-mismatch` | quarantine | critical | yes | evals/w224_quar_probes.py, tests/test_quarantine.py |
| `quarantine-envelope-override-refused` | quarantine | medium | yes | evals/w224_quar_probes.py, tests/test_quarantine.py |
| `quarantine-malformed` | quarantine | medium | yes | evals/w224_quar_probes.py, tests/test_quarantine.py |
| `quarantine-not-admitted` | quarantine | medium | yes | evals/w224_quar_probes.py, tests/test_quarantine.py |
| `quarantine-policy-contract-refused` | quarantine | medium | yes | evals/w224_quar_probes.py, tests/test_quarantine.py |
| `quarantine-rejected` | quarantine | medium | yes | evals/w224_quar_probes.py, tests/test_quarantine.py |
| `quarantine-unknown-staged` | quarantine | medium | yes | evals/w224_quar_probes.py, tests/test_quarantine.py |
| `quorum-ambiguous` | quorum | high | yes | evals/w217_quorum_probes.py |
| `quorum-attestation-expired` | quorum | medium | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py |
| `quorum-deny-veto` | quorum | high | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py, tests/test_quorum_approval.py |
| `quorum-duplicate-approver` | quorum | high | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py, tests/test_quorum_approval.py |
| `quorum-gate-refused` | namespace | medium | yes | evals/w217_quorum_probes.py, tests/test_quorum_policy.py |
| `quorum-insufficient` | quorum | high | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py, tests/test_quorum_approval.py |
| `quorum-key-reuse` | quorum | high | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py, tests/test_quorum_approval.py |
| `quorum-malformed` | quorum | medium | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py, tests/test_quorum_approval.py |
| `quorum-not-met` | quorum | high | **NO** |  |
| `quorum-operation-mismatch` | quorum | medium | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py, tests/test_quorum_approval.py |
| `quorum-policy-version-invalid` | quorum | high | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py, tests/test_quorum_approval.py |
| `quorum-replay-refused` | quorum | high | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py |
| `quorum-rollback-refused` | namespace | medium | yes | evals/w219_rollback_probes.py, tests/test_version_manifest.py |
| `quorum-signature-invalid` | quorum | high | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py |
| `quorum-unknown-approver` | quorum | medium | yes | evals/w320_quorum_probes.py, evals/w321_redteam_probes.py |
| `quorum-unreachable` | quorum | high | yes | evals/w320_quorum_probes.py, tests/test_quorum_approval.py |
| `r3-grant-beyond-document` | r3 | high | **NO** |  |
| `r3-grant-hash-mismatch` | r3 | high | **NO** |  |
| `r3-malformed` | r3 | medium | **NO** |  |
| `r3-no-match` | r3 | medium | **NO** |  |
| `r3-per-call-binding-broken` | r3 | high | **NO** |  |
| `r3-s256-mismatch` | r3 | high | **NO** |  |
| `r3-unknown-operation` | r3 | high | **NO** |  |
| `r3-vocabulary-unknown` | r3 | high | **NO** |  |
| `rail-adapter-unknown-verdict` | rail | high | yes | evals/w274_rail_probes.py, evals/w275_redteam_probes.py, evals/w277_conflict_probes.py (+1) |
| `rail-allow` | rail | low | yes | evals/w275_redteam_probes.py, tests/test_rail_verdict.py |
| `rail-chunk-body-mismatch` | rail | high | yes | tests/test_rail_verdict.py |
| `rail-chunk-relabel-refused` | rail | high | yes | evals/w274_rail_probes.py, evals/w275_redteam_probes.py, tests/test_rail_verdict.py |
| `rail-chunk-unlabeled` | rail | medium | yes | evals/w274_rail_probes.py, evals/w276_f293_probes.py, tests/test_rail_verdict.py |
| `rail-instruction-chunk-masked` | rail | medium | **NO** |  |
| `rail-merge-contract-violated` | rail | medium | yes | evals/w274_rail_probes.py, evals/w276_f293_probes.py, tests/test_rail_verdict.py |
| `rail-transform-empty-spans` | rail | medium | yes | evals/w274_rail_probes.py, evals/w277_conflict_probes.py, tests/test_rail_verdict.py |
| `ratify-admission-unverifiable` | ratify | high | yes | evals/w282_ratify_probes.py, tests/test_ratify.py |
| `ratify-policy-unsatisfied` | ratify | medium | **NO** |  |
| `ratify-unratified-tool-refused` | ratify | high | yes | evals/w282_ratify_probes.py, tests/test_ratify.py |
| `ratify-verifier-error` | ratify | medium | yes | evals/w282_ratify_probes.py |
| `receipt-expired` | authorization_receipt | medium | yes | evals/w217_receipt_probes.py, tests/test_authorization_receipts.py |
| `receipt-fork-detected` | receipt | high | yes | evals/w286_receipts_probes.py |
| `receipt-format-mismatch` | authorization_receipt | medium | yes | tests/test_authorization_receipts.py |
| `receipt-inclusion-mismatch` | receipt | high | yes | evals/w286_receipts_probes.py, tests/test_evidence_receipt.py |
| `receipt-leaf-mismatch` | receipt | high | yes | evals/w286_receipts_probes.py, tests/test_evidence_receipt.py |
| `receipt-malformed` | authorization_receipt | medium | **NO** |  |
| `receipt-pair-decision-drift` | receipt_pair | critical | yes | evals/w227_pairs_probes.py, evals/w228_codes_probes.py, tests/test_decision_codes.py (+1) |
| `receipt-pair-decision-mismatch` | receipt_pair | critical | yes | evals/w227_pairs_probes.py, tests/test_receipt_pairs.py |
| `receipt-pair-effect-drift` | receipt_pair | critical | yes | evals/w227_pairs_probes.py, tests/test_receipt_pairs.py |
| `receipt-pair-malformed` | receipt_pair | medium | yes | tests/test_receipt_pairs.py |
| `receipt-pair-not-authorization` | receipt_pair | high | yes | evals/w227_pairs_probes.py, tests/test_receipt_pairs.py |
| `receipt-pair-refused` | receipt_pair | medium | **NO** |  |
| `receipt-pair-time-inversion` | receipt_pair | medium | yes | evals/w227_pairs_probes.py, tests/test_receipt_pairs.py |
| `receipt-pair-unknown-field` | receipt_pair | medium | yes | evals/w227_pairs_probes.py, tests/test_receipt_pairs.py |
| `receipt-policy-mismatch` | receipt | medium | yes | evals/w286_receipts_probes.py, tests/test_evidence_receipt.py |
| `receipt-signature-invalid` | receipt | high | yes | evals/w286_receipts_probes.py, tests/test_evidence_receipt.py |
| `receipt_unverifiable` | platform | high | yes | evals/s7egress_break.py, tests/test_s7_egress_launcher.py |
| `recipient-plugin-identity-refused` | envelope | medium | yes | tests/test_recipient_plugins.py |
| `recipient-plugin-label-inconsistent` | envelope | medium | yes | evals/w263_recipient_probes.py, tests/test_recipient_plugins.py |
| `recipient-plugin-malformed-wrap` | envelope | medium | yes | evals/w263_recipient_probes.py, tests/test_recipient_plugins.py |
| `recipient-plugin-namespace-conflict` | envelope | medium | yes | evals/w263_recipient_probes.py, tests/test_recipient_plugins.py |
| `recipient-plugin-unknown-label` | envelope | medium | yes | evals/w263_recipient_probes.py, tests/test_recipient_plugins.py |
| `recipient-plugin-unwrap-refused` | envelope | high | yes | evals/w263_recipient_probes.py, tests/test_recipient_plugins.py |
| `recipient-plugin-wrap-refused` | envelope | medium | yes | tests/test_recipient_plugins.py |
| `recipient-policy-invalid` | envelope | medium | yes | evals/w284_sops_probes.py, evals/w286_f326_probes.py, tests/test_bundle_envelope.py |
| `recompute-absent-refusal-no-coverage` | recompute | medium | yes | evals/w241_recompute_check_probes.py, tests/test_recompute_check.py |
| `recompute-backlink-mismatch` | recompute | critical | yes | evals/w241_recompute_check_probes.py, tests/test_recompute_check.py |
| `recompute-digest-mismatch` | recompute | critical | yes | evals/w241_recompute_check_probes.py |
| `recompute-malformed` | recompute | medium | yes | evals/w241_recompute_check_probes.py, tests/test_recompute_check.py |
| `recompute-no-execution-link` | recompute | medium | yes | evals/w241_recompute_check_probes.py |
| `recompute-signature-invalid` | recompute | critical | yes | evals/w241_recompute_check_probes.py, tests/test_recompute_check.py |
| `reconintent-malformed` | reconintent | medium | yes | evals/w266_reconintent_probes.py, tests/test_reconstructed_intent.py |
| `reconintent-queue-failed` | reconintent | medium | yes | evals/w266_reconintent_probes.py, tests/test_reconstructed_intent.py |
| `reconintent-suspect` | reconintent | medium | yes | evals/w266_reconintent_probes.py, tests/test_reconstructed_intent.py |
| `record-depth-exceeded` | canonical | high | yes | evals/w237_canonrecord_probes.py, tests/test_canonical_record.py |
| `record-duplicate-member` | canonical | high | yes | evals/w237_canonrecord_probes.py, tests/test_canonical_record.py |
| `record-malformed` | canonical | high | yes | evals/w237_canonrecord_probes.py, tests/test_canonical_record.py |
| `record-noncanonical-float` | canonical | high | yes | evals/w237_canonrecord_probes.py, tests/test_canonical_record.py |
| `record-opaque-bytes` | canonical | low | yes | evals/w237_canonrecord_probes.py, tests/test_canonical_record.py |
| `recover_torn_tail` | journal | medium | **NO** |  |
| `reference-not-digest` | namespace | critical | yes | evals/admit_deploy_wiring_probes.py, evals/sign_deploy_namespace_probes.py, tests/test_sign_deploy_namespaces.py |
| `registry-malformed` | jail | medium | yes | tests/test_jail_pci.py, tests/test_version_manifest.py |
| `registry-threshold-unmet` | registry-acceptance | high | yes | evals/w243_threat_model_probes.py, evals/w244_treeship_advisory_probes.py, tests/test_advisory_binding.py (+1) |
| `release_digest` | release | medium | yes | evals/release_approval_break_battery.py, tests/test_durable_release.py, tests/test_release_approval.py |
| `render-pair-refused` | render | medium | yes | tests/test_untrusted_render.py |
| `rendering-commitment-broken` | render | high | yes | evals/w221_rendercommit_probes.py, evals/w222_digestlink_probes.py, evals/w222_display_probes.py (+3) |
| `replay-approval-receipt-invalid` | replay | high | yes | evals/w271_replay_probes.py, tests/test_replay_manifest.py |
| `replay-broken-chain` | replay | critical | yes | evals/w271_replay_probes.py, evals/w272_driftrev_probes.py, tests/test_replay_manifest.py (+1) |
| `replay-dirty-codebase-seal` | replay | high | yes | evals/w271_replay_probes.py, tests/test_replay_manifest.py |
| `replay-evidence-tampered` | policy_replay | critical | yes | evals/w229_replay_probes.py, tests/test_policy_revisions.py |
| `replay-malformed` | replay | medium | yes | evals/w271_replay_probes.py, evals/w272_driftrev_probes.py, evals/w273_rslreplay_probes.py (+2) |
| `replay-missing-approval-receipt` | replay | high | yes | evals/w271_replay_probes.py, tests/test_replay_manifest.py |
| `replay-policy-digest-mismatch` | policy_replay | critical | yes | evals/w229_replay_probes.py, tests/test_policy_revisions.py |
| `replay-policy-drift` | policy_replay | high | yes | evals/w229_replay_probes.py, tests/test_policy_revisions.py |
| `replay-policy-malformed` | policy_replay | medium | yes | tests/test_policy_revisions.py |
| `replay-policy-not-authorization` | policy_replay | high | yes | tests/test_policy_revisions.py |
| `replay-policy-revision-conflict` | policy_replay | high | yes | evals/w229_replay_probes.py, tests/test_policy_revisions.py |
| `replay-policy-revision-unknown` | policy_replay | medium | yes | evals/w229_replay_probes.py, tests/test_policy_revisions.py |
| `replay-presentation-mismatch` | replay | medium | yes | evals/w271_replay_probes.py, tests/test_replay_manifest.py |
| `replay-refused` | policy_replay | medium | **NO** |  |
| `replay-unverifiable-tool-digest` | replay | high | yes | evals/w271_replay_probes.py, tests/test_replay_manifest.py |
| `replayed_nonce` | identity | medium | yes | evals/f152_hunt_break.py, evals/identity_covert_break.py |
| `repo-hook-escape-refused` | session-trust | critical | yes | evals/w244_session_trust_ordering_probes.py, tests/test_session_trust.py |
| `repo-hook-pretrust-refused` | session-trust | critical | yes | evals/w244_session_trust_ordering_probes.py, evals/w245_gitspawn_open_path_probes.py, tests/test_session_trust.py (+1) |
| `repo-hook-trust-denied` | session-trust | high | yes | evals/w244_session_trust_ordering_probes.py, tests/test_session_trust.py |
| `reputation-entry-malformed` | reputation | medium | yes | evals/w246_agent_identity_probes.py |
| `reputation-event-kind-unknown` | reputation | medium | yes | evals/w246_agent_identity_probes.py, tests/test_agent_identity.py |
| `reputation-ledger-tampered` | reputation | high | yes | evals/w246_agent_identity_probes.py, evals/w247_redteam_probes.py, tests/test_agent_identity.py |
| `requester_target` | approval | medium | yes | evals/w22_probes.py, tests/test_approvals_d1.py |
| `requester_vote` | approval | medium | yes | evals/w22_probes.py, tests/test_approvals_d1.py, tests/test_delegation_executor_wiring.py (+1) |
| `resource-server-mismatch` | transaction | high | yes | evals/w243_transactional_tokens_probes.py, tests/test_transactional_tokens.py |
| `resume_authority_not_reissued` | recovery | medium | yes | evals/w77_probes.py, tests/test_w77_recovery.py |
| `resume_refused` | recovery | medium | yes | evals/w77_probes.py, tests/test_pending_approvals.py, tests/test_w77_recovery.py |
| `revbind-content-mismatch` | revbind | high | yes | evals/w272_driftrev_probes.py, tests/test_drift_report.py, tests/test_revision_binding.py |
| `revbind-equivalence-accepted` | revbind | low | yes | evals/w272_driftrev_probes.py, tests/test_drift_report.py, tests/test_revision_binding.py |
| `revbind-malformed` | revbind | medium | yes | evals/w272_driftrev_probes.py, tests/test_drift_report.py, tests/test_revision_binding.py |
| `reverify-malformed` | reverify | medium | yes | evals/w225_reverify_probes.py |
| `reverify-not-authorization` | reverify | high | yes | evals/w225_reverify_probes.py, tests/test_reverify.py |
| `reverify-parent-signature-invalid` | reverify | high | yes | evals/w225_reverify_probes.py, tests/test_reverify.py |
| `reverify-refused` | reverify | medium | **NO** |  |
| `reverify-required` | reverify | medium | yes | evals/w225_reverify_probes.py, tests/test_reverify.py |
| `reverify-revoked` | reverify | high | yes | evals/w225_reverify_probes.py, tests/test_reverify.py |
| `reverify-stale` | reverify | medium | yes | evals/w225_reverify_probes.py, evals/w228_codes_probes.py, tests/test_reverify.py |
| `reverify-unknown-parent-kind` | reverify | medium | yes | evals/w225_reverify_probes.py, tests/test_reverify.py |
| `revocation-applicable` | revocation | high | yes | evals/w243_finality_bound_probes.py, tests/test_finality_bound.py |
| `revocation-basis-malformed` | revocation | medium | yes | evals/w243_finality_bound_probes.py, tests/test_finality_bound.py |
| `revocation-basis-tampered` | revocation | critical | yes | evals/w243_finality_bound_probes.py, tests/test_finality_bound.py |
| `revocation-category-error` | axis | high | **NO** |  |
| `revocation-check-unsealed` | revocation | high | yes | evals/w243_finality_bound_probes.py, tests/test_finality_bound.py |
| `revocation-entry-unverifiable` | revocation | medium | yes | evals/w222_revoke_probes.py, evals/w292_revocation_probes.py, tests/test_absence_revocation.py (+1) |
| `revocation-inexact-target-refused` | revocation | high | yes | evals/w222_revoke_probes.py, tests/test_absence_revocation.py |
| `revocation-push-event-malformed` | revocation-push | medium | yes | evals/w333_revpush_probes.py, evals/w334_redteam_probes.py |
| `revocation-push-event-replayed` | revocation-push | low | yes | evals/w333_revpush_probes.py, evals/w334_redteam_probes.py |
| `revocation-push-event-unsigned` | revocation-push | high | yes | evals/w333_revpush_probes.py, evals/w334_redteam_probes.py |
| `revocation-push-refused` | revocation-push | medium | **NO** |  |
| `revocation-push-session-suspended` | revocation-push | high | yes | evals/w333_revpush_probes.py, evals/w334_redteam_probes.py |
| `revocation-push-session-terminated` | revocation-push | low | yes | evals/w333_revpush_probes.py, evals/w334_attack_probes.py, evals/w334_redteam_probes.py (+1) |
| `revocation-push-session-unknown` | revocation-push | medium | yes | evals/w333_revpush_probes.py, evals/w334_redteam_probes.py |
| `revocation-push-subject-unbound` | revocation-push | low | yes | evals/w333_revpush_probes.py, evals/w334_redteam_probes.py |
| `revocation-refused` | revocation | medium | yes | evals/w292_revocation_probes.py, evals/w293_redteam_probes.py, tests/test_revocation_status.py |
| `revocation-retired-reuse` | revocation | high | yes | evals/w292_revocation_probes.py, evals/w293_redteam_probes.py, evals/w293_sweep_probes.py (+2) |
| `revocation-revoked` | revocation | high | yes | evals/w292_revocation_probes.py, evals/w293_redteam_probes.py, evals/w294_f364_probes.py (+1) |
| `revocation-sink-nonatomic` | revocation | high | yes | evals/w243_finality_bound_probes.py, tests/test_finality_bound.py |
| `revocation-state-unknown` | axis | high | **NO** |  |
| `revocation-status-unverifiable` | revocation | high | yes | evals/w292_revocation_probes.py, evals/w293_redteam_probes.py, evals/w294_f364_probes.py (+3) |
| `revoke_not_authorized` | approval | high | yes | tests/test_delegation_primitive.py |
| `rollback-detected` | manifest | critical | yes | evals/w219_rollback_probes.py, evals/w228_codes_probes.py, tests/test_version_manifest.py |
| `rsl-fork-detected` | bundle | high | yes | evals/w271_rsl_probes.py, tests/test_bundle_rsl.py |
| `rsl-log-corrupt` | bundle | high | yes | evals/w272_redteam_probes.py, evals/w273_rslreplay_probes.py, tests/test_bundle_rsl.py |
| `rsl-rollback-attempt` | bundle | high | yes | evals/w271_rsl_probes.py, tests/test_bundle_rsl.py |
| `rsl-rule-expired` | bundle | high | yes | evals/w271_rsl_probes.py, evals/w272_redteam_probes.py, evals/w273_rslreplay_probes.py (+1) |
| `rsl-skipped-revoked` | bundle | high | yes | evals/w271_rsl_probes.py, tests/test_bundle_rsl.py |
| `rsl-terminal-rule-unsigned` | bundle | high | yes | evals/w271_rsl_probes.py, tests/test_bundle_rsl.py |
| `rsl-threshold-invalid` | bundle | medium | yes | evals/w271_rsl_probes.py, tests/test_bundle_rsl.py |
| `rsl-transition-unauthorized` | bundle | high | yes | evals/w271_rsl_probes.py, tests/test_bundle_rsl.py |
| `rule-missing` | audit | medium | yes | evals/sigma_detection_probes.py, tests/test_audit_detect.py |
| `rule-tampered` | audit | critical | yes | evals/sigma_detection_probes.py, tests/test_audit_detect.py |
| `rule-unbound` | audit | medium | yes | evals/sigma_detection_probes.py, tests/test_audit_detect.py |
| `run_limits` | policy | medium | **NO** |  |
| `sandbox-landlock-apply-failed` | sandbox | high | yes | evals/w266_landlock_probes.py, evals/w331_landlock_probes.py, evals/w331_redteam_probes.py (+3) |
| `sandbox-landlock-required` | sandbox | high | yes | evals/w266_landlock_probes.py, evals/w267_redteam_probes.py, evals/w331_landlock_probes.py (+2) |
| `sandbox-landlock-unavailable` | sandbox | low | yes | evals/w266_landlock_probes.py, evals/w267_redteam_probes.py, evals/w331_landlock_probes.py (+4) |
| `sandbox-policy-drift` | sandbox | high | yes | evals/w284_nsjail_probes.py, evals/w286_f329_f330_probes.py, tests/test_sandbox_policy.py |
| `sandbox-policy-host-mismatch` | sandbox | high | yes | evals/w284_nsjail_probes.py, tests/test_sandbox_policy.py |
| `sandbox-policy-invalid` | sandbox | medium | yes | evals/w284_nsjail_probes.py, tests/test_sandbox_policy.py |
| `sandbox-policy-kill` | sandbox | low | yes | tests/test_sandbox_policy.py |
| `sandbox-policy-no-default` | sandbox | medium | yes | evals/w284_nsjail_probes.py, tests/test_sandbox_policy.py |
| `sandbox-policy-unpinned` | sandbox | high | yes | evals/w284_nsjail_probes.py, tests/test_sandbox_policy.py |
| `sandbox-real-credential-blocked` | sandbox | high | yes | evals/w273_sandboxcred_probes.py, evals/w274_redteam_probes.py, tests/test_sandbox_real_credential.py |
| `sandbox-refused` | capability | medium | **NO** |  |
| `satisfied-missing` | evaluation | high | yes | evals/w243_outcome_vocabulary_probes.py, tests/test_outcome_vocabulary.py |
| `scan_gate` | scan | medium | **NO** |  |
| `scan_gate_refused` | load_gate | medium | yes | tests/test_scan_verdicts.py |
| `scan_gate_unwired` | load_gate | medium | yes | tests/test_scan_verdicts.py |
| `scan_policy` | scan | medium | **NO** |  |
| `scan_policy_duplicates` | scan | medium | **NO** |  |
| `scan_verdict_bad_bytes` | scan | medium | **NO** |  |
| `scan_verdict_bad_digest` | scan | medium | **NO** |  |
| `scan_verdict_bad_json` | scan | medium | yes | evals/w339_covgap1_probes.py |
| `scan_verdict_bad_scanner_name` | scan | medium | yes | tests/test_scan_verdicts.py |
| `scan_verdict_bad_scanner_version` | scan | medium | **NO** |  |
| `scan_verdict_bad_severity_counts` | scan | medium | **NO** |  |
| `scan_verdict_bad_timestamp` | scan | medium | **NO** |  |
| `scan_verdict_bad_verdict` | scan | medium | **NO** |  |
| `scan_verdict_bad_verifiers` | scan | medium | **NO** |  |
| `scan_verdict_born_stale` | scan | medium | **NO** |  |
| `scan_verdict_empty_window` | scan | medium | **NO** |  |
| `scan_verdict_future_scan` | scan | medium | yes | evals/w339_covgap1_probes.py |
| `scan_verdict_malformed_envelope` | scan | medium | yes | evals/w339_covgap1_probes.py |
| `scan_verdict_missing` | scan | medium | **NO** |  |
| `scan_verdict_missing_fields` | scan | medium | **NO** |  |
| `scan_verdict_negative` | scan | medium | **NO** |  |
| `scan_verdict_no_signer` | scan | medium | **NO** |  |
| `scan_verdict_no_verifiers` | scan | medium | **NO** |  |
| `scan_verdict_not_canonical` | scan | medium | yes | evals/w339_covgap1_probes.py |
| `scan_verdict_payload_type` | scan | medium | yes | evals/w339_covgap1_probes.py |
| `scan_verdict_scanner_mismatch` | scan | medium | yes | evals/w339_covgap1_probes.py |
| `scan_verdict_signature_invalid` | scan | high | yes | evals/w339_covgap1_probes.py |
| `scan_verdict_stale` | scan | medium | yes | evals/w339_covgap1_probes.py |
| `scan_verdict_target_mismatch` | scan | medium | yes | evals/w339_covgap1_probes.py |
| `scan_verdict_unknown_fields` | scan | medium | **NO** |  |
| `scan_verdict_unknown_scanner` | scan | medium | **NO** |  |
| `scan_verdict_window_too_long` | scan | medium | **NO** |  |
| `scan_verdicts_unpresented` | load_gate | medium | yes | evals/w213_scan_gate_probes.py, tests/test_scan_verdicts.py |
| `schema-record-malformed` | schema-ref | medium | yes | evals/w246_schema_ref_probes.py, tests/test_schema_ref_guard.py |
| `schema-ref-budget-exhausted` | schema-ref | high | yes | evals/w246_schema_ref_probes.py, evals/w247_redteam_probes.py, tests/test_schema_ref_guard.py |
| `schema-ref-depth-exceeded` | schema-ref | high | yes | evals/w246_schema_ref_probes.py, evals/w247_redteam_probes.py, tests/test_schema_ref_guard.py |
| `schema-ref-external` | schema-ref | high | yes | evals/w246_schema_ref_probes.py, evals/w247_redteam_probes.py, tests/test_schema_ref_guard.py |
| `schema-refs-resolved` | schema-ref | low | yes | evals/w246_schema_ref_probes.py, tests/test_schema_ref_guard.py |
| `scope-consent-expired` | scope-listing | medium | yes | evals/w263_redteam_probes.py, evals/w264_f240f241f242_probes.py, evals/w265_redteam_probes.py (+2) |
| `scope-consent-forged` | scope-listing | high | yes | evals/w262_scopelist_probes.py, evals/w264_f240f241f242_probes.py, evals/w264_merge_audit.py (+1) |
| `scope-consent-unbound` | scope-listing | high | yes | evals/w262_scopelist_probes.py, evals/w263_redteam_probes.py, evals/w265_redteam_probes.py (+1) |
| `scope-grant-tampered` | token-scope | critical | yes | evals/w244_token_scope_probes.py, evals/w263_redteam_probes.py, evals/w264_f240f241f242_probes.py (+5) |
| `scope-grant-unbound` | token-scope | high | yes | evals/w244_token_scope_probes.py |
| `scope-key-missing` | token-scope | high | yes | tests/test_token_scope_enforcement.py |
| `scope-listing-denied` | scope-listing | high | yes | evals/w262_scopelist_probes.py, evals/w263_redteam_probes.py, evals/w264_f240f241f242_probes.py (+4) |
| `scope-listing-not-registered` | scope-listing | medium | yes | evals/w262_scopelist_probes.py, evals/w263_redteam_probes.py, evals/w264_f240f241f242_probes.py (+2) |
| `scope-listing-subject-mismatch` | scope-listing | high | yes | evals/w264_f240f241f242_probes.py, evals/w264_merge_audit.py |
| `scope-listing-unknown-scope` | scope-listing | medium | yes | evals/w262_scopelist_probes.py, evals/w263_redteam_probes.py, tests/test_scoped_tool_listing.py |
| `scope-policy-tampered` | token-scope | critical | yes | evals/w244_token_scope_probes.py, tests/test_token_scope_enforcement.py |
| `scope-verdict-mismatched` | token-scope | high | yes | evals/w244_token_scope_probes.py, tests/test_token_scope_enforcement.py |
| `scope_amplification` | approval | high | yes | tests/test_delegation_primitive.py |
| `scope_denied` | lease | medium | yes | evals/w78_probes.py, tests/test_w78_supplychain.py |
| `scope_exceeded` | approval | high | yes | evals/w26rt_probes.py, evals/w_incident_probes.py, tests/test_delegation_executor_wiring.py (+1) |
| `scope_widened` | approval | high | yes | tests/test_delegation_primitive.py |
| `scoped-approval-capability-unknown` | scoped | medium | yes | tests/test_closure_scoped_approvals.py |
| `scoped-approval-malformed` | scoped | medium | yes | evals/w237_closescoped_probes.py, tests/test_closure_scoped_approvals.py |
| `scoped-approval-tampered` | scoped | high | yes | evals/w237_closescoped_probes.py, tests/test_closure_scoped_approvals.py |
| `seeded-denial-digest-mismatch` | seeded_denial | critical | yes | evals/w231_seed_probes.py, tests/test_seeded_denials.py |
| `seeded-denial-malformed` | seeded_denial | medium | yes | evals/w231_seed_probes.py, tests/test_seeded_denials.py |
| `seeded-denial-not-authorization` | seeded_denial | high | yes | evals/w231_seed_probes.py, tests/test_seeded_denials.py |
| `seeded-denial-refused` | seeded_denial | medium | yes | tests/test_seeded_denials.py |
| `self_delegation` | approval | high | yes | evals/w22_probes.py, tests/test_approvals_d1.py, tests/test_delegation_primitive.py |
| `sessbind-domain-mismatch` | sessbind | high | yes | evals/w269_sessbind_probes.py, evals/w270_redteam_probes.py, tests/test_session_binding.py |
| `sessbind-ehd-mismatch` | sessbind | high | yes | evals/w269_sessbind_probes.py, evals/w270_redteam_probes.py, tests/test_session_binding.py |
| `sessbind-malformed` | sessbind | medium | yes | evals/w269_sessbind_probes.py, evals/w270_redteam_probes.py, evals/w271_redteam_probes.py (+1) |
| `sessbind-ok` | sessbind | low | yes | evals/w270_redteam_probes.py, tests/test_session_binding.py |
| `sessbind-signature-invalid` | sessbind | high | yes | evals/w269_sessbind_probes.py, evals/w270_redteam_probes.py, tests/test_session_binding.py |
| `sessbind-token-expired` | sessbind | medium | yes | evals/w269_sessbind_probes.py, evals/w270_redteam_probes.py, tests/test_session_binding.py |
| `sessbind-transcript-mismatch` | sessbind | high | yes | evals/w269_sessbind_probes.py, evals/w270_redteam_probes.py, evals/w271_redteam_probes.py (+1) |
| `sessbind-verifier-misconfigured` | sessbind | medium | yes | evals/w269_sessbind_probes.py, evals/w270_redteam_probes.py, tests/test_session_binding.py |
| `session-trust-malformed` | session-trust | medium | yes | evals/w244_session_trust_ordering_probes.py, evals/w245_gitspawn_open_path_probes.py, tests/test_session_trust.py (+1) |
| `shield-bad-id` | guardrail | medium | **NO** |  |
| `shield-bad-params` | guardrail | medium | **NO** |  |
| `shield-bad-provider-kind` | guardrail | medium | **NO** |  |
| `shield-bad-verdict` | guardrail | medium | yes | tests/test_shield_registry.py |
| `shield-duplicate-id` | guardrail | medium | yes | tests/test_shield_registry.py |
| `shield-no-run` | guardrail | medium | **NO** |  |
| `shield-non-verdict` | guardrail | medium | **NO** |  |
| `shield-remote-no-endpoint` | guardrail | medium | yes | tests/test_shield_registry.py |
| `shield-unknown-id` | guardrail | medium | yes | evals/w281_redteam_probes.py, tests/test_shield_registry.py |
| `shield-violation` | guardrail | medium | yes | tests/test_shield_registry.py |
| `short-lived-credential-chain-broken` | short-lived-credential | high | yes | evals/w256_credentials_probes.py, tests/test_short_lived_credentials.py |
| `short-lived-credential-corrupted` | short-lived-credential | high | yes | evals/w256_credentials_probes.py, tests/test_short_lived_credentials.py |
| `short-lived-credential-expired` | short-lived-credential | medium | yes | evals/w256_credentials_probes.py, tests/test_short_lived_credentials.py |
| `short-lived-credential-key-weak` | short-lived-credential | high | yes | tests/test_short_lived_credentials.py |
| `short-lived-credential-malformed` | short-lived-credential | low | yes | evals/w256_credentials_probes.py, evals/w260_redteam_probes.py, tests/test_short_lived_credentials.py |
| `short-lived-credential-revoked` | short-lived-credential | medium | yes | evals/w256_credentials_probes.py, tests/test_short_lived_credentials.py |
| `short-lived-credential-scope-forbidden` | short-lived-credential | medium | yes | evals/w256_credentials_probes.py, tests/test_short_lived_credentials.py |
| `short-lived-credential-ttl-unbounded` | short-lived-credential | medium | yes | evals/w256_credentials_probes.py, tests/test_short_lived_credentials.py |
| `short-lived-credential-unknown` | short-lived-credential | medium | yes | evals/w256_credentials_probes.py, tests/test_short_lived_credentials.py |
| `signal-kind-required` | posture | medium | yes | evals/w223_set_probes.py, tests/test_posture.py |
| `signal-not-authorization` | posture | high | yes | evals/w223_set_probes.py, tests/test_posture.py |
| `signal-scope-mismatch` | posture | critical | yes | evals/w223_set_probes.py, tests/test_posture.py |
| `signal-unknown-event` | posture | medium | yes | evals/w223_set_probes.py, tests/test_posture.py |
| `signal-unknown-kind` | posture | medium | yes | evals/w223_set_probes.py, tests/test_posture.py |
| `signal-unverifiable` | posture | medium | yes | evals/w223_set_probes.py, evals/w224_agile_probes.py, tests/test_alg_registry.py (+1) |
| `signature-invalid` | authorization_receipt | high | yes | evals/w217_receipt_probes.py, evals/w232_dsse_probes.py, tests/test_authorization_receipts.py |
| `signed-receipt-malformed` | kms-signer | medium | yes | evals/w244_kms_signer_probes.py, tests/test_kms_signer.py |
| `signed-receipt-signature-invalid` | kms-signer | high | yes | evals/w244_kms_signer_probes.py, tests/test_kms_signer.py |
| `signer-adapter-tampered` | kms-signer | high | yes | evals/w244_kms_signer_probes.py, tests/test_kms_signer.py |
| `signer-denied` | c2pa | high | yes | evals/w215_c2pa24_probes.py, tests/test_c2pa24_conformance.py |
| `signer-digest-length-mismatch` | signer-interop | high | yes | evals/w243_cosign_interop_probes.py, evals/w244_treeship_advisory_probes.py, tests/test_signer_interop.py |
| `signer-error` | jail | medium | **NO** |  |
| `signer-hash-downshift-refused` | signer-interop | high | yes | evals/w243_cosign_interop_probes.py, evals/w244_treeship_advisory_probes.py, tests/test_signer_interop.py |
| `signer-identity-mismatch` | kms-signer | high | yes | evals/w244_kms_signer_probes.py, tests/test_kms_signer.py |
| `signer-key-material-in-process` | kms-signer | high | yes | evals/w244_kms_signer_probes.py, tests/test_kms_signer.py |
| `signer-unavailable` | kms-signer | medium | yes | evals/w244_kms_signer_probes.py, tests/test_kms_signer.py |
| `sigstore-keyed-envelope` | evbundle | medium | **NO** |  |
| `sigstore-keyed-hint-mismatch` | evbundle | medium | yes | evals/w321_sigstore_probes.py, evals/w322_redteam_probes.py, evals/w329_sigb_probes.py |
| `sigstore-keyed-keyid-mismatch` | evbundle | medium | yes | evals/w321_sigstore_probes.py, evals/w322_redteam_probes.py, evals/w329_sigb_probes.py |
| `sigstore-keyed-malformed` | evbundle | medium | **NO** |  |
| `sigstore-keyed-media-type` | evbundle | medium | yes | evals/w321_sigstore_probes.py, evals/w322_redteam_probes.py |
| `sigstore-keyed-message-signature-unexpected` | evbundle | medium | yes | evals/w321_sigstore_probes.py, evals/w322_redteam_probes.py, tests/test_sigstore_bundle.py |
| `sigstore-keyed-multi-signature` | evbundle | medium | yes | evals/w321_sigstore_probes.py, evals/w322_redteam_probes.py, tests/test_sigstore_bundle.py |
| `sigstore-keyed-payload-type` | evbundle | medium | yes | evals/w322_redteam_probes.py |
| `sigstore-keyed-signature-invalid` | evbundle | medium | yes | evals/w321_sigstore_probes.py, evals/w322_redteam_probes.py, evals/w329_sigb_probes.py (+1) |
| `sigstore-keyed-subject-mismatch` | evbundle | medium | yes | evals/w321_sigstore_probes.py, evals/w322_redteam_probes.py, tests/test_sigstore_bundle.py |
| `sigstore-keyed-timestamp-unexpected` | evbundle | medium | yes | evals/w321_sigstore_probes.py, evals/w322_redteam_probes.py |
| `sigstore-keyed-tlog-unexpected` | evbundle | medium | yes | evals/w321_sigstore_probes.py, evals/w322_redteam_probes.py |
| `sigstore-keyed-verification-material` | evbundle | medium | yes | evals/w321_sigstore_probes.py, evals/w322_redteam_probes.py |
| `single-use-issuer-revoked` | single_use | high | yes | evals/w226_singleuse_probes.py, tests/test_single_use.py |
| `single-use-lifecycle-refused` | single_use | medium | yes | evals/w229_reconcile_probes.py, tests/test_single_use_lifecycle.py |
| `single-use-malformed` | single_use | medium | yes | evals/w226_singleuse_probes.py, evals/w229_reconcile_probes.py, evals/w234_consumed_probes.py (+2) |
| `single-use-not-reserved` | single_use | high | yes | evals/w229_reconcile_probes.py, tests/test_single_use_lifecycle.py |
| `single-use-reconcile-replayed` | single_use | high | yes | evals/w229_reconcile_probes.py, tests/test_single_use_lifecycle.py |
| `single-use-refused` | single_use | medium | **NO** |  |
| `single-use-replay-refused` | single_use | high | yes | evals/w226_singleuse_probes.py, evals/w228_codes_probes.py, tests/test_consumption_ledger.py (+1) |
| `single-use-reservation-mismatch` | single_use | high | yes | evals/w229_reconcile_probes.py, tests/test_single_use_lifecycle.py |
| `single-use-reservation-unknown` | single_use | high | yes | evals/w229_reconcile_probes.py, tests/test_single_use_lifecycle.py |
| `single-use-reserve-conflict` | single_use | high | yes | evals/w229_reconcile_probes.py, tests/test_single_use_lifecycle.py |
| `single-use-unknown` | single_use | medium | yes | evals/w226_singleuse_probes.py, evals/w234_consumed_probes.py, tests/test_single_use.py |
| `skill-admission-artifact-rule-violated` | skill-admission | high | yes | evals/w248_skill_admission_probes.py |
| `skill-admission-authority-is-step-signer` | skill-admission | high | yes | evals/w248_skill_admission_probes.py |
| `skill-admission-command-mismatch` | skill-admission | high | yes | evals/w248_skill_admission_probes.py, evals/w249_redteam_probes.py |
| `skill-admission-layout-malformed` | skill-admission | medium | yes | evals/w248_skill_admission_probes.py |
| `skill-admission-layout-signature-invalid` | skill-admission | high | yes | evals/w248_skill_admission_probes.py, evals/w249_redteam_probes.py |
| `skill-admission-link-malformed` | skill-admission | medium | yes | evals/w248_skill_admission_probes.py |
| `skill-admission-link-missing` | skill-admission | medium | yes | evals/w248_skill_admission_probes.py |
| `skill-admission-link-signature-invalid` | skill-admission | high | yes | evals/w248_skill_admission_probes.py |
| `skill-admission-unauthorized-signer` | skill-admission | high | yes | evals/w248_skill_admission_probes.py |
| `skill-id-mismatch` | capability | high | yes | tests/test_capability_manifests.py |
| `skill-update-digest-changed` | skill-update | medium | yes | evals/w248_skill_update_probes.py, evals/w250_f211_closure_probes.py, evals/w251_redteam_probes.py (+1) |
| `skill-update-digest-mismatch` | skill-update | high | yes | evals/w248_skill_update_probes.py, tests/test_skill_update.py |
| `skill-update-index-untrusted` | skill-update | high | yes | evals/w248_skill_update_probes.py, tests/test_skill_update.py, tests/test_wiring.py |
| `skill-update-malformed` | skill-update | medium | yes | evals/w248_skill_update_probes.py, evals/w250_f211_closure_probes.py, evals/w251_redteam_probes.py (+1) |
| `skill-update-metadata-expired` | skill-update | high | yes | evals/w248_skill_update_probes.py, evals/w249_redteam_probes.py, tests/test_skill_update.py |
| `skill-update-record-unpinned` | skill-update | high | yes | evals/w248_skill_update_probes.py, tests/test_skill_update.py |
| `skill-update-version-rollback` | skill-update | high | yes | evals/w248_skill_update_probes.py, evals/w249_redteam_probes.py, tests/test_skill_update.py |
| `skill_not_found` | load_gate | medium | yes | tests/test_w80_loadgate_forced.py |
| `spawn-context-declared-risk` | spawn-context | low | yes | evals/w245_spawn_context_probes.py, tests/test_spawn_context_guard.py |
| `spawn-context-record-malformed` | spawn-context | medium | yes | evals/w245_spawn_context_probes.py, tests/test_spawn_context_guard.py |
| `spawn_failed` | platform | medium | **NO** |  |
| `spiffe-audience-mismatch` | spiffe | high | yes | evals/w232_spiffe_probes.py, tests/test_spiffe_credential_provider.py |
| `spiffe-auth-refused` | spiffe | high | yes | evals/w232_spiffe_probes.py, tests/test_spiffe_credential_provider.py |
| `spiffe-permission-invalid` | spiffe | high | yes | evals/w232_spiffe_probes.py, tests/test_spiffe_credential_provider.py |
| `spiffe-refused` | spiffe | medium | **NO** |  |
| `spiffe-svid-expired` | spiffe | medium | yes | evals/w232_spiffe_probes.py, tests/test_spiffe_credential_provider.py |
| `spiffe-svid-malformed` | spiffe | medium | yes | evals/w232_spiffe_probes.py, tests/test_spiffe_credential_provider.py |
| `spiffe-svid-unavailable` | spiffe | medium | yes | evals/w232_spiffe_probes.py, tests/test_spiffe_credential_provider.py |
| `stale-authority` | authority | high | yes | evals/w242_stale_authority_probes.py, evals/w243_finality_bound_probes.py, evals/w243_verifier_failclosed_probes.py (+6) |
| `stale-authority-malformed` | authority | medium | yes | evals/w242_stale_authority_probes.py, tests/test_wave242_containment.py |
| `stale-trust` | agent_card | medium | yes | evals/a2a_card_verifier_probes.py |
| `stale_seq` | drift | medium | yes | tests/test_drift_budget.py |
| `stale_sequence` | identity | medium | yes | evals/f152_hunt_break.py, evals/identity_covert_break.py |
| `statement-too-large` | scitt | medium | yes | tests/test_scitt_receipt.py |
| `store_lock_unavailable` | approval | medium | **NO** |  |
| `sub_threshold` | drift | medium | yes | tests/test_drift_budget.py |
| `subject-denied` | scitt | high | yes | tests/test_scitt_receipt.py |
| `subject-not-allowlisted` | scitt | medium | **NO** |  |
| `subject-unanchored` | mcp | medium | **NO** |  |
| `subject_claims` | vc | medium | **NO** |  |
| `supervision-capability-rights-exceeded` | supervision | high | yes | evals/w299_capability_manifest_probes.py, evals/w300_redteam_probes.py, tests/test_supervision_capabilities.py |
| `supervision-capability-route-violation` | supervision | high | yes | evals/w299_capability_manifest_probes.py, evals/w300_redteam_probes.py, tests/test_supervision_capabilities.py |
| `supervision-capability-undeclared` | supervision | medium | yes | evals/w299_capability_manifest_probes.py, evals/w300_redteam_probes.py, tests/test_supervision_capabilities.py |
| `supervision-crash-loop` | supervision | medium | yes | evals/w297_supervision_probes.py, tests/test_supervision.py |
| `supervision-intensity-exceeded` | supervision | medium | yes | evals/w297_supervision_probes.py, evals/w298_redteam_probes.py, tests/test_supervision.py |
| `supervision-invalid` | supervision | low | yes | evals/w297_supervision_probes.py, evals/w298_supervision_lease_probes.py, evals/w299_capability_manifest_probes.py (+4) |
| `supervision-lease-obligation-expired` | supervision | medium | yes | evals/w298_supervision_lease_probes.py, tests/test_supervision_lease.py |
| `supervision-undeclared-child` | supervision | medium | yes | evals/w297_supervision_probes.py, evals/w299_capability_manifest_probes.py, evals/w300_redteam_probes.py (+2) |
| `supplychain-delegation-path-unauthorized` | supplychain | high | yes | evals/w267_suppchain_probes.py |
| `supplychain-delegation-revoked` | supplychain | high | yes | evals/w267_suppchain_probes.py, evals/w268_redteam_probes.py, evals/w326_sched_probes.py (+1) |
| `supplychain-delegation-signature-invalid` | supplychain | high | yes | evals/w267_suppchain_probes.py, evals/w268_redteam_probes.py, evals/w326_redteam_probes.py (+2) |
| `supplychain-eval-start-invalid` | supplychain | medium | yes | evals/w267_suppchain_probes.py, tests/test_skill_supply_chain.py |
| `supplychain-feed-outside-trust-boundary` | supplychain | medium | yes | evals/w326_standing_probes.py, evals/w327_redteam_probes.py, tests/test_standing_verdicts.py |
| `supplychain-frozen` | supplychain | high | yes | evals/w267_suppchain_probes.py, evals/w268_redteam_probes.py, tests/test_skill_supply_chain.py |
| `supplychain-layout-expired` | supplychain | high | yes | evals/w267_suppchain_probes.py |
| `supplychain-layout-signature-invalid` | supplychain | high | yes | evals/w267_suppchain_probes.py |
| `supplychain-link-chain-broken` | supplychain | high | yes | evals/w267_suppchain_probes.py, evals/w268_redteam_probes.py |
| `supplychain-link-unauthorized` | supplychain | high | yes | evals/w267_suppchain_probes.py |
| `supplychain-malformed` | supplychain | medium | yes | evals/w267_suppchain_probes.py, evals/w268_redteam_probes.py, tests/test_skill_supply_chain.py |
| `supplychain-rollback` | supplychain | high | yes | evals/w267_suppchain_probes.py, evals/w326_redteam_probes.py, tests/test_skill_supply_chain.py |
| `supplychain-scan-already-registered` | supplychain | medium | yes | evals/w328_resid_probes.py, evals/w329_redteam_probes.py, tests/test_background_scan.py (+1) |
| `supplychain-scan-content-mismatch` | supplychain | high | yes | evals/w326_sched_probes.py |
| `supplychain-scan-crash-recovered` | supplychain | medium | yes | evals/w326_sched_probes.py, evals/w327_redteam_probes.py |
| `supplychain-scan-malformed` | supplychain | medium | yes | evals/w326_sched_probes.py, evals/w328_resid_probes.py, tests/test_background_scan.py (+1) |
| `supplychain-scan-missed-interval` | supplychain | medium | yes | evals/w326_sched_probes.py, tests/test_residual_hardening_w328.py |
| `supplychain-scan-state-corrupt` | supplychain | medium | yes | evals/w326_sched_probes.py, evals/w327_redteam_probes.py, tests/test_background_scan.py |
| `supplychain-scan-state-missing` | supplychain | medium | yes | evals/w326_sched_probes.py |
| `supplychain-snapshot-mismatch` | supplychain | high | yes | evals/w267_suppchain_probes.py, tests/test_skill_supply_chain.py |
| `supplychain-standing-conflict` | supplychain | medium | yes | evals/w326_standing_probes.py, evals/w327_redteam_probes.py, evals/w328_redteam_probes.py (+2) |
| `supplychain-standing-flip-unauthenticated` | supplychain | high | yes | evals/w326_standing_probes.py, evals/w327_redteam_probes.py, tests/test_standing_verdicts.py |
| `supplychain-standing-flip-unjustified` | supplychain | medium | yes | evals/w326_standing_probes.py, evals/w327_redteam_probes.py, tests/test_standing_verdicts.py |
| `supplychain-standing-history-rewrite` | supplychain | medium | yes | evals/w326_standing_probes.py, evals/w327_redteam_probes.py, tests/test_standing_verdicts.py |
| `supplychain-standing-journal-corrupt` | supplychain | medium | yes | evals/w329_redteam_probes.py, tests/test_standing_verdicts.py |
| `supplychain-standing-knowledge-unattached` | supplychain | low | yes | evals/w326_standing_probes.py, tests/test_standing_verdicts.py |
| `supplychain-standing-lapsed` | supplychain | high | yes | evals/w326_sched_probes.py, evals/w327_redteam_probes.py, tests/test_background_scan.py |
| `supplychain-standing-schema-unknown` | supplychain | low | yes | evals/w326_standing_probes.py, evals/w327_redteam_probes.py, tests/test_standing_verdicts.py |
| `supplychain-transition-rules-failed` | supplychain | high | yes | evals/w267_suppchain_probes.py, evals/w326_redteam_probes.py, tests/test_skill_supply_chain.py |
| `surface-admin-unauthenticated` | mcp-surface | high | yes | evals/w244_surface_defaults_probes.py, tests/test_surface_defaults.py |
| `surface-attestation-key-missing` | mcp-surface | medium | yes | tests/test_surface_defaults.py |
| `surface-config-malformed` | mcp-surface | medium | yes | tests/test_surface_defaults.py |
| `surface-default-credentials` | mcp-surface | high | yes | evals/w244_surface_defaults_probes.py, tests/test_surface_defaults.py |
| `surface-public-unguarded` | mcp-surface | high | yes | evals/w244_surface_defaults_probes.py, tests/test_surface_defaults.py |
| `surface-transport-bypass` | mcp-surface | high | yes | evals/w244_surface_defaults_probes.py, tests/test_surface_defaults.py |
| `svid-acl-denied` | svid | medium | yes | evals/w259_identity_probes.py, evals/w260_identity2_probes.py, tests/test_mesh_admission.py (+1) |
| `svid-enrollment-key-expired` | svid | medium | yes | evals/w260_identity2_probes.py, tests/test_svid_enrollment.py |
| `svid-enrollment-key-replayed` | svid | high | yes | evals/w260_identity2_probes.py, evals/w262_enrollment2_probes.py, tests/test_svid_enrollment.py |
| `svid-enrollment-key-unknown` | svid | medium | yes | evals/w260_identity2_probes.py, tests/test_svid_enrollment.py |
| `svid-enrollment-spiffe-mismatch` | svid | medium | yes | evals/w260_identity2_probes.py, tests/test_svid_enrollment.py |
| `svid-expired` | svid | medium | yes | evals/w259_identity_probes.py, tests/test_mesh_admission.py, tests/test_svid_issuer.py |
| `svid-identity-malformed` | svid | medium | yes | evals/w259_identity_probes.py, evals/w260_identity2_probes.py, tests/test_svid_enrollment.py (+1) |
| `svid-issuer-unknown` | svid | high | yes | evals/w259_identity_probes.py, evals/w264_federation_probes.py, tests/test_svid_issuer.py (+1) |
| `svid-malformed` | svid | medium | yes | evals/w259_identity_probes.py, evals/w264_federation_probes.py, tests/test_mesh_admission.py (+3) |
| `svid-missing` | svid | medium | yes | evals/w259_identity_probes.py, evals/w260_identity2_probes.py, tests/test_mesh_admission.py (+2) |
| `svid-signature-invalid` | svid | high | yes | evals/w259_identity_probes.py, evals/w260_identity2_probes.py, tests/test_mesh_admission.py (+2) |
| `svid-trust-domain-mismatch` | svid | high | yes | evals/w259_identity_probes.py, tests/test_svid_issuer.py |
| `svid-ttl-stretched` | svid | medium | yes | evals/w259_identity_probes.py, tests/test_svid_issuer.py |
| `svid-ttl-unbounded` | svid | medium | yes | evals/w259_identity_probes.py, tests/test_svid_issuer.py |
| `svid-usage-mismatch` | svid | medium | yes | tests/test_svid_issuer.py, tests/test_trust_federation.py |
| `svr-digest-malformed` | svr | medium | yes | evals/w227_escalate_probes.py, tests/test_escalation_svr.py |
| `svr-digest-mismatch` | svr | critical | yes | evals/w227_escalate_probes.py, tests/test_escalation_svr.py |
| `svr-malformed` | svr | medium | yes | tests/test_escalation_svr.py |
| `svr-no-reproduction-pointer` | svr | medium | yes | evals/w227_escalate_probes.py, evals/w228_codes_probes.py, tests/test_escalation_svr.py |
| `svr-not-authorization` | svr | high | yes | evals/w227_escalate_probes.py, tests/test_escalation_svr.py |
| `svr-pointer-malformed` | svr | medium | yes | evals/w227_escalate_probes.py, tests/test_escalation_svr.py |
| `svr-refused` | svr | medium | **NO** |  |
| `tainted_run` | memory | medium | yes | evals/adversarial_h17_tainted.py, evals/w228_codes_probes.py |
| `tamper` | approval | high | yes | evals/amsb_corpus.py, evals/amsb_harness.py, evals/display_exec_battery.py (+16) |
| `taxonomy-receipt-missing` | receipts | medium | yes | evals/w230_deny_probes.py, tests/test_deny_receipts.py |
| `terminal-transition-refused` | arap | medium | yes | evals/w218_arap_probes.py, tests/test_arap.py |
| `threshold-unmet` | quorum | medium | yes | evals/sign_deploy_namespace_probes.py, evals/tuf_corpus_probes.py, tests/test_audit_detect.py (+2) |
| `token-audience-mismatch` | token_hygiene | high | yes | evals/w234_tokenhygiene_probes.py, evals/w242_ir8587_conformance_probes.py, tests/test_token_hygiene.py |
| `token-audience-missing` | token_hygiene | medium | yes | evals/w234_tokenhygiene_probes.py, evals/w242_ir8587_conformance_probes.py, tests/test_token_hygiene.py |
| `token-expired` | token_hygiene | high | yes | evals/w234_tokenhygiene_probes.py, evals/w314_redteam_probes.py, tests/test_token_hygiene.py |
| `token-in-log` | token_hygiene | high | yes | evals/w234_tokenhygiene_probes.py, evals/w242_ir8587_conformance_probes.py, tests/test_token_hygiene.py |
| `token-key-stale` | token_hygiene | high | yes | evals/w234_tokenhygiene_probes.py, evals/w242_ir8587_conformance_probes.py, tests/test_token_hygiene.py |
| `token-malformed` | token_hygiene | medium | yes | tests/test_token_hygiene.py |
| `token-scope-exceeded` | token-scope | high | yes | evals/w244_token_scope_probes.py |
| `token-scope-unparseable` | token-scope | medium | yes | evals/w244_token_scope_probes.py, tests/test_token_scope_enforcement.py |
| `token-ttl-exceeded` | token_hygiene | high | yes | evals/w234_tokenhygiene_probes.py, evals/w242_ir8587_conformance_probes.py, tests/test_token_hygiene.py |
| `tool-budget-config-invalid` | velocity | medium | yes | evals/w337_ratelimit2_probes.py |
| `tool-budget-exhausted` | velocity | medium | yes | evals/w337_ratelimit2_probes.py, evals/w338_attack_probes.py, tests/test_tool_budget.py |
| `tool-budget-unavailable` | velocity | high | yes | evals/w337_ratelimit2_probes.py |
| `tool-crashed` | capability | medium | **NO** |  |
| `tool-definition-malformed` | mcp-surface | medium | yes | tests/test_wave243_effect_agreement.py |
| `tool-executable-content` | mcp-surface | high | yes | evals/w243_threat_model_probes.py, evals/w244_token_scope_probes.py, tests/test_wave243_effect_agreement.py |
| `tool-failed-no-commit` | capability | medium | yes | evals/capability_grant_probes.py |
| `tool-guardrail-tripwire` | guardrail | high | yes | evals/w279_triad_probes.py, evals/w281_f306_probes.py, tests/test_tool_guardrails.py |
| `tool-rate-limit-config-invalid` | velocity | medium | yes | evals/w335_ratelimit_probes.py, evals/w336_redteam_probes.py, evals/w337_redteam_probes.py |
| `tool-rate-limit-exceeded` | velocity | medium | yes | evals/w335_ratelimit_probes.py, evals/w336_attack_probes.py, evals/w336_redteam_probes.py (+3) |
| `tool-rate-limiter-unavailable` | velocity | high | yes | evals/w335_ratelimit_probes.py, evals/w336_redteam_probes.py, evals/w337_f424f425_probes.py (+1) |
| `tool-scope-undeclared` | token-scope | medium | yes | evals/w244_token_scope_probes.py |
| `tool-spawn-context-untrusted` | spawn-context | high | yes | evals/w245_spawn_context_probes.py, tests/test_spawn_context_guard.py |
| `tool-timed-out` | capability | medium | **NO** |  |
| `tool_ratings` | tool | medium | **NO** |  |
| `toolcall-audit-would-deny` | toolcall | low | yes | evals/w286_toolpolicy_probes.py, evals/w294_tool_schemas_probes.py, tests/test_tool_call_policy.py (+1) |
| `toolcall-budget-exhausted` | toolcall | medium | yes | evals/w294_filter_pipeline_probes.py, tests/test_invocation_pipeline.py |
| `toolcall-budget-reserve-invalid` | toolcall | low | yes | evals/w294_filter_pipeline_probes.py, evals/w297_redteam_probes.py, tests/test_invocation_pipeline.py |
| `toolcall-call-denied` | toolcall | medium | yes | evals/w286_toolpolicy_probes.py |
| `toolcall-caller-out-of-scope` | toolcall | medium | yes | evals/w286_toolpolicy_probes.py, tests/test_tool_call_policy.py |
| `toolcall-custom-denied` | toolcall | medium | yes | evals/w286_toolpolicy_probes.py, tests/test_tool_call_policy.py |
| `toolcall-exception-scope-mismatch` | toolcall | low | **NO** |  |
| `toolcall-exception-suppressed` | toolcall | low | yes | evals/w286_toolpolicy_probes.py, tests/test_tool_call_policy.py |
| `toolcall-filter-frozen` | toolcall | low | yes | evals/w294_filter_pipeline_probes.py, evals/w296_f368_probes.py, evals/w297_redteam_probes.py (+1) |
| `toolcall-invalid-call` | toolcall | low | yes | evals/w294_filter_pipeline_probes.py, evals/w297_redteam_probes.py, tests/test_invocation_pipeline.py |
| `toolcall-no-allow` | toolcall | medium | yes | evals/w286_toolpolicy_probes.py, tests/test_tool_call_policy.py |
| `toolcall-no-covering-exception` | toolcall | medium | yes | evals/w286_toolpolicy_probes.py, tests/test_tool_call_policy.py |
| `toolcall-policy-drift` | toolcall | high | yes | evals/w286_toolpolicy_probes.py, evals/w288_f340_f342_probes.py, tests/test_tool_call_policy.py |
| `toolcall-policy-invalid` | toolcall | medium | yes | evals/w286_toolpolicy_probes.py, tests/test_tool_call_policy.py |
| `toolcall-policy-unpinned` | toolcall | high | yes | evals/w286_toolpolicy_probes.py, tests/test_tool_call_policy.py |
| `toolcall-predicate-budget` | toolcall | medium | yes | evals/w295_predicates_probes.py, tests/test_rule_predicates.py |
| `toolcall-predicate-invalid` | toolcall | high | yes | evals/w295_predicates_probes.py, tests/test_rule_predicates.py |
| `toolcall-predicate-undeclared-field` | toolcall | high | yes | evals/w295_predicates_probes.py, tests/test_rule_predicates.py |
| `toolcall-regex-unsafe` | toolcall | medium | **NO** |  |
| `toolcall-rule-compile-invalid` | toolcall | high | yes | evals/w293_tool_rules_probes.py, evals/w294_filter_pipeline_probes.py, evals/w295_predicates_probes.py (+3) |
| `toolcall-schema-compile-invalid` | toolcall | high | yes | evals/w294_tool_schemas_probes.py, tests/test_tool_schemas.py |
| `toolcall-schema-invalid` | toolcall | high | yes | evals/w294_tool_schemas_probes.py, tests/test_tool_schemas.py |
| `toolcall-schema-secret-field` | toolcall | high | yes | evals/w294_tool_schemas_probes.py, evals/w296_f370_probes.py, tests/test_tool_schemas.py |
| `toolcall-schema-unknown-tool` | toolcall | high | yes | evals/w294_tool_schemas_probes.py, tests/test_tool_schemas.py |
| `toolcall-secret-in-args` | toolcall | high | yes | evals/w293_tool_rules_probes.py, evals/w294_filter_pipeline_probes.py, evals/w294_tool_schemas_probes.py (+3) |
| `toolcall-secret-scan-incomplete` | toolcall | high | yes | evals/w295_f365_probes.py |
| `toolcall-sequence-violated` | toolcall | high | yes | evals/w293_tool_rules_probes.py, evals/w294_filter_pipeline_probes.py, evals/w295_f365_probes.py (+4) |
| `toolcall-unauthenticated-caller` | toolcall | high | yes | evals/w286_toolpolicy_probes.py, evals/w297_redteam_probes.py, tests/test_tool_call_policy.py |
| `toolfilter-skip-denied` | toolcall | medium | yes | evals/w294_filter_pipeline_probes.py, evals/w297_redteam_probes.py, tests/test_invocation_pipeline.py |
| `transaction-expired` | transaction | medium | yes | evals/w243_transactional_tokens_probes.py, tests/test_token_scope_enforcement.py, tests/test_transactional_tokens.py |
| `transaction-id-mismatch` | transaction | high | yes | evals/w243_transactional_tokens_probes.py, tests/test_token_scope_enforcement.py, tests/test_transactional_tokens.py |
| `transaction-key-missing` | transaction | medium | yes | evals/w243_transactional_tokens_probes.py, tests/test_transactional_tokens.py |
| `transaction-malformed` | transaction | medium | yes | evals/w243_transactional_tokens_probes.py, tests/test_transactional_tokens.py |
| `transaction-signature-invalid` | transaction | critical | yes | evals/w243_transactional_tokens_probes.py, tests/test_transactional_tokens.py |
| `transform-capacity-exceeded` | transform | high | yes | evals/w316_transform_probes.py, evals/w317_redteam_probes.py, tests/test_transform_policy.py |
| `transform-contract-violated` | transform | high | yes | evals/w316_transform_probes.py, evals/w317_redteam_probes.py, tests/test_transform_policy.py |
| `transform-identity-mismatch` | transform | high | yes | evals/w316_transform_probes.py, tests/test_transform_policy.py |
| `transform-ledger-corrupt` | transform | high | yes | evals/w316_transform_probes.py, tests/test_transform_policy.py |
| `transform-model-lowering-refused` | transform | high | yes | evals/w316_transform_probes.py, evals/w317_redteam_probes.py, tests/test_transform_policy.py |
| `transform-registration-denylist-refused` | transform | medium | yes | evals/w316_transform_probes.py, tests/test_transform_policy.py |
| `transform-registration-duplicate` | transform | medium | yes | evals/w317_redteam_probes.py, tests/test_transform_policy.py |
| `transform-registration-marking-refused` | transform | medium | yes | evals/w316_transform_probes.py, evals/w317_redteam_probes.py, tests/test_transform_policy.py |
| `transform-registration-model-lowering-refused` | transform | medium | yes | tests/test_transform_policy.py |
| `transform-token-invalid` | transform | high | yes | evals/w316_transform_probes.py, evals/w317_redteam_probes.py, tests/test_transform_policy.py |
| `transform-token-replayed` | transform | high | yes | evals/w316_transform_probes.py, evals/w317_redteam_probes.py, tests/test_transform_policy.py |
| `transform-unregistered` | transform | medium | yes | evals/w316_transform_probes.py, evals/w317_redteam_probes.py, tests/test_transform_policy.py |
| `trust-class-unknown` | deploy | medium | yes | evals/deploy_trust_probes.py |
| `trust-key-repointed` | trust | high | yes | evals/w235_trustmat_probes.py, tests/test_trust_material.py |
| `trust-material-malformed` | trust | low | yes | evals/w235_trustmat_probes.py, tests/test_trust_material.py |
| `trust-root-chain-malformed` | evidence | medium | yes | tests/test_trust_root_refresh.py |
| `trust-root-expired` | evidence | medium | yes | evals/w318_trustroot_probes.py, evals/w319_redteam_probes.py, tests/test_trust_root_refresh.py |
| `trust-root-receipt-unbound` | evidence | medium | yes | tests/test_trust_root_refresh.py |
| `trust-root-revoked` | deploy | high | yes | evals/deploy_trust_probes.py |
| `trust-root-rotation-invalid` | evidence | medium | yes | evals/w319_redteam_probes.py, tests/test_trust_root_refresh.py |
| `trust-root-silent-swap` | evidence | medium | yes | evals/w318_trustroot_probes.py, evals/w319_redteam_probes.py, tests/test_trust_root_refresh.py |
| `trust-root-stale-freshness` | evidence | medium | yes | evals/w318_trustroot_probes.py, evals/w319_redteam_probes.py, tests/test_trust_root_refresh.py |
| `trust-root-unknown` | deploy | medium | yes | evals/deploy_trust_probes.py, tests/test_deploy_trust_config.py |
| `trust-threshold-unmet` | deploy | medium | yes | tests/test_deploy_trust_config.py |
| `trustvec-appraisal-contraindicated` | trustvec | high | yes | evals/w287_ear_probes.py |
| `trustvec-appraisal-insufficient` | trustvec | medium | yes | evals/w287_ear_probes.py |
| `trustvec-endorsement-not-independent` | trustvec | medium | yes | evals/w287_ear_probes.py, evals/w290_redteam_probes.py |
| `trustvec-evidence-invalid` | trustvec | medium | yes | evals/w287_ear_probes.py, evals/w289_f344_f345_probes.py, evals/w290_redteam_probes.py |
| `trustvec-no-covering-exception` | trustvec | medium | yes | evals/w287_ear_probes.py |
| `trustvec-policy-drift` | trustvec | high | yes | evals/w287_ear_probes.py |
| `trustvec-policy-invalid` | trustvec | medium | yes | evals/w290_redteam_probes.py |
| `trustvec-policy-unpinned` | trustvec | high | yes | evals/w287_ear_probes.py |
| `trustvec-scheme-duplicate` | trustvec | low | yes | evals/w287_ear_probes.py |
| `trustvec-scheme-unknown` | trustvec | medium | yes | evals/w287_ear_probes.py |
| `tsa-gentime-backdated` | tsa | high | yes | evals/w287_tsa_probes.py, tests/test_tsa_checkpoints.py |
| `tsa-gentime-in-future` | tsa | medium | yes | evals/w287_tsa_probes.py, tests/test_tsa_checkpoints.py |
| `tsa-gentime-invalid` | tsa | medium | yes | evals/w287_tsa_probes.py, tests/test_tsa_checkpoints.py |
| `tsa-imprint-mismatch` | tsa | high | yes | evals/w287_tsa_probes.py, tests/test_tsa_checkpoints.py |
| `tsa-nonce-mismatch` | tsa | medium | yes | evals/w287_tsa_probes.py, tests/test_tsa_checkpoints.py |
| `tsa-signature-invalid` | tsa | high | yes | evals/w287_tsa_probes.py, tests/test_tsa_checkpoints.py |
| `tsa-token-malformed` | tsa | medium | yes | evals/w287_tsa_probes.py, tests/test_tsa_checkpoints.py |
| `ttl_extended` | approval | medium | yes | tests/test_delegation_primitive.py |
| `ttl_out_of_range` | approval | medium | **NO** |  |
| `typed-action-malformed` | typed_action | medium | yes | tests/test_typed_actions.py |
| `typed-action-not-bound` | typed_action | medium | yes | evals/w228_typed_probes.py, tests/test_typed_actions.py |
| `typed-action-refused` | typed_action | medium | **NO** |  |
| `typed-context` | context | medium | **NO** |  |
| `unbound-grant-label` | capability | medium | yes | evals/capability_grant_probes.py |
| `undeclared_credential_in_scope` | credential | high | yes | evals/w40_probes.py, evals/w42_probes.py, tests/test_f111_credential_manifest.py (+1) |
| `unexpected-participant-signed` | participants | high | yes | evals/w241_probe_classes_probes.py, tests/test_wave241_probe_classes.py |
| `unknown-action-label` | c2pa | medium | yes | evals/w215_c2pa24_probes.py, tests/test_c2pa24_conformance.py |
| `unknown-assertion-label` | c2pa | medium | yes | evals/w215_c2pa24_probes.py, tests/test_c2pa24_conformance.py |
| `unknown-bundle` | namespace | medium | yes | evals/sign_deploy_namespace_probes.py, evals/w213b_promotion_gate_probes.py, tests/test_admit_deploy_wiring.py (+2) |
| `unknown-grant` | authorization_receipt | medium | yes | evals/w217_receipt_probes.py, tests/test_authorization_receipts.py |
| `unknown-grant-id` | capability | medium | **NO** |  |
| `unknown-kid` | capability | high | yes | tests/test_capability_manifests.py |
| `unknown-manifest-category` | capability | medium | **NO** |  |
| `unknown_agent` | discovery | medium | yes | tests/test_discovery_diff.py |
| `unknown_approval` | approval | medium | **NO** |  |
| `unknown_delegatee_agent` | approval | high | **NO** |  |
| `unknown_grant` | approval | medium | yes | evals/w42_probes.py, tests/test_delegation_executor_wiring.py, tests/test_delegation_primitive.py |
| `unknown_issuer` | lease | medium | yes | evals/w78_probes.py, tests/test_w78_supplychain.py |
| `unknown_parent` | approval | medium | **NO** |  |
| `unpin_version_not_monotonic` | load_gate | medium | yes | evals/tuf_load_seam_probes.py, tests/test_w194_tuf_load_seam.py |
| `unregistered_agent` | discovery | medium | yes | tests/test_discovery.py, tests/test_discovery_diff.py |
| `unregistered_delegatee` | approval | high | yes | tests/test_approvals_d1.py |
| `unresolvable_mode` | deployment | medium | **NO** |  |
| `unsigned-field-ignored` | trust | high | yes | evals/w235_trustmat_probes.py, tests/test_trust_material.py |
| `unsigned-refused` | signature | high | yes | evals/deploy_trust_probes.py, evals/sign_deploy_namespace_probes.py, evals/w213b_promotion_gate_probes.py (+3) |
| `unsupported-alg` | alg | medium | yes | evals/a2a_card_verifier_probes.py, evals/w246_jwt_alg_confusion_probes.py, tests/test_capability_manifests.py |
| `unsupported-correlation` | audit | medium | yes | evals/sigma_detection_probes.py, tests/test_audit_detect.py |
| `untrusted-jku` | agent_card | high | yes | evals/a2a_card_verifier_probes.py, evals/w214_agentcard_probes.py |
| `untrusted-key` | trust | high | yes | evals/w235_trustmat_probes.py, evals/w338_honesty_probes.py, tests/test_close_signer_binding.py (+1) |
| `untrusted-render-error` | render | medium | **NO** |  |
| `untrusted-signer` | c2pa | high | yes | evals/w215_c2pa24_probes.py, tests/test_c2pa24_conformance.py |
| `untrusted_tier` | memory | medium | yes | evals/memory_inbox_battery.py, evals/w228_codes_probes.py, tests/test_memory_inbox.py |
| `upload_failed` | platform | medium | yes | evals/w35_probes.py, tests/test_f110_platform_egress.py |
| `uri-host-invalid` | uri-normalize | high | yes | evals/w247_uri_normalize_probes.py, tests/test_uri_normalize.py |
| `uri-host-unparseable` | uri-normalize | high | yes | evals/w247_uri_normalize_probes.py, tests/test_uri_normalize.py |
| `verifier-input-malformed` | authority | medium | yes | evals/w243_verifier_failclosed_probes.py, evals/w245_registry_adversary_probes.py, tests/test_advisory_binding.py (+3) |
| `verifier-malformed` | authorization_receipt | medium | **NO** |  |
| `verify-artifactsfrom-empty` | verify | high | yes | evals/w238_bundle_verify_probes.py, tests/test_bundle_verify_invariant.py |
| `verify-attestor-shadowed` | verify | high | yes | evals/w238_bundle_verify_probes.py, tests/test_bundle_verify_invariant.py |
| `verify-collection-empty-match` | verify | high | yes | evals/w238_bundle_verify_probes.py, tests/test_bundle_verify_invariant.py |
| `verify-hash-downgrade` | verify | high | yes | evals/w238_bundle_verify_probes.py, tests/test_bundle_verify_invariant.py |
| `verify-no-clean-verifier` | verify | high | yes | tests/test_bundle_verify_invariant.py |
| `verify-signature-failed` | verify | critical | yes | evals/w238_bundle_verify_probes.py, tests/test_bundle_verify_invariant.py |
| `verify-symlink-escape` | verify | high | yes | evals/w238_bundle_verify_probes.py, tests/test_bundle_verify_invariant.py |
| `verify-timestamp-eku-missing` | verify | high | yes | evals/w238_bundle_verify_probes.py, tests/test_bundle_verify_invariant.py |
| `verpol-attestation-missing` | verpol | high | yes | evals/w267_verpol_probes.py |
| `verpol-attestation-policy-failed` | verpol | high | yes | evals/w267_verpol_probes.py, evals/w268_redteam_probes.py |
| `verpol-log-not-anchored` | verpol | high | yes | evals/w267_verpol_probes.py, tests/test_verification_policy.py |
| `verpol-malformed-policy` | verpol | high | yes | evals/w267_verpol_probes.py, tests/test_verification_policy.py |
| `verpol-no-authority-matched` | verpol | high | yes | evals/w267_verpol_probes.py |
| `verpol-no-match` | verpol | high | yes | evals/w267_verpol_probes.py, evals/w268_redteam_probes.py, tests/test_verification_policy.py |
| `verpol-packet-invalid` | verpol | high | yes | evals/w267_verpol_probes.py |
| `verpol-policy-failed` | verpol | high | yes | evals/w267_verpol_probes.py, evals/w268_redteam_probes.py |
| `verpol-uncheckable` | verpol | medium | **NO** |  |
| `vote_already_cast` | approval | medium | yes | tests/test_approvals_d1.py |
| `vsa-packet-levels-missing` | vsa | medium | yes | evals/w315_vsa_probes.py, evals/w324_vsa_probes.py, tests/test_vsa_packet.py |
| `vsa-packet-malformed` | vsa | medium | yes | evals/w315_vsa_probes.py, evals/w316_redteam_probes.py, evals/w324_vsa_probes.py (+2) |
| `vsa-packet-predicate-mismatch` | vsa | medium | yes | evals/w315_vsa_probes.py |
| `vsa-packet-resource-mismatch` | vsa | medium | yes | evals/w315_vsa_probes.py, evals/w316_redteam_probes.py, tests/test_vsa_packet.py |
| `vsa-packet-result-not-passed` | vsa | medium | yes | evals/w315_vsa_probes.py, evals/w316_redteam_probes.py |
| `vsa-packet-signature-invalid` | vsa | critical | yes | evals/w315_vsa_probes.py, evals/w316_redteam_probes.py |
| `vsa-packet-signer-unpinned` | vsa | high | yes | evals/w315_vsa_probes.py, tests/test_vsa_packet.py |
| `vsa-packet-subject-mismatch` | vsa | high | yes | evals/w315_vsa_probes.py, evals/w316_redteam_probes.py, evals/w324_vsa_probes.py (+1) |
| `vsa-packet-verifier-mismatch` | vsa | high | yes | evals/w315_vsa_probes.py, evals/w316_redteam_probes.py, tests/test_vsa_packet.py |
| `vsa-packet-window-invalid` | vsa | medium | yes | evals/w315_vsa_probes.py, evals/w316_redteam_probes.py, evals/w324_vsa_probes.py (+2) |
| `vsa-threshold-below-quorum` | vsa | medium | yes | evals/w324_vsa_probes.py, tests/test_vsa_threshold.py |
| `vsa-threshold-policy-stale` | vsa | medium | yes | evals/w324_vsa_probes.py, evals/w325_redteam_probes.py |
| `vsa-threshold-signature-invalid` | vsa | high | yes | evals/w324_vsa_probes.py, evals/w325_redteam_probes.py, tests/test_vsa_threshold.py |
| `vsa-threshold-signer-unpinned` | vsa | medium | yes | evals/w324_vsa_probes.py, evals/w325_redteam_probes.py, tests/test_vsa_threshold.py |
| `vsa-threshold-verdict-not-passed` | vsa | medium | yes | evals/w324_vsa_probes.py |
| `wall_proof_unreadable` | platform | high | **NO** |  |
| `wiring-malformed` | jail | medium | **NO** |  |
| `wiring-unmapped-mount` | jail | medium | yes | evals/w216_jail_policy_probes.py, tests/test_jail_policy.py |
| `witness-alert-queue-overflow` | witness | medium | yes | evals/w325_resid_probes.py, tests/test_monitor_alert.py |
| `witness-alert-state-lost` | witness | medium | **NO** |  |
| `witness-alert-wrapper-error` | witness | medium | yes | evals/w324_alert_probes.py, evals/w325_redteam_probes.py, evals/w325_resid_probes.py (+1) |
| `witness-checkpoint-stale` | witness | medium | yes | evals/w319_witness_probes.py, evals/w320_redteam_probes.py, evals/w322_witpub_probes.py (+4) |
| `witness-checkpoint-unknown-origin` | witness | medium | yes | evals/w322_witpub_probes.py, evals/w323_monitor_probes.py, evals/w323_redteam_probes.py (+2) |
| `witness-config-cwd-autoload` | witness | critical | yes | evals/w240_witness_config_probes.py, tests/test_witness_config_rule.py |
| `witness-config-filter-downgrade` | witness | high | yes | evals/w240_witness_config_probes.py, tests/test_witness_config_rule.py |
| `witness-config-upload-ungated` | witness | high | yes | evals/w240_witness_config_probes.py, tests/test_witness_config_rule.py |
| `witness-consistency-fork-detected` | witness | high | yes | evals/w319_witness_probes.py, evals/w320_redteam_probes.py, evals/w322_witpub_probes.py (+4) |
| `witness-consistency-invalid` | witness | medium | yes | evals/w319_witness_probes.py, evals/w322_witpub_probes.py, evals/w323_monitor_probes.py (+2) |
| `witness-consistency-missing` | witness | medium | yes | evals/w319_witness_probes.py, tests/test_witness_consistency.py |
| `witness-cosignature-invalid` | witness | medium | yes | evals/w319_witness_probes.py, evals/w322_witpub_probes.py, evals/w323_redteam_probes.py (+3) |
| `witness-daemon-state-failed` | witness | high | yes | evals/w339_witness_probes.py, tests/test_witness_daemon.py |
| `witness-gossip-conflict` | witness | high | yes | evals/w319_witness_probes.py, evals/w320_redteam_probes.py |
| `witness-intermediates-missing` | witness | high | yes | evals/w240_witness_config_probes.py, tests/test_witness_config_rule.py |
| `witness-log-checkpoint-malformed` | witness | medium | yes | tests/test_witness_log.py |
| `witness-log-checkpoint-signature-invalid` | witness | medium | yes | evals/w312_witness_log_probes.py, tests/test_witness_log.py |
| `witness-log-consistency-invalid` | witness | medium | yes | evals/w312_witness_log_probes.py, evals/w314_redteam_probes.py, evals/w323_monitor_probes.py (+2) |
| `witness-log-empty` | witness | medium | yes | tests/test_witness_log.py |
| `witness-log-inclusion-invalid` | witness | medium | yes | evals/w312_witness_log_probes.py, evals/w314_redteam_probes.py, tests/test_witness_log.py |
| `witness-log-index-out-of-range` | witness | medium | **NO** |  |
| `witness-log-key-mismatch` | witness | medium | yes | evals/w312_witness_log_probes.py, tests/test_witness_log.py |
| `witness-log-malformed` | witness | medium | yes | evals/w314_redteam_probes.py, evals/w324_redteam_probes.py, tests/test_witness_log.py |
| `witness-monitor-fetch-failed` | witness | medium | yes | evals/w323_monitor_probes.py, evals/w324_alert_probes.py, tests/test_witness_monitor.py |
| `witness-monitor-stale` | witness | medium | yes | evals/w323_monitor_probes.py, evals/w324_redteam_probes.py, tests/test_monitor_alert.py (+1) |
| `witness-monitor-state-corrupt` | witness | high | yes | evals/w323_monitor_probes.py, evals/w324_redteam_probes.py, tests/test_witness_monitor.py |
| `witness-monitor-state-mismatch` | witness | high | yes | evals/w323_monitor_probes.py, tests/test_witness_monitor.py |
| `witness-monitor-state-missing` | witness | high | yes | evals/w323_monitor_probes.py, evals/w324_redteam_probes.py, tests/test_witness_monitor.py |
| `witness-note-malformed` | witness | medium | yes | evals/w322_witpub_probes.py, evals/w323_redteam_probes.py, tests/test_witness_daemon.py (+1) |
| `witness-policy-dual-threshold-unmet` | witness | high | yes | evals/w339_witness_probes.py, tests/test_witness_daemon.py |
| `witness-policy-duplicate-witness` | witness | medium | yes | evals/w322_witpol_probes.py, evals/w323_redteam_probes.py, tests/test_witness_policy.py |
| `witness-policy-expired` | witness | medium | yes | evals/w322_witpol_probes.py |
| `witness-policy-id-mismatch` | witness | medium | yes | evals/w322_witpol_probes.py, evals/w323_monitor_probes.py, evals/w323_redteam_probes.py (+1) |
| `witness-policy-key-unverifiable` | witness | medium | yes | evals/w322_witpol_probes.py |
| `witness-policy-malformed` | witness | medium | yes | evals/w323_monitor_probes.py, evals/w324_redteam_probes.py, tests/test_witness_consistency.py (+1) |
| `witness-policy-signature-invalid` | witness | medium | yes | evals/w322_witpol_probes.py, evals/w323_redteam_probes.py, tests/test_witness_daemon.py (+1) |
| `witness-policy-threshold-invalid` | witness | medium | yes | evals/w322_witpol_probes.py, tests/test_witness_policy.py |
| `witness-policy-threshold-unmet` | witness | medium | yes | evals/w322_witpol_probes.py, evals/w323_redteam_probes.py, tests/test_witness_policy.py |
| `witness-policy-unknown-field` | witness | medium | yes | evals/w322_witpol_probes.py, evals/w323_redteam_probes.py, evals/w325_resid_probes.py (+1) |
| `witness-policy-version-rollback` | witness | medium | yes | evals/w322_witpol_probes.py, evals/w323_monitor_probes.py, evals/w323_redteam_probes.py (+2) |
| `witness-publish-quorum-unmet` | witness | medium | yes | evals/w322_witpub_probes.py, evals/w323_redteam_probes.py, evals/w339_witness_probes.py (+2) |
| `witness-publish-rollback` | witness | high | yes | evals/w322_witpub_probes.py, evals/w323_monitor_probes.py, evals/w323_redteam_probes.py (+2) |
| `witness-quorum-unmet` | witness | medium | yes | evals/w319_witness_probes.py, evals/w320_redteam_probes.py, evals/w322_witpub_probes.py (+4) |
| `witness-rekor-anchor-expired` | witness | medium | yes | evals/w314_rekor_probes.py, evals/w315_redteam_probes.py, tests/test_witness_rekor.py |
| `witness-rekor-anchor-missing` | witness | medium | yes | evals/w314_rekor_probes.py, tests/test_witness_rekor.py |
| `witness-rekor-checkpoint-invalid` | witness | critical | yes | evals/w314_rekor_probes.py, evals/w315_redteam_probes.py, tests/test_witness_rekor.py |
| `witness-rekor-digest-mismatch` | witness | critical | yes | evals/w314_rekor_probes.py, evals/w315_redteam_probes.py, tests/test_witness_rekor.py |
| `witness-rekor-inclusion-invalid` | witness | critical | yes | evals/w314_rekor_probes.py, evals/w315_redteam_probes.py, tests/test_witness_rekor.py |
| `witness-rekor-malformed` | witness | medium | yes | evals/w315_redteam_probes.py, tests/test_witness_rekor.py |
| `witness-unreachable` | witness | medium | yes | evals/w319_witness_probes.py, evals/w320_redteam_probes.py |
| `workflow-approval-binding-invalid` | workflow-approval | high | yes | evals/w302_workflow_approval_probes.py, tests/test_workflow_approval.py |
| `workflow-approval-digest-mismatch` | workflow-approval | high | yes | evals/w302_workflow_approval_probes.py, tests/test_workflow_approval.py |
| `workflow-authority-revoked` | workflow | high | yes | evals/w301_workflow_probes.py, evals/w302_redteam_probes.py, evals/w302_workflow_composed_probes.py (+8) |
| `workflow-branch-decision-forgery` | workflow-branch | critical | yes | evals/w302_branch_probes.py, tests/test_workflow_branch.py |
| `workflow-branch-unregistered` | workflow-branch | high | yes | evals/w302_branch_probes.py, tests/test_workflow_branch.py |
| `workflow-branch-xid-mismatch` | workflow-branch | high | yes | evals/w302_branch_probes.py, evals/w303_f385_probes.py, evals/w305_redteam_probes.py (+6) |
| `workflow-checkpoint-tampered` | workflow | critical | yes | evals/w301_workflow_probes.py, evals/w302_redteam_probes.py, evals/w303_f382f383_probes.py (+2) |
| `workflow-composed-authority-mismatch` | workflow | high | yes | evals/w302_workflow_composed_probes.py, tests/test_workflow_composed.py |
| `workflow-composed-definition-invalid` | workflow | high | yes | evals/w302_workflow_composed_probes.py, evals/w309_f393_probes.py, evals/w310_redteam_probes.py (+12) |
| `workflow-composed-divergent` | workflow | critical | yes | evals/w302_workflow_composed_probes.py, tests/test_workflow_composed.py |
| `workflow-composed-plan-mismatch` | workflow | critical | yes | evals/w303_f388_probes.py, evals/w303_f390_probes.py, evals/w306_redteam_probes.py (+15) |
| `workflow-composed-replay-foreign` | workflow | critical | yes | evals/w303_f388_probes.py, evals/w303_f390_probes.py, evals/w303_redteam_probes.py (+11) |
| `workflow-idempotency-authority-lapsed` | workflow-idempotency | high | yes | evals/w301_idempotency_probes.py, evals/w302_redteam_probes.py, evals/w303_f381_probes.py (+2) |
| `workflow-idempotency-caller-mismatch` | workflow-idempotency | high | yes | evals/w302_redteam_probes.py, evals/w303_f381_probes.py, evals/w304_redteam_probes.py (+2) |
| `workflow-idempotency-key-invalid` | workflow-idempotency | high | yes | evals/w301_idempotency_probes.py, tests/test_workflow_idempotency.py |
| `workflow-routing-rights-widened` | workflow-routing | high | yes | evals/w301_routing_probes.py, tests/test_workflow_routing.py |
| `workflow-routing-slip-tampered` | workflow-routing | high | yes | evals/w301_routing_probes.py, evals/w302_redteam_probes.py, tests/test_workflow_routing.py |
| `workflow-saga-compensation-failed` | workflow_saga | high | yes | evals/w301_saga_probes.py, evals/w302_redteam_probes.py, evals/w303_f384_probes.py (+4) |
| `workflow-saga-compensation-unauthorized` | workflow_saga | high | yes | evals/w301_saga_probes.py, evals/w302_workflow_composed_probes.py, evals/w303_f386_probes.py (+11) |
| `workflow-saga-definition-invalid` | workflow_saga | high | yes | evals/w301_saga_probes.py, tests/test_workflow_saga.py |
| `workflow-saga-operator-unauthorized` | workflow_saga | high | yes | evals/w303_f384_probes.py, evals/w305_redteam_probes.py, evals/w310_f394_probes.py (+5) |
| `workflow-saga-resolution-invalid` | workflow_saga | high | yes | evals/w303_f384_probes.py, evals/w310_f394_probes.py, evals/w311_redteam_probes.py (+5) |
| `workflow-step-unauthorized` | workflow | high | yes | evals/w301_workflow_probes.py, evals/w302_redteam_probes.py, evals/w303_f380_probes.py (+14) |
| `wrong-keyset-purpose` | key_identity | high | yes | evals/pack_loader_probes.py, tests/test_pack_loader.py |
| `wrong-purpose` | key_identity | high | yes | evals/tuf_corpus_probes.py, tests/test_audit_detect.py, tests/test_pack_loader.py |
| `wrong_delegator` | approval | high | yes | tests/test_approvals_d1.py |
| `wrong_run_identity` | approval | high | **NO** |  |
