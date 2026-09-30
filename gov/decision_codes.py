"""Machine decision-code taxonomy + evidence re-execution pointers.

Wave-228 lane C. Stdlib only.

Every refusal string the repository emits is mapped to a closed
:class:`DecisionCode` record::

    {domain, code, human, severity, evidence_kinds_required}

plus, on every EMITTED code, a ``reevaluate`` pointer::

    {"evidence_digests": [...], "reverify_steps": [...]}

``evidence_digests`` carries digest-shaped (64 lowercase hex chars)
digests of the evidence the check ran over; ``reverify_steps`` names
the deterministic re-execution steps a third party runs to reproduce
the refusal WITHOUT the engine (recompute the digest, replay the
classifier, re-check revocation, ...). Decision codes are EVIDENCE,
never authority: any authority-shaped use refuses
``decision-code-not-authorization``.

Inventory definition (the closed vocabulary this module maps):
1. Class-level ``code = "..."`` attributes on exception classes.
2. Module constants demonstrably USED as machine codes: raised
   directly, passed as a ``code=`` kwarg, assigned to ``.code``,
   passed to a code-first exception constructor, or used as a
   ``"kind"`` finding value (100-char lookbehind over the file).
3. Literals passed as the first positional arg to code-first
   exception constructors (25 public classes whose first arg is the
   machine code).
4. Dynamic ``self.code = "..."`` assignments.
5. ``reason="..."`` keyword literals (the four lifecycle status
   markers evaluated/manual/human_confirm/uninitialized excepted).
6. ``_refuse_*("...")`` refusal-helper literals.
7. Pre-colon identifiers in raise-site ``"code: detail"`` literals
   (lowercase-leading; camelCase field paths like claimBounds.proves
   are field references, not codes).
8. Pre-colon codes in PlatformEgressError raises (same shape as
   idiom 7).
9. Curated: gov/memory_inbox.py pending-review reasons
   (``untrusted_tier``, ``tainted_run``, ``carrier_mismatch``),
   refusal strings by construction (fail-closed pending review).

Documented exclusions (audited machine strings that are NOT refusal
codes): ``envelope``, ``jail``, ``quorum``, ``arap-context``,
``read``, ``write`` (generic words reused elsewhere);
``user`` / ``agent_action`` (intent-slice step kinds);
``lifecycle`` (discovery event kind); ``warm_retired``
(evidence-tier journal event kind); ``ceremony-tip-manifest`` /
``signer-share-store`` (custody document kinds);
``verify_chain`` / ``evidence_digest`` (wave-229 merge: pre-colon location
labels in gov/checkpoints.py human exception messages, not emitted machine
refusal codes).

Severity semantics (triage guidance, not authority):
- critical: recomputed evidence disagrees with the claim -- treat as
  possible tampering and escalate.
- high: an authorization, revocation, replay, or key-confusion
  boundary was crossed.
- medium: fail-closed on malformed/unknown/expired input -- routine,
  no tamper evidence.
- low: informational machine outcome with no security implication.

Composition: decision codes attach to decision packets
(gov/decision_packet.py ``decision_code`` kwarg, signature-covered)
and to action capsules (digest-linked evidence via
:func:`attach_decision_code`; the capsule still carries no
authority -- see gov/action_capsule.py ``capsule-not-authorization``).
"""

import hashlib
import json

try:
    from .action_capsule import seal_capsule, verify_capsule
except ImportError:  # standalone: composition needs the capsule module
    seal_capsule = None
    verify_capsule = None

DECISION_CODE_VERSION = 1

SEVERITIES = ("low", "medium", "high", "critical")

# The module's own machine codes (fail-closed seams of THIS module).
UNMAPPED = "decision-code-unmapped"
MALFORMED = "decision-code-malformed"
DIGEST_MALFORMED = "decision-code-digest-malformed"
NOT_AUTHORIZATION = "decision-code-not-authorization"
DIGEST_MISMATCH = "decision-code-digest-mismatch"


class DecisionCodeError(Exception):
    """Loud decision-code failure. ``code`` is the machine-readable
    failure mode."""

    def __init__(self, code, detail=""):
        super(DecisionCodeError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


TAXONOMY = {
    'absence-advertised-but-missing': {
        "domain": 'absence',
        "code": 'absence-advertised-but-missing',
        "human": 'signed negative outcome: required evidence is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['negative-record', 'signature', 'revocation-registry'],
        "reverify_steps": ['recompute'],
    },
    'absence-never-advertised': {
        "domain": 'absence',
        "code": 'absence-never-advertised',
        "human": 'signed negative outcome: the absence was never advertised',
        "severity": 'medium',
        "evidence_kinds_required": ['negative-record', 'signature', 'revocation-registry'],
        "reverify_steps": ['recompute'],
    },
    'absence-refused': {
        "domain": 'absence',
        "code": 'absence-refused',
        "human": 'signed negative outcome: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['negative-record', 'signature', 'revocation-registry'],
        "reverify_steps": ['recompute'],
    },
    'absence-revoked': {
        "domain": 'absence',
        "code": 'absence-revoked',
        "human": 'signed negative outcome: the credential or key has been revoked',
        "severity": 'high',
        "evidence_kinds_required": ['negative-record', 'signature', 'revocation-registry'],
        "reverify_steps": ['recompute'],
    },
    'absence-unverifiable': {
        "domain": 'absence',
        "code": 'absence-unverifiable',
        "human": 'signed negative outcome: the evidence could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['negative-record', 'signature', 'revocation-registry'],
        "reverify_steps": ['recompute'],
    },
    'action-binding-tampered': {
        "domain": 'typed_action',
        "code": 'action-binding-tampered',
        "human": 'typed action: the recomputed binding digest does not match the claimed binding',
        "severity": 'critical',
        "evidence_kinds_required": ['digest', 'type-definition'],
        "reverify_steps": ['recompute-digest'],
    },
    'action-material-missing': {
        "domain": 'typed_action',
        "code": 'action-material-missing',
        "human": 'typed action: a required material field is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['type-definition'],
        "reverify_steps": ['recompute'],
    },
    'action-type-drift': {
        "domain": 'typed_action',
        "code": 'action-type-drift',
        "human": 'typed action: the registered type definition disagrees with the type digest the binding commits to',
        "severity": 'critical',
        "evidence_kinds_required": ['type-definition', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'action-type-unknown': {
        "domain": 'typed_action',
        "code": 'action-type-unknown',
        "human": 'typed action: the action type is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['type-registry'],
        "reverify_steps": ['recompute'],
    },
    'action-semantics-drift': {
        "domain": 'typed_action',
        "code": 'action-semantics-drift',
        "human": 'typed action: the registered validation semantics '
                 'disagree with the definition_sha256 the '
                 'binding commits to',
        "severity": 'critical',
        "evidence_kinds_required": ['type-definition', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'action-depth-exceeded': {
        "domain": 'typed_action',
        "code": 'action-depth-exceeded',
        "human": 'typed action: the material nesting depth exceeds '
                 'max_depth for the type',
        "severity": 'medium',
        "evidence_kinds_required": ['type-definition'],
        "reverify_steps": ['recompute'],
    },
    'action-value-count-exceeded': {
        "domain": 'typed_action',
        "code": 'action-value-count-exceeded',
        "human": 'typed action: the material leaf-value count exceeds '
                 'max_values for the type',
        "severity": 'medium',
        "evidence_kinds_required": ['type-definition'],
        "reverify_steps": ['recompute'],
    },
    'action-duplicate-key': {
        "domain": 'typed_action',
        "code": 'action-duplicate-key',
        "human": 'typed action: the material JSON contains a duplicate '
                 'object key',
        "severity": 'high',
        "evidence_kinds_required": ['type-definition'],
        "reverify_steps": ['recompute'],
    },
    'action-material-type-mismatch': {
        "domain": 'typed_action',
        "code": 'action-material-type-mismatch',
        "human": 'typed action: a material field violates its declared '
                 'type',
        "severity": 'medium',
        "evidence_kinds_required": ['type-definition'],
        "reverify_steps": ['recompute'],
    },
    'action-value-too-long': {
        "domain": 'typed_action',
        "code": 'action-value-too-long',
        "human": 'typed action: a material scalar exceeds '
                 'max_value_len for the type',
        "severity": 'medium',
        "evidence_kinds_required": ['type-definition'],
        "reverify_steps": ['recompute'],
    },
    'admission-conjunction-refused': {
        "domain": 'admission',
        "code": 'admission-conjunction-refused',
        "human": 'admission policy: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'admission-digest-mismatch': {
        "domain": 'admission',
        "code": 'admission-digest-mismatch',
        "human": 'admission policy: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'admission-format-unknown': {
        "domain": 'admission',
        "code": 'admission-format-unknown',
        "human": 'admission policy: the identifier is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'admission-inspection-bundle-mismatch': {
        "domain": 'admission',
        "code": 'admission-inspection-bundle-mismatch',
        "human": 'admission policy: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'admission-inspection-missing': {
        "domain": 'admission',
        "code": 'admission-inspection-missing',
        "human": 'admission policy: required evidence is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'admission-issuer-untrusted': {
        "domain": 'admission',
        "code": 'admission-issuer-untrusted',
        "human": 'admission policy: the issuer is not trusted',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'admission-malformed': {
        "domain": 'admission',
        "code": 'admission-malformed',
        "human": 'admission policy: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'admission-severity-exceeded': {
        "domain": 'admission',
        "code": 'admission-severity-exceeded',
        "human": 'admission policy: the severity exceeded the limit',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'admission-severity-unverifiable': {
        "domain": 'admission',
        "code": 'admission-severity-unverifiable',
        "human": 'admission policy: the evidence could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'admission-tag-mutated': {
        "domain": 'admission',
        "code": 'admission-tag-mutated',
        "human": 'admission policy: the tag was mutated',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'admission-unverifiable': {
        "domain": 'admission',
        "code": 'admission-unverifiable',
        "human": 'admission policy: the evidence could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'inspection', 'policy'],
        "reverify_steps": ['replay-admission'],
    },
    'alg-mismatch': {
        "domain": 'alg',
        "code": 'alg-mismatch',
        "human": 'algorithm registry: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['algorithm', 'record', 'signature'],
        "reverify_steps": ['negotiate-algorithm'],
    },
    'alg-no-mutual': {
        "domain": 'alg',
        "code": 'alg-no-mutual',
        "human": 'algorithm registry: no mutual algorithm could be negotiated',
        "severity": 'medium',
        "evidence_kinds_required": ['algorithm', 'record', 'signature'],
        "reverify_steps": ['negotiate-algorithm'],
    },
    'alg-non-repudiation-refused': {
        "domain": 'alg',
        "code": 'alg-non-repudiation-refused',
        "human": 'algorithm registry: refused by policy',
        "severity": 'high',
        "evidence_kinds_required": ['algorithm', 'record', 'signature'],
        "reverify_steps": ['negotiate-algorithm'],
    },
    'alg-refused': {
        "domain": 'alg',
        "code": 'alg-refused',
        "human": 'algorithm registry: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['algorithm', 'record', 'signature'],
        "reverify_steps": ['negotiate-algorithm'],
    },
    'alg-registration-refused': {
        "domain": 'alg',
        "code": 'alg-registration-refused',
        "human": 'algorithm registry: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['algorithm', 'record', 'signature'],
        "reverify_steps": ['negotiate-algorithm'],
    },
    'alg-unregistered': {
        "domain": 'alg',
        "code": 'alg-unregistered',
        "human": 'algorithm registry: the scheme or algorithm is not in the registry',
        "severity": 'medium',
        "evidence_kinds_required": ['algorithm', 'record', 'signature'],
        "reverify_steps": ['negotiate-algorithm'],
    },
    'already-bootstrapped': {
        "domain": 'manifest',
        "code": 'already-bootstrapped',
        "human": 'version manifest: the bootstrap already ran',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'already_finalized': {
        "domain": 'approval',
        "code": 'already_finalized',
        "human": 'approval and delegation: the record is already finalized',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'approval-digest-diverged': {
        "domain": 'digest_link',
        "code": 'approval-digest-diverged',
        "human": 'digest linkage: the recorded value diverged from the recomputed value',
        "severity": 'critical',
        "evidence_kinds_required": ['digest', 'record'],
        "reverify_steps": ['recompute-digest'],
    },
    'approval-record-digest-mismatch': {
        "domain": 'capability',
        "code": 'approval-record-digest-mismatch',
        "human": 'capability assessment: the approval record digest does not match the recomputed digest',
        "severity": 'critical',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'approval-record-undigestible': {
        "domain": 'capability',
        "code": 'approval-record-undigestible',
        "human": 'capability assessment: the approval record cannot be digested',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'approval-record-unresolvable': {
        "domain": 'capability',
        "code": 'approval-record-unresolvable',
        "human": 'capability assessment: the approval record cannot be resolved',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'arap-error': {
        "domain": 'arap',
        "code": 'arap-error',
        "human": 'ARAP lifecycle: an error was detected; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['request', 'context', 'handle', 'timestamp'],
        "reverify_steps": ['recompute'],
    },
    'arg_constraint_violated': {
        "domain": 'approval',
        "code": 'arg_constraint_violated',
        "human": 'approval and delegation: an argument constraint was violated',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'artifact-gate-refused': {
        "domain": 'namespace',
        "code": 'artifact-gate-refused',
        "human": 'deployment namespace: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'artifact_unpinned': {
        "domain": 'load_gate',
        "code": 'artifact_unpinned',
        "human": 'load gate: the artifact is not pinned',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'artifact_unreadable': {
        "domain": 'load_gate',
        "code": 'artifact_unreadable',
        "human": 'load gate: the artifact could not be read',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'assessment_from_future': {
        "domain": 'capability',
        "code": 'assessment_from_future',
        "human": 'capability assessment: the assessment is dated in the future',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'assessment_malformed': {
        "domain": 'capability',
        "code": 'assessment_malformed',
        "human": 'capability assessment: the assessment is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'assessment_report_digest_mismatch': {
        "domain": 'capability',
        "code": 'assessment_report_digest_mismatch',
        "human": 'capability assessment: the assessment report digest does not match',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'assessment_signature_invalid': {
        "domain": 'capability',
        "code": 'assessment_signature_invalid',
        "human": 'capability assessment: the assessment signature is invalid',
        "severity": 'high',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'assessment_unsealed': {
        "domain": 'capability',
        "code": 'assessment_unsealed',
        "human": 'capability assessment: the assessment is not sealed',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'assessment_untrusted_key': {
        "domain": 'capability',
        "code": 'assessment_untrusted_key',
        "human": 'capability assessment: the assessment key is not trusted',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'attenuation-expired': {
        "domain": 'attenuation',
        "code": 'attenuation-expired',
        "human": 'attenuation: the validity window has passed',
        "severity": 'medium',
        "evidence_kinds_required": ['attenuation', 'permit', 'timestamp'],
        "reverify_steps": ['check-ttl', 'check-lease-binding'],
    },
    'attenuation-lease-mismatch': {
        "domain": 'attenuation',
        "code": 'attenuation-lease-mismatch',
        "human": 'attenuation: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['attenuation', 'permit', 'timestamp'],
        "reverify_steps": ['check-ttl', 'check-lease-binding'],
    },
    'attenuation-missing': {
        "domain": 'attenuation',
        "code": 'attenuation-missing',
        "human": 'attenuation: required evidence is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['attenuation', 'permit', 'timestamp'],
        "reverify_steps": ['check-ttl', 'check-lease-binding'],
    },
    'attenuation-refused': {
        "domain": 'attenuation',
        "code": 'attenuation-refused',
        "human": 'attenuation: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['attenuation', 'permit', 'timestamp'],
        "reverify_steps": ['check-ttl', 'check-lease-binding'],
    },
    'attenuation-ttl-refused': {
        "domain": 'attenuation',
        "code": 'attenuation-ttl-refused',
        "human": 'attenuation: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['attenuation', 'permit', 'timestamp'],
        "reverify_steps": ['check-ttl', 'check-lease-binding'],
    },
    'attenuation-unverifiable': {
        "domain": 'attenuation',
        "code": 'attenuation-unverifiable',
        "human": 'attenuation: the evidence could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['attenuation', 'permit', 'timestamp'],
        "reverify_steps": ['check-ttl', 'check-lease-binding'],
    },
    'attenuation-widening-refused': {
        "domain": 'attenuation',
        "code": 'attenuation-widening-refused',
        "human": 'attenuation: an attenuation that widens scope was refused',
        "severity": 'high',
        "evidence_kinds_required": ['attenuation', 'permit', 'timestamp'],
        "reverify_steps": ['check-ttl', 'check-lease-binding'],
    },
    'attest_absence': {
        "domain": 'absence',
        "code": 'attest_absence',
        "human": 'signed negative outcome: attestation of absence was refused',
        "severity": 'medium',
        "evidence_kinds_required": ['negative-record', 'signature', 'revocation-registry'],
        "reverify_steps": ['recompute'],
    },
    'authorized_builders': {
        "domain": 'slsa',
        "code": 'authorized_builders',
        "human": 'SLSA predicate: the builder is not authorized',
        "severity": 'medium',
        "evidence_kinds_required": ['predicate', 'signature', 'digest'],
        "reverify_steps": ['verify-signature'],
    },
    'bad-artifacts': {
        "domain": 'corpus',
        "code": 'bad-artifacts',
        "human": 'corpus manifest: the artifacts failed validation',
        "severity": 'medium',
        "evidence_kinds_required": ['corpus-manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-assertion-shape': {
        "domain": 'c2pa',
        "code": 'bad-assertion-shape',
        "human": 'C2PA conformance: the assertion shape is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-enforcement-mode': {
        "domain": 'pack',
        "code": 'bad-enforcement-mode',
        "human": 'rule pack: the enforcement mode is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['pack', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-expiry': {
        "domain": 'corpus',
        "code": 'bad-expiry',
        "human": 'corpus manifest: the expiry is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['corpus-manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-files': {
        "domain": 'deploy',
        "code": 'bad-files',
        "human": 'deployment trust config: the files failed validation',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-format': {
        "domain": 'corpus',
        "code": 'bad-format',
        "human": 'corpus manifest: the format is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['corpus-manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-handoff': {
        "domain": 'deploy',
        "code": 'bad-handoff',
        "human": 'deployment trust config: the handoff is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-identity-policy': {
        "domain": 'namespace',
        "code": 'bad-identity-policy',
        "human": 'deployment namespace: the identity policy is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'bad-issuer-key': {
        "domain": 'measurement',
        "code": 'bad-issuer-key',
        "human": 'measurement policy: the issuer key is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['measurement', 'policy', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'bad-measurements': {
        "domain": 'measurement',
        "code": 'bad-measurements',
        "human": 'measurement policy: the measurements failed validation',
        "severity": 'medium',
        "evidence_kinds_required": ['measurement', 'policy', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'bad-namespace': {
        "domain": 'namespace',
        "code": 'bad-namespace',
        "human": 'deployment namespace: the namespace is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'bad-now': {
        "domain": 'deploy',
        "code": 'bad-now',
        "human": 'deployment trust config: the timestamp is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-operator': {
        "domain": 'deploy',
        "code": 'bad-operator',
        "human": 'deployment trust config: the operator is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-operator-ceremony': {
        "domain": 'pack',
        "code": 'bad-operator-ceremony',
        "human": 'rule pack: the operator ceremony failed validation',
        "severity": 'medium',
        "evidence_kinds_required": ['pack', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-operators': {
        "domain": 'deploy',
        "code": 'bad-operators',
        "human": 'deployment trust config: the operators failed validation',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-pack-class': {
        "domain": 'deploy',
        "code": 'bad-pack-class',
        "human": 'deployment trust config: the pack class is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-pack-id': {
        "domain": 'pack',
        "code": 'bad-pack-id',
        "human": 'rule pack: the pack id is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['pack', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-pin': {
        "domain": 'c2pa',
        "code": 'bad-pin',
        "human": 'C2PA conformance: the pin is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-quorum-policy': {
        "domain": 'namespace',
        "code": 'bad-quorum-policy',
        "human": 'deployment namespace: the quorum policy is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'bad-quorum-rollback-guard': {
        "domain": 'namespace',
        "code": 'bad-quorum-rollback-guard',
        "human": 'deployment namespace: the quorum rollback guard is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'bad-rule': {
        "domain": 'audit',
        "code": 'bad-rule',
        "human": 'audit detection: the rule failed validation',
        "severity": 'medium',
        "evidence_kinds_required": ['rule-pack', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'bad-rules': {
        "domain": 'pack',
        "code": 'bad-rules',
        "human": 'rule pack: the rules failed validation',
        "severity": 'medium',
        "evidence_kinds_required": ['pack', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-ruleset': {
        "domain": 'namespace',
        "code": 'bad-ruleset',
        "human": 'deployment namespace: the ruleset failed validation',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'bad-seed': {
        "domain": 'measurement',
        "code": 'bad-seed',
        "human": 'measurement policy: the seed is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['measurement', 'policy', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'bad-signature': {
        "domain": 'signature',
        "code": 'bad-signature',
        "human": 'signature verification: the signature failed verification',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'message', 'key'],
        "reverify_steps": ['verify-signature', 'check-key-purpose'],
    },
    'bad-statement-signature': {
        "domain": 'scitt',
        "code": 'bad-statement-signature',
        "human": 'SCITT receipt: the statement signature failed verification',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-threshold': {
        "domain": 'quorum',
        "code": 'bad-threshold',
        "human": 'quorum and thresholds: the threshold is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['quorum', 'vote', 'signature'],
        "reverify_steps": ['recount-votes', 'check-threshold'],
    },
    'bad-trust-record': {
        "domain": 'c2pa',
        "code": 'bad-trust-record',
        "human": 'C2PA conformance: the trust record failed validation',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-trust-signature': {
        "domain": 'c2pa',
        "code": 'bad-trust-signature',
        "human": 'C2PA conformance: the trust signature failed verification',
        "severity": 'high',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad-version': {
        "domain": 'corpus',
        "code": 'bad-version',
        "human": 'corpus manifest: the version is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['corpus-manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad_delegatee': {
        "domain": 'approval',
        "code": 'bad_delegatee',
        "human": 'approval and delegation: the delegatee is invalid',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'bad_key': {
        "domain": 'drift',
        "code": 'bad_key',
        "human": 'drift detection: the key is invalid',
        "severity": 'high',
        "evidence_kinds_required": ['observation', 'baseline', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad_mac': {
        "domain": 'drift',
        "code": 'bad_mac',
        "human": 'drift detection: the message authentication code is invalid',
        "severity": 'high',
        "evidence_kinds_required": ['observation', 'baseline', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bad_scope': {
        "domain": 'approval',
        "code": 'bad_scope',
        "human": 'approval and delegation: the scope is invalid',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'bad_signature': {
        "domain": 'lease',
        "code": 'bad_signature',
        "human": 'capability lease: the signature is invalid',
        "severity": 'high',
        "evidence_kinds_required": ['lease', 'timestamp', 'revocation-registry'],
        "reverify_steps": ['check-expiry', 'check-revocation'],
    },
    'binding_mismatch': {
        "domain": 'lease',
        "code": 'binding_mismatch',
        "human": 'capability lease: the recomputed value does not match the claimed value',
        "severity": 'high',
        "evidence_kinds_required": ['lease', 'timestamp', 'revocation-registry'],
        "reverify_steps": ['check-expiry', 'check-revocation'],
    },
    'blank_ack': {
        "domain": 'deployment',
        "code": 'blank_ack',
        "human": 'deployment guard: the ungoverned acknowledgement was blank; a hollow justification is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'bootstrap-required': {
        "domain": 'manifest',
        "code": 'bootstrap-required',
        "human": 'version manifest: a required check or input is missing',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bundle-inspection-malformed': {
        "domain": 'bundle',
        "code": 'bundle-inspection-malformed',
        "human": 'bundle inspection: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'inspection', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bundle-link-unverifiable': {
        "domain": 'bundle',
        "code": 'bundle-link-unverifiable',
        "human": 'bundle inspection: the evidence could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'inspection', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bundle_refresh_mismatch': {
        "domain": 'load_gate',
        "code": 'bundle_refresh_mismatch',
        "human": 'load gate: the recomputed value does not match the claimed value',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'bundle_refresh_suspended': {
        "domain": 'load_gate',
        "code": 'bundle_refresh_suspended',
        "human": 'load gate: the operation is suspended',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'bundle_refresh_unbound': {
        "domain": 'load_gate',
        "code": 'bundle_refresh_unbound',
        "human": 'load gate: a rule is not bound to a verifiable source',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'cancellation-unauthorized': {
        "domain": 'arap',
        "code": 'cancellation-unauthorized',
        "human": 'ARAP lifecycle: the principal is not authorized to cancel this request',
        "severity": 'high',
        "evidence_kinds_required": ['request', 'context', 'handle', 'timestamp'],
        "reverify_steps": ['recompute'],
    },
    'canonical_link_body': {
        "domain": 'quorum',
        "code": 'canonical_link_body',
        "human": 'quorum and thresholds: the canonical link body could not be constructed',
        "severity": 'medium',
        "evidence_kinds_required": ['quorum', 'vote', 'signature'],
        "reverify_steps": ['recount-votes', 'check-threshold'],
    },
    'canonicalization-failure': {
        "domain": 'agent_card',
        "code": 'canonicalization-failure',
        "human": 'agent card: canonicalization failed',
        "severity": 'medium',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'capability_assessment_expired': {
        "domain": 'capability',
        "code": 'capability_assessment_expired',
        "human": 'capability assessment: the capability assessment has expired',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'capability_assessment_insufficient': {
        "domain": 'capability',
        "code": 'capability_assessment_insufficient',
        "human": 'capability assessment: the capability assessment is insufficient',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'capability_assessment_missing': {
        "domain": 'capability',
        "code": 'capability_assessment_missing',
        "human": 'capability assessment: the capability assessment is missing',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'capsule-attempt-effect-diverged': {
        "domain": 'capsule',
        "code": 'capsule-attempt-effect-diverged',
        "human": 'action capsule: the capsule attempt/effect diverged from the recomputed values',
        "severity": 'critical',
        "evidence_kinds_required": ['capsule', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'capsule-closestate-mismatch': {
        "domain": 'capsule',
        "code": 'capsule-closestate-mismatch',
        "human": 'action capsule: the recomputed close-state does not match the claimed close-state',
        "severity": 'critical',
        "evidence_kinds_required": ['capsule', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'capsule-count-mismatch': {
        "domain": 'capsule',
        "code": 'capsule-count-mismatch',
        "human": 'action capsule: the recomputed verdict/refusal/link counts do not match the claimed counts',
        "severity": 'critical',
        "evidence_kinds_required": ['capsule', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'capsule-digest-mismatch': {
        "domain": 'capsule',
        "code": 'capsule-digest-mismatch',
        "human": 'action capsule: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['capsule', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'capsule-malformed': {
        "domain": 'capsule',
        "code": 'capsule-malformed',
        "human": 'action capsule: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['capsule', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'capsule-noncanonical': {
        "domain": 'capsule',
        "code": 'capsule-noncanonical',
        "human": 'action capsule: the capsule is non-canonical',
        "severity": 'medium',
        "evidence_kinds_required": ['capsule', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'capsule-not-authorization': {
        "domain": 'capsule',
        "code": 'capsule-not-authorization',
        "human": 'action capsule: an evidence record presented as authority was refused',
        "severity": 'high',
        "evidence_kinds_required": ['capsule', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'capsule-refused': {
        "domain": 'capsule',
        "code": 'capsule-refused',
        "human": 'action capsule: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['capsule', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'capsule-unknown-field': {
        "domain": 'capsule',
        "code": 'capsule-unknown-field',
        "human": 'action capsule: the capsule carries an unknown field',
        "severity": 'medium',
        "evidence_kinds_required": ['capsule', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'card-version': {
        "domain": 'agent_card',
        "code": 'card-version',
        "human": 'agent card: the card version is not supported',
        "severity": 'medium',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'carrier_mismatch': {
        "domain": 'memory',
        "code": 'carrier_mismatch',
        "human": 'memory: the declared carrier does not match the actual bytes',
        "severity": 'medium',
        "evidence_kinds_required": ['memory', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-refused': {
        "domain": 'namespace',
        "code": 'ceremony-refused',
        "human": 'deployment namespace: the key ceremony was refused',
        "severity": 'high',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'chain_broken': {
        "domain": 'approval',
        "code": 'chain_broken',
        "human": 'approval and delegation: the delegation chain is broken',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'child-refused-op': {
        "domain": 'capability',
        "code": 'child-refused-op',
        "human": 'capability assessment: the child process refused the operation',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'clear_cross_run_lineage': {
        "domain": 'lineage',
        "code": 'clear_cross_run_lineage',
        "human": 'lineage: clearing cross-run lineage was refused',
        "severity": 'medium',
        "evidence_kinds_required": ['lineage-record', 'signature'],
        "reverify_steps": ['replay-chain'],
    },
    'commit-path-escape': {
        "domain": 'capability',
        "code": 'commit-path-escape',
        "human": 'capability assessment: the commit path escapes its root',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'commit-right-missing': {
        "domain": 'capability',
        "code": 'commit-right-missing',
        "human": 'capability assessment: the commit right is missing',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'commit-unknown-token': {
        "domain": 'capability',
        "code": 'commit-unknown-token',
        "human": 'capability assessment: the commit token is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'component_tampered': {
        "domain": 'platform',
        "code": 'component_tampered',
        "human": 'platform egress: evidence of tampering was detected',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'compute_candidate': {
        "domain": 'release',
        "code": 'compute_candidate',
        "human": 'release approval: the release candidate could not be computed',
        "severity": 'medium',
        "evidence_kinds_required": ['release', 'approval-record', 'signature'],
        "reverify_steps": ['verify-signature', 'replay-chain'],
    },
    'config-body-malformed': {
        "domain": 'deploy',
        "code": 'config-body-malformed',
        "human": 'deployment trust config: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'config-malformed': {
        "domain": 'authorization_receipt',
        "code": 'config-malformed',
        "human": 'authorization receipt: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'config-version-mismatch': {
        "domain": 'deploy',
        "code": 'config-version-mismatch',
        "human": 'deployment trust config: the recomputed value does not match the claimed value',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'consent_expired': {
        "domain": 'platform',
        "code": 'consent_expired',
        "human": 'platform egress: the platform consent token has expired',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'consent_invalid': {
        "domain": 'platform',
        "code": 'consent_invalid',
        "human": 'platform egress: the platform consent token failed verification',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'consent_key_required': {
        "domain": 'platform',
        "code": 'consent_key_required',
        "human": 'platform egress: the consent key is not configured',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'consent_required': {
        "domain": 'platform',
        "code": 'consent_required',
        "human": 'platform egress: no platform consent token was presented',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'content-type-not-allowlisted': {
        "domain": 'scitt',
        "code": 'content-type-not-allowlisted',
        "human": 'SCITT receipt: the content type is not allowlisted',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'context-binding-mismatch': {
        "domain": 'arap',
        "code": 'context-binding-mismatch',
        "human": 'ARAP lifecycle: the recomputed value does not match the claimed value',
        "severity": 'high',
        "evidence_kinds_required": ['request', 'context', 'handle', 'timestamp'],
        "reverify_steps": ['recompute'],
    },
    'context-key-mismatch': {
        "domain": 'policy',
        "code": 'context-key-mismatch',
        "human": 'policy compilation: the recomputed value does not match the claimed value',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'context-not-declared': {
        "domain": 'arap',
        "code": 'context-not-declared',
        "human": 'ARAP lifecycle: the context was not declared',
        "severity": 'high',
        "evidence_kinds_required": ['request', 'context', 'handle', 'timestamp'],
        "reverify_steps": ['recompute'],
    },
    'contradictory_declaration': {
        "domain": 'deployment',
        "code": 'contradictory_declaration',
        "human": 'deployment guard: the declaration is contradictory',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'corpus-expired': {
        "domain": 'corpus',
        "code": 'corpus-expired',
        "human": 'corpus manifest: the validity window has passed',
        "severity": 'medium',
        "evidence_kinds_required": ['corpus-manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'corpus_manifest_mismatch': {
        "domain": 'load_gate',
        "code": 'corpus_manifest_mismatch',
        "human": 'load gate: the recomputed value does not match the claimed value',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'corpus_manifest_stale': {
        "domain": 'load_gate',
        "code": 'corpus_manifest_stale',
        "human": 'load gate: the record is older than the allowed verification age',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'corpus_manifest_unbound': {
        "domain": 'load_gate',
        "code": 'corpus_manifest_unbound',
        "human": 'load gate: a rule is not bound to a verifiable source',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'corpus_manifest_unpresented': {
        "domain": 'load_gate',
        "code": 'corpus_manifest_unpresented',
        "human": 'load gate: required evidence was not presented',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'cross_run_denied': {
        "domain": 'approval',
        "code": 'cross_run_denied',
        "human": 'approval and delegation: the cross-run operation was denied',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'decision-code-digest-malformed': {
        "domain": 'decision_codes',
        "code": 'decision-code-digest-malformed',
        "human": 'decision-code taxonomy: an evidence digest is not digest-shaped (64-char hex)',
        "severity": 'high',
        "evidence_kinds_required": ['taxonomy', 'digest'],
        "reverify_steps": ['replay-claim'],
    },
    'decision-code-digest-mismatch': {
        "domain": 'decision_codes',
        "code": 'decision-code-digest-mismatch',
        "human": 'decision-code taxonomy: the recomputed machine-code digest does not match the linked digest',
        "severity": 'high',
        "evidence_kinds_required": ['taxonomy', 'digest'],
        "reverify_steps": ['replay-claim'],
    },
    'decision-code-malformed': {
        "domain": 'decision_codes',
        "code": 'decision-code-malformed',
        "human": 'decision-code taxonomy: the refusal string is not a well-formed decision code',
        "severity": 'medium',
        "evidence_kinds_required": ['taxonomy', 'digest'],
        "reverify_steps": ['replay-claim'],
    },
    'decision-code-not-authorization': {
        "domain": 'decision_codes',
        "code": 'decision-code-not-authorization',
        "human": 'decision-code taxonomy: a decision code was presented as authority; refused -- codes are evidence, never authorization',
        "severity": 'critical',
        "evidence_kinds_required": ['taxonomy', 'digest'],
        "reverify_steps": ['replay-claim'],
    },
    'decision-code-unmapped': {
        "domain": 'decision_codes',
        "code": 'decision-code-unmapped',
        "human": 'decision-code taxonomy: no taxonomy mapping exists for the refusal string; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['taxonomy', 'digest'],
        "reverify_steps": ['replay-claim'],
    },
    'decision-labels-invalid': {
        "domain": 'decision',
        "code": 'decision-labels-invalid',
        "human": 'decision packet: the value failed semantic validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['decision-packet', 'signature'],
        "reverify_steps": ['verify-packet-signature'],
    },
    'decommission_refused': {
        "domain": 'recovery',
        "code": 'decommission_refused',
        "human": 'recovery: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['journal', 'digest'],
        "reverify_steps": ['replay-chain'],
    },
    'delegatee_mismatch': {
        "domain": 'approval',
        "code": 'delegatee_mismatch',
        "human": 'approval and delegation: the delegatee does not match the grant',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'delegation-decision-mismatch': {
        "domain": 'capability',
        "code": 'delegation-decision-mismatch',
        "human": 'capability assessment: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-not-allowlisted': {
        "domain": 'capability',
        "code": 'delegation-not-allowlisted',
        "human": 'capability assessment: the delegation is not allowlisted',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-unknown-parent': {
        "domain": 'capability',
        "code": 'delegation-unknown-parent',
        "human": 'capability assessment: the delegation parent is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-would-widen': {
        "domain": 'capability',
        "code": 'delegation-would-widen',
        "human": 'capability assessment: the delegation would widen scope',
        "severity": 'high',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation_disabled': {
        "domain": 'approval',
        "code": 'delegation_disabled',
        "human": 'approval and delegation: delegation is disabled',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'delegation_loop': {
        "domain": 'approval',
        "code": 'delegation_loop',
        "human": 'approval and delegation: the delegation would form a loop',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'deny_first_rules': {
        "domain": 'decision_log',
        "code": 'deny_first_rules',
        "human": 'decision log: the log inputs violate the deny-first rule',
        "severity": 'medium',
        "evidence_kinds_required": ['log-entry', 'digest'],
        "reverify_steps": ['replay-chain'],
    },
    'deprecated-assertion-version': {
        "domain": 'c2pa',
        "code": 'deprecated-assertion-version',
        "human": 'C2PA conformance: the assertion version is deprecated',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'depth_exceeded': {
        "domain": 'approval',
        "code": 'depth_exceeded',
        "human": 'approval and delegation: the depth limit was exceeded',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'device-pin-malformed': {
        "domain": 'jail',
        "code": 'device-pin-malformed',
        "human": 'jail policy: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'digest-bad-input': {
        "domain": 'authorization_receipt',
        "code": 'digest-bad-input',
        "human": 'authorization receipt: the digest input is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'digest-linkage-malformed': {
        "domain": 'digest_link',
        "code": 'digest-linkage-malformed',
        "human": 'digest linkage: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'record'],
        "reverify_steps": ['recompute-digest'],
    },
    'digest-linkage-mismatch': {
        "domain": 'digest_link',
        "code": 'digest-linkage-mismatch',
        "human": 'digest linkage: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['digest', 'record'],
        "reverify_steps": ['recompute-digest'],
    },
    'digest-linkage-refused': {
        "domain": 'digest_link',
        "code": 'digest-linkage-refused',
        "human": 'digest linkage: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'record'],
        "reverify_steps": ['recompute-digest'],
    },
    'digest-malformed': {
        "domain": 'authorization_receipt',
        "code": 'digest-malformed',
        "human": 'authorization receipt: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'digest-mismatch': {
        "domain": 'digest_link',
        "code": 'digest-mismatch',
        "human": 'digest linkage: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['digest', 'record'],
        "reverify_steps": ['recompute-digest'],
    },
    'digest-role-mismatch': {
        "domain": 'authorization_receipt',
        "code": 'digest-role-mismatch',
        "human": 'authorization receipt: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'digest-role-missing': {
        "domain": 'authorization_receipt',
        "code": 'digest-role-missing',
        "human": 'authorization receipt: required evidence is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'digest_mismatch': {
        "domain": 'load_gate',
        "code": 'digest_mismatch',
        "human": 'load gate: the recomputed value does not match the claimed value',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'display-attestation-error': {
        "domain": 'display',
        "code": 'display-attestation-error',
        "human": 'display attestation: an error was detected; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['render', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'display-hash-mismatch': {
        "domain": 'presentation',
        "code": 'display-hash-mismatch',
        "human": 'presentation binding: the recomputed value does not match the claimed value',
        "severity": 'high',
        "evidence_kinds_required": ['render', 'digest', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'display-no-render-commitment': {
        "domain": 'display',
        "code": 'display-no-render-commitment',
        "human": 'display attestation: no rendering commitment was presented',
        "severity": 'medium',
        "evidence_kinds_required": ['render', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'display-policy-unknown': {
        "domain": 'display',
        "code": 'display-policy-unknown',
        "human": 'display attestation: the identifier is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['render', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'display-rederivation-failed': {
        "domain": 'display',
        "code": 'display-rederivation-failed',
        "human": 'display attestation: the operation failed; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['render', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'downgrade-refused': {
        "domain": 'presentation',
        "code": 'downgrade-refused',
        "human": 'presentation binding: a version or authority downgrade was refused',
        "severity": 'high',
        "evidence_kinds_required": ['render', 'digest', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'duplicate-trust-record': {
        "domain": 'c2pa',
        "code": 'duplicate-trust-record',
        "human": 'C2PA conformance: a duplicate trust record was refused',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'duplicate_request': {
        "domain": 'arap',
        "code": 'duplicate_request',
        "human": 'ARAP lifecycle: a duplicate request was refused',
        "severity": 'medium',
        "evidence_kinds_required": ['request', 'context', 'handle', 'timestamp'],
        "reverify_steps": ['recompute'],
    },
    'duplicate_vote': {
        "domain": 'approval',
        "code": 'duplicate_vote',
        "human": 'approval and delegation: a duplicate vote was refused',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'effect-status-ambiguous-refused': {
        "domain": 'effect',
        "code": 'effect-status-ambiguous-refused',
        "human": 'effect status: ambiguous evidence was refused rather than silently classified',
        "severity": 'medium',
        "evidence_kinds_required": ['observation', 'effect-status'],
        "reverify_steps": ['replay-classify'],
    },
    'effect-status-invalid': {
        "domain": 'effect',
        "code": 'effect-status-invalid',
        "human": 'effect status: the value failed semantic validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['observation', 'effect-status'],
        "reverify_steps": ['replay-classify'],
    },
    'effect-status-refused': {
        "domain": 'effect',
        "code": 'effect-status-refused',
        "human": 'effect status: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['observation', 'effect-status'],
        "reverify_steps": ['replay-classify'],
    },
    'empty_reason': {
        "domain": 'approval',
        "code": 'empty_reason',
        "human": 'approval and delegation: no reason was supplied; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'escalation-action-mismatch': {
        "domain": 'escalation',
        "code": 'escalation-action-mismatch',
        "human": 'escalation binding: the escalation action does not match the approval',
        "severity": 'critical',
        "evidence_kinds_required": ['approval-record', 'capsule', 'digest'],
        "reverify_steps": ['recompute-approval-digest', 'recompute-action-digest'],
    },
    'escalation-already-bound': {
        "domain": 'escalation',
        "code": 'escalation-already-bound',
        "human": 'escalation binding: the escalation is already bound',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record', 'capsule', 'digest'],
        "reverify_steps": ['recompute-approval-digest', 'recompute-action-digest'],
    },
    'escalation-approval-digest-mismatch': {
        "domain": 'escalation',
        "code": 'escalation-approval-digest-mismatch',
        "human": 'escalation binding: the escalation approval digest does not match',
        "severity": 'critical',
        "evidence_kinds_required": ['approval-record', 'capsule', 'digest'],
        "reverify_steps": ['recompute-approval-digest', 'recompute-action-digest'],
    },
    'escalation-bind-refused': {
        "domain": 'escalation',
        "code": 'escalation-bind-refused',
        "human": 'escalation binding: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record', 'capsule', 'digest'],
        "reverify_steps": ['recompute-approval-digest', 'recompute-action-digest'],
    },
    'escalation-malformed': {
        "domain": 'escalation',
        "code": 'escalation-malformed',
        "human": 'escalation binding: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record', 'capsule', 'digest'],
        "reverify_steps": ['recompute-approval-digest', 'recompute-action-digest'],
    },
    'escalation-not-bound': {
        "domain": 'escalation',
        "code": 'escalation-not-bound',
        "human": 'escalation binding: the escalation is not bound',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record', 'capsule', 'digest'],
        "reverify_steps": ['recompute-approval-digest', 'recompute-action-digest'],
    },
    'evidence-incomplete': {
        "domain": 'evidence',
        "code": 'evidence-incomplete',
        "human": 'evidence completeness: the evidence is incomplete',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'evidence-refused': {
        "domain": 'evidence',
        "code": 'evidence-refused',
        "human": 'evidence completeness: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'evidence-unverifiable-item': {
        "domain": 'evidence',
        "code": 'evidence-unverifiable-item',
        "human": 'evidence completeness: an evidence item could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'expired-card': {
        "domain": 'agent_card',
        "code": 'expired-card',
        "human": 'agent card: the card has expired',
        "severity": 'medium',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'faithfulness-error': {
        "domain": 'presentation',
        "code": 'faithfulness-error',
        "human": 'presentation binding: an error was detected; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['render', 'digest', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'gitspawn-config-unparseable': {
        "domain": 'gitspawn',
        "code": 'gitspawn-config-unparseable',
        "human": 'git subprocess sanitization: the input could not be parsed; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['git-config'],
        "reverify_steps": ['rescan-config'],
    },
    'gitspawn-hostile-config': {
        "domain": 'gitspawn',
        "code": 'gitspawn-hostile-config',
        "human": 'git subprocess sanitization: the git config contains a hostile exec-sink key',
        "severity": 'medium',
        "evidence_kinds_required": ['git-config'],
        "reverify_steps": ['rescan-config'],
    },
    'gitspawn-in-repo-git-refused': {
        "domain": 'gitspawn',
        "code": 'gitspawn-in-repo-git-refused',
        "human": 'git subprocess sanitization: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['git-config'],
        "reverify_steps": ['rescan-config'],
    },
    'gov.capability_manifests.manifest_absent_advisory': {
        "domain": 'skill',
        "code": 'gov.capability_manifests.manifest_absent_advisory',
        "human": 'skill watch: advisory: the capability manifest is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['skill', 'assessment'],
        "reverify_steps": ['recompute'],
    },
    'gov.executor.capability_gate_unconfigured_refused': {
        "domain": 'deployment',
        "code": 'gov.executor.capability_gate_unconfigured_refused',
        "human": 'deployment guard: no capability gate is configured',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'gov.policy_compile.post_compile_mutation_refused': {
        "domain": 'policy',
        "code": 'gov.policy_compile.post_compile_mutation_refused',
        "human": 'policy compilation: the policy was mutated after compilation',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grant-already-consumed': {
        "domain": 'capability',
        "code": 'grant-already-consumed',
        "human": 'capability assessment: the grant was already consumed',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'grant-decision-mismatch': {
        "domain": 'capability',
        "code": 'grant-decision-mismatch',
        "human": 'capability assessment: the grant decision does not match',
        "severity": 'critical',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'grant-malformed': {
        "domain": 'authorization_receipt',
        "code": 'grant-malformed',
        "human": 'authorization receipt: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grant-not-minted': {
        "domain": 'capability',
        "code": 'grant-not-minted',
        "human": 'capability assessment: the grant was not minted',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'grant-revoked': {
        "domain": 'authorization_receipt',
        "code": 'grant-revoked',
        "human": 'authorization receipt: the credential or key has been revoked',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grant_consumed': {
        "domain": 'approval',
        "code": 'grant_consumed',
        "human": 'approval and delegation: the grant was already consumed',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'grant_expired': {
        "domain": 'approval',
        "code": 'grant_expired',
        "human": "approval and delegation: the grant's validity window has passed",
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'grant_integrity_violation': {
        "domain": 'approval',
        "code": 'grant_integrity_violation',
        "human": 'approval and delegation: the grant failed its integrity check; the store may be tampered',
        "severity": 'critical',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'grant_revoked': {
        "domain": 'approval',
        "code": 'grant_revoked',
        "human": 'approval and delegation: the grant has been revoked',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'halt_refused': {
        "domain": 'recovery',
        "code": 'halt_refused',
        "human": 'recovery: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['journal', 'digest'],
        "reverify_steps": ['replay-chain'],
    },
    'handle-not-authority': {
        "domain": 'handle',
        "code": 'handle-not-authority',
        "human": 'client handle: a non-authority handle presented as authority was refused',
        "severity": 'high',
        "evidence_kinds_required": ['handle', 'request'],
        "reverify_steps": ['recompute'],
    },
    'handle-unknown': {
        "domain": 'handle',
        "code": 'handle-unknown',
        "human": 'client handle: the identifier is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['handle', 'request'],
        "reverify_steps": ['recompute'],
    },
    'handoff-invalid': {
        "domain": 'deploy',
        "code": 'handoff-invalid',
        "human": 'deployment trust config: the value failed semantic validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'harness_config_digest_mismatch': {
        "domain": 'capability',
        "code": 'harness_config_digest_mismatch',
        "human": 'capability assessment: the harness config digest does not match',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'harness_id_mismatch': {
        "domain": 'capability',
        "code": 'harness_id_mismatch',
        "human": 'capability assessment: the harness id does not match',
        "severity": 'high',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'helper_not_configured': {
        "domain": 'platform',
        "code": 'helper_not_configured',
        "human": 'platform egress: the component is not configured',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'hop_token_refs': {
        "domain": 'delegation',
        "code": 'hop_token_refs',
        "human": 'delegation token: the hop token references are invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['token', 'signature'],
        "reverify_steps": ['verify-signature', 'check-revocation'],
    },
    'hybrid-classical-fallback-refused': {
        "domain": 'hybrid_gate',
        "code": 'hybrid-classical-fallback-refused',
        "human": 'hybrid gate: a suite declaring PQC entries presented only the classical signature (downgrade refused)',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'signature', 'key-registry'],
        "reverify_steps": ['recompute-digest', 'replay-admission'],
    },
    'hybrid-entry-mismatch': {
        "domain": 'hybrid_gate',
        "code": 'hybrid-entry-mismatch',
        "human": 'hybrid gate: a presented key is not declared in the verifier-pinned policy, or its claimed key type disagrees with the registry',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'key-registry', 'pubkey'],
        "reverify_steps": ['recompute-digest', 'resolve-key'],
    },
    'hybrid-gate-malformed': {
        "domain": 'hybrid_gate',
        "code": 'hybrid-gate-malformed',
        "human": 'hybrid gate: the policy or the presented signature bundle is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'hybrid-gate-not-authorization': {
        "domain": 'hybrid_gate',
        "code": 'hybrid-gate-not-authorization',
        "human": 'hybrid gate: an admission record was used as authority; records are evidence only',
        "severity": 'low',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'hybrid-gate-refused': {
        "domain": 'hybrid_gate',
        "code": 'hybrid-gate-refused',
        "human": 'hybrid gate: generic admission refusal',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'signature'],
        "reverify_steps": ['replay-admission'],
    },
    'hybrid-incomplete': {
        "domain": 'hybrid_gate',
        "code": 'hybrid-incomplete',
        "human": 'hybrid gate: a declared suite entry presented no signature material',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'signature'],
        "reverify_steps": ['recompute-digest', 'replay-admission'],
    },
    'hybrid-leg-failed': {
        "domain": 'key_identity',
        "code": 'hybrid-leg-failed',
        "human": 'registered key identity: a hybrid signature leg failed verification',
        "severity": 'medium',
        "evidence_kinds_required": ['key-registry', 'pubkey', 'revocation-registry', 'signature'],
        "reverify_steps": ['recompute-pubkey-digest', 'resolve-key', 'check-revocation', 'verify-signature'],
    },
    'hybrid-leg-invalid': {
        "domain": 'key_identity',
        "code": 'hybrid-leg-invalid',
        "human": 'registered key identity: a hybrid signature leg is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['key-registry', 'pubkey', 'revocation-registry', 'signature'],
        "reverify_steps": ['recompute-pubkey-digest', 'resolve-key', 'check-revocation', 'verify-signature'],
    },
    'hybrid-policy-tampered': {
        "domain": 'hybrid_gate',
        "code": 'hybrid-policy-tampered',
        "human": 'hybrid gate: the verifier-pinned policy was mutated after pinning',
        "severity": 'critical',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'hybrid-suite-not-accepted': {
        "domain": 'hybrid_gate',
        "code": 'hybrid-suite-not-accepted',
        "human": 'hybrid gate: the presented suite is not accepted by the verifier-pinned policy',
        "severity": 'high',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute-digest'],
    },
    'identity-mismatch': {
        "domain": 'agent_card',
        "code": 'identity-mismatch',
        "human": 'agent card: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'identity-policy-refused': {
        "domain": 'namespace',
        "code": 'identity-policy-refused',
        "human": 'deployment namespace: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'identity_key_of': {
        "domain": 'detection',
        "code": 'identity_key_of',
        "human": 'detection: the identity key could not be derived',
        "severity": 'medium',
        "evidence_kinds_required": ['signal', 'digest'],
        "reverify_steps": ['replay-chain'],
    },
    'input_closure_digest': {
        "domain": 'provenance',
        "code": 'input_closure_digest',
        "human": 'provenance verifier: the input closure digest could not be computed',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance', 'digest', 'signature'],
        "reverify_steps": ['recompute-digest'],
    },
    'inspection-failed': {
        "domain": 'inspection',
        "code": 'inspection-failed',
        "human": 'inspection: the inspection failed',
        "severity": 'medium',
        "evidence_kinds_required": ['inspection', 'bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'inspection-link-unverifiable': {
        "domain": 'inspection',
        "code": 'inspection-link-unverifiable',
        "human": 'inspection: the evidence could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['inspection', 'bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'inspection-malformed': {
        "domain": 'inspection',
        "code": 'inspection-malformed',
        "human": 'inspection: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['inspection', 'bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'inspection-script-digest-mismatch': {
        "domain": 'inspection',
        "code": 'inspection-script-digest-mismatch',
        "human": 'inspection: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['inspection', 'bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'insufficient_data': {
        "domain": 'evidence',
        "code": 'insufficient_data',
        "human": 'evidence completeness: there is insufficient data to decide',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'integrity_violation': {
        "domain": 'sweep',
        "code": 'integrity_violation',
        "human": 'artifact sweep: an integrity violation was detected',
        "severity": 'critical',
        "evidence_kinds_required": ['artifact', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'invalid-signature': {
        "domain": 'agent_card',
        "code": 'invalid-signature',
        "human": 'agent card: the signature is invalid',
        "severity": 'high',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'invalid_target': {
        "domain": 'approval',
        "code": 'invalid_target',
        "human": 'approval and delegation: the target is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'invocation-malformed': {
        "domain": 'jail',
        "code": 'invocation-malformed',
        "human": 'jail policy: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'invocation-network-request-refused': {
        "domain": 'jail',
        "code": 'invocation-network-request-refused',
        "human": 'jail policy: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'invocation-timeout-exceeds-policy': {
        "domain": 'jail',
        "code": 'invocation-timeout-exceeds-policy',
        "human": 'jail policy: the invocation timeout exceeds policy',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'invocation-writable-dir-mismatch': {
        "domain": 'jail',
        "code": 'invocation-writable-dir-mismatch',
        "human": 'jail policy: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'ip_not_found': {
        "domain": 'platform',
        "code": 'ip_not_found',
        "human": 'platform egress: the item was not found',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'issuer-malformed': {
        "domain": 'authorization_receipt',
        "code": 'issuer-malformed',
        "human": 'authorization receipt: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'issuer-not-allowlisted': {
        "domain": 'scitt',
        "code": 'issuer-not-allowlisted',
        "human": 'SCITT receipt: the issuer is not allowlisted',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'jku-not-allowed': {
        "domain": 'capability',
        "code": 'jku-not-allowed',
        "human": 'capability assessment: the JWK set URL is not allowlisted',
        "severity": 'high',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'keep_evidence_types': {
        "domain": 'vc',
        "code": 'keep_evidence_types',
        "human": 'verifiable credential bundle: the evidence types are not permitted',
        "severity": 'medium',
        "evidence_kinds_required": ['credential', 'signature', 'digest'],
        "reverify_steps": ['verify-signature'],
    },
    'keep_subject_fields': {
        "domain": 'vc',
        "code": 'keep_subject_fields',
        "human": 'verifiable credential bundle: the subject fields are not permitted',
        "severity": 'medium',
        "evidence_kinds_required": ['credential', 'signature', 'digest'],
        "reverify_steps": ['verify-signature'],
    },
    'key-identity-malformed': {
        "domain": 'key_identity',
        "code": 'key-identity-malformed',
        "human": 'registered key identity: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['key-registry', 'pubkey', 'revocation-registry', 'signature'],
        "reverify_steps": ['recompute-pubkey-digest', 'resolve-key', 'check-revocation', 'verify-signature'],
    },
    'key-identity-refused': {
        "domain": 'key_identity',
        "code": 'key-identity-refused',
        "human": 'registered key identity: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['key-registry', 'pubkey', 'revocation-registry', 'signature'],
        "reverify_steps": ['recompute-pubkey-digest', 'resolve-key', 'check-revocation', 'verify-signature'],
    },
    'key-identity-revoked': {
        "domain": 'key_identity',
        "code": 'key-identity-revoked',
        "human": 'registered key identity: the credential or key has been revoked',
        "severity": 'high',
        "evidence_kinds_required": ['key-registry', 'pubkey', 'revocation-registry', 'signature'],
        "reverify_steps": ['recompute-pubkey-digest', 'resolve-key', 'check-revocation', 'verify-signature'],
    },
    'key-identity-unknown': {
        "domain": 'key_identity',
        "code": 'key-identity-unknown',
        "human": 'registered key identity: the key id is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['key-registry', 'pubkey', 'revocation-registry', 'signature'],
        "reverify_steps": ['recompute-pubkey-digest', 'resolve-key', 'check-revocation', 'verify-signature'],
    },
    'key-identity-unregistered': {
        "domain": 'key_identity',
        "code": 'key-identity-unregistered',
        "human": 'registered key identity: the scheme or algorithm is not in the registry',
        "severity": 'medium',
        "evidence_kinds_required": ['key-registry', 'pubkey', 'revocation-registry', 'signature'],
        "reverify_steps": ['recompute-pubkey-digest', 'resolve-key', 'check-revocation', 'verify-signature'],
    },
    'key-swap-refused': {
        "domain": 'authorization_receipt',
        "code": 'key-swap-refused',
        "human": 'authorization receipt: a key substitution was detected and refused',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'kid-ambiguity': {
        "domain": 'agent_card',
        "code": 'kid-ambiguity',
        "human": 'agent card: the key id is ambiguous',
        "severity": 'high',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'kms-signer-algorithm-refused': {
        "domain": 'kms',
        "code": 'kms-signer-algorithm-refused',
        "human": 'KMS signer: the KMS algorithm was refused',
        "severity": 'medium',
        "evidence_kinds_required": ['key-ref', 'message', 'signature'],
        "reverify_steps": ['validate-keyref', 'verify-signature'],
    },
    'kms-signer-keyref-invalid': {
        "domain": 'kms',
        "code": 'kms-signer-keyref-invalid',
        "human": 'KMS signer: the KMS key reference is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['key-ref', 'message', 'signature'],
        "reverify_steps": ['validate-keyref', 'verify-signature'],
    },
    'kms-signer-message-too-large': {
        "domain": 'kms',
        "code": 'kms-signer-message-too-large',
        "human": 'KMS signer: the KMS message exceeds the size limit',
        "severity": 'medium',
        "evidence_kinds_required": ['key-ref', 'message', 'signature'],
        "reverify_steps": ['validate-keyref', 'verify-signature'],
    },
    'kms-signer-refused': {
        "domain": 'kms',
        "code": 'kms-signer-refused',
        "human": 'KMS signer: the KMS signer refused the operation',
        "severity": 'medium',
        "evidence_kinds_required": ['key-ref', 'message', 'signature'],
        "reverify_steps": ['validate-keyref', 'verify-signature'],
    },
    'lease_expired': {
        "domain": 'lease',
        "code": 'lease_expired',
        "human": 'capability lease: the validity window has passed',
        "severity": 'medium',
        "evidence_kinds_required": ['lease', 'timestamp', 'revocation-registry'],
        "reverify_steps": ['check-expiry', 'check-revocation'],
    },
    'lease_missing': {
        "domain": 'lease',
        "code": 'lease_missing',
        "human": 'capability lease: required evidence is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['lease', 'timestamp', 'revocation-registry'],
        "reverify_steps": ['check-expiry', 'check-revocation'],
    },
    'lease_not_yet_valid': {
        "domain": 'lease',
        "code": 'lease_not_yet_valid',
        "human": 'capability lease: the credential is not yet valid',
        "severity": 'medium',
        "evidence_kinds_required": ['lease', 'timestamp', 'revocation-registry'],
        "reverify_steps": ['check-expiry', 'check-revocation'],
    },
    'lease_revoked': {
        "domain": 'lease',
        "code": 'lease_revoked',
        "human": 'capability lease: the credential or key has been revoked',
        "severity": 'medium',
        "evidence_kinds_required": ['lease', 'timestamp', 'revocation-registry'],
        "reverify_steps": ['check-expiry', 'check-revocation'],
    },
    'lock_unavailable': {
        "domain": 'platform',
        "code": 'lock_unavailable',
        "human": 'platform egress: the resource is unavailable',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'make_link_record': {
        "domain": 'quorum',
        "code": 'make_link_record',
        "human": 'quorum and thresholds: the link record could not be constructed',
        "severity": 'medium',
        "evidence_kinds_required": ['quorum', 'vote', 'signature'],
        "reverify_steps": ['recount-votes', 'check-threshold'],
    },
    'malformed-card': {
        "domain": 'agent_card',
        "code": 'malformed-card',
        "human": 'agent card: the card is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'malformed-context': {
        "domain": 'mcp',
        "code": 'malformed-context',
        "human": 'MCP invocation authorization: the context is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['message', 'permit', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'malformed-message': {
        "domain": 'mcp',
        "code": 'malformed-message',
        "human": 'MCP invocation authorization: the message is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['message', 'permit', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'malformed-permit': {
        "domain": 'mcp',
        "code": 'malformed-permit',
        "human": 'MCP invocation authorization: the permit is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['message', 'permit', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'malformed-signature-entry': {
        "domain": 'signature',
        "code": 'malformed-signature-entry',
        "human": 'signature verification: the signature entry is malformed',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'message', 'key'],
        "reverify_steps": ['verify-signature', 'check-key-purpose'],
    },
    'malformed-statement': {
        "domain": 'scitt',
        "code": 'malformed-statement',
        "human": 'SCITT receipt: the statement is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'malformed_binding': {
        "domain": 'deployment',
        "code": 'malformed_binding',
        "human": 'deployment guard: the binding is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'malformed_lease': {
        "domain": 'lease',
        "code": 'malformed_lease',
        "human": 'capability lease: the lease is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['lease', 'timestamp', 'revocation-registry'],
        "reverify_steps": ['check-expiry', 'check-revocation'],
    },
    'manifest-downgrade-refused': {
        "domain": 'manifest',
        "code": 'manifest-downgrade-refused',
        "human": 'version manifest: a version or authority downgrade was refused',
        "severity": 'high',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'manifest-refused': {
        "domain": 'manifest',
        "code": 'manifest-refused',
        "human": 'version manifest: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'mapping-drift': {
        "domain": 'mcp',
        "code": 'mapping-drift',
        "human": 'MCP invocation authorization: recomputed evidence drifted from the claimed record',
        "severity": 'critical',
        "evidence_kinds_required": ['message', 'permit', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'max_hops_exceeded': {
        "domain": 'approval',
        "code": 'max_hops_exceeded',
        "human": 'approval and delegation: the maximum hop count was exceeded',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'measurement-mismatch': {
        "domain": 'measurement',
        "code": 'measurement-mismatch',
        "human": 'measurement policy: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['measurement', 'policy', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'measurement-missing': {
        "domain": 'measurement',
        "code": 'measurement-missing',
        "human": 'measurement policy: required evidence is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['measurement', 'policy', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'measurement-unlisted': {
        "domain": 'measurement',
        "code": 'measurement-unlisted',
        "human": 'measurement policy: the measurement is not listed',
        "severity": 'medium',
        "evidence_kinds_required": ['measurement', 'policy', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'missing-digest': {
        "domain": 'authorization_receipt',
        "code": 'missing-digest',
        "human": 'authorization receipt: the digest is missing',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'missing-signatures': {
        "domain": 'signature',
        "code": 'missing-signatures',
        "human": 'signature verification: the signatures are missing',
        "severity": 'medium',
        "evidence_kinds_required": ['signature', 'message', 'key'],
        "reverify_steps": ['verify-signature', 'check-key-purpose'],
    },
    'missing-skill-id': {
        "domain": 'capability',
        "code": 'missing-skill-id',
        "human": 'capability assessment: the skill id is missing',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'mission-binding-mismatch': {
        "domain": 'presentation',
        "code": 'mission-binding-mismatch',
        "human": 'presentation binding: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['render', 'digest', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'namespace_admission_refused': {
        "domain": 'load_gate',
        "code": 'namespace_admission_refused',
        "human": 'load gate: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'never_registered': {
        "domain": 'sweep',
        "code": 'never_registered',
        "human": 'artifact sweep: the artifact is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['artifact', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'no-active-pack': {
        "domain": 'pack',
        "code": 'no-active-pack',
        "human": 'rule pack: no rule pack is active; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['pack', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'no-trust-config': {
        "domain": 'deploy',
        "code": 'no-trust-config',
        "human": 'deployment trust config: no trust configuration is registered; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'no_ack': {
        "domain": 'deployment',
        "code": 'no_ack',
        "human": 'deployment guard: no ungoverned acknowledgement was declared; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'no_amplification_oracle': {
        "domain": 'approval',
        "code": 'no_amplification_oracle',
        "human": 'approval and delegation: no amplification oracle is available',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'no_binding_no_ack': {
        "domain": 'deployment',
        "code": 'no_binding_no_ack',
        "human": 'deployment guard: no capability gate is configured and no acknowledgement was declared; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'no_common_algorithm': {
        "domain": 'platform',
        "code": 'no_common_algorithm',
        "human": 'platform egress: no common algorithm could be negotiated',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'no_drift_store': {
        "domain": 'deployment',
        "code": 'no_drift_store',
        "human": 'deployment guard: no drift store is configured',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'no_framing_store': {
        "domain": 'deployment',
        "code": 'no_framing_store',
        "human": 'deployment guard: no framing store is configured',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'no_resolved_target': {
        "domain": 'deployment',
        "code": 'no_resolved_target',
        "human": 'deployment guard: no target could be resolved',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'non_delegable_power': {
        "domain": 'approval',
        "code": 'non_delegable_power',
        "human": 'approval and delegation: the power is non-delegable',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'not-yet-valid': {
        "domain": 'agent_card',
        "code": 'not-yet-valid',
        "human": 'agent card: the credential is not yet valid',
        "severity": 'medium',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'not_eligible': {
        "domain": 'approval',
        "code": 'not_eligible',
        "human": 'approval and delegation: not eligible',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'not_parent_delegatee': {
        "domain": 'approval',
        "code": 'not_parent_delegatee',
        "human": 'approval and delegation: the caller is not the parent delegatee',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'not_pending': {
        "domain": 'approval',
        "code": 'not_pending',
        "human": 'approval and delegation: not pending',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'not_quorum': {
        "domain": 'approval',
        "code": 'not_quorum',
        "human": 'approval and delegation: quorum was not reached',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'opt-out-consumed': {
        "domain": 'deploy',
        "code": 'opt-out-consumed',
        "human": 'deployment trust config: the opt-out was already consumed',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'opt-out-quorum-unmet': {
        "domain": 'deploy',
        "code": 'opt-out-quorum-unmet',
        "human": 'deployment trust config: a threshold or quorum was not met',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'opt-out-self-ack': {
        "domain": 'deploy',
        "code": 'opt-out-self-ack',
        "human": 'deployment trust config: an opt-out cannot acknowledge itself',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'opt-out-unknown-proposal': {
        "domain": 'deploy',
        "code": 'opt-out-unknown-proposal',
        "human": 'deployment trust config: the opt-out proposal is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'outside_sandbox': {
        "domain": 'deployment',
        "code": 'outside_sandbox',
        "human": 'deployment guard: the operation is outside the sandbox',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'pack-expired': {
        "domain": 'pack',
        "code": 'pack-expired',
        "human": 'rule pack: the validity window has passed',
        "severity": 'medium',
        "evidence_kinds_required": ['pack', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'pack-invalid': {
        "domain": 'audit',
        "code": 'pack-invalid',
        "human": 'audit detection: the value failed semantic validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['rule-pack', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'pack-lint-failed': {
        "domain": 'pack',
        "code": 'pack-lint-failed',
        "human": 'rule pack: the pack failed linting',
        "severity": 'medium',
        "evidence_kinds_required": ['pack', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'pass-vacuous': {
        "domain": 'identity',
        "code": 'pass-vacuous',
        "human": 'identity policy: vacuous pass: no non-vacuous predicate matched; informational only',
        "severity": 'low',
        "evidence_kinds_required": ['identity-policy', 'claim'],
        "reverify_steps": ['recompute'],
    },
    'pci-allowlist-widening-refused': {
        "domain": 'jail',
        "code": 'pci-allowlist-widening-refused',
        "human": 'jail policy: a scope-widening change was refused',
        "severity": 'high',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'pci-attach-refused': {
        "domain": 'jail',
        "code": 'pci-attach-refused',
        "human": 'jail policy: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'pci-attach-request-malformed': {
        "domain": 'jail',
        "code": 'pci-attach-request-malformed',
        "human": 'jail policy: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'permit-digest-mismatch': {
        "domain": 'permit',
        "code": 'permit-digest-mismatch',
        "human": 'permit lease: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['permit', 'digest', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['recompute-digest', 'check-expiry', 'check-revocation'],
    },
    'permit-downgrade-refused': {
        "domain": 'permit',
        "code": 'permit-downgrade-refused',
        "human": 'permit lease: a version or authority downgrade was refused',
        "severity": 'high',
        "evidence_kinds_required": ['permit', 'digest', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['recompute-digest', 'check-expiry', 'check-revocation'],
    },
    'permit-expired': {
        "domain": 'permit',
        "code": 'permit-expired',
        "human": 'permit lease: the validity window has passed',
        "severity": 'medium',
        "evidence_kinds_required": ['permit', 'digest', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['recompute-digest', 'check-expiry', 'check-revocation'],
    },
    'permit-message-mismatch': {
        "domain": 'mcp',
        "code": 'permit-message-mismatch',
        "human": 'MCP invocation authorization: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['message', 'permit', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'permit-refused': {
        "domain": 'permit',
        "code": 'permit-refused',
        "human": 'permit lease: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['permit', 'digest', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['recompute-digest', 'check-expiry', 'check-revocation'],
    },
    'permit-reused': {
        "domain": 'permit',
        "code": 'permit-reused',
        "human": 'permit lease: reuse of a single-use permit was refused',
        "severity": 'high',
        "evidence_kinds_required": ['permit', 'digest', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['recompute-digest', 'check-expiry', 'check-revocation'],
    },
    'permit-revoked': {
        "domain": 'permit',
        "code": 'permit-revoked',
        "human": 'permit lease: the credential or key has been revoked',
        "severity": 'high',
        "evidence_kinds_required": ['permit', 'digest', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['recompute-digest', 'check-expiry', 'check-revocation'],
    },
    'permit-unknown': {
        "domain": 'permit',
        "code": 'permit-unknown',
        "human": 'permit lease: the identifier is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['permit', 'digest', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['recompute-digest', 'check-expiry', 'check-revocation'],
    },
    'pin_authorship_invalid': {
        "domain": 'platform',
        "code": 'pin_authorship_invalid',
        "human": 'platform egress: the value failed semantic validation; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'pin_chain_broken': {
        "domain": 'platform',
        "code": 'pin_chain_broken',
        "human": 'platform egress: the chain or commitment is broken',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'pin_expired': {
        "domain": 'load_gate',
        "code": 'pin_expired',
        "human": 'load gate: the validity window has passed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'pin_version_not_monotonic': {
        "domain": 'load_gate',
        "code": 'pin_version_not_monotonic',
        "human": 'load gate: the version is not monotonic',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'policy-body-malformed': {
        "domain": 'policy',
        "code": 'policy-body-malformed',
        "human": 'policy compilation: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-compile-refused': {
        "domain": 'policy',
        "code": 'policy-compile-refused',
        "human": 'policy compilation: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-envelope-malformed': {
        "domain": 'jail',
        "code": 'policy-envelope-malformed',
        "human": 'jail policy: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'policy-expired': {
        "domain": 'manifest',
        "code": 'policy-expired',
        "human": 'version manifest: the validity window has passed',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-needs-unimplemented-feature': {
        "domain": 'jail',
        "code": 'policy-needs-unimplemented-feature',
        "human": 'jail policy: the policy needs an unimplemented feature',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'policy-signature-invalid': {
        "domain": 'signature',
        "code": 'policy-signature-invalid',
        "human": 'signature verification: the value failed semantic validation; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'message', 'key'],
        "reverify_steps": ['verify-signature', 'check-key-purpose'],
    },
    'policy-stale': {
        "domain": 'policy',
        "code": 'policy-stale',
        "human": 'policy compilation: the record is older than the allowed verification age',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-unknown': {
        "domain": 'policy',
        "code": 'policy-unknown',
        "human": 'policy compilation: the identifier is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-version-downgrade': {
        "domain": 'jail',
        "code": 'policy-version-downgrade',
        "human": 'jail policy: the policy version would be downgraded',
        "severity": 'high',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'post-rotation': {
        "domain": 'bundle',
        "code": 'post-rotation',
        "human": 'bundle inspection: the post-rotation chain could not be completed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'inspection', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'posture-refused': {
        "domain": 'posture',
        "code": 'posture-refused',
        "human": 'posture signal: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['signal', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'precommit_refused': {
        "domain": 'precommit',
        "code": 'precommit_refused',
        "human": 'pre-commit gate: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['replay-chain'],
    },
    'preexec_chain_failed': {
        "domain": 'platform',
        "code": 'preexec_chain_failed',
        "human": 'platform egress: the operation failed; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'preexec_child_died': {
        "domain": 'platform',
        "code": 'preexec_child_died',
        "human": 'platform egress: the pre-execution child died',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'preexec_recheck_failed': {
        "domain": 'platform',
        "code": 'preexec_recheck_failed',
        "human": 'platform egress: the pre-execution recheck failed',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'preexec_recheck_timeout': {
        "domain": 'platform',
        "code": 'preexec_recheck_timeout',
        "human": 'platform egress: the operation timed out',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'presentation-missing': {
        "domain": 'presentation',
        "code": 'presentation-missing',
        "human": 'presentation binding: required evidence is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['render', 'digest', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'production': {
        "domain": 'deployment',
        "code": 'production',
        "human": 'deployment guard: ungoverned construction was refused because the deployment mode is production',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'production_credential_rejected': {
        "domain": 'credential',
        "code": 'production_credential_rejected',
        "human": 'credential manifest: the item was rejected',
        "severity": 'high',
        "evidence_kinds_required": ['credential', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'proof.envelope': {
        "domain": 'vc',
        "code": 'proof.envelope',
        "human": 'verifiable credential bundle: the proof envelope is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['credential', 'signature', 'digest'],
        "reverify_steps": ['verify-signature'],
    },
    'proof.type': {
        "domain": 'vc',
        "code": 'proof.type',
        "human": 'verifiable credential bundle: the proof type is not supported',
        "severity": 'medium',
        "evidence_kinds_required": ['credential', 'signature', 'digest'],
        "reverify_steps": ['verify-signature'],
    },
    'propose_release': {
        "domain": 'release',
        "code": 'propose_release',
        "human": 'release approval: the release proposal was refused',
        "severity": 'medium',
        "evidence_kinds_required": ['release', 'approval-record', 'signature'],
        "reverify_steps": ['verify-signature', 'replay-chain'],
    },
    'provisioned_required': {
        "domain": 'approval',
        "code": 'provisioned_required',
        "human": 'approval and delegation: a provisioned session identity is required',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'quarantine-bypass-refused': {
        "domain": 'quarantine',
        "code": 'quarantine-bypass-refused',
        "human": 'quarantine admission: refused by policy',
        "severity": 'high',
        "evidence_kinds_required": ['envelope', 'policy', 'digest'],
        "reverify_steps": ['replay-admission'],
    },
    'quarantine-digest-mismatch': {
        "domain": 'quarantine',
        "code": 'quarantine-digest-mismatch',
        "human": 'quarantine admission: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['envelope', 'policy', 'digest'],
        "reverify_steps": ['replay-admission'],
    },
    'quarantine-envelope-override-refused': {
        "domain": 'quarantine',
        "code": 'quarantine-envelope-override-refused',
        "human": 'quarantine admission: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'policy', 'digest'],
        "reverify_steps": ['replay-admission'],
    },
    'quarantine-malformed': {
        "domain": 'quarantine',
        "code": 'quarantine-malformed',
        "human": 'quarantine admission: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'policy', 'digest'],
        "reverify_steps": ['replay-admission'],
    },
    'quarantine-not-admitted': {
        "domain": 'quarantine',
        "code": 'quarantine-not-admitted',
        "human": 'quarantine admission: the item was not admitted from quarantine',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'policy', 'digest'],
        "reverify_steps": ['replay-admission'],
    },
    'quarantine-policy-contract-refused': {
        "domain": 'quarantine',
        "code": 'quarantine-policy-contract-refused',
        "human": 'quarantine admission: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'policy', 'digest'],
        "reverify_steps": ['replay-admission'],
    },
    'quarantine-rejected': {
        "domain": 'quarantine',
        "code": 'quarantine-rejected',
        "human": 'quarantine admission: the quarantine item was rejected',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'policy', 'digest'],
        "reverify_steps": ['replay-admission'],
    },
    'quarantine-unknown-staged': {
        "domain": 'quarantine',
        "code": 'quarantine-unknown-staged',
        "human": 'quarantine admission: the staged quarantine item is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['envelope', 'policy', 'digest'],
        "reverify_steps": ['replay-admission'],
    },
    'quorum-ambiguous': {
        "domain": 'quorum',
        "code": 'quorum-ambiguous',
        "human": 'quorum and thresholds: ambiguous evidence was refused rather than silently classified',
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'vote', 'signature'],
        "reverify_steps": ['recount-votes', 'check-threshold'],
    },
    'quorum-gate-refused': {
        "domain": 'namespace',
        "code": 'quorum-gate-refused',
        "human": 'deployment namespace: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'quorum-not-met': {
        "domain": 'quorum',
        "code": 'quorum-not-met',
        "human": 'quorum and thresholds: a threshold or quorum was not met',
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'vote', 'signature'],
        "reverify_steps": ['recount-votes', 'check-threshold'],
    },
    'quorum-rollback-refused': {
        "domain": 'namespace',
        "code": 'quorum-rollback-refused',
        "human": 'deployment namespace: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'receipt-expired': {
        "domain": 'authorization_receipt',
        "code": 'receipt-expired',
        "human": 'authorization receipt: the validity window has passed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'receipt-format-mismatch': {
        "domain": 'authorization_receipt',
        "code": 'receipt-format-mismatch',
        "human": 'authorization receipt: the recomputed value does not match the claimed value',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'receipt-malformed': {
        "domain": 'authorization_receipt',
        "code": 'receipt-malformed',
        "human": 'authorization receipt: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'receipt-pair-decision-drift': {
        "domain": 'receipt_pair',
        "code": 'receipt-pair-decision-drift',
        "human": "receipt pair: the receipt pair's decision drifted from the recomputed decision",
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'observation', 'digest'],
        "reverify_steps": ['rebind-backlink', 'recompute-decision-digest', 'replay-effect-classify'],
    },
    'receipt-pair-decision-mismatch': {
        "domain": 'receipt_pair',
        "code": 'receipt-pair-decision-mismatch',
        "human": "receipt pair: the receipt pair's decision does not match",
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'observation', 'digest'],
        "reverify_steps": ['rebind-backlink', 'recompute-decision-digest', 'replay-effect-classify'],
    },
    'receipt-pair-effect-drift': {
        "domain": 'receipt_pair',
        "code": 'receipt-pair-effect-drift',
        "human": "receipt pair: the receipt pair's effect drifted",
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'observation', 'digest'],
        "reverify_steps": ['rebind-backlink', 'recompute-decision-digest', 'replay-effect-classify'],
    },
    'receipt-pair-malformed': {
        "domain": 'receipt_pair',
        "code": 'receipt-pair-malformed',
        "human": 'receipt pair: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'observation', 'digest'],
        "reverify_steps": ['rebind-backlink', 'recompute-decision-digest', 'replay-effect-classify'],
    },
    'receipt-pair-not-authorization': {
        "domain": 'receipt_pair',
        "code": 'receipt-pair-not-authorization',
        "human": 'receipt pair: an evidence record presented as authority was refused',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'observation', 'digest'],
        "reverify_steps": ['rebind-backlink', 'recompute-decision-digest', 'replay-effect-classify'],
    },
    'receipt-pair-refused': {
        "domain": 'receipt_pair',
        "code": 'receipt-pair-refused',
        "human": 'receipt pair: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'observation', 'digest'],
        "reverify_steps": ['rebind-backlink', 'recompute-decision-digest', 'replay-effect-classify'],
    },
    'receipt-pair-time-inversion': {
        "domain": 'receipt_pair',
        "code": 'receipt-pair-time-inversion',
        "human": 'receipt pair: the receipt pair timestamps are inverted',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'observation', 'digest'],
        "reverify_steps": ['rebind-backlink', 'recompute-decision-digest', 'replay-effect-classify'],
    },
    'receipt-pair-unknown-field': {
        "domain": 'receipt_pair',
        "code": 'receipt-pair-unknown-field',
        "human": 'receipt pair: the receipt pair carries an unknown field',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'observation', 'digest'],
        "reverify_steps": ['rebind-backlink', 'recompute-decision-digest', 'replay-effect-classify'],
    },
    'decision-effect-decision-drift': {
        "domain": 'decision_effect',
        "code": 'decision-effect-decision-drift',
        "human": 'decision effect: the decision receipt claim drifted from the digest recomputed from its verdict bytes',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'digest'],
        "reverify_steps": ['reseal-decision', 'recompute-decision-digest'],
    },
    'decision-effect-effect-drift': {
        "domain": 'decision_effect',
        "code": 'decision-effect-effect-drift',
        "human": 'decision effect: the execution receipt effect drifted from the re-classified, re-sealed effect',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'observation', 'digest'],
        "reverify_steps": ['replay-effect-classify', 'reseal-effect'],
    },
    'decision-effect-disagreement': {
        "domain": 'decision_effect',
        "code": 'decision-effect-disagreement',
        "human": 'decision effect: what was executed is not what was decided (attempt digests or backlink disagree)',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute-attempt-digests', 'rebind-backlink'],
    },
    'decision-effect-effect-absent': {
        "domain": 'decision_effect',
        "code": 'decision-effect-effect-absent',
        "human": 'decision effect: a decision was presented with no execution record; absence is evidence of non-execution, never acceptance',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['require-execution-record'],
    },
    'decision-effect-extra-effect': {
        "domain": 'decision_effect',
        "code": 'decision-effect-extra-effect',
        "human": 'decision effect: an execution record was presented with no decision authorizing it',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['require-decision-record'],
    },
    'decision-effect-malformed': {
        "domain": 'decision_effect',
        "code": 'decision-effect-malformed',
        "human": 'decision effect: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['validate-shape'],
    },
    'decision-effect-not-authorization': {
        "domain": 'decision_effect',
        "code": 'decision-effect-not-authorization',
        "human": 'decision effect: agreement evidence presented as authority was refused',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['deny-authority-use'],
    },
    'decision-effect-refused': {
        "domain": 'decision_effect',
        "code": 'decision-effect-refused',
        "human": 'decision effect: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['validate-shape'],
    },
    'decision-effect-time-inversion': {
        "domain": 'decision_effect',
        "code": 'decision-effect-time-inversion',
        "human": 'decision effect: the effect timestamp precedes the decision timestamp',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['check-time-order'],
    },
    'agreement-input-unmapped': {
        "domain": 'reconcile_agreement',
        "code": 'agreement-input-unmapped',
        "human": 'reconcile agreement: the input fell outside the closed decision.reported x effect.observed axes, or the not-exercised evidence was not digest-bound; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['validate-axes'],
    },
    'agreement-not-authorization': {
        "domain": 'reconcile_agreement',
        "code": 'agreement-not-authorization',
        "human": 'reconcile agreement: agreement evidence presented as authority was refused',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['deny-authority-use'],
    },
    'receipt_unverifiable': {
        "domain": 'platform',
        "code": 'receipt_unverifiable',
        "human": 'platform egress: the evidence could not be verified',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'recover_torn_tail': {
        "domain": 'journal',
        "code": 'recover_torn_tail',
        "human": 'durable journal: the torn journal tail could not be recovered',
        "severity": 'medium',
        "evidence_kinds_required": ['journal', 'digest'],
        "reverify_steps": ['replay-chain'],
    },
    'reference-not-digest': {
        "domain": 'namespace',
        "code": 'reference-not-digest',
        "human": 'deployment namespace: the reference is not a digest',
        "severity": 'critical',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'registry-malformed': {
        "domain": 'jail',
        "code": 'registry-malformed',
        "human": 'jail policy: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'release_digest': {
        "domain": 'release',
        "code": 'release_digest',
        "human": 'release approval: the release digest could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['release', 'approval-record', 'signature'],
        "reverify_steps": ['verify-signature', 'replay-chain'],
    },
    'render-pair-refused': {
        "domain": 'render',
        "code": 'render-pair-refused',
        "human": 'untrusted render: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['render', 'claim', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'rendering-commitment-broken': {
        "domain": 'render',
        "code": 'rendering-commitment-broken',
        "human": 'untrusted render: the chain or commitment is broken',
        "severity": 'high',
        "evidence_kinds_required": ['render', 'claim', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'replayed_nonce': {
        "domain": 'identity',
        "code": 'replayed_nonce',
        "human": 'identity policy: the nonce was already seen',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-policy', 'claim'],
        "reverify_steps": ['recompute'],
    },
    'requester_target': {
        "domain": 'approval',
        "code": 'requester_target',
        "human": 'approval and delegation: the requester is not the target',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'requester_vote': {
        "domain": 'approval',
        "code": 'requester_vote',
        "human": 'approval and delegation: the requester already voted',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'resume_authority_not_reissued': {
        "domain": 'recovery',
        "code": 'resume_authority_not_reissued',
        "human": 'recovery: resume authority was not reissued',
        "severity": 'medium',
        "evidence_kinds_required": ['journal', 'digest'],
        "reverify_steps": ['replay-chain'],
    },
    'resume_refused': {
        "domain": 'recovery',
        "code": 'resume_refused',
        "human": 'recovery: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['journal', 'digest'],
        "reverify_steps": ['replay-chain'],
    },
    'reverify-malformed': {
        "domain": 'reverify',
        "code": 'reverify-malformed',
        "human": 'use-time re-verification: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['parent-record', 'signature', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['verify-signature', 'check-revocation', 'check-liveness'],
    },
    'reverify-not-authorization': {
        "domain": 'reverify',
        "code": 'reverify-not-authorization',
        "human": 'use-time re-verification: an evidence record presented as authority was refused',
        "severity": 'high',
        "evidence_kinds_required": ['parent-record', 'signature', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['verify-signature', 'check-revocation', 'check-liveness'],
    },
    'reverify-parent-signature-invalid': {
        "domain": 'reverify',
        "code": 'reverify-parent-signature-invalid',
        "human": 'use-time re-verification: the value failed semantic validation; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['parent-record', 'signature', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['verify-signature', 'check-revocation', 'check-liveness'],
    },
    'reverify-refused': {
        "domain": 'reverify',
        "code": 'reverify-refused',
        "human": 'use-time re-verification: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['parent-record', 'signature', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['verify-signature', 'check-revocation', 'check-liveness'],
    },
    'reverify-required': {
        "domain": 'reverify',
        "code": 'reverify-required',
        "human": 'use-time re-verification: use-time re-verification is required',
        "severity": 'medium',
        "evidence_kinds_required": ['parent-record', 'signature', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['verify-signature', 'check-revocation', 'check-liveness'],
    },
    'reverify-revoked': {
        "domain": 'reverify',
        "code": 'reverify-revoked',
        "human": 'use-time re-verification: the credential or key has been revoked',
        "severity": 'high',
        "evidence_kinds_required": ['parent-record', 'signature', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['verify-signature', 'check-revocation', 'check-liveness'],
    },
    'reverify-stale': {
        "domain": 'reverify',
        "code": 'reverify-stale',
        "human": 'use-time re-verification: the parent record is older than the allowed verification age',
        "severity": 'medium',
        "evidence_kinds_required": ['parent-record', 'signature', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['verify-signature', 'check-revocation', 'check-liveness'],
    },
    'reverify-unknown-parent-kind': {
        "domain": 'reverify',
        "code": 'reverify-unknown-parent-kind',
        "human": 'use-time re-verification: the parent record kind is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['parent-record', 'signature', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['verify-signature', 'check-revocation', 'check-liveness'],
    },
    'revocation-entry-unverifiable': {
        "domain": 'revocation',
        "code": 'revocation-entry-unverifiable',
        "human": 'revocation: the evidence could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['revocation-registry', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'revocation-inexact-target-refused': {
        "domain": 'revocation',
        "code": 'revocation-inexact-target-refused',
        "human": 'revocation: an inexact revocation target was refused',
        "severity": 'high',
        "evidence_kinds_required": ['revocation-registry', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'revocation-refused': {
        "domain": 'revocation',
        "code": 'revocation-refused',
        "human": 'revocation: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['revocation-registry', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'revoke_not_authorized': {
        "domain": 'approval',
        "code": 'revoke_not_authorized',
        "human": 'approval and delegation: the revoker is not authorized to revoke this grant',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'rollback-detected': {
        "domain": 'manifest',
        "code": 'rollback-detected',
        "human": 'version manifest: a rollback to an older signed version was detected',
        "severity": 'critical',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'rule-missing': {
        "domain": 'audit',
        "code": 'rule-missing',
        "human": 'audit detection: required evidence is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['rule-pack', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'rule-tampered': {
        "domain": 'audit',
        "code": 'rule-tampered',
        "human": 'audit detection: evidence of tampering was detected',
        "severity": 'critical',
        "evidence_kinds_required": ['rule-pack', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'rule-unbound': {
        "domain": 'audit',
        "code": 'rule-unbound',
        "human": 'audit detection: a rule is not bound to a verifiable source',
        "severity": 'medium',
        "evidence_kinds_required": ['rule-pack', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'run_limits': {
        "domain": 'policy',
        "code": 'run_limits',
        "human": 'policy compilation: the run limits are invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'sandbox-refused': {
        "domain": 'capability',
        "code": 'sandbox-refused',
        "human": 'capability assessment: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'scan_gate': {
        "domain": 'scan',
        "code": 'scan_gate',
        "human": 'scan verdict: the scan gate is not satisfied',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_gate_refused': {
        "domain": 'load_gate',
        "code": 'scan_gate_refused',
        "human": 'load gate: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'scan_gate_unwired': {
        "domain": 'load_gate',
        "code": 'scan_gate_unwired',
        "human": 'load gate: the scan gate is not wired',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'scan_policy': {
        "domain": 'scan',
        "code": 'scan_policy',
        "human": 'scan verdict: the scan policy is not satisfied',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_policy_duplicates': {
        "domain": 'scan',
        "code": 'scan_policy_duplicates',
        "human": 'scan verdict: the scan policy contains duplicates',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_bad_bytes': {
        "domain": 'scan',
        "code": 'scan_verdict_bad_bytes',
        "human": 'scan verdict: the scan verdict failed validation (bad bytes)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_bad_digest': {
        "domain": 'scan',
        "code": 'scan_verdict_bad_digest',
        "human": 'scan verdict: the scan verdict failed validation (bad digest)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_bad_json': {
        "domain": 'scan',
        "code": 'scan_verdict_bad_json',
        "human": 'scan verdict: the scan verdict failed validation (bad json)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_bad_scanner_name': {
        "domain": 'scan',
        "code": 'scan_verdict_bad_scanner_name',
        "human": 'scan verdict: the scan verdict failed validation (bad scanner name)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_bad_scanner_version': {
        "domain": 'scan',
        "code": 'scan_verdict_bad_scanner_version',
        "human": 'scan verdict: the scan verdict failed validation (bad scanner version)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_bad_severity_counts': {
        "domain": 'scan',
        "code": 'scan_verdict_bad_severity_counts',
        "human": 'scan verdict: the scan verdict failed validation (bad severity counts)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_bad_timestamp': {
        "domain": 'scan',
        "code": 'scan_verdict_bad_timestamp',
        "human": 'scan verdict: the scan verdict failed validation (bad timestamp)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_bad_verdict': {
        "domain": 'scan',
        "code": 'scan_verdict_bad_verdict',
        "human": 'scan verdict: the scan verdict failed validation (bad verdict)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_bad_verifiers': {
        "domain": 'scan',
        "code": 'scan_verdict_bad_verifiers',
        "human": 'scan verdict: the scan verdict failed validation (bad verifiers)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_born_stale': {
        "domain": 'scan',
        "code": 'scan_verdict_born_stale',
        "human": 'scan verdict: the scan verdict failed validation (born stale)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_empty_window': {
        "domain": 'scan',
        "code": 'scan_verdict_empty_window',
        "human": 'scan verdict: the scan verdict failed validation (empty window)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_future_scan': {
        "domain": 'scan',
        "code": 'scan_verdict_future_scan',
        "human": 'scan verdict: the scan verdict failed validation (future scan)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_malformed_envelope': {
        "domain": 'scan',
        "code": 'scan_verdict_malformed_envelope',
        "human": 'scan verdict: the scan verdict failed validation (malformed envelope)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_missing': {
        "domain": 'scan',
        "code": 'scan_verdict_missing',
        "human": 'scan verdict: the scan verdict failed validation (missing)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_missing_fields': {
        "domain": 'scan',
        "code": 'scan_verdict_missing_fields',
        "human": 'scan verdict: the scan verdict failed validation (missing fields)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_negative': {
        "domain": 'scan',
        "code": 'scan_verdict_negative',
        "human": 'scan verdict: the scan verdict failed validation (negative)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_no_signer': {
        "domain": 'scan',
        "code": 'scan_verdict_no_signer',
        "human": 'scan verdict: the scan verdict failed validation (no signer)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_no_verifiers': {
        "domain": 'scan',
        "code": 'scan_verdict_no_verifiers',
        "human": 'scan verdict: the scan verdict failed validation (no verifiers)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_not_canonical': {
        "domain": 'scan',
        "code": 'scan_verdict_not_canonical',
        "human": 'scan verdict: the scan verdict failed validation (not canonical)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_payload_type': {
        "domain": 'scan',
        "code": 'scan_verdict_payload_type',
        "human": 'scan verdict: the scan verdict failed validation (payload type)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_scanner_mismatch': {
        "domain": 'scan',
        "code": 'scan_verdict_scanner_mismatch',
        "human": 'scan verdict: the scan verdict failed validation (scanner mismatch)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_signature_invalid': {
        "domain": 'scan',
        "code": 'scan_verdict_signature_invalid',
        "human": 'scan verdict: the scan verdict failed validation (signature invalid)',
        "severity": 'high',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_stale': {
        "domain": 'scan',
        "code": 'scan_verdict_stale',
        "human": 'scan verdict: the scan verdict failed validation (stale)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_target_mismatch': {
        "domain": 'scan',
        "code": 'scan_verdict_target_mismatch',
        "human": 'scan verdict: the scan verdict failed validation (target mismatch)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_unknown_fields': {
        "domain": 'scan',
        "code": 'scan_verdict_unknown_fields',
        "human": 'scan verdict: the scan verdict failed validation (unknown fields)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_unknown_scanner': {
        "domain": 'scan',
        "code": 'scan_verdict_unknown_scanner',
        "human": 'scan verdict: the scan verdict failed validation (unknown scanner)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdict_window_too_long': {
        "domain": 'scan',
        "code": 'scan_verdict_window_too_long',
        "human": 'scan verdict: the scan verdict failed validation (window too long)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'signature', 'digest'],
        "reverify_steps": ['verify-signature', 'recompute-digest'],
    },
    'scan_verdicts_unpresented': {
        "domain": 'load_gate',
        "code": 'scan_verdicts_unpresented',
        "human": 'load gate: required evidence was not presented',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'scope_amplification': {
        "domain": 'approval',
        "code": 'scope_amplification',
        "human": 'approval and delegation: scope amplification was detected',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'scope_denied': {
        "domain": 'lease',
        "code": 'scope_denied',
        "human": 'capability lease: the scope was denied',
        "severity": 'medium',
        "evidence_kinds_required": ['lease', 'timestamp', 'revocation-registry'],
        "reverify_steps": ['check-expiry', 'check-revocation'],
    },
    'scope_exceeded': {
        "domain": 'approval',
        "code": 'scope_exceeded',
        "human": 'approval and delegation: the scope was exceeded',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'scope_widened': {
        "domain": 'approval',
        "code": 'scope_widened',
        "human": 'approval and delegation: the scope was widened',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'self_delegation': {
        "domain": 'approval',
        "code": 'self_delegation',
        "human": 'approval and delegation: self-delegation was refused',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'signal-kind-required': {
        "domain": 'posture',
        "code": 'signal-kind-required',
        "human": 'posture signal: a required check or input is missing',
        "severity": 'medium',
        "evidence_kinds_required": ['signal', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'signal-not-authorization': {
        "domain": 'posture',
        "code": 'signal-not-authorization',
        "human": 'posture signal: an evidence record presented as authority was refused',
        "severity": 'high',
        "evidence_kinds_required": ['signal', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'signal-scope-mismatch': {
        "domain": 'posture',
        "code": 'signal-scope-mismatch',
        "human": 'posture signal: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['signal', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'signal-unknown-event': {
        "domain": 'posture',
        "code": 'signal-unknown-event',
        "human": 'posture signal: the signal event is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['signal', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'signal-unknown-kind': {
        "domain": 'posture',
        "code": 'signal-unknown-kind',
        "human": 'posture signal: the signal kind is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['signal', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'signal-unverifiable': {
        "domain": 'posture',
        "code": 'signal-unverifiable',
        "human": 'posture signal: the evidence could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['signal', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'signature-invalid': {
        "domain": 'authorization_receipt',
        "code": 'signature-invalid',
        "human": 'authorization receipt: the value failed semantic validation; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'signer-denied': {
        "domain": 'c2pa',
        "code": 'signer-denied',
        "human": 'C2PA conformance: the signer denied the operation',
        "severity": 'high',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'signer-error': {
        "domain": 'jail',
        "code": 'signer-error',
        "human": 'jail policy: the signer returned an error',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'single-use-issuer-revoked': {
        "domain": 'single_use',
        "code": 'single-use-issuer-revoked',
        "human": 'single-use attestation: the attestation issuer has been revoked',
        "severity": 'high',
        "evidence_kinds_required": ['attestation', 'revocation-registry'],
        "reverify_steps": ['check-not-consumed', 'check-issuer-revocation'],
    },
    'single-use-malformed': {
        "domain": 'single_use',
        "code": 'single-use-malformed',
        "human": 'single-use attestation: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['attestation', 'revocation-registry'],
        "reverify_steps": ['check-not-consumed', 'check-issuer-revocation'],
    },
    'single-use-refused': {
        "domain": 'single_use',
        "code": 'single-use-refused',
        "human": 'single-use attestation: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['attestation', 'revocation-registry'],
        "reverify_steps": ['check-not-consumed', 'check-issuer-revocation'],
    },
    'single-use-replay-refused': {
        "domain": 'single_use',
        "code": 'single-use-replay-refused',
        "human": 'single-use attestation: replay of a consumed single-use attestation was refused',
        "severity": 'high',
        "evidence_kinds_required": ['attestation', 'revocation-registry'],
        "reverify_steps": ['check-not-consumed', 'check-issuer-revocation'],
    },
    'single-use-unknown': {
        "domain": 'single_use',
        "code": 'single-use-unknown',
        "human": 'single-use attestation: the single-use attestation is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['attestation', 'revocation-registry'],
        "reverify_steps": ['check-not-consumed', 'check-issuer-revocation'],
    },
    'single-use-lifecycle-refused': {
        "domain": 'single_use',
        "code": 'single-use-lifecycle-refused',
        "human": 'single-use lifecycle: refused by policy (generic lifecycle refusal)',
        "severity": 'medium',
        "evidence_kinds_required": ['reservation'],
        "reverify_steps": ['check-not-consumed', 'check-approval-registered'],
    },
    'single-use-reserve-conflict': {
        "domain": 'single_use',
        "code": 'single-use-reserve-conflict',
        "human": 'single-use lifecycle: atomic reserve of the (approval digest, step id, input digest) triple lost the race; the second consumer was refused',
        "severity": 'high',
        "evidence_kinds_required": ['reservation', 'approval-digest'],
        "reverify_steps": ['check-not-consumed', 'check-approval-registered'],
    },
    'single-use-not-reserved': {
        "domain": 'single_use',
        "code": 'single-use-not-reserved',
        "human": 'single-use lifecycle: execution was attempted with no live reservation for the (approval digest, step id, input digest) triple',
        "severity": 'high',
        "evidence_kinds_required": ['reservation', 'approval-digest'],
        "reverify_steps": ['check-not-consumed', 'check-approval-registered'],
    },
    'single-use-reservation-mismatch': {
        "domain": 'single_use',
        "code": 'single-use-reservation-mismatch',
        "human": 'single-use lifecycle: the presented step id, input digest, or consumption binding does not match the reservation',
        "severity": 'high',
        "evidence_kinds_required": ['reservation', 'consumption-record'],
        "reverify_steps": ['check-not-consumed', 'check-approval-registered'],
    },
    'single-use-reservation-unknown': {
        "domain": 'single_use',
        "code": 'single-use-reservation-unknown',
        "human": 'single-use lifecycle: the approval digest, reservation, or admission is not known to this registry',
        "severity": 'high',
        "evidence_kinds_required": ['reservation', 'approval-digest'],
        "reverify_steps": ['check-not-consumed', 'check-approval-registered'],
    },
    'single-use-reconcile-replayed': {
        "domain": 'single_use',
        "code": 'single-use-reconcile-replayed',
        "human": 'single-use lifecycle: reconcile was called on an already-reconciled reservation',
        "severity": 'high',
        "evidence_kinds_required": ['reservation', 'consumption-record'],
        "reverify_steps": ['check-not-consumed', 'check-approval-registered'],
    },
    'skill-id-mismatch': {
        "domain": 'capability',
        "code": 'skill-id-mismatch',
        "human": 'capability assessment: the recomputed value does not match the claimed value',
        "severity": 'high',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'skill_not_found': {
        "domain": 'load_gate',
        "code": 'skill_not_found',
        "human": 'load gate: the item was not found',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'spawn_failed': {
        "domain": 'platform',
        "code": 'spawn_failed',
        "human": 'platform egress: the operation failed; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'stale-trust': {
        "domain": 'agent_card',
        "code": 'stale-trust',
        "human": 'agent card: the trust record is stale',
        "severity": 'medium',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'stale_seq': {
        "domain": 'drift',
        "code": 'stale_seq',
        "human": 'drift detection: the sequence number is stale',
        "severity": 'medium',
        "evidence_kinds_required": ['observation', 'baseline', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'stale_sequence': {
        "domain": 'identity',
        "code": 'stale_sequence',
        "human": 'identity policy: the sequence number is stale',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-policy', 'claim'],
        "reverify_steps": ['recompute'],
    },
    'statement-too-large': {
        "domain": 'scitt',
        "code": 'statement-too-large',
        "human": 'SCITT receipt: the statement exceeds the size limit',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'store_lock_unavailable': {
        "domain": 'approval',
        "code": 'store_lock_unavailable',
        "human": 'approval and delegation: the delegation store lock could not be acquired; refusing to mutate rather than risk a torn race',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'sub_threshold': {
        "domain": 'drift',
        "code": 'sub_threshold',
        "human": 'drift detection: below the threshold',
        "severity": 'medium',
        "evidence_kinds_required": ['observation', 'baseline', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'subject-denied': {
        "domain": 'scitt',
        "code": 'subject-denied',
        "human": 'SCITT receipt: the subject was denied',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'subject-not-allowlisted': {
        "domain": 'scitt',
        "code": 'subject-not-allowlisted',
        "human": 'SCITT receipt: the subject is not allowlisted',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'subject-unanchored': {
        "domain": 'mcp',
        "code": 'subject-unanchored',
        "human": 'MCP invocation authorization: the subject is not anchored',
        "severity": 'medium',
        "evidence_kinds_required": ['message', 'permit', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'subject_claims': {
        "domain": 'vc',
        "code": 'subject_claims',
        "human": 'verifiable credential bundle: the subject claims are invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['credential', 'signature', 'digest'],
        "reverify_steps": ['verify-signature'],
    },
    'svr-digest-malformed': {
        "domain": 'svr',
        "code": 'svr-digest-malformed',
        "human": 'supply-chain verification record: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['svr', 'artifact-digest', 'reproduction-pointer'],
        "reverify_steps": ['recompute-svr-digest', 'validate-pointers'],
    },
    'svr-digest-mismatch': {
        "domain": 'svr',
        "code": 'svr-digest-mismatch',
        "human": 'supply-chain verification record: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['svr', 'artifact-digest', 'reproduction-pointer'],
        "reverify_steps": ['recompute-svr-digest', 'validate-pointers'],
    },
    'svr-malformed': {
        "domain": 'svr',
        "code": 'svr-malformed',
        "human": 'supply-chain verification record: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['svr', 'artifact-digest', 'reproduction-pointer'],
        "reverify_steps": ['recompute-svr-digest', 'validate-pointers'],
    },
    'svr-no-reproduction-pointer': {
        "domain": 'svr',
        "code": 'svr-no-reproduction-pointer',
        "human": 'supply-chain verification record: the SVR has no reproduction pointer',
        "severity": 'medium',
        "evidence_kinds_required": ['svr', 'artifact-digest', 'reproduction-pointer'],
        "reverify_steps": ['recompute-svr-digest', 'validate-pointers'],
    },
    'svr-not-authorization': {
        "domain": 'svr',
        "code": 'svr-not-authorization',
        "human": 'supply-chain verification record: an evidence record presented as authority was refused',
        "severity": 'high',
        "evidence_kinds_required": ['svr', 'artifact-digest', 'reproduction-pointer'],
        "reverify_steps": ['recompute-svr-digest', 'validate-pointers'],
    },
    'svr-pointer-malformed': {
        "domain": 'svr',
        "code": 'svr-pointer-malformed',
        "human": 'supply-chain verification record: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['svr', 'artifact-digest', 'reproduction-pointer'],
        "reverify_steps": ['recompute-svr-digest', 'validate-pointers'],
    },
    'svr-refused': {
        "domain": 'svr',
        "code": 'svr-refused',
        "human": 'supply-chain verification record: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['svr', 'artifact-digest', 'reproduction-pointer'],
        "reverify_steps": ['recompute-svr-digest', 'validate-pointers'],
    },
    'tainted_run': {
        "domain": 'memory',
        "code": 'tainted_run',
        "human": 'memory: the run is tainted',
        "severity": 'medium',
        "evidence_kinds_required": ['memory', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'tamper': {
        "domain": 'approval',
        "code": 'tamper',
        "human": 'approval and delegation: tampering was detected; refused',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'terminal-transition-refused': {
        "domain": 'arap',
        "code": 'terminal-transition-refused',
        "human": 'ARAP lifecycle: a terminal lifecycle transition was refused',
        "severity": 'medium',
        "evidence_kinds_required": ['request', 'context', 'handle', 'timestamp'],
        "reverify_steps": ['recompute'],
    },
    'threshold-unmet': {
        "domain": 'quorum',
        "code": 'threshold-unmet',
        "human": 'quorum and thresholds: a threshold or quorum was not met',
        "severity": 'medium',
        "evidence_kinds_required": ['quorum', 'vote', 'signature'],
        "reverify_steps": ['recount-votes', 'check-threshold'],
    },
    'tool-crashed': {
        "domain": 'capability',
        "code": 'tool-crashed',
        "human": 'capability assessment: the tool crashed',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'tool-failed-no-commit': {
        "domain": 'capability',
        "code": 'tool-failed-no-commit',
        "human": 'capability assessment: the tool failed without committing',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'tool-timed-out': {
        "domain": 'capability',
        "code": 'tool-timed-out',
        "human": 'capability assessment: the tool timed out',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'tool_ratings': {
        "domain": 'tool',
        "code": 'tool_ratings',
        "human": 'tool rating: the tool ratings are invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['rating', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'trust-class-unknown': {
        "domain": 'deploy',
        "code": 'trust-class-unknown',
        "human": 'deployment trust config: the trust class is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'trust-root-revoked': {
        "domain": 'deploy',
        "code": 'trust-root-revoked',
        "human": 'deployment trust config: the trust root has been revoked',
        "severity": 'high',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'trust-root-unknown': {
        "domain": 'deploy',
        "code": 'trust-root-unknown',
        "human": 'deployment trust config: the trust root is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'trust-threshold-unmet': {
        "domain": 'deploy',
        "code": 'trust-threshold-unmet',
        "human": 'deployment trust config: a threshold or quorum was not met',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'ttl_extended': {
        "domain": 'approval',
        "code": 'ttl_extended',
        "human": 'approval and delegation: the TTL was extended beyond policy',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'ttl_out_of_range': {
        "domain": 'approval',
        "code": 'ttl_out_of_range',
        "human": 'approval and delegation: the TTL is out of range',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'typed-action-malformed': {
        "domain": 'typed_action',
        "code": 'typed-action-malformed',
        "human": 'typed action: the binding is structurally malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'typed-action-not-bound': {
        "domain": 'typed_action',
        "code": 'typed-action-not-bound',
        "human": 'typed action: the capsule carries no bound typed-action block',
        "severity": 'medium',
        "evidence_kinds_required": ['capsule'],
        "reverify_steps": ['replay-chain'],
    },
    'typed-action-refused': {
        "domain": 'typed_action',
        "code": 'typed-action-refused',
        "human": 'typed action: generic refusal',
        "severity": 'medium',
        "evidence_kinds_required": ['type-definition'],
        "reverify_steps": ['recompute'],
    },
    'typed-context': {
        "domain": 'context',
        "code": 'typed-context',
        "human": 'context schema: the typed context is invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['context', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'unbound-grant-label': {
        "domain": 'capability',
        "code": 'unbound-grant-label',
        "human": 'capability assessment: the grant label is not bound',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'undeclared_credential_in_scope': {
        "domain": 'credential',
        "code": 'undeclared_credential_in_scope',
        "human": 'credential manifest: an undeclared credential is in scope',
        "severity": 'high',
        "evidence_kinds_required": ['credential', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'unknown-action-label': {
        "domain": 'c2pa',
        "code": 'unknown-action-label',
        "human": 'C2PA conformance: the action label is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'unknown-assertion-label': {
        "domain": 'c2pa',
        "code": 'unknown-assertion-label',
        "human": 'C2PA conformance: the assertion label is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'unknown-bundle': {
        "domain": 'namespace',
        "code": 'unknown-bundle',
        "human": 'deployment namespace: the bundle is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'unknown-grant': {
        "domain": 'authorization_receipt',
        "code": 'unknown-grant',
        "human": 'authorization receipt: the grant id is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'unknown-grant-id': {
        "domain": 'capability',
        "code": 'unknown-grant-id',
        "human": 'capability assessment: the grant id is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'unknown-kid': {
        "domain": 'capability',
        "code": 'unknown-kid',
        "human": 'capability assessment: the key id is not known',
        "severity": 'high',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'unknown-manifest-category': {
        "domain": 'capability',
        "code": 'unknown-manifest-category',
        "human": 'capability assessment: the manifest category is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'unknown_agent': {
        "domain": 'discovery',
        "code": 'unknown_agent',
        "human": 'agent discovery: the agent is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['inventory', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'unknown_approval': {
        "domain": 'approval',
        "code": 'unknown_approval',
        "human": 'approval and delegation: the approval is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'unknown_delegatee_agent': {
        "domain": 'approval',
        "code": 'unknown_delegatee_agent',
        "human": 'approval and delegation: the delegatee agent is not known',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'unknown_grant': {
        "domain": 'approval',
        "code": 'unknown_grant',
        "human": 'approval and delegation: the grant id is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'unknown_issuer': {
        "domain": 'lease',
        "code": 'unknown_issuer',
        "human": 'capability lease: the issuer is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['lease', 'timestamp', 'revocation-registry'],
        "reverify_steps": ['check-expiry', 'check-revocation'],
    },
    'unknown_parent': {
        "domain": 'approval',
        "code": 'unknown_parent',
        "human": 'approval and delegation: the delegation parent is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'unpin_version_not_monotonic': {
        "domain": 'load_gate',
        "code": 'unpin_version_not_monotonic',
        "human": 'load gate: the version is not monotonic',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest', 'replay-chain'],
    },
    'unregistered_agent': {
        "domain": 'discovery',
        "code": 'unregistered_agent',
        "human": 'agent discovery: the agent is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['inventory', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'unregistered_delegatee': {
        "domain": 'approval',
        "code": 'unregistered_delegatee',
        "human": 'approval and delegation: the delegatee is not registered',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'unresolvable_mode': {
        "domain": 'deployment',
        "code": 'unresolvable_mode',
        "human": 'deployment guard: the deployment mode could not be resolved; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['deployment', 'checklist', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'unsigned-refused': {
        "domain": 'signature',
        "code": 'unsigned-refused',
        "human": 'signature verification: refused by policy',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'message', 'key'],
        "reverify_steps": ['verify-signature', 'check-key-purpose'],
    },
    'unsupported-alg': {
        "domain": 'alg',
        "code": 'unsupported-alg',
        "human": 'algorithm registry: the algorithm is not supported',
        "severity": 'medium',
        "evidence_kinds_required": ['algorithm', 'record', 'signature'],
        "reverify_steps": ['negotiate-algorithm'],
    },
    'unsupported-correlation': {
        "domain": 'audit',
        "code": 'unsupported-correlation',
        "human": 'audit detection: the correlation is not supported',
        "severity": 'medium',
        "evidence_kinds_required": ['rule-pack', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'untrusted-jku': {
        "domain": 'agent_card',
        "code": 'untrusted-jku',
        "human": 'agent card: the JWK set URL is not trusted',
        "severity": 'high',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'untrusted-render-error': {
        "domain": 'render',
        "code": 'untrusted-render-error',
        "human": 'untrusted render: an error was detected; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['render', 'claim', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'untrusted-signer': {
        "domain": 'c2pa',
        "code": 'untrusted-signer',
        "human": 'C2PA conformance: the signer is not trusted',
        "severity": 'high',
        "evidence_kinds_required": ['manifest', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'untrusted_tier': {
        "domain": 'memory',
        "code": 'untrusted_tier',
        "human": 'memory: the tier is not trusted',
        "severity": 'medium',
        "evidence_kinds_required": ['memory', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'upload_failed': {
        "domain": 'platform',
        "code": 'upload_failed',
        "human": 'platform egress: the platform egress upload failed; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'verifier-malformed': {
        "domain": 'authorization_receipt',
        "code": 'verifier-malformed',
        "human": 'authorization receipt: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'vote_already_cast': {
        "domain": 'approval',
        "code": 'vote_already_cast',
        "human": 'approval and delegation: the vote was already cast',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'wall_proof_unreadable': {
        "domain": 'platform',
        "code": 'wall_proof_unreadable',
        "human": 'platform egress: the artifact could not be read',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'wiring-malformed': {
        "domain": 'jail',
        "code": 'wiring-malformed',
        "human": 'jail policy: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'wiring-unmapped-mount': {
        "domain": 'jail',
        "code": 'wiring-unmapped-mount',
        "human": 'jail policy: the mount is not mapped in the wiring',
        "severity": 'medium',
        "evidence_kinds_required": ['jail-policy', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'wrong-keyset-purpose': {
        "domain": 'key_identity',
        "code": 'wrong-keyset-purpose',
        "human": 'registered key identity: the key set was used for the wrong purpose',
        "severity": 'high',
        "evidence_kinds_required": ['key-registry', 'pubkey', 'revocation-registry', 'signature'],
        "reverify_steps": ['recompute-pubkey-digest', 'resolve-key', 'check-revocation', 'verify-signature'],
    },
    'wrong-purpose': {
        "domain": 'key_identity',
        "code": 'wrong-purpose',
        "human": 'registered key identity: the key was used for the wrong purpose',
        "severity": 'high',
        "evidence_kinds_required": ['key-registry', 'pubkey', 'revocation-registry', 'signature'],
        "reverify_steps": ['recompute-pubkey-digest', 'resolve-key', 'check-revocation', 'verify-signature'],
    },
    'wrong_delegator': {
        "domain": 'approval',
        "code": 'wrong_delegator',
        "human": 'approval and delegation: the delegator identity is wrong',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'wrong_run_identity': {
        "domain": 'approval',
        "code": 'wrong_run_identity',
        "human": 'approval and delegation: the run identity is wrong',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    # Wave-229 merge (integration fix): the wave-228 taxonomy was closed
    # over the wave-228 tree; the battery's independent whole-tree scanner
    # found 16 new wave-229 lane-A/C refusal strings unmapped. Added here in
    # the module's own conventions; severities follow the documented
    # triage guide (critical = recomputed evidence disagrees with the claim).
    'checkpoint-refused': {
        "domain": 'checkpoints',
        "code": 'checkpoint-refused',
        "human": 'audit checkpoints: generic checkpoint refusal',
        "severity": 'medium',
        "evidence_kinds_required": ['checkpoint', 'audit-log', 'signature'],
        "reverify_steps": ['recompute', 'verify-signature'],
    },
    'checkpoint-malformed': {
        "domain": 'checkpoints',
        "code": 'checkpoint-malformed',
        "human": 'audit checkpoints: the checkpoint or its inputs are structurally malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['checkpoint', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-signature-invalid': {
        "domain": 'checkpoints',
        "code": 'checkpoint-signature-invalid',
        "human": 'audit checkpoints: the checkpoint signature does not verify',
        "severity": 'critical',
        "evidence_kinds_required": ['checkpoint', 'signature'],
        "reverify_steps": ['verify-signature'],
    },
    'checkpoint-log-incomplete': {
        "domain": 'checkpoints',
        "code": 'checkpoint-log-incomplete',
        "human": 'audit checkpoints: the log is truncated against the checkpoint (fewer entries than committed)',
        "severity": 'critical',
        "evidence_kinds_required": ['checkpoint', 'audit-log', 'signature'],
        "reverify_steps": ['recompute', 'verify-signature'],
    },
    'checkpoint-count-mismatch': {
        "domain": 'checkpoints',
        "code": 'checkpoint-count-mismatch',
        "human": 'audit checkpoints: the log has more entries than the checkpoint commits to',
        "severity": 'critical',
        "evidence_kinds_required": ['checkpoint', 'audit-log', 'signature'],
        "reverify_steps": ['recompute', 'verify-signature'],
    },
    'checkpoint-log-reordered': {
        "domain": 'checkpoints',
        "code": 'checkpoint-log-reordered',
        "human": 'audit checkpoints: the recomputed MMR peaks disagree with the committed peaks (reorder or silent content substitution)',
        "severity": 'critical',
        "evidence_kinds_required": ['checkpoint', 'audit-log', 'signature'],
        "reverify_steps": ['recompute', 'verify-signature'],
    },
    'checkpoint-chain-broken': {
        "domain": 'checkpoints',
        "code": 'checkpoint-chain-broken',
        "human": 'audit checkpoints: a checkpoint prev_digest link does not match its predecessor',
        "severity": 'critical',
        "evidence_kinds_required": ['checkpoint', 'signature'],
        "reverify_steps": ['recompute', 'verify-signature'],
    },
    'checkpoint-evidence-not-authorization': {
        "domain": 'checkpoints',
        "code": 'checkpoint-evidence-not-authorization',
        "human": 'audit checkpoints: checkpoint evidence was used as authority',
        "severity": 'high',
        "evidence_kinds_required": ['checkpoint'],
        "reverify_steps": ['recompute'],
    },
    'replay-refused': {
        "domain": 'policy_replay',
        "code": 'replay-refused',
        "human": 'policy replay: generic replay refusal',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-revision', 'evidence'],
        "reverify_steps": ['recompute', 'replay-claim'],
    },
    'replay-policy-malformed': {
        "domain": 'policy_replay',
        "code": 'replay-policy-malformed',
        "human": 'policy replay: the revision record or evidence envelope is structurally malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-revision', 'evidence'],
        "reverify_steps": ['recompute'],
    },
    'replay-policy-revision-unknown': {
        "domain": 'policy_replay',
        "code": 'replay-policy-revision-unknown',
        "human": 'policy replay: the pinned revision is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-revision'],
        "reverify_steps": ['recompute'],
    },
    'replay-policy-revision-conflict': {
        "domain": 'policy_replay',
        "code": 'replay-policy-revision-conflict',
        "human": 'policy replay: the same rev_id was registered with different ruleset bytes',
        "severity": 'high',
        "evidence_kinds_required": ['policy-revision', 'evidence'],
        "reverify_steps": ['recompute'],
    },
    'replay-policy-digest-mismatch': {
        "domain": 'policy_replay',
        "code": 'replay-policy-digest-mismatch',
        "human": 'policy replay: a caller-supplied digest disagrees with the digest recomputed from the ruleset bytes',
        "severity": 'critical',
        "evidence_kinds_required": ['policy-revision', 'evidence'],
        "reverify_steps": ['recompute'],
    },
    'replay-evidence-tampered': {
        "domain": 'policy_replay',
        "code": 'replay-evidence-tampered',
        "human": 'policy replay: the captured evidence digest does not match its contents',
        "severity": 'critical',
        "evidence_kinds_required": ['policy-revision', 'evidence'],
        "reverify_steps": ['recompute'],
    },
    'replay-policy-drift': {
        "domain": 'policy_replay',
        "code": 'replay-policy-drift',
        "human": 'policy replay: the live policy revision differs from the pinned revision and would change the verdict',
        "severity": 'high',
        "evidence_kinds_required": ['policy-revision', 'evidence'],
        "reverify_steps": ['recompute', 'replay-claim'],
    },
    'replay-policy-not-authorization': {
        "domain": 'policy_replay',
        "code": 'replay-policy-not-authorization',
        "human": 'policy replay: replay evidence was used as authority',
        "severity": 'high',
        "evidence_kinds_required": ['policy-revision'],
        "reverify_steps": ['recompute'],
    },
    'deny-receipt-refused': {
        "domain": 'receipts',
        "code": 'deny-receipt-refused',
        "human": 'signed receipts: base refusal for signed receipt failures',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'decision'],
        "reverify_steps": ['recompute', 'verify-signature'],
    },
    'taxonomy-receipt-missing': {
        "domain": 'receipts',
        "code": 'taxonomy-receipt-missing',
        "human": 'signed receipts: the decision lacked digest-shaped evidence, so no receipt was formed',
        "severity": 'medium',
        "evidence_kinds_required": ['decision'],
        "reverify_steps": ['recompute'],
    },
    'deny-receipt-malformed': {
        "domain": 'receipts',
        "code": 'deny-receipt-malformed',
        "human": 'signed receipts: the presented receipt record is not well-formed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'deny-receipt-signature-invalid': {
        "domain": 'receipts',
        "code": 'deny-receipt-signature-invalid',
        "human": 'signed receipts: the receipt signature does not verify (tampered or wrong key)',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'signature'],
        "reverify_steps": ['recompute', 'verify-signature'],
    },
    'deny-receipt-unavailable-as-permit': {
        "domain": 'receipts',
        "code": 'deny-receipt-unavailable-as-permit',
        "human": 'signed receipts: a permit verdict was paired with an unavailable (outage) class',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'decision'],
        "reverify_steps": ['recompute', 'replay-claim'],
    },
    'deny-receipt-not-authorization': {
        "domain": 'receipts',
        "code": 'deny-receipt-not-authorization',
        "human": 'signed receipts: receipt evidence was used as authority',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'seeded-denial-refused': {
        "domain": 'seeded_denial',
        "code": 'seeded-denial-refused',
        "human": 'seeded denials: base refusal for seeded-denial failures',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'seeded-denial-malformed': {
        "domain": 'seeded_denial',
        "code": 'seeded-denial-malformed',
        "human": 'seeded denials: the presented record is not well-formed, '
                 'or silence was offered instead of a record',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'seeded-denial-digest-mismatch': {
        "domain": 'seeded_denial',
        "code": 'seeded-denial-digest-mismatch',
        "human": 'seeded denials: the record digest does not recompute from '
                 'its body (tampered or misbound)',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'denial-anchored-in-denied-transaction': {
        "domain": 'seeded_denial',
        "code": 'denial-anchored-in-denied-transaction',
        "human": 'seeded denials: the denial record anchors inside the '
                 'denied transaction, so a rollback could erase the denial',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute', 'check-anchor'],
    },
    'denial-evidence-lost': {
        "domain": 'seeded_denial',
        "code": 'denial-evidence-lost',
        "human": 'seeded denials: the committed denial record is absent from '
                 'the post-rollback log; the denial evidence did not survive',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute', 'check-commit'],
    },
    'seeded-denial-not-authorization': {
        "domain": 'seeded_denial',
        "code": 'seeded-denial-not-authorization',
        "human": 'seeded denials: denial evidence was used as authority',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'spiffe-refused': {
        "domain": 'spiffe',
        "code": 'spiffe-refused',
        "human": 'spiffe KMS auth: base-class fallback code; concrete '
                 'refusals carry a specific spiffe-* code',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'spiffe-svid-unavailable': {
        "domain": 'spiffe',
        "code": 'spiffe-svid-unavailable',
        "human": 'spiffe KMS auth: the SVID file is absent or unreadable '
                 '(SPIRE agent down or volume unmounted); refused before '
                 'any network call',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['check-svid-file'],
    },
    'spiffe-svid-expired': {
        "domain": 'spiffe',
        "code": 'spiffe-svid-expired',
        "human": 'spiffe KMS auth: the SVID exp claim has passed; refused '
                 'before any network call',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['check-svid-expiry'],
    },
    'spiffe-svid-malformed': {
        "domain": 'spiffe',
        "code": 'spiffe-svid-malformed',
        "human": 'spiffe KMS auth: the SVID is not a usable JWT (shape, '
                 'encoding, claims) or the file is wrong; refused before '
                 'any network call',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['check-svid-shape'],
    },
    'spiffe-audience-mismatch': {
        "domain": 'spiffe',
        "code": 'spiffe-audience-mismatch',
        "human": 'spiffe KMS auth: the SVID aud does not match the '
                 'configured audience; a foreign SVID is never presented',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['check-svid-audience'],
    },
    'spiffe-auth-refused': {
        "domain": 'spiffe',
        "code": 'spiffe-auth-refused',
        "human": 'spiffe KMS auth: the JWT login failed (403 after one '
                 're-login, other HTTP errors, transport failure, or '
                 'malformed login response)',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['check-jwt-login'],
    },
    'spiffe-permission-invalid': {
        "domain": 'spiffe',
        "code": 'spiffe-permission-invalid',
        "human": 'spiffe KMS auth: the SVID file has group/other '
                 'permission bits or is not owned by the process uid; '
                 'never read a secret other principals could have swapped',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['check-svid-permissions'],
    },
    # Wave-232 lane C (DSSE envelope discipline): additive, 575 -> 578.
    'dsse-envelope-malformed': {
        "domain": 'dsse',
        "code": 'dsse-envelope-malformed',
        "human": 'DSSE envelope: the envelope or PAE bytes are ambiguous '
                 'or malformed (leading-zero length, trailing bytes, '
                 'unknown fields, digest-binding mismatch)',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'dsse-payload-type-refused': {
        "domain": 'dsse',
        "code": 'dsse-payload-type-refused',
        "human": 'DSSE envelope: payloadType outside the vendored '
                 'application/vnd.sasanam.*+json namespace, or an envelope '
                 'presented under the wrong expected payloadType',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'verdict-record'],
        "reverify_steps": ['recompute'],
    },
    'dsse-signature-invalid': {
        "domain": 'dsse',
        "code": 'dsse-signature-invalid',
        "human": 'DSSE envelope: the signature does not verify over the '
                 'PAE bytes (payloadType + payload bound by length prefix)',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'evaluation-malformed': {
        "domain": 'evaluation',
        "code": 'evaluation-malformed',
        "human": 'evaluation function: the frozen call or evaluation '
                 'record is not well-formed (empty or misshapen '
                 'authorization_details, half-pinned policy revision, '
                 'non-UTC instant)',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'evaluation-incomplete-details': {
        "domain": 'evaluation',
        "code": 'evaluation-incomplete-details',
        "human": 'evaluation function: an authorization_details entry '
                 'was never evaluated (skipped, failed, or its '
                 'per-entry verdict is missing from the record); the '
                 'whole call is refused',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute', 're-evaluate'],
    },
    'evaluation-key-role-conflation': {
        "domain": 'evaluation',
        "code": 'evaluation-key-role-conflation',
        "human": 'evaluation function: the evidence key and the '
                 'adjudication key are the same key; the freezer and '
                 'the adjudicator must be different roles',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'evaluation-input-swapped': {
        "domain": 'evaluation',
        "code": 'evaluation-input-swapped',
        "human": 'evaluation function: the call_digest or verdict_digest '
                 'does not match the recomputed digest of the frozen '
                 'input; the input or verdict was swapped after '
                 'freezing/evaluation',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'evaluation-non-reproducible': {
        "domain": 'evaluation',
        "code": 'evaluation-non-reproducible',
        "human": 'evaluation function: replay of the frozen input under '
                 'the pinned revision produced a different verdict than '
                 'the record claims',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute', 're-evaluate'],
    },
    'evaluation-policy-drift': {
        "domain": 'evaluation',
        "code": 'evaluation-policy-drift',
        "human": 'evaluation function: replay against the current engine '
                 'would change the verdict; the pinned revision is '
                 'reproducible but the live policy has drifted',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute', 're-evaluate'],
    },
    'evaluation-revision-unknown': {
        "domain": 'evaluation',
        "code": 'evaluation-revision-unknown',
        "human": 'evaluation function: the pinned policy_rev_id is not '
                 'registered in the revision registry',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'evaluation-policy-digest-mismatch': {
        "domain": 'evaluation',
        "code": 'evaluation-policy-digest-mismatch',
        "human": 'evaluation function: the registry digest for the '
                 'pinned policy_rev_id disagrees with the record\'s '
                 'pinned digest; digests are recomputed from ruleset '
                 'bytes, never trusted from claims',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'evaluation-not-authorization': {
        "domain": 'evaluation',
        "code": 'evaluation-not-authorization',
        "human": 'evaluation function: an evaluation record is evidence, '
                 'never authority; presenting one as authority refuses',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    # Wave-233 lane B (exactly-one-signature DSSE + binding): additive, 4 codes.
    'dsse-envelope-no-signature': {
        "domain": 'dsse',
        "code": 'dsse-envelope-no-signature',
        "human": 'DSSE envelope: the envelope carries zero signatures; '
                 'the exactly-one-signature discipline refuses a '
                 'signature-less envelope fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'dsse-envelope-multi-signature': {
        "domain": 'dsse',
        "code": 'dsse-envelope-multi-signature',
        "human": 'DSSE envelope: the envelope carries more than one '
                 'signature without an explicit expected_signatures '
                 'opt-in, or the signature count does not match the '
                 'opted-in count; signature-count ambiguity is refused, '
                 'never silently accepted',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'dsse-payloadtype-mismatch': {
        "domain": 'dsse',
        "code": 'dsse-payloadtype-mismatch',
        "human": 'DSSE envelope: the envelope payloadType differs from '
                 'the caller-bound expected type; transplant across '
                 'evidence kinds is refused',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'verdict-record'],
        "reverify_steps": ['recompute'],
    },
    'dsse-envelope-transplant': {
        "domain": 'dsse',
        "code": 'dsse-envelope-transplant',
        "human": 'DSSE envelope: the envelope payloadType is registered '
                 'to a different verifier module domain than the one '
                 'verifying (cross-module transplant)',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'verdict-record'],
        "reverify_steps": ['recompute'],
    },
    # Wave-233 lane C (honest-claim discipline): additive; merged pin 585 -> 599 (lane-local 586).
    'honest-claim-reserved-token': {
        "domain": 'honest_claims',
        "code": 'honest-claim-reserved-token',
        "human": 'honest claims: a rendered evidence artifact emitted a '
                 'reserved claim token (proves-execution, tamper-proof, '
                 'non-repudiation, formally-verified, ...); the artifact '
                 'was refused before signing or sealing, naming the token',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    # Wave-233 merge: 585 + 14 = 599 (9 lane-A evaluation + 4 lane-B dsse + 1 lane-C honest_claims), additive only.
    # Wave-234 lane A (octet-digest receipt chaining: gov/log.py octet-digest pre-pass codes), additive.
    # 599 -> 602 (3 new chain-domain codes). The codes name the exact
    # refusal in gov.log's octet-digest pre-pass.
    'chain-octet-digest-mismatch': {
        "domain": 'audit',
        "code": 'chain-octet-digest-mismatch',
        "human": 'audit log: an entry\u2019s prev_record_octets_digest does '
                 'not match the stored previous-record octets (the '
                 'previous record was re-encoded: byte-different, '
                 'semantically equal); refusing',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'chain-octet-digest-absent': {
        "domain": 'audit',
        "code": 'chain-octet-digest-absent',
        "human": 'audit log: an entry carries no well-formed '
                 'prev_record_octets_digest; refusing instead of '
                 'silently degrading to semantic chaining',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'chain-record-truncated': {
        "domain": 'audit',
        "code": 'chain-record-truncated',
        "human": 'audit log: a record\u2019s stored bytes (or its '
                 'predecessor\u2019s) do not decode as a JSON record; '
                 'refusing, never silently skipping',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    # Wave-234 lane B (NIST IR 8587-style token hygiene: gov/token_hygiene.py codes), additive.
    'token-malformed': {
        "domain": 'token_hygiene',
        "code": 'token-malformed',
        "human": 'token hygiene: agent credential claims are misshapen '
                 '(not a dict, bad iat/exp/key fields); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'token-ttl-exceeded': {
        "domain": 'token_hygiene',
        "code": 'token-ttl-exceeded',
        "human": 'token hygiene: token lifetime exceeds the 1h issuance '
                 'cap; a token must never be issued with a longer life',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'token-expired': {
        "domain": 'token_hygiene',
        "code": 'token-expired',
        "human": 'token hygiene: expired token presented; refused '
                 'outright, never refreshed, never tolerated',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'token-audience-missing': {
        "domain": 'token_hygiene',
        "code": 'token-audience-missing',
        "human": 'token hygiene: token issued without an explicit '
                 'audience (aud); every agent credential must declare one',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'token-audience-mismatch': {
        "domain": 'token_hygiene',
        "code": 'token-audience-mismatch',
        "human": 'token hygiene: token presented outside its declared '
                 'audience; the presentation is refused',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'token-key-stale': {
        "domain": 'token_hygiene',
        "code": 'token-key-stale',
        "human": 'token hygiene: high-impact issuing key is older than '
                 'the 90-day rotation window; rotate before issuing',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'token-in-log': {
        "domain": 'token_hygiene',
        "code": 'token-in-log',
        "human": 'token hygiene: a bearer token value reached a log '
                 'line; INCIDENT MATERIAL -- rotate the token and audit '
                 'the leak path; lines must carry {type, issuer, scope, '
                 'audience} metadata only',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    # Wave-234 lane C (at-most-once consumption ledger: gov/consumption_ledger.py codes), additive.
    'previously-consumed': {
        "domain": 'consumption',
        "code": 'previously-consumed',
        "human": 'consumption ledger: the authorization instance was '
                 'already consumed; replay is an explicit named outcome '
                 'carrying the original receipt, never a silent release',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'consumption-idempotency-reused': {
        "domain": 'consumption',
        "code": 'consumption-idempotency-reused',
        "human": 'consumption ledger: an entity-bound idempotency key '
                 'already consumed one frozen instance; a different '
                 'instance cannot release under it',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'consumption-instance-malformed': {
        "domain": 'consumption',
        "code": 'consumption-instance-malformed',
        "human": 'consumption ledger: the presented instance digest is '
                 'not a bare 64-hex sha256 digest; the ledger is keyed '
                 'to frozen-instance digests only',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'consumption-key-malformed': {
        "domain": 'consumption',
        "code": 'consumption-key-malformed',
        "human": 'consumption ledger: idempotency key parts must be a '
                 'tuple/list of at least two non-empty strings (key '
                 'type + entity identifier)',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'consumption-journal-unusable': {
        "domain": 'consumption',
        "code": 'consumption-journal-unusable',
        "human": 'consumption ledger: the write-ahead journal cannot be '
                 'read or fails receipt verification; the ledger refuses '
                 'to operate rather than release against an untrustworthy '
                 'consumed set',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'consumption-journal-write-failed': {
        "domain": 'consumption',
        "code": 'consumption-journal-write-failed',
        "human": 'consumption ledger: the write-ahead commit failed; '
                 'nothing was marked consumed and no receipt was issued',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'consumption-receipt-malformed': {
        "domain": 'consumption',
        "code": 'consumption-receipt-malformed',
        "human": 'consumption ledger: the presented receipt is missing '
                 'fields or carries non-digest values',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'consumption-receipt-tampered': {
        "domain": 'consumption',
        "code": 'consumption-receipt-tampered',
        "human": 'consumption ledger: the receipt digest does not '
                 'recompute over the receipt body; the receipt was '
                 'edited after issuance',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    # Wave-234 merge: 599 + 18 = 617 (3 lane-A audit-chain + 7 lane-B token_hygiene + 8 lane-C consumption), additive only.
    # Wave-235 lane A (trust-material externality: gov/trust_material.py
    # codes), additive.
    'untrusted-key': {
        "domain": 'trust',
        "code": 'untrusted-key',
        "human": 'trust material: the record\'s signing key id is not '
                 'pinned in the external trust root; key material '
                 'supplied inside the record is never trusted',
        "severity": 'high',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'trust-key-repointed': {
        "domain": 'trust',
        "code": 'trust-key-repointed',
        "human": 'trust material: the key id is pinned in the external '
                 'trust root but the record\'s key material differs from '
                 'the pinned material; the label was re-pointed',
        "severity": 'high',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'unsigned-field-ignored': {
        "domain": 'trust',
        "code": 'unsigned-field-ignored',
        "human": 'trust material: verification was asked to rely on a '
                 'field outside the signature-covered body; unsigned '
                 'fields are never consulted, refusing fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'trust-material-malformed': {
        "domain": 'trust',
        "code": 'trust-material-malformed',
        "human": 'trust material: malformed key material presented at '
                 'trust-root construction; a construction-time refusal, '
                 'never emitted at verification',
        "severity": 'low',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    # Wave-235 lane B (bound-permit conjunction: gov/bound_permit.py codes), additive.
    'permit-decision-absent': {
        "domain": 'permit',
        "code": 'permit-decision-absent',
        "human": 'bound permit: issuance attempted without a decision '
                 'record; a permit is decision AND mandate AND policy, '
                 'so the absent leg refuses',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-mandate-absent': {
        "domain": 'permit',
        "code": 'permit-mandate-absent',
        "human": 'bound permit: issuance attempted without a mandate '
                 'record; the mandate leg is absent so no permit issues',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-policy-absent': {
        "domain": 'permit',
        "code": 'permit-policy-absent',
        "human": 'bound permit: issuance attempted without a local '
                 'policy binding; the policy leg is absent so no permit '
                 'issues',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-jti-duplicate': {
        "domain": 'permit',
        "code": 'permit-jti-duplicate',
        "human": 'bound permit: (iss, jti) is already claimed and the '
                 'outcome is not settled as not-executed; a fresh '
                 'permit refuses until the unknown outcome is '
                 'reconciled via jti -- never re-mint',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-leg-refusal-unmapped': {
        "domain": 'permit',
        "code": 'permit-leg-refusal-unmapped',
        "human": 'bound permit: a leg verifier refused without naming '
                 'a machine code; unnamed refusals are unauditable and '
                 'cannot issue a permit',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-malformed': {
        "domain": 'permit',
        "code": 'permit-malformed',
        "human": 'bound permit: the presented permit, reconciliation '
                 'record, leg, or registry argument is the wrong shape; '
                 'refusing instead of guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-tampered': {
        "domain": 'permit',
        "code": 'permit-tampered',
        "human": 'bound permit: a permit or reconciliation record '
                 'digest does not recompute over its body; the record '
                 'was edited after issuance',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    # Wave-235 lane C (grant anti-widening: gov/grant_attenuation.py codes), additive.
    'grant-widened': {
        "domain": 'grants',
        "code": 'grant-widened',
        "human": 'grant attenuation: a delegation attenuation widens a '
                 'scope dimension of the parent grant (a value, dimension, '
                 'or scalar change the parent never held); grants refine, '
                 'never extend',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'grant-attenuation-gap': {
        "domain": 'grants',
        "code": 'grant-attenuation-gap',
        "human": 'grant attenuation: a delegation hop fails to narrow '
                 '(a rights copy, not an attenuation), or a hop digest '
                 'or chain continuity does not check out',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'grant-chain-required': {
        "domain": 'grants',
        "code": 'grant-chain-required',
        "human": 'grant attenuation: the presented grant carries no '
                 'attenuation chain; a leaf alone is not auditable',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    # grant-revoked and grant-malformed are REUSED from the existing
    # taxonomy (authorization_receipt domain): a revoked hop is a
    # revoked credential, and a malformed grant/hop shape is a
    # structural validation failure. Additive-only: no redefinition.
    # Wave-235 merge: 617 + 14 = 631 (4 lane-A trust-material + 7 lane-B bound-permit
    # + 3 lane-C grant-attenuation), additive only, zero key collisions, composed from
    # the three lane commits by direct byte-verification.
    # codes), additive.
    'close-signer-mismatch': {
        "domain": 'close',
        "code": 'close-signer-mismatch',
        "human": 'close binding: the close record\u2019s signer id differs '
                 'from the chain-root session-start signer id; being a '
                 'listed key does not excuse a different signer',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'close-trust-repointed': {
        "domain": 'close',
        "code": 'close-trust-repointed',
        "human": 'close binding: the close record re-points a trust id '
                 '-- the same key-id label with key material differing '
                 'from the external trust root\u2019s pinned material',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log', 'trust-config', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'close-unsigned-scope': {
        "domain": 'close',
        "code": 'close-unsigned-scope',
        "human": 'close binding: verification was asked to rely on a '
                 'scope/authority field outside the close record\u2019s '
                 'signature-covered body; unsigned scope is never '
                 'consulted, refusing fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'close-chain-digest-mismatch': {
        "domain": 'close',
        "code": 'close-chain-digest-mismatch',
        "human": 'close binding: the close record\u2019s chain digest '
                 'does not match the recomputed digest over the chain; '
                 'a chain record was rewritten',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'close-record-malformed': {
        "domain": 'close',
        "code": 'close-record-malformed',
        "human": 'close binding: the chain or the close record is not a '
                 'well-formed record mapping, or a record digest is '
                 'missing/malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'close-signer-absent': {
        "domain": 'close',
        "code": 'close-signer-absent',
        "human": 'close binding: the chain\u2019s first record carries no '
                 'signer identity, so no session-start signer can be '
                 'pinned; binding to nothing is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'close-signature-invalid': {
        "domain": 'close',
        "code": 'close-signature-invalid',
        "human": 'close binding: the close record\u2019s signature fails '
                 'against the trust root\u2019s pinned key material; the '
                 'record\u2019s signer id is claimed, not authenticated',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    # added after the spec review authenticated the close record's
    # (4 new denial-domain codes naming the exact refusal in
    # gov.denial_capsule's sealed-capsule and selective-disclosure
    # seams).
    'denial-unsealed': {
        "domain": 'denial',
        "code": 'denial-unsealed',
        "human": 'denial capsules: a denial was emitted without a '
                 'sealed denial capsule; a denial must be sealed or '
                 'the action never ran; refusing',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'denial-capsule-malformed': {
        "domain": 'denial',
        "code": 'denial-capsule-malformed',
        "human": 'denial capsules: the presented denial capsule, its '
                 'disclosure record, or a seal-time input is not '
                 'well-formed; refusing',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'denial-capsule-signature-invalid': {
        "domain": 'denial',
        "code": 'denial-capsule-signature-invalid',
        "human": 'denial capsules: the denial capsule seal does not '
                 'verify against the presented key; refusing',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'denial-disclosure-mismatch': {
        "domain": 'denial',
        "code": 'denial-disclosure-mismatch',
        "human": 'denial capsules: a disclosed field does not match '
                 'its salted commitment in the sealed capsule, or the '
                 'disclosure binds a different capsule; refusing',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    # gov/permit_closure.py codes), additive.
    'permit-binding-mismatch': {
        "domain": 'permit',
        "code": 'permit-binding-mismatch',
        "human": 'permit/closure: the dispatched request bytes do not '
                 'match the canonical request bytes bound in the '
                 'permit; the permit refuses the dispatch',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'dispatch-without-permit': {
        "domain": 'permit',
        "code": 'dispatch-without-permit',
        "human": 'permit/closure: dispatch attempted with no permit; '
                 'the permit must be issued pre-dispatch',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'closure-permit-absent': {
        "domain": 'permit',
        "code": 'closure-permit-absent',
        "human": 'permit/closure: a closure presented without its '
                 'matching permit; the two halves must be presented '
                 'together',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'closure-permit-mismatch': {
        "domain": 'permit',
        "code": 'closure-permit-mismatch',
        "human": 'permit/closure: the closure binds a different permit '
                 'digest than the presented permit; the two halves '
                 'disagree',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'closure-scope-widened': {
        "domain": 'permit',
        "code": 'closure-scope-widened',
        "human": 'permit/closure: the closure claims effects outside '
                 'the permit\'s scope; a closure may narrow, never '
                 'widen',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    # permit-malformed and permit-tampered are REUSED from the existing
    # taxonomy (permit domain): malformed shapes and edited-after-issue
    # records at this seam are the same structural failures. Additive-
    # only: no redefinition.
    # only, zero key collisions, verified by direct byte-inspection of
    # the taxonomy.
    # Lane A codes: three-outcome gate rule (gov/gate_outcomes.py) — undecidable is a failure to verify, never tamper.
    'gate-tampered': {
        "domain": 'gate',
        "code": 'gate-tampered',
        "human": 'gate: the verifier reported that the evidence was '
                 'tampered; the gate refuses the action',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gate-undecidable': {
        "domain": 'gate',
        "code": 'gate-undecidable',
        "human": 'gate: the verifier could not verify the evidence; '
                 'undecidable is a failure to verify, not evidence of '
                 'tampering; the gate refuses fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gate-verdict-unreasoned': {
        "domain": 'gate',
        "code": 'gate-verdict-unreasoned',
        "human": 'gate: the verifier returned undecidable without a '
                 'mandatory reason from the closed vocabulary; the '
                 'gate contract refuses the verdict itself',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gate-undecidable-allowed': {
        "domain": 'gate',
        "code": 'gate-undecidable-allowed',
        "human": 'gate self-check: a gate allowed an undecidable '
                 'verdict (or crashed on the probe instead of refusing '
                 'it); the gate is declared non-compliant',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    # Lane B codes: edited-approval refusal at the adapter boundary (gov/approval_edit_guard.py).
    'approval-edited': {
        "domain": 'approval',
        "code": 'approval-edited',
        "human": 'approval: the approved action bytes differ from the '
                 'proposed action bytes; approving with edits is '
                 'refused -- re-propose the edited action instead',
        "severity": 'high',
        "evidence_kinds_required": ['approval-record', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'approval-rebinding': {
        "domain": 'approval',
        "code": 'approval-rebinding',
        "human": 'approval: the approval is presented in a proposal '
                 'context it does not belong to (proposal id mismatch); '
                 'approvals are never rebound across proposals',
        "severity": 'high',
        "evidence_kinds_required": ['approval-record', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'approval-malformed': {
        "domain": 'approval',
        "code": 'approval-malformed',
        "human": 'approval: the proposal or approval record is not a '
                 'well-formed adapter-boundary record; refusing',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record'],
        "reverify_steps": ['recompute'],
    },
    # Lane C codes: canonical audit-record contract (gov/canonical_record.py) — RFC 8785 + I-JSON; opaque bytes never coerced.
    'record-duplicate-member': {
        "domain": 'canonical',
        "code": 'record-duplicate-member',
        "human": 'canonical records: a JSON record carries the same '
                 'object member twice; duplicate keys are a '
                 'cross-deployment canonicalization hazard, refusing',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'record-depth-exceeded': {
        "domain": 'canonical',
        "code": 'record-depth-exceeded',
        "human": 'canonical records: nesting deeper than 128 levels; '
                 'unbounded nesting is a parser hazard, refusing',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'record-noncanonical-float': {
        "domain": 'canonical',
        "code": 'record-noncanonical-float',
        "human": 'canonical records: a float value cannot be '
                 'canonicalized byte-identically across deployments; '
                 'refusing, never coercing to integer',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'record-malformed': {
        "domain": 'canonical',
        "code": 'record-malformed',
        "human": 'canonical records: the record shape is not '
                 'canonicalizable (non-string keys, unsupported types, '
                 'unencodable characters); refusing',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    'record-opaque-bytes': {
        "domain": 'canonical',
        "code": 'record-opaque-bytes',
        "human": 'canonical records: input is non-JSON bytes; passing '
                 'through byte-exact with the opaque-bytes marker, '
                 'never silently coercing',
        "severity": 'low',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['recompute'],
    },
    # Lane D codes: closure-scoped approvals (gov/closure_scoped_approvals.py).
    'approval-run-mismatch': {
        "domain": 'scoped',
        "code": 'approval-run-mismatch',
        "human": 'closure-scoped approval: the packet is sealed for a '
                 'different run_id than the one it is presented against',
        "severity": 'high',
        "evidence_kinds_required": ['approval-packet'],
        "reverify_steps": ['recompute'],
    },
    'approval-sandbox-mismatch': {
        "domain": 'scoped',
        "code": 'approval-sandbox-mismatch',
        "human": 'closure-scoped approval: the packet is sealed for a '
                 'different sandbox_id than the one it is presented '
                 'against',
        "severity": 'high',
        "evidence_kinds_required": ['approval-packet'],
        "reverify_steps": ['recompute'],
    },
    'approval-route-mismatch': {
        "domain": 'scoped',
        "code": 'approval-route-mismatch',
        "human": 'closure-scoped approval: the packet is sealed for a '
                 'different route than the one it is presented against; '
                 'a pre-computed approval is never replayed at another '
                 'route',
        "severity": 'high',
        "evidence_kinds_required": ['approval-packet'],
        "reverify_steps": ['recompute'],
    },
    'approval-capability-dead': {
        "domain": 'scoped',
        "code": 'approval-capability-dead',
        "human": 'closure-scoped approval: the packet\u2019s attempt is '
                 'settled; capabilities die at settlement, there is no '
                 'second execution',
        "severity": 'high',
        "evidence_kinds_required": ['approval-packet'],
        "reverify_steps": ['recompute'],
    },
    'approval-state-stale': {
        "domain": 'scoped',
        "code": 'approval-state-stale',
        "human": 'closure-scoped approval: state moved since issuance; '
                 'the write-time recheck refused because the approval no '
                 'longer covers the current state',
        "severity": 'high',
        "evidence_kinds_required": ['approval-packet', 'state-digest'],
        "reverify_steps": ['recompute'],
    },
    'scoped-approval-malformed': {
        "domain": 'scoped',
        "code": 'scoped-approval-malformed',
        "human": 'closure-scoped approval: the presented packet or '
                 'argument is the wrong shape; refusing instead of '
                 'guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-packet'],
        "reverify_steps": ['recompute'],
    },
    'scoped-approval-tampered': {
        "domain": 'scoped',
        "code": 'scoped-approval-tampered',
        "human": 'closure-scoped approval: the packet\u2019s '
                 'approval_digest does not recompute over its body; the '
                 'record was edited after issuance',
        "severity": 'high',
        "evidence_kinds_required": ['approval-packet'],
        "reverify_steps": ['recompute'],
    },
    'scoped-approval-capability-unknown': {
        "domain": 'scoped',
        "code": 'scoped-approval-capability-unknown',
        "human": 'closure-scoped approval: the requested capability was '
                 'never granted by this packet',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-packet'],
        "reverify_steps": ['recompute'],
    },
    # Wave-237 merge: 647 + 20 = 667 (4 lane-A three-outcome
    # gate-rule + 3 lane-B edited-approval refusal +
    # 5 lane-C canonical-record + 8 lane-D closure-scoped
    # approval codes), additive only, zero key collisions,
    # composed from the four lane commits by direct
    # byte-verification.
}


def _machine_code(refusal, entry, digests, steps, detail):
    """Single constructor for the emitted machine-code dict shape.

    Shared by emit() and replay() so the canonical bytes (and hence
    machine_code_digest) cannot drift between construction sites.
    All list fields are copied; the caller's objects are never
    aliased.
    """
    return {
        "v": DECISION_CODE_VERSION,
        "refusal": refusal,
        "code": refusal,
        "domain": entry["domain"],
        "severity": entry["severity"],
        "human": entry["human"],
        "evidence_kinds_required": list(entry["evidence_kinds_required"]),
        "reevaluate": {
            "evidence_digests": list(digests),
            "reverify_steps": list(steps),
        },
        "authority": False,
        "detail": detail,
    }


def mapped_refusal_codes():
    """The closed refusal vocabulary, sorted. Deterministic."""
    return tuple(sorted(TAXONOMY))


def code_for(refusal_string):
    """Return the DecisionCode record for a refusal string.

    Fails closed with ``decision-code-unmapped`` for anything that is
    not a mapped refusal string (unknown, empty, or non-string).
    Returns a copy; mutating it cannot change the taxonomy.
    """
    if not isinstance(refusal_string, str) or not refusal_string:
        raise DecisionCodeError(
            UNMAPPED, "refusal must be a non-empty string")
    try:
        entry = TAXONOMY[refusal_string]
    except KeyError:
        raise DecisionCodeError(
            UNMAPPED, "no mapping for %r" % (refusal_string,))
    return {
        "domain": entry["domain"],
        "code": entry["code"],
        "human": entry["human"],
        "severity": entry["severity"],
        "evidence_kinds_required": list(
            entry["evidence_kinds_required"]),
        "reverify_steps": list(entry["reverify_steps"]),
    }


def _check_digests(evidence_digests):
    if evidence_digests is None:
        return []
    if not isinstance(evidence_digests, (list, tuple)):
        raise DecisionCodeError(
            DIGEST_MALFORMED, "evidence_digests must be a list of digests")
    out = []
    for digest in evidence_digests:
        if not isinstance(digest, str) or len(digest) != 64 or any(
                ch not in "0123456789abcdef" for ch in digest):
            raise DecisionCodeError(
                DIGEST_MALFORMED,
                "evidence digest must be 64 lowercase hex chars")
        out.append(digest)
    return out


def emit(refusal_string, evidence_digests=(), detail=""):
    """Emit the machine decision code for a refusal string.

    The returned dict is the THIRD-PARTY-VERIFIABLE evidence record:
    the taxonomy entry plus the ``reevaluate`` pointer. ``authority``
    is always False -- the code is evidence, never authorization.
    ``evidence_digests`` must be digest-shaped (64 lowercase hex).
    """
    entry = code_for(refusal_string)  # fail-closed on unmapped
    digests = _check_digests(evidence_digests)
    if detail is None:
        detail = ""
    if not isinstance(detail, str):
        raise DecisionCodeError(MALFORMED, "detail must be a string")
    return _machine_code(refusal_string, entry, digests,
                        entry["reverify_steps"], detail)


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def machine_code_digest(machine_code):
    """The digest identity of an emitted machine code (sha256 over the
    canonical JSON). Used for digest linkage into action capsules."""
    if not isinstance(machine_code, dict):
        raise DecisionCodeError(MALFORMED, "machine code must be a dict")
    return hashlib.sha256(_canonical_bytes(machine_code)).hexdigest()


def replay(machine_code):
    """Strictly re-validate an emitted machine-code dict against the
    live taxonomy and return a canonical copy.

    Refuses ``decision-code-malformed`` on any shape violation,
    unknown field, digest-shape violation, or taxonomy drift (the
    embedded entry no longer matches ``code_for``).
    """
    if not isinstance(machine_code, dict):
        raise DecisionCodeError(MALFORMED, "machine code must be a dict")
    expected_keys = {"v", "refusal", "code", "domain", "severity",
                     "human", "evidence_kinds_required", "reevaluate",
                     "authority", "detail"}
    unknown = set(machine_code) - expected_keys
    if unknown:
        raise DecisionCodeError(
            MALFORMED, "unknown machine-code fields: %s"
            % ",".join(sorted(unknown)))
    if machine_code.get("v") != DECISION_CODE_VERSION:
        raise DecisionCodeError(MALFORMED, "bad version")
    refusal = machine_code.get("refusal")
    entry = code_for(refusal)  # fail-closed on unmapped
    if machine_code.get("code") != refusal:
        raise DecisionCodeError(MALFORMED, "code/refusal mismatch")
    for key in ("domain", "severity", "human"):
        if machine_code.get(key) != entry[key]:
            raise DecisionCodeError(
                MALFORMED, "taxonomy drift on %r" % key)
    for key in ("evidence_kinds_required",):
        if list(machine_code.get(key) or []) != entry[key]:
            raise DecisionCodeError(
                MALFORMED, "taxonomy drift on %r" % key)
    ree = machine_code.get("reevaluate")
    if not isinstance(ree, dict):
        raise DecisionCodeError(MALFORMED, "reevaluate must be a dict")
    digests = _check_digests(ree.get("evidence_digests"))
    steps = ree.get("reverify_steps")
    if not isinstance(steps, list) or not steps or not all(
            isinstance(s, str) and s for s in steps):
        raise DecisionCodeError(MALFORMED, "reverify_steps malformed")
    if machine_code.get("authority") is not False:
        raise DecisionCodeError(
            NOT_AUTHORIZATION,
            "emitted code carries authority semantics")
    detail = machine_code.get("detail", "")
    if not isinstance(detail, str):
        raise DecisionCodeError(MALFORMED, "detail must be a string")
    return _machine_code(refusal, entry, digests, steps, detail)


_AUTHORITY_SHAPED_KEYS = ("grants", "grant", "permit", "approve",
                          "approval", "allow", "authorization",
                          "authority_token")


def require_evidence_only(machine_code):
    """Refuse authority-shaped use of a decision code.

    Decision codes are evidence, never authority. Any truthy
    ``authority`` flag or authority-shaped field (grants, permit,
    approve, ...) refuses ``decision-code-not-authorization``.
    Returns True for clean evidence-only use.
    """
    if not isinstance(machine_code, dict):
        raise DecisionCodeError(MALFORMED, "machine code must be a dict")
    if machine_code.get("authority"):
        raise DecisionCodeError(
            NOT_AUTHORIZATION, "authority flag is set on a decision code")
    for key in _AUTHORITY_SHAPED_KEYS:
        if machine_code.get(key):
            raise DecisionCodeError(
                NOT_AUTHORIZATION,
                "authority-shaped field %r on a decision code" % (key,))
    return True


def attach_decision_code(capsule, machine_code):
    """Attach a decision code to a sealed action capsule as
    digest-linked evidence.

    Replays the capsule and strictly re-validates the machine code,
    then seals a NEW capsule whose effect carries
    ``decision_code_digest`` (recomputed, never asserted) and the
    refusal string. Additive: ``gov/action_capsule.py`` is not
    modified, and the capsule still carries no authority.
    """
    if seal_capsule is None or verify_capsule is None:
        raise DecisionCodeError(
            MALFORMED, "action-capsule composition needs gov.action_capsule")
    checked = replay(machine_code)  # strict; tampering refuses here
    require_evidence_only(checked)  # no authority semantics, ever
    if not isinstance(capsule, dict):
        raise DecisionCodeError(MALFORMED, "capsule must be a dict")
    body = verify_capsule(capsule)  # replay; tampering refuses here
    new_effect = dict(body["effect"])
    new_effect["decision_code_digest"] = machine_code_digest(checked)
    new_effect["decision_code"] = checked["refusal"]
    return seal_capsule({"attempt": dict(body["attempt"]),
                         "effect": new_effect})


def verify_capsule_decision_code(capsule, machine_code):
    """Verify the digest link between a capsule and a decision code.

    Replays the capsule, strictly re-validates the machine code
    (recomputing its digest), and checks the effect's
    ``decision_code_digest`` against the recomputed digest. Returns
    the linked digest. A mismatch refuses
    ``decision-code-digest-mismatch``; a capsule with no decision-code
    link refuses ``decision-code-malformed``.
    """
    if verify_capsule is None:
        raise DecisionCodeError(
            MALFORMED, "action-capsule composition needs gov.action_capsule")
    checked = replay(machine_code)  # strict; tampering refuses here
    if not isinstance(capsule, dict):
        raise DecisionCodeError(MALFORMED, "capsule must be a dict")
    body = verify_capsule(capsule)  # replay; tampering refuses here
    linked = body["effect"].get("decision_code_digest")
    if not isinstance(linked, str):
        raise DecisionCodeError(
            MALFORMED, "capsule effect carries no decision-code link")
    recomputed = machine_code_digest(checked)
    if linked != recomputed:
        raise DecisionCodeError(
            DIGEST_MISMATCH,
            "capsule decision-code link does not match the code digest")
    return linked
