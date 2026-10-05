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
1. Class-level ``code = "..."`` attributes on exception classes,
   EXCLUDING family-fallback base classes whose ``code`` is never
   raised with that value: a base class whose every concrete subclass
   overrides ``code`` contributes no emitted refusal string of its
   own, so its default is implementation vocabulary, not evidence
   vocabulary (wave-342 lane 6: ``single-use-refused``,
   ``evidence-refused``, ``key-identity-refused``, ``spiffe-refused``
   removed for exactly this reason -- all raise sites use the
   overriding subclass codes).
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
except ImportError:# standalone: composition needs the capsule module
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
    'aauth-aud-mismatch': {
        "domain": 'aauth',
        "code": 'aauth-aud-mismatch',
        "human": 'aauth egress rule: token audience does not match the '
                 'expected audience, or the audience is missing; failing '
                 'closed',
        "severity": 'high',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },
    'aauth-egress-blocked': {
        "domain": 'aauth',
        "code": 'aauth-egress-blocked',
        "human": 'aauth egress rule: HTTPS-only default-deny egress '
                 'refuses loopback, RFC1918, link-local, localhost, or '
                 'non-https targets',
        "severity": 'high',
        "evidence_kinds_required": ['egress-target'],
        "reverify_steps": ['recompute'],
    },
    'aauth-iss-mismatch': {
        "domain": 'aauth',
        "code": 'aauth-iss-mismatch',
        "human": 'aauth egress rule: token issuer does not match the '
                 'expected issuer, or the issuer is missing; confused '
                 'deputy prevention',
        "severity": 'high',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },
    'aauth-scheme-not-allowed': {
        "domain": 'aauth',
        "code": 'aauth-scheme-not-allowed',
        "human": 'aauth egress rule: scheme resolution without an '
                 'explicitly allowing policy refuses; policy precedes '
                 'discovery',
        "severity": 'high',
        "evidence_kinds_required": ['scheme-resolution'],
        "reverify_steps": ['recompute'],
    },
    'aauth-stale-created': {
        "domain": 'aauth',
        "code": 'aauth-stale-created',
        "human": 'aauth egress rule: RFC 9421 created timestamp is more '
                 'than 60s from the verifier clock (past or future); '
                 'failing closed',
        "severity": 'high',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },
    'absence-advertised-but-missing': {
        "domain": 'absence',
        "code": 'absence-advertised-but-missing',
        "human": 'signed negative outcome: required evidence is absent',
        "severity": 'medium',
        "evidence_kinds_required": ['negative-record', 'signature', 'revocation-registry'],
        "reverify_steps": ['recompute'],
    },
    'absence-backdated': {
        "domain": 'absence-epoch',
        "code": 'absence-backdated',
        "human": 'observation time is outside the closed epoch window',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'epoch-record'],
        "reverify_steps": ['recompute'],
    },
    'absence-disclosure-recorded': {
        "domain": 'absence-epoch',
        "code": 'absence-disclosure-recorded',
        "human": 'a disclosure is recorded for this cell; the absence claim is forged',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'epoch-record', 'disclosure-record'],
        "reverify_steps": ['recompute'],
    },
    'absence-epoch-beacon-unsigned': {
        "domain": 'absence-epoch',
        "code": 'absence-epoch-beacon-unsigned',
        "human": 'epoch beacon or close signature does not verify',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'epoch-record'],
        "reverify_steps": ['recompute'],
    },
    'absence-epoch-closed': {
        "domain": 'absence-epoch',
        "code": 'absence-epoch-closed',
        "human": 'new observation refused: the epoch is already closed',
        "severity": 'medium',
        "evidence_kinds_required": ['epoch-record'],
        "reverify_steps": ['recompute'],
    },
    'absence-epoch-malformed': {
        "domain": 'absence-epoch',
        "code": 'absence-epoch-malformed',
        "human": 'absence-epoch record or bundle is not the expected shape',
        "severity": 'medium',
        "evidence_kinds_required": ['epoch-record'],
        "reverify_steps": ['recompute'],
    },
    'absence-epoch-not-closed': {
        "domain": 'absence-epoch',
        "code": 'absence-epoch-not-closed',
        "human": 'epoch has no close record; unclosed epochs verify nothing',
        "severity": 'high',
        "evidence_kinds_required": ['epoch-record'],
        "reverify_steps": ['recompute'],
    },
    'absence-epoch-not-open': {
        "domain": 'absence-epoch',
        "code": 'absence-epoch-not-open',
        "human": 'no beacon record for the claimed epoch',
        "severity": 'high',
        "evidence_kinds_required": ['epoch-record'],
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
    'absence-not-observed': {
        "domain": 'absence-epoch',
        "code": 'absence-not-observed',
        "human": 'no absence observation recorded for this cell',
        "severity": 'medium',
        "evidence_kinds_required": ['epoch-record'],
        "reverify_steps": ['recompute'],
    },
    'absence-observation-unsigned': {
        "domain": 'absence-epoch',
        "code": 'absence-observation-unsigned',
        "human": 'absence observation signature invalid or not bound to the beacon',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'epoch-record'],
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
    'absence-root-mismatch': {
        "domain": 'absence-epoch',
        "code": 'absence-root-mismatch',
        "human": 'ledger does not recompute to the closed Merkle root',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'epoch-record', 'merkle-root'],
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
    'access-request-duplicate-review-refused': {
        "domain": 'access-request',
        "code": 'access-request-duplicate-review-refused',
        "human": 'access request: the same reviewer attempted to vote '
                 'twice on one request; each reviewer votes at most once; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['access-request', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'access-request-grant-refused': {
        "domain": 'access-request',
        "code": 'access-request-grant-refused',
        "human": 'access request: an ephemeral grant was minted from a '
                 'request that is not APPROVED; grants exist only as '
                 'reissued identity from approved requests, never as '
                 'standing capabilities; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['access-request', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'access-request-reviewer-ineligible': {
        "domain": 'access-request',
        "code": 'access-request-reviewer-ineligible',
        "human": 'access request: a reviewer outside the declared '
                 'suggested-reviewer set attempted to vote; refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['access-request', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'access-request-self-review-refused': {
        "domain": 'access-request',
        "code": 'access-request-self-review-refused',
        "human": 'access request: the requestor attempted to review '
                 'their own request; self-approval is blocked because the '
                 'requestor lacks the review verb on their own request; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['access-request', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'access-request-terminal-refused': {
        "domain": 'access-request',
        "code": 'access-request-terminal-refused',
        "human": 'access request: a review, decision, or grant was '
                 'attempted on a request that is no longer PENDING '
                 '(APPROVED, DENIED, or read-time EXPIRED); terminal '
                 'states are final; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['access-request', 'audit-log'],
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
    'action-depth-exceeded': {
        "domain": 'typed_action',
        "code": 'action-depth-exceeded',
        "human": 'typed action: the material nesting depth exceeds '
                 'max_depth for the type',
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
    'action-material-missing': {
        "domain": 'typed_action',
        "code": 'action-material-missing',
        "human": 'typed action: a required material field is absent',
        "severity": 'medium',
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
    'action-value-count-exceeded': {
        "domain": 'typed_action',
        "code": 'action-value-count-exceeded',
        "human": 'typed action: the material leaf-value count exceeds '
                 'max_values for the type',
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
    'admission-at-risk-accepted': {
        "domain": 'admission',
        "code": 'admission-at-risk-accepted',
        "human": 'evidence admission: a refused admission was accepted at '
                 'operator risk through a live governed exception; the '
                 'refusal record is unchanged (SKIPPED-shaped, never an '
                 'upgrade)',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record', 'exception-record'],
        "reverify_steps": ['recompute'],
    },

    'admission-check-failed': {
        "domain": 'admission',
        "code": 'admission-check-failed',
        "human": 'evidence admission: a required check has no usable '
                 'outcome (missing or malformed); admission refuses '
                 'fail-closed rather than running blind',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
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
    'admission-exception-refused': {
        "domain": 'admission',
        "code": 'admission-exception-refused',
        "human": 'evidence admission: accept-at-risk refused -- no live '
                 'covering exception, the refusal was caused by the '
                 'integrity floor (which no exception can override), or '
                 'the decision was not a REFUSE',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
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
    'admission-integrity-floor-violated': {
        "domain": 'admission',
        "code": 'admission-integrity-floor-violated',
        "human": 'evidence admission: an integrity-floor check '
                 '(signature-valid, digest-binds) failed; refused -- the '
                 'floor is non-overridable by policy, override, skip '
                 'level, or exception',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
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
    'admission-no-applicable-policy': {
        "domain": 'admission',
        "code": 'admission-no-applicable-policy',
        "human": 'evidence admission: the evidence kind matches no policy '
                 'scope and no default_level is declared; refused, never '
                 'defaulted',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record', 'policy'],
        "reverify_steps": ['recompute'],
    },

    'admission-policy-attestation-refused': {
        "domain": 'admission-policy',
        "code": 'admission-policy-attestation-refused',
        "human": 'admission-time signature policy: no presented '
                 'attestation satisfies the required predicate for '
                 'this digest (missing, wrong digest, or '
                 'unverifiable); failing closed',
        "severity": 'medium',
        "evidence_kinds_required": ['admission-policy', 'artifact',
                                    'attestation'],
        "reverify_steps": ['recompute'],
    },
    'admission-policy-authority-unknown': {
        "domain": 'admission-policy',
        "code": 'admission-policy-authority-unknown',
        "human": 'admission-time signature policy: policy names an '
                 'unknown authority type; the policy cannot be loaded',
        "severity": 'medium',
        "evidence_kinds_required": ['admission-policy'],
        "reverify_steps": ['recompute'],
    },
    'admission-policy-digest-changed': {
        "domain": 'admission-policy',
        "code": 'admission-policy-digest-changed',
        "human": 'admission-time signature policy: the artifact '
                 'reference resolves to a different digest at use '
                 'time than at verify time; use refused -- what was '
                 'verified is what runs',
        "severity": 'critical',
        "evidence_kinds_required": ['admission-policy', 'artifact',
                                    'decision-record'],
        "reverify_steps": ['recompute'],
    },
    'admission-policy-identity-refused': {
        "domain": 'admission-policy',
        "code": 'admission-policy-identity-refused',
        "human": 'admission-time signature policy: the presented '
                 'keyless identity (issuer, subject) does not match '
                 'the pinned identity; failing closed',
        "severity": 'high',
        "evidence_kinds_required": ['admission-policy', 'artifact',
                                    'identity-assertion'],
        "reverify_steps": ['recompute'],
    },
    'admission-policy-invalid': {
        "domain": 'admission',
        "code": 'admission-policy-invalid',
        "human": 'evidence admission: the admission-policy document failed '
                 'validation -- malformed shape, vacuous scope list, '
                 'unknown check name, or an attempt to lower an '
                 'integrity-floor check below strict; refused at compile '
                 'time',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },

    'admission-policy-malformed': {
        "domain": 'admission-policy',
        "code": 'admission-policy-malformed',
        "human": 'admission-time signature policy: the policy '
                 'document failed structural validation; refused at '
                 'load, never at admission time',
        "severity": 'medium',
        "evidence_kinds_required": ['admission-policy'],
        "reverify_steps": ['recompute'],
    },
    'admission-policy-not-covered': {
        "domain": 'admission-policy',
        "code": 'admission-policy-not-covered',
        "human": 'admission-time signature policy: the artifact '
                 'matches no policy entry; default deny -- policy '
                 'precedes discovery',
        "severity": 'medium',
        "evidence_kinds_required": ['admission-policy', 'artifact'],
        "reverify_steps": ['recompute'],
    },
    'admission-policy-signature-refused': {
        "domain": 'admission-policy',
        "code": 'admission-policy-signature-refused',
        "human": 'admission-time signature policy: no presented '
                 'signature verifies under a pinned key for this '
                 'digest (wrong signer or cross-digest replay); '
                 'failing closed',
        "severity": 'high',
        "evidence_kinds_required": ['admission-policy', 'artifact',
                                    'signature'],
        "reverify_steps": ['recompute'],
    },
    'admission-policy-transparency-refused': {
        "domain": 'admission-policy',
        "code": 'admission-policy-transparency-refused',
        "human": 'admission-time signature policy: no presented '
                 'transparency-log membership claim verifies for '
                 'this digest; failing closed',
        "severity": 'medium',
        "evidence_kinds_required": ['admission-policy', 'artifact',
                                    'transparency-receipt'],
        "reverify_steps": ['recompute'],
    },
    'admission-policy-unresolvable': {
        "domain": 'admission-policy',
        "code": 'admission-policy-unresolvable',
        "human": 'admission-time signature policy: the artifact tag '
                 'cannot be resolved to a digest; never admit what '
                 'you cannot resolve',
        "severity": 'medium',
        "evidence_kinds_required": ['admission-policy', 'artifact'],
        "reverify_steps": ['recompute'],
    },
    'admission-policy-unsigned': {
        "domain": 'admission-policy',
        "code": 'admission-policy-unsigned',
        "human": 'admission-time signature policy: the matched entry '
                 'demands a key authority but the artifact presents '
                 'no signature at all; failing closed',
        "severity": 'high',
        "evidence_kinds_required": ['admission-policy', 'artifact'],
        "reverify_steps": ['recompute'],
    },
    'admission-policy-vacuous': {
        "domain": 'admission-policy',
        "code": 'admission-policy-vacuous',
        "human": 'admission-time signature policy: the policy has no '
                 'entries or an entry has no authorities -- it '
                 'admits nothing and cannot be constructed',
        "severity": 'medium',
        "evidence_kinds_required": ['admission-policy'],
        "reverify_steps": ['recompute'],
    },
    'admission-refused': {
        "domain": 'admission',
        "code": 'admission-refused',
        "human": 'evidence admission: evidence refused at its effective '
                 'trust level (strict failed checks, or raised override '
                 'failed)',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
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
    'advisory-input-malformed': {
        "domain": 'advisory',
        "code": 'advisory-input-malformed',
        "human": 'caller-supplied flaw-level advisory data is malformed '
                 '(bad flaw shape, bad CVE id, bad version spec, or flaw '
                 'list not inside the signed canonical bytes); refused '
                 'fail-closed, never silently',
        "severity": 'high',
        "evidence_kinds_required": ['advisory', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'advisory-input-unpinned': {
        "domain": 'authority',
        "code": 'advisory-input-unpinned',
        "human": 'advisory input: the presented pinned advisory is a '
                 'hand-built dict, not a bind_advisory_input-sealed '
                 'PinnedAdvisory; refused fail-closed, never trusted on '
                 'shape alone',
        "severity": 'high',
        "evidence_kinds_required": ['advisory', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'advisory-version-tie': {
        "domain": 'authority',
        "code": 'advisory-version-tie',
        "human": 'advisory supersede: two presented advisories share the '
                 'same version; the survivor would be order-dependent; '
                 'refused fail-closed, the feed must not contain '
                 'same-version conflicts',
        "severity": 'medium',
        "evidence_kinds_required": ['advisory', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'aggregate-budget-already-charged': {
        "domain": 'budget',
        "code": 'aggregate-budget-already-charged',
        "human": 'aggregate budget: this (iss, jti) was already '
                 'charged in this scope; a permit is never '
                 're-chargeable',
        "severity": 'high',
        "evidence_kinds_required": ['budget-ledger'],
        "reverify_steps": ['recompute'],
    },
    'aggregate-budget-exhausted': {
        "domain": 'budget',
        "code": 'aggregate-budget-exhausted',
        "human": 'aggregate budget: charging the amount would push '
                 'the scope aggregate past its declared cap; the '
                 'individual act is permitted but the composition is '
                 'not',
        "severity": 'high',
        "evidence_kinds_required": ['budget-ledger'],
        "reverify_steps": ['recompute'],
    },
    'aggregate-budget-malformed': {
        "domain": 'budget',
        "code": 'aggregate-budget-malformed',
        "human": 'aggregate budget: malformed scope declaration or '
                 'charge (non-positive cap/window, non-positive or '
                 'non-numeric amount); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['budget-ledger'],
        "reverify_steps": ['recompute'],
    },
    'aggregate-budget-scope-undeclared': {
        "domain": 'budget',
        "code": 'aggregate-budget-scope-undeclared',
        "human": 'aggregate budget: the scope was never declared; '
                 'charging an undeclared scope refuses fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['budget-ledger'],
        "reverify_steps": ['recompute'],
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
    'anchor-checkpoint-invalid': {
        "domain": 'anchor',
        "code": 'anchor-checkpoint-invalid',
        "human": 'anchor: the transparency-log checkpoint is malformed or '
                 'its operator signature does not verify; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'anchor-inclusion-mismatch': {
        "domain": 'anchor',
        "code": 'anchor-inclusion-mismatch',
        "human": 'anchor: the inclusion proof does not chain the claimed '
                 'leaf to the checkpoint root; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'anchor-index-unpublished': {
        "domain": 'anchor',
        "code": 'anchor-index-unpublished',
        "human": 'anchor: the claimed log index is not covered by any '
                 'published checkpoint (publication never awaited); refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'anchor-leaf-mismatch': {
        "domain": 'anchor',
        "code": 'anchor-leaf-mismatch',
        "human": 'anchor: the bundle digest claimed by the receipt is not '
                 'the leaf anchored at the claimed index; refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'anchor-log-corrupt': {
        "domain": 'anchor',
        "code": 'anchor-log-corrupt',
        "human": 'anchor: the POSIX tile store is structurally inconsistent '
                 'with state or checkpoints (tamper-evident trip); refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'anchor-no-signer': {
        "domain": 'anchor',
        "code": 'anchor-no-signer',
        "human": 'anchor: publication requested on a log handle with no '
                 'operator signer key; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'anchor-witness-quorum-failed': {
        "domain": 'anchor',
        "code": 'anchor-witness-quorum-failed',
        "human": 'anchor: fewer than the pinned quorum of witnesses '
                 'cosigned the checkpoint; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
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
    'approval-digest-diverged': {
        "domain": 'digest_link',
        "code": 'approval-digest-diverged',
        "human": 'digest linkage: the recorded value diverged from the recomputed value',
        "severity": 'critical',
        "evidence_kinds_required": ['digest', 'record'],
        "reverify_steps": ['recompute-digest'],
    },
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
    'approval-malformed': {
        "domain": 'approval',
        "code": 'approval-malformed',
        "human": 'approval: the proposal or approval record is not a '
                 'well-formed adapter-boundary record; refusing',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-policy-audit-failed': {
        "domain": 'approval-policy',
        "code": 'approval-policy-audit-failed',
        "human": 'approval policy: the audit sink raised while recording '
                 'an auto-approve or opt-in disapproval; the decision is '
                 'refused, never silently taken',
        "severity": 'high',
        "evidence_kinds_required": ['approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-policy-disapproval-defaulted': {
        "domain": 'approval-policy',
        "code": 'approval-policy-disapproval-defaulted',
        "human": 'approval policy: a disapproval outcome was about to '
                 'fire without an explicit opt-in rule; disapproval is '
                 'never the default, refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-policy-malformed': {
        "domain": 'approval-policy',
        "code": 'approval-policy-malformed',
        "human": 'approval policy: the rule document, rule, or request '
                 'is not well-formed; it never compiles into something '
                 'weaker, refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'approval-policy-no-audit-sink': {
        "domain": 'approval-policy',
        "code": 'approval-policy-no-audit-sink',
        "human": 'approval policy: auto-approve or opt-in disapproval '
                 'refused -- no audit sink is configured, and silent '
                 'non-human decisions are never allowed',
        "severity": 'high',
        "evidence_kinds_required": ['approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-policy-seam-unavailable': {
        "domain": 'approval-policy',
        "code": 'approval-policy-seam-unavailable',
        "human": 'approval policy: require-approval refused -- the '
                 'human queue public seam is unavailable; the request '
                 'is dropped, never auto-passed',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-quorum-invalid': {
        "domain": 'approval',
        "code": 'approval-quorum-invalid',
        "human": 'approval quorum: malformed request, malformed vote, '
                 'bad signature, unknown voter, duplicate voter, '
                 'non-role veto, or registry over the predicate bound; '
                 'a bad ballot poisons the whole tally, refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-quorum-self-vote': {
        "domain": 'approval',
        "code": 'approval-quorum-self-vote',
        "human": 'approval quorum: the requester voted on their own '
                 'request; the requester approves by re-proposing, never '
                 'by voting',
        "severity": 'high',
        "evidence_kinds_required": ['approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-quorum-unmet': {
        "domain": 'approval',
        "code": 'approval-quorum-unmet',
        "human": 'approval quorum: fewer distinct verified approves than '
                 'the predicate minimum; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-quorum-vetoed': {
        "domain": 'approval',
        "code": 'approval-quorum-vetoed',
        "human": 'approval quorum: a blocking veto role cast a veto; '
                 'one veto is un-outvotable, no number of approves '
                 'overrides it',
        "severity": 'high',
        "evidence_kinds_required": ['approval-record'],
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
    'approval-request-digest-missing': {
        "domain": 'approval',
        "code": 'approval-request-digest-missing',
        "human": 'approval request: the request does not completely bind '
                 'its subject -- missing or malformed digests, or the '
                 'presented action digest is not the one this request '
                 'authorizes (re-plan => re-request)',
        "severity": 'high',
        "evidence_kinds_required": ['approval-request', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'approval-request-expired': {
        "domain": 'approval',
        "code": 'approval-request-expired',
        "human": 'approval request: the request time box elapsed; silence '
                 'refuses -- the agent must re-issue, a late decision can '
                 'never resurrect it; an expired request cannot complete '
                 'a quorum',
        "severity": 'high',
        "evidence_kinds_required": ['approval-request', 'approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-request-forgery': {
        "domain": 'approval',
        "code": 'approval-request-forgery',
        "human": 'approval request: the signature does not verify against '
                 'the request body (mutated post-issue, wrong key, or '
                 'requester-pubkey pin mismatch)',
        "severity": 'critical',
        "evidence_kinds_required": ['approval-request', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'approval-request-invalid': {
        "domain": 'approval',
        "code": 'approval-request-invalid',
        "human": 'approval request: malformed shape, bad approver schema, '
                 'or a request from the future',
        "severity": 'high',
        "evidence_kinds_required": ['approval-request'],
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
    'approval-token-argument-mismatch': {
        "domain": 'approval',
        "code": 'approval-token-argument-mismatch',
        "human": 'approval token: the presented arguments do not match '
                 'the token\'s argument binding -- substitution, removal, '
                 'or widening of the approved arguments; the token '
                 'authorizes a different action than the one presented',
        "severity": 'high',
        "evidence_kinds_required": ['approval-token', 'approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-token-capability-mismatch': {
        "domain": 'approval',
        "code": 'approval-token-capability-mismatch',
        "human": 'approval token: the presented capability (tool/operation) '
                 'is not the capability the token was minted for; a token '
                 'for one tool never authorizes another',
        "severity": 'high',
        "evidence_kinds_required": ['approval-token', 'approval-record'],
        "reverify_steps": ['recompute'],
    },
    'approval-token-expired': {
        "domain": 'approval',
        "code": 'approval-token-expired',
        "human": 'approval token: the token\'s time box elapsed; an '
                 'expired token authorizes nothing -- re-approval mints a '
                 'fresh token',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-token'],
        "reverify_steps": ['recompute'],
    },
    'approval-token-malformed': {
        "domain": 'approval',
        "code": 'approval-token-malformed',
        "human": 'approval token: malformed shape -- missing fields, bad '
                 'version, non-JSON-native argument binding, or a token '
                 'from the future; uninterpretable tokens authorize nothing',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-token'],
        "reverify_steps": ['recompute'],
    },
    'approval-token-replayed': {
        "domain": 'approval',
        "code": 'approval-token-replayed',
        "human": 'approval token: the token\'s nonce was already consumed -- '
                 'a token authorizes at most one execution; replaying a '
                 'consumed token is refused',
        "severity": 'high',
        "evidence_kinds_required": ['approval-token'],
        "reverify_steps": ['recompute'],
    },
    'approval-token-tampered': {
        "domain": 'approval',
        "code": 'approval-token-tampered',
        "human": 'approval token: the seal does not recompute over the '
                 'token body under any keyring epoch -- the token was '
                 'edited after minting',
        "severity": 'critical',
        "evidence_kinds_required": ['approval-token', 'signature'],
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
    'artifact-blob-extra': {
        "domain": 'artifact-pack',
        "code": 'artifact-blob-extra',
        "human": 'artifact pack: a blob was provided that the manifest '
                 'does not list; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['artifact', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'artifact-blob-missing': {
        "domain": 'artifact-pack',
        "code": 'artifact-blob-missing',
        "human": 'artifact pack: the manifest lists a blob that was not '
                 'provided; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['artifact', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'artifact-blob-tampered': {
        "domain": 'artifact-pack',
        "code": 'artifact-blob-tampered',
        "human": 'artifact pack: a blob digest does not match its '
                 'content; the blob was altered after packing; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['artifact', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'artifact-gate-refused': {
        "domain": 'namespace',
        "code": 'artifact-gate-refused',
        "human": 'deployment namespace: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'artifact-manifest-malformed': {
        "domain": 'artifact-pack',
        "code": 'artifact-manifest-malformed',
        "human": 'artifact pack: the manifest or pack input is '
                 'structurally invalid; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['artifact', 'manifest'],
        "reverify_steps": ['recompute'],
    },
    'artifact-manifest-tampered': {
        "domain": 'artifact-pack',
        "code": 'artifact-manifest-tampered',
        "human": 'artifact pack: the manifest digest does not match; '
                 'the manifest was altered after packing; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['artifact', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'artifact-size-mismatch': {
        "domain": 'artifact-pack',
        "code": 'artifact-size-mismatch',
        "human": 'artifact pack: a manifest size field disagrees with '
                 'the provided bytes; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['artifact', 'manifest', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'artifact-type-unknown': {
        "domain": 'artifact-pack',
        "code": 'artifact-type-unknown',
        "human": 'artifact pack: the artifactType is not a registered '
                 'Sasanam artifact type; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['artifact', 'manifest'],
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
    'atomic-arg-refused': {
        "domain": 'atomic',
        "code": 'atomic-arg-refused',
        "human": 'atomic test: caller args failed typed validation before '
                 'the run -- unknown argument, wrong type (bool is not int), '
                 'missing required argument, or enum outside choices; '
                 'refused fail-closed before any executor ran',
        "severity": 'medium',
        "evidence_kinds_required": ['atomic-run'],
        "reverify_steps": ['recompute'],
    },
    'atomic-cleanup-failed': {
        "domain": 'atomic',
        "code": 'atomic-cleanup-failed',
        "human": 'atomic test: the guaranteed cleanup_command raised; '
                 'raised LOUD as AtomicCleanupError carrying the executor '
                 'outcome -- a cleanup failure is never silent',
        "severity": 'high',
        "evidence_kinds_required": ['atomic-run'],
        "reverify_steps": ['recompute'],
    },
    'atomic-dependency-refused': {
        "domain": 'atomic',
        "code": 'atomic-dependency-refused',
        "human": 'atomic test: a dependency prereq self-check failed and '
                 'auto-remediation did not establish it; refused LOUD '
                 'instead of silently skipping the test',
        "severity": 'medium',
        "evidence_kinds_required": ['atomic-run'],
        "reverify_steps": ['recompute'],
    },
    'atomic-elevation-required': {
        "domain": 'atomic',
        "code": 'atomic-elevation-required',
        "human": 'atomic test: the executor declares elevation_required '
                 'but the run did not assert elevation_granted; refused '
                 'fail-closed rather than running unprivileged',
        "severity": 'medium',
        "evidence_kinds_required": ['atomic-run'],
        "reverify_steps": ['recompute'],
    },
    'atomic-guid-collision': {
        "domain": 'atomic',
        "code": 'atomic-guid-collision',
        "human": 'atomic test: a guid already registered with a different '
                 'spec, or a committed manifest whose spec_digest no longer '
                 'matches the registered test; replay identity drift '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['atomic-manifest'],
        "reverify_steps": ['recompute'],
    },
    'atomic-spec-invalid': {
        "domain": 'atomic',
        "code": 'atomic-spec-invalid',
        "human": 'atomic test: the spec or committed manifest failed the '
                 'CI schema gate -- malformed shape, unknown arg type, '
                 'non-callable executor/dependency, or unreadable manifest; '
                 'refused before any run',
        "severity": 'high',
        "evidence_kinds_required": ['atomic-manifest'],
        "reverify_steps": ['recompute'],
    },
    'attackpath-duplicate-node': {
        "domain": 'policy',
        "code": 'attackpath-duplicate-node',
        "human": 'attack-path auditor: a node id is already registered in '
                 'the grant graph; the duplicate registration is refused, '
                 'never merged',
        "severity": 'low',
        "evidence_kinds_required": ['trust-record'],
        "reverify_steps": ['recompute'],
    },
    'attackpath-unknown-edge-type': {
        "domain": 'policy',
        "code": 'attackpath-unknown-edge-type',
        "human": 'attack-path auditor: an edge names a type outside the '
                 'closed vocabulary {granted_to, delegated_by, approved, '
                 'checked}; refused fail-closed, never widened implicitly',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-record'],
        "reverify_steps": ['recompute'],
    },
    'attackpath-unknown-node': {
        "domain": 'policy',
        "code": 'attackpath-unknown-node',
        "human": 'attack-path auditor: an edge or marking references an '
                 'unregistered node id, or a node id is malformed; refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-record'],
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
    'attestation-class-inflation': {
        "domain": 'attested',
        "code": 'attestation-class-inflation',
        "human": 'attested-vs-asserted field column: a caller-declared or '
                 'caller-asserted field was presented as issuer-verified; '
                 'refusing instead of conferring verification it never had',
        "severity": 'high',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'attestation-class-unlabeled': {
        "domain": 'attested',
        "code": 'attestation-class-unlabeled',
        "human": 'attested-vs-asserted field column: a record field has no '
                 'attestation class; refusing at emit instead of inventing '
                 'one',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'attestation-outcome-misread': {
        "domain": 'attested',
        "code": 'attestation-outcome-misread',
        "human": 'attested-vs-asserted field column: the decision outcome '
                 'was presented as proof of execution; ALLOWED attests the '
                 'decision only, proof of execution needs issuer-attested '
                 'effect evidence',
        "severity": 'high',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'attestation-record-malformed': {
        "domain": 'attested',
        "code": 'attestation-record-malformed',
        "human": 'attested-vs-asserted field column: the record is the '
                 'wrong shape; refusing instead of guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'attestor-ceremony-invalid': {
        "domain": 'attested',
        "code": 'attestor-ceremony-invalid',
        "human": 'attestor registry: a registration entry write without a '
                 'valid claim-level ceremony (missing, unknown signer, or '
                 'bad signature); the write never lands',
        "severity": 'high',
        "evidence_kinds_required": ['audit-record', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'attestor-entry-ambiguous': {
        "domain": 'attested',
        "code": 'attestor-entry-ambiguous',
        "human": 'attestor registry: collected environment facts matched '
                 'more than one registration entry; refused fail-closed '
                 'rather than picking one',
        "severity": 'high',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'attestor-entry-malformed': {
        "domain": 'attested',
        "code": 'attestor-entry-malformed',
        "human": 'attestor registry: a registration entry fails shape '
                 'validation (or duplicates an existing entry id); '
                 'refusing instead of guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'attestor-entry-unmatched': {
        "domain": 'attested',
        "code": 'attestor-entry-unmatched',
        "human": 'attestor registry: collected environment facts match no '
                 'registration entry (or the matched entry is bound to a '
                 'different producer); cert issuance refused unattested',
        "severity": 'high',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'attestor-facts-malformed': {
        "domain": 'attested',
        "code": 'attestor-facts-malformed',
        "human": 'attestor seam: the attestor returned a malformed '
                 'collection (missing attestor id, non-dict or non-scalar '
                 'facts); refusing rather than issuing unattested',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'authority-lifecycle-expired': {
        "domain": 'authority-lifecycle',
        "code": 'authority-lifecycle-expired',
        "human": 'authority lease with heartbeat: the lease is past its '
                 'ttl -- absolute death, terminal; a suspension parked the '
                 'lease but never extended it',
        "severity": 'high',
        "evidence_kinds_required": ['authority-status', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'authority-lifecycle-heartbeat-lapsed': {
        "domain": 'authority-lifecycle',
        "code": 'authority-lifecycle-heartbeat-lapsed',
        "human": 'authority lease with heartbeat: the re-proof stream '
                 'broke -- a heartbeat was missed (silence revokes), '
                 'replayed, stale, misbound, or forged, the proof signer '
                 'is not the subject or the designated monitor, the lease '
                 'is suspended, or a suspend/resume authorization is '
                 'invalid',
        "severity": 'high',
        "evidence_kinds_required": ['authority-status', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'authority-lifecycle-revoked': {
        "domain": 'authority-lifecycle',
        "code": 'authority-lifecycle-revoked',
        "human": 'authority lease with heartbeat: a per-delegator revoker '
                 'entry targets this lease -- terminal; a revoked lease '
                 'never heartbeats, checks, or resumes back to life',
        "severity": 'high',
        "evidence_kinds_required": ['authority-status', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'authority-stale': {
        "domain": 'authority',
        "code": 'authority-stale',
        "human": 'proof != authority fail-safe: the proof verified but '
                 'the authority is revoked, expired, or lapsed; refused '
                 'fail-safe, never proof pass-through',
        "severity": 'high',
        "evidence_kinds_required": ['authority-status', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'authority-unavailable': {
        "domain": 'authority',
        "code": 'authority-unavailable',
        "human": 'proof != authority fail-safe: the authority source is '
                 'unavailable; deterministic named fail-safe, not a '
                 'timeout-retry loop',
        "severity": 'high',
        "evidence_kinds_required": ['authority-status'],
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
    'authz-allow': {
        "domain": 'authz',
        "code": 'authz-allow',
        "human": 'four-bucket authorization combine: an ALLOW rule '
                 'matched (or default-allow with no allow rules '
                 'configured); the request is admitted',
        "severity": 'low',
        "evidence_kinds_required": ['authorization-bundle',
                                    'authorization-request'],
        "reverify_steps": ['recompute'],
    },
    'authz-audit-hit': {
        "domain": 'authz',
        "code": 'authz-audit-hit',
        "human": 'four-bucket authorization combine: an AUDIT rule '
                 'matched; logged only, never enforced',
        "severity": 'low',
        "evidence_kinds_required": ['authorization-bundle',
                                    'authorization-request'],
        "reverify_steps": ['recompute'],
    },
    'authz-default-deny': {
        "domain": 'authz',
        "code": 'authz-default-deny',
        "human": 'four-bucket authorization combine: no allow rule '
                 'matched and at least one allow rule is configured; '
                 'default-deny refuses',
        "severity": 'high',
        "evidence_kinds_required": ['authorization-bundle',
                                    'authorization-request'],
        "reverify_steps": ['recompute'],
    },
    'authz-deny': {
        "domain": 'authz',
        "code": 'authz-deny',
        "human": 'four-bucket authorization combine: a DENY rule '
                 'matched (or a provider denied); deny-before-allow '
                 'is structural',
        "severity": 'high',
        "evidence_kinds_required": ['authorization-bundle',
                                    'authorization-request'],
        "reverify_steps": ['recompute'],
    },
    'authz-malformed-bundle': {
        "domain": 'authz',
        "code": 'authz-malformed-bundle',
        "human": 'four-bucket authorization combine: the bundle is '
                 'not a well-formed authorization bundle; refusing '
                 'at load',
        "severity": 'medium',
        "evidence_kinds_required": ['authorization-bundle'],
        "reverify_steps": ['recompute'],
    },
    'authz-malformed-rule': {
        "domain": 'authz',
        "code": 'authz-malformed-rule',
        "human": 'four-bucket authorization combine: a rule is not '
                 'well-formed (bad name, unknown action, unknown '
                 'keys, bad clause); refusing at load',
        "severity": 'medium',
        "evidence_kinds_required": ['authorization-bundle'],
        "reverify_steps": ['recompute'],
    },
    'authz-partial-attributes': {
        "domain": 'authz',
        "code": 'authz-partial-attributes',
        "human": 'four-bucket authorization combine: decision-path '
                 'rules were unevaluable on attributes missing at '
                 'the enforcement point; the fidelity loss is loud '
                 'and the verdict fails closed',
        "severity": 'high',
        "evidence_kinds_required": ['authorization-bundle',
                                    'authorization-request'],
        "reverify_steps": ['recompute'],
    },
    'authz-provider-misconfigured': {
        "domain": 'authz',
        "code": 'authz-provider-misconfigured',
        "human": 'four-bucket authorization combine: a custom rule '
                 'matched but the external authorizer provider is '
                 'misconfigured, absent, errored, or timed out; '
                 'fail-closed deny-everything',
        "severity": 'high',
        "evidence_kinds_required": ['authorization-bundle',
                                    'authorization-request'],
        "reverify_steps": ['recompute'],
    },
    'authz-shadow-evaluated': {
        "domain": 'authz',
        "code": 'authz-shadow-evaluated',
        "human": 'four-bucket authorization combine: a shadow '
                 '(dry-run) rule was evaluated and reported but not '
                 'enforced',
        "severity": 'low',
        "evidence_kinds_required": ['authorization-bundle',
                                    'authorization-request'],
        "reverify_steps": ['recompute'],
    },
    'authz-uncheckable': {
        "domain": 'authz',
        "code": 'authz-uncheckable',
        "human": 'four-bucket authorization combine: the request or '
                 'bundle could not be evaluated; fail-closed backstop',
        "severity": 'medium',
        "evidence_kinds_required": ['authorization-request'],
        "reverify_steps": ['recompute'],
    },
    'axis-ceiling-hit': {
        "domain": 'axis',
        "code": 'axis-ceiling-hit',
        "human": 'axis/result model: require_valid refused a chain that '
                 'is indeterminate because a verifier ceiling was hit; '
                 'the limit is named, never treated as invalid',
        "severity": 'medium',
        "evidence_kinds_required": ['verification-result'],
        "reverify_steps": ['recompute'],
    },
    'axis-indeterminate': {
        "domain": 'axis',
        "code": 'axis-indeterminate',
        "human": 'axis/result model: require_valid refused a chain that '
                 'is indeterminate for a non-ceiling reason; '
                 'indeterminate never reads as valid',
        "severity": 'medium',
        "evidence_kinds_required": ['verification-result'],
        "reverify_steps": ['recompute'],
    },
    'axis-invalid': {
        "domain": 'axis',
        "code": 'axis-invalid',
        "human": 'axis/result model: require_valid refused a chain that '
                 'aggregates to invalid; invalid chains never read as '
                 'valid',
        "severity": 'high',
        "evidence_kinds_required": ['verification-result'],
        "reverify_steps": ['recompute'],
    },
    'axis-unestablished': {
        "domain": 'axis',
        "code": 'axis-unestablished',
        "human": 'axis/result model: require_valid refused a chain that '
                 'is not valid because an axis was unestablished; '
                 'unestablished axes never contribute to valid',
        "severity": 'medium',
        "evidence_kinds_required": ['verification-result'],
        "reverify_steps": ['recompute'],
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
    'ballot-bad-signature': {
        "domain": 'ballot',
        "code": 'ballot-bad-signature',
        "human": 'ballot governance: the vote signature does not verify '
                 'against the member key; the vote is refused, never counted',
        "severity": 'high',
        "evidence_kinds_required": ['ballot', 'vote', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ballot-double-vote': {
        "domain": 'ballot',
        "code": 'ballot-double-vote',
        "human": 'ballot governance: the member already voted on this '
                 'ballot; the second vote is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ballot', 'vote'],
        "reverify_steps": ['recompute'],
    },
    'ballot-late-vote': {
        "domain": 'ballot',
        "code": 'ballot-late-vote',
        "human": 'ballot governance: the vote arrived after the ballot was '
                 'resolved; the late vote is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ballot', 'vote'],
        "reverify_steps": ['recompute'],
    },
    'ballot-malformed-proposal': {
        "domain": 'ballot',
        "code": 'ballot-malformed-proposal',
        "human": 'ballot governance: the proposal or vote payload is '
                 'malformed; refused at admission',
        "severity": 'medium',
        "evidence_kinds_required": ['ballot', 'proposal'],
        "reverify_steps": ['recompute'],
    },
    'ballot-not-member': {
        "domain": 'ballot',
        "code": 'ballot-not-member',
        "human": 'ballot governance: the proposer or voter is not a '
                 'consortium member; refused, never counted',
        "severity": 'high',
        "evidence_kinds_required": ['ballot', 'constitution', 'vote'],
        "reverify_steps": ['recompute'],
    },
    'ballot-quorum-not-reached': {
        "domain": 'ballot',
        "code": 'ballot-quorum-not-reached',
        "human": 'ballot governance: the electorate is exhausted without '
                 'an adoption outcome; the ballot is explicitly rejected, '
                 'never silently adopted',
        "severity": 'medium',
        "evidence_kinds_required": ['ballot', 'vote'],
        "reverify_steps": ['recompute'],
    },
    'ballot-unknown-ballot': {
        "domain": 'ballot',
        "code": 'ballot-unknown-ballot',
        "human": 'ballot governance: the ballot id is unknown; the '
                 'operation is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ballot'],
        "reverify_steps": ['recompute'],
    },
    'ballot-unknown-ballot-type': {
        "domain": 'ballot',
        "code": 'ballot-unknown-ballot-type',
        "human": 'ballot governance: the proposal names a ballot type not '
                 'in the constitution; refused at admission',
        "severity": 'medium',
        "evidence_kinds_required": ['ballot', 'constitution'],
        "reverify_steps": ['recompute'],
    },
    'ballot-vote-hook-failed': {
        "domain": 'ballot',
        "code": 'ballot-vote-hook-failed',
        "human": 'ballot governance: the programmable vote() or resolve() '
                 'hook failed or broke its contract; the vote or resolution '
                 'is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ballot', 'constitution'],
        "reverify_steps": ['recompute'],
    },
    'battery-lang-bad-manifest': {
        "domain": 'battery',
        "code": 'battery-lang-bad-manifest',
        "human": 'battery language: the committed manifest is malformed '
                 '(unknown format, missing fields, empty probe list, or '
                 'duplicate probe ids); refused fail-closed, never '
                 'eval-evaluated',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-bad-metadata': {
        "domain": 'battery',
        "code": 'battery-lang-bad-metadata',
        "human": 'battery language: a probe metadata entry is not a '
                 '(plugin, strategy, grader) triple of registered ids; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-bad-module': {
        "domain": 'battery',
        "code": 'battery-lang-bad-module',
        "human": 'battery language: the probe module named by the manifest '
                 'cannot be imported; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-bad-probe': {
        "domain": 'battery',
        "code": 'battery-lang-bad-probe',
        "human": 'battery language: a manifest probe entry is malformed '
                 '(missing field, unregistered plugin/strategy/grader, or '
                 'expected outside the verdict vocabulary); refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-bad-probe-entry': {
        "domain": 'battery',
        "code": 'battery-lang-bad-probe-entry',
        "human": 'battery language: a PROBES entry is not a '
                 '(probe_id, expected, callable) triple with a registered '
                 'expected verdict; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-expected-drift': {
        "domain": 'battery',
        "code": 'battery-lang-expected-drift',
        "human": 'battery language: the probe module expectations drifted '
                 'from the committed manifest (the manifest is the contract); '
                 'eval refused fail-closed until the manifest is regenerated',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-no-metadata': {
        "domain": 'battery',
        "code": 'battery-lang-no-metadata',
        "human": 'battery language: the probe module exposes no '
                 'PROBE_METADATA mapping; unannotated modules cannot '
                 'generate a committed manifest (no unlabeled probes)',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-no-probes': {
        "domain": 'battery',
        "code": 'battery-lang-no-probes',
        "human": 'battery language: the probe module exposes no PROBES '
                 'list; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-probe-missing': {
        "domain": 'battery',
        "code": 'battery-lang-probe-missing',
        "human": 'battery language: a manifest probe id is absent from the '
                 'probe module; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-unannotated': {
        "domain": 'battery',
        "code": 'battery-lang-unannotated',
        "human": 'battery language: one or more probes lack vocabulary '
                 'metadata; generate refused so no unlabeled probe enters a '
                 'committed suite',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-unknown-grader': {
        "domain": 'battery',
        "code": 'battery-lang-unknown-grader',
        "human": 'battery language: the grader id is not registered; '
                 'refused fail-closed (no LLM judges, deterministic only)',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-unknown-plugin': {
        "domain": 'battery',
        "code": 'battery-lang-unknown-plugin',
        "human": 'battery language: the plugin id is not in the registered '
                 'attack vocabulary; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'battery-lang-unknown-strategy': {
        "domain": 'battery',
        "code": 'battery-lang-unknown-strategy',
        "human": 'battery language: the strategy id is not in the registered '
                 'delivery vocabulary; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['regenerate-manifest'],
    },
    'behsig-correlator-advisory': {
        "domain": 'behsig',
        "code": 'behsig-correlator-advisory',
        "human": 'behavioral-signature v2: the stateful correlator '
                 'fired above the stateless rule predicates (burst, '
                 'fire-storm, slow-drip, or ratio gate); journaled '
                 'advisory with a queued human hold request -- never '
                 'a denial, never a block',
        "severity": 'medium',
        "evidence_kinds_required": ['journal', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'behsig-pack-malformed': {
        "domain": 'behsig',
        "code": 'behsig-pack-malformed',
        "human": 'behavioral-signature v2: the signature pack fails '
                 'schema validation (bad shape, unknown comparator, '
                 'duplicate name); refused loudly before any rule '
                 'loads -- malformed packs are never silently passed',
        "severity": 'high',
        "evidence_kinds_required": ['pack', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'behsig-pack-untrusted': {
        "domain": 'behsig',
        "code": 'behsig-pack-untrusted',
        "human": 'behavioral-signature v2: the signature pack has no '
                 'valid signature from the configured trust material '
                 '(tampered, unsigned, or no trust material '
                 'configured); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['pack', 'signature',
                                    'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'behsig-rule-disabled': {
        "domain": 'behsig',
        "code": 'behsig-rule-disabled',
        "human": 'behavioral-signature v2: a rule references an '
                 'enrichment field the engine does not know; the '
                 'rule is disabled with a loud journal record and '
                 'the rest of the pack still loads -- unknown fields '
                 'never silently pass and never silently drop a pack',
        "severity": 'medium',
        "evidence_kinds_required": ['pack', 'journal'],
        "reverify_steps": ['recompute'],
    },
    'behsig-rule-eval-failed': {
        "domain": 'behsig',
        "code": 'behsig-rule-eval-failed',
        "human": 'behavioral-signature v2: a rule condition raised '
                 'during evaluation on one event; the rule was '
                 'skipped for that event only (transient), the rule '
                 'itself stays loaded -- evaluation failures never '
                 'silently pass and never drop a pack',
        "severity": 'medium',
        "evidence_kinds_required": ['pack', 'journal'],
        "reverify_steps": ['recompute'],
    },
    'behsig-tuning-applied': {
        "domain": 'behsig',
        "code": 'behsig-tuning-applied',
        "human": 'behavioral-signature v2: a deployment tuning '
                 'overlay was applied (added exceptions, raised '
                 'floors, or a justified stable-rule disable); '
                 'journaled loudly -- tuning is append/override '
                 'only, packs are never edited in place',
        "severity": 'low',
        "evidence_kinds_required": ['pack', 'journal'],
        "reverify_steps": ['recompute'],
    },
    'behsig-tuning-rejected': {
        "domain": 'behsig',
        "code": 'behsig-tuning-rejected',
        "human": 'behavioral-signature v2: a deployment tuning '
                 'overlay was refused (threshold below an author '
                 'floor, unknown rule, an unjustified stable-rule '
                 'disable, or an exception shape the rule author '
                 'did not declare); the pack is unchanged',
        "severity": 'medium',
        "evidence_kinds_required": ['pack', 'refusal-record'],
        "reverify_steps": ['recompute'],
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
    'breach-boundary-budget-exceeded': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-budget-exceeded',
        "human": 'a declared component exceeded its consequence budget '
                 'for the deployment window; the circuit breaker tripped '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['boundary-record', 'spend-ledger'],
        "reverify_steps": ['recompute'],
    },
    'breach-boundary-circuit-tripped': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-circuit-tripped',
        "human": 'the circuit breaker is tripped for this component; '
                 'ingest, verify, spend, and use are refused fail-closed '
                 'until a deployment-vouched reset',
        "severity": 'high',
        "evidence_kinds_required": ['boundary-record', 'breach-signal'],
        "reverify_steps": ['recompute'],
    },
    'breach-boundary-compromised-source': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-compromised-source',
        "human": 'the component is marked compromised; its outputs are '
                 'refused until a deployment-vouched rotation (the '
                 'instance-as-compromised rotation doctrine)',
        "severity": 'high',
        "evidence_kinds_required": ['boundary-record',
                                    'compromise-record'],
        "reverify_steps": ['recompute', 'provenance-check'],
    },
    'breach-boundary-external-untrusted': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-external-untrusted',
        "human": 'an output arrived from an external-untrusted component; '
                 'it sits outside the boundary and is refused outright, '
                 'never quarantined',
        "severity": 'high',
        "evidence_kinds_required": ['boundary-record', 'provenance'],
        "reverify_steps": ['recompute', 'provenance-check'],
    },
    'breach-boundary-quarantined': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-quarantined',
        "human": 'informational: an assumed-breachable component output '
                 'was quarantined with containment metadata; use is '
                 'allowed only after deployment-vouched verification',
        "severity": 'low',
        "evidence_kinds_required": ['boundary-record',
                                    'quarantine-record'],
        "reverify_steps": ['recompute'],
    },
    'breach-boundary-record-malformed': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-record-malformed',
        "human": 'a boundary record (declaration, signal, verifier, '
                 'reset, rotation, or quarantine record) is malformed; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['boundary-record'],
        "reverify_steps": ['recompute'],
    },
    'breach-boundary-reset-unvouched': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-reset-unvouched',
        "human": 'a circuit-breaker reset was not deployment-vouched; a '
                 'self-asserted reset never clears a trip',
        "severity": 'medium',
        "evidence_kinds_required": ['boundary-record', 'vouch-map'],
        "reverify_steps": ['recompute', 'provenance-check'],
    },
    'breach-boundary-rotation-unvouched': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-rotation-unvouched',
        "human": 'a compromise rotation was not deployment-vouched; a '
                 'self-asserted rotation never clears a compromise mark',
        "severity": 'medium',
        "evidence_kinds_required": ['boundary-record', 'vouch-map'],
        "reverify_steps": ['recompute', 'provenance-check'],
    },
    'breach-boundary-seal-invalid': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-seal-invalid',
        "human": 'a quarantined record claimed verified status but its '
                 'verification seal was missing or did not match: the '
                 'record was forged or mutated after verification',
        "severity": 'high',
        "evidence_kinds_required": ['boundary-record', 'quarantine-record'],
        "reverify_steps": ['recompute'],
    },
    'breach-boundary-unknown-component': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-unknown-component',
        "human": 'the component was never declared to the boundary; '
                 'undeclared components have no containment posture',
        "severity": 'medium',
        "evidence_kinds_required": ['boundary-record'],
        "reverify_steps": ['recompute'],
    },
    'breach-boundary-unverified-use-refused': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-unverified-use-refused',
        "human": 'a quarantined output was used without '
                 'deployment-vouched verification; containment means '
                 'never trusted downstream unverified',
        "severity": 'high',
        "evidence_kinds_required": ['boundary-record',
                                    'quarantine-record'],
        "reverify_steps": ['recompute', 'provenance-check'],
    },
    'breach-boundary-verifier-unvouched': {
        "domain": 'breach-boundary',
        "code": 'breach-boundary-verifier-unvouched',
        "human": 'the verifier that approved a quarantined output was '
                 'not deployment-vouched; agent-asserted verification '
                 'never unwraps quarantine',
        "severity": 'medium',
        "evidence_kinds_required": ['boundary-record', 'vouch-map'],
        "reverify_steps": ['recompute', 'provenance-check'],
    },
    'bundle-delivery-cache-locked': {
        "domain": 'bundle',
        "code": 'bundle-delivery-cache-locked',
        "human": 'bundle delivery: cache directory already held by another refresher; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'cache', 'lock'],
        "reverify_steps": ['retry'],
    },
    'bundle-delivery-delegation-cap-exceeded': {
        "domain": 'bundle',
        "code": 'bundle-delivery-delegation-cap-exceeded',
        "human": 'bundle delivery: delegation walk visited more than 32 roles; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'delegation', 'walk'],
        "reverify_steps": ['recompute'],
    },
    'bundle-delivery-delegation-cycle': {
        "domain": 'bundle',
        "code": 'bundle-delivery-delegation-cycle',
        "human": 'bundle delivery: a delegation cycle was detected on the trust walk; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'delegation', 'cycle'],
        "reverify_steps": ['recompute'],
    },
    'bundle-delivery-delegation-malformed': {
        "domain": 'bundle',
        "code": 'bundle-delivery-delegation-malformed',
        "human": 'bundle delivery: a delegation or delegated-targets document failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'delegation', 'shape'],
        "reverify_steps": ['recompute'],
    },
    'bundle-delivery-delegation-unverified': {
        "domain": 'bundle',
        "code": 'bundle-delivery-delegation-unverified',
        "human": 'bundle delivery: a delegated-targets envelope failed the delegation key/threshold check, or eligible delegated metadata is missing; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'bundle-delivery-expired-authority-refused': {
        "domain": 'bundle',
        "code": 'bundle-delivery-expired-authority-refused',
        "human": 'bundle delivery: expired metadata presented as an authority for a target digest; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'delegation', 'expiry'],
        "reverify_steps": ['recompute'],
    },
    'bundle-delivery-expired-bootstrap-refused': {
        "domain": 'bundle',
        "code": 'bundle-delivery-expired-bootstrap-refused',
        "human": 'bundle delivery: an expired intermediate could not bootstrap a verified successor; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'delegation', 'expiry'],
        "reverify_steps": ['recompute'],
    },
    'bundle-delivery-mirror-stale': {
        "domain": 'bundle',
        "code": 'bundle-delivery-mirror-stale',
        "human": 'bundle delivery: bytes at a versioned URL do not match the bound version or digest; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'mirror', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bundle-delivery-shadowed-delegation': {
        "domain": 'bundle',
        "code": 'bundle-delivery-shadowed-delegation',
        "human": 'bundle delivery: a terminating delegation provably shadows a later delegation; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'delegation', 'shadowing'],
        "reverify_steps": ['recompute'],
    },
    'bundle-delivery-target-not-found': {
        "domain": 'bundle',
        "code": 'bundle-delivery-target-not-found',
        "human": 'bundle delivery: no visited delegation binds the requested target; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'delegation', 'target'],
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
    'bundlescan-malformed': {
        "domain": 'bundle',
        "code": 'bundlescan-malformed',
        "human": 'bundle content scan: the payload failed structural validation; refused fail-closed, never unpickled',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bundlescan-odd-packaging': {
        "domain": 'bundle',
        "code": 'bundlescan-odd-packaging',
        "human": 'bundle content scan: odd but non-threatening pickle packaging (trailing bytes, multiple STOPs); advisory',
        "severity": 'low',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bundlescan-oversized': {
        "domain": 'bundle',
        "code": 'bundlescan-oversized',
        "human": 'bundle content scan: the payload exceeds the scan size bound; refused before parsing',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'bundlescan-rce-global': {
        "domain": 'bundle',
        "code": 'bundlescan-rce-global',
        "human": 'bundle content scan: a code-execution sink global with REDUCE in the pickle stream; ingestion refused',
        "severity": 'critical',
        "evidence_kinds_required": ['bundle', 'digest', 'scan-report'],
        "reverify_steps": ['recompute', 'rescan'],
    },
    'bundlescan-suspicious-global': {
        "domain": 'bundle',
        "code": 'bundlescan-suspicious-global',
        "human": 'bundle content scan: an exploitable-but-not-executing global (gadget primitive or sink without REDUCE); loud advisory',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest', 'scan-report'],
        "reverify_steps": ['recompute', 'rescan'],
    },
    'bundlescan-unknown-global': {
        "domain": 'bundle',
        "code": 'bundlescan-unknown-global',
        "human": 'bundle content scan: an unnameable global in the pickle stream; loud advisory, the scanner vouches only what it names',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle', 'digest', 'scan-report'],
        "reverify_steps": ['recompute', 'rescan'],
    },
    'callauthz-check-error': {
        "domain": 'callauthz',
        "code": 'callauthz-check-error',
        "human": 'per-call authorization: the policy check raised, timed '
                 'out, or returned a malformed verdict; denied fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['check-request'],
        "reverify_steps": ['recompute'],
    },
    'callauthz-denied': {
        "domain": 'callauthz',
        "code": 'callauthz-denied',
        "human": 'per-call authorization: the policy check denied the call',
        "severity": 'high',
        "evidence_kinds_required": ['check-request'],
        "reverify_steps": ['recompute'],
    },
    'callauthz-not-configured': {
        "domain": 'callauthz',
        "code": 'callauthz-not-configured',
        "human": 'per-call authorization: no check configured (or no '
                 'policy matched) where a check is required; denied '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['check-request'],
        "reverify_steps": ['recompute'],
    },
    'callback-approval-denied': {
        "domain": 'callback',
        "code": 'callback-approval-denied',
        "human": 'callback seam: the human denied the paused approval '
                 'request; the call never runs',
        "severity": 'medium',
        "evidence_kinds_required": ['journal-record'],
        "reverify_steps": ['recompute'],
    },
    'callback-approval-expired': {
        "domain": 'callback',
        "code": 'callback-approval-expired',
        "human": 'callback seam: the approval request was expired before '
                 'a decision arrived; a stale approval can never resolve',
        "severity": 'medium',
        "evidence_kinds_required": ['journal-record'],
        "reverify_steps": ['recompute'],
    },
    'callback-approval-requested': {
        "domain": 'callback',
        "code": 'callback-approval-requested',
        "human": 'callback seam: execution paused for human approval; '
                 'the request record carries the args digest, never raw '
                 'args',
        "severity": 'low',
        "evidence_kinds_required": ['journal-record'],
        "reverify_steps": ['recompute'],
    },
    'callback-blocked': {
        "domain": 'callback',
        "code": 'callback-blocked',
        "human": 'callback seam: a before_tool callback BLOCKed the '
                 'call; the tool never runs',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'callback-cannot-widen': {
        "domain": 'callback',
        "code": 'callback-cannot-widen',
        "human": 'callback seam: a callback rewrite widened the call '
                 'past the enforcement floor; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['policy-declaration', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'callback-faulted': {
        "domain": 'callback',
        "code": 'callback-faulted',
        "human": 'callback seam: a callback (or the enforcement '
                 'predicate) threw; the call is refused fail-closed and '
                 'no raw exception escapes into the enforcement path',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'callback-finding-escalated': {
        "domain": 'callback',
        "code": 'callback-finding-escalated',
        "human": 'callback seam: an after_tool callback escalated a '
                 'finding into the journal; the result was returned '
                 'unchanged',
        "severity": 'low',
        "evidence_kinds_required": ['journal-record'],
        "reverify_steps": ['recompute'],
    },
    'callback-malformed-verdict': {
        "domain": 'callback',
        "code": 'callback-malformed-verdict',
        "human": 'callback seam: a callback returned a non-verdict shape '
                 'or the call inputs were malformed; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'callback-unknown-approval': {
        "domain": 'callback',
        "code": 'callback-unknown-approval',
        "human": 'callback seam: resolve/expire named an approval id '
                 'with no pending request; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['journal-record'],
        "reverify_steps": ['recompute'],
    },
    'campaign-produces-suppressed': {
        "domain": 'campaign',
        "code": 'campaign-produces-suppressed',
        "human": 'campaign: a produces entry with on="always" was withheld '
                 'because the step verdict was ERROR/atomic-error -- an '
                 'atomic that raised produced nothing, so writing the '
                 'static value would fabricate evidence; the suppression '
                 'is recorded on the step record, never silent',
        "severity": 'low',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
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
    'capability-token-agent-mismatch': {
        "domain": 'capability',
        "code": 'capability-token-agent-mismatch',
        "human": 'context-bound capability token: the presenting agent is '
                 'not the agent the token was minted for; a token minted '
                 'for one agent never authorizes another',
        "severity": 'high',
        "evidence_kinds_required": ['capability-token', 'binding'],
        "reverify_steps": ['recompute'],
    },
    'capability-token-expired': {
        "domain": 'capability',
        "code": 'capability-token-expired',
        "human": 'context-bound capability token: the token\'s time box '
                 'elapsed; an expired token authorizes nothing -- '
                 're-approval mints a fresh token',
        "severity": 'medium',
        "evidence_kinds_required": ['capability-token'],
        "reverify_steps": ['recompute'],
    },
    'capability-token-malformed': {
        "domain": 'capability',
        "code": 'capability-token-malformed',
        "human": 'context-bound capability token: malformed shape -- '
                 'missing fields, bad version, unbindable context values, '
                 'or a token from the future; uninterpretable tokens '
                 'authorize nothing',
        "severity": 'medium',
        "evidence_kinds_required": ['capability-token'],
        "reverify_steps": ['recompute'],
    },
    'capability-token-mission-mismatch': {
        "domain": 'capability',
        "code": 'capability-token-mission-mismatch',
        "human": 'context-bound capability token: the presented mission is '
                 'not the mission the token was minted for; a token minted '
                 'for one mission never authorizes another',
        "severity": 'high',
        "evidence_kinds_required": ['capability-token', 'binding'],
        "reverify_steps": ['recompute'],
    },
    'capability-token-policy-stale': {
        "domain": 'capability',
        "code": 'capability-token-policy-stale',
        "human": 'context-bound capability token: the presented policy '
                 'version is not the policy version the token was minted '
                 'under; a policy rotation invalidates old tokens -- '
                 're-approval under the current policy mints a fresh token',
        "severity": 'high',
        "evidence_kinds_required": ['capability-token', 'binding'],
        "reverify_steps": ['recompute'],
    },
    'capability-token-tampered': {
        "domain": 'capability',
        "code": 'capability-token-tampered',
        "human": 'context-bound capability token: the seal does not '
                 'recompute over the token body under any keyring epoch -- '
                 'the token was edited after minting',
        "severity": 'critical',
        "evidence_kinds_required": ['capability-token', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'capability-token-tools-mismatch': {
        "domain": 'capability',
        "code": 'capability-token-tools-mismatch',
        "human": 'context-bound capability token: the presented tool set '
                 'is not the tool set the token was minted for; a token '
                 'minted for one tool set never authorizes a different one',
        "severity": 'high',
        "evidence_kinds_required": ['capability-token', 'binding'],
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
    'casbin-conf-invalid': {
        "domain": 'policy',
        "code": 'casbin-conf-invalid',
        "human": 'casbin PERM: the CONF text is malformed (unknown section, '
                 'bad definition, unknown policy_effect form); refused '
                 'fail-closed at compile',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-record'],
        "reverify_steps": ['recompute'],
    },
    'casbin-enforce-error-fail-closed': {
        "domain": 'policy',
        "code": 'casbin-enforce-error-fail-closed',
        "human": 'casbin PERM: a matcher or request-shape error failed the '
                 'whole enforcement closed to deny; never raised, never '
                 'allowed',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-record'],
        "reverify_steps": ['recompute'],
    },
    'casbin-policy-shadowed': {
        "domain": 'policy',
        "code": 'casbin-policy-shadowed',
        "human": 'casbin PERM: a policy row can never decide (exact '
                 'duplicate, or shadowed/contradicted by an earlier row); '
                 'refused fail-closed at load',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-record'],
        "reverify_steps": ['recompute'],
    },
    'casbin-unknown-matcher-function': {
        "domain": 'policy',
        "code": 'casbin-unknown-matcher-function',
        "human": 'casbin PERM: the matcher names a function outside the '
                 'audited builtin set {g, keyMatch, keyMatch2, regexMatch, '
                 'ipMatch}; refused fail-closed at compile',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-record'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-bad-signature': {
        "domain": 'ceremony',
        "code": 'ceremony-bad-signature',
        "human": 'root ceremony: a keyholder attestation signature does '
                 'not verify against the claimed key; the attestation is '
                 'refused, never counted',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-digest-mismatch': {
        "domain": 'ceremony',
        "code": 'ceremony-digest-mismatch',
        "human": 'root ceremony: a keyholder attestation references a '
                 'ceremony digest different from the ceremony under '
                 'execution; the attestation is refused as a detached '
                 'approval, never counted',
        "severity": 'high',
        "evidence_kinds_required": ['ceremony', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-double-review': {
        "domain": 'ceremony',
        "code": 'ceremony-double-review',
        "human": 'root ceremony: the keyholder already recorded a review '
                 'attestation for this ceremony; the duplicate is refused '
                 'and not double-counted',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-malformed-proposal': {
        "domain": 'ceremony',
        "code": 'ceremony-malformed-proposal',
        "human": 'root ceremony: the proposed ceremony event is malformed '
                 '(unknown event type, bad fingerprint, bad thresholds); '
                 'no ceremony opens',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-not-keyholder': {
        "domain": 'ceremony',
        "code": 'ceremony-not-keyholder',
        "human": 'root ceremony: the actor is not a named keyholder in '
                 'the ceremony constitution; the action is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-phase-violation': {
        "domain": 'ceremony',
        "code": 'ceremony-phase-violation',
        "human": 'root ceremony: the requested transition is not legal '
                 'from the current ceremony phase (propose -> review -> '
                 'rehearse -> execute -> complete); the transition is '
                 'refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-private-key-material': {
        "domain": 'ceremony',
        "code": 'ceremony-private-key-material',
        "human": 'root ceremony: the proposal carries private-key-shaped '
                 'material (forbidden field names); only the public '
                 'fingerprint may travel in a ceremony; the proposal is '
                 'refused',
        "severity": 'high',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-quorum-not-reached': {
        "domain": 'ceremony',
        "code": 'ceremony-quorum-not-reached',
        "human": 'root ceremony: execution was attempted without a '
                 'threshold of keyholder signatures; the execution is '
                 'refused, never performed',
        "severity": 'high',
        "evidence_kinds_required": ['ceremony', 'signature'],
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
    'ceremony-rehearsal-forged': {
        "domain": 'ceremony',
        "code": 'ceremony-rehearsal-forged',
        "human": 'root ceremony: the staged-rehearsal record fails '
                 'verification (digest mismatch, failed checks, wrong '
                 'namespace, or fingerprint drift); the ceremony does not '
                 'advance',
        "severity": 'high',
        "evidence_kinds_required": ['ceremony', 'rehearsal'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-rehearsal-missing': {
        "domain": 'ceremony',
        "code": 'ceremony-rehearsal-missing',
        "human": 'root ceremony: execution was attempted with no passing '
                 'staged-rehearsal record; the ceremony refuses to advance '
                 'without rehearsal evidence',
        "severity": 'high',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-replayed': {
        "domain": 'ceremony',
        "code": 'ceremony-replayed',
        "human": 'root ceremony: the ceremony id is already completed '
                 '(superseded) or a completed ceremony was mutated; the '
                 'replay is refused',
        "severity": 'high',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-routine-path-refused': {
        "domain": 'ceremony',
        "code": 'ceremony-routine-path-refused',
        "human": 'root ceremony: a root-key action was attempted through '
                 'the routine (KMS/daily) signing path; root-key actions '
                 'require the full ceremony; the routine attempt is '
                 'refused',
        "severity": 'high',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-unknown-ceremony': {
        "domain": 'ceremony',
        "code": 'ceremony-unknown-ceremony',
        "human": 'root ceremony: no ceremony exists with this id; the '
                 'action is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-already-consumed': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-already-consumed',
        "human": 'approval ceremony v2: the approval was already consumed; '
                 'a second resume is refused (one-shot consumption)',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-ambiguous-resume': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-ambiguous-resume',
        "human": 'approval ceremony v2: more than one approval is pending '
                 'and the resume did not address one by id; refused rather '
                 'than binding to an arbitrary approval',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-malformed': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-malformed',
        "human": 'approval ceremony v2: the request or resume is '
                 'shape-invalid (ids, verdicts, payloads, journal); refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-payload-tampered': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-payload-tampered',
        "human": 'approval ceremony v2: the approver receipt is validly '
                 'signed but does not bind the surfaced payload digest; '
                 'the resume is refused',
        "severity": 'high',
        "evidence_kinds_required": ['ceremony', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-receipt-invalid': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-receipt-invalid',
        "human": 'approval ceremony v2: the approver receipt does not '
                 'verify, names an unregistered reviewer, or is unreadable; '
                 'the resume is refused',
        "severity": 'high',
        "evidence_kinds_required": ['ceremony', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-schema-invalid': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-schema-invalid',
        "human": 'approval ceremony v2: the response schema is not a real '
                 'ResponseSchema type (bare dict refused); the request is '
                 'refused rather than surfacing an unvalidated schema',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-schema-violation': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-schema-violation',
        "human": 'approval ceremony v2: the resume value fails the '
                 'engine-validated response schema; the resume is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-stale-lineage': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-stale-lineage',
        "human": 'approval ceremony v2: the approval belongs to an '
                 'abandoned thread lineage; it can never resume — the fork '
                 're-fires it under a new id instead',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-unknown-approval': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-unknown-approval',
        "human": 'approval ceremony v2: no such pending approval exists; '
                 'the resume is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-verdict-arg-mismatch': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-verdict-arg-mismatch',
        "human": 'approval ceremony v2: the resume value has the wrong '
                 'type for the verdict (accept/ignore carry none, respond '
                 'carries str, edit carries an action mapping); refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
        "reverify_steps": ['recompute'],
    },
    'ceremony-v2-verdict-not-allowed': {
        "domain": 'ceremony',
        "code": 'ceremony-v2-verdict-not-allowed',
        "human": 'approval ceremony v2: the verdict is not in the '
                 'engine-held allow-list for this approval; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['ceremony'],
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
    'chain-source-stale': {
        "domain": 'authority',
        "code": 'chain-source-stale',
        "human": 'verifier-side fail-closed: the delegation-chain source '
                 'input is stale; explicit stale verdict, never a '
                 'silent pass',
        "severity": 'high',
        "evidence_kinds_required": ['chain-source-declaration'],
        "reverify_steps": ['recompute'],
    },
    'chain-source-unavailable': {
        "domain": 'authority',
        "code": 'chain-source-unavailable',
        "human": 'verifier-side fail-closed: the delegation-chain source '
                 'is unavailable; fail closed, never allow',
        "severity": 'high',
        "evidence_kinds_required": ['chain-source-declaration'],
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
    'challenge-anchor-mismatch': {
        "domain": 'challenge',
        "code": 'challenge-anchor-mismatch',
        "human": 'ceremony binding: the anchor receipt does not cover the '
                 'record\'s (content digest, nonce, purpose) tuple -- the '
                 'anchor was substituted from a different ceremony; '
                 'refused, never verified',
        "severity": 'high',
        "evidence_kinds_required": ['anchor', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'challenge-invalid-shape': {
        "domain": 'challenge',
        "code": 'challenge-invalid-shape',
        "human": 'ceremony binding: the challenge-bound record or its '
                 'issuance arguments are malformed (bad shape, bad digest, '
                 'bad purpose); the record was not minted or is not '
                 'verified',
        "severity": 'medium',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'challenge-nonce-invalid': {
        "domain": 'challenge',
        "code": 'challenge-nonce-invalid',
        "human": 'ceremony binding: the challenge nonce is shorter than '
                 'the 64-bit floor (RFC 9711 minimum); the record was not '
                 'minted or is not verified',
        "severity": 'medium',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'challenge-nonce-mismatch': {
        "domain": 'challenge',
        "code": 'challenge-nonce-mismatch',
        "human": 'ceremony binding: the record\'s challenge nonce does not '
                 'match the appraisal request -- possible replay into a '
                 'different ceremony; refused',
        "severity": 'high',
        "evidence_kinds_required": ['record', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'challenge-purpose-mismatch': {
        "domain": 'challenge',
        "code": 'challenge-purpose-mismatch',
        "human": 'ceremony binding: the record\'s challenge purpose does '
                 'not match the appraisal request -- possible purpose '
                 'confusion; refused',
        "severity": 'high',
        "evidence_kinds_required": ['record', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'challenge-signature-invalid': {
        "domain": 'challenge',
        "code": 'challenge-signature-invalid',
        "human": 'ceremony binding: the operator signature over the '
                 '(nonce, purpose, content digest) tuple did not verify -- '
                 'the record is forged or tampered; refused',
        "severity": 'high',
        "evidence_kinds_required": ['signature'],
        "reverify_steps": ['recompute'],
    },
    'channel-identity-unattested': {
        "domain": 'attested-channel',
        "code": 'channel-identity-unattested',
        "human": 'self-reported principal with no attested peer identity; refused, never downgraded',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'channel-peer-mismatch': {
        "domain": 'attested-channel',
        "code": 'channel-peer-mismatch',
        "human": 'attested peer identity names a different principal than the self-reported one',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'channel-record-malformed': {
        "domain": 'attested-channel',
        "code": 'channel-record-malformed',
        "human": 'emitter claim or attested peer block is not the shape the admission layer speaks',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'channel-sequence-break': {
        "domain": 'attested-channel',
        "code": 'channel-sequence-break',
        "human": 'claim sequence does not follow the peer last admitted sequence',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'channel-timestamp-divergence': {
        "domain": 'attested-channel',
        "code": 'channel-timestamp-divergence',
        "human": 'emitter ts_emit diverges from daemon time beyond the forgery bound',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-chain-broken': {
        "domain": 'checkpoints',
        "code": 'checkpoint-chain-broken',
        "human": 'audit checkpoints: a checkpoint prev_digest link does not match its predecessor',
        "severity": 'critical',
        "evidence_kinds_required": ['checkpoint', 'signature'],
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
    'checkpoint-evidence-not-authorization': {
        "domain": 'checkpoints',
        "code": 'checkpoint-evidence-not-authorization',
        "human": 'audit checkpoints: checkpoint evidence was used as authority',
        "severity": 'high',
        "evidence_kinds_required": ['checkpoint'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-extension-empty': {
        "domain": 'checkpoint',
        "code": 'checkpoint-extension-empty',
        "human": 'C2SP checkpoint: an extension line is empty',
        "severity": 'low',
        "evidence_kinds_required": ['checkpoint-note'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-inconsistent': {
        "domain": 'checkpoint',
        "code": 'checkpoint-inconsistent',
        "human": 'C2SP checkpoint: journal refused a different root '
                 'for an already-signed (origin, size)',
        "severity": 'high',
        "evidence_kinds_required": ['checkpoint-note'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-known-signature-invalid': {
        "domain": 'checkpoint',
        "code": 'checkpoint-known-signature-invalid',
        "human": 'C2SP checkpoint: a known key signature failed; '
                 'whole note rejected',
        "severity": 'high',
        "evidence_kinds_required": ['checkpoint-note'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-log-empty': {
        "domain": 'checkpoint',
        "code": 'checkpoint-log-empty',
        "human": 'C2SP checkpoint: log tree is empty; no checkpoint '
                 'can be emitted',
        "severity": 'medium',
        "evidence_kinds_required": ['checkpoint-note'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-log-incomplete': {
        "domain": 'checkpoints',
        "code": 'checkpoint-log-incomplete',
        "human": 'audit checkpoints: the log is truncated against the checkpoint (fewer entries than committed)',
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
    'checkpoint-malformed': {
        "domain": 'checkpoints',
        "code": 'checkpoint-malformed',
        "human": 'audit checkpoints: the checkpoint or its inputs are structurally malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['checkpoint', 'audit-log'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-no-trusted-signature': {
        "domain": 'checkpoint',
        "code": 'checkpoint-no-trusted-signature',
        "human": 'C2SP checkpoint: no signature from a known key '
                 'verified',
        "severity": 'high',
        "evidence_kinds_required": ['checkpoint-note'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-not-c2sp': {
        "domain": 'checkpoint',
        "code": 'checkpoint-not-c2sp',
        "human": 'C2SP checkpoint: signed note body is not the '
                 'checkpoint format; bespoke notes stay internal',
        "severity": 'high',
        "evidence_kinds_required": ['checkpoint-note'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-note-malformed': {
        "domain": 'checkpoint',
        "code": 'checkpoint-note-malformed',
        "human": 'C2SP checkpoint: bytes are not a valid signed note',
        "severity": 'high',
        "evidence_kinds_required": ['checkpoint-note'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-origin-empty': {
        "domain": 'checkpoint',
        "code": 'checkpoint-origin-empty',
        "human": 'C2SP checkpoint: origin line empty or carries '
                 'spaces/plus',
        "severity": 'medium',
        "evidence_kinds_required": ['checkpoint-note'],
        "reverify_steps": ['recompute'],
    },
    'checkpoint-refused': {
        "domain": 'checkpoints',
        "code": 'checkpoint-refused',
        "human": 'audit checkpoints: generic checkpoint refusal',
        "severity": 'medium',
        "evidence_kinds_required": ['checkpoint', 'audit-log', 'signature'],
        "reverify_steps": ['recompute', 'verify-signature'],
    },
    'checkpoint-root-malformed': {
        "domain": 'checkpoint',
        "code": 'checkpoint-root-malformed',
        "human": 'C2SP checkpoint: root hash is not base64 of 32 bytes',
        "severity": 'medium',
        "evidence_kinds_required": ['checkpoint-note'],
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
    'checkpoint-size-malformed': {
        "domain": 'checkpoint',
        "code": 'checkpoint-size-malformed',
        "human": 'C2SP checkpoint: tree size is not ASCII decimal '
                 'without leading zeros',
        "severity": 'medium',
        "evidence_kinds_required": ['checkpoint-note'],
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
    'claim-invalid-grant': {
        "domain": 'claim',
        "code": 'claim-invalid-grant',
        "human": 'claim-at-dispatch: the grant seal does not recompute, '
                 'or the claim binds another payload digest; tampered or '
                 'foreign grants claim nothing',
        "severity": 'high',
        "evidence_kinds_required": ['grant-record'],
        "reverify_steps": ['recompute'],
    },
    'claim-lease-expired': {
        "domain": 'claim',
        "code": 'claim-lease-expired',
        "human": 'claim-at-dispatch: the claim lease elapsed on the '
                 'monotonic clock before presentation; a slow upstream '
                 'cannot outlive the permission',
        "severity": 'medium',
        "evidence_kinds_required": ['grant-record'],
        "reverify_steps": ['recompute'],
    },
    'claim-malformed': {
        "domain": 'claim',
        "code": 'claim-malformed',
        "human": 'claim-at-dispatch: the grant, claim, or an argument is '
                 'the wrong shape; refusing instead of guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['grant-record'],
        "reverify_steps": ['recompute'],
    },
    'claim-not-presented': {
        "domain": 'claim',
        "code": 'claim-not-presented',
        "human": 'claim-at-dispatch: dispatch attempted without a claim '
                 'presented at the authority; a locally verified grant '
                 'alone authorizes nothing',
        "severity": 'high',
        "evidence_kinds_required": ['grant-record'],
        "reverify_steps": ['recompute'],
    },
    'claim-not-releasable': {
        "domain": 'claim',
        "code": 'claim-not-releasable',
        "human": 'claim-at-dispatch: a second claim against an '
                 'already-consumed grant; consumed grants are never '
                 'released, never retried',
        "severity": 'high',
        "evidence_kinds_required": ['grant-record'],
        "reverify_steps": ['recompute'],
    },
    'claim-replay': {
        "domain": 'claim',
        "code": 'claim-replay',
        "human": 'claim-at-dispatch: the same claim presented twice; one '
                 'claim, one dispatch attempt',
        "severity": 'high',
        "evidence_kinds_required": ['grant-record'],
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
    'combine-default-deny': {
        "domain": 'policy-combine',
        "code": 'combine-default-deny',
        "human": 'policy-set combiner: no policy in the set permitted '
                 'the request; denied fail-closed (default deny)',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'combine-forbid-overrides': {
        "domain": 'policy-combine',
        "code": 'combine-forbid-overrides',
        "human": 'policy-set combiner: at least one policy forbade the '
                 'request; the forbid overrides all permits and the '
                 'request is denied',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'combine-misuse': {
        "domain": 'policy-combine',
        "code": 'combine-misuse',
        "human": 'policy-set combiner: the input was not a sequence of '
                 'validated policy decisions; refused fail-closed rather '
                 'than guessing a verdict',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
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
    'compliance-emitter-malformed': {
        "domain": 'compliance-emitter',
        "code": 'compliance-emitter-malformed',
        "human": 'compliance emitter: malformed control source, mapping, or findings index; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'compliance-emitter-unknown-code': {
        "domain": 'compliance-emitter',
        "code": 'compliance-emitter-unknown-code',
        "human": 'compliance emitter: mapping references a decision code not in the live taxonomy; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'compliance-emitter-unknown-finding': {
        "domain": 'compliance-emitter',
        "code": 'compliance-emitter-unknown-finding',
        "human": 'compliance emitter: mapping references a finding id not in the deployment findings index; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'compliance-emitter-unknown-format': {
        "domain": 'compliance-emitter',
        "code": 'compliance-emitter-unknown-format',
        "human": 'compliance emitter: emit requested an unknown format; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'compliance-emitter-unknown-mechanism': {
        "domain": 'compliance-emitter',
        "code": 'compliance-emitter-unknown-mechanism',
        "human": 'compliance emitter: mapping references a mechanism id not in the evidence crosswalk; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'compliance-emitter-unknown-track': {
        "domain": 'compliance-emitter',
        "code": 'compliance-emitter-unknown-track',
        "human": 'compliance emitter: mapping references a posture track outside the closed track vocabulary; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'compliance-emitter-unlinked-claim': {
        "domain": 'compliance-emitter',
        "code": 'compliance-emitter-unlinked-claim',
        "human": 'compliance emitter: control has no evidence mappings; a claim with no evidence link is never emitted',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
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
    'config-authority-claim-refused': {
        "domain": 'config',
        "code": 'config-authority-claim-refused',
        "human": 'agent-trusts-config: agent-observed config claims a privilege with no matching grant in the deployment-pinned authority; config never self-attests into authority; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['config-record', 'authority-source', 'provenance'],
        "reverify_steps": ['authority-check', 'recompute'],
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
    'config-provenance-agent-asserted': {
        "domain": 'config',
        "code": 'config-provenance-agent-asserted',
        "human": 'agent-trusts-config: the config asserts its own provenance trust; provenance is deployment-vouched, never agent-asserted; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['config-record', 'provenance'],
        "reverify_steps": ['provenance-check'],
    },
    'config-provenance-untrusted': {
        "domain": 'config',
        "code": 'config-provenance-untrusted',
        "human": 'agent-trusts-config: the config carries privilege claims with no provenance block; provenance absence is not trust; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['config-record', 'provenance'],
        "reverify_steps": ['provenance-check'],
    },
    'config-record-malformed': {
        "domain": 'config',
        "code": 'config-record-malformed',
        "human": 'agent-trusts-config: the config record or authority source failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['config-record'],
        "reverify_steps": ['recompute'],
    },
    'config-rewritten-privilege': {
        "domain": 'config',
        "code": 'config-rewritten-privilege',
        "human": 'agent-trusts-config: the config was rewritten mid-run adding privileges; the rewrite is audit-logged and the privileged action fails closed',
        "severity": 'medium',
        "evidence_kinds_required": ['config-record', 'audit-journal', 'provenance'],
        "reverify_steps": ['recompute', 'authority-check'],
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
    'control-profile-check-passed': {
        "domain": 'control-profile',
        "code": 'control-profile-check-passed',
        "human": 'control profile: a control check passed; result marker so clean profiles emit linked artifacts',
        "severity": 'low',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['rerun-profile-check', 'recompute'],
    },
    'control-profile-duplicate-control-id': {
        "domain": 'control-profile',
        "code": 'control-profile-duplicate-control-id',
        "human": 'control profile: duplicate control id; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['recompute'],
    },
    'control-profile-empty': {
        "domain": 'control-profile',
        "code": 'control-profile-empty',
        "human": 'control profile: profile has no controls; a vacuous profile must never pass; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['recompute'],
    },
    'control-profile-evidence-malformed': {
        "domain": 'control-profile',
        "code": 'control-profile-evidence-malformed',
        "human": 'control profile: the evidence snapshot under evaluation is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'control-profile-gate-failed': {
        "domain": 'control-profile',
        "code": 'control-profile-gate-failed',
        "human": 'control profile: the evidence-quality gate refused emission; an expectation failed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'control-profile-invalid-impact': {
        "domain": 'control-profile',
        "code": 'control-profile-invalid-impact',
        "human": 'control profile: control impact is not a number in [0.0, 1.0]; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['recompute'],
    },
    'control-profile-malformed': {
        "domain": 'control-profile',
        "code": 'control-profile-malformed',
        "human": 'control profile: the profile or control shape is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['recompute'],
    },
    'control-profile-non-callable-check': {
        "domain": 'control-profile',
        "code": 'control-profile-non-callable-check',
        "human": 'control profile: control check is not a runtime callable (serialized/call-by-name checks refused; no eval of stored strings)',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['recompute'],
    },
    'control-profile-unknown-key': {
        "domain": 'control-profile',
        "code": 'control-profile-unknown-key',
        "human": 'control profile: unknown profile/control key; a typo must never silently change what gets checked; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['recompute'],
    },
    'coord-lease-denied': {
        "domain": 'coord-lease',
        "code": 'coord-lease-denied',
        "human": 'coord-lease: acquire refused -- an unexpired lease '
                 'already covers the scope; authority is leased, never '
                 'held; the current holder and fencing token are named '
                 'in the refusal -- refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'coord-lease-expired': {
        "domain": 'coord-lease',
        "code": 'coord-lease-expired',
        "human": 'coord-lease: the lease expired -- every grant carries '
                 'an expiry and expired authority is unusable at every '
                 'seam (acquire/renew/write/verify); re-acquire for a '
                 'new generation with a higher fencing token -- refused '
                 'fail-closed (pre-decay: before any state change)',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'coord-lease-fencing': {
        "domain": 'coord-lease',
        "code": 'coord-lease-fencing',
        "human": 'coord-lease: stale fencing token refused -- the token '
                 'presented is not the current token for the scope; '
                 'zombie writes from a superseded generation die here, '
                 'as do token replays from older generations -- refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'coord-lease-invalid': {
        "domain": 'coord-lease',
        "code": 'coord-lease-invalid',
        "human": 'coord-lease: malformed lease material or call -- bad '
                 'scope/holder grammar, non-positive or unbounded ttl, '
                 'bad authority key, unsigned or tampered lease, '
                 'non-circular-JSON structure; every refusal carries a '
                 'coded decision, never a bare traceback -- refused '
                 'fail-closed at the seam',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'coord-lease-manager-mismatch': {
        "domain": 'coord-lease',
        "code": 'coord-lease-manager-mismatch',
        "human": 'coord-lease: the lease manager presented is not the '
                 'manager bound to this transaction -- the suspend-time '
                 'holdership proof and the resume-time liveness check '
                 'must consult the coordinator-bound oracle; a '
                 'substituted (e.g. rubber-stamp) manager cannot attest '
                 'liveness -- refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'coord-state-bound': {
        "domain": 'coord-state',
        "code": 'coord-state-bound',
        "human": 'coord-state: DAG bound exceeded -- more than 1024 '
                 'changes, payload over 4096 bytes, change depth over '
                 '256, too many parents, or an oversized string value; '
                 'refused fail-closed at ingest -- the DAG cannot grow '
                 'without limit',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'coord-state-forgery': {
        "domain": 'coord-state',
        "code": 'coord-state-forgery',
        "human": 'coord-state: change signature does not verify under '
                 'the claimed author key -- a fork with a forged '
                 'signature is refused, never merged',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'coord-state-invalid': {
        "domain": 'coord-state',
        "code": 'coord-state-invalid',
        "human": 'coord-state: malformed change or call -- bad actor '
                 'id/key grammar, non-positive or gapped seq, unsigned '
                 'or tampered change, unknown author key, or circular '
                 'structure; every refusal carries a coded decision, '
                 'never a bare traceback -- refused fail-closed at the '
                 'seam',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'coord-state-overwrite': {
        "domain": 'coord-state',
        "code": 'coord-state-overwrite',
        "human": 'coord-state: seq slot already holds a different signed '
                 'change -- overwriting a signed change is refused; '
                 'shared state merges, never overwrites',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
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
    'corrob-receipt-failed': {
        "domain": 'corroboration',
        "code": 'corrob-receipt-failed',
        "human": 'human-corroboration receipt: emission failed with an '
                 'unexpected (non-receipt) error; the decision stands but '
                 'no receipt was minted; failing closed and loud',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'corrob-receipt-malformed': {
        "domain": 'corroboration',
        "code": 'corrob-receipt-malformed',
        "human": 'human-corroboration receipt: the statement, envelope, '
                 'or VC is malformed (missing fields, bad digests, bad '
                 'did:key); refusing closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'corrob-receipt-not-approved': {
        "domain": 'corroboration',
        "code": 'corrob-receipt-not-approved',
        "human": 'human-corroboration receipt: refusing to mint a '
                 'corroboration receipt for a decision that was not '
                 'approved',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'corrob-receipt-predicate-mismatch': {
        "domain": 'corroboration',
        "code": 'corrob-receipt-predicate-mismatch',
        "human": 'human-corroboration receipt: the statement predicateType '
                 'is not the human-corroboration predicate; refusing closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'corrob-receipt-self-corroboration': {
        "domain": 'corroboration',
        "code": 'corrob-receipt-self-corroboration',
        "human": 'human-corroboration receipt: the reviewer is the '
                 'requesting agent; a principal cannot corroborate its '
                 'own request; refusing closed',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'corrob-receipt-signature-invalid': {
        "domain": 'corroboration',
        "code": 'corrob-receipt-signature-invalid',
        "human": 'human-corroboration receipt: the DSSE envelope signature '
                 'does not verify under the reviewer key; refusing closed',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'corrob-receipt-subject-mismatch': {
        "domain": 'corroboration',
        "code": 'corrob-receipt-subject-mismatch',
        "human": 'human-corroboration receipt: the statement subject digest '
                 'does not match the decision being corroborated; a valid '
                 'signature alone is not enough; refusing closed',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'corrob-receipt-unbound-issuer': {
        "domain": 'corroboration',
        "code": 'corrob-receipt-unbound-issuer',
        "human": 'human-corroboration receipt: the signing/verifying key '
                 'is not the key the receipt names as reviewer (did:key '
                 'binding failed); refusing closed',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'corrob-vc-proof-invalid': {
        "domain": 'corroboration',
        "code": 'corrob-vc-proof-invalid',
        "human": 'human-corroboration receipt: the W3C VC DataIntegrityProof '
                 '(eddsa-jcs-2022) does not verify, or the credential is '
                 'malformed or not issuer-bound; refusing closed',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'corroboration-key-inequality': {
        "domain": 'corroboration',
        "code": 'corroboration-key-inequality',
        "human": 'independent corroboration: two items presented as '
                 'distinct sources share one key_id; not key-independent',
        "severity": 'high',
        "evidence_kinds_required": ['evidence-envelope'],
        "reverify_steps": ['recompute'],
    },
    'corroboration-malformed': {
        "domain": 'corroboration',
        "code": 'corroboration-malformed',
        "human": 'independent corroboration: the envelope or an evidence '
                 'item is the wrong shape; refusing instead of guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence-envelope'],
        "reverify_steps": ['recompute'],
    },
    'corroboration-signature-invalid': {
        "domain": 'corroboration',
        "code": 'corroboration-signature-invalid',
        "human": 'independent corroboration: the Ed25519 signature fails '
                 'under the policy-held key; the item was edited after '
                 'signing',
        "severity": 'high',
        "evidence_kinds_required": ['evidence-envelope'],
        "reverify_steps": ['recompute'],
    },
    'corroboration-unattested': {
        "domain": 'corroboration',
        "code": 'corroboration-unattested',
        "human": 'independent corroboration: the item provenance resolves '
                 'to the gated runtime itself; self-attested evidence is '
                 'never corroboration',
        "severity": 'high',
        "evidence_kinds_required": ['evidence-envelope'],
        "reverify_steps": ['recompute'],
    },
    'corroboration-uncorroborated': {
        "domain": 'corroboration',
        "code": 'corroboration-uncorroborated',
        "human": 'independent corroboration: a required dimension has '
                 'fewer than two key-inequal corroborating sources; a '
                 'lone source cannot corroborate itself',
        "severity": 'high',
        "evidence_kinds_required": ['evidence-envelope'],
        "reverify_steps": ['recompute'],
    },
    'corroboration-untrusted-source': {
        "domain": 'corroboration',
        "code": 'corroboration-untrusted-source',
        "human": 'independent corroboration: the item key_id is not in '
                 'the consumer\u2019s own trust policy; the consumer '
                 'cannot corroborate against key material it does not '
                 'independently hold',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence-envelope'],
        "reverify_steps": ['recompute'],
    },
    'coverage-logbook-chain-broken': {
        "domain": 'coverage',
        "code": 'coverage-logbook-chain-broken',
        "human": 'coverage ledger: a score-logbook entry failed chain '
                 'verification (rewritten history, dropped entry, or '
                 'broken linkage); the logbook is untrusted until '
                 're-initialized',
        "severity": 'high',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'coverage-refused-backdated-entry': {
        "domain": 'coverage',
        "code": 'coverage-refused-backdated-entry',
        "human": 'coverage ledger: a score entry dated earlier than the '
                 'previous logbook entry was refused; the logbook is '
                 'timestamp-monotonic and append-only',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'coverage-refused-future-dated-entry': {
        "domain": 'coverage',
        "code": 'coverage-refused-future-dated-entry',
        "human": 'coverage ledger: a score entry dated more than the '
                 'clock-skew tolerance in the future was refused; a '
                 'far-future stamp would brick the logbook, since every '
                 'later honest append would refuse as backdated '
                 'relative to it',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'coverage-refused-monitor-implies-prevention': {
        "domain": 'coverage',
        "code": 'coverage-refused-monitor-implies-prevention',
        "human": 'coverage ledger: monitor-mode coverage was presented as '
                 'prevention; refused -- monitor-mode verdicts are evidence '
                 'of visibility, never of prevention',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'coverage-refused-no-denominator': {
        "domain": 'coverage',
        "code": 'coverage-refused-no-denominator',
        "human": 'coverage ledger: a coverage percentage was requested '
                 'without a denominator; refused -- a percentage without '
                 'its denominator is not emitted',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'coverage-refused-no-proof-method': {
        "domain": 'coverage',
        "code": 'coverage-refused-no-proof-method',
        "human": 'coverage ledger: a coverage percentage or score was '
                 'requested without a named proof method; refused -- '
                 'coverage without a proof method is not emitted',
        "severity": 'medium',
        "evidence_kinds_required": ['audit-record'],
        "reverify_steps": ['recompute'],
    },
    'credential-strict-config-invalid': {
        "domain": 'credential',
        "code": 'credential-strict-config-invalid',
        "human": 'strict credential misconfigured: strict=True without '
                 'a non-empty strict_injector operator label, or '
                 'strict_injector without strict=True; nothing is '
                 'registered',
        "severity": 'high',
        "evidence_kinds_required": ['credential', 'binding', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'credential-strict-host-denied': {
        "domain": 'credential',
        "code": 'credential-strict-host-denied',
        "human": 'supervisor egress injection refused: the request '
                 'destination is not in the credential\u2019s '
                 'authorized host set',
        "severity": 'high',
        "evidence_kinds_required": ['credential', 'binding', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'credential-strict-refused': {
        "domain": 'credential',
        "code": 'credential-strict-refused',
        "human": 'agent-side resolution of a never-materialize (strict) '
                 'credential is refused: the value may only be injected '
                 'in the supervisor-owned egress path',
        "severity": 'high',
        "evidence_kinds_required": ['credential', 'binding', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'credential-strict-unapproved': {
        "domain": 'credential',
        "code": 'credential-strict-unapproved',
        "human": 'supervisor egress injection refused: the request has '
                 'no valid approval for the tool and destination',
        "severity": 'high',
        "evidence_kinds_required": ['credential', 'binding', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'cross_run_denied': {
        "domain": 'approval',
        "code": 'cross_run_denied',
        "human": 'approval and delegation: the cross-run operation was denied',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'custody-shamir-bad-params': {
        "domain": 'custody',
        "code": 'custody-shamir-bad-params',
        "human": 'shamir custody: ceremony parameters invalid (t/n range, '
                 't=1 refused, secret below the 128-bit floor, bad ceremony id)',
        "severity": 'medium',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'custody-shamir-ceremony-mismatch': {
        "domain": 'custody',
        "code": 'custody-shamir-ceremony-mismatch',
        "human": 'shamir custody: reconstruction set spans more than one '
                 'ceremony; shards from different ceremonies never mix',
        "severity": 'high',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'custody-shamir-commitment-mismatch': {
        "domain": 'custody',
        "code": 'custody-shamir-commitment-mismatch',
        "human": 'shamir custody: reconstructed secret does not match the '
                 'shard commitment (corrupt shard or wrong-secret mix); '
                 'no secret returned',
        "severity": 'high',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'custody-shamir-distribute-refused': {
        "domain": 'custody',
        "code": 'custody-shamir-distribute-refused',
        "human": 'shamir custody: distribution refused (duplicate custodian '
                 'or path, missing parent dir, or existing shard file); '
                 'nothing was written',
        "severity": 'medium',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'custody-shamir-duplicate-share': {
        "domain": 'custody',
        "code": 'custody-shamir-duplicate-share',
        "human": 'shamir custody: reconstruction set contains a duplicate '
                 'share index; interpolation would be unsound',
        "severity": 'high',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'custody-shamir-insufficient-shares': {
        "domain": 'custody',
        "code": 'custody-shamir-insufficient-shares',
        "human": 'shamir custody: fewer than t shards supplied; the module '
                 'never outputs a guess below threshold',
        "severity": 'medium',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'custody-shamir-share-malformed': {
        "domain": 'custody',
        "code": 'custody-shamir-share-malformed',
        "human": 'shamir custody: shard fails shape validation (missing '
                 'keys, bad index, length mismatch, bad encoding)',
        "severity": 'medium',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'custody-shamir-transcript-corrupt': {
        "domain": 'custody',
        "code": 'custody-shamir-transcript-corrupt',
        "human": 'shamir custody: ceremony transcript fails hash-chain '
                 'replay; no event is appended to a broken chain',
        "severity": 'high',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'deadctrl-subject-mutated': {
        "domain": 'deadctrl',
        "code": 'deadctrl-subject-mutated',
        "human": 'dead-controls CI gate: the test subject changed under the '
                 'gate (TOCTOU) -- a file was modified, added, or removed '
                 'between the pre-run subject pin and the post-run '
                 'verification; the gate analyzed a different tree than it '
                 'pinned; refused fail-closed, never report on a swapped '
                 'subject',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
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
    'decision-effect-decision-drift': {
        "domain": 'decision_effect',
        "code": 'decision-effect-decision-drift',
        "human": 'decision effect: the decision receipt claim drifted from the digest recomputed from its verdict bytes',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'digest'],
        "reverify_steps": ['reseal-decision', 'recompute-decision-digest'],
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
    'decision-effect-effect-drift': {
        "domain": 'decision_effect',
        "code": 'decision-effect-effect-drift',
        "human": 'decision effect: the execution receipt effect drifted from the re-classified, re-sealed effect',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'observation', 'digest'],
        "reverify_steps": ['replay-effect-classify', 'reseal-effect'],
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
    'decision-labels-invalid': {
        "domain": 'decision',
        "code": 'decision-labels-invalid',
        "human": 'decision packet: the value failed semantic validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['decision-packet', 'signature'],
        "reverify_steps": ['verify-packet-signature'],
    },
    'decision-log-equivocation': {
        "domain": 'decision-log',
        "code": 'decision-log-equivocation',
        "human": 'decision log: two logged combined decisions share the '
                 'same request digest and policy-revision set but carry '
                 'different effects; the equivocation is proven by '
                 'inclusion proofs against the log root',
        "severity": 'high',
        "evidence_kinds_required": ['log-record'],
        "reverify_steps": ['recompute'],
    },
    'decision-log-malformed': {
        "domain": 'decision-log',
        "code": 'decision-log-malformed',
        "human": 'decision log: a leaf, request digest, STH, or proof was '
                 'malformed; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'decision-log-proof-invalid': {
        "domain": 'decision-log',
        "code": 'decision-log-proof-invalid',
        "human": 'decision log: an inclusion or consistency proof did not '
                 'verify against the claimed root; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'decision-log-request-mismatch': {
        "domain": 'decision-log',
        "code": 'decision-log-request-mismatch',
        "human": 'decision log: an append carried a different request '
                 'digest than the bound epoch without an explicit '
                 'new_epoch() separation; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'decision-trace-forgery': {
        "domain": 'decision-trace',
        "code": 'decision-trace-forgery',
        "human": 'decision trace: the trace signature does not verify '
                 'against the trace-signing key; the trace is forged or '
                 'was signed by a different key; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'decision-trace-invalid': {
        "domain": 'decision-trace',
        "code": 'decision-trace-invalid',
        "human": 'decision trace: the trace envelope or body is malformed '
                 '(missing fields, bad hex, unknown format); refused '
                 'instead of guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'decision-trace-replay-mismatch': {
        "domain": 'decision-trace',
        "code": 'decision-trace-replay-mismatch',
        "human": 'decision trace: replay divergence -- the ordered edges '
                 'fold to a different verdict than the recorded final '
                 'decision, or the trace was evaluated against a different '
                 'policy version/snapshot than the verifier trusts; '
                 'recomputed evidence disagrees with the claim',
        "severity": 'critical',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'decodetrust-binding-mismatch': {
        "domain": 'evcert',
        "code": 'decodetrust-binding-mismatch',
        "human": 'decode trust: sealed evidence failed its binding check '
                 '(wire digest differs or scope mismatches); refusing to '
                 'decode into trusted typed values',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'decodetrust-malformed-evidence': {
        "domain": 'evcert',
        "code": 'decodetrust-malformed-evidence',
        "human": 'decode trust: the sealed evidence envelope is malformed; '
                 'refusing instead of guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'decodetrust-no-evidence': {
        "domain": 'evcert',
        "code": 'decodetrust-no-evidence',
        "human": 'decode trust: no sealed evidence presented where trusted '
                 'decode requires it; refusing rather than decoding raw',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'decommission_refused': {
        "domain": 'recovery',
        "code": 'decommission_refused',
        "human": 'recovery: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['journal', 'digest'],
        "reverify_steps": ['replay-chain'],
    },
    'decoy-grant-not-issuable': {
        "domain": 'tool_grant',
        "code": 'decoy-grant-not-issuable',
        "human": 'decoy grants: the issuer refused to mint a grant covering '
                 'a registered decoy (honeypot) tool identifier; decoys are '
                 'never legitimized',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'refusal-record'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'decoy-grant-tripped': {
        "domain": 'tool_grant',
        "code": 'decoy-grant-tripped',
        "human": 'decoy grants: a registered decoy (honeypot) tool was '
                 'invoked at the enforcement seam; high-confidence '
                 'prompt-injection evidence, denied fail-closed with an '
                 'injection-evidence event for the audit log',
        "severity": 'critical',
        "evidence_kinds_required": ['grant', 'proof', 'refusal-record'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'delegatee_mismatch': {
        "domain": 'approval',
        "code": 'delegatee_mismatch',
        "human": 'approval and delegation: the delegatee does not match the grant',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'delegation-action-refused': {
        "domain": 'delegation',
        "code": 'delegation-action-refused',
        "human": 'signed delegation chain: the presented action is not '
                 'covered by the leaf delegation capabilities; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-approval-chain-mismatch': {
        "domain": 'delegation',
        "code": 'delegation-approval-chain-mismatch',
        "human": 'delegated approval: the presented delegation chain (or '
                 'its root delegator) does not match the chain digest bound '
                 'into the approval request; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-approval-right-mismatch': {
        "domain": 'delegation',
        "code": 'delegation-approval-right-mismatch',
        "human": 'delegated approval: the presented delegation right does '
                 'not match the right digest bound into the approval '
                 'request at issue time; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-attenuation-inverted': {
        "domain": 'delegation',
        "code": 'delegation-attenuation-inverted',
        "human": 'signed delegation chain: a hop grants capabilities '
                 'not covered by its parent (attenuation inversion); '
                 'widening refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-attestation-malformed': {
        "domain": 'delegation-freshness',
        "code": 'delegation-attestation-malformed',
        "human": 'delegation freshness: the attestation record is not the '
                 'expected shape (non-string fields, non-sequence or '
                 'non-string capabilities, unparseable or timezone-naive '
                 'timestamps); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['capability-attestation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-ceremony-mismatch': {
        "domain": 'delegation',
        "code": 'delegation-ceremony-mismatch',
        "human": 'signed delegation chain: a hop is bound to a different '
                 'ceremony than the expected challenge nonce (or carries '
                 'no ceremony binding while one is expected); cross-'
                 'ceremony replay refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-chain-broken': {
        "domain": 'delegation-freshness',
        "code": 'delegation-chain-broken',
        "human": 'delegation freshness: the delegation chain is empty, not '
                 'a sequence, or a hop issuer does not equal its parent '
                 "subject; refused fail-closed",
        "severity": 'high',
        "evidence_kinds_required": ['capability-attestation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-containment-violated': {
        "domain": 'containment',
        "code": 'delegation-containment-violated',
        "human": 'delegation containment: a child grant bound exceeds the '
                 "parent's bound on a named key (wei §13 Contains)",
        "severity": 'high',
        "evidence_kinds_required": ['permit', 'parent-permit-bounds'],
        "reverify_steps": ['recompute'],
    },
    'delegation-custody-splice': {
        "domain": 'delegation',
        "code": 'delegation-custody-splice',
        "human": 'signed delegation chain: hop i>0 names an issuer '
                 'that is not the presented parent\'s audience; a '
                 'grafted hop from an unrelated keyholder refuses '
                 'fail-closed even when digest linkage and '
                 'attenuation are sound',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
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
    'delegation-depth-exceeded': {
        "domain": 'delegation',
        "code": 'delegation-depth-exceeded',
        "human": 'signed delegation receipt: delegating at or beyond the '
                 'parent receipt\'s max_depth; the chain cannot grow deeper; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-ephemeral-grant-refused': {
        "domain": 'delegation',
        "code": 'delegation-ephemeral-grant-refused',
        "human": 'ephemeral grant (contextual tuple): no tuple authorized '
                 'the invocation, a tuple condition failed at check time, '
                 'a single-use lease was presented without its contextual '
                 'tuple, or the lease was already spent; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'grant-decision'],
        "reverify_steps": ['recompute'],
    },
    'delegation-escrow-violated': {
        "domain": 'delegation',
        "code": 'delegation-escrow-violated',
        "human": 'delegation escrow: commit attempted on a non-open escrow, '
                 'a declared step presented no verifiable receipt chain, a '
                 'step\'s leaf lacks the escrow.commit right, or a step\'s '
                 'leaf designates a different effect than declared; '
                 'offer-safety violated, refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature', 'escrow'],
        "reverify_steps": ['recompute'],
    },
    'delegation-expired': {
        "domain": 'delegation',
        "code": 'delegation-expired',
        "human": 'signed delegation chain: a delegation in the chain is '
                 'outside its not_before/not_after window at '
                 'verification time; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-freshness-expired': {
        "domain": 'delegation-freshness',
        "code": 'delegation-freshness-expired',
        "human": 'delegation freshness: the attestation TTL has elapsed at '
                 'check time (inclusive of the exact expiry instant); '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['capability-attestation',
                                    'freshness-timestamp'],
        "reverify_steps": ['recompute'],
    },
    'delegation-identity-false-hardware-claim': {
        "domain": 'delegation-identity',
        "code": 'delegation-identity-false-hardware-claim',
        "human": 'delegation identity: claim_hardware set without quote '
                 'bytes -- a hardware attestation claim with no real quote '
                 'path is refused; honest naming enforced in code',
        "severity": 'high',
        "evidence_kinds_required": ['attestation', 'identity'],
        "reverify_steps": ['recompute'],
    },
    'delegation-identity-invalid': {
        "domain": 'delegation-identity',
        "code": 'delegation-identity-invalid',
        "human": 'delegation identity: malformed identity evidence, DID '
                 'document, ceremony transcript, receipt, or chain link; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['identity', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'delegation-identity-unauthorized-key': {
        "domain": 'delegation-identity',
        "code": 'delegation-identity-unauthorized-key',
        "human": 'delegation identity: the receipt signer is not authorized '
                 'for delegation by the identity evidence (not in the DID '
                 "document's delegation_keys, or transcript not about the "
                 'signer); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['identity', 'signature', 'delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-invalid': {
        "domain": 'delegation',
        "code": 'delegation-invalid',
        "human": 'delegation receipt: malformed shape (unknown schema, bad '
                 'ids, non-hex digests, rights outside the closed '
                 'vocabulary, or bad constraints); refused fail-closed '
                 'before any authority is considered',
        "severity": 'high',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-invocation-audience-mismatch': {
        "domain": 'delegation',
        "code": 'delegation-invocation-audience-mismatch',
        "human": 'signed delegation invocation: the proven key is not the '
                 'leaf delegation\'s audience; invocation by a non-holder '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-invocation-not-proven': {
        "domain": 'delegation',
        "code": 'delegation-invocation-not-proven',
        "human": 'signed delegation invocation: no proof of possession of '
                 'the leaf audience key was presented; possession is never '
                 'assumed; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-lineage-overflow': {
        "domain": 'delegation',
        "code": 'delegation-lineage-overflow',
        "human": 'signed delegation chain: the verifier retirement '
                 'lineage is full; a new succession was refused '
                 'fail-closed rather than evicting lineage',
        "severity": 'medium',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-malformed': {
        "domain": 'delegation',
        "code": 'delegation-malformed',
        "human": 'signed delegation chain: a delegation, chain, '
                 'capability, key, or time value is not the expected '
                 'shape; refused before verification',
        "severity": 'medium',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-monotonicity-violated': {
        "domain": 'delegation-freshness',
        "code": 'delegation-monotonicity-violated',
        "human": 'delegation freshness: a hop delegates a capability entry '
                 'not covered by the parent set (exact entry, "*", or '
                 '"<prefix>:*"); widening refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['capability-attestation',
                                    'parent-attestation'],
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
    'delegation-orphaned-branch': {
        "domain": 'delegation',
        "code": 'delegation-orphaned-branch',
        "human": 'signed delegation chain: a presented chain routes '
                 'through a retired hop into a child that is not the '
                 'registered successor -- a forked branch minted under '
                 'a retired leaf; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-parent-mismatch': {
        "domain": 'delegation',
        "code": 'delegation-parent-mismatch',
        "human": 'signed delegation chain: a hop parent_digest does not '
                 'equal the digest of the presented parent; the chain '
                 'is broken or spliced; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-pop-signature-invalid': {
        "domain": 'delegation',
        "code": 'delegation-pop-signature-invalid',
        "human": 'signed delegation invocation: the proof-of-possession '
                 'signature is malformed or fails to verify against the '
                 'invoker key; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-replay': {
        "domain": 'delegation',
        "code": 'delegation-replay',
        "human": 'signed delegation chain: the same (chain, action) '
                 'invocation was already verified; the second '
                 'presentation is a replay; refused',
        "severity": 'high',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-retired-reuse': {
        "domain": 'delegation',
        "code": 'delegation-retired-reuse',
        "human": 'signed delegation chain: a retired (superseded) '
                 'delegation was presented after its succession; reuse '
                 'of a retired credential is a revocation event, not '
                 'an authentication failure; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-revocation-invalid': {
        "domain": 'delegation',
        "code": 'delegation-revocation-invalid',
        "human": 'delegation revocation: a revocation record, revocation '
                 'list, or delegation chain failed structural validation '
                 '(bad shape, digest mismatch, broken linkage, backwards '
                 'revoked_at); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'revocation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-revocation-list-full': {
        "domain": 'delegation',
        "code": 'delegation-revocation-list-full',
        "human": 'delegation revocation: the per-delegator revocation '
                 'list is at its bound (4096 entries); further '
                 'revocations refuse loud rather than silently drop; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['delegation', 'revocation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-revoked': {
        "domain": 'delegation',
        "code": 'delegation-revoked',
        "human": 'delegation revocation: a presented receipt (or one of '
                 'its ancestors) was revoked by its delegator; '
                 'revocation binds all downstream copies and beats '
                 'expiry; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'revocation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-root-exceeds-policy': {
        "domain": 'delegation',
        "code": 'delegation-root-exceeds-policy',
        "human": 'signed delegation chain: a root delegation grants '
                 'capabilities not covered by the trust anchor\'s pinned '
                 'root policy; unbounded root power refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-root-untrusted': {
        "domain": 'delegation',
        "code": 'delegation-root-untrusted',
        "human": 'signed delegation chain: the root issuer is not in '
                 'the deployment-pinned trust anchors; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-signature-invalid': {
        "domain": 'delegation',
        "code": 'delegation-signature-invalid',
        "human": 'signed delegation chain: an Ed25519 delegation '
                 'signature failed to verify; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'delegation-stale-lineage': {
        "domain": 'delegation',
        "code": 'delegation-stale-lineage',
        "human": 'signed delegation chain: a delegation from a '
                 'superseded generation was presented while a newer '
                 'succession exists; stale lineage refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-state-mismatch': {
        "domain": 'delegation-freshness',
        "code": 'delegation-state-mismatch',
        "human": 'delegation freshness: the attestation state_hash does '
                 'not equal the digest of its presented capability set; '
                 'the hop swapped its set or never bound it; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['capability-attestation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-ticket-expired': {
        "domain": 'delegation',
        "code": 'delegation-ticket-expired',
        "human": 'delegation ticket presented or used outside its '
                 'validity window (or its ok-as-delegate declaration '
                 'lapsed); time-boxed authority refuses fail-closed, '
                 'silence never extends it',
        "severity": 'medium',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-ticket-invalid': {
        "domain": 'delegation',
        "code": 'delegation-ticket-invalid',
        "human": 'delegation ticket malformed, bad signature, wrong '
                 'holder, action scope escapes the ticket scope, broken '
                 'parent chain, ticket-key confusion, or a child ticket '
                 'that outlives its parent; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-ticket-not-opted-in': {
        "domain": 'delegation',
        "code": 'delegation-ticket-not-opted-in',
        "human": 'delegation ticket issued to a delegatee with no live, '
                 'signed ok-as-delegate declaration; authority is never '
                 'pushed onto an unwilling principal; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-ticket-type-violated': {
        "domain": 'delegation',
        "code": 'delegation-ticket-type-violated',
        "human": 'delegation ticket type rule broken: re-delegating a '
                 'non-forwardable ticket, presenting outside a '
                 'constrained downstream set, an empty downstream set '
                 'on a constrained ticket, or a delegation that widens '
                 'the parent scope; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-ttl-excessive': {
        "domain": 'delegation-freshness',
        "code": 'delegation-ttl-excessive',
        "human": 'delegation freshness: the attestation TTL exceeds the '
                 'deployment max_ttl cap; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['capability-attestation',
                                    'deployment-policy'],
        "reverify_steps": ['recompute'],
    },
    'delegation-ttl-missing': {
        "domain": 'delegation-freshness',
        "code": 'delegation-ttl-missing',
        "human": 'delegation freshness: the capability attestation carries '
                 'no usable TTL (missing, zero, negative, non-integer, or '
                 'boolean); treated as expired and refused fail-closed, '
                 'never an infinite-life attestation',
        "severity": 'high',
        "evidence_kinds_required": ['capability-attestation'],
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
    'delegation-version-mismatch': {
        "domain": 'delegation',
        "code": 'delegation-version-mismatch',
        "human": 'signed delegation chain: a delegation carried an '
                 'unknown type version; implementations must match '
                 'the exact type string, so it is refused before '
                 'interpretation',
        "severity": 'medium',
        "evidence_kinds_required": ['delegation'],
        "reverify_steps": ['recompute'],
    },
    'delegation-widened': {
        "domain": 'delegation',
        "code": 'delegation-widened',
        "human": 'signed delegation receipt: a downstream receipt claims '
                 'rights wider than its parent\'s rights; delegation '
                 'narrows, never widens; refused fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['delegation', 'signature'],
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
    'denial-anchored-in-denied-transaction': {
        "domain": 'seeded_denial',
        "code": 'denial-anchored-in-denied-transaction',
        "human": 'seeded denials: the denial record anchors inside the '
                 'denied transaction, so a rollback could erase the denial',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'verdict-record', 'digest'],
        "reverify_steps": ['recompute', 'check-anchor'],
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
    'denial-evidence-lost': {
        "domain": 'seeded_denial',
        "code": 'denial-evidence-lost',
        "human": 'seeded denials: the committed denial record is absent from '
                 'the post-rollback log; the denial evidence did not survive',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute', 'check-commit'],
    },
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
    'deny-receipt-malformed': {
        "domain": 'receipts',
        "code": 'deny-receipt-malformed',
        "human": 'signed receipts: the presented receipt record is not well-formed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'deny-receipt-not-authorization': {
        "domain": 'receipts',
        "code": 'deny-receipt-not-authorization',
        "human": 'signed receipts: receipt evidence was used as authority',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
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
    'detector-cycle': {
        "domain": 'detector',
        "code": 'detector-cycle',
        "human": 'declarative detectors: the subscribes graph contains a '
                 'cycle; refused fail-closed, nothing registered',
        "severity": 'medium',
        "evidence_kinds_required": ['detector-definition'],
        "reverify_steps": ['recompute'],
    },
    'detector-deprecated': {
        "domain": 'detector',
        "code": 'detector-deprecated',
        "human": 'declarative detectors: the detector declares a deprecated '
                 'maturity tier; refused fail-closed, nothing registered',
        "severity": 'medium',
        "evidence_kinds_required": ['detector-definition'],
        "reverify_steps": ['recompute'],
    },
    'detector-duplicate-name': {
        "domain": 'detector',
        "code": 'detector-duplicate-name',
        "human": 'declarative detectors: a detector name is already '
                 'registered; refused fail-closed, engine state unchanged',
        "severity": 'medium',
        "evidence_kinds_required": ['detector-definition'],
        "reverify_steps": ['recompute'],
    },
    'detector-exception-malformed': {
        "domain": 'detector',
        "code": 'detector-exception-malformed',
        "human": 'declarative detectors: an alert-discipline exception '
                 '(allowlist) block is malformed (bad name, misaligned '
                 'fields/comps/values, unknown comparator, illegal path); '
                 'refused fail-closed, nothing registered',
        "severity": 'medium',
        "evidence_kinds_required": ['detector-definition'],
        "reverify_steps": ['recompute'],
    },
    'detector-malformed': {
        "domain": 'detector',
        "code": 'detector-malformed',
        "human": 'declarative detectors: the detector definition fails '
                 'structural validation (bad name/version, empty '
                 'predicates, bad produced schema, bad threat metadata, '
                 'dangling subscription); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['detector-definition'],
        "reverify_steps": ['recompute'],
    },
    'detector-unknown-maturity': {
        "domain": 'detector',
        "code": 'detector-unknown-maturity',
        "human": 'declarative detectors: the detector declares a maturity '
                 'tier outside the fixed vocabulary '
                 '(stable/experimental/deprecated); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['detector-definition'],
        "reverify_steps": ['recompute'],
    },
    'detector-unknown-predicate': {
        "domain": 'detector',
        "code": 'detector-unknown-predicate',
        "human": 'declarative detectors: a predicate uses an op outside '
                 'the closed DSL, an illegal field path (dunder traversal, '
                 'bad shape), or a malformed operand; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['detector-definition'],
        "reverify_steps": ['recompute'],
    },
    'detector-unknown-priority': {
        "domain": 'detector',
        "code": 'detector-unknown-priority',
        "human": 'declarative detectors: the detector declares a priority '
                 'outside the fixed alert ladder (emergency/alert/critical/'
                 'error/warning/notice/informational/debug); refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['detector-definition'],
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
    'did-key-binding-invalid': {
        "domain": 'identity',
        "code": 'did-key-binding-invalid',
        "human": 'a signature did not verify against the public key '
                 'resolved from the did:key identifier (forged binding or '
                 'reporter/key mismatch); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'did-key-malformed': {
        "domain": 'identity',
        "code": 'did-key-malformed',
        "human": 'a did:key identifier failed structural validation (bad '
                 'multibase, bad multicodec, wrong payload length); no key '
                 'was derived, refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'did-key-method-unsupported': {
        "domain": 'identity',
        "code": 'did-key-method-unsupported',
        "human": 'an identifier used a DID method other than did:key; only '
                 'the key-derived method is supported, refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
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
    'discipline-inhibitor-malformed': {
        "domain": 'discipline',
        "code": 'discipline-inhibitor-malformed',
        "human": 'approval discipline: a refusal fact presented for '
                 'inhibition is malformed (missing identity fields '
                 'or not a refusal kind); refused fail-closed, the '
                 'prompt proceeds',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'discipline-inhibitor-unverifiable': {
        "domain": 'discipline',
        "code": 'discipline-inhibitor-unverifiable',
        "human": 'approval discipline: a refusal fact carries no '
                 'journal_digest binding, so it is a caller claim '
                 'rather than a digest-bound fact; refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'discipline-prompt-coalesced': {
        "domain": 'discipline',
        "code": 'discipline-prompt-coalesced',
        "human": 'approval discipline: an identical approval request '
                 'is already pending inside the repeat window; the '
                 'prompt is coalesced onto the existing pending '
                 'request and not re-issued (informational)',
        "severity": 'low',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'discipline-prompt-inhibited': {
        "domain": 'discipline',
        "code": 'discipline-prompt-inhibited',
        "human": 'approval discipline: a digest-bound refusal fact '
                 'for the same decision is active, so the redundant '
                 'prompt is inhibited (informational)',
        "severity": 'low',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },
    'discipline-prompt-silenced': {
        "domain": 'discipline',
        "code": 'discipline-prompt-silenced',
        "human": 'approval discipline: an operator-signed, '
                 'time-bounded silence covers this prompt class; '
                 'the re-prompt is suppressed (informational; '
                 'prompts only, never enforcement denials)',
        "severity": 'low',
        "evidence_kinds_required": ['signature', 'record'],
        "reverify_steps": ['recompute'],
    },
    'discipline-request-malformed': {
        "domain": 'discipline',
        "code": 'discipline-request-malformed',
        "human": 'approval discipline: the approval request is '
                 'malformed (missing or mistyped identity fields); '
                 'refused loudly -- a malformed request is never '
                 'coalesced and never reaches the queue',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'discipline-silence-forbidden-class': {
        "domain": 'discipline',
        "code": 'discipline-silence-forbidden-class',
        "human": 'approval discipline: the silence matchers cover a '
                 'high or critical severity class; refused at '
                 'creation -- silences can never cover high-severity '
                 'approval classes',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'discipline-silence-malformed': {
        "domain": 'discipline',
        "code": 'discipline-silence-malformed',
        "human": 'approval discipline: the silence is malformed '
                 '(bad shape, invalid operator signature, missing '
                 'or expired not_after, window beyond the maximum); '
                 'refused fail-closed, prompts proceed',
        "severity": 'medium',
        "evidence_kinds_required": ['signature'],
        "reverify_steps": ['recompute'],
    },
    'discipline-silence-unjournaled': {
        "domain": 'discipline',
        "code": 'discipline-silence-unjournaled',
        "human": 'approval discipline: no journal is available for '
                 'the silence record; refused -- a silence nobody '
                 'records is a governance hole',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'discovery-definition-drift': {
        "domain": 'discovery-scan',
        "code": 'discovery-definition-drift',
        "human": 'a discovered tool definition drifted from its hash pin '
                 '(rug pull / unauthorized change); the tool is held out '
                 'of the grant graph fail-closed until a governed re-pin',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'discovery-definition-unregistered': {
        "domain": 'discovery-scan',
        "code": 'discovery-definition-unregistered',
        "human": 'a discovered tool has no definition pin (first '
                 'sighting); the discovery plane is untrusted, so the '
                 'tool is held fail-closed until first pinned',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'discovery-emit-failed': {
        "domain": 'discovery-scan',
        "code": 'discovery-emit-failed',
        "human": 'the audit sink refused a discovery drift/re-pin event '
                 'after a bounded retry; the event is in the in-memory '
                 'drift list only -- the registry fails LOUD rather than '
                 'letting drift go unaudited (F313)',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'discovery-identity-mismatch': {
        "domain": 'mcp-discovery',
        "code": 'discovery-identity-mismatch',
        "human": 'a discovery result claims a pinned server name with an '
                 'identity that does not match the deployment pin; '
                 'refused fail-closed as an impersonation/forgery signal',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'gate-record'],
        "reverify_steps": ['recompute'],
    },
    'discovery-result-malformed': {
        "domain": 'mcp-discovery',
        "code": 'discovery-result-malformed',
        "human": 'a discovery result or pin set is malformed; refused '
                 'fail-closed, never silently admitted',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'discovery-scope-unknown': {
        "domain": 'discovery-scan',
        "code": 'discovery-scope-unknown',
        "human": 'a discovery observation named a scope outside the '
                 'closed system/user/project/extension vocabulary; '
                 'refused fail-closed, never silently mapped',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'discovery-unpinned': {
        "domain": 'mcp-discovery',
        "code": 'discovery-unpinned',
        "human": 'a discovery result names a server with no deployment '
                 'pin; the discovery plane is untrusted, so explicit '
                 'pinning is required; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'gate-record'],
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
    'drift-baseline-updated': {
        "domain": 'drift',
        "code": 'drift-baseline-updated',
        "human": 'drift report: the per-request decision baseline was '
                 '(re)recorded; the event anchors the drift chain',
        "severity": 'low',
        "evidence_kinds_required": ['chain'],
        "reverify_steps": ['recompute'],
    },
    'drift-detected': {
        "domain": 'drift',
        "code": 'drift-detected',
        "human": 'drift report: a rescan found an item the baseline '
                 'allowed that the current policy set denies; the '
                 'event carries then/now decisions and the gate digest',
        "severity": 'medium',
        "evidence_kinds_required": ['chain'],
        "reverify_steps": ['recompute'],
    },
    'drift-log-corrupt': {
        "domain": 'drift',
        "code": 'drift-log-corrupt',
        "human": 'drift report: the drift-event chain failed '
                 'verification (edit, reorder, or truncation); refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['chain'],
        "reverify_steps": ['recompute'],
    },
    'drift-malformed': {
        "domain": 'drift',
        "code": 'drift-malformed',
        "human": 'drift report: the drift event, scanner, or reporter '
                 'argument is the wrong shape (non-dict event, scanner '
                 'without scan(), bad digest or request id); refusing '
                 'instead of guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['chain'],
        "reverify_steps": ['recompute'],
    },
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
    'dsse-signature-invalid': {
        "domain": 'dsse',
        "code": 'dsse-signature-invalid',
        "human": 'DSSE envelope: the signature does not verify over the '
                 'PAE bytes (payloadType + payload bound by length prefix)',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'digest'],
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
    'effect-decision-contradicted': {
        "domain": 'effect-agreement',
        "code": 'effect-decision-contradicted',
        "human": 'observed effect contradicts the recorded decision',
        "severity": 'high',
        "evidence_kinds_required": ['decision-record', 'effect-record'],
        "reverify_steps": ['recompute'],
    },
    'effect-decision-missing': {
        "domain": 'effect-agreement',
        "code": 'effect-decision-missing',
        "human": 'no decision recorded for this action id',
        "severity": 'medium',
        "evidence_kinds_required": ['decision-record'],
        "reverify_steps": ['recompute'],
    },
    'effect-not-bound': {
        "domain": 'effect-agreement',
        "code": 'effect-not-bound',
        "human": 'effect bytes do not digest to the recorded effect digest',
        "severity": 'high',
        "evidence_kinds_required": ['effect-record'],
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
    'egress-destination-exemption-refused': {
        "domain": 'spawn-context',
        "code": 'egress-destination-exemption-refused',
        "human": 'a review exemption claimed on destination-ownership '
                 'grounds, or deployment-pinned status claimed for a '
                 'destination the pinned map does not vouch; '
                 'destination-ownership never exempts review',
        "severity": 'medium',
        "evidence_kinds_required": ['egress-record', 'provenance'],
        "reverify_steps": ['recompute', 'provenance-check'],
    },
    'egress-injection-propagation': {
        "domain": 'egress',
        "code": 'egress-injection-propagation',
        "human": 'outbound public-channel content reproduces an injected '
                 'instruction span observed from untrusted input; refused '
                 'at hop 1',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'span'],
        "reverify_steps": ['recompute'],
    },
    'egress-propagation-malformed': {
        "domain": 'egress',
        "code": 'egress-propagation-malformed',
        "human": 'the egress-propagation guard input is not the shape the '
                 'seam speaks; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'egress-ref-data-exfil': {
        "domain": 'egress',
        "code": 'egress-ref-data-exfil',
        "human": 'egress reference screening: an auto-fetchable reference '
                 'in agent-produced content carries exfiltration-shaped '
                 'data -- a sensitive-data digest match or an oversized '
                 'query/fragment payload on a non-allow-listed host; '
                 'refused (EchoLeak class)',
        "severity": 'high',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'egress-refs-malformed': {
        "domain": 'egress',
        "code": 'egress-refs-malformed',
        "human": 'egress reference screening: input is not str/bytes or '
                 'screening hit an internal error; refused fail-closed, '
                 'never raises',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'egress-refs-oversized': {
        "domain": 'egress',
        "code": 'egress-refs-oversized',
        "human": 'egress reference screening: content exceeds the byte '
                 'budget; refused before parsing, never raises',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'egress-relay-exfil': {
        "domain": 'egress',
        "code": 'egress-relay-exfil',
        "human": 'egress reference screening: an auto-fetchable reference '
                 'routes through a deployment-declared trusted relay proxy '
                 'to an external inner target with an exfil-shaped payload '
                 '(EchoLeak trusted-relay shape); the allow-listed relay '
                 'is treated as an untrusted channel; refused',
        "severity": 'high',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'elicitation_budget_exhausted': {
        "domain": 'elicitation',
        "code": 'elicitation_budget_exhausted',
        "human": 'approval elicitation: the record exhausted its re-prompt budget (MAX_ELICITATIONS); further elicitations refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'elicitation_refused': {
        "domain": 'elicitation',
        "code": 'elicitation_refused',
        "human": 'approval elicitation: the elicitation response or rationale failed the contract (unknown response, missing/invalid rationale, failed pre-checks); the record stays pending',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'elicitation_secret_detected': {
        "domain": 'elicitation',
        "code": 'elicitation_secret_detected',
        "human": 'approval elicitation: credential-shaped material detected in the rationale channel; refused loudly, the secret is never echoed, the record stays pending',
        "severity": 'high',
        "evidence_kinds_required": ['approval-record', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'empty_reason': {
        "domain": 'approval',
        "code": 'empty_reason',
        "human": 'approval and delegation: no reason was supplied; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'envelope-aad-mismatch': {
        "domain": 'envelope',
        "code": 'envelope-aad-mismatch',
        "human": 'encrypted bundle envelope: the bundle digest or bundle id '
                 'does not match the envelope\'s authenticated binding '
                 '(bundle-swapping attempt); refused',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-bad-header': {
        "domain": 'envelope',
        "code": 'envelope-bad-header',
        "human": 'battery evidence envelope: the run header is incomplete or inconsistent (missing battery identity, digest, taxonomy pin, or deployment mode); the envelope is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-bad-sample': {
        "domain": 'envelope',
        "code": 'envelope-bad-sample',
        "human": 'battery evidence envelope: a sample record is malformed (unknown oracle, bad verdict vocabulary, or broken chain link); the envelope is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-custody-unavailable': {
        "domain": 'envelope',
        "code": 'envelope-custody-unavailable',
        "human": 'encrypted bundle envelope: a custody recipient has no '
                 'wrap/unwrap provider configured (the KMS/Vault seam is '
                 'undeployed); refused fail-closed rather than silently '
                 'skipping the recipient',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-mac-failed': {
        "domain": 'envelope',
        "code": 'envelope-mac-failed',
        "human": 'encrypted bundle envelope: the encrypt-then-MAC tag or '
                 'the envelope header MAC does not verify (tampered '
                 'ciphertext, tag, or header); the plaintext is never '
                 'returned unverified',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-malformed': {
        "domain": 'envelope',
        "code": 'envelope-malformed',
        "human": 'encrypted envelope: the envelope bytes are structurally '
                 'invalid (bad magic, truncated header/recipient/ciphertext, '
                 'bad lengths); refused before any cryptographic work',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-open-refused': {
        "domain": 'envelope',
        "code": 'envelope-open-refused',
        "human": 'encrypted envelope: open refused under the single '
                 'generic code (wrong key, unknown recipient, or tampered '
                 'tag/ciphertext/header); failure does not leak which check '
                 'or which recipient failed',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-recipient-refused': {
        "domain": 'envelope',
        "code": 'envelope-recipient-refused',
        "human": 'encrypted envelope: a seal recipient spec is invalid '
                 '(not a Recipient, empty/non-str id, id too long, or key '
                 'material shorter than the 16-byte minimum)',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-recipient-unknown': {
        "domain": 'envelope',
        "code": 'envelope-recipient-unknown',
        "human": 'encrypted bundle envelope: the envelope carries no key '
                 'wrap for the requesting recipient id; only listed '
                 'recipients may unwrap -- refused',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-rekey-refused': {
        "domain": 'envelope',
        "code": 'envelope-rekey-refused',
        "human": 'encrypted bundle envelope: the re-keying ceremony '
                 '(rotate/updatekeys) was attempted by a party that cannot '
                 'open the current envelope; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-sample-too-large': {
        "domain": 'envelope',
        "code": 'envelope-sample-too-large',
        "human": 'battery evidence envelope: a sample record exceeds the size budget; the envelope is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-seal-refused': {
        "domain": 'envelope',
        "code": 'envelope-seal-refused',
        "human": 'encrypted envelope: seal refused (empty recipient list, '
                 'duplicate recipient id, non-bytes/empty/oversize payload)',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-signature-invalid': {
        "domain": 'envelope',
        "code": 'envelope-signature-invalid',
        "human": 'encrypted bundle envelope: no authorship signature '
                 'verifies under a trusted sealer key (unsigned envelope '
                 'or unknown signer); a MAC proves integrity, not '
                 'authorship -- refused',
        "severity": 'high',
        "evidence_kinds_required": ['digest', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'envelope-too-many-samples': {
        "domain": 'envelope',
        "code": 'envelope-too-many-samples',
        "human": 'battery evidence envelope: the run declares more samples than the envelope budget allows; the envelope is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-unwrap-failed': {
        "domain": 'envelope',
        "code": 'envelope-unwrap-failed',
        "human": 'encrypted bundle envelope: the per-recipient data-key '
                 'unwrap failed (wrong key, tampered wrap, or provider '
                 'failure); refused without revealing which check failed',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'envelope-version-unknown': {
        "domain": 'envelope',
        "code": 'envelope-version-unknown',
        "human": 'encrypted envelope: the envelope version is not '
                 'supported; refused before any cryptographic work',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
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
    'evaltask-bad-dataset-id': {
        "domain": 'evidence',
        "code": 'evaltask-bad-dataset-id',
        "human": 'eval task: dataset_id must be a non-empty string; the '
                 'dataset declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-bad-sample': {
        "domain": 'evidence',
        "code": 'evaltask-bad-sample',
        "human": 'eval task: a dataset sample is malformed; the dataset '
                 'declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-bad-samples': {
        "domain": 'evidence',
        "code": 'evaltask-bad-samples',
        "human": 'eval task: the dataset sample list is malformed or empty; '
                 'the dataset declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-bad-score': {
        "domain": 'evidence',
        "code": 'evaltask-bad-score',
        "human": 'eval task: a grader returned a score outside the [0,1] '
                 'contract; the run is refused fail-closed (no silent zeros)',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-bad-scoring-id': {
        "domain": 'evidence',
        "code": 'evaltask-bad-scoring-id',
        "human": 'eval task: scoring_id must be a non-empty string; the '
                 'scoring-function declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-bad-scoring-refs': {
        "domain": 'evidence',
        "code": 'evaltask-bad-scoring-refs',
        "human": 'eval task: an eval task references an unknown dataset or '
                 'scoring function; the task declaration is refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-bad-target': {
        "domain": 'evidence',
        "code": 'evaltask-bad-target',
        "human": 'eval task: the evaluation target must be callable; the '
                 'task declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-bad-task-id': {
        "domain": 'evidence',
        "code": 'evaltask-bad-task-id',
        "human": 'eval task: eval_task_id must be a non-empty string; the '
                 'task declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-dataset-changed': {
        "domain": 'evidence',
        "code": 'evaltask-dataset-changed',
        "human": 'eval task: the dataset digest no longer matches the pinned '
                 'digest (dataset changed under a pinned task); refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-duplicate-dataset': {
        "domain": 'evidence',
        "code": 'evaltask-duplicate-dataset',
        "human": 'eval task: a dataset id is already registered; the '
                 'duplicate declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-duplicate-scoring-function': {
        "domain": 'evidence',
        "code": 'evaltask-duplicate-scoring-function',
        "human": 'eval task: a scoring-function id is already registered; '
                 'the duplicate declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-duplicate-task': {
        "domain": 'evidence',
        "code": 'evaltask-duplicate-task',
        "human": 'eval task: an eval-task id is already registered; the '
                 'duplicate declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-grader-changed': {
        "domain": 'evidence',
        "code": 'evaltask-grader-changed',
        "human": 'eval task: the scoring-function source digest no longer '
                 'matches the pinned digest (grader changed under a pinned '
                 'task); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-grader-crashed': {
        "domain": 'evidence',
        "code": 'evaltask-grader-crashed',
        "human": 'eval task: the scoring function crashed; loud failure, no '
                 'partial evidence, the run produces no result',
        "severity": 'high',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-not-json': {
        "domain": 'evidence',
        "code": 'evaltask-not-json',
        "human": 'eval task: eval-task evidence material is not JSON-'
                 'serializable; the package is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-scoring-not-callable': {
        "domain": 'evidence',
        "code": 'evaltask-scoring-not-callable',
        "human": 'eval task: the registered scoring function is not '
                 'callable; the declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-scoring-source-unavailable': {
        "domain": 'evidence',
        "code": 'evaltask-scoring-source-unavailable',
        "human": 'eval task: the scoring-function source is unavailable for '
                 'digest pinning; the declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-target-crashed': {
        "domain": 'evidence',
        "code": 'evaltask-target-crashed',
        "human": 'eval task: the evaluation target crashed; loud failure, '
                 'no partial evidence, the run produces no result',
        "severity": 'high',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-unknown-dataset': {
        "domain": 'evidence',
        "code": 'evaltask-unknown-dataset',
        "human": 'eval task: an eval task references a dataset id the '
                 'registry never declared; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-unknown-scoring-function': {
        "domain": 'evidence',
        "code": 'evaltask-unknown-scoring-function',
        "human": 'eval task: an eval task references a scoring-function id '
                 'the registry never declared; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-unknown-task': {
        "domain": 'evidence',
        "code": 'evaltask-unknown-task',
        "human": 'eval task: a run was requested for an eval-task id the '
                 'registry never declared; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['eval-task-result'],
        "reverify_steps": ['recompute'],
    },
    'evaltask-unverifiable': {
        "domain": 'evidence',
        "code": 'evaltask-unverifiable',
        "human": 'eval task: an unverifiable eval result cannot be packaged '
                 'as evidence; packaging is refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['eval-task-result'],
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
    'evaluation-not-authorization': {
        "domain": 'evaluation',
        "code": 'evaluation-not-authorization',
        "human": 'evaluation function: an evaluation record is evidence, '
                 'never authority; presenting one as authority refuses',
        "severity": 'high',
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
    'evbundle-checkpoint-invalid': {
        "domain": 'evbundle',
        "code": 'evbundle-checkpoint-invalid',
        "human": 'evidence bundle v2: the transparency checkpoint is for a '
                 'different log, outside the log history, or its root does '
                 'not recompute from the log leaves',
        "severity": 'medium',
        "evidence_kinds_required": ['checkpoint'],
        "reverify_steps": ['re-verify-checkpoint'],
    },
    'evbundle-consistency-invalid': {
        "domain": 'evbundle',
        "code": 'evbundle-consistency-invalid',
        "human": 'evidence bundle v2: the old and new checkpoints are not '
                 'consistent (different logs, invalid checkpoint, or the '
                 'old tree is not a prefix of the new)',
        "severity": 'medium',
        "evidence_kinds_required": ['checkpoint'],
        "reverify_steps": ['re-verify-consistency'],
    },
    'evbundle-contract-refused': {
        "domain": 'evbundle',
        "code": 'evbundle-contract-refused',
        "human": 'evidence bundle v2: the artifact body fails the evidence '
                 'contract for its invocation class (missing or malformed '
                 'materials, out-of-vocabulary decision, or unknown class); '
                 'refused at seal time, fail-closed -- a signed bundle '
                 'attests both integrity and compliance',
        "severity": 'medium',
        "evidence_kinds_required": ['contract'],
        "reverify_steps": ['re-verify-contract'],
    },
    'evbundle-inclusion-unverified': {
        "domain": 'evbundle',
        "code": 'evbundle-inclusion-unverified',
        "human": 'evidence bundle v2: the inclusion proof does not '
                 'recompute the checkpoint root (forged or stale proof)',
        "severity": 'medium',
        "evidence_kinds_required": ['inclusion-proof'],
        "reverify_steps": ['re-verify-inclusion'],
    },
    'evbundle-issuance-unverifiable': {
        "domain": 'evbundle',
        "code": 'evbundle-issuance-unverifiable',
        "human": 'evidence bundle v2: no evidence-cert-issued attestation '
                 'in the audit log for this cert_digest, or the log chain '
                 'does not verify; issuance is never detached from the log',
        "severity": 'high',
        "evidence_kinds_required": ['audit-log'],
        "reverify_steps": ['re-verify-chain'],
    },
    'evbundle-join-mismatch': {
        "domain": 'evbundle',
        "code": 'evbundle-join-mismatch',
        "human": 'evidence bundle v2: cross-artifact digests disagree -- '
                 'the artifact, signature attestation, or issuance '
                 'attestation do not join on the same cert_digest / '
                 'artifact_digest',
        "severity": 'high',
        "evidence_kinds_required": ['artifact', 'attestation'],
        "reverify_steps": ['re-check-joins'],
    },
    'evbundle-malformed': {
        "domain": 'evbundle',
        "code": 'evbundle-malformed',
        "human": 'evidence bundle v2: a bundle, submission, or receipt '
                 'record is malformed (bad shape, non-dict, bad digest '
                 'encoding)',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle-record'],
        "reverify_steps": ['re-check-shape'],
    },
    'evbundle-transparency-unavailable': {
        "domain": 'evbundle',
        "code": 'evbundle-transparency-unavailable',
        "human": 'evidence bundle v2: the transparency provider failed or '
                 'was unreachable; the log is never silently skipped, so '
                 'submission refused',
        "severity": 'medium',
        "evidence_kinds_required": ['transparency-status'],
        "reverify_steps": ['re-check-provider'],
    },
    'evbundle-unauthorized-producer': {
        "domain": 'evbundle',
        "code": 'evbundle-unauthorized-producer',
        "human": 'evidence bundle v2: the producer authorization was '
                 'missing, wrong-shaped, or rejected (bare digest, forged '
                 'artifact signature, or ceremony refusal); the digest is '
                 'NOT authorized for the transparency log',
        "severity": 'high',
        "evidence_kinds_required": ['producer-authorization'],
        "reverify_steps": ['re-verify-producer-auth'],
    },
    'evcert-anchor-unavailable': {
        "domain": 'evcert',
        "code": 'evcert-anchor-unavailable',
        "human": 'evidence cert: the transparency anchor (or the '
                 'seen-key registry alongside the audit log) is '
                 'unreachable; issuance refused -- no bypass switch exists',
        "severity": 'medium',
        "evidence_kinds_required": ['anchor-status', 'audit-log'],
        "reverify_steps": ['re-check-anchor'],
    },
    'evcert-assertion-expired': {
        "domain": 'evcert',
        "code": 'evcert-assertion-expired',
        "human": 'evidence cert: the identity assertion is expired '
                 '(exp <= issuance time)',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-assertion'],
        "reverify_steps": ['re-fetch-assertion'],
    },
    'evcert-binding-invalid': {
        "domain": 'evcert',
        "code": 'evcert-binding-invalid',
        "human": 'evidence cert: the evidence signature does not bind to '
                 'the certificate (wrong key, approval mismatch, or '
                 'intent mismatch)',
        "severity": 'high',
        "evidence_kinds_required": ['certificate', 'signature'],
        "reverify_steps": ['re-verify-signature'],
    },
    'evcert-cert-expired': {
        "domain": 'evcert',
        "code": 'evcert-cert-expired',
        "human": 'evidence cert: the certificate is outside its validity '
                 'window at verification time',
        "severity": 'medium',
        "evidence_kinds_required": ['certificate'],
        "reverify_steps": ['recompute'],
    },
    'evcert-chain-invalid': {
        "domain": 'evcert',
        "code": 'evcert-chain-invalid',
        "human": 'evidence cert: the CA signature does not verify against '
                 'the configured CA public key',
        "severity": 'high',
        "evidence_kinds_required": ['certificate'],
        "reverify_steps": ['re-verify-signature'],
    },
    'evcert-identity-not-decider': {
        "domain": 'evcert',
        "code": 'evcert-identity-not-decider',
        "human": 'evidence cert: the assertion subject is not the decider '
                 'of record on the approval',
        "severity": 'high',
        "evidence_kinds_required": ['identity-assertion', 'approval-record'],
        "reverify_steps": ['re-fetch-approval'],
    },
    'evcert-key-reused': {
        "domain": 'evcert',
        "code": 'evcert-key-reused',
        "human": 'evidence cert: the subject key was already bound to an '
                 'approval; ephemeral keys are single-use',
        "severity": 'high',
        "evidence_kinds_required": ['certificate', 'audit-log'],
        "reverify_steps": ['re-check-registry'],
    },
    'evcert-kms-cannot-sign': {
        "domain": 'evcert',
        "code": 'evcert-kms-cannot-sign',
        "human": 'evidence cert: the KMS provider cannot sign '
                 '(envelope-only backend); issuance refused rather than '
                 'falling back to a local key',
        "severity": 'medium',
        "evidence_kinds_required": ['kms-response'],
        "reverify_steps": ['recompute'],
    },
    'evcert-lifetime-exceeded': {
        "domain": 'evcert',
        "code": 'evcert-lifetime-exceeded',
        "human": 'evidence cert: the requested lifetime exceeds the '
                 'deployment maximum',
        "severity": 'medium',
        "evidence_kinds_required": ['certificate'],
        "reverify_steps": ['recompute'],
    },
    'evcert-malformed-cert': {
        "domain": 'evcert',
        "code": 'evcert-malformed-cert',
        "human": 'evidence cert: the certificate fails shape validation '
                 '(fields, EKU, extensions, or key bindings)',
        "severity": 'medium',
        "evidence_kinds_required": ['certificate'],
        "reverify_steps": ['recompute'],
    },
    'evcert-malformed-request': {
        "domain": 'evcert',
        "code": 'evcert-malformed-request',
        "human": 'evidence cert: the issuance request fails shape '
                 'validation',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-assertion'],
        "reverify_steps": ['recompute'],
    },
    'evcert-pop-invalid': {
        "domain": 'evcert',
        "code": 'evcert-pop-invalid',
        "human": 'evidence cert: the proof-of-possession signature does '
                 'not verify against the presented subject key and the '
                 'approval-bound challenge',
        "severity": 'high',
        "evidence_kinds_required": ['identity-assertion', 'signature'],
        "reverify_steps": ['re-verify-signature'],
    },
    'evcert-provisioner-policy-violated': {
        "domain": 'evcert',
        "code": 'evcert-provisioner-policy-violated',
        "human": 'evidence cert: the requested lifetime is within the CA '
                 'global bounds but outside the provisioner class '
                 'tightening bounds; the class policy was enforced',
        "severity": 'medium',
        "evidence_kinds_required": ['certificate-request', 'ca-configuration'],
        "reverify_steps": ['re-check-lifetime-bounds'],
    },
    'evcert-unknown-approval': {
        "domain": 'evcert',
        "code": 'evcert-unknown-approval',
        "human": 'evidence cert: the approval id is unknown or not in the '
                 'pending state',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-record'],
        "reverify_steps": ['re-fetch-approval'],
    },
    'evcert-unknown-issuer': {
        "domain": 'evcert',
        "code": 'evcert-unknown-issuer',
        "human": 'evidence cert: the identity issuer is not in the CA '
                 'allowlist',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-assertion'],
        "reverify_steps": ['re-fetch-assertion'],
    },
    'evidence-bundle-hint-mismatch': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-hint-mismatch',
        "human": 'sigstore bundle: verificationMaterial.publicKey.hint is '
                 'neither empty nor the authenticated primary key\'s '
                 'fingerprint; the hint is informational, never authority, '
                 'and a non-matching hint names a key that did not '
                 'authenticate this bundle; refused, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-check-verification-material'],
    },
    'evidence-bundle-malformed': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-malformed',
        "human": 'sigstore bundle: bundle/envelope/token shape violation '
                 '(bad mediaType, bad base64, missing fields, bad token '
                 'shape, non-numeric time, missing validity window); '
                 'refused at parse, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle'],
    },
    'evidence-bundle-payload-type-refused': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-payload-type-refused',
        "human": 'sigstore bundle: the DSSE envelope payloadType is not '
                 'application/vnd.in-toto+json; the payload type is bound '
                 'into the signature (PAE), fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-check-payload-type'],
    },
    'evidence-bundle-predicate-refused': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-predicate-refused',
        "human": 'sigstore bundle: the in-toto statement _type / '
                 'predicateType / predicate shape is rejected by the '
                 'always-on content checks; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-check-statement'],
    },
    'evidence-bundle-signature-invalid': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-signature-invalid',
        "human": 'sigstore bundle: the DSSE signature threshold is not '
                 'met over the exact PAE bytes; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-verify-signatures'],
    },
    'evidence-bundle-subject-mismatch': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-subject-mismatch',
        "human": 'sigstore bundle: the statement subject digest does not '
                 'match the caller-expected bundle bytes; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-check-subject-digest'],
    },
    'evidence-bundle-timestamp-malformed': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-timestamp-malformed',
        "human": 'sigstore bundle: the RFC 3161 timestamp token is '
                 'malformed; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-token'],
    },
    'evidence-bundle-verification-material': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-verification-material',
        "human": 'sigstore bundle: verificationMaterial.publicKey is not '
                 'the Bundle v0.3 form-(1) PublicKeyIdentifier shape '
                 '(hint field only); unknown fields are refused -- strict '
                 'protobuf-JSON parsers reject them; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-check-verification-material'],
    },
    'evidence-bundle-witness-checkpoint-invalid': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-witness-checkpoint-invalid',
        "human": 'sigstore bundle: the log-backed witness entry checkpoint '
                 'does not verify -- bad signature, malformed checkpoint, '
                 'or logId not naming the pinned witness key; the '
                 'checkpoint signature is verified first, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-entry'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'evidence-bundle-witness-expired': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-witness-expired',
        "human": 'sigstore bundle: the witness entry integratedTime is '
                 'outside the caller-pinned validity window; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-entry'],
        "reverify_steps": ['re-check-witness-time'],
    },
    'evidence-bundle-witness-inclusion-invalid': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-witness-inclusion-invalid',
        "human": 'sigstore bundle: the log-backed witness entry Merkle '
                 'inclusion proof does not verify against the checkpoint '
                 'root (or logIndex is outside the checkpoint tree_size); '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-entry'],
        "reverify_steps": ['re-verify-witness-inclusion'],
    },
    'evidence-bundle-witness-key-unavailable': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-witness-key-unavailable',
        "human": 'sigstore bundle: the witness verifier does not expose '
                 'its public key, required for the logId binding; '
                 'key-remote witness verifiers are unsupported, '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-entry'],
        "reverify_steps": ['re-check-witness-key'],
    },
    'evidence-bundle-witness-missing': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-witness-missing',
        "human": 'sigstore bundle: no witness entry present; '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-entry'],
        "reverify_steps": ['re-check-witness-present'],
    },
    'evidence-bundle-witness-signature-invalid': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-witness-signature-invalid',
        "human": 'sigstore bundle: the witness signed-entry-timestamp '
                 'does not verify against the pinned witness verifier; '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-entry'],
        "reverify_steps": ['re-verify-witness-set'],
    },
    'evidence-bundle-witness-unbound': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-witness-unbound',
        "human": 'sigstore bundle: the witness entry body or logId does '
                 'not bind this bundle artifact/signature/key; '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-entry'],
        "reverify_steps": ['re-check-witness-binding'],
    },
    'evidence-bundle-witness-unsupported': {
        "domain": 'evbundle',
        "code": 'evidence-bundle-witness-unsupported',
        "human": 'sigstore bundle: not exactly one witness entry, or an '
                 'unknown witness kind/version; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-entry'],
        "reverify_steps": ['re-check-witness-shape'],
    },
    'evidence-envelope-record-limit': {
        "domain": 'evidence',
        "code": 'evidence-envelope-record-limit',
        "human": 'evidence envelope: record/envelope count exceeds the '
                 'verification-work bound (refused before any signature '
                 'verification)',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'evidence-envelope-record-too-large': {
        "domain": 'evidence',
        "code": 'evidence-envelope-record-too-large',
        "human": 'evidence envelope: a single record exceeds the '
                 'per-record canonical-byte bound',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'evidence-graph-ambiguous-link': {
        "domain": 'evidence-graph',
        "code": 'evidence-graph-ambiguous-link',
        "human": 'evidence graph: an identity selector matched more than '
                 'one node; refused fail-closed rather than guessing '
                 '(GUAC-adapted heuristic-linking hardening)',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'evidence-graph-malformed': {
        "domain": 'evidence-graph',
        "code": 'evidence-graph-malformed',
        "human": 'evidence graph: malformed node, edge, or projection '
                 'input; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'evidence-graph-overflow': {
        "domain": 'evidence-graph',
        "code": 'evidence-graph-overflow',
        "human": 'evidence graph: a node or edge add would exceed the '
                 'configured cap; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'evidence-graph-unlinked': {
        "domain": 'evidence-graph',
        "code": 'evidence-graph-unlinked',
        "human": 'evidence graph: an identity selector matched no node; '
                 'refused fail-closed rather than leaving a dangling edge',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'evidence-incomplete': {
        "domain": 'evidence',
        "code": 'evidence-incomplete',
        "human": 'evidence completeness: the evidence is incomplete',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'evidence-pq-not-enabled': {
        "domain": 'evbundle',
        "code": 'evidence-pq-not-enabled',
        "human": 'reserved PQ envelope slot: the bundle/seal names a PQ'
                 ' algorithm identifier, but PQ verification is not enabled'
                 ' in this build; refused fail-closed (no PQ signature was'
                 ' checked)',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 'check-pq-slot-disabled'],
    },
    'evidence-pq-unknown-alg': {
        "domain": 'evbundle',
        "code": 'evidence-pq-unknown-alg',
        "human": 'reserved PQ envelope slot: pqAlgId names an identifier'
                 ' outside the closed PQ table (19 identifiers: mldsa44/65/87,'
                 ' falcon512/padded/1024, 12 slh-dsa variants); refused'
                 ' fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 'check-pq-alg-table'],
    },
    'evidence-quality-empty-evidence': {
        "domain": 'evidence-quality',
        "code": 'evidence-quality-empty-evidence',
        "human": 'evidence quality: the evidence under evaluation is empty; a vacuous gate must never pass',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'evidence-quality-evidence-malformed': {
        "domain": 'evidence-quality',
        "code": 'evidence-quality-evidence-malformed',
        "human": 'evidence quality: the evidence under evaluation is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'evidence-quality-gate-failed': {
        "domain": 'evidence-quality',
        "code": 'evidence-quality-gate-failed',
        "human": 'evidence quality: the quality gate refused emission; an expectation failed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'evidence-quality-malformed': {
        "domain": 'evidence-quality',
        "code": 'evidence-quality-malformed',
        "human": 'evidence quality: the expectation or gate input is malformed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'attestation'],
        "reverify_steps": ['check-evidence-present', 'check-evidence-verifiable'],
    },
    'evidence-quality-unknown-expectation': {
        "domain": 'evidence-quality',
        "code": 'evidence-quality-unknown-expectation',
        "human": 'evidence quality: unknown expectation type; refused rather than skipped',
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
    'exception-baseline-drift': {
        "domain": 'exception',
        "code": 'exception-baseline-drift',
        "human": 'governed exception: the live exception set drifted beyond the pinned '
                 'baseline, or the baseline document was tampered with; refusing LOUD',
        "severity": 'high',
        "evidence_kinds_required": ['exception-record', 'baseline'],
        "reverify_steps": ['recompute'],
    },
    'exception-close-refused': {
        "domain": 'exception',
        "code": 'exception-close-refused',
        "human": 'governed exception: an attempt to close a finding through the exception '
                 'seam was refused; exceptions annotate findings as exception-suppressed '
                 'but can never close them',
        "severity": 'high',
        "evidence_kinds_required": ['exception-record', 'finding'],
        "reverify_steps": ['recompute'],
    },
    'exception-compensating-validation-failed': {
        "domain": 'exception',
        "code": 'exception-compensating-validation-failed',
        "human": 'policy exception: one or more compensating validations '
                 'failed, so the exception was refused and the rule outcome '
                 'stands; exceptions are granted only while their own '
                 'validations still pass',
        "severity": 'medium',
        "evidence_kinds_required": ['exception-record', 'validation-result'],
        "reverify_steps": ['recompute', 'replay-match'],
    },
    'exception-declaration-invalid': {
        "domain": 'exception',
        "code": 'exception-declaration-invalid',
        "human": 'governed exception: the exception or check declaration is '
                 'malformed -- a future created_at, an empty check category, '
                 'or another invalid declaration field; the grant or '
                 'registration was refused LOUD',
        "severity": 'medium',
        "evidence_kinds_required": ['exception-record', 'validation-result'],
        "reverify_steps": ['recompute'],
    },
    'exception-duplicate': {
        "domain": 'exception',
        "code": 'exception-duplicate',
        "human": 'governed exception: the same exception declaration was already granted; '
                 'the existing grant stands',
        "severity": 'low',
        "evidence_kinds_required": ['exception-record'],
        "reverify_steps": ['recompute'],
    },
    'exception-duplicate-check': {
        "domain": 'exception',
        "code": 'exception-duplicate-check',
        "human": 'governed exception: a check id is already registered in the check '
                 'registry; registration is idempotent by refusal',
        "severity": 'low',
        "evidence_kinds_required": ['check-registry'],
        "reverify_steps": ['recompute'],
    },
    'exception-expired': {
        "domain": 'exception',
        "code": 'exception-expired',
        "human": 'policy exception: the exception is past its expiresAt at '
                 'the pinned evaluation time and was skipped fail-closed '
                 'toward enforcement; expired exceptions grant nothing',
        "severity": 'medium',
        "evidence_kinds_required": ['exception-record'],
        "reverify_steps": ['recompute'],
    },
    'exception-expiry-invalid': {
        "domain": 'exception',
        "code": 'exception-expiry-invalid',
        "human": 'governed exception: the exception expiry is in the past or beyond the '
                 'maximum TTL; there are no permanent exceptions',
        "severity": 'medium',
        "evidence_kinds_required": ['exception-record'],
        "reverify_steps": ['recompute'],
    },
    'exception-granted-with-attribution': {
        "domain": 'exception',
        "code": 'exception-granted-with-attribution',
        "human": 'policy exception: a rule hit was converted to a skip with '
                 'the exception identities attached; the skip flows into the '
                 'decision trail, never a silent bypass',
        "severity": 'low',
        "evidence_kinds_required": ['exception-record'],
        "reverify_steps": ['recompute', 'replay-match'],
    },
    'exception-justification-missing': {
        "domain": 'exception',
        "code": 'exception-justification-missing',
        "human": 'governed exception: the exception declaration has no justification or '
                 'one shorter than the minimum length; justification is mandatory',
        "severity": 'medium',
        "evidence_kinds_required": ['exception-record'],
        "reverify_steps": ['recompute'],
    },
    'exception-malformed': {
        "domain": 'exception',
        "code": 'exception-malformed',
        "human": 'policy exception: the exception wire failed closed-shape '
                 'validation (unknown keys, bad DSL op, unparseable '
                 'expiresAt, or missing required fields); nothing half-loads',
        "severity": 'medium',
        "evidence_kinds_required": ['exception-record'],
        "reverify_steps": ['recompute'],
    },
    'exception-rule-skipped': {
        "domain": 'exception',
        "code": 'exception-rule-skipped',
        "human": 'policy exception: a behavioral-signature rule hit was '
                 'converted to a skip by a canonical policy exception; the '
                 'skip is journaled with the exception identities instead of '
                 'being silently suppressed',
        "severity": 'low',
        "evidence_kinds_required": ['exception-record', 'decision-trail'],
        "reverify_steps": ['recompute'],
    },
    'exception-scope-mismatch': {
        "domain": 'exception',
        "code": 'exception-scope-mismatch',
        "human": 'governed exception: the exception scope does not cover the evaluated '
                 'scope, or the declared scope is malformed; exceptions are scoped to '
                 'their resource, tool, or policy',
        "severity": 'high',
        "evidence_kinds_required": ['exception-record', 'scope'],
        "reverify_steps": ['recompute'],
    },
    'exception-unapproved-approver': {
        "domain": 'exception',
        "code": 'exception-unapproved-approver',
        "human": 'governed exception: the approver is not in the configured approver set, '
                 'or no approvers are configured; exceptions are never open by default',
        "severity": 'high',
        "evidence_kinds_required": ['exception-record', 'approver'],
        "reverify_steps": ['recompute'],
    },
    'exception-unauthorized-authorship': {
        "domain": 'exception',
        "code": 'exception-unauthorized-authorship',
        "human": 'policy exception: the exception is unsigned, signed by a '
                 'key outside the deployment trust set, or its body was '
                 'tampered after sealing; unprivileged authorship is refused '
                 'loudly and the exception never loads',
        "severity": 'high',
        "evidence_kinds_required": ['exception-record', 'signature-verification'],
        "reverify_steps": ['recompute', 'reverify-signature'],
    },
    'exception-unknown-check': {
        "domain": 'exception',
        "code": 'exception-unknown-check',
        "human": 'governed exception: the check id is not registered in the check '
                 'registry; only registered checks can be excepted',
        "severity": 'medium',
        "evidence_kinds_required": ['check-registry'],
        "reverify_steps": ['recompute'],
    },
    'exception-unknown-digest': {
        "domain": 'exception',
        "code": 'exception-unknown-digest',
        "human": 'governed exception: the exception digest is unknown to the store',
        "severity": 'low',
        "evidence_kinds_required": ['exception-record'],
        "reverify_steps": ['recompute'],
    },
    'expected-participant-missing': {
        "domain": 'participants',
        "code": 'expected-participant-missing',
        "human": 'expected-participants audit: a participant declared '
                 'expected for the workload has no signed hop in the '
                 'delegation chain; omission is not detectable without '
                 'the declared policy',
        "severity": 'high',
        "evidence_kinds_required": ['delegation-chain'],
        "reverify_steps": ['recompute'],
    },
    'expected-participants-malformed': {
        "domain": 'participants',
        "code": 'expected-participants-malformed',
        "human": 'expected-participants audit: malformed policy or '
                 'chain input; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['config-source'],
        "reverify_steps": ['recompute'],
    },
    'expected-participants-undeclared': {
        "domain": 'participants',
        "code": 'expected-participants-undeclared',
        "human": 'expected-participants audit: no declared '
                 'expected-participants policy for the workload; the '
                 'chain is not verifiable and refuses fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['config-source'],
        "reverify_steps": ['recompute'],
    },
    'expired-card': {
        "domain": 'agent_card',
        "code": 'expired-card',
        "human": 'agent card: the card has expired',
        "severity": 'medium',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'export-witness-bundle-mismatch': {
        "domain": 'witness',
        "code": 'export-witness-bundle-mismatch',
        "human": 'offline export witness layer: the layer names a bundle '
                 'digest different from the bundle the auditor holds -- '
                 'transplant attack; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'export-witness-carrier-oversize': {
        "domain": 'witness',
        "code": 'export-witness-carrier-oversize',
        "human": 'offline export witness layer: the QR-scale carrier '
                 'exceeds the 3072-byte budget -- the auditor must use '
                 'the file form; refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'export-witness-checkpoint-invalid': {
        "domain": 'witness',
        "code": 'export-witness-checkpoint-invalid',
        "human": 'offline export witness layer: the embedded checkpoint '
                 'does not authenticate under the operator key with the '
                 "policy's witness quorum; refused fail-closed",
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'export-witness-malformed': {
        "domain": 'witness',
        "code": 'export-witness-malformed',
        "human": 'offline export witness layer: the layer or carrier is '
                 'malformed -- bad shape, unknown fields, bad digests, '
                 'or missing trusted time; refused fail-closed, never '
                 'defaulted',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'export-witness-policy-invalid': {
        "domain": 'witness',
        "code": 'export-witness-policy-invalid',
        "human": 'offline export witness layer: the embedded sealed '
                 'witness-policy document does not verify against the '
                 "auditor's trust anchor; refused fail-closed",
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'export-witness-policy-version-below-minimum': {
        "domain": 'witness',
        "code": 'export-witness-policy-version-below-minimum',
        "human": 'offline export witness layer: the verified witness '
                 'policy is below the auditor-pinned minimum policy '
                 'version (policy-currency floor) -- the policy is '
                 'stale; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'export-witness-proof-mismatch': {
        "domain": 'witness',
        "code": 'export-witness-proof-mismatch',
        "human": 'offline export witness layer: a consistency or '
                 'inclusion proof does not bind the bundle digest to the '
                 'checkpoint root; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'export-witness-stale': {
        "domain": 'witness',
        "code": 'export-witness-stale',
        "human": 'offline export witness layer: the checkpoint '
                 'cosignatures are older than the policy staleness bound '
                 'or a timestamp is in the future; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'export-witness-vkey-mismatch': {
        "domain": 'witness',
        "code": 'export-witness-vkey-mismatch',
        "human": 'offline export witness layer: the embedded log/witness '
                 'vkeys differ from the verified policy -- the policy is '
                 'the trust source, embedded keys are a convenience '
                 'copy; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
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
    'federation-attestation-malformed': {
        "domain": 'federation',
        "code": 'federation-attestation-malformed',
        "human": 'peer attestation: the attestation request is malformed '
                 '(bad peer id, bad anchor key, bad identity syntax, or '
                 'bad claim shape); refused loudly at the seam',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-bundle-confusion': {
        "domain": 'federation',
        "code": 'federation-bundle-confusion',
        "human": 'trust federation: a bundle whose trust_domain does not '
                 'match the relationship it was presented under; '
                 'cross-domain bundle use refused',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-bundle-expired': {
        "domain": 'federation',
        "code": 'federation-bundle-expired',
        "human": 'trust federation: the foreign trust bundle is past its '
                 'expires_at; stale bundles are fail-closed at install '
                 'and at verify time',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-bundle-malformed': {
        "domain": 'federation',
        "code": 'federation-bundle-malformed',
        "human": 'trust federation: the fetched bundle bytes are not a '
                 'well-formed bundle document; refused before any '
                 'signature check',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-bundle-missing': {
        "domain": 'federation',
        "code": 'federation-bundle-missing',
        "human": 'trust federation: a federation relationship is '
                 'declared but no bundle was ever polled for it; '
                 'refused until the bundle endpoint is polled',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-bundle-signature-invalid': {
        "domain": 'federation',
        "code": 'federation-bundle-signature-invalid',
        "human": 'trust federation: the foreign bundle signature does '
                 'not verify under the relationship-pinned endpoint '
                 'key; the bundle is not installed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-claim-class-denied': {
        "domain": 'federation',
        "code": 'federation-claim-class-denied',
        "human": 'peer attestation: a claim was denied by its tier -- a '
                 'self-assertable claim key not on the deployment '
                 'allowlist, or an anchor-signed claim without a valid '
                 'signature (selector-spoofing is the threat model)',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-double-join': {
        "domain": 'federation',
        "code": 'federation-double-join',
        "human": 'peer attestation: a second registration attempt for an '
                 'already-bound peer id or anchor key; refused and '
                 'journaled as a security incident (TOFU)',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-endpoint-unpinned': {
        "domain": 'federation',
        "code": 'federation-endpoint-unpinned',
        "human": 'peer attestation: the cross-domain identity was '
                 'presented through a bundle endpoint that does not '
                 'exactly match the pinned relationship endpoint; no '
                 'auto-discovery, substitution fails closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-identity-unmapped': {
        "domain": 'federation',
        "code": 'federation-identity-unmapped',
        "human": 'peer attestation: the peer presented a valid anchor and '
                 'possession proof for an identity it was never mapped to; '
                 'attestation selects from the deployment-authored '
                 'mapping, it never mints',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-peer-banned': {
        "domain": 'federation',
        "code": 'federation-peer-banned',
        "human": 'peer attestation: a banned peer attempted registration, '
                 'attestation, or a challenge; bans are per-peer and '
                 'survive pruning',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-possession-failed': {
        "domain": 'federation',
        "code": 'federation-possession-failed',
        "human": 'peer attestation: the challenge-response '
                 'proof-of-possession failed (bad signature, wrong key, '
                 'stale or replayed challenge); bearer presentation is '
                 'not accepted',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-relationship-malformed': {
        "domain": 'federation',
        "code": 'federation-relationship-malformed',
        "human": 'trust federation: a malformed federation relationship '
                 'declaration (bad trust domain, non-https endpoint, '
                 'unknown endpoint profile, or bad endpoint key); '
                 'refused at declaration',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'federation-untrusted-domain': {
        "domain": 'federation',
        "code": 'federation-untrusted-domain',
        "human": 'trust federation: no live federation relationship for '
                 'the SVID trust domain (one-way: trusting them never '
                 'lets them trust us); refused',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'finding-illegal-transition': {
        "domain": 'policy',
        "code": 'finding-illegal-transition',
        "human": 'finding lifecycle: the requested state transition is not '
                 'in the closed transition table, or the target state '
                 'requires evidence that was not supplied (verified/ '
                 'mitigated require red-first evidence by reference; '
                 'false_positive/risk_accepted require a triage note); '
                 'refused, state unchanged',
        "severity": 'low',
        "evidence_kinds_required": ['trust-record'],
        "reverify_steps": ['recompute'],
    },
    'finding-sla-breached': {
        "domain": 'policy',
        "code": 'finding-sla-breached',
        "human": 'finding lifecycle: an open finding passed its '
                 'per-severity wave SLA (HIGH 1 wave, MEDIUM 2 waves, '
                 'LOW 3 waves); the breach is raised loudly instead of '
                 'silently aging',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-record'],
        "reverify_steps": ['recompute'],
    },
    'gate-exception-malformed': {
        "domain": 'gate',
        "code": 'gate-exception-malformed',
        "human": 'gate exception path: the exception declaration is '
                 'malformed -- it requires a numeric valid_until '
                 'horizon, a non-empty reason, and a non-empty scope; '
                 'a horizon-less exception cannot shield an '
                 'undecidable verdict',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
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
    'gatehard-breakglass-invalid': {
        "domain": 'gatehard',
        "code": 'gatehard-breakglass-invalid',
        "human": 'enforcement hardening: a break-glass token was '
                 'presented but is invalid (bad signature, wrong '
                 'request class, or expired); a namespace claim alone '
                 'is never sufficient -- break-glass is signed policy '
                 'only',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-breakglass-used': {
        "domain": 'gatehard',
        "code": 'gatehard-breakglass-used',
        "human": 'enforcement hardening: a valid signed break-glass '
                 'token overrode a deny; the override is audited with '
                 'its reason',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-gate-error': {
        "domain": 'gatehard',
        "code": 'gatehard-gate-error',
        "human": 'enforcement hardening: a gate policy raised during '
                 'evaluation; the gate refuses fail-closed (default '
                 'deny, never silent allow)',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-gate-timeout': {
        "domain": 'gatehard',
        "code": 'gatehard-gate-timeout',
        "human": 'enforcement hardening: a gate policy exceeded its '
                 'deadline (global floor, per-policy override '
                 'tightening only); the gate refuses fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-global-deadline-unset': {
        "domain": 'gatehard',
        "code": 'gatehard-global-deadline-unset',
        "human": 'enforcement hardening: gate construction without a '
                 'global deadline is refused; an unset global '
                 'deadline would silently ignore per-policy timeouts',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-host-callback-denied': {
        "domain": 'gatehard',
        "code": 'gatehard-host-callback-denied',
        "human": 'enforcement hardening: a policy invoked a host '
                 'callback not on the enumerated allowlist; the '
                 'callback is refused and the gate denies',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-host-callback-wildcard': {
        "domain": 'gatehard',
        "code": 'gatehard-host-callback-wildcard',
        "human": 'enforcement hardening: a wildcard host-callback '
                 'allowlist entry was offered at construction and '
                 'refused; wildcards are not offered',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-ignore-exception-invalid': {
        "domain": 'gatehard',
        "code": 'gatehard-ignore-exception-invalid',
        "human": 'enforcement hardening: a failure-ignore exception '
                 'was presented for a crashed policy but is invalid '
                 '(bad signature, wrong policy, or expired); the deny '
                 'stands',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-ignore-exception-used': {
        "domain": 'gatehard',
        "code": 'gatehard-ignore-exception-used',
        "human": 'enforcement hardening: a crashed policy was allowed '
                 'under a valid signed, expiring failure-ignore '
                 'exception; the exception is audited',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-monitor-would-deny': {
        "domain": 'gatehard',
        "code": 'gatehard-monitor-would-deny',
        "human": 'enforcement hardening: monitor mode allowed a '
                 'request that protect mode would have denied; the '
                 'would-deny is recorded, never enforced',
        "severity": 'low',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-per-policy-deadline-exceeds-global': {
        "domain": 'gatehard',
        "code": 'gatehard-per-policy-deadline-exceeds-global',
        "human": 'enforcement hardening: a per-policy deadline '
                 'exceeding the global floor was refused at '
                 'registration; overrides tighten only',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-policy-denied': {
        "domain": 'gatehard',
        "code": 'gatehard-policy-denied',
        "human": 'enforcement hardening: a gate policy predicate '
                 'returned deny; the gate refuses the request',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-policy-malformed': {
        "domain": 'gatehard',
        "code": 'gatehard-policy-malformed',
        "human": 'enforcement hardening: a policy spec is missing a '
                 'required key (policy_id, predicate_name, predicate, '
                 'host_callbacks); compilation refuses it',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'gatehard-unknown-mode': {
        "domain": 'gatehard',
        "code": 'gatehard-unknown-mode',
        "human": 'enforcement hardening: gate construction with an '
                 'unrecognized mode is refused fail-closed; the mode '
                 'vocabulary is monitor | protect',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
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
    'grantneg-anchor-untrusted': {
        "domain": 'grantneg',
        "code": 'grantneg-anchor-untrusted',
        "human": 'grant negotiation: the delegation chain root was not '
                 'issued by the tool\u2019s registered resource owner; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grantneg-audience-mismatch': {
        "domain": 'grantneg',
        "code": 'grantneg-audience-mismatch',
        "human": 'grant negotiation: the grant audience does not match '
                 'the presenting agent (replay by another agent); refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grantneg-chain-unverifiable': {
        "domain": 'grantneg',
        "code": 'grantneg-chain-unverifiable',
        "human": 'grant negotiation: a chain link signature does not '
                 'verify, its issuer key is unknown, or parent linkage is '
                 'broken; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grantneg-chain-widened': {
        "domain": 'grantneg',
        "code": 'grantneg-chain-widened',
        "human": 'grant negotiation: a delegation hop is not '
                 'equal-or-narrower than its parent; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grantneg-expired': {
        "domain": 'grantneg',
        "code": 'grantneg-expired',
        "human": 'grant negotiation: the grant TTL lapsed '
                 '(expiry-as-revocation); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grantneg-malformed': {
        "domain": 'grantneg',
        "code": 'grantneg-malformed',
        "human": 'grant negotiation: the grant or grant request failed '
                 'the grammar/shape check; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grantneg-product-of-fields': {
        "domain": 'grantneg',
        "code": 'grantneg-product-of-fields',
        "human": 'grant negotiation: one grant object names more than one '
                 '(tool, resource) pair -- the RFC 9396 S2.2 '
                 'multiplicative-privilege trap; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grantneg-registry-withdrawn': {
        "domain": 'grantneg',
        "code": 'grantneg-registry-withdrawn',
        "human": 'grant negotiation: the approval record carries a grant '
                 'that cannot be re-verified at execution -- the grant '
                 'registry is not installed or the tool is no longer '
                 'registered (registry withdrawn after queue time); '
                 'refused fail-closed, never silently downgraded',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grantneg-scope-mismatch': {
        "domain": 'grantneg',
        "code": 'grantneg-scope-mismatch',
        "human": 'grant negotiation: the grant does not cover this call '
                 '-- the grant tool differs from the called tool, or the '
                 'grant resource differs from the call resource locator; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'grantneg-widening-refused': {
        "domain": 'grantneg',
        "code": 'grantneg-widening-refused',
        "human": 'grant negotiation: derive() was asked for a delegation '
                 'that is not strictly narrower than its parent; refused '
                 'fail-fast at construction',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'guac-graph-ambiguous-link': {
        "domain": 'guac-graph',
        "code": 'guac-graph-ambiguous-link',
        "human": 'guac evidence graph: an identity selector matched more '
                 'than one node; refused fail-closed rather than guessing '
                 '(GUAC-pattern corroboration graph)',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'guac-graph-bad-spec': {
        "domain": 'guac-graph',
        "code": 'guac-graph-bad-spec',
        "human": 'guac evidence graph: a query Spec named an unknown field '
                 'or edge kind; refused fail-closed (no raw query language)',
        "severity": 'low',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'guac-graph-claim-conflict': {
        "domain": 'guac-graph',
        "code": 'guac-graph-claim-conflict',
        "human": 'guac evidence graph: quorum disagreement on a subject '
                 '(both CertifyBad and CertifyGood verified); the graph '
                 'never picks a side, blast radius refuses the subject',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'guac-graph-envelope-refused': {
        "domain": 'guac-graph',
        "code": 'guac-graph-envelope-refused',
        "human": 'guac evidence graph: a DSSE claim envelope failed strict '
                 'parse, signature threshold, payload-type binding, or '
                 'actor/signer binding at ingest; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'guac-graph-malformed': {
        "domain": 'guac-graph',
        "code": 'guac-graph-malformed',
        "human": 'guac evidence graph: malformed node, edge, or claim '
                 'input; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'guac-graph-overflow': {
        "domain": 'guac-graph',
        "code": 'guac-graph-overflow',
        "human": 'guac evidence graph: a node, edge, or claim add would '
                 'exceed the configured cap; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'guac-graph-unlinked': {
        "domain": 'guac-graph',
        "code": 'guac-graph-unlinked',
        "human": 'guac evidence graph: an edge or query referenced a node '
                 'not in the graph; refused fail-closed rather than '
                 'leaving a dangling reference',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'guardplugin-bad-hook': {
        "domain": 'guardplugin',
        "code": 'guardplugin-bad-hook',
        "human": 'guard plugin: declaration named a hook outside '
                 'before_tool_call / after_tool_call / start / end; '
                 'refused at declaration time',
        "severity": 'low',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'guardplugin-bad-id': {
        "domain": 'guardplugin',
        "code": 'guardplugin-bad-id',
        "human": 'guard plugin: declaration used an empty or non-string '
                 'plugin id; refused at declaration time',
        "severity": 'low',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'guardplugin-bad-params': {
        "domain": 'guardplugin',
        "code": 'guardplugin-bad-params',
        "human": 'guard plugin: declaration params are not JSON-serializable '
                 'or a default guard is misconfigured; refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'guardplugin-bad-run': {
        "domain": 'guardplugin',
        "code": 'guardplugin-bad-run',
        "human": 'guard plugin: the declared run handler is not callable; '
                 'refused at declaration time',
        "severity": 'low',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'guardplugin-bad-transform': {
        "domain": 'guardplugin',
        "code": 'guardplugin-bad-transform',
        "human": 'guard plugin: a transform outcome carried a non-dict '
                 'payload; treated as a technical failure and refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'guardplugin-bad-verdict': {
        "domain": 'guardplugin',
        "code": 'guardplugin-bad-verdict',
        "human": 'guard plugin: a handler returned a non-verdict; treated '
                 'as a technical failure and refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'guardplugin-denied': {
        "domain": 'guardplugin',
        "code": 'guardplugin-denied',
        "human": 'guard plugin: a plugin returned deny (or raised its '
                 'declared PluginDeny); the guarded action is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'guardplugin-duplicate-id': {
        "domain": 'guardplugin',
        "code": 'guardplugin-duplicate-id',
        "human": 'guard plugin: a plugin id was registered twice; '
                 'refused at registration time (no shadowing)',
        "severity": 'low',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'guardplugin-error-refused': {
        "domain": 'guardplugin',
        "code": 'guardplugin-error-refused',
        "human": 'guard plugin: a plugin errored technically; the error is '
                 'structurally a deny -- recorded as technical_failure, '
                 'never as a policy block, and refused LOUDLY fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'guardplugin-unknown-id': {
        "domain": 'guardplugin',
        "code": 'guardplugin-unknown-id',
        "human": 'guard plugin: an attach list named a plugin id the '
                 'registry never declared; refused fail-closed before any '
                 'plugin ran',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'guest-budget-amplified': {
        "domain": 'guest-budget',
        "code": 'guest-budget-amplified',
        "human": 'host-measured guest consumption exceeded declared '
                 'envelope plus the declared accounting slack; guest '
                 'terminated fail-closed, never re-budgeted',
        "severity": 'high',
        "evidence_kinds_required": ['budget-envelope', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'guest-budget-deadline-fired': {
        "domain": 'guest-budget',
        "code": 'guest-budget-deadline-fired',
        "human": 'guest blew its declared wall-clock bound; guest '
                 'terminated fail-closed; in-flight effects are not '
                 'committed',
        "severity": 'high',
        "evidence_kinds_required": ['budget-envelope', 'measurement'],
        "reverify_steps": ['recompute'],
    },
    'guest-budget-envelope-malformed': {
        "domain": 'guest-budget',
        "code": 'guest-budget-envelope-malformed',
        "human": 'guest budget envelope declaration or measurement is not '
                 'the expected shape; envelopes are never renegotiated',
        "severity": 'medium',
        "evidence_kinds_required": ['budget-envelope'],
        "reverify_steps": ['recompute'],
    },
    'guest-budget-scope-undeclared': {
        "domain": 'guest-budget',
        "code": 'guest-budget-scope-undeclared',
        "human": 'measurement or commit presented for a guest scope with '
                 'no declared envelope; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['budget-envelope'],
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
    'honesty-baseline-tampered': {
        "domain": 'honesty',
        "code": 'honesty-baseline-tampered',
        "human": 'forcing-honesty: a baseline JSON not written by --sync '
                 '(checksum mismatch); the gate refuses to use it',
        "severity": 'high',
        "evidence_kinds_required": ['forcing-honesty-baseline'],
        "reverify_steps": ['recompute'],
    },
    'honesty-baseline-unforced': {
        "domain": 'honesty',
        "code": 'honesty-baseline-unforced',
        "human": 'forcing-honesty: a condition that was forced in the '
                 'baseline stopped being forced; tighten-only ratchet '
                 'refuses unless the condition is named to --accept-unforced',
        "severity": 'high',
        "evidence_kinds_required": ['forcing-honesty-baseline'],
        "reverify_steps": ['recompute'],
    },
    'honesty-condition-silent': {
        "domain": 'honesty',
        "code": 'honesty-condition-silent',
        "human": 'forcing-honesty: a mutation changed observations without '
                 'failing any probe; the battery does not observe what the '
                 'condition claims to force (filed finding)',
        "severity": 'medium',
        "evidence_kinds_required": ['forcing-honesty-campaign'],
        "reverify_steps": ['recompute'],
    },
    'honesty-mutant-inconclusive': {
        "domain": 'honesty',
        "code": 'honesty-mutant-inconclusive',
        "human": 'forcing-honesty: the mutant did not build or run '
                 '(syntax/import failure); never folded into gaps',
        "severity": 'low',
        "evidence_kinds_required": ['forcing-honesty-campaign'],
        "reverify_steps": ['recompute'],
    },
    'honesty-mutant-invalid': {
        "domain": 'honesty',
        "code": 'honesty-mutant-invalid',
        "human": 'forcing-honesty: the requested mutation site is absent '
                 'from the target module',
        "severity": 'low',
        "evidence_kinds_required": ['forcing-honesty-campaign'],
        "reverify_steps": ['recompute'],
    },
    'honesty-tautology-suspect': {
        "domain": 'honesty',
        "code": 'honesty-tautology-suspect',
        "human": 'forcing-honesty: a probe vector killed zero mutations '
                 'across the campaign; it cannot disagree with the code',
        "severity": 'low',
        "evidence_kinds_required": ['forcing-honesty-campaign'],
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
    'hostid-hostname-digest-not-identity': {
        "domain": 'hostid',
        "code": 'hostid-hostname-digest-not-identity',
        "human": 'host identity rule: a receipt claimed a digest of the '
                 'machine hostname as host identity; a digest with no '
                 'secret reverses from a short guess list of common '
                 'machine names',
        "severity": 'high',
        "evidence_kinds_required": ['host-identity'],
        "reverify_steps": ['recompute'],
    },
    'hostid-hostname-not-identity': {
        "domain": 'hostid',
        "code": 'hostid-hostname-not-identity',
        "human": 'host identity rule: a receipt claimed the machine '
                 'hostname itself as host identity; hostnames are '
                 'observable and non-random, they are not identities',
        "severity": 'high',
        "evidence_kinds_required": ['host-identity'],
        "reverify_steps": ['recompute'],
    },
    'hostid-id-file-corrupt': {
        "domain": 'hostid',
        "code": 'hostid-id-file-corrupt',
        "human": 'host identity rule: the persisted id file is missing, '
                 'not a regular file, holds a value that is not a '
                 'valid host identity, or could not be minted '
                 'atomically (short write)',
        "severity": 'high',
        "evidence_kinds_required": ['host-identity'],
        "reverify_steps": ['recompute'],
    },
    'hostid-malformed-identity': {
        "domain": 'hostid',
        "code": 'hostid-malformed-identity',
        "human": 'host identity rule: the claimed host identity is not '
                 'host_[0-9a-f]{16}; only minted random ids validate',
        "severity": 'medium',
        "evidence_kinds_required": ['host-identity'],
        "reverify_steps": ['recompute'],
    },
    'hostid-symlink-at-id-path': {
        "domain": 'hostid',
        "code": 'hostid-symlink-at-id-path',
        "human": 'host identity rule: refusing to mint through or read '
                 'a symlink at the id path; the persisted id must be a '
                 'regular file',
        "severity": 'critical',
        "evidence_kinds_required": ['host-identity'],
        "reverify_steps": ['recompute'],
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
    'identity-anchor-unknown': {
        "domain": 'attested-identity',
        "code": 'identity-anchor-unknown',
        "human": 'the attestation references an anchor key the '
                 'deployment did not provision (or the provisioned key '
                 'is malformed); refused rather than trusting an '
                 'unprovisioned anchor',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-attestation-malformed': {
        "domain": 'attested-identity',
        "code": 'identity-attestation-malformed',
        "human": 'the attestation (or check input) presented for the '
                 'agent-identity cross-check failed structural '
                 'validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-attestation-unverifiable': {
        "domain": 'attested-identity',
        "code": 'identity-attestation-unverifiable',
        "human": 'the anchor Ed25519 signature over the attested '
                 'principal failed verification (forged or corrupt); '
                 'refused',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-attested': {
        "domain": 'attested-identity',
        "code": 'identity-attested',
        "human": 'workload identity: the identity document verified -- '
                 'minted by a trusted issuer for the presented selectors, '
                 'unexpired, presented for its audience (never evidence '
                 'of node/platform integrity)',
        "severity": 'low',
        "evidence_kinds_required": ['identity-document', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'identity-audience-mismatch': {
        "domain": 'attested-identity',
        "code": 'identity-audience-mismatch',
        "human": 'workload identity: the document names a different '
                 'audience than the one presented for -- no token '
                 'passthrough; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['identity-document'],
        "reverify_steps": ['recompute'],
    },
    'identity-claim-mismatch': {
        "domain": 'attested-identity',
        "code": 'identity-claim-mismatch',
        "human": 'the anchor-attested principal does not match the '
                 "peer's claimed principal; refused",
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-claims-ambiguous': {
        "domain": 'identity',
        "code": 'identity-claims-ambiguous',
        "human": 'two subject-candidate claims were both present and '
                 'disagreed (e.g. sub vs uid); the connector refuses to '
                 'guess which is authoritative, refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-claims-malformed': {
        "domain": 'identity',
        "code": 'identity-claims-malformed',
        "human": 'the upstream claim set failed structural validation '
                 '(not a dict, subject not a string, groups not a list of '
                 'strings); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-claims-missing-subject': {
        "domain": 'identity',
        "code": 'identity-claims-missing-subject',
        "human": 'the upstream claim set carried no usable subject claim; '
                 'no identity was minted, refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-connector-unsupported': {
        "domain": 'identity',
        "code": 'identity-connector-unsupported',
        "human": 'the requested identity connector is unknown or '
                 'explicitly disabled (the SAML connector stays off: '
                 'unmaintained upstream); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-expired': {
        "domain": 'attested-identity',
        "code": 'identity-expired',
        "human": 'workload identity: the document is past its not_after -- '
                 'expiry is the revocation mechanism; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-document'],
        "reverify_steps": ['recompute'],
    },
    'identity-forged': {
        "domain": 'attested-identity',
        "code": 'identity-forged',
        "human": 'workload identity: the document signature does not '
                 'verify under the trust domain\'s issuer key, the issuer '
                 'is unknown, or the document is malformed -- refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['identity-document'],
        "reverify_steps": ['recompute'],
    },
    'identity-issuer-key-retired': {
        "domain": 'identity',
        "code": 'identity-issuer-key-retired',
        "human": 'the federated identity token was signed by a retired '
                 'issuer key outside the rotation grace window; the agent '
                 'must re-authenticate for a token from the current key, '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-mint-refused': {
        "domain": 'attested-identity',
        "code": 'identity-mint-refused',
        "human": 'workload identity: the mint request was not mintable -- '
                 'unrecognized selectors, empty audience, excessive TTL, '
                 'or malformed inputs; no document issued',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-document'],
        "reverify_steps": ['recompute'],
    },
    'identity-mismatch': {
        "domain": 'agent_card',
        "code": 'identity-mismatch',
        "human": 'agent card: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['agent-card', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'identity-not-yet-valid': {
        "domain": 'attested-identity',
        "code": 'identity-not-yet-valid',
        "human": 'workload identity: the document is before its '
                 'not_before -- refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-document'],
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
    'identity-refresh-expired': {
        "domain": 'identity',
        "code": 'identity-refresh-expired',
        "human": 'the refresh token was past its expiry; no new identity '
                 'token was issued, refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-refresh-lock-unavailable': {
        "domain": 'identity',
        "code": 'identity-refresh-lock-unavailable',
        "human": 'the per-token rotation lock could not be acquired within '
                 'the timeout, so the refresh was refused fail-closed '
                 'rather than proceeding unlocked (F421)',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-refresh-reuse-detected': {
        "domain": 'identity',
        "code": 'identity-refresh-reuse-detected',
        "human": 'a rotated (already-spent) refresh token was presented '
                 'again: suspected theft, the whole refresh chain was '
                 'revoked, refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-refresh-revoked': {
        "domain": 'identity',
        "code": 'identity-refresh-revoked',
        "human": 'the refresh token belongs to a revoked chain (reuse was '
                 'detected earlier); no new identity token was issued, '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-refresh-unknown': {
        "domain": 'identity',
        "code": 'identity-refresh-unknown',
        "human": 'the refresh token id is unknown or its secret does not '
                 'match (one code, no oracle); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-selector-mismatch': {
        "domain": 'attested-identity',
        "code": 'identity-selector-mismatch',
        "human": 'workload identity: the re-attested workload facts do '
                 'not match the document\'s selectors -- a stolen document '
                 'presented by a different workload; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['identity-document'],
        "reverify_steps": ['recompute'],
    },
    'identity-token-audience-mismatch': {
        "domain": 'identity',
        "code": 'identity-token-audience-mismatch',
        "human": 'the identity token was presented to an audience other '
                 'than the one it was issued for; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-token-expired': {
        "domain": 'identity',
        "code": 'identity-token-expired',
        "human": 'the short-lived identity token was past its exp; '
                 'refused fail-closed (refresh for a new one)',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-token-issuer-unknown': {
        "domain": 'identity',
        "code": 'identity-token-issuer-unknown',
        "human": 'the federated identity token names an issuer (or issuer '
                 'key) this deployment has not pinned; unknown issuers are '
                 'never silently accepted, refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-token-key-binding-mismatch': {
        "domain": 'identity',
        "code": 'identity-token-key-binding-mismatch',
        "human": 'the federated identity token is bound to a different '
                 'agent public key than the caller presented (possible '
                 'stolen token); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-token-malformed': {
        "domain": 'identity',
        "code": 'identity-token-malformed',
        "human": 'the identity token failed structural validation (not '
                 'two parts, bad base64, bad JSON, wrong version); '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-token-not-yet-valid': {
        "domain": 'identity',
        "code": 'identity-token-not-yet-valid',
        "human": 'the identity token claims an issue time in the future '
                 '(beyond clock leeway): pre-issued token, refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-token-replayed': {
        "domain": 'identity',
        "code": 'identity-token-replayed',
        "human": 'the federated identity token nonce was already '
                 'presented (replay); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-token-required': {
        "domain": 'identity',
        "code": 'identity-token-required',
        "human": 'this deployment authenticates agent identity with '
                 'short-lived signed tokens and the mint named no token; '
                 'self-asserted minting is refused where token '
                 'authentication is required, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-token-tampered': {
        "domain": 'identity',
        "code": 'identity-token-tampered',
        "human": 'the identity token signature did not verify (payload '
                 'forged or corrupt); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-token-ttl-exceeded': {
        "domain": 'identity',
        "code": 'identity-token-ttl-exceeded',
        "human": 'the federated identity token lifetime exceeds this '
                 'verifier TTL ceiling (long-lived token); short-lived '
                 'tokens bound the theft window, refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'identity-untrusted-domain': {
        "domain": 'attested-identity',
        "code": 'identity-untrusted-domain',
        "human": 'workload identity: the document\'s trust domain is '
                 'foreign with no federation record, or the federated '
                 'document exceeds the federation TTL bound -- trust is '
                 'never implicit; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['identity-document', 'trust-config'],
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
    'ifc-audit-required': {
        "domain": 'ifc',
        "code": 'ifc-audit-required',
        "human": 'IFC privilege exercise without an audit hook refuses: '
                 'privilege use is never silent; every declassification or '
                 'endorsement must leave audit evidence',
        "severity": 'medium',
        "evidence_kinds_required": ['label-record'],
        "reverify_steps": ['recompute'],
    },
    'ifc-grant-unissued': {
        "domain": 'ifc',
        "code": 'ifc-grant-unissued',
        "human": 'IFC privilege exercise with a grant that was never '
                 'issued by the ceremony refuses: the digest is valid '
                 'but no issuance registry recorded it, so the grant '
                 'is attributable as self-minted (forged), not tampered',
        "severity": 'high',
        "evidence_kinds_required": ['label-record', 'grant'],
        "reverify_steps": ['recompute'],
    },
    'ifc-integrity-flow-denied': {
        "domain": 'ifc',
        "code": 'ifc-integrity-flow-denied',
        "human": 'IFC sink check: labeled data lacks the trust tags the '
                 'sink requires; unendorsed tool output is refused at '
                 'trust-requiring sinks (execution)',
        "severity": 'high',
        "evidence_kinds_required": ['label-record', 'sink-policy'],
        "reverify_steps": ['recompute'],
    },
    'ifc-label-malformed': {
        "domain": 'ifc',
        "code": 'ifc-label-malformed',
        "human": 'IFC: malformed label, provenance, registry, sink policy, '
                 'grant, or timestamp; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['label-record'],
        "reverify_steps": ['recompute'],
    },
    'ifc-privilege-denied': {
        "domain": 'ifc',
        "code": 'ifc-privilege-denied',
        "human": 'IFC privilege exercise without a covering privilege '
                 'refuses: declassification/endorsement needs an authorized '
                 'grant, and trust tags cannot be self-claimed at '
                 'assignment time',
        "severity": 'high',
        "evidence_kinds_required": ['label-record', 'grant'],
        "reverify_steps": ['recompute'],
    },
    'ifc-privilege-expired': {
        "domain": 'ifc',
        "code": 'ifc-privilege-expired',
        "human": 'IFC privilege exercise with an expired grant refuses',
        "severity": 'medium',
        "evidence_kinds_required": ['label-record', 'grant'],
        "reverify_steps": ['recompute'],
    },
    'ifc-privilege-scope-denied': {
        "domain": 'ifc',
        "code": 'ifc-privilege-scope-denied',
        "human": 'IFC privilege exercise for tags outside the granted '
                 'privilege scope refuses',
        "severity": 'high',
        "evidence_kinds_required": ['label-record', 'grant'],
        "reverify_steps": ['recompute'],
    },
    'ifc-privilege-unauthorized': {
        "domain": 'ifc',
        "code": 'ifc-privilege-unauthorized',
        "human": 'IFC privilege grant with invalid authorization evidence '
                 'refuses: authorization must be human-approval or '
                 'deployment-role with a non-empty reference; tampered or '
                 'forged grants are detected via digest',
        "severity": 'high',
        "evidence_kinds_required": ['label-record', 'grant'],
        "reverify_steps": ['recompute'],
    },
    'ifc-registry-corrupt': {
        "domain": 'ifc',
        "code": 'ifc-registry-corrupt',
        "human": 'IFC issuance-registry journal is unreadable or corrupt: '
                 'the registry refuses loudly rather than replaying '
                 'partial state; no grant authenticates until the '
                 'deployment repairs the journal',
        "severity": 'high',
        "evidence_kinds_required": ['label-record', 'grant'],
        "reverify_steps": ['recompute'],
    },
    'ifc-secrecy-flow-denied': {
        "domain": 'ifc',
        "code": 'ifc-secrecy-flow-denied',
        "human": 'IFC sink check: labeled data would leak secrecy tags to '
                 'a sink with lower clearance; declassify via an authorized '
                 'privilege before release',
        "severity": 'high',
        "evidence_kinds_required": ['label-record', 'sink-policy'],
        "reverify_steps": ['recompute'],
    },
    'ifc-sink-unmapped': {
        "domain": 'ifc',
        "code": 'ifc-sink-unmapped',
        "human": 'IFC sink check against an unknown sink name refuses: '
                 'sinks must be declared, never assumed',
        "severity": 'medium',
        "evidence_kinds_required": ['label-record'],
        "reverify_steps": ['recompute'],
    },
    'imgscreen-instruction-detected': {
        "domain": 'imgscreen',
        "code": 'imgscreen-instruction-detected',
        "human": 'image carrier screening: instruction-shaped text found '
                 'in image container metadata (PNG tEXt/zTXt/iTXt, JPEG '
                 'COM/EXIF UserComment/XMP, GIF comment); refused '
                 'fail-closed, bytes never reach the model as content',
        "severity": 'high',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'imgscreen-malformed': {
        "domain": 'imgscreen',
        "code": 'imgscreen-malformed',
        "human": 'image carrier screening: input is not bytes, has an '
                 'unknown magic, or has truncated/impossible container '
                 'structure; refused fail-closed, never raises',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'imgscreen-oversized': {
        "domain": 'imgscreen',
        "code": 'imgscreen-oversized',
        "human": 'image carrier screening: input exceeds the parse budget; '
                 'refused before parsing',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'imgscreen-stego-suspect': {
        "domain": 'imgscreen',
        "code": 'imgscreen-stego-suspect',
        "human": 'image carrier screening: LSB-plane chi-square anomaly '
                 'consistent with least-significant-bit embedding; '
                 'flag-only advisory, never a denial (false positives '
                 'from compression/quantization are documented)',
        "severity": 'low',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'imgtext-extraction-failed': {
        "domain": 'imgtext',
        "code": 'imgtext-extraction-failed',
        "human": 'image text extraction: corrupt/unparseable text chunks '
                 'in an otherwise-parseable image; extraction refused '
                 'fail-closed rather than silently dropping channels',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'imgtext-malformed': {
        "domain": 'imgtext',
        "code": 'imgtext-malformed',
        "human": 'image text extraction: input is not bytes or has an '
                 'unknown magic; refused fail-closed, never raises',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'imgtext-oversized': {
        "domain": 'imgtext',
        "code": 'imgtext-oversized',
        "human": 'image text extraction: input exceeds the parse budget; '
                 'refused before parsing',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'imgtext-reassembled-instruction-detected': {
        "domain": 'imgtext',
        "code": 'imgtext-reassembled-instruction-detected',
        "human": 'image text extraction: reassembled cross-channel text '
                 '(joined before screening) is instruction-shaped per the '
                 'house instruction-shaping seam; refuses the wave-270 '
                 'fragment-evasion residual (benign fragments across '
                 'channels that only form an instruction when joined)',
        "severity": 'high',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'incident-gpai9-final-overdue': {
        "domain": 'incident',
        "code": 'incident-gpai9-final-overdue',
        "human": 'GPAI Code ch.9 Measure 9.3: final report not submitted '
                 'within 60 days after the serious incident was resolved; '
                 'flagged, never silently absorbed',
        "severity": 'medium',
        "evidence_kinds_required": ['incident'],
        "reverify_steps": ['check-timeliness'],
    },
    'incident-gpai9-incomplete': {
        "domain": 'incident',
        "code": 'incident-gpai9-incomplete',
        "human": 'GPAI Code ch.9 Measure 9.2: incident report refused -- a '
                 'numbered checklist point is neither present nor explicitly '
                 'marked unavailable with a recorded reason; report not '
                 'emitted fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['incident'],
        "reverify_steps": ['validate-input-shape'],
    },
    'incident-gpai9-initial-overdue': {
        "domain": 'incident',
        "code": 'incident-gpai9-initial-overdue',
        "human": 'GPAI Code ch.9 Measure 9.3: initial report (points 1-7) '
                 'not submitted within the band deadline (2/5/10/15 days '
                 'from suspicion-inclusive awareness); flagged, never '
                 'silently absorbed',
        "severity": 'medium',
        "evidence_kinds_required": ['incident'],
        "reverify_steps": ['check-timeliness'],
    },
    'incident-gpai9-intermediate-overdue': {
        "domain": 'incident',
        "code": 'incident-gpai9-intermediate-overdue',
        "human": 'GPAI Code ch.9 Measure 9.3: intermediate report not '
                 'submitted within the 4-week cadence while the serious '
                 'incident is unresolved; flagged, never silently absorbed',
        "severity": 'medium',
        "evidence_kinds_required": ['incident'],
        "reverify_steps": ['check-timeliness'],
    },
    'incident-gpai9-malformed': {
        "domain": 'incident',
        "code": 'incident-gpai9-malformed',
        "human": 'GPAI Code ch.9 artifact: malformed input (bad incident '
                 'shape, unknown class/stage/awareness basis, non-UTC '
                 'timestamp); refused fail-closed, never coerced',
        "severity": 'medium',
        "evidence_kinds_required": ['incident'],
        "reverify_steps": ['validate-input-shape'],
    },
    'incident-gpai9-retention-violation': {
        "domain": 'incident',
        "code": 'incident-gpai9-retention-violation',
        "human": 'GPAI Code ch.9 Measure 9.4: disposal of incident '
                 'documentation before the 5-year floor (later of '
                 'documentation/incident date) refused fail-closed; '
                 'records are never silently dropped',
        "severity": 'medium',
        "evidence_kinds_required": ['incident'],
        "reverify_steps": ['check-retention-floor'],
    },
    'incident-illegal-transition': {
        "domain": 'incident',
        "code": 'incident-illegal-transition',
        "human": 'incident lifecycle: transition between the two states is '
                 'not legal; refused fail-closed, state unchanged',
        "severity": 'medium',
        "evidence_kinds_required": ['incident', 'journal'],
        "reverify_steps": ['replay-journal', 'check-transition-table'],
    },
    'incident-malformed': {
        "domain": 'incident',
        "code": 'incident-malformed',
        "human": 'incident lifecycle: malformed input (bad id, title, '
                 'role, task, notification, postmortem shape, or duplicate '
                 'id); refused fail-closed, never coerced',
        "severity": 'medium',
        "evidence_kinds_required": ['incident'],
        "reverify_steps": ['validate-input-shape'],
    },
    'incident-open-findings': {
        "domain": 'incident',
        "code": 'incident-open-findings',
        "human": 'incident lifecycle: resolve refused while linked '
                 'findings are open, unknown, or unanswerable '
                 '(fail-closed); refusal journaled',
        "severity": 'medium',
        "evidence_kinds_required": ['incident', 'journal'],
        "reverify_steps": ['replay-journal', 'check-finding-status'],
    },
    'incident-open-tasks': {
        "domain": 'incident',
        "code": 'incident-open-tasks',
        "human": 'incident lifecycle: resolve refused while tasks are '
                 'incomplete; refusal journaled',
        "severity": 'medium',
        "evidence_kinds_required": ['incident', 'journal'],
        "reverify_steps": ['replay-journal', 'check-tasks-done'],
    },
    'incident-premature-postmortem': {
        "domain": 'incident',
        "code": 'incident-premature-postmortem',
        "human": 'incident lifecycle: postmortem attached before the '
                 'incident was contained or resolved; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['incident', 'journal'],
        "reverify_steps": ['replay-journal', 'check-state'],
    },
    'incident-unknown': {
        "domain": 'incident',
        "code": 'incident-unknown',
        "human": 'incident lifecycle: reference to an unknown incident or '
                 'task id; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['incident'],
        "reverify_steps": ['check-id-exists'],
    },
    'inclusion-receipt-malformed': {
        "domain": 'receipt',
        "code": 'inclusion-receipt-malformed',
        "human": 'receipt: the inclusion receipt fails the envelope grammar '
                 '(unknown format tag, bad field types, index out of range); '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'ingest-admit': {
        "domain": 'ingest',
        "code": 'ingest-admit',
        "human": 'evidence-ingest gate: sealed bundle passed transparency, '
                 'issuance, revision-binding and staleness checks; admitted',
        "severity": 'low',
        "evidence_kinds_required": ['sealed-bundle'],
        "reverify_steps": ['recheck-transparency', 'recheck-issuance'],
    },
    'ingest-freshness-invalid': {
        "domain": 'ingest',
        "code": 'ingest-freshness-invalid',
        "human": 'evidence-ingest gate: freshness annotation present but '
                 'invalid (bad signature, wrong issuer, expired or '
                 'future-dated); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['sealed-bundle', 'freshness-annotation'],
        "reverify_steps": ['recheck-annotation-signature',
                           'recheck-annotation-ttl'],
    },
    'ingest-issuance-unverifiable': {
        "domain": 'ingest',
        "code": 'ingest-issuance-unverifiable',
        "human": 'evidence-ingest gate: issuance attestation missing or '
                 'unverifiable; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['sealed-bundle', 'issuance'],
        "reverify_steps": ['recheck-issuance'],
    },
    'ingest-malformed': {
        "domain": 'ingest',
        "code": 'ingest-malformed',
        "human": 'evidence-ingest gate: submission malformed; refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['sealed-bundle'],
        "reverify_steps": ['recheck-bundle-shape'],
    },
    'ingest-producer-unauthorized': {
        "domain": 'ingest',
        "code": 'ingest-producer-unauthorized',
        "human": 'evidence-ingest gate: producer-authorization claim failed '
                 '(attestation signature invalid or issuer not authorized); '
                 'refused fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['sealed-bundle', 'producer-cert'],
        "reverify_steps": ['recheck-producer-authorization'],
    },
    'ingest-revision-unbound': {
        "domain": 'ingest',
        "code": 'ingest-revision-unbound',
        "human": 'evidence-ingest gate: bundle content not bound to any '
                 'registered revision; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['sealed-bundle', 'revision-binding'],
        "reverify_steps": ['recheck-revision-binding'],
    },
    'ingest-scan-error': {
        "domain": 'ingest',
        "code": 'ingest-scan-error',
        "human": 'evidence-ingest gate: background scan of an admitted '
                 'bundle errored; recorded loudly, never silently passed',
        "severity": 'high',
        "evidence_kinds_required": ['scan-report'],
        "reverify_steps": ['rerun-scan'],
    },
    'ingest-signature-unverified': {
        "domain": 'ingest',
        "code": 'ingest-signature-unverified',
        "human": 'evidence-ingest gate: sealed-bundle signature or '
                 'transparency inclusion unverifiable; refused fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['sealed-bundle', 'transparency-receipt'],
        "reverify_steps": ['recheck-transparency', 'recheck-signature'],
    },
    'ingest-stale-revision': {
        "domain": 'ingest',
        "code": 'ingest-stale-revision',
        "human": 'evidence-ingest gate: bundle references an audit-chain '
                 'revision older than the staleness horizon with no valid '
                 'freshness annotation; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['sealed-bundle', 'revision-binding'],
        "reverify_steps": ['recheck-revision-age'],
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
    'instruction-provenance-public-channel': {
        "domain": 'egress',
        "code": 'instruction-provenance-public-channel',
        "human": 'instruction authority requested for public-channel '
                 'provenance; public channels are untrusted input and can '
                 'never become instruction authority',
        "severity": 'high',
        "evidence_kinds_required": ['provenance'],
        "reverify_steps": ['recompute'],
    },
    'instruction-provenance-untrusted': {
        "domain": 'egress',
        "code": 'instruction-provenance-untrusted',
        "human": 'instruction authority requested for provenance outside '
                 'the trusted set; untrusted input can never become '
                 'instruction authority',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance'],
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
    'inventory-catalog-card-malformed': {
        "domain": 'inventory-catalog',
        "code": 'inventory-catalog-card-malformed',
        "human": 'inventory catalog: attached scorecard cards must be a '
                 'list of dicts; refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['signal'],
        "reverify_steps": ['recompute'],
    },
    'inventory-catalog-dangling-reference': {
        "domain": 'inventory-catalog',
        "code": 'inventory-catalog-dangling-reference',
        "human": 'inventory catalog: a relationship references an entry '
                 'name that does not exist; the catalog is refused '
                 'fail-closed, never loaded with silent orphans',
        "severity": 'medium',
        "evidence_kinds_required": ['signal'],
        "reverify_steps": ['recompute'],
    },
    'inventory-catalog-duplicate-entry': {
        "domain": 'inventory-catalog',
        "code": 'inventory-catalog-duplicate-entry',
        "human": 'inventory catalog: two entries share a name; refused '
                 'fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['signal'],
        "reverify_steps": ['recompute'],
    },
    'inventory-catalog-entry-malformed': {
        "domain": 'inventory-catalog',
        "code": 'inventory-catalog-entry-malformed',
        "human": 'inventory catalog: the entry or catalog shape is not '
                 'well-formed; it is refused instead of guessed',
        "severity": 'low',
        "evidence_kinds_required": ['signal'],
        "reverify_steps": ['recompute'],
    },
    'inventory-catalog-grant-unresolved': {
        "domain": 'inventory-catalog',
        "code": 'inventory-catalog-grant-unresolved',
        "human": 'inventory catalog: a grant relationship is not confirmed '
                 'by the grants provider; refused, never assumed',
        "severity": 'medium',
        "evidence_kinds_required": ['signal', 'grant'],
        "reverify_steps": ['recompute'],
    },
    'inventory-catalog-seam-unavailable': {
        "domain": 'inventory-catalog',
        "code": 'inventory-catalog-seam-unavailable',
        "human": 'inventory catalog: grant relationships require a '
                 'deployment-supplied grants provider; the seam is '
                 'unavailable so grants are refused fail-closed, never '
                 'auto-passed',
        "severity": 'medium',
        "evidence_kinds_required": ['signal'],
        "reverify_steps": ['recompute'],
    },
    'inventory-catalog-unknown-entry': {
        "domain": 'inventory-catalog',
        "code": 'inventory-catalog-unknown-entry',
        "human": 'inventory catalog: operation names an entry that is not '
                 'in the catalog; refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['signal'],
        "reverify_steps": ['recompute'],
    },
    'inventory-identity-collision': {
        "domain": 'inventory-query',
        "code": 'inventory-identity-collision',
        "human": 'an inventory table seed or extension-provider fetch '
                 'contained two rows with the same identity; the rows '
                 'would silently shadow (last-write-wins) and hide '
                 'content from the drift audit; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'inventory-pack-drift': {
        "domain": 'inventory-query',
        "code": 'inventory-pack-drift',
        "human": 'a scheduled inventory query pack drifted from its '
                 'pinned rows (content changed under a pinned identity); '
                 'the row is held fail-closed until re-pinned',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'inventory-pack-unpinned': {
        "domain": 'inventory-query',
        "code": 'inventory-pack-unpinned',
        "human": 'a query pack was executed without a committed pin; '
                 'packs never establish a new baseline silently; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'inventory-provider-failed': {
        "domain": 'inventory-query',
        "code": 'inventory-provider-failed',
        "human": 'an inventory extension provider crashed or '
                 'violated the closed provider API (bad table list, '
                 'non-list rows); the table is unobservable, so the '
                 'query refuses fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'inventory-row-malformed': {
        "domain": 'inventory-query',
        "code": 'inventory-row-malformed',
        "human": 'an inventory table row failed shape validation '
                 '(unknown table, undeclared column, missing identity '
                 'column, non-JSON value); refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'inventory-schema-mismatch': {
        "domain": 'inventory-query',
        "code": 'inventory-schema-mismatch',
        "human": 'an inventory table or extension provider declared a '
                 'schema version other than the pinned version, or named '
                 'an unknown table; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'inventory-unregistered': {
        "domain": 'inventory-query',
        "code": 'inventory-unregistered',
        "human": 'a scheduled inventory query pack observed a row with '
                 'no pin (first sighting); the discovery plane is '
                 'untrusted, so the row is held fail-closed until '
                 'first pinned',
        "severity": 'medium',
        "evidence_kinds_required": ['pin', 'refusal-record'],
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
    'issuance-monitor-misissuance': {
        "domain": 'issuance',
        "code": 'issuance-monitor-misissuance',
        "human": 'issuance monitoring: the signed monitor report carries '
                 'misissuance findings (unexpected issuer key, rid '
                 'collision, cross-issuer duplicate, out-of-window '
                 'issuance, or malformed entries), or the monitor report '
                 'itself is unverifiable; detection feeds revocation',
        "severity": 'high',
        "evidence_kinds_required": ['issuance-log', 'signature',
                                   'monitor-report'],
        "reverify_steps": ['verify-signature', 'check-revocation'],
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
    'jwks-issuer-unpinned': {
        "domain": 'jwks',
        "code": 'jwks-issuer-unpinned',
        "human": 'no pinned issuer origin supplied for a JWKS fetch; '
                 'refused rather than fetching unpinned key material',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'jwks-origin-mismatch': {
        "domain": 'jwks',
        "code": 'jwks-origin-mismatch',
        "human": 'the JWKS request URL origin does not match the pinned '
                 'issuer origin; refused before any transport call',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'jwks-redirect-refused': {
        "domain": 'jwks',
        "code": 'jwks-redirect-refused',
        "human": 'a JWKS fetch response carried a redirect (3xx status or '
                 'Location header); refused without contacting the redirect '
                 'destination -- redirects are never followed for key '
                 'material',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'jwks-transport-failed': {
        "domain": 'jwks',
        "code": 'jwks-transport-failed',
        "human": 'the deployment transport raised, returned a malformed '
                 'response, or returned a non-2xx status; refused rather '
                 'than treating it as key material',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'jwks-url-malformed': {
        "domain": 'jwks',
        "code": 'jwks-url-malformed',
        "human": 'the JWKS request URL or pinned origin is not a '
                 'well-formed absolute http(s) URL; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
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
    'key-in-agent-process': {
        "domain": 'attested-channel',
        "code": 'key-in-agent-process',
        "human": 'emitting context declares direct key access inside the agent process',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'key-swap-refused': {
        "domain": 'authorization_receipt',
        "code": 'key-swap-refused',
        "human": 'authorization receipt: a key substitution was detected and refused',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'keygroup-malformed': {
        "domain": 'envelope',
        "code": 'keygroup-malformed',
        "human": 'key-group envelope: the key-group envelope bytes are '
                 'structurally invalid (bad magic, truncated header/groups/'
                 'wraps/ciphertext, bad lengths); refused before any '
                 'key-dependent work',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keygroup-open-refused': {
        "domain": 'envelope',
        "code": 'keygroup-open-refused',
        "human": 'key-group envelope: open refused under the single '
                 'generic code (wrong key material, sub-quorum shares, '
                 'tampered tag/header/ciphertext, or no share usable '
                 'under the caller scope); failure does not leak which '
                 'check or which share failed',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keygroup-scope-mismatch': {
        "domain": 'envelope',
        "code": 'keygroup-scope-mismatch',
        "human": 'key-group envelope: the caller-provided scope matches '
                 'no declared key-group entry; entries bound to other '
                 'scopes are not attempted, refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keygroup-seal-refused': {
        "domain": 'envelope',
        "code": 'keygroup-seal-refused',
        "human": 'key-group envelope: seal refused (empty group list, '
                 'zero-member group, bad quorum, duplicate key id, '
                 'conflicting scopes for one key id, or weak key '
                 'material)',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keygroup-unknown-key-id': {
        "domain": 'envelope',
        "code": 'keygroup-unknown-key-id',
        "human": 'key-group envelope: open presented a key id the '
                 'envelope never declared; unknown key ids are refused '
                 'explicitly, never silently skipped',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keygroup-version-unknown': {
        "domain": 'envelope',
        "code": 'keygroup-version-unknown',
        "human": 'key-group envelope: the envelope version is not '
                 'supported; refused before any key-dependent work',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keyset-bad-template': {
        "domain": 'kms',
        "code": 'keyset-bad-template',
        "human": 'kms master-key keyset: unknown or versionless key '
                 'template (templates bind the primitive choice to a '
                 'version; undeclared primitives are refused)',
        "severity": 'low',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keyset-ceremony-incomplete': {
        "domain": 'kms',
        "code": 'keyset-ceremony-incomplete',
        "human": 'kms master-key keyset: rotation ceremony refused -- a '
                 'ceremony is already in progress, the phase does not '
                 'permit the step (e.g. promote before roll-out '
                 'verification), or there is no ceremony to abandon',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keyset-duplicate-key': {
        "domain": 'kms',
        "code": 'keyset-duplicate-key',
        "human": 'kms master-key keyset: duplicate key id refused at '
                 'declaration or parse time (no shadowing, no silent '
                 'override)',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keyset-key-destroyed': {
        "domain": 'kms',
        "code": 'keyset-key-destroyed',
        "human": 'kms master-key keyset: operation refused -- the key is '
                 'DESTROYED (terminal; refuses wrap, unwrap, and every '
                 'further transition)',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keyset-key-disabled': {
        "domain": 'kms',
        "code": 'keyset-key-disabled',
        "human": 'kms master-key keyset: operation refused -- the key is '
                 'DISABLED (no new wraps; old records still verify)',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keyset-pin-key-invalid': {
        "domain": 'kms',
        "code": 'keyset-pin-key-invalid',
        "human": 'kms master-key keyset: pin-key problem -- the keyed-MAC '
                 'pin key is missing, the wrong size, or its file is '
                 'unreadable (the keyset_digest pin can neither be '
                 'recomputed nor verified without the deployment-held '
                 'pin key)',
        "severity": 'low',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },

    'keyset-primary-not-enabled': {
        "domain": 'kms',
        "code": 'keyset-primary-not-enabled',
        "human": 'kms master-key keyset: the designated primary is not '
                 'enabled, or an operation would leave the keyset without '
                 'an enabled primary (destroy/disable the primary without '
                 'a promoted successor)',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keyset-unknown-key': {
        "domain": 'kms',
        "code": 'keyset-unknown-key',
        "human": 'kms master-key keyset: unknown key id (or malformed '
                 'keyset document); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keyset-verify-failed': {
        "domain": 'kms',
        "code": 'keyset-verify-failed',
        "human": 'kms master-key keyset: verification failed -- digest '
                 'mismatch on the keyset document, broken audit chain, or '
                 'exhausted roll-out verification window',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keysuccession-invalid-transition': {
        "domain": 'keysuccession',
        "code": 'keysuccession-invalid-transition',
        "human": 'key-succession ceremony: invalid transition -- a '
                 'transition record with a bad signature, a tampered body, '
                 'a replayed record, a double begin, or material signed by '
                 'a key the ceremony has not authorized (e.g. the successor '
                 'key before completing, or a signature under neither key); '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keysuccession-phase-skipped': {
        "domain": 'keysuccession',
        "code": 'keysuccession-phase-skipped',
        "human": 'key-succession ceremony: phase skip refused -- every '
                 'transition moves exactly one phase forward '
                 '(none -> preparing -> prepared -> completing -> '
                 'completed); skipping a phase is refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keysuccession-retired-reuse': {
        "domain": 'keysuccession',
        "code": 'keysuccession-retired-reuse',
        "human": 'key-succession ceremony: reuse of the retired old key '
                 'refused LOUD -- a revocation EVENT, not an authentication '
                 'failure (old key used after the overlap window closed or '
                 'after the ceremony completed)',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'keysuccession-window-missing': {
        "domain": 'keysuccession',
        "code": 'keysuccession-window-missing',
        "human": 'key-succession ceremony: entering completing without a '
                 'bounded overlap window refused -- the window is mandatory '
                 '(1s .. 30 days); there is no unbounded overlap',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
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
    'label-annotation-unregistered': {
        "domain": 'label',
        "code": 'label-annotation-unregistered',
        "human": 'trajectory label fold: the tool has no '
                 'deployment-declared annotation in the registry; refusing '
                 'to fold an undeclared tool surface (fail closed, '
                 'F427-style truth binding)',
        "severity": 'high',
        "evidence_kinds_required": ['tool-name', 'registry'],
        "reverify_steps": ['recompute'],
    },
    'label-egress-refused': {
        "domain": 'label',
        "code": 'label-egress-refused',
        "human": 'trajectory label check: the proposed recipient is '
                 'outside the trajectory audience; refusing with a '
                 'structured remedy plan (authorize/accept/withhold/'
                 'sanitize/derive/redispatch/fork)',
        "severity": 'high',
        "evidence_kinds_required": ['trajectory-digest', 'remedy-plan'],
        "reverify_steps": ['recompute'],
    },
    'label-remedy-empty-unliftable': {
        "domain": 'label',
        "code": 'label-remedy-empty-unliftable',
        "human": 'trajectory label check: the trajectory carries the '
                 'absolute-deny mark; no authority can permit the dispatch; '
                 'the EMPTY remedy plan is the proof of unliftability, '
                 'relative to the implemented remedy vocabulary version '
                 'bound in the plan digest',
        "severity": 'high',
        "evidence_kinds_required": ['trajectory-digest', 'remedy-plan'],
        "reverify_steps": ['recompute'],
    },
    'label-trust-floor-refused': {
        "domain": 'label',
        "code": 'label-trust-floor-refused',
        "human": 'trajectory label check: the trajectory trust tier is '
                 'below the recipient trust floor; refusing with a '
                 'structured remedy plan',
        "severity": 'high',
        "evidence_kinds_required": ['trajectory-digest', 'remedy-plan'],
        "reverify_steps": ['recompute'],
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
    'lineage-gap': {
        "domain": 'evaluation',
        "code": 'lineage-gap',
        "human": 'evaluation lineage: a link skips its predecessor '
                 'challenge or the genesis does not bind the expected '
                 'anchor; the chain is broken, not shortened',
        "severity": 'high',
        "evidence_kinds_required": ['lineage-record'],
        "reverify_steps": ['recompute'],
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
    'mandate-constraint-exceeded': {
        "domain": 'mandate',
        "code": 'mandate-constraint-exceeded',
        "human": 'bounded mandate: a closed mandate exceeded an open '
                 'mandate constraint (tool outside the allowlist, or '
                 'cumulative cost over the spend cap); refused at the '
                 'audit seam',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mandate-expired': {
        "domain": 'mandate',
        "code": 'mandate-expired',
        "human": 'bounded mandate: the action was executed outside the '
                 'open mandate time window, or the window had closed at '
                 'verification time; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mandate-malformed': {
        "domain": 'mandate',
        "code": 'mandate-malformed',
        "human": 'bounded mandate: a malformed open mandate, proposal, '
                 'closed action, or MAC key; refused before any '
                 'verification',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mandate-replay': {
        "domain": 'mandate',
        "code": 'mandate-replay',
        "human": 'bounded mandate: a closed mandate was presented twice; '
                 'the second presentation is a replay; refused',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mandate-tampered': {
        "domain": 'mandate',
        "code": 'mandate-tampered',
        "human": 'bounded mandate: a mandate MAC failed to verify, the '
                 'closed-mandate hash chain is broken, or the action '
                 'claims a future execution time; refused',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mandate-unknown': {
        "domain": 'mandate',
        "code": 'mandate-unknown',
        "human": 'bounded mandate: a closed mandate bound to a different '
                 'open mandate than the one presented; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mandate-version-mismatch': {
        "domain": 'mandate',
        "code": 'mandate-version-mismatch',
        "human": 'bounded mandate: a mandate carried an unknown type '
                 'version; implementations must match the exact type '
                 'string, so it is refused before interpretation',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
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
    'manifest-regex-unsafe': {
        "domain": 'manifest',
        "code": 'manifest-regex-unsafe',
        "human": 'attack manifest: a matcher/extractor regex was refused '
                 'at load: static analysis found nested-quantifier '
                 'ambiguity (a ReDoS shape); fail-closed, the pattern '
                 'never reaches the matching engine',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'manifest-selection-invalid': {
        "domain": 'manifest',
        "code": 'manifest-selection-invalid',
        "human": 'attack manifest: a -tc selection expression failed to '
                 'parse or named an unknown field; refused fail-closed '
                 '(never silently select everything or nothing)',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'manifest-signature-invalid': {
        "domain": 'manifest',
        "code": 'manifest-signature-invalid',
        "human": 'attack manifest: an Ed25519 template signature failed '
                 'verification (tampered body, wrong key, or bad envelope); '
                 'refused before any matcher evaluated',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'message', 'key'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'manifest-template-malformed': {
        "domain": 'manifest',
        "code": 'manifest-template-malformed',
        "human": 'attack manifest: a template failed schema validation '
                 '(bad id/version, unknown severity, bad matcher or '
                 'extractor shape); refused at load, never at run',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'manifest-template-unsigned': {
        "domain": 'manifest',
        "code": 'manifest-template-unsigned',
        "human": 'attack manifest: an unsigned template was aimed at a '
                 'production trust target without a recorded explicit '
                 'opt-out; refused (unsigned templates run only against '
                 'isolated fixtures)',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
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
    'mcp-oauth-binding-tampered': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-binding-tampered',
        "human": "the sealed authorization-server binding's MAC does "
                 'not cover its bytes; refused as tamper, never as a '
                 'shape gap',
        "severity": 'high',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-binding-mismatch': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-binding-mismatch',
        "human": 'the fetched CIMD document client_id does not string-equal the client_id URL it was fetched from (draft-02 section 4 binding rule; comparisons are simple string comparisons per RFC 3986 section 6.2.1), or the presented document does not match the pinned document bytes; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-credential-present': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-credential-present',
        "human": 'the CIMD document carries a client_secret* member (credential smuggling via metadata; the deployment handles no client secrets at all); refused, never ignored, fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['binding', 'credential-label'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-document-malformed': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-document-malformed',
        "human": 'the CIMD document violates the emission/shape contract (not a record, client_id missing or failing URL shape, private_key_jwt without a discoverable https jwks_uri, logo_uri not https); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-fetch-non200': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-fetch-non200',
        "human": 'the CIMD fetch did not return a 200 OK document (non-200 status or transport failure); the intake aborts without a document; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-fetch-redirect': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-fetch-redirect',
        "human": 'the CIMD fetch returned a redirect (3xx or Location); the pre-registration intake never follows redirects (draft-02 section 5); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-fetch-ssrf-range': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-fetch-ssrf-range',
        "human": 'the client_id URL resolved to an address or domain outside the deployment fetch trust (RFC 6890 special-use range, DNS-rebind IP mismatch, or domain outside the configured allowlist); the fetch does not happen; refused fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-fetch-timeout': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-fetch-timeout',
        "human": 'the CIMD fetch exceeded the deployment-configured timeout; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-fetch-too-large': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-fetch-too-large',
        "human": 'the fetched CIMD document exceeded the 5 KB read cap (draft-02 section 8.7); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-redirect-origin-mismatch': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-redirect-origin-mismatch',
        "human": 'a redirect_uri in the CIMD document is not https or is not same-origin with the document origin (the deployment unconditional section 8.1 restriction, applied symmetrically inbound); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-url-dot-segment': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-url-dot-segment',
        "human": 'the CIMD client_id URL path contains a dot or dot-dot segment, which draft-02 section 3 forbids (path traversal in the identifier); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-url-fragment': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-url-fragment',
        "human": 'the CIMD client_id URL carries a fragment component, which draft-02 section 3 forbids (fragments are never sent to the server; the identifier would not address the document); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-url-not-https': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-url-not-https',
        "human": 'the CIMD client_id URL is not a valid https URL per the draft-02 section 3 shape (wrong scheme, invalid syntax, or raw control characters); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-url-query': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-url-query',
        "human": 'the CIMD client_id URL carries a query component (stricter than the draft SHOULD-NOT; a query-bearing identifier is not a stable document address); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-url-root-path': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-url-root-path',
        "human": 'the CIMD client_id URL has an empty or root path (stricter than the draft NOT-RECOMMENDED; a root-path document collides with site content and cannot be bound to a single client); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-cimd-url-userinfo': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-cimd-url-userinfo',
        "human": 'the CIMD client_id URL carries a userinfo component, which draft-02 section 3 forbids (credential smuggling in the identifier); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-credential-misbound': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-credential-misbound',
        "human": 'a credential stored under one authorization server is '
                 'presented at another authorization server\'s token '
                 'endpoint; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding', 'credential-label'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-fix-gap-refused': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-fix-gap-refused',
        "human": 'issuer was omitted for a provider that requires it '
                 '(patched-but-vulnerable-by-configuration); refused '
                 'fail-closed, never silent fallback',
        "severity": 'high',
        "evidence_kinds_required": ['binding', 'gate-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-iss-mismatched': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-iss-mismatched',
        "human": 'the authorization response iss parameter names a '
                 'different issuer than the sealed authorization-server '
                 'binding (RFC 9207 mix-up shape); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding', 'authorization-response'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-iss-missing': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-iss-missing',
        "human": 'the authorization response carries no iss parameter '
                 '(RFC 9207 requires the authorization server to send '
                 'it); the issuing server cannot be identified; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding', 'authorization-response'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-issuer-unbound': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-issuer-unbound',
        "human": "the token endpoint's origin is not the bound "
                 "authorization server's origin nor a "
                 "deployment-declared alternate; refused fail-closed",
        "severity": 'high',
        "evidence_kinds_required": ['binding', 'endpoint'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-issuer-unverified': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-issuer-unverified',
        "human": 'the issuer hint or server metadata names a different '
                 'issuer than the sealed authorization-server binding; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding', 'metadata'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-key-missing': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-key-missing',
        "human": 'no deployment key supplied for the OAuth binding; '
                 'failing closed (no dev-key fallback)',
        "severity": 'medium',
        "evidence_kinds_required": ['key-reference'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-metadata-malformed': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-metadata-malformed',
        "human": 'a presented runtime input (binding wrapper, endpoint, '
                 'issuer hint, metadata, flag) is malformed; refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-prm-challenge-malformed': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-prm-challenge-malformed',
        "human": 'the WWW-Authenticate header carries no usable '
                 'resource_metadata parameter (RFC 9728 section 5.1); '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },    'mcp-oauth-prm-cross-origin': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-prm-cross-origin',
        "human": 'the resource_metadata URL is not same-origin as the '
                 'deployment-configured resource server; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },    'mcp-oauth-prm-fetch-refused': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-prm-fetch-refused',
        "human": 'the PRM fetch was refused: no fetcher supplied, the '
                 'fetcher failed, or the URL failed the SSRF guards '
                 '(RFC 9728 section 7.7); no implicit network, refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },    'mcp-oauth-prm-issuer-unlisted': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-prm-issuer-unlisted',
        "human": 'the PRM authorization_servers list is present but does '
                 'not list the sealed binding issuer (AS-substitution '
                 'shape); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['binding', 'prm-document'],
        "reverify_steps": ['recompute'],
    },    'mcp-oauth-prm-malformed': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-prm-malformed',
        "human": 'a protected resource metadata document, PRM URL, or '
                 'resource identifier is malformed (RFC 9728 shape '
                 'validation); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['prm-document', 'gate-record'],
        "reverify_steps": ['recompute'],
    },    'mcp-oauth-prm-resource-mismatched': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-prm-resource-mismatched',
        "human": 'the PRM document resource value is not the '
                 'deployment-configured resource identifier (RFC 9728 '
                 'section 3.3 impersonation shape); the data MUST NOT be '
                 'used; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['prm-document', 'resource'],
        "reverify_steps": ['recompute'],
    },    'mcp-oauth-resource-misbound': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-resource-misbound',
        "human": 'an access token bound to one protected resource is '
                 'presented at another (RFC 8707 cross-server replay); '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['token-claims', 'resource'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-resource-missing': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-resource-missing',
        "human": 'an access token carries no resource indicator for the '
                 'server it is presented to (RFC 8707); refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['token-claims', 'resource'],
        "reverify_steps": ['recompute'],
    },
    'mcp-oauth-verdict-mismatched': {
        "domain": 'mcp-oauth',
        "code": 'mcp-oauth-verdict-mismatched',
        "human": 'an OAuth verdict presented for a different token '
                 'endpoint than it was granted for; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['verdict', 'gate-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-insufficient-scope': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-insufficient-scope',
        "human": 'mcp-server-auth: the bearer token is valid but its '
                 'scope does not cover every required scope; HTTP 403 '
                 'with insufficient_scope',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-issuer-mismatched': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-issuer-mismatched',
        "human": 'mcp-server-auth: the token iss names a different '
                 'issuer than the deployment-configured trusted issuer; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-issuer-missing': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-issuer-missing',
        "human": 'mcp-server-auth: the token carries no iss claim; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-malformed': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-malformed',
        "human": 'mcp-server-auth: the Authorization header is not a '
                 'well-formed Bearer credential, or a token claim has '
                 'an unparseable shape; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-missing-token': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-missing-token',
        "human": 'mcp-server-auth: no bearer token presented with the '
                 'request; HTTP 401 with WWW-Authenticate challenge',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-resource-misbound': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-resource-misbound',
        "human": 'mcp-server-auth: the token names a different protected '
                 'resource than this server (RFC 8707 cross-server '
                 'replay); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-resource-missing': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-resource-missing',
        "human": 'mcp-server-auth: the token carries no RFC 8707 '
                 'resource indicator (nor RFC 9068 aud) for this '
                 'server; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-token-expired': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-token-expired',
        "human": 'mcp-server-auth: the token exp is at or before now; '
                 'HTTP 401',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-token-in-query': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-token-in-query',
        "human": 'mcp-server-auth: an access token traveled in the '
                 'query string; tokens must travel in the Authorization '
                 'header; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-token-invalid': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-token-invalid',
        "human": 'mcp-server-auth: the deployment token verifier '
                 'rejected the token; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mcp-server-auth-token-not-yet-valid': {
        "domain": 'mcp-server-auth',
        "code": 'mcp-server-auth-token-not-yet-valid',
        "human": 'mcp-server-auth: the token nbf is after now; HTTP 401',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
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
    'memory-composed-divergent': {
        "domain": 'memory_composed',
        "code": 'memory-composed-divergent',
        "human": 'memory composed: the bi-temporal store and the '
                 'reconciler disagree about a key (a second writer '
                 'touched one layer outside the composed path, or a '
                 'different store object was offered for a bound '
                 'namespace) -- refusing to serve a forked claim',
        "severity": 'critical',
        "evidence_kinds_required": ['reconciliation-record'],
        "reverify_steps": ['recompute'],
    },
    'memory-composed-key-invalid': {
        "domain": 'memory_composed',
        "code": 'memory-composed-key-invalid',
        "human": 'memory composed: the key is valid for the reconciler '
                 'but not representable in the bi-temporal store, whose '
                 'key grammar ([a-z][a-z0-9-]) is immutable -- the '
                 'composed path narrows to the store grammar fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['reconciliation-record'],
        "reverify_steps": ['recompute'],
    },
    'memory-composed-key-too-long': {
        "domain": 'memory_composed',
        "code": 'memory-composed-key-too-long',
        "human": 'memory composed: composed keys are bounded at 48 '
                 'chars (room for the tombstone-generation suffix '
                 'inside the store id grammar)',
        "severity": 'high',
        "evidence_kinds_required": ['reconciliation-record'],
        "reverify_steps": ['recompute'],
    },
    'memory-reconcile-conflict-unresolved': {
        "domain": 'memory_reconcile',
        "code": 'memory-reconcile-conflict-unresolved',
        "human": 'memory reconcile: an ADD arrived for a key that already '
                 'holds a live fact with a different value; ADD is not a '
                 'supersession -- use op=update or retract first',
        "severity": 'medium',
        "evidence_kinds_required": ['reconciliation-record'],
        "reverify_steps": ['recompute'],
    },
    'memory-reconcile-invalid': {
        "domain": 'memory_reconcile',
        "code": 'memory-reconcile-invalid',
        "human": 'memory reconcile: malformed record, forged signature, '
                 'missing snapshot-before-mutation, tombstoned recall, '
                 'divergent store history, or exceeded write-rate bound',
        "severity": 'high',
        "evidence_kinds_required": ['reconciliation-record', 'signature'],
        "reverify_steps": ['recompute', 'verify-signature'],
    },
    'memory-reconcile-poison-refused': {
        "domain": 'memory_reconcile',
        "code": 'memory-reconcile-poison-refused',
        "human": 'memory reconcile: an UPDATE contradicting a '
                 'high-reliability fact without corroboration >= 2 or a '
                 'signed archivist override; refused as poison',
        "severity": 'critical',
        "evidence_kinds_required": ['reconciliation-record'],
        "reverify_steps": ['recompute'],
    },
    'memory-reconcile-scope-missing': {
        "domain": 'memory_reconcile',
        "code": 'memory-reconcile-scope-missing',
        "human": 'memory reconcile: recall without a scope predicate; '
                 'there is no default scope',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'memory-reconcile-unauthorized-namespace': {
        "domain": 'memory_reconcile',
        "code": 'memory-reconcile-unauthorized-namespace',
        "human": 'memory reconcile: write or recall against an undeclared '
                 'namespace, a write not signed by the namespace owner, or '
                 'cross-namespace recall without a live sharing grant',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'memory-store-expired': {
        "domain": 'memory_store',
        "code": 'memory-store-expired',
        "human": 'memory store: no live record for the statement key at the requested instant -- the claim\'s validity window does not cover it',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'message'],
        "reverify_steps": ['recompute'],
    },
    'memory-store-invalid': {
        "domain": 'memory_store',
        "code": 'memory-store-invalid',
        "human": 'memory store: malformed episode, fact, or retraction -- shape, signature, provenance reference, or store bound violated; refused',
        "severity": 'high',
        "evidence_kinds_required": ['message'],
        "reverify_steps": ['recompute'],
    },
    'memory-store-retention-lapsed': {
        "domain": 'memory_store',
        "code": 'memory-store-retention-lapsed',
        "human": 'memory store: the record lapsed its declared retention schedule -- refused loud, never silently vanished',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'message'],
        "reverify_steps": ['recompute'],
    },
    'memory-store-tombstoned': {
        "domain": 'memory_store',
        "code": 'memory-store-tombstoned',
        "human": 'memory store: the claim was retracted via a signed tombstone -- the claim is withdrawn, not time-boxed; history remains queryable',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'signature'],
        "reverify_steps": ['verify-signature'],
    },
    'memory-store-unsigned-retraction': {
        "domain": 'memory_store',
        "code": 'memory-store-unsigned-retraction',
        "human": 'memory store: retraction is not signed by the claim\'s source key or a named archivist -- refused',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'message', 'key'],
        "reverify_steps": ['verify-signature', 'check-key-purpose'],
    },
    'mesh-auth-envelope-missing': {
        "domain": 'mesh-auth',
        "code": 'mesh-auth-envelope-missing',
        "human": 'mesh auth contract: a mesh call carried no auth '
                 'envelope; refused before routing',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mesh-auth-escalation-bypass': {
        "domain": 'mesh-auth',
        "code": 'mesh-auth-escalation-bypass',
        "human": 'mesh auth contract: a paused (AUTH_REQUIRED) task was '
                 'resumed with the old/weaker scheme instead of the '
                 'escalated one; refused, the task stays paused',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mesh-auth-malformed': {
        "domain": 'mesh-auth',
        "code": 'mesh-auth-malformed',
        "human": 'mesh auth contract: a malformed card declaration, '
                 'envelope, task id, or escalation record; refused '
                 'before any verification',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mesh-auth-not-owner': {
        "domain": 'mesh-auth',
        "code": 'mesh-auth-not-owner',
        "human": 'mesh auth contract: a task state transition '
                 '(escalate, resume, or abandon) was attempted by a '
                 'subject that is not the task owner recorded at '
                 'begin, or the task was begun without an owner and '
                 'so has no authorization anchor; refused, the task '
                 'state is unchanged',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mesh-auth-scheme-confusion': {
        "domain": 'mesh-auth',
        "code": 'mesh-auth-scheme-confusion',
        "human": 'mesh auth contract: a credential was presented under a '
                 'different scheme than the call requires (or the '
                 'payload does not match its declared scheme); schemes '
                 'are never substituted for each other',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mesh-auth-scope-uncovered': {
        "domain": 'mesh-auth',
        "code": 'mesh-auth-scope-uncovered',
        "human": 'mesh auth contract: the verified credential scopes do '
                 'not cover the scopes the call requires (exact-set); '
                 'refused at the call seam',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mesh-auth-subject-mismatch': {
        "domain": 'mesh-auth',
        "code": 'mesh-auth-subject-mismatch',
        "human": 'mesh auth contract: a scope ticket presented alongside '
                 'an authenticated subject is bound to a different '
                 'subject; refused',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mesh-auth-task-paused': {
        "domain": 'mesh-auth',
        "code": 'mesh-auth-task-paused',
        "human": 'mesh auth contract: a call against an AUTH_REQUIRED '
                 'task was refused without evaluating the envelope; the '
                 'task stays paused until re-auth with the required '
                 'scheme',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'mesh-auth-undeclared-scheme': {
        "domain": 'mesh-auth',
        "code": 'mesh-auth-undeclared-scheme',
        "human": 'mesh auth contract: the envelope scheme is not in the '
                 'callee card declared securitySchemes; refused '
                 'default-deny',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
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
    'no-effect-asserted-and-ignored': {
        "domain": 'permit',
        "code": 'no-effect-asserted-and-ignored',
        "human": 'bound permit: a signed no_effect on a non-failure '
                 'outcome was accepted and ignored (not a budget '
                 'release); named in the reconciliation record detail',
        "severity": 'medium',
        "evidence_kinds_required": ['reconciliation-record'],
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
    'obligation-malformed': {
        "domain": 'obligation',
        "code": 'obligation-malformed',
        "human": 'obligation binding: malformed obligation declaration '
                 'or fulfillment evidence; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['config-source'],
        "reverify_steps": ['recompute'],
    },
    'obligation-unfulfilled': {
        "domain": 'obligation',
        "code": 'obligation-unfulfilled',
        "human": 'obligation binding: a permit obligation declared at '
                 'issue has no fulfillment evidence at settlement; '
                 'obligations silently ignored at execution are refused',
        "severity": 'high',
        "evidence_kinds_required": ['execution-evidence'],
        "reverify_steps": ['recompute'],
    },
    'oci-artifact-type-mismatch': {
        "domain": 'oci',
        "code": 'oci-artifact-type-mismatch',
        "human": 'OCI distribution: candidate manifest artifactType is not '
                 'the expected Sasanam evidence artifactType; refused '
                 'fail-closed, never silently accepted',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'oci-blob-digest-mismatch': {
        "domain": 'oci',
        "code": 'oci-blob-digest-mismatch',
        "human": 'OCI distribution: bytes pulled by digest do not match the '
                 'descriptor (bytes differ, or the blob was not served) -- '
                 'recomputed evidence disagrees with the claim, treat as '
                 'possible tampering; refused fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'oci-bundle-not-verifiable': {
        "domain": 'oci',
        "code": 'oci-bundle-not-verifiable',
        "human": 'OCI referrer transport: the keyed bundle the caller asked '
                 'to attach is structurally unverifiable -- the offline '
                 'verifier cannot evaluate it (tlog/timestamp claims, a '
                 'messageSignature alongside the envelope, a non-keyed '
                 'payload type, more or fewer than one signature, a '
                 'missing DSSE envelope, or malformed verification '
                 'material); the builder attaches only bundles the verifier '
                 'can verify (wave-339 R22, Bernstein #6371); refused '
                 'fail-closed, never attached as bundle evidence',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'oci-layer-media-type-mismatch': {
        "domain": 'oci',
        "code": 'oci-layer-media-type-mismatch',
        "human": 'OCI referrer transport: the keyed-bundle layer is not the '
                 'Sigstore bundle media type '
                 '(application/vnd.dev.sigstore.bundle.v0.3+json) -- the '
                 'registry served, or the caller supplied, content that is '
                 'not a keyed Sigstore bundle; refused fail-closed, never '
                 'attached or pulled as bundle evidence',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'oci-manifest-malformed': {
        "domain": 'oci',
        "code": 'oci-manifest-malformed',
        "human": 'OCI distribution: manifest bytes from the registry fail '
                 'shape validation (not a subject-bearing OCI manifest); '
                 'the registry is untrusted, its bytes are validated before '
                 'any field is trusted; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'oci-referrers-malformed': {
        "domain": 'oci',
        "code": 'oci-referrers-malformed',
        "human": 'OCI distribution: the referrers discovery response is not '
                 'well-formed (non-object referrers body, non-object '
                 'subject, non-string entry digest, or non-list tag list); '
                 'the registry is untrusted, its bytes are validated before '
                 'any field is dereferenced; refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'oci-referrers-unavailable': {
        "domain": 'oci',
        "code": 'oci-referrers-unavailable',
        "human": 'OCI distribution: no referrer discovered for the subject '
                 'digest via the referrers API or the tag-schema fallback; '
                 'refused fail-closed, never a silent None',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'oci-registry-onboarding-refused': {
        "domain": 'oci',
        "code": 'oci-registry-onboarding-refused',
        "human": 'OCI registry onboarding gate: the registry endpoint or '
                 'distribution path is not certified for evidence '
                 'distribution -- live Referrers-API probe inconclusive, '
                 'probe disagrees with the trust matrix, unknown registry '
                 'kind, or a forbidden path (e.g. Harbor replication); '
                 'refused fail-closed, never distribute on an uncertified '
                 'path',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'oci-subject-mismatch': {
        "domain": 'oci',
        "code": 'oci-subject-mismatch',
        "human": 'OCI distribution: candidate manifest subject digest is not '
                 'the queried subject digest -- the registry served a '
                 'manifest for a different subject; refused fail-closed, '
                 'never returns the wrong evidence',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'oci-tag-refused': {
        "domain": 'oci',
        "code": 'oci-tag-refused',
        "human": 'OCI referrer transport: a tag (or other non-digest '
                 'reference) was supplied where a canonical digest is '
                 'required -- digest-only addressing by construction; tags '
                 'are mutable and can never be bundle identity; refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-anchor-invalid': {
        "domain": 'witness',
        "code": 'offline-verify-anchor-invalid',
        "human": 'offline evidence verifier: the bundle anchor receipt is '
                 'invalid -- its statement does not commit to this manifest, '
                 'its Merkle inclusion proof does not verify, or its log '
                 'signature does not verify under the pinned anchor key; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-anchor-key-mismatch': {
        "domain": 'witness',
        "code": 'offline-verify-anchor-key-mismatch',
        "human": 'offline evidence verifier: the manifest-pinned anchor log '
                 'key is not the trust-root-pinned key -- a self-consistent '
                 'receipt under an untrusted key proves nothing; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-anchor-unsupported': {
        "domain": 'witness',
        "code": 'offline-verify-anchor-unsupported',
        "human": 'offline evidence verifier: the bundle anchor adapter is '
                 'not verifiable by this tool (v1 verifies fake-log '
                 'receipts fully); refused fail-closed -- the auditor '
                 'cannot verify what it cannot check',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-bundle-digest-mismatch': {
        "domain": 'witness',
        "code": 'offline-verify-bundle-digest-mismatch',
        "human": 'offline evidence verifier: the recomputed bundle digest '
                 'does not match the witness layer (transplant refused) or '
                 'the exporter-recorded digest (post-export tampering); '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-chain-broken': {
        "domain": 'witness',
        "code": 'offline-verify-chain-broken',
        "human": 'offline evidence verifier: the unkeyed export chain does '
                 'not recompute to the anchored tip -- a ledger entry was '
                 'added, removed, or altered; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-containment': {
        "domain": 'witness',
        "code": 'offline-verify-containment',
        "human": 'offline evidence verifier: the exported window is not '
                 'fully present -- entry_count disagrees with the ledger; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-entry-signature-invalid': {
        "domain": 'witness',
        "code": 'offline-verify-entry-signature-invalid',
        "human": 'offline evidence verifier: a ledger entry signature does '
                 'not verify under the manifest-pinned entry-signer key, or '
                 'its key id does not match; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-internal': {
        "domain": 'witness',
        "code": 'offline-verify-internal',
        "human": 'offline evidence verifier: an unexpected internal failure '
                 'interrupted verification -- fails LOUD, never a success '
                 'signal; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-malformed': {
        "domain": 'witness',
        "code": 'offline-verify-malformed',
        "human": 'offline evidence verifier: the package, manifest, or layer '
                 'is malformed -- bad shape, unknown fields, bad digests, '
                 'or missing trusted time; refused fail-closed, never '
                 'defaulted',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-monotonicity': {
        "domain": 'witness',
        "code": 'offline-verify-monotonicity',
        "human": 'offline evidence verifier: ledger sequence numbers are '
                 'not strictly increasing by 1 over the window -- a gap or '
                 'reorder; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-policy-window': {
        "domain": 'witness',
        "code": 'offline-verify-policy-window',
        "human": 'offline evidence verifier: the newest cosignature time '
                 'falls outside the verified policy validity window -- a '
                 'policy valid now but issued after (or expired before) the '
                 'checkpoint was cosigned does not cover it; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-redaction-undisclosed': {
        "domain": 'witness',
        "code": 'offline-verify-redaction-undisclosed',
        "human": 'offline evidence verifier: a redacted ledger entry is not '
                 'listed in the redaction report -- silent redaction; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-trust-root-invalid': {
        "domain": 'witness',
        "code": 'offline-verify-trust-root-invalid',
        "human": 'offline evidence verifier: the caller-pinned trust root '
                 'is malformed -- policy signers, threshold, or anchor log '
                 'key missing or misshapen; refused fail-closed, never '
                 'defaulted',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-version-skew': {
        "domain": 'witness',
        "code": 'offline-verify-version-skew',
        "human": 'offline evidence verifier: the package or bundle format '
                 'version is not the supported v1; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-witness-layer-invalid': {
        "domain": 'witness',
        "code": 'offline-verify-witness-layer-invalid',
        "human": 'offline evidence verifier: the witness layer is rejected '
                 '-- checkpoint, cosignature quorum, proofs, policy, '
                 'freshness, or small carrier failed (inner coded reason '
                 'preserved); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'offline-verify-witness-layer-missing': {
        "domain": 'witness',
        "code": 'offline-verify-witness-layer-missing',
        "human": 'offline evidence verifier: the package carries no witness '
                 'layer -- the auditor tool requires the witness dimension; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'oidc-ambiguous-subject': {
        "domain": 'oidc',
        "code": 'oidc-ambiguous-subject',
        "human": 'evidence cert OIDC gate: the token payload carries '
                 'duplicate sub claims; the producer identity is ambiguous '
                 'and fails closed',
        "severity": 'high',
        "evidence_kinds_required": ['identity-assertion', 'jwks'],
        "reverify_steps": ['re-verify-token'],
    },
    'oidc-audience-mismatch': {
        "domain": 'oidc',
        "code": 'oidc-audience-mismatch',
        "human": 'evidence cert OIDC gate: the token aud does not include '
                 'this ceremony audience; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['identity-assertion', 'jwks'],
        "reverify_steps": ['re-verify-token'],
    },
    'oidc-issuer-mismatch': {
        "domain": 'oidc',
        "code": 'oidc-issuer-mismatch',
        "human": 'evidence cert OIDC gate: the token iss is not the '
                 'expected issuer; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['identity-assertion', 'jwks'],
        "reverify_steps": ['re-verify-token'],
    },
    'oidc-malformed-token': {
        "domain": 'oidc',
        "code": 'oidc-malformed-token',
        "human": 'evidence cert OIDC gate: the token is not a well-formed '
                 'three-part JWT with a JSON object header and payload; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-assertion'],
        "reverify_steps": ['re-verify-token'],
    },
    'oidc-missing-claim': {
        "domain": 'oidc',
        "code": 'oidc-missing-claim',
        "human": 'evidence cert OIDC gate: the token is missing one of the '
                 'required iss/aud/sub/exp claims; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-assertion'],
        "reverify_steps": ['re-verify-token'],
    },
    'oidc-signature-invalid': {
        "domain": 'oidc',
        "code": 'oidc-signature-invalid',
        "human": 'evidence cert OIDC gate: the token signature does not '
                 'verify against the issuer JWKS (wrong alg, unknown kid, '
                 'or bad signature); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['identity-assertion', 'jwks'],
        "reverify_steps": ['re-verify-token'],
    },
    'oidc-token-expired': {
        "domain": 'oidc',
        "code": 'oidc-token-expired',
        "human": 'evidence cert OIDC gate: the token exp is past now plus '
                 'the clock-skew bound; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-assertion'],
        "reverify_steps": ['re-verify-token'],
    },
    'oidc-token-required': {
        "domain": 'oidc',
        "code": 'oidc-token-required',
        "human": 'evidence cert OIDC gate: this CA requires an OIDC token '
                 'and none was presented; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['identity-assertion'],
        "reverify_steps": ['re-verify-token'],
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
    'oracle-could-not-evaluate': {
        "domain": 'oracle',
        "code": 'oracle-could-not-evaluate',
        "human": 'refusal-oracle guard: an authorization dependency was '
                 'unavailable so a path could not be evaluated; distinct '
                 'from evaluated-and-refused',
        "severity": 'medium',
        "evidence_kinds_required": ['authorization-request'],
        "reverify_steps": ['recompute'],
    },
    'oracle-evaluated-and-refused': {
        "domain": 'oracle',
        "code": 'oracle-evaluated-and-refused',
        "human": 'refusal-oracle guard: every authorization path was '
                 'evaluated and refused; the refusal names no path, '
                 'grant, or issuer standing',
        "severity": 'medium',
        "evidence_kinds_required": ['authorization-request'],
        "reverify_steps": ['recompute'],
    },
    'oracle-verifier-misconfigured': {
        "domain": 'oracle',
        "code": 'oracle-verifier-misconfigured',
        "human": 'refusal-oracle guard: the verifier configuration is '
                 'invalid; refusing loudly fail-closed instead of '
                 'authorizing',
        "severity": 'high',
        "evidence_kinds_required": ['authorization-request'],
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
    'package-advisory-flagged': {
        "domain": 'advisory',
        "code": 'package-advisory-flagged',
        "human": 'advisory flags a package whose signature verifies; '
                 'refused (a signature proves who signed, never safety)',
        "severity": 'high',
        "evidence_kinds_required": ['advisory', 'manifest', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'package-digest-first-seen-mismatch': {
        "domain": 'registry-acceptance',
        "code": 'package-digest-first-seen-mismatch',
        "human": 'package digest differs from the first-seen digest for '
                 'this name+version; the registry substituted bytes after '
                 'first observation; refused',
        "severity": 'critical',
        "evidence_kinds_required": ['manifest', 'package-bytes'],
        "reverify_steps": ['recompute'],
    },
    'package-digest-mismatch': {
        "domain": 'registry-acceptance',
        "code": 'package-digest-mismatch',
        "human": 'package bytes do not digest to the signed manifest digest',
        "severity": 'critical',
        "evidence_kinds_required": ['manifest', 'package-bytes'],
        "reverify_steps": ['recompute'],
    },
    'package-identity-name-untrusted': {
        "domain": 'registry-acceptance',
        "code": 'package-identity-name-untrusted',
        "human": 'policy declares trust by name (account/publisher/name '
                 'allowlist); trust is by pinned key identity, never by '
                 'name; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'package-manifest-malformed': {
        "domain": 'registry-acceptance',
        "code": 'package-manifest-malformed',
        "human": 'registry manifest is not the expected shape',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['recompute'],
    },
    'package-signature-invalid': {
        "domain": 'registry-acceptance',
        "code": 'package-signature-invalid',
        "human": 'manifest signature does not verify or is not from a trusted key',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'manifest'],
        "reverify_steps": ['recompute'],
    },
    'package-signer-compromised': {
        "domain": 'registry-acceptance',
        "code": 'package-signer-compromised',
        "human": 'a counted signature key is in the revocation set; the '
                 'signature verifies but the signer is known-compromised '
                 '(tamper-window shape); refused',
        "severity": 'critical',
        "evidence_kinds_required": ['manifest', 'signature', 'revocation'],
        "reverify_steps": ['recompute'],
    },
    'package-stale': {
        "domain": 'registry-acceptance',
        "code": 'package-stale',
        "human": 'manifest is outside its freshness window',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest'],
        "reverify_steps": ['recompute'],
    },
    'parameter-malformed': {
        "domain": 'parameter',
        "code": 'parameter-malformed',
        "human": 'parameter canonicalization: malformed command or '
                 'allowlist/denylist input; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['config-source'],
        "reverify_steps": ['recompute'],
    },
    'parameter-obfuscation': {
        "domain": 'parameter',
        "code": 'parameter-obfuscation',
        "human": 'parameter canonicalization: the canonical command '
                 'form contains a denied parameter the raw string '
                 'comparison would have missed; the canonical '
                 'comparison is authoritative',
        "severity": 'high',
        "evidence_kinds_required": ['command-bytes'],
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
    'pending-approval-resume-refused': {
        "domain": 'approval',
        "code": 'pending-approval-resume-refused',
        "human": 'durable pending-approval ledger: the resume was refused '
                 'fail-closed -- unknown approval id, already-decided '
                 'record, expired wait horizon, or malformed resume value; '
                 'a refused resume never executes',
        "severity": 'medium',
        "evidence_kinds_required": ['approval', 'ledger'],
        "reverify_steps": ['recompute'],
    },
    'pending-approval-snapshot-tampered': {
        "domain": 'approval',
        "code": 'pending-approval-snapshot-tampered',
        "human": 'durable pending-approval ledger: the parked snapshot '
                 'bytes no longer match the parked digest (recomputed '
                 'evidence disagrees with the claim); refuse-to-resume, '
                 'the record stays parked and never executes',
        "severity": 'critical',
        "evidence_kinds_required": ['approval', 'ledger', 'digest'],
        "reverify_steps": ['recompute'],
    },
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
    'permit-consume-store-not-durable': {
        "domain": 'permit',
        "code": 'permit-consume-store-not-durable',
        "human": 'bound permit: the consume store is not durable; the saha admission gate refuses permits unless the deployment explicitly opts into the single-node contract',
        "severity": 'high',
        "evidence_kinds_required": ['permit', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'permit-consume-store-unavailable': {
        "domain": 'permit',
        "code": 'permit-consume-store-unavailable',
        "human": 'bound permit: the consume store is unavailable; could-not-check names the consume-store dependency',
        "severity": 'high',
        "evidence_kinds_required": ['permit', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'permit-containment-malformed': {
        "domain": 'containment',
        "code": 'permit-containment-malformed',
        "human": 'delegation containment: the permit record or the bound '
                 'caps are malformed; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['permit'],
        "reverify_steps": ['recompute'],
    },
    'permit-currentness-could-not-check': {
        "domain": 'containment',
        "code": 'permit-currentness-could-not-check',
        "human": 'policy currentness: presentation-time currentness is '
                 'recognized in the claim vocabulary but the mechanism is '
                 'unavailable, so the claim reports could-not-check naming '
                 'the policy-currentness-authority dependency; never a '
                 'refusal, never "verified"',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-currentness'],
        "reverify_steps": ['recompute'],
    },
    'permit-currentness-violated': {
        "domain": 'permit',
        "code": 'permit-currentness-violated',
        "human": 'action-bound permit: the declared currentness mode '
                 '(e.g. fresh-at-use) was not satisfied at presentation',
        "severity": 'medium',
        "evidence_kinds_required": ['permit-record', 'freshness-evidence'],
        "reverify_steps": ['recompute'],
    },
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
    'permit-idempotency-conflict': {
        "domain": 'permit',
        "code": 'permit-idempotency-conflict',
        "human": 'bound permit: same (iss, jti) re-presented with a different content digest; refused, never a second release',
        "severity": 'high',
        "evidence_kinds_required": ['permit', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'permit-in-progress': {
        "domain": 'permit',
        "code": 'permit-in-progress',
        "human": 'bound permit: the effect for (iss, jti) is in progress elsewhere; the presentation is retryable, nothing consumed',
        "severity": 'medium',
        "evidence_kinds_required": ['permit', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'permit-instance-replay': {
        "domain": 'permit',
        "code": 'permit-instance-replay',
        "human": 'action-bound permit: the permit was replayed for a '
                 'different action instance than the bound one',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record', 'binding-digest'],
        "reverify_steps": ['recompute'],
    },
    'permit-journal-chain-broken': {
        "domain": 'permit-journal',
        "code": 'permit-journal-chain-broken',
        "human": 'permit journal: HMAC chain verification failed on '
                 'load -- an event was not made by a key holder or was '
                 'tampered after write; failed closed',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-journal-corrupted': {
        "domain": 'permit-journal',
        "code": 'permit-journal-corrupted',
        "human": 'permit journal: the underlying durable journal '
                 'failed verification (chain break, torn tail, or '
                 'missing snapshot sidecar); failed closed',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-journal-duplicate-event': {
        "domain": 'permit-journal',
        "code": 'permit-journal-duplicate-event',
        "human": 'permit journal: the event_id is already recorded; '
                 'appends are idempotent and replays refuse',
        "severity": 'medium',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-journal-key-weak': {
        "domain": 'permit-journal',
        "code": 'permit-journal-key-weak',
        "human": 'permit journal: the HMAC key is missing, malformed, '
                 'or shorter than 16 bytes; refused rather than '
                 'running with weak integrity',
        "severity": 'medium',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-journal-misuse': {
        "domain": 'permit-journal',
        "code": 'permit-journal-misuse',
        "human": 'permit journal: programmer misuse (bad argument '
                 'types, non-permit snapshot sidecar); refused '
                 'fail-closed rather than guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-journal-snapshot-tampered': {
        "domain": 'permit-journal',
        "code": 'permit-journal-snapshot-tampered',
        "human": 'permit journal: the snapshot fold was not made by a '
                 'key holder at the claimed tip (snapshot MAC '
                 'mismatch); failed closed',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-journal-transition-illegal': {
        "domain": 'permit-journal',
        "code": 'permit-journal-transition-illegal',
        "human": 'permit journal: the lifecycle transition is illegal '
                 '(second grant, or a transition on a terminal '
                 'permit); refused, permits never resurrect',
        "severity": 'medium',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-journal-unknown-permit': {
        "domain": 'permit-journal',
        "code": 'permit-journal-unknown-permit',
        "human": 'permit journal: no grant recorded for the permit id; '
                 'use/expire/revoke/finalize refuse before grant',
        "severity": 'medium',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-journal-write-conflict': {
        "domain": 'permit-journal',
        "code": 'permit-journal-write-conflict',
        "human": 'permit journal: the append lost the tip compare-and-'
                 'swap after 3 attempts; another writer holds the '
                 'journal -- retry the operation',
        "severity": 'medium',
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
    'permit-mandate-absent': {
        "domain": 'permit',
        "code": 'permit-mandate-absent',
        "human": 'bound permit: issuance attempted without a mandate '
                 'record; the mandate leg is absent so no permit issues',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record'],
        "reverify_steps": ['recompute'],
    },
    'permit-message-mismatch': {
        "domain": 'mcp',
        "code": 'permit-message-mismatch',
        "human": 'MCP invocation authorization: the recomputed value does not match the claimed value',
        "severity": 'critical',
        "evidence_kinds_required": ['message', 'permit', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'permit-no-effect-unattested': {
        "domain": 'permit',
        "code": 'permit-no-effect-unattested',
        "human": 'bound permit: an unsigned no_effect refusal does not establish no effect; the budget stays committed',
        "severity": 'medium',
        "evidence_kinds_required": ['permit', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'permit-no-fallback': {
        "domain": 'permit',
        "code": 'permit-no-fallback',
        "human": 'bound permit: permit absence is malformed; never a reason to accept another credential',
        "severity": 'high',
        "evidence_kinds_required": ['permit', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'permit-parent-named': {
        "domain": 'containment',
        "code": 'permit-parent-named',
        "human": 'delegation containment: a permit naming a parent_permit '
                 'reference is refused outright at admission; containment '
                 'must be proved against the parent bounds, not merely '
                 'claimed by reference',
        "severity": 'high',
        "evidence_kinds_required": ['permit'],
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
    'permit-presenter-mismatch': {
        "domain": 'permit',
        "code": 'permit-presenter-mismatch',
        "human": 'action-bound permit: the presenter key is not the bound key; '
                 'the permit names exactly one recipient key',
        "severity": 'high',
        "evidence_kinds_required": ['permit-record', 'binding-digest'],
        "reverify_steps": ['recompute'],
    },
    'permit-rate-budget-unreleasable': {
        "domain": 'permit',
        "code": 'permit-rate-budget-unreleasable',
        "human": 'bound permit: rate budgets are never released once committed',
        "severity": 'medium',
        "evidence_kinds_required": ['permit', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'permit-refusal-vocabulary-invalid': {
        "domain": 'permit',
        "code": 'permit-refusal-vocabulary-invalid',
        "human": 'action-bound permit: a refusal was raised (or declared) '
                 'with a reason outside the registered refusal vocabulary; '
                 'no ad-hoc refusal vocabulary is permitted',
        "severity": 'medium',
        "evidence_kinds_required": ['permit-record', 'refusal-record'],
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
    'permit-registry-unavailable': {
        "domain": 'permit',
        "code": 'permit-registry-unavailable',
        "human": 'bound permit: a re-issue binding cannot be checked without the permit registry; could-not-check names the permit-registry dependency',
        "severity": 'high',
        "evidence_kinds_required": ['permit', 'digest'],
        "reverify_steps": ['recompute-digest'],
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
    'permit-unknown': {
        "domain": 'permit',
        "code": 'permit-unknown',
        "human": 'permit lease: the identifier is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['permit', 'digest', 'revocation-registry', 'timestamp'],
        "reverify_steps": ['recompute-digest', 'check-expiry', 'check-revocation'],
    },
    'persistence-modification-refused': {
        "domain": 'spawn-context',
        "code": 'persistence-modification-refused',
        "human": 'a shell-rc target written by an unvouched source; only '
                 'deployment-vouched admin sources may modify rc files; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['persistence-record', 'provenance'],
        "reverify_steps": ['recompute', 'provenance-check'],
    },
    'pin-scope-insufficient': {
        "domain": 'advisory',
        "code": 'pin-scope-insufficient',
        "human": 'unscoped agent_cert pin grades asserted at most; '
                 're-pin with agent scope for verification evidence',
        "severity": 'medium',
        "evidence_kinds_required": ['pin'],
        "reverify_steps": ['recompute'],
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
    'plan-policy-capability': {
        "domain": 'workflow',
        "code": 'plan-policy-capability',
        "human": 'plan-policy admission: capability coverage violated -- '
                 'a unit hid an inherent tool-class capability behind a '
                 'weaker declaration, the plan envelope does not cover '
                 'the units\' declared capabilities, or the envelope '
                 'claims a capability the deployment policy does not allow',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'plan-policy-data-flow': {
        "domain": 'workflow',
        "code": 'plan-policy-data-flow',
        "human": 'plan-policy admission: a declared data flow is '
                 'incoherent (unknown producer, non-forward edge, '
                 'duplicate, or classification above the producer\u2019s '
                 'trust) or an implied intra-unit edge (slip leg->leg) '
                 'is undeclared or phantom-declared',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'plan-policy-manifest-missing': {
        "domain": 'workflow',
        "code": 'plan-policy-manifest-missing',
        "human": 'plan-policy admission: the plan carries no manifest -- '
                 'a plan submitted to the policy regime must declare its '
                 'units\' tools, capabilities, trust levels and data '
                 'flows',
        "severity": 'medium',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'plan-policy-not-admitted': {
        "domain": 'workflow',
        "code": 'plan-policy-not-admitted',
        "human": 'composed workflow: a plan carrying a policy manifest '
                 'was presented for execution without an admission '
                 'verdict for its exact digest -- admit_plan must run '
                 'first; a mutated plan presents a different digest and '
                 'is not admitted',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'plan-policy-trust-mixing': {
        "domain": 'workflow',
        "code": 'plan-policy-trust-mixing',
        "human": 'plan-policy admission: a data flow carries a '
                 'classification above the consumer\'s trust level '
                 'without a declared declassify entry -- trust-boundary '
                 'crossings must be declared with a reason',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'plan-policy-unknown-tool': {
        "domain": 'workflow',
        "code": 'plan-policy-unknown-tool',
        "human": 'plan-policy admission: a unit declares a tool outside '
                 'the fixed tool-class table -- capability cannot be '
                 'attributed to an unknown tool, so the plan refuses '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'poldist-bundle-malformed': {
        "domain": 'poldist',
        "code": 'poldist-bundle-malformed',
        "human": 'policy distribution: the bundle envelope is not '
                 'well-formed JSON or a required field (v, topic, '
                 'version, payload, sig) has the wrong shape; refused '
                 'before any verification, never applied',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['recheck-bundle-shape'],
    },
    'poldist-signature-mismatch': {
        "domain": 'poldist',
        "code": 'poldist-signature-mismatch',
        "human": 'policy distribution: the bundle Ed25519 signature '
                 'does not verify under the subscriber-pinned publisher '
                 'key (forgery, post-signing tamper, or key confusion); '
                 'refused, never applied',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'signature'],
        "reverify_steps": ['reverify-bundle-signature'],
    },
    'poldist-signature-missing': {
        "domain": 'poldist',
        "code": 'poldist-signature-missing',
        "human": 'policy distribution: the bundle carries no '
                 'well-formed Ed25519 signature (unsigned bundle); '
                 'refused, never applied',
        "severity": 'high',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['reverify-bundle-signature'],
    },
    'poldist-topic-cross': {
        "domain": 'poldist',
        "code": 'poldist-topic-cross',
        "human": 'policy distribution: the bundle topic is not the '
                 "subscriber's bound topic (unknown topic or cross-topic "
                 'replay); refused before any signature work, never '
                 'applied',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['recheck-topic-binding'],
    },
    'poldist-version-rollback': {
        "domain": 'poldist',
        "code": 'poldist-version-rollback',
        "human": 'policy distribution: the bundle version is older than '
                 'the loaded head, or the same version carries different '
                 'payload bytes (equivocation-shaped); the head is not '
                 'switched, the bundle is refused',
        "severity": 'high',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['recheck-bundle-version'],
    },
    'policy-authoring-compile-refused': {
        "domain": 'policy-authoring',
        "code": 'policy-authoring-compile-refused',
        "human": 'policy authoring: the compiled native policy was '
                 'refused by PolicyEngine on round-trip; the authored '
                 'source is not loadable, refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-authoring-conflicting-filters': {
        "domain": 'policy-authoring',
        "code": 'policy-authoring-conflicting-filters',
        "human": 'policy authoring: two filters in one AND conjunction '
                 'constrain the same match key; merging them would be a '
                 'UNION (weaker) contradicting the author AND, refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-authoring-empty': {
        "domain": 'policy-authoring',
        "code": 'policy-authoring-empty',
        "human": 'policy authoring: authored document has no policies; '
                 'refused fail-closed, never compiled to an empty set',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-authoring-malformed': {
        "domain": 'policy-authoring',
        "code": 'policy-authoring-malformed',
        "human": 'policy authoring: authored document is unparseable or '
                 'wrong-shaped (bad version, non-mapping filter/action, '
                 'mistyped value); refused fail-closed, never skipped',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-authoring-unknown-action': {
        "domain": 'policy-authoring',
        "code": 'policy-authoring-unknown-action',
        "human": 'policy authoring: unknown action type (known: deny, '
                 'allow, require-approval); refused fail-closed so a '
                 'misspelled action never compiles to a weaker effect',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-authoring-unknown-filter': {
        "domain": 'policy-authoring',
        "code": 'policy-authoring-unknown-filter',
        "human": 'policy authoring: unknown filter type or filter key; '
                 'refused fail-closed so a misspelled filter never '
                 'compiles to a weaker rule',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-authoring-unknown-op': {
        "domain": 'policy-authoring',
        "code": 'policy-authoring-unknown-op',
        "human": 'policy authoring: op not supported for the filter key; '
                 'refused fail-closed, never coerced',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-body-malformed': {
        "domain": 'policy',
        "code": 'policy-body-malformed',
        "human": 'policy compilation: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-boundary-exceeded': {
        "domain": 'policy',
        "code": 'policy-boundary-exceeded',
        "human": 'policy change: the candidate grants authority outside '
                 'the declared damage boundary; refused',
        "severity": 'high',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-change-capability-expansion': {
        "domain": 'policy',
        "code": 'policy-change-capability-expansion',
        "human": 'policy change: the candidate adds a new (method, path) '
                 'capability on a host:port the subject already reaches; '
                 'refused',
        "severity": 'high',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-change-credential-reach-expansion': {
        "domain": 'policy',
        "code": 'policy-change-credential-reach-expansion',
        "human": 'policy change: a subject newly gains reach to a '
                 'credential it had no reach to; refused',
        "severity": 'high',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-change-l7-bypass-credentialed': {
        "domain": 'policy',
        "code": 'policy-change-l7-bypass-credentialed',
        "human": 'policy change: the candidate adds L7 reach on a '
                 'deployment-declared credentialed host; refused',
        "severity": 'high',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-change-link-local-reach': {
        "domain": 'policy',
        "code": 'policy-change-link-local-reach',
        "human": 'policy change: the candidate newly reaches link-local, '
                 'loopback, or cloud-metadata endpoints; refused',
        "severity": 'high',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-change-malformed': {
        "domain": 'policy',
        "code": 'policy-change-malformed',
        "human": 'policy change: the input failed structural validation; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-change-uncheckable': {
        "domain": 'policy',
        "code": 'policy-change-uncheckable',
        "human": 'policy change: the delta uses a shape the static check '
                 'cannot model; refused fail-closed, never a vacuous pass',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-channel-activation-failed': {
        "domain": 'policy',
        "code": 'policy-channel-activation-failed',
        "human": 'policy channel: an orphaned activation tmp shows a crash '
                 'mid-activation; the previous policy stays in force, '
                 'reported loud',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'record'],
        "reverify_steps": ['recompute'],
    },
    'policy-channel-feed-escape': {
        "domain": 'policy',
        "code": 'policy-channel-feed-escape',
        "human": 'policy channel: a feed file escapes the feed directory '
                 'trust boundary; refused',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'record'],
        "reverify_steps": ['recompute'],
    },
    'policy-channel-malformed': {
        "domain": 'policy',
        "code": 'policy-channel-malformed',
        "human": 'policy channel: the policy envelope or document is '
                 'malformed; refused, never applied',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-channel-rollback': {
        "domain": 'policy',
        "code": 'policy-channel-rollback',
        "human": 'policy channel: the document version is not newer than '
                 'the applied floor; replay refused',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'record'],
        "reverify_steps": ['recompute'],
    },
    'policy-channel-stale': {
        "domain": 'policy',
        "code": 'policy-channel-stale',
        "human": 'policy channel: no refresh within the staleness budget; '
                 'the last verified policy is served loudly, never silently '
                 'trusted',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'record'],
        "reverify_steps": ['recompute'],
    },
    'policy-channel-superseded': {
        "domain": 'policy',
        "code": 'policy-channel-superseded',
        "human": 'policy channel: the document version was revoked; it is '
                 'never re-applied',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'record'],
        "reverify_steps": ['recompute'],
    },
    'policy-channel-unknown-policy': {
        "domain": 'policy',
        "code": 'policy-channel-unknown-policy',
        "human": 'policy channel: the document names a policy this channel '
                 'does not serve; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-channel-unsigned': {
        "domain": 'policy',
        "code": 'policy-channel-unsigned',
        "human": 'policy channel: the document signature does not verify '
                 'under the pinned feed key; refused, never applied',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'policy-channel-version-skip': {
        "domain": 'policy',
        "code": 'policy-channel-version-skip',
        "human": 'policy channel: the document version jumps beyond the '
                 'bounded skip window; refused (freeze/DoS bound)',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'record'],
        "reverify_steps": ['recompute'],
    },
    'policy-ci-companion-missing': {
        "domain": 'policy',
        "code": 'policy-ci-companion-missing',
        "human": 'policy CI: a policy change ships without its mandatory '
                 'companions (author, change note, declared probe battery); '
                 'refused fail-closed, never a bare policy change',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-ci-derived-tampered': {
        "domain": 'policy',
        "code": 'policy-ci-derived-tampered',
        "human": 'policy CI: a derived artifact was hand-edited or is stale '
                 'for the source (digest mismatch); refused fail-closed, '
                 'never served',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-ci-dryrun-skipped': {
        "domain": 'policy',
        "code": 'policy-ci-dryrun-skipped',
        "human": 'policy CI: enforcement attempted without a completed '
                 'dryrun observation window (no dryrun state, no signed '
                 'dryrun report, or window not elapsed); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-ci-invalid': {
        "domain": 'policy',
        "code": 'policy-ci-invalid',
        "human": 'policy CI: malformed policy source, artifact, or rollout '
                 'record (or forged dryrun report); refused fail-closed, '
                 'never a vacuous pass',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
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
    'policy-delta-allow-modified': {
        "domain": 'policy-delta',
        "code": 'policy-delta-allow-modified',
        "human": 'policy delta changes an allow (or require_approval) '
                 'rule match without provable widening; flagged for review, '
                 'verdict stays pass',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-allow-unforbidden': {
        "domain": 'policy-delta',
        "code": 'policy-delta-allow-unforbidden',
        "human": 'policy delta adds an allow rule no deny rule covers '
                 '(no tool overlap); flagged for review, verdict stays pass',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-check-removed': {
        "domain": 'policy-delta',
        "code": 'policy-delta-check-removed',
        "human": 'policy delta removes a require_approval rule; the human '
                 'check it imposed no longer applies; flagged for review',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-counterexample-raised': {
        "domain": 'policy-delta',
        "code": 'policy-delta-counterexample-raised',
        "human": 'policy delta counterexample: an expansion grant is '
                 'emitted as a concrete review artifact with its boundary '
                 'verdict and fired checks; queued for human review',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-default-deny': {
        "domain": 'policy-delta',
        "code": 'policy-delta-default-deny',
        "human": 'policy delta request engine: no allow rule covers the '
                 'request; denied by engine default, never by implicit '
                 'allow',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-effect-weakened': {
        "domain": 'policy-delta',
        "code": 'policy-delta-effect-weakened',
        "human": 'policy delta moves a rule effect up the deny < '
                 'require_approval < allow ladder; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-evaluation-error': {
        "domain": 'policy-delta',
        "code": 'policy-delta-evaluation-error',
        "human": 'policy delta evaluation hit an error mid-check; the '
                 'error skips toward deny, never toward allow',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-forbid': {
        "domain": 'policy-delta',
        "code": 'policy-delta-forbid',
        "human": 'policy delta request engine: a deny (forbid) rule '
                 'covers the request; the forbid hard-overrides any '
                 'allow',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-forbid-modified': {
        "domain": 'policy-delta',
        "code": 'policy-delta-forbid-modified',
        "human": 'policy delta changes a deny rule match without provable '
                 'narrowing; flagged for review, verdict stays pass',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-forbid-narrowed': {
        "domain": 'policy-delta',
        "code": 'policy-delta-forbid-narrowed',
        "human": 'policy delta provably narrows a deny rule match, so '
                 'previously-forbidden actions escape the forbid; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-forbid-removed': {
        "domain": 'policy-delta',
        "code": 'policy-delta-forbid-removed',
        "human": 'policy delta removes a deny (forbid) rule outright; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-forbid-residual': {
        "domain": 'policy-delta',
        "code": 'policy-delta-forbid-residual',
        "human": 'policy delta: a deny (forbid) rule survives that the '
                 'static check cannot model; the delta is uncheckable, '
                 'never a vacuous pass, and a request it might cover is '
                 'Unknown, never fail-open',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-malformed': {
        "domain": 'policy-delta',
        "code": 'policy-delta-malformed',
        "human": 'policy delta input is malformed (unparseable, non-mapping '
                 'policy, duplicate rule id, unknown effect); refused '
                 'fail-closed, never passed',
        "severity": 'high',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-role-added': {
        "domain": 'policy-delta',
        "code": 'policy-delta-role-added',
        "human": 'policy delta adds a new role carrying tools: a new '
                 'capability surface; flagged for review',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-section-changed': {
        "domain": 'policy-delta',
        "code": 'policy-delta-section-changed',
        "human": 'policy delta changes an unclassified section whose risk '
                 'direction cannot be assessed from policy text alone; '
                 'flagged for review',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-unknown': {
        "domain": 'policy-delta',
        "code": 'policy-delta-unknown',
        "human": 'policy delta uses a shape the static check cannot '
                 'model; refused fail-closed, never a vacuous pass',
        "severity": 'medium',
        "evidence_kinds_required": ['policy', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'policy-delta-widening': {
        "domain": 'policy-delta',
        "code": 'policy-delta-widening',
        "human": 'policy delta widens capability: a role gained tools, a '
                 'budget grew, the egress allowlist gained domains, an '
                 'allow match widened, or approval delegation was enabled; '
                 'refused fail-closed',
        "severity": 'high',
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
    'policy-harness-malformed': {
        "domain": 'policy-harness',
        "code": 'policy-harness-malformed',
        "human": 'policy harness: malformed fixture, expected outcome, or '
                 'policy file (unparseable or wrong shape); refused '
                 'fail-closed, never skipped',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-harness-missing-expected': {
        "domain": 'policy-harness',
        "code": 'policy-harness-missing-expected',
        "human": 'policy harness: a fixture has no expected outcome file; '
                 'refused fail-closed rather than evaluated without an '
                 'oracle',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-harness-no-policies': {
        "domain": 'policy-harness',
        "code": 'policy-harness-no-policies',
        "human": 'policy harness: the policies dir is missing or has no '
                 'loadable policy files; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'policy-harness-unknown-format': {
        "domain": 'policy-harness',
        "code": 'policy-harness-unknown-format',
        "human": 'policy harness: unknown file format in policies/ or '
                 'fixtures/ (expected *.yaml/*.yml policies, *.json '
                 'fixtures); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
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
    'posture-card-malformed': {
        "domain": 'posture-card',
        "code": 'posture-card-malformed',
        "human": 'posture cards: malformed assessment state, summary, or '
                 'issue input; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'posture-card-unknown-track': {
        "domain": 'posture-card',
        "code": 'posture-card-unknown-track',
        "human": 'posture cards: maturity level requested for a track '
                 'outside the closed track vocabulary; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['evidence'],
        "reverify_steps": ['recompute'],
    },
    'posture-card-unverifiable': {
        "domain": 'posture-card',
        "code": 'posture-card-unverifiable',
        "human": 'posture cards: VSA-style summary signature does not '
                 'verify against the issuer key',
        "severity": 'high',
        "evidence_kinds_required": ['evidence', 'signature'],
        "reverify_steps": ['verify-signature'],
    },
    'posture-endorsement-missing': {
        "domain": 'posture',
        "code": 'posture-endorsement-missing',
        "human": 'runtime posture: a claim lacks its separately-sourced '
                 'endorsement slot (every claim must carry one); the '
                 'record was not minted',
        "severity": 'medium',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },

    'posture-endorsement-not-independent': {
        "domain": 'posture',
        "code": 'posture-endorsement-not-independent',
        "human": 'runtime posture: an endorsement slot is sourced from '
                 'the record\'s own producer -- endorsements must be '
                 'separately sourced; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['record', 'endorsement'],
        "reverify_steps": ['recompute'],
    },

    'posture-invalid-shape': {
        "domain": 'posture',
        "code": 'posture-invalid-shape',
        "human": 'runtime posture: the attestation record or its claims '
                 'are malformed (non-mapping, missing fields, bad types); '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['record'],
        "reverify_steps": ['recompute'],
    },

    'posture-nonce-invalid': {
        "domain": 'posture',
        "code": 'posture-nonce-invalid',
        "human": 'runtime posture: eat_nonce is missing, below the 64-bit '
                 'minimum, or does not match the appraisal request '
                 '(possible replay); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['record', 'nonce'],
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
    'posture-signature-invalid': {
        "domain": 'posture',
        "code": 'posture-signature-invalid',
        "human": 'runtime posture: the operator signature over the '
                 'attestation record did not verify -- the record is '
                 'forged or tampered',
        "severity": 'high',
        "evidence_kinds_required": ['record', 'signature'],
        "reverify_steps": ['verify-signature'],
    },

    'posture-submod-invalid': {
        "domain": 'posture',
        "code": 'posture-submod-invalid',
        "human": 'runtime posture: a submod measurement entry is '
                 'malformed or its digest is not 64-hex; refused '
                 'fail-closed so substitution cannot hide in shape',
        "severity": 'medium',
        "evidence_kinds_required": ['record'],
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
    'prodauth-claim-expired': {
        "domain": 'prodauth',
        "code": 'prodauth-claim-expired',
        "human": 'producer authorization: the SLSA-shaped producer-authorization claim expired before the use time',
        "severity": 'medium',
        "evidence_kinds_required": ['signature', 'claim'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'prodauth-claim-invalid': {
        "domain": 'prodauth',
        "code": 'prodauth-claim-invalid',
        "human": 'producer authorization: the producer-authorization claim has a bad shape or its claim-authority signature does not verify',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'claim'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'prodauth-claim-mismatch': {
        "domain": 'prodauth',
        "code": 'prodauth-claim-mismatch',
        "human": 'producer authorization: the producer-authorization claim was minted for a different issuance (approval/subject-key join failed)',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'claim'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'prodauth-producer-unknown': {
        "domain": 'prodauth',
        "code": 'prodauth-producer-unknown',
        "human": 'producer authorization: the presenting producer is not in the producer registry; refusing rather than defaulting',
        "severity": 'high',
        "evidence_kinds_required": ['registry', 'identity'],
        "reverify_steps": ['recompute'],
    },
    'prodauth-registry-unauthorized': {
        "domain": 'prodauth',
        "code": 'prodauth-registry-unauthorized',
        "human": 'producer authorization: a producer-registry registration statement is malformed, expired, or not signed by the registry admin key',
        "severity": 'medium',
        "evidence_kinds_required": ['signature', 'registry'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'prodauth-scope-not-authorized': {
        "domain": 'prodauth',
        "code": 'prodauth-scope-not-authorized',
        "human": 'producer authorization: the producer is registered but not authorized for the requested scope (exact match, no wildcards)',
        "severity": 'high',
        "evidence_kinds_required": ['registry', 'identity'],
        "reverify_steps": ['recompute'],
    },
    'prodauth-token-expired': {
        "domain": 'prodauth',
        "code": 'prodauth-token-expired',
        "human": 'producer authorization: the presented identity token expired',
        "severity": 'medium',
        "evidence_kinds_required": ['signature', 'identity'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'prodauth-token-invalid': {
        "domain": 'prodauth',
        "code": 'prodauth-token-invalid',
        "human": 'producer authorization: the presented identity token has a bad shape, wrong audience, or a signature that does not verify against the identity issuer key',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'identity'],
        "reverify_steps": ['verify-signature', 'recompute'],
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
    'provenance-artifact-mismatch': {
        "domain": 'evidence-provenance',
        "code": 'provenance-artifact-mismatch',
        "human": 'evidence provenance: the provenance claim is about a '
                 'different artifact digest than the one being anchored '
                 'or graphed; claims never transfer across artifacts',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-claim', 'digest'],
        "reverify_steps": ['recompute'],
    },

    'provenance-builder-refused': {
        "domain": 'provenance-policy',
        "code": 'provenance-builder-refused',
        "human": 'admission-time provenance policy: the statement builder '
                 'id is missing or not in the policy allowlist (a '
                 'validly-signed statement from a foreign builder still '
                 'refuses; claims are checked, not made true)',
        "severity": 'high',
        "evidence_kinds_required": ['provenance-statement'],
        "reverify_steps": ['recompute'],
    },
    'provenance-builder-untrusted': {
        "domain": 'evidence-provenance',
        "code": 'provenance-builder-untrusted',
        "human": 'evidence provenance: the claim builder id is not in '
                 'the auditor-pinned allowlist (a validly-signed claim '
                 'from a foreign builder still refuses); claims are '
                 'checked, not made true',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-claim'],
        "reverify_steps": ['recompute'],
    },

    'provenance-chain-class-mismatch': {
        "domain": 'provenance',
        "code": 'provenance-chain-class-mismatch',
        "human": 'provenance non-upgrade: a chain entry failed class or '
                 'linkage verification; chain validity never promotes '
                 'provenance',
        "severity": 'high',
        "evidence_kinds_required": ['provenance-chain'],
        "reverify_steps": ['recompute'],
    },
    'provenance-class-missing': {
        "domain": 'provenance',
        "code": 'provenance-class-missing',
        "human": 'provenance non-upgrade: emission named no provenance '
                 'class; a receipt must name exactly one class',
        "severity": 'high',
        "evidence_kinds_required": ['provenance-receipt'],
        "reverify_steps": ['recompute'],
    },
    'provenance-class-unknown': {
        "domain": 'provenance',
        "code": 'provenance-class-unknown',
        "human": 'provenance non-upgrade: unknown provenance class '
                 '(case-exact LOGGED/EXECUTED vocabulary)',
        "severity": 'high',
        "evidence_kinds_required": ['provenance-receipt'],
        "reverify_steps": ['recompute'],
    },
    'provenance-critical-arg-refused': {
        "domain": 'provenance',
        "code": 'provenance-critical-arg-refused',
        "human": 'sink policy: a critical argument (recipient, path, url, '
                 'command) binds below the tool\'s required trust -- the '
                 'argument\'s value traces to untrusted-influenced context '
                 'and no audited declassification clears it; refused',
        "severity": 'high',
        "evidence_kinds_required": ['quarantine-record'],
        "reverify_steps": ['recompute'],
    },
    'provenance-declassify-invalid': {
        "domain": 'provenance',
        "code": 'provenance-declassify-invalid',
        "human": 'sink policy: a declassification token was invalid, expired, '
                 'replayed, or bound to a different (segment, tool, '
                 'scope) -- declassification is single-use and '
                 'argument-bound; anything else refuses fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['declassification-token'],
        "reverify_steps": ['recompute'],
    },
    'provenance-digest-mismatch': {
        "domain": 'provenance',
        "code": 'provenance-digest-mismatch',
        "human": 'provenance non-upgrade: receipt bytes differ from the '
                 'emission digest (no silent re-grade)',
        "severity": 'high',
        "evidence_kinds_required": ['provenance-receipt'],
        "reverify_steps": ['recompute'],
    },
    'provenance-envelope-malformed': {
        "domain": 'evidence-provenance',
        "code": 'provenance-envelope-malformed',
        "human": 'evidence provenance: the provenance envelope or claim '
                 'failed structural validation; refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['provenance-claim'],
        "reverify_steps": ['recompute'],
    },

    'provenance-label-tampered': {
        "domain": 'provenance',
        "code": 'provenance-label-tampered',
        "human": 'sink policy: a segment label carries a signature but it does '
                 'not verify against the segment content -- the '
                 'label or the content was edited after issuance; '
                 'the segment downgrades to UNTRUSTED',
        "severity": 'high',
        "evidence_kinds_required": ['provenance-label'],
        "reverify_steps": ['recompute', 'reverify-signature'],
    },
    'provenance-label-unverifiable': {
        "domain": 'provenance',
        "code": 'provenance-label-unverifiable',
        "human": 'sink policy: a segment label carries no usable signature -- '
                 'unsigned labels never verify; the segment '
                 'downgrades to UNTRUSTED, fail closed',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-label'],
        "reverify_steps": ['recompute'],
    },
    'provenance-material-unmarked': {
        "domain": 'evidence-provenance',
        "code": 'provenance-material-unmarked',
        "human": 'evidence provenance: a build material carries no '
                 'explicit completeness marking (must be verified or '
                 'unverified); the honesty discipline is enforced, not '
                 'assumed',
        "severity": 'low',
        "evidence_kinds_required": ['provenance-claim'],
        "reverify_steps": ['recompute'],
    },

    'provenance-material-unverified': {
        "domain": 'evidence-provenance',
        "code": 'provenance-material-unverified',
        "human": 'evidence provenance: a build material is marked '
                 'unverified and the verifier did not opt in to '
                 'unverified materials; unverified inputs are loud, '
                 'never silent',
        "severity": 'low',
        "evidence_kinds_required": ['provenance-claim'],
        "reverify_steps": ['recompute'],
    },

    'provenance-missing': {
        "domain": 'evidence-provenance',
        "code": 'provenance-missing',
        "human": 'evidence provenance: no provenance envelope was '
                 'supplied at a provenance-gated anchor; missing '
                 'provenance never anchors silently',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'provenance-policy-vacuous': {
        "domain": 'provenance-policy',
        "code": 'provenance-policy-vacuous',
        "human": 'admission-time provenance policy: the policy is vacuous '
                 'or malformed (no allowed sources, no allowed builders, '
                 'no pinned statement signers); it admits nothing so it '
                 'cannot be constructed — never a vacuous allow',
        "severity": 'high',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },

    'provenance-quarantine-terminal': {
        "domain": 'provenance',
        "code": 'provenance-quarantine-terminal',
        "human": 'sink policy: the bounded re-plan budget is exhausted for this '
                 'context -- the call is parked escalate-terminal; '
                 'a human owns the reroute, never an automatic '
                 'retry loop',
        "severity": 'medium',
        "evidence_kinds_required": ['quarantine-record'],
        "reverify_steps": ['recompute'],
    },
    'provenance-rebuild-invalid': {
        "domain": 'evidence-provenance',
        "code": 'provenance-rebuild-invalid',
        "human": 'evidence provenance: the re-derivation recipe is malformed '
                 'or cannot deterministically reproduce the artifact digest '
                 '(bad grammar, undeclared input, budget violation, '
                 'non-terminal-hash); non-deterministic recipes can never '
                 're-derive, refused fail-closed at registration',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-claim'],
        "reverify_steps": ['recompute'],
    },
    'provenance-rebuild-mismatch': {
        "domain": 'evidence-provenance',
        "code": 'provenance-rebuild-mismatch',
        "human": 'evidence provenance: re-deriving the artifact digest from '
                 'the signed re-derivation recipe and the supplied materials '
                 'disagrees with the claimed artifact digest; treat as '
                 'possible tampering and escalate',
        "severity": 'critical',
        "evidence_kinds_required": ['provenance-claim', 'material-bytes'],
        "reverify_steps": ['recompute'],
    },
    'provenance-rebuild-missing': {
        "domain": 'evidence-provenance',
        "code": 'provenance-rebuild-missing',
        "human": 'evidence provenance: the verifier demanded re-derivation '
                 '(strict builder policy) but the claim carries no '
                 're-derivation recipe; a claim that cannot be re-derived '
                 'refuses under a strict policy',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-claim'],
        "reverify_steps": ['recompute'],
    },
    'provenance-rebuild-transform-unknown': {
        "domain": 'evidence-provenance',
        "code": 'provenance-rebuild-transform-unknown',
        "human": 'evidence provenance: the re-derivation recipe names a '
                 'transform outside the closed deterministic allowlist; '
                 'recipes describe, they never execute unlisted code, '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-claim'],
        "reverify_steps": ['recompute'],
    },
    'provenance-signature-invalid': {
        "domain": 'evidence-provenance',
        "code": 'provenance-signature-invalid',
        "human": 'evidence provenance: the provenance envelope signature '
                 'does not verify under the auditor-pinned builder key; '
                 'unsigned-is-not-evidence, refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-claim', 'signature'],
        "reverify_steps": ['recompute'],
    },

    'provenance-sink-escalated': {
        "domain": 'provenance',
        "code": 'provenance-sink-escalated',
        "human": 'sink policy: a destructive or hard-to-undo tool call on '
                 'untrusted-influenced context is parked for human '
                 'adjudication -- never auto-executed',
        "severity": 'medium',
        "evidence_kinds_required": ['quarantine-record'],
        "reverify_steps": ['recompute'],
    },
    'provenance-sink-redacted': {
        "domain": 'provenance',
        "code": 'provenance-sink-redacted',
        "human": 'sink policy: an untrusted-bound critical argument was replaced '
                 'with an opaque ref ($UNTRUSTED_n) -- the call '
                 'continues without the raw untrusted bytes in '
                 'the model-visible context',
        "severity": 'low',
        "evidence_kinds_required": ['quarantine-record'],
        "reverify_steps": ['recompute'],
    },
    'provenance-sink-refused': {
        "domain": 'provenance',
        "code": 'provenance-sink-refused',
        "human": 'sink policy: required_trust(tool) exceeds the minimum trust '
                 'among influencing segments and no per-argument '
                 'refinement or audited declassification clears '
                 'it -- the call never executes',
        "severity": 'high',
        "evidence_kinds_required": ['quarantine-record'],
        "reverify_steps": ['recompute'],
    },
    'provenance-sink-unknown-tool': {
        "domain": 'provenance',
        "code": 'provenance-sink-unknown-tool',
        "human": 'sink policy: the tool is not declared in the sink policy -- '
                 'deny by default; undeclared tools cannot have '
                 'capability attributed, so they refuse',
        "severity": 'medium',
        "evidence_kinds_required": ['quarantine-record'],
        "reverify_steps": ['recompute'],
    },
    'provenance-source-refused': {
        "domain": 'provenance-policy',
        "code": 'provenance-source-refused',
        "human": 'admission-time provenance policy: the statement source '
                 '(uri or digest) is missing or not in the policy '
                 'allowlist, or a policy-expected build input mismatches; '
                 'the artifact is not admitted',
        "severity": 'high',
        "evidence_kinds_required": ['provenance-statement'],
        "reverify_steps": ['recompute'],
    },
    'provenance-statement-unverified': {
        "domain": 'provenance-policy',
        "code": 'provenance-statement-unverified',
        "human": 'admission-time provenance policy: the provenance '
                 'statement signature does not verify under a pinned '
                 'statement signer (or the statement is malformed); '
                 'tampered bytes are never emitted downstream',
        "severity": 'high',
        "evidence_kinds_required": ['provenance-statement', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'provenance-step-break': {
        "domain": 'provenance',
        "code": 'provenance-step-break',
        "human": 'provenance non-upgrade: workflow step sequence does not '
                 'match the committed order (deletion or reorder); the '
                 'break is named, surviving classes are unchanged',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-commitment'],
        "reverify_steps": ['recompute'],
    },
    'provenance-subject-refused': {
        "domain": 'provenance-policy',
        "code": 'provenance-subject-refused',
        "human": 'admission-time provenance policy: the statement subject '
                 'digest is missing/malformed or does not match the '
                 'expected artifact digest; the provenance is about a '
                 'different artifact',
        "severity": 'high',
        "evidence_kinds_required": ['provenance-statement', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'provenance-tag-refused': {
        "domain": 'provenance-policy',
        "code": 'provenance-tag-refused',
        "human": 'admission-time provenance policy: the statement tag is '
                 'missing while required, unparseable, outside the '
                 'policy semver range, or not in the allowed list',
        "severity": 'high',
        "evidence_kinds_required": ['provenance-statement'],
        "reverify_steps": ['recompute'],
    },
    'provenance-upgraded': {
        "domain": 'provenance',
        "code": 'provenance-upgraded',
        "human": 'provenance non-upgrade: a receipt presented at an '
                 'authority weight above its own class (report posed as '
                 'observation); refused, never re-graded',
        "severity": 'critical',
        "evidence_kinds_required": ['provenance-receipt'],
        "reverify_steps": ['recompute'],
    },
    'provenance-vsa-refused': {
        "domain": 'provenance-policy',
        "code": 'provenance-vsa-refused',
        "human": 'admission-time provenance policy: the Verification '
                 'Summary Attestation is refused — unpinned verifier, bad '
                 'signature, scope (policy id) mismatch, expired or '
                 'not-yet-valid, older than the policy max age, or below '
                 'the required verification level; VSA delegates trust, '
                 'it does not create it',
        "severity": 'high',
        "evidence_kinds_required": ['vsa', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'provisioned_required': {
        "domain": 'approval',
        "code": 'provisioned_required',
        "human": 'approval and delegation: a provisioned session identity is required',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'provlabel-approval-required': {
        "domain": 'provlabel',
        "code": 'provlabel-approval-required',
        "human": 'instruction-provenance labeling: a consequential action '
                 'whose driving instruction provenance is below the required '
                 'provenance (USER_DIRECT by default) is routed to approval '
                 'with the provenance chain surfaced, never silently '
                 'executed (toxic-agent-flow / EchoLeak / GTG-50020 class)',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-chain', 'action-request'],
        "reverify_steps": ['recompute'],
    },
    'provlabel-malformed': {
        "domain": 'provlabel',
        "code": 'provlabel-malformed',
        "human": 'instruction-provenance labeling: the seam input is not the '
                 'expected shape (bad label rank, non-str text, non-unit '
                 'compose values, non-ActionRequest); refused fail-closed, '
                 'never raises',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'provlabel-mixed-provenance': {
        "domain": 'provlabel',
        "code": 'provlabel-mixed-provenance',
        "human": 'instruction-provenance labeling: a consequential action '
                 'whose instruction-shaped drivers MIX below-bar and '
                 'at/above-bar provenance (toxic-agent-flow shape: user '
                 'instruction plus retrieved injection) is routed to '
                 'approval with a distinct code -- the injection cannot '
                 'piggyback on the user-shaped driver (F294)',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-chain', 'action-request'],
        "reverify_steps": ['recompute'],
    },
    'provlabel-omitted-driver': {
        "domain": 'provlabel',
        "code": 'provlabel-omitted-driver',
        "human": 'instruction-provenance labeling: the agent plan trace '
                 'narrowed the operator-installed driver set and the '
                 'narrowed set no longer routes while the full installed '
                 'set does (F307 plan-trace omission) -- routed to '
                 'approval loud with the server-side chain; an installed '
                 'injection-shaped driver can never be narrowed away '
                 'silently',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-chain', 'action-request'],
        "reverify_steps": ['recompute'],
    },
    'provlabel-unresolvable-driver': {
        "domain": 'provlabel',
        "code": 'provlabel-unresolvable-driver',
        "human": 'instruction-provenance labeling: driving unit ids from the '
                 'plan trace have no label on record; approval required with '
                 'the gap surfaced (fail-closed)',
        "severity": 'medium',
        "evidence_kinds_required": ['provenance-chain', 'action-request'],
        "reverify_steps": ['recompute'],
    },
    'ptgrant-arg-attribute-missing': {
        "domain": 'tool_grant',
        "code": 'ptgrant-arg-attribute-missing',
        "human": 'per-tool grant v2: a required arg_bounds attribute is missing from both the stored grant params and the request-scoped invocation material',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'proof'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-arg-bound-violated': {
        "domain": 'tool_grant',
        "code": 'ptgrant-arg-bound-violated',
        "human": 'per-tool grant: an invocation argument violates its registered bound',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'proof'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-attenuation-invalid': {
        "domain": 'tool_grant',
        "code": 'ptgrant-attenuation-invalid',
        "human": 'per-tool grant: an attenuation caveat record is malformed or mis-chained',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'proof'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-audience-mismatch': {
        "domain": 'tool_grant',
        "code": 'ptgrant-audience-mismatch',
        "human": 'per-tool grant: the grant audience does not match the server (confused server)',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-batch-tool-cap-exceeded': {
        "domain": 'tool_grant',
        "code": 'ptgrant-batch-tool-cap-exceeded',
        "human": 'per-tool grant v2: a batch evaluation exceeds the per-request tool cap',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature', 'proof'],
        "reverify_steps": ['recompute'],
    },
    'ptgrant-caller-unauthorized': {
        "domain": 'tool_grant',
        "code": 'ptgrant-caller-unauthorized',
        "human": 'per-tool grant v2: the caller credential lacks the required scope (data-plane) for the operation',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'proof'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-cnf-missing': {
        "domain": 'tool_grant',
        "code": 'ptgrant-cnf-missing',
        "human": 'per-tool grant: the grant carries no confirmation key binding',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-context-oversize': {
        "domain": 'tool_grant',
        "code": 'ptgrant-context-oversize',
        "human": 'per-tool grant v2: request-scoped context material exceeds the size cap',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature', 'proof'],
        "reverify_steps": ['recompute'],
    },
    'ptgrant-grant-expired': {
        "domain": 'tool_grant',
        "code": 'ptgrant-grant-expired',
        "human": 'per-tool grant: the grant is past its expiry',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-grant-malformed': {
        "domain": 'tool_grant',
        "code": 'ptgrant-grant-malformed',
        "human": 'per-tool grant: the grant body fails shape checks',
        "severity": 'medium',
        "evidence_kinds_required": ['grant'],
        "reverify_steps": ['recompute'],
    },
    'ptgrant-grant-not-yet-valid': {
        "domain": 'tool_grant',
        "code": 'ptgrant-grant-not-yet-valid',
        "human": 'per-tool grant: the grant is presented before its not-before time',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-invalid-target': {
        "domain": 'tool_grant',
        "code": 'ptgrant-invalid-target',
        "human": 'per-tool grant: the grant targets a mandate or scope that cannot be issued',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-issuer-unknown': {
        "domain": 'tool_grant',
        "code": 'ptgrant-issuer-unknown',
        "human": 'per-tool grant: the grant issuer is not a trusted issuer',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-jti-reused': {
        "domain": 'tool_grant',
        "code": 'ptgrant-jti-reused',
        "human": 'per-tool grant: the proof nonce was already consumed (replay refused)',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'proof', 'store'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-link-unverifiable': {
        "domain": 'tool_grant',
        "code": 'ptgrant-link-unverifiable',
        "human": 'per-tool grant: the tool supply-chain link could not be verified',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-mandate-drift': {
        "domain": 'tool_grant',
        "code": 'ptgrant-mandate-drift',
        "human": 'per-tool grant: the mandate version moved since the grant was issued',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-mandate-unreachable': {
        "domain": 'tool_grant',
        "code": 'ptgrant-mandate-unreachable',
        "human": 'per-tool grant v2: the mandate store is unreachable (raise or None); fail closed',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'proof'],
        "reverify_steps": ['recompute'],
    },
    'ptgrant-max-calls-exhausted': {
        "domain": 'tool_grant',
        "code": 'ptgrant-max-calls-exhausted',
        "human": 'per-tool grant: the per-detail call budget is exhausted',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature', 'proof', 'store'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-ok': {
        "domain": 'tool_grant',
        "code": 'ptgrant-ok',
        "human": 'per-tool grant: the invocation was authorized (emitted as a decision record, not a refusal)',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature', 'proof'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-pop-invalid': {
        "domain": 'tool_grant',
        "code": 'ptgrant-pop-invalid',
        "human": 'per-tool grant: the proof-of-possession proof fails binding or signature',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'proof'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-predicate-hash-mismatch': {
        "domain": 'tool_grant',
        "code": 'ptgrant-predicate-hash-mismatch',
        "human": 'per-tool grant v2: the grant-pinned predicate-registry content hash does not match the registry under evaluation',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature', 'proof'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-predicate-unknown': {
        "domain": 'tool_grant',
        "code": 'ptgrant-predicate-unknown',
        "human": 'per-tool grant: the grant or caveat uses an unregistered predicate',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-signature-invalid': {
        "domain": 'tool_grant',
        "code": 'ptgrant-signature-invalid',
        "human": 'per-tool grant: the grant signature fails verification',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-supply-chain-failed': {
        "domain": 'tool_grant',
        "code": 'ptgrant-supply-chain-failed',
        "human": 'per-tool grant: the tool supply-chain link digest does not match',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
    },
    'ptgrant-tool-not-covered': {
        "domain": 'tool_grant',
        "code": 'ptgrant-tool-not-covered',
        "human": 'per-tool grant: the invoked tool is not covered by any grant detail',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'signature'],
        "reverify_steps": ['verify-signature', 'recompute'],
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
    'quorum-attestation-expired': {
        "domain": 'quorum',
        "code": 'quorum-attestation-expired',
        "human": "m-of-n operation approval: the attestation's validity window has passed; fail-closed",
        "severity": 'medium',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-deny-veto': {
        "domain": 'quorum',
        "code": 'quorum-deny-veto',
        "human": "m-of-n operation approval: an eligible approver's signed dissent vetoes the quorum (D1-core one-deny veto); fail-closed",
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-duplicate-approver': {
        "domain": 'quorum',
        "code": 'quorum-duplicate-approver',
        "human": 'm-of-n operation approval: duplicate approver names at policy registration -- one human must not fill two quorum slots; fail-closed at load',
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-gate-refused': {
        "domain": 'namespace',
        "code": 'quorum-gate-refused',
        "human": 'deployment namespace: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'quorum-insufficient': {
        "domain": 'quorum',
        "code": 'quorum-insufficient',
        "human": 'm-of-n operation approval: fewer than m distinct valid attestations collected; the operation is not executable; fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-key-reuse': {
        "domain": 'quorum',
        "code": 'quorum-key-reuse',
        "human": 'm-of-n operation approval: the same public key under two approver names -- one key must not fill two quorum slots; fail-closed at load',
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-malformed': {
        "domain": 'quorum',
        "code": 'quorum-malformed',
        "human": 'm-of-n operation approval: malformed policy, attestation, or operation descriptor; fail-closed, never silently accepted',
        "severity": 'medium',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-not-met': {
        "domain": 'quorum',
        "code": 'quorum-not-met',
        "human": 'quorum and thresholds: a threshold or quorum was not met',
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'vote', 'signature'],
        "reverify_steps": ['recount-votes', 'check-threshold'],
    },
    'quorum-operation-mismatch': {
        "domain": 'quorum',
        "code": 'quorum-operation-mismatch',
        "human": 'm-of-n operation approval: the attestation is bound to a different operation digest than the collector; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-policy-version-invalid': {
        "domain": 'quorum',
        "code": 'quorum-policy-version-invalid',
        "human": 'm-of-n operation approval: non-monotonic policy version or a changed approver set without a version bump; fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-replay-refused': {
        "domain": 'quorum',
        "code": 'quorum-replay-refused',
        "human": 'm-of-n operation approval: the attestation nonce was already seen for this operation -- replay refused; fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-rollback-refused': {
        "domain": 'namespace',
        "code": 'quorum-rollback-refused',
        "human": 'deployment namespace: refused by policy',
        "severity": 'medium',
        "evidence_kinds_required": ['namespace', 'signature', 'quorum'],
        "reverify_steps": ['recompute'],
    },
    'quorum-signature-invalid': {
        "domain": 'quorum',
        "code": 'quorum-signature-invalid',
        "human": "m-of-n operation approval: the attestation signature does not verify against the approver's pinned key; fail-closed",
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-unknown-approver': {
        "domain": 'quorum',
        "code": 'quorum-unknown-approver',
        "human": 'm-of-n operation approval: the attestation names an approver not eligible under the policy; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'quorum-unreachable': {
        "domain": 'quorum',
        "code": 'quorum-unreachable',
        "human": 'm-of-n operation approval: m exceeds the number of eligible approvers -- the quorum can never be met (silent starvation); fail-closed at load',
        "severity": 'high',
        "evidence_kinds_required": ['quorum', 'attestation', 'signature'],
        "reverify_steps": ['recount-approvals', 'check-threshold'],
    },
    'r3-grant-beyond-document': {
        "domain": 'r3',
        "code": 'r3-grant-beyond-document',
        "human": 'AAuth R3 grant token: the grant authorizes an operation '
                 'the R3 document itself does not define; the issuer may '
                 'narrow, never widen',
        "severity": 'high',
        "evidence_kinds_required": ['grant-token', 'r3-document'],
        "reverify_steps": ['recompute'],
    },
    'r3-grant-hash-mismatch': {
        "domain": 'r3',
        "code": 'r3-grant-hash-mismatch',
        "human": 'AAuth R3 grant token: the token-pinned r3_grant_hash does '
                 'not match the recomputed hash of the presented grant '
                 'lists; the lists were edited after issuance',
        "severity": 'high',
        "evidence_kinds_required": ['grant-token'],
        "reverify_steps": ['recompute'],
    },
    'r3-malformed': {
        "domain": 'r3',
        "code": 'r3-malformed',
        "human": 'AAuth R3 grant token: the token, R3 document, or per-call '
                 'proposal is the wrong shape',
        "severity": 'medium',
        "evidence_kinds_required": ['grant-token', 'r3-document'],
        "reverify_steps": ['recompute'],
    },
    'r3-no-match': {
        "domain": 'r3',
        "code": 'r3-no-match',
        "human": 'AAuth R3 grant token: the operation matches neither '
                 'r3_granted nor r3_per_call; the reject decision',
        "severity": 'medium',
        "evidence_kinds_required": ['grant-token', 'r3-document'],
        "reverify_steps": ['recompute'],
    },
    'r3-per-call-binding-broken': {
        "domain": 'r3',
        "code": 'r3-per-call-binding-broken',
        "human": 'AAuth R3 per-call challenge: the challenged call is not '
                 'byte-equal to the content-addressed proposal operation; '
                 'parameters were edited after addressing',
        "severity": 'high',
        "evidence_kinds_required": ['grant-token', 'r3-document'],
        "reverify_steps": ['recompute'],
    },
    'r3-s256-mismatch': {
        "domain": 'r3',
        "code": 'r3-s256-mismatch',
        "human": 'AAuth R3 grant token: the token-pinned r3_s256 does not '
                 'match the recomputed hash of the presented R3 document; '
                 'the approval-time binding is broken',
        "severity": 'high',
        "evidence_kinds_required": ['grant-token', 'r3-document'],
        "reverify_steps": ['recompute'],
    },
    'r3-unknown-operation': {
        "domain": 'r3',
        "code": 'r3-unknown-operation',
        "human": 'AAuth R3 grant token: an operation is not well-formed in '
                 'the registered vocabulary (unknown field, missing '
                 'required field, non-string value)',
        "severity": 'high',
        "evidence_kinds_required": ['grant-token', 'r3-document'],
        "reverify_steps": ['recompute'],
    },
    'r3-vocabulary-unknown': {
        "domain": 'r3',
        "code": 'r3-vocabulary-unknown',
        "human": 'AAuth R3 grant token: a vocabulary URI the consumer does '
                 'not register; closed vocabulary refuses',
        "severity": 'high',
        "evidence_kinds_required": ['grant-token', 'r3-document'],
        "reverify_steps": ['recompute'],
    },
    'rail-adapter-unknown-verdict': {
        "domain": 'rail',
        "code": 'rail-adapter-unknown-verdict',
        "human": 'rail verdict adaptor: a guard seam emitted a verdict '
                 'word outside the known vocabulary (or a malformed '
                 'verdict); refused fail-closed rather than treated as '
                 'allow -- the vocabulary-mismatch block-evasion choke '
                 'point',
        "severity": 'high',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'rail-allow': {
        "domain": 'rail',
        "code": 'rail-allow',
        "human": 'rail verdict: a guard seam allowed under the uniform '
                 'ALLOW/BLOCK/TRANSFORM vocabulary (informational)',
        "severity": 'low',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'rail-chunk-body-mismatch': {
        "domain": 'rail',
        "code": 'rail-chunk-body-mismatch',
        "human": 'retrieval rail: a chunk id was re-registered with '
                 'different bytes; content swap under a stable id is '
                 'refused',
        "severity": 'high',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'rail-chunk-relabel-refused': {
        "domain": 'rail',
        "code": 'rail-chunk-relabel-refused',
        "human": 'retrieval rail: a chunk id was re-registered with a '
                 'different provenance label; labels never change across '
                 'turns',
        "severity": 'high',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'rail-chunk-unlabeled': {
        "domain": 'rail',
        "code": 'rail-chunk-unlabeled',
        "human": 'retrieval rail: a chunk arrived without a label from the '
                 'closed vocabulary, or carried label unknown; blocked '
                 'fail-closed, never trusted',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'rail-instruction-chunk-masked': {
        "domain": 'rail',
        "code": 'rail-instruction-chunk-masked',
        "human": 'retrieval rail: an instruction-shaped retrieved chunk '
                 'was masked in place (TRANSFORM) with a visible '
                 'placeholder; the approver sees the masking, not the '
                 'injection',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'rail-merge-contract-violated': {
        "domain": 'rail',
        "code": 'rail-merge-contract-violated',
        "human": 'retrieval rail: an attempt to assemble or stage a '
                 'non-chunk (bare string) value; merging provenance away '
                 'is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'rail-transform-empty-spans': {
        "domain": 'rail',
        "code": 'rail-transform-empty-spans',
        "human": 'rail verdict: a TRANSFORM with no masked spans (or '
                 'overlapping/out-of-bounds spans) was requested; masking '
                 'nothing with no record is an audit-trail hole, refused',
        "severity": 'medium',
        "evidence_kinds_required": ['screen-verdict'],
        "reverify_steps": ['recompute'],
    },
    'ratify-admission-unverifiable': {
        "domain": 'ratify',
        "code": 'ratify-admission-unverifiable',
        "human": 'ratification: the admission gate was given no ratification '
                 'report, or a malformed one; nothing binds into the grant '
                 'graph on unverifiable metadata -- refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['ratification-report'],
        "reverify_steps": ['recompute'],
    },
    'ratify-policy-unsatisfied': {
        "domain": 'ratify',
        "code": 'ratify-policy-unsatisfied',
        "human": 'ratification: the per-artifact-type any/all policy rollup '
                 'did not satisfy the deployment policy; the nested report '
                 'tree records which verifier or combinator failed',
        "severity": 'medium',
        "evidence_kinds_required": ['ratification-report'],
        "reverify_steps": ['recompute'],
    },
    'ratify-unratified-tool-refused': {
        "domain": 'ratify',
        "code": 'ratify-unratified-tool-refused',
        "human": 'ratification: a tool whose metadata did not ratify (or a '
                 'report naming a different subject) was refused binding '
                 'into the grant graph -- admission before binding, '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['ratification-report'],
        "reverify_steps": ['recompute'],
    },
    'ratify-verifier-error': {
        "domain": 'ratify',
        "code": 'ratify-verifier-error',
        "human": 'ratification: a verifier raised technically instead of '
                 'returning a report; recorded as a technical error and '
                 'rolled up as verification failure -- never a silent pass',
        "severity": 'medium',
        "evidence_kinds_required": ['ratification-report'],
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
    'receipt-fork-detected': {
        "domain": 'receipt',
        "code": 'receipt-fork-detected',
        "human": 'receipt: two validly-signed tree heads name the same log '
                 'position with different roots -- fork proven; denounced '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
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
    'receipt-inclusion-mismatch': {
        "domain": 'receipt',
        "code": 'receipt-inclusion-mismatch',
        "human": 'receipt: the inclusion path does not chain the claimed '
                 'bundle digest to the signed tree root; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'receipt-leaf-mismatch': {
        "domain": 'receipt',
        "code": 'receipt-leaf-mismatch',
        "human": 'receipt: the tile leaf at the claimed index is not the '
                 'claimed bundle digest (log store disagrees with the '
                 'receipt); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
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
    'receipt-policy-mismatch': {
        "domain": 'receipt',
        "code": 'receipt-policy-mismatch',
        "human": 'receipt: the witness cosigning on the receipt does not '
                 'satisfy the pinned witness policy (wrong policy id or '
                 'under-quorum); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'receipt-signature-invalid': {
        "domain": 'receipt',
        "code": 'receipt-signature-invalid',
        "human": 'receipt: the operator (or witness) signature over the '
                 'signed binding does not verify; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'receipt_unverifiable': {
        "domain": 'platform',
        "code": 'receipt_unverifiable',
        "human": 'platform egress: the evidence could not be verified',
        "severity": 'high',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
    },
    'recipient-plugin-identity-refused': {
        "domain": 'envelope',
        "code": 'recipient-plugin-identity-refused',
        "human": 'envelope recipient plugin: the seal/open identity a '
                 'plugin needs is missing or malformed (bad key material, '
                 'bad quorum, colliding share ids, too few shares)',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'recipient-plugin-label-inconsistent': {
        "domain": 'envelope',
        "code": 'recipient-plugin-label-inconsistent',
        "human": 'envelope recipient plugin: a plugin emitted a wire '
                 'label outside its own namespace in one seal operation; '
                 'refused by the framework',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'recipient-plugin-malformed-wrap': {
        "domain": 'envelope',
        "code": 'recipient-plugin-malformed-wrap',
        "human": 'envelope recipient plugin: a plugin emitted a wrap '
                 'that is not exactly 48 bytes, or no wire entries at '
                 'all; refused by the framework',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'recipient-plugin-namespace-conflict': {
        "domain": 'envelope',
        "code": 'recipient-plugin-namespace-conflict',
        "human": 'envelope recipient plugin: registration refused -- the '
                 'plugin claims an already-claimed namespace, overlaps '
                 'one by prefix, reuses a plugin name, or declares a '
                 'malformed namespace',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'recipient-plugin-unknown-label': {
        "domain": 'envelope',
        "code": 'recipient-plugin-unknown-label',
        "human": 'envelope recipient plugin: a recipient label names a '
                 'namespace no registered plugin claims (or a plugin '
                 'name with no registration); refused',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'recipient-plugin-unwrap-refused': {
        "domain": 'envelope',
        "code": 'recipient-plugin-unwrap-refused',
        "human": 'envelope recipient plugin: a plugin refused or '
                 'errored during unwrap; the vault converts this to the '
                 'generic envelope-open-refused, never partial plaintext',
        "severity": 'high',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'recipient-plugin-wrap-refused': {
        "domain": 'envelope',
        "code": 'recipient-plugin-wrap-refused',
        "human": 'envelope recipient plugin: a plugin refused or '
                 'errored during wrap; seal refused with no envelope '
                 'emitted',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'recipient-policy-invalid': {
        "domain": 'envelope',
        "code": 'recipient-policy-invalid',
        "human": 'encrypted bundle envelope: the recipient policy is '
                 'invalid (bad public key, unknown recipient type, '
                 'duplicate ids, or empty recipient list); the policy is '
                 'the auditable key config -- refused',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'recompute-absent-refusal-no-coverage': {
        "domain": 'recompute',
        "code": 'recompute-absent-refusal-no-coverage',
        "human": 'recompute check: an absent refusal outside the declared '
                 'coverage boundary is not evidence -- absence is evidence '
                 'only where something promised to record',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'recompute-backlink-mismatch': {
        "domain": 'recompute',
        "code": 'recompute-backlink-mismatch',
        "human": 'recompute check: the execution receipt backLink does not '
                 'name the decision receipt digest+nonce -- the pair is '
                 'not linked',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'recompute-digest-mismatch': {
        "domain": 'recompute',
        "code": 'recompute-digest-mismatch',
        "human": 'recompute check: the digest recomputed over the '
                 'JCS-canonical receipt body does not match the claimed '
                 'receipt_digest -- possible tampering, escalate',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'recompute-malformed': {
        "domain": 'recompute',
        "code": 'recompute-malformed',
        "human": 'recompute check: receipt is structurally malformed '
                 '(unknown kind, bad version, non-hex digests, or '
                 'unsupported value in the canonical form)',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'recompute-no-execution-link': {
        "domain": 'recompute',
        "code": 'recompute-no-execution-link',
        "human": 'recompute check: an allow decision with no linked '
                 'execution receipt proves nothing about whether '
                 'anything ran',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'recompute-signature-invalid': {
        "domain": 'recompute',
        "code": 'recompute-signature-invalid',
        "human": 'recompute check: the Ed25519 signature does not verify '
                 'over the canonical receipt bytes with the checker-supplied '
                 'public key',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'reconintent-malformed': {
        "domain": 'reconintent',
        "code": 'reconintent-malformed',
        "human": 'reconstructed-intent seam: a chunk fails shape, '
                 'fingerprint, or cap validation; refused loudly '
                 'before scoring -- malformed input is never scored '
                 'silently',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'reconintent-queue-failed': {
        "domain": 'reconintent',
        "code": 'reconintent-queue-failed',
        "human": 'reconstructed-intent seam: the suspect hold could '
                 'not be queued for human review; the suspect flag '
                 'stays journaled -- operator must review manually',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'reconintent-suspect': {
        "domain": 'reconintent',
        "code": 'reconintent-suspect',
        "human": 'reconstructed-intent seam: the run\'s untrusted '
                 'chunks jointly complete an actionable directive no '
                 'single chunk carried, and the action\'s critical '
                 'destination is sourced from those chunks rather '
                 'than the user turn; advisory journal flag plus a '
                 'queued human approval -- never a silent block',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-verdict', 'digest'],
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
    'registry-threshold-unmet': {
        "domain": 'registry-acceptance',
        "code": 'registry-threshold-unmet',
        "human": 'fewer valid trusted signatures than the registry policy threshold',
        "severity": 'high',
        "evidence_kinds_required": ['signature', 'manifest'],
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
    'replay-approval-receipt-invalid': {
        "domain": 'replay',
        "code": 'replay-approval-receipt-invalid',
        "human": 'replay manifest: an approval link\'s corroboration '
                 'receipt failed cryptographic binding (statement digest '
                 'mismatch, bad envelope signature, or no receipt supplied '
                 'for the reference); the approval is not non-repudiated',
        "severity": 'high',
        "evidence_kinds_required": ['manifest-record'],
        "reverify_steps": ['recompute'],
    },
    'replay-broken-chain': {
        "domain": 'replay',
        "code": 'replay-broken-chain',
        "human": 'replay manifest: a link prev_hash, link_hash, or the '
                 'manifest seal does not recompute; the record is not '
                 'tamper-evident as presented -- treat as tampering',
        "severity": 'critical',
        "evidence_kinds_required": ['manifest-record'],
        "reverify_steps": ['recompute'],
    },
    'replay-dirty-codebase-seal': {
        "domain": 'replay',
        "code": 'replay-dirty-codebase-seal',
        "human": 'replay manifest: a tool call recorded a dirty codebase; '
                 'sealing (or verifying) a dirty chain is refused -- a dirty '
                 'codebase is never sealed',
        "severity": 'high',
        "evidence_kinds_required": ['manifest-record'],
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
    'replay-malformed': {
        "domain": 'replay',
        "code": 'replay-malformed',
        "human": 'replay manifest: the manifest, link, or builder argument '
                 'is the wrong shape (bad digests, unknown action, bad '
                 'sequence); refusing instead of guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest-record'],
        "reverify_steps": ['re-check-shape'],
    },
    'replay-missing-approval-receipt': {
        "domain": 'replay',
        "code": 'replay-missing-approval-receipt',
        "human": 'replay manifest: an approval_received link has no '
                 'corroboration-receipt reference; an approval without a '
                 'receipt is not sealable',
        "severity": 'high',
        "evidence_kinds_required": ['manifest-record'],
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
    'replay-policy-drift': {
        "domain": 'policy_replay',
        "code": 'replay-policy-drift',
        "human": 'policy replay: the live policy revision differs from the pinned revision and would change the verdict',
        "severity": 'high',
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
    'replay-policy-not-authorization': {
        "domain": 'policy_replay',
        "code": 'replay-policy-not-authorization',
        "human": 'policy replay: replay evidence was used as authority',
        "severity": 'high',
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
    'replay-policy-revision-unknown': {
        "domain": 'policy_replay',
        "code": 'replay-policy-revision-unknown',
        "human": 'policy replay: the pinned revision is not registered',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-revision'],
        "reverify_steps": ['recompute'],
    },
    'replay-presentation-mismatch': {
        "domain": 'replay',
        "code": 'replay-presentation-mismatch',
        "human": 'replay manifest: the verifier-supplied presentation bytes '
                 'do not hash to the recorded presentation_digest; '
                 'what-was-shown disagrees with the record',
        "severity": 'medium',
        "evidence_kinds_required": ['manifest-record'],
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
    'replay-unverifiable-tool-digest': {
        "domain": 'replay',
        "code": 'replay-unverifiable-tool-digest',
        "human": 'replay manifest: a tool call has no verifiable code '
                 'digest pin (missing, malformed, or registry-mismatched); '
                 'unpinned tools are not sealable',
        "severity": 'high',
        "evidence_kinds_required": ['manifest-record'],
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
    'repo-hook-escape-refused': {
        "domain": 'session-trust',
        "code": 'repo-hook-escape-refused',
        "human": 'repo-local git material (.git, .git/config) resolves '
                 'outside the canonical workspace root via symlink; hook '
                 'resolution never follows escapes; refused fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['workspace-root'],
        "reverify_steps": ['recompute'],
    },
    'repo-hook-pretrust-refused': {
        "domain": 'session-trust',
        "code": 'repo-hook-pretrust-refused',
        "human": 'git/subprocess attempt against a workspace with no '
                 'recorded trust decision; refused fail-closed before any '
                 'repo-supplied configuration could execute',
        "severity": 'critical',
        "evidence_kinds_required": ['workspace-root'],
        "reverify_steps": ['recompute'],
    },
    'repo-hook-trust-denied': {
        "domain": 'session-trust',
        "code": 'repo-hook-trust-denied',
        "human": 'git/subprocess attempt against a workspace whose trust '
                 'was explicitly denied; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['workspace-root'],
        "reverify_steps": ['recompute'],
    },
    'reputation-entry-malformed': {
        "domain": 'reputation',
        "code": 'reputation-entry-malformed',
        "human": 'a reputation ledger entry failed schema validation '
                 '(missing fields, bad types, non-canonical JSON); never '
                 'appended, refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'reputation-event-kind-unknown': {
        "domain": 'reputation',
        "code": 'reputation-event-kind-unknown',
        "human": 'a reputation event carried a kind outside the fixed '
                 'weight table; the closed kind vocabulary is load-bearing '
                 'for deterministic scoring, refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'reputation-ledger-tampered': {
        "domain": 'reputation',
        "code": 'reputation-ledger-tampered',
        "human": 'ledger re-validation failed: broken hash chain, bad '
                 'reporter signature, sequence gap, or head digest '
                 'mismatch; the ledger is not recomputable as presented',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
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
    'resource-server-mismatch': {
        "domain": 'transaction',
        "code": 'resource-server-mismatch',
        "human": 'transactional token presented to a resource server it was '
                 'not issued for; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['token'],
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
    'revbind-content-mismatch': {
        "domain": 'revbind',
        "code": 'revbind-content-mismatch',
        "human": 'revision binding: a replayed tool_call pins a content '
                 'digest that does not match the digest bound for this '
                 'chain revision, and no content-equivalence annotation '
                 'covers the change; the replay is refused',
        "severity": 'high',
        "evidence_kinds_required": ['chain', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'revbind-equivalence-accepted': {
        "domain": 'revbind',
        "code": 'revbind-equivalence-accepted',
        "human": 'revision binding: a replayed tool_call pins a '
                 'different content digest than the revision binding, '
                 'but an explicit content_equivalence annotation covers '
                 'the change; accepted and reported (advisory)',
        "severity": 'low',
        "evidence_kinds_required": ['chain', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'revbind-malformed': {
        "domain": 'revbind',
        "code": 'revbind-malformed',
        "human": 'revision binding: the revision label, manifest link, '
                 'or registry argument is the wrong shape (empty '
                 'revision, missing tool id, malformed revision block); '
                 'refusing instead of guessing',
        "severity": 'medium',
        "evidence_kinds_required": ['chain', 'digest'],
        "reverify_steps": ['recompute'],
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
    'revocation-applicable': {
        "domain": 'revocation',
        "code": 'revocation-applicable',
        "human": 'finality-bound revocation: the authorization\'s revocation '
                 'basis is revoked at commit time; the Finality Sink refuses '
                 'check-and-commit and the protected consequence must not '
                 'commit',
        "severity": 'high',
        "evidence_kinds_required": ['authorization', 'revocation-registry',
                                   'digest'],
        "reverify_steps": ['recompute-digest', 'check-revocation'],
    },
    'revocation-basis-malformed': {
        "domain": 'revocation',
        "code": 'revocation-basis-malformed',
        "human": 'finality-bound revocation: the revocation basis or the '
                 'authorization record is malformed; refused fail-closed, '
                 'never a silent pass',
        "severity": 'medium',
        "evidence_kinds_required": ['authorization'],
        "reverify_steps": ['recompute'],
    },
    'revocation-basis-tampered': {
        "domain": 'revocation',
        "code": 'revocation-basis-tampered',
        "human": 'finality-bound revocation: the recomputed binding digest '
                 'disagrees with the claimed binding; the binding was not '
                 're-derived from issuer trust',
        "severity": 'critical',
        "evidence_kinds_required": ['authorization', 'digest'],
        "reverify_steps": ['recompute-digest'],
    },
    'revocation-category-error': {
        "domain": 'axis',
        "code": 'revocation-category-error',
        "human": 'axis/result model: a non-revocation state (suspension '
                 'or expiry) was presented as revocation; refusing the '
                 'category error',
        "severity": 'high',
        "evidence_kinds_required": ['verification-result'],
        "reverify_steps": ['recompute'],
    },
    'revocation-check-unsealed': {
        "domain": 'revocation',
        "code": 'revocation-check-unsealed',
        "human": 'finality-bound revocation: the revocation store mutated '
                 'between the check and the commit decision (TOCTOU); the '
                 'check-and-commit was not atomic and is refused',
        "severity": 'high',
        "evidence_kinds_required": ['authorization', 'revocation-registry'],
        "reverify_steps": ['check-revocation'],
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
    'revocation-push-event-malformed': {
        "domain": 'revocation-push',
        "code": 'revocation-push-event-malformed',
        "human": 'revocation-push: the event envelope violates the typed '
                 'schema (event_id, event_type, subject, issued_at); '
                 'refused before any fan-out',
        "severity": 'medium',
        "evidence_kinds_required": ['revocation-event'],
        "reverify_steps": ['recompute'],
    },
    'revocation-push-event-replayed': {
        "domain": 'revocation-push',
        "code": 'revocation-push-event-replayed',
        "human": 'revocation-push: duplicate event_id; the original '
                 'receipt is returned idempotently, bound sessions are '
                 'not re-terminated, callbacks fire exactly once',
        "severity": 'low',
        "evidence_kinds_required": ['revocation-event'],
        "reverify_steps": ['recompute'],
    },
    'revocation-push-event-unsigned': {
        "domain": 'revocation-push',
        "code": 'revocation-push-event-unsigned',
        "human": 'revocation-push: the hub requires signed events and '
                 'the event carries no (or a bad) HMAC; an '
                 'unauthenticated kill channel is a session-DoS vector; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['revocation-event', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'revocation-push-refused': {
        "domain": 'revocation-push',
        "code": 'revocation-push-refused',
        "human": 'revocation-push: the hub refused a caller-side misuse '
                 '(bad registration shape, duplicate session id, hub '
                 're-entry from a terminate callback); fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['revocation-event'],
        "reverify_steps": ['recompute'],
    },
    'revocation-push-session-suspended': {
        "domain": 'revocation-push',
        "code": 'revocation-push-session-suspended',
        "human": 'revocation-push: the terminate callback raised or the '
                 'liveness probe could not confirm the kill; the session '
                 'is suspended fail-closed and may not continue silently',
        "severity": 'high',
        "evidence_kinds_required": ['revocation-event', 'session-binding'],
        "reverify_steps": ['recompute'],
    },
    'revocation-push-session-terminated': {
        "domain": 'revocation-push',
        "code": 'revocation-push-session-terminated',
        "human": 'revocation-push: a revocation event matched the '
                 'session subject; the in-flight session was terminated '
                 'via its kill callback (F417 closure)',
        "severity": 'low',
        "evidence_kinds_required": ['revocation-event', 'session-binding'],
        "reverify_steps": ['recompute'],
    },
    'revocation-push-session-unknown': {
        "domain": 'revocation-push',
        "code": 'revocation-push-session-unknown',
        "human": 'revocation-push: require_live on a session id the hub '
                 'never registered; liveness of an unregistered session '
                 'cannot be proven; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['session-binding'],
        "reverify_steps": ['recompute'],
    },
    'revocation-push-subject-unbound': {
        "domain": 'revocation-push',
        "code": 'revocation-push-subject-unbound',
        "human": 'revocation-push: the event subject matches no live '
                 'registered session; acknowledged, nothing terminated',
        "severity": 'low',
        "evidence_kinds_required": ['revocation-event'],
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
    'revocation-retired-reuse': {
        "domain": 'revocation',
        "code": 'revocation-retired-reuse',
        "human": 'credential revocation lineage: a retired credential '
                 '(rotation successor named) was presented again; reuse '
                 'of a retired credential is a REVOCATION EVENT, not an '
                 'authentication failure -- refused LOUD',
        "severity": 'high',
        "evidence_kinds_required": ['revocation-registry', 'signature',
                                   'revocation-status'],
        "reverify_steps": ['verify-signature', 'check-revocation'],
    },
    'revocation-revoked': {
        "domain": 'revocation',
        "code": 'revocation-revoked',
        "human": 'credential revocation lineage: the presented credential '
                 'has been revoked; revoked credentials are refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['revocation-registry', 'signature',
                                   'revocation-status'],
        "reverify_steps": ['verify-signature', 'check-revocation'],
    },
    'revocation-sink-nonatomic': {
        "domain": 'revocation',
        "code": 'revocation-sink-nonatomic',
        "human": 'finality-bound revocation: the revocation store does not '
                 'implement the atomic check protocol; the Finality Sink '
                 'fails closed rather than check-then-act',
        "severity": 'high',
        "evidence_kinds_required": ['authorization'],
        "reverify_steps": ['recompute'],
    },
    'revocation-state-unknown': {
        "domain": 'axis',
        "code": 'revocation-state-unknown',
        "human": 'axis/result model: the revocation state is unknown, so '
                 'the credential is classified not-active (fail-closed); '
                 'unknown is never active',
        "severity": 'high',
        "evidence_kinds_required": ['verification-result'],
        "reverify_steps": ['recompute'],
    },
    'revocation-status-unverifiable': {
        "domain": 'revocation',
        "code": 'revocation-status-unverifiable',
        "human": 'credential revocation lineage: the revocation status '
                 'envelope is malformed, signed by the wrong key, or '
                 'covers an unknown rid; unknown is never active -- '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['revocation-registry', 'signature',
                                   'revocation-status'],
        "reverify_steps": ['verify-signature', 'check-revocation'],
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
    'rsl-fork-detected': {
        "domain": 'bundle',
        "code": 'rsl-fork-detected',
        "human": 'bundle RSL: two state entries for one bundle share a parent or a sequence number; the log forked; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'rsl-log-corrupt': {
        "domain": 'bundle',
        "code": 'rsl-log-corrupt',
        "human": 'bundle RSL: the state log failed chain verification (break, gap, or tamper); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'rsl-rollback-attempt': {
        "domain": 'bundle',
        "code": 'rsl-rollback-attempt',
        "human": 'bundle RSL: an ancestor state digest was pinned or re-recorded as current; downgrades are refused loudly, never applied silently',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'rsl-rule-expired': {
        "domain": 'bundle',
        "code": 'rsl-rule-expired',
        "human": 'bundle RSL: the rule file is expired; expiry is enforced at creation, open, and every operation',
        "severity": 'high',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['recompute'],
    },
    'rsl-skipped-revoked': {
        "domain": 'bundle',
        "code": 'rsl-skipped-revoked',
        "human": 'bundle RSL: a state entry in the chain carries a skip (revocation) annotation; verification fails closed',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'rsl-terminal-rule-unsigned': {
        "domain": 'bundle',
        "code": 'rsl-terminal-rule-unsigned',
        "human": 'bundle RSL: the rule file lacks a valid terminal-key signature over the rule body; the always-last allow-rule is unsigned',
        "severity": 'high',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['recompute'],
    },
    'rsl-threshold-invalid': {
        "domain": 'bundle',
        "code": 'rsl-threshold-invalid',
        "human": 'bundle RSL: a delegation threshold is outside [1, principals]; refused at rule-creation time, not at evaluation',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['recompute'],
    },
    'rsl-transition-unauthorized': {
        "domain": 'bundle',
        "code": 'rsl-transition-unauthorized',
        "human": 'bundle RSL: a state upgrade has no threshold-satisfying signed transition authorization; refused',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest', 'signature'],
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
    'sandbox-landlock-apply-failed': {
        "domain": 'sandbox',
        "code": 'sandbox-landlock-apply-failed',
        "human": 'sandbox: the Landlock filesystem tier was requested but '
                 'the ruleset could not be built or enforced for this call; '
                 'refused fail-closed — the tool never runs under the weak '
                 'tier while the deployment asked for the strong one',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'sandbox-landlock-required': {
        "domain": 'sandbox',
        "code": 'sandbox-landlock-required',
        "human": 'sandbox: the Landlock filesystem tier was required but is '
                 'unavailable on this kernel/LSM; refused fail-closed rather '
                 'than running without the required layer',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'sandbox-landlock-unavailable': {
        "domain": 'sandbox',
        "code": 'sandbox-landlock-unavailable',
        "human": 'sandbox: the Landlock filesystem tier was requested but is '
                 'unavailable on this kernel/LSM; the call ran with the '
                 'remaining defense-in-depth limits only',
        "severity": 'low',
        "evidence_kinds_required": ['assessment'],
        "reverify_steps": ['recompute'],
    },
    'sandbox-policy-drift': {
        "domain": 'sandbox',
        "code": 'sandbox-policy-drift',
        "human": 'sandbox: the live sandbox-policy document differs from '
                 'its committed pin (any diff, including subset/superset '
                 'changes, is a drift); refused fail-closed -- a sandbox '
                 'never runs under a changed policy',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'sandbox-policy-host-mismatch': {
        "domain": 'sandbox',
        "code": 'sandbox-policy-host-mismatch',
        "human": 'sandbox: the sandbox policy declares isolation '
                 'requirements (namespaces) the host/executor cannot '
                 'enforce; refused fail-closed rather than running '
                 'degraded under a stronger declaration',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'sandbox-policy-invalid': {
        "domain": 'sandbox',
        "code": 'sandbox-policy-invalid',
        "human": 'sandbox: the sandbox-policy document or syscall rule is '
                 'malformed (unknown field, bad grammar, pin-store '
                 'corruption); refused at compile time, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'sandbox-policy-kill': {
        "domain": 'sandbox',
        "code": 'sandbox-policy-kill',
        "human": 'sandbox: the compiled syscall policy killed a syscall '
                 'decision; emitted as a digest-bound audit event per '
                 'execution',
        "severity": 'low',
        "evidence_kinds_required": ['signal'],
        "reverify_steps": ['recompute'],
    },
    'sandbox-policy-no-default': {
        "domain": 'sandbox',
        "code": 'sandbox-policy-no-default',
        "human": 'sandbox: the syscall policy declares no explicit DEFAULT '
                 'action; fail-closed by construction (no DEFAULT -> KILL) '
                 '-- refused at compile time',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'sandbox-policy-unpinned': {
        "domain": 'sandbox',
        "code": 'sandbox-policy-unpinned',
        "human": 'sandbox: execution was attempted under a sandbox policy '
                 'with no committed pin; refused fail-closed -- sandboxes '
                 'run only under pinned, reviewable policy',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'sandbox-real-credential-blocked': {
        "domain": 'sandbox',
        "code": 'sandbox-real-credential-blocked',
        "human": 'sandbox: a value byte-equal to a vault-registered real '
                 'credential was observed crossing the sandbox boundary '
                 '(environment, argv, or stdin); refused fail-closed before '
                 'spawn — the sandboxed (untrusted) side never receives real '
                 'credentials, only sentinel placeholders',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
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
    'satisfied-missing': {
        "domain": 'evaluation',
        "code": 'satisfied-missing',
        "human": 'evidence presented below grade SATISFIED as '
                 'authorization or as satisfied: VERIFIED (crypto '
                 'measured true) is not authorization; sufficiency '
                 'is never asserted without the requirements met',
        "severity": 'high',
        "evidence_kinds_required": ['evidence-record', 'gate-verdict'],
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
    'schema-record-malformed': {
        "domain": 'schema-ref',
        "code": 'schema-record-malformed',
        "human": 'the tool schema is not a dict, carries a non-string '
                 '$ref, a dangling in-document pointer, or a cyclic '
                 'container; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record', 'schema'],
        "reverify_steps": ['recompute'],
    },
    'schema-ref-budget-exhausted': {
        "domain": 'schema-ref',
        "code": 'schema-ref-budget-exhausted',
        "human": 'tool-schema $ref resolutions exhausted '
                 'max_resolution_steps (event-loop freeze bound); '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record', 'schema'],
        "reverify_steps": ['recompute'],
    },
    'schema-ref-depth-exceeded': {
        "domain": 'schema-ref',
        "code": 'schema-ref-depth-exceeded',
        "human": 'in-document $ref resolution exceeded max_ref_depth or '
                 'revisited a pointer already on the resolution chain '
                 '(cycle); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record', 'schema'],
        "reverify_steps": ['recompute'],
    },
    'schema-ref-external': {
        "domain": 'schema-ref',
        "code": 'schema-ref-external',
        "human": 'a tool-schema $ref ($recursiveRef/$dynamicRef) does '
                 'not start with # and is therefore out-of-document; '
                 'refused fail-closed and never fetched',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record', 'schema'],
        "reverify_steps": ['recompute'],
    },
    'schema-refs-resolved': {
        "domain": 'schema-ref',
        "code": 'schema-refs-resolved',
        "human": 'every $ref in the tool schema resolved in-document, '
                 'acyclically, and within budget; allowed with '
                 'resolution statistics',
        "severity": 'low',
        "evidence_kinds_required": ['schema'],
        "reverify_steps": ['recompute'],
    },
    'scope-consent-expired': {
        "domain": 'scope-listing',
        "code": 'scope-consent-expired',
        "human": 'scope-gated listing: an out-of-band consent token was '
                 'presented after its TTL; the consent is not recorded',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'scope-consent-forged': {
        "domain": 'scope-listing',
        "code": 'scope-consent-forged',
        "human": 'scope-gated listing: a consent token failed MAC '
                 'verification (forged, wrong key, or malformed); no '
                 'consent is recorded — there is no path to record '
                 'approval without the human step',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'scope-consent-unbound': {
        "domain": 'scope-listing',
        "code": 'scope-consent-unbound',
        "human": 'scope-gated listing: a genuine consent token was '
                 'presented for a different approval/tool/subject than it '
                 'was minted for; the consent is not recorded',
        "severity": 'high',
        "evidence_kinds_required": ['receipt', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'scope-grant-tampered': {
        "domain": 'token-scope',
        "code": 'scope-grant-tampered',
        "human": 'the scope grant MAC does not cover the presented bytes; '
                 'tamper is reported as tamper, never as a scope gap',
        "severity": 'critical',
        "evidence_kinds_required": ['grant', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'scope-grant-unbound': {
        "domain": 'token-scope',
        "code": 'scope-grant-unbound',
        "human": 'the scope grant is bound to a different token than the '
                 'one presented (e.g. scope narrowed mid-session); a new '
                 'grant is required',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'token'],
        "reverify_steps": ['recompute'],
    },
    'scope-key-missing': {
        "domain": 'token-scope',
        "code": 'scope-key-missing',
        "human": 'no deployment key supplied for scope policy/grant '
                 'cryptography; fails closed (no dev-key fallback)',
        "severity": 'high',
        "evidence_kinds_required": ['key-reference'],
        "reverify_steps": ['recompute'],
    },
    'scope-listing-denied': {
        "domain": 'scope-listing',
        "code": 'scope-listing-denied',
        "human": 'scope-gated listing: the caller ticket scopes do not '
                 'cover the tool (exact-match scope comparison; '
                 'read != read-admin); the call never runs',
        "severity": 'high',
        "evidence_kinds_required": ['policy-declaration', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'scope-listing-not-registered': {
        "domain": 'scope-listing',
        "code": 'scope-listing-not-registered',
        "human": 'scope-gated listing: the named tool is not registered '
                 'in the scope-gated registry; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'scope-listing-subject-mismatch': {
        "domain": 'scope-listing',
        "code": 'scope-listing-subject-mismatch',
        "human": 'scope-gated listing: the asserted presenter subject '
                 'does not match the sealed ticket\'s bound subject '
                 '(constant-time comparison); the call never runs',
        "severity": 'high',
        "evidence_kinds_required": ['policy-declaration', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'scope-listing-unknown-scope': {
        "domain": 'scope-listing',
        "code": 'scope-listing-unknown-scope',
        "human": 'scope-gated listing: a presented scope is outside the '
                 'deployment-declared scope universe; refused fail-closed '
                 '(the issuer never mints what it cannot interpret)',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'scope-policy-tampered': {
        "domain": 'token-scope',
        "code": 'scope-policy-tampered',
        "human": 'the sealed scope policy MAC does not cover its spec '
                 'bytes, or the spec fails shape validation; refused '
                 'fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['policy-declaration', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'scope-verdict-mismatched': {
        "domain": 'token-scope',
        "code": 'scope-verdict-mismatched',
        "human": 'a scope verdict presented to the executor for different '
                 '(tool, action) parameters than it was granted for; the '
                 'call never runs',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'policy-declaration'],
        "reverify_steps": ['recompute'],
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
    'scoped-approval-capability-unknown': {
        "domain": 'scoped',
        "code": 'scoped-approval-capability-unknown',
        "human": 'closure-scoped approval: the requested capability was '
                 'never granted by this packet',
        "severity": 'medium',
        "evidence_kinds_required": ['approval-packet'],
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
    'seeded-denial-digest-mismatch': {
        "domain": 'seeded_denial',
        "code": 'seeded-denial-digest-mismatch',
        "human": 'seeded denials: the record digest does not recompute from '
                 'its body (tampered or misbound)',
        "severity": 'critical',
        "evidence_kinds_required": ['receipt', 'digest'],
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
    'seeded-denial-not-authorization': {
        "domain": 'seeded_denial',
        "code": 'seeded-denial-not-authorization',
        "human": 'seeded denials: denial evidence was used as authority',
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
    'self_delegation': {
        "domain": 'approval',
        "code": 'self_delegation',
        "human": 'approval and delegation: self-delegation was refused',
        "severity": 'high',
        "evidence_kinds_required": ['grant', 'delegation', 'signature', 'store'],
        "reverify_steps": ['recompute'],
    },
    'sessbind-domain-mismatch': {
        "domain": 'sessbind',
        "code": 'sessbind-domain-mismatch',
        "human": 'session-bound presentation: the token info domain does '
                 'not match the verifier role (receipt vs approval vs '
                 'decision); confused-deputy attempt refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['presentation'],
        "reverify_steps": ['recompute'],
    },
    'sessbind-ehd-mismatch': {
        "domain": 'sessbind',
        "code": 'sessbind-ehd-mismatch',
        "human": 'session-bound presentation: the token EHD does not match '
                 'H(nonce || pinned verifier key); the session is bound to '
                 'a different ephemeral key; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['presentation'],
        "reverify_steps": ['recompute'],
    },
    'sessbind-malformed': {
        "domain": 'sessbind',
        "code": 'sessbind-malformed',
        "human": 'session-bound presentation: malformed token, transcript '
                 'record, or API argument; refused fail-closed, never a '
                 'silent accept',
        "severity": 'medium',
        "evidence_kinds_required": ['presentation'],
        "reverify_steps": ['recompute'],
    },
    'sessbind-ok': {
        "domain": 'sessbind',
        "code": 'sessbind-ok',
        "human": 'session-bound presentation: signature, transcript, EHD, '
                 'domain, and expiry all verified for this session; the '
                 'artifact was shown in-session by the pinned key',
        "severity": 'low',
        "evidence_kinds_required": ['presentation'],
        "reverify_steps": ['recompute'],
    },
    'sessbind-signature-invalid': {
        "domain": 'sessbind',
        "code": 'sessbind-signature-invalid',
        "human": 'session-bound presentation: the presentation signature '
                 'does not verify under the pinned key; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['presentation'],
        "reverify_steps": ['recompute'],
    },
    'sessbind-token-expired': {
        "domain": 'sessbind',
        "code": 'sessbind-token-expired',
        "human": 'session-bound presentation: the token is expired (or not '
                 'yet valid) at the verifier now; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['presentation'],
        "reverify_steps": ['recompute'],
    },
    'sessbind-transcript-mismatch': {
        "domain": 'sessbind',
        "code": 'sessbind-transcript-mismatch',
        "human": 'session-bound presentation: the token transcript digest '
                 'does not match the verifier session transcript; cross-'
                 'session replay refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['presentation'],
        "reverify_steps": ['recompute'],
    },
    'sessbind-verifier-misconfigured': {
        "domain": 'sessbind',
        "code": 'sessbind-verifier-misconfigured',
        "human": 'session-bound presentation: no verifier is configured '
                 'for the signer key, or the provider failed; refused '
                 'fail-closed with a loud journal entry',
        "severity": 'medium',
        "evidence_kinds_required": ['presentation'],
        "reverify_steps": ['recompute'],
    },
    'session-trust-malformed': {
        "domain": 'session-trust',
        "code": 'session-trust-malformed',
        "human": 'trust record malformed: unknown trust state or unnamed '
                 'deciding principal; refused fail-closed, never a silent '
                 'accept',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-record'],
        "reverify_steps": ['recompute'],
    },
    'shield-bad-id': {
        "domain": 'guardrail',
        "code": 'shield-bad-id',
        "human": 'shield registry: shield_id must be a non-empty string; '
                 'the declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'shield-bad-params': {
        "domain": 'guardrail',
        "code": 'shield-bad-params',
        "human": 'shield registry: shield params must be JSON-serializable; '
                 'the declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'shield-bad-provider-kind': {
        "domain": 'guardrail',
        "code": 'shield-bad-provider-kind',
        "human": 'shield registry: unknown shield provider kind; the '
                 'declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'shield-bad-verdict': {
        "domain": 'guardrail',
        "code": 'shield-bad-verdict',
        "human": 'shield registry: a shield returned a verdict outside the '
                 'allow/violation contract; fail-closed, the run is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'shield-duplicate-id': {
        "domain": 'guardrail',
        "code": 'shield-duplicate-id',
        "human": 'shield registry: a shield id is already registered; the '
                 'duplicate declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'shield-no-run': {
        "domain": 'guardrail',
        "code": 'shield-no-run',
        "human": 'shield registry: the shield declares no runnable check; '
                 'attaching it is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'shield-non-verdict': {
        "domain": 'guardrail',
        "code": 'shield-non-verdict',
        "human": 'shield registry: a shield run returned a non-verdict '
                 'object; fail-closed, the run is refused',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'shield-remote-no-endpoint': {
        "domain": 'guardrail',
        "code": 'shield-remote-no-endpoint',
        "human": 'shield registry: a remote shield declared no http(s) '
                 'endpoint; the declaration is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'shield-unknown-id': {
        "domain": 'guardrail',
        "code": 'shield-unknown-id',
        "human": 'shield registry: an attach list named a shield id the '
                 'registry never declared; refused fail-closed rather than '
                 'silently skipping the shield',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'shield-violation': {
        "domain": 'guardrail',
        "code": 'shield-violation',
        "human": 'shield registry: a shield raised its declared intentional-'
                 'block signal (violation verdict); the guarded action is '
                 'refused',
        "severity": 'medium',
        "evidence_kinds_required": ['guardrail-run'],
        "reverify_steps": ['recompute'],
    },
    'short-lived-credential-chain-broken': {
        "domain": 'short-lived-credential',
        "code": 'short-lived-credential-chain-broken',
        "human": 'credential journal: HMAC chain verification failed on '
                 'load -- an event was not made by a key holder or was '
                 'tampered after write; failed closed',
        "severity": 'high',
        "evidence_kinds_required": ['credential-record'],
        "reverify_steps": ['recompute'],
    },
    'short-lived-credential-corrupted': {
        "domain": 'short-lived-credential',
        "code": 'short-lived-credential-corrupted',
        "human": 'credential journal: the underlying durable journal '
                 'failed verification (chain break, torn tail); failed '
                 'closed',
        "severity": 'high',
        "evidence_kinds_required": ['credential-record'],
        "reverify_steps": ['recompute'],
    },
    'short-lived-credential-expired': {
        "domain": 'short-lived-credential',
        "code": 'short-lived-credential-expired',
        "human": 'a presented credential is past its TTL; refused '
                 'fail-closed and the expiry is journaled',
        "severity": 'medium',
        "evidence_kinds_required": ['credential-record'],
        "reverify_steps": ['recompute'],
    },
    'short-lived-credential-key-weak': {
        "domain": 'short-lived-credential',
        "code": 'short-lived-credential-key-weak',
        "human": 'credential journal: the HMAC key is missing, malformed, '
                 'or too short; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['credential-record'],
        "reverify_steps": ['recompute'],
    },
    'short-lived-credential-malformed': {
        "domain": 'short-lived-credential',
        "code": 'short-lived-credential-malformed',
        "human": 'credential issuance: principal, scope, ttl, or issuer '
                 'configuration is malformed; refused instead of guessed',
        "severity": 'low',
        "evidence_kinds_required": ['credential-record'],
        "reverify_steps": ['recompute'],
    },
    'short-lived-credential-revoked': {
        "domain": 'short-lived-credential',
        "code": 'short-lived-credential-revoked',
        "human": 'a presented credential was revoked before expiry; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['credential-record'],
        "reverify_steps": ['recompute'],
    },
    'short-lived-credential-scope-forbidden': {
        "domain": 'short-lived-credential',
        "code": 'short-lived-credential-scope-forbidden',
        "human": 'credential issuance or verification: a wildcard scope '
                 'was requested without explicit opt-in, or the presented '
                 'scope does not match the bound scope; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['credential-record'],
        "reverify_steps": ['recompute'],
    },
    'short-lived-credential-ttl-unbounded': {
        "domain": 'short-lived-credential',
        "code": 'short-lived-credential-ttl-unbounded',
        "human": 'credential issuance: the TTL is missing, non-positive, '
                 'or above the configured maximum; unbounded leases are '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['credential-record'],
        "reverify_steps": ['recompute'],
    },
    'short-lived-credential-unknown': {
        "domain": 'short-lived-credential',
        "code": 'short-lived-credential-unknown',
        "human": 'a presented credential id is unknown or its secret does '
                 'not match; refused with a single code so id-existence '
                 'is not leaked',
        "severity": 'medium',
        "evidence_kinds_required": ['credential-record'],
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
    'signed-receipt-malformed': {
        "domain": 'kms-signer',
        "code": 'signed-receipt-malformed',
        "human": 'the receipt or signed record is not the shape the '
                 'discipline speaks; includes post-signing mutation '
                 'detected via the canonical digest',
        "severity": 'medium',
        "evidence_kinds_required": ['signed-receipt'],
        "reverify_steps": ['recompute'],
    },
    'signed-receipt-signature-invalid': {
        "domain": 'kms-signer',
        "code": 'signed-receipt-signature-invalid',
        "human": 'the consumer-pinned verifier did not return True for '
                 'the retained bytes; never verified',
        "severity": 'high',
        "evidence_kinds_required": ['signed-receipt'],
        "reverify_steps": ['recompute'],
    },
    'signer-adapter-tampered': {
        "domain": 'kms-signer',
        "code": 'signer-adapter-tampered',
        "human": 'a declared KMS adapter handle wraps in-process key '
                 'material; refused for production receipts',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
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
    'signer-digest-length-mismatch': {
        "domain": 'signer-interop',
        "code": 'signer-digest-length-mismatch',
        "human": 'caller-supplied digest length does not match the stated hash digest size (the cosign sign-side loud failure shape)',
        "severity": 'high',
        "evidence_kinds_required": ['signature'],
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
    'signer-hash-downshift-refused': {
        "domain": 'signer-interop',
        "code": 'signer-hash-downshift-refused',
        "human": 'curve/hash pairing reproduces the cosign sign-side SHA-256 hardcode shape; refused loudly, never silently downshifted',
        "severity": 'high',
        "evidence_kinds_required": ['signature'],
        "reverify_steps": ['recompute'],
    },
    'signer-identity-mismatch': {
        "domain": 'kms-signer',
        "code": 'signer-identity-mismatch',
        "human": 'a signed receipt verified against a different adapter '
                 'identity than the one that signed it',
        "severity": 'high',
        "evidence_kinds_required": ['signed-receipt'],
        "reverify_steps": ['recompute'],
    },
    'signer-key-material-in-process': {
        "domain": 'kms-signer',
        "code": 'signer-key-material-in-process',
        "human": 'raw private-key bytes in an input path (signer '
                 'argument, declaration config, env-derived value); '
                 'the signing key is never in-process',
        "severity": 'high',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'signer-unavailable': {
        "domain": 'kms-signer',
        "code": 'signer-unavailable',
        "human": 'the KMS adapter could not be used (unreachable, '
                 'misconfigured, declared-but-unconnected); failed '
                 'closed with no fallback to in-process signing',
        "severity": 'medium',
        "evidence_kinds_required": ['gate-record'],
        "reverify_steps": ['recompute'],
    },
    'sigstore-keyed-envelope': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-envelope',
        "human": 'keyed sigstore bundle: dsseEnvelope shape violations;'
                 'refused at parse, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-hint-mismatch': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-hint-mismatch',
        "human": 'keyed sigstore bundle: verificationMaterial.publicKey hint'
                 'is neither empty nor the pinned key fingerprint; refused,'
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-keyid-mismatch': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-keyid-mismatch',
        "human": 'keyed sigstore bundle: DSSE keyid is neither empty nor'
                 'absent (hint-consistency MUST); refused, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-malformed': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-malformed',
        "human": 'keyed sigstore bundle: bundle/envelope shape violations (not'
                 'a dict, bad base64, missing fields, bad key types); refused'
                 'at parse, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-media-type': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-media-type',
        "human": 'keyed sigstore bundle: mediaType is not the pinned v0.3'
                 'value; refused, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-message-signature-unexpected': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-message-signature-unexpected',
        "human": 'keyed sigstore bundle: bundle carries a messageSignature'
                 '(v0.3 content oneof is message_signature XOR dsse_envelope);'
                 'refused, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-multi-signature': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-multi-signature',
        "human": 'keyed sigstore bundle: signatures list length != 1 (exactly'
                 'one signature per envelope); refused, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-payload-type': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-payload-type',
        "human": 'keyed sigstore bundle: payloadType is not the auditor-pinned'
                 'value; refused, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-signature-invalid': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-signature-invalid',
        "human": 'keyed sigstore bundle: the single Ed25519 signature does not'
                 'verify over PAE(payloadType, payload) under the pinned key;'
                 'refused, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-subject-mismatch': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-subject-mismatch',
        "human": 'keyed sigstore bundle: in-toto statement subject digest does'
                 'not name the caller-expected evidence digest'
                 '(artifact+signature+key binding); refused, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-timestamp-unexpected': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-timestamp-unexpected',
        "human": 'keyed sigstore bundle: non-empty timestampVerificationData'
                 'on an offline bundle; refused, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-tlog-unexpected': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-tlog-unexpected',
        "human": 'keyed sigstore bundle: non-empty tlogEntries on an offline'
                 'bundle; refused, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'sigstore-keyed-verification-material': {
        "domain": 'evbundle',
        "code": 'sigstore-keyed-verification-material',
        "human": 'keyed sigstore bundle: verificationMaterial is not the'
                 'form-(1) oneof (missing publicKey, or'
                 'x509CertificateChain/certificate/publicKeyIdentifier'
                 'present, or non-hint keys inside publicKey); refused, fail-'
                 'closed',
        "severity": 'medium',
        "evidence_kinds_required": ['bundle'],
        "reverify_steps": ['re-parse-bundle', 're-verify-signature'],
    },
    'single-use-issuer-revoked': {
        "domain": 'single_use',
        "code": 'single-use-issuer-revoked',
        "human": 'single-use attestation: the attestation issuer has been revoked',
        "severity": 'high',
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
    'single-use-malformed': {
        "domain": 'single_use',
        "code": 'single-use-malformed',
        "human": 'single-use attestation: the input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['attestation', 'revocation-registry'],
        "reverify_steps": ['check-not-consumed', 'check-issuer-revocation'],
    },
    'single-use-not-reserved': {
        "domain": 'single_use',
        "code": 'single-use-not-reserved',
        "human": 'single-use lifecycle: execution was attempted with no live reservation for the (approval digest, step id, input digest) triple',
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
    'single-use-replay-refused': {
        "domain": 'single_use',
        "code": 'single-use-replay-refused',
        "human": 'single-use attestation: replay of a consumed single-use attestation was refused',
        "severity": 'high',
        "evidence_kinds_required": ['attestation', 'revocation-registry'],
        "reverify_steps": ['check-not-consumed', 'check-issuer-revocation'],
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
    'single-use-reserve-conflict': {
        "domain": 'single_use',
        "code": 'single-use-reserve-conflict',
        "human": 'single-use lifecycle: atomic reserve of the (approval digest, step id, input digest) triple lost the race; the second consumer was refused',
        "severity": 'high',
        "evidence_kinds_required": ['reservation', 'approval-digest'],
        "reverify_steps": ['check-not-consumed', 'check-approval-registered'],
    },
    'single-use-unknown': {
        "domain": 'single_use',
        "code": 'single-use-unknown',
        "human": 'single-use attestation: the single-use attestation is not known',
        "severity": 'medium',
        "evidence_kinds_required": ['attestation', 'revocation-registry'],
        "reverify_steps": ['check-not-consumed', 'check-issuer-revocation'],
    },
    'skill-admission-artifact-rule-violated': {
        "domain": 'skill-admission',
        "code": 'skill-admission-artifact-rule-violated',
        "human": 'a step link\'s materials/products violated the '
                 'layout-authorized artifact rules (absent material, '
                 'digest mismatch, or unconsumed leftover); a step that '
                 'produced nothing cannot pass a REQUIRE-products rule',
        "severity": 'high',
        "evidence_kinds_required": ['admission-record', 'link-record'],
        "reverify_steps": ['recompute'],
    },
    'skill-admission-authority-is-step-signer': {
        "domain": 'skill-admission',
        "code": 'skill-admission-authority-is-step-signer',
        "human": 'the layout authority key is also a step signer key; '
                 'authorization and execution must be separate '
                 'principals, structurally, never by convention',
        "severity": 'high',
        "evidence_kinds_required": ['admission-record', 'layout-record'],
        "reverify_steps": ['recompute'],
    },
    'skill-admission-command-mismatch': {
        "domain": 'skill-admission',
        "code": 'skill-admission-command-mismatch',
        "human": 'the command a step actually ran differs from the '
                 'layout-authorized command; command substitution is a '
                 'hard refusal, never a warning',
        "severity": 'high',
        "evidence_kinds_required": ['admission-record', 'link-record'],
        "reverify_steps": ['recompute'],
    },
    'skill-admission-layout-malformed': {
        "domain": 'skill-admission',
        "code": 'skill-admission-layout-malformed',
        "human": 'the skill layout record is malformed (bad shape, '
                 'duplicate steps, invalid rules); refused before any '
                 'cryptographic verification',
        "severity": 'medium',
        "evidence_kinds_required": ['admission-record'],
        "reverify_steps": ['recompute'],
    },
    'skill-admission-layout-signature-invalid': {
        "domain": 'skill-admission',
        "code": 'skill-admission-layout-signature-invalid',
        "human": 'the skill layout signature does not verify under the '
                 'registry-known layout authority key',
        "severity": 'high',
        "evidence_kinds_required": ['admission-record', 'layout-record'],
        "reverify_steps": ['recompute'],
    },
    'skill-admission-link-malformed': {
        "domain": 'skill-admission',
        "code": 'skill-admission-link-malformed',
        "human": 'a step link record is malformed (bad shape, unknown '
                 'step, layout-id mismatch); refused before its '
                 'signature is trusted',
        "severity": 'medium',
        "evidence_kinds_required": ['admission-record'],
        "reverify_steps": ['recompute'],
    },
    'skill-admission-link-missing': {
        "domain": 'skill-admission',
        "code": 'skill-admission-link-missing',
        "human": 'a layout step has no presented link metadata; every '
                 'authorized step must be vouched',
        "severity": 'medium',
        "evidence_kinds_required": ['admission-record'],
        "reverify_steps": ['recompute'],
    },
    'skill-admission-link-signature-invalid': {
        "domain": 'skill-admission',
        "code": 'skill-admission-link-signature-invalid',
        "human": 'a step link signature does not verify under the '
                 'link\'s claimed signer key',
        "severity": 'high',
        "evidence_kinds_required": ['admission-record', 'link-record'],
        "reverify_steps": ['recompute'],
    },
    'skill-admission-unauthorized-signer': {
        "domain": 'skill-admission',
        "code": 'skill-admission-unauthorized-signer',
        "human": 'a step link was signed by a key that is not the '
                 'layout-authorized signer for that step',
        "severity": 'high',
        "evidence_kinds_required": ['admission-record', 'link-record'],
        "reverify_steps": ['recompute'],
    },
    'skill-id-mismatch': {
        "domain": 'capability',
        "code": 'skill-id-mismatch',
        "human": 'capability assessment: the recomputed value does not match the claimed value',
        "severity": 'high',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'skill-update-digest-changed': {
        "domain": 'skill-update',
        "code": 'skill-update-digest-changed',
        "human": 'install gate: same-version reinstall carries a '
                 'different digest than the installed bundle '
                 '(bytes swapped under a pinned version); refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal', 'digest', 'input'],
        "reverify_steps": ['recompute-digest'],
    },
    'skill-update-digest-mismatch': {
        "domain": 'skill-update',
        "code": 'skill-update-digest-mismatch',
        "human": 'install gate: the bundle bytes\' sha256 does not '
                 'match the skill record\'s digest (tampered or '
                 'truncated download); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal', 'digest', 'input'],
        "reverify_steps": ['recompute-digest'],
    },
    'skill-update-index-untrusted': {
        "domain": 'skill-update',
        "code": 'skill-update-index-untrusted',
        "human": 'install gate: no trusted metadata-chain pin for this '
                 'skill (pin missing/malformed, chain stale or '
                 'suspended, or skill unbound); a skill outside the '
                 'verified chain is refused at install',
        "severity": 'high',
        "evidence_kinds_required": ['refusal', 'input'],
        "reverify_steps": ['recompute'],
    },
    'skill-update-malformed': {
        "domain": 'skill-update',
        "code": 'skill-update-malformed',
        "human": 'install gate: the skill record, chain pin, or bundle '
                 'input is malformed; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal', 'input'],
        "reverify_steps": ['recompute'],
    },
    'skill-update-metadata-expired': {
        "domain": 'skill-update',
        "code": 'skill-update-metadata-expired',
        "human": 'install gate: the skill record is past its expiry '
                 '(freeze protection); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal', 'input'],
        "reverify_steps": ['recompute'],
    },
    'skill-update-record-unpinned': {
        "domain": 'skill-update',
        "code": 'skill-update-record-unpinned',
        "human": 'install gate: the skill record\'s digest does not '
                 'match the metadata chain\'s pinned digest '
                 '(mix-and-match or planted record); refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal', 'digest', 'input'],
        "reverify_steps": ['recompute-digest'],
    },
    'skill-update-version-rollback': {
        "domain": 'skill-update',
        "code": 'skill-update-version-rollback',
        "human": 'install gate: the skill record\'s version is older '
                 'than the installed version (downgrade attack); '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal', 'input'],
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
    'spawn-context-declared-risk': {
        "domain": 'spawn-context',
        "code": 'spawn-context-declared-risk',
        "human": 'permission-bypass flags in a user-invoked, '
                 'deployment-vouched, explicitly authorized context; '
                 'allowed-but-declared, never silent',
        "severity": 'low',
        "evidence_kinds_required": ['spawn-record', 'provenance'],
        "reverify_steps": ['recompute', 'authority-check'],
    },
    'spawn-context-record-malformed': {
        "domain": 'spawn-context',
        "code": 'spawn-context-record-malformed',
        "human": 'the spawn/egress/persistence record is not the expected '
                 'shape (unknown spawn context, non-string flags, bad '
                 'ownership class); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['spawn-record'],
        "reverify_steps": ['recompute'],
    },
    'spawn_failed': {
        "domain": 'platform',
        "code": 'spawn_failed',
        "human": 'platform egress: the operation failed; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['egress', 'policy', 'consent'],
        "reverify_steps": ['recompute'],
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
    'stale-authority': {
        "domain": 'authority',
        "code": 'stale-authority',
        "human": 'stale-authority probe class: a receipt minted after the '
                 'cited authority lapsed cites it as normative authority; '
                 'passing such a receipt is the green-on-lapsed-authority '
                 'defect',
        "severity": 'high',
        "evidence_kinds_required": ['authority-citation', 'receipt-timestamp'],
        "reverify_steps": ['recompute'],
    },
    'stale-authority-malformed': {
        "domain": 'authority',
        "code": 'stale-authority-malformed',
        "human": 'stale-authority check: the authority citation or the '
                 'receipt timestamp is malformed; refused fail-closed, '
                 'never a silent pass',
        "severity": 'medium',
        "evidence_kinds_required": ['authority-citation'],
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
    'supervision-capability-rights-exceeded': {
        "domain": 'supervision',
        "code": 'supervision-capability-rights-exceeded',
        "human": 'supervision: a capability grant or route claims rights wider than held -- delegation narrows, never widens; refused',
        "severity": 'high',
        "evidence_kinds_required": ['message'],
        "reverify_steps": ['recompute'],
    },
    'supervision-capability-route-violation': {
        "domain": 'supervision',
        "code": 'supervision-capability-route-violation',
        "human": 'supervision: a use claim on a merely-routed capability -- a parent that only routes a capability cannot exercise it; refused',
        "severity": 'high',
        "evidence_kinds_required": ['message'],
        "reverify_steps": ['recompute'],
    },
    'supervision-capability-undeclared': {
        "domain": 'supervision',
        "code": 'supervision-capability-undeclared',
        "human": 'supervision: a capability use, offer, or exercise names a capability outside the closed inventory -- refused',
        "severity": 'medium',
        "evidence_kinds_required": ['message'],
        "reverify_steps": ['recompute'],
    },
    'supervision-crash-loop': {
        "domain": 'supervision',
        "code": 'supervision-crash-loop',
        "human": 'supervision: the child crashed with the identical reason digest repeatedly -- restart refused as a crash-loop, escalated',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'signature'],
        "reverify_steps": ['verify-signature'],
    },
    'supervision-intensity-exceeded': {
        "domain": 'supervision',
        "code": 'supervision-intensity-exceeded',
        "human": 'supervision: the child exceeded its declared restart intensity bound -- restart refused, escalated to the parent supervisor',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'supervision-invalid': {
        "domain": 'supervision',
        "code": 'supervision-invalid',
        "human": 'supervision: malformed supervisor declaration, crash report, or escalation -- refused',
        "severity": 'low',
        "evidence_kinds_required": ['message'],
        "reverify_steps": ['recompute'],
    },
    'supervision-lease-obligation-expired': {
        "domain": 'supervision',
        "code": 'supervision-lease-obligation-expired',
        "human": 'supervision: a lease re-acquisition obligation expired unsatisfied -- the crashed child was not re-entered; escalated to the parent supervisor',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'signature'],
        "reverify_steps": ['verify-signature'],
    },
    'supervision-undeclared-child': {
        "domain": 'supervision',
        "code": 'supervision-undeclared-child',
        "human": 'supervision: the child is not declared in the supervisor inventory -- the inventory is closed; undeclared children cannot be supervised',
        "severity": 'medium',
        "evidence_kinds_required": ['message'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-delegation-path-unauthorized': {
        "domain": 'supplychain',
        "code": 'supplychain-delegation-path-unauthorized',
        "human": 'supplychain delegation: no delegation covers the skill path; refused',
        "severity": 'high',
        "evidence_kinds_required": ['metadata', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-delegation-revoked': {
        "domain": 'supplychain',
        "code": 'supplychain-delegation-revoked',
        "human": 'supplychain delegation: a previously trusted delegation is absent from the new document (revocation by absence is loud); refused',
        "severity": 'high',
        "evidence_kinds_required": ['metadata', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-delegation-signature-invalid': {
        "domain": 'supplychain',
        "code": 'supplychain-delegation-signature-invalid',
        "human": 'supplychain delegation: the delegation document or authorization statement failed its role threshold; refused',
        "severity": 'high',
        "evidence_kinds_required": ['metadata', 'signature'],
        "reverify_steps": ['verify-signature'],
    },
    'supplychain-eval-start-invalid': {
        "domain": 'supplychain',
        "code": 'supplychain-eval-start-invalid',
        "human": 'supplychain: the pinned evaluation start is not a non-negative epoch number; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-feed-outside-trust-boundary': {
        "domain": 'supplychain',
        "code": 'supplychain-feed-outside-trust-boundary',
        "human": 'supplychain: an advisory document path escapes the configured feed directory (the feed trust boundary); refused',
        "severity": 'medium',
        "evidence_kinds_required": ['advisory', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-frozen': {
        "domain": 'supplychain',
        "code": 'supplychain-frozen',
        "human": 'supplychain: metadata is expired at the pinned evaluation start (freeze); refused',
        "severity": 'high',
        "evidence_kinds_required": ['metadata', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-layout-expired': {
        "domain": 'supplychain',
        "code": 'supplychain-layout-expired',
        "human": 'supplychain: the lifecycle layout is expired at the pinned evaluation start; refused',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-layout-signature-invalid': {
        "domain": 'supplychain',
        "code": 'supplychain-layout-signature-invalid',
        "human": 'supplychain: the lifecycle layout failed the authority threshold; refused',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'signature'],
        "reverify_steps": ['verify-signature'],
    },
    'supplychain-link-chain-broken': {
        "domain": 'supplychain',
        "code": 'supplychain-link-chain-broken',
        "human": 'supplychain: a lifecycle link prev_digest does not chain to the previous link; refused',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-link-unauthorized': {
        "domain": 'supplychain',
        "code": 'supplychain-link-unauthorized',
        "human": 'supplychain: a lifecycle link failed its transition signer threshold; refused',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'signature'],
        "reverify_steps": ['verify-signature'],
    },
    'supplychain-malformed': {
        "domain": 'supplychain',
        "code": 'supplychain-malformed',
        "human": 'supplychain: the delegation, authorization, layout, or link input failed structural validation; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['digest'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-rollback': {
        "domain": 'supplychain',
        "code": 'supplychain-rollback',
        "human": 'supplychain: the delegation document version is older than trusted (rollback); refused',
        "severity": 'high',
        "evidence_kinds_required": ['metadata', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-scan-already-registered': {
        "domain": 'supplychain',
        "code": 'supplychain-scan-already-registered',
        "human": 'background scan: the skill is already registered; '
                 're-registration is refused fail-closed to protect scan '
                 'history (TTL/interval changes go through '
                 'update_skill_registration)',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-report'],
        "reverify_steps": ['register'],
    },
    'supplychain-scan-content-mismatch': {
        "domain": 'supplychain',
        "code": 'supplychain-scan-content-mismatch',
        "human": 'background scan: the installed skill bytes do not match the digest pinned in the authorized statement (SkillJacking shape); the authority check alone cannot see this, so the scanner binds content itself -- refused, report only',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-scan-crash-recovered': {
        "domain": 'supplychain',
        "code": 'supplychain-scan-crash-recovered',
        "human": 'background scan: the previous scheduler run crashed mid-scan (sidecar marker left behind); the affected skill was re-scanned on this run and the recovery is recorded LOUD, never silently resumed',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-report'],
        "reverify_steps": ['re-run'],
    },
    'supplychain-scan-malformed': {
        "domain": 'supplychain',
        "code": 'supplychain-scan-malformed',
        "human": 'background scan: scheduler input (inventory entry, registration args, state record) is malformed; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-report'],
        "reverify_steps": ['re-run'],
    },
    'supplychain-scan-missed-interval': {
        "domain": 'supplychain',
        "code": 'supplychain-scan-missed-interval',
        "human": 'background scan: one or more scheduled scan intervals elapsed without a run (crash, stall, or scheduler down); the missed intervals are caught up LOUD in the report, never silently skipped',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-report'],
        "reverify_steps": ['re-run'],
    },
    'supplychain-scan-state-corrupt': {
        "domain": 'supplychain',
        "code": 'supplychain-scan-state-corrupt',
        "human": 'background scan: the scheduler state file exists but cannot be parsed or has a bad schema; refused fail-closed rather than starting fresh and dropping every baseline',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-report'],
        "reverify_steps": ['re-run'],
    },
    'supplychain-scan-state-missing': {
        "domain": 'supplychain',
        "code": 'supplychain-scan-state-missing',
        "human": 'background scan: no scheduler state file (nothing registered); refused fail-closed rather than silently scanning nothing',
        "severity": 'medium',
        "evidence_kinds_required": ['scan-report'],
        "reverify_steps": ['register'],
    },
    'supplychain-snapshot-mismatch': {
        "domain": 'supplychain',
        "code": 'supplychain-snapshot-mismatch',
        "human": 'supplychain: the delegation wire digest does not match the pinned snapshot binding (mix-and-match); refused',
        "severity": 'high',
        "evidence_kinds_required": ['metadata', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-standing-conflict': {
        "domain": 'supplychain',
        "code": 'supplychain-standing-conflict',
        "human": 'supplychain: concurrent advisories for one artifact disagree on standing and agree on known_since; unresolvable without a human decision; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['advisory', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-standing-flip-unauthenticated': {
        "domain": 'supplychain',
        "code": 'supplychain-standing-flip-unauthenticated',
        "human": 'supplychain: an advisory failed authentication against the feed key; quarantined as untrusted input, never applied',
        "severity": 'high',
        "evidence_kinds_required": ['advisory', 'signature'],
        "reverify_steps": ['verify-signature'],
    },
    'supplychain-standing-flip-unjustified': {
        "domain": 'supplychain',
        "code": 'supplychain-standing-flip-unjustified',
        "human": 'supplychain: a standing flip cites no justification; flips require origin, collector, known_since, and a justification; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['advisory', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-standing-history-rewrite': {
        "domain": 'supplychain',
        "code": 'supplychain-standing-history-rewrite',
        "human": 'supplychain: knowledge supersedes a non-tip journal entry; knowledge must attach at the tip, never rewrite history; refused',
        "severity": 'medium',
        "evidence_kinds_required": ['advisory', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-standing-journal-corrupt': {
        "domain": 'supplychain',
        "code": 'supplychain-standing-journal-corrupt',
        "human": 'supplychain: a standing-verdict journal tip is not a valid knowledge record; refusing rather than guessing at the standing',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-standing-knowledge-unattached': {
        "domain": 'supplychain',
        "code": 'supplychain-standing-knowledge-unattached',
        "human": 'supplychain: an advisory names an artifact outside the standing inventory; recorded as unattached knowledge, never a standing',
        "severity": 'low',
        "evidence_kinds_required": ['advisory', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-standing-lapsed': {
        "domain": 'supplychain',
        "code": 'supplychain-standing-lapsed',
        "human": 'background scan: a skill trust standing TTL expired without a successful re-verification; the standing lapsed (revocation by non-renewal), reported LOUD for the actuator',
        "severity": 'high',
        "evidence_kinds_required": ['scan-report'],
        "reverify_steps": ['re-verify'],
    },
    'supplychain-standing-schema-unknown': {
        "domain": 'supplychain',
        "code": 'supplychain-standing-schema-unknown',
        "human": 'supplychain: an advisory declares an unknown schema version; refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['advisory', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'supplychain-transition-rules-failed': {
        "domain": 'supplychain',
        "code": 'supplychain-transition-rules-failed',
        "human": 'supplychain: a lifecycle transition artifact rules were violated; refused',
        "severity": 'high',
        "evidence_kinds_required": ['bundle', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'surface-admin-unauthenticated': {
        "domain": 'mcp-surface',
        "code": 'surface-admin-unauthenticated',
        "human": 'an admin endpoint declares no auth mechanism; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['surface-config'],
        "reverify_steps": ['recompute'],
    },
    'surface-attestation-key-missing': {
        "domain": 'mcp-surface',
        "code": 'surface-attestation-key-missing',
        "human": 'no deployment issuer key supplied for the secure-'
                 'defaults attestation; refused rather than issuing an '
                 'unsigned attestation',
        "severity": 'medium',
        "evidence_kinds_required": ['key-reference'],
        "reverify_steps": ['recompute'],
    },
    'surface-config-malformed': {
        "domain": 'mcp-surface',
        "code": 'surface-config-malformed',
        "human": 'the surface config is not the expected shape; refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['surface-config'],
        "reverify_steps": ['recompute'],
    },
    'surface-default-credentials': {
        "domain": 'mcp-surface',
        "code": 'surface-default-credentials',
        "human": 'surface credentials are missing, empty, or a well-known '
                 'placeholder/default value; refused fail-closed, never '
                 'auto-remediated',
        "severity": 'high',
        "evidence_kinds_required": ['surface-config'],
        "reverify_steps": ['recompute'],
    },
    'surface-public-unguarded': {
        "domain": 'mcp-surface',
        "code": 'surface-public-unguarded',
        "human": 'a public endpoint declares no execution guard / per-call '
                 'authorization; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['surface-config'],
        "reverify_steps": ['recompute'],
    },
    'surface-transport-bypass': {
        "domain": 'mcp-surface',
        "code": 'surface-transport-bypass',
        "human": 'a stdio/unmediated transport carries traffic outside the '
                 'mediated auth path; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['surface-config'],
        "reverify_steps": ['recompute'],
    },
    'svid-acl-denied': {
        "domain": 'svid',
        "code": 'svid-acl-denied',
        "human": 'mesh control: the presented SVID identity is denied by '
                 'the default-deny ACL; no allow entry admits the '
                 'identity at a segment boundary',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-enrollment-key-expired': {
        "domain": 'svid',
        "code": 'svid-enrollment-key-expired',
        "human": 'SVID enrollment: the presented pre-auth enrollment key '
                 'is expired (now >= expires_at); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-enrollment-key-replayed': {
        "domain": 'svid',
        "code": 'svid-enrollment-key-replayed',
        "human": 'SVID enrollment: the presented pre-auth enrollment key '
                 'was already consumed; replay refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-enrollment-key-unknown': {
        "domain": 'svid',
        "code": 'svid-enrollment-key-unknown',
        "human": 'SVID enrollment: the presented pre-auth enrollment key '
                 'matches no issued key; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-enrollment-spiffe-mismatch': {
        "domain": 'svid',
        "code": 'svid-enrollment-spiffe-mismatch',
        "human": 'SVID enrollment: the pre-auth enrollment key is bound '
                 'to a different spiffe id; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-expired': {
        "domain": 'svid',
        "code": 'svid-expired',
        "human": 'SVID identity: the presented SVID is expired '
                 '(now >= expires_at); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-identity-malformed': {
        "domain": 'svid',
        "code": 'svid-identity-malformed',
        "human": 'SVID identity: the presented identity document is '
                 'structurally malformed; refused before any '
                 'cryptographic work',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-issuer-unknown': {
        "domain": 'svid',
        "code": 'svid-issuer-unknown',
        "human": 'SVID identity: the issuer key id is not among the '
                 'pinned trust roots; parallel trust roots are never '
                 'fetched, refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-malformed': {
        "domain": 'svid',
        "code": 'svid-malformed',
        "human": 'SVID identity: the presented SVID is structurally '
                 'malformed; refused before signature verification',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-missing': {
        "domain": 'svid',
        "code": 'svid-missing',
        "human": 'SVID identity: no SVID was presented where the mesh '
                 'admission seam requires one; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-signature-invalid': {
        "domain": 'svid',
        "code": 'svid-signature-invalid',
        "human": 'SVID identity: the issuer signature does not verify '
                 'against the pinned issuer key (forgery or key '
                 'mismatch); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-trust-domain-mismatch': {
        "domain": 'svid',
        "code": 'svid-trust-domain-mismatch',
        "human": 'SVID identity: the SVID trust domain does not exactly '
                 'match the verifier trust domain; refused fail-closed, '
                 'never downgraded',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-ttl-stretched': {
        "domain": 'svid',
        "code": 'svid-ttl-stretched',
        "human": 'SVID issuance: the requested TTL exceeds the profile '
                 'cap; refused fail-closed rather than silently '
                 'shortened',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-ttl-unbounded': {
        "domain": 'svid',
        "code": 'svid-ttl-unbounded',
        "human": 'SVID issuance: no explicit TTL in minutes was '
                 'requested; an unbounded TTL is refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'svid-usage-mismatch': {
        "domain": 'svid',
        "code": 'svid-usage-mismatch',
        "human": 'SVID identity: the presented SVID\'s signed usage list '
                 'does not cover the expected usage; refused fail-closed, '
                 'never downgraded',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
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
    'taxonomy-receipt-missing': {
        "domain": 'receipts',
        "code": 'taxonomy-receipt-missing',
        "human": 'signed receipts: the decision lacked digest-shaped evidence, so no receipt was formed',
        "severity": 'medium',
        "evidence_kinds_required": ['decision'],
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
    'token-audience-mismatch': {
        "domain": 'token_hygiene',
        "code": 'token-audience-mismatch',
        "human": 'token hygiene: token presented outside its declared '
                 'audience; the presentation is refused',
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
    'token-expired': {
        "domain": 'token_hygiene',
        "code": 'token-expired',
        "human": 'token hygiene: expired token presented; refused '
                 'outright, never refreshed, never tolerated',
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
    'token-key-stale': {
        "domain": 'token_hygiene',
        "code": 'token-key-stale',
        "human": 'token hygiene: high-impact issuing key is older than '
                 'the 90-day rotation window; rotate before issuing',
        "severity": 'high',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'token-malformed': {
        "domain": 'token_hygiene',
        "code": 'token-malformed',
        "human": 'token hygiene: agent credential claims are misshapen '
                 '(not a dict, bad iat/exp/key fields); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['receipt'],
        "reverify_steps": ['recompute'],
    },
    'token-scope-exceeded': {
        "domain": 'token-scope',
        "code": 'token-scope-exceeded',
        "human": 'the scope grant does not cover the (tool, action) being '
                 'invoked; also covers alias-not-granted anti-widening; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['token', 'grant', 'policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'token-scope-unparseable': {
        "domain": 'token-scope',
        "code": 'token-scope-unparseable',
        "human": 'a presented scope-check input (grant, sealed policy '
                 'wrapper, tool name, action, epoch) is malformed; refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['grant', 'policy-declaration'],
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
    'tool-budget-config-invalid': {
        "domain": 'velocity',
        "code": 'tool-budget-config-invalid',
        "human": 'per-tool budget enforcement: the deployment\'s '
                 'tool_budgets: policy section is malformed '
                 '(non-mapping, bad tool name, unknown key, missing '
                 'budget, non-positive or non-finite budget/cost); the '
                 'executor never constructs on uninterpretable budget '
                 'policy',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'tool-budget-exhausted': {
        "domain": 'velocity',
        "code": 'tool-budget-exhausted',
        "human": 'per-tool budget enforcement: the tool\'s cumulative '
                 'spend would exceed its configured budget; this call '
                 'is refused coded -- the run continues, unlike the '
                 'F162 class tripwire which pauses the whole run',
        "severity": 'medium',
        "evidence_kinds_required": ['budget-state', 'policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'tool-budget-unavailable': {
        "domain": 'velocity',
        "code": 'tool-budget-unavailable',
        "human": 'per-tool budget enforcement: the budget wire itself '
                 'failed unexpectedly at call time; fail closed -- the '
                 'call is denied, never allowed unlimited spend',
        "severity": 'high',
        "evidence_kinds_required": ['budget-state'],
        "reverify_steps": ['recompute'],
    },
    'tool-crashed': {
        "domain": 'capability',
        "code": 'tool-crashed',
        "human": 'capability assessment: the tool crashed',
        "severity": 'medium',
        "evidence_kinds_required": ['assessment', 'pack', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'tool-definition-malformed': {
        "domain": 'mcp-surface',
        "code": 'tool-definition-malformed',
        "human": 'tool definition is not the expected shape',
        "severity": 'medium',
        "evidence_kinds_required": ['tool-definition'],
        "reverify_steps": ['recompute'],
    },
    'tool-executable-content': {
        "domain": 'mcp-surface',
        "code": 'tool-executable-content',
        "human": 'tool definition carries executable content; quarantined',
        "severity": 'high',
        "evidence_kinds_required": ['tool-definition'],
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
    'tool-guardrail-tripwire': {
        "domain": 'guardrail',
        "code": 'tool-guardrail-tripwire',
        "human": 'a per-tool guardrail halted the run (raise_exception) or '
                 'the guard itself failed: loud fail-closed halt, distinct '
                 'from policy refusals',
        "severity": 'high',
        "evidence_kinds_required": ['guardrail-tripwire'],
        "reverify_steps": ['recompute'],
    },
    'tool-rate-limit-config-invalid': {
        "domain": 'velocity',
        "code": 'tool-rate-limit-config-invalid',
        "human": 'per-tool rate limiting: the deployment\'s '
                 'tool_rate_limits: policy section is malformed '
                 '(non-mapping, bad tool name, unknown key, missing '
                 'window_secs/max_calls, non-positive window, or '
                 'negative call budget); the executor never constructs '
                 'on uninterpretable velocity policy',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'tool-rate-limit-exceeded': {
        "domain": 'velocity',
        "code": 'tool-rate-limit-exceeded',
        "human": 'per-tool rate limiting: the tool\'s sliding-window '
                 'execution count exceeded its configured limit; this '
                 'call is refused coded -- the run continues, unlike '
                 'the F162 class tripwire which pauses the whole run',
        "severity": 'medium',
        "evidence_kinds_required": ['windowed-count', 'policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'tool-rate-limiter-unavailable': {
        "domain": 'velocity',
        "code": 'tool-rate-limiter-unavailable',
        "human": 'per-tool rate limiting: the limiter itself failed '
                 'unexpectedly at call time; fail closed -- the call '
                 'is denied, never allowed unlimited',
        "severity": 'high',
        "evidence_kinds_required": ['limiter-state'],
        "reverify_steps": ['recompute'],
    },
    'tool-scope-undeclared': {
        "domain": 'token-scope',
        "code": 'tool-scope-undeclared',
        "human": 'the tool or action is absent from the sealed scope '
                 'policy; fail closed, authority never auto-expands',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
        "reverify_steps": ['recompute'],
    },
    'tool-spawn-context-untrusted': {
        "domain": 'spawn-context',
        "code": 'tool-spawn-context-untrusted',
        "human": 'permission-bypass flags presented through a postinstall '
                 'spawn context, or through an unvouched context claiming '
                 'to be user-invoked; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['spawn-record', 'provenance'],
        "reverify_steps": ['recompute', 'provenance-check'],
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
    'toolcall-audit-would-deny': {
        "domain": 'toolcall',
        "code": 'toolcall-audit-would-deny',
        "human": 'toolcall: audit rollout mode -- the call would have been '
                 'denied; recorded as prospective evidence, not enforced',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-budget-exhausted': {
        "domain": 'toolcall',
        "code": 'toolcall-budget-exhausted',
        "human": 'toolcall: the invocation filter pipeline refused to '
                 'reserve the declared cost -- the caller would exceed its '
                 'per-window budget cap (used + outstanding + declared); '
                 'refused fail-closed before the tool ran',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-budget-reserve-invalid': {
        "domain": 'toolcall',
        "code": 'toolcall-budget-reserve-invalid',
        "human": 'toolcall: a budget reservation was malformed -- '
                 'non-positive or non-finite amount, undeclared scope, '
                 'duplicate reservation for the call, actual cost above the '
                 'reserved amount (overrun), or an unknown reservation '
                 'token; refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-call-denied': {
        "domain": 'toolcall',
        "code": 'toolcall-call-denied',
        "human": 'toolcall: a DENY rule matched the call (tool, operation, '
                 'caller binding, and arg constraints under fail-closed '
                 'under-specification semantics); the call was denied',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-caller-out-of-scope': {
        "domain": 'toolcall',
        "code": 'toolcall-caller-out-of-scope',
        "human": 'toolcall: the caller is not covered by the policy '
                 'selector; no decision is available from this policy; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-custom-denied': {
        "domain": 'toolcall',
        "code": 'toolcall-custom-denied',
        "human": 'toolcall: the CUSTOM rule external authorizer denied the '
                 'call (or failed closed); the custom decision point can '
                 'only tighten, never loosen',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-exception-scope-mismatch': {
        "domain": 'toolcall',
        "code": 'toolcall-exception-scope-mismatch',
        "human": 'toolcall: suppression refused -- the governed exception '
                 'scope does not bind to the suppressed alert: a ("tool", X) '
                 'scope must name (fnmatch-cover) the alert tool, and a '
                 '("policy", P) scope must name the compiled policy by name '
                 'or digest; refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-exception-suppressed': {
        "domain": 'toolcall',
        "code": 'toolcall-exception-suppressed',
        "human": 'toolcall: the DENY alert was suppressed under a live '
                 'governed exception (SKIPPED with the exception digest, '
                 'never PASSED); the record carries the actual decision '
                 'verdict (DENY for enforced denials, ALLOW for '
                 'audit-mode would-denys)',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-filter-frozen': {
        "domain": 'toolcall',
        "code": 'toolcall-filter-frozen',
        "human": 'toolcall: a filter was added to an invocation pipeline '
                 'stack after construction -- the stack is frozen at build '
                 '(F330/F340 pattern); post-freeze mutation would change '
                 'decisions under a still-valid digest; refused fail-closed',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-invalid-call': {
        "domain": 'toolcall',
        "code": 'toolcall-invalid-call',
        "human": 'toolcall: ill-typed decide() input refused LOUD -- '
                 'tool/operation must be non-empty strings and args keys '
                 'must be strings (no uncoded TypeError escapes)',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-no-allow': {
        "domain": 'toolcall',
        "code": 'toolcall-no-allow',
        "human": 'toolcall: no rule allowed the call; default deny '
                 '(deliberate divergence from Istio: Sasanam is fail-closed)',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-no-covering-exception': {
        "domain": 'toolcall',
        "code": 'toolcall-no-covering-exception',
        "human": 'toolcall: suppression was requested but no live governed '
                 'exception covers the scope; a DENY verdict cannot be '
                 'suppressed ad-hoc; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-policy-drift': {
        "domain": 'toolcall',
        "code": 'toolcall-policy-drift',
        "human": 'toolcall: the compiled policy document no longer matches '
                 'its pin; refused fail-closed -- re-review and re-pin '
                 'before deciding',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-policy-invalid': {
        "domain": 'toolcall',
        "code": 'toolcall-policy-invalid',
        "human": 'toolcall: the policy document failed schema validation '
                 '(format, selector, mode, rule actions, arg matchers, '
                 'custom authorizer registration); refused fail-closed at '
                 'compile time',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-policy-unpinned': {
        "domain": 'toolcall',
        "code": 'toolcall-policy-unpinned',
        "human": 'toolcall: a decision was attempted under a tool-call '
                 'policy with no committed pin; refused fail-closed -- '
                 'policies decide only under pinned, reviewable documents',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-predicate-budget': {
        "domain": 'toolcall',
        "code": 'toolcall-predicate-budget',
        "human": 'toolcall: a Conditional rule predicate exhausted its '
                 'evaluation budget (over-bound AST or too many evaluation '
                 'steps); the predicate never evaluates -- refused '
                 'fail-closed, never silently truncated',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-predicate-invalid': {
        "domain": 'toolcall',
        "code": 'toolcall-predicate-invalid',
        "human": 'toolcall: a Conditional rule predicate spec was malformed '
                 'or ill-typed (unknown builtin, arity or type mismatch, '
                 'non-bool result, bad const) or failed at evaluation; the '
                 'rule never compiles -- refused fail-closed at compile time',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-predicate-undeclared-field': {
        "domain": 'toolcall',
        "code": 'toolcall-predicate-undeclared-field',
        "human": 'toolcall: a Conditional rule predicate referenced a field '
                 'outside its declared predicate environment; undeclared '
                 'fields do not exist -- refused fail-closed at compile time',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-regex-unsafe': {
        "domain": 'toolcall',
        "code": 'toolcall-regex-unsafe',
        "human": 'toolcall: an arg-matcher regex was refused by the '
                 'shared backtracking-safety gate (F325 mechanism) -- the '
                 'pattern is exponential-backtracking-prone and '
                 'caller-triggerable; refused fail-closed at compile time',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-rule-compile-invalid': {
        "domain": 'toolcall',
        "code": 'toolcall-rule-compile-invalid',
        "human": 'toolcall: a declared tool-rule set document failed '
                 'compile-time validation (unknown kind, undeclared tool '
                 'or predicate reference, malformed shape); the rule set '
                 'never compiles -- refused fail-closed at compile time',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-schema-compile-invalid': {
        "domain": 'toolcall',
        "code": 'toolcall-schema-compile-invalid',
        "human": 'toolcall: a declared tool-schema set document failed '
                 'compile-time validation (unknown field type, undeclared '
                 'or malformed shape, unbounded string/list/dict, unsafe '
                 'pattern); the schema set never compiles -- refused '
                 'fail-closed at compile time',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-schema-invalid': {
        "domain": 'toolcall',
        "code": 'toolcall-schema-invalid',
        "human": 'toolcall: a tool call failed schema validation (ill-typed '
                 'args, undeclared arg, missing required field, type/range/'
                 'shape mismatch, pattern or choices violation); the call '
                 'never executes -- refused fail-closed at decide time',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-schema-secret-field': {
        "domain": 'toolcall',
        "code": 'toolcall-schema-secret-field',
        "human": 'toolcall: a tool-schema document declared a credential-'
                 'like field name (bounded credential token list); '
                 'credentials travel in typed execution context, never in '
                 'the call schema -- refused fail-closed at compile time',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-schema-unknown-tool': {
        "domain": 'toolcall',
        "code": 'toolcall-schema-unknown-tool',
        "human": 'toolcall: a tool call named a tool outside the bound '
                 'schema set; undeclared tools do not exist -- refused '
                 'fail-closed at decide time',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'toolcall-secret-in-args': {
        "domain": 'toolcall',
        "code": 'toolcall-secret-in-args',
        "human": 'toolcall: a tool call carried a secret-shaped value in '
                 'its args (bounded secret-shape pattern set, or a '
                 'secret-shaped arg name with a non-empty value); secrets '
                 'travel via typed context, never tool args -- refused '
                 'fail-closed before the call executes',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-secret-scan-incomplete': {
        "domain": 'toolcall',
        "code": 'toolcall-secret-scan-incomplete',
        "human": 'toolcall: the secret-shape scan of a tool call\'s args '
                 'could not complete within its declared bounds (nesting '
                 'depth 4 / 64KB scan budget); unevaluatable input is '
                 'refused fail-closed rather than silently allowed, so the '
                 'documented scan bound cannot serve as a bypass -- '
                 'refused fail-closed before the call executes',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-sequence-violated': {
        "domain": 'toolcall',
        "code": 'toolcall-sequence-violated',
        "human": 'toolcall: a tool call violated the bound declared '
                 'sequence grammar (Init/Child/Terminal/Conditional) or '
                 'named a tool outside the closed inventory; undeclared '
                 'tools do not exist -- refused fail-closed at decide time',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolcall-unauthenticated-caller': {
        "domain": 'toolcall',
        "code": 'toolcall-unauthenticated-caller',
        "human": 'toolcall: the caller identity was not authenticated; '
                 'authorization is never evaluated without identity '
                 '(identity-before-authorization layering); refused '
                 'fail-closed at the authn layer',
        "severity": 'high',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'toolfilter-skip-denied': {
        "domain": 'toolcall',
        "code": 'toolfilter-skip-denied',
        "human": 'toolcall: an invocation-pipeline filter violated the '
                 'chain contract -- it returned without calling next() and '
                 'without a coded refusal (the invocation was swallowed), '
                 'called next() twice (double execution), crashed uncoded, '
                 'or the audit signer misbehaved; refused fail-closed -- '
                 'skipping never silently allows',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },
    'transaction-expired': {
        "domain": 'transaction',
        "code": 'transaction-expired',
        "human": 'transactional token presented at or after its per-token '
                 'expiry; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },
    'transaction-id-mismatch': {
        "domain": 'transaction',
        "code": 'transaction-id-mismatch',
        "human": 'transactional token presented for a transaction it was '
                 'not issued for; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },
    'transaction-key-missing': {
        "domain": 'transaction',
        "code": 'transaction-key-missing',
        "human": 'transactional token operation attempted without a '
                 'deployment key; refused fail-closed (no dev fallback)',
        "severity": 'medium',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },
    'transaction-malformed': {
        "domain": 'transaction',
        "code": 'transaction-malformed',
        "human": 'transactional token or issuance request is malformed; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },
    'transaction-signature-invalid': {
        "domain": 'transaction',
        "code": 'transaction-signature-invalid',
        "human": 'transactional token MAC does not cover the presented '
                 'bytes; possible tampering',
        "severity": 'critical',
        "evidence_kinds_required": ['token', 'key-reference'],
        "reverify_steps": ['recompute'],
    },
    'transform-capacity-exceeded': {
        "domain": 'transform',
        "code": 'transform-capacity-exceeded',
        "human": 'a registered transform emitted on a wider capacity '
                 'channel than its declared output contract (the FIDES '
                 'laundering budget is blown); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['transform-output'],
        "reverify_steps": ['recompute'],
    },
    'transform-contract-violated': {
        "domain": 'transform',
        "code": 'transform-contract-violated',
        "human": 'a registered transform output failed its declared '
                 'output contract (shape, max_bytes, or enum membership) '
                 'on post-transform re-verification; laundered bytes are '
                 'never silently passed',
        "severity": 'high',
        "evidence_kinds_required": ['transform-output'],
        "reverify_steps": ['recompute'],
    },
    'transform-identity-mismatch': {
        "domain": 'transform',
        "code": 'transform-identity-mismatch',
        "human": 'the presented function is not the registered transform '
                 '(module/qualname/code-digest identity check); the (where) '
                 'half of the (where, what) pair does not hold',
        "severity": 'high',
        "evidence_kinds_required": ['transform-registration'],
        "reverify_steps": ['recompute'],
    },
    'transform-ledger-corrupt': {
        "domain": 'transform',
        "code": 'transform-ledger-corrupt',
        "human": 'the durable transform-declassify consume ledger is '
                 'corrupt or unreadable; at-most-once cannot be enforced, '
                 'so every token-gated lowering refuses fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['ledger'],
        "reverify_steps": ['recompute'],
    },
    'transform-model-lowering-refused': {
        "domain": 'transform',
        "code": 'transform-model-lowering-refused',
        "human": 'a model-mediated transform can never lower a label, '
                 'even with a declassification token (CaMeL discipline; '
                 'structural, not a policy knob)',
        "severity": 'high',
        "evidence_kinds_required": ['transform-registration'],
        "reverify_steps": ['recompute'],
    },
    'transform-registration-denylist-refused': {
        "domain": 'transform',
        "code": 'transform-registration-denylist-refused',
        "human": 'a transform registration with a denylist-shaped output '
                 'contract was refused; only allowlist contracts register '
                 '(the mXSS record: denylists lose)',
        "severity": 'medium',
        "evidence_kinds_required": ['transform-registration'],
        "reverify_steps": ['recompute'],
    },
    'transform-registration-duplicate': {
        "domain": 'transform',
        "code": 'transform-registration-duplicate',
        "human": 'a transform name is already registered; registrations '
                 'are never silently replaced',
        "severity": 'medium',
        "evidence_kinds_required": ['transform-registration'],
        "reverify_steps": ['recompute'],
    },
    'transform-registration-marking-refused': {
        "domain": 'transform',
        "code": 'transform-registration-marking-refused',
        "human": 'a byte-marking/delimiter transform was refused at '
                 'registration; marking transforms are not label-lowering '
                 'transforms (Spotlighting negative rule)',
        "severity": 'medium',
        "evidence_kinds_required": ['transform-registration'],
        "reverify_steps": ['recompute'],
    },
    'transform-registration-model-lowering-refused': {
        "domain": 'transform',
        "code": 'transform-registration-model-lowering-refused',
        "human": 'a model-mediated transform declaring a label-lowering '
                 'rule was refused at registration; model transforms are '
                 'never declassification points',
        "severity": 'medium',
        "evidence_kinds_required": ['transform-registration'],
        "reverify_steps": ['recompute'],
    },
    'transform-token-invalid': {
        "domain": 'transform',
        "code": 'transform-token-invalid',
        "human": 'a transform-declassify token failed verification or its '
                 'exact argument binding (transform, output digest, '
                 'capacity, input min trust); the lowering refuses',
        "severity": 'high',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },
    'transform-token-replayed': {
        "domain": 'transform',
        "code": 'transform-token-replayed',
        "human": 'a transform-declassify token nonce was already consumed '
                 '(durable ledger); a token authorizes at most one lowering',
        "severity": 'high',
        "evidence_kinds_required": ['token', 'ledger'],
        "reverify_steps": ['recompute'],
    },
    'transform-unregistered': {
        "domain": 'transform',
        "code": 'transform-unregistered',
        "human": 'a transform not in the registry was presented; it runs '
                 'on the data plane (output keeps min input trust) and can '
                 'never lower a label',
        "severity": 'medium',
        "evidence_kinds_required": ['transform-registration'],
        "reverify_steps": ['recompute'],
    },
    'trust-class-unknown': {
        "domain": 'deploy',
        "code": 'trust-class-unknown',
        "human": 'deployment trust config: the trust class is not known',
        "severity": 'medium',
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
    'trust-root-chain-malformed': {
        "domain": 'evidence',
        "code": 'trust-root-chain-malformed',
        "human": 'trust-root chain: the chain is structurally invalid -- '
                 'empty, versions not strictly consecutive from v1, content '
                 'hash mismatch, or bad pin fields; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'trust-root-expired': {
        "domain": 'evidence',
        "code": 'trust-root-expired',
        "human": 'trust-root chain: the chain tip was not valid at the '
                 'bundle timestamp\'s time (expiry is evaluated at the '
                 'timestamp\'s time, chain-wide, per CVE-2026-24122); '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'trust-root-receipt-unbound': {
        "domain": 'evidence',
        "code": 'trust-root-receipt-unbound',
        "human": 'trust-root chain: a witness receipt does not bind the '
                 'artifact digest, signature, and signer key (a valid '
                 'receipt alone is never enough, per CVE-2026-22703); '
                 'refused fail-closed',
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
    'trust-root-rotation-invalid': {
        "domain": 'evidence',
        "code": 'trust-root-rotation-invalid',
        "human": 'trust-root chain: the rotation ceremony record is invalid '
                 '-- bad version link, hash mismatch, future review date, '
                 'reviewed outside the signing root\'s window, or not '
                 'signed by the old root\'s keys; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'trust-root-silent-swap': {
        "domain": 'evidence',
        "code": 'trust-root-silent-swap',
        "human": 'trust-root chain: a chain link was adopted without a '
                 'rotation record -- rotation is a policy ceremony, never '
                 'silent; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['trust-config', 'signature', 'digest'],
        "reverify_steps": ['recompute'],
    },
    'trust-root-stale-freshness': {
        "domain": 'evidence',
        "code": 'trust-root-stale-freshness',
        "human": 'trust-root chain: the freshness signal is missing, stale, '
                 'future-dated, for the wrong chain version, or not signed '
                 'by the tip root\'s keys; refused fail-closed',
        "severity": 'medium',
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
    'trustvec-appraisal-contraindicated': {
        "domain": 'trustvec',
        "code": 'trustvec-appraisal-contraindicated',
        "human": 'trust-vector appraisal: require_affirmed refused -- one or '
                 'more trust-vector dimensions are contraindicated; a live '
                 'governed exception can never upgrade a contraindication',
        "severity": 'high',
        "evidence_kinds_required": ['digest', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'trustvec-appraisal-insufficient': {
        "domain": 'trustvec',
        "code": 'trustvec-appraisal-insufficient',
        "human": 'trust-vector appraisal: require_affirmed refused -- the '
                 'vector is insufficient (unendorsed dimensions) and no '
                 'exception store was offered to accept the risk',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'trustvec-endorsement-not-independent': {
        "domain": 'trustvec',
        "code": 'trustvec-endorsement-not-independent',
        "human": 'trust-vector appraisal: an endorsement was sourced from '
                 'the evidence producer itself; endorsements must be '
                 'separately sourced or the verifier trusts the producer',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'trustvec-evidence-invalid': {
        "domain": 'trustvec',
        "code": 'trustvec-evidence-invalid',
        "human": 'trust-vector appraisal: evidence failed the scheme claim '
                 'grammar (missing/extra claims, wrong types) or a malformed '
                 'EAR/appraise-hook output was rejected; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'trustvec-no-covering-exception': {
        "domain": 'trustvec',
        "code": 'trustvec-no-covering-exception',
        "human": 'trust-vector appraisal: the vector is insufficient and no '
                 'live governed exception covers the appraisal policy; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['digest', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'trustvec-policy-drift': {
        "domain": 'trustvec',
        "code": 'trustvec-policy-drift',
        "human": 'trust-vector appraisal: the appraisal policy digest '
                 'drifted from its pin; refused fail-closed -- re-review '
                 'and re-pin before appraising',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'trustvec-policy-invalid': {
        "domain": 'trustvec',
        "code": 'trustvec-policy-invalid',
        "human": 'trust-vector appraisal: the appraisal-policy document '
                 'failed validation (format, policy id, scheme binding, '
                 'trust anchors); refused fail-closed at compile time',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'trustvec-policy-unpinned': {
        "domain": 'trustvec',
        "code": 'trustvec-policy-unpinned',
        "human": 'trust-vector appraisal: appraisal attempted under a '
                 'policy with no committed pin; refused fail-closed -- '
                 'appraisal decides only under pinned, reviewable policy',
        "severity": 'high',
        "evidence_kinds_required": ['pin', 'refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'trustvec-scheme-duplicate': {
        "domain": 'trustvec',
        "code": 'trustvec-scheme-duplicate',
        "human": 'trust-vector appraisal: a scheme id was registered twice; '
                 'the duplicate registration was refused (no silent '
                 'replacement of the appraisal plugin)',
        "severity": 'low',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'trustvec-scheme-unknown': {
        "domain": 'trustvec',
        "code": 'trustvec-scheme-unknown',
        "human": 'trust-vector appraisal: evidence named an unregistered '
                 'attestation scheme; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['refusal-record'],
        "reverify_steps": ['recompute'],
    },

    'tsa-gentime-backdated': {
        "domain": 'tsa',
        "code": 'tsa-gentime-backdated',
        "human": 'tsa: the token genTime predates the auditor first-observed '
                 'ledger entry for this tree head; possible backdated time '
                 'forgery',
        "severity": 'high',
        "evidence_kinds_required": ['token', 'ledger'],
        "reverify_steps": ['recompute'],
    },


    'tsa-gentime-in-future': {
        "domain": 'tsa',
        "code": 'tsa-gentime-in-future',
        "human": 'tsa: the token genTime is beyond the allowed future skew; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },


    'tsa-gentime-invalid': {
        "domain": 'tsa',
        "code": 'tsa-gentime-invalid',
        "human": 'tsa: the token genTime is missing, non-integer, or not '
                 'positive; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },


    'tsa-imprint-mismatch': {
        "domain": 'tsa',
        "code": 'tsa-imprint-mismatch',
        "human": 'tsa: the token imprint does not match the recomputed '
                 'imprint over the operator signature; the token is not '
                 'bound to this checkpoint or receipt',
        "severity": 'high',
        "evidence_kinds_required": ['token', 'signature'],
        "reverify_steps": ['recompute'],
    },


    'tsa-nonce-mismatch': {
        "domain": 'tsa',
        "code": 'tsa-nonce-mismatch',
        "human": 'tsa: the token nonce does not match the expected request '
                 'nonce; possible replay',
        "severity": 'medium',
        "evidence_kinds_required": ['token'],
        "reverify_steps": ['recompute'],
    },


    'tsa-signature-invalid': {
        "domain": 'tsa',
        "code": 'tsa-signature-invalid',
        "human": 'tsa: the TSA signature does not verify under the pinned '
                 'TSA public key; possible tampering or time forgery',
        "severity": 'high',
        "evidence_kinds_required": ['token', 'key-reference'],
        "reverify_steps": ['recompute'],
    },


    'tsa-token-malformed': {
        "domain": 'tsa',
        "code": 'tsa-token-malformed',
        "human": 'tsa: the timestamp token or issuance request is malformed; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['token'],
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
    'unexpected-participant-signed': {
        "domain": 'participants',
        "code": 'unexpected-participant-signed',
        "human": 'expected-participants audit: a signed hop names a '
                 'participant not declared expected for the workload',
        "severity": 'high',
        "evidence_kinds_required": ['delegation-chain'],
        "reverify_steps": ['recompute'],
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
    'uri-host-invalid': {
        "domain": 'uri-normalize',
        "code": 'uri-host-invalid',
        "human": 'shared host normalizer: the hostname is empty after '
                 'stripping, is not a string, or fails IDNA encoding; '
                 'refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal', 'input'],
        "reverify_steps": ['recompute'],
    },
    'uri-host-unparseable': {
        "domain": 'uri-normalize',
        "code": 'uri-host-unparseable',
        "human": 'shared host normalizer: the URL has no parseable '
                 'hostname or the address has no @ separator; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['refusal', 'input'],
        "reverify_steps": ['recompute'],
    },
    'verifier-input-malformed': {
        "domain": 'authority',
        "code": 'verifier-input-malformed',
        "human": 'verifier fail-closed check: the chain, verifier policy, '
                 'or authority store is malformed; refused fail-closed, '
                 'never a silent pass',
        "severity": 'medium',
        "evidence_kinds_required": ['policy-declaration'],
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
    'verify-artifactsfrom-empty': {
        "domain": 'verify',
        "code": 'verify-artifactsfrom-empty',
        "human": 'bundle verification: an artifactsFrom edge carries zero '
                 'shared digests (no genuine artifact flow)',
        "severity": 'high',
        "evidence_kinds_required": ['attestation-section'],
        "reverify_steps": ['recompute'],
    },
    'verify-attestor-shadowed': {
        "domain": 'verify',
        "code": 'verify-attestor-shadowed',
        "human": 'bundle verification: an attestor type has an instance '
                 'that was never evaluated (shadowing)',
        "severity": 'high',
        "evidence_kinds_required": ['attestation-section'],
        "reverify_steps": ['recompute'],
    },
    'verify-collection-empty-match': {
        "domain": 'verify',
        "code": 'verify-collection-empty-match',
        "human": 'bundle verification: an empty collection name matched a '
                 'step, or a step is not in the claimed collection',
        "severity": 'high',
        "evidence_kinds_required": ['attestation-section'],
        "reverify_steps": ['recompute'],
    },
    'verify-hash-downgrade': {
        "domain": 'verify',
        "code": 'verify-hash-downgrade',
        "human": 'bundle verification: a digest comparison used a weak '
                 'hash while a stronger shared digest existed',
        "severity": 'high',
        "evidence_kinds_required": ['attestation-section'],
        "reverify_steps": ['recompute'],
    },
    'verify-no-clean-verifier': {
        "domain": 'verify',
        "code": 'verify-no-clean-verifier',
        "human": 'bundle verification: no signature verify attempt passed '
                 'cleanly; failed attempts confer no trust',
        "severity": 'high',
        "evidence_kinds_required": ['attestation-section'],
        "reverify_steps": ['recompute'],
    },
    'verify-signature-failed': {
        "domain": 'verify',
        "code": 'verify-signature-failed',
        "human": 'bundle verification: a signature verify attempt matched '
                 'the identity constraints but its signature never '
                 'verified (forged-policy shape); refused, never trusted',
        "severity": 'critical',
        "evidence_kinds_required": ['attestation-section'],
        "reverify_steps": ['recompute'],
    },
    'verify-symlink-escape': {
        "domain": 'verify',
        "code": 'verify-symlink-escape',
        "human": 'bundle verification: an artifact symlink resolves '
                 'outside the attested root',
        "severity": 'high',
        "evidence_kinds_required": ['attestation-section'],
        "reverify_steps": ['recompute'],
    },
    'verify-timestamp-eku-missing': {
        "domain": 'verify',
        "code": 'verify-timestamp-eku-missing',
        "human": 'bundle verification: the timestamp signer does not '
                 'carry the sole critical id-kp-timeStamping EKU',
        "severity": 'high',
        "evidence_kinds_required": ['attestation-section'],
        "reverify_steps": ['recompute'],
    },
    'verpol-attestation-missing': {
        "domain": 'verpol',
        "code": 'verpol-attestation-missing',
        "human": 'verification policy: a policy authority declares a '
                 'required attestation but no attestation evidence was '
                 'presented for it; failing closed',
        "severity": 'high',
        "evidence_kinds_required": ['envelope', 'attestation', 'policy'],
        "reverify_steps": ['recompute'],
    },
    'verpol-attestation-policy-failed': {
        "domain": 'verpol',
        "code": 'verpol-attestation-policy-failed',
        "human": 'verification policy: attestation evidence was presented '
                 'but its predicateType does not match the declared type, '
                 'or the attestation inline policy evaluated false over '
                 'the payload; failing closed',
        "severity": 'high',
        "evidence_kinds_required": ['envelope', 'attestation', 'policy'],
        "reverify_steps": ['recompute'],
    },
    'verpol-log-not-anchored': {
        "domain": 'verpol',
        "code": 'verpol-log-not-anchored',
        "human": 'verification policy: the authority requires '
                 'transparency-log anchoring (required by default; the '
                 'ClusterImagePolicy quiet skip is inverted) and the '
                 'packet digest is not anchored; failing closed',
        "severity": 'high',
        "evidence_kinds_required": ['envelope', 'policy'],
        "reverify_steps": ['recompute'],
    },
    'verpol-malformed-policy': {
        "domain": 'verpol',
        "code": 'verpol-malformed-policy',
        "human": 'verification policy: the policy document failed '
                 'structural validation (including empty authorities and '
                 'unknown predicate ops); refused fail-closed at load',
        "severity": 'high',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'verpol-no-authority-matched': {
        "domain": 'verpol',
        "code": 'verpol-no-authority-matched',
        "human": 'verification policy: no authority in a matching policy '
                 'verified (unpinned key, unmet threshold, unanchored '
                 'digest, or failed attestations); failing closed',
        "severity": 'high',
        "evidence_kinds_required": ['envelope', 'policy'],
        "reverify_steps": ['recompute'],
    },
    'verpol-no-match': {
        "domain": 'verpol',
        "code": 'verpol-no-match',
        "human": 'verification policy: no verification policy matches '
                 'this packet; unmatched packets refuse fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['policy'],
        "reverify_steps": ['recompute'],
    },
    'verpol-packet-invalid': {
        "domain": 'verpol',
        "code": 'verpol-packet-invalid',
        "human": 'verification policy: the packet failed its own '
                 'verification (structure, signature, or authority '
                 'self-consistency) before policy evaluation; refused',
        "severity": 'high',
        "evidence_kinds_required": ['envelope', 'policy'],
        "reverify_steps": ['recompute'],
    },
    'verpol-policy-failed': {
        "domain": 'verpol',
        "code": 'verpol-policy-failed',
        "human": 'verification policy: the outer policy evaluated false '
                 'over the normalized verification result; failing closed',
        "severity": 'high',
        "evidence_kinds_required": ['envelope', 'policy'],
        "reverify_steps": ['recompute'],
    },
    'verpol-uncheckable': {
        "domain": 'verpol',
        "code": 'verpol-uncheckable',
        "human": 'verification policy: the packet could not be checked '
                 '(evaluation error); refused fail-closed, never a '
                 'vacuous pass',
        "severity": 'medium',
        "evidence_kinds_required": ['policy'],
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
    'vsa-packet-levels-missing': {
        "domain": 'vsa',
        "code": 'vsa-packet-levels-missing',
        "human": 'VSA decision packet: the required verification level is '
                 'not among the VSA asserted verifiedLevels; the VSA does '
                 'not cover what the consumer requires; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-packet-malformed': {
        "domain": 'vsa',
        "code": 'vsa-packet-malformed',
        "human": 'VSA decision packet: the envelope or statement is '
                 'malformed -- not an object, wrong field set, unexpected '
                 'payloadType, not exactly one signature, undecodable '
                 'payload; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-packet-predicate-mismatch': {
        "domain": 'vsa',
        "code": 'vsa-packet-predicate-mismatch',
        "human": 'VSA decision packet: predicateType is not the SLSA '
                 'verification_summary; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-packet-resource-mismatch': {
        "domain": 'vsa',
        "code": 'vsa-packet-resource-mismatch',
        "human": 'VSA decision packet: resourceUri does not name the '
                 'expected decision packet; cross-decision replay refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-packet-result-not-passed': {
        "domain": 'vsa',
        "code": 'vsa-packet-result-not-passed',
        "human": 'VSA decision packet: verificationResult is not PASSED; '
                 'the evidence does not assert success; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-packet-signature-invalid': {
        "domain": 'vsa',
        "code": 'vsa-packet-signature-invalid',
        "human": 'VSA decision packet: the envelope signature does not '
                 'verify under any key pinned for the expected verifier; '
                 'forged VSA refused fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-packet-signer-unpinned': {
        "domain": 'vsa',
        "code": 'vsa-packet-signer-unpinned',
        "human": 'VSA decision packet: the signing key is not pinned for '
                 'the expected verifier id -- not an accepted (signer, '
                 'verifier) pair; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-packet-subject-mismatch': {
        "domain": 'vsa',
        "code": 'vsa-packet-subject-mismatch',
        "human": 'VSA decision packet: the statement subject digest does '
                 'not name the expected decision packet; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-packet-verifier-mismatch': {
        "domain": 'vsa',
        "code": 'vsa-packet-verifier-mismatch',
        "human": 'VSA decision packet: the statement verifier id is not '
                 'the expected pinned verifier, or the expected verifier '
                 'is not pinned at all; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-packet-window-invalid': {
        "domain": 'vsa',
        "code": 'vsa-packet-window-invalid',
        "human": 'VSA decision packet: timeVerified is unparseable or the '
                 'consumer clock falls outside [timeVerified, timeVerified '
                 '+ max_age]; stale or not-yet-valid VSA refused '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-threshold-below-quorum': {
        "domain": 'vsa',
        "code": 'vsa-threshold-below-quorum',
        "human": 'threshold VSA: fewer distinct valid verifier signatures '
                 'than the packet threshold (or the consumer minimum); '
                 'duplicate signatures from one verifier count once; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-threshold-policy-stale': {
        "domain": 'vsa',
        "code": 'vsa-threshold-policy-stale',
        "human": 'threshold VSA: the attested policy id/version is below '
                 'the consumer currency floor; a VSA under a superseded '
                 'policy is not silently accepted; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-threshold-signature-invalid': {
        "domain": 'vsa',
        "code": 'vsa-threshold-signature-invalid',
        "human": 'threshold VSA: an attestation signature does not verify '
                 'over the common statement plus the signer identity '
                 'descriptor -- forgery or transplant signal; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-threshold-signer-unpinned': {
        "domain": 'vsa',
        "code": 'vsa-threshold-signer-unpinned',
        "human": 'threshold VSA: the attestation names a verifier (or a '
                 'key for a verifier) the consumer has not pinned; '
                 'consumers accept only specific (signer, verifier) pairs; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
    },
    'vsa-threshold-verdict-not-passed': {
        "domain": 'vsa',
        "code": 'vsa-threshold-verdict-not-passed',
        "human": 'threshold VSA: the quorum verdict is not PASSED; a '
                 'non-passing attestation quorum is evidence input, never '
                 'an authorization; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['vsa-packet', 'signature'],
        "reverify_steps": ['replay-vsa-consumer'],
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
    'witness-alert-queue-overflow': {
        "domain": 'witness',
        "code": 'witness-alert-queue-overflow',
        "human": 'witness monitor webhook alert queue: the retry queue '
                 'exceeded its bound and the oldest queued alerts were '
                 'dropped -- the drop itself is reported LOUD with the '
                 'exact count, never silent',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-alert-state-lost': {
        "domain": 'witness',
        "code": 'witness-alert-state-lost',
        "human": 'witness monitor alerting wrapper: the alert-state file '
                 'was missing while the monitor state shows prior history '
                 '-- the incident/dedupe history is lost; the loss is '
                 'alerted LOUD and the new outage uses a timestamp-bound '
                 'incident identity that cannot dedupe-collide with any '
                 'earlier outage\'s alerts',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-alert-wrapper-error': {
        "domain": 'witness',
        "code": 'witness-alert-wrapper-error',
        "human": 'witness monitor alerting wrapper: the wrapper itself hit '
                 'an unexpected error (malformed monitor verdict, broken '
                 'dependency, bad config, corrupt alert state); the error '
                 'is alerted LOUD before propagating -- never silent',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-checkpoint-stale': {
        "domain": 'witness',
        "code": 'witness-checkpoint-stale',
        "human": 'witness consistency: the checkpoint note is older than the '
                 'freshness window, is dated in the future vs the observed '
                 'time, or carries no issuance timestamp at all (a note '
                 'with no issuance time cannot be freshness-checked); '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-checkpoint-unknown-origin': {
        "domain": 'witness',
        "code": 'witness-checkpoint-unknown-origin',
        "human": 'witness checkpoint publication: the note origin is not '
                 'in the pinned allowed origins; the note is not this '
                 "log's checkpoint; refused fail-closed",
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-config-cwd-autoload': {
        "domain": 'witness',
        "code": 'witness-config-cwd-autoload',
        "human": 'witness config rule: refusing a config discovered by '
                 'CWD auto-load in a CI or untrusted-repo context; the '
                 'repo under attestation must not ship its own verifier '
                 'configuration',
        "severity": 'critical',
        "evidence_kinds_required": ['config-source'],
        "reverify_steps": ['recompute'],
    },
    'witness-config-filter-downgrade': {
        "domain": 'witness',
        "code": 'witness-config-filter-downgrade',
        "human": 'witness config rule: refusing a sensitive-values filter '
                 'change that drops patterns; filters are tighten-only',
        "severity": 'high',
        "evidence_kinds_required": ['config-source'],
        "reverify_steps": ['recompute'],
    },
    'witness-config-upload-ungated': {
        "domain": 'witness',
        "code": 'witness-config-upload-ungated',
        "human": 'witness config rule: refusing an upload-destination '
                 'change presented without explicit confirmation',
        "severity": 'high',
        "evidence_kinds_required": ['config-source'],
        "reverify_steps": ['recompute'],
    },
    'witness-consistency-fork-detected': {
        "domain": 'witness',
        "code": 'witness-consistency-fork-detected',
        "human": 'witness consistency: two checkpoint notes from one log '
                 'key at the same tree size name different roots -- '
                 'cryptographic proof of log misbehavior (RFC 6962 gossip '
                 'rule); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-consistency'],
    },
    'witness-consistency-invalid': {
        "domain": 'witness',
        "code": 'witness-consistency-invalid',
        "human": 'witness consistency: the consistency proof does not '
                 'recompute both checkpoint roots, the old checkpoint does '
                 'not match the anchored receipt checkpoint, or the note '
                 'does not verify under the log key (forged evidence); a '
                 'valid proof alone is never enough (CVE-2026-22703); '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-consistency'],
    },
    'witness-consistency-missing': {
        "domain": 'witness',
        "code": 'witness-consistency-missing',
        "human": 'witness consistency: the signed policy configures the '
                 'witness-consistency mode but the bundle carries no '
                 'consistency evidence (no cosigned head note or no '
                 'consistency proof); the mode is optional-but-fail-closed '
                 '-- configured means required',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-consistency'],
    },
    'witness-cosignature-invalid': {
        "domain": 'witness',
        "code": 'witness-cosignature-invalid',
        "human": 'witness consistency: a signature from a CONFIGURED '
                 'witness key failed verification (on a cosignature line '
                 'or a gossip view); unknown keys are ignored per the '
                 'signed-note collision rules, but a known key\\u2019s bad '
                 'signature is a refusal, never an accept; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-daemon-state-failed': {
        "domain": 'witness',
        "code": 'witness-daemon-state-failed',
        "human": 'witness daemon: the checkpoint state store could not be '
                 'read or updated; the witness refuses to cosign rather '
                 'than risk a state rollback; fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-gossip-conflict': {
        "domain": 'witness',
        "code": 'witness-gossip-conflict',
        "human": 'witness consistency: witnesses report conflicting signed '
                 'tree heads for one log (same tree size, different roots) '
                 '-- cryptographic proof of log misbehavior (RFC 6962 '
                 'gossip); refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-consistency'],
    },
    'witness-intermediates-missing': {
        "domain": 'witness',
        "code": 'witness-intermediates-missing',
        "human": 'witness completeness rule: a chain-verify entry point '
                 'that never loaded intermediate CAs refuses; '
                 'intermediate-CA completeness is asserted before '
                 'verification',
        "severity": 'high',
        "evidence_kinds_required": ['chain-bundle'],
        "reverify_steps": ['recompute'],
    },
    'witness-log-checkpoint-malformed': {
        "domain": 'witness',
        "code": 'witness-log-checkpoint-malformed',
        "human": 'witness log: the VERIFIED checkpoint document has bad '
                 'fields (treeSize/rootHash/timestamp/logId); sizes and '
                 'hashes are parsed only after the checkpoint signature '
                 'verifies, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-log-checkpoint-signature-invalid': {
        "domain": 'witness',
        "code": 'witness-log-checkpoint-signature-invalid',
        "human": 'witness log: the checkpoint signature does not verify '
                 'against the pinned witness key; the signature is '
                 'verified FIRST, before any checkpoint field is parsed, '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-log-consistency-invalid': {
        "domain": 'witness',
        "code": 'witness-log-consistency-invalid',
        "human": 'witness log: the consistency proof does not verify old '
                 '-> new (the old tree is not a prefix of the new tree); '
                 'both roots are recomputed from the proof, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-consistency'],
    },
    'witness-log-empty': {
        "domain": 'witness',
        "code": 'witness-log-empty',
        "human": 'witness log: checkpoint or proof requested on an empty '
                 'log; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-log-inclusion-invalid': {
        "domain": 'witness',
        "code": 'witness-log-inclusion-invalid',
        "human": 'witness log: the Merkle inclusion proof does not verify '
                 'the leaf against the checkpoint root (wrong position, '
                 'wrong size binding, or path does not recompute the '
                 'root); fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-inclusion'],
    },
    'witness-log-index-out-of-range': {
        "domain": 'witness',
        "code": 'witness-log-index-out-of-range',
        "human": 'witness log: leaf index or size argument outside the '
                 'log; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-log-key-mismatch': {
        "domain": 'witness',
        "code": 'witness-log-key-mismatch',
        "human": 'witness log: the checkpoint signer key is not this '
                 "log's bound witness key; a log never co-signs for a "
                 'foreign key, fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-log-malformed': {
        "domain": 'witness',
        "code": 'witness-log-malformed',
        "human": 'witness log: malformed input -- non-bytes leaf, bad '
                 'base64/hex, bad proof structure, or bad export; '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-monitor-fetch-failed': {
        "domain": 'witness',
        "code": 'witness-monitor-fetch-failed',
        "human": 'witness monitor: no checkpoint bytes were available this '
                 'run (the fetch failed before verification); the failure '
                 'counter persists and the run refuses -- alert from the '
                 '3rd consecutive failure',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-monitor-stale': {
        "domain": 'witness',
        "code": 'witness-monitor-stale',
        "human": 'witness monitor: the head advanced but the required '
                 'consistency evidence is absent; the monitor refuses '
                 'LOUD instead of silently stalling (the missing-fringe '
                 'edge); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-monitor-state-corrupt': {
        "domain": 'witness',
        "code": 'witness-monitor-state-corrupt',
        "human": 'witness monitor: the durable state file is missing '
                 'fields, not valid JSON, or the wrong shape; a corrupt '
                 'state is a hard stop, never a silent re-baseline',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-monitor-state-mismatch': {
        "domain": 'witness',
        "code": 'witness-monitor-state-mismatch',
        "human": 'witness monitor: the caller last_seen disagrees with the '
                 'durable head (replay guard); the run refuses without '
                 'advancing state -- hard stop fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-monitor-state-missing': {
        "domain": 'witness',
        "code": 'witness-monitor-state-missing',
        "human": 'witness monitor: the caller expected durable state '
                 '(last_seen given) but no state file exists; refusing to '
                 're-baseline silently -- hard stop fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-note-malformed': {
        "domain": 'witness',
        "code": 'witness-note-malformed',
        "human": 'witness consistency: the checkpoint note is not a valid '
                 'C2SP signed note (bad UTF-8, no signature section, bad '
                 'checkpoint body, or bad origin/size/root/timestamp '
                 'fields); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-dual-threshold-unmet': {
        "domain": 'witness',
        "code": 'witness-policy-dual-threshold-unmet',
        "human": 'witness policy: the update changes the policy-signer set '
                 'but lacks threshold(old set) AND threshold(new set) '
                 'signatures (TUF section 5.3); a rotation cannot be '
                 'self-authorized by one side alone; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-duplicate-witness': {
        "domain": 'witness',
        "code": 'witness-policy-duplicate-witness',
        "human": 'witness policy: duplicate witness names or duplicate witness key material -- one operator would fill two quorum slots; refused fail-closed at load',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-expired': {
        "domain": 'witness',
        "code": 'witness-policy-expired',
        "human": 'witness policy: the policy document is past expires_at; refused fail-closed (rotation requires a newer signed version)',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-id-mismatch': {
        "domain": 'witness',
        "code": 'witness-policy-id-mismatch',
        "human": 'witness policy: the update document policy_id does not match the installed policy -- policy-family swap refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-key-unverifiable': {
        "domain": 'witness',
        "code": 'witness-policy-key-unverifiable',
        "human": 'witness policy: a witness vkey does not parse or its keyID does not recompute from the key material; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-malformed': {
        "domain": 'witness',
        "code": 'witness-policy-malformed',
        "human": 'witness consistency: the witness_consistency policy '
                 'section or the gossip input is malformed -- bad '
                 'verifier-key strings, bad quorum, bad freshness window, '
                 'missing accepted head, or a view from an unconfigured '
                 'witness; refused fail-closed, never defaulted',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-signature-invalid': {
        "domain": 'witness',
        "code": 'witness-policy-signature-invalid',
        "human": 'witness policy: a trust-anchor-authorized signer signature does not verify -- forgery signal, refused fail-closed, never ignored',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-threshold-invalid': {
        "domain": 'witness',
        "code": 'witness-policy-threshold-invalid',
        "human": 'witness policy: the witness quorum k or the policy-signer threshold t is out of range (need 1 <= k <= n, 1 <= t <= signers); refused fail-closed at load',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-threshold-unmet': {
        "domain": 'witness',
        "code": 'witness-policy-threshold-unmet',
        "human": 'witness policy: fewer valid trust-anchor-authorized signatures than the anchor threshold; refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-unknown-field': {
        "domain": 'witness',
        "code": 'witness-policy-unknown-field',
        "human": 'witness policy: unknown field(s) in the policy document -- fail closed on shape drift, never silently ignored',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-policy-version-rollback': {
        "domain": 'witness',
        "code": 'witness-policy-version-rollback',
        "human": 'witness policy: the update version does not exceed the installed version (TUF N+1 rollback protection); refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-publish-quorum-unmet': {
        "domain": 'witness',
        "code": 'witness-publish-quorum-unmet',
        "human": 'witness checkpoint publication: publish-time cosigning '
                 'fell below quorum_k; the checkpoint was not published; '
                 'refused fail-closed at the source',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-publish-rollback': {
        "domain": 'witness',
        "code": 'witness-publish-rollback',
        "human": 'witness checkpoint publication: the checkpoint tree '
                 'size is older than the caller-tracked last seen head; '
                 'a rollback is never accepted; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-quorum-unmet': {
        "domain": 'witness',
        "code": 'witness-quorum-unmet',
        "human": 'witness consistency: fewer than quorum_k distinct '
                 'configured witnesses cosigned the log head; the head is '
                 'accepted only with the policy\\u2019s witness quorum; '
                 'refused fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-rekor-anchor-expired': {
        "domain": 'witness',
        "code": 'witness-rekor-anchor-expired',
        "human": 'transparency witness: the anchor receipt is stale -- '
                 'checkpoint time outside the witness key validFor window '
                 'at anchor time, or older than max_anchor_age; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-rekor-anchor-missing': {
        "domain": 'witness',
        "code": 'witness-rekor-anchor-missing',
        "human": 'transparency witness: no anchor receipt presented for '
                 'the bundle digest -- the bundle was never anchored; '
                 'fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-rekor-checkpoint-invalid': {
        "domain": 'witness',
        "code": 'witness-rekor-checkpoint-invalid',
        "human": 'transparency witness: checkpoint signature does not '
                 'verify against the pinned witness key, the logId names '
                 'a foreign key, or the checkpoint time is in the future; '
                 'fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-checkpoint'],
    },
    'witness-rekor-digest-mismatch': {
        "domain": 'witness',
        "code": 'witness-rekor-digest-mismatch',
        "human": 'transparency witness: the receipt binds a different '
                 'digest than the claimed bundle digest -- a receipt '
                 'replayed across bundles; fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-rekor-inclusion-invalid': {
        "domain": 'witness',
        "code": 'witness-rekor-inclusion-invalid',
        "human": 'transparency witness: the Merkle inclusion proof does '
                 'not verify against the checkpoint root hash, or the '
                 'log index is out of bounds; fail-closed',
        "severity": 'critical',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-rekor-malformed': {
        "domain": 'witness',
        "code": 'witness-rekor-malformed',
        "human": 'transparency witness: malformed input -- bad digest '
                 'hex, bad receipt shape, bad witness key, or bad '
                 'validFor window; fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['recompute'],
    },
    'witness-unreachable': {
        "domain": 'witness',
        "code": 'witness-unreachable',
        "human": 'witness consistency: a configured witness reported no '
                 'view during gossip; silence refuses, never passes (the '
                 'TesseraCT fail-open caveat inverted); fail-closed',
        "severity": 'medium',
        "evidence_kinds_required": ['witness-log'],
        "reverify_steps": ['re-verify-witness-consistency'],
    },
    'workflow-approval-binding-invalid': {
        "domain": 'workflow-approval',
        "code": 'workflow-approval-binding-invalid',
        "human": 'approval-gated workflow step: the step\u2019s approval '
                 'binding is malformed -- non-dict inputs (the binding is '
                 'augmented into the inputs), user inputs carrying the '
                 'reserved _gated_step key, or uncanonicalizable material',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-approval-digest-mismatch': {
        "domain": 'workflow-approval',
        "code": 'workflow-approval-digest-mismatch',
        "human": 'approval-gated workflow step: the presented approval does '
                 'not authorize this step -- its bound step digest differs '
                 '(wrong step, cross-step replay, or a non-gated approval), '
                 'its requester is not the step\u2019s actor, or the '
                 'executing authority chain is not the chain the approval '
                 'bound',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-authority-revoked': {
        "domain": 'workflow',
        "code": 'workflow-authority-revoked',
        "human": 'durable workflow: a step execution or resume presented a '
                 'delegation chain that is no longer live (revoked; '
                 'revocation beats expiry) -- resume re-proves authority, '
                 'never trusts the checkpoint',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-branch-decision-forgery': {
        "domain": 'workflow-branch',
        "code": 'workflow-branch-decision-forgery',
        "human": 'branch transaction: the coordinator decision signature '
                 'does not verify under the transaction coordinator key; '
                 'refused fail-closed, never applied',
        "severity": 'critical',
        "evidence_kinds_required": ['decision-package', 'signature'],
        "reverify_steps": ['recompute', 'verify-signature'],
    },
    'workflow-branch-unregistered': {
        "domain": 'workflow-branch',
        "code": 'workflow-branch-unregistered',
        "human": 'branch transaction: an unregistered branch tried to '
                 'apply a coordinator decision; registration must precede '
                 'commit',
        "severity": 'high',
        "evidence_kinds_required": ['decision-package', 'branch-registry'],
        "reverify_steps": ['recompute'],
    },
    'workflow-branch-xid-mismatch': {
        "domain": 'workflow-branch',
        "code": 'workflow-branch-xid-mismatch',
        "human": 'branch transaction: a step ran without the expected '
                 'transaction XID, or a decision package was applied under '
                 'the wrong XID',
        "severity": 'high',
        "evidence_kinds_required": ['step-record', 'xid'],
        "reverify_steps": ['recompute'],
    },
    'workflow-checkpoint-tampered': {
        "domain": 'workflow',
        "code": 'workflow-checkpoint-tampered',
        "human": 'durable workflow: a stored step/run record digest does '
                 'not recompute (stored state was tampered with), or the '
                 'presented inputs/outputs are not JSON-serializable and '
                 'therefore cannot be checkpointed',
        "severity": 'critical',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-composed-authority-mismatch': {
        "domain": 'workflow',
        "code": 'workflow-composed-authority-mismatch',
        "human": 'composed workflow: the authority actor changed '
                 'mid-execution across composed units (authority '
                 'substitution); the plan actor is pinned at first '
                 'execute and every later call must present the same '
                 'actor',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-composed-definition-invalid': {
        "domain": 'workflow',
        "code": 'workflow-composed-definition-invalid',
        "human": 'composed workflow: the composed plan is malformed '
                 '(empty, duplicate unit name, unknown unit kind, '
                 'missing fn/definition/leg material, or non-checkpointable '
                 'inputs)',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-composed-divergent': {
        "domain": 'workflow',
        "code": 'workflow-composed-divergent',
        "human": 'composed workflow: the idempotency layer and the '
                 'workflow checkpoint layer disagree (replay points at a '
                 'missing/incomplete/digest-mismatched step) -- the layers '
                 'have forked; refused fail-closed instead of re-executing '
                 'or trusting either side',
        "severity": 'critical',
        "evidence_kinds_required": ['workflow-record', 'idempotency-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-composed-plan-mismatch': {
        "domain": 'workflow',
        "code": 'workflow-composed-plan-mismatch',
        "human": 'composed workflow: a run is bound to the first plan '
                 'digest executed under it; executing a different plan '
                 'under the same run is refused fail-closed (the plan '
                 'digest binds the units\' code, so a '
                 'descriptor-identical plan with different code cannot '
                 'share the run, while crash-recovery re-execution of '
                 'the same plan still replays)',
        "severity": 'critical',
        "evidence_kinds_required": ['workflow-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-composed-replay-foreign': {
        "domain": 'workflow',
        "code": 'workflow-composed-replay-foreign',
        "human": 'composed workflow: an idempotency replay references a '
                 '(digest, ref) pair foreign to this composed execution -- '
                 'the ref names a run other than the one the composer is '
                 'executing, the record was begun by a different actor, or '
                 'resolution was attempted outside a composed execution; '
                 'the composer only ever completes refs of the form '
                 'wfstep:<current run>:<seq> under its plan actor, so a '
                 'foreign pair is refused fail-closed instead of trusted',
        "severity": 'critical',
        "evidence_kinds_required": ['workflow-record', 'idempotency-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-idempotency-authority-lapsed': {
        "domain": 'workflow-idempotency',
        "code": 'workflow-idempotency-authority-lapsed',
        "human": 'idempotency registry: the caller authority re-verification '
                 'at begin/retry time failed (revoked, expired, or '
                 'unverifiable); the retry is refused instead of replaying',
        "severity": 'high',
        "evidence_kinds_required": ['idempotency-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-idempotency-caller-mismatch': {
        "domain": 'workflow-idempotency',
        "code": 'workflow-idempotency-caller-mismatch',
        "human": 'idempotency registry: complete()/checkpoint() called on '
                 'an outcome whose caller is not the in-flight record\'s '
                 'beginning caller; cross-caller completion/checkpoint '
                 '(result poisoning) refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['idempotency-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-idempotency-key-invalid': {
        "domain": 'workflow-idempotency',
        "code": 'workflow-idempotency-key-invalid',
        "human": 'idempotency registry: keying material (namespace, '
                 'op_class, key, caller, digest) failed grammar; refused '
                 'fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['idempotency-record'],
        "reverify_steps": ['recompute'],
    },
    'workflow-routing-rights-widened': {
        "domain": 'workflow-routing',
        "code": 'workflow-routing-rights-widened',
        "human": 'routing slip: a leg forwarded rights it was not granted, '
                 'or a later leg was granted rights never forwarded by the '
                 'previous leg; delegation narrows, never widens',
        "severity": 'high',
        "evidence_kinds_required": ['routing-slip', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'workflow-routing-slip-tampered': {
        "domain": 'workflow-routing',
        "code": 'workflow-routing-slip-tampered',
        "human": 'routing slip: signature invalid, issuer untrusted, leg '
                 'skipped or reordered, handler key mismatch, or receipt '
                 'chain broken; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['routing-slip', 'signature'],
        "reverify_steps": ['recompute'],
    },
    'workflow-saga-compensation-failed': {
        "domain": 'workflow_saga',
        "code": 'workflow-saga-compensation-failed',
        "human": 'saga: a compensation action failed after all retry '
                 'attempts; the saga is escalated -- the failure is '
                 'recorded, never silently skipped',
        "severity": 'high',
        "evidence_kinds_required": ['saga-history'],
        "reverify_steps": ['recompute'],
    },
    'workflow-saga-compensation-unauthorized': {
        "domain": 'workflow_saga',
        "code": 'workflow-saga-compensation-unauthorized',
        "human": 'saga: a compensation action was refused because its '
                 'step authority could not be re-verified (revoked or '
                 'unknown) at compensation time; the saga is escalated '
                 'and the step stays recorded as uncompensated',
        "severity": 'high',
        "evidence_kinds_required": ['saga-history'],
        "reverify_steps": ['recompute'],
    },
    'workflow-saga-definition-invalid': {
        "domain": 'workflow_saga',
        "code": 'workflow-saga-definition-invalid',
        "human": 'saga: the saga definition is invalid (empty, duplicate '
                 'step id, missing action, or a step without a declared '
                 'compensation) -- compensation is declared up front, '
                 'never invented at failure time',
        "severity": 'high',
        "evidence_kinds_required": ['saga-definition'],
        "reverify_steps": ['recompute'],
    },
    'workflow-saga-operator-unauthorized': {
        "domain": 'workflow_saga',
        "code": 'workflow-saga-operator-unauthorized',
        "human": 'saga: operator recovery of an escalated saga was '
                 'refused because the operator authority could not be '
                 're-verified at recovery time (missing, unknown, or '
                 'refusing verifier); the escalation is unchanged',
        "severity": 'high',
        "evidence_kinds_required": ['saga-history'],
        "reverify_steps": ['recompute'],
    },
    'workflow-saga-resolution-invalid': {
        "domain": 'workflow_saga',
        "code": 'workflow-saga-resolution-invalid',
        "human": 'saga: an operator recovery request was invalid -- the '
                 'saga is not escalated, the resolution action is '
                 'unknown, or a manual-remediation attestation does not '
                 'cover exactly the outstanding steps; refused fail-closed',
        "severity": 'high',
        "evidence_kinds_required": ['saga-history'],
        "reverify_steps": ['recompute'],
    },
    'workflow-step-unauthorized': {
        "domain": 'workflow',
        "code": 'workflow-step-unauthorized',
        "human": 'durable workflow: a step was attempted without a '
                 'verifiable delegation chain, by an actor other than the '
                 "run's initiating actor, or the step slot was already "
                 'executed with different inputs (workflow definition '
                 'drift) -- checkpointed evidence is never overwritten',
        "severity": 'high',
        "evidence_kinds_required": ['workflow-record'],
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
    entry = code_for(refusal_string)# fail-closed on unmapped
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
    entry = code_for(refusal)# fail-closed on unmapped
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
    checked = replay(machine_code)# strict; tampering refuses here
    require_evidence_only(checked)# no authority semantics, ever
    if not isinstance(capsule, dict):
        raise DecisionCodeError(MALFORMED, "capsule must be a dict")
    body = verify_capsule(capsule)# replay; tampering refuses here
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
    checked = replay(machine_code)# strict; tampering refuses here
    if not isinstance(capsule, dict):
        raise DecisionCodeError(MALFORMED, "capsule must be a dict")
    body = verify_capsule(capsule)# replay; tampering refuses here
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
