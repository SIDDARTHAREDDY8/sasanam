#!/usr/bin/env python3
"""Recovery-as-product post-block UX (wave-343 lane 6).

Steal source: Archestra OpenAPPA (https://github.com/archestra-ai/openappa),
MIT engine repo -- ADAPT patterns only, never embed their code. The steal
verdict item built here: **recovery-as-product** -- subagent isolation +
guided recovery as first-class post-block UX (their ablations: Bench-Corp
utility 88% -> 35% without guided recovery; the utility lives in the
post-block design). This module is the product surface on top of the
wave-342 R40 work (``gov/trajectory_labels.py``): R40 landed the
trajectory-label monoid, the absolute-deny ``blocked`` mark, and structured
remedy plans on refusal. This module turns a coded refusal into a
**RecoveryGuide** -- a structured, human-readable, evidence-grade record
that says what was blocked, why (in the policy's own language), and exactly
what lawful steps the operator/agent can take next.

Name note: ``gov/recovery.py`` is the wave-77 recovery controller
(checkpoint/verify/resume/halt). This module is separate: it never
touches run state, keys, or sessions -- only refusal records.

What this module is NOT:

* It is not an enforcement path. It imports nothing that authorizes,
  permits, or lifts anything. Every public function takes *records*
  (refusals, diagnostics, dicts) and returns *records* (guides, journal
  entries). There is no function here that can change a verdict, clear a
  mark, or authorize an action -- by construction, not by convention.
* It emits NO new machine decision codes. The guide and the block-mark
  journal reference the *original* refusal code (already registered in
  ``gov/decision_codes.py``). Retry-vs-fresh is a journal *field*
  (``attempt_kind``), not a code. The taxonomy pin is unchanged.
* It does not invent remedies. Steps come from the refusal's own remedy
  plan (R40 ``RemedyPlan``) or from always-true procedural guidance for
  engine verdicts. An empty remedy plan yields the unliftable notice --
  never a fabricated alternative.

Blocked-mark semantics (the second half of this module): every blocked
request gets a persistent, digest-chained mark in a ``BlockJournal``. A
later attempt with the same canonical request digest is journaled as a
*retry* (``retry_of`` points at the initial mark, ``attempt_no`` counts
up) -- retries are distinguishable from fresh requests in the evidence
trail. Marks are permanent: there is no unmark/clear API, and issuing a
guide never touches the refusal outcome. The trajectory-level
absolute-deny mark itself lives in
``gov/trajectory_labels.py::mark_blocked``; the journal records its
evidence footprint.

Oracle discipline (per ``gov/refusal_oracle_guard.py``): the requester
section of a guide uses fixed templates and never interpolates raw
request arguments, secret material, or "which check almost passed".
Policy internals (full reason text, rule reasons) live in the audit
section -- the same audience split the oracle guard documents. The guide
is operator/UX-facing, like ``Diagnostics``.

Honest ceilings (stated explicitly, as is our culture):

* A recovery guide is informational. Completing a listed step does not
  lift the refusal -- the enforcement seam re-evaluates, and for an
  absolute-deny mark no authority can permit at all. Every step says
  what happens next; none promises a lift.
* The unliftability notice is relative to the implemented remedy
  vocabulary version bound in the plan digest (same bound R40 documents).
* The ``withhold``/``sanitize`` steps bind deployment properties this
  module cannot verify (whether the re-submission truly drops the spans,
  whether the sanitizer truly sanitizes). The guide names the binding;
  it does not certify the transform.
* Retry detection keys on the canonical request digest. Two requests
  that differ only in a nonce are different requests -- the caller that
  wants cross-nonce retry linking must pass its own digest.

$0 SPEND BY CONSTRUCTION: no model calls, no network, stdlib only.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Mapping, Optional, Tuple

try:
    from gov.decision_codes import TAXONOMY as _TAXONOMY
except Exception:  # noqa: BLE001 -- taxonomy unavailable: generic why-text
    _TAXONOMY = {}


# ------------------------------------------------------------------ errors
class RecoveryGuideError(Exception):
    """Loud construction error: the guide input is not a refusal."""


# ------------------------------------------------------- remedy vocabulary
# Mirrors gov/trajectory_labels.py::Remedy values (the implemented remedy
# vocabulary). Kept as plain strings here so this module stays a leaf;
# REMEDY_VOCAB_VERSION is echoed from the source refusal's plan.
_remedy_names = frozenset({
    "authorize", "accept", "withhold", "sanitize", "derive",
    "redispatch", "fork",
})

# Fixed, oracle-clean step templates. No template interpolates raw request
# arguments or secret material -- only requester-known identifiers
# (action, resource, principal, rule/policy ids) are formatted in.
_step_templates = {
    "authorize": {
        "title": "Seek human or quorum approval",
        "detail": (
            "File an approval request binding this action's digest "
            "(gov/approval_request.issue: action_digest, requester identity, "
            "approver schema, TTL). The named authority must approve THIS "
            "specific action; filing alone changes nothing -- the refusal "
            "stands until a recorded approval exists."),
        "prerequisite":
            "a human or quorum authority reachable through the approval queue",
    },
    "accept": {
        "title": "Narrow the action and sign a risk acceptance",
        "detail": (
            "Re-scope the request to exclude the refused span, attach a "
            "signed risk acceptance naming the residual risk, and submit the "
            "narrowed request -- it is evaluated fresh, not as a retry."),
        "prerequisite":
            "authority to sign a risk acceptance for the residual risk",
    },
    "withhold": {
        "title": "Drop the sensitive spans and re-submit",
        "detail": (
            "Remove the spans flagged by the DLP scan (gov/dlp.find_credential) "
            "from the payload and re-submit with only the remaining content. "
            "The new request carries a new request digest and is evaluated as "
            "a fresh request, not a retry of the blocked one."),
        "prerequisite":
            "the ability to complete the task without the flagged content",
    },
    "sanitize": {
        "title": "Sanitize through a deployment-bound sanitizer",
        "detail": (
            "Pass the data through the deployment-registered sanitizer; the "
            "sanitizer binding is recorded in the evidence trail. Honest "
            "bound: whether the transform truly sanitizes is a deployment "
            "property -- this guide binds the sanitizer, it does not verify it."),
        "prerequisite": "a registered sanitizer for this data class",
    },
    "derive": {
        "title": "Release a derivative instead of raw data",
        "detail": (
            "Compute an aggregate or redacted derivative (counts, redacted "
            "summary, statistics) and release that instead of the raw bytes."),
        "prerequisite":
            "a defined aggregation that preserves the task's utility",
    },
    "redispatch": {
        "title": "Reroute to a higher-trust recipient",
        "detail": (
            "Send to a recipient inside the trajectory audience or via a "
            "higher-trust tool; the recipient must satisfy the trust floor "
            "the refusal named."),
        "prerequisite": "an eligible recipient for the data",
    },
    "fork": {
        "title": "Isolate the sensitive work in a subagent",
        "detail": (
            "Run the sensitive reads in a separate context (subagent) with a "
            "schema-checked return path; the parent trajectory never sees "
            "the raw sensitive bytes."),
        "prerequisite":
            "subagent-spawn capability with return attestation",
    },
}

# Procedural step templates for engine verdicts (no remedy plan exists).
# kind="procedural": always-true process guidance, never a plan remedy.
_procedural_templates = {
    "procedural-authorize": {
        "title": "File an approval request",
        "detail": (
            "This verdict is require_approval, not deny: file an approval "
            "request (gov/approval_request.issue) binding the action digest. "
            "The action proceeds only if the named authority approves."),
        "prerequisite":
            "a human or quorum authority reachable through the approval queue",
    },
    "procedural-rescope": {
        "title": "Re-scope the request so the deciding rule no longer matches",
        "detail": (
            "Change the request (narrow the resource, drop the flagged "
            "arguments) so deciding rule '{rule_id}' no longer matches, then "
            "submit as a new request. The refusal stands for the request as "
            "it was evaluated."),
        "prerequisite": "control over the request's arguments",
    },
    "procedural-policy-owner": {
        "title": "Ask the policy owner to amend the rule",
        "detail": (
            "Only the owner of policy '{policy_id}' amending the deciding "
            "rule lifts this class of refusal. The refusal stands until the "
            "policy changes; do not retry the identical request."),
        "prerequisite": "access to the policy owner / change process",
    },
}

_unliftable_notice_template = (
    "No lawful alternative exists in the implemented remedy vocabulary "
    "(v{version}). The refusal is final for this trajectory: do not retry "
    "the same request -- retries are journaled as retries of this block "
    "mark and change nothing. Escalate to a human operator.")

# Codes whose refusal is absolute: no authority can permit.
_absolute_codes = frozenset({"label-remedy-empty-unliftable"})

#: Retry count at which the journal attaches a storm advisory (UX text,
#: not enforcement).
RETRY_STORM_THRESHOLD = 5

_journal_init = hashlib.sha256(b"block-marks:v1:init").hexdigest()


# ------------------------------------------------------------------ digests
def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_request_digest(principal: str, action: str,
                             resource: Optional[str] = None,
                             args: Optional[Mapping] = None) -> str:
    """Deterministic digest identifying a blocked request.

    Retry detection keys on this digest: the same (principal, action,
    resource, args) always yields the same digest. Callers that want
    retry-linking across arg variations (e.g. nonces) must pass their own
    digest instead of this one.
    """
    return _sha(_canonical({
        "action": action,
        "args": dict(args) if args else {},
        "principal": principal,
        "resource": resource,
    }))


# ------------------------------------------------------------ normalized view
@dataclass(frozen=True)
class RefusalView:
    """The normalized refusal a guide is built from.

    ``remedies`` holds remedy-vocabulary names (see ``_remedy_names``);
    empty means the source refusal carried an empty plan (unliftable).
    ``procedural`` steps are added by the diagnostics adapter only.
    """

    code: str
    action: str
    principal: str = "unknown"
    resource: Optional[str] = None
    reason: str = ""
    deciding_rule: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    remedies: FrozenSet[str] = field(default_factory=frozenset)
    remedy_vocab_version: int = 1
    procedural: Tuple[str, ...] = ()
    trajectory_digest: Optional[str] = None
    request_digest: str = ""
    refusal_digest: Optional[str] = None

    def __post_init__(self):
        if not self.code or not isinstance(self.code, str):
            raise RecoveryGuideError(
                "a recovery guide needs a non-empty refusal code")
        if not self.action or not isinstance(self.action, str):
            raise RecoveryGuideError(
                "a recovery guide needs a non-empty action name")
        unknown = set(self.remedies) - _remedy_names
        if unknown:
            raise RecoveryGuideError(
                "remedy names outside the implemented vocabulary")
        unknown_proc = set(self.procedural) - set(_procedural_templates)
        if unknown_proc:
            raise RecoveryGuideError("unknown procedural steps")
        if not self.request_digest:
            object.__setattr__(
                self, "request_digest",
                canonical_request_digest(self.principal, self.action,
                                         self.resource))


def _code_human(code: str) -> Optional[str]:
    try:
        entry = _TAXONOMY.get(code)
    except Exception:  # noqa: BLE001
        return None
    if isinstance(entry, dict):
        return entry.get("human")
    return None


# ------------------------------------------------------------------ guide
@dataclass(frozen=True)
class RecoveryStep:
    """One lawful next step.

    ``kind`` is "remedy" (from the implemented remedy vocabulary),
    "procedural" (always-true process guidance), or "notice".
    """

    remedy: str
    kind: str
    title: str
    detail: str
    prerequisite: str

    def to_record(self) -> Dict:
        return {"detail": self.detail, "kind": self.kind,
                "prerequisite": self.prerequisite, "remedy": self.remedy,
                "title": self.title}


@dataclass(frozen=True)
class RecoveryGuide:
    """The built guide: requester section + audit section, digest-bound."""

    code: str
    what: str
    why: str
    steps: Tuple[RecoveryStep, ...]
    unliftable: bool
    notice: Optional[str]
    request_digest: str
    refusal_digest: Optional[str]
    remedy_vocab_version: int
    guide_digest: str
    audit: Dict

    def to_record(self) -> Dict:
        return {
            "audit": dict(self.audit),
            "requester": {
                "code": self.code,
                "guide_digest": self.guide_digest,
                "notice": self.notice,
                "remedy_vocab_version": self.remedy_vocab_version,
                "request_digest": self.request_digest,
                "steps": [s.to_record() for s in self.steps],
                "unliftable": self.unliftable,
                "what": self.what,
                "why": self.why,
            },
        }

    def record_digest(self) -> str:
        return _sha(_canonical(self.to_record()))


def _what_text(view: RefusalView) -> str:
    resource = (" targeting '%s'" % view.resource) if view.resource else ""
    return ("Action '%s'%s by principal '%s' was refused "
            "(code %s)." % (view.action, resource, view.principal,
                            view.code))


def _why_text(view: RefusalView) -> str:
    # Requester-safe: the policy's own language comes from the taxonomy's
    # static human text for the code plus the deciding rule/policy ids.
    # Full dynamic reason text stays in the audit section.
    human = _code_human(view.code)
    parts = []
    if view.deciding_rule:
        parts.append("deciding rule '%s'" % view.deciding_rule)
    if view.policy_id:
        ver = (" v%s" % view.policy_version) if view.policy_version else ""
        parts.append("policy '%s'%s" % (view.policy_id, ver))
    where = (" under " + ", ".join(parts)) if parts else ""
    if human:
        return "%s%s." % (human.rstrip("."), where)
    return "Refused%s (code %s)." % (where, view.code)


def build_guide(view: RefusalView) -> RecoveryGuide:
    """Build the recovery guide for a normalized refusal view.

    Pure function: records in, records out. Cannot authorize, cannot
    lift, cannot clear marks -- it has no handle on any enforcement
    path.
    """
    if not isinstance(view, RefusalView):
        raise RecoveryGuideError("build_guide needs a RefusalView")
    what = _what_text(view)
    why = _why_text(view)
    steps = []
    for name in sorted(view.remedies):
        tpl = _step_templates[name]
        steps.append(RecoveryStep(remedy=name, kind="remedy",
                                 title=tpl["title"], detail=tpl["detail"],
                                 prerequisite=tpl["prerequisite"]))
    for pname in view.procedural:
        tpl = _procedural_templates[pname]
        detail = tpl["detail"]
        if "{rule_id}" in detail:
            detail = detail.replace("{rule_id}",
                                    view.deciding_rule or "unknown")
        if "{policy_id}" in detail:
            detail = detail.replace("{policy_id}",
                                    view.policy_id or "unknown")
        steps.append(RecoveryStep(remedy=pname, kind="procedural",
                                 title=tpl["title"], detail=detail,
                                 prerequisite=tpl["prerequisite"]))
    unliftable = (len(view.remedies) == 0 and len(view.procedural) == 0)
    notice = None
    if unliftable:
        notice = _unliftable_notice_template.format(
            version=view.remedy_vocab_version)
    guide_digest = _sha(_canonical({
        "code": view.code,
        "notice": notice,
        "remedy_vocab_version": view.remedy_vocab_version,
        "request_digest": view.request_digest,
        "steps": [s.to_record() for s in steps],
        "unliftable": unliftable,
        "what": what,
        "why": why,
    }))
    audit = {
        "deciding_rule": view.deciding_rule,
        "guide_digest": guide_digest,
        "policy_id": view.policy_id,
        "policy_version": view.policy_version,
        "reason": view.reason,
        "refusal_digest": view.refusal_digest,
        "remedy_plan_remedies": sorted(view.remedies),
        "remedy_vocab_version": view.remedy_vocab_version,
        "request_digest": view.request_digest,
        "trajectory_digest": view.trajectory_digest,
    }
    return RecoveryGuide(code=view.code, what=what, why=why,
                         steps=tuple(steps), unliftable=unliftable,
                         notice=notice, request_digest=view.request_digest,
                         refusal_digest=view.refusal_digest,
                         remedy_vocab_version=view.remedy_vocab_version,
                         guide_digest=guide_digest, audit=audit)


# ---------------------------------------------------------------- adapters
def view_from_refusal(refusal, *, principal: str = "unknown",
                      resource: Optional[str] = None,
                      request_digest: str = "") -> RefusalView:
    """Adapt a ``gov/trajectory_labels.py::Refusal``.

    The remedy plan is used verbatim -- including the empty plan, which
    yields the unliftable notice. This adapter never invents remedies.
    """
    plan = getattr(refusal, "plan", None)
    if plan is None:
        raise RecoveryGuideError("view_from_refusal needs a Refusal")
    remedies = frozenset(r.value for r in plan.remedies)
    try:
        import gov.trajectory_labels as _tl
        vocab_version = int(_tl.REMEDY_VOCAB_VERSION)
    except Exception:  # noqa: BLE001
        vocab_version = 1
    record_digest = None
    try:
        record_digest = refusal.record_digest()
    except Exception:  # noqa: BLE001
        record_digest = None
    return RefusalView(
        code=refusal.code, action=refusal.action, principal=principal,
        resource=resource, reason=getattr(refusal, "reason", "") or "",
        remedies=remedies, remedy_vocab_version=vocab_version,
        trajectory_digest=getattr(refusal, "trajectory_digest", None),
        request_digest=request_digest or canonical_request_digest(
            principal, refusal.action, resource),
        refusal_digest=record_digest)


def view_from_diagnostics(request, decision, diagnostics,
                         *, request_digest: str = "",
                         code: Optional[str] = None) -> RefusalView:
    """Adapt a ``gov/decision_contract.py`` Request/Decision/Diagnostics.

    * ``effect == "require_approval"`` -> one procedural authorize step.
    * ``effect == "deny"`` -> procedural re-scope + policy-owner steps,
      naming the deciding rule.
    * ``effect == "allow"`` -> RecoveryGuideError (a guide for an allowed
      action is a programming error; loud, never silent).

    ``code``: the engine's machine refusal code when the caller knows it;
    otherwise the literal "unknown" (honest: the contract's Decision
    carries no code field).
    """
    effect = getattr(decision, "effect", None)
    if effect == "allow":
        raise RecoveryGuideError(
            "cannot build a recovery guide for an allowed action")
    if effect not in ("deny", "require_approval"):
        raise RecoveryGuideError("unknown decision effect")
    deciding = diagnostics.deciding_rule
    rule_id = deciding.rule_id if deciding else None
    rule_reason = deciding.reason if deciding else ""
    policy_ids = sorted(diagnostics.policy_ids) if \
        getattr(diagnostics, "policy_ids", None) else []
    policy_id = policy_ids[0] if policy_ids else None
    final_code = code or getattr(decision, "decision_code", None) or "unknown"
    if effect == "require_approval":
        procedural = ("procedural-authorize",)
    else:
        procedural = ("procedural-rescope", "procedural-policy-owner")
    principal = getattr(request, "principal", "unknown") or "unknown"
    action = getattr(request, "action", None) or ""
    return RefusalView(
        code=final_code, action=action, principal=principal,
        resource=getattr(request, "resource", None),
        reason=rule_reason or "", deciding_rule=rule_id,
        policy_id=policy_id, remedies=frozenset(),
        procedural=procedural,
        request_digest=request_digest or canonical_request_digest(
            principal, action, getattr(request, "resource", None)))


def view_from_record(record: Mapping) -> RefusalView:
    """Adapt a plain mapping (generic fallback for any refusal source)."""
    if not isinstance(record, Mapping):
        raise RecoveryGuideError("view_from_record needs a mapping")
    remedies = record.get("remedies") or ()
    procedural = record.get("procedural") or ()
    return RefusalView(
        code=record.get("code", "") or "", action=record.get("action", ""),
        principal=record.get("principal", "unknown") or "unknown",
        resource=record.get("resource"),
        reason=record.get("reason", "") or "",
        deciding_rule=record.get("deciding_rule"),
        policy_id=record.get("policy_id"),
        policy_version=record.get("policy_version"),
        remedies=frozenset(remedies), procedural=tuple(procedural),
        remedy_vocab_version=int(record.get("remedy_vocab_version", 1)),
        trajectory_digest=record.get("trajectory_digest"),
        request_digest=record.get("request_digest", "") or "",
        refusal_digest=record.get("refusal_digest"))


# ------------------------------------------------------------ block journal
@dataclass(frozen=True)
class BlockMark:
    """One journaled block mark.

    ``attempt_kind`` is "initial" or "retry"; a retry points ``retry_of``
    at the initial mark's id and counts up ``attempt_no``. ``absolute``
    is True for absolute-deny refusals (no authority can permit).
    ``advisory`` carries the retry-storm notice once the threshold is
    reached (UX text, not enforcement).
    """

    mark_id: str
    request_digest: str
    code: str
    attempt_kind: str
    retry_of: Optional[str]
    attempt_no: int
    absolute: bool
    prev: str
    chain_digest: str
    advisory: Optional[str] = None
    noted_at: Optional[str] = None

    def to_record(self) -> Dict:
        return {"absolute": self.absolute, "advisory": self.advisory,
                "attempt_kind": self.attempt_kind,
                "attempt_no": self.attempt_no,
                "chain_digest": self.chain_digest, "code": self.code,
                "mark_id": self.mark_id, "noted_at": self.noted_at,
                "prev": self.prev, "request_digest": self.request_digest,
                "retry_of": self.retry_of}


class BlockJournal:
    """Append-only, digest-chained journal of block marks.

    There is deliberately no unmark/clear/remove API: a recorded block
    mark is permanent for the journal's lifetime. Retries of the same
    canonical request digest are labeled retries, never fresh requests.
    """

    def __init__(self):
        self._entries = []
        self._head = _journal_init
        self._by_request: Dict[str, list] = {}

    def mark(self, request_digest: str, code: str, *,
             noted_at: Optional[str] = None) -> BlockMark:
        """Journal a blocked request. Same digest twice -> retry."""
        if not request_digest or not code:
            raise RecoveryGuideError(
                "mark needs a non-empty request digest and code")
        prior = self._by_request.get(request_digest, [])
        if prior:
            attempt_kind = "retry"
            retry_of: Optional[str] = prior[0]
            attempt_no = len(prior) + 1
        else:
            attempt_kind = "initial"
            retry_of = None
            attempt_no = 1
        absolute = code in _absolute_codes
        mark_id = _sha(("block-mark:v1|%s|%s|%d|%s"
                        % (request_digest, code, attempt_no,
                           self._head)).encode("utf-8"))
        chain = _sha(("block-mark-chain:v1|%s|%s"
                      % (self._head, mark_id)).encode("utf-8"))
        advisory = None
        if attempt_no >= RETRY_STORM_THRESHOLD:
            advisory = ("retry storm: this request has been refused %d "
                        "times; stop retrying and escalate to a human "
                        "operator." % attempt_no)
        entry = BlockMark(
            mark_id=mark_id, request_digest=request_digest, code=code,
            attempt_kind=attempt_kind, retry_of=retry_of,
            attempt_no=attempt_no, absolute=absolute, prev=self._head,
            chain_digest=chain, advisory=advisory, noted_at=noted_at)
        self._entries.append(entry)
        self._by_request.setdefault(request_digest, []).append(mark_id)
        self._head = chain
        return entry

    def head(self) -> str:
        return self._head

    def __len__(self) -> int:
        return len(self._entries)

    def marks_for(self, request_digest: str):
        return [e for e in self._entries
                if e.request_digest == request_digest]

    def verify_chain(self) -> bool:
        """Recompute every link. False on any tampering."""
        head = _journal_init
        seen: Dict[str, list] = {}
        for e in self._entries:
            prior = seen.get(e.request_digest, [])
            if prior:
                exp_kind, exp_of, exp_no = "retry", prior[0], len(prior) + 1
            else:
                exp_kind, exp_of, exp_no = "initial", None, 1
            if (e.attempt_kind != exp_kind or e.retry_of != exp_of
                    or e.attempt_no != exp_no):
                return False
            if e.prev != head:
                return False
            exp_id = _sha(("block-mark:v1|%s|%s|%d|%s"
                           % (e.request_digest, e.code, e.attempt_no,
                              head)).encode("utf-8"))
            if e.mark_id != exp_id:
                return False
            head = _sha(("block-mark-chain:v1|%s|%s"
                         % (head, exp_id)).encode("utf-8"))
            if e.chain_digest != head:
                return False
            if e.absolute != (e.code in _absolute_codes):
                return False
            seen.setdefault(e.request_digest, []).append(e.mark_id)
        return head == self._head

    def to_records(self):
        return [e.to_record() for e in self._entries]


def retry_advisory(mark: BlockMark) -> Optional[str]:
    """The UX advisory for a retry mark, if the storm threshold tripped."""
    return mark.advisory


__all__ = [
    "RETRY_STORM_THRESHOLD",
    "BlockJournal",
    "BlockMark",
    "RecoveryGuideError",
    "RecoveryGuide",
    "RecoveryStep",
    "RefusalView",
    "build_guide",
    "canonical_request_digest",
    "retry_advisory",
    "view_from_diagnostics",
    "view_from_record",
    "view_from_refusal",
]
