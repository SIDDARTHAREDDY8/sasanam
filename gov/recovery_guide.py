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

Recovery sessions (wave-346 lane 4): the guide says what to do; a
``RecoverySession`` (opened via ``open_session``) tracks what was
actually done. Each session carries a machine-readable step protocol
(stable step ids, preconditions, verification text), records every
step attempt as a digest-chained event, refines guidance after failed
attempts (fixed templates only -- never inventing remedies), and links
its final chain digest into the ``BlockJournal`` as a "session-link"
entry (which never affects retry numbering). The load-bearing promise:
there is no lift/permit/unmark API anywhere -- ``refusal_lifted()``
is a constant False sentinel, dependent steps attempted before their
preconditions raise loudly instead of being skipped, and completing
every step changes nothing about the refusal.

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

    ``attempt_kind`` is "initial", "retry", or "session-link" (a recovery
    session chained into the journal; see ``BlockJournal.link_session``).
    A retry points ``retry_of`` at the initial mark's id and counts up
    ``attempt_no``. ``absolute`` is True for absolute-deny refusals (no
    authority can permit). ``advisory`` carries the retry-storm notice
    once the threshold is reached (UX text, not enforcement). For
    session-link entries ``retry_of`` holds the session id and
    ``link_final`` holds the session's final chain digest.
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
    link_final: Optional[str] = None

    def to_record(self) -> Dict:
        return {"absolute": self.absolute, "advisory": self.advisory,
                "attempt_kind": self.attempt_kind,
                "attempt_no": self.attempt_no,
                "chain_digest": self.chain_digest, "code": self.code,
                "link_final": self.link_final, "mark_id": self.mark_id,
                "noted_at": self.noted_at, "prev": self.prev,
                "request_digest": self.request_digest,
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

    def link_session(self, session) -> BlockMark:
        """Chain a recovery session's digest trail into the journal.

        The link is typed "session-link": it shares the session's
        request digest but is deliberately NOT counted as a retry --
        retry numbering for the request is unaffected. ``session`` is
        any object exposing ``session_id``, ``request_digest``,
        ``code``, and ``head()`` (see ``RecoverySession``). Linking
        twice raises.
        """
        if getattr(session, "_linked", False):
            raise RecoveryGuideError("session is already linked to a journal")
        session_id = session.session_id
        final = session.head()
        if not session_id or not final:
            raise RecoveryGuideError(
                "link_session needs a session with an id and a chain head")
        mark_id = _sha(("session-link:v1|%s|%s|%s"
                        % (session_id, final, self._head)).encode("utf-8"))
        chain = _sha(("block-mark-chain:v1|%s|%s"
                      % (self._head, mark_id)).encode("utf-8"))
        entry = BlockMark(
            mark_id=mark_id, request_digest=session.request_digest,
            code=session.code, attempt_kind="session-link",
            retry_of=session_id, attempt_no=0, absolute=False,
            prev=self._head, chain_digest=chain, link_final=final)
        self._entries.append(entry)
        session._linked = True
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
            if e.attempt_kind == "session-link":
                # Session-link entries are not retries: they must not
                # affect retry numbering (``seen``) or the absolute-deny
                # recomputation. Recompute the link formula only.
                exp_id = _sha(("session-link:v1|%s|%s|%s"
                               % (e.retry_of, e.link_final,
                                  head)).encode("utf-8"))
                if e.mark_id != exp_id:
                    return False
                head = _sha(("block-mark-chain:v1|%s|%s"
                             % (head, exp_id)).encode("utf-8"))
                if e.chain_digest != head:
                    return False
                if e.attempt_no != 0 or e.absolute or not e.retry_of \
                        or not e.link_final:
                    return False
                continue
            prior = seen.get(e.request_digest, [])
            if prior:
                exp_kind, exp_of, exp_no = "retry", prior[0], len(prior) + 1
            else:
                exp_kind, exp_of, exp_no = "initial", None, 1
            if e.attempt_kind not in ("initial", "retry"):
                return False
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


# ------------------------------------------------------- recovery sessions
# Recovery-as-product loop (wave-346 lane 4): the guide tells the operator
# what to do; the session tracks what was actually done. A RecoverySession
# is a per-block, digest-chained record of attempted recovery steps with a
# machine-readable step protocol (stable step ids, preconditions,
# verification). It is NOT an enforcement path: there is no lift/permit
# API anywhere here -- ``refusal_lifted()`` is a constant False sentinel,
# and dependent steps attempted before their preconditions raise loudly
# instead of being skipped.

#: Outcomes accepted by ``RecoverySession.attempt_step``.
_STEP_OUTCOMES = frozenset({"attempted", "succeeded", "failed"})

_session_chain_init = hashlib.sha256(
    b"recovery-session-chain:v1:init").hexdigest()


@dataclass(frozen=True)
class RecoveryStepSpec:
    """One machine-followable recovery step.

    ``step_id`` is stable across calls (e.g. "step-withhold-resubmit").
    ``preconditions`` lists the step_ids that must report "succeeded"
    before this step may be attempted -- an early attempt raises
    ``RecoveryGuideError`` instead of being skipped. ``verification``
    names what the agent must re-check after performing the step; it
    never claims the refusal is lifted.
    """

    step_id: str
    remedy: str
    kind: str
    title: str
    detail: str
    prerequisite: str
    preconditions: Tuple[str, ...] = ()
    verification: str = ""

    def to_record(self) -> Dict:
        return {"detail": self.detail, "kind": self.kind,
                "preconditions": list(self.preconditions),
                "prerequisite": self.prerequisite, "remedy": self.remedy,
                "step_id": self.step_id, "title": self.title,
                "verification": self.verification}


# What the agent must re-check after each remedy step. Fixed text: the
# refusal is never claimed lifted, re-submissions are always fresh
# requests at the enforcement seam.
_step_verification = {
    "authorize": (
        "Re-submit the ORIGINAL request at the enforcement seam: the "
        "refusal persists until a recorded approval for THIS action "
        "digest exists. The session never grants -- only the enforcement "
        "path evaluates."),
    "accept": (
        "Submit the narrowed request at the enforcement seam: it is "
        "evaluated fresh. A new refusal is a NEW request with its own "
        "session, not a lift of this one."),
    "withhold": (
        "The transformed request is a fresh request at the enforcement "
        "seam. A new refusal gets its own block mark and its own "
        "session -- open a new session instead of extending this one."),
    "sanitize": (
        "The transformed request is a fresh request at the enforcement "
        "seam. A new refusal gets its own block mark and its own "
        "session -- open a new session instead of extending this one."),
    "derive": (
        "Release only the derivative; the raw bytes stay refused. A new "
        "refusal is a NEW request with its own session."),
    "redispatch": (
        "Confirm the recipient satisfies the trust floor the refusal "
        "named, then dispatch at the enforcement seam -- it evaluates "
        "fresh."),
    "fork": (
        "Verify the return attestation before using the subagent's "
        "result; the parent trajectory must never have seen the raw "
        "sensitive bytes."),
}

_procedural_verification = (
    "The verdict stands for the request as evaluated. Any re-submission "
    "is a new request at the enforcement seam.")

# Remedies that split into two session steps: the base step plus a
# follow-up whose preconditions bind the base. The follow-up never adds
# a remedy -- it is the verification half of the same remedy.
_step_followups = {
    "accept": ("sign", "Sign a risk acceptance",
               "Attach a signed risk acceptance naming the residual risk "
               "to the narrowed request and submit it -- evaluated fresh, "
               "not as a retry of the blocked request.",
               "authority to sign a risk acceptance for the residual risk",
               "Submit with the signed acceptance: the enforcement seam "
               "evaluates it fresh. A new refusal is a NEW request with "
               "its own session."),
    "withhold": ("resubmit", "Re-submit with the spans removed",
                 "Re-submit the payload with only the remaining content. "
                 "The new request carries a new request digest and is "
                 "evaluated as a fresh request, not a retry of the "
                 "blocked one.",
                 "the withhold step reported succeeded",
                 "A new refusal is a NEW request with its own block mark "
                 "-- open a new session for it rather than extending "
                 "this one."),
    "sanitize": ("resubmit", "Re-submit the sanitized payload",
                 "Re-submit the sanitizer's output. The new request is "
                 "evaluated fresh at the enforcement seam; the guide "
                 "binds the sanitizer, it does not verify it.",
                 "the sanitize step reported succeeded",
                 "A new refusal is a NEW request with its own block mark "
                 "-- open a new session for it rather than extending "
                 "this one."),
    "derive": ("release", "Release the derivative",
               "Release the computed derivative instead of the raw bytes.",
               "the derive step reported succeeded",
               "Release only the derivative; the raw bytes stay refused. "
               "A new refusal is a NEW request with its own session."),
    "redispatch": ("confirm", "Confirm the trust floor",
                   "Confirm the chosen recipient satisfies the trust "
                   "floor the refusal named, then dispatch.",
                   "the redispatch step reported succeeded",
                   "Dispatch at the enforcement seam -- it evaluates "
                   "fresh. A new refusal is a NEW request with its own "
                   "session."),
    "fork": ("attest", "Attest the subagent return path",
             "Run the sensitive reads in the isolated context and "
             "verify the return attestation before using the result.",
             "the fork step reported succeeded",
             "Verify the return attestation; the parent trajectory must "
             "never have seen the raw sensitive bytes."),
}

# Progressive guidance after a failed step attempt. Fixed templates only
# -- they rephrase the step's own guidance and never name a remedy
# outside the session's plan vocabulary.
_guidance_templates = {
    "generic": (
        "The step did not succeed. Re-check the prerequisite before "
        "re-attempting; dependent steps stay locked until this one "
        "reports succeeded. The refusal stands regardless -- the "
        "enforcement seam decides, never this session."),
    "authorize": (
        "Filing alone changed nothing: confirm the named authority "
        "approved THIS action digest -- a pending, mis-bound, or "
        "different-digest approval is not a lift. If no authority is "
        "reachable, stop retrying and escalate to a human operator; the "
        "storm advisory applies."),
    "resubmit": (
        "The re-submission was refused again. That refusal is a SEPARATE "
        "request with its own block mark -- open a new session for it "
        "instead of extending this one. Continuing identical retries "
        "trips the storm advisory and changes nothing."),
}


def _session_steps(guide: RecoveryGuide) -> Tuple[RecoveryStepSpec, ...]:
    """Expand a guide's steps into the session's machine-readable protocol.

    Every step comes from the guide -- which comes verbatim from the
    refusal's own remedy plan -- so no remedy can be invented here.
    """
    specs = []
    for gs in guide.steps:
        if gs.kind == "procedural":
            base_id = "step-procedural-%s" % gs.remedy
            verification = _procedural_verification
        else:
            base_id = "step-%s" % gs.remedy
            verification = _step_verification.get(gs.remedy, "")
        specs.append(RecoveryStepSpec(
            step_id=base_id, remedy=gs.remedy, kind=gs.kind,
            title=gs.title, detail=gs.detail,
            prerequisite=gs.prerequisite, preconditions=(),
            verification=verification))
        if gs.kind == "remedy" and gs.remedy in _step_followups:
            suffix, title, detail, prerequisite, verification = \
                _step_followups[gs.remedy]
            specs.append(RecoveryStepSpec(
                step_id="%s-%s" % (base_id, suffix), remedy=gs.remedy,
                kind="remedy-followup", title=title, detail=detail,
                prerequisite=prerequisite, preconditions=(base_id,),
                verification=verification))
    return tuple(specs)


def guidance_after_failure(step_id: str, fail_count: int,
                           allowed_remedies: FrozenSet[str]) -> str:
    """Progressive guidance for a step that reported a failure.

    The guidance is chosen from fixed templates only; the templates are
    verified at call time to name no remedy outside ``allowed_remedies``
    (the session's plan vocabulary) -- if a template ever violated that,
    this raises instead of inventing a remedy.
    """
    if fail_count < 1:
        raise RecoveryGuideError("guidance_after_failure needs fail_count>=1")
    if step_id.startswith("step-authorize"):
        template = _guidance_templates["authorize"]
    elif step_id.endswith(("-resubmit", "-release", "-confirm", "-sign",
                           "-attest")):
        template = _guidance_templates["resubmit"]
    else:
        template = _guidance_templates["generic"]
    _assert_no_invented_remedies(template, allowed_remedies)
    return template


def _assert_no_invented_remedies(text: str,
                                 allowed_remedies: FrozenSet[str]) -> None:
    """The never-invent rule, executable: every remedy-vocabulary name
    in the text must be inside the plan's own vocabulary."""
    import re
    words = set(re.findall(r"[a-z][a-z-]*", text.lower()))
    invented = (words & _remedy_names) - set(allowed_remedies)
    if invented:
        raise RecoveryGuideError(
            "guidance invents remedies outside the plan vocabulary: %s"
            % sorted(invented))


class RecoverySession:
    """A per-block recovery session digest-chained into the BlockJournal.

    Created only through :func:`open_session`. The session records what
    the operator/agent actually did: every step attempt is a
    digest-chained event. There is deliberately no lift/permit/unmark
    API -- ``refusal_lifted()`` always returns False, and completing
    every step changes nothing about the refusal; the enforcement seam
    re-evaluates.
    """

    def __init__(self, session_id: str, mark_id: str, view: RefusalView,
                 guide: RecoveryGuide,
                 steps: Tuple[RecoveryStepSpec, ...]):
        if not session_id or not mark_id:
            raise RecoveryGuideError("a session needs an id and a mark")
        self.session_id = session_id
        self.mark_id = mark_id
        self.request_digest = view.request_digest
        self.code = view.code
        self.guide_digest = guide.guide_digest
        self.notice = guide.notice
        self.unliftable = guide.unliftable
        self._steps = tuple(steps)
        self._by_id = {s.step_id: s for s in steps}
        self._completed = set()
        self._failed: Dict[str, int] = {}
        self._events = []
        self._linked = False
        self._head = _sha((_session_chain_init + "|" + session_id
                           ).encode("utf-8"))
        self._record("opened", None, None)

    # ------------------------------------------------------------ events
    def _record(self, event: str, step_id: Optional[str],
                outcome: Optional[str]) -> Dict:
        seq = len(self._events) + 1
        body = {"chain": "recovery-session-chain:v1", "event": event,
                "outcome": outcome, "prev": self._head, "seq": seq,
                "session_id": self.session_id, "step_id": step_id}
        digest = _sha(_canonical(body))
        rec = dict(body)
        rec["chain_digest"] = digest
        self._events.append(rec)
        self._head = digest
        return rec

    def head(self) -> str:
        return self._head

    def verify_chain(self) -> bool:
        """Recompute every session event link. False on any tampering."""
        head = _sha((_session_chain_init + "|" + self.session_id
                     ).encode("utf-8"))
        completed = set()
        for rec in self._events:
            if rec.get("chain") != "recovery-session-chain:v1" \
                    or rec.get("session_id") != self.session_id:
                return False
            body = {k: v for k, v in rec.items() if k != "chain_digest"}
            if _sha(_canonical(body)) != rec.get("chain_digest"):
                return False
            if rec.get("prev") != head:
                return False
            head = rec["chain_digest"]
            if rec["event"] == "step-attempted" \
                    and rec.get("outcome") == "succeeded":
                completed.add(rec["step_id"])
        return head == self._head

    # ------------------------------------------------------------- steps
    def steps(self) -> Tuple[RecoveryStepSpec, ...]:
        return self._steps

    def completed(self) -> Tuple[str, ...]:
        return tuple(sorted(self._completed))

    def next_steps(self) -> Tuple[RecoveryStepSpec, ...]:
        """Steps ready now: preconditions complete, not yet succeeded."""
        ready = []
        for spec in self._steps:
            if spec.step_id in self._completed:
                continue
            if all(p in self._completed for p in spec.preconditions):
                ready.append(spec)
        return tuple(ready)

    def is_complete(self) -> bool:
        """Every step reported succeeded (vacuous for unliftable: no
        steps exist, the record IS the notice)."""
        return all(s.step_id in self._completed for s in self._steps)

    def attempt_step(self, step_id: str, outcome: str,
                     note: str = "") -> Dict:
        """Record a step attempt.

        ``outcome`` is one of "attempted", "succeeded", "failed".
        Attempting a step whose preconditions are not complete raises
        ``RecoveryGuideError`` LOUDLY -- steps cannot be skipped, and
        the failed attempt is NOT recorded (the chain is untouched).
        """
        if outcome not in _STEP_OUTCOMES:
            raise RecoveryGuideError(
                "unknown step outcome: %r" % (outcome,))
        spec = self._by_id.get(step_id)
        if spec is None:
            raise RecoveryGuideError("unknown step id: %r" % (step_id,))
        missing = [p for p in spec.preconditions
                   if p not in self._completed]
        if missing:
            raise RecoveryGuideError(
                "step %r is locked: preconditions not complete: %s"
                % (step_id, ", ".join(missing)))
        rec = self._record("step-attempted", step_id, outcome)
        if outcome == "succeeded":
            self._completed.add(step_id)
            self._record("step-completed", step_id, outcome)
        elif outcome == "failed":
            self._failed[step_id] = self._failed.get(step_id, 0) + 1
        return rec

    def guidance_for(self, step_id: str) -> str:
        """Current guidance for a step: the step detail, refined by the
        fixed progressive templates once it has failed."""
        spec = self._by_id.get(step_id)
        if spec is None:
            raise RecoveryGuideError("unknown step id: %r" % (step_id,))
        fails = self._failed.get(step_id, 0)
        if fails < 1:
            return spec.detail
        allowed = frozenset(s.remedy for s in self._steps)
        return guidance_after_failure(step_id, fails, allowed)

    # ------------------------------------------------------- the promise
    def refusal_lifted(self) -> bool:
        """ALWAYS False. This is the load-bearing promise of the module:
        a recovery session records attempts; it can never lift, weaken,
        or clear a refusal. There is no API here that can change the
        verdict -- completing every step changes nothing about it."""
        return False

    # ------------------------------------------------------------- export
    def protocol(self) -> Dict:
        """The machine-readable recovery protocol: stable step ids,
        preconditions, verification, attempt history, and the promise."""
        return {
            "code": self.code,
            "completed": list(self.completed()),
            "guide_digest": self.guide_digest,
            "mark_id": self.mark_id,
            "next": [s.step_id for s in self.next_steps()],
            "notice": self.notice,
            "refusal_lifted": self.refusal_lifted(),
            "request_digest": self.request_digest,
            "session_id": self.session_id,
            "steps": [s.to_record() for s in self._steps],
            "unliftable": self.unliftable,
        }

    def export_to_journal(self, journal: "BlockJournal") -> BlockMark:
        """Chain this session's digest trail into the journal.

        The journal records the session's final chain digest as a
        "session-link" entry; retry numbering for the request is
        unaffected. Linking twice raises.
        """
        return journal.link_session(self)


def open_session(view: RefusalView, journal: "BlockJournal", *,
                 noted_at: Optional[str] = None) -> RecoverySession:
    """Open a recovery session for a normalized refusal view.

    The refusal is marked in the journal (retry-linking applies), the
    guide is built, and the session's steps come verbatim from the
    refusal's own remedy plan. Records in, records out: nothing here
    touches enforcement.
    """
    if not isinstance(view, RefusalView):
        raise RecoveryGuideError("open_session needs a RefusalView")
    if not isinstance(journal, BlockJournal):
        raise RecoveryGuideError("open_session needs a BlockJournal")
    guide = build_guide(view)
    mark = journal.mark(view.request_digest, view.code, noted_at=noted_at)
    session_id = _sha(("recovery-session:v1|%s|%s"
                       % (mark.mark_id, guide.guide_digest)).encode("utf-8"))
    return RecoverySession(session_id, mark.mark_id, view, guide,
                           _session_steps(guide))


def retry_advisory(mark: BlockMark) -> Optional[str]:
    """The UX advisory for a retry mark, if the storm threshold tripped."""
    return mark.advisory


__all__ = [
    "RETRY_STORM_THRESHOLD",
    "BlockJournal",
    "BlockMark",
    "RecoveryGuideError",
    "RecoveryGuide",
    "RecoverySession",
    "RecoveryStepSpec",
    "RefusalView",
    "RecoveryStep",
    "build_guide",
    "canonical_request_digest",
    "guidance_after_failure",
    "open_session",
    "retry_advisory",
    "view_from_diagnostics",
    "view_from_record",
    "view_from_refusal",
]
