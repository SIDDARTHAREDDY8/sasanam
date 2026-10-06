#!/usr/bin/env python3
"""Trajectory-level label monoid + remedy plans (R40, OpenAPPA ADAPT pattern).

Steal source: Archestra OpenAPPA (https://github.com/archestra-ai/openappa),
LICENSE.md verified genuine MIT 2026-10-05 (Copyright 2026 Archestra Inc.,
no riders). Prospecting lane report: wave-341 lane A. Pin any reference to
their commit hash, not ``main`` -- the repo self-describes as "Preview & RFC"
with no compatibility guarantees. What is stolen here is the PATTERN (a
checked label monoid folded across a trajectory + remedy plans on refusal),
re-implemented in Python in Sasanam idioms. The Rust engine was NOT ported.

The bypass class this answers: **annotation arbitrage** (R40). OpenAPPA's
guarantees are conditional on truthful deployment annotations: a tool result's
output label comes from the deployer's annotation delta, so a mis-annotated
tool (``Delta::NONE``) lets sensitive bytes cross the trajectory without the
label ever descending -- the label tracks *which tools were used*, not *how
sensitive the data is*. This module binds labels to ground truth as well as
to declarations: every fold combines the deployment-declared annotation with
an independently computed content-truth label (currently the DLP
credential scan, ``gov.dlp.find_credential``), and the meet can only descend.
A mislabeled tool can therefore never *raise* the label above what the
content scan justifies -- misannotation is fail-closed by construction.

Honest ceiling (stated explicitly, as is our culture):
  * The truth scan is only as good as the underlying detectors. The F428
    residual is documented: JSFuck-obfuscated credentials currently miss
    ``find_credential``, so the truth scan misses them too and the label
    does not descend. ``fold()`` does not claim to fix F428; the battery
    pins the residual so F428's closure is observable here.
  * The empty-remedy-set "proof of unliftability" is RELATIVE to the
    implemented remedy vocabulary (``REMEDY_VOCAB_VERSION``). The plan
    digest binds the vocabulary version, so a verifier can see the exact
    scope of the unliftability claim. An empty set is not a proof against
    remedies nobody implemented -- exactly the honest bound OpenAPPA's own
    ``plan.rs`` documents.
  * Sanitizer correctness is trusted, not verified: ``Remedy.SANITIZE``
    binds a deployment-registered sanitizer the way OpenAPPA binds
    sanitizer derivations; whether the transform actually sanitizes is a
    deployment property this module cannot check.

Overlay discipline: this module changes NO existing enforcement path. It is
a self-contained decision aid: fold a trajectory label across tool outputs,
check proposed dispatches against it, and attach coded refusals with
remedy plans to the evidence trail. Existing seams stay authoritative.

$0 SPEND BY CONSTRUCTION: no model calls, no network, stdlib only.
"""

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Dict, FrozenSet, Iterable, Optional, Set

from gov.dlp import find_credential

# ------------------------------------------------------------------ codes
# Machine decision-code literals (registered in gov/decision_codes.py;
# pin 2131 -> 2134, wave-342 lane 3). Passed as code= kwargs so the
# vocabulary inventory (idiom 2) maps them.

LABEL_EGRESS_REFUSED = "label-egress-refused"
LABEL_REMEDY_EMPTY_UNLIFTABLE = "label-remedy-empty-unliftable"
LABEL_ANNOTATION_UNREGISTERED = "label-annotation-unregistered"
LABEL_TRUST_FLOOR_REFUSED = "label-trust-floor-refused"

# ------------------------------------------------------------ trust tiers
class Trust(IntEnum):
    """Data-provenance trustworthiness. Higher = more trusted source."""

    UNTRUSTED = 0
    LOW = 1
    HIGH = 2
    SYSTEM = 3


# ----------------------------------------------------------------- label
_UNIVERSAL = None  # audience None = the universal audience (top)


@dataclass(frozen=True)
class Label:
    """A checked security label: ``audience x trust`` with a blocked mark.

    *audience*: the set of audience atoms permitted to receive data at this
    label, or None for the universal audience (top). The empty set means no
    permitted audience (maximally restrictive short of BLOCKED).
    *trust*: provenance-trust tier of the data.
    *blocked*: the absolute-deny mark -- no authority can permit data at
    the blocked label (adapted from OpenAPPA's ``blocked`` mark).
    """

    audience: Optional[FrozenSet[str]] = None
    trust: Trust = Trust.SYSTEM
    blocked: bool = False

    def __post_init__(self):
        if self.audience is not None and not isinstance(
                self.audience, frozenset):
            object.__setattr__(self, "audience",
                               frozenset(self.audience))


#: The top label: everything permitted, maximally trusted. Identity of
#: combine(). Deployment-default start of a trajectory.
TOP = Label(audience=_UNIVERSAL, trust=Trust.SYSTEM, blocked=False)

#: The bottom label: absolute deny. Absorbing element of combine().
BLOCKED = Label(audience=frozenset(), trust=Trust.UNTRUSTED, blocked=True)


def _aud_meet(a, b):
    if a is _UNIVERSAL:
        return b
    if b is _UNIVERSAL:
        return a
    return frozenset(a) & frozenset(b)


def combine(x: Label, y: Label) -> Label:
    """The checked monoid operation: the restrictive meet.

    combine(x, y) is more restrictive than (or equal to) both x and y --
    it never ascends. Associative, commutative, idempotent; TOP is the
    identity, BLOCKED is absorbing. Proved by the battery's property
    probes, not just asserted here.
    """
    if x.blocked or y.blocked:
        return BLOCKED
    return Label(audience=_aud_meet(x.audience, y.audience),
                 trust=x.trust if x.trust < y.trust else y.trust,
                 blocked=False)


def more_restrictive(a: Label, b: Label) -> bool:
    """True iff *a* is at least as restrictive as *b* (a <= b)."""
    if b.blocked:
        return True  # everything is >= bottom... i.e. bottom <= everything
    if a.blocked:
        return True
    if b.audience is _UNIVERSAL:
        aud_ok = True
    elif a.audience is _UNIVERSAL:
        aud_ok = False
    else:
        aud_ok = frozenset(a.audience) <= frozenset(b.audience)
    return aud_ok and a.trust <= b.trust


def canonical_label(label: Label) -> str:
    """Deterministic canonical form of a label (digest input)."""
    if label.blocked:
        return "blocked"
    aud = "*" if label.audience is _UNIVERSAL else ",".join(
        sorted(label.audience))
    return "aud=%s|trust=%d" % (aud, int(label.trust))


# ------------------------------------------------------------ ground truth
def truth_label(output: bytes) -> Label:
    """Ground-truth label of tool-output bytes, from content scanning.

    A credential found by the DLP scan (``gov.dlp.find_credential``) means
    the bytes are exfiltratable secrets: the audience collapses to the
    agent itself and the trust tier to UNTRUSTED. Benign content is the
    neutral element (TOP): the truth scan can only ever *descend* the
    label, never raise it -- this is what defeats annotation arbitrage.

    DOCUMENTED RESIDUAL (F428, open): JSFuck-obfuscated credentials miss
    ``find_credential``, so they miss this scan too and the label does not
    descend. This function does not fix F428; the battery pins the
    residual so F428's closure is observable as a probe flip.
    """
    try:
        text = output.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 -- fail closed on undecodable input
        return Label(audience=frozenset(), trust=Trust.UNTRUSTED)
    rule = find_credential(text)
    if rule is not None:
        return Label(audience=frozenset({"self"}), trust=Trust.UNTRUSTED)
    return TOP


# --------------------------------------------------------------- trajectory
def _chain_digest(prev: str, label: Label, tool: str, output: bytes) -> str:
    h = hashlib.sha256()
    h.update(prev.encode("utf-8"))
    h.update(b"|")
    h.update(canonical_label(label).encode("utf-8"))
    h.update(b"|")
    h.update(tool.encode("utf-8"))
    h.update(b"|")
    h.update(hashlib.sha256(output).hexdigest().encode("utf-8"))
    return h.hexdigest()


_TRAJ_INIT = hashlib.sha256(b"trajectory-labels:v1:init").hexdigest()


@dataclass(frozen=True)
class Trajectory:
    """A folded trajectory: the running label plus a digest chain.

    The digest chain makes the fold evidence-grade: any verifier can
    recompute it offline from the same (tool, output, annotation) inputs
    without the engine. Deterministic, stdlib only.
    """

    label: Label = TOP
    digest: str = _TRAJ_INIT
    steps: int = 0


def _resolve_declared(tool: str, declared: Optional[Label],
                      registry: Optional[Dict[str, Label]],
                      strict: bool) -> Label:
    if registry is not None:
        if tool not in registry:
            raise UnregisteredToolError(tool)
        return registry[tool]
    if declared is None:
        if strict:
            # No annotation source at all: fail closed rather than fold a
            # tool whose declared sensitivity is unknown.
            raise UnregisteredToolError(tool)
        return TOP  # non-strict: treat missing annotation as neutral
    return declared


class UnregisteredToolError(Exception):
    """Fail-closed fold error: no deployment-declared annotation.

    Machine code: ``label-annotation-unregistered``.
    """

    code = LABEL_ANNOTATION_UNREGISTERED

    def __init__(self, tool: str):
        self.tool = tool
        super().__init__(
            "%s: tool %r has no deployment-declared annotation; refusing "
            "to fold an undeclared tool surface" % (self.code, tool))


def fold(traj: Trajectory, *, tool: str, output: bytes,
         declared: Optional[Label] = None,
         registry: Optional[Dict[str, Label]] = None,
         strict: bool = True) -> Trajectory:
    """Fold one tool output into the trajectory label.

    content = combine(declared_annotation, truth_label(output))
    new_traj = combine(traj, content)

    The declared annotation and the ground-truth scan meet, so a
    mislabeled tool (the annotation-arbitrage class: Delta::NONE /
    missing delta on a tool that returns secrets) still descends the
    trajectory -- misannotation can only be *as permissive as declared*,
    never above what the content scan justifies. In strict mode (default)
    a tool with no deployment-declared annotation refuses outright
    (``label-annotation-unregistered``), the F427-style truth binding.
    """
    ann = _resolve_declared(tool, declared, registry, strict)
    content = combine(ann, truth_label(output))
    new_label = combine(traj.label, content)
    return Trajectory(
        label=new_label,
        digest=_chain_digest(traj.digest, new_label, tool, output),
        steps=traj.steps + 1)


def fold_declared_only(traj: Trajectory, *, tool: str, output: bytes,
                       declared: Optional[Label] = None,
                       registry: Optional[Dict[str, Label]] = None,
                       strict: bool = True) -> Trajectory:
    """NAIVE BASELINE kept for red-first falsifiability.

    Folds ONLY the declared annotation, skipping the ground-truth scan.
    This is the pre-R40 algebra OpenAPPA's analysis showed to be
    vulnerable to annotation arbitrage: a tool annotated Delta::NONE
    (neutral) that returns a credential leaves the trajectory at TOP, and
    a later public egress is allowed. The battery's expected-BREAK probe
    demonstrates the bypass against this function so the hardened
    :func:`fold` has something falsifiable to beat. Do NOT use in
    production paths.
    """
    ann = _resolve_declared(tool, declared, registry, strict)
    new_label = combine(traj.label, ann)
    return Trajectory(
        label=new_label,
        digest=_chain_digest(traj.digest, new_label, tool, output),
        steps=traj.steps + 1)


def mark_blocked(traj: Trajectory, *, tool: str = "policy",
                 output: bytes = b"") -> Trajectory:
    """Apply the absolute-deny mark to a trajectory (unliftable)."""
    return Trajectory(
        label=BLOCKED,
        digest=_chain_digest(traj.digest, BLOCKED, tool, output),
        steps=traj.steps + 1)


# ------------------------------------------------------------ remedy plans
class Remedy(Enum):
    """Lawful alternatives enumerated on refusal (adapted OpenAPPA plan.rs).

    AUTHORIZE  -- a named-human / quorum authority ruling lifts the refusal
    ACCEPT     -- narrow the action and sign a risk acceptance
    WITHHOLD   -- drop the sensitive spans, proceed with the rest
    SANITIZE   -- pass the data through a deployment-bound sanitizer
                  (binding only: whether the transform truly sanitizes is a
                  deployment property, stated honestly)
    DERIVE     -- compute an aggregate/derivative instead of releasing raw data
    REDISPATCH -- reroute to a higher-trust recipient or tool
    FORK       -- split the trajectory into compliant / non-compliant branches
    """

    AUTHORIZE = "authorize"
    ACCEPT = "accept"
    WITHHOLD = "withhold"
    SANITIZE = "sanitize"
    DERIVE = "derive"
    REDISPATCH = "redispatch"
    FORK = "fork"


#: Version of the implemented remedy vocabulary. The empty-plan
#: "proof of unliftability" is relative to THIS vocabulary; the plan
#: digest binds the version so verifiers see the claim's exact scope.
REMEDY_VOCAB_VERSION = 1


def _plan_digest(code: str, traj_digest: str, action: str,
                 remedies: FrozenSet[Remedy]) -> str:
    h = hashlib.sha256()
    h.update(b"remedy-plan:v1|")
    h.update(("vocab=%d|" % REMEDY_VOCAB_VERSION).encode("utf-8"))
    h.update(code.encode("utf-8"))
    h.update(b"|")
    h.update(traj_digest.encode("utf-8"))
    h.update(b"|")
    h.update(action.encode("utf-8"))
    h.update(b"|")
    h.update(",".join(sorted(r.value for r in remedies)).encode("utf-8"))
    return h.hexdigest()


@dataclass(frozen=True)
class RemedyPlan:
    """A structured, digest-bound set of lawful alternatives to a refusal.

    The EMPTY plan is the unliftability proof: ``remedies`` is empty and
    the digest binds (code, trajectory, action, vocabulary version), so a
    third party can verify that no remedy in the implemented vocabulary
    was available -- without the engine. The claim's scope is exactly the
    implemented vocabulary; it is not a proof against unimplemented
    remedies.
    """

    remedies: FrozenSet[Remedy] = field(default_factory=frozenset)
    digest: str = ""

    @classmethod
    def of(cls, code: str, traj_digest: str, action: str,
           remedies: Iterable[Remedy]) -> "RemedyPlan":
        rem = frozenset(remedies)
        return cls(remedies=rem,
                   digest=_plan_digest(code, traj_digest, action, rem))

    @classmethod
    def empty(cls, code: str, traj_digest: str, action: str) -> "RemedyPlan":
        return cls.of(code, traj_digest, action, ())

    def is_unliftable(self) -> bool:
        return len(self.remedies) == 0


# ---------------------------------------------------------------- refusals
@dataclass(frozen=True)
class Refusal:
    """A coded refusal carrying its remedy plan and trajectory evidence."""

    code: str
    reason: str
    plan: RemedyPlan
    trajectory_digest: str
    action: str

    def to_record(self) -> Dict:
        """Deterministic JSON-able record (sorted keys) for evidence."""
        return {
            "action": self.action,
            "code": self.code,
            "plan_digest": self.plan.digest,
            "plan_remedies": sorted(r.value for r in self.plan.remedies),
            "reason": self.reason,
            "remedy_vocab_version": REMEDY_VOCAB_VERSION,
            "trajectory_digest": self.trajectory_digest,
        }

    def record_digest(self) -> str:
        return hashlib.sha256(
            json.dumps(self.to_record(), sort_keys=True,
                       separators=(",", ":")).encode("utf-8")).hexdigest()


class LabelRefusalError(Exception):
    """Raised form of a :class:`Refusal` (code-first, like other seams)."""

    def __init__(self, refusal: Refusal):
        self.refusal = refusal
        self.code = refusal.code
        super().__init__("%s: %s" % (refusal.code, refusal.reason))


# The implemented remedy table: refusal class -> lawful alternatives.
# Kept as data so the "implemented subset" behind an empty plan is
# auditable in one place.
_EGRESS_REMEDIES = frozenset({
    Remedy.WITHHOLD, Remedy.SANITIZE, Remedy.DERIVE,
    Remedy.AUTHORIZE, Remedy.REDISPATCH,
})
_TRUST_FLOOR_REMEDIES = frozenset({Remedy.AUTHORIZE, Remedy.REDISPATCH})


def check_dispatch(traj: Trajectory, *, recipient: Set[str], action: str = "",
                   recipient_trust_floor: Trust = Trust.UNTRUSTED
                   ) -> Optional[Refusal]:
    """Check-before-dispatch against the trajectory label.

    Returns None (allowed) or a coded :class:`Refusal` with a remedy plan.
    Fail-closed ordering: the blocked mark is checked first (unliftable),
    then the audience boundary, then the trust floor.
    """
    label = traj.label
    if label.blocked:
        return Refusal(
            code=LABEL_REMEDY_EMPTY_UNLIFTABLE,
            reason="trajectory carries the absolute-deny mark; no "
                   "authority can permit this dispatch",
            plan=RemedyPlan.empty(LABEL_REMEDY_EMPTY_UNLIFTABLE,
                                  traj.digest, action),
            trajectory_digest=traj.digest,
            action=action)
    if label.audience is not _UNIVERSAL:
        if not frozenset(recipient) <= frozenset(label.audience):
            return Refusal(
                code=LABEL_EGRESS_REFUSED,
                reason="recipient %s outside trajectory audience %s"
                       % (sorted(recipient), sorted(label.audience)),
                plan=RemedyPlan.of(LABEL_EGRESS_REFUSED, traj.digest,
                                   action, _EGRESS_REMEDIES),
                trajectory_digest=traj.digest,
                action=action)
    if label.trust < recipient_trust_floor:
        return Refusal(
            code=LABEL_TRUST_FLOOR_REFUSED,
            reason="trajectory trust %s below recipient floor %s"
                   % (label.trust.name, recipient_trust_floor.name),
            plan=RemedyPlan.of(LABEL_TRUST_FLOOR_REFUSED, traj.digest,
                               action, _TRUST_FLOOR_REMEDIES),
            trajectory_digest=traj.digest,
            action=action)
    return None
