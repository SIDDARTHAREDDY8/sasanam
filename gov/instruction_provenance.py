"""Instruction-provenance labeling: whose instruction drove this action?

Wave-274 lane 1 (STEAL of the wave-273 lane-G instruction-provenance
spike). The spike asked, red-first: can a provenance label attached at
the content-ingress seam let the grant/approval seam distinguish
user-instructed from injection-instructed calls? (10/10 spike probes;
verdict STEAL.) This module is the product seam built from that design,
rewritten to product standards.

The problem: Sasanam's authority model is boundary-scoped (which server,
which tool, which args -- ``AuthorityProof`` exact ``server::tool``
matching, per-tool grants with PoP). It never asks *who authored the
instruction that caused this call*. Three real incidents are the same
failure shape: an **injection-instructed** call looks exactly like a
**user-instructed** call at every seam Sasanam currently governs:

- GitHub MCP toxic-agent flow (Invariant Labs, May 2025): poisoned public
  issues hijack the agent into data exfiltration.
- EchoLeak (CVE-2025-32711): zero-click prompt injection via crafted email
  exfiltrates tenant data through a trusted relay; the egress rides client
  auto-fetch of markdown images -- never an agent tool call.
- GTG-50020 (Anthropic Sep 2026 threat report): injected instructions in an
  eval sandbox cause it to hand over production API keys.

This module supplies the missing dimension: every content unit the agent
acts on carries a **provenance label** attached at the ingress seam,
before the agent sees it. Three seams:

1. **Ingress** (:class:`IngressLabeler`): ``ingest`` labels content before
   the agent sees it; unlabeled content defaults to
   ``RETRIEVED_UNTRUSTED`` (fail-closed). ``compose`` mixes units and
   downgrades monotonically to the least-authoritative label. Labels
   never upgrade without an explicit authority action.
2. **Grant** (:func:`grant_check`): provenance-scoped authorization. A
   *consequential* action (external write, egress, privilege change) whose
   instruction-shaped driving units are all below the required provenance
   (``USER_DIRECT`` by default) is routed to approval -- never silently
   executed. The agent runtime passes ``driving_units`` from its plan
   trace as an explicit contract; governance verifies labels, it does
   not guess them.
3. **Approval** (:func:`render_provenance_section`): the approval record
   renders the full provenance chain. Without this, the approver sees a
   plausible issue comment and approves (the GitHub MCP lesson).

Labels (total authority order, most to least authoritative):

    SYSTEM > USER_DIRECT > AGENT_MEMORY > TOOL_OUTPUT > USER_QUOTED
        > RETRIEVED_UNTRUSTED

``TOOL_OUTPUT`` wraps the retrieved payload's own label: an MCP
``get_issue`` result carrying a public issue body is
``TOOL_OUTPUT(github-mcp)`` wrapping ``RETRIEVED_UNTRUSTED(
github-issue#12, public, @attacker)`` -- the inner label is what the
instruction rule reads. See :func:`wrap_tool_output`.

Data vs instruction are tracked independently: the label decides
*authority*, a second independent judgment decides *instruction shape*
(:func:`instruction_shaped`, documented stand-in below). A ``USER_DIRECT``
instruction acting on ``RETRIEVED_UNTRUSTED`` *data* ("summarize this
email") is allowed.

Honest limits (stated, not hidden):

- Instruction-shape detection is the hard part. ``instruction_shaped``
  is a deterministic heuristic stand-in for the product so the labeling
  mechanics are testable red-first; the real detector is the agent
  runtime's plan trace (``driving_units`` contract) graduating to an
  intent-slicing judge (the OpenAI-guardrails direction). The scheme
  works regardless of which detector produces the units.
- Trust-relay / client auto-fetch (EchoLeak): labeling flags
  rendering-destined output with auto-executable fetches at the ACT
  seam, but cannot interdict inside a third-party client. That leg is
  the egress gate's job (``gov/egress_refs.py``) or a deployment
  control -- flagged output is the hand-off, not the interdiction.
- Approver fatigue is explicit non-coverage: surfacing provenance helps
  the approver; it does not model or fix rubber-stamping.
- Label laundering via paraphrase defeats carrier matching, not the
  label: the label travels with the unit, not its bytes. A genuinely
  new, unlabeled unit is ``RETRIEVED_UNTRUSTED`` by default.

Machine codes (domain ``provlabel``, all in the taxonomy):

- ``provlabel-approval-required`` -- consequential action whose driving
  instruction provenance is below the requirement; routed to approval.
- ``provlabel-unresolvable-driver`` -- driving unit ids unresolvable
  (no label on record); approval required with the gap surfaced.
- ``provlabel-malformed`` -- the seam input is not the expected shape;
  refused fail-closed, never raises.

Stdlib only. Deterministic.
"""

import re

#: The machine codes this module emits, pinned by
#: ``evals/w274_provenance_probes.py`` (``c-pin-check``) and the
#: decision-code taxonomy.
EXPECTED_CODES = (
    "provlabel-approval-required",
    "provlabel-unresolvable-driver",
    "provlabel-malformed",
)

#: Authority order, most to least authoritative. The public constant
#: ``AUTHORITY_ORDER`` lists the Label names in the same order.
_AUTHORITY_RANK = (
    "SYSTEM",
    "USER_DIRECT",
    "AGENT_MEMORY",
    "TOOL_OUTPUT",
    "USER_QUOTED",
    "RETRIEVED_UNTRUSTED",
)

AUTHORITY_ORDER = list(_AUTHORITY_RANK)


class ProvenanceError(Exception):
    """Coded fail-closed error from the provenance seam.

    ``code`` is the taxonomy machine code; ``detail`` is a human
    explanation that never carries secret material.
    """

    def __init__(self, code, detail):
        super(ProvenanceError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _refuse(code, detail):
    if code not in EXPECTED_CODES:
        raise AssertionError("unknown provenance code %r" % (code,))
    raise ProvenanceError(code, detail)


class Label(object):
    """Provenance labels as a total authority order.

    Implemented as ordered class attributes (not an enum) so the module
    stays dependency-free and the rank comparison is a plain int
    comparison; ``rank_of`` / ``name_of`` are the only conversions.
    """

    RETRIEVED_UNTRUSTED = 0
    USER_QUOTED = 1
    TOOL_OUTPUT = 2
    AGENT_MEMORY = 3
    USER_DIRECT = 4
    SYSTEM = 5


_RANK_TO_NAME = {i: name for i, name in
                 enumerate(reversed(_AUTHORITY_RANK))}
_NAME_TO_RANK = {name: i for i, name in _RANK_TO_NAME.items()}


def label_name(rank):
    """Human name for a label rank (e.g. 4 -> 'USER_DIRECT')."""
    return _RANK_TO_NAME.get(rank, "RETRIEVED_UNTRUSTED")


def label_rank(name):
    """Rank for a label name; unknown names fail closed to
    RETRIEVED_UNTRUSTED's rank."""
    return _NAME_TO_RANK.get(name, Label.RETRIEVED_UNTRUSTED)


class ContentUnit(object):
    """One labeled chunk of content. Provenance chain via parent ids.

    ``unit_id`` is the labeler's opaque id; ``text`` the content bytes;
    ``label`` a :class:`Label` rank; ``carrier`` identifies the source
    (e.g. ``"github-issue#12(public,@attacker)"``); ``parents`` the ids
    of the units this one was composed from (empty for ingested units).
    """

    __slots__ = ("unit_id", "text", "label", "carrier", "parents")

    def __init__(self, unit_id, text, label, carrier="", parents=()):
        self.unit_id = unit_id
        self.text = text
        self.label = label
        self.carrier = carrier
        self.parents = tuple(parents)

    def __repr__(self):
        return "ContentUnit(%r, label=%s, carrier=%r)" % (
            self.unit_id, label_name(self.label), self.carrier)


class IngressLabeler(object):
    """The ingress seam: label content before the agent sees it.

    Adapter points call :meth:`ingest` with the label for their content
    class. The two wave-273 carrier adapters (``gov/image_text.py``,
    ``gov/egress_refs.py``) emit records carrying
    ``"provenance_label": "RETRIEVED_UNTRUSTED"`` on every return path --
    retrieved content with no trust anchor. The session input path
    labels typed text ``USER_DIRECT`` (see :func:`label_user_direct`).
    Anything unlabeled -- use :meth:`ingest_default` -- is
    ``RETRIEVED_UNTRUSTED`` by construction.
    """

    def __init__(self):
        self._units = {}
        self._seq = 0

    def _new_id(self):
        self._seq += 1
        return "u%04d" % self._seq

    def _register(self, unit):
        """Record a pre-built unit (used by wrap_tool_output)."""
        self._units[unit.unit_id] = unit
        return unit

    def _check_label(self, label):
        if label not in _RANK_TO_NAME:
            _refuse("provlabel-malformed",
                    "label must be a Label rank 0..5, got %r" % (label,))

    def ingest(self, text, label, carrier=""):
        """Label ``text`` with ``label`` and record its ``carrier``."""
        self._check_label(label)
        if not isinstance(text, str):
            _refuse("provlabel-malformed",
                    "content text must be str, got %s"
                    % type(text).__name__)
        if not isinstance(carrier, str):
            _refuse("provlabel-malformed", "carrier must be str")
        unit = ContentUnit(self._new_id(), text, label, carrier)
        self._units[unit.unit_id] = unit
        return unit

    def ingest_default(self, text, carrier=""):
        """Fail-closed unlabeled ingress: RETRIEVED_UNTRUSTED."""
        return self.ingest(text, Label.RETRIEVED_UNTRUSTED, carrier)

    def compose(self, units, text, carrier=""):
        """Mix content (e.g. the user quotes a tool result into the
        prompt): the result takes the LEAST authoritative label.
        Monotonic -- labels never upgrade here."""
        units = list(units or [])
        for u in units:
            if not isinstance(u, ContentUnit):
                _refuse("provlabel-malformed",
                        "compose expects ContentUnit values")
        if not units:
            return self.ingest_default(text, carrier or "unlabeled")
        label = min(u.label for u in units)
        parents = tuple(u.unit_id for u in units)
        unit = ContentUnit(self._new_id(), text, label, carrier, parents)
        self._units[unit.unit_id] = unit
        return unit

    def unit(self, unit_id):
        """Return the recorded unit, or None when unresolvable."""
        return self._units.get(unit_id)

    def chain(self, unit):
        """Full provenance chain, least-recent first (parents before
        children)."""
        out = []
        seen = set()

        def walk(u):
            for pid in u.parents:
                p = self._units.get(pid)
                if p is not None and pid not in seen:
                    seen.add(pid)
                    walk(p)
            out.append(u)

        walk(unit)
        return out


def wrap_tool_output(labeler, inner_unit, tool_carrier):
    """TOOL_OUTPUT wraps the retrieved payload's own label: the tool
    result is ``(tool identity, inner unit)`` -- the inner unit's label
    is what the instruction rule reads (GTG-50020: an injected
    instruction inside a governed tool's output does not launder to
    TOOL_OUTPUT authority)."""
    if not isinstance(labeler, IngressLabeler):
        _refuse("provlabel-malformed",
                "labeler must be an IngressLabeler")
    if not isinstance(inner_unit, ContentUnit):
        _refuse("provlabel-malformed",
                "wrap_tool_output expects a ContentUnit inner unit")
    if not isinstance(tool_carrier, str) or not tool_carrier:
        _refuse("provlabel-malformed",
                "tool carrier must be a non-empty str")
    return labeler._register(ContentUnit(
        labeler._new_id(),
        "tool output from %s (inner unit %s)"
        % (tool_carrier, inner_unit.unit_id),
        Label.TOOL_OUTPUT, tool_carrier,
        (inner_unit.unit_id,)))


# ---------------------------------------------------------------------------
# Instruction-shape judgment.
#
# Honest limit (stated, not hidden): deciding "is this text an
# instruction the agent followed?" for real LLM content is a
# model-judgment problem (the OpenAI-guardrails intent-slicing direction
# from the 2026-09-27 prospectus). This heuristic is a deterministic
# stand-in so the *labeling* mechanics can be tested red-first; the
# product takes the driving-unit set from the agent runtime's plan
# trace. The scheme works regardless of which detector produces it.
# ---------------------------------------------------------------------------

# instruction. Attackers embed instructions mid-document (the toxic-agent
# flow hides them inside an otherwise-benign issue body), so the verbs
# are matched anywhere with word boundaries, not only at line starts.
# This is deliberately coarse: it is a stand-in for the plan-trace /
# intent-slicing detector, and over-triggering here routes to approval
# (loud) rather than allowing silently.
_IMPERATIVES = re.compile(
    r"(?i)\b(?:please\s+)?(ignore|disregard|forget|do\s+not\s+follow|"
    r"instead|now|you\s+must|you\s+should|send|post|exfiltrate|upload|"
    r"share|forward|fetch|retrieve|get|open|create|run|execute|delete|"
    r"copy|leak|disclose|reveal|wire|transfer|embed|collect|attach|"
    r"schedule)\b")


def instruction_shaped(text):
    """Deterministic heuristic: does this unit read like an instruction
    to the agent? A stand-in for the plan-trace / intent-slicing
    detector; the grant seam reads only its boolean, never its
    internals."""
    if not isinstance(text, str):
        return False
    return bool(_IMPERATIVES.search(text))


class ActionRequest(object):
    """A consequential action the agent wants to take.

    ``consequential``: external write / egress / privilege change.
    ``driving_units``: content-unit ids from the agent runtime's plan
    trace -- the explicit contract. Governance verifies labels; it does
    not guess them.
    """

    __slots__ = ("action", "args", "consequential", "driving_units")

    def __init__(self, action, args, consequential, driving_units):
        self.action = action
        self.args = dict(args or {})
        self.consequential = bool(consequential)
        self.driving_units = tuple(driving_units or ())


class Decision(object):
    """The grant seam's verdict."""

    __slots__ = ("allowed", "routed_to_approval", "code", "reason",
                 "provenance_chain")

    def __init__(self, allowed, routed_to_approval, code, reason,
                 provenance_chain=()):
        self.allowed = bool(allowed)
        self.routed_to_approval = bool(routed_to_approval)
        self.code = code
        self.reason = reason
        self.provenance_chain = list(provenance_chain)


def grant_check(req, labeler, require_provenance=Label.USER_DIRECT):
    """The grant seam: provenance-scoped authorization.

    Rule: a consequential action whose driving instruction provenance
    is entirely below ``require_provenance`` is NOT silently executed --
    it is routed to approval with the provenance chain surfaced and the
    coded decision ``provlabel-approval-required``. Read-only actions
    are provenance-advisory only (data plane, as today).
    """
    if not isinstance(req, ActionRequest):
        _refuse("provlabel-malformed", "req must be an ActionRequest")
    if not isinstance(labeler, IngressLabeler):
        _refuse("provlabel-malformed", "labeler must be an IngressLabeler")
    if require_provenance not in _RANK_TO_NAME:
        _refuse("provlabel-malformed",
                "require_provenance must be a Label rank")

    if not req.consequential:
        return Decision(True, False, None,
                        "read-only action: provenance advisory only")

    units = [labeler.unit(uid) for uid in req.driving_units]
    missing = [uid for uid, u in zip(req.driving_units, units)
               if u is None]
    if missing:
        # Unresolvable driving units = fail closed to approval with
        # the gap surfaced.
        return Decision(False, True, "provlabel-unresolvable-driver",
                        "driving units unresolvable (no label on record): "
                        "%s" % (missing,))

    instr_units = []
    for u in units:
        # The instruction rule reads through wrappers: a TOOL_OUTPUT
        # unit carrying retrieved content does not launder the inner
        # unit's instruction shape (GTG-50020). The candidates are the
        # unit plus everything in its provenance chain.
        for cand in labeler.chain(u):
            if instruction_shaped(cand.text) and cand not in instr_units:
                instr_units.append(cand)
    if not instr_units:
        # No instruction-shaped driver: the action is agent-initiated;
        # falls back to the agent's own authority (boundary-scoped,
        # as today).
        return Decision(True, False, None,
                        "no instruction-shaped driver; agent authority")

    # The rule reads the INNER label of wrapped tool outputs: a
    # TOOL_OUTPUT unit carrying retrieved content inherits the least
    # authoritative label in its wrap chain (label laundering by
    # re-carriering is refused by construction).
    def effective_label(u):
        best = u.label
        for parent in labeler.chain(u)[:-1]:
            best = min(best, parent.label)
        return best

    best = max(effective_label(u) for u in instr_units)
    chain = []
    for u in instr_units:
        chain.extend(labeler.chain(u))
    if best >= require_provenance:
        return Decision(True, False, None,
                        "driven by %s; meets provenance requirement"
                        % label_name(best), chain)
    return Decision(
        False, True, "provlabel-approval-required",
        "driven by instruction provenance %s (below required %s); "
        "approval required with provenance surfaced"
        % (label_name(best), label_name(require_provenance)),
        chain)


def render_provenance_section(req, decision):
    """What the approver sees: the action PLUS its provenance chain.

    The GitHub MCP lesson: without this, the approver sees a plausible
    issue comment and approves. Returns ``{"text", "code"}`` -- ``text``
    is the human rendering, ``code`` the machine decision code
    (``provlabel-approval-required`` / ``provlabel-unresolvable-driver``
    / ``None`` when no routing happened) so the record stays
    machine-checkable.
    """
    if not isinstance(req, ActionRequest):
        _refuse("provlabel-malformed", "req must be an ActionRequest")
    if not isinstance(decision, Decision):
        _refuse("provlabel-malformed", "decision must be a Decision")
    lines = ["ACTION: %s" % req.action,
             "ARGS: %r" % (req.args,),
             "DECISION: %s" % decision.code,
             "REASON: %s" % decision.reason]
    if decision.provenance_chain:
        lines.append("PROVENANCE CHAIN (least-recent first):")
        for u in decision.provenance_chain:
            lines.append("  [%s] %s: %r"
                         % (label_name(u.label),
                            u.carrier or "(no carrier)",
                            u.text[:90]))
    return {"text": "\n".join(lines), "code": decision.code}


# ---------------------------------------------------------------------------
# Adapter points. Helpers for the agent runtime side of the ingress
# seam: the two wave-273 carrier adapters already emit records carrying
# "provenance_label": "RETRIEVED_UNTRUSTED" on every return path (added
# at their source in gov/image_text.py and gov/egress_refs.py); these
# helpers let the runtime attach the same labels to content units it
# ingests itself (session input, tool outputs it wraps).
# ---------------------------------------------------------------------------

def label_image_text(labeler, text, carrier=""):
    """Label image-text carrier extraction output: retrieved content
    with no trust anchor -- RETRIEVED_UNTRUSTED."""
    return labeler.ingest(text, Label.RETRIEVED_UNTRUSTED, carrier)


def label_egress_ref(labeler, text, carrier=""):
    """Label egress-reference screening content: agent-produced text
    about to be screened -- RETRIEVED_UNTRUSTED."""
    return labeler.ingest(text, Label.RETRIEVED_UNTRUSTED, carrier)


def label_user_direct(labeler, text, carrier="session:user"):
    """Label session input typed by the authenticated user."""
    return labeler.ingest(text, Label.USER_DIRECT, carrier)


def attach_to_approval_record(record, req, decision):
    """Merge the provenance section into an approval record dict.

    The approval seam: when the grant path routes a consequential
    action to approval, the runtime merges the rendered provenance
    chain into the approval record so the approver sees whose
    instruction drives the action (the GitHub MCP lesson). Returns a
    NEW dict; the input record is not mutated. The ``"provenance"``
    value is the ``render_provenance_section`` ``{"text", "code"}``
    mapping, so the record stays machine-checkable.
    """
    if not isinstance(record, dict):
        _refuse("provlabel-malformed", "record must be a dict")
    section = render_provenance_section(req, decision)
    merged = dict(record)
    merged["provenance"] = section
    return merged
