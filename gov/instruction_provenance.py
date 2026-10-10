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
- ``provlabel-omitted-driver`` -- the agent's plan trace narrowed the
  operator-installed driver set and the narrowed set no longer routes
  while the full installed set does (F307: plan-trace omission). The
  narrowing is audit-logged and the action routes to approval loud --
  an installed injection-shaped driver can never be narrowed away
  silently.

Stdlib only. Deterministic.
"""

import json
import re

#: The machine codes this module emits, pinned by
#: ``evals/w274_provenance_probes.py`` (``c-pin-check``) and the
#: decision-code taxonomy.
EXPECTED_CODES = (
    "provlabel-approval-required",
    "provlabel-mixed-provenance",
    "provlabel-omitted-driver",
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

    def installed_unit_ids(self):
        """All operator-installed unit ids, in installation order.

        Wave-281 (F307): the server-side driver derivation reads this,
        never the agent's plan-trace kwarg. The labeler is installed
        by the operator via ``set_instruction_provenance``; the agent
        never holds a handle to it, so this enumeration is
        server-side by construction.
        """
        return tuple(self._units.keys())

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

# F1024: zero-width characters attackers interleave inside imperative
# keywords ("W\u200bire") so the keyword heuristic misses while a
# human/model reader still sees the word. Stripped before the
# keyword search; the characters are invisible, so removal cannot
# create a false keyword out of visible text.
_ZW_CHARS = "\u200b\u200c\u200d\ufeff"


def _strip_zero_width(text):
    for ch in _ZW_CHARS:
        if ch in text:
            text = text.replace(ch, "")
    return text


def _has_hidden_comment(text):
    """True when *text* carries a substantive hidden HTML comment.

    F1024: `<!-- ... -->` content is not rendered by mail/user
    agents, so a driving unit carrying it is acting on text the
    human principal never saw. Such content is instruction-shaped
    by construction -- it is either an injection or dead markup,
    and the seam routes it to approval (loud) rather than allowing
    silently. Only comments with non-whitespace content count; an
    UNTERMINATED `<!--` with substantive trailing content also
    counts (in HTML rendering it hides everything after it from
    the human -- not counting it would be fail-open at the seam;
    2026-10-10 wave-394 spec-review). Never evals.
    """
    i = 0
    n = len(text)
    while True:
        i = text.find("<!--", i)
        if i < 0:
            return False
        j = text.find("-->", i + 4)
        if j < 0:
            return bool(text[i + 4:].strip())
        if text[i + 4:j].strip():
            return True
        i = j + 3


# F1034: hidden-instruction carriers beyond HTML comments. All three
# detectors run on the zero-width-stripped norm (F1024) and count a
# carrier only when it carries SUBSTANTIVE text -- an empty or
# whitespace-only carrier is dead markup, not a hidden instruction.
# No re.compile() here (module-level count stays as audited); string
# patterns ride the re module's cache.

#: CSS `content` keyword values that carry no text; everything else
#: unquoted counts (fail-closed).
_CSS_CONTENT_KEYWORDS = ("none", "normal", "inherit", "initial", "unset")


def _scan_quoted_string(buf, start):
    """Scan the quoted string opening at ``buf[start]``.

    Returns ``(inner_text, terminated)`` with backslash escapes
    honored. An unterminated string yields ``terminated=False``
    (fail-closed: in CSS error recovery the declaration swallows
    the rest of the block, hiding the text from the human).
    """
    quote = buf[start]
    j = start + 1
    val = []
    while j < len(buf):
        c = buf[j]
        if c == "\\" and j + 1 < len(buf):
            val.append(buf[j + 1])
            j += 2
            continue
        if c == quote:
            return "".join(val), True
        val.append(c)
        j += 1
    return "".join(val), False


def _css_content_value_substantive(block, start):
    """True when the CSS `content:` declaration starting at ``start``
    (the index just past the colon) carries substantive text.

    Quoted strings: the unescaped inner text must be non-whitespace;
    an UNTERMINATED quote counts (fail-closed -- the text is hidden
    from the human either way). Unquoted values: only the known
    text-less keywords are quiet; any other value (url(), attr(),
    counter(), an identifier) fails closed to carrier.
    """
    rest = block[start:].lstrip()
    if not rest or rest[0] not in ("'", '"'):
        word = re.match(r"[^\s;}{]+", rest)
        return bool(word) and word.group(0).lower() \
            not in _CSS_CONTENT_KEYWORDS
    inner, terminated = _scan_quoted_string(rest, 0)
    if not terminated:
        return True
    return bool(inner.strip())


def _has_hidden_content_carrier(block):
    # Declaration boundary (^, ; or {): avoids matching `content`
    # inside selectors (e.g. `.content:x{...}`).
    for m in re.finditer(r"(?:^|[;{])\s*content\s*:", block, re.I):
        if _css_content_value_substantive(block, m.end()):
            return True
    return False


def _has_hidden_css_content(text):
    """True when *text* hides substantive text in a CSS `content:`
    property inside a `<style>` block or an inline `style` attribute.

    F1034: `content:` only generates text into `::before`/`::after`
    pseudo-elements -- never into the visible document flow the human
    reads -- so substantive text there is a hidden carrier, and by
    the F1024 construction is instruction-shaped by construction.
    An UNTERMINATED `<style>` block or `style` attribute is scanned to
    end of text (in HTML/CSS error recovery the declaration swallows
    the rest -- the text is hidden from the human either way; the
    F1024 unterminated-`<!--` rule, fail-closed).
    Fail-closed bounds: empty/whitespace strings (`content:""`),
    keyword values (`content: none`), and `content:` mentions in
    visible prose (outside style contexts) do not count.
    """
    for m in re.finditer(r"<style\b[^>]*>", text, re.I):
        start = m.end()
        close = re.search(r"</style\s*>", text[start:], re.I)
        end = start + close.start() if close else len(text)
        if _has_hidden_content_carrier(text[start:end]):
            return True
    for m in re.finditer(r"\bstyle\s*=\s*([\"'])", text, re.I):
        inner, terminated = _scan_quoted_string(text, m.start(1))
        # Unterminated attribute: the value swallows to end of text.
        region = inner if terminated else text[m.end():]
        if _has_hidden_content_carrier(region):
            return True
    return False


def _has_hidden_svg_foreign_object(text):
    """True when *text* carries substantive text inside an SVG
    `<foreignObject>` element.

    F1034: in the mail/summary contexts Sasanam governs, foreignObject
    content is hidden from the human reader, so substantive text there
    is instruction-shaped by construction (the F1024 rationale).
    Empty/whitespace-only and self-closing forms are quiet; the
    rendered `<text>` element is not a foreignObject and is never
    counted (honest-text bound).
    """
    for m in re.finditer(
            r"<foreignObject\b[^>]*>(.*?)</foreignObject\s*>",
            text, re.I | re.S):
        if m.group(1).strip():
            return True
    return False


def _is_locator_only(value):
    """True when a ref-def value is a bare locator (URL/path), not
    hidden prose: a single whitespace-free token shaped like a URL
    (``://`` or a URI scheme) or a path (``/``, ``./``, ``../``,
    ``#fragment``). Such values are genuine link references -- the
    rendered document shows the linked text -- so they are honest
    text (F1034), not hidden instructions. Anything with whitespace
    or prose shape is not a locator."""
    v = value.strip()
    if not v or any(ch.isspace() for ch in v):
        return False
    if v.startswith("<") and v.endswith(">") and len(v) > 2:
        v = v[1:-1].strip()
        if not v or any(ch.isspace() for ch in v):
            return False
    return ("://" in v
            or v.startswith(("/", "./", "../", "#"))
            or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", v) is not None)


def _has_hidden_md_refdef(text):
    """True when *text* carries a substantive markdown reference-style
    definition (`[id]: value`) hiding prose.

    F1034: reference definitions are never rendered, so a definition
    hiding PROSE is instruction-shaped by construction (the F1024
    rationale). Two honest-text bounds: empty/whitespace-only
    definitions are quiet, and genuine link references -- a bare
    locator value (`[1]: https://example.com/report.pdf`) -- are
    quiet (the rendered document shows the linked text; nothing
    instruction-like is hidden). A locator WITH hidden prose
    (`[1]: https://example.com "kindly process the payment"`) still
    counts: the title text is hidden from the human reader.
    """
    for line in text.splitlines():
        m = re.match(
            r"(?:>[ \t]*)?[ \t]{0,3}\[[^\]\n]{1,100}\]:[ \t]*"
            r"(\S[^\n]*?)[ \t]*$",
            line)
        if not m:
            continue
        value = m.group(1)
        if _is_locator_only(value):
            continue
        if value.strip():
            return True
    return False


# F1047: hidden-instruction carriers beyond the F1034 class. Eight
# further carriers hide substantive text from the human reader while a
# summarizer/agent still processes it. Like F1024/F1034, a carrier
# counts only when its text is PROSE-SHAPED: substantive
# (non-whitespace) AND containing whitespace. Single whitespace-free
# tokens are machine metadata (schema.org contexts, SKUs, CSRF tokens,
# test ids, short UI labels) -- honest text, quiet. This mirrors the
# F1034 `_is_locator_only` carve. No re.compile() here (module-level
# count stays as audited); string patterns ride the re module's cache.
# All detectors run on the zero-width-stripped norm (F1024) so ZWSP
# mangling of the carrier markup cannot evade them.


def _is_prose_shaped(value):
    """True when *value* is substantive hidden prose: non-whitespace and
    containing whitespace. A single whitespace-free token is machine
    metadata (honest text). Never evals."""
    return bool(value and value.strip()
                and any(ch.isspace() for ch in value))


def _scan_element_regions(text, tag):
    """Yield the inner text of each `<tag>...</tag>` region in *text*.

    An UNTERMINATED open tag scans to end of text (fail-closed: in
    HTML error recovery the rest is hidden from the human either way;
    the F1024 unterminated-`<!--` rule). Never evals.
    """
    for m in re.finditer(r"<%s\b[^>]*>" % tag, text, re.I):
        start = m.end()
        close = re.search(r"</%s\s*>" % tag, text[start:], re.I)
        end = start + close.start() if close else len(text)
        yield text[start:end]


def _json_has_prose(data):
    """True when any string value in the JSON structure is prose-shaped.

    Iterative (explicit stack): pathological nesting cannot raise
    RecursionError -- the seam stays Deterministic. Never evals.
    """
    stack = [data]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            if _is_prose_shaped(cur):
                return True
        elif isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)
    return False


def _has_hidden_jsonld(text):
    """True when *text* carries prose-shaped text in a JSON-LD script block.

    F1047: `<script type="application/ld+json">` is never rendered, so
    prose inside it is hidden from the human reader -- instruction-shaped
    by construction (the F1024 rationale). Machine data (valid JSON whose
    string values are all whitespace-free tokens) is honest text, quiet;
    malformed JSON with substantive text fails closed (flagged).
    Never evals.
    """
    for m in re.finditer(
            r"<script\b[^>]*\btype\s*=\s*(\"[^\"]*\"|'[^']*')[^>]*>",
            text, re.I):
        if "ld+json" not in m.group(1).lower():
            continue
        start = m.end()
        close = re.search(r"</script\s*>", text[start:], re.I)
        end = start + close.start() if close else len(text)
        inner = text[start:end]
        if not inner.strip():
            continue
        try:
            data = json.loads(inner)
        except (ValueError, RecursionError):
            # Not valid JSON-LD, or pathologically nested: hidden text,
            # fail closed. RecursionError is caught because the seam is
            # documented Deterministic -- an escaping exception would be
            # a loud crash, not a verdict.
            return True
        if _json_has_prose(data):
            return True
    return False


def _has_hidden_template(text):
    """True when *text* carries prose-shaped text in a `<template>` element.

    F1047: template contents are inert -- never rendered -- so prose
    there is hidden from the human reader (the F1024 rationale).
    Empty/whitespace-only and markup-only templates are quiet.
    Never evals.
    """
    for region in _scan_element_regions(text, "template"):
        if _is_prose_shaped(re.sub(r"<[^>]*>", "", region)):
            return True
    return False


def _has_hidden_svg_title(text):
    """True when *text* carries prose-shaped text in an SVG `<title>`.

    F1047: SVG titles are accessible names, not visually rendered, so
    prose there is hidden from the human reader (the F1024 rationale).
    Scoped to `<svg>` blocks -- the HTML document `<title>` (shown in
    the tab) is out of scope. Never evals.
    """
    for svg in _scan_element_regions(text, "svg"):
        for region in _scan_element_regions(svg, "title"):
            if _is_prose_shaped(region):
                return True
    return False


def _has_hidden_svg_desc(text):
    """True when *text* carries prose-shaped text in an SVG `<desc>`.

    F1047: SVG descriptions are accessible names, not visually rendered
    (the F1024 rationale), scoped to `<svg>` blocks like titles.
    Never evals.
    """
    for svg in _scan_element_regions(text, "svg"):
        for region in _scan_element_regions(svg, "desc"):
            if _is_prose_shaped(region):
                return True
    return False


def _f1047_attr_value(tag_text, name):
    """Extract attribute *name*'s value from a tag string.

    Returns (value, found); quoted values honor backslash escapes via
    the shared scanner. Never evals.
    """
    m = re.search(r"\b%s\s*=\s*" % re.escape(name), tag_text, re.I)
    if not m:
        return None, False
    rest = tag_text[m.end():].lstrip()
    if rest and rest[0] in "\"'":
        inner, _ = _scan_quoted_string(rest, 0)
        return inner, True
    um = re.match(r"[^\s>]+", rest)
    return (um.group(0), True) if um else ("", True)


def _has_hidden_meta_itemprop(text):
    """True when *text* carries prose-shaped text in a `<meta itemprop>`
    content attribute.

    F1047: `<meta itemprop>` is not rendered, so prose in its content
    is hidden from the human reader (the F1024 rationale). Machine
    tokens (`content="ABC-123"`) are honest text, quiet. `<meta
    name="description">` is not an itemprop carrier (out of scope).
    Never evals.
    """
    for m in re.finditer(r"<meta\b[^>]*>", text, re.I):
        tag = m.group(0)
        _, has_itemprop = _f1047_attr_value(tag, "itemprop")
        if not has_itemprop:
            continue
        content, has_content = _f1047_attr_value(tag, "content")
        if has_content and _is_prose_shaped(content):
            return True
    return False


def _has_hidden_aria_label(text):
    """True when *text* carries prose-shaped text in an `aria-label`.

    F1047: aria-labels are screen-reader only -- not visually rendered --
    so prose there is hidden from the human reader (the F1024 rationale).
    Short UI labels (`aria-label="Close"`) are honest text, quiet.
    Never evals.
    """
    for m in re.finditer(r"\baria-label\s*=\s*", text, re.I):
        rest = text[m.end():].lstrip()
        if rest and rest[0] in "\"'":
            inner, _ = _scan_quoted_string(rest, 0)
        else:
            um = re.match(r"[^\s>]+", rest)
            inner = um.group(0) if um else ""
        if _is_prose_shaped(inner):
            return True
    return False


def _has_hidden_input_value(text):
    """True when *text* carries prose-shaped text in an
    `<input type="hidden">` value.

    F1047: hidden inputs are not rendered, so prose in the value is
    hidden from the human reader (the F1024 rationale). Machine tokens
    (`value="tok_abc123"`) are honest text, quiet. Never evals.
    """
    for m in re.finditer(r"<input\b[^>]*>", text, re.I):
        tag = m.group(0)
        itype, has_type = _f1047_attr_value(tag, "type")
        if not has_type or itype.lower() != "hidden":
            continue
        value, has_value = _f1047_attr_value(tag, "value")
        if has_value and _is_prose_shaped(value):
            return True
    return False


def _has_hidden_data_attr(text):
    """True when *text* carries prose-shaped text in a `data-*` attribute.

    F1047: data attributes are not rendered, so prose there is hidden
    from the human reader (the F1024 rationale). Machine tokens
    (`data-testid="submit-btn"`) are honest text, quiet. Never evals.
    """
    for m in re.finditer(r"\bdata-[A-Za-z0-9-]+\s*=\s*(\"[^\"]*\"|'[^']*')",
                         text, re.I):
        if _is_prose_shaped(m.group(1)[1:-1]):
            return True
    return False


# F1064: fourteen further hidden-instruction carriers beyond F1024 /
# F1034 / F1047. Same construction: substantive PROSE-SHAPED text in a
# carrier never rendered to the human reader is instruction-shaped by
# construction (the F1024 rationale); machine tokens, short labels,
# and empty carriers are honest text, quiet. No re.compile() here
# (module-level count stays as audited); patterns ride the re
# module's cache. All detectors run on the zero-width-stripped norm
# (F1024) so ZWSP mangling of the carrier markup cannot evade them.


def _f1064_tag_regions(text, tag):
    """Yield (open_tag_text, inner_text) for each `<tag>...</tag>` region.

    An UNTERMINATED open tag scans to end of text (fail-closed: in
    HTML error recovery the rest is hidden from the human either way;
    the F1024 unterminated-`<!--` rule). Never evals.
    """
    for m in re.finditer(r"<%s\b[^>]*>" % tag, text, re.I):
        start = m.end()
        close = re.search(r"</%s\s*>" % tag, text[start:], re.I)
        end = start + close.start() if close else len(text)
        yield m.group(0), text[start:end]


def _f1064_hidden_element_prose(text, hidden_check):
    """True when an element passing hidden_check(open_tag) carries
    prose-shaped inner text (F1064 helper).

    Inner markup is stripped before the prose test. Never evals.
    """
    for m in re.finditer(r"<([A-Za-z][\w-]*)\b[^>]*>", text, re.I):
        if not hidden_check(m.group(0)):
            continue
        start = m.end()
        close = re.search(r"</%s\s*>" % m.group(1), text[start:], re.I)
        end = start + close.start() if close else len(text)
        if _is_prose_shaped(re.sub(r"<[^>]*>", "", text[start:end])):
            return True
    return False


def _f1064_hidden_class_names(text, prop, value):
    """Class names whose `<style>` rules declare `prop: value` (F1064).

    Strict `.cls{...prop: value...}` rules only; complex selectors
    (descendant, attribute, pseudo) fail closed (not matched). Never
    evals.
    """
    hidden = set()
    pat = (r"\.([A-Za-z_][\w-]*)\s*\{[^}]*?%s\s*:\s*%s\b"
           % (re.escape(prop), re.escape(value)))
    for region in _scan_element_regions(text, "style"):
        for m in re.finditer(pat, region, re.I):
            hidden.add(m.group(1).lower())
    return hidden


def _has_hidden_display_none(text):
    """True when prose hides in a display:none element (F1064).

    Inline `style="display:none"` or a class whose `<style>` rule
    declares display:none. Hidden from the human reader (the F1024
    rationale). Never evals.
    """
    hidden_classes = _f1064_hidden_class_names(text, "display", "none")

    def _check(open_tag):
        style, has_style = _f1047_attr_value(open_tag, "style")
        if has_style and re.search(r"(?:^|;)\s*display\s*:\s*none\b",
                                   style, re.I):
            return True
        cls, has_cls = _f1047_attr_value(open_tag, "class")
        return (has_cls and bool(hidden_classes)
                and any(c.lower() in hidden_classes
                        for c in cls.split()))

    return _f1064_hidden_element_prose(text, _check)


def _has_hidden_visibility_hidden(text):
    """True when prose hides in a visibility:hidden element (F1064).

    Inline style or a class whose `<style>` rule declares
    visibility:hidden. Never evals.
    """
    hidden_classes = _f1064_hidden_class_names(text, "visibility",
                                                "hidden")

    def _check(open_tag):
        style, has_style = _f1047_attr_value(open_tag, "style")
        if has_style and re.search(
                r"(?:^|;)\s*visibility\s*:\s*hidden\b", style, re.I):
            return True
        cls, has_cls = _f1047_attr_value(open_tag, "class")
        return (has_cls and bool(hidden_classes)
                and any(c.lower() in hidden_classes
                        for c in cls.split()))

    return _f1064_hidden_element_prose(text, _check)


def _has_hidden_hidden_attr(text):
    """True when prose hides in an element with the `hidden` attribute
    (F1064). `<div hidden>prose</div>` is never rendered. The
    `aria-hidden` / `data-hidden` attributes are NOT this carrier --
    `aria-hidden="true"` content is visually rendered (excluded via
    the hyphen lookbehinds). Never evals.
    """
    def _check(open_tag):
        return re.search(r"(?<![\w-])hidden(?![\w-])", open_tag,
                         re.I) is not None

    return _f1064_hidden_element_prose(text, _check)


def _has_hidden_html_title(text):
    """True when prose hides in the HTML `<title>` (F1064).

    The document title is not page content -- in the dual-target
    harness the human sees the rendered body, not the tab title (the
    F1024 rationale). Single-token titles are honest text, quiet.
    Never evals.
    """
    for region in _scan_element_regions(text, "title"):
        if _is_prose_shaped(region):
            return True
    return False


def _has_hidden_img_alt(text):
    """True when prose hides in an `<img alt>` (F1064).

    Alt text renders only when the image fails to load; in the
    harness it is hidden from the human reader (the F1024
    rationale). Short alts (`alt="logo"`) are honest text, quiet.
    Never evals.
    """
    for m in re.finditer(r"<img\b[^>]*>", text, re.I):
        alt, has_alt = _f1047_attr_value(m.group(0), "alt")
        if has_alt and _is_prose_shaped(alt):
            return True
    return False


def _has_hidden_title_attr(text):
    """True when prose hides in a `title` attribute (F1064).

    Tooltips are hover-only -- hidden from the human reader unless
    hovered (the F1024 rationale). Short titles are honest text,
    quiet. Never evals.
    """
    for m in re.finditer(r"\btitle\s*=\s*", text, re.I):
        rest = text[m.end():].lstrip()
        if rest and rest[0] in "\"'":
            inner, _ = _scan_quoted_string(rest, 0)
        else:
            um = re.match(r"[^\s>]+", rest)
            inner = um.group(0) if um else ""
        if _is_prose_shaped(inner):
            return True
    return False


def _has_hidden_dialog(text):
    """True when prose hides in a `<dialog>` without the `open`
    attribute (F1064). A closed dialog is never rendered; `<dialog
    open>` is rendered and stays quiet. Never evals.
    """
    for open_tag, region in _f1064_tag_regions(text, "dialog"):
        if re.search(r"(?<![\w-])open(?![\w-])", open_tag, re.I):
            continue
        if _is_prose_shaped(re.sub(r"<[^>]*>", "", region)):
            return True
    return False


def _has_hidden_popover(text):
    """True when prose hides in an element with the `popover`
    attribute (F1064). Popovers are hidden until shown. Never evals.
    """
    def _check(open_tag):
        return re.search(r"(?<![\w-])popover(?![\w-])", open_tag,
                         re.I) is not None

    return _f1064_hidden_element_prose(text, _check)


def _has_hidden_vtt_note(text):
    """True when prose hides in a WebVTT NOTE block (F1064).

    NOTE blocks are comments -- never rendered as captions (the
    F1024 rationale). Rendered cue text stays quiet. Never evals.
    """
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"NOTE(?:\s+(.*))?$", lines[i].strip())
        if not m:
            i += 1
            continue
        buf = []
        j = i + 1
        while j < len(lines) and lines[j].strip():
            buf.append(lines[j].strip())
            j += 1
        body = ((m.group(1) or "") + " " + " ".join(buf)).strip()
        if _is_prose_shaped(body):
            return True
        i = j
    return False


def _has_hidden_xmp_desc(text):
    """True when prose hides in XMP `dc:description` metadata (F1064).

    XMP metadata is never rendered. Never evals.
    """
    for region in _scan_element_regions(text, "dc:description"):
        if _is_prose_shaped(region):
            return True
    return False


def _has_hidden_meta_descriptions(text):
    """True when prose hides in og:/twitter: meta descriptions (F1064).

    `<meta property="og:description">` and `<meta
    name="twitter:description">` are social-card metadata -- never
    rendered in the page body (the F1024 rationale). Honest machine
    tokens stay quiet. Never evals.
    """
    for m in re.finditer(r"<meta\b[^>]*>", text, re.I):
        tag = m.group(0)
        prop, has_prop = _f1047_attr_value(tag, "property")
        name, has_name = _f1047_attr_value(tag, "name")
        if not ((has_prop and prop.lower() == "og:description")
                or (has_name
                    and name.lower() == "twitter:description")):
            continue
        content, has_content = _f1047_attr_value(tag, "content")
        if has_content and _is_prose_shaped(content):
            return True
    return False


def _has_hidden_hidden_option(text):
    """True when prose hides in `<option hidden>` (F1064).

    Hidden options are never shown in the dropdown. Never evals.
    """
    for open_tag, region in _f1064_tag_regions(text, "option"):
        if re.search(r"(?<![\w-])hidden(?![\w-])", open_tag,
                     re.I) is None:
            continue
        if _is_prose_shaped(re.sub(r"<[^>]*>", "", region)):
            return True
    return False


def instruction_shaped(text):
    """Deterministic heuristic: does this unit read like an instruction
    to the agent? A stand-in for the plan-trace / intent-slicing
    detector; the grant seam reads only its boolean, never its
    internals."""
    if not isinstance(text, str):
        return False
    norm = _strip_zero_width(text)
    if _IMPERATIVES.search(norm):
        return True
    # F1024: hidden-from-human carriers evade the keyword heuristic
    # (polite paraphrase, zero-width mangling) -- a substantive
    # hidden HTML comment in the driving text is instruction-shaped
    # by construction, so the grant seam routes to approval instead
    # of falling through to "agent authority".
    if _has_hidden_comment(norm):
        return True
    # F1034: the same construction for the three further
    # hidden-from-human carriers -- CSS `content:` text, SVG
    # `<foreignObject>` text, and markdown reference definitions.
    # All detectors run on the zero-width-stripped norm so ZWSP
    # mangling of the carrier markup cannot evade them.
    if (_has_hidden_css_content(norm)
            or _has_hidden_svg_foreign_object(norm)
            or _has_hidden_md_refdef(norm)):
        return True
    # F1047: the same construction for eight further hidden-from-human
    # carriers -- JSON-LD script blocks, <template> contents, SVG
    # <title>/<desc>, <meta itemprop>, aria-label, <input type=hidden>,
    # and data-* attributes. Prose-shaped text in these carriers is
    # instruction-shaped by construction; machine tokens stay quiet.
    if (_has_hidden_jsonld(norm)
            or _has_hidden_template(norm)
            or _has_hidden_svg_title(norm)
            or _has_hidden_svg_desc(norm)
            or _has_hidden_meta_itemprop(norm)
            or _has_hidden_aria_label(norm)
            or _has_hidden_input_value(norm)
            or _has_hidden_data_attr(norm)):
        return True
    # F1064: the same construction for fourteen further
    # hidden-from-human carriers -- display:none (inline and
    # class-based), visibility:hidden, the hidden attribute, HTML
    # <title>, img alt, title attributes, <dialog>, popover, VTT
    # NOTE blocks, XMP dc:description, og:/twitter: meta
    # descriptions, and <option hidden>. All detectors run on the
    # zero-width-stripped norm (F1024).
    return (_has_hidden_display_none(norm)
            or _has_hidden_visibility_hidden(norm)
            or _has_hidden_hidden_attr(norm)
            or _has_hidden_html_title(norm)
            or _has_hidden_img_alt(norm)
            or _has_hidden_title_attr(norm)
            or _has_hidden_dialog(norm)
            or _has_hidden_popover(norm)
            or _has_hidden_vtt_note(norm)
            or _has_hidden_xmp_desc(norm)
            or _has_hidden_meta_descriptions(norm)
            or _has_hidden_hidden_option(norm))


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
    coded decision ``provlabel-approval-required``. A driver set that
    MIXES below-bar and at/above-bar instruction-shaped drivers (the
    toxic-agent-flow shape: a user instruction plus a retrieved
    injection) is likewise routed, with the distinct coded decision
    ``provlabel-mixed-provenance``, so the injection cannot piggyback
    on the user's authority. Read-only actions are provenance-advisory
    only (data plane, as today).
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

    ranked = [(u, effective_label(u)) for u in instr_units]
    best = max(label for _, label in ranked)
    worst = min(label for _, label in ranked)
    chain = []
    for u in instr_units:
        chain.extend(labeler.chain(u))
    if worst < require_provenance <= best:
        # Mixed provenance: an instruction-shaped driver below the bar
        # rides with one at/above it (the toxic-agent-flow shape: user
        # instruction + retrieved injection). The old max-of-drivers
        # rule silently allowed this; route to approval with a
        # distinct code so the approver sees the below-bar driver in
        # the surfaced chain. F294.
        below = sorted({label_name(label)
                        for _, label in ranked
                        if label < require_provenance})
        return Decision(
            False, True, "provlabel-mixed-provenance",
            "instruction-shaped drivers span the provenance bar "
            "(below-bar: %s; required: %s); approval required with "
            "provenance surfaced"
            % (", ".join(below), label_name(require_provenance)),
            chain)
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
