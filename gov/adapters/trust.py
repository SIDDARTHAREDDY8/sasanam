"""Instruction Hierarchy at the adapter boundary (Wallace et al.).

Priority order: ``system > developer > user > tool``. The training half
is OUT-OF-SCOPE; this module codifies the hierarchy in adapter trust
levels:

* every content item is tagged with its privilege level
  (:func:`tag_privilege`);
* TOOL-level content is NEVER instruction-channel -- it is data, always;
* instruction-like framing inside lower-privilege content is
  quarantined: the item is marked ``quarantined`` with a reason and an
  audit event, so a downstream builder renders it as data and never
  executes it as an instruction;
* a lower-privilege item CLAIMING a higher privilege
  (``"SYSTEM: ..."``, ``"[DEVELOPER] ..."``, or a markdown fenced code
  block whose info string is ``system``/``developer`` -- F119) is
  demoted to its actual level and quarantined.

Higher privilege always wins structurally: quarantine only ever
demotes, never promotes.

Policy-engine mapping: the executor's policy match context already
carries the coarse ``source_untrusted`` bit
(``ToolExecutor._context``); the adapter-side hierarchy refines it
structurally -- by the time content reaches the model context,
TOOL-level imperatives have been quarantined, so policy never has to
decide whether a tool instruction outranks a system one. A future
fine-grained ``trust_level`` policy context would extend
``ToolExecutor._context`` directly; that is deferred (it overlaps
architect item A1's per-value provenance work) and deliberately NOT
done here.
"""

import json
import re
import unicodedata

from .core import AdapterError
from .mcp_adapter import MetadataPoisoningError, scan_tool_description

__all__ = [
    "SYSTEM",
    "DEVELOPER",
    "USER",
    "TOOL",
    "LEVEL_NAMES",
    "tag_privilege",
    "resolve_hierarchy",
]

#: Instruction Hierarchy privilege levels, highest first.
SYSTEM = 3
DEVELOPER = 2
USER = 1
TOOL = 0

LEVEL_NAMES = {
    SYSTEM: "system",
    DEVELOPER: "developer",
    USER: "user",
    TOOL: "tool",
}

#: "SYSTEM: ...", "[SYSTEM] ...", "Developer instructions: ..." --
#: a lower-privilege item claiming a higher privilege. The trailing
#: class requires a claim delimiter so "the system is down" does not
#: match. The delimiter class is ASCII-only BY CONSTRUCTION:
#: ``[:\]\-]`` -- every non-ASCII delimiter folds to ":" on the
#: matching copy (``_fold_delimiter_confusables``, F87) before this
#: regex runs, so the class never enumerates code points and the next
#: colon lookalike is a table row, not a regex change.
_SYSTEM_CLAIM_RE = re.compile(
    r"(?i)(?:^|[\s>\"'(\[])\s*system\s*[:\]\-]")
_DEVELOPER_CLAIM_RE = re.compile(
    r"(?i)(?:^|[\s>\"'(\[])\s*developer\s*[:\]\-]")


#: F119 (RT12, wave-43): markdown fenced code blocks whose info string
#: claims a privilege level (```system / ```developer / ~~~ variants,
#: optional blockquote prefix) -- the Comment-and-Control markdown-abuse
#: shape. The info string is the block's LABELED ROLE (how GitHub
#: renders it, how models are trained to read code fences), so it is an
#: unambiguous privilege claim: "```system" is the fence analog of
#: "SYSTEM: ...". Unlike ATX headers ("## System requirements" is a
#: topic, not a claim -- deliberately NOT covered) or bold/inline-code
#: emphasis ("**System:**", "`system:`" -- emphasis, not role
#: attribution; pinned residuals), a fence info string of "system" /
#: "developer" has no honest use ("system" is not a programming
#: language), so the false-positive surface is ~zero. Runs on the
#: NFKC-normalized matching copy like the keyword regexes, so homoglyph
#: fence/keyword shapes (fullwidth letters, U+FF40/U+FF5E fence
#: confusables) fold before matching -- the F82/F87 mechanism, no
#: enumeration. Markdown allows up to 3 leading spaces before a fence;
#: the lookahead after the keyword permits end-of-line or the existing
#: delimiter class so "```system", "```System: x```" both match while
#: "```systemic" does not.
#:
#: F120 (wave-44): two CommonMark-valid fence positions were missed --
#: (a) fenced code blocks nested inside list items ("- ```system",
#: "1. ```system", "> - ```system", task-list "- [ ] ```system"):
#: the old prefix allowed only spaces and blockquote markers before
#: the fence, so a fence after a list marker sailed through; (b) lone
#: CR as a line separator (CommonMark treats CR not followed by LF as
#: a line ending): the old anchor was ^|\n and the lookahead's
#: end-of-line was $ (before \n only). The prefix is now two
#: alternatives: the original plain/blockquote path (unchanged, so the
#: 4-space-indented-code boundary and the mid-line-fence boundary are
#: preserved) or a run of one-or-more blockquote/list/task markers
#: (the marker's presence is what licenses deeper indentation, so
#: bare "    ```system" still does not match). The line anchor is
#: ^|[\r\n] and the lookahead accepts a lone \r as end-of-line.
#: F121 (wave-45): the blockquote arm of the marker run is a ">"
#: CLUSTER (">(?:[ \t]*>)*") so ">> - ```system" (nested blockquotes
#: with no space between markers -- CommonMark-valid, RT14 A2 missed
#: it) chains into a following list marker. F122 (wave-46): the run
#: additionally allows a blockquote cluster GLUED to a following
#: list/ordered marker ("> >-", ">-", ">1. ") -- CommonMark lets ">"
#: be followed immediately by the next block, no space required (RT15
#: A2 missed "> >- ```system"). The glue alternative carries a
#: lookahead for a list/ordered marker, so "-```system" (paragraph
#: text, not a list) still does not match: only ">"-elements may
#: glue. The trailing [ \t]+ after each run element is UNCHANGED: a
#: list/bullet marker still needs whitespace after it, so
#: "-```system" (paragraph text, not a list) still does not match.
#: F122 also closes a ReDoS in this arm (demonstrated wave-46): the
#: marker-run loop ("(?:[ \t]*ELEMENT)+", ELEMENT containing
#: ">(?:[ \t]*>)*") explored exponentially many ">"-partitionings on
#: blockquote-heavy lines with no fence ("> > ... x": 5.5s at n=24,
#: doubling per ~4 markers -- a CPU-amplification vector via
#: attacker-influenced text). Fix: each run iteration is atomic
#: ("(?>...)"), so the engine cannot re-partition ">"s across
#: iterations while backtracking -- an iteration matches greedily
#: once, in O(n), instead of exploring all 2^n partitionings. This
#: is match-equivalent: ">"s are fungible -- after a maximal cluster
#: the only valid continuations are another element or the fence,
#: and fewer iterations would leave a marker character (never a
#: backtick) at the fence position, so the atomic maximal parse
#: accepts exactly the same language, in linear time. Within one
#: iteration the whitespace runs keep their normal backtracking
#: (needed: "[ \t]*" before the checkbox shares spaces with the
#: mandatory trailing "[ \t]+", e.g. "- > ```system"); that is
#: polynomial per iteration, not exponential.
#: Deliberately NOT covered: fence-shaped text that CommonMark does
#: not recognize as an info string (4-space-indented code, mid-line
#: inline code, info strings with extra words like "```system python").
#: List-item CONTINUATION lines ("- item\n    ```system") are handled
#: by _list_continuation_fence_claim, not by this regex: the regex is
#: stateless per line and cannot know a list is open.
_FENCE_CLAIM_RE = re.compile(
    r"(?m)(?:^|[\r\n])"
    r"(?:[ \t]{0,3}(?:>[ \t]*)*"
    r"|(?>(?:[ \t]*(?:"
    r">(?:[ \t]*>)*[ \t]*(?=[-+*]|\d{1,9}[.)])"
    r"|>(?:[ \t]*>)*[ \t]*(?:[ \t]*\[[xX ]\])?[ \t]+"
    r"|[-+*](?:[ \t]*\[[xX ]\])?[ \t]+"
    r"|\d{1,9}[.)](?:[ \t]*\[[xX ]\])?[ \t]+"
    r"))+)"
    r"[ \t]*)"
    r"(`{3,}|~{3,})[ \t]*"
    r"(system|developer)(?=[ \t\r]*(?:$|\r|[:\]-]))",
    re.IGNORECASE)


#: F121: fence claim on a list-item continuation line.
#:
#: CommonMark renders "- item\n    ```system" as a fenced code block
#: INSIDE the list item (container content indent + up to 3 spaces of
#: relative indent), so the info string is a real claim -- but
#: _FENCE_CLAIM_RE is stateless per line: no marker on the fence's own
#: line, and 4+ spaces of indent, so it misses (RT14 B1/B2/B3/B7/C2).
#: This scanner is the stateful complement: it walks lines, tracks
#: open list containers (blockquote depth + content indent), and
#: reports a claim when a continuation line of an open list item opens
#: a fenced code block with a privilege info string.
#:
#: Mechanism, not enumeration: any list marker the regex knows
#: ("-"/"+"/"*", 1-9 digits + "."/")", optional task checkbox) opens a
#: container at any nesting depth, inside any blockquote depth; the
#: relative-indent rule (content indent + 0..3) is CommonMark's, not a
#: shape list. F122 (wave-46): the mechanism is the FULL marker run --
#: every marker on a marker line opens its own nested container ("-
#: - item" opens two; a ">" inside the run deepens the blockquote
#: depth for later markers), because CommonMark nests them and a
#: fence on an inner item's continuation line is a real claim (RT15
#: A5). A fence opener also pops containers it dedents below (a
#: fenced code block cannot be a lazy paragraph continuation), so an
#: inner container cannot shadow an outer container the fence belongs
#: to. Deliberate boundaries (pinned by tests):
#: * bare "    ```system" with no open list still does NOT match --
#:   indented code, literal backticks (wave-44 boundary pin);
#: * relative indent > 3 (6+ spaces in a "- " list) is indented code;
#: * a list marker indented 4+ spaces does NOT open a container --
#:   that is itself indented code, not a list (keeps the scanner from
#:   eating honest indented code);
#: * blank lines neither open nor close containers (a list item
#:   survives blank lines); a non-blank line dedented below a
#:   container's content indent closes it only after a blank line --
#:   otherwise it is a lazy paragraph continuation and the list item
#:   is still open (CommonMark). Residual: a dedented ATX heading with
#:   no blank line after a list keeps the container open (fail-closed
#:   over-quarantine on an exotic honest shape; documented, not a
#:   finding).
_FENCE_INFO_RE = re.compile(
    r"(`{3,}|~{3,})[ \t]*(system|developer)(?=[ \t]*(?:$|[:\]-]))",
    re.IGNORECASE)
_LIST_MARKER_RE = re.compile(r"([ \t]{0,3})([-+*]|\d{1,9}[.)])(?=[ \t]|$)")
_BQ_PREFIX_RE = re.compile(r"[ \t]{0,3}>")
_WS_RE = re.compile(r"[ \t]*")
_LINE_SPLIT_RE = re.compile(r"\r\n|\r|\n")


def _indent_cols(s):
    """Column width of leading whitespace (CommonMark tab rule: a tab
    advances to the next multiple of 4)."""
    col = 0
    for ch in s:
        if ch == "\t":
            col += 4 - (col % 4)
        elif ch == " ":
            col += 1
        else:
            break
    return col


def _advance_cols(col, ws):
    """Column after ``ws`` (spaces/tabs) starting at absolute column
    ``col``. F122: the CommonMark tab rule is position-relative -- a
    tab at column 2 advances to 4, not to 4 from zero -- so inner
    markers in a marker run ("- \\t- item") need the running column,
    which _indent_cols (from-zero) cannot give."""
    for ch in ws:
        if ch == "\t":
            col += 4 - (col % 4)
        else:
            col += 1
    return col


def _strip_blockquotes(line):
    """Strip blockquote prefixes; return (depth, base_col, rest).

    Each level is 0-3 spaces + ">" + one optional space/tab (a tab
    advances per the tab rule). "    > x" (4 spaces) is NOT a
    blockquote marker -- indented code -- so stripping stops there.
    """
    depth = 0
    col = 0
    rest = line
    while True:
        m = _BQ_PREFIX_RE.match(rest)
        if not m:
            break
        depth += 1
        col += _indent_cols(m.group(0)[:-1]) + 1  # spaces + ">"
        rest = rest[m.end():]
        if rest[:1] == " ":
            col += 1
            rest = rest[1:]
        elif rest[:1] == "\t":
            col += 4 - (col % 4)
            rest = rest[1:]
    return depth, col, rest


def _list_continuation_fence_claim(text):
    """Return SYSTEM/DEVELOPER for a fence claim on a list-item
    continuation line, else None. Runs on the normalized matching
    copy; only called when _FENCE_CLAIM_RE found nothing (fast path
    first). Same level-comparison semantics as the regex path -- the
    caller applies them."""
    containers = []  # stack of [bq_depth, content_indent]
    prev_blank = True  # start-of-text behaves like post-blank
    for line in _LINE_SPLIT_RE.split(text):
        bq_depth, base_col, inner = _strip_blockquotes(line)
        # A shallower blockquote depth ends containers opened deeper.
        containers = [c for c in containers if c[0] <= bq_depth]
        ws = _WS_RE.match(inner).group(0)
        indent = base_col + _indent_cols(ws)
        rest = inner[len(ws):]
        if not rest:
            prev_blank = True
            continue  # blank line: containers stay open
        m = _LIST_MARKER_RE.match(inner)
        if m:
            # F122: parse the FULL marker run on this line -- every
            # marker opens a nested container ("- - item" opens two).
            # Previously only the first marker was tracked, so a fence
            # on a continuation line of an inner item ("- - item\n
            #      ```system", relative indent 2 of the inner content
            # indent 4) was missed (RT15 A5). A ">" inside the run
            # deepens the blockquote depth for the markers that follow
            # it ("- > - item").
            seg = inner
            seg_col = base_col
            seg_bq = bq_depth
            while True:
                lm = _LIST_MARKER_RE.match(seg)
                if lm is None:
                    bm = _BQ_PREFIX_RE.match(seg)
                    if bm is None:
                        break
                    seg_bq += 1
                    seg_col = _advance_cols(seg_col,
                                            bm.group(0)[:-1]) + 1
                    seg = seg[bm.end():]
                    if seg[:1] == " ":
                        seg_col += 1
                        seg = seg[1:]
                    elif seg[:1] == "\t":
                        seg_col += 4 - (seg_col % 4)
                        seg = seg[1:]
                    continue
                marker = lm.group(2)
                marker_end = (_advance_cols(seg_col, lm.group(1))
                              + len(marker))
                after = seg[lm.end(2):]
                # CommonMark content indent: marker width + following
                # spaces (1-4); +1 when 5+ spaces follow or the item is
                # empty; a tab advances to the next multiple of 4.
                if after[:1] == "\t":
                    adv_cols = 4 - (marker_end % 4) or 4
                    adv_chars = 1
                else:
                    nsp = len(after) - len(after.lstrip(" "))
                    if 1 <= nsp <= 4:
                        adv_cols = adv_chars = nsp
                    elif nsp >= 5:
                        adv_cols = adv_chars = 1
                    else:
                        # nsp == 0: marker at end of line (empty item)
                        # -- CommonMark content indent is marker + 1.
                        adv_cols, adv_chars = 1, 0
                new_indent = marker_end + adv_cols
                containers = [c for c in containers
                              if c[1] < new_indent]
                containers.append([seg_bq, new_indent])
                seg_col = new_indent
                seg = after[adv_chars:]
        else:
            # Dedent below the innermost container closes it -- but
            # only after a blank line; otherwise this is a lazy
            # paragraph continuation and the list item stays open.
            if prev_blank:
                containers = [c for c in containers if c[1] <= indent]
            fm = _FENCE_INFO_RE.match(rest)
            if fm:
                # F122: a fenced code block cannot be a lazy paragraph
                # continuation (it interrupts the paragraph), so a
                # fence opener pops every container it dedents below
                # before the relative-indent test -- otherwise an
                # inner container would shadow an outer container the
                # fence legitimately belongs to. For a single
                # container this is a no-op (indent >= c[1] keeps it,
                # indent < c[1] pops it and the old test failed
                # anyway), so pre-F122 behavior is unchanged.
                while containers and containers[-1][1] > indent:
                    containers.pop()
                if containers and indent - containers[-1][1] <= 3:
                    return (SYSTEM if fm.group(2).lower() == "system"
                            else DEVELOPER)
        prev_blank = False
    return None


#: F87: delimiter confusables table. The F79 family fixed one
#: demonstrated colon shape per wave by enumerating it in the claim
#: regex (F79 U+FF1A -> F82 U+3002 -> F87 U+A789/U+2236). This table
#: replaces that enumeration with a mechanism: every non-ASCII
#: character a human reads as a claim delimiter folds to its ASCII
#: canonical (here always ":") on the MATCHING COPY inside
#: ``_claims_higher_privilege``, before the claim regexes run. The
#: regex delimiter class is therefore ASCII-only and closed; adding a
#: lookalike means adding a table row, not touching the regex and not
#: filing a new finding.
#:
#: Curation rule (enforced by
#: ``test_colon_confusable_table_covers_unicode_colon_family``):
#: every non-ASCII character whose Unicode name contains "COLON",
#: with category in {Lm, Sk, Sm, Po}, that is NOT already folded to
#: ":" by NFKC, must appear here or in the documented exclusion set
#: below. Exclusions, by rule (documented, NOT covered):
#: * semicolons (U+061B, U+1364, U+204F, U+2E35, U+A6F6, U+FE14,
#:   U+FE54, U+FF1B, ...): ";" is not a claim delimiter by design;
#: * multi-glyph operators (U+2254 COLON EQUALS, U+2255 EQUALS COLON,
#:   U+2A74 DOUBLE COLON EQUAL, U+2AF6 TRIPLE COLON OPERATOR, U+205D
#:   TRICOLON, U+12473/U+12474 cuneiform tricolon/quadcolon): distinct
#:   operators, not colon delimiters -- needs its own analysis;
#: * U+20A1 COLON SIGN (Sc): a currency glyph, not a colon;
#: * U+2360/U+236E (So APL symbols): technical symbols, not
#:   delimiters;
#: * U+E003A TAG COLON (Cf): already stripped by ``_strip_format_chars``;
#: * U+FE13, U+FE55, U+FF1A: NFKC folds them to ":" already, no row needed.
#: Documented non-name lookalikes (glyph reads as a colon but the
#: name does not say so): U+2236 RATIO (demonstrated, F87), U+0589
#: ARMENIAN FULL STOP, U+205A TWO DOT PUNCTUATION. Also folded: the
#: pre-existing non-ASCII delimiters U+3001 (ideographic comma),
#: U+3002 (ideographic full stop, F82), U+2013 (en dash) -- folding
#: them to ":" is behavior-identical to the old regex literals on
#: the matching copy.
_DELIMITER_CONFUSABLES = {
    # Colon family: Unicode name contains "COLON", not NFKC-folded.
    "\u02D0": ":",  # MODIFIER LETTER TRIANGULAR COLON
    "\u02D1": ":",  # MODIFIER LETTER HALF TRIANGULAR COLON
    "\u02F8": ":",  # MODIFIER LETTER RAISED COLON
    "\u0703": ":",  # SYRIAC SUPRALINEAR COLON
    "\u0704": ":",  # SYRIAC SUBLINEAR COLON
    "\u0705": ":",  # SYRIAC HORIZONTAL COLON
    "\u0706": ":",  # SYRIAC COLON SKEWED LEFT
    "\u0707": ":",  # SYRIAC COLON SKEWED RIGHT
    "\u0708": ":",  # SYRIAC SUPRALINEAR COLON SKEWED LEFT
    "\u0709": ":",  # SYRIAC SUBLINEAR COLON SKEWED RIGHT
    "\u1365": ":",  # ETHIOPIC COLON
    "\u1366": ":",  # ETHIOPIC PREFACE COLON
    "\u1804": ":",  # MONGOLIAN COLON
    "\u2982": ":",  # Z NOTATION TYPE COLON
    "\uA6F4": ":",  # BAMUM COLON
    "\uA789": ":",  # MODIFIER LETTER COLON (demonstrated, F87)
    "\U0001DA8A": ":",  # SIGNWRITING COLON
    "\U00010781": ":",  # MODIFIER LETTER SUPERSCRIPT TRIANGULAR COLON
    "\U00010782": ":",  # MODIFIER LETTER SUPERSCRIPT HALF TRIANGULAR COLON
    "\U00012471": ":",  # CUNEIFORM PUNCTUATION SIGN VERTICAL COLON
    "\U00012472": ":",  # CUNEIFORM PUNCTUATION SIGN DIAGONAL COLON
    # Demonstrated / documented non-name colon lookalikes.
    "\u2236": ":",  # RATIO (demonstrated, F87)
    "\u0589": ":",  # ARMENIAN FULL STOP (renders as a colon)
    "\u205A": ":",  # TWO DOT PUNCTUATION
    # Pre-existing non-ASCII claim delimiters (fold = old literals).
    "\u3001": ":",  # IDEOGRAPHIC COMMA (was a regex literal)
    "\u3002": ":",  # IDEOGRAPHIC FULL STOP (was a regex literal, F82)
    "\u2013": ":",  # EN DASH (was a regex literal)
}
#: str.translate table for the fold above.
_DELIMITER_FOLD_TABLE = {ord(k): v for k, v in _DELIMITER_CONFUSABLES.items()}


def _fold_delimiter_confusables(text):
    """Fold delimiter confusables to ":" on the matching copy (F87).

    Matching-copy-only: the stored/logged/quarantined item keeps its
    true bytes (F84 precedent). Only matters adjacent to a privilege
    keyword -- the claim regex still requires "system"/"developer"
    with a boundary -- so honest prose containing e.g. a RATIO sign
    in math ("a\\u2236b") is unaffected.
    """
    return text.translate(_DELIMITER_FOLD_TABLE)


def tag_privilege(content, level, source):
    """Tag content with its Instruction Hierarchy privilege level."""
    if level not in LEVEL_NAMES:
        raise ValueError(
            "level must be one of SYSTEM/DEVELOPER/USER/TOOL, got %r"
            % (level,))
    if not isinstance(source, str) or not source:
        raise TypeError("source must be a non-empty string")
    return {"privilege": level, "privilege_name": LEVEL_NAMES[level],
            "source": source, "content": content}


def _as_text(content):
    if isinstance(content, str):
        return content
    try:
        return json.dumps(content, sort_keys=True, default=str)
    except Exception:
        return str(content)


def _instruction_framing_reason(text):
    """Machine-readable reason tag for instruction-like framing, or None.

    F109 (A+C) trust-layer decision, made explicit here: the scanner's
    reason tag (e.g. "high_signal_material_benign_framing") is exposed
    for AUDIT/ROUTING consumers only. ``resolve_hierarchy`` keys its
    quarantine DECISION and its ``quarantine_reason`` string off the
    boolean only -- the framing tag never changes whether an item is
    quarantined, nor the reason string. Rationale: the adversary can
    add framing tokens for free, so letting the tag touch the
    quarantine outcome would reintroduce suppression through the back
    door (tag-trust creep, the F109 cry-wolf shape); and downstream
    consumers exact-match ``"tool_instruction_framing"``. Both scanner
    entry points still move together through the shared predicate.
    """
    if not isinstance(text, str) or not text:
        return None
    try:
        scan_tool_description("<hierarchy-check>", text)
    except MetadataPoisoningError as exc:
        return exc.reason
    except Exception:
        return None
    return None


def _has_instruction_framing(text):
    """Whether text carries instruction-like framing (shared scanner)."""
    return _instruction_framing_reason(text) is not None


def _strip_format_chars(text):
    """Remove Unicode format characters (category Cf) from ``text``.

    F84: NFKC folds compatibility characters (fullwidth letters,
    circled letters) but NEVER strips default-ignorable format
    characters -- ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, WORD JOINER
    U+2060 survive normalization, so "SY\\u200bSTEM:" never shows the
    claim regex a contiguous keyword. Stripping category Cf closes the
    whole invisible-character class at once instead of enumerating
    code points, the same strategy the F82 NFKC fix used for the
    letter-homoglyph class.

    Safety (why this is confined to the MATCHING COPY only):
    * Invisible format characters carry no semantic content; removing
      them cannot change what honest text says. No ASCII character is
      category Cf, so honest ASCII traffic is byte-identical.
    * This function is applied only to the copy of the text used for
      claim matching in ``_claims_higher_privilege``. The stored item
      (``resolve_hierarchy`` copies the original dict, ``content``
      included) and everything logged/audited keeps the TRUE bytes --
      the Cf characters remain visible to forensics and to any
      downstream consumer of the item.
    What it does NOT do:
    * It does not alter stored, logged, or rendered text.
    * It does not strip variation selectors (category Mn, F86 -- see
      ``_strip_variation_selectors``): the "whole invisible-character
      class" claim this docstring once made was broken by F86, and is
      corrected here to Cf-only.
    * It does not fold scripts: mixed-script confusables (Cyrillic
      U+0455 etc.) are untouched by design -- that class needs a
      confusables table with its own false-positive analysis and stays
      the documented residual (``redteam.struq.r23_cyrillic_confusable_residual``).
    """
    return "".join(ch for ch in text
                   if unicodedata.category(ch) != "Cf")


#: F86: variation-selector ranges (the core subset of the F92
#: property table below). Variation selectors (U+FE00-U+FE0F and the
#: supplementary U+E0100-U+E01EF) are category Mn (Mark, nonspacing),
#: NOT Cf -- they are Default_Ignorable_Code_Points that survive NFKC
#: and the F84 Cf-strip, so "S\\uFE00YSTEM:" never showed the claim
#: regex a contiguous keyword. They select glyph variants of the
#: preceding character and carry no semantic content, so stripping
#: them from the matching copy is as safe as the Cf strip.
_VARIATION_SELECTOR_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))

#: F92: Mn default-ignorable property table. The F86 closure stripped
#: exactly the two variation-selector ranges above; the wave-25
#: red-team ratchet (F92) showed named variation selectors OUTSIDE
#: those ranges -- Mongolian free variation selectors U+180B-U+180D
#: and CGJ U+034F -- evade identically (all Mn, invisible,
#: Default_Ignorable_Code_Points, surviving NFKC and the Cf-strip).
#: This table implements F86's stated fix direction ("strip Mn
#: default-ignorable ranges") instead of the 2-range subset: it is the
#: Mn subset of the Unicode Default_Ignorable_Code_Point property
#: (pinned: Unicode 15.0, the runtime
#: ``unicodedata.unidata_version``), i.e. every Mn code point that is
#: default-ignorable, minus the documented meaningful-orthography
#: exclusions below. The mechanism is range membership over this
#: property table -- a new default-ignorable Mn is a table row (or a
#: documented exclusion), not a regex change and not a new finding.
#:
#: Curation rule (enforced by
#: ``test_f92_mn_default_ignorable_table_complete``): the strip set
#: plus the exclusion set must cover exactly the Mn
#: Default_Ignorable_Code_Points of the pinned Unicode version.
#: Exclusions, by rule (documented, NOT stripped -- meaningful
#: orthography, they need the diacritic-class analysis the F86
#: residual already documents):
#: * U+17B4/U+17B5 KHMER VOWEL INHERENT AQ/AA (F92 noted, not a
#:   demonstrated shape);
#: * combining diacritics U+0300-U+036F (the F86 documented residual,
#:   ``redteam.struq.r24_combining_mark_claim_residual``) -- not
#:   default-ignorables, excluded by construction.
#: NOT a blanket Mn strip: the table is the property, nothing more.
_MN_DEFAULT_IGNORABLE_RANGES = _VARIATION_SELECTOR_RANGES + (
    (0x034F, 0x034F),   # COMBINING GRAPHEME JOINER (F92 demonstrated)
    (0x180B, 0x180D),   # MONGOLIAN FREE VARIATION SELECTOR ONE..THREE
                        # (F92 demonstrated)
    (0x180F, 0x180F),   # MONGOLIAN FREE VARIATION SELECTOR FOUR
                        # (same class; not a demonstrated shape)
)


def _strip_variation_selectors(text):
    """Remove Mn default-ignorable code points (F86, extended F92).

    F86 stripped exactly the two variation-selector ranges; F92
    extends this to the Mn default-ignorable property table
    (``_MN_DEFAULT_IGNORABLE_RANGES``) -- the F86 ranges plus the
    named variation selectors the F86 closure missed (Mongolian FVS
    U+180B-U+180D, U+180F; CGJ U+034F). Same safety contract as
    ``_strip_format_chars`` (matching-copy-only: the stored/logged/
    quarantined item keeps its true bytes) -- default-ignorables
    carry no semantic content by definition, and no ASCII character
    is default-ignorable, so honest ASCII traffic is byte-identical.
    Deliberately NOT a blanket Mn strip: combining diacritics
    (U+0300-U+036F) and the documented Khmer exclusions stay --
    they carry honest semantics and remain the documented residual.
    """
    return "".join(
        ch for ch in text
        if not any(lo <= ord(ch) <= hi
                   for lo, hi in _MN_DEFAULT_IGNORABLE_RANGES))


#: F93: emoji-modifier range (category Sk). Emoji modifiers
#: U+1F3FB-U+1F3FF survive NFKC and every strip stage, so
#: "S\\U0001F3FDSYSTEM:" never showed the claim regex a contiguous
#: keyword. Deliberately NOT a blanket Sk strip (the F93 finding
#: warns against it): Sk also holds ASCII-visible modifier symbols
#: with honest semantics -- U+005E CIRCUMFLEX ACCENT, U+0060 GRAVE
#: ACCENT (markdown/code), U+00A8/U+00AF/U+00B4/U+00B8, and U+02F8
#: MODIFIER LETTER RAISED COLON which is an F87 delimiter-table row.
#: The F93 demonstrated Sk class is exactly this range; the curation
#: rule (enforced by ``test_f93_emoji_modifier_range_complete``) is
#: that every Sk code point named "EMOJI MODIFIER*" is in the range.
_EMOJI_MODIFIER_RANGE = (0x1F3FB, 0x1F3FF)


def _strip_modifier_marks(text):
    """Remove emoji modifiers and combining enclosing marks (F93).

    F93 demonstrated two fresh keyword-splitting classes the F86/F87
    closures do not cover: emoji modifiers (Sk U+1F3FB-U+1F3FF) and
    combining enclosing marks (Me, e.g. U+20DD COMBINING ENCLOSING
    CIRCLE). The mechanism: strip category Me whole-class (all 13 are
    enclosing marks that draw around the preceding glyph -- closing
    the class at once instead of enumerating U+20DD) plus the
    emoji-modifier range above.
    Matching-copy-only, same safety contract as the other strips:
    the stored/logged/quarantined item keeps its true bytes. False-
    positive analysis: removing an enclosing/modifier mark cannot
    join or split ASCII text -- the claim regex still requires the
    literal ASCII keyword plus a delimiter boundary, so honest prose
    (emoji in normal text, enclosing marks on non-keyword words)
    sees zero verdict change; pinned by
    ``test_f93_honest_prose_not_quarantined``. NOT a blanket Sk/Me
    strip globally: this function runs only on the claim-matching
    copy inside ``_claims_higher_privilege``.
    """
    lo, hi = _EMOJI_MODIFIER_RANGE
    return "".join(
        ch for ch in text
        if unicodedata.category(ch) != "Me"
        and not (lo <= ord(ch) <= hi))


#: F95: Lo default-ignorable property table. The F92 property table is
#: scoped to category Mn by its fix direction; the remaining
#: Default_Ignorable_Code_Points in category Lo -- U+115F HANGUL
#: CHOSEONG FILLER, U+1160 HANGUL JUNGSEONG FILLER, U+3164 HANGUL
#: FILLER, U+FFA0 HALFWIDTH HANGUL FILLER -- are invisible-ish
#: fillers that survive every strip stage, so "S\\u3164YSTEM:" never
#: showed the claim regex a contiguous keyword. (Mechanical note:
#: NFKC folds U+3164 and U+FFA0 to U+1160 before this strip runs, so
#: the strip is load-bearing for U+115F/U+1160; the table still
#: documents the full property, not the fold.)
#:
#: Curation rule (enforced by
#: ``test_f95_lo_default_ignorable_table_complete``): the strip set
#: plus the exclusion set must cover exactly the Lo
#: Default_Ignorable_Code_Points of the pinned Unicode version
#: (15.0, ``unicodedata.unidata_version``). The exclusion set is
#: EMPTY by analysis, not by omission: these fillers are meaningful
#: in Hangul jamo sequences, but jamo sequences are never the ASCII
#: keywords "system"/"developer", and this strip runs only on the
#: claim-matching copy -- honest Korean prose (pinned by
#: ``test_f95_honest_korean_prose_clean``) sees zero verdict change.
#: NOT a blanket Lo strip: the table is the property, nothing more.
_LO_DEFAULT_IGNORABLE_RANGES = (
    (0x115F, 0x1160),   # HANGUL CHOSEONG/JUNGSEONG FILLER (F95 demonstrated)
    (0x3164, 0x3164),   # HANGUL FILLER (F95 demonstrated; NFKC->U+1160)
    (0xFFA0, 0xFFA0),   # HALFWIDTH HANGUL FILLER (F95 demonstrated; NFKC->U+1160)
)


def _strip_lo_fillers(text):
    """Remove Lo default-ignorable fillers (F95).

    Same safety contract as ``_strip_format_chars``
    (matching-copy-only: the stored/logged/quarantined item keeps its
    true bytes) -- default-ignorables carry no semantic content by
    definition, and no ASCII character is default-ignorable, so
    honest ASCII traffic is byte-identical. The Korean-orthography
    false-positive analysis is in the table comment above: the strip
    only matters adjacent to the ASCII privilege keywords, which
    honest Hangul text never contains.
    """
    return "".join(
        ch for ch in text
        if not any(lo <= ord(ch) <= hi
                   for lo, hi in _LO_DEFAULT_IGNORABLE_RANGES))


def _strip_spacing_marks(text):
    """Remove spacing combining marks (category Mc) -- F96.

    F96 demonstrated U+0903 DEVANAGARI SIGN VISARGA splitting the
    keyword on the matching copy. Mc marks are visible and meaningful
    (Indic orthography) -- outside the F92 Mn class and the F93
    Sk-range/Me class -- so per the F93 precedent (F79/F82),
    visibility to a human renderer does not close the agent-facing
    text contract. The mechanism strips Mc whole-class on the
    matching copy only (same safety contract as the other strips):
    honest Indic prose never contains the ASCII keywords
    "system"/"developer" with Mc marks inside them, so verdicts on
    honest text are unchanged (pinned by
    ``test_f96_honest_indic_prose_clean``). NOT a blanket Mc strip
    globally: this function runs only on the claim-matching copy
    inside ``_claims_higher_privilege``.
    """
    return "".join(ch for ch in text
                   if unicodedata.category(ch) != "Mc")


#: F97: blank-symbol table (category So). U+2800 BRAILLE PATTERN
#: BLANK renders blank, survives NFKC, and sits in category So --
#: outside every landed strip class (Cf/Mn-DIP/Me/Sk-range/Mc/Lo).
#: Stripping it from the matching copy lets the claim regex see the
#: contiguous keyword again.
#:
#: Curation rule (enforced by
#: ``test_f97_blank_symbol_table_complete``): every So code point
#: whose Unicode name contains "BLANK", that is NOT already folded
#: by NFKC, must appear here or in the documented exclusion set.
#: Exclusions, by rule (documented, NOT stripped):
#: * U+2422 BLANK SYMBOL: the visible glyph FOR blank (renders as
#:   an honest visible symbol), not blank-rendering -- an agent
#:   reading it sees the glyph, so it is not a keyword-split
#:   confusable and needs no strip.
#: Deliberately NOT a blanket So strip: dotted braille (U+2801+)
#: is meaningful braille text and stays (pinned unquarantined by
#: ``test_f97_dotted_braille_not_stripped``).
_BLANK_SYMBOLS = frozenset({
    "\u2800",  # BRAILLE PATTERN BLANK (demonstrated, F97)
})


def _strip_blank_symbols(text):
    """Remove blank-rendering symbols (F97).

    Matching-copy-only, same safety contract as the other strips:
    the stored/logged/quarantined item keeps its true bytes.
    False-positive analysis: removing a blank cannot join or split
    ASCII text -- the claim regex still requires the literal ASCII
    keyword plus a delimiter boundary, so honest prose (braille
    text, honest blank-adjacent words) sees zero verdict change;
    pinned by ``test_f97_honest_prose_clean``.
    """
    return "".join(ch for ch in text if ch not in _BLANK_SYMBOLS)


def _strip_modifier_letters(text):
    """Remove modifier letters (category Lm) -- F98.

    F98 demonstrated U+02B0 MODIFIER LETTER SMALL H splitting the
    keyword: small, easily overlooked inside a word, surviving NFKC
    (the superscript modifier letters NFKC-fold, but U+02BC/U+02BB
    and friends do not), outside every landed strip class. The
    mechanism strips Lm whole-class on the matching copy only (same
    safety contract as the other strips): honest phonetic
    transcription never contains the ASCII keywords
    "system"/"developer" with modifier letters inside them, so
    verdicts on honest text are unchanged (pinned by
    ``test_f98_honest_phonetic_prose_clean``). NOT a blanket Lm
    strip globally: this function runs only on the claim-matching
    copy inside ``_claims_higher_privilege``.
    The F87 delimiter-table rows that are Lm (U+02D0, U+02D1, U+A789,
    U+10781, U+10782) are folded to ":" BEFORE this strip runs
    (fold-first ordering in ``_claims_higher_privilege``), so the
    strip cannot eat a delimiter the F87 table claims -- pinned by
    ``test_f98_delimiter_rows_still_fold``.
    """
    return "".join(ch for ch in text
                   if unicodedata.category(ch) != "Lm")


#: F107: spacing modifier symbol table (category Sk, Spacing Modifier
#: Letters block U+02B0-U+02FF). The wave-27 sweep demonstrated U+02D6
#: MODIFIER LETTER PLUS SIGN, U+02E5 EXTRA-HIGH TONE BAR, and U+02C2
#: LEFT ARROWHEAD splitting the privilege keyword on the matching
#: copy: they survive NFKC and sit outside the F87 delimiter table
#: and the F93 emoji-modifier range. (Premise correction: the finding
#: lists U+02B9/U+02BA as Sk, but on the pinned Unicode 15.0 runtime
#: both are category Lm -- already stripped by the F98 whole-class
#: Lm strip, so the prime shapes quarantined without this table.)
#:
#: Curation rule (enforced by
#: ``test_f107_sk_modifier_block_table_complete``): every Sk code
#: point in U+02B0-U+02FF that survives NFKC and is not an F87
#: delimiter-table row must appear here or in the documented
#: exclusion set below. Exclusions, by rule (documented, NOT
#: stripped):
#: * F87 delimiter rows (U+02D0, U+02D1, U+02F8): folded to ":"
#:   BEFORE this strip runs (fold-first ordering, pinned by
#:   ``test_f107_f87_sk_rows_still_fold``) -- the strip must never
#:   eat a delimiter the F87 table claims;
#: * the NFKC-folded spacing clones (U+02C6-U+02CF, U+02D8-U+02DD):
#:   compatibility decompositions (to ASCII diacritics or space +
#:   combining mark) remove them before the strip runs -- the fold
#:   handles them, not this table.
#: The exclusion set is otherwise EMPTY: the 36 survivors are the
#: demonstrated confusable family (small phonetic/modifier symbols
#: that read as word-internal marks).
#:
#: False-positive analysis (the F93 no-blanket-Sk warning, answered):
#: Sk is NOT stripped whole-class. ASCII-visible modifier symbols
#: keep their bytes on the matching copy: U+005E CIRCUMFLEX ACCENT
#: and U+0060 GRAVE ACCENT survive NFKC, and U+00A8/U+00AF/U+00B4/
#: U+00B8 (plus fullwidth clones U+FF3E/U+FF40) NFKC-fold to ASCII
#: or space + combining mark. They are honest code/markdown/prose
#: punctuation -- stripping e.g. U+0060 would false-positive on
#: honest "`SYSTEM:`" inline-code prose -- and they render visibly,
#: so a split keyword stays visible to a human reviewer. The
#: meaningful Sk outside the modifier block also keeps its bytes:
#: katakana voiced marks U+309B/U+309C (NFKC-folded anyway), Greek
#: spacing diacritics U+1FBF-U+1FFE (all NFKC-folded), U+0375 GREEK
#: LOWER NUMERAL SIGN, U+0888 ARABIC RAISED ROUND DOT, U+A700-U+A721
#: Chinese tone modifiers, U+A78A, U+AB5B/U+AB6A/U+AB6B, and
#: U+FBB2-U+FBC2 Arabic Quranic annotation symbols -- visible,
#: script-meaningful text the F93 discipline says not to touch,
#: undemonstrated as claim-splitting shapes. They are the
#: documented residual, not an oversight. Inside the modifier
#: block, the strip is safe by the F98 contract: honest
#: phonetic/IPA prose never contains the ASCII privilege keywords
#: with modifier symbols inside them, so the matching-copy strip
#: changes no honest verdict (pinned by
#: ``test_f107_honest_prose_clean``). Matching-copy-only, same
#: safety contract as the other strips: the stored/logged/
#: quarantined item keeps its true bytes.
_SK_MODIFIER_SYMBOL_RANGES = (
    (0x02C2, 0x02C5),   # arrowheads (U+02C2 demonstrated)
    (0x02D2, 0x02D7),   # half rings, tacks, plus/minus (U+02D6 demonstrated)
    (0x02DE, 0x02DF),   # rhotic hook, cross accent
    (0x02E5, 0x02EB),   # tone bars, yin/yang departing (U+02E5 demonstrated)
    (0x02ED, 0x02ED),   # unspirated
    (0x02EF, 0x02F7),   # low arrows, low ring, middle accents, low tilde
    (0x02F9, 0x02FF),   # begin/end tones, shelves, low left arrow
)


def _strip_sk_modifier_symbols(text):
    """Remove Sk spacing modifier symbols (F107).

    Strips the 36 NFKC-surviving Sk code points of the Spacing
    Modifier Letters block (``_SK_MODIFIER_SYMBOL_RANGES``) from the
    claim-matching copy only. Deliberately NOT a blanket Sk strip:
    ASCII-visible modifiers (^, `, diaeresis, ...) and meaningful
    script Sk outside the block keep their bytes (see the table
    comment for the false-positive analysis). The F87 delimiter
    fold runs FIRST, so its Sk rows (U+02D0, U+02D1, U+02F8, U+A789)
    already folded to ":" before this strip runs -- pinned by
    ``test_f107_f87_sk_rows_still_fold``.
    """
    return "".join(
        ch for ch in text
        if not any(lo <= ord(ch) <= hi
                   for lo, hi in _SK_MODIFIER_SYMBOL_RANGES))


#: F108: invisible control characters (category Cc minus
#: whitespace). DEL U+007F, the C1 controls U+0080-U+009F, and the
#: non-whitespace C0 controls are invisible in virtually every
#: renderer -- "SY\\u007fSTEM:" reads as "SYSTEM:" -- survive NFKC
#: and every landed strip stage, so the claim regex never sees the
#: contiguous keyword. Same invisible-split contract as F84's Cf
#: strip, one category over.
#:
#: Whitespace Cc is EXCLUDED (pinned, not stripped): \\t \\n \\v \\f
#: \\r, the \\x1c-\\x1f information separators, and NEL U+0085 are
#: Python-``\\s`` and serve as claim-regex boundaries -- stripping
#: them could erase a boundary the regex needs (a false negative),
#: and they render visibly (line breaks/tabs), so they are not
#: keyword-split confusables. The exclusion set is exactly
#: ``{Cc}`` intersect ``str.isspace()`` on the pinned runtime
#: (asserted by ``test_f103_whitespace_exclusion_exact``).
_INVISIBLE_CONTROL_EXCLUSIONS = frozenset(
    "\t\n\v\f\r\x1c\x1d\x1e\x1f\x85")


def _strip_invisible_controls(text):
    """Remove invisible control characters (F108).

    Matching-copy-only, same safety contract as the other strips.
    False-positive analysis: non-whitespace Cc carries no linguistic
    content; honest prose never contains it meaningfully, and the
    whitespace exclusions keep every claim-regex boundary intact
    (pinned by ``test_f103_whitespace_boundaries_intact``).
    """
    return "".join(
        ch for ch in text
        if not (unicodedata.category(ch) == "Cc"
                and ch not in _INVISIBLE_CONTROL_EXCLUSIONS))


def _fence_claims_level(text):
    """Return SYSTEM/DEVELOPER if a fenced code block's info string
    claims that privilege (F119), else None. Runs on the normalized
    matching copy; the caller applies the same level comparison as the
    keyword claim regexes (a SYSTEM-tagged item containing "```system"
    claims nothing above itself). The stateless regex runs first (fast
    path); only if it finds nothing, the F121 container-aware scanner
    checks list-item continuation lines ("- item\\n    ```system")."""
    m = _FENCE_CLAIM_RE.search(text)
    if m:
        return SYSTEM if m.group(2).lower() == "system" else DEVELOPER
    cont = _list_continuation_fence_claim(text)
    if cont is not None:
        return cont
    return None


def _claims_higher_privilege(level, text):
    """Return the claimed level if text claims above ``level``.

    The text is NFKC-normalized before matching (F82): fullwidth
    letters (e.g. U+FF33 U+FF39 U+FF33 U+FF34 U+FF25 U+FF2D) fold to
    ASCII, closing the whole letter-homoglyph class at once instead
    of enumerating code points. ASCII traffic is byte-identical under
    NFKC, so honest traffic sees zero behavior change.

    Format characters (category Cf) are stripped after NFKC (F84):
    ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, WORD JOINER U+2060 and
    friends are invisible and default-ignorable, so removing them from
    the matching copy lets the claim regex see the contiguous keyword
    again. The stripping applies to the matching copy only -- the
    original text (stored, logged, quarantined item content) is
    untouched.

    Variation selectors (F86, extended F92) are stripped next: the
    Mn default-ignorable property table (``_MN_DEFAULT_IGNORABLE_RANGES``)
    -- the two F86 variation-selector ranges plus the named variation
    selectors F86 missed (Mongolian FVS U+180B-U+180D, U+180F; CGJ
    U+034F). Combining diacritics (also Mn) are deliberately NOT
    stripped -- they carry honest semantics (documented residual).

    Modifier/enclosing marks (F93) are stripped next: emoji modifiers
    (Sk U+1F3FB-U+1F3FF) and combining enclosing marks (Me, e.g.
    U+20DD) -- a new class the F86 closure did not cover. Me is
    stripped whole-class, Sk only the emoji-modifier range (blanket
    Sk would eat honest ASCII-visible modifiers and an F87 table
    row, U+02F8).

    Lo default-ignorable fillers (F95) are stripped next: the Lo
    subset of the Default_Ignorable_Code_Point property
    (``_LO_DEFAULT_IGNORABLE_RANGES`` -- U+115F/U+1160/U+3164/U+FFA0).

    Spacing combining marks (F96) are stripped next: category Mc
    whole-class on the matching copy (visible Indic marks, but
    visibility does not close the agent-facing contract per the F93
    precedent).

    Blank-rendering symbols (F97) are stripped next: the So
    blank-symbol table (``_BLANK_SYMBOLS`` -- U+2800 BRAILLE PATTERN
    BLANK; dotted braille stays).

    Modifier letters (F98) are stripped next: category Lm
    whole-class on the matching copy. The F87 delimiter fold runs
    FIRST precisely so its Lm rows (U+02D0, U+02D1, U+A789,
    U+10781, U+10782) fold to ":" before this strip can eat them.

    Spacing modifier symbols (F107) are stripped next: the
    NFKC-surviving Sk code points of the Spacing Modifier Letters
    block (``_SK_MODIFIER_SYMBOL_RANGES`` -- U+02D6/U+02E5/U+02C2
    demonstrated). NOT a blanket Sk strip: ASCII-visible modifiers
    (^, `, ...) and meaningful script Sk keep their bytes (the F93
    warning, answered in the table comment). The F87 fold runs FIRST
    so its Sk rows (U+02D0, U+02D1, U+02F8, U+A789) already folded
    to ":" before this strip runs.

    Invisible control characters (F108) are stripped last: category
    Cc minus whitespace (DEL, C1/C0 non-whitespace controls).

    Delimiter confusables (F87) are folded to ":" FIRST, before any
    strip: the claim regex's delimiter class is ASCII-only by
    construction, and the confusables table
    (``_DELIMITER_CONFUSABLES``) is the extension point for the next
    lookalike -- no regex change, no new finding. Fold-first (moved
    ahead of the strips in wave-27) is behavior-identical for all
    pre-existing shapes -- no strip stage touches a delimiter-table
    code point -- and it protects the table's Lm rows from the F98
    Lm strip.
    """
    if not isinstance(text, str) or not text:
        return None
    text = unicodedata.normalize("NFKC", text)
    text = _fold_delimiter_confusables(text)
    text = _strip_format_chars(text)
    text = _strip_variation_selectors(text)
    text = _strip_modifier_marks(text)
    text = _strip_lo_fillers(text)
    text = _strip_spacing_marks(text)
    text = _strip_blank_symbols(text)
    text = _strip_modifier_letters(text)
    text = _strip_sk_modifier_symbols(text)
    text = _strip_invisible_controls(text)
    fence_claimed = _fence_claims_level(text)
    if level < SYSTEM and (_SYSTEM_CLAIM_RE.search(text)
                           or fence_claimed == SYSTEM):
        return SYSTEM
    if level < DEVELOPER and (_DEVELOPER_CLAIM_RE.search(text)
                              or fence_claimed == DEVELOPER):
        return DEVELOPER
    return None


def resolve_hierarchy(items):
    """Apply the Instruction Hierarchy to tagged content items.

    ``items``: iterable of ``tag_privilege`` dicts. Returns
    ``(kept, events)``:

    * ``kept`` -- the input items with ``effective_privilege`` (never
      promoted above the tagged level) and ``quarantined`` flags; a
      quarantined item also carries ``quarantine_reason``. Downstream
      builders must render quarantined items through the data channel.
    * ``events`` -- audit records
      ``{"source", "actual", "claimed", "reason"}`` for every
      quarantine.

    Unknown privilege levels are coerced to TOOL (fail-safe: unknown
    content is never treated as privileged).
    """
    kept = []
    events = []
    for item in items or []:
        if not isinstance(item, dict):
            raise AdapterError(
                "hierarchy items must be dicts, got %r"
                % type(item).__name__)
        level = item.get("privilege")
        if level not in LEVEL_NAMES:
            level = TOOL  # fail-safe: unknown -> lowest privilege
        source = item.get("source", "<unknown>")
        text = _as_text(item.get("content", ""))
        claimed = _claims_higher_privilege(level, text)
        quarantined = False
        reason = None
        if claimed is not None:
            quarantined = True
            reason = "privilege_claim:" + LEVEL_NAMES[claimed]
        elif level == TOOL and _has_instruction_framing(text):
            # TOOL content is never instruction-channel; imperative
            # framing in it is an escalation attempt, not an order.
            # F109: the quarantine REASON string stays coarse
            # ("tool_instruction_framing") even when the scanner
            # carries a framing tag -- see _instruction_framing_reason.
            # The tag is triage metadata and must never gate
            # quarantine; quarantined items still carry the scanner's
            # tag on their audit event for routing.
            quarantined = True
            reason = "tool_instruction_framing"
        out = dict(item)
        out["privilege"] = level
        out["privilege_name"] = LEVEL_NAMES[level]
        out["effective_privilege"] = level
        out["quarantined"] = quarantined
        if quarantined:
            out["quarantine_reason"] = reason
            events.append({
                "source": source,
                "actual": LEVEL_NAMES[level],
                "claimed": (LEVEL_NAMES[claimed]
                            if claimed is not None else None),
                "reason": reason,
            })
        kept.append(out)
    return kept, events
