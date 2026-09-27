"""Output-boundary injection-propagation screening (wave-151 lane 1; Row 19).

Worm shape (OpenAI GPT-Red, disclosed Sept 23-27 2026; SwarmTraces report,
2026-09-25, https://swarmtraces.org): an instruction payload causes the
agent to reproduce the instruction into a NEW output channel (a file, a
comment, a chat message), which then infects the next agent that reads it.
The SwarmTraces redacted corpus (80,000+ reassembled payloads) shows the
shape in the wild: the comment "# Remove only files we introduce; original
repo has neither." reproduced byte-identically across payloads (R0045500,
R0076188); the commit instruction "restore original no-card" reproduced
across 6 payloads (R0045113 et al.); the warning "DO NOT, EVER, MAKE THIS
DATASET PUBLIC" preserved while malicious config was added around it.

This module is the OUTPUT-CONTINENCE seam: when agent output is destined
to cross a trust boundary (written to a file, posted to a chat, embedded
in code), scan for instruction-reproduction patterns -- the output
contains an imperative instruction that was NOT in the user's original
request but WAS present in the agent's input context
(injected-instruction propagation). On match the tracker returns
``propagation_suspect`` and the executor renders it as the LOUD
``injection_propagation_suspect`` audit event carrying the reproduced
span(s).

TRIAGE TIER ONLY -- like the wave-137 ``read_then_egress_novel`` flag:
never blocking, never a halt, never an approval. Execution proceeds.

How it works (deterministic, $0, stdlib-only):
- ``extract_instruction_spans(text)``: split text into clauses
  (sentence ends, semicolons, newlines); strip comment/bullet/quote
  prefixes; a clause is "instruction-shaped" when its first content
  word (after an optional "please") is an imperative verb from the
  curated pilot set, or is an auxiliary-led prohibition ("do not
  ...", "don't ...", "never ..."). Returns (raw_span, normalized_span)
  pairs; normalization is lowercase + whitespace-collapse + edge
  punctuation strip.
- ``PropagationTracker``: per-run, per-agent, in-process (the operator
  trust domain, like SentinelVault). ``observe_input(agent_id,
  source_id, text)`` records the normalized instruction spans of each
  input-context segment (tool results, retrieved docs, emails, commit
  summaries -- whatever the deployment feeds it); wave-152 adds the
  automatic path: a successful governed ``read_file`` returning real
  sandbox bytes observes itself into the installed tracker with the
  auto source id ``read:auto:<sandbox-relative-path>``, mirroring the
  wave-141 rare-token discipline. The auto observation is
  best-effort (never raises, never breaks the read, no audit event)
  and idempotent with the explicit path (the tracker keys by
  (agent_id, source_id), so an explicit ``note_propagation_input``
  with the same id replaces the auto observation). Reads that never
  cross the governed tool boundary (direct filesystem access) stay
  invisible by construction -- the documented coverage ceiling.
  ``check_output`` extracts the output's instruction spans and flags
  any span that is present in the observed input spans AND absent
  from the user's original request spans; wave-152 adds substring
  matching (an observed span embedded as a word-boundary-delimited
  substring of a longer, non-instruction-shaped output clause --
  the worm-in-README shape -- also flags). The channel label
  ("file"/"chat"/"code"/...) is recorded for triage, never
  verdict-relevant.
- The executor renders a suspect as LOUD ``injection_propagation_suspect``
  (flag "injection_propagation"); with no tracker installed the check is
  a silent allow (zero behavior change).

Honest ceilings (documented, measured in
evals/injection_propagation_probes.py):
- Matching is EXACT on normalized spans, plus word-boundary-delimited
  SUBSTRING matching (wave-152): an observed instruction span embedded
  inside a longer output clause flags even when the clause is not
  itself instruction-shaped (the worm-in-README shape). Substring
  matching applies only to spans >= ``MIN_SUBSTRING_CHARS`` (10) to
  hold the word-boundary FP rate down; mid-word matches never fire.
  A paraphrased reproduction ("Only delete the files we added" for
  "Remove only files we introduce") is still invisible by design --
  fuzzy/semantic matching is out of scope for this pilot (pinned
  EXPECTED, measured miss rate 6/6). This is the same class boundary
  as the row-7/row-11 paraphrase ceilings: token overlap is not
  semantics, and embeddings are outside the $0 deterministic envelope.
- The imperative-verb set is a curated English pilot list. Non-English
  injections, and English imperatives outside the list ("bring",
  "tidy"), are invisible. Extending the list is calibration, not a
  fix: a wider list raises the FP rate on benign instructional prose.
- Input observation is EXPLICIT (``observe_input`` /
  ``note_propagation_input``) PLUS AUTOMATIC for governed reads
  (wave-152: a successful governed ``read_file`` returning real
  sandbox bytes observes itself with id ``read:auto:<path>``,
  mirroring the wave-141 rare-token discipline -- the follow-up is
  now landed). Reads that never cross the governed tool boundary
  (direct filesystem access, out-of-band) remain invisible by design
  -- pinned EXPECTED in the battery (p11), the documented coverage
  ceiling.
- The reproduced span IS logged in the audit event (truncated to 400
  chars). Unlike rare_token.py (which never logs token strings), the
  span here is the evidence the operator triages on, and it comes from
  already-observed input context -- but an injected instruction can
  itself carry a secret, so the event is triage data, not a clean
  bill.
- The tracker is per-run and in-process. Cross-run worm persistence
  (yesterday's payload file re-read tomorrow) needs a durable
  observed-input store -- named follow-up.
"""

import re

__all__ = [
    "extract_instruction_spans",
    "normalize_span",
    "PropagationTracker",
    "IMPERATIVE_VERBS",
    "MAX_SPAN_CHARS",
    "MIN_SUBSTRING_CHARS",
]

# Curated English imperative pilot set: verbs characteristic of the
# worm shape (directives that reproduce into files/comments/chats).
# Deliberately NOT exhaustive -- see the module docstring.
IMPERATIVE_VERBS = frozenset("""
remove restore clean delete erase wipe upload download send post share
forward commit push publish create write run execute copy move ignore
bypass disable enable stop start scan map decode encode follow submit
request fetch install build open close archive backup overwrite replace
revert reset configure exfiltrate leak hide embed inject
""".split())

# Auxiliary-led prohibitions/injunctions ("do not ...", "never ...").
_AUX_CUES = frozenset({"don't", "dont", "never", "always", "must"})
_POLITE_PREFIX = "please"

_CLAUSE_SPLIT_RE = re.compile(r"[.!?;\n]+")
_COMMENT_PREFIX_RE = re.compile(
    r"^\s*(?:#{1,3}|//|--|>|[*+\-]\s|\d+[.)]\s*|\"\"\"|''')\s*")
_WS_RE = re.compile(r"\s+")

MAX_SPAN_CHARS = 400

# Wave-152: observed spans shorter than this are exempt from SUBSTRING
# matching (below ~10 chars the word-boundary FP rate dominates: short
# verb phrases like "share" or "run" appear in benign prose). Exact
# whole-span matching still applies at any length.
MIN_SUBSTRING_CHARS = 10


def normalize_span(span):
    """Deterministic normalization for span comparison.

    Lowercase, strip comment/bullet/quote prefixes, collapse
    whitespace, strip edge punctuation. Non-strings return "".
    """
    if not isinstance(span, str):
        return ""
    s = span.strip().lower()
    s = _COMMENT_PREFIX_RE.sub("", s)
    s = _WS_RE.sub(" ", s)
    s = s.strip(" \t.,!?;:\"'()[]{}<>-")
    return s


def _all_normalized_clauses(text):
    """Every clause of ``text`` normalized (wave-152).

    Unlike ``extract_instruction_spans`` this keeps non-instruction
    clauses too -- the substring matcher scans them for embedded
    observed spans (a worm instruction embedded mid-message inside a
    longer, non-instruction-shaped clause).
    """
    clauses = []
    if not isinstance(text, str):
        return clauses
    for clause in _CLAUSE_SPLIT_RE.split(text):
        norm = normalize_span(clause)
        if norm:
            clauses.append(norm)
    return clauses


def _word_boundary_substring(haystack, needle):
    """True when ``needle`` occurs in ``haystack`` at word boundaries.

    Guards against mid-word matches ("clean up our pod" must not fire
    on "clean up our podcast"). Unicode-aware like the rest of the
    module (``\\w`` covers Arabic/CJK word chars for future lists).
    """
    if not haystack or not needle:
        return False
    return re.search(r"(?<!\w)%s(?!\w)" % re.escape(needle),
                     haystack) is not None


def _first_words(normalized):
    words = normalized.split()
    if words and words[0] == _POLITE_PREFIX:
        words = words[1:]
    return words


def extract_instruction_spans(text):
    """Extract instruction-shaped spans from text.

    Returns a list of ``(raw_span, normalized_span)``. A clause is
    instruction-shaped when its first content word is an imperative
    verb from the curated set, or an auxiliary-led prohibition
    ("do not ...", "don't ...", "never ..."). Deterministic,
    stdlib-only.
    """
    spans = []
    if not isinstance(text, str):
        return spans
    for clause in _CLAUSE_SPLIT_RE.split(text):
        norm = normalize_span(clause)
        if not norm:
            continue
        words = _first_words(norm)
        if not words:
            continue
        first = words[0].strip(",")
        is_instruction = False
        if first in IMPERATIVE_VERBS:
            is_instruction = True
        elif first in _AUX_CUES:
            is_instruction = True
        elif first == "do" and len(words) > 1 and words[1].strip(",") == "not":
            is_instruction = True
        if is_instruction:
            spans.append((clause.strip(), norm))
    return spans


class PropagationTracker:
    """Per-run, per-agent injected-instruction propagation tracker.

    ``observe_input`` records instruction spans seen in the agent's
    input context; ``check_output`` flags output spans that reproduce
    observed input spans without being in the user's original request.
    Wave-152: the executor also calls ``observe_input`` automatically
    for successful governed ``read_file`` results (source id
    ``read:auto:<path>``); the tracker keys by (agent_id, source_id),
    so explicit and automatic observations of the same document are
    one observation, never a double count. In-process only (operator
    trust domain); no persistence.
    """

    def __init__(self):
        # agent_id -> source_id -> set(normalized spans)
        self._inputs = {}
        # agent_id -> source_id -> list(raw spans) for triage display
        self._raw = {}

    def observe_input(self, agent_id, source_id, text):
        """Record the instruction spans of one input-context segment.

        Returns {"observed": bool, "span_count": int, ...}. Never
        raises on bad input (best-effort, like the wave-141 auto hook).
        """
        agent_id = str(agent_id)
        source_id = str(source_id)
        try:
            spans = extract_instruction_spans(text)
        except Exception:  # noqa: BLE001 -- observation never breaks input
            spans = []
        by_agent = self._inputs.setdefault(agent_id, {})
        raw_by_agent = self._raw.setdefault(agent_id, {})
        bucket = by_agent.setdefault(source_id, set())
        raw_bucket = raw_by_agent.setdefault(source_id, [])
        for raw, norm in spans:
            if norm not in bucket:
                bucket.add(norm)
                raw_bucket.append(raw[:MAX_SPAN_CHARS])
        return {"observed": True, "agent_id": agent_id,
                "source_id": source_id, "span_count": len(spans),
                "sources": sorted(by_agent)}

    def input_span_count(self, agent_id):
        """Total distinct observed input spans for one agent."""
        return sum(len(s) for s in self._inputs.get(str(agent_id), {}).values())

    def check_output(self, agent_id, channel, output_text, user_request=None):
        """Score one boundary-crossing output.

        Verdicts: "allow" (silent); "propagation_suspect" (the output
        reproduces >=1 observed input instruction span that was NOT in
        the user's original request). Two match modes:
        - "exact": the output contains the whole observed span as an
          instruction-shaped clause (wave-151).
        - "substring" (wave-152): the observed span appears as a
          word-boundary-delimited SUBSTRING of a longer output clause
          that is not itself instruction-shaped (the worm-in-README
          shape). Spans shorter than ``MIN_SUBSTRING_CHARS`` are
          exempt from substring matching (word-boundary FP control);
          exact matching still applies at any length. An output that
          merely quotes the observed instruction as a warning still
          reproduces it -- it flags; the FP control is the
          user-request exclusion (whole-clause or substring), which
          suppresses user-given instructions in both modes.
        The result dict carries the reproduced raw spans, the source
        ids they were observed in, and the channel. Never blocks --
        the executor renders the suspect as a LOUD triage event and
        proceeds.
        """
        agent_id = str(agent_id)
        channel = str(channel)
        out_spans = extract_instruction_spans(output_text)
        user_spans = {norm for _, norm in
                      extract_instruction_spans(user_request or "")}
        user_full_norm = normalize_span(user_request or "")
        observed = self._inputs.get(agent_id, {})
        suspects = []
        flagged = set()
        for raw, norm in out_spans:
            if norm in user_spans:
                continue  # user-given instruction: the FP control
            hit_sources = sorted(
                sid for sid, spans in observed.items() if norm in spans)
            if hit_sources:
                flagged.add(norm)
                suspects.append({"span": raw[:MAX_SPAN_CHARS],
                                 "normalized": norm,
                                 "sources": hit_sources,
                                 "match": "exact"})
        # Wave-152 substring matching (deterministic order: sorted
        # source ids, sorted spans -- set iteration is hash-order).
        clause_norms = _all_normalized_clauses(output_text)
        for sid in sorted(observed):
            for s in sorted(observed[sid]):
                if s in flagged or s in user_spans:
                    continue
                if len(s) < MIN_SUBSTRING_CHARS:
                    continue
                if _word_boundary_substring(user_full_norm, s):
                    continue  # user-given: the FP control
                hit_clause = None
                for cn in clause_norms:
                    if _word_boundary_substring(cn, s):
                        hit_clause = cn
                        break
                if hit_clause is not None:
                    flagged.add(s)
                    srcs = sorted(x for x, ss in observed.items()
                                  if s in ss)
                    suspects.append({"span": s[:MAX_SPAN_CHARS],
                                     "normalized": s,
                                     "sources": srcs,
                                     "match": "substring",
                                     "context": hit_clause[:MAX_SPAN_CHARS]})
        if not suspects:
            return {"verdict": "allow",
                    "spans": [],
                    "channel": channel,
                    "agent_id": agent_id,
                    "sources": [],
                    "input_span_count": self.input_span_count(agent_id),
                    "output_span_count": len(out_spans)}
        return {"verdict": "propagation_suspect",
                "spans": [s["span"] for s in suspects],
                "span_detail": suspects,
                "channel": channel,
                "agent_id": agent_id,
                "sources": sorted({sid for s in suspects
                                   for sid in s["sources"]}),
                "input_span_count": self.input_span_count(agent_id),
                "output_span_count": len(out_spans)}
