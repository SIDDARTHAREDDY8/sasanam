"""Intent-slice judge for row-7 intent/temporal correlation.

Row-7 residual: no cross-agent intent/temporal correlation, no
revoke-after-approve. ``evals/row7_delayed_break.py`` pins the gap red
(plant-then-harm with zero correlating signal; no revocation path).

Pattern adapted from openai/openai-guardrails-python (MIT License,
(c) 2025 OpenAI; https://github.com/openai/openai-guardrails-python,
v0.3.2 = commit 60401f4ca6c832e8be1a82f6fc3783d6e51c59a9, resolved via
the GitHub tag-refs API on 2026-09-27; MIT license confirmed from the
upstream LICENSE at that tag):

- ``UserIntentDict``: ``{"most_recent_message": str,
  "previous_context": list[str]}`` -- the latest user turn plus prior
  user turns as the intent anchor.
- ``_slice_conversation_since_latest_user()``: the intent anchor is the
  index of the LATEST user message; the analyzed actions are everything
  after that index. User messages are never analyzed -- they ARE the
  intent.
- The direct-evidence rubric: flag only on direct evidence (a quoted
  contradiction, a countermanded recipient), never on competence
  issues (poor quality, partial progress, safe intermediate steps).

Adapted, not cloned: no code copied (the upstream judge calls paid
OpenAI APIs -- a $0-spend violation here). The LLM semantic judgment is
replaced with a deterministic local slicer: slot extraction (recipients,
URLs, paths), content-token overlap, countermand/redirect detection, and
negation-scoped verb matching. The verdict shape mirrors the upstream
structured contract (flagged / confidence / observation / evidence).

What this is NOT:
- Not an enforcer. The judge ANNOTATES approval-queue items; it never
  denies. A ``stale_intent`` flag routes to human review with evidence.
  False positives cost reviewer attention, not blocked work.
- Not a content oracle. It does not judge whether an action is harmful;
  it judges whether the action is still anchored to the LATEST user
  intent or only to a superseded earlier instruction.
- Not row-7 closure. Causal relevance here is heuristic: a paraphrase
  that launders a stale instruction through a vague latest message
  (no extractable slots, no countermand signal) defeats the slicer.
  That ceiling is measured, not claimed away (see
  ``evals/intent_slice_probes.py::p5_paraphrase_residual``).

$0, stdlib only. Deterministic.
"""

from __future__ import annotations

import json
import re

__all__ = [
    "UserIntent",
    "IntentSlice",
    "slice_intent",
    "judge_candidate",
    "judge_queued_action",
    "STEP_USER",
    "STEP_ACTION",
    "STEP_RESULT",
    "STEP_MESSAGE",
]

# Step kinds. Only "user" and "agent_action" participate in slicing;
# tool results and agent prose are neutral context (they neither anchor
# intent nor need anchoring).
STEP_USER = "user"
STEP_ACTION = "agent_action"
STEP_RESULT = "tool_result"
STEP_MESSAGE = "agent_message"

# Per-step labels produced by the slicer.
IN_SLICE = "in_slice"   # causally relevant to the latest user intent
STALE = "stale"         # serves only a superseded earlier instruction
NEUTRAL = "neutral"     # neither (weak signal, no countermand)

FLAG_STALE_INTENT = "stale_intent"

# Redirect/countermand signals: a latest user message carrying one of
# these AND sharing topic overlap with a prior user message marks that
# prior instruction as superseded.
_REDIRECT_RE = re.compile(
    r"\b(stop|don't|dont|do not|doesn't|doesnt|never mind|cancel|abort|"
    r"hold off|hold on|instead|forget|ignore|no longer|revert|undo|"
    r"on hold|not anymore|change of plans|scratch that)\b",
    re.IGNORECASE,
)

# Negation words for verb-scope negation ("don't delete", "never send").
_NEGATION_RE = re.compile(
    r"\b(don'?t|dont|do not|doesn'?t|doesnt|never|not|no|stop|halt|"
    r"cease|avoid|refrain|cancel)\b",
    re.IGNORECASE,
)

# Action verbs per tool family (stems, matched as substrings of tokens).
_TOOL_VERBS = {
    "delete_file": ("delet", "remov", "eras", "wipe", "clean", "clear",
                    "trash"),
    "send_email": ("send", "email", "mail"),
    "http_post": ("post", "upload", "submit", "publish", "push"),
    "write_file": ("write", "creat", "save", "draft"),
    "read_file": ("read", "open", "load", "summar", "review"),
    "api_call": ("call", "query", "fetch", "invoke"),
}

# Slot patterns: the extractable parameters an intent anchor carries.
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+", re.IGNORECASE)
_PATH_RE = re.compile(
    r"(?:/[\w.\-~]+)+/?|(?:[A-Za-z]:)?[\\/][\w.\-\\/~]+")

_STOPWORDS = frozenset(
    "a an the and or but if then else when at by for with about into "
    "through during before after above below to from up down in out on "
    "off over under again further once here there all any both each few "
    "more most other some such no nor not only own same so than too very "
    "can will just don should now of is are was were be been being have "
    "has had having do does did doing would could ought i you he she it "
    "we they them his her its our their this that these those am as me "
    "my your youre im ive dont isnt its lets".split())

# Minimum shared content tokens for a token-overlap relevance claim.
_OVERLAP_THRESHOLD = 2
# Tokens scanned backwards from a verb for negation scope.
_NEGATION_WINDOW = 6


def _tokens(text):
    """Content tokens: lowercased alphanumeric words, stopwords and
    1-2 char fragments dropped, canonical light stemming (a trailing
    's' is stripped so "emails" and "email" share one token -- the
    stem REPLACES the word, so one shared word counts once).
    Deterministic."""
    if not text:
        return set()
    words = re.findall(r"[a-z0-9]+", str(text).lower())
    out = set()
    for w in words:
        if len(w) <= 2 or w in _STOPWORDS:
            continue
        if len(w) > 3 and w.endswith("s") and not w.endswith("ss"):
            w = w[:-1]
        out.add(w)
    return out


def _extract_slots(text):
    """Extractable intent slots from free text.

    Returns {"emails": set, "urls": set, "paths": set}. Quoted text is
    NOT excluded here -- callers doing target comparison must use the
    tool-aware target slot, not raw text slots (an action quoting the
    latest message must not launder a contradictory target).
    """
    t = str(text or "")
    return {
        "emails": set(m.lower() for m in _EMAIL_RE.findall(t)),
        "urls": set(m.lower().rstrip(".,;:") for m in _URL_RE.findall(t)),
        "paths": set(_PATH_RE.findall(t)),
    }


def _action_target_slot(tool, args):
    """The tool-aware PRIMARY target of an action: the slot the latest
    intent's same-class slots are compared against.

    This is the quoting defense: for send_email the target is the
    recipient (args["to"]), not every email mentioned in the body. An
    action that quotes the latest message while targeting a different
    recipient contradicts the latest intent regardless of the quote.
    Returns (slot_class, value) or (None, None).
    """
    args = args or {}
    if not isinstance(args, dict):
        return (None, None)
    if tool == "send_email":
        for k in ("to", "recipient", "to_email", "email"):
            v = args.get(k)
            if v:
                return ("emails", str(v).lower())
    elif tool == "http_post":
        for k in ("url", "endpoint", "target"):
            v = args.get(k)
            if v:
                return ("urls", str(v).lower().rstrip(".,;:"))
    elif tool in ("read_file", "write_file", "delete_file"):
        for k in ("path", "file", "filename", "filepath"):
            v = args.get(k)
            if v:
                return ("paths", str(v))
    elif tool == "api_call":
        for k in ("url", "endpoint"):
            v = args.get(k)
            if v:
                return ("urls", str(v).lower().rstrip(".,;:"))
    return (None, None)


def _slot_contradiction(tool, args, latest_text):
    """True when the action's primary target contradicts the latest
    intent's same-class slots: the latest message names at least one
    slot of that class and the action's target matches none of them.

    Paths compare by prefix ("/tmp/scratch/x" serves "/tmp/scratch");
    URLs compare by prefix; emails compare exactly.
    """
    cls, target = _action_target_slot(tool, args)
    if cls is None or not target:
        return False
    want = _extract_slots(latest_text).get(cls, set())
    if not want:
        return False  # latest names no slot of this class: no claim
    if cls == "emails":
        return target not in want
    # paths / urls: the target serves the intent when it is under (or
    # equal to) a wanted slot.
    t = target.lower()
    for w in want:
        w = w.lower()
        if t == w or t.startswith(w.rstrip("/") + "/") or \
                w.startswith(t.rstrip("/") + "/"):
            return False
    return True


def _verb_stems(tool):
    return _TOOL_VERBS.get(tool, (tool.replace("_", " "),))


def _negated_verb(latest_text, tool):
    """True when the latest message negates the action's verb within a
    token window ("don't delete", "never send anything"). Direct
    evidence in the rubric sense."""
    tokens = re.findall(r"[a-z']+", str(latest_text or "").lower())
    stems = _verb_stems(tool)
    for i, tok in enumerate(tokens):
        if any(tok.startswith(s) for s in stems):
            window = tokens[max(0, i - _NEGATION_WINDOW):i]
            if any(_NEGATION_RE.fullmatch(w) for w in window):
                return True
    return False


# "don't forget X" / "do not ignore Y" are continuations, not
# redirects: strip them before redirect matching so benign reminders
# are not read as countermands.
_NEGATED_REDIRECT_STRIP_RE = re.compile(
    r"\b(don'?t|dont|do not|doesn'?t|doesnt|never)\s+(forget|ignore)\b",
    re.IGNORECASE,
)


def _detect_countermand(latest_text, previous_texts):
    """True when the latest user message supersedes a prior instruction:
    it carries a redirect signal AND shares topic overlap (>= 1 content
    token, or a shared slot) with at least one prior user message.

    Returns (countermanded: bool, superseded_index: int | None) where
    superseded_index is the most recent prior user message it overlaps.

    Heuristic, stated plainly: the redirect signal is the main gate and
    a single shared token links it to the prior instruction. Vague
    latest messages with no signal and no shared topic do NOT
    countermand -- that is the measured paraphrase ceiling (see
    evals/intent_slice_probes.py::p5_paraphrase_residual).
    """
    latest = str(latest_text or "")
    stripped = _NEGATED_REDIRECT_STRIP_RE.sub("", latest)
    if not _REDIRECT_RE.search(stripped):
        return (False, None)
    latest_toks = _tokens(latest)
    latest_slots = _extract_slots(latest)
    for idx in range(len(previous_texts) - 1, -1, -1):
        prev = str(previous_texts[idx] or "")
        if _tokens(prev) & latest_toks:
            return (True, idx)
        prev_slots = _extract_slots(prev)
        for cls in ("emails", "urls", "paths"):
            if latest_slots[cls] & prev_slots[cls]:
                return (True, idx)
    return (False, None)


def _render_action_text(tool, args, justification):
    """Textual rendering of an action for token overlap."""
    try:
        args_text = json.dumps(args, sort_keys=True, default=str)
    except Exception:  # noqa: BLE001 - never break slicing on odd args
        args_text = str(args)
    return "%s %s %s" % (tool or "", args_text, justification or "")


class UserIntent(dict):
    """The intent anchor, adapted from guardrails-py's UserIntentDict:
    the latest user message plus bounded prior context."""

    def __init__(self, most_recent_message, previous_context=()):
        super().__init__(
            most_recent_message=str(most_recent_message or ""),
            previous_context=[str(m) for m in previous_context])


class IntentSlice(dict):
    """Result of slicing a trajectory against the latest user intent."""

    def __init__(self, user_intent, boundary, labels, countermand,
                 superseded_index):
        super().__init__(
            user_intent=dict(user_intent) if user_intent else None,
            boundary=boundary,
            labels=list(labels),
            countermand=bool(countermand),
            superseded_index=superseded_index,
            n_in_slice=sum(1 for l in labels if l == IN_SLICE),
            n_stale=sum(1 for l in labels if l == STALE))


def _label_action(tool, args, justification, latest_text,
                  previous_texts, countermand, superseded_index):
    """Label one agent_action step. Stale checks run before in_slice:
    a countermanded verb with fresh token overlap is still stale."""
    action_text = _render_action_text(tool, args, justification)
    action_toks = _tokens(action_text)
    latest_toks = _tokens(latest_text)

    # 1. Direct evidence: the action's primary target contradicts the
    #    latest intent's same-class slots (quoting the latest message in
    #    the body does not count -- the target is tool-aware).
    if _slot_contradiction(tool, args, latest_text):
        return STALE
    # 2. Direct evidence: the latest message negates this action's verb
    #    ("don't delete", "never send") under a countermand.
    if countermand and _negated_verb(latest_text, tool):
        return STALE
    # 3. Heuristic: under a countermand, an action with zero fresh
    #    overlap that overlaps the superseded instruction serves only
    #    the stale intent.
    if countermand and superseded_index is not None:
        if not (action_toks & latest_toks):
            prev_toks = _tokens(previous_texts[superseded_index])
            if len(action_toks & prev_toks) >= _OVERLAP_THRESHOLD:
                return STALE
    # 4. Fresh relevance: token overlap or a slot the latest intent
    #    names (non-contradictory -- contradiction returned above).
    if len(action_toks & latest_toks) >= _OVERLAP_THRESHOLD:
        return IN_SLICE
    cls, target = _action_target_slot(tool, args)
    if cls and target:
        want = _extract_slots(latest_text).get(cls, set())
        if want and not _slot_contradiction(tool, args, latest_text):
            return IN_SLICE
    return NEUTRAL


def slice_intent(steps):
    """Slice a trajectory against the latest user message.

    ``steps``: list of dicts with ``kind`` in {"user", "agent_action",
    "tool_result", "agent_message"}. User steps carry ``text``;
    agent_action steps carry ``tool``, ``args``, ``agent_id``,
    ``justification``.

    Returns an IntentSlice. With no user step, the boundary is None and
    every action is NEUTRAL (no intent anchor exists to slice against).
    Deterministic; raises nothing (malformed steps degrade to NEUTRAL).
    """
    steps = list(steps or [])
    user_idx = [i for i, s in enumerate(steps)
                if isinstance(s, dict) and s.get("kind") == STEP_USER]
    labels = [NEUTRAL] * len(steps)
    if not user_idx:
        return IntentSlice(None, None, labels, False, None)
    boundary = user_idx[-1]
    user_texts = [str(steps[i].get("text") or "") for i in user_idx]
    latest_text = user_texts[-1]
    previous_texts = user_texts[:-1]
    intent = UserIntent(latest_text, previous_context=previous_texts)
    countermand, superseded = _detect_countermand(latest_text,
                                                 previous_texts)
    for i, s in enumerate(steps):
        if not isinstance(s, dict) or s.get("kind") != STEP_ACTION:
            continue
        try:
            labels[i] = _label_action(
                s.get("tool"), s.get("args"), s.get("justification"),
                latest_text, previous_texts, countermand, superseded)
        except Exception:  # noqa: BLE001 - slicing never breaks the caller
            labels[i] = NEUTRAL
    return IntentSlice(intent, boundary, labels, countermand, superseded)


def judge_candidate(steps):
    """Judge the CANDIDATE action: the last agent_action step in
    ``steps``. Everything before it (including the latest user message)
    is the trajectory it is judged against.

    Flags ``stale_intent`` when the candidate is sliced STALE and its
    justification provides no fresh support: no slot alignment with the
    latest intent, and justification token overlap with the latest
    message below threshold -- or a slot contradiction, in which case
    quoting the latest message is explicitly not support (quoting !=
    causation).

    Returns a verdict dict: {flagged, flag, confidence, observation,
    evidence, slice_summary}. Never raises; never denies.
    """
    steps = list(steps or [])
    action_positions = [i for i, s in enumerate(steps)
                        if isinstance(s, dict)
                        and s.get("kind") == STEP_ACTION]
    no_anchor = {
        "flagged": False, "flag": None, "confidence": 0.0,
        "observation": "no candidate action to judge",
        "evidence": [],
        "slice_summary": {"n_in_slice": 0, "n_stale": 0,
                          "countermand": False},
    }
    if not action_positions:
        return no_anchor
    cand_idx = action_positions[-1]
    sliced = slice_intent(steps)
    summary = {"n_in_slice": sliced["n_in_slice"],
               "n_stale": sliced["n_stale"],
               "countermand": sliced["countermand"],
               "boundary": sliced["boundary"]}
    base = {"flagged": False, "flag": None, "confidence": 0.0,
            "observation": "", "evidence": [],
            "slice_summary": summary}
    if sliced["user_intent"] is None:
        base["observation"] = ("no user message in trajectory: no intent "
                               "anchor; candidate left unflagged")
        return base
    if sliced["labels"][cand_idx] != STALE:
        base["observation"] = (
            "candidate is %s to the latest user intent; no stale-intent "
            "signal" % sliced["labels"][cand_idx])
        base["confidence"] = 0.6
        return base

    # Candidate is STALE. Does its justification carry fresh support?
    cand = steps[cand_idx]
    tool = cand.get("tool")
    args = cand.get("args")
    justification = cand.get("justification") or ""
    latest_text = sliced["user_intent"]["most_recent_message"]
    contra = _slot_contradiction(tool, args, latest_text)
    j_overlap = len(_tokens(justification) & _tokens(latest_text))
    fresh_support = (j_overlap >= _OVERLAP_THRESHOLD) and not contra
    if fresh_support:
        base["observation"] = (
            "candidate sliced stale but its justification shows fresh "
            "intent support (%d shared tokens, no slot contradiction); "
            "left for human review unflagged" % j_overlap)
        base["evidence"] = [justification[:280]]
        base["confidence"] = 0.5
        return base

    evidence = []
    if contra:
        cls, target = _action_target_slot(tool, args)
        want = sorted(_extract_slots(latest_text).get(cls, set()))
        evidence.append(
            "target %s=%r contradicts latest intent %s=%s"
            % (cls, target, cls, want))
    if sliced["countermand"]:
        evidence.append("latest user message countermands a prior "
                        "instruction: %r" % latest_text[:200])
        if _negated_verb(latest_text, tool):
            evidence.append("latest message negates this action's verb "
                            "(%s)" % tool)
    prev = sliced["user_intent"]["previous_context"]
    if sliced["superseded_index"] is not None and prev:
        evidence.append("superseded instruction: %r"
                        % prev[sliced["superseded_index"]][:200])
    evidence.append("candidate justification: %r"
                    % (justification[:200] if justification
                       else "<none>"))
    if contra or (sliced["countermand"]
                  and _negated_verb(latest_text, tool)):
        confidence = 0.9
    else:
        confidence = 0.7
    base.update(
        flagged=True,
        flag=FLAG_STALE_INTENT,
        confidence=confidence,
        observation=(
            "candidate action serves only a superseded instruction; the "
            "latest user intent does not support it. Flagged for human "
            "review (judge only -- nothing denied)."),
        evidence=evidence)
    return base


def judge_queued_action(tool, args, justification, user_turns,
                        prior_actions=()):
    """Convenience for the approval-queue wiring: build the trajectory
    from operator-provided user turns plus prior agent actions, append
    the candidate, and judge it.

    ``user_turns``: list of user message strings, oldest first.
    ``prior_actions``: list of {"tool", "args", "agent_id",
    "justification"} dicts (or step dicts).
    Returns the verdict dict from judge_candidate. Never raises.

    Ordering note: prior actions are placed after the user turns rather
    than truly interleaved. This does not affect the candidate verdict
    -- the judge compares the candidate against the user turns (latest
    first) only; prior actions contribute slice-summary counts, not the
    verdict. True chronological interleaving is not required for the
    judge's advisory purpose.
    """
    steps = []
    try:
        for t in (user_turns or []):
            steps.append({"kind": STEP_USER, "text": str(t)})
        for a in (prior_actions or []):
            a = dict(a) if isinstance(a, dict) else {}
            a["kind"] = STEP_ACTION
            steps.append(a)
        steps.append({"kind": STEP_ACTION, "tool": tool, "args": args,
                      "justification": justification})
        return judge_candidate(steps)
    except Exception:  # noqa: BLE001 - the judge never breaks queueing
        return {"flagged": False, "flag": None, "confidence": 0.0,
                "observation": "judge error: left unflagged",
                "evidence": [],
                "slice_summary": {"n_in_slice": 0, "n_stale": 0,
                                  "countermand": False}}
