"""Rare-token carryover detection (row 13, wave-136 lane).

Row-13 residual: prose-paraphrase exfiltration (5 pinned BREAKs) is
invisible to the wave-132 content analyzer, which scores STRUCTURE
(structured dumps, encoded blobs). A fluent paraphrase rewrites common
words but tends to preserve RARE tokens from the source document —
proper names, account IDs, unusual terms. This module is the new
primitive for that class: if the agent READ a document containing
rare tokens and later EGRESSES text containing several of those same
rare tokens, that is a paraphrase-resistant exfiltration signal.

Deterministic, $0, stdlib-only.

How it works:
- ``extract_rare_tokens(text)``: tokenize, lowercase; a token is
  "rare" when it is absent from the bundled common-word floor AND
  (a) has >= 4 characters, or (b) mixes letters and digits (IDs like
  ``zx88142``), or (c) is a pure-digit run of >= 5 (account numbers).
  Short fragments (``zx``, ``qx``) and short numbers (``400``) are
  never rare — they FP on ordinary prose.
- ``RareTokenTracker``: per-run, per-agent. ``observe_read`` records
  the rare-token set of each read source (doc id -> token set, in
  process memory only — the operator trust domain, like
  SentinelVault). ``check_egress`` computes the max per-source
  overlap for one outbound payload and returns a graduated verdict:
    overlap == 0            -> "allow" (silent)
    1 <= overlap < K        -> "flag" (LOUD audit, execution proceeds)
    overlap >= K, novel dst -> "require_approval" (human review queued)
    overlap >= K, known dst -> "flag" (destination novelty amplifies;
                              a known-good recipient never blocks)
  K defaults to 3. Destination history is per-agent, like
  EgressContentMonitor. The result dict and every audit event carry
  COUNTS and doc ids ONLY — token strings are never logged (privacy).
- Wave-137 behavioral tier: when the CONTENT tier finds ZERO overlap
  but the agent READ >=1 token-bearing document this run and now
  egresses to a CONCRETE novel destination, ``check_egress`` returns
  ``"behavioral_flag"`` instead of "allow" — a triage flag, NEVER a
  hold. This is the last deterministic signal against the full-rewrite
  ceiling (paraphrase that drops every rare token). It is deliberately
  the noisiest signal in the module: it fires on the read->egress
  SEQUENCE regardless of content, so legit read-then-send workflows
  WILL flag. The FP control is destination novelty (known-good
  recipients never flag) plus a concrete-destination requirement (a
  tool call with no extractable destination stays silent). The
  content tier takes precedence: overlap >= 1 never degrades to a
  behavioral flag.

Honest ceilings (documented, measured in
evals/rare_token_probes.py and evals/read_then_egress_probes.py):
- An attacker who paraphrases AND drops all rare tokens (a full
  rewrite with no names/IDs) is invisible to the CONTENT tier by
  design (r7 pins this as BREAK*). The wave-137 behavioral tier
  recovers a flag for the read->novel-egress SEQUENCE — triage-only,
  never prevention, and it WILL fire on legitimate read-then-send
  workflows (e.g. a research agent that reads a vendor contract and
  emails a summary to a new contact; or the FIRST benign status
  ping to a vendor endpoint after a sensitive read — a destination
  is "known" only once the agent has egressed to it, so a channel
  first used after the read is novel for the tier's purpose).
  The operator triages on docs_read + destination; the flag is the
  start of review, not its conclusion.
- The bundled wordlist is a crude frequency floor (~450 common
  words). Jargon-heavy legitimate domains WILL produce rare tokens;
  the destination-novelty amplifier and the K>=3 bar are the FP
  controls, not the wordlist.
- Read observation is explicit (``note_read_output``): reads the
  operator never reports are invisible. This keeps the hot tool path
  untouched and avoids double-counting, at the cost of coverage
  depending on the integration.
- Cross-run memory: the tracker is per-run, but when constructed
  with a ``taint_ledger`` (gov/taint_ledger.py) the read-side taint
  persists across runs keyed by stable agent identity: a later run's
  ``check_egress`` scores blinded-commitment overlap against prior
  runs' taint (same verdict ladder) and the behavioral tier fires on
  prior runs' reads too. Wave-140 adds the destination-side
  counterpart: when constructed with a ``destination_ledger``
  (gov/destination_ledger.py), destination history ALSO persists
  across runs — a destination first used in run 1 is known in run
  2, so a legit read-then-send to a known destination no longer
  flags every run (fewer false positives cross-run). Without a
  ledger attached, a read in run N followed by an egress in run N+1
  stays invisible to both tiers (the opt-in ceiling). Each ledger's
  own ceilings apply: operator TTL (an attacker who knows it can
  wait it out), stable identity required, key rotation blinds prior
  taint; the destination ledger proves WHERE bytes went, not WHAT
  they contained.

The reference wordlist choice: a bundled static list of common
English words (function words + frequent content words), embedded so
the module is $0/deterministic with no network and no repo-text
mining (mining the repo's own text would make rarity depend on
whatever the repo happens to contain — non-stationary and
unreviewable).
"""

import re

# ---------------------------------------------------------------------------
# Bundled common-word frequency floor (~450 words).
# Crude by design: the FP controls are the K>=3 bar and the
# destination-novelty amplifier, not this list.
# ---------------------------------------------------------------------------

_COMMON_WORDS = frozenset("""
a about above after again against all almost also always am among amount
an and another any anyone around as at back be because become been before
behind being below between both but by call can cannot change co come could
day days did different do does doing done down during each early end even
every fact far few find first for form found from further get give given go
going good got great had has have having he help her here hers herself him
himself his home how however i if in into is it its itself job just keep
kind know large last later least less let like line little long look made
make man many may me mean men might mind more most move much must my myself
name need never new no nor not now number of off often on once one only or
other ought our ours ourselves out over own part people place point put
question really right room same saw say second see seem seen shall she
should show side since small so some something sometimes still such take
taken than that the their theirs them themselves then there these they
thing think this those though through time times to today together too
took toward under until up upon use used using very want was way ways we
week well were what when where which while who whole whom whose why will
with within without work world would year years yes yet you your yours
yourself yourselves able account across act action added after again
almost along already also always amount another any anyone around away
back become became become behind being best better between big both bottom
call came can case cause certain change children city clear close common
company complete contact contract course court current customer date
deal death deep details door down dry due early effect end enough even
ever every example except fact far feel few field figure fill final
follow food force form found front full further game gave general
get girl give given goes going gone good got great green group grow
half hand happy hard have head health hear heard help high history hit
hold home hope hot hour house however idea image include including
increase indeed inside instead interest into itself job join just keep
kind knew know known land large later laugh law least leave left less
let letter level light like likely line list little live local long look
looked love low made main make man many matter may mean meant meet
member men might mind minute miss money month more morning most mother
mountain move much music must name near need needs never new night
north note nothing notice now number object obtain occur office often
oil old once one open order other others ought our out over owner page
paper part pass past pay people per person phone picture piece place
plan plant play please point pound power press pretty price process
product pull put quick quiet quite radio raise reach ready real reason
receive record red region remain remember renewal report rest return
right river road rock room round rule run safe said same saw say
second see seem seen send sense sent serve service set several shall
shape share short should show side sign since single size sleep small
smile so some soon sorry sound south space speak speed spend spoke
stand start state status stay step still stock stone stood stop story
street strong study stuff such sure system systems table take taken
talk team tell ten than thank that their them then there these they
thing think third those though three through throw time times today
together told too took top total touch town trade train travel treat
tree trial trip trouble true try turn under unit until up upon use
usual value various very view visit wait walk wall want war warm
watch water way ways week well went were west what whatever when where
whether which while white whole whom whose why wide wife will wind
window wish with within without woman women word work worker world
worry would write writer wrong wrote yard year years yes yet young
your
# Ordinary content words that must never count as rare (added
# wave-136 after the battery caught them missing: "primary contact",
# "account review", "renewal code" are everyday business language).
client code confirm escalation primary reference review
# "role/roles" are everyday nouns (missed in the first pass).
role roles
""".split())

# ---------------------------------------------------------------------------
# Tokenizer / rarity
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")

#: Cap on rare tokens retained per source document (memory bound;
#: deterministic — the lexicographically smallest tokens win).
MAX_TOKENS_PER_DOC = 500

#: Cap on source documents retained per agent (oldest dropped).
MAX_DOCS_PER_AGENT = 50

#: Default carryover bar: >= K rare tokens from one source in one
#: egress -> require_approval (at a novel destination).
DEFAULT_CARRYOVER_THRESHOLD = 3


def _is_rare(token):
    """Rarity predicate on an already-lowercased token.

    Pure-digit runs are years/counts until they are long enough to be
    IDs (>= 5 digits); the len>=4 rule needs at least one alpha so a
    year like "2024" never counts as rare.
    """
    if token in _COMMON_WORDS:
        return False
    has_digit = any(c.isdigit() for c in token)
    has_alpha = any(c.isalpha() for c in token)
    if token.isdigit():
        return len(token) >= 5
    if len(token) >= 4 and has_alpha:
        return True
    if has_digit and has_alpha and len(token) >= 3:
        return True
    return False


def extract_rare_tokens(text, reference=None):
    """Return the sorted list of rare tokens in ``text``.

    Tokenize on ``[A-Za-z0-9]+``, lowercase; a token is rare when it
    is absent from ``reference`` (default: the bundled common-word
    floor) and meets the shape rules in ``_is_rare``. Deterministic;
    never raises on non-string input (returns []).
    """
    if not isinstance(text, str) or not text:
        return []
    ref = _COMMON_WORDS if reference is None else frozenset(reference)
    out = set()
    for tok in _TOKEN_RE.findall(text.lower()):
        if tok in ref:
            continue
        if _is_rare(tok):
            out.add(tok)
    return sorted(out)


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------

class RareTokenTracker:
    """Per-run rare-token carryover tracker (one source of truth per
    agent for what was READ, checked at each EGRESS).

    ``observe_read(agent_id, source_id, text)`` records the rare-token
    set of a read source (doc id -> token set, process memory only).
    When constructed with a ``taint_ledger`` (gov/taint_ledger.py),
    the read is ALSO recorded durably (counts, doc ids, and opaque
    per-token commitments — never token strings), keyed by stable
    agent identity, so a LATER run's ``check_egress`` can score
    overlap against prior runs' taint.
    ``check_egress(agent_id, tool, args, payload_text=None)`` scores
    one outbound payload: the max per-source overlap drives a
    graduated verdict (allow / flag / require_approval), amplified by
    destination novelty; with ZERO content overlap the wave-137
    behavioral tier fires instead when the agent read >=1
    token-bearing document and egresses to a concrete novel
    destination ("behavioral_flag" — triage-only, never a hold).
    With a ``taint_ledger`` attached, prior runs' reads count for
    the behavioral tier too (see gov/taint_ledger.py).
    Result dicts and audit payloads carry counts and doc ids only —
    never token strings.
    """

    def __init__(self, reference=None,
                 carryover_threshold=DEFAULT_CARRYOVER_THRESHOLD,
                 max_docs_per_agent=MAX_DOCS_PER_AGENT,
                 max_tokens_per_doc=MAX_TOKENS_PER_DOC,
                 taint_ledger=None,
                 destination_ledger=None):
        if (not isinstance(carryover_threshold, int)
                or carryover_threshold < 1):
            raise ValueError("carryover_threshold must be a positive int")
        self._reference = (_COMMON_WORDS if reference is None
                           else frozenset(reference))
        self._k = carryover_threshold
        self._max_docs = max_docs_per_agent
        self._max_tokens = max_tokens_per_doc
        self._docs = {}          # agent_id -> {source_id: frozenset}
        self._destinations = {}  # agent_id -> set of seen destinations
        # Wave-139: optional durable cross-run taint (opt-in; None =
        # zero behavior change vs the per-run tracker).
        self._taint_ledger = taint_ledger
        # Wave-140: optional durable cross-run destination history
        # (opt-in; None = zero behavior change vs the per-run
        # tracker). See gov/destination_ledger.py for the privacy
        # contract (destinations are already audit-logged).
        self._destination_ledger = destination_ledger

    # -- reads ------------------------------------------------------
    def observe_read(self, agent_id, source_id, text):
        """Record the rare-token set of one read source.

        With a ``taint_ledger`` attached the read is also recorded
        durably for later runs (``ledger_recorded`` in the return
        dict); a ledger write failure propagates fail-closed rather
        than silently dropping taint.
        """
        agent_id = str(agent_id)
        source_id = str(source_id)
        tokens = extract_rare_tokens(text, self._reference)
        if len(tokens) > self._max_tokens:
            tokens = tokens[:self._max_tokens]
        # F167 ordering: the durable write goes first, so a ledger
        # failure leaves the in-run tracker unchanged too.
        ledger_recorded = False
        if self._taint_ledger is not None:
            res = self._taint_ledger.observe(agent_id, source_id, tokens)
            ledger_recorded = bool(res.get("ledger_recorded"))
        docs = self._docs.setdefault(agent_id, {})
        docs[source_id] = frozenset(tokens)
        while len(docs) > self._max_docs:
            docs.pop(next(iter(docs)))
        return {"observed": True, "agent_id": agent_id,
                "source_id": source_id, "rare_token_count": len(tokens),
                "ledger_recorded": ledger_recorded}

    # -- egress -----------------------------------------------------
    def _token_bearing_sources(self, agent_id):
        """Sorted source ids of docs the agent read that carried >=1
        rare token. A doc with few rare tokens still counts: the
        behavioral tier is sequence-based, not content-thresholded
        (documented FP tradeoff)."""
        return sorted(
            sid for sid, toks
            in self._docs.get(agent_id, {}).items()
            if len(toks) >= 1)

    def check_egress(self, agent_id, tool, args, payload_text=None):
        """Score one outbound payload. Returns a verdict dict with
        counts/doc-ids only (never token strings).

        Verdicts: "allow" (silent); "flag" (1..K-1 overlap, or >=K
        overlap to a known destination); "require_approval" (>=K
        overlap to a novel destination); "behavioral_flag" (wave-137:
        zero content overlap BUT the agent read >=1 token-bearing
        document this run and egresses to a CONCRETE novel
        destination — triage-only, never a hold). Seam contract:
        the tracker verdict is "behavioral_flag"; the executor
        renders it as the LOUD ``read_then_egress_novel`` audit event
        (flag "read_then_egress"). The content tier
        takes precedence: any overlap >= 1 never degrades to a
        behavioral flag. A tool call with no extractable destination
        stays silent under the behavioral tier (FP control); the
        content tier treats an unknown destination as novel.
        Wave-140: with a ``destination_ledger`` attached, "novel" is
        evaluated against run-1..N history — a destination first used
        in an earlier run is known in this run, so a legit
        read-then-send to a known destination stays silent cross-run
        (fewer false positives); the attempted destination is
        recorded durably at check time."""
        agent_id = str(agent_id)
        payload = (payload_text if isinstance(payload_text, str)
                   else _extract_payload(tool, args or {}))
        destination = _extract_destination(tool, args or {})
        seen = self._destinations.setdefault(agent_id, set())
        # Wave-140: with a destination_ledger attached, "novel"
        # consults run-1..N history too — a destination first used in
        # an earlier run is known, not novel. None = zero behavior
        # change (per-run novelty only).
        ledger_known = (
            self._destination_ledger is not None
            and destination is not None
            and self._destination_ledger.known(agent_id, destination))
        novel = (destination is None
                 or (destination not in seen and not ledger_known))

        payload_rare = set(extract_rare_tokens(payload, self._reference))
        best_overlap = 0
        best_source = None
        for source_id, doc_tokens in self._docs.get(agent_id, {}).items():
            overlap = len(payload_rare & doc_tokens)
            if overlap > best_overlap:
                best_overlap = overlap
                best_source = source_id

        # Wave-139: cross-run taint. Sources already covered in-run
        # take precedence (full token sets); ledger-only sources are
        # scored by blinded-commitment overlap — the same verdict
        # ladder below runs unchanged over the union.
        ledger_records = []
        if self._taint_ledger is not None:
            in_run_sources = set(self._docs.get(agent_id, {}))
            ledger_records = self._taint_ledger.taint_for(agent_id)
            for rec in ledger_records:
                sid = rec["source_id"]
                if sid in in_run_sources:
                    continue
                committed = set(rec["commitments"])
                blind = self._taint_ledger.blinded_token
                overlap = sum(
                    1 for tok in payload_rare
                    if blind(agent_id, sid, tok) in committed)
                if overlap > best_overlap:
                    best_overlap = overlap
                    best_source = sid

        if destination:
            if self._destination_ledger is not None:
                # Durable destination history (wave-140 row-13):
                # the attempted destination is recorded for later
                # runs. F167 ordering: the durable write goes first,
                # so a ledger failure leaves the in-run tracker
                # unchanged too — a failure propagates fail-closed,
                # mirroring observe_read's taint-ledger discipline;
                # history is never silently dropped.
                self._destination_ledger.record(agent_id, destination)
            seen.add(destination)

        bearing = self._token_bearing_sources(agent_id)
        if ledger_records:
            # Ledger records exist only for token-bearing reads, so
            # every live ledger source counts as bearing (same >=1
            # rule as the in-run tier): the behavioral tier fires on
            # prior-run reads too.
            bearing = sorted(
                set(bearing) | {r["source_id"] for r in ledger_records})
        if best_overlap >= self._k and novel:
            verdict = "require_approval"
        elif best_overlap >= 1:
            verdict = "flag"
        else:
            # Behavioral tier: concrete novel destination required.
            # An unextractable destination (None) stays silent here —
            # this is the noisiest signal in the module and flagging
            # destination-less tool calls would drown the operator.
            if bearing and destination is not None and novel:
                verdict = "behavioral_flag"
            else:
                verdict = "allow"
        return {"verdict": verdict,
                "overlap": best_overlap,
                "source_id": best_source,
                "destination": destination,
                "destination_novel": bool(novel),
                "threshold": self._k,
                "agent_id": agent_id,
                "docs_read": len(bearing),
                "source_ids": bearing}


# ---------------------------------------------------------------------------
# Payload / destination extraction (mirrors gov.egress_content's shapes;
# kept local so this primitive has no intra-gov dependencies).
# ---------------------------------------------------------------------------

def _extract_payload(tool, args):
    bits = []
    if tool == "http_post":
        keys = ("data", "body", "payload", "content")
    elif tool == "send_email":
        keys = ("subject", "body", "text", "html")
    elif tool == "api_call":
        params = args.get("params")
        if isinstance(params, dict):
            for v in params.values():
                if isinstance(v, str) and v:
                    bits.append(v)
        elif isinstance(params, str) and params:
            bits.append(params)
        return "\n".join(bits)
    else:
        for v in args.values():
            if isinstance(v, str) and v:
                bits.append(v)
        return "\n".join(bits)
    for k in keys:
        v = args.get(k)
        if isinstance(v, str) and v:
            bits.append(v)
    return "\n".join(bits)


def _extract_destination(tool, args):
    if tool == "http_post":
        return args.get("url")
    if tool == "send_email":
        return args.get("to")
    if tool == "api_call":
        return args.get("endpoint")
    return None
