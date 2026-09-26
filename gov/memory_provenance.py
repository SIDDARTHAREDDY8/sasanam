"""Memory provenance firewall (S1 stream; memo Part D row 1: memory poisoning).

The GAP: memory writes pass through ToolExecutor as ordinary tool calls, so
per-action policy applies -- but there is no memory *provenance*. Nothing
records which entries came from untrusted sources, and nothing re-checks
provenance at retrieval. An injected instruction becomes "the agent's own
memory" and every check sees legitimate learned preference. Cross-session,
the January poison fires in June with zero warning (AgentPoison / MINJA /
SpAIware / eTAMP class).

What this module does:

* Every write to a deployment-designated memory path (default prefixes
  ``memory/``, ``notes/``) becomes a governed object: :class:`MemoryLedger`
  records ``(entry hash, writer identity, source-trust tier, tainted-run
  flag, write-time instruction-shaping classification, timestamp)`` in a
  per-deployment HMAC-chained JSONL ledger, separate from the action log
  (modeled on :class:`gov.egress_ledger.EgressLedger`: seq chaining,
  checkpoints, file locking, fail-closed reads).
* Retrieval re-checks: the ledger entry's trust tier is looked up, the
  current file content is hash-verified against the recorded digest (a file
  changed outside governance reads as ``unknown`` -- fail-closed), and
  instruction-shaped content in a low-trust entry triggers quarantine
  BEFORE the agent acts on it.
* Session open: the ledger is scanned for untrusted, instruction-shaped
  entries recorded by earlier sessions, so a poison written in January is
  flagged in June instead of silently trusted.

Trust tiers are COMPUTED BY THE FIREWALL, never from a caller kwarg
(no tier-smuggling, cf. F79's matched_rules probe):

* ``agent`` -- the written bytes share no verbatim normalized substring
  (>= 64 chars) with any ingested tool-result fingerprint of the writing
  run. The agent's own notes, even imperative ones ("remind me to file
  expenses"), are never quarantined: the agent's own history is its
  business.
* ``untrusted_derived`` -- the bytes ARE traceably copied from untrusted
  tool output (``read_file`` / ``api_call`` / ``http_post`` /
  ``send_email`` results; http_post joined in F144 -- an http_post
  response body is untrusted external content exactly like an api_call
  result; send_email joined in F175 -- a response-carrying mail relay /
  MCP email adapter reply is untrusted external content exactly like a
  webhook response, while the built-in no-content send_email result
  ingests nothing). Paraphrase laundering
  (the agent rewords the poison instead of copying it) evades the verbatim
  match and is a DOCUMENTED residual, the same class as F15's paraphrase
  boundary.

Quarantine rule: ``tier in {"untrusted_derived", "unknown"}`` AND
instruction-shaped content -> quarantine: the read is denied (fail-closed,
loud, chained ``memory_quarantine`` event), never silently delivered.
Agent-tiered entries are always allowed.

The firewall is OPT-IN: ``ToolExecutor(memory_firewall=...)``. ``None``
(the default) means zero behavior change. A deployment that opts in
accepts the fail-closed posture explicitly, including the ``unknown``
treatment of memory files that predate the ledger (pre-seed them with
:meth:`MemoryFirewall.seed_entry` after review).

Honest residuals (documented, not claimed away):

* Paraphrased poison (no verbatim 64-char overlap) is not tiered
  untrusted -- same boundary as F15.
* The write-time fingerprint store is bounded (256 KiB, like the
  executor's); eviction before the write loses the verbatim link.
* Instruction-shaping is deterministic heuristics, not semantics: a
  careful adversary can phrase a poison to dodge the patterns, and a
  genuinely instructional untrusted note (\"always approve vacation
  requests quickly\") quarantines conservatively by design -- the operator
  releases it with :meth:`MemoryFirewall.release_entry` after review.
  GAP-1 hardened the detector with an evasion register
  (``evasion_standing_instruction``, ``evasion_stored_directive``,
  ``evasion_preference_directive``, ``evasion_workflow_rule``,
  ``evasion_confirmation_waiver``) pinned by evals/gap1mem_break.py;
  further rewordings remain an arms-race surface, not a closed one.
* The ledger's HMAC key is the deployment log key: whoever holds it can
  forge entries. That is the same trust story as the action log itself.
* Provenance is recorded after the filesystem write executes: if the
  ledger append itself fails, the bytes land untracked. The failure is
  loud (the exception propagates out of the tool call), and the next
  read treats the untracked bytes as ``unknown`` -- instruction-shaped
  content still quarantines, so the failure mode is fail-safe, just
  unattributed.
* Operator release is a deployment-side call on the firewall, not a
  governed tool: the reviewer identity is asserted by the deployment,
  not minted. The release is chained and attributed in the ledger, but
  a compromised deployment process can bless its own poison -- the
  same trust boundary as the ledger key itself.
"""

import hashlib
import json
import re
import time
import unicodedata

from .egress_ledger import (
    EgressLedger,
    LedgerUnverifiableError,
    _ledger_read_locked,
    _LedgerMissing,
)

#: Local copy of the invisible-character stripping used for the MATCHING
#: COPY ONLY (stored/logged bytes keep their true content for forensics).
#: Mirrors gov.adapters.trust._strip_format_chars (F84: category Cf) and
#: _strip_variation_selectors (F86/F92: Mn default-ignorable ranges). It is
#: reimplemented here -- rather than imported -- because
#: ``gov.adapters.__init__`` -> ``gov.adapters.core`` imports
#: ``gov.executor`` (ToolExecutor), so importing anything under
#: ``gov.adapters`` from a module that ``gov.executor`` itself imports
#: is a circular import. The ranges below are pinned to the documented
#: F84/F86/F92 closures; if those evolve, this copy must be re-synced
#: (a unit test below asserts the known-evasion coverage).
_INVISIBLE_RANGES = (
    (0xFE00, 0xFE0F),    # variation selectors (F86)
    (0xE0100, 0xE01EF),  # supplementary variation selectors (F86)
    (0x034F, 0x034F),    # COMBINING GRAPHEME JOINER (F92)
    (0x180B, 0x180D),    # MONGOLIAN FVS ONE..THREE (F92)
    (0x180F, 0x180F),    # MONGOLIAN FVS FOUR (F92)
)


def _strip_invisible(text):
    """Remove category-Cf format characters and Mn default-ignorable
    variation selectors from ``text`` (matching copy only)."""
    out = []
    for ch in text:
        o = ord(ch)
        if unicodedata.category(ch) == "Cf":
            continue
        if any(lo <= o <= hi for lo, hi in _INVISIBLE_RANGES):
            continue
        out.append(ch)
    return "".join(out)

__all__ = [
    "MemoryFirewall",
    "MemoryLedger",
    "MemoryQuarantineError",
    "instruction_shaping_reason",
    "TRUST_TIER_AGENT",
    "TRUST_TIER_UNTRUSTED",
    "TRUST_TIER_UNKNOWN",
]

TRUST_TIER_AGENT = "agent"
TRUST_TIER_UNTRUSTED = "untrusted_derived"
TRUST_TIER_UNKNOWN = "unknown"

#: Verbatim-copy threshold: a normalized 64-char substring shared between
#: written memory bytes and an ingested tool-result fingerprint tiers the
#: write untrusted_derived. Below this, accidental overlap (boilerplate,
#: short quotes) must not taint.
_VERBATIM_CHARS = 64

_DEFAULT_MEMORY_PREFIXES = ("memory/", "notes/")


class MemoryQuarantineError(Exception):
    """Raised when a memory read is quarantined: fail-closed, loud.

    The chained ``memory_quarantine`` audit event carries the entry key,
    trust tier, and shaping reason; the content is never delivered.
    """


def _match_copy(text):
    """The copy patterns match against: NFKC, invisible characters
    stripped (F84 Cf class + F86/F92 variation selectors -- the matching
    copy only; stored/logged bytes keep the true content for forensics),
    whitespace collapsed, lowercased."""
    if not isinstance(text, str):
        return ""
    t = unicodedata.normalize("NFKC", text)
    t = _strip_invisible(t)
    t = re.sub(r"\s+", " ", t)
    return t.lower()


#: (reason, compiled pattern) over the match copy. Tuned for the memory
#: poison shape: declarative authority framing + broad behavioral
#: directives, the MINJA/SpAIware register. Deliberately narrower than a
#: general instruction detector: agent-tiered notes are never screened, so
#: these patterns only ever fire on untrusted-derived or unknown bytes,
#: where conservative is correct.
_MEMORY_INSTRUCTION_PATTERNS = (
    ("policy_authority_framing", re.compile(
        r"\b(policy update|system update|system instruction|admin notice|"
        r"security policy update|updated policy|new policy)\b")),
    ("override_directive", re.compile(
        r"\b(ignore|disregard|override|bypass)\s+(all\s+)?(previous|prior|"
        r"earlier|these|current)\s+(instructions?|policies|policy|rules?|"
        r"safeguards?|restrictions?)\b")),
    ("self_persistence", re.compile(
        r"\b(note to self|remember to always|from now on[,:]?\s+(always|you)|"
        r"going forward[,:]?\s+(always|you must|never))\b")),
    ("authority_impersonation", re.compile(
        r"\b(as (an?\s+)?(system administrator|administrator|admin|"
        r"developer|system)|on behalf of (the\s+)?(system|admin|"
        r"administrator))\b")),
    ("broad_behavioral_directive", re.compile(
        r"\b(you must|you shall|always (approve|allow|send|share|disclose|"
        r"ignore|skip)|never (ask|request|require|verify|confirm|"
        r"escalate))\b")),
    ("suppression_directive", re.compile(
        r"\b(do not|don't|never)\s+(ask|verify|confirm|escalate|require|"
        r"disclose|tell|inform|log)\b")),
    ("supersession_claim", re.compile(
        r"\b(supersedes?|overrides?|replaces?)\s+(all\s+)?(prior|previous|"
        r"existing)\b")),
)

#: GAP-1 evasion register: phrasings the research predicts (and the
#: gap1mem battery red-teamed) that dodge the seven legacy patterns
#: while carrying an unambiguous behavioral directive. Reason tags are
#: prefixed ``evasion_`` so the quarantine taxonomy stays auditable.
#: Same conservative posture as the legacy set: these patterns only
#: ever screen untrusted-derived / unknown tiers (agent-tiered bytes
#: are never classified), so a wider net cannot touch the agent's own
#: notes; instructional untrusted notes quarantine and are
#: operator-releasable by design.
_MEMORY_EVASION_PATTERNS = (
    ("evasion_standing_instruction", re.compile(
        r"\bstanding\s+(instruction|directive|rule|policy|order)s?\b")),
    ("evasion_stored_directive", re.compile(
        r"\b(store|save|record|log|keep)\s+(this|that|the\s+following)\s+"
        r"(directive|instruction|rule|preference|policy)\b|"
        r"\bsave\s+this\s+as\s+a\s+(rule|directive|instruction)\b")),
    ("evasion_preference_directive", re.compile(
        r"\bremember\s+my\s+(preference|rule|instruction)s?\b")),
    ("evasion_workflow_rule", re.compile(
        r"\bworkflow\s+(rule|policy|directive)\b")),
    ("evasion_confirmation_waiver", re.compile(
        r"\b(no|without)\s+([a-z]+\s+)?(confirmation|approval|"
        r"escalation|review)\s+(is\s+|was\s+)?(not\s+)?(required|"
        r"needed|necessary)\b|"
        r"\b(confirmation|approval|escalation|review)\s+is\s+"
        r"(not\s+|un)?(required|needed|necessary)\b")),
)


def instruction_shaping_reason(text):
    """Reason tag when ``text`` is instruction-shaped for memory purposes,
    else None. Deterministic heuristics over the match copy; see the
    module docstring for the honest limits. Legacy patterns are checked
    first so their reason tags stay stable on content matching both."""
    if not isinstance(text, str) or not text.strip():
        return None
    probe = _match_copy(text)
    for reason, pattern in (_MEMORY_INSTRUCTION_PATTERNS
                            + _MEMORY_EVASION_PATTERNS):
        if pattern.search(probe):
            return reason
    return None


def _normalize_content(text):
    """Normalization for the verbatim-copy comparison: NFKC, invisible
    chars stripped, whitespace collapsed, lowercased -- the same match
    copy the shaping detector uses, so Cf-stuffed copies still match."""
    return _match_copy(text)


def _verbatim_untrusted_overlap(content, fingerprints,
                                min_chars=_VERBATIM_CHARS):
    """True when normalized ``content`` shares a verbatim substring of
    >= ``min_chars`` with any normalized fingerprint. Exact at every
    alignment: a shared >=min_chars substring exists iff some min_chars
    window of the SHORTER text appears in the longer, so windows slide
    over the shorter text one char at a time (no stride that could skip
    an unaligned copy)."""
    norm = _normalize_content(content)
    if len(norm) < min_chars:
        return False
    for fp in fingerprints:
        fp_norm = _normalize_content(fp)
        if len(fp_norm) < min_chars:
            continue
        if len(norm) <= len(fp_norm):
            hay, windows = fp_norm, norm
        else:
            hay, windows = norm, fp_norm
        for i in range(0, len(windows) - min_chars + 1):
            if windows[i:i + min_chars] in hay:
                return True
    return False


class MemoryLedger(EgressLedger):
    """Append-only HMAC-chained JSONL of memory-write provenance records.

    One ledger per deployment (NOT per run -- it must survive across
    sessions). Inherits seq chaining, checkpoints, file locking, and
    fail-closed reads from :class:`EgressLedger`; the entry ``kind`` is
    ``memory_write`` / ``memory_release`` so the two ledgers never share
    a file.
    """

    def record_write(self, principal, mem_key, content_sha256,
                     writer_agent_id, writer_run_id, trust_tier,
                     tainted_run, instruction_shaped,
                     instruction_reason=None, now=None):
        """Append one memory-write provenance record; returns it."""
        return self.append({
            "kind": "memory_write",
            "principal": principal,
            "mem_key": mem_key,
            "content_sha256": content_sha256,
            "writer_agent_id": writer_agent_id,
            "writer_run_id": writer_run_id,
            "trust_tier": trust_tier,
            "tainted_run": bool(tainted_run),
            "instruction_shaped": bool(instruction_shaped),
            "instruction_reason": instruction_reason,
            "ts": time.time() if now is None else now,
        })

    def record_release(self, principal, mem_key, content_sha256,
                       reviewer, review_note="", now=None):
        """Operator release after review: appends a superseding
        agent-tiered record bound to the REVIEWED bytes (content_sha256
        is required -- a release that does not name the bytes it blesses
        would let a later silent modification ride the blessing). The
        newest record for (principal, mem_key) wins, so this lifts
        quarantine for exactly those bytes; if the file changes
        afterwards the digest no longer matches and the bytes read as
        unknown."""
        return self.append({
            "kind": "memory_release",
            "principal": principal,
            "mem_key": mem_key,
            "content_sha256": content_sha256,
            "reviewer": reviewer,
            "review_note": review_note,
            "trust_tier": TRUST_TIER_AGENT,
            "instruction_shaped": False,
            "instruction_reason": None,
            "ts": time.time() if now is None else now,
        })

    def _scan(self, predicate):
        """All entries matching ``predicate``, oldest first, under the
        shared lock with verify-first (fail-closed like taint_active)."""
        if not self.path.exists():
            return []
        try:
            with _ledger_read_locked(self.path):
                self.require_verified()  # nested: reentrant under read hold
                out = []
                for line in self.path.read_text(
                        encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(entry, dict) and predicate(entry):
                        out.append(entry)
                return out
        except _LedgerMissing:
            return []

    def latest_entry(self, principal, mem_key):
        """Newest record for (principal, mem_key), or None. A tampered
        ledger raises LedgerUnverifiableError -- never reads as 'no
        provenance'."""
        hits = self._scan(
            lambda e: e.get("kind") in ("memory_write", "memory_release")
            and e.get("principal") == principal
            and e.get("mem_key") == mem_key)
        return hits[-1] if hits else None

    def flagged_entries(self, principal):
        """Untrusted, instruction-shaped write records for ``principal``
        -- the session-open scan surface (the January poison).

        Returns every historical flagged write; callers that need the
        CURRENT status of a key (e.g. ``scan_at_session_open``) must
        evaluate the newest record per (principal, mem_key) instead, so
        a later safe overwrite or operator release clears the flag."""
        return self._scan(
            lambda e: e.get("kind") == "memory_write"
            and e.get("principal") == principal
            and e.get("trust_tier") == TRUST_TIER_UNTRUSTED
            and e.get("instruction_shaped"))

    def records_for(self, principal):
        """All memory_write/memory_release records for ``principal``,
        oldest first, verify-first under the shared lock."""
        return self._scan(
            lambda e: e.get("kind") in ("memory_write", "memory_release")
            and e.get("principal") == principal)


class MemoryFirewall:
    """The firewall itself: path scoping, tier computation, read checks.

    Constructed by the deployment (opt-in) and passed to ToolExecutor as
    ``memory_firewall=``. All tier computation happens here; the executor
    only routes write_file/read_file events through it.
    """

    def __init__(self, ledger_path, memory_prefixes=None):
        self.ledger = MemoryLedger(ledger_path)
        self.memory_prefixes = tuple(
            memory_prefixes or _DEFAULT_MEMORY_PREFIXES)

    # -- path scoping -------------------------------------------------

    @staticmethod
    def _norm_path(raw_path):
        p = str(raw_path or "").replace("\\", "/").strip()
        while p.startswith("./"):
            p = p[2:]
        return p.lstrip("/")

    def mem_key_for(self, raw_path):
        """Normalized memory key for ``raw_path``, or None when the path
        is not a deployment-designated memory path. Callers pass the
        sandbox-relative form (the executor resolves ``write_file`` /
        ``read_file`` paths against the sandbox before calling here)."""
        norm = self._norm_path(raw_path)
        for prefix in self.memory_prefixes:
            if norm == prefix.rstrip("/") or norm.startswith(prefix):
                return norm
        return None

    # -- write path ----------------------------------------------------

    def tier_for_write(self, content, read_fingerprints):
        """Compute the trust tier for about-to-be-written memory bytes.
        The tier comes from the run's ingested tool-result fingerprints,
        never from a caller assertion."""
        if _verbatim_untrusted_overlap(content, read_fingerprints or ()):
            return TRUST_TIER_UNTRUSTED
        return TRUST_TIER_AGENT

    def record_memory_write(self, principal, mem_key, content,
                            writer_agent_id, writer_run_id,
                            read_fingerprints, tainted_run):
        """Tier, classify, and chain one memory write. Returns
        (record, tier, shaping_reason)."""
        tier = self.tier_for_write(content, read_fingerprints)
        reason = instruction_shaping_reason(content)
        record = self.ledger.record_write(
            principal=principal,
            mem_key=mem_key,
            content_sha256=hashlib.sha256(
                content.encode("utf-8")).hexdigest(),
            writer_agent_id=writer_agent_id,
            writer_run_id=writer_run_id,
            trust_tier=tier,
            tainted_run=tainted_run,
            instruction_shaped=reason is not None,
            instruction_reason=reason,
        )
        return record, tier, reason

    def seed_entry(self, principal, mem_key, content, reviewer,
                   review_note="pre-ledger memory blessed after review"):
        """Bless a pre-existing memory file (no ledger record yet) after
        human review. Records it agent-tiered with the content digest, so
        later reads verify instead of quarantining as unknown."""
        reason = instruction_shaping_reason(content)
        return self.ledger.record_write(
            principal=principal,
            mem_key=mem_key,
            content_sha256=hashlib.sha256(
                content.encode("utf-8")).hexdigest(),
            writer_agent_id=reviewer,
            writer_run_id="seed",
            trust_tier=TRUST_TIER_AGENT,
            tainted_run=False,
            instruction_shaped=reason is not None,
            instruction_reason=reason,
        )

    def release_entry(self, principal, mem_key, content, reviewer,
                      review_note=""):
        """Operator reversal of a quarantine: appends a superseding
        agent-tiered record bound to the reviewed ``content`` bytes.
        Chained and attributed; the digest binding means the blessing
        covers exactly the reviewed bytes."""
        return self.ledger.record_release(
            principal, mem_key,
            content_sha256=hashlib.sha256(
                content.encode("utf-8")).hexdigest(),
            reviewer=reviewer, review_note=review_note)

    # -- read path -----------------------------------------------------

    def check_memory_read(self, principal, mem_key, content):
        """Verdict for delivering ``content`` of ``mem_key`` to
        ``principal``: ``("allow", reason)`` or ``("quarantine",
        reason)``. Fail-closed: missing ledger entry or content-digest
        mismatch (file changed outside governance) reads as unknown, and
        unknown + instruction-shaped quarantines."""
        entry = self.ledger.latest_entry(principal, mem_key)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if entry is None:
            tier = TRUST_TIER_UNKNOWN
            tainted_run = False
        elif entry.get("content_sha256") != digest:
            # Changed outside governance after recording: the recorded
            # tier no longer describes these bytes.
            tier = TRUST_TIER_UNKNOWN
            tainted_run = False
        else:
            tier = entry.get("trust_tier") or TRUST_TIER_UNKNOWN
            # H17: the planting run's taint bit. A tainted run escalates:
            # agent-tiered bytes from a tainted run do NOT take the early
            # allow below; they face the instruction-shaping check like
            # any non-agent tier. (Releases/seeds record tainted_run=False
            # or omit it, so operator blessings are unaffected.)
            tainted_run = bool(entry.get("tainted_run"))
        if tier == TRUST_TIER_AGENT and not tainted_run:
            return "allow", "agent_tiered"
        shaping = instruction_shaping_reason(content)
        if shaping is not None:
            if tainted_run and tier == TRUST_TIER_AGENT:
                # H17 escalation: instruction-shaped content planted by a
                # tainted run quarantines even when tiered agent. The
                # tainted_run tag makes the escalation auditable; the FP
                # gate is that non-instruction-shaped tainted-run content
                # still reads clean (see evals/h17_tainted_run_escalation.py).
                # Non-agent tiers keep their existing {tier}:{shaping}
                # reason below (no behavior change there).
                return ("quarantine",
                        "tainted_run:%s" % shaping)
            return ("quarantine",
                    "%s:%s" % (tier, shaping))
        return "allow", "%s_not_instruction_shaped" % tier

    # -- session open --------------------------------------------------

    def scan_at_session_open(self, principal):
        """Ledger scan for untrusted, instruction-shaped entries from
        earlier sessions: ``[(mem_key, instruction_reason)]``. The
        January poison, flagged in June. Evaluates the NEWEST record per
        (principal, mem_key): a later safe overwrite or operator
        release clears the flag for that key."""
        latest = {}
        for e in self.ledger.records_for(principal):
            if e.get("mem_key") is not None:
                latest[e.get("mem_key")] = e
        out = []
        for mem_key, e in latest.items():
            if (e.get("kind") == "memory_write"
                    and e.get("trust_tier") == TRUST_TIER_UNTRUSTED
                    and e.get("instruction_shaped")):
                out.append((mem_key, e.get("instruction_reason")))
        return out
