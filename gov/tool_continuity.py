"""S5-stream (wave-89): tool-execution continuity.

Three controls closing the post-approval / trajectory gaps the attack
memo's Part D rows #7 (delayed execution), #9 (caution erosion), and
#14 (post-approval tool-definition swap) name:

1. ``ToolInventory`` — name -> (description, schema) with digest pinning.
   ``queue()`` stamps ``tool_digest`` (MAC-bound via
   ``_SECURITY_PAYLOAD_FIELDS``); the sweep re-verifies the digest against
   the inventory's CURRENT definition and refuses on drift
   (``tool_digest_mismatch``). Use-time drift against the last-seen
   definition quarantines the tool (fail-closed refuse +
   ``tool_quarantined`` chained event).

2. ``TrajectoryReverifier`` — every Nth call (default 50) chains a
   ``trajectory_reverified`` event and forces full gate re-verification
   (ledger re-verify + policy snapshot refresh). A risk-tier escalation
   (read < mutating < egress < irreversible) chains
   ``risk_tier_escalation``. Escalation never auto-downgrades
   allow -> require_approval (documented design choice: false-positive
   cost on legitimate trajectories; the suite is the judge).

3. ``scan_deferred_effect()`` — cron / schedule / run_at-shaped content in
   a call forces require_approval with the deferred nature surfaced in
   the preview and MAC-bound on the record (the intent-ledger entry).

Honest boundaries (not claimed):
- We cannot observe the model's INTERNAL caution decay — only
  behavioral correlates (trajectory length, tier escalation). The
  control is visibility + checkpointing, not mind-reading.
- A deferred trigger firing entirely OUTSIDE the governed tool surface
  is out of scope; our guarantee covers plants THROUGH the governed
  executor (made loud + approval-bound + ledgered).
- Digest pinning covers tool METADATA (name+description+schema).
  Built-in simulated tools' implementation bytes are in-process (no
  separate artifact to pin); MCP server-side implementation drift is the
  adapter's pinning domain (``GovenedMCPClient`` /
  ``MetadataChangedError``).
- The inventory's definitions are deployment-controlled data, like the
  policy: a provider that can rewrite the inventory out-of-band is
  already outside the threat model (same trust assumption as the
  policy file).
"""

import hashlib
import json
import re

# ---------------------------------------------------------------------------
# Risk tiers: read < mutating < egress < irreversible.
# ---------------------------------------------------------------------------

TIER_READ = 0
TIER_MUTATING = 1
TIER_EGRESS = 2
TIER_IRREVERSIBLE = 3

TIER_NAMES = {
    TIER_READ: "read",
    TIER_MUTATING: "mutating",
    TIER_EGRESS: "egress",
    TIER_IRREVERSIBLE: "irreversible",
}

# Coarse tiering from the executor's existing tool classes. api_call is
# egress-tier (it is in the executor's _EGRESS_TOOLS): an api_call to a
# read-only endpoint is over-tiered by design — coarse and loud beats
# precise and gameable.
_EGRESS_TOOLS = ("send_email", "http_post", "api_call")
_MUTATING_TOOLS = ("write_file", "delete_file")


def risk_tier_for(tool, irreversible_tools=()):
    """Return the risk tier (0-3) for a tool name."""
    if tool in (irreversible_tools or ()):
        return TIER_IRREVERSIBLE
    if tool in _EGRESS_TOOLS:
        return TIER_EGRESS
    if tool in _MUTATING_TOOLS:
        return TIER_MUTATING
    return TIER_READ


# ---------------------------------------------------------------------------
# Tool inventory: digest-pinned tool definitions.
# ---------------------------------------------------------------------------

def tool_definition_digest(name, description=None, schema=None):
    """Hex digest pinning a tool's name + description + input schema.

    Same shape as the MCP adapter's ``metadata_hash`` (sha256 over the
    canonical name/description/schema triple) so adapter-pinned metadata
    and executor-pinned metadata are comparable byte-for-byte.
    """
    if isinstance(name, dict):
        entry = name
        name = entry.get("name")
        description = entry.get("description")
        schema = entry.get("inputSchema", entry.get("schema"))
    payload = json.dumps(
        {"name": name, "description": description or "",
         "schema": schema or {}},
        sort_keys=True, separators=(",", ":"), default=str,
        ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# Canonical in-process descriptions for the built-in simulated tools.
# These are the deployment's pinned notion of what each tool IS; a
# provider-side redefinition is drift by definition.
BUILTIN_TOOL_DEFINITIONS = {
    "read_file": {
        "description": "Read a file inside the run sandbox; returns content.",
        "schema": {"path": "string"},
    },
    "write_file": {
        "description": "Write content to a file inside the run sandbox.",
        "schema": {"path": "string", "content": "string"},
    },
    "delete_file": {
        "description": "Delete a file inside the run sandbox.",
        "schema": {"path": "string"},
    },
    "api_call": {
        "description": "Call an external HTTP API endpoint.",
        "schema": {"endpoint": "string", "method": "string",
                   "params": "object"},
    },
    "http_post": {
        "description": "POST a payload to an external URL.",
        "schema": {"url": "string", "payload": "object"},
    },
    "send_email": {
        "description": "Send an email to a recipient.",
        "schema": {"to": "string", "subject": "string", "body": "string"},
    },
    "install_package": {
        "description": "Install a package from the governed registry.",
        "schema": {"package": "string", "version": "string"},
    },
}


class ToolInventory:
    """Digest-pinned registry of tool definitions.

    ``definitions`` maps tool name -> {"description", "schema"}. When
    ``provider`` is given it is re-queried on every digest computation,
    so a provider-side redefinition is observable as digest drift
    (the MCP rug-pull shape). The default provider serves the static
    built-in table: built-in digests are stable, so no false drift.

    ``strict`` (default False) switches the trust anchor from
    trust-on-first-use to deployment-declared. In default mode the
    first provider bytes seen become the baseline (``_last_seen``): a
    hostile provider that serves poisoned bytes from the very first
    observation gets its poison pinned as "unchanged", and honest bytes
    served later read as drift (baseline inversion -- pinned red by
    ``evals/mcp_description_drift_probes.py`` p2). In strict mode the
    ``definitions`` table is the anchor: provider bytes are compared
    against the deployment digest on every call, a poisoned first
    sighting is refused at once, and tools the deployment never
    declared are denied without pinning (default-deny). Quarantine in
    strict mode clears only via explicit ``pin()`` -- the deployment's
    reviewed re-declaration workflow. Strict mode is purely opt-in:
    ``strict=False`` preserves the historical behavior byte-for-byte.
    """

    def __init__(self, definitions=None, provider=None, strict=False):
        self._definitions = dict(definitions if definitions is not None
                                 else BUILTIN_TOOL_DEFINITIONS)
        self._provider = provider
        self._strict = bool(strict)
        self._last_seen = {}  # tool -> digest, for use-time drift detection
        self._quarantined = set()

    def definition_for(self, tool):
        if self._provider is not None:
            try:
                return self._provider(tool)
            except Exception:  # noqa: BLE001 - provider failure reads as
                return None    # absent, never as "unchanged"
        return self._definitions.get(tool)

    def digest_for(self, tool):
        """Current pinned digest for a tool, or None when unregistered."""
        definition = self.definition_for(tool)
        if not isinstance(definition, dict):
            return None
        return tool_definition_digest(
            tool, definition.get("description"),
            definition.get("schema"))

    def anchor_digest_for(self, tool):
        """Deployment-declared digest for a tool.

        Reads ONLY the deployment's ``definitions`` table -- never the
        provider -- so it is a trust anchor even when the provider is
        hostile from first contact. Returns None when the deployment
        table declares nothing for the tool.
        """
        definition = self._definitions.get(tool)
        if not isinstance(definition, dict):
            return None
        return tool_definition_digest(
            tool, definition.get("description"),
            definition.get("schema"))

    def pin(self, tool, description, schema):
        """Deployment re-pinning after a reviewed definition change."""
        self._definitions[tool] = {"description": description,
                                   "schema": schema}
        self._last_seen.pop(tool, None)
        self._quarantined.discard(tool)

    def is_quarantined(self, tool):
        return tool in self._quarantined

    def verify_at_use(self, tool):
        """Use-time drift check.

        Returns (ok, previous_digest, current_digest). The first sighting
        pins last_seen. A changed digest quarantines the tool
        (fail-closed at the call site). A previously-pinned tool whose
        definition source now FAILS also quarantines fail-closed: waving
        it through would let a definition swap hide behind a provider
        outage. Tools never pinned return ok=True — the policy's own
        unknown-tool handling decides those; the inventory refuses to
        invent a refusal for a tool it never pinned.

        In strict mode the comparison is against the deployment anchor
        (``anchor_digest_for``), never against first-observed bytes;
        see ``_verify_strict``.
        """
        if tool in self._quarantined:
            return False, self._last_seen.get(tool), self.digest_for(tool)
        current = self.digest_for(tool)
        if self._strict:
            return self._verify_strict(tool, current)
        previous = self._last_seen.get(tool)
        if current is None:
            if previous is not None:
                self._quarantined.add(tool)
                return False, previous, None
            return True, None, None
        if previous is None:
            self._last_seen[tool] = current
            return True, None, current
        if previous != current:
            self._quarantined.add(tool)
            return False, previous, current
        return True, previous, current

    def _verify_strict(self, tool, current):
        """Strict-mode use-time check: deployment anchor, never TOFU.

        ``current`` is the provider's present digest (already computed
        by the caller). The provider's bytes are compared against the
        deployment table's digest: a hostile first sighting cannot
        become the baseline because first sighting is never trusted.
        A tool the deployment table never declared is denied WITHOUT
        pinning (default-deny -- no trust-on-first-use). A declared
        tool the provider cannot currently serve is quarantined
        fail-closed (a definition swap must not hide behind a provider
        outage -- same idiom as the default mode). Quarantine clears
        only via explicit ``pin()``, the deployment's reviewed
        re-declaration workflow (which also moves the anchor).
        """
        anchor = self.anchor_digest_for(tool)
        if anchor is None:
            # Undeclared in strict mode: refuse to TOFU-pin. Not added
            # to _quarantined (nothing drifted); the denial itself is
            # the control, and pin() is the declaration path.
            return False, None, current
        if current is None:
            self._quarantined.add(tool)
            return False, anchor, None
        if current != anchor:
            self._quarantined.add(tool)
            return False, anchor, current
        return True, anchor, current


# ---------------------------------------------------------------------------
# Trajectory re-verifier: checkpoints + tier-escalation markers.
# ---------------------------------------------------------------------------

class TrajectoryReverifier:
    """Counts calls through the gate; reports when a checkpoint is due or
    the risk tier escalated.

    ``note_call`` returns (checkpoint_due, escalated, previous_tier).
    checkpoint_every=0/None disables periodic checkpoints (tier
    escalation markers still fire — they are cheap and always on).
    """

    def __init__(self, checkpoint_every=50):
        self.checkpoint_every = checkpoint_every or 0
        self.calls = 0
        self.max_tier = TIER_READ

    def note_call(self, tier):
        self.calls += 1
        escalated = tier > self.max_tier
        previous_tier = self.max_tier
        if escalated:
            self.max_tier = tier
        due = bool(self.checkpoint_every
                   and self.calls % self.checkpoint_every == 0)
        return due, escalated, previous_tier


# ---------------------------------------------------------------------------
# Deferred-effect scanner: plant-now/harm-later markers.
# ---------------------------------------------------------------------------

# Argument keys that carry deferred-execution semantics. Matched
# case-insensitively against the call's kwarg names; a non-empty value
# is a hit. Deliberately narrow: "path" containing the substring
# "cron" is NOT a hit (see w23 probe: a symlink named cron_link must
# keep its existing verdict).
_DEFERRED_ARG_KEYS = frozenset({
    "cron", "cron_expression", "crontab", "schedule", "scheduled_for",
    "run_at", "execute_at", "trigger_at", "not_before", "delay_seconds",
    "activate_after", "activates_at", "valid_after", "start_at",
})

# Five-field cron shape (minute hour dom month dow). Crude on purpose:
# the scanner forces human review, it does not prove schedulability.
# _CRON_LINE_RE: a bare crontab-style line (the whole line IS the
# schedule — inherently deferred, no trigger word needed).
_CRON_LINE_RE = re.compile(
    r"^\s*([*\/\d,\-]+)\s+([*\/\d,\-]+)\s+([*\/\d,\-]+)\s+"
    r"([*\/\d,\-]+)\s+([*\/\d,\-]+)\s+\S")
# _CRON_ANYWHERE_RE: a cron shape embedded after a config key, e.g.
# `cron: "0 3 * * *"`. Only consulted on lines that ALSO carry a
# trigger word (below) — "1 2 3 4 5" in chatty prose is not a hit.
_CRON_ANYWHERE_RE = re.compile(
    r"([*\/\d,\-]+)\s+([*\/\d,\-]+)\s+([*\/\d,\-]+)\s+"
    r"([*\/\d,\-]+)\s+([*\/\d,\-]+)")

# Future-dated ISO timestamps in trigger-adjacent prose.
_FUTURE_ISO_RE = re.compile(
    r"\b(20[2-9]\d)-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])"
    r"[T ]([01]\d|2[0-3]):[0-5]\d")

# Trigger words that, adjacent to a cron shape or a future timestamp on
# the SAME line, mark plant-now/harm-later intent. Deliberately excludes
# bare "at" ("meeting at 10:00" is not a logic bomb) and matches
# "cron_link" as no word at all (\b between n and _ fails).
_TRIGGER_WORD_RE = re.compile(
    r"(?i)\b(cron|crontab|schedule[dr]?|run[-_ ]?at|execute[-_ ]?at|"
    r"trigger[-_ ]?at|not[-_ ]?before|delay|defer|activat\w*|every)\b")


def _fingerprint(fragment):
    """Stable correlation handle for a matched trigger fragment.

    SHA-256 over the matched fragment only (never the whole raw value,
    never stored alongside the value). Lets an auditor correlate the
    SAME planted trigger across runs and records without the record
    carrying the content. Caveat, stated honestly: a low-entropy trigger
    fragment is confirmable by guessing against this digest. That is
    strictly less exposure than the pre-fix behavior (the raw fragment
    sat verbatim in the audit log and the MAC-bound approval record),
    but it is not zero — treat the digest as a correlation handle, not
    as a secret, and never as a substitute for redaction.
    """
    return hashlib.sha256(fragment.encode("utf-8", "replace")).hexdigest()


def _string_hits(text, source):
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if _CRON_LINE_RE.match(line):
            # A bare crontab line is self-evidently a schedule. The
            # record carries shape/position/fingerprint — never the
            # line itself (it may embed commands, paths, credentials).
            frag = line.strip()
            hits.append({"source": source, "kind": "cron_expression",
                         "descriptor": {"shape": "cron_line",
                                        "line": lineno,
                                        "match_len": len(frag),
                                        "match_sha256": _fingerprint(frag)}})
            continue
        if not _TRIGGER_WORD_RE.search(line):
            continue
        m = _CRON_ANYWHERE_RE.search(line)
        if m:
            frag = m.group(0).strip()
            hits.append({"source": source, "kind": "cron_expression",
                         "descriptor": {"shape": "cron_embedded",
                                        "line": lineno,
                                        "match_len": len(frag),
                                        "match_sha256": _fingerprint(frag)}})
        m2 = _FUTURE_ISO_RE.search(line)
        if m2:
            frag = m2.group(0)
            hits.append({"source": source, "kind": "future_timestamp",
                         "descriptor": {"shape": "future_iso",
                                        "line": lineno,
                                        "match_len": len(frag),
                                        "match_sha256": _fingerprint(frag)}})
    return hits


def _trigger_sig(trigger):
    """Dedup signature: identical trigger fragments collapse, distinct
    fragments stay distinct — same semantics as the old
    (source, kind, value) triple, without carrying the value."""
    d = trigger["descriptor"]
    return (trigger["source"], trigger["kind"], d["shape"],
            d.get("line"),
            d.get("match_len", d.get("value_len")),
            d.get("match_sha256", d.get("value_sha256")))


def scan_deferred_effect(tool, kwargs):
    """Scan a tool call for deferred-effect (plant-now/harm-later) markers.

    Returns a details dict ``{"triggers": [...]}`` on a hit, else None.
    Scans (a) kwarg NAMES against the deferred-arg key set — a non-empty
    value is a hit; (b) string kwarg VALUES line by line: a bare
    crontab-style line is a hit on its own, and a line carrying a
    trigger word (cron, schedule, run_at, delay, ...) adjacent to a
    cron shape or a future ISO timestamp is a hit. Never scans the
    tool name or unrelated substrings: a file literally named
    "cron_link" is not a hit, and "meeting at 10:00" is not a hit.

    Output contract (wave-90, S8): the scan runs on the RAW kwargs —
    redaction must not get a chance to destroy trigger evidence before
    detection — but each trigger carries a structured DESCRIPTOR
    (shape/position/fingerprint), never a raw value. The audit log and
    the MAC-bound approval record therefore attest to WHAT kind of
    trigger was planted, WHERE, and a correlation fingerprint, without
    becoming a second store for the payload itself. The human reviewer
    still sees the redacted call args in the approval preview; the
    retained evidence does not.
    """
    triggers = []
    for key, value in (kwargs or {}).items():
        if str(key).lower() in _DEFERRED_ARG_KEYS \
                and value not in (None, "", 0, 0.0, False):
            # The trigger here is the ARG NAME; the value is arbitrary
            # content. Record its length and fingerprint, not itself.
            sval = str(value)
            triggers.append({"source": "arg:%s" % key,
                             "kind": "deferred_arg",
                             "descriptor": {"shape": "deferred_arg_name",
                                            "value_len": len(sval),
                                            "value_sha256": _fingerprint(sval)}})
        if isinstance(value, str) and len(value) <= 65536:
            triggers.extend(_string_hits(value, "arg:%s" % key))
    if triggers:
        # De-duplicate identical trigger signatures.
        seen = set()
        uniq = []
        for t in triggers:
            sig = _trigger_sig(t)
            if sig not in seen:
                seen.add(sig)
                uniq.append(t)
        return {"tool": tool, "triggers": uniq}
    return None


def deferred_preview_banner(deferred):
    """One-line human-facing banner describing the deferred nature."""
    kinds = sorted({t["kind"] for t in deferred["triggers"]})
    return ("DEFERRED-EFFECT: this action plants a trigger that fires "
            "later (%s). Review WHEN it fires, not just WHAT it does."
            % ", ".join(kinds))
