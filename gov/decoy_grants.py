"""Decoy grants -- honeypot tool/grant canaries (wave-276).

Pattern source (STEAL verdict, wave-275 prospectus): mthamil107/prompt-shield
d034 "honeypot tool detector" (Apache-2.0, LICENSE verified from the repo).
This module is a clean-room reimplementation against Sasanam's tool_grant
seams: no prompt-shield code is copied, vendored, or imported. Only the
*detection pattern* is adapted:

- register fake tools with attractive names alongside real tools;
- any invocation is high-confidence evidence of prompt injection;
- two firing modes: text-mention (0.95) and context-invocation (1.0).

Mapping onto Sasanam: decoy tools are registered in a DecoyRegistry that
the deployment hands to the tool_grant enforcement seam. A decoy is never
covered by any grant and the issuer never mints grants for decoy
identifiers, so a decoy invocation can only arrive via a coerced /
injected agent. The enforcement seam denies with the coded verdict
``decoy-grant-tripped`` (fail closed) and attaches an injection-evidence
event for the gateway's audit writer -- the "sell evidence, not the
engine" shape: the trip IS the evidence bundle's seed.

Text-mention matching discipline (adapted from d034's word-boundary
rule): matching runs on normalized text (NFKC, casefold, homoglyph fold,
separator-tolerant token patterns) with ``\\b`` word boundaries, so
``admin_shell`` matches "call ADMIN-SHELL" and "the admin shell" but not
``xadmin_shell``. Homoglyph folding uses a small curated table for Latin
tool-name characters only (documented below); it is deterministic and
total -- never raises on hostile input.

Deliberately NOT adapted: prompt-shield d028's Smith-Waterman
synonym-matrix alignment. That algorithm's discriminative power comes
from aligning multi-token attack sequences; decoy needles are 1-3 tokens,
where the synonym matrix would be hand-curated arbitrariness with real
false-positive risk at the 0.95 operating point. The normalized
token-subsequence matcher here covers the realistic paraphrase shapes
(separators, spacing, padding, homoglyphs) deterministically. SW-with-
synonyms is recorded as a residual, not a gap: if deployments need
reordered-synonym coverage ("console debug internal"), that is a new
detector with its own FPR operating-point report.

Determinism: no ambient clock, no randomness; compiled regexes are built
once at registry construction. Every public function is total on
hostile input (non-string inputs -> no hit, never raise).
"""

import re
import unicodedata

# ---------------------------------------------------------------------------
# Firing-mode confidences (d034's discipline, kept verbatim as constants)
# ---------------------------------------------------------------------------

CONFIDENCE_TEXT_MENTION = 0.95
CONFIDENCE_INVOCATION = 1.0

# Coded verdicts (taxonomy domain: tool_grant).
DECOY_TRIP_CODE = "decoy-grant-tripped"
DECOY_MINT_REFUSAL_CODE = "decoy-grant-not-issuable"

# Default decoy tool names: attractive to an injected instruction, never
# part of a legitimate workflow. Deployments SHOULD extend this list with
# their own deployment-specific trap names (d034's operator guidance).
DEFAULT_DECOY_TOOLS = (
    "admin_shell",
    "internal_debug_console",
    "system_key_dump",
    "sudo_execute_raw",
    "priv_esc_helper",
    "root_command_proxy",
)

# Homoglyph fold table: Latin lookalikes that appear in tool-name
# paraphrases. Applied AFTER NFKC + casefold. Deliberately small and
# documented; each entry is a single visually-confounded character.
_HOMOGLYPH_FOLD = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
}

# Separators tolerated between a decoy name's tokens: whitespace,
# underscore, hyphen, in any run (covers "admin shell", "admin-shell",
# "adminshell", "admin__shell").
_SEPARATOR_RUN = r"[\s_\-]*"


def _normalize(text):
    """NFKC + casefold + homoglyph fold. Total: non-string -> ""."""
    if not isinstance(text, str):
        return ""
    folded = unicodedata.normalize("NFKC", text).casefold()
    return "".join(_HOMOGLYPH_FOLD.get(ch, ch) for ch in folded)


def _compile_mention_pattern(name):
    """Word-bounded, separator-tolerant pattern for one decoy name.

    ``internal_debug_console`` becomes
    ``\\binternal[\\s_\\-]*debug[\\s_\\-]*console\\b`` on normalized text.
    """
    tokens = [t for t in re.split(r"[_\s\-]+", _normalize(name)) if t]
    if not tokens:
        return None
    body = _SEPARATOR_RUN.join(re.escape(t) for t in tokens)
    return re.compile(r"\b(?:%s)\b" % body)


class DecoyRegistry:
    """Deployment-configured set of decoy (honeypot) tools.

    ``names``: bare tool names (``admin_shell``) and/or server-scoped
    forms (``fileserver::admin_shell``). Matching is case-insensitive.
    A registry with no names matches nothing (fail-closed direction:
    no decoys configured -> no trips, never a false trip).
    """

    def __init__(self, names=None):
        raw = DEFAULT_DECOY_TOOLS if names is None else tuple(names)
        bare = []
        scoped = []
        seen = set()
        for n in raw:
            if not isinstance(n, str) or not n.strip():
                continue
            norm = _normalize(n.strip())
            if not norm or norm in seen:
                continue
            seen.add(norm)
            if "::" in norm:
                scoped.append(norm)
            else:
                bare.append(norm)
        self._bare = tuple(bare)
        self._scoped = frozenset(scoped)
        self._lookup = frozenset(bare)
        self._patterns = tuple(
            (name, _compile_mention_pattern(name)) for name in bare)
        # Scoped forms also contribute their tool half to text mentions:
        # "fileserver::admin_shell" as a decoy still trips on "admin_shell".
        for s in scoped:
            tool_half = s.split("::", 1)[1]
            if tool_half and tool_half not in self._lookup:
                pat = _compile_mention_pattern(tool_half)
                if pat is not None:
                    self._patterns += ((tool_half, pat),)

    @property
    def names(self):
        """Configured decoy names (normalized)."""
        return self._bare + tuple(sorted(self._scoped))

    def _match(self, server_name, tool):
        """Normalized decoy name (or scoped identifier) or None.

        Shared by is_decoy() and check_invocation(); total on hostile
        input (non-string tool -> None, never raises).
        """
        if not isinstance(tool, str):
            return None
        norm_tool = _normalize(tool)
        if norm_tool in self._lookup:
            return norm_tool
        if isinstance(server_name, str):
            ident = "%s::%s" % (_normalize(server_name), norm_tool)
            if ident in self._scoped:
                return ident
        return None

    def is_decoy(self, server_name, tool):
        """True iff (server_name, tool) names a registered decoy.

        Total on hostile input: non-string tool/server -> False.
        """
        return self._match(server_name, tool) is not None

    def is_decoy_identifier(self, identifier):
        """True iff a ``server::tool`` identifier names a registered decoy."""
        if not isinstance(identifier, str) or "::" not in identifier:
            return False
        server, _, tool = identifier.partition("::")
        return self.is_decoy(server, tool)

    def check_invocation(self, server_name, tool):
        """Context-invocation mode (confidence 1.0).

        Returns a trip dict when the invoked tool is a decoy, else None.
        """
        hit = self._match(server_name, tool)
        if hit is None:
            return None
        return {
            "mode": "context_invocation",
            "confidence": CONFIDENCE_INVOCATION,
            "name": hit,
            "invoked_as": tool,
        }

    def scan_text(self, text):
        """Text-mention mode (confidence 0.95).

        Returns a list of hit dicts (deduplicated by decoy name, in
        first-mention order). Positions are character offsets in the
        *normalized* text. Non-string input -> [].
        """
        if not isinstance(text, str) or not text:
            return []
        normed = _normalize(text)
        hits = []
        seen = set()
        for name, pat in self._patterns:
            if pat is None or name in seen:
                continue
            m = pat.search(normed)
            if m is not None:
                seen.add(name)
                hits.append({
                    "mode": "text_mention",
                    "confidence": CONFIDENCE_TEXT_MENTION,
                    "name": name,
                    "position": (m.start(), m.end()),
                })
        return hits


def trip_event(trip, *, server_name, tool, grant_jti):
    """Build the injection-evidence event attached to a decoy verdict.

    The event is JSON-serializable and carries everything the gateway's
    audit writer needs: what tripped, how (mode/confidence), the
    invocation material, and the grant under evaluation. ``grant_jti``
    may be None when the grant itself was malformed. A None/invalid
    ``trip`` yields an event with null trip fields rather than raising
    (total on hostile input, like the rest of this module).
    """
    trip = trip if isinstance(trip, dict) else {}
    return {
        "event": "decoy_trip",
        "code": DECOY_TRIP_CODE,
        "mode": trip.get("mode"),
        "confidence": trip.get("confidence"),
        "decoy": trip.get("name"),
        "server": server_name if isinstance(server_name, str) else None,
        "invoked_tool": tool if isinstance(tool, str) else None,
        "grant_jti": grant_jti,
    }


# ---------------------------------------------------------------------------
# Trip fatigue tracking (ADAPT from prompt-shield's fatigue tracker)
# ---------------------------------------------------------------------------
# Pattern source: prompt-shield's fatigue tracker (Apache-2.0, pattern
# only, clean-room reimplementation). Detector firewalls drown operators
# in repeat alerts; the CISO complaint is alert fatigue, and a
# compromised agent tripping one decoy in a loop can flood the
# hash-chained audit log (a log-DoS riding the canary).
#
# Discipline, stated absolutely: the tracker NEVER suppresses the
# denial. Every decoy invocation still fails closed at the enforcement
# seam. It only compacts audit *volume*: the first
# ``full_events_per_window`` trips per (decoy, agent_key) in a window
# produce full events; further trips in the same window produce compact
# summary events carrying the suppressed count. No evidence is lost --
# only compacted -- and the denial is never gated on the tracker.
#
# The tracker is NOT consulted by enforce(): the seam always attaches the
# full event, and the gateway's audit writer consults the tracker before
# writing (deployment integration; the writer owns the audit-volume
# decision). ``agent_key`` is caller-supplied (e.g. the grant's ``sub``);
# the tracker never mints identities. ``now`` is explicit (determinism).
# The store is bounded (oldest-touched eviction).


def _tracker_key(value):
    """Hashable, deterministic key component. Total on hostile input."""
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    return repr(value)


class TripFatigueTracker:
    """Bounded per-(decoy, agent) trip accounting for audit-volume control."""

    def __init__(self, *, window_s=300, full_events_per_window=5,
                 max_keys=1024):
        for name, val in (("window_s", window_s),
                          ("full_events_per_window", full_events_per_window),
                          ("max_keys", max_keys)):
            if (not isinstance(val, int) or isinstance(val, bool)
                    or val < 1):
                raise ValueError("%s must be a positive int" % (name,))
        self._window_s = window_s
        self._full_per_window = full_events_per_window
        self._max_keys = max_keys
        # key -> [window_id, count, last_touched_now]
        self._store = {}

    def note_trip(self, *, decoy, agent_key, now):
        """Record one trip. Returns an accounting dict.

        ``{"emit_full": bool, "window_count": int, "suppressed": int}``:
        ``emit_full`` True for the first ``full_events_per_window``
        trips in the window (gateway writes the full event); False
        afterwards (gateway writes a compact summary carrying
        ``suppressed``). ``window_count`` is the trip count in the
        current window. Total on hostile input (keys coerced; a
        non-int ``now`` starts a fresh window rather than raising).
        """
        key = (_tracker_key(decoy), _tracker_key(agent_key))
        window = now // self._window_s if isinstance(now, int) \
            and not isinstance(now, bool) else None
        rec = self._store.get(key)
        if rec is None or rec[0] != window:
            if rec is None and len(self._store) >= self._max_keys:
                # Bounded store: evict the oldest-touched entry.
                oldest = min(self._store.items(),
                             key=lambda kv: kv[1][2])[0]
                del self._store[oldest]
            rec = [window, 0, now]
            self._store[key] = rec
        rec[1] += 1
        rec[2] = now
        count = rec[1]
        if count <= self._full_per_window:
            return {"emit_full": True, "window_count": count,
                    "suppressed": 0}
        return {"emit_full": False, "window_count": count,
                "suppressed": count - self._full_per_window}
