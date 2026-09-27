"""Cross-run argument-distribution (framing) drift detection (row 9).

Row 9's remaining cross-run residual after wave-131's ``gov.drift``:
the tool-count detector is blind to *framing* drift. The agent keeps
calling the same tools at the same rate, but the ARGUMENTS shift --
``http_post`` destinations rotate from vendor APIs to personal
inboxes, ``write_file`` targets move from log dirs to credential
dirs, ``send_email`` recipients change domains. ``gov.drift``'s
chi-square over tool counts sees identical distributions and stays
silent (probe d1 in ``evals/framing_probes.py`` demonstrates this
against the real ``gov.drift`` seam).

This module tracks per-tool ARGUMENT distributions, one fingerprint
per run per agent/principal:

  - ``http_post`` / ``api_call`` -> destination host (from ``url`` /
    ``endpoint``)
  - ``write_file``              -> top-level path prefix (from ``path``)
  - ``send_email``              -> recipient domain (from ``to``)

and compares the recent window against the agent's own baseline with
the same chi-square machinery as ``gov.drift`` (``chi_square_sf`` is
reused, not reinvented). A shift is *substitutive* (old destinations
abandoned -> strong) or *additive* (old destinations retained, new
ones added -> capped at weak, the novel-adoption analog of
``gov.drift``'s novel-tool cap).

The response is graduated, never a binary block -- the same contract
as ``gov.drift``: SILENT -> WATCH (a chained audit event) -> WARN
(LOUD audit event for the operator) -> HOLD (a ``framing_review``
approval is queued for human resolution; the run is never
auto-denied by this layer).

Honest ceilings (documented, not hidden):
- Change, not badness. An agent that posts to attacker-controlled
  hosts from run 1 poisons its baseline and never drifts -- the same
  ceiling as ``gov.drift`` p4. Cross-run *badness* without *change*
  is out of scope.
- Slow-enough drift under the statistical thresholds is invisible by
  design: a gradual destination rotation that keeps old destinations
  present reads as additive adoption (capped at weak) until the old
  destinations are abandoned.
- Content-level framing is invisible. Same destination, different
  payload meaning cannot be seen without reading payloads -- and the
  store deliberately never holds payloads, full URLs, full paths, or
  message bodies (privacy boundary, same posture as ``gov.drift``).
  The row-9 e4 within-run semantic residual (16 writes with shifting
  prose framing) is OUT OF SCOPE: this module must stay silent on it
  (probe d2 pins this).
- Argument extraction is routing metadata only: destination host,
  recipient domain, top-level path prefix. Entries whose routing
  field is missing (redacted away) are skipped, never guessed.

Privacy: the store holds argument-distribution counts, never raw
prompts, payloads, tool outputs, or log contents. Treat the store
directory as sensitive operational data (same posture as the audit
logs and the drift store).

$0, stdlib only, deterministic. All statistics are exact
deterministic computations (no sampling, no RNG). Fingerprint
validation is fail-closed: negative counts or untracked tools raise
ValueError rather than being silently accepted.
"""

from collections import Counter
from pathlib import Path

from gov.drift import chi_square_sf

__all__ = [
    "FramingFingerprint",
    "FramingStore",
    "FramingSignal",
    "FramingResult",
    "detect_framing",
    "framing_fingerprint_from_entries",
    "default_store_dir",
]

_FRAMING_VERSION = 1

# Minimum per-tool call mass for the chi-square signal: tiny
# denominators make the test meaningless (FP risk). Same value as
# gov.drift's _MIN_TOOL_CALLS_FOR_CHISQ, for the same reason.
_MIN_CALLS_FOR_ARG_CHISQ = 20

# Substitutive-vs-additive discriminator: the baseline mass sitting in
# categories the window abandoned (vanished entirely) or shrunk to
# under this fraction of their baseline share. Above 0.5 the agent
# abandoned its old destinations -> the shift may be strong. At or
# below, old destinations are essentially retained -> additive
# adoption, capped at weak (the novel-adoption analog).
_SHRINK_FRACTION = 0.2
_SUBSTITUTIVE_MASS = 0.5

# Decisions that mean "the call never became an attempt": excluded
# from argument fingerprints. Everything else (allowed_executed,
# approved_executed, queued, require_approval, entries without a
# decision field) counts as an attempt the agent made.
_NON_ATTEMPT_DECISIONS = frozenset({
    "denied", "refused", "velocity_paused", "velocity_check_failed",
})


# ------------------------------------------------- argument extraction

def _norm_host(url):
    """Destination host from a URL/endpoint: lowercase, no scheme,
    port, userinfo, path, or leading www. Returns None when the value
    is missing or unparseable (never guessed)."""
    if not isinstance(url, str):
        return None
    u = url.strip().lower()
    if not u:
        return None
    if "://" in u:
        u = u.split("://", 1)[1]
    u = u.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in u:  # userinfo@host
        u = u.rsplit("@", 1)[1]
    u = u.split(":", 1)[0].strip()
    if u.startswith("www."):
        u = u[4:]
    return u or None


def _norm_domain(to):
    """Recipient domain from a ``to`` field (str or list): lowercase
    domain of the first address. Returns None when unparseable."""
    addrs = to if isinstance(to, list) else [to]
    for addr in addrs:
        if not isinstance(addr, str):
            continue
        a = addr.strip().lower()
        if "@" not in a:
            continue
        dom = a.rsplit("@", 1)[1].strip().split(">", 1)[0]
        if dom:
            return dom
    return None


def _norm_prefix(path):
    """Top-level path prefix: first component only, lowercased.
    Never the full path (filenames can carry sensitive data)."""
    if not isinstance(path, str):
        return None
    p = path.strip().lstrip("/")
    if not p:
        return None
    first = p.split("/", 1)[0].strip().lower()
    return first or None


# tool -> (args key, normalizer)
_ARG_EXTRACTORS = {
    "http_post": ("url", _norm_host),
    "api_call": ("endpoint", _norm_host),
    "write_file": ("path", _norm_prefix),
    "send_email": ("to", _norm_domain),
}
_TRACKED_TOOLS = tuple(_ARG_EXTRACTORS)


def _check_arg_counts(arg_counts):
    if not isinstance(arg_counts, dict):
        raise ValueError("arg_counts must be a dict, got %r" % (arg_counts,))
    out = {}
    for tool, cats in arg_counts.items():
        if tool not in _ARG_EXTRACTORS:
            raise ValueError("untracked tool %r: tracked tools are %s"
                             % (tool, ", ".join(_TRACKED_TOOLS)))
        if not isinstance(cats, dict):
            raise ValueError("arg_counts[%r] must be a dict, got %r"
                             % (tool, cats))
        clean = {}
        for cat, n in cats.items():
            if not isinstance(cat, str) or not cat:
                raise ValueError("arg_counts[%r] keys must be non-empty "
                                 "strings, got %r" % (tool, cat))
            if not isinstance(n, int) or n < 0:
                raise ValueError("arg_counts[%r][%r] must be a "
                                 "non-negative int, got %r"
                                 % (tool, cat, n))
            if n:
                clean[cat] = n
        out[tool] = clean
    return out


class FramingFingerprint:
    """Per-run argument-distribution fingerprint.

    ``arg_counts`` maps tracked tool -> {argument category -> count},
    e.g. ``{"http_post": {"vendor.example": 20}}``. Routing metadata
    only (hosts, domains, top-level path prefixes) -- never payloads,
    full URLs, full paths, or message bodies.
    """

    __slots__ = ("arg_counts", "run_seq", "run_id")

    def __init__(self, arg_counts, run_seq=0, run_id=""):
        self.arg_counts = _check_arg_counts(arg_counts)
        if not isinstance(run_seq, int) or run_seq < 0:
            raise ValueError("run_seq must be a non-negative int, got %r"
                             % (run_seq,))
        self.run_seq = run_seq
        self.run_id = str(run_id)

    def to_dict(self):
        return {
            "arg_counts": {t: dict(c)
                           for t, c in self.arg_counts.items()},
            "run_seq": self.run_seq,
            "run_id": self.run_id,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            arg_counts=d.get("arg_counts", {}),
            run_seq=d.get("run_seq", 0),
            run_id=d.get("run_id", ""),
        )


def framing_fingerprint_from_entries(entries):
    """Fold raw audit-log entries into a FramingFingerprint
    (documented heuristic).

    Recognized: ``event == "tool_call"`` for a tracked tool, with a
    decision that is not in ``_NON_ATTEMPT_DECISIONS``. The routing
    field (``url``/``endpoint``/``path``/``to``) is read from
    ``entry["args"]`` and normalized to host/domain/top-level-prefix.
    Entries whose routing field is missing or unparseable are skipped,
    never guessed. Untracked tools are ignored.
    """
    counts = {t: Counter() for t in _TRACKED_TOOLS}
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        if e.get("event") != "tool_call":
            continue
        tool = e.get("tool")
        if tool not in _ARG_EXTRACTORS:
            continue
        if e.get("decision") in _NON_ATTEMPT_DECISIONS:
            continue
        arg_key, norm = _ARG_EXTRACTORS[tool]
        args = e.get("args")
        if not isinstance(args, dict):
            continue
        cat = norm(args.get(arg_key))
        if cat is None:
            continue
        counts[tool][cat] += 1
    return FramingFingerprint(
        {t: dict(c) for t, c in counts.items() if c})


# ---------------------------------------------------------------- store

from gov.chained_store import ChainedStore


def default_store_dir():
    """Default on-disk home for framing profiles. Kept out of any run
    TMPDIR: profiles must survive across runs."""
    return Path.home() / ".agent-governance-demo" / "framing"


class FramingStore(ChainedStore):
    """Durable per-agent cross-run framing-profile store.

    One JSONL file per agent under ``store_dir``. Every record is
    hash-chained (``prev_digest`` linkage): new records carry
    ``chain_keyed: true`` and a HMAC-SHA256 digest under the deployment
    key, pre-upgrade records carry the legacy unkeyed SHA-256 digest
    and still verify. ``verify_chain`` rejects tampered payloads,
    dropped records, and broken linkage. Audit runs BEFORE local
    mutation (F167 lesson): a logging failure leaves the store
    unchanged.

    Storage mechanics live in ``gov.chained_store.ChainedStore``; this
    class only declares the framing record schema (``framing_version`` /
    ``framing_run_recorded`` / ``FramingFingerprint``). The on-disk
    format is identical to the pre-extraction store.
    """

    _record_version_key = "framing_version"
    _record_version = _FRAMING_VERSION
    _record_event = "framing_run_recorded"
    _fingerprint_cls = FramingFingerprint


# --------------------------------------------------------------- signals

class FramingSignal:
    """One fired framing signal: kind, strength, and an explanation."""

    __slots__ = ("kind", "strength", "detail", "explanation")

    def __init__(self, kind, strength, detail, explanation):
        if kind not in ("argument_distribution",):
            raise ValueError("unknown framing signal kind %r" % (kind,))
        if strength not in ("weak", "strong"):
            raise ValueError("strength must be weak|strong, got %r"
                             % (strength,))
        self.kind = kind
        self.strength = strength
        self.detail = dict(detail)
        self.explanation = str(explanation)

    def to_dict(self):
        return {"kind": self.kind, "strength": self.strength,
                "detail": self.detail, "explanation": self.explanation}


class FramingResult:
    """Outcome of detect_framing: level in {silent, watch, warn, hold}."""

    __slots__ = ("level", "signals", "agent_id", "baseline_n", "window_n",
                 "reason")

    def __init__(self, level, signals=(), agent_id="", baseline_n=0,
                 window_n=0, reason=""):
        if level not in ("silent", "watch", "warn", "hold"):
            raise ValueError("unknown framing level %r" % (level,))
        self.level = level
        self.signals = list(signals)
        self.agent_id = str(agent_id)
        self.baseline_n = baseline_n
        self.window_n = window_n
        self.reason = str(reason)

    def to_dict(self):
        return {"level": self.level, "agent_id": self.agent_id,
                "baseline_n": self.baseline_n, "window_n": self.window_n,
                "reason": self.reason,
                "signals": [s.to_dict() for s in self.signals]}


def _signal_argument_distribution(tool, baseline_fps, window_fps):
    """Chi-square shift in one tool's argument distribution.

    Laplace (+1) smoothing avoids zero expected counts (same as
    ``gov.drift._signal_tool_distribution``). A shift where the agent
    essentially retained its old argument categories and merely added
    new ones is *additive adoption* -- benign evolution until
    corroborated -- and is capped at weak. A shift where the agent
    abandoned its old categories (vanished or shrunk below
    ``_SHRINK_FRACTION`` of their baseline share) is *substitutive*
    and keeps the p-value strength.
    """
    base = Counter()
    for fp in baseline_fps:
        base.update(fp["fingerprint"]["arg_counts"].get(tool, {}))
    win = Counter()
    for fp in window_fps:
        win.update(fp["fingerprint"]["arg_counts"].get(tool, {}))
    base_total = sum(base.values())
    win_total = sum(win.values())
    if base_total < _MIN_CALLS_FOR_ARG_CHISQ or \
            win_total < _MIN_CALLS_FOR_ARG_CHISQ:
        return None
    cats = sorted(set(base) | set(win))
    if len(cats) < 2:
        return None
    smooth_base_total = base_total + len(cats)  # Laplace +1 per category
    stat = 0.0
    for c in cats:
        expected = (base.get(c, 0) + 1) / smooth_base_total * win_total
        observed = win.get(c, 0)
        stat += (observed - expected) ** 2 / expected
    p = chi_square_sf(stat, len(cats) - 1)
    if p >= 0.05:
        return None
    strength = "strong" if p < 0.001 else "weak"
    # Substitutive vs additive: how much baseline mass sits in
    # categories the window abandoned (gone) or shrank hard.
    base_frac = {c: base[c] / base_total for c in cats}
    win_frac = {c: win[c] / win_total for c in cats}
    abandoned_mass = sum(
        base_frac[c] for c in cats
        if win.get(c, 0) == 0
        or win_frac[c] < _SHRINK_FRACTION * base_frac[c])
    substitutive = abandoned_mass > _SUBSTITUTIVE_MASS
    capped = False
    if not substitutive:
        strength = "weak"
        capped = True
    return FramingSignal(
        "argument_distribution", strength,
        {"tool": tool, "chi_square": stat, "df": len(cats) - 1,
         "p_value": p, "abandoned_mass": abandoned_mass,
         "substitutive": substitutive, "additive_capped": capped,
         "baseline_args": dict(base), "window_args": dict(win)},
        "%s argument distribution shifted vs baseline (chi2=%.1f, "
        "df=%d, p=%.4g%s)" % (
            tool, stat, len(cats) - 1, p,
            "; substitutive destination abandonment" if substitutive
            else "; additive adoption, capped at weak"))


def detect_framing(store, agent_id, window=8, baseline_runs=5):
    """Compare the agent's recent argument distributions against its
    own baseline.

    ``window``: most recent runs to evaluate (default 8).
    ``baseline_runs``: runs immediately preceding the window that form
    the baseline (default 5). Needs at least ``baseline_runs + 2``
    runs total, else SILENT with reason "insufficient_data".

    Level combination (same contract as ``gov.drift.detect_drift``):
    2+ strong signals or 3+ total -> hold; 1 strong or 2 total ->
    warn; 1 total -> watch; 0 -> silent.
    """
    if not isinstance(store, FramingStore):
        raise TypeError("store must be a FramingStore, got %r"
                        % type(store).__name__)
    runs = store.runs(agent_id)
    n = len(runs)
    if n < baseline_runs + 2:
        return FramingResult("silent", agent_id=agent_id,
                             baseline_n=0, window_n=0,
                             reason="insufficient_data")
    w = min(window, n - baseline_runs)
    window_runs = runs[n - w:]
    baseline_list = runs[n - w - baseline_runs:n - w]

    signals = []
    for tool in _TRACKED_TOOLS:
        sig = _signal_argument_distribution(tool, baseline_list,
                                            window_runs)
        if sig is not None:
            signals.append(sig)

    strong = sum(1 for s in signals if s.strength == "strong")
    total = len(signals)
    if strong >= 2 or total >= 3:
        level = "hold"
    elif strong >= 1 or total >= 2:
        level = "warn"
    elif total >= 1:
        level = "watch"
    else:
        level = "silent"
    return FramingResult(level, signals, agent_id=agent_id,
                         baseline_n=len(baseline_list),
                         window_n=len(window_runs),
                         reason="evaluated" if signals else "no_signal")
