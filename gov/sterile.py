"""Wave-52 P2 — Sterile Cockpit: temporal input quarantine.

Wave-53 INTEGRATED with the executor (see
workstreams/architect/STERILE_COCKPIT_INTEGRATION.md). The state
machine below is still the authority on window lifecycle; the
executor now calls ``maybe_open``/``check``/``request_close``/``tick``
from ``ToolExecutor.call()`` and wires the loop side through the
``LoopContract`` capability handshake (``attach_loop_contract``):
entry freezes loop context and withholds loop-owned channels, close
and expiry release them and re-issue refused reads through the loop
(never marked vetted).

What this module is: the input-channel trusted/untrusted taxonomy
(§2 of the design doc) as data, plus the per-run critical-window
state machine — enter on tool-pattern match, untrusted-channel
suspension with audited WINDOW_SUSPENDED refusals, nested windows
(union suspension, LIFO close, depth bound), close verification
(agent_declared vs human_approval), fail-closed expiry, and the
reconciliation contract.

What it still does NOT do by itself: it does not freeze any real
model's context, withhold loop-owned channels (user messages, skill
content, summaries), or vet content — those are the deployment loop's
responsibilities behind the ``LoopContract`` interface, and no real
in-repo model loop implements that contract yet (synthetic
``FakeLoop`` in tests only). The reconciliation list returned at
close is data for the loop to re-issue through the normal
content-defense stack — IT IS NEVER MARKED VETTED (design §8 R4: a
"trusted refresh" optimization here would re-open the hole).

$0, stdlib only. Deterministic (injectable clock).
"""

import fnmatch
import hmac
import secrets
import time

__all__ = [
    "ChannelRegistry",
    "WindowPolicy",
    "SterileController",
    "SterilePolicyError",
    "LoopContract",
    "lint_windows",
    "CHANNELS",
    "TOOL_CHANNELS",
    # Wave-64 D5: typed unvetted marker for the reissue pipe.
    "Unvetted",
    "Vetted",
    "VettingStack",
    "VettingCapability",
    "VettingError",
    # Wave-65 D5: structured acknowledgment-evidence sink.
    "AckAuditSink",
    # Wave-66 D5: per-run cumulative ack-drain budget (refuse-loud).
    "AckCumulativeBudgetExceeded",
    # Wave-67 D5: authenticated consumer registry for ack evidence.
    "ConsumerRegistry",
    "ConsumerToken",
    "ConsumerAuthError",
]

# ------------------------------------------------------------------
# §2 taxonomy: channel -> {trust, rationale, executor_mediated}.
# Default: untrusted. Trust is never the default.
# ------------------------------------------------------------------
CHANNELS = {
    "tool_result": {
        "trust": "untrusted",
        "executor_mediated": True,
        "rationale": "External data by definition; the canonical "
                     "indirect-injection path.",
    },
    "file_read": {
        "trust": "untrusted",
        "executor_mediated": True,
        "rationale": "File content is data, even inside the sandbox; "
                     "poisoned files are a favorite B1 shape.",
    },
    "web_fetch": {
        "trust": "untrusted",
        "executor_mediated": True,
        "rationale": "Highest poison base-rate of the read channels.",
    },
    "user_message": {
        "trust": "untrusted",
        "executor_mediated": False,
        "rationale": "Operator identity can be authenticated; operator "
                     "content cannot be vetted for injection. The "
                     "human-error shape (pasted untrusted content "
                     "mid-task). Loop-owned: the executor can only "
                     "declare and audit, not withhold.",
    },
    "memory_recall": {
        "trust": "untrusted",
        "executor_mediated": False,
        "rationale": "Cross-run state is attacker-influenced (a prior "
                     "compromised run wrote it).",
    },
    "skill_content": {
        "trust": "untrusted",
        "executor_mediated": False,
        "rationale": "Third-party skill definitions/prompts are "
                     "supply-chain input. Labeled now, before a skill "
                     "system exists in-repo.",
    },
    "summary_state": {
        "trust": "untrusted",
        "executor_mediated": False,
        "rationale": "Wave-50 Astra evidence: self-written compaction "
                     "summaries carried jailbreak-style instructions "
                     "the successor FOLLOWED. Self-written != trusted.",
    },
    "approval_decision": {
        "trust": "trusted",
        "executor_mediated": True,
        "rationale": "The governance root of trust: human review "
                     "through the approval queue. Narrow: the "
                     "decision only, never reviewer free text.",
    },
}

# Default tool -> input-channel mapping for the executor integration.
# A tool call's *input* channel is what suspension consults (reads);
# write-like tools carry no input channel. Tools absent from this map
# are refused fail-closed during an open window (integration §5).
TOOL_CHANNELS = {
    "read_file": "file_read",
    "api_call": "web_fetch",
    "http_post": "tool_result",
    "send_email": "tool_result",
    "write_file": None,
    "delete_file": None,
}

# ------------------------------------------------------------------
# Wave-53 P1 — the deployment-loop contract (integration design §1).
#
# The executor mediates tool calls; it cannot freeze a model's live
# context, withhold operator/skill/summary arrivals, or re-issue reads
# through a content stack. Those are deployment-loop
# responsibilities. This interface names them. A deployment that does
# not attach a loop gets executor-side enforcement only (declared in
# audit as loop_contract_absent) — never an end-to-end sterility
# claim. $0, stdlib only; the base implementation raises
# NotImplementedError so a half-implemented loop fails loud, not
# silently partial.
# ------------------------------------------------------------------


class LoopContract:
    """Adapter interface for the deployment's model loop.

    ``snapshot_ref`` is the executor's entry snapshot reference
    (policy hash + log-seq range of delivered tool results, carried
    on the sterile_window_enter audit event).
    """

    def freeze_context(self, snapshot_ref):
        """Pin the agent's working context to the entry snapshot.

        New arrivals on suspended channels must not be added to the
        model's context until release. Deployment-implemented.
        """
        raise NotImplementedError

    def withhold(self, channel):
        """Stop delivering arrivals on an executor-unmediated channel
        (user_message, skill_content, summary_state)."""
        raise NotImplementedError

    def release(self, channel):
        """Resume delivery on a previously withheld channel."""
        raise NotImplementedError

    def reissue_reads(self, reads):
        """Re-issue refused-during-window reads through the FULL
        content-defense stack. ``reads`` is [(tool, channel), ...].

        Returns a list of {tool, channel, result_summary,
        delta_vs_snapshot} dicts. The loop MUST NOT mark re-issued
        content vetted (integration design §7, R4 invariant) — deltas
        are flagged for review.

        Wave-64 D5: the executor wraps this method's return value in
        ``sterile.Unvetted`` before anything else touches it (audit
        stash included) — the summaries cross the pipe carrying a
        machine-readable "never vetted" marker. The loop's own code
        inside this method is the loop author's responsibility: do
        not merge result_summary into trusted context, do not
        represent it as vetted anywhere downstream.
        """
        raise NotImplementedError


# ------------------------------------------------------------------
# Wave-53 P1 — policy lint (integration design §6). Warnings, not
# errors: these name judgment gaps for the review workflow; the hard
# fail-closed rules stay in WindowPolicy._load.
# ------------------------------------------------------------------

# Tool-name families treated as irreversible for the lint's
# agent_declared-close warning (integration design §3.4). A
# deployment extends this via the known_irreversible argument.
_IRREVERSIBLE_FAMILIES = ("payment", "delete", "drop", "revoke",
                          "transfer", "publish")


def lint_windows(block, known_tools=None, known_irreversible=None):
    """Lint a critical_windows block. Returns [warning, ...].

    ``known_tools``: iterable of tool names the deployment registers
    (unmapped tools fail closed at runtime during a window — warn at
    review time). ``known_irreversible``: extra irreversible families.
    """
    warnings = []
    block = block or []
    fams = tuple(_IRREVERSIBLE_FAMILIES) + tuple(known_irreversible or ())
    for w in block:
        if not isinstance(w, dict):
            continue
        wid = w.get("id", "?")
        if not w.get("suspend"):
            warnings.append(
                "window %r suspends no channels — a window that "
                "suspends nothing is probably a mis-declaration" % wid)
        if known_tools is not None:
            for pat in w.get("on_tools") or []:
                if not any(fnmatch.fnmatchcase(t, pat)
                           for t in known_tools):
                    warnings.append(
                        "window %r on_tools pattern %r matches no known "
                        "tool — unmapped tools are refused fail-closed "
                        "during the window" % (wid, pat))
        if (w.get("close_policy", "agent_declared") == "agent_declared"):
            for pat in w.get("on_tools") or []:
                fam = pat.strip("*").split(".")[0].split("_")[0]
                if any(fam.startswith(f) or f.startswith(fam)
                       for f in fams):
                    warnings.append(
                        "window %r uses agent_declared close over "
                        "irreversible-family pattern %r — prefer "
                        "human_approval (integration design §3.4)" % (wid, pat))
                    break
        max_d = w.get("max_duration_s")
        if isinstance(max_d, (int, float)) and max_d > 3600:
            warnings.append(
                "window %r max_duration_s=%r exceeds one hour — long "
                "windows risk stale snapshots (design §9.2)" % (wid, max_d))
    return warnings


class SterilePolicyError(Exception):
    """A critical_windows block failed validation (fail-closed load)."""


class ChannelRegistry:
    """The §2 taxonomy. Unknown channels fail closed (KeyError)."""

    def __init__(self, channels=None):
        self._channels = dict(CHANNELS if channels is None else channels)

    def get(self, channel):
        """Return the channel's record; KeyError on unknown channels."""
        return self._channels[channel]

    def is_trusted(self, channel):
        return self.get(channel)["trust"] == "trusted"

    def __contains__(self, channel):
        return channel in self._channels


class WindowPolicy:
    """Validated ``critical_windows:`` block (design §3).

    Each entry: {id, on_tools, suspend, close_policy,
    max_duration_s, rationale}. Validation (the lint rules, executable
    form): unknown channels, trusted-channel suspension, missing
    expiry, empty/over-broad patterns, duplicate ids, and missing
    rationale are all SterilePolicyError — the block fails closed at
    load, never half-applied at runtime.
    """

    def __init__(self, block, registry=None):
        self.registry = registry or ChannelRegistry()
        self.windows = []
        self._load(block or [])

    def _load(self, block):
        if not isinstance(block, list):
            raise SterilePolicyError("critical_windows must be a list")
        seen = set()
        for i, w in enumerate(block):
            if not isinstance(w, dict):
                raise SterilePolicyError("window #%d must be a mapping" % i)
            wid = w.get("id")
            if not wid or not isinstance(wid, str):
                raise SterilePolicyError(
                    "window #%d needs a string id" % i)
            if wid in seen:
                raise SterilePolicyError("duplicate window id %r" % wid)
            seen.add(wid)
            if not w.get("rationale"):
                raise SterilePolicyError(
                    "window %r needs a rationale (design §4)" % wid)
            on_tools = w.get("on_tools")
            if not on_tools or not isinstance(on_tools, (list, tuple)):
                raise SterilePolicyError(
                    "window %r needs a non-empty on_tools list" % wid)
            for pat in on_tools:
                if not isinstance(pat, str) or not pat:
                    raise SterilePolicyError(
                        "window %r has a bad on_tools pattern" % wid)
                if pat == "*" or pat.strip("*") == "":
                    raise SterilePolicyError(
                        "window %r: bare '*' on_tools is over-broad "
                        "(design §8 R2)" % wid)
            suspend = w.get("suspend") or []
            if not isinstance(suspend, (list, tuple)):
                raise SterilePolicyError(
                    "window %r: suspend must be a list" % wid)
            for ch in suspend:
                if ch not in self.registry:
                    raise SterilePolicyError(
                        "window %r suspends unknown channel %r" % (wid, ch))
                if self.registry.is_trusted(ch):
                    raise SterilePolicyError(
                        "window %r suspends trusted channel %r "
                        "(the human channel is never suspended)" % (wid, ch))
            close_policy = w.get("close_policy", "agent_declared")
            if close_policy not in ("agent_declared", "human_approval"):
                raise SterilePolicyError(
                    "window %r: bad close_policy %r" % (wid, close_policy))
            max_d = w.get("max_duration_s")
            if (not isinstance(max_d, (int, float)) or max_d <= 0):
                raise SterilePolicyError(
                    "window %r needs a positive max_duration_s "
                    "(design §5: expiry is mandatory)" % wid)
            # Wave-53 P1 (integration §2): entry-time re-scan of
            # retained pre-window read content through the current
            # content stack. Opt-in; the honest scope is documented
            # in the integration design — this catches stale-stack
            # misses, never lineage.
            entry_rescan = w.get("entry_rescan", False)
            if not isinstance(entry_rescan, bool):
                raise SterilePolicyError(
                    "window %r: entry_rescan must be a bool" % wid)
            # Wave-53 P1 (integration §4): refusal-rate telemetry
            # threshold. Non-negative int; exceeding it audits
            # window_refusal_rate_alert (a mis-scoping signal).
            alert_after = w.get("refusal_alert_after")
            if alert_after is not None and (
                    not isinstance(alert_after, int) or alert_after < 0
                    or isinstance(alert_after, bool)):
                raise SterilePolicyError(
                    "window %r: refusal_alert_after must be a "
                    "non-negative int" % wid)
            self.windows.append({
                "id": wid,
                "on_tools": list(on_tools),
                "suspend": list(suspend),
                "close_policy": close_policy,
                "max_duration_s": max_d,
                "rationale": w["rationale"],
                "entry_rescan": entry_rescan,
                "refusal_alert_after": alert_after,
            })

    def match_all(self, tool):
        """Every window whose on_tools glob-matches tool, in block order.

        Overlapping entries nest (design §7) rather than shadowing:
        the outer (earlier in the block) opens first, the inner
        pushes on top.
        """
        return [w for w in self.windows
                if any(fnmatch.fnmatchcase(tool, pat)
                       for pat in w["on_tools"])]


class SterileController:
    """Per-run critical-window state machine (design §5–§7).

    ``audit`` is a list the controller appends event dicts to
    (sterile_window_enter/exit, window_suspended_refusal,
    window_close_denied). ``now`` is an injectable clock (seconds).
    """

    def __init__(self, policy, audit=None, now=None, max_depth=4):
        self.policy = policy
        self.events = audit if audit is not None else []
        self._now = now or __import__("time").time
        self._max_depth = max_depth
        self._stack = []  # open windows, outermost first

    # -- internal ---------------------------------------------------
    def _t(self, t):
        return self._now() if t is None else t

    def _emit(self, event):
        self.events.append(event)

    def _suspended_channels(self):
        sus = set()
        for w in self._stack:
            sus.update(w["suspend"])
        return sus

    # -- lifecycle --------------------------------------------------
    def maybe_open(self, tool, t=None):
        """Open every window matching tool that is not already open.

        Returns the list of enter/reentry events (possibly empty).
        Executor-side entry only (design §8 R8): the agent cannot
        opt out; it never calls this. Overlapping entries nest —
        ``match_all`` order (outermost first).
        """
        now = self._t(t)
        events = []
        for w in self.policy.match_all(tool):
            if any(o["id"] == w["id"] for o in self._stack):
                events.append({"reentered": w["id"], "tool": tool})
                continue
            if len(self._stack) >= self._max_depth:
                ev = {"event": "window_nesting_exceeded", "window": w["id"],
                      "tool": tool, "depth": len(self._stack)}
                self._emit(ev)
                events.append(ev)
                continue
            entry = {
                "id": w["id"],
                "suspend": list(w["suspend"]),
                "close_policy": w["close_policy"],
                "entered_at": now,
                "deadline": now + w["max_duration_s"],
                "trigger_tool": tool,
                "refused": [],  # (tool, channel) refused during window
            }
            self._stack.append(entry)
            ev = {"event": "sterile_window_enter", "window": w["id"],
                  "tool": tool, "depth": len(self._stack),
                  "suspend": list(w["suspend"]),
                  "close_policy": w["close_policy"]}
            self._emit(ev)
            events.append(ev)
        return events

    def check(self, tool, channel=None, t=None):
        """Input-channel gate for one tool call.

        Returns {"allowed": True} or {"allowed": False,
        "status": "window_suspended", "window": <id>}. Refusals are
        audited (window_suspended_refusal) and recorded for the
        exit reconciliation list.

        Wave-53 P1: channel "unknown_tool" (a tool with no
        TOOL_CHANNELS mapping) is refused fail-closed while any
        window is open — deployments register custom tool->channel
        mappings; unmapped tools never get the benefit of the doubt
        inside a window. Outside a window everything is allowed
        (default-off).
        """
        if channel is None:
            channel = TOOL_CHANNELS.get(tool)
        if channel is None or not self._stack:
            return {"allowed": True}
        suspended = self._suspended_channels()
        if channel != "unknown_tool" and channel not in suspended:
            return {"allowed": True}
        top = self._stack[-1]["id"]
        self._stack[-1]["refused"].append((tool, channel))
        ev = {"event": "window_suspended_refusal", "window": top,
              "tool": tool, "channel": channel}
        self._emit(ev)
        return {"allowed": False, "status": "window_suspended",
                "window": top}

    def request_close(self, window_id=None, human_approved=False, t=None):
        """The agent's window_close primitive (design §5–§6).

        LIFO: only the innermost window may close. human_approval
        windows need human_approved=True. Denials are audited
        (window_close_denied) — window-escape attempts fail closed
        and leave evidence. On grant, returns {"closed": True,
        "reconcile": [...]} — the refused-during-window read list,
        NEVER marked vetted (design §8 R4).
        """
        now = self._t(t)  # noqa: F841 - kept for the future executor call
        if not self._stack:
            ev = {"event": "window_close_denied", "window": window_id,
                  "reason": "no_window_open"}
            self._emit(ev)
            return {"closed": False, "reason": "no_window_open"}
        top = self._stack[-1]
        target = window_id or top["id"]
        if target != top["id"]:
            ev = {"event": "window_close_denied", "window": target,
                  "reason": "not_innermost",
                  "innermost": top["id"]}
            self._emit(ev)
            return {"closed": False, "reason": "not_innermost"}
        if (top["close_policy"] == "human_approval"
                and not human_approved):
            ev = {"event": "window_close_denied", "window": target,
                  "reason": "human_approval_required"}
            self._emit(ev)
            return {"closed": False,
                    "reason": "human_approval_required"}
        self._stack.pop()
        ev = {"event": "sterile_window_exit", "window": target,
              "reason": "closed", "depth": len(self._stack)}
        self._emit(ev)
        return {"closed": True, "reconcile": list(top["refused"])}

    def tick(self, t=None):
        """Expire windows past their deadline (fail-closed).

        Returns the list of expired window ids. Expiry closes the
        window, marks the task incomplete, and resumes the channels —
        it never silently succeeds (design §5).
        """
        now = self._t(t)
        expired = []
        while self._stack and self._stack[-1]["deadline"] <= now:
            top = self._stack.pop()
            expired.append(top["id"])
            self._emit({"event": "sterile_window_exit",
                        "window": top["id"], "reason": "expired",
                        "task": "incomplete",
                        "depth": len(self._stack)})
        return expired

    # -- introspection ----------------------------------------------
    def open_windows(self):
        return [w["id"] for w in self._stack]

    def peek(self, window_id):
        """A copy of one open window's entry record, or None.

        Wave-53 P1: the executor integration reads entry metadata
        (entered_at, refused-during-window list) for expiry
        reconciliation and the agent_declared pending-approval
        check. Read-only — mutating the copy changes nothing.
        """
        for w in self._stack:
            if w["id"] == window_id:
                return {
                    "id": w["id"],
                    "suspend": list(w["suspend"]),
                    "close_policy": w["close_policy"],
                    "entered_at": w["entered_at"],
                    "deadline": w["deadline"],
                    "trigger_tool": w["trigger_tool"],
                    "refused": list(w["refused"]),
                }
        return None

    def suspended(self):
        return sorted(self._suspended_channels())


# ------------------------------------------------------------------
# Wave-64 D5 — typed unvetted marker for the reissue pipe.
#
# The open question from wave-63: the sterile-cockpit reissue pipe
# (LoopContract.reissue_reads) is documented contract — "never
# marked vetted" (design §8 R4) — but loop consumers got no
# machine-readable "never vetted" marker on the summaries. A
# consumer doing ``for r in delta: ctx.append(r["result_summary"])``
# silently treated unvetted content as trusted context.
#
# What this is: ``Unvetted``, a value wrapper applied by the
# EXECUTOR at the producer boundary (immediately around the loop's
# reissue_reads return, before audit stashing). Accidental silent
# treatment as vetted becomes structurally impossible — the wrapper
# is not iterable, indexable, sized, or equal to its payload, and
# the only documented read path is acknowledge().
#
# What this is NOT (graded honestly): enforcement against a
# hostile in-process consumer. CPython cannot make an attribute
# truly private — ``_payload`` is reachable by deliberate dunder
# access. The wrapper is ADVISORY against hostile code and a real
# gate against confused code (the human-error shape: a loop author
# who forgets the summaries are unvetted). The enforcement half
# stays where it was: the executor never marks reconciled reads
# vetted (R4, pinned), and the positive "vetted" mark below is
# mint-gated so untrusted code cannot manufacture trust.
#
# Ground truth of the whole scheme: NOTHING is vetted unless it
# carries a minted Vetted mark. Unvetted is the default state;
# this wrapper makes the default explicit and machine-readable at
# the pipe where confusion is likeliest.
#
# $0, stdlib only (hmac, secrets). Deterministic.
# ------------------------------------------------------------------

_UNVETTED_KEY = "__gov_unvetted__"
_VETTED_KEY = "__gov_vetted__"

# Module-private mint seal: Vetted.__init__ requires this exact
# object, and only VettingStack.vet() holds it. Importable (single
# underscore) but not part of the contract — the capability check
# inside vet() is the real gate; the seal keeps honest code from
# constructing Vetted by accident.
_VETTED_SEAL = object()

_UNVETTED_CONFUSION_MSG = (
    "Unvetted value cannot be used as its payload: call "
    ".acknowledge(consumer_id) to explicitly accept never-vetted data")
_VETTED_CONFUSION_MSG = (
    "Vetted value cannot be used as its payload directly: read "
    ".payload (the vetted mark stays visible on the wrapper)")


class VettingError(Exception):
    """A vetted-mark mint or verification failed (fail-closed)."""


# ------------------------------------------------------------------
# Wave-65 D5 — acknowledgment audit trail.
#
# Wave-64's open question: should acknowledge() sink records feed the
# hash-chained audit log? An acknowledgment that leaves no evidence is
# a control without a trail — the auditor can't tell who treated
# unvetted data as usable, when, or in which window. This answers it
# WITHOUT letting sterile.py own the audit log (it never does): the
# codebase's standing convention is a passive sink (a plain list for
# the controller's events) that the log OWNER drains — see
# ToolExecutor._drain_sterile. AckAuditSink is the structured version
# of that convention for acknowledgments: the consumer appends via
# acknowledge(); the deployment drains into its ActionLog (see
# ToolExecutor.drain_ack_sink), which re-stamps the run context.
#
# Design answers (see workstreams/evals/STERILE_D5_ACK_AUDIT.md):
# (a) per ack: event, consumer (self-attested string), origin,
#     executor-stamped ack_context {window, run_id}, ts (ack time),
#     count. NEVER payload contents (repr already never leaks).
# (b) flood: per-sink budget (default 256 records) + consecutive-
#     duplicate coalescing with EXACT counts + one count-preserving
#     overflow summary. No sampling (sampling loses evidence); no
#     silent drops (every unrecorded ack is counted in the summary).
# (c) honesty: "acknowledged" is precisely "consumer_id called
#     acknowledge() on this marker and the marker was unwrapped".
#     It does NOT claim the consumer used/read the data, that the
#     payload is safe, or that the consumer identity is
#     authenticated (self-attested — the documented gap).
# (d) sink failure: AckAuditSink.append is TOTAL w.r.t. the budget
#     (never raises for volume); a caller-supplied broken sink that
#     raises propagates LOUD before the payload is returned (never
#     silent evidence loss). A failed drain into the ActionLog
#     (LogFullError/AppendLockError) raises with the record still in
#     the sink (peek-confirm) — the run fails closed per F22.
#
# Wave-66 D5: the per-sink budget bounds ONE batch before ONE drain.
# Repeated drain/refill cycles are now bounded per RUN by a cumulative
# cap (8 full sink batches, default 2048 records), enforced at
# ToolExecutor.drain_ack_sink — the choke point into the hash chain.
# The counter lives on the run (executor + run-dir marker), never the
# sink, so sink replacement cannot reset it. Exhaustion refuses LOUD
# (AckCumulativeBudgetExceeded, evidence retained in the sink, one
# audited control event). The counter increments only after a
# successful log-append + pop, so a failed drain re-drains with exact
# accounting — no double-count. See
# workstreams/evals/ACK_CUMULATIVE_BUDGET.md.
#
# Wave-67 D5: the self-attested-consumer gap is now answered by
# mechanism (ConsumerRegistry / ConsumerToken / ConsumerAuthError,
# appended at the end of this module; design:
# workstreams/evals/CONSUMER_REGISTRY.md). acknowledge() accepts an
# optional (consumer_token, registry) pair; a verified pair stamps
# the record "attribution": "authenticated" (+ non-secret token_id),
# everything else stays "attribution": "unattributed". Tokens are
# never mandatory (Wave-49 lesson); a presented-but-invalid token
# raises ConsumerAuthError LOUD — there is no silent degradation to
# "unattributed". "Authenticated" proves token possession at ack
# time (HMAC-bound registration, constant-time verify), NOT human
# identity and NOT non-theft (in-process theft within the bound name
# is an F59-class residual, stated in the design doc).
# ------------------------------------------------------------------

# Default per-sink acknowledgment budget. Worst-case chain growth per
# sink (measured wave-65: ~630 bytes per chained log entry at default
# budget): 256 records + 1 overflow summary ≈ under 170KB. A sink is
# drained per run, so this bounds ack-driven chain growth per run, not
# per deployment.
_ACK_BUDGET_DEFAULT = 256

# Wave-66 D5: per-run cumulative ack-drain budget, in full sink batches.
# The cumulative cap is _ACK_CUMULATIVE_BATCHES_DEFAULT * (the drained
# sink's per-batch budget, defaulting to _ACK_BUDGET_DEFAULT for plain
# lists). 8 full batches (2048 records at the default) is far beyond
# any legitimate flow — the posture drains one batch per window close,
# runs have a handful of windows, and consecutive-duplicate coalescing
# collapses legitimate per-row loops — but a hard bound against a
# buggy/adversarial drain/refill cycle. The counter lives on the RUN
# (executor + run-dir marker), never the sink, so sink replacement
# cannot reset it; see ToolExecutor.drain_ack_sink.
_ACK_CUMULATIVE_BATCHES_DEFAULT = 8


class AckCumulativeBudgetExceeded(Exception):
    """Wave-66 D5: the per-run cumulative ack-drain budget is exhausted.

    Raised by ``ToolExecutor.drain_ack_sink`` — fail-closed, LOUD.
    Records already drained stay chained (exact accounting); records
    not yet drained stay IN the sink (peek-confirm: evidence retained,
    nothing silently dropped). Exactly once per run the executor also
    chains a ``unvetted_ack_cumulative_budget_hit`` control event so
    the refusal is visible in the audit trail, not just the
    exception."""


def _valid_ack_context(ctx):
    """True when ctx is a usable ack correlation context: a dict with
    string keys and JSON-scalar values (executor-stamped, e.g.
    {"window": wid, "run_id": rid}). Anything else is not trusted as
    correlation — callers get {} (fail-closed: under-inform, never
    over-trust)."""
    if not isinstance(ctx, dict):
        return False
    for k, v in ctx.items():
        if not isinstance(k, str):
            return False
        if v is not None and not isinstance(v, (str, int, float, bool)):
            return False
    return True


def _ack_dup_key(record):
    """Identity key for consecutive-duplicate coalescing: two acks
    that agree on consumer, origin, and correlation context are the
    same claim repeated (e.g. a loop acknowledging every row)."""
    ctx = record.get("ack_context") or {}
    frozen = tuple(sorted((k, ctx[k]) for k in ctx))
    return (record.get("consumer"), record.get("origin"), frozen)


class AckAuditSink:
    """Structured acknowledgment-evidence sink (wave-65 D5).

    Passive container — sterile.py never owns the audit log. The
    consumer passes this (or a plain list) as ``sink=`` to
    ``Unvetted.acknowledge()``; the deployment drains it into its
    ActionLog via ``ToolExecutor.drain_ack_sink`` (peek-confirm, so a
    failed log append never loses the in-flight record).

    Flood resistance: at most ``max_records`` individual ack records;
    consecutive duplicates (same consumer/origin/context) coalesce
    with an exact ``count``; beyond the budget, further acks are
    counted — exactly, by consumer — in ONE overflow summary record
    at the tail. Nothing is silently dropped and nothing is sampled.

    ``expected_consumer`` (optional) is a CONFUSION guard, not a
    security boundary: acks naming anyone else raise ValueError
    (catches a dashboard wiring bug; hostile in-process code is the
    F59 accepted residual). ``now`` is an injectable clock (seconds).
    """

    def __init__(self, max_records=_ACK_BUDGET_DEFAULT,
                 expected_consumer=None, now=None):
        if (isinstance(max_records, bool)
                or not isinstance(max_records, int) or max_records < 1):
            raise ValueError("max_records must be a positive int")
        if expected_consumer is not None and (
                not isinstance(expected_consumer, str)
                or not expected_consumer):
            raise TypeError(
                "expected_consumer must be a non-empty string or None")
        self._max_records = max_records
        self._expected_consumer = expected_consumer
        self._now = now or time.time
        self._records = []
        self._n_individual = 0  # unvetted_acknowledged records held
        self._overflow_dropped = 0
        self._overflow_by_consumer = {}

    @property
    def max_records(self):
        """The per-sink batch budget (read-only). The wave-66 per-run
        cumulative drain cap scales from this
        (``_ACK_CUMULATIVE_BATCHES_DEFAULT`` batches)."""
        return self._max_records

    # -- sink protocol: acknowledge() calls append ------------------
    def append(self, record):
        """Append one ack record. TOTAL w.r.t. the flood budget: volume
        never raises — it coalesces (exact count) or overflows into the
        count-preserving summary. Raises only on programmer error
        (non-dict record, expected_consumer mismatch): loud, never
        silent."""
        if not isinstance(record, dict):
            raise TypeError("AckAuditSink.append takes a record dict")
        consumer = record.get("consumer")
        if (self._expected_consumer is not None
                and consumer != self._expected_consumer):
            raise ValueError(
                "ack consumer %r does not match this sink's expected "
                "consumer %r (wiring bug?)" % (consumer,
                                               self._expected_consumer))
        rec = dict(record)
        if "ts" not in rec:
            rec["ts"] = self._now()
        # Consecutive-duplicate coalescing: the tail record is the
        # same claim repeated — bump its exact count instead of
        # growing the chain. (After overflow begins the tail is the
        # summary, so further dups are overflow-counted — exact either
        # way, just located in the summary.)
        if (self._records
                and self._records[-1].get("event")
                == "unvetted_acknowledged"
                and _ack_dup_key(self._records[-1]) == _ack_dup_key(rec)):
            self._records[-1]["count"] = \
                self._records[-1].get("count", 1) + 1
            return
        if self._n_individual >= self._max_records:
            self._overflow_dropped += 1
            by = self._overflow_by_consumer
            by[consumer] = by.get(consumer, 0) + 1
            self._refresh_overflow_summary()
            return
        self._records.append(rec)
        self._n_individual += 1

    def _refresh_overflow_summary(self):
        """Maintain the single tail summary over dropped acks."""
        summary = {
            "event": "unvetted_ack_overflow",
            "dropped": self._overflow_dropped,
            "by_consumer": dict(self._overflow_by_consumer),
            "budget": self._max_records,
            "ts": self._now(),
            "note": ("count-preserving overflow: per-ack records beyond "
                     "the sink budget are counted here by consumer — "
                     "exact counts, no sampling, nothing silently "
                     "dropped"),
        }
        if self._records and self._records[-1].get("event") == \
                "unvetted_ack_overflow":
            self._records[-1] = summary
        else:
            self._records.append(summary)

    # -- drain protocol: peek-confirm, never loses a record ---------
    def pending(self):
        """Number of undrained records (individual + overflow summary)."""
        return len(self._records)

    def peek_oldest(self):
        """Oldest undrained record WITHOUT removing it (None when empty).

        The drain loop appends this to the ActionLog first and pops it
        only after the append succeeds — a failed log write leaves the
        record in the sink."""
        return self._records[0] if self._records else None

    def pop_oldest(self):
        """Remove and return the oldest record (None when empty)."""
        if not self._records:
            return None
        rec = self._records.pop(0)
        if rec.get("event") == "unvetted_acknowledged":
            self._n_individual -= 1
        return rec

    def __repr__(self):
        return "AckAuditSink(pending=%d, budget=%d%s)" % (
            len(self._records), self._max_records,
            ", expected_consumer=%r" % self._expected_consumer
            if self._expected_consumer else "")


class Unvetted:
    """Typed "never vetted" marker (wave-64 D5, advisory).

    Wraps a value that crossed the sterile-cockpit reissue pipe —
    or any other value the producer knows was never vetted.
    Marking unvetted is fail-closed-safe, so the constructor is
    public; the reverse direction (claiming vetted) is mint-gated
    (see Vetted / VettingStack).
    """

    __slots__ = ("_payload", "_origin", "_ack_context")

    def __init__(self, payload, origin="reissue_reads", ack_context=None):
        self._payload = payload
        self._origin = origin
        # Wave-65 D5: executor-stamped correlation context (e.g.
        # {"window": wid, "run_id": rid}) carried through the envelope
        # so acknowledge() records name the window/run. Validated:
        # anything untrusted-looking becomes {} (under-inform, never
        # over-trust). NEVER payload contents.
        if ack_context is None:
            ack_context = {}
        if not _valid_ack_context(ack_context):
            raise TypeError(
                "ack_context must be a dict with string keys and "
                "JSON-scalar values")
        self._ack_context = dict(ack_context)

    @property
    def origin(self):
        """Where the unvetted value came from (e.g. "reissue_reads")."""
        return self._origin

    def acknowledge(self, consumer_id, sink=None, *,
                    consumer_token=None, registry=None):
        """The ONLY documented read path.

        ``consumer_id`` names who accepts the never-vetted data
        (e.g. "review-dashboard", "loop-context-merge"). When
        ``sink`` is given, an acknowledgement record is appended —
        auditable evidence of who took unvetted data. The record
        carries ``event``, ``consumer``, ``origin``, the
        executor-stamped ``ack_context`` ({window, run_id} when the
        marker came through the reissue pipe), ``ts`` (ack time),
        and ``count`` (1; >1 only via AckAuditSink coalescing of
        consecutive duplicates). NEVER payload contents.

        Honesty definition (wave-65): "acknowledged" means exactly
        "consumer_id called acknowledge() on this marker and the
        marker was unwrapped" — not that the consumer used, read, or
        understood the payload, not that the payload is safe, and
        not that consumer_id is authenticated (self-attested; the
        documented gap — see STERILE_D5_ACK_AUDIT.md).

        Wave-67 D5: the self-attestation gap is closed by mechanism,
        optionally. Pass ``consumer_token=`` (a ConsumerToken issued
        by the deployment's registration authority) together with
        ``registry=`` (the ConsumerRegistry that issued it) and the
        token is verified before anything is recorded: success
        stamps the record ``"attribution": "authenticated"`` plus
        the token's public (non-secret) ``token_id``; any failure
        raises ``ConsumerAuthError`` LOUD — no record is appended
        and the payload is never returned. Omitting the pair keeps
        the wave-66 behavior exactly, stamped
        ``"attribution": "unattributed"`` (tokens are never
        mandatory — Wave-49 lesson). A token presented WITHOUT a
        registry raises loud (fail-closed: a token no one can
        verify proves nothing). A registry given with no token is
        honest ``unattributed``. There is deliberately NO
        invalid-token→unattributed degradation path.

        What "authenticated" proves, precisely: at ack time the
        caller presented a bearer token issued by this registry,
        HMAC-bound to the named consumer_id, neither expired nor
        revoked. It does NOT prove human identity, non-theft (an
        in-process holder using the token under the bound name is an
        F59-class residual), or payload safety — see
        workstreams/evals/CONSUMER_REGISTRY.md.

        Ordering: verification, then record append, then unwrap —
        through this API a record implies both the verification and
        the unwrap happened. A raising sink withholds the payload
        (never silent evidence loss). Unwrap without a record is the
        caller's explicit choice (sink=None). An AckAuditSink stamps
        ts from its injectable clock and enforces the flood budget;
        a plain list gets time.time() stamped here.
        """
        if not isinstance(consumer_id, str) or not consumer_id:
            raise TypeError(
                "acknowledge() requires a non-empty consumer_id string")
        # Wave-67 D5: authenticated consumer registry (optional).
        attribution = "unattributed"
        token_id = None
        if registry is not None:
            if not isinstance(registry, ConsumerRegistry):
                raise TypeError(
                    "acknowledge() registry= must be a ConsumerRegistry")
            if consumer_token is not None:
                # Raises ConsumerAuthError on ANY verification failure
                # (forgery, bit-flip, foreign-registry token, bound-id
                # mismatch, expiry, revocation) — before any record is
                # appended and before the payload is reachable.
                attestation = registry.verify(consumer_token, consumer_id)
                attribution = "authenticated"
                token_id = attestation["token_id"]
        elif consumer_token is not None:
            raise ConsumerAuthError(
                "consumer token presented without a registry to verify "
                "it against (fail-closed: an unverifiable token proves "
                "nothing)")
        record = {"event": "unvetted_acknowledged",
                  "consumer": consumer_id,
                  "origin": self._origin,
                  "ack_context": dict(self._ack_context),
                  "count": 1,
                  "attribution": attribution}
        if token_id is not None:
            record["token_id"] = token_id
        if sink is not None:
            if isinstance(sink, AckAuditSink):
                sink.append(record)
            else:
                record["ts"] = time.time()
                sink.append(record)
        return self._payload

    # -- anti-confusion: the wrapper never silently behaves like ----
    # -- the payload. Every one of these raises TypeError naming ----
    # -- acknowledge(), so a confused consumer fails loud, never ----
    # -- silent. (Deliberate dunder/attribute access still reaches --
    # -- _payload in CPython — advisory grading, documented above.) -
    def __iter__(self):
        raise TypeError(_UNVETTED_CONFUSION_MSG)

    def __len__(self):
        raise TypeError(_UNVETTED_CONFUSION_MSG)

    def __getitem__(self, _index):
        raise TypeError(_UNVETTED_CONFUSION_MSG)

    def __contains__(self, _item):
        raise TypeError(_UNVETTED_CONFUSION_MSG)

    # __eq__ deliberately left as identity: Unvetted(x) != x is the
    # fail-closed default — a marker that compared equal to its
    # payload would dissolve silently in ``==`` checks.

    def __repr__(self):
        # Never render payload contents: unvetted summaries must not
        # leak into logs through a stray repr().
        try:
            shape = "items=%d" % len(self._payload)
        except TypeError:
            shape = "type=%s" % type(self._payload).__name__
        return "Unvetted(origin=%r, %s)" % (self._origin, shape)

    # -- serialization boundary ------------------------------------
    # JSON round-trips erase Python types. The envelope below makes
    # the marker survive honest serialization (audit log -> review
    # tooling -> from_envelope re-marks). Decode is total and
    # fail-closed: there is NO input to from_envelope that yields a
    # bare (potentially trusted-looking) value.
    def to_envelope(self):
        """JSON-safe dict carrying the marker: the form stored in
        audit events (the live object would be erased by the log's
        ``default=str``). Carries the executor-stamped ``ack_context``
        so acknowledge() records can name the window/run."""
        return {_UNVETTED_KEY: True, "origin": self._origin,
                "payload": self._payload,
                "ack_context": dict(self._ack_context)}

    @classmethod
    def from_envelope(cls, decoded):
        """Re-mark a JSON-decoded envelope. Total and fail-closed:

        - envelope with the marker key -> Unvetted (origin restored);
        - any other JSON value (key stripped, pre-D5 plain list,
          anything) -> Unvetted with origin "unmarked-erased".
          Erasure can only under-inform, never over-trust, because
          the ground truth is "vetted requires a minted mark";
        - non-JSON types -> TypeError (programmer error, loud).

        Marker keys are meaningful ONLY at the envelope top level:
        a ``__gov_vetted__``-looking key nested inside payload is
        inert data, never interpreted here.
        """
        if isinstance(decoded, dict) and decoded.get(_UNVETTED_KEY) is True:
            ctx = decoded.get("ack_context")
            return cls(decoded.get("payload"),
                       origin=decoded.get("origin") or "reissue_reads",
                       ack_context=ctx if _valid_ack_context(ctx) else {})
        if isinstance(decoded, (dict, list, str, int, float, bool)) \
                or decoded is None:
            return cls(decoded, origin="unmarked-erased")
        raise TypeError(
            "Unvetted.from_envelope() takes a JSON-decoded value, got %s"
            % type(decoded).__name__)


class VettingCapability:
    """Possession token authorizing a vetting stack to mint Vetted.

    The gate is POSSESSION, not class: anyone may construct a
    VettingCapability, but only one issued by
    ``VettingStack.issue_capability()`` carries the stack's secret
    token, and only that token passes ``VettingStack.vet()``.
    Tokens are 256-bit secrets — unguessable, never serialized
    (copy/deepcopy/pickle all raise: possession is by reference).
    The loop is never issued a capability.
    """

    __slots__ = ("_token", "_purpose", "_public_id")

    def __init__(self, token, purpose="", public_id=None):
        self._token = bytes(token)
        self._purpose = purpose
        self._public_id = public_id or "cap-%s" % secrets.token_hex(8)

    @property
    def purpose(self):
        return self._purpose

    @property
    def public_id(self):
        """Non-secret id recorded in vetted envelopes so a decoder
        holding the stack can match capability to envelope without
        ever seeing the secret token."""
        return self._public_id

    def __copy__(self):
        raise VettingError("VettingCapability cannot be copied "
                           "(possession is by reference)")

    def __deepcopy__(self, _memo):
        raise VettingError("VettingCapability cannot be deep-copied "
                           "(possession is by reference)")

    def __reduce__(self):
        raise VettingError("VettingCapability cannot be pickled")

    def __reduce_ex__(self, _protocol):
        raise VettingError("VettingCapability cannot be pickled")


class VettingStack:
    """Mint authority for the "vetted" marker.

    Models the deployment's content-defense stack — the ONLY party
    that may claim content was vetted. Holds a per-instance 256-bit
    mint token; ``vet()`` mints only for capabilities carrying that
    token (constant-time compare). The executor, the agent, and the
    loop never receive a VettingStack — in-repo, tests construct one
    to stand in for the deployment stack.
    """

    def __init__(self, name="content-defense-stack"):
        self._name = name
        self._token = secrets.token_bytes(32)

    @property
    def name(self):
        return self._name

    def issue_capability(self, purpose):
        """Issue a minting-capable token for ``purpose`` (e.g.
        "human-review-queue", "dlp-rescan"). The ONLY source of
        capabilities that pass vet()."""
        if not isinstance(purpose, str) or not purpose:
            raise TypeError("issue_capability() requires a purpose string")
        return VettingCapability(self._token, purpose=purpose)

    def vet(self, payload, capability):
        """Mint the vetted marker for payload. Raises VettingError
        unless ``capability`` is a VettingCapability issued by THIS
        stack. Untrusted code holding no such capability cannot mint
        — the marker proves the stack saw the content."""
        if not isinstance(capability, VettingCapability):
            raise VettingError(
                "vet() requires a VettingCapability issued by this stack")
        if not hmac.compare_digest(bytes(capability._token), self._token):
            raise VettingError(
                "capability was not issued by this stack (mint refused)")
        return Vetted(payload, _VETTED_SEAL,
                      mint_id=capability.public_id, stack=self._name)


class Vetted:
    """Positive "vetted by the content-defense stack" marker.

    Cannot be constructed directly (TypeError) — only
    ``VettingStack.vet()`` mints. Read via ``.payload`` (no
    acknowledgement needed: the stack already vetted it). Like
    Unvetted, the wrapper never silently behaves as its payload,
    so the mark stays visible wherever the value travels.
    """

    __slots__ = ("_payload", "_mint_id", "_stack")

    def __init__(self, payload, _seal=None, mint_id=None, stack=None):
        if _seal is not _VETTED_SEAL:
            raise TypeError(
                "Vetted cannot be constructed directly — only "
                "VettingStack.vet() mints the vetted marker")
        self._payload = payload
        self._mint_id = mint_id
        self._stack = stack

    @property
    def payload(self):
        return self._payload

    @property
    def mint_id(self):
        return self._mint_id

    @property
    def stack(self):
        return self._stack

    def __iter__(self):
        raise TypeError(_VETTED_CONFUSION_MSG)

    def __len__(self):
        raise TypeError(_VETTED_CONFUSION_MSG)

    def __getitem__(self, _index):
        raise TypeError(_VETTED_CONFUSION_MSG)

    def __contains__(self, _item):
        raise TypeError(_VETTED_CONFUSION_MSG)

    def __repr__(self):
        try:
            shape = "items=%d" % len(self._payload)
        except TypeError:
            shape = "type=%s" % type(self._payload).__name__
        return "Vetted(stack=%r, mint_id=%r, %s)" % (
            self._stack, self._mint_id, shape)

    def to_envelope(self):
        """JSON-safe dict. Carries the NON-SECRET mint_id only — the
        secret token never serializes. A decoder re-materializes the
        mark only via Vetted.from_envelope WITH a live (stack,
        capability); without one the envelope decodes as Unvetted
        (fail-closed)."""
        return {_VETTED_KEY: True, "mint_id": self._mint_id,
                "stack": self._stack, "payload": self._payload}

    @classmethod
    def from_envelope(cls, decoded, stack, capability):
        """Re-materialize a vetted mark from a JSON envelope. Raises
        VettingError unless the envelope carries the vetted key, the
        mint_id matches the capability, and the capability passes
        the stack's vet() check. There is deliberately no
        capability-free decode path — an unverifiable "vetted" claim
        is unvetted, full stop."""
        if not isinstance(decoded, dict) \
                or decoded.get(_VETTED_KEY) is not True:
            raise VettingError("not a vetted envelope")
        if not isinstance(stack, VettingStack):
            raise VettingError("from_envelope() requires the VettingStack")
        if not isinstance(capability, VettingCapability):
            raise VettingError("from_envelope() requires a VettingCapability")
        if capability.public_id != decoded.get("mint_id"):
            raise VettingError("vetted envelope mint_id does not match "
                               "the capability (forgery or wrong stack)")
        return stack.vet(decoded.get("payload"), capability)


# ------------------------------------------------------------------
# Wave-67 D5 — authenticated consumer registry for ack evidence.
#
# The documented gap from waves 64–66: consumer identity in the D5
# acknowledgment trail was SELF-ATTESTED ("anyone can type a consumer
# name"). For the founder's evidence bet (sell evidence, not the
# engine), unattributable evidence is weak evidence — an auditor
# cannot distinguish "the loop acknowledged" from "anyone typed a
# consumer name." This closes the gap by mechanism without making
# tokens mandatory (Wave-49 lesson: existing acknowledge() callers
# keep working, stamped "unattributed").
#
# Design (full answers in workstreams/evals/CONSUMER_REGISTRY.md):
#
# (a) PLACEMENT — the registry is DEPLOYMENT-scoped, never
# run-scoped. The executor never issues consumer tokens: issuance
# belongs to the deployment's consumer-registration authority
# (operator console, deployment IAM, onboarding flow) OUTSIDE the
# evidenced run — a run minting its own evidence tokens is
# self-attestation with extra steps. In-repo, the ConsumerRegistry
# object stands in for that authority, exactly as VettingStack
# stands in for the deployment's content-defense stack. Run-side
# code (sterile.py, the executor) only VERIFIES.
#
# (b) LIFECYCLE — register_consumer() issues a ConsumerToken: a
# 256-bit bearer HMAC-bound (registry's 256-bit mint secret) to
# (public_token_id, consumer_id, issued_at, ttl_s). Non-serializable,
# non-copyable (VettingCapability precedent: possession is by
# reference; copy/deepcopy/pickle raise). verify() checks type, MAC
# (constant-time), bound-id == claimed consumer_id (cross-name token
# theft fails LOUD), ttl (injectable clock), and the revocation set.
# revoke(public_token_id) fails future acks LOUD; history is
# APPEND-ONLY — already-chained records keep their attribution with
# the public token_id and ts, so an auditor verifies validity-at-
# time. Nothing is ever rewritten.
#
# (c) ANONYMOUS PATH — acknowledge() without the (token, registry)
# pair behaves exactly as wave-66, stamped "attribution":
# "unattributed". An attacker "laundering" a sensitive ack as
# unattributed is the designed behavior (honestly marked; the
# anonymous path was always open) — a deployment that needs
# attribution for sensitive flows refuses unattributed acks at ITS
# policy layer. The mechanism's guarantee is exact: nothing reaches
# the chain marked "authenticated" without a live registry-issued
# token bound to the named consumer.
#
# (d) THE PRECISE CLAIM — "authenticated" means: at ack time the
# caller presented a bearer token issued by this registry,
# HMAC-bound to the named consumer_id, neither expired nor revoked
# at ack time. It does NOT prove human identity (the registry binds
# registrations; the deployment binds registrations to people), and
# it does NOT prove non-theft: an in-process holder using the token
# under the bound name verifies as that registration (possession is
# the claim — F59-class residual, stated honestly, not filed).
#
# $0, stdlib only (hmac, secrets, time). Deterministic (injectable
# clock).
# ------------------------------------------------------------------


class ConsumerAuthError(VettingError):
    """A consumer-token verification failed (fail-closed, LOUD).

    Subclasses VettingError (the family of mint/verification
    failures): a forged, flipped, foreign, misbound, expired, or
    revoked consumer token is refused exactly like a forged vetted
    mark. Raised by ConsumerRegistry.verify() — and therefore by
    Unvetted.acknowledge() — BEFORE any record is appended and
    before the payload is reachable. There is deliberately no
    invalid-token→"unattributed" degradation path: silent downgrade
    would be a laundering primitive."""


def _reg_mac(secret, public_id, consumer_id, issued_at, ttl_s, bearer):
    """Registry token MAC: binds bearer to its registration tuple."""
    ttl_repr = b"" if ttl_s is None else repr(ttl_s).encode("ascii")
    msg = b"\x00".join((
        public_id.encode("ascii"),
        consumer_id.encode("utf-8"),
        repr(issued_at).encode("ascii"),
        ttl_repr,
        bearer,
    ))
    return hmac.new(secret, msg, "sha256").digest()


class ConsumerToken:
    """Bearer token binding a consumer registration to ack evidence.

    Issued ONLY by ``ConsumerRegistry.register_consumer()``. The
    256-bit bearer is possession; the HMAC binds it to the
    registration tuple (public_token_id, consumer_id, issued_at,
    ttl_s) under the registry's mint secret, so bit-flips and
    foreign mints fail verification. Non-serializable, non-copyable
    (VettingCapability precedent): possession is by reference, the
    secret never leaves the object. Two registrations of the same
    consumer_id get distinct public ids — the chained record
    distinguishes them.
    """

    __slots__ = ("_bearer", "_mac", "_consumer_id", "_public_id",
                 "_issued_at", "_ttl_s")

    def __init__(self, bearer, mac, consumer_id, public_id, issued_at,
                 ttl_s):
        self._bearer = bytes(bearer)
        self._mac = bytes(mac)
        self._consumer_id = consumer_id
        self._public_id = public_id
        self._issued_at = issued_at
        self._ttl_s = ttl_s

    @property
    def consumer_id(self):
        """The registration's consumer label (the id the token is
        bound to; verify() requires the caller to claim exactly this)."""
        return self._consumer_id

    @property
    def public_id(self):
        """Non-secret token id recorded in ack records so an auditor
        can match record to registration (and distinguish two
        registrations of the same consumer_id) without ever seeing
        the secret bearer."""
        return self._public_id

    @property
    def issued_at(self):
        return self._issued_at

    @property
    def ttl_s(self):
        return self._ttl_s

    def __copy__(self):
        raise ConsumerAuthError("ConsumerToken cannot be copied "
                                "(possession is by reference)")

    def __deepcopy__(self, _memo):
        raise ConsumerAuthError("ConsumerToken cannot be deep-copied "
                                "(possession is by reference)")

    def __reduce__(self):
        raise ConsumerAuthError("ConsumerToken cannot be pickled")

    def __reduce_ex__(self, _protocol):
        raise ConsumerAuthError("ConsumerToken cannot be pickled")

    def __repr__(self):
        return "ConsumerToken(consumer_id=%r, public_id=%r)" % (
            self._consumer_id, self._public_id)


class ConsumerRegistry:
    """Deployment-scoped issuance/verification authority for consumer
    tokens (wave-67 D5).

    Holds a per-instance 256-bit mint secret; ``register_consumer()``
    is the ONLY source of tokens that pass ``verify()`` (constant-
    time MAC compare). The executor is never given a registry with
    mint power — in-repo the deployment's registration authority IS
    this object; a real deployment wires its own registration
    service (operator console / IAM / onboarding) behind the same
    interface. ``now`` is an injectable clock (seconds); ``name`` is
    the authority's label for audit.
    """

    def __init__(self, name="consumer-registry", now=None):
        if not isinstance(name, str) or not name:
            raise TypeError("ConsumerRegistry requires a name string")
        self._name = name
        self._secret = secrets.token_bytes(32)
        self._now = now or time.time
        self._revoked = set()

    @property
    def name(self):
        return self._name

    def register_consumer(self, consumer_id, ttl_s=None):
        """Issue a token for ``consumer_id`` (non-empty string).

        ``ttl_s`` (optional): token lifetime in seconds; None means
        no expiry. Returns a ConsumerToken. Two registrations of the
        same consumer_id are independent registrations (distinct
        public ids, independent revocation) — the chained record
        distinguishes them via token_id.
        """
        if not isinstance(consumer_id, str) or not consumer_id:
            raise TypeError(
                "register_consumer() requires a non-empty consumer_id "
                "string")
        if ttl_s is not None:
            if (isinstance(ttl_s, bool) or not isinstance(ttl_s, (int, float))
                    or ttl_s <= 0):
                raise TypeError("ttl_s must be a positive number or None")
        issued_at = self._now()
        public_id = "tok-%s" % secrets.token_hex(16)
        bearer = secrets.token_bytes(32)
        mac = _reg_mac(self._secret, public_id, consumer_id, issued_at,
                       ttl_s, bearer)
        return ConsumerToken(bearer, mac, consumer_id, public_id,
                             issued_at, ttl_s)

    def verify(self, token, consumer_id):
        """Verify a presented token against a claimed consumer_id.

        Returns {"token_id": public_id, "consumer_id": consumer_id,
        "issued_at": ...} on success. Raises ConsumerAuthError (loud,
        fail-closed) on: non-ConsumerToken, MAC mismatch (forgery,
        bit-flip, foreign-registry token), bound-id != claimed
        consumer_id (cross-name token theft), expiry, revocation.
        """
        if not isinstance(token, ConsumerToken):
            raise ConsumerAuthError(
                "verify() requires a ConsumerToken issued by a "
                "ConsumerRegistry")
        expected = _reg_mac(self._secret, token._public_id,
                            token._consumer_id, token._issued_at,
                            token._ttl_s, token._bearer)
        if not hmac.compare_digest(expected, token._mac):
            raise ConsumerAuthError(
                "consumer token MAC invalid (forgery, bit-flip, or "
                "foreign-registry token)")
        if token._consumer_id != consumer_id:
            raise ConsumerAuthError(
                "consumer token is bound to %r, presented for %r "
                "(cross-name token use refused)" % (token._consumer_id,
                                                   consumer_id))
        if (token._ttl_s is not None
                and self._now() >= token._issued_at + token._ttl_s):
            raise ConsumerAuthError(
                "consumer token %r expired" % token._public_id)
        if token._public_id in self._revoked:
            raise ConsumerAuthError(
                "consumer token %r revoked" % token._public_id)
        return {"token_id": token._public_id,
                "consumer_id": token._consumer_id,
                "issued_at": token._issued_at}

    def revoke(self, public_id):
        """Revoke a token by public id. Fails FUTURE verifications
        LOUD; already-chained ack records are append-only history and
        are never rewritten (validity-at-time is auditable via the
        record's token_id + ts). Unknown ids revoke silently (a
        no-op) — revocation is idempotent."""
        if not isinstance(public_id, str) or not public_id:
            raise TypeError("revoke() requires a non-empty public_id "
                            "string")
        self._revoked.add(public_id)

    def is_revoked(self, public_id):
        """Introspection for auditors/tests (read-only)."""
        return public_id in self._revoked

    def __repr__(self):
        return "ConsumerRegistry(name=%r, revoked=%d)" % (
            self._name, len(self._revoked))
