"""Provenance-graded sink policy + CaMeL-style quarantine (Row 7 build step 5).

Design lineage (attributed, not vendored):
- The ``allow(tool, ctx) iff required_trust(tool) <= min trust`` invariant is
  Tessera's (https://github.com/kenithphilip/Tessera, Apache-2.0, LICENSE
  re-verified 2026-10-03). Copyright 2026 Kenith Philip and Tessera
  contributors. Tessera's library deps (pydantic/fastapi/uvicorn) cannot land
  in this stdlib-only tree, so the invariant is re-implemented here.
- Single-use argument-bound declassification is TokenTaint's
  ``CapabilityAuthority`` bridge (MIT), wired to our step-3 authority
  (gov/approval_tokens.py).
- The capacity rule (bool/enum/number declassify by value; string only as an
  opaque ref) is FIDES's information-capacity lattice (MIT, arXiv:2505.23643).
- The refuse+re-plan / escalate / redact / quarantine verdict contract and
  "call never executes, prefix preserved" semantics are CaMeL's
  (google-research/camel-prompt-injection, Apache-2.0); the refusal-feedback
  redaction answers CaMeL's redacted-error discipline.
- The "attack_success_rate, not detection rate" measurement discipline is
  provenance-gateway C3's (MIT).

Threat model (what this gate is and is not):
- IS: a per-tool-call enforcement check at the tool-call boundary. Every
  influencing segment carries an HMAC-sealed provenance label
  (gov/provenance_labels.py); unverifiable labels downgrade to UNTRUSTED.
  The gate refuses, escalates, or redacts calls whose required trust is not
  met by the context's minimum trust, with a per-critical-argument
  refinement so user-bound arguments (recipient copied from the user prompt)
  do not false-positive on mixed-trust context.
- IS the answer to wave-313 lane E's deferred fn-body indirection:
  plan-policy attributes capability from *declared* tool names; a lying fn
  (declares ``read_file``, actually exfiltrates) passed it. Any real
  exfiltration must pass through an actual egress-sink tool call, and that
  call is labeled by its REAL identity here. Coverage requires this gate
  wired at the call boundary (see ``provenance_gate``).
- IS NOT a laundering detector. Trusted-transform laundering
  (paraphrase/summarize through trusted transforms, model-internal
  reconstruction) is unsolved deterministically -- the field's honest answer
  is quarantine + constrained outputs + capability-bounded sinks, stated
  here as a boundary, not hidden.
- Denials are first-class provenance nodes with GENERIC reasons (the
  causality-laundering lesson: a refusal informs the agent, so refusal
  reasons carry no content).

Determinism: no time on the hot path (``now`` is passed explicitly for
declassification verification), no randomness, no I/O, no LLM.

Stdlib only.
"""

import hashlib
import json
import re
import time

try:
    from . import provenance_labels as _pl
    from . import approval_tokens as _at
except ImportError:  # standalone
    import provenance_labels as _pl
    import approval_tokens as _at

# ---------------------------------------------------------------------------
# Codes (+9 -> pin 1888)
# ---------------------------------------------------------------------------

LABEL_UNVERIFIABLE = "provenance-label-unverifiable"
LABEL_TAMPERED = "provenance-label-tampered"
UNKNOWN_TOOL = "provenance-sink-unknown-tool"
SINK_REFUSED = "provenance-sink-refused"
CRITICAL_ARG_REFUSED = "provenance-critical-arg-refused"
DECLASSIFY_INVALID = "provenance-declassify-invalid"
QUARANTINE_TERMINAL = "provenance-quarantine-terminal"
SINK_ESCALATED = "provenance-sink-escalated"
SINK_REDACTED = "provenance-sink-redacted"

T = _pl.TrustLevel

# ---------------------------------------------------------------------------
# Tool declarations. ALIGNED with gov/trajectory_risk.py and
# gov/plan_policy.py tool-class tables (same operational tool names);
# drift is caught by the alignment unit test, not a shared import.
# Undeclared tools are deny-by-default at USER trust.
# ---------------------------------------------------------------------------

_EGRESS = ("send_email", "http_post", "http_request", "send_message",
           "upload_file", "scp", "ftp_put", "webhook_post", "publish")
_STATE = ("write_file", "delete_file", "append_file", "chmod", "shell_exec",
          "run_command", "mkdir", "move_file", "install_package",
          "pip_install")
_OBSERVE = ("read_file", "list_dir", "glob", "http_get", "search", "cat")

#: Default critical arguments per tool (recipients, accounts, paths,
#: commands -- never amounts/body). A tool not listed here falls back to
#: the generic critical-arg vocabulary intersected with its actual args.
_DEFAULT_CRITICAL_ARGS = {
    "send_email": ("to", "cc", "bcc"),
    "send_message": ("to", "recipient"),
    "http_post": ("url",),
    "http_request": ("url",),
    "upload_file": ("path", "dest"),
    "scp": ("dest", "host"),
    "ftp_put": ("dest", "host"),
    "webhook_post": ("url",),
    "publish": ("endpoint",),
    "write_file": ("path",),
    "delete_file": ("path",),
    "append_file": ("path",),
    "move_file": ("src", "dest"),
    "chmod": ("path",),
    "shell_exec": ("command",),
    "run_command": ("command",),
    "install_package": ("package",),
    "pip_install": ("package",),
}
_GENERIC_CRITICAL = frozenset({"to", "cc", "bcc", "recipient", "url",
                               "host", "address", "endpoint", "path",
                               "filepath", "filename", "dest", "src",
                               "command", "package"})

#: Tools whose default on_violation is ESCALATE (destructive or
#: hard-to-undo): a human adjudicates instead of an automatic refuse.
_DEFAULT_ESCALATE = frozenset({"delete_file", "chmod", "shell_exec",
                               "run_command", "install_package",
                               "pip_install"})


class SinkError(Exception):
    """Coded refusal from the sink gate."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class ToolSpec(object):
    """One tool's sink declaration: the minimum trust a context must
    carry for the call to proceed, its side effects, the arguments
    that get per-argument refinement, and the violation posture."""

    def __init__(self, name, required_trust, side_effects=(),
                 critical_args=(), on_violation="REFUSE"):
        self.name = str(name)
        self.required_trust = int(required_trust)
        self.side_effects = tuple(side_effects)
        self.critical_args = tuple(critical_args)
        if on_violation not in ("REFUSE", "ESCALATE", "REDACT"):
            raise SinkError("unknown on_violation %r" % (on_violation,),
                            code=UNKNOWN_TOOL)
        self.on_violation = on_violation

    def __repr__(self):
        return "ToolSpec(%r, trust=%d, %s)" % (
            self.name, self.required_trust, self.on_violation)


def _default_policy():
    policy = {}
    for name in _EGRESS:
        policy[name] = ToolSpec(
            name, T.USER, side_effects=("egress",),
            critical_args=_DEFAULT_CRITICAL_ARGS.get(name, ()),
            on_violation="REFUSE")
    for name in _STATE:
        policy[name] = ToolSpec(
            name, T.TOOL, side_effects=("state",),
            critical_args=_DEFAULT_CRITICAL_ARGS.get(name, ()),
            on_violation=("ESCALATE" if name in _DEFAULT_ESCALATE
                          else "REFUSE"))
    for name in _OBSERVE:
        policy[name] = ToolSpec(name, T.UNTRUSTED,
                                side_effects=("observation",),
                                critical_args=(),
                                on_violation="REFUSE")
    return policy


class SinkVerdict(object):
    """The outcome of one sink check. ``verdict`` is one of ALLOW /
    REFUSE / ESCALATE / REDACT. ``redacted_args`` carries the
    post-redaction call args (opaque refs, never raw untrusted bytes).
    ``audit_codes`` names every coded event the check emitted
    (label problems ride along even when the verdict is ALLOW).
    ``declassified`` marks an audited declassification having applied."""

    __slots__ = ("verdict", "code", "detail", "audit_codes",
                 "redacted_args", "declassified")

    def __init__(self, verdict, code, detail="", audit_codes=(),
                 redacted_args=None, declassified=False):
        self.verdict = verdict
        self.code = code
        self.detail = detail
        self.audit_codes = tuple(audit_codes)
        self.redacted_args = (dict(redacted_args)
                              if redacted_args is not None else None)
        self.declassified = bool(declassified)

    def to_dict(self):
        return {
            "verdict": self.verdict,
            "code": self.code,
            "detail": self.detail,
            "audit_codes": list(self.audit_codes),
            "redacted_args": self.redacted_args,
            "declassified": self.declassified,
        }

    def __repr__(self):
        return "SinkVerdict(%s, %s)" % (self.verdict, self.code)


def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


#: Deterministic negation vocabulary for the F398 critical-arg fix.
#: A critical-arg value that occurs inside a negated clause is not an
#: authorizing mention -- mention is not authorization. This is a
#: conservative floor, not an NLP claim: anything not recognized as
#: negated is still judged by the ordinary trust rules, and anything
#: recognized as negated simply stops contributing trust (fail closed).
#: Tokens are lowercased, punctuation-stripped, apostrophes preserved.
_NEGATION_CUES = frozenset({
    "never", "not", "no", "none", "nobody", "nothing", "neither", "nor",
    "without", "cannot",
    "don't", "doesn't", "didn't", "can't", "won't", "shouldn't",
    "wouldn't", "couldn't", "mustn't", "isn't", "aren't", "wasn't",
    "weren't", "haven't", "hasn't", "hadn't",
    "refuse", "refuses", "refused",
    "prohibit", "prohibits", "prohibited",
    "forbid", "forbids", "forbidden", "forbade",
    "block", "blocks", "blocked",
    "avoid", "avoided",
    "exclude", "excludes", "excluded",
    "disallow", "disallows", "disallowed",
    "stop", "stopped", "stopping",
    "deny", "denies", "denied",
    "reject", "rejects", "rejected",
    "halt", "halts", "halted",
})

#: Clause boundaries for negation scoping. A period splits only when
#: followed by whitespace, so values like "mallory@evil.com" and
#: "v1.2" are never torn apart; contrastive conjunctions start a new
#: clause so "you may email X but never cc Y" judges X and Y
#: independently (per-mention).
_CLAUSE_SPLIT = re.compile(
    r"[!?;\n]+|\.(?=\s)|\b(?:but|however|yet|although|though)\b",
    re.IGNORECASE)

_WORD = re.compile(r"[a-zA-Z']+")


def _clause_negated(clause):
    """True iff the clause carries a negation cue (F398)."""
    return any(tok in _NEGATION_CUES
               for tok in _WORD.findall(clause.lower()))


def _affirmative_mention(content, text):
    """True iff ``text`` occurs in ``content`` in at least one clause
    with no negation cue (F398). A negated occurrence -- a prohibition,
    a "don't", a "never" -- is not an authorizing mention and is
    discounted everywhere it appears."""
    if not content or not text:
        return False
    start = 0
    for match in _CLAUSE_SPLIT.finditer(content):
        clause = content[start:match.start()]
        if text in clause and not _clause_negated(clause):
            return True
        start = match.end()
    tail = content[start:]
    return text in tail and not _clause_negated(tail)


def _coerce_segment(raw):
    """Accept a Segment or its to_dict() form (records are JSON-native,
    so segments cross the queue as dicts). Anything else is an
    unverifiable segment -- fail closed, never guess."""
    if isinstance(raw, _pl.Segment):
        return raw
    try:
        return _pl.Segment.from_dict(raw)
    except _pl.LabelError:
        return _pl.Segment(
            segment_id="uncoercible",
            label=_pl.ProvenanceLabel(origin=_pl.Origin.WEB,
                                      principal="unknown",
                                      trust_level=_pl.TrustLevel.UNTRUSTED,
                                      nonce="x", signature=""),
            content="")


def _hex(value):
    return hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


#: Refusals against the same (tool, segment-set) context before the
#: gate goes escalate-terminal (CaMeL's bounded re-plan, tightened:
#: three strikes, then a human owns it).
REPLAN_BUDGET = 3

#: Opaque-ref prefix for redacted critical args (FIDES variable-hiding:
#: untrusted bytes never reach the model-visible context again).
REDACT_PREFIX = "$UNTRUSTED_"

#: The step-3 capability a declassification token must carry.
DECLASSIFY_CAPABILITY = "provenance-declassify"

#: FIDES capacity classes. Only bounded capacities declassify by value;
#: a STRING channel declassifies as an opaque ref or not at all.
CAPACITIES = ("bool", "enum", "number", "string")
_VALUE_CAPACITIES = frozenset({"bool", "enum", "number"})


def _capacity_of(value, enum_values=None):
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if enum_values and value in enum_values:
        return "enum"
    return "string"


class ProvenanceSink(object):
    """The provenance-graded sink gate. ``check`` is pure given the
    segments; the sink object itself holds the quarantine set, the
    re-plan budget counters, the consumed-declassification set, and the
    hash-chained quarantine log (all in-memory; a deployment persists
    them or loses them on restart -- fail closed, never silently)."""

    def __init__(self, policy=None):
        self._policy = dict(policy) if policy is not None \
            else _default_policy()
        self._quarantined = set()      # segment ids
        self._refusals = {}            # ctx key -> count
        self._consumed = set()         # declassification nonces
        self._log = []                 # QuarantineRecords (chained)
        self._redact_seq = 0

    @classmethod
    def with_policy(cls, policy):
        """Build a sink with an explicit per-tool policy (tests and
        deployments declare; the default policy is never silently
        extended)."""
        base = _default_policy()
        base.update(dict(policy))
        return cls(policy=base)

    # -- introspection -------------------------------------------------
    def quarantined(self):
        return tuple(sorted(self._quarantined))

    def quarantine_log(self):
        return [dict(r) for r in self._log]

    # -- the check ------------------------------------------------------
    def check(self, tool, args, segments, declassify_token=None, now=None):
        """Evaluate one tool call against labeled context segments.

        ``segments``: iterable of provenance_labels.Segment (id, label,
        content). ``declassify_token``: an optional step-3 approval
        token (capability ``provenance-declassify``). ``now``: explicit
        epoch seconds for token verification (never read on the hot
        path otherwise). Returns a SinkVerdict; never raises on
        adversarial input -- every refusal is a verdict with a code.
        """
        at = int(now) if now is not None else int(time.time())
        args = dict(args or {})
        segments = [_coerce_segment(s) for s in (segments or [])]
        audit = []

        spec = self._policy.get(tool)
        if spec is None:
            # Undeclared tools are deny-by-default at USER trust.
            spec = ToolSpec(tool, T.USER, side_effects=("unknown",),
                            critical_args=(), on_violation="REFUSE")
            unknown = True
        else:
            unknown = False

        # 1. Verify every segment label. Unverifiable -> UNTRUSTED,
        #    fail closed; the tamper is coded and rides the audit trail.
        graded = []  # (segment, trust, verified)
        for seg in segments:
            ok = _pl.verify_label(seg.label, seg.content)
            if ok:
                graded.append((seg, int(seg.label.trust_level), True))
            else:
                code = (LABEL_TAMPERED if seg.label.signature
                        else LABEL_UNVERIFIABLE)
                audit.append(code)
                graded.append((seg, T.UNTRUSTED, False))

        # 2. Re-plan budget: three refusals against the same context,
        #    then escalate-terminal (bounded re-plan, CaMeL discipline).
        ctx_key = _hex({"tool": tool,
                        "segments": sorted(s.segment_id
                                           for s, _, _ in graded)})
        if self._refusals.get(ctx_key, 0) >= REPLAN_BUDGET:
            return self._refuse(QUARANTINE_TERMINAL,
                                "re-plan budget exhausted for this "
                                "context -- escalate-terminal; a human "
                                "owns the reroute",
                                audit, graded)

        # 3. Declassification: a valid single-use step-3 token lifts one
        #    named segment (scalar scope) or one named critical arg
        #    (arg scope). Anything invalid refuses DECLASSIFY_INVALID.
        cleared_segment = None
        cleared_arg = None
        redacted = None
        declassified = False
        if declassify_token is not None:
            outcome = self._apply_declassification(
                declassify_token, tool, args, graded, at, audit)
            if outcome.get("invalid"):
                return self._refuse(DECLASSIFY_INVALID,
                                    outcome["invalid"], audit, graded)
            if outcome.get("redacted_args") is not None:
                # FIDES: a string-capacity channel declassifies as an
                # opaque ref, never by value
                return SinkVerdict(
                    "REDACT", SINK_REDACTED,
                    "declassified string-capacity channel continues "
                    "as an opaque ref",
                    audit_codes=audit,
                    redacted_args=outcome["redacted_args"],
                    declassified=True)
            cleared_segment = outcome.get("segment_id")
            cleared_arg = outcome.get("arg")
            declassified = True

        # 4. Scalar floor: required_trust <= min trust over LIVE
        #    segments (quarantined segments are excluded -- they stay
        #    auditable but stop influencing). An empty live set means
        #    no live trust at all -> UNTRUSTED.
        live = [(s, t) for s, t, _ in graded
                if s.segment_id not in self._quarantined
                and s.segment_id != cleared_segment]
        if cleared_segment is not None:
            live.append((None, T.USER))  # audited endorsement
        min_trust = min((t for _, t in live), default=T.UNTRUSTED)

        if unknown:
            return self._violate(spec, UNKNOWN_TOOL,
                                 "tool %r is not declared in the sink "
                                 "policy -- deny by default" % (tool,),
                                 audit, graded, ctx_key, args)

        if min_trust >= spec.required_trust:
            if declassified:
                # An audited declassification applied: record it as an
                # informational (non-taxonomy) audit event. The step-3
                # token is the durable audit trail; this log entry is
                # the local one.
                self._record(graded, tool, "provenance-declassified",
                             "single-use capability applied; segment "
                             "endorsed at USER trust for this check")
            return SinkVerdict("ALLOW", "provenance-sink-allowed",
                               "min trust %d meets required %d"
                               % (min_trust, spec.required_trust),
                               audit_codes=audit, declassified=declassified)

        # 5. Critical-arg refinement (Tessera's over-blocking fix): for
        #    critical args only, bind each arg to the most trusted
        #    segment that contains its value; an arg copied from the
        #    user prompt binds at USER even on mixed-trust context.
        critical = [a for a in self._critical_for(spec, args)
                    if a != cleared_arg]
        if not critical:
            if cleared_arg is not None:
                # the only contested arg was declassified by value
                self._record(graded, tool, "provenance-declassified",
                             "single-use capability applied; arg %r "
                             "declassified by value" % (cleared_arg,))
                return SinkVerdict(
                    "ALLOW", "provenance-sink-allowed",
                    "critical arg %r declassified by audited "
                    "single-use capability" % (cleared_arg,),
                    audit_codes=audit, declassified=True)
            return self._violate(spec, SINK_REFUSED,
                                 "min trust %d < required %d for %r; no "
                                 "critical args to refine"
                                 % (min_trust, spec.required_trust, tool),
                                 audit, graded, ctx_key, args)
        failing = []
        for name in critical:
            bound = self._bind_arg(args[name], graded)
            if bound < spec.required_trust:
                failing.append(name)
        if not failing:
            return SinkVerdict(
                "ALLOW", "provenance-sink-allowed",
                "min trust %d < required %d but every critical arg "
                "binds at or above required trust (user-bound refinement)"
                % (min_trust, spec.required_trust),
                audit_codes=audit, declassified=declassified)
        return self._violate(
            spec, CRITICAL_ARG_REFUSED,
            "critical arg(s) %s bind below required trust %d "
            "(context min %d)" % (sorted(failing),
                                   spec.required_trust, min_trust),
            audit, graded, ctx_key, args, failing=failing)

    # -- internals -------------------------------------------------------
    def _critical_for(self, spec, args):
        names = list(spec.critical_args) or [
            a for a in args if a in _GENERIC_CRITICAL]
        return [a for a in names if a in args]

    def _bind_arg(self, value, graded):
        """Bind one arg value to a trust level, in precedence order:
        (1) the value appears AFFIRMATIVELY in a live user/system
        segment -> USER; (2) else the trust of the most-recent live
        segment containing it affirmatively; (3) else the context min.
        A negated occurrence (a prohibition: "never email X") is not an
        authorizing mention -- mention is not authorization -- and is
        discounted in both rules (F398). Deterministic (trajectory order
        is the tiebreak)."""
        text = value if isinstance(value, str) else _canon(value)
        if not text:
            return T.UNTRUSTED
        live = [(s, t) for s, t, _ in graded
                if s.segment_id not in self._quarantined]
        for s, t in live:
            if t >= T.USER and _affirmative_mention(s.content or "",
                                                    text):
                return T.USER
        for s, t in reversed(live):
            if _affirmative_mention(s.content or "", text):
                return t
        return min((t for _, t in live), default=T.UNTRUSTED)

    def _apply_declassification(self, token, tool, args, graded, at,
                                audit):
        """Validate a step-3 declassification token. Returns a dict
        with segment_id/arg/redacted_args, or {"invalid": reason}."""
        try:
            body = token if isinstance(token, dict) else None
            if body is None:
                return {"invalid": "declassification token must be a dict"}
            binding = body.get("argument_binding") or {}
            if not isinstance(binding, dict) or \
                    binding.get("mode") != "exact":
                return {"invalid": "declassification requires an "
                                   "exact-mode token"}
            bound = binding.get("args") or {}
            for k in ("segment_id", "tool", "scope", "capacity"):
                if k not in bound:
                    return {"invalid": "declassification binding "
                                       "missing %r" % k}
            if bound["capacity"] not in CAPACITIES:
                return {"invalid": "unknown capacity class"}
            sid = bound["segment_id"]
            seg = next((s for s, _, _ in graded
                        if s.segment_id == sid), None)
            if seg is None:
                return {"invalid": "declassification names an unknown "
                                   "segment"}
            scope = bound["scope"]
            presented = {"segment_id": sid, "tool": tool,
                         "scope": scope,
                         "capacity": bound["capacity"]}
            if "enum_values" in bound:
                presented["enum_values"] = bound["enum_values"]
            if scope == "scalar":
                pass  # presented capacity is the authority's declaration
            elif scope.startswith("arg:"):
                name = scope[4:]
                if name not in args:
                    return {"invalid": "declassification names an arg "
                                       "not present in the call"}
                # the presented capacity is recomputed from the live
                # value; a token declaring "string" for a bool value
                # (or vice versa) does not verify
                presented["capacity"] = _capacity_of(
                    args[name], bound.get("enum_values"))
            else:
                return {"invalid": "unknown declassification scope"}
            _at.verify_token(token, capability=DECLASSIFY_CAPABILITY,
                             args=presented, now=at)
        except _at.ApprovalTokenError as e:
            return {"invalid": "token rejected: %s"
                    % (e.code or "approval-token error",)}
        except Exception as e:
            return {"invalid": "token rejected: %r" % (e,)}
        nonce = token.get("nonce")
        if nonce in self._consumed:
            return {"invalid": "declassification token already consumed "
                               "(single-use)"}
        self._consumed.add(nonce)
        if scope == "scalar":
            # Audited endorsement: the named segment's influence is
            # accepted at USER trust for this check only. The token is
            # the audit trail of the review.
            return {"segment_id": sid}
        # arg scope: FIDES capacity rule -- bounded capacities flow by
        # value; a string channel flows only as an opaque ref.
        if bound["capacity"] in _VALUE_CAPACITIES and \
                presented["capacity"] in _VALUE_CAPACITIES:
            return {"arg": name}
        self._redact_seq += 1
        ref = "%s%d" % (REDACT_PREFIX, self._redact_seq)
        new_args = dict(args)
        new_args[name] = ref
        return {"arg": name, "redacted_args": new_args}

    def _violate(self, spec, code, detail, audit, graded, ctx_key,
                 args, failing=None):
        """Route a violation through the tool's on_violation posture."""
        if spec.on_violation == "ESCALATE":
            rec = self._record(graded, spec.name, SINK_ESCALATED,
                               "parked for human adjudication")
            return SinkVerdict("ESCALATE", SINK_ESCALATED, detail,
                               audit_codes=audit)
        if spec.on_violation == "REDACT" and failing:
            new_args = dict(args)
            for name in failing:
                self._redact_seq += 1
                new_args[name] = "%s%d" % (REDACT_PREFIX,
                                           self._redact_seq)
            self._record(graded, spec.name, SINK_REDACTED,
                         "critical args redacted to opaque refs")
            return SinkVerdict("REDACT", SINK_REDACTED, detail,
                               audit_codes=audit,
                               redacted_args=new_args)
        return self._refuse(code, detail, audit, graded, ctx_key)

    def _refuse(self, code, detail, audit, graded, ctx_key=None):
        # Quarantine the least-trusted live segments (the offenders):
        # they stay in the audit trail but leave future min-trust
        # computations.
        live = [(s, t) for s, t, _ in graded
                if s.segment_id not in self._quarantined]
        if live:
            floor = min(t for _, t in live)
            for s, t in live:
                if t == floor:
                    self._quarantined.add(s.segment_id)
        if ctx_key is not None:
            self._refusals[ctx_key] = self._refusals.get(ctx_key, 0) + 1
        self._record(graded, None, code, detail)
        return SinkVerdict("REFUSE", code, detail, audit_codes=audit)

    def _record(self, graded, tool, code, detail):
        """Append a hash-chained quarantine/audit record. Reasons are
        generic by construction (no segment content ever lands here).
        Informational codes (``provenance-sink-allowed``,
        ``provenance-declassified``) are audit-only and intentionally
        NOT in the decision taxonomy -- the taxonomy registers refusal
        and action codes."""
        prev = self._log[-1]["digest"] if self._log else "GENESIS"
        rec = {
            "seq": len(self._log),
            "prev_digest": prev,
            "segment_ids": sorted(s.segment_id for s, _, _ in graded),
            "quarantined": sorted(self._quarantined),
            "tool": tool,
            "code": code,
            # generic: trust numbers only, never content
            "detail": detail,
        }
        rec["digest"] = _hex(rec)
        self._log.append(rec)
        return rec


def provenance_gate(tool, args, segments, **kwargs):
    """The executor-seam entry point. Returns None when no provenance
    context is supplied (the check is skipped entirely -- backward
    compatible, the lane-B token-check discipline); otherwise returns
    the SinkVerdict. A REFUSE/ESCALATE verdict must block the call."""
    if segments is None:
        return None
    return ProvenanceSink().check(tool, args, segments, **kwargs)
