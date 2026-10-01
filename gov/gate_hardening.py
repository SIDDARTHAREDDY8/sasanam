"""Enforcement-path hardening: Kubewarden-style hot-gate disciplines.

Architecture stolen (pattern only, nothing copied) from
kubewarden-controller ``09a105bc`` + kubewarden/policy-evaluator
``f599912f`` (both Apache-2.0): Monitor/Protect as a first-class
per-gate field, compile-once / fresh-runtime-per-request, inverted
deadline discipline (global floor required, per-policy overrides
tighten only), deny-by-default host-callback allowlist, default-deny
on gate error/timeout, and an audit-scanner analog with deterministic
ordering.

Sasanam-side decisions that differ from Kubewarden (documented traps
not copied):
  * ``failurePolicy=Ignore`` silently allowing is DROPPED -- Sasanam
    default = Fail; ignore only as a signed, expiring, audited
    exception.
  * Hardcoded namespace bypass is DROPPED -- break-glass is signed
    policy, never a namespace check.
  * Audit-scanner iteration is deterministic (sorted request ids) --
    Kubewarden's nondeterministic order trap is not copied.

Honest limits (documented, not hidden):
  * In-process Python predicates are trusted code. "Fresh discarded
    runtime" means each request gets a fresh, discarded ``Runtime``
    context object and the gate retains no per-request state -- it is
    NOT WASM-grade memory isolation. The host-callback allowlist and
    the deadline budget are the enforced boundaries.
  * Deadlines are a budget on *observed* evaluation time
    (``clock()`` before/after). A predicate that never returns is a
    deployment bug, not a preempted kill -- the gate cannot preempt
    in-process Python. The deadline refuses anything observed to
    exceed it, fail-closed.
  * The audit log is in-memory (deployment-owned durability is the
    caller's duty, as with the other in-memory stores in this tree).
    It is BOUNDED: ``audit_maxlen`` entries by construction (default
    1024); beyond the bound the oldest entries are evicted and the
    eviction is counted, never silent (see ``audit_dropped``).
  * fail-closed discipline applies even to BaseException: a predicate
    that raises SystemExit or KeyboardInterrupt produces a
    ``gatehard-gate-error`` deny instead of propagating -- this trades
    process-interrupt semantics for the fail-closed guarantee at the
    enforcement path. GeneratorExit is explicitly NOT swallowed: it is
    re-raised so generator cleanup semantics stay intact (pinned by
    unit test).
  * Monitor-but-count accounting (``monitor_deny_counts``,
    ``monitor_allow_count``, ``monitor_report()``, ``scan_summary()``)
    is verdict-level in-process counting, NOT kernel enforcement:
    monitor mode never denies (see ``gatehard-monitor-would-deny``), the
    counters count what the gate's own logic decided, they are lost on
    gate restart, and they are not thread-safe under concurrent
    evaluate() calls -- aggregation is a deployment-level duty.

Stdlib only. Deterministic given explicit ``now`` / ``clock``.
"""

import collections
import copy
import hashlib
import json
import time

from gov import ed25519 as _ed

# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------

class GateConfigError(Exception):
    """Loud constructor/registration refusal. Carries the machine code so
    batteries can pin the exact refusal."""

    def __init__(self, code, detail=""):
        super(GateConfigError, self).__init__(detail)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Policy compilation (compile-once, digest-keyed, deterministic)
# ---------------------------------------------------------------------------

def _request_id_of(request):
    """Best-effort request_id extraction that never raises (F291).

    Used on the early deepcopy-failure path in ``evaluate()``/``scan()``,
    where the caller's request object is hostile (non-copyable) and may
    not even be a dict -- ``request.get`` itself could raise. Returns "?"
    as the last resort, matching the modules' other fallbacks.
    """
    try:
        return request.get("request_id", "?")
    except Exception:  # noqa: BLE001 -- never raise on the error path
        return "?"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def compile_policy(spec):
    """Compile a policy spec dict into an immutable CompiledPolicy.

    spec keys: policy_id (str), predicate_name (str), predicate
    (callable), deadline_s (optional float), host_callbacks (list of str).
    The digest covers everything except the callable itself (which is
    named); two specs with the same bytes share a digest.
    """
    required = ("policy_id", "predicate_name", "predicate",
                "host_callbacks")
    for k in required:
        if k not in spec:
            raise GateConfigError("gatehard-policy-malformed",
                                  "missing spec key: %s" % k)
    # F276: host_callbacks is a list-typed field. A bare str used to be
    # silently mangled by tuple('exec') into ('e','x','e','c'), recording
    # garbage in the policy digest. Refuse loudly instead.
    hcb = spec["host_callbacks"]
    if isinstance(hcb, (str, bytes)) or not isinstance(hcb, (list, tuple)):
        raise GateConfigError(
            "gatehard-policy-malformed",
            "host_callbacks must be a list/tuple of str, got %r"
            % (hcb,))
    for entry in hcb:
        if not isinstance(entry, str):
            raise GateConfigError(
                "gatehard-policy-malformed",
                "host_callbacks entries must be str, got %r" % (entry,))
    return CompiledPolicy(
        policy_id=str(spec["policy_id"]),
        predicate_name=str(spec["predicate_name"]),
        predicate=spec["predicate"],
        deadline_s=spec.get("deadline_s"),
        host_callbacks=tuple(hcb),
    )


class CompiledPolicy(object):
    __slots__ = ("policy_id", "predicate_name", "predicate", "deadline_s",
                 "host_callbacks", "digest")

    def __init__(self, policy_id, predicate_name, predicate, deadline_s,
                 host_callbacks):
        self.policy_id = policy_id
        self.predicate_name = predicate_name
        self.predicate = predicate
        self.deadline_s = deadline_s
        self.host_callbacks = host_callbacks
        self.digest = hashlib.sha256(_canonical({
            "policy_id": policy_id,
            "predicate_name": predicate_name,
            "deadline_s": deadline_s,
            "host_callbacks": list(host_callbacks),
        })).hexdigest()


# ---------------------------------------------------------------------------
# Signed tokens: failure-ignore exception + break-glass
# ---------------------------------------------------------------------------

def failure_ignore_body(policy_id, not_before, expires_at, reason):
    return _canonical({"kind": "gatehard-failure-ignore",
                       "policy_id": policy_id,
                       "not_before": not_before,
                       "expires_at": expires_at,
                       "reason": reason})


def breakglass_body(request_class, not_before, expires_at, reason):
    return _canonical({"kind": "gatehard-breakglass",
                       "request_class": request_class,
                       "not_before": not_before,
                       "expires_at": expires_at,
                       "reason": reason})


class FailureIgnore(object):
    """Signed, expiring, audited exception to the default-deny-on-error
    rule. Verified against the deployment's exception-issuer key."""

    def __init__(self, policy_id, not_before, expires_at, reason,
                 signature):
        self.policy_id = policy_id
        self.not_before = not_before
        self.expires_at = expires_at
        self.reason = reason
        self.signature = signature


class BreakGlassToken(object):
    """Signed break-glass: signed policy, never a namespace check."""

    def __init__(self, request_class, not_before, expires_at, reason,
                 signature, namespace=None):
        self.request_class = request_class
        self.not_before = not_before
        self.expires_at = expires_at
        self.reason = reason
        self.signature = signature
        self.namespace = namespace


class _HostCallbackDenied(Exception):
    pass


# ---------------------------------------------------------------------------
# Fresh discarded runtime per request
# ---------------------------------------------------------------------------

class Runtime(object):
    """Per-request evaluation runtime. Fresh per request, discarded
    after -- the gate retains no reference once evaluate() returns."""

    __slots__ = ("ctx", "request", "_host_callback")

    def __init__(self, request, host_callback):
        self.ctx = {}
        self.request = request
        self._host_callback = host_callback

    def host_callback(self, name, *args):
        return self._host_callback(name, *args)


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

_MODES = ("monitor", "protect")


class Gate(object):
    #: Default audit-store bound (F257). The audit log never grows past
    #: this many entries; evictions are counted in ``audit_dropped``.
    DEFAULT_AUDIT_MAXLEN = 1024

    def __init__(self, mode="protect", global_deadline_s=None,
                 host_allowlist=frozenset(), now=None, clock=None,
                 breakglass_issuer_pub=None, exception_issuer_pub=None,
                 audit_maxlen=None):
        if mode not in _MODES:
            raise GateConfigError(
                "gatehard-unknown-mode",
                "mode must be one of %r, got %r" % (_MODES, mode))
        if not isinstance(global_deadline_s, (int, float)) or \
                not (global_deadline_s > 0):
            # Inverted Kubewarden trap: an UNSET global deadline is a
            # constructor refusal, never a silent per-policy ignore.
            raise GateConfigError(
                "gatehard-global-deadline-unset",
                "global_deadline_s is required and must be > 0; an "
                "unset global deadline would silently ignore "
                "per-policy timeouts")
        allow = frozenset(host_allowlist or ())
        for entry in allow:
            if "*" in str(entry):
                raise GateConfigError(
                    "gatehard-host-callback-wildcard",
                    "wildcard host-callback entries are not offered; "
                    "got %r" % (entry,))
        self.mode = mode
        self.global_deadline_s = float(global_deadline_s)
        self.host_allowlist = allow
        self._now = now or (lambda: int(time.time()))
        self._clock = clock or time.monotonic
        self._breakglass_issuer_pub = breakglass_issuer_pub
        self._exception_issuer_pub = exception_issuer_pub
        if audit_maxlen is None:
            audit_maxlen = Gate.DEFAULT_AUDIT_MAXLEN
        if (isinstance(audit_maxlen, bool)
                or not isinstance(audit_maxlen, int)
                or audit_maxlen <= 0):
            raise GateConfigError(
                "gatehard-policy-malformed",
                "audit_maxlen must be a positive int, got %r"
                % (audit_maxlen,))
        self.audit_maxlen = audit_maxlen
        self.audit_dropped = 0  # evicted audit entries, never silent loss
        self._policies = {}  # digest -> CompiledPolicy
        self._audit = collections.deque(maxlen=audit_maxlen)
        self._last_runtime = None  # never retained across evaluate()
        # Monitor-but-count verdict accounting (Tetragon-style,
        # reimplemented stdlib-only): in monitor mode each enforcement
        # point that WOULD deny increments the per-code counter, and
        # each would-allow increments monitor_allow_count. Protect-mode
        # verdicts never touch these counters.
        self.monitor_deny_counts = collections.Counter()
        self.monitor_allow_count = 0

    # -- registration ----------------------------------------------------

    def register_policy(self, compiled):
        # F276: a non-numeric deadline_s used to leak a raw ValueError
        # from float() here. The config contract is loud coded refusal.
        if compiled.deadline_s is not None:
            if (isinstance(compiled.deadline_s, bool)
                    or not isinstance(compiled.deadline_s, (int, float))):
                raise GateConfigError(
                    "gatehard-policy-malformed",
                    "deadline_s must be numeric, got %r"
                    % (compiled.deadline_s,))
        if compiled.deadline_s is not None and \
                float(compiled.deadline_s) > self.global_deadline_s:
            raise GateConfigError(
                "gatehard-per-policy-deadline-exceeds-global",
                "per-policy deadline %r exceeds global floor %r; "
                "overrides tighten only"
                % (compiled.deadline_s, self.global_deadline_s))
        self._policies[compiled.digest] = compiled
        self._audit_append({
            "ts": self._now(),
            "event": "policy-registered",
            "policy_id": compiled.policy_id,
            "digest": compiled.digest,
        })
        return compiled.digest

    # -- mode promotion (explicit, recorded) ------------------------------

    def promote_to_protect(self, now=None, reason=""):
        ts = self._now() if now is None else now
        self.mode = "protect"
        self._audit_append({"ts": ts, "event": "mode-promoted",
                            "from": "monitor", "to": "protect",
                            "reason": reason})

    def demote_to_monitor(self, now=None, reason=""):
        ts = self._now() if now is None else now
        self.mode = "monitor"
        self._audit_append({"ts": ts, "event": "mode-demoted",
                            "from": "protect", "to": "monitor",
                            "reason": reason})

    def _audit_append(self, entry):
        """Append one audit event. The store is bounded (F257): when it
        is full the oldest entry is evicted and ``audit_dropped`` is
        incremented so the loss is counted, never silent."""
        if len(self._audit) == self.audit_maxlen:
            self.audit_dropped += 1
        self._audit.append(entry)

    def audit_log(self):
        return list(self._audit)

    def policy_digest(self):
        """Digest identifying the registered policy set (wave-272).

        Pure and additive: the sha256 of the canonical sorted list of
        compiled-policy digests. ``gov.drift_report`` carries this on
        every drift event so a policy change between baseline and
        rescan is visible ON the events."""
        return hashlib.sha256(_canonical(
            sorted(self._policies.keys()))).hexdigest()

    def _runtime_after_eval_is_none(self):
        return self._last_runtime is None

    # -- token verification ------------------------------------------------

    def _verify_ignore(self, exc, policy_id):
        if self._exception_issuer_pub is None:
            return False
        body = failure_ignore_body(exc.policy_id, exc.not_before,
                                   exc.expires_at, exc.reason)
        if _ed.verify(self._exception_issuer_pub, body,
                      exc.signature) is not True:
            return False
        now = self._now()
        return (exc.policy_id == policy_id
                and exc.not_before <= now < exc.expires_at)

    def _verify_breakglass(self, tok, request):
        if self._breakglass_issuer_pub is None:
            return False
        body = breakglass_body(tok.request_class, tok.not_before,
                               tok.expires_at, tok.reason)
        if _ed.verify(self._breakglass_issuer_pub, body,
                      tok.signature) is not True:
            return False
        now = self._now()
        if not (tok.not_before <= now < tok.expires_at):
            return False
        # F281: request_class is matched against the request's class
        # ONLY. The old request.get("class", request.get("request_id"))
        # fallback let a class-scoped token authorize a REQUEST ID of the
        # same name, and request_class=None (None == None) was a wildcard
        # for keyless requests. A request without a class key never
        # matches a class-scoped token; None never matches anything.
        cls = tok.request_class
        if cls is None or not isinstance(cls, str):
            return False
        return cls == request.get("class")

    # -- evaluation --------------------------------------------------------

    def _host_callback(self, name, *args):
        if name not in self.host_allowlist:
            raise _HostCallbackDenied(name)
        return "cb:%s:%s" % (name, args[0] if args else "")

    def _deny(self, code, detail, request):
        verdict = {"allowed": False, "mode": self.mode, "code": code,
                   "detail": detail,
                   "request_id": request.get("request_id", "?")}
        self._audit_append({"ts": self._now(), "event": "deny",
                            "code": code, "detail": detail,
                            "request_id": verdict["request_id"]})
        return verdict

    def _monitor_would_deny(self, code, detail, request):
        # Monitor-but-count: every monitor-mode would-deny mirrors its
        # protect-mode enforcement point with a per-code counter, so the
        # deployment can see what protect would do without enforcing it.
        self.monitor_deny_counts[code] += 1
        verdict = {"allowed": True, "mode": self.mode,
                   "code": "gatehard-monitor-would-deny",
                   "would_deny_code": code, "detail": detail,
                   "request_id": request.get("request_id", "?")}
        self._audit_append({"ts": self._now(),
                            "event": "monitor-would-deny",
                            "would_deny_code": code, "detail": detail,
                            "request_id": verdict["request_id"]})
        return verdict

    def evaluate(self, request, failure_ignore=None, break_glass=None):
        """Evaluate one request. Never raises for gate discipline:
        errors and timeouts fail closed. Returns a verdict dict.

        Fail-closed extends to BaseException (F256): a predicate that
        raises SystemExit or KeyboardInterrupt produces a
        ``gatehard-gate-error`` deny instead of propagating -- this
        deliberately trades process-interrupt semantics for the
        fail-closed guarantee at the enforcement path. GeneratorExit is
        re-raised (never swallowed into a deny) so generator cleanup
        semantics stay intact.

        The request handed to the predicate is a deep copy (F258): the
        predicate shares no mutable state with the caller's dict. The
        per-evaluation copy cost is one deepcopy of the request.

        The deepcopy sits INSIDE the fail-closed boundary (F291): a
        hostile copy (TypeError on non-copyable values, RecursionError
        on pathological nesting) becomes a ``gatehard-gate-error``
        deny instead of propagating. GeneratorExit is re-raised, never
        swallowed into a deny.

        A valid signed FailureIgnore (F280) is per-policy as documented:
        the errored policy's error is treated as non-fatal and
        evaluation CONTINUES through the remaining policies; the
        ignore-allow verdict is returned only if every remaining policy
        allows.
        """
        # F258: deep copy so the predicate cannot mutate (or smuggle
        # state out of) the caller's nested request values.
        # F291: inside the fail-closed boundary -- a hostile deepcopy
        # raises (TypeError on non-copyable values, RecursionError on
        # pathological nesting); it becomes a coded fail-closed deny,
        # not a raw raise. GeneratorExit is re-raised per F256.
        monitor = (self.mode == "monitor")
        try:
            request = copy.deepcopy(request or {})
        except GeneratorExit:
            raise
        except BaseException as e:  # noqa: BLE001 -- F291
            detail = ("request could not be copied for evaluation: %s: %s"
                      % (type(e).__name__, e))
            snap = {"request_id": _request_id_of(request)}
            v = (self._monitor_would_deny("gatehard-gate-error", detail,
                                          snap)
                 if monitor else self._deny("gatehard-gate-error", detail,
                                            snap))
            return self._maybe_breakglass(v, snap, break_glass)
        ignore_used = None
        try:
            for policy in sorted(self._policies.values(),
                                 key=lambda p: p.policy_id):
                deadline = self.global_deadline_s
                if policy.deadline_s is not None:
                    deadline = min(deadline, float(policy.deadline_s))
                runtime = Runtime(request, self._host_callback)
                try:
                    start = self._clock()
                    result = policy.predicate(runtime)
                    elapsed = self._clock() - start
                except _HostCallbackDenied as e:
                    v = self._monitor_would_deny(
                        "gatehard-host-callback-denied",
                        "host callback %r not in allowlist" % (e.args[0],),
                        request) if monitor else self._deny(
                        "gatehard-host-callback-denied",
                        "host callback %r not in allowlist" % (e.args[0],),
                        request)
                    return self._maybe_breakglass(v, request, break_glass)
                except GeneratorExit:
                    # F256(3): control-flow exception for generator
                    # cleanup; swallowing it into a deny would corrupt
                    # generator semantics. Re-raise (finally still
                    # discards the runtime).
                    raise
                except BaseException as e:  # F256 -- fail closed
                    v = self._policy_errored(policy, e, request,
                                             failure_ignore, monitor)
                    if v.get("code") == "gatehard-ignore-exception-used":
                        # F280: a valid ignore is per-policy. Record it
                        # and CONTINUE evaluating the remaining
                        # policies instead of returning immediately.
                        ignore_used = v
                        continue
                    return self._maybe_breakglass(v, request, break_glass)
                finally:
                    # fresh discarded runtime: no per-request state kept.
                    self._last_runtime = None
                if elapsed > deadline:
                    v = self._monitor_would_deny(
                        "gatehard-gate-timeout",
                        "policy %r exceeded deadline %.3fs (%.3fs)"
                        % (policy.policy_id, deadline, elapsed),
                        request) if monitor else self._deny(
                        "gatehard-gate-timeout",
                        "policy %r exceeded deadline %.3fs (%.3fs)"
                        % (policy.policy_id, deadline, elapsed),
                        request)
                    return self._maybe_breakglass(v, request, break_glass)
                if not result:
                    v = self._monitor_would_deny(
                        "gatehard-policy-denied",
                        "policy %r denied" % (policy.policy_id,),
                        request) if monitor else self._deny(
                        "gatehard-policy-denied",
                        "policy %r denied" % (policy.policy_id,),
                        request)
                    return self._maybe_breakglass(v, request, break_glass)
            if ignore_used is not None:
                # Every remaining policy allowed: the ignore was valid
                # and its effect was per-policy as documented. This is
                # an allowed verdict, so it counts as a monitor
                # would-allow.
                if monitor:
                    self.monitor_allow_count += 1
                return ignore_used
            if monitor:
                self.monitor_allow_count += 1
            verdict = {"allowed": True, "mode": self.mode,
                       "code": None, "detail": "all policies allowed",
                       "request_id": request.get("request_id", "?")}
            self._audit_append({"ts": self._now(), "event": "allow",
                                "request_id": verdict["request_id"]})
            return verdict
        except GeneratorExit:
            raise
        except BaseException as e:  # noqa: BLE001 -- never raise on discipline
            self._last_runtime = None
            return self._deny("gatehard-gate-error",
                              "gate internal error: %r" % (e,), request)

    def _policy_errored(self, policy, exc, request, failure_ignore,
                        monitor):
        if failure_ignore is not None:
            if self._verify_ignore(failure_ignore, policy.policy_id):
                self._audit_append(
                    {"ts": self._now(),
                     "event": "ignore-exception-used",
                     "policy_id": policy.policy_id,
                     "reason": failure_ignore.reason,
                     "request_id": request.get("request_id", "?")})
                return {"allowed": True, "mode": self.mode,
                        "code": "gatehard-ignore-exception-used",
                        "detail": "signed exception %r" % (
                            failure_ignore.reason,),
                        "request_id": request.get("request_id", "?")}
            code = "gatehard-ignore-exception-invalid"
            detail = ("failure-ignore exception presented but invalid "
                      "(bad signature, wrong policy, or expired)")
            return self._monitor_would_deny(
                code, detail, request) if monitor else self._deny(
                code, detail, request)
        code = "gatehard-gate-error"
        detail = "policy %r raised %r" % (policy.policy_id, exc)
        return self._monitor_would_deny(
            code, detail, request) if monitor else self._deny(
            code, detail, request)

    def _maybe_breakglass(self, verdict, request, tok):
        if tok is None or verdict["allowed"]:
            return verdict
        if self._verify_breakglass(tok, request):
            self._audit_append({"ts": self._now(),
                                "event": "breakglass-used",
                                "reason": tok.reason,
                                "request_id": verdict["request_id"]})
            return {"allowed": True, "mode": self.mode,
                    "code": "gatehard-breakglass-used",
                    "detail": "signed break-glass %r" % (tok.reason,),
                    "request_id": verdict["request_id"]}
        self._audit_append({"ts": self._now(),
                            "event": "breakglass-invalid",
                            "request_id": verdict["request_id"]})
        verdict = dict(verdict)
        verdict["code"] = "gatehard-breakglass-invalid"
        verdict["detail"] = ("break-glass token presented but invalid "
                             "(bad signature, wrong class, or expired); "
                             "namespace alone is never sufficient")
        return verdict

    # -- audit-scanner analog -----------------------------------------------

    def scan(self, requests, now=None):
        """Synthesize evaluations against standing inventory in
        deterministic (request_id) order. Read-only: does not touch the
        audit log. Each entry is what protect mode would decide today.
        A request whose deepcopy fails (F291) yields a fail-closed
        ``gatehard-gate-error`` row rather than raising."""
        out = []
        for req in sorted(requests, key=lambda r: r.get("request_id", "")):
            # F258: same deep-copy discipline as evaluate().
            # F291: inside the per-request try so a hostile deepcopy
            # becomes a coded fail-closed row, not a raw raise.
            req_id = _request_id_of(req)
            try:
                req = copy.deepcopy(req)
            except GeneratorExit:
                raise
            except BaseException:  # noqa: BLE001 -- F291
                out.append({"request_id": req_id, "would": "deny",
                            "code": "gatehard-gate-error"})
                continue
            would = "allow"
            code = None
            try:
                for policy in sorted(self._policies.values(),
                                     key=lambda p: p.policy_id):
                    deadline = self.global_deadline_s
                    if policy.deadline_s is not None:
                        deadline = min(deadline, float(policy.deadline_s))
                    runtime = Runtime(req, self._host_callback)
                    try:
                        start = self._clock()
                        result = policy.predicate(runtime)
                        elapsed = self._clock() - start
                    except _HostCallbackDenied:
                        would, code = "deny", "gatehard-host-callback-denied"
                        break
                    except GeneratorExit:
                        raise
                    except BaseException:  # noqa: BLE001 -- F256
                        would, code = "deny", "gatehard-gate-error"
                        break
                    if elapsed > deadline:
                        would, code = "deny", "gatehard-gate-timeout"
                        break
                    if not result:
                        would, code = "deny", "gatehard-policy-denied"
                        break
            except GeneratorExit:
                raise
            except BaseException:  # noqa: BLE001 -- F256
                would, code = "deny", "gatehard-gate-error"
            out.append({"request_id": req.get("request_id", "?"),
                        "would": would, "code": code})
        return out

    def monitor_report(self):
        """Monitor-but-count verdict accounting report.

        Returns the per-code would-deny counters plus the would-allow
        count accumulated by evaluate() in monitor mode.

        Honest limits: the counters are verdict-level and in-process --
        they count what the gate's own logic decided, not kernel- or
        OS-enforced actions (monitor mode never enforces; see
        gatehard-monitor-would-deny). They are lost when the gate is
        restarted, and they are not thread-safe under concurrent
        evaluate() calls -- the discipline is deployment-level
        aggregation, not this process's dict.
        """
        total_deny = sum(self.monitor_deny_counts.values())
        return {"mode": self.mode,
                "monitor_would_allow": self.monitor_allow_count,
                "monitor_would_deny": dict(self.monitor_deny_counts),
                "monitor_would_deny_total": total_deny,
                "monitor_evaluations":
                    self.monitor_allow_count + total_deny}

    def scan_summary(self, requests):
        """Report what protect would deny today, with counts.

        Runs the read-only audit scanner (scan) over the given requests
        and aggregates per-code would-deny counts plus the would-allow
        count. Pure read: the live monitor counters are never touched,
        so a scan cannot double-count what evaluate() already recorded.
        """
        deny = collections.Counter()
        n_allow = 0
        for row in self.scan(requests):
            if row["would"] == "deny":
                deny[row["code"]] += 1
            else:
                n_allow += 1
        return {"would_allow": n_allow, "would_deny": dict(deny)}


def rail_verdict_of(verdict):
    """Adapt a protect-gate verdict dict to the uniform rail vocabulary.

    Wave-274 lane 2: composition, not fork -- evaluate() keeps its
    ``{"allowed": bool, ...}`` contract; this is the uniform-vocabulary
    view of the same decision. Unknown shapes refuse loudly via
    ``rail-adapter-unknown-verdict`` (never fall through to ALLOW).
    """
    from gov import rail_verdict as _rv
    return _rv.from_gate_verdict(verdict, stage="protect-gate")
