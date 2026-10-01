"""Per-call policy enforcement seam (the check-per-call contract).

ADAPTED DESIGN -- credit: ``envoyproxy/envoy``, the ``ext_authz`` HTTP
filter (Apache-2.0, pattern only -- no envoy code is vendored, linked,
or translated here). Envoy's contract, adapted to our call path:

* EVERY security-sensitive call carries its authorization context to
  a policy check as a structured request
  ``{caller_identity, action, resource, context}`` (their
  ``CheckRequest``: headers, body bytes, peer certificate).
* Deny refuses the call (their ``403``; ours: ``SentinelError`` with
  the machine code at the wired seam, so the swap never happens).
* ``failure_mode_allow`` defaults to ``false`` and is NOT
  configurable here at all: a check that errors, times out, or is
  unconfigured where required DENIES with a machine code -- never
  allows. There is deliberately no knob to open it.
* Per-route scoping (their ``ExtAuthzPerRoute``): policies bind to
  action/resource patterns with SEGMENT-BOUNDARY matching -- a policy
  for ``tool/read`` never authorizes ``tool/readwrite`` (the identity
  lane's prefix-confusion precedent: exact segments, never naive
  prefix matching).
* Decision telemetry (their ``ok/error/denied/disabled`` counters):
  per-policy allow/deny/error counters, in memory, no external
  metrics -- the exact counters an audit trail wants.
* Route-cache lesson (their Security Considerations section: a later
  filter clearing the route cache can reroute a request PAST its
  authorization check): any cached authorization decision is keyed by
  the FULL request context (identity+action+resource+context); a
  context change is a cache miss, never a stale allow.

Wired seam (wave-260): the sentinel credential substitution path
(``gov.sentinel_substitution.substitute_for_execution``,
``enforcer=`` kwarg) -- every swap goes through the check. The
``ToolExecutor`` carries the enforcer as ``call_authorizer``
(opt-in, ``None`` = pre-wave-260 behavior, zero change). Other call
sites are future waves.

Fail-closed contract ("throwing or rejecting denies the request"):

* no check configured on the enforcer, or a policy without a check
  and no enforcer default -> ``callauthz-not-configured`` DENY.
* request matches no policy -> ``callauthz-not-configured`` DENY.
* check raises (``Exception``), exceeds its deadline, or returns
  anything other than an :class:`AuthorizationVerdict` ->
  ``callauthz-check-error`` DENY.
* check returns ``allow=False`` -> ``callauthz-denied`` DENY.
* only an explicit ``allow=True`` verdict from a configured check on
  a matching policy -> ALLOW.

Machine codes: the three deny codes are registered in
``gov.decision_codes.TAXONOMY`` (domain ``callauthz``).
``callauthz-allowed`` is informational (an allow is not a refusal)
and is deliberately NOT in the taxonomy.

$0, stdlib only, no network calls. Deterministic given the check,
the policies, and the clock.
"""

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FuturesTimeout

try:
    from . import decision_codes as _decision_codes  # noqa: F401 -- registry
except ImportError:  # pragma: no cover - direct module use
    _decision_codes = None

__all__ = [
    "CODE_ALLOWED",
    "CODE_DENIED",
    "CODE_CHECK_ERROR",
    "CODE_NOT_CONFIGURED",
    "DEFAULT_CHECK_TIMEOUT_S",
    "DEFAULT_CACHE_TTL_S",
    "CheckRequest",
    "AuthorizationVerdict",
    "CheckTimeout",
    "CheckContractError",
    "ScopedPolicy",
    "DecisionCache",
    "DecisionCounters",
    "CallEnforcer",
]

# Machine codes. The three deny codes are registered in
# gov.decision_codes.TAXONOMY (domain "callauthz"); CODE_ALLOWED is
# informational and deliberately unregistered (allows are not
# refusals).
CODE_DENIED = "callauthz-denied"
CODE_CHECK_ERROR = "callauthz-check-error"
CODE_NOT_CONFIGURED = "callauthz-not-configured"
CODE_ALLOWED = "callauthz-allowed"

_DENY_CODES = frozenset([CODE_DENIED, CODE_CHECK_ERROR, CODE_NOT_CONFIGURED])

DEFAULT_CHECK_TIMEOUT_S = 1.0
DEFAULT_CACHE_TTL_S = 30.0
DEFAULT_CACHE_MAX_ENTRIES = 1024


class CheckTimeout(Exception):
    """The policy check exceeded its deadline (fail-closed: deny)."""


class CheckContractError(Exception):
    """The policy check violated its contract (raised, or returned a
    non-verdict). Fail-closed: deny."""


def _freeze_context(context):
    """Canonicalize the context mapping for cache keys. Values are
    JSON-encoded with sorted keys (``default=str`` for exotic values);
    the digest covers the exact bytes, so any context change is a
    different key."""
    if context is None:
        return "{}"
    if not isinstance(context, dict):
        raise TypeError("context must be a mapping or None, got %r"
                        % type(context).__name__)
    for k in context.keys():
        if not isinstance(k, str):
            raise TypeError("context keys must be strings, got %r" % (k,))
    return json.dumps(context, sort_keys=True, default=str,
                      separators=(",", ":"))


class CheckRequest(object):
    """The structured authorization question, envoy's ``CheckRequest``
    adapted: ``{caller_identity, action, resource, context}``.

    Immutable after construction (slots + no setters). ``action`` and
    ``resource`` are matched against policy patterns with
    segment-boundary semantics; ``context`` carries the rest of the
    call (destination host, tool, release policy, ...) and participates
    in the cache key in full.
    """

    __slots__ = ("caller_identity", "action", "resource", "context",
                 "_cache_key")

    def __init__(self, caller_identity, action, resource, context=None):
        for name, v in (("caller_identity", caller_identity),
                        ("action", action), ("resource", resource)):
            if not isinstance(v, str) or not v:
                raise TypeError("%s must be a non-empty string, got %r"
                                % (name, v))
        frozen = _freeze_context(context)
        object.__setattr__(self, "caller_identity", caller_identity)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "resource", resource)
        object.__setattr__(self, "context", frozen)
        digest = hashlib.sha256("|".join(
            [caller_identity, action, resource, frozen]).encode(
                "utf-8")).hexdigest()
        object.__setattr__(self, "_cache_key", digest)

    def __setattr__(self, name, value):
        raise AttributeError("CheckRequest is immutable")

    def __repr__(self):
        return ("CheckRequest(caller_identity=%r, action=%r, resource=%r, "
                "context=%s)" % (self.caller_identity, self.action,
                                 self.resource, self.context))

    def cache_key(self):
        """Full-context cache key: identity+action+resource+context."""
        return self._cache_key

    def context_dict(self):
        """The context back as a dict (parse of the canonical form)."""
        return json.loads(self.context)


class AuthorizationVerdict(object):
    """The check's answer: allow/deny with a machine code and a human
    reason. ``policy_id`` names the policy that produced it (set by
    the enforcer when the check leaves it empty).

    Immutable: verdicts are cached and shared, so mutation would
    poison the cache."""

    __slots__ = ("allow", "code", "reason", "policy_id")

    def __init__(self, allow, code, reason="", policy_id=None):
        if not isinstance(allow, bool):
            raise TypeError("allow must be bool, got %r" % (allow,))
        if not isinstance(code, str) or not code:
            raise TypeError("code must be a non-empty string, got %r"
                            % (code,))
        object.__setattr__(self, "allow", allow)
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "reason",
                           reason if isinstance(reason, str)
                           else str(reason))
        object.__setattr__(self, "policy_id", policy_id)

    def __setattr__(self, name, value):
        raise AttributeError("AuthorizationVerdict is immutable")

    def __repr__(self):
        return ("AuthorizationVerdict(allow=%r, code=%r, policy_id=%r)" %
                (self.allow, self.code, self.policy_id))


def _validate_pattern(pattern, name):
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("%s pattern must be a non-empty string, got %r"
                         % (name, pattern))
    if any(ch.isspace() for ch in pattern):
        raise ValueError("%s pattern %r contains whitespace: refused "
                         "(patterns are literal segments)" % (name, pattern))
    segments = pattern.split("/")
    for seg in segments:
        if seg == "":
            raise ValueError("%s pattern %r has an empty segment: refused"
                             % (name, pattern))
        if seg != "*" and ("*" in seg):
            raise ValueError(
                "%s pattern %r has a partial-segment wildcard: refused "
                "(wildcards match whole segments only -- the "
                "prefix-confusion fix)" % (name, pattern))
        if "**" in seg:
            raise ValueError("%s pattern %r uses '**': unsupported "
                             "(match whole segments with '*')" % (name,
                                                                  pattern))
    return segments


def _match_pattern(pattern_segments, value):
    """Segment-boundary matching: ``*`` matches exactly one whole
    segment; literal segments must equal. ``tool/*`` matches
    ``tool/read`` but NOT ``tool/readwrite`` and NOT ``tool/a/b``."""
    if not isinstance(value, str) or not value:
        return False
    vsegs = value.split("/")
    if len(vsegs) != len(pattern_segments):
        return False
    if any(s == "" for s in vsegs):
        return False
    return all(p == "*" or p == v
               for p, v in zip(pattern_segments, vsegs))


class ScopedPolicy(object):
    """One authorization rule: (action pattern x resource pattern) ->
    check. First matching policy wins (envoy's per-route config is
    likewise first-match by route table order)."""

    __slots__ = ("policy_id", "action_pattern", "resource_pattern",
                 "check", "timeout_s", "_action_segs", "_resource_segs")

    def __init__(self, policy_id, action_pattern, resource_pattern,
                 check=None, timeout_s=DEFAULT_CHECK_TIMEOUT_S):
        if not isinstance(policy_id, str) or not policy_id:
            raise ValueError("policy_id must be a non-empty string")
        if timeout_s is not None and not (
                isinstance(timeout_s, (int, float)) and timeout_s > 0):
            raise ValueError("timeout_s must be a positive number or "
                             "None (no deadline), got %r" % (timeout_s,))
        if check is not None and not callable(check):
            raise TypeError("check must be callable or None")
        self.policy_id = policy_id
        self.action_pattern = action_pattern
        self.resource_pattern = resource_pattern
        self.check = check
        self.timeout_s = timeout_s
        self._action_segs = _validate_pattern(action_pattern, "action")
        self._resource_segs = _validate_pattern(resource_pattern,
                                                "resource")

    def matches(self, request):
        """True when BOTH patterns match at segment boundaries."""
        return (_match_pattern(self._action_segs, request.action)
                and _match_pattern(self._resource_segs,
                                   request.resource))

    def __repr__(self):
        return ("ScopedPolicy(%r, action=%r, resource=%r)" %
                (self.policy_id, self.action_pattern,
                 self.resource_pattern))


class DecisionCache(object):
    """Full-context decision cache (the route-cache lesson): the key is
    the request's full cache key (identity+action+resource+context
    digest), so a context change is ALWAYS a miss -- a cached allow
    can never be replayed against a different destination, identity,
    or resource. TTL expiry re-evaluates. In-memory only."""

    def __init__(self, ttl_s=DEFAULT_CACHE_TTL_S,
                 max_entries=DEFAULT_CACHE_MAX_ENTRIES, clock=None):
        if not (isinstance(ttl_s, (int, float)) and ttl_s > 0):
            raise ValueError("ttl_s must be positive, got %r" % (ttl_s,))
        self.ttl_s = ttl_s
        self.max_entries = max_entries
        self._clock = clock or time.time
        self._entries = {}  # key -> (verdict, expires_at)
        self._order = []  # insertion order for FIFO eviction
        self._lock = threading.Lock()

    def lookup(self, request):
        """(verdict, True) on a live hit; (None, False) on miss/expiry."""
        key = request.cache_key()
        now = self._clock()
        with self._lock:
            ent = self._entries.get(key)
            if ent is None:
                return None, False
            verdict, expires_at = ent
            if now >= expires_at:
                del self._entries[key]
                try:
                    self._order.remove(key)
                except ValueError:
                    pass
                return None, False
            return verdict, True

    def store(self, request, verdict):
        key = request.cache_key()
        with self._lock:
            if key not in self._entries:
                self._order.append(key)
                while len(self._order) > self.max_entries:
                    old = self._order.pop(0)
                    self._entries.pop(old, None)
            self._entries[key] = (verdict, self._clock() + self.ttl_s)

    def invalidate(self, request=None):
        """Drop one entry, or the whole cache when request is None."""
        with self._lock:
            if request is None:
                self._entries.clear()
                self._order = []
            else:
                key = request.cache_key()
                self._entries.pop(key, None)
                try:
                    self._order.remove(key)
                except ValueError:
                    pass

    def __len__(self):
        with self._lock:
            return len(self._entries)


class DecisionCounters(object):
    """Per-policy allow/deny/error counters (envoy's
    ok/error/denied telemetry, in memory). ``_unmatched`` buckets the
    no-policy-matched denies. Thread-safe; snapshots are isolated
    copies."""

    UNMATCHED = "_unmatched"

    def __init__(self):
        self._counters = {}
        self._lock = threading.Lock()

    def _bucket(self, policy_id):
        return self._counters.setdefault(
            policy_id, {"allow": 0, "deny": 0, "error": 0})

    def record(self, policy_id, outcome):
        if outcome not in ("allow", "deny", "error"):
            raise ValueError("outcome must be allow/deny/error, got %r"
                             % (outcome,))
        with self._lock:
            self._bucket(policy_id)[outcome] += 1

    def snapshot(self):
        with self._lock:
            return {pid: dict(c) for pid, c in self._counters.items()}

    def __repr__(self):
        return "DecisionCounters(%r)" % (self.snapshot(),)


def _run_with_timeout(check, request, timeout_s):
    """Run the check with a deadline. Timeout -> CheckTimeout.
    ``timeout_s=None`` means no deadline (discouraged: a hung decision
    point hangs the call)."""
    if timeout_s is None:
        try:
            return check(request)
        except Exception as exc:
            raise CheckContractError(
                "check raised %s: %s" % (type(exc).__name__, exc))
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        fut = pool.submit(check, request)
        try:
            return fut.result(timeout=timeout_s)
        except _FuturesTimeout:
            raise CheckTimeout(
                "check exceeded its %.3fs deadline" % (timeout_s,))
        except Exception as exc:
            raise CheckContractError(
                "check raised %s: %s" % (type(exc).__name__, exc))
    finally:
        # wait=False: the timed-out worker is abandoned, never joined
        # here (its result is never read again). Non-daemon, so it
        # finishes on its own; interpreter exit waits for it.
        pool.shutdown(wait=False)


class CallEnforcer(object):
    """The per-call enforcement point. ``enforce`` is fail-closed:

    * no matching policy -> deny ``callauthz-not-configured``
    * no check (policy check None and no enforcer default) -> deny
      ``callauthz-not-configured``
    * check raises / times out / returns a non-verdict -> deny
      ``callauthz-check-error``
    * check denies -> deny ``callauthz-denied`` (machine code from the
      registered vocabulary; the check's reason is preserved)
    * only an explicit allow verdict -> allow.

    There is no ``failure_mode_allow`` knob: the fail-closed default
    is structural, not configurable.
    """

    def __init__(self, check=None, cache=None, counters=None,
                 clock=None):
        if check is not None and not callable(check):
            raise TypeError("check must be callable or None")
        if cache is not None and not isinstance(cache, DecisionCache):
            raise TypeError("cache must be a DecisionCache or None")
        if counters is not None and not isinstance(
                counters, DecisionCounters):
            raise TypeError("counters must be a DecisionCounters or None")
        self._check = check
        self._policies = []
        self._cache = cache
        self._counters = counters or DecisionCounters()
        self._clock = clock or time.time
        self._lock = threading.Lock()

    def register_policy(self, policy):
        """Add a policy (first match wins). Duplicate policy_id is a
        loud misconfiguration -- fail fast, never shadow silently."""
        if not isinstance(policy, ScopedPolicy):
            raise TypeError("policy must be a ScopedPolicy")
        with self._lock:
            if any(p.policy_id == policy.policy_id
                   for p in self._policies):
                raise ValueError("duplicate policy_id %r: refused"
                                 % (policy.policy_id,))
            self._policies.append(policy)

    @property
    def policies(self):
        with self._lock:
            return tuple(self._policies)

    def counters_snapshot(self):
        return self._counters.snapshot()

    def _deny(self, code, reason, policy_id, cache_request=None):
        verdict = AuthorizationVerdict(False, code, reason,
                                       policy_id=policy_id)
        self._counters.record(policy_id, "deny")
        if self._cache is not None and cache_request is not None:
            self._cache.store(cache_request, verdict)
        return verdict

    def enforce(self, request):
        """Evaluate one call. Returns an :class:`AuthorizationVerdict`;
        never raises for authorization outcomes (programming errors --
        wrong types -- raise loudly instead of denying silently)."""
        if not isinstance(request, CheckRequest):
            raise TypeError("enforce() takes a CheckRequest, got %r"
                            % type(request).__name__)
        with self._lock:
            policies = list(self._policies)
        policy = None
        for p in policies:
            if p.matches(request):
                policy = p
                break
        if policy is None:
            return self._deny(
                CODE_NOT_CONFIGURED,
                "no policy matches action %r resource %r: denied "
                "fail-closed (a call with no authorizing policy is "
                "never allowed)" % (request.action, request.resource),
                DecisionCounters.UNMATCHED, cache_request=request)
        if self._cache is not None:
            verdict, hit = self._cache.lookup(request)
            if hit:
                # A cached decision is served as-is (denies stay
                # denies); it is still observed in the counters.
                self._counters.record(
                    policy.policy_id,
                    "allow" if verdict.allow else "deny")
                return verdict
        check = policy.check if policy.check is not None else self._check
        if check is None:
            return self._deny(
                CODE_NOT_CONFIGURED,
                "policy %r matched but no check is configured (and no "
                "enforcer default): denied fail-closed"
                % (policy.policy_id,), policy.policy_id,
                cache_request=request)
        try:
            raw = _run_with_timeout(check, request, policy.timeout_s)
        except (CheckTimeout, CheckContractError) as exc:
            verdict = AuthorizationVerdict(
                False, CODE_CHECK_ERROR, str(exc),
                policy_id=policy.policy_id)
            self._counters.record(policy.policy_id, "error")
            if self._cache is not None:
                self._cache.store(request, verdict)
            return verdict
        if not isinstance(raw, AuthorizationVerdict):
            verdict = AuthorizationVerdict(
                False, CODE_CHECK_ERROR,
                "check returned %r instead of an AuthorizationVerdict: "
                "contract violation, denied fail-closed"
                % type(raw).__name__, policy_id=policy.policy_id)
            self._counters.record(policy.policy_id, "error")
            if self._cache is not None:
                self._cache.store(request, verdict)
            return verdict
        if not raw.allow:
            # Normalize the machine code into the registered
            # vocabulary; the check's reason (and its own code) ride
            # along for forensics.
            reason = raw.reason
            if raw.code not in _DENY_CODES:
                reason = "[check code %r] %s" % (raw.code, raw.reason)
            return self._deny(CODE_DENIED, reason, policy.policy_id,
                              cache_request=request)
        verdict = AuthorizationVerdict(
            True, raw.code if raw.code else CODE_ALLOWED, raw.reason,
            policy_id=policy.policy_id or raw.policy_id)
        self._counters.record(policy.policy_id, "allow")
        if self._cache is not None:
            self._cache.store(request, verdict)
        return verdict
