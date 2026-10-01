"""Sentinel credential substitution — host-gated injection on the egress path.

ADAPTED DESIGN — credit: ``anthropics/sandbox-runtime``
(``src/sandbox/credential-sentinel.ts``, ``SentinelRegistry``, Apache-2.0).
Their design: the sandboxed agent sees only ``fake_value_<uuid4>``
placeholders; the host-side proxy swaps sentinel -> real value on
egress, and substitution is gated PER CREDENTIAL — a sentinel is
injected only when the destination matches THAT credential's
``injectHosts`` list, so credential A cannot be laundered through
credential B's allowlisted host. The map lives only in process memory
(never written to disk, never logged); length-matched padding keeps
``Content-Length`` invariant (fail-safe: worst case a wrong *fake*
reaches upstream, never a secret).

Adaptation to OUR architecture: our CONNECT proxy deliberately does
NOT intercept TLS (``gov/egress_proxy.py`` — destination-shaped wall,
bytes tunnel opaquely), so the substitution seam is the
``ToolExecutor``'s egress-attempt path — the same host-side choke
point as the canary tripwire (``gov/canary.py``), where args are
plaintext. The security property is identical: secrets are unusable
outside their authorized channel.

Mechanism
---------
:class:`SentinelVault` (operator trust domain, process memory ONLY):
``sentinel -> (credential_id, real_value, inject_hosts)``. The agent's
environment carries only sentinels. TWO seams, split deliberately:

1. ATTEMPT PATH — :func:`validate_sentinel_binding` runs on the
   egress-attempt path (``http_post`` / ``api_call`` / ``send_email`` —
   the same tool set the canary tripwire governs), BEFORE the policy
   decision. Every known sentinel's host binding is verified; a
   mismatch (or an unresolvable destination) means NO substitution, a
   LOUD ``sentinel_trip`` audit event, approval-queue escalation, and
   :class:`SentinelTripHalt` — the run halts fail-closed. The exfil is
   blocked AND the trip signals: detection + prevention in one
   primitive. Args pass through UNCHANGED (sentinel-bearing).

2. EXECUTION BOUNDARY — :func:`substitute_for_execution` runs ONLY at
   the final execution seam (direct-allow path and approved sweep),
   substituting into an EPHEMERAL copy of the args immediately before
   the tool is invoked. The binding is re-validated here fail-closed.

Why the split: DLP, the policy engine, the approval queue, previews,
and every audit-bound arg snapshot see ONLY the sentinel form — so a
high-entropy real credential can never trip the DLP entropy tripwire
on legitimate authorized use, and the real secret NEVER enters the
audit log, the approval record (which is MAC-bound to the
sentinel-bearing args), or any run artifact. The write-ahead audit
entry logs the sentinel-bearing args; the substituted copy exists
only for the duration of the tool call. This mirrors the upstream
``request-filter.ts`` order (approve/filter first, substitute at the
wire) adapted to our executor seams.

Unification with Egress Canaries: :meth:`SentinelVault.register_decoy`
mints a canary AS a sentinel — ``inject_hosts`` is empty, so it can
never be legitimately substituted; any appearance on the egress path
trips. :func:`register_decoys_in_canary_registry` additionally plants
decoy sentinel values in a :class:`CanaryRegistry`, so the existing
canary tripwire (which runs first) catches them too — defense in
depth, documented.

Fail-closed contract (their ``request-filter.ts`` language, adopted in
spirit): "Throwing or rejecting denies the request." Concretely here:

- unknown sentinel-shaped token (not in this vault): left alone — no
  substitution, no trip. We cannot attribute intent for a token we did
  not mint, and a uuid4 collision is negligible. Documented, not a
  hole: an attacker gains nothing from a token that never substitutes.
- destination not extractable from the args: trip. We cannot verify
  the host binding, so we refuse — the binding is the control.
- ``inject_hosts`` matching is exact-FQDN, normalized
  (lowercase, trailing-dot stripped). No wildcards — the Wiki-shape
  lesson from ``gov/egress_proxy.py`` applies here too.
- the vault deliberately exposes NO serialization of real values
  (no ``to_dict``/``from_dict``); ``repr`` is redacted. Real values
  never reach the audit log: substitution happens after every
  audit-bound arg snapshot, so there is nothing to redact — the
  ``[credential-redacted]`` marker exists only as a defense-in-depth
  primitive (:func:`redact_substituted`) for integrators.

Wave-198: attestation-conditioned release (Trustee KBS mechanism steal)
---------------------------------------------------------------------------
The host binding above is now one conjunct of the release predicate,
not the whole predicate. Every credential carries a
``release_policy`` (see :meth:`SentinelVault.register`):

* ``"attested"`` (default for new credentials): release requires a
  live, verified attestation (``gov.attestation_release``) covering
  the credential's class, bound to the requesting agent and the
  current run, with status ``affirming`` -- AND the host binding.
  Evaluated per release at the execution boundary
  (:func:`substitute_for_execution`, authoritative, consumes the
  token's ``jti``), with a fail-closed pre-check on the attempt path
  (:func:`validate_sentinel_binding`, never consumes).
* ``"legacy-host-only"``: the pre-wave-198 host-binding path.
  Migration bridge only: explicitly selected per credential, LOUDLY
  audited on every use, and sunset on
  ``attestation_release.LEGACY_RELEASE_SUNSET`` (2026-12-31).
* ``"deny_all"``: incident hold -- refused at both seams.

There is NO silent downgrade: an attestation-mandatory credential
whose attestation is missing, malformed, expired, replayed, or bound
to another agent/run -- or for which no issuer trust anchor is
configured -- is LOUDLY refused. Host allowlisting is never a
fallback.

Honest boundaries (prototype)
-----------------------------
- The pre-commit gate (wave-79) binds its digest to the
  sentinel-bearing (tool, args): the human approves the sentinel
  form, and the trusted layer performs the deterministic host-gated
  fill afterwards. The semantic action is unchanged; this matches
  the upstream model (approve the placeholder form, substitute at
  the wire).
- Prototype real values must be DLP-clean synthetic values (asserted
  at registration against ``gov.dlp.find_credential``): the F111
  ``credential_manifest`` (non-production provisioning assertion) is
  the natural home for the production version of this rule.
- False-positive cost (measured in the battery): a credential used at
  a legitimate host missing from its ``inject_hosts`` is blocked AND
  trips. The allowlist must be complete — host-binding trades
  availability for containment, loudly.
- Length side-channel: unlike the TypeScript original, this prototype
  does NOT pad substituted values (no Content-Length to preserve at
  this seam — the executor's tools are simulated). A deployment doing
  wire substitution must preserve the padding property.
- Non-egress tools (``write_file`` etc.) may carry sentinels freely:
  the placeholder is useless outside the substitution seam.
- If the vault is detached between queue and sweep
  (``sentinel_registry=None``), approved records execute with the
  useless sentinel — fail-safe by construction, never the secret.

$0, stdlib only, no network calls. Deterministic given the vault.
"""

import re
import uuid
from urllib.parse import urlparse

try:
    from .attestation_release import (
        RELEASE_POLICIES,
        LEGACY_RELEASE_SUNSET,
        REASON_OPERATOR_OVERRIDE,
        AttestationReleaseConfig,
        evaluate_release,
        release_event,
        legacy_release_event,
    )
except ImportError:  # pragma: no cover - direct module use
    from attestation_release import (
        RELEASE_POLICIES,
        LEGACY_RELEASE_SUNSET,
        REASON_OPERATOR_OVERRIDE,
        AttestationReleaseConfig,
        evaluate_release,
        release_event,
        legacy_release_event,
    )

__all__ = [
    "SENTINEL_RE",
    "SentinelError",
    "SentinelTripHalt",
    "SentinelVault",
    "extract_dest_host",
    "find_sentinels",
    "substitute_in",
    "redact_substituted",
    "preserve_sentinels",
    "validate_sentinel_binding",
    "substitute_for_execution",
    "register_decoys_in_canary_registry",
    "EGRESS_TOOLS",
]

# Same shape as the upstream design: fake_value_<uuid4>.
SENTINEL_RE = re.compile(
    r"fake_value_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}")

# Tools whose attempts pass the substitution/trip layer — the same set
# the canary tripwire governs (gov/canary.py EGRESS_TOOLS).
EGRESS_TOOLS = ("http_post", "send_email", "api_call")


class SentinelError(Exception):
    """Fail-closed refusal of a sentinel-vault misuse."""


class SentinelTripHalt(Exception):
    """Fail-closed halt: a sentinel appeared at an unauthorized
    destination (or with an unresolvable destination).

    Raised by :func:`check_and_substitute` after the LOUD
    ``sentinel_trip`` audit event lands and the approval-queue
    escalation is queued. Nothing in ``ToolExecutor.call`` catches
    this — the call never executes.
    """


def _normalize_host(host):
    # Wave-247: delegate to the shared gov/uri_normalize canonicalizer
    # so sentinel host bindings see the byte-identical string the auth
    # and IoC paths see. UriNormalizeError is converted to
    # SentinelError to preserve this module's error contract.
    from gov import uri_normalize as _un
    try:
        return _un.normalize_host(host)
    except _un.UriNormalizeError as exc:
        raise SentinelError(
            "inject_hosts entries must be valid hostnames, got %r "
            "(%s)" % (host, exc.code))


_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def _check_host(host):
    norm = _normalize_host(host)
    if not norm or not _HOST_RE.match(norm):
        raise SentinelError(
            "inject_hosts entries must be valid hostnames, got %r" % (host,))
    if norm.startswith("*."):
        raise SentinelError(
            "inject_hosts entry %r uses a suffix wildcard: refused "
            "(Wiki shape); enumerate each allowed FQDN explicitly" % (host,))
    try:
        import ipaddress
        ipaddress.ip_address(norm)
    except ValueError:
        pass
    else:
        raise SentinelError(
            "inject_hosts entry %r is an IP literal: refused (hostnames "
            "only, like the egress proxy allowlist)" % (host,))
    return norm


def extract_dest_host(tool, args):
    """Destination hostname for an egress attempt, or None.

    Same discipline as ``gov/canary.py`` destination extraction:
    ``http_post`` -> url, ``api_call`` -> endpoint, ``send_email`` ->
    recipient domain. Returns the normalized host or None when not
    extractable (fail-closed: the caller trips on None).
    """
    if not isinstance(args, dict):
        return None
    try:
        if tool == "http_post":
            raw = args.get("url")
            if isinstance(raw, str) and raw:
                h = urlparse(raw).hostname
                return _normalize_host(h) if h else None
        elif tool == "api_call":
            raw = args.get("endpoint")
            if isinstance(raw, str) and raw:
                h = urlparse(raw).hostname
                return _normalize_host(h) if h else None
        elif tool == "send_email":
            to = args.get("to")
            if isinstance(to, str) and "@" in to:
                h = to.rsplit("@", 1)[-1]
                return _normalize_host(h) if h else None
    except Exception:
        return None
    return None


def find_sentinels(obj):
    """Yield every sentinel-shaped token in a nested arg structure."""
    stack = [obj]
    seen = set()
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            for m in SENTINEL_RE.finditer(v):
                tok = m.group(0)
                if tok not in seen:
                    seen.add(tok)
                    yield tok
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)


def substitute_in(obj, mapping):
    """Return a copy of ``obj`` with every sentinel in ``mapping``
    replaced by its real value. Exact token replacement inside string
    leaves (a sentinel embedded in a larger string is still the
    sentinel — the agent pasted it)."""
    if isinstance(obj, str):
        out = obj
        for tok, real in mapping.items():
            if tok in out:
                out = out.replace(tok, real)
        return out
    if isinstance(obj, dict):
        return {substitute_in(k, mapping): substitute_in(v, mapping)
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute_in(v, mapping) for v in obj]
    if isinstance(obj, tuple):
        return tuple(substitute_in(v, mapping) for v in obj)
    return obj


def redact_substituted(obj, real_values):
    """Exact-match redaction of substituted real values for the audit
    path. Defense-in-depth primitive: in the current executor wiring
    substitution happens after every audit-bound arg snapshot, so this
    is not on the hot path — but integrators adapting the design to a
    different seam can use it to keep real values out of logs. Exact
    match only: we know the precise values, so there is no fuzzy-match
    FP risk."""
    if not real_values:
        return obj
    if isinstance(obj, str):
        out = obj
        for real in real_values:
            if real and real in out:
                out = out.replace(real, "[credential-redacted]")
        return out
    if isinstance(obj, dict):
        return {redact_substituted(k, real_values):
                redact_substituted(v, real_values)
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_substituted(v, real_values) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_substituted(v, real_values) for v in obj)
    return obj


def _is_summary_dict(v):
    return isinstance(v, dict) and set(v.keys()) == {"bytes",
                                                    "sha256_prefix"}


def _skeleton_str(vault, s):
    """Original string with validated sentinel tokens kept verbatim and
    everything else masked. Sentinels are fixed-format vault-minted
    placeholders — provably not secret material — so keeping them is
    safe; the surrounding content stays summarized."""
    toks = [t for t in SENTINEL_RE.findall(s)
            if vault.lookup(t) is not None]
    if not toks:
        return "[summarized]"
    if len(toks) == 1 and SENTINEL_RE.fullmatch(s):
        return s
    # Mixed content: keep validated sentinels verbatim, mask
    # everything else. Unknown sentinel-shaped text stays masked (it
    # can never substitute anyway).
    toks_all = SENTINEL_RE.findall(s)
    parts_all = SENTINEL_RE.split(s)
    out = []
    for i, part in enumerate(parts_all):
        if part:
            out.append("[masked]")
        if i < len(toks_all):
            t = toks_all[i]
            out.append(t if vault.lookup(t) is not None else "[masked]")
    return "".join(out)


def _skeleton(vault, v):
    """Original structure with validated sentinels kept and everything
    else summarized — the shape the approved sweep substitutes into."""
    if isinstance(v, str):
        return _skeleton_str(vault, v)
    if isinstance(v, dict):
        return {k: _skeleton(vault, x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_skeleton(vault, x) for x in v]
    return "[summarized]"


def preserve_sentinels(vault, redacted_args, original_args):
    """Merge validated sentinel placeholders back through DLP payload
    summaries.

    The DLP summary (``{"bytes", "sha256_prefix"}``) exists because
    payload fields can carry arbitrary secret material — but a
    validated sentinel is a fixed-format vault-minted placeholder,
    provably not secret material. Without this, the summary destroys
    the sentinel before queueing and the approved sweep has nothing
    to substitute (the authorized channel would break for
    human-approved calls). Every non-sentinel string is still
    summarized/masked, so the DLP property holds.

    Returns a copy of ``redacted_args`` with sentinel skeletons in
    place of summaries that contained validated sentinels.
    """
    if isinstance(redacted_args, dict) and isinstance(original_args,
                                                       dict):
        out = {}
        for k, rv in redacted_args.items():
            ov = original_args.get(k)
            if (_is_summary_dict(rv) and ov is not None
                    and any(vault.lookup(t) is not None
                            for t in SENTINEL_RE.findall(
                                ov if isinstance(ov, str)
                                else str(ov)))):
                out[k] = _skeleton(vault, ov)
            else:
                out[k] = preserve_sentinels(vault, rv, ov)
        return out
    if isinstance(redacted_args, list) and isinstance(original_args,
                                                       list) \
            and len(redacted_args) == len(original_args):
        return [preserve_sentinels(vault, rv, ov)
                for rv, ov in zip(redacted_args, original_args)]
    return redacted_args


class SentinelVault(object):
    """Operator-side credential vault. Process memory ONLY.

    ``register(credential_id, real_value, inject_hosts)`` mints a fresh
    ``fake_value_<uuid4>`` sentinel and records the binding. The agent
    receives ONLY the sentinel (e.g. in its environment). ``real_value``
    is asserted DLP-clean at registration (prototype rule — see module
    docstring; the F111 credential_manifest owns the production
    version).

    Deliberately NO serialization: the map is never written to disk,
    never logged, never pickled. ``repr`` shows credential ids and
    host counts, never values.
    """

    def __init__(self):
        self._entries = {}  # sentinel -> dict(credential_id, real, hosts, decoy)
        self._by_cred = {}
        # Operator-side diagnostics (process memory only, never
        # persisted, never logged): what was substituted where, and
        # what tripped. The battery asserts substitution through
        # these — the audit path must NEVER show real values, so the
        # vault's own log is the honest observable.
        self.substitution_log = []  # (credential_id, dest_host, ts)
        self.trip_log = []  # (credential_id, dest_host, ts)

    def __repr__(self):
        return ("SentinelVault(credentials=%d, values=REDACTED)" %
                len(self._entries))

    def _mint(self):
        return "fake_value_%s" % uuid.uuid4()

    def register(self, credential_id, real_value, inject_hosts,
                 credential_class, release_policy="attested"):
        """Bind a real credential to its authorized hosts. Returns the
        sentinel the agent sees.

        Wave-198: every credential is classified and carries a release
        policy:

        * ``credential_class`` (required, non-empty string): the class
          the release attestation must cover (e.g. ``"db-password"``).
        * ``release_policy``: ``"attested"`` (default -- the credential
          is attestation-mandatory from day one: release requires a
          live, verified attestation at the execution boundary AND the
          host binding); ``"legacy-host-only"`` (the pre-wave-198
          host-binding path -- migration bridge ONLY, must be selected
          explicitly per credential, LOUD-audited on every use, sunsets
          on ``attestation_release.LEGACY_RELEASE_SUNSET``);
          ``"deny_all"`` (incident hold -- refused at both seams).

        There is no silent default: a credential registered without an
        explicit ``release_policy`` is attestation-mandatory, so a
        caller that has not migrated fails closed at release instead
        of silently falling back to host-only.
        """
        if not isinstance(credential_id, str) or not credential_id.strip():
            raise SentinelError("credential_id must be a non-empty string")
        if credential_id in self._by_cred:
            raise SentinelError(
                "credential_id %r already registered" % (credential_id,))
        if not isinstance(real_value, str) or not real_value:
            raise SentinelError("real_value must be a non-empty string")
        if SENTINEL_RE.search(real_value):
            raise SentinelError(
                "real_value must not itself be sentinel-shaped")
        if not isinstance(credential_class, str) or not credential_class:
            raise SentinelError(
                "credential_class must be a non-empty string "
                "(classify every credential; attestations bind to the "
                "class)")
        if release_policy not in RELEASE_POLICIES:
            raise SentinelError(
                "release_policy %r is not one of %s"
                % (release_policy, RELEASE_POLICIES))
        hosts = frozenset(_check_host(h) for h in inject_hosts)
        if not hosts:
            raise SentinelError(
                "inject_hosts must be non-empty (use register_decoy() "
                "for never-substitutable canary sentinels)")
        # Prototype rule: real values must be DLP-clean synthetic
        # values, else the DLP scan would block legitimate authorized
        # use after substitution (documented in the module docstring).
        try:
            from . import dlp as _dlp
            if _dlp.find_credential(real_value) is not None:
                raise SentinelError(
                    "real_value for %r is credential-shaped: refused "
                    "(prototype rule — provision DLP-clean synthetic "
                    "values; F111 credential_manifest owns the "
                    "production version)" % (credential_id,))
        except ImportError:
            pass
        sentinel = self._mint()
        rec = {"credential_id": credential_id, "real": real_value,
               "hosts": hosts, "decoy": False, "sentinel": sentinel,
               "credential_class": credential_class,
               "release_policy": release_policy}
        self._entries[sentinel] = rec
        self._by_cred[credential_id] = sentinel
        return sentinel

    def register_decoy(self, label):
        """Mint a canary AS a sentinel: ``inject_hosts`` is empty, so it
        can never be legitimately substituted — any appearance on the
        egress path trips. Detection + prevention in one primitive."""
        if not isinstance(label, str) or not label.strip():
            raise SentinelError("decoy label must be a non-empty string")
        sentinel = self._mint()
        rec = {"credential_id": "decoy:%s" % label, "real": None,
               "hosts": frozenset(), "decoy": True, "sentinel": sentinel}
        self._entries[sentinel] = rec
        return sentinel

    def lookup(self, sentinel):
        """The binding for a sentinel token, or None (unknown token)."""
        return self._entries.get(sentinel)

    def sentinel_for(self, credential_id):
        """The minted sentinel for a credential id (test/operator use)."""
        return self._by_cred.get(credential_id)

    def __len__(self):
        return len(self._entries)


def register_decoys_in_canary_registry(vault, canary_registry, mint):
    """Unification helper: plant decoy sentinel values in a
    :class:`CanaryRegistry` (via a :class:`CanaryMint`-shaped shim) so
    the existing canary tripwire — which runs BEFORE the sentinel check
    — catches decoy sentinels too. Defense in depth: two independent
    trip paths over one primitive.

    ``mint`` must expose ``run_id`` and ``values()`` (list of dicts
    with ``kind``/``label``/``value``/``channel``); a tiny shim is
    provided below for callers that only have a vault.
    """
    values = []
    for sentinel, rec in vault._entries.items():
        if rec["decoy"]:
            values.append({"kind": "sentinel_decoy",
                           "label": rec["credential_id"],
                           "value": sentinel,
                           "channel": "sentinel"})
    if not values:
        return 0

    class _Shim(object):
        def __init__(self, run_id, values):
            self.run_id = run_id
            self._values = values

        def values(self):
            return [dict(v) for v in self._values]

    canary_registry.register(_Shim(
        getattr(mint, "run_id", "sentinel-decoys"), values))
    return len(values)


def _binding_map(vault, tool, args):
    """Shared core: (dest, {sentinel: record}) for the KNOWN sentinels
    in ``args``. Unknown sentinel-shaped tokens are ignored (no
    attribution possible — documented in the module docstring). A
    ``__mismatch__`` / ``__unresolvable__`` marker entry reports the
    fail-closed conditions; the callers trip or refuse on it."""
    tokens = list(find_sentinels(args))
    if not tokens:
        return None, {}
    dest = extract_dest_host(tool, args)
    if dest is None:
        import time as _time
        rec0 = vault.lookup(tokens[0])
        vault.trip_log.append(
            (rec0["credential_id"] if rec0 else "unknown", None,
             _time.time()))
        return None, {"__unresolvable__": tokens[0]}
    bound = {}
    for tok in tokens:
        rec = vault.lookup(tok)
        if rec is None:
            continue
        if dest not in rec["hosts"]:
            import time as _time
            vault.trip_log.append(
                (rec["credential_id"], dest, _time.time()))
            bound["__mismatch__"] = (tok, rec, dest)
            return dest, bound
        # rec["real"] is None only for decoys, whose hosts is empty, so
        # a decoy can never reach this branch (it mismatches above).
        bound[tok] = rec
    return dest, bound


def _identity_agent_id(identity):
    """Agent id from an identity object, a mapping, or None."""
    if identity is None:
        return None
    if isinstance(identity, dict):
        aid = identity.get("agent_id")
    else:
        aid = getattr(identity, "agent_id", None)
    return aid if isinstance(aid, str) and aid else None


def _identity_run_id(identity):
    """Run id from an identity object, a mapping, or None."""
    if identity is None:
        return None
    if isinstance(identity, dict):
        rid = identity.get("run_id")
    else:
        rid = getattr(identity, "run_id", None)
    return rid if isinstance(rid, str) and rid else None


def _attested_decision(release_config, credential_id, credential_class,
                       identity, run_id, *, attestation=None,
                       policy_override=None, policy_override_keyset=None,
                       now=None, consume=False):
    """Evaluate the attestation conjunct for one credential.

    Returns ``(ok, reason, via_override, jti)``; never raises. Shared by
    the attempt-path pre-check (``consume=False``) and the
    execution-boundary evaluation (``consume=True`` -- the single jti
    consumer).
    """
    agent_id = _identity_agent_id(identity)
    if not isinstance(release_config, AttestationReleaseConfig):
        return (False,
                "credential %r is attestation-mandatory but no attestation "
                "trust anchor is configured on this executor: refused "
                "(no silent fallback to host-only)" % (credential_id,),
                False, None)
    if not agent_id:
        return (False,
                "credential %r is attestation-mandatory but the requesting "
                "agent identity is unknown: refused" % (credential_id,),
                False, None)
    token = attestation
    if token is None:
        # Fresh lookup at every evaluation -- never cached from run
        # start (per-release evaluation; revocation between attempt and
        # execution is caught here).
        token = release_config.attestation_for(agent_id)
    ovr, ovr_ks = policy_override, policy_override_keyset
    if ovr is None:
        stored = getattr(release_config, "policy_override", None)
        if stored is not None:
            ovr, ovr_ks = stored
    ok, reason, jti = evaluate_release(
        credential_id, credential_class, token, config=release_config,
        agent_id=agent_id, run_id=run_id, policy="attested",
        override=ovr, override_keyset_doc=ovr_ks, now=now, consume=consume)
    # The via-override flag is recovered from the module's reason
    # constant, never a re-typed literal (no magic strings).
    return ok, reason, (reason == REASON_OPERATOR_OVERRIDE), jti


def _attestation_trip(executor, identity, tool, args, credential_id,
                      reason):
    """LOUD attestation trip: audit event + approval-queue escalation,
    then halt. The attestation analog of :func:`_trip` -- the release
    predicate failed closed on the attempt path."""
    run_id = getattr(executor, "run_id", "?")
    agent_id = _identity_agent_id(identity) or "?"
    if isinstance(identity, dict):
        principal = identity.get("principal", "?")
        role = identity.get("role", "?")
        id_dict = dict(identity)
    else:
        principal = getattr(identity, "principal", "?")
        role = getattr(identity, "role", "?")
        try:
            id_dict = identity.as_dict()
        except Exception:
            id_dict = {"agent_id": agent_id}
    full_reason = (
        "Attestation-release trip: agent %s attempted egress via %s "
        "carrying the sentinel for attestation-mandatory credential %r. "
        "%s. The credential is unusable without a live, verified "
        "attestation bound to this agent and run; this is a refused "
        "release with a trip signal. Run halted fail-closed; escalated "
        "for human review."
        % (agent_id, tool, credential_id, reason))
    try:
        cfg = getattr(executor, "attestation_config", None)
        counters = (cfg.counters_snapshot()
                    if isinstance(cfg, AttestationReleaseConfig) else None)
        executor.log.append({
            "event": "attestation_release_trip",
            "run_id": run_id,
            "agent_id": agent_id,
            "role": role,
            "principal": principal,
            "tool": tool,
            "credential_id": credential_id,
            "decision": "halted",
            "policy_id": "attestation-release-trip",
            "flag": "attestation_release_trip",
            "reason": full_reason,
            "counters": counters,
        })
    except Exception:
        pass  # the halt below is the control; audit is best-effort

    try:
        from .policy import PolicyDecision
        decision = PolicyDecision(
            "require_approval", full_reason,
            policy_id="attestation-release-trip",
            flag="attestation_release_trip")
        action = {"tool": tool, "args": args,
                  "identity": id_dict,
                  "agent_justification": None, "redactions": []}
        preview = executor._preview(tool, args)
        egress_bytes = 0
        _ebf = getattr(executor, "_egress_bytes_for", None)
        if callable(_ebf):
            try:
                egress_bytes = _ebf(tool, args)
            except Exception:
                egress_bytes = 0
        executor.approvals.queue(
            action, decision, "agent_direct", preview,
            policy_hash=executor.policy.policy_hash,
            policy_flag="attestation_release_trip",
            egress_bytes=egress_bytes,
            caller_identity=identity)
    except Exception:
        pass  # fail-closed: queue failure must not un-halt

    raise SentinelTripHalt(full_reason)


def validate_sentinel_binding(executor, identity, tool, args, *, now=None):
    """ATTEMPT-PATH seam: verify every known sentinel's host binding,
    BEFORE the policy decision. Args pass through UNCHANGED
    (sentinel-bearing) — DLP, policy, approval, previews, and all
    audit-bound snapshots see only the sentinel form.

    Wave-198: after the host binding, the attestation conjunct is
    PRE-CHECKED fail-closed for attestation-mandatory credentials
    (``consume=False`` -- the pre-check never consumes the token's
    ``jti``; the execution-boundary evaluation is authoritative).
    Credentials under incident hold (``deny_all``) trip here too.
    ``now`` is the evaluation instant (default: real time).

    Returns the list of validated credential ids (no secrets). On a
    host mismatch (or unresolvable destination): LOUD ``sentinel_trip``
    audit event, approval-queue escalation, then
    :class:`SentinelTripHalt`. On an attestation refusal: LOUD
    ``attestation_release_trip``, escalation, then
    :class:`SentinelTripHalt`. Best-effort audit/queue like
    ``gov/canary.py`` — the halt is not best-effort.
    """
    vault = getattr(executor, "sentinel_registry", None)
    if vault is None or tool not in EGRESS_TOOLS:
        return []
    if not isinstance(args, dict):
        return []
    dest, bound = _binding_map(vault, tool, args)
    bad = bound.pop("__mismatch__", None)
    if bad is not None:
        tok, rec, dest = bad
        _trip(executor, identity, tool, args, tok, dest,
              "sentinel for credential %r presented at %r, which "
              "is not in its inject_hosts %s — the secret is "
              "unusable outside its authorized channel"
              % (rec["credential_id"], dest,
                 sorted(rec["hosts"]) or ["(decoy: never)"]))
        raise SentinelTripHalt("unreachable")  # _trip raises
    if "__unresolvable__" in bound:
        _trip(executor, identity, tool, args, bound["__unresolvable__"],
              None,
              "destination unresolvable: cannot verify the host binding "
              "for sentinel use — refused fail-closed")
        # _trip always raises; the line below is unreachable but keeps
        # the fail-closed intent explicit if the trip path ever changes.
        raise SentinelTripHalt("unreachable")
    # Wave-198 attestation pre-check (fail-closed, never consumes jti).
    run_id = getattr(executor, "run_id", "?")
    release_config = getattr(executor, "attestation_config", None)
    for rec in bound.values():
        # No silent downgrade (R6): a record missing release_policy is
        # attestation-mandatory, never host-only.
        policy = rec.get("release_policy", "attested")
        cid = rec["credential_id"]
        if policy == "deny_all":
            _attestation_trip(
                executor, identity, tool, args, cid,
                "credential %r is under incident hold (deny_all): the "
                "attempt is refused and the run halts" % (cid,))
            raise SentinelTripHalt("unreachable")  # _attestation_trip raises
        if policy == "attested":
            ok, reason, _via, _jti = _attested_decision(
                release_config, cid, rec.get("credential_class"),
                identity, run_id, consume=False, now=now)
            if not ok:
                _attestation_trip(executor, identity, tool, args, cid,
                                  reason)
                raise SentinelTripHalt("unreachable")  # raises above
        # "legacy-host-only": host binding only, LOUD-audited at the
        # execution seam; "deny_all" handled above.
    return [rec["credential_id"] for rec in bound.values()]


def substitute_for_execution(vault, tool, args, *, identity=None,
                             attestation=None, release_config=None,
                             audit_log=None, run_id=None, now=None,
                             policy_override=None,
                             policy_override_keyset=None,
                             enforcer=None):
    """EXECUTION-BOUNDARY seam: substitute known sentinels into an
    EPHEMERAL copy of ``args`` immediately before the tool is invoked.
    The host binding is RE-VALIDATED here fail-closed (the vault may
    have changed between attempt and execution).

    Wave-198: for attestation-mandatory credentials the release
    predicate (``gov.attestation_release.evaluate_release``) is
    evaluated HERE, authoritatively, per release -- the TOCTOU guard.
    The attempt-path pre-check never consumes the token's ``jti``; this
    evaluation is the single consumer. The host binding is still ANDed
    (re-validated above). ``identity`` is the requesting agent identity
    (object or mapping); ``attestation`` an explicitly resolved token
    (else looked up fresh from ``release_config``);
    ``policy_override``/``policy_override_keyset`` carry an optional
    operator-signed override. Every attested/legacy/deny_all decision
    is audit-logged via ``audit_log`` (no secrets, no token material).

    Wave-260: ``enforcer`` (a ``gov.call_enforcement.CallEnforcer`` or
    None) is the per-call authorization check (envoy ext_authz
    adaptation). When provided, EVERY credential swap goes through
    ``enforcer.enforce`` with
    ``{caller_identity, action="credential.swap", resource=credential_id,
    context={dest_host, tool, release_policy, sentinel_prefix}}``
    AFTER the release predicate allows and BEFORE any jti is consumed
    or any value substituted -- no partial release. A deny raises
    :class:`SentinelError` with the verdict's machine code
    (``callauthz-denied`` / ``callauthz-check-error`` /
    ``callauthz-not-configured``), fail-closed, and nothing is
    substituted. ``None`` (default) preserves the pre-wave-260
    behavior for direct/test callers; the ``ToolExecutor`` wires its
    ``call_authorizer`` here on both execution paths.

    Returns ``(new_args, substituted_real_values)``. Appends to
    ``vault.substitution_log`` (operator-side, in-memory only). Raises
    :class:`SentinelError` (fail-closed, no trip — the attempt path
    already had its chance to trip) on a binding mismatch, an
    attestation refusal, or a per-call authorization denial.
    """
    if vault is None or tool not in EGRESS_TOOLS:
        return args, ()
    if not isinstance(args, dict):
        return args, ()
    dest, bound = _binding_map(vault, tool, args)
    bad = bound.pop("__mismatch__", None)
    if bad is not None:
        tok, rec, dest = bad
        raise SentinelError(
            "execution refused: sentinel for credential %r no longer "
            "bound to destination %r (inject_hosts changed since the "
            "attempt) — fail-closed" % (rec["credential_id"], dest))
    if "__unresolvable__" in bound:
        raise SentinelError(
            "execution refused: destination unresolvable for sentinel "
            "use — fail-closed")
    if not bound:
        return args, ()
    import time as _time
    ts = _time.time() if now is None else now
    # The run id binds the attestation session: explicit kwarg wins,
    # else the identity's own run id (object or mapping). Unknown
    # stays "?" and fails the session check fail-closed below.
    rid = run_id if run_id is not None else _identity_run_id(identity)
    if not rid:
        rid = "?"
    aid = _identity_agent_id(identity) or "?"
    decisions = []  # (tok, rec, ok, reason, via_override, jti)
    for tok, rec in bound.items():
        # No silent downgrade (R6): a record missing release_policy is
        # attestation-mandatory, never host-only.
        policy = rec.get("release_policy", "attested")
        cid = rec["credential_id"]
        if policy == "legacy-host-only":
            decisions.append((tok, rec, True,
                              "legacy host-only release (migration path; "
                              "sunsets %s)" % (LEGACY_RELEASE_SUNSET,),
                              False, None))
        elif policy == "deny_all":
            decisions.append((tok, rec, False,
                              "credential %r is under incident hold "
                              "(deny_all): refused" % (cid,), False, None))
        elif policy == "attested":
            ok, reason, via, jti = _attested_decision(
                release_config, cid, rec.get("credential_class"),
                identity, rid, attestation=attestation,
                policy_override=policy_override,
                policy_override_keyset=policy_override_keyset,
                now=ts, consume=False)
            decisions.append((tok, rec, ok, reason, via, jti))
        else:
            decisions.append((tok, rec, False,
                              "unknown release policy %r for credential "
                              "%r: refused fail-closed" % (policy, cid),
                              False, None))
    # Audit every decision (no secrets, no token material), then fail
    # closed on ANY refusal BEFORE consuming a jti or substituting
    # anything -- no partial release.
    if audit_log is not None:
        counters = (release_config.counters_snapshot()
                    if isinstance(release_config, AttestationReleaseConfig)
                    else None)
        for tok, rec, ok, reason, via, jti in decisions:
            policy = rec.get("release_policy", "attested")
            if policy == "legacy-host-only" and ok:
                audit_log.append(legacy_release_event(
                    credential_id=rec["credential_id"], agent_id=aid,
                    run_id=rid, dest=dest, counters=counters))
            else:
                audit_log.append(release_event(
                    credential_id=rec["credential_id"], agent_id=aid,
                    run_id=rid, verdict="allowed" if ok else "denied",
                    reason=reason, policy=policy, via_override=via,
                    counters=counters))
    refused = [d for d in decisions if not d[2]]
    if refused:
        _tok, rec, _ok, reason, _via, _jti = refused[0]
        raise SentinelError(
            "execution refused: attestation-conditioned release failed "
            "for credential %r: %s" % (rec["credential_id"], reason))
    # Wave-260: per-call authorization (envoy ext_authz adaptation).
    # Every swap goes through the enforcer AFTER the release predicate
    # allows and BEFORE any jti is consumed or any value substituted --
    # no partial release. A deny raises with the verdict's machine
    # code; nothing is substituted. The check request carries the full
    # authorization context; the audit event carries no secrets (the
    # credential id is an operator label, the sentinel only a prefix).
    if enforcer is not None:
        try:
            from . import call_enforcement as _ce
        except ImportError:
            raise SentinelError(
                "callauthz-not-configured: an enforcer was supplied but "
                "gov.call_enforcement is unimportable -- refused "
                "fail-closed")
        for tok, rec, ok, reason, via, jti in decisions:
            cid = rec["credential_id"]
            request = _ce.CheckRequest(
                caller_identity=aid,
                action="credential.swap",
                resource=cid,
                context={"dest_host": dest, "tool": tool,
                         "release_policy": rec.get("release_policy",
                                                   "attested"),
                         "sentinel_prefix": (tok[:20] + "..."
                                             if isinstance(tok, str)
                                             else "?")})
            verdict = enforcer.enforce(request)
            if audit_log is not None:
                audit_log.append({
                    "event": "callauthz_decision",
                    "credential_id": cid,
                    "agent_id": aid,
                    "run_id": rid,
                    "dest_host": dest,
                    "verdict": "allowed" if verdict.allow else "denied",
                    "code": verdict.code,
                    "policy_id": verdict.policy_id,
                    "reason": verdict.reason,
                })
            if not verdict.allow:
                raise SentinelError(
                    "%s: per-call authorization denied the swap of "
                    "credential %r for agent %s at %r (policy %s): %s"
                    % (verdict.code, cid, aid, dest,
                       verdict.policy_id, verdict.reason))
    # All decisions allow: consume the jtis (single consumption point),
    # then substitute.
    for tok, rec, ok, reason, via, jti in decisions:
        if jti is not None and release_config is not None:
            release_config.mark_jti(jti)
    mapping = {}
    reals = []
    for tok, rec, ok, reason, via, jti in decisions:
        mapping[tok] = rec["real"]
        reals.append(rec["real"])
        vault.substitution_log.append(
            (rec["credential_id"], dest, _time.time()))
    return substitute_in(args, mapping), tuple(reals)


def _trip(executor, identity, tool, args, sentinel, dest, reason):
    """LOUD trip: audit event + approval-queue escalation, then halt."""
    run_id = getattr(executor, "run_id", "?")
    agent_id = getattr(identity, "agent_id", "?")
    principal = getattr(identity, "principal", "?")
    full_reason = (
        "Sentinel trip: agent %s (principal %s) attempted egress via %s "
        "carrying a credential sentinel at destination %r. %s. "
        "Sentinels are useless outside their authorized channel by "
        "construction; this is blocked exfiltration with a trip "
        "signal. Run halted fail-closed; escalated for human review."
        % (agent_id, principal, tool, dest, reason))

    try:
        executor.log.append({
            "event": "sentinel_trip",
            "run_id": run_id,
            "agent_id": agent_id,
            "role": getattr(identity, "role", "?"),
            "principal": principal,
            "tool": tool,
            "destination": dest,
            "decision": "halted",
            "policy_id": "sentinel-trip",
            "flag": "sentinel_trip",
            "sentinel_prefix": (sentinel[:20] + "..."
                                if isinstance(sentinel, str) else "?"),
            "reason": full_reason,
        })
    except Exception:
        pass  # the halt below is the control; audit is best-effort

    try:
        from .policy import PolicyDecision
        decision = PolicyDecision(
            "require_approval", full_reason,
            policy_id="sentinel-trip", flag="sentinel_trip")
        action = {"tool": tool, "args": args,
                  "identity": identity.as_dict(),
                  "agent_justification": None, "redactions": []}
        preview = executor._preview(tool, args)
        egress_bytes = 0
        _ebf = getattr(executor, "_egress_bytes_for", None)
        if callable(_ebf):
            try:
                egress_bytes = _ebf(tool, args)
            except Exception:
                egress_bytes = 0
        executor.approvals.queue(
            action, decision, "agent_direct", preview,
            policy_hash=executor.policy.policy_hash,
            policy_flag="sentinel_trip",
            egress_bytes=egress_bytes,
            caller_identity=identity)
    except Exception:
        pass  # fail-closed: queue failure must not un-halt

    raise SentinelTripHalt(full_reason)
