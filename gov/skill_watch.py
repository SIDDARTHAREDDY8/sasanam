"""Continuous skill/MCP supply-chain verification (integrated).

Install-time scanning is dead: a skill verified once at install can be
mutated afterwards (SkillJacking shape) and neither the installer nor a
periodic sweep notices in time. A naive watcher that silently re-pins on
mismatch launders the attacker's skill into "verified" status. This
module provides:

1. **Pinned digests at install** — :meth:`SkillWatch.register_skill`
   hashes the skill's content (sha256) and records provenance
   (registry URL, installer identity, install time).
2. **Continuous verification** — :meth:`SkillWatch.verify_all` is the
   scheduled sweep (always re-hashes); :meth:`SkillWatch.check_at_use`
   is the cheap use-time check for the governed call path (stat
   prefilter, full re-hash on any change). The executor's verdict path
   calls ``check_at_use`` and DENIES the tool call fail-closed on
   ``ok=False``.
3. **Fail-closed mutation response** — on digest mismatch the skill is
   quarantined (its tool calls are denied), a ``skill_mutated`` audit
   event is emitted carrying before/after *digests* (never content)
   plus the provenance needed to trace the skill to its source.
4. **Governed re-pinning** — re-pinning a mutated skill requires an
   explicit operator approval (:meth:`SkillWatch.approve_repin`) whose
   ``new_digest`` must match the freshly observed digest: the approval
   binds to the actual mutation, so an attacker cannot bait-and-switch
   the content between the operator's review and the re-pin. There is
   no silent auto-update, ever.
5. **Persistent pins** — :class:`PinStore` serializes the pin registry
   (pins, quarantine set, mutation counts) to JSON atomically. Pins are
   NEVER silently forgotten: a pin file that exists but cannot be
   parsed fails LOUD (:class:`PinStoreError`), and the executor refuses
   to start a pinning deployment over a corrupt pin file.

Fail-closed throughout: unreadable content, stat failures, and hash
errors quarantine the skill — a watcher failure never reads as "clean".

Integration contract (executor wiring):
- The deployment constructs (or loads via ``PinStore.load``) a
  ``SkillWatch``, registers skills at install, and passes it to the
  executor as ``skill_watch=``. ``None`` = pre-integration behavior,
  zero behavior change.
- Tool -> skill attribution is DEPLOYMENT CONFIG, never inferred from
  tool names: ``skill_tool_map={tool_name: skill_id}`` wins; MCP
  servers attribute via ``skill_mcp_map={server_id: skill_id}`` (see
  :func:`skill_id_for_tool` for the ``mcp/<server_id>`` default
  convention) with the executor's ``mcp_server`` framing kwarg
  carrying the adapter's server identity. The executor cannot observe
  a tool's provenance on its own — an unattributed tool is the
  policy's decision, exactly like the tool inventory's unknown-tool
  handling.
- Whoever mutates pins (register / re-pin approval) must
  :meth:`PinStore.save`; the executor persists automatically after
  each :meth:`ToolExecutor.run_skill_sweep`.
- Scheduled sweeps: this tree has NO in-process scheduler/cron. The
  deployment's own scheduler/heartbeat calls
  ``executor.run_skill_sweep()`` (which runs ``verify_all()``,
  persists pins, and returns the report). Recommended interval:
  ``SWEEP_INTERVAL_SECONDS`` (300s). On mismatch the sweep
  quarantines the skill — its tool calls are denied at use time until
  an explicit ``request_repin`` + ``approve_repin`` — and chains a
  ``skill_mutated`` event into the HMAC audit log.

$0 spend, synthetic/local only. No network. Stdlib only.

Honest residuals:
- The use-time stat prefilter trusts mtime/size; an attacker able to
  forge both defeats the *cheap* path — the scheduled sweep always
  re-hashes and still catches it, and any stat change triggers a
  re-hash at use time.
- Single-process in-memory state plus a JSON pin file: no cross-
  process registry locking (same as the rest of the prototype
  surface).
- Content is hashed as opaque bytes: semantic mutation that preserves
  the byte stream is impossible, but the residual is out-of-band
  content the watcher cannot see (e.g. a skill that fetches
  instructions at runtime — needs the egress/tool surface).
- ``installed_at`` is caller-supplied (not independently attested);
  registry-signed timestamps are future work.
"""

import abc
import hashlib
import hmac
import json
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SkillWatchError(Exception):
    """Fail-closed skill-watch violation."""


class PinStoreError(SkillWatchError):
    """Pin persistence failed fail-closed (corrupt/unwritable pin file)."""


class ReferenceResolutionError(SkillWatchError):
    """A referenced URL could not be resolved to bytes."""
    pass


# ---------------------------------------------------------------------------
# Referenced-URL content binding (F142 Leg B)
#
# A skill's pinned manifest can reference content that lives behind a
# URL (SkillJacking dead-link shape: ~925 live skills pulling from dead
# links). The manifest digest binds the manifest, not what it points
# to -- an attacker who takes over the URL serves new instructions
# under the original install-time approval. Leg B binds each referenced
# http(s) URL to the sha256 of the bytes it served at registration;
# use-time and sweep verification re-resolve and quarantine on drift
# or resolution failure. Deployments supply a resolver that performs
# real fetches; the default refuses (no network), in which case
# references are audited but unenforced.
# ---------------------------------------------------------------------------

class ReferenceResolver(abc.ABC):
    """Resolves a referenced URL to bytes for content binding."""

    @abc.abstractmethod
    def resolve(self, url):
        """Return the current bytes served at ``url``.

        Raise :class:`ReferenceResolutionError` when the URL cannot be
        resolved (no network, DNS failure, 404, ...).
        """


class RefusingResolver(ReferenceResolver):
    """Default resolver: refuses every fetch (no network, $0 spend).

    With this resolver every referenced URL registers as
    ``unverified`` -- audited in the event log, never enforced. A
    deployment that wants enforcement supplies a resolver that
    performs real (proxied, filtered) fetches.
    """

    def resolve(self, url):
        raise ReferenceResolutionError(
            "default reference resolver refuses network fetches: %r"
            % (url,))


_REFERENCE_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")

#: F142: cap on references extracted per skill (bounded scan).
_REFERENCE_MAX_URLS = 25

_EVENT_REF_BOUND = "skill_reference_bound"
_EVENT_REF_UNVERIFIED = "skill_reference_unverified"
_EVENT_REF_DRIFT = "skill_reference_drift"
_EVENT_REF_UNVERIFIABLE = "skill_reference_unverifiable"


def _normalize_reference_url(url):
    """Normalize a referenced URL for stable binding.

    Lowercases scheme and host, drops the fragment and default ports.
    Returns None for non-http(s) or unparseable URLs.
    """
    try:
        parts = urlsplit(str(url).strip())
    except Exception:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower()
    port = parts.port
    default = 443 if scheme == "https" else 80
    netloc = host if port in (None, default) else "%s:%d" % (host, port)
    path = parts.path or "/"
    query = ("?" + parts.query) if parts.query else ""
    return "%s://%s%s%s" % (scheme, netloc, path, query)


# ---------------------------------------------------------------------------
# Content sources — the seam that keeps the watcher testable and the
# production path file-backed.
# ---------------------------------------------------------------------------

class ContentSource(abc.ABC):
    """Yields the skill's current content bytes."""

    @abc.abstractmethod
    def read_bytes(self):
        """Return the full current content. Any failure raises OSError."""

    def stat_hint(self):
        """Optional cheap change hint: (mtime_ns, size) or None.

        The use-time check uses this to skip re-hashing unchanged files.
        A changed hint always triggers a full re-hash; the hint is never
        trusted as proof of sameness beyond skipping work.
        """
        return None


class FileContentSource(ContentSource):
    """File-backed skill content (the production shape)."""

    def __init__(self, path):
        self.path = path

    def read_bytes(self):
        with open(self.path, "rb") as f:
            return f.read()

    def stat_hint(self):
        st = os.stat(self.path)
        return (st.st_mtime_ns, st.st_size)


class CallableContentSource(ContentSource):
    """In-memory/test content source."""

    def __init__(self, fn):
        self._fn = fn

    def read_bytes(self):
        return self._fn()


# ---------------------------------------------------------------------------
# Skill watch
# ---------------------------------------------------------------------------

_SKILL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")

_EVENT_REGISTERED = "skill_registered"
_EVENT_MUTATED = "skill_mutated"
_EVENT_UNVERIFIABLE = "skill_unverifiable"
_EVENT_REPIN_REQUESTED = "skill_repin_requested"
_EVENT_REPINNED = "skill_repinned"
_EVENT_SWEEP = "skill_sweep_completed"

#: Recommended scheduled-sweep interval (seconds). The deployment's own
#: scheduler/heartbeat calls ``executor.run_skill_sweep()`` this often.
#: On mismatch the sweep quarantines the skill — tool calls deny at use
#: time until an explicit re-pin approval — and chains ``skill_mutated``
#: into the audit log. The use-time check is the fast path; the sweep is
#: the backstop that defeats forged stat metadata.
SWEEP_INTERVAL_SECONDS = 300


def _utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(content_bytes):
    return hashlib.sha256(content_bytes).hexdigest()


def _check_skill_id(skill_id):
    if not isinstance(skill_id, str) or not _SKILL_ID_RE.match(skill_id):
        raise SkillWatchError("invalid skill id %r" % (skill_id,))
    return skill_id


def skill_id_for_tool(tool, *, tool_to_skill=None, mcp_server=None,
                      mcp_server_to_skill=None):
    """Attribute a tool call to a skill id for pinning purposes.

    Precedence:
    1. Explicit per-tool map ``tool_to_skill[tool]`` — deployment
       config, always wins.
    2. ``mcp_server`` framing hint: ``mcp_server_to_skill[server_id]``
       when the deployment supplied a server map, else the default
       convention ``"mcp/<server_id>"`` (validated against the skill-id
       grammar; invalid server ids raise loudly instead of being
       silently mangled).
    3. ``None`` — unattributed. The caller (executor) does NOT refuse
       unattributed tools; the policy's unknown-skill handling decides
       those, exactly like the tool inventory's unknown-tool handling.

    MCP server mapping decision: an MCP server's executable content —
    its tool definitions, prompts, and resources — is pinned as ONE
    skill whose id is ``mcp/<server_id>`` unless the deployment's
    ``mcp_server_to_skill`` map says otherwise (e.g. two servers
    sharing one audited skill bundle, or opting a server out with an
    explicit ``None`` entry). The executor cannot observe which server
    served a tool — the ``mcp_server`` framing kwarg is the adapter's
    declared attribution, and the binding that makes it trustworthy is
    the deployment's map, not the kwarg's value: a lying kwarg can only
    attribute a tool to a deployment-mapped skill (worst case a
    fail-closed deny), never to an unpinned one.
    """
    if tool_to_skill:
        mapped = tool_to_skill.get(tool)
        if mapped is not None:
            return _check_skill_id(mapped)
    if mcp_server:
        if mcp_server_to_skill:
            mapped = mcp_server_to_skill.get(mcp_server)
            if mapped is not None:
                return _check_skill_id(mapped)
            # Explicit map present but no entry: fall through to the
            # default convention only when the map does not claim the
            # server at all; an explicit None entry opts the server
            # OUT of skill verification.
            if mcp_server in mcp_server_to_skill:
                return None
        return _check_skill_id("mcp/" + mcp_server)
    return None


def sweep_due(last_sweep_at, now=None, interval=SWEEP_INTERVAL_SECONDS):
    """True when a scheduled sweep is due.

    ``last_sweep_at`` is a unix timestamp (or None when no sweep has
    ever run — always due). Deployments with their own scheduler can
    ignore this; it exists so a heartbeat loop has one canonical
    "should I sweep now" predicate.
    """
    if last_sweep_at is None:
        return True
    now = time.time() if now is None else now
    try:
        last = float(last_sweep_at)
    except (TypeError, ValueError):
        return True  # unparseable state: sweep rather than skip
    return (now - last) >= interval


class SkillWatch:
    """Continuous verifier for registered skill/MCP content.

    ``emit`` is the audit-event sink: a callable taking one event dict.
    The default records events in memory (``.events``). Integration
    wires this to the HMAC-chained audit log's ``append`` (the executor
    does this automatically via :meth:`set_emit`). Event payloads carry
    digests and provenance — never skill content.
    """

    def __init__(self, emit=None, reference_resolver=None):
        self._skills = {}  # skill_id -> record dict
        self._quarantined = set()
        self._repin_requests = {}  # skill_id -> request record
        self._events = []
        self._using_default_sink = emit is None
        self._emit = emit if emit is not None else self._events.append
        # F142 Leg B: resolver for referenced-URL content binding.
        # Defaults to RefusingResolver (no network): references are
        # audited but unenforced unless the deployment supplies a
        # resolver that performs real fetches.
        self._reference_resolver = (
            reference_resolver if reference_resolver is not None
            else RefusingResolver())

    # -- introspection --------------------------------------------------------

    @property
    def events(self):
        return list(self._events)

    def registered_skills(self):
        return sorted(self._skills)

    def is_quarantined(self, skill_id):
        """Gate for the governed call path: deny tool calls when True."""
        return skill_id in self._quarantined

    def provenance_for(self, skill_id):
        rec = self._skills.get(skill_id)
        return dict(rec["origin"]) if rec else None

    def set_emit(self, emit):
        """Replace the event sink (the executor calls this at install).

        Events buffered in the default in-memory sink before wiring are
        replayed through the new sink first, so install-time events
        recorded before the executor existed are not silently lost. A
        caller-supplied custom sink is NOT replayed — it was already
        someone's deliberate destination.
        """
        if not callable(emit):
            raise SkillWatchError("emit sink must be callable")
        if self._using_default_sink and self._events:
            buffered = self._events
            self._events = []
            self._using_default_sink = False
            self._emit = emit
            for event in buffered:
                self._emit(event)
        else:
            self._using_default_sink = False
            self._emit = emit

    def _record_event(self, event_type, skill_id, **fields):
        event = {"event_type": event_type, "skill_id": skill_id,
                 "ts": _utcnow()}
        event.update(fields)
        self._emit(event)
        return event

    # -- registration (install time) ------------------------------------------

    def register_skill(self, skill_id, source, *, origin):
        """Pin a skill's content digest at install and record provenance.

        ``origin`` must carry ``registry_url``, ``installer_identity``,
        and ``installed_at`` (a caller-supplied timestamp; the watcher
        fills ``registered_at`` itself). Re-registering an existing id
        fails closed — use the re-pin flow for updates.
        """
        _check_skill_id(skill_id)
        if skill_id in self._skills:
            raise SkillWatchError(
                "skill %r already registered: updates go through the "
                "governed re-pin flow, not re-registration" % skill_id)
        if not isinstance(source, ContentSource):
            raise SkillWatchError("source must be a ContentSource")
        origin = dict(origin or {})
        for key in ("registry_url", "installer_identity", "installed_at"):
            if not origin.get(key):
                raise SkillWatchError(
                    "origin missing required field %r (skill %r cannot be "
                    "traced to its source without provenance)"
                    % (key, skill_id))
        try:
            content = source.read_bytes()
        except OSError as e:
            raise SkillWatchError(
                "cannot read skill %r content at registration (%s): "
                "refusing to pin an unreadable skill" % (skill_id, e))
        if not isinstance(content, (bytes, bytearray)) or not content:
            raise SkillWatchError(
                "skill %r has empty/unreadable content: refusing to pin"
                % skill_id)
        digest = _digest(bytes(content))
        try:
            last_stat = source.stat_hint()
        except Exception:
            # A source that yields bytes but cannot be stat'ed gets no
            # prefilter: every check re-hashes. Never fail registration
            # on the optimization path.
            last_stat = None
        self._skills[skill_id] = {
            "source": source,
            "pinned_digest": digest,
            "origin": origin,
            "registered_at": _utcnow(),
            "last_stat": last_stat,
            "last_verified_at": _utcnow(),
            "mutation_count": 0,
            # F142 Leg B: referenced-URL content bindings (bound at
            # registration; see _bind_references).
            "references": self._bind_references(
                skill_id, bytes(content)),
        }
        self._record_event(_EVENT_REGISTERED, skill_id,
                           pinned_digest=digest, origin=dict(origin))
        return digest

    def _bind_references(self, skill_id, content):
        """F142 Leg B: bind referenced http(s) URLs to content hashes.

        Extracts up to 25 http(s) URLs from the skill content and
        resolves each through the reference resolver, storing
        {url, bound_sha256, status, bound_at} per reference. A URL the
        resolver cannot fetch registers as ``unverified`` (audited via
        an event, never enforced); a hostile or broken resolver must
        not crash registration, so any resolver failure degrades to
        unverified. Never raises.
        """
        refs = []
        seen = set()
        try:
            text = bytes(content).decode("utf-8", "replace")
        except Exception:
            return refs
        try:
            for m in _REFERENCE_URL_RE.finditer(text):
                if len(refs) >= _REFERENCE_MAX_URLS:
                    break
                url = _normalize_reference_url(
                    m.group(0).rstrip(".,;:!?"))
                if not url or url in seen:
                    continue
                seen.add(url)
                try:
                    body = self._reference_resolver.resolve(url)
                except Exception as e:  # noqa: BLE001 — any resolver
                    # failure (refusal, network, hostile resolver)
                    # degrades to unverified, never crashes
                    # registration.
                    refs.append({"url": url, "bound_sha256": None,
                                 "status": "unverified",
                                 "bound_at": _utcnow()})
                    self._record_event(_EVENT_REF_UNVERIFIED, skill_id,
                                       url=url, reason=str(e)[:200])
                    continue
                if not isinstance(body, (bytes, bytearray)) or not body:
                    refs.append({"url": url, "bound_sha256": None,
                                 "status": "unverified",
                                 "bound_at": _utcnow()})
                    self._record_event(_EVENT_REF_UNVERIFIED, skill_id,
                                       url=url,
                                       reason="resolver returned empty/"
                                              "non-bytes")
                    continue
                bound = _digest(bytes(body))
                refs.append({"url": url, "bound_sha256": bound,
                             "status": "bound", "bound_at": _utcnow()})
                self._record_event(_EVENT_REF_BOUND, skill_id,
                                   url=url, bound_sha256=bound)
        except Exception:
            # Binding is a correlation aid, never a registration gate.
            pass
        return refs

    def _verify_references(self, skill_id):
        """F142 Leg B: re-resolve bound references against their pins.

        Returns (True, "references-clean") when every bound reference
        still serves its pinned bytes. A bound reference whose content
        drifted, or that can no longer be resolved, quarantines
        fail-closed and returns (False, detail). ``unverified``
        references are audited but unenforced (skipped).
        """
        rec = self._skills[skill_id]
        for ref in rec.get("references") or []:
            if ref.get("status") != "bound":
                continue
            url = ref["url"]
            try:
                body = self._reference_resolver.resolve(url)
            except Exception as e:  # noqa: BLE001 — a bound reference
                # that goes dark quarantines fail-closed (dead-link
                # takeover / takedown both end enforcement here).
                self._quarantine(skill_id, _EVENT_REF_UNVERIFIABLE,
                                 url=url, reason=str(e)[:200])
                return False, "reference-unresolvable-quarantined"
            if not isinstance(body, (bytes, bytearray)):
                self._quarantine(skill_id, _EVENT_REF_UNVERIFIABLE,
                                 url=url,
                                 reason="resolver returned non-bytes")
                return False, "reference-unresolvable-quarantined"
            observed = _digest(bytes(body))
            if not hmac.compare_digest(observed,
                                       ref.get("bound_sha256") or ""):
                self._quarantine(
                    skill_id, _EVENT_REF_DRIFT, url=url,
                    previous_sha256=ref.get("bound_sha256"),
                    observed_sha256=observed)
                return False, "reference-drift-quarantined"
        return True, "references-clean"

    # -- verification ----------------------------------------------------------

    def _current_digest(self, skill_id):
        """Read and hash current content. Returns (digest, stat_hint).

        Raises SkillWatchError on any read/stat/hash failure — the
        caller quarantines fail-closed. A stat failure here must NOT
        escape as an unexpected exception: the watcher promises that a
        failed check reads as quarantined, never as a crash or a pass.
        """
        rec = self._skills[skill_id]
        try:
            content = rec["source"].read_bytes()
        except Exception as e:  # noqa: BLE001 — any source failure
            # quarantines fail-closed; a hostile source must not be able
            # to crash the watcher into a pass.
            raise SkillWatchError("unreadable content: %s: %s"
                                  % (type(e).__name__, e))
        if not isinstance(content, (bytes, bytearray)):
            raise SkillWatchError("content source returned non-bytes")
        try:
            stat = rec["source"].stat_hint()
        except Exception as e:  # noqa: BLE001 — fail closed, never escape
            raise SkillWatchError("stat failed: %s: %s"
                                  % (type(e).__name__, e))
        return _digest(bytes(content)), stat

    def _quarantine(self, skill_id, event_type, **fields):
        self._quarantined.add(skill_id)
        rec = self._skills.get(skill_id)
        origin = dict(rec["origin"]) if rec else {}
        self._record_event(event_type, skill_id, origin=origin,
                           quarantined=True, **fields)

    def _handle_mismatch(self, skill_id, observed_digest):
        """Digest mismatch: quarantine fail-closed, emit skill_mutated."""
        rec = self._skills[skill_id]
        rec["mutation_count"] += 1
        self._quarantine(
            skill_id, _EVENT_MUTATED,
            previous_digest=rec["pinned_digest"],
            observed_digest=observed_digest,
            mutation_count=rec["mutation_count"])

    def verify_all(self):
        """Scheduled sweep: re-hash EVERY registered skill (no prefilter).

        Returns {"checked": N, "clean": [...], "mutated": [...],
        "unverifiable": [...]}. Mutations and read failures quarantine
        fail-closed.
        """
        report = {"checked": 0, "clean": [], "mutated": [],
                  "unverifiable": [], "reference_drift": []}
        for skill_id in sorted(self._skills):
            report["checked"] += 1
            rec = self._skills[skill_id]
            try:
                observed, stat = self._current_digest(skill_id)
            except SkillWatchError as e:
                report["unverifiable"].append(skill_id)
                self._quarantine(skill_id, _EVENT_UNVERIFIABLE,
                                 reason=str(e)[:200])
                continue
            rec["last_stat"] = stat
            rec["last_verified_at"] = _utcnow()
            manifest_ok = (observed == rec["pinned_digest"])
            if not manifest_ok:
                report["mutated"].append(skill_id)
                self._handle_mismatch(skill_id, observed)
            # F142 Leg B: referenced-URL content binding -- a clean
            # manifest can still point at a rug-pulled URL.
            rok, _ = self._verify_references(skill_id)
            if not rok:
                report["reference_drift"].append(skill_id)
            if manifest_ok and rok:
                report["clean"].append(skill_id)
        self._record_event(_EVENT_SWEEP, "-",
                           checked=report["checked"],
                           clean=len(report["clean"]),
                           mutated=report["mutated"],
                           unverifiable=report["unverifiable"])
        return report

    def check_at_use(self, skill_id):
        """Cheap use-time check for the governed call path.

        Stat prefilter: unchanged (mtime_ns, size) since the last
        verification skips the re-hash. Any stat change — or any skill
        without a stat hint — triggers a full re-hash against the pin.
        Returns (ok, detail) where ok=False means the caller MUST deny
        the tool call. Unregistered skills return (False,
        "unregistered-no-pin"): an id the inventory never pinned is a
        fail-closed denial, not a pass — a tool mapped (by typo, stale
        config, or the MCP "mcp/<server>" default convention) to a
        never-registered id carries zero verification. The ONLY
        permitted "no pin, no denial" posture is the deployment's
        explicit opt-out, which never reaches this seam:
        skill_id_for_tool maps an explicit ``None`` entry to ``None``
        ("unattributed"), and the executor declines to check those.

        Never raises for a registered skill: every source failure
        quarantines fail-closed and returns (False, ...). No
        quarantine state is invented for an unregistered id: a later
        register_skill for that id starts clean.

        F142 Leg B: after the manifest digest check passes, bound
        referenced URLs are re-resolved against their pinned content
        hashes; drift or resolution failure quarantines fail-closed.
        ``unverified`` references (default refusing resolver) are
        audited but unenforced.
        """
        if skill_id in self._quarantined:
            return False, "quarantined"
        rec = self._skills.get(skill_id)
        if rec is None:
            return False, "unregistered-no-pin"
        try:
            current_stat = rec["source"].stat_hint()
        except Exception as e:  # noqa: BLE001 — fail-closed on any stat fault
            self._quarantine(skill_id, _EVENT_UNVERIFIABLE,
                             reason="stat failed: %s" % str(e)[:200])
            return False, "unverifiable-quarantined"
        if (current_stat is not None and rec["last_stat"] is not None
                and current_stat == rec["last_stat"]):
            # F142 Leg B: the stat prefilter only covers the manifest.
            # The manifest being byte-identical is exactly the rug-pull
            # shape (referenced URL content swapped, manifest
            # untouched), so bound references are rechecked even on the
            # fast path. Unverified references stay audited-but-
            # unenforced inside _verify_references.
            rok, rdetail = self._verify_references(skill_id)
            if not rok:
                return False, rdetail
            return True, "clean"
        # Stat changed (or no hint available): re-hash against the pin.
        try:
            observed, stat = self._current_digest(skill_id)
        except SkillWatchError as e:
            self._quarantine(skill_id, _EVENT_UNVERIFIABLE,
                             reason=str(e)[:200])
            return False, "unverifiable-quarantined"
        rec["last_stat"] = stat
        rec["last_verified_at"] = _utcnow()
        if observed != rec["pinned_digest"]:
            self._handle_mismatch(skill_id, observed)
            return False, "mutated-quarantined"
        # F142 Leg B: the manifest digest binds the manifest, not what
        # it references -- re-resolve bound URLs and quarantine on
        # drift or resolution failure.
        rok, rdetail = self._verify_references(skill_id)
        if not rok:
            return False, rdetail
        return True, "clean"

    # -- governed re-pinning ----------------------------------------------------

    def request_repin(self, skill_id, operator):
        """Operator requests re-approval of a mutated/quarantined skill.

        Records the currently observed digest in the request. Returns a
        request id. Emits ``skill_repin_requested``.
        """
        if skill_id not in self._skills:
            raise SkillWatchError("unknown skill %r" % (skill_id,))
        if not operator:
            raise SkillWatchError("re-pin request requires an operator "
                                  "identity")
        try:
            observed, _ = self._current_digest(skill_id)
        except SkillWatchError as e:
            raise SkillWatchError(
                "cannot request re-pin for unverifiable skill %r (%s)"
                % (skill_id, e))
        req_id = "%s:%d" % (skill_id, self._skills[skill_id][
            "mutation_count"])
        # F142 Leg B: capture the currently observed reference content
        # hashes so the approval can bind to them (bait-and-switch
        # protection for references, mirroring the manifest digest).
        ref_observed = {}
        for ref in self._skills[skill_id].get("references") or []:
            url = ref["url"]
            try:
                body = self._reference_resolver.resolve(url)
                ref_observed[url] = (
                    _digest(bytes(body))
                    if isinstance(body, (bytes, bytearray)) and body
                    else None)
            except Exception:
                ref_observed[url] = None
        self._repin_requests[skill_id] = {
            "request_id": req_id,
            "operator": operator,
            "observed_digest": observed,
            "requested_at": _utcnow(),
            "observed_reference_hashes": ref_observed,
        }
        self._record_event(_EVENT_REPIN_REQUESTED, skill_id,
                           request_id=req_id, operator=operator,
                           observed_digest=observed)
        return req_id

    def approve_repin(self, skill_id, approval):
        """Approve a re-pin: binds the approval to the actual mutation.

        ``approval`` must be a dict with ``operator``, ``new_digest``,
        and ``reason``. The ``new_digest`` must equal the digest observed
        fresh at approval time: if the skill changed again between the
        operator's review and this call, the approval does not apply and
        the skill stays quarantined (fail-closed against bait-and-switch).
        There is no silent auto-update: without a matching approval the
        pin never moves.
        """
        if skill_id not in self._skills:
            raise SkillWatchError("unknown skill %r" % (skill_id,))
        if not isinstance(approval, dict):
            raise SkillWatchError("approval must be a dict")
        operator = approval.get("operator")
        new_digest = approval.get("new_digest")
        reason = approval.get("reason")
        if not operator or not new_digest or not reason:
            raise SkillWatchError(
                "approval requires operator, new_digest, and reason")
        req = self._repin_requests.get(skill_id)
        if req is None:
            raise SkillWatchError(
                "no re-pin request for skill %r: re-pinning requires an "
                "explicit request first" % skill_id)
        try:
            observed, stat = self._current_digest(skill_id)
        except SkillWatchError as e:
            raise SkillWatchError(
                "cannot re-pin unverifiable skill %r (%s)" % (skill_id, e))
        if not (isinstance(new_digest, str)
                and hmac.compare_digest(new_digest, observed)):
            # The content moved under the operator's review: the approval
            # binds to a digest that is no longer current. Stay
            # quarantined; the operator must review the NEW content.
            raise SkillWatchError(
                "approval new_digest does not match the currently observed "
                "digest for skill %r: content changed after review; "
                "re-review required (bait-and-switch refused)" % skill_id)
        # F142 Leg B: re-bind references. Each claimed hash is verified
        # against a FRESH resolution at approval time: if the reference
        # changed again between the operator's review and this call,
        # the stale hash is refused (bait-and-switch on the reference).
        new_ref_hashes = approval.get("new_reference_hashes") or {}
        if new_ref_hashes:
            if not isinstance(new_ref_hashes, dict):
                raise SkillWatchError(
                    "approval new_reference_hashes must be a dict")
            for url, claimed in new_ref_hashes.items():
                try:
                    body = self._reference_resolver.resolve(url)
                except Exception as e:  # noqa: BLE001
                    raise SkillWatchError(
                        "cannot re-pin reference %r for skill %r: "
                        "unresolvable at approval time (%s)"
                        % (url, skill_id, e))
                if not isinstance(body, (bytes, bytearray)) or not body:
                    raise SkillWatchError(
                        "cannot re-pin reference %r for skill %r: "
                        "resolver returned empty/non-bytes at approval"
                        % (url, skill_id))
                fresh = _digest(bytes(body))
                if not (isinstance(claimed, str)
                        and hmac.compare_digest(claimed, fresh)):
                    raise SkillWatchError(
                        "approval new_reference_hashes[%r] does not match "
                        "the currently served content for skill %r: "
                        "reference changed after review; re-review "
                        "required (bait-and-switch refused)"
                        % (url, skill_id))
        rec = self._skills[skill_id]
        previous = rec["pinned_digest"]
        rec["pinned_digest"] = observed
        rec["last_stat"] = stat
        rec["last_verified_at"] = _utcnow()
        if new_ref_hashes:
            for ref in rec.get("references") or []:
                if ref["url"] in new_ref_hashes:
                    ref["bound_sha256"] = new_ref_hashes[ref["url"]]
                    ref["status"] = "bound"
                    ref["bound_at"] = _utcnow()
            self._record_event("skill_reference_repinned", skill_id,
                               urls=sorted(new_ref_hashes))
        self._quarantined.discard(skill_id)
        del self._repin_requests[skill_id]
        self._record_event(_EVENT_REPINNED, skill_id,
                           previous_digest=previous, new_digest=observed,
                           operator=operator, reason=str(reason)[:300])
        return observed


# ---------------------------------------------------------------------------
# Persistent pin storage — pins survive restarts, never silently forgotten.
# ---------------------------------------------------------------------------

_PIN_FORMAT = "skill-pins/1"


def default_source_factory(skill_id, origin):
    """Re-attach a content source for a persisted pin.

    File-backed skills record their path in ``origin["content_path"]``
    at registration; anything else needs a deployment-supplied factory
    (pass your own ``source_factory`` to :meth:`PinStore.load`).
    """
    path = (origin or {}).get("content_path")
    if not path:
        raise PinStoreError(
            "no content_path in origin for skill %r: supply a "
            "deployment source_factory to PinStore.load" % (skill_id,))
    return FileContentSource(path)


class PinStore:
    """Atomic JSON persistence for skill pins.

    Contract:
    - :meth:`save` writes atomically (temp file + rename) with mode
      0600 — pins are a trust anchor, not world-readable.
    - :meth:`peek` parses and schema-validates an existing pin file
      WITHOUT building a watcher; a file that exists but is corrupt
      raises :class:`PinStoreError` LOUD (fail-closed: never start a
      pinning deployment over unparseable pins).
    - :meth:`load` peeks, then rebuilds a ``SkillWatch`` via
      ``source_factory(skill_id, origin)``: pins, mutation counts, and
      the quarantine set are restored (a skill quarantined at shutdown
      stays quarantined after restart).
    - A MISSING pin file is not an error — it is a fresh registry. The
      deployment registers skills, then saves. Whoever mutates pins
      (register / approve_repin) must save afterwards; the executor
      persists automatically after each scheduled sweep.
    """

    @staticmethod
    def _serialize(watch):
        pins = {}
        for skill_id in watch.registered_skills():
            rec = watch._skills[skill_id]
            pins[skill_id] = {
                "pinned_digest": rec["pinned_digest"],
                "origin": dict(rec["origin"]),
                "registered_at": rec["registered_at"],
                "last_verified_at": rec["last_verified_at"],
                "mutation_count": rec["mutation_count"],
                # F142 Leg B: referenced-URL content bindings.
                "references": [dict(r)
                               for r in (rec.get("references") or [])],
            }
        return {
            "format": _PIN_FORMAT,
            "saved_at": _utcnow(),
            "pins": pins,
            "quarantined": sorted(watch._quarantined),
        }

    @staticmethod
    def save(watch, path):
        """Atomically persist a watcher's pins to ``path`` (mode 0600)."""
        if not isinstance(watch, SkillWatch):
            raise PinStoreError("can only persist a SkillWatch")
        path = os.fspath(path)
        directory = os.path.dirname(os.path.abspath(path)) or "."
        data = PinStore._serialize(watch)
        fd, tmp = tempfile.mkstemp(prefix=".skill-pins-",
                                   dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise PinStoreError("cannot persist skill pins to %r: %s"
                                % (path, e))
        return path

    @staticmethod
    def peek(path):
        """Parse + schema-validate a pin file; return the raw pin dict.

        Raises :class:`PinStoreError` when the file exists but is
        corrupt — the caller must fail closed, never silently start
        with an empty registry.
        """
        path = os.fspath(path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            raise PinStoreError("skill pin file %r unreadable/corrupt: "
                                "%s: %s"
                                % (path, type(e).__name__, e))
        if not isinstance(data, dict) or data.get("format") != _PIN_FORMAT:
            raise PinStoreError(
                "skill pin file %r has unknown format %r (expected %r)"
                % (path, data.get("format")
                   if isinstance(data, dict) else type(data).__name__,
                   _PIN_FORMAT))
        pins = data.get("pins")
        quarantined = data.get("quarantined", [])
        if not isinstance(pins, dict) or not isinstance(quarantined, list):
            raise PinStoreError("skill pin file %r schema violation"
                                % (path,))
        for skill_id, rec in pins.items():
            _check_skill_id(skill_id)
            if not isinstance(rec, dict):
                raise PinStoreError(
                    "skill pin file %r: bad record for %r" % (path, skill_id))
            for key in ("pinned_digest", "origin", "registered_at",
                        "last_verified_at", "mutation_count"):
                if key not in rec:
                    raise PinStoreError(
                        "skill pin file %r: record %r missing %r"
                        % (path, skill_id, key))
            if not isinstance(rec["origin"], dict):
                raise PinStoreError(
                    "skill pin file %r: record %r origin not a dict"
                    % (path, skill_id))
            # F142 Leg B: references are additive -- pin files written
            # before Leg B load with an empty binding list.
            refs = rec.get("references", [])
            if not isinstance(refs, list):
                raise PinStoreError(
                    "skill pin file %r: record %r references not a list"
                    % (path, skill_id))
            for ref in refs:
                if not isinstance(ref, dict):
                    raise PinStoreError(
                        "skill pin file %r: record %r bad reference"
                        % (path, skill_id))
                for key in ("url", "bound_sha256", "status", "bound_at"):
                    if key not in ref:
                        raise PinStoreError(
                            "skill pin file %r: record %r reference "
                            "missing %r" % (path, skill_id, key))
                if ref["status"] not in ("bound", "unverified"):
                    raise PinStoreError(
                        "skill pin file %r: record %r bad reference "
                        "status %r" % (path, skill_id, ref["status"]))
        for skill_id in quarantined:
            _check_skill_id(skill_id)
            if skill_id not in pins:
                raise PinStoreError(
                    "skill pin file %r: quarantined unknown skill %r"
                    % (path, skill_id))
        return data

    @staticmethod
    def load(path, source_factory=None, emit=None, reference_resolver=None):
        """Rebuild a ``SkillWatch`` from a persisted pin file.

        ``source_factory(skill_id, origin)`` re-attaches content
        sources; defaults to :func:`default_source_factory` (file-backed
        skills with ``origin["content_path"]``). Sources that fail to
        attach make the load LOUD — a pin without observable content
        is a trust hole, not a fresh registry. ``reference_resolver``
        is passed through to the rebuilt watcher (F142 Leg B); without
        one, restored ``bound`` references cannot be re-verified until
        the deployment supplies a resolver.
        """
        data = PinStore.peek(path)
        factory = (source_factory if source_factory is not None
                   else default_source_factory)
        watch = SkillWatch(emit=emit,
                           reference_resolver=reference_resolver)
        for skill_id in sorted(data["pins"]):
            rec = data["pins"][skill_id]
            try:
                source = factory(skill_id, dict(rec["origin"]))
            except Exception as e:  # noqa: BLE001 — fail closed, loud
                raise PinStoreError(
                    "cannot re-attach content source for skill %r: %s"
                    % (skill_id, e))
            if not isinstance(source, ContentSource):
                raise PinStoreError(
                    "source_factory returned non-ContentSource for %r"
                    % (skill_id,))
            try:
                last_stat = source.stat_hint()
            except Exception:
                last_stat = None  # no prefilter: every check re-hashes
            watch._skills[skill_id] = {
                "source": source,
                "pinned_digest": rec["pinned_digest"],
                "origin": dict(rec["origin"]),
                "registered_at": rec["registered_at"],
                "last_stat": last_stat,
                "last_verified_at": rec["last_verified_at"],
                "mutation_count": rec["mutation_count"],
                # F142 Leg B: restored bindings (pre-Leg-B pin files
                # carry none).
                "references": [dict(r)
                               for r in (rec.get("references") or [])],
            }
        for skill_id in data["quarantined"]:
            watch._quarantined.add(skill_id)
        watch._record_event("skill_pins_restored", "-",
                           restored=len(data["pins"]),
                           quarantined_restored=len(data["quarantined"]))
        return watch
