"""Passive agent-discovery substrate (STREAM-A, integrated).

THE PROBLEM (direction-check 2026-09-23): we govern REGISTERED agents,
but the industry's #1 pain is agents nobody knows about (CSA: 82% of
orgs run unidentified agents). This module is the discovery primitive:
it finds agent footprints in filesystem/config/process data, keeps a
tamper-evident inventory of candidates, and surfaces
discovered-but-unregistered agents to the governed identity path as
``unregistered_agent`` audit events (see :func:`report_unregistered`).

DESIGN (invention-from-old: census, not surveillance):
* **Signals, not verdicts.** The scanner emits weighted signals
  (harness configs, MCP registrations, credentials, processes, prompt
  footprints). A candidate is a *sighting*, never an accusation.
* **Registration stays an explicit operator act.** Discovered candidates
  are NEVER auto-registered and NEVER auto-blocked. The only automatic
  output is the finding.
* **Hash-chained ledger.** Every sighting, merge, registration, and
  scan error is an append-only chained record — the inventory itself is
  evidence, auditable like the action log.
* **Fail-closed.** Scanner errors are recorded as ``scan_error``
  entries; a failed scan never shrinks the inventory. Ledger tamper
  raises on load. The scanner refuses any root outside the
  operator-designated fixture base (never a real home directory).

WHY THE LEDGER DOES NOT REUSE gov.log.ActionLog:
The action log's HMAC chain requires a provisioned key
(``GOV_LOG_KEY`` / keyring; fail-closed without one — wave-81), which
would couple discovery availability to key custody: a deployment with
no key configured could not even run a discovery sweep. The discovery
ledger instead uses an unkeyed SHA-256 chain rooted at ``"GENESIS"``,
verifiable offline by anyone holding the file — the same trust model as
Surety's newspaper-printed hash-chain heads (invention-from-old). The
compromise: every ``unregistered_agent`` finding handed to the governed
identity path IS mirrored onto the deployment's ``ActionLog`` by
:func:`report_unregistered` as an ``{"event": "unregistered_agent"}``
entry, inheriting the HMAC chain there. Residual: an attacker with
write access to the discovery ledger FILE can rewrite it end-to-end
and recompute the chain (no key binds it); the mitigation is the
audit-log mirror plus file-level protection of the ledger.

SCOPE (honest boundary): filesystem + config + process-list signals
only, read-only, synthetic fixture dirs in this integration (the
``allowed_base`` guard). No network traffic analysis, no host-wide
daemon, no live /proc scraping in tests (the process source is
injectable; production wiring is future work). The differential
live-host pattern (osquery-style {query, interval, removed} over
stdlib snapshots, injectable in tests) now lives in
gov/discovery_diff.py. Secret VALUES are never
stored — only rule ids and fingerprints.

$0 spend, synthetic/local only, no network, stdlib only.
"""

import hashlib
import json
import logging
import os
import re
import tempfile
import time

from .dlp import find_credential

_log = logging.getLogger("gov.discovery")

# ---------------------------------------------------------------------------
# Signal taxonomy
# ---------------------------------------------------------------------------
#: (signal_kind, weight) — weights are ordinal, not probabilities.
SIGNAL_WEIGHTS = {
    "harness_config": 3,    # .claude/ .cursor/ .codex/ ... config dirs
    "mcp_server": 3,        # MCP server registration entries
    "credential": 2,        # credential-shaped secret in a file
    "agent_process": 4,     # running process matching a known harness
    "unknown_agent_process": 4,  # differential (gov/discovery_diff.py):
                                 # added process absent from the governed
                                 # inventory — same severity class as
                                 # agent_process
    "prompt_footprint": 1,  # CLAUDE.md / AGENTS.md style instruction files
    # Shadow-scan kinds (gov/shadow_scan.py): behavioral signals over
    # the audit trail. scan_action_log() passes the MEASURED 0..1
    # signal strength explicitly, so these weights are the default
    # scale only — see scan_action_log's docstring.
    "machine_cadence": 3,        # sustained machine-rate action cadence
    "orchestration_patterns": 3,  # LLM-orchestration tool-use patterns
    "credential_shape": 2,       # operator-hinted credential shape
    # R7 #5 (gov/enumeration_signal.py): rate-independent enumeration
    # structure. scan_action_log() passes the MEASURED 0..1 strength
    # explicitly, so this weight is the default scale only.
    "enumeration_structure": 3,  # list->read loops + distinct-target
                                 # coverage, no rate band, long window
    # scan_error is a ledger EVENT, not a candidate signal: strength 0,
    # and candidate_id_for_sig() returns None for it. Scanner failures
    # are recorded, never silent — the fail-closed direction.
    "scan_error": 0,
}

#: Signal kinds emitted by the behavioral shadow scan (audit-trail
#: surface). Their candidate ids key on the principal fingerprint,
#: never on a filesystem path.
SHADOW_SIGNAL_KINDS = frozenset({
    "machine_cadence", "orchestration_patterns", "credential_shape",
    "enumeration_structure",
})

#: Directory names that mark an agent harness workspace.
HARNESS_DIRS = frozenset({
    ".claude", ".cursor", ".codex", ".aider", ".continue", ".windsurf",
    ".copilot", ".amazonq", ".gemini",
})

#: Config files that may carry MCP server registrations.
MCP_CONFIG_NAMES = frozenset({
    "mcp.json", ".mcp.json", "claude_desktop_config.json",
})

#: Instruction-file names that mark an agent working directory.
PROMPT_FILES = frozenset({
    "CLAUDE.md", "AGENTS.md", ".claude.md", "CURSOR.md",
})

#: Process-name fragments that mark a known agent harness.
HARNESS_PROCESS_RES = tuple(
    re.compile(p, re.IGNORECASE) for p in (
        r"\bcodex\b", r"\bclaude\b", r"\bcursor\b", r"\baider\b",
        r"mcp-server", r"\bcopilot\b", r"opencode",
    )
)

#: Scanner safety caps.
MAX_FILE_BYTES = 1 << 20        # 1 MiB per file
MAX_FILES_PER_SCAN = 20000
MAX_DIR_DEPTH = 32


class DiscoveryError(Exception):
    """Scanner/ledger failure. Never silently swallowed."""


class LedgerCorruptError(DiscoveryError):
    """The discovery ledger failed chain verification on load."""


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------

def _fingerprint(value):
    """Stable non-reversible fingerprint for secret-shaped material."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def signal(kind, source, detail=None, strength=None):
    """Build one signal record."""
    if kind not in SIGNAL_WEIGHTS:
        raise DiscoveryError("unknown signal kind %r" % (kind,))
    return {
        "kind": kind,
        "source": source,
        "detail": detail or {},
        "strength": (SIGNAL_WEIGHTS[kind] if strength is None
                     else strength),
        "ts": int(time.time()),
    }


def scan_mcp_config(path, text):
    """Extract MCP server-registration signals from a config file."""
    signals = []
    try:
        doc = json.loads(text)
    except Exception:
        return signals
    servers = None
    if isinstance(doc, dict):
        servers = doc.get("mcpServers") or doc.get("servers")
    if not isinstance(servers, dict):
        return signals
    for name, spec in servers.items():
        if not isinstance(name, str):
            continue
        detail = {"server": name}
        if isinstance(spec, dict):
            cmd = spec.get("command")
            if isinstance(cmd, str):
                detail["command"] = cmd[:200]
        signals.append(signal("mcp_server", path, detail))
    return signals


def scan_file_content(path, text):
    """Content signals for one file: credentials + prompt footprints."""
    signals = []
    rule = find_credential(text)
    if rule:
        # NEVER the value: rule id + fingerprint only.
        signals.append(signal("credential", path, {
            "rule": rule,
            "fp": _fingerprint(text[:4096]),
        }))
    base = os.path.basename(path)
    if base in PROMPT_FILES:
        signals.append(signal("prompt_footprint", path,
                              {"file": base}))
    return signals


def scan_process_list(processes):
    """Signals from a process snapshot.

    ``processes`` is an iterable of ``(pid, name, cmdline)`` triples —
    injectable so tests never touch the live host. A production wiring
    would feed this from a read-only host inventory source.
    """
    signals = []
    for pid, name, cmdline in processes:
        hay = "%s %s" % (name or "", cmdline or "")
        for rx in HARNESS_PROCESS_RES:
            if rx.search(hay):
                signals.append(signal("agent_process",
                                      "pid:%s" % pid,
                                      {"name": (name or "")[:120],
                                       "cmdline": (cmdline or "")[:200]}))
                break
    return signals


# ---------------------------------------------------------------------------
# Read-only directory scanner
# ---------------------------------------------------------------------------

def _is_text(data):
    return b"\x00" not in data[:8192]


def _check_scan_root(root, allowed_base):
    """Enforce the fixture-only boundary: fail CLOSED if ``root`` is not
    inside the operator-designated ``allowed_base``, and fail CLOSED if
    ``allowed_base`` itself is not inside the OS temp area.

    This integration governs synthetic fixtures only. A production
    deployment must replace this with an operator allowlist; the guard
    below exists so the discovery primitive can never be pointed at a
    real user home by mistake (or by an attacker who controls a scan
    request).
    """
    sys_tmp = os.path.realpath(tempfile.gettempdir())
    if allowed_base is None:
        allowed_base = sys_tmp
    base = os.path.realpath(allowed_base)
    if not (base == sys_tmp or base.startswith(sys_tmp + os.sep)):
        raise DiscoveryError(
            "allowed_base %r is outside the system temp area %r; "
            "discovery scans synthetic fixtures only" % (base, sys_tmp))
    real_root = os.path.realpath(root)
    if not (real_root == base or real_root.startswith(base + os.sep)):
        raise DiscoveryError(
            "scan root %r is outside allowed_base %r; discovery scans "
            "synthetic fixtures only" % (real_root, base))
    return real_root


def scan_directory(root, *, process_snapshot=(), allowed_base=None):
    """Read-only scan of ``root``. Returns a list of signals.

    ``root`` must lie inside ``allowed_base`` (default: the OS temp
    area); anything else raises :class:`DiscoveryError` — the scanner
    is never pointed at a real home directory. ``allowed_base`` itself
    must be inside the OS temp area.

    Safety: symlinks are never followed outside ``root``; files over
    MAX_FILE_BYTES are skipped (recorded); unreadable entries become
    ``scan_error`` signals instead of aborting the scan. ``root`` must
    be an explicit operator choice — never default this to a home dir.
    """
    root = _check_scan_root(root, allowed_base)
    if not os.path.isdir(root):
        raise DiscoveryError("scan root %r is not a directory" % (root,))
    signals = []
    errors = []
    seen = 0
    capped = False

    def record_error(where, exc):
        errors.append(signal("scan_error", where,
                             {"error": "%s: %s" % (type(exc).__name__,
                                                  str(exc)[:200])},
                             strength=0))

    for dirpath, dirnames, filenames in os.walk(root,
                                                followlinks=False):
        if capped:
            # File cap already hit and recorded once: stop the walk
            # entirely instead of emitting one scan_error per dir.
            dirnames[:] = []
            break
        depth = os.path.relpath(dirpath, root).count(os.sep)
        if depth > MAX_DIR_DEPTH:
            dirnames[:] = []
            continue
        # Prune symlinked dirs that escape the root (read-only: do not
        # follow, just note).
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            try:
                if os.path.islink(full):
                    target = os.path.realpath(full)
                    if not target.startswith(root + os.sep):
                        record_error(full, OSError(
                            "symlink escapes scan root; not followed"))
                    dirnames.remove(d)
            except OSError as e:
                record_error(full, e)
                dirnames.remove(d)
        # Harness config dirs: one signal per dir, no need to descend
        # for content (their files are scanned as regular files anyway).
        for d in dirnames:
            if d in HARNESS_DIRS:
                signals.append(signal(
                    "harness_config", os.path.join(dirpath, d),
                    {"dir": d}))
        for fn in filenames:
            if seen >= MAX_FILES_PER_SCAN:
                record_error(root, OSError(
                    "file cap %d reached; remainder unscanned"
                    % MAX_FILES_PER_SCAN))
                capped = True
                break
            full = os.path.join(dirpath, fn)
            seen += 1
            try:
                if os.path.islink(full):
                    continue
                st = os.stat(full)
                if not st or st.st_size > MAX_FILE_BYTES:
                    continue
                with open(full, "rb") as f:
                    data = f.read(MAX_FILE_BYTES + 1)
                if not _is_text(data):
                    continue
                text = data.decode("utf-8", "replace")
            except OSError as e:
                record_error(full, e)
                continue
            if fn in MCP_CONFIG_NAMES:
                signals.extend(scan_mcp_config(full, text))
            signals.extend(scan_file_content(full, text))
    signals.extend(scan_process_list(process_snapshot))
    signals.extend(errors)
    _log.info("discovery scan of %s: %d signals, %d errors",
              root, len(signals) - len(errors), len(errors))
    return signals


# ---------------------------------------------------------------------------
# Behavioral shadow scan over the audit trail
# ---------------------------------------------------------------------------

from . import shadow_scan as _shadow_scan


def scan_action_log(entries, registered_principals, credential_hints=None):
    """Behavioral shadow-agent fingerprinting over audit-log entries.

    This closes the telemetry surface ``scan_directory`` cannot see:
    an unregistered agent acting through the governed executor at
    machine rate leaves no filesystem/config/process footprint, but it
    does leave cadence + orchestration-pattern evidence in the audit
    trail. The fingerprinting itself lives in ``gov/shadow_scan.py``
    (MandateZ shadow-scan shape, rebuilt from documentation):
    machine-rate cadence, LLM-orchestration tool patterns, and
    operator-hinted credential shape.

    Signals, not verdicts: one signal per PRESENT signal kind per
    flagged principal (``machine_cadence`` / ``orchestration_patterns``
    / ``credential_shape``), each with the measured 0..1 strength
    passed explicitly — the ordinal ``SIGNAL_WEIGHTS`` are the default
    scale only, and the measured scale is documented here so ledger
    readers are not misled. The candidate id keys on the principal
    fingerprint (``shadow:<fp16>``); registration stays an explicit
    operator act via ``DiscoveryLedger.mark_registered``.

    Feed the returned signals into ``DiscoveryLedger.note_signals``
    exactly like a ``scan_directory`` batch.
    """
    findings = _shadow_scan.scan(entries, set(registered_principals),
                                 credential_hints)
    signals = []
    for f in findings:
        for s in f["signals"]:
            if not s["present"]:
                continue
            signals.append(signal(
                s["kind"],
                "principal:%s" % f["principal"],
                {"principal": f["principal"],
                 "fingerprint_score": f["score"],
                 "actions": f["actions"],
                 "skipped": f["skipped"],
                 "signal_strength": s["strength"],
                 "signal_detail": s["detail"],
                 "remediation": f["remediation"]},
                strength=s["strength"]))
    _log.info("shadow scan over %d entries: %d signals for %d principals",
              len(entries), len(signals), len(findings))
    return signals


def scan_log_file(path, registered_principals, *, credential_hints=None,
                  limit=None):
    """Read-only convenience: ``gov.log.query_log`` on ``path``, then
    :func:`scan_action_log`. Never raises on content problems — the
    query path reads, it does not judge (malformed lines are skipped
    by ``query_log`` and malformed entries by the fingerprinter, both
    counted, never silently trusted).
    """
    from .log import query_log  # lazy: keep discovery importable alone
    entries = query_log(path, limit=limit)
    return scan_action_log(entries, registered_principals,
                           credential_hints)


# ---------------------------------------------------------------------------
# Candidate identity + hash-chained ledger
# ---------------------------------------------------------------------------

def candidate_id_for_sig(sig):
    """Stable candidate id for a signal.

    Filesystem/config/credential signals key on the real path (the file
    IS the footprint); process signals key on pid+name fingerprint;
    shadow-scan signals key on the principal fingerprint (the principal
    IS the footprint — never a path, never colliding with ``fs:``).
    """
    kind = sig["kind"]
    if kind in ("agent_process", "unknown_agent_process"):
        return "proc:" + _fingerprint(sig["source"] + json.dumps(
            sig["detail"], sort_keys=True))
    if kind == "scan_error":
        return None  # errors are ledger events, not candidates
    if kind in SHADOW_SIGNAL_KINDS:
        return "shadow:" + _fingerprint(sig["source"])
    path = os.path.realpath(sig["source"]) \
        if os.path.exists(sig["source"]) else sig["source"]
    return "fs:" + _fingerprint(path)


def _chain_hash(prev_hash, canonical):
    return hashlib.sha256(
        (prev_hash + canonical).encode("utf-8")).hexdigest()


class DiscoveryLedger:
    """Append-only, hash-chained inventory of agent candidates.

    Record kinds: ``sighting`` (new candidate), ``merge`` (repeat
    sighting folded into an existing candidate), ``registered`` /
    ``dismissed`` (explicit operator acts — the ONLY way a candidate
    leaves ``candidate`` status), ``scan_error`` (scanner failure).

    RESIDUAL: appends are not inter-process locked (contrast the
    action log's fcntl-flocked appends, F25). Two processes holding
    the same ledger file can interleave and fork the chain; the next
    load then raises LedgerCorruptError (fail-closed on read), but the
    write side is not linearizable. Deployments must single-writer
    the ledger file or add locking.
    """

    def __init__(self, path):
        self.path = path
        self._entries = []
        self._candidates = {}  # candidate_id -> latest merged view
        if os.path.exists(path):
            self._load()

    # -- persistence --------------------------------------------------
    def _load(self):
        prev = "GENESIS"
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    raise LedgerCorruptError(
                        "ledger line %d is not JSON" % lineno)
                try:
                    body = {k: e[k] for k in sorted(e)
                            if k != "entry_hash"}
                    expect = _chain_hash(
                        e["prev_hash"], json.dumps(body, sort_keys=True))
                    if e["prev_hash"] != prev or e["entry_hash"] != expect:
                        raise ValueError("chain mismatch")
                except LedgerCorruptError:
                    raise
                except Exception:
                    # Any malformed entry — missing fields, wrong types —
                    # is ledger corruption, never a raw KeyError/TypeError.
                    raise LedgerCorruptError(
                        "ledger line %d is malformed" % lineno)
                prev = e["entry_hash"]
                self._entries.append(e)
                self._apply(e)

    def _append(self, kind, payload):
        prev = (self._entries[-1]["entry_hash"]
                if self._entries else "GENESIS")
        body = {"seq": len(self._entries), "prev_hash": prev,
                "ts": int(time.time()), "kind": kind,
                "payload": payload}
        body["entry_hash"] = _chain_hash(
            prev, json.dumps(body, sort_keys=True))
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(body, sort_keys=True) + "\n")
        self._entries.append(body)
        self._apply(body)
        return body

    def _apply(self, entry):
        p = entry["payload"]
        cid = p.get("candidate_id")
        if entry["kind"] in ("sighting", "merge") and cid:
            view = self._candidates.get(cid)
            if view is None:
                self._candidates[cid] = {
                    "candidate_id": cid,
                    "first_seen": p["first_seen"],
                    "last_seen": p["last_seen"],
                    "signals": list(p["signals"]),
                    "strength": p["strength"],
                    "status": "candidate",
                }
            else:
                view["last_seen"] = p["last_seen"]
                have = {(s["kind"], s["source"])
                        for s in view["signals"]}
                for s in p["signals"]:
                    if (s["kind"], s["source"]) not in have:
                        view["signals"].append(s)
                        have.add((s["kind"], s["source"]))
                view["strength"] = sum(
                    s["strength"] for s in view["signals"])
        elif entry["kind"] in ("registered", "dismissed") and cid:
            view = self._candidates.get(cid)
            if view is not None:
                view["status"] = entry["kind"]
                view["status_by"] = p.get("operator")
                view["status_ts"] = entry["ts"]

    # -- intake --------------------------------------------------------
    def note_signals(self, signals):
        """Fold scanner signals into the ledger. Returns [candidate_ids].

        ``scan_error`` signals become ledger events, never candidates.
        Re-sighting an existing candidate appends a ``merge`` record —
        the inventory only grows on intake; nothing is ever deleted or
        auto-resolved here.
        """
        by_cid = {}
        for sig in signals:
            cid = candidate_id_for_sig(sig)
            if cid is None:
                self._append("scan_error", {"signal": {
                    k: sig[k] for k in ("kind", "source", "detail")}})
                continue
            by_cid.setdefault(cid, []).append(sig)
        touched = []
        for cid, sigs in by_cid.items():
            now = int(time.time())
            strength = sum(s["strength"] for s in sigs)
            if cid in self._candidates:
                self._append("merge", {
                    "candidate_id": cid, "last_seen": now,
                    "signals": sigs, "strength": strength})
            else:
                self._append("sighting", {
                    "candidate_id": cid, "first_seen": now,
                    "last_seen": now, "signals": sigs,
                    "strength": strength})
            touched.append(cid)
        return touched

    # -- explicit operator acts (the ONLY status transitions) ---------
    def mark_registered(self, candidate_id, operator):
        if candidate_id not in self._candidates:
            raise DiscoveryError("unknown candidate %r" % (candidate_id,))
        self._append("registered", {"candidate_id": candidate_id,
                                   "operator": operator})

    def mark_dismissed(self, candidate_id, operator, reason=""):
        if candidate_id not in self._candidates:
            raise DiscoveryError("unknown candidate %r" % (candidate_id,))
        self._append("dismissed", {"candidate_id": candidate_id,
                                  "operator": operator, "reason": reason})

    # -- reads ----------------------------------------------------------
    def candidates(self, status=None):
        views = list(self._candidates.values())
        if status is not None:
            views = [v for v in views if v["status"] == status]
        return views

    def verify(self):
        """Re-verify the whole chain. Raises LedgerCorruptError."""
        prev = "GENESIS"
        for e in self._entries:
            body = {k: e[k] for k in sorted(e) if k != "entry_hash"}
            expect = _chain_hash(e["prev_hash"],
                                 json.dumps(body, sort_keys=True))
            if e["prev_hash"] != prev or e["entry_hash"] != expect:
                raise LedgerCorruptError("chain broken at seq %d"
                                        % e["seq"])
            prev = e["entry_hash"]
        return len(self._entries)


# ---------------------------------------------------------------------------
# Findings + governed-identity handoff
# ---------------------------------------------------------------------------

#: Finding schema handed to the detection/response layer.
FINDING_KIND = "unregistered_agent"


def unregistered_candidates(ledger, is_registered=None):
    """Return ``unregistered_agent`` findings for candidates.

    ``is_registered`` is an optional callable
    ``candidate_view -> bool`` backed by the deployment's
    ``PrincipalRegistry`` (or equivalent). ``None`` means no registry is
    wired: every candidate in ``candidate`` status is reported — loud,
    not silent. Findings are plain dicts with a stable schema; this
    module never writes to the detection layer directly — use
    :func:`report_unregistered` to mirror findings onto the governed
    audit log.
    """
    findings = []
    for view in ledger.candidates(status="candidate"):
        if is_registered is not None:
            try:
                if is_registered(view):
                    continue
            except Exception as e:
                # A broken registry check must not suppress the finding.
                _log.warning("is_registered check failed for %s: %s "
                             "(finding kept)", view["candidate_id"], e)
        findings.append({
            "kind": FINDING_KIND,
            "candidate_id": view["candidate_id"],
            "strength": view["strength"],
            "signal_kinds": sorted({s["kind"]
                                    for s in view["signals"]}),
            "sources": sorted({s["source"] for s in view["signals"]}),
            "first_seen": view["first_seen"],
            "last_seen": view["last_seen"],
        })
    return sorted(findings, key=lambda f: (-f["strength"],
                                           f["candidate_id"]))


def report_unregistered(ledger, *, audit_log=None, registry=None,
                        principal_for=None, operator=None):
    """Report candidates through the governed identity path.

    This is the discovery -> identity handoff. It computes
    ``unregistered_agent`` findings (see :func:`unregistered_candidates`)
    and, when ``audit_log`` is supplied (a ``gov.log.ActionLog``), appends
    one ``{"event": "unregistered_agent", ...}`` entry per finding to the
    HMAC-chained action log — the same event namespace as
    ``identity_minted`` / ``identity_mint_refused``, so discovery output
    is auditable by the governed identity path. Never auto-registers and
    never auto-blocks: the ONLY automatic output is the finding.

    ``registry``: an optional ``gov.identity.PrincipalRegistry``.
    ``principal_for``: optional callable
    ``candidate_view -> (principal, role, agent_id|None) | None``
    supplied by the deployment to map a candidate's footprint to a
    claimed registry identity. When both are given, a candidate is
    suppressed ONLY if the claimed identity passes
    ``registry.check_identity``; a claim the registry REJECTS
    (``UnregisteredPrincipalError``) keeps the finding LOUD — a false
    registration claim is exactly what must surface. When a registry is
    present but no mapping is supplied, every candidate is reported
    (no mechanical principal->footprint mapping exists, so anything
    else would be silent suppression).

    Returns ``(findings, appended)``: the finding list and the number of
    audit entries appended.
    """
    from . import identity as _identity  # lazy: identity.py sits on the
    # executor-adjacent import graph; keep discovery importable alone.

    if registry is not None and principal_for is not None:
        def is_registered(view):
            claim = principal_for(view)
            if not claim:
                return False
            try:
                principal, role = claim[0], claim[1]
                agent_id = claim[2] if len(claim) > 2 else None
            except (TypeError, IndexError, KeyError):
                _log.warning("principal_for returned malformed claim "
                             "for %s (finding kept)",
                             view["candidate_id"])
                return False
            try:
                registry.check_identity(principal, role,
                                        agent_id=agent_id)
                return True
            except _identity.UnregisteredPrincipalError:
                return False
    else:
        # No registry, or no mapping: loud, not silent.
        is_registered = None

    findings = unregistered_candidates(ledger, is_registered=is_registered)
    appended = 0
    if audit_log is not None:
        for f in findings:
            audit_log.append({
                "event": "unregistered_agent",
                "candidate_id": f["candidate_id"],
                "strength": f["strength"],
                "signal_kinds": f["signal_kinds"],
                "sources": f["sources"],
                "first_seen": f["first_seen"],
                "last_seen": f["last_seen"],
                "reported_by": operator or "discovery",
                "reason": ("agent candidate has no registry identity; "
                           "operator must review, register, or dismiss"),
            })
            appended += 1
    return findings, appended
