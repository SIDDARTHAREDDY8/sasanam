"""Mandatory infection-lineage substrate (S6, wave-90 — closes F137).

The problem (F137, HIGH): a self-replicating payload crosses spawn hops
through RAW FILE communication with zero infection-lineage records. The
S2 governed message bus is opt-in, so the file channel bypasses every
lineage control: the infection monitor never sees it, quarantine never
fires, and the audit chain has no hop records.

The fix is a lineage layer that sits UNDERNEATH both the bus and the raw
file channel (the bus stays opt-in — see the design note below). Three
old ideas recombined:

- OS process lineage / birth certificates -> every spawn mints a signed,
  inheritable lineage record ("birth certificate"). The child carries it;
  execution verifies it. There is no opt-out within a governed run: a
  child executor without a birth record fails closed at first use.
- Dynamic taint tracking -> every agent-driven file write is
  lineage-stamped (HMAC sidecar: writer lineage, content hash, taint
  bit). Every read picks up the stamp, records a ``lineage_contact``
  event, and propagates taint: reading an infected file infects the
  reader; the reader's later writes are stamped infected.
- Process accounting -> a per-run spawn registry
  (``run_dir/lineage/registry.jsonl``), each record hash-chained to the
  previous one, mirrored by chained ``lineage_birth`` audit events.

Population-level detection: ``observe_content`` watches content hashes
across the file channel — the same payload bytes appearing under >= 3
distinct agent lineages fires ``infection_suspected`` and taint-marks
the origin lineage (the file-channel analogue of the bus infection
monitor). Content is correlated by hash, so renames and copies do not
evade it.

Why the bus is NOT made mandatory (deliberate, documented): the bus is
typed (note/data/status), bandwidth-capped (200 msgs / 1 MiB per sender
per run), and limited to 64 KiB data payloads. Forcing every inter-agent
byte — large artifacts, binary payloads, tool outputs — through it would
break legitimate workflows and incentivize bypassing governance
entirely. Provenance must not dictate traffic shape. The lineage
substrate gives one uniform provenance graph across bus + files +
spawn, which is what population-level detection actually needs.

Trust model (honest): sidecar stamps live next to agent files, so they
are agent-reachable by construction — exactly like the audit log the S2
bus treats as agent-reachable. Stamps are therefore HMAC-signed with a
per-run key held in the operator trust domain
(``run_dir/lineage/.key``, mode 0600); governed tools cannot read
outside the sandbox, so agents cannot reach the key through
``read_file``/``write_file``. A deployment that grants agents raw host
filesystem access outside governed tools must protect
``run_dir/lineage`` exactly as it protects audit-log key material. A
forged or mismatched stamp is LOUD (``lineage_stamp_forged``) and the
content is treated as tainted.

Deployment wiring contract (the deployment owns this; the tracker is
opt-in at deployment, mandatory within the run once installed):
  1. ``tracker = LineageTracker(run_dir, action_log)`` — one per run,
     operator trust domain, shared by reference (like the bus).
  2. ``tracker.genesis(agent_id, role=..., principal=...)`` for every
     top-level agent BEFORE it acts.
  3. ``ToolExecutor(..., lineage_tracker=tracker)`` — the constructor
     takes it as ``lineage_tracker=`` (None = pre-wave-90 behavior,
     zero behavior change).
  4. Child spawns birth automatically in ``spawn_sub_agent`` — AFTER
     key registration and child-token creation succeed, so a refused
     spawn leaves no orphan record; the certificate carries both
     token refs. Deployments that mint identities outside the
     executor MUST birth them first (``tracker.birth(parent, child)``
     fails closed on unregistered parents).
  5. ``call()`` refuses unlineaged identities fail-closed (loud,
     audit-logged) — there is no execution path that bypasses the
     gate when the tracker is installed.
Single-writer assumption: the registry is append-only under one
process, like the run's ActionLog; concurrent multi-process trackers
on one run_dir are not safe.

Integration notes:
- New tools that touch files MUST route through the executor's
  ``_lineage_file_hook`` (it is centralized in ``call()`` between
  execution and result ingestion, next to ``_memory_firewall_hook``);
  a file-touching tool added without hook coverage silently leaves
  the lineage graph — review checklists should name the hook.
- Detection is taint-marking, not auto-denial: a deployment that
  wants containment can subscribe to ``infection_suspected`` /
  ``lineage_stamp_forged`` and drive the S2 bus quarantine
  (``bus.quarantine(agent)``) — deliberately NOT automatic, so a
  detection false positive cannot halt the whole workflow.
- Filename-encoded exfiltration (payload in the path, not the bytes)
  is invisible to the content-hash watch — the same ceiling as any
  content monitor; paths ARE recorded on ``lineage_file_write``
  events, so the forensic trail exists.
- Sub-64-byte payload shards evade the replication watch floor (a
  false-positive tradeoff); per-hop taint still propagates through
  the infected stamp bit.

What this does NOT do (residuals, stated not claimed away):
- Without a message bus, containment is taint-marking + operator action,
  not automatic execution denial. The tracker marks lineages infected;
  the S2 bus quarantine (when a bus is installed) is the execution-denial
  layer. Auto-denying infected agents at the tracker level would turn a
  detection false positive into a total workflow halt.
- Semantic paraphrase ladders (payload reworded per hop below any hash
  match) are invisible to content-hash correlation — same ceiling as the
  bus infection monitor.
- Writes that bypass governed tools entirely (raw host syscalls by an
  agent with ungoverned FS access) bypass stamping — the same boundary
  as the whole executor: ungoverned host access is outside the model.
- Env-var / argument channels between parent and child carry no content
  visibility, but they do NOT evade lineage: taint is hereditary at
  birth, so an infected parent's child is born infected.

$0 spend, synthetic/local only. No credentials, no network.
"""

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

# Replication watch: distinct agent lineages that must touch the same
# content hash before the population-level alarm fires. Mirrors the bus
# infection monitor's >= 3 distinct senders threshold.
_REPLICATION_MIN_AGENTS = 3
# Minimum content bytes correlated by the watch. Tiny strings ("ok",
# "done") recur across agents benignly; the watch is for payloads.
_REPLICATION_MIN_BYTES = 64

_REGISTRY_NAME = "registry.jsonl"
_KEY_NAME = ".key"
_STAMP_SUFFIX = ".lineage.json"
_STAMP_VERSION = 1


class LineageError(Exception):
    """Fail-closed lineage refusal: unlineaged execution, unregistered
    parent spawn, broken registry chain, or forged stamp."""


def _sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


class LineageTracker(object):
    """Per-run infection-lineage substrate. Constructed by the
    deployment (operator trust domain) and shared across a spawn
    lineage by reference — the executor takes it as the
    ``lineage_tracker=`` kwarg (None = pre-wave-90 behavior, zero
    behavior change).

    ``run_dir`` roots the registry (``run_dir/lineage/``); ``log`` is
    the run's chained ActionLog. All state-relevant transitions append
    chained audit events carrying lineage ids and hashes, never raw
    file content.
    """

    def __init__(self, run_dir, log):
        self._run_dir = Path(run_dir)
        self._log = log
        self._dir = self._run_dir / "lineage"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._registry_path = self._dir / _REGISTRY_NAME
        self._key = self._load_or_create_key()
        self._records = []          # ordered registry records (dicts)
        self._by_agent = {}         # agent_id -> latest BIRTH record
        self._tainted = {}          # agent_id -> infected_reason (taint
                                    # updates are append-only records)
        self._content_agents = {}   # content_sha256 -> [agent_ids...]
        self._fired_content = set()   # content hashes already escalated
        self._stripped = set()        # real paths whose stamp was
                                      # deliberately deleted (sidecar
                                      # removed but file kept)
        self._stamped = set()         # real paths with a live stamp
                                      # (reserved-namespace
                                      # disambiguation for deletes)
        self._load_registry()
        self._replay_file_state()

    # -- run key (stamp HMAC) ------------------------------------------

    def _load_or_create_key(self):
        from .keyfiles import require_private_key_file
        key_path = self._dir / _KEY_NAME
        if key_path.is_file() or key_path.is_symlink():
            # Wave-91 (G1): uniform fail-closed permission posture. An
            # existing key file with group/world bits — or a symlink,
            # or a non-regular path — is refused outright, never
            # silently loaded. The check runs BEFORE any key bytes are
            # read. Migration note: .key files created by this
            # tracker are 0600; only hand-placed files can trip this.
            require_private_key_file(key_path)
            key = key_path.read_bytes()
            if len(key) >= 16:
                return key
            # Degenerate key file: rotate rather than run weak.
        key = os.urandom(32)
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                     0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return key

    # -- registry -------------------------------------------------------

    def _record_hash(self, record):
        body = {k: v for k, v in record.items() if k != "record_hash"}
        return _sha256_hex(_canonical(body))

    def _load_registry(self):
        if not self._registry_path.is_file():
            return
        prev = "GENESIS"
        for line in self._registry_path.read_text(
                encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("prev") != prev:
                raise LineageError(
                    "lineage registry chain broken at seq %r: refusing "
                    "to run on an unverifiable lineage (fail closed)"
                    % (rec.get("seq"),))
            if rec.get("record_hash") != self._record_hash(rec):
                raise LineageError(
                    "lineage registry record tampered at seq %r (fail "
                    "closed)" % (rec.get("seq"),))
            prev = rec["record_hash"]
            self._records.append(rec)
            kind = rec.get("kind", "birth")
            if kind == "birth":
                self._by_agent[rec["agent_id"]] = rec
                if rec.get("infected"):
                    self._tainted[rec["agent_id"]] = rec.get(
                        "infected_reason")
            elif kind == "taint" and rec.get("infected"):
                self._tainted[rec["agent_id"]] = rec.get("infected_reason")

    def _append_record(self, record):
        record["seq"] = len(self._records)
        record["prev"] = (self._records[-1]["record_hash"]
                          if self._records else "GENESIS")
        record["record_hash"] = self._record_hash(record)
        with self._registry_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        self._records.append(record)
        # Only birth records index by agent: taint updates must never
        # shadow the birth record (verify() walks parent links, which
        # live on the birth record).
        if record.get("kind", "birth") == "birth":
            self._by_agent[record["agent_id"]] = record
        return record

    def _replay_file_state(self):
        """Rebuild the stripped-stamp set and the live-stamp set across
        restarts from the chained audit log (detection metadata:
        fail-open to empty on any trouble — enforcement never depends
        on it).

        Order-exact: events replay in append order, so a strip
        followed by a governed rewrite (which discards the record)
        does not resurrect a stale strip — and a file delete clears
        it, mirroring note_delete/stamp_write. The live-stamp set
        lets a post-restart sidecar delete be told apart from a
        legitimate user file ending in ".lineage.json"."""
        try:
            from .log import read_entries
            events = read_entries(self._run_dir / "actions.jsonl")
        except Exception:  # noqa: BLE001 - fail open, loud-ish below
            return
        for e in events:
            name = e.get("event")
            if name == "lineage_file_delete":
                base = e.get("stripped_stamp_for")
                if base:
                    self._stripped.add(base)
                    self._stamped.discard(base)
                elif e.get("path"):
                    self._stripped.discard(e["path"])
                    self._stamped.discard(e["path"])
            elif name == "lineage_file_write" and e.get("path"):
                self._stripped.discard(e["path"])
                self._stamped.add(e["path"])

    # -- birth certificates ---------------------------------------------

    def genesis(self, agent_id, role="", principal=""):
        """Mint the run's root lineage record (deployment act). Exactly
        one genesis per run: a second genesis for a DIFFERENT agent is
        refused — every agent must trace to one root. Idempotent for the
        same agent."""
        existing = [r for r in self._records if r.get("parent") is None]
        if existing:
            if existing[0]["agent_id"] != agent_id:
                raise LineageError(
                    "lineage genesis already minted for %r: refusing a "
                    "second root (every agent must trace to one root)"
                    % (existing[0]["agent_id"],))
            return existing[0]
        lineage_id = "lin_" + _sha256_hex(
            ("genesis|" + self._run_dir.name + "|" + agent_id).encode(
                "utf-8"))[:16]
        rec = self._append_record({
            "kind": "birth",
            "agent_id": agent_id,
            "parent": None,
            "lineage_id": lineage_id,
            "depth": 0,
            "role": role,
            "principal": principal,
            "infected": False,
            "infected_reason": None,
            "parent_token_ref": None,
            "child_token_ref": None,
            "issued_at": _utcnow_iso(),
        })
        self._log.append({
            "event": "lineage_birth",
            "run_id": self._run_dir.name,
            "agent_id": agent_id,
            "decision": "genesis",
            "policy_id": "infection-lineage",
            "lineage_id": lineage_id,
            "depth": 0,
            "flag": "lineage_genesis",
            "reason": ("Lineage genesis minted for %r: the run's root "
                       "birth certificate." % agent_id),
        })
        return rec

    def birth(self, parent_agent_id, child_agent_id, parent_token_ref=None,
              child_token_ref=None, role="", principal=""):
        """Mint a child's birth certificate from a registered parent.
        Fail-closed: an unregistered parent cannot spawn a lineaged
        child. Taint is hereditary: a child of an infected parent is
        born infected (covers env-var/argument channels that carry no
        file contact)."""
        parent = self._by_agent.get(parent_agent_id)
        if parent is None:
            raise LineageError(
                "spawn refused: parent %r has no lineage record — "
                "unlineaged parents cannot mint children (fail closed)"
                % (parent_agent_id,))
        if child_agent_id in self._by_agent:
            raise LineageError(
                "spawn refused: agent id %r is already lineaged — "
                "agent ids are unique per run (fail closed)"
                % (child_agent_id,))
        lineage_id = "lin_" + _sha256_hex(
            (parent["lineage_id"] + "|" + child_agent_id + "|"
             + str(len(self._records))).encode("utf-8"))[:16]
        infected = self.is_infected(parent_agent_id)
        rec = self._append_record({
            "kind": "birth",
            "agent_id": child_agent_id,
            "parent": parent_agent_id,
            "lineage_id": lineage_id,
            "depth": parent["depth"] + 1,
            "role": role,
            "principal": principal,
            "infected": infected,
            "infected_reason": ("hereditary: parent %r infected (%s)"
                                % (parent_agent_id,
                                   self._tainted.get(parent_agent_id,
                                                     "birth taint"))
                                if infected else None),
            "parent_token_ref": parent_token_ref,
            "child_token_ref": child_token_ref,
            "issued_at": _utcnow_iso(),
        })
        self._log.append({
            "event": "lineage_birth",
            "run_id": self._run_dir.name,
            "agent_id": parent_agent_id,
            "decision": "spawned",
            "policy_id": "infection-lineage",
            "sub_agent_id": child_agent_id,
            "lineage_id": lineage_id,
            "parent_lineage_id": parent["lineage_id"],
            "depth": parent["depth"] + 1,
            "infected_at_birth": infected,
            "flag": "lineage_birth",
            "reason": ("Birth certificate minted for %r from parent %r "
                       "(lineage %s)%s." % (
                           child_agent_id, parent_agent_id, lineage_id,
                           " — born infected (hereditary taint)"
                           if infected else "")),
        })
        return rec

    def certificate(self, agent_id):
        """Return the agent's birth certificate (the record the child
        carries), with the CURRENT taint state merged in. Raises
        LineageError when unlineaged."""
        rec = self._by_agent.get(agent_id)
        if rec is None:
            raise LineageError(
                "no lineage record for %r" % (agent_id,))
        cert = dict(rec)
        cert["infected"] = self.is_infected(agent_id)
        if cert["infected"]:
            cert["infected_reason"] = self._tainted.get(
                agent_id, rec.get("infected_reason"))
        return cert

    def is_registered(self, agent_id):
        return agent_id in self._by_agent

    def verify(self, agent_id):
        """True iff the agent's parent chain resolves to the run's
        genesis. Ordering is by registry seq (never wall-clock), so
        clock skew cannot reorder or break a chain."""
        seen = set()
        cur = self._by_agent.get(agent_id)
        while cur is not None:
            if cur["agent_id"] in seen:
                return False  # cycle: not a valid lineage
            seen.add(cur["agent_id"])
            if cur.get("parent") is None:
                return True  # reached genesis
            cur = self._by_agent.get(cur["parent"])
        return False

    def lineage_id(self, agent_id):
        rec = self._by_agent.get(agent_id)
        return rec["lineage_id"] if rec else None

    # -- taint ------------------------------------------------------------

    def is_infected(self, agent_id):
        rec = self._by_agent.get(agent_id)
        return bool((rec and rec.get("infected"))
                    or agent_id in self._tainted)

    def mark_infected(self, agent_id, reason):
        """Taint-mark a lineage (detection outcome). Hereditary going
        forward: future children are born infected. The taint is an
        append-only registry record, so it survives tracker reloads
        (executor restarts). Loud and chained."""
        rec = self._by_agent.get(agent_id)
        if rec is None:
            raise LineageError(
                "cannot mark %r infected: no lineage record" % (agent_id,))
        if self.is_infected(agent_id):
            return rec
        self._tainted[agent_id] = reason
        self._append_record({
            "kind": "taint",
            "agent_id": agent_id,
            "lineage_id": rec["lineage_id"],
            "infected": True,
            "infected_reason": reason,
            "issued_at": _utcnow_iso(),
        })
        self._log.append({
            "event": "lineage_infected",
            "run_id": self._run_dir.name,
            "agent_id": agent_id,
            "decision": "tainted",
            "policy_id": "infection-lineage",
            "lineage_id": rec["lineage_id"],
            "flag": "lineage_infected",
            "reason": "Lineage %s (%r) taint-marked: %s" % (
                rec["lineage_id"], agent_id, reason),
        })
        return rec

    # -- file stamps (raw-channel interposition) ---------------------------

    def _stamp_path(self, real_path):
        return Path(str(real_path) + _STAMP_SUFFIX)

    def _sign_stamp(self, body):
        mac = hmac.new(self._key, _canonical(body), hashlib.sha256)
        return mac.hexdigest()

    def stamp_write(self, agent_id, real_path, content_sha256,
                    content_bytes):
        """Stamp an agent-driven file write. The sidecar carries the
        writer's lineage + taint bit + content hash, HMAC-signed with
        the run key. Chained event carries hashes, never content."""
        rec = self._by_agent.get(agent_id)
        if rec is None:
            raise LineageError(
                "cannot stamp write for unlineaged agent %r (fail "
                "closed)" % (agent_id,))
        body = {
            "v": _STAMP_VERSION,
            "writer": agent_id,
            "lineage_id": rec["lineage_id"],
            "depth": rec["depth"],
            "content_sha256": content_sha256,
            "content_bytes": content_bytes,
            "infected": self.is_infected(agent_id),
            "seq": len(self._records),
        }
        stamp = dict(body)
        stamp["hmac"] = self._sign_stamp(body)
        sp = self._stamp_path(real_path)
        try:
            sp.write_text(json.dumps(stamp, sort_keys=True),
                          encoding="utf-8")
        except OSError:
            # Stamping is detection metadata, not the write itself: a
            # stamp failure must not break the tool call, but it is
            # LOUD — an unstamped write is a lineage gap by definition.
            self._log.append({
                "event": "lineage_stamp_failed",
                "run_id": self._run_dir.name,
                "agent_id": agent_id,
                "decision": "stamp_failed",
                "policy_id": "infection-lineage",
                "flag": "lineage_stamp_failed",
                "reason": ("Write executed but the lineage stamp could "
                           "not be stored for %s; the file is "
                           "unstamped." % real_path),
            })
            return None
        # The stamp is live: remember the base path so a later delete
        # of the sidecar path can be told apart from a legitimate user
        # file that merely ends in ".lineage.json" (reserved-namespace
        # disambiguation — the strip rule only fires for sidecars we
        # actually created).
        self._stamped.add(str(real_path))
        self._log.append({
            "event": "lineage_file_write",
            "run_id": self._run_dir.name,
            "agent_id": agent_id,
            "decision": "stamped",
            "policy_id": "infection-lineage",
            "path": str(real_path),
            "lineage_id": rec["lineage_id"],
            "content_sha256": content_sha256,
            "infected": self.is_infected(agent_id),
            "flag": "lineage_file_write",
            "reason": ("Agent-driven write lineage-stamped (writer %r, "
                       "lineage %s%s)." % (
                           agent_id, rec["lineage_id"],
                           ", INFECTED" if self.is_infected(agent_id) else "")),
        })
        # A fresh stamp supersedes any earlier strip record for the path.
        self._stripped.discard(str(real_path))
        return stamp

    def _read_stamp(self, real_path):
        sp = self._stamp_path(real_path)
        if not sp.is_file():
            return None, "absent"
        try:
            stamp = json.loads(sp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, "unparseable"
        body = {k: v for k, v in stamp.items() if k != "hmac"}
        if not isinstance(stamp.get("hmac"), str) or not hmac.compare_digest(
                stamp["hmac"], self._sign_stamp(body)):
            return None, "forged"
        if stamp.get("v") != _STAMP_VERSION:
            # A stamp from an unknown schema version cannot be
            # interpreted safely: treat it as hostile (loud + taint),
            # never as a clean contact.
            return None, "forged"
        return stamp, "ok"

    def note_read(self, agent_id, real_path, content_sha256=None,
                  content_bytes=0):
        """Record a file read against the stamp. Returns
        ``(status, stamp)`` where status is one of:

        - ``"contact"``: stamped read; ``lineage_contact`` chained.
        - ``"tainted"``: stamp said infected and the reader was clean —
          the reader is now taint-marked (propagation). Chained.
        - ``"forged"``: stamp failed HMAC, is unparseable, describes
          different bytes, or was deliberately stripped (sidecar
          deleted, file kept) — LOUD ``lineage_stamp_forged``; the
          content is treated as tainted.
        - ``"unstamped"``: pre-existing / foreign file, no stamp —
          informational only (reads must not fail closed on files the
          governance layer never wrote).
        """
        reader = self._by_agent.get(agent_id)
        if reader is None:
            raise LineageError(
                "cannot record read for unlineaged agent %r (fail "
                "closed)" % (agent_id,))
        stamp, status = self._read_stamp(real_path)
        if status == "absent":
            if str(real_path) in self._stripped:
                # Stamp-stripping: the file was stamped, then its
                # provenance was deliberately removed. Not a quiet
                # downgrade to 'pre-existing file' — LOUD + tainted.
                self._log.append({
                    "event": "lineage_stamp_forged",
                    "run_id": self._run_dir.name,
                    "agent_id": agent_id,
                    "decision": "flagged",
                    "policy_id": "infection-lineage",
                    "flag": "lineage_stamp_stripped",
                    "reason": ("Stamp for %s was deliberately removed "
                               "(sidecar deleted, file kept): treating "
                               "the content as tainted; the reader is "
                               "taint-marked." % real_path),
                })
                if not self.is_infected(agent_id):
                    self.mark_infected(
                        agent_id,
                        "read file whose lineage stamp was stripped "
                        "(%s)" % real_path)
                return "forged", None
            self._log.append({
                "event": "lineage_unstamped_read",
                "run_id": self._run_dir.name,
                "agent_id": agent_id,
                "decision": "allowed",
                "policy_id": "infection-lineage",
                "flag": "lineage_unstamped_read",
                "reason": ("Read of unstamped file %s: pre-existing or "
                           "foreign bytes; informational, not refused."
                           % real_path),
            })
            return "unstamped", None
        if status in ("forged", "unparseable"):
            self._log.append({
                "event": "lineage_stamp_forged",
                "run_id": self._run_dir.name,
                "agent_id": agent_id,
                "decision": "flagged",
                "policy_id": "infection-lineage",
                "flag": "lineage_stamp_forged",
                "reason": ("Stamp for %s failed verification (%s): "
                           "treating the content as tainted; the reader "
                           "is taint-marked." % (real_path, status)),
            })
            if not self.is_infected(agent_id):
                self.mark_infected(
                    agent_id,
                    "read file with %s lineage stamp (%s)"
                    % (status, real_path))
            return "forged", None
        # status == "ok": verify the stamp still describes THIS file.
        # A stamp copied onto different bytes (or bytes rewritten
        # around the stamp) is caught here even with a valid HMAC.
        if (content_sha256 is not None
                and stamp.get("content_sha256") != content_sha256):
            self._log.append({
                "event": "lineage_stamp_forged",
                "run_id": self._run_dir.name,
                "agent_id": agent_id,
                "decision": "flagged",
                "policy_id": "infection-lineage",
                "flag": "lineage_stamp_mismatch",
                "reason": ("Stamp for %s names content %s... but the "
                           "file now hashes %s...: stamp does not "
                           "describe these bytes; treating as tainted."
                           % (real_path,
                              str(stamp.get("content_sha256"))[:12],
                              str(content_sha256)[:12])),
            })
            if not self.is_infected(agent_id):
                self.mark_infected(
                    agent_id,
                    "read file whose bytes no longer match its lineage "
                    "stamp (%s)" % real_path)
            return "forged", stamp
        # Live writer taint: the stamp is a point-in-time claim, but a
        # writer taint-marked AFTER the write (e.g. by the replication
        # watch) still taints later readers. The stamp binds content to
        # a writer lineage; taint is evaluated live.
        writer_tainted = (bool(stamp.get("infected"))
                          or self.is_infected(stamp.get("writer")))
        self._log.append({
            "event": "lineage_contact",
            "run_id": self._run_dir.name,
            "agent_id": agent_id,
            "decision": "contact",
            "policy_id": "infection-lineage",
            "writer": stamp.get("writer"),
            "writer_lineage_id": stamp.get("lineage_id"),
            "content_sha256": stamp.get("content_sha256"),
            "stamp_infected": writer_tainted,
            "flag": "lineage_contact",
            "reason": ("File-mediated lineage contact: %r read bytes "
                       "written by %r (lineage %s%s)." % (
                           agent_id, stamp.get("writer"),
                           stamp.get("lineage_id"),
                           ", INFECTED" if writer_tainted else "")),
        })
        if writer_tainted and not self.is_infected(agent_id):
            self.mark_infected(
                agent_id,
                "read infected file written by %r (lineage %s)" % (
                    stamp.get("writer"), stamp.get("lineage_id")))
            return "tainted", stamp
        return "contact", stamp

    def note_message(self, agent_id, msg_id, stamp):
        """Record a governed-bus message read against the sender's
        lineage (GAP-2). ``stamp`` is the message's provenance stamp
        dict, as chained on the bus's ``agent_message`` send event.

        Returns ``(status, detail)`` where status is one of:

        - ``"contact"``: clean lineage contact; ``lineage_contact``
          (channel ``"bus"``) chained.
        - ``"tainted"``: the sender lineage was infected — at send time
          (the stamp's ``sender_infected`` bit) or live, evaluated now —
          and the reader was clean: the reader is now taint-marked
          (propagation). Chained.
        - ``"forged"``: the stamp carries no lineage fields, names an
          unregistered sender, or the claimed lineage id does not match
          the sender's live record — LOUD ``lineage_stamp_forged``
          (channel ``"bus"``); the content is treated as tainted and
          the reader is taint-marked. (The bus additionally verifies the
          stamp against the chained send record before calling here; a
          hand-written inbox file never reaches this method as clean.)

        Raises ``LineageError`` for an unlineaged *recipient* (fail
        closed), mirroring ``note_read``.
        """
        reader = self._by_agent.get(agent_id)
        if reader is None:
            raise LineageError(
                "cannot record bus message for unlineaged agent %r (fail "
                "closed)" % (agent_id,))
        sender = stamp.get("sender")
        claimed = stamp.get("sender_lineage_id")

        def _forged(reason):
            self._log.append({
                "event": "lineage_stamp_forged",
                "run_id": self._run_dir.name,
                "agent_id": agent_id,
                "decision": "flagged",
                "policy_id": "infection-lineage",
                "channel": "bus",
                "msg_id": msg_id,
                "flag": "lineage_stamp_forged",
                "reason": reason,
            })
            if not self.is_infected(agent_id):
                self.mark_infected(
                    agent_id,
                    "received bus message with forged lineage (%s)"
                    % msg_id)
            return "forged", reason

        if not claimed or not isinstance(claimed, str):
            return _forged(
                "bus message %r carries no sender lineage provenance"
                % (msg_id,))
        rec = self._by_agent.get(sender)
        if rec is None:
            return _forged(
                "bus message %r names unregistered sender %r"
                % (msg_id, sender))
        if rec["lineage_id"] != claimed:
            return _forged(
                "bus message %r claims lineage %s for sender %r; the "
                "live record is %s"
                % (msg_id, claimed, sender, rec["lineage_id"]))
        # Live sender taint: the stamp is a point-in-time claim, but a
        # sender taint-marked AFTER the send (e.g. by the replication
        # watch) still taints later readers. The stamp binds content to
        # a sender lineage; taint is evaluated live — the file-channel
        # "live writer taint" rule, applied to the bus.
        writer_tainted = (bool(stamp.get("sender_infected"))
                          or self.is_infected(sender))
        self._log.append({
            "event": "lineage_contact",
            "run_id": self._run_dir.name,
            "agent_id": agent_id,
            "decision": "contact",
            "policy_id": "infection-lineage",
            "channel": "bus",
            "msg_id": msg_id,
            "writer": sender,
            "writer_lineage_id": claimed,
            "writer_depth": stamp.get("sender_lineage_depth"),
            "content_sha256": stamp.get("content_sha256"),
            "stamp_infected": writer_tainted,
            "flag": "lineage_contact",
            "reason": ("Bus-mediated lineage contact: %r received message "
                       "%r from %r (lineage %s%s)." % (
                           agent_id, msg_id, sender, claimed,
                           ", INFECTED" if writer_tainted else "")),
        })
        if writer_tainted and not self.is_infected(agent_id):
            self.mark_infected(
                agent_id,
                "received bus message %r from infected lineage %s (%r)"
                % (msg_id, claimed, sender))
            return "tainted", "sender lineage infected"
        return "contact", "clean"

    def note_delete(self, agent_id, real_path):
        """Remove the sidecar when the file is deleted (stale stamps
        must not haunt recreated files). When the DELETED path is
        itself a sidecar (stamp-stripping: the file is kept, its
        provenance removed), the base path is remembered — a later
        read of the now-unstamped file fires ``lineage_stamp_stripped``
        and taints the reader, so stripping is not a quiet downgrade
        to 'pre-existing file'."""
        sp = self._stamp_path(real_path)
        try:
            if sp.is_file():
                sp.unlink()
        except OSError:
            pass
        path_s = str(real_path)
        stripped_for = None
        if path_s.endswith(_STAMP_SUFFIX):
            base = path_s[:-len(_STAMP_SUFFIX)]
            if base in self._stamped:
                # This was OUR sidecar for a live stamp: the file is
                # kept, its provenance removed — stamp-stripping.
                # Ensure it is gone (the tool deleted it; best-effort
                # idempotence for races) and remember the strip.
                try:
                    if Path(path_s).is_file():
                        Path(path_s).unlink()
                except OSError:
                    pass
                self._stamped.discard(base)
                stripped_for = base
                self._stripped.add(stripped_for)
            else:
                # A legitimate user file that merely ends in
                # ".lineage.json": treat it as a normal file delete —
                # remove ITS sidecar if one exists, record no strip.
                try:
                    if sp.is_file():
                        sp.unlink()
                except OSError:
                    pass
                self._stamped.discard(path_s)
        else:
            # The file itself is gone: a later recreation is genuinely
            # new, so any strip record for it is stale.
            self._stamped.discard(path_s)
            self._stripped.discard(path_s)
        self._log.append({
            "event": "lineage_file_delete",
            "run_id": self._run_dir.name,
            "agent_id": agent_id,
            "decision": "deleted",
            "policy_id": "infection-lineage",
            "path": path_s,
            "stripped_stamp_for": stripped_for,
            "flag": ("lineage_stamp_stripped" if stripped_for
                     else "lineage_file_delete"),
            "reason": ("Lineage stamp stripped from %s (file kept; "
                       "provenance removed)."
                       % stripped_for if stripped_for else
                       "File %s deleted; lineage stamp removed." % path_s),
        })

    # -- population-level replication watch (file channel) ------------------

    def observe_content(self, content_sha256, agent_id, content_bytes=0):
        """File-channel replication watch. The same content hash under
        >= ``_REPLICATION_MIN_AGENTS`` distinct agent lineages fires
        ``infection_suspected`` and taint-marks the origin lineage —
        the file-channel analogue of the bus infection monitor.
        Content is correlated by hash, so renames and copies do not
        evade it. Returns True when the alarm fired on this call."""
        if (not content_sha256
                or content_bytes < _REPLICATION_MIN_BYTES
                or content_sha256 in self._fired_content):
            return False
        agents = self._content_agents.setdefault(content_sha256, [])
        if agent_id not in agents:
            agents.append(agent_id)
            # Bound the watch's memory: a run that touches many large
            # distinct blobs must not grow this map without limit.
            if len(self._content_agents) > 4096:
                oldest = next(iter(self._content_agents))
                del self._content_agents[oldest]
        if len(agents) >= _REPLICATION_MIN_AGENTS:
            self._fired_content.add(content_sha256)
            origin = agents[0]
            self._log.append({
                "event": "infection_suspected",
                "run_id": self._run_dir.name,
                "agent_id": origin,
                "decision": "escalated",
                "policy_id": "infection-lineage",
                "flag": "infection_suspected",
                "reason": ("file-channel replication: identical content "
                           "(sha256 %s...) observed across %d distinct "
                           "agent lineages (%s); taint-marking origin "
                           "lineage" % (content_sha256[:12], len(agents),
                                        ",".join(sorted(agents)))),
                "content_sha256": content_sha256,
                "agents": sorted(agents),
            })
            if self.is_registered(origin):
                self.mark_infected(
                    origin,
                    "file-channel replication across %d lineages "
                    "(content %s...)" % (len(agents),
                                         content_sha256[:12]))
            return True
        return False
