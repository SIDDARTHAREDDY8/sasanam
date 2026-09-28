"""Wave-173 Lane 1: TMA-NM corroboration-gated memory elevation + act-time gate.

Implements the prospecting-R7 headline steal (arXiv:2606.24322, MIT):
memory-trust elevation that is *corroboration-gated* (M3) and an
*act-time* gate binding memory provenance to consequential actions
(M1), with append-only elevation-verdict records (M4).

The construction refuses the paraphrase-detection game: instead of
classifying content at act time, it classifies *provenance* --
write-time origin facts already chained by ``gov.memory_provenance`` --
and refuses to let un-elevated provenance drive a consequential action
without informed human authorization.

Provenance classes (``classify_read``):

  ``trusted``      the latest ledger entry was written by a
                   deployment-trusted principal (operator seed/release
                   or a trusted writer).
  ``elevated``     the fact's current bytes carry attestations from at
                   least two *distinct* trusted principals (M3 --
                   duplicate/Sybil attestations by the same principal
                   do not count).
  ``agent_clean``  agent-tiered, non-instruction-shaped, written in a
                   run with no tainted lineage and no shaped-ingestion
                   history before the write. The agent's own clean
                   notes: the gate does not fire.
  ``un_elevated``  everything else memory-derived: untrusted/unknown
                   tier, instruction-shaped, lineage-shaped, written in
                   a tainted run (externally-derived origin), written
                   after a shaped ingestion even when the 24h delivery
                   banner window has lapsed (M1 write-time origin --
                   origin does not expire), or bytes the ledger never
                   recorded.

The act-time gate (``ActGate``) is opt-in on the executor
(``ToolExecutor(memory_actgate=...)``). While attached it tracks every
governed memory read's provenance class per run. At queue time the
executor stamps the run's un-elevated reads into the approval record's
``policy_context`` (MAC-bound, WYSINWYS-rendered in the packet); at the
approved sweep the gate re-checks: any *currently* un-elevated read not
disclosed at queue time -- a read taken during the human-pending window
-- refuses the execution fail-closed (``memory_actgate_un_elevated``).
A disclosed-then-granted read is informed human authorization, so the
execution proceeds: the gate informs, the human decides.

M4: every attestation and every elevation verdict is an HMAC-chained
record in ``CorroborationStore`` (a per-deployment append-only JSONL
beside the memory ledger). Tamper raises
``LedgerUnverifiableError`` fail-closed via the inherited
``require_verified`` path.

Honest boundaries (from the prospectus verdict): the gate contains
single-source/parametric-memory risk *at act time*; it does not prevent
false facts from existing in memory. A human who grants with full
disclosure authorizes the action -- that is the design, not a bypass.
"""

import hashlib
import json
import os
import time

from .egress_ledger import (
    EgressLedger,
    LedgerUnverifiableError,
    _ledger_read_locked,
    _LedgerMissing,
)

#: Provenance classes, ordered least -> most authority.
PROVENANCE_TRUSTED = "trusted"
PROVENANCE_ELEVATED = "elevated"
PROVENANCE_AGENT_CLEAN = "agent_clean"
PROVENANCE_UN_ELEVATED = "un_elevated"

#: Corroboration quorum (TMA-NM M3): elevation requires attestations
#: from at least this many *distinct* trusted principals.
CORROBORATION_QUORUM = 2

#: Default corroboration-log filename, resolved as a sibling of the
#: memory ledger (same deployment, same lifetime, separate chain --
#: the entry ``kind`` is ``attestation`` so chains never mix).
DEFAULT_CORROBORATION_FILENAME = "corroboration_log.jsonl"


class AttestationError(ValueError):
    """An attestation was refused: untrusted attestor, digest mismatch,
    or self-corroboration. Fail-closed at the corroboration seam."""


def _sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CorroborationStore(EgressLedger):
    """Append-only HMAC-chained JSONL of corroboration attestations.

    One store per deployment (NOT per run -- attestations must survive
    across sessions). Each record binds ``(principal, mem_key,
    content_sha256)`` to one attesting trusted principal. ``is_elevated``
    counts *distinct* trusted attestors on the fact's current digest;
    the quorum is :data:`CORROBORATION_QUORUM`.

    Inherits seq chaining, checkpoints, file locking, and fail-closed
    reads from :class:`EgressLedger`; the entry ``kind`` is
    ``attestation``.
    """

    def __init__(self, path, trusted_principals=()):
        super().__init__(path)
        self.trusted_principals = frozenset(trusted_principals or ())

    # -- reads (verify-first, fail-closed) ------------------------------

    def _scan(self, predicate):
        """All attestation entries matching ``predicate``, oldest first,
        under the shared lock with verify-first (fail-closed: a
        tampered corroboration log raises LedgerUnverifiableError --
        never reads as 'no attestations')."""
        if not self.path.exists():
            return []
        try:
            with _ledger_read_locked(self.path):
                self.require_verified()  # nested: reentrant under read hold
                out = []
                for line in self.path.read_text(
                        encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    if (isinstance(entry, dict)
                            and entry.get("kind") == "attestation"
                            and predicate(entry)):
                        out.append(entry)
                return out
        except _LedgerMissing:
            return []

    def attestations_for(self, principal, mem_key, content_sha256):
        """Every attestation bound to these exact bytes, oldest first."""
        return self._scan(
            lambda e: e.get("principal") == principal
            and e.get("mem_key") == mem_key
            and e.get("content_sha256") == content_sha256)

    def attestor_set(self, principal, mem_key, content_sha256):
        """Distinct *trusted* principals that attested these bytes.

        Attestations by principals outside the deployment's trusted set
        are ignored here (they were refused at ``attest`` time, but a
        record written before a principal's removal must not linger as
        authority)."""
        return {
            e.get("attesting_principal")
            for e in self.attestations_for(principal, mem_key,
                                           content_sha256)
            if e.get("attesting_principal") in self.trusted_principals
        }

    def is_elevated(self, principal, mem_key, content_sha256):
        """True when at least CORROBORATION_QUORUM distinct trusted
        principals attested these exact bytes (TMA-NM M3)."""
        return len(self.attestor_set(principal, mem_key,
                                     content_sha256)) >= CORROBORATION_QUORUM

    def verify_chain(self):
        """True when the corroboration chain authenticates; raises
        LedgerUnverifiableError on tamper (fail-closed)."""
        self.require_verified()
        return True

    # -- writes ----------------------------------------------------------

    def attest(self, principal, mem_key, content_sha256,
               attesting_principal, writer_agent_id=None, now=None):
        """Record one trusted attestation of these exact bytes.

        Refuses fail-closed (AttestationError): an attestor outside the
        trusted set, an attestor identical to the fact's writer
        (self-corroboration is not corroboration), or a blank
        attestor. Idempotent: re-attesting the same bytes by the same
        principal returns the existing record -- a duplicate never
        counts twice toward the quorum (Sybil resistance is structural:
        the quorum counts distinct principals, not records).

        ``writer_agent_id`` is the ledger entry's writer, resolved by
        the caller (``ActGate.attest``) from the memory ledger so the
        self-corroboration check binds the attested fact's actual
        origin. Returns the chained record.
        """
        if not attesting_principal or not isinstance(
                attesting_principal, str):
            raise AttestationError(
                "attest refused: attesting_principal must be a "
                "non-empty principal string")
        if attesting_principal not in self.trusted_principals:
            raise AttestationError(
                "attest refused: %r is not a trusted principal"
                % (attesting_principal,))
        if (writer_agent_id is not None
                and attesting_principal == writer_agent_id):
            raise AttestationError(
                "attest refused: self-corroboration -- %r wrote the "
                "fact and cannot corroborate it" % (attesting_principal,))
        for existing in self.attestations_for(principal, mem_key,
                                              content_sha256):
            if existing.get("attesting_principal") == attesting_principal:
                return existing  # idempotent: no double count
        return self.append({
            "kind": "attestation",
            "principal": principal,
            "mem_key": mem_key,
            "content_sha256": content_sha256,
            "attesting_principal": attesting_principal,
            "writer_agent_id": writer_agent_id,
            "ts": time.time() if now is None else now,
        })


class ActGate:
    """The TMA-NM act-time gate: provenance classification (M1),
    corroboration-gated elevation (M3), execution-boundary enforcement.

    Constructed by the deployment in the operator trust domain and
    passed to the executor as ``memory_actgate=``. Opt-in: the executor
    never consults the gate unless it is attached.

    ``trusted_principals`` is the deployment's trust root -- the human
    operators / reviewer identities whose writes are ``trusted`` and
    whose attestations count toward elevation. Empty means no principal
    is trusted (attestations are refused; trusted writes never occur).
    """

    def __init__(self, firewall, trusted_principals=(),
                 corroboration_path=None, store=None):
        self.firewall = firewall
        self.trusted_principals = frozenset(trusted_principals or ())
        if store is not None:
            self.store = store
        else:
            if corroboration_path is None:
                corroboration_path = str(
                    os.path.join(
                        os.path.dirname(str(firewall.ledger.path)),
                        DEFAULT_CORROBORATION_FILENAME))
            self.store = CorroborationStore(
                corroboration_path,
                trusted_principals=self.trusted_principals)
        # Run-scoped working set: un-elevated reads, each
        # {run_id, principal, mem_key, content_sha256,
        #  provenance_class, detail, ts}. Only un-elevated reads are
        # tracked -- they are the gate's decision surface.
        self._reads = []

    # -- M1: provenance classification -----------------------------------

    def classify_read(self, principal, mem_key, content):
        """Classify one governed memory read. Returns
        ``(provenance_class, detail)``; never raises for ledger tamper
        -- an unverifiable ledger classifies ``un_elevated`` with
        detail ``provenance_unverifiable`` (fail-closed toward the
        gate firing, never toward silent trust)."""
        digest = _sha256_hex(content)
        try:
            entry = self.firewall.ledger.latest_entry(principal, mem_key)
        except LedgerUnverifiableError:
            return PROVENANCE_UN_ELEVATED, "provenance_unverifiable"
        if entry is None or entry.get("content_sha256") != digest:
            # Bytes the ledger never recorded (planted outside the
            # governed write path, or silently modified after the
            # recorded write): no provenance to elevate.
            return PROVENANCE_UN_ELEVATED, "no_ledger_entry"
        writer = entry.get("writer_agent_id")
        reviewer = entry.get("reviewer")
        if (writer in self.trusted_principals
                or reviewer in self.trusted_principals):
            return PROVENANCE_TRUSTED, "trusted_writer"
        try:
            if self.store.is_elevated(principal, mem_key, digest):
                return PROVENANCE_ELEVATED, "corroborated_quorum"
        except LedgerUnverifiableError:
            return PROVENANCE_UN_ELEVATED, "provenance_unverifiable"
        tier = entry.get("trust_tier")
        if tier in ("untrusted", "unknown"):
            return PROVENANCE_UN_ELEVATED, "tier_%s" % tier
        if entry.get("instruction_shaped"):
            return PROVENANCE_UN_ELEVATED, "instruction_shaped"
        if entry.get("lineage_shaped_source"):
            return PROVENANCE_UN_ELEVATED, "lineage_shaped_source"
        if entry.get("tainted_run"):
            # M1 write-time origin binding: the fact was written in a
            # run that had ingested untrusted external content, so its
            # origin includes that content even when the bytes
            # themselves are descriptive paraphrase (the F154
            # paraphrase-poison residual -- undetectable by shaping
            # analysis, contained by origin).
            return PROVENANCE_UN_ELEVATED, "tainted_run_origin"
        try:
            write_ts = float(entry.get("ts") or 0)
        except (TypeError, ValueError):
            write_ts = 0
        try:
            if self.firewall.lineage_journal.ingested_before(
                    principal, write_ts):
                # The principal ingested instruction-shaped content
                # BEFORE this write -- the 24h delivery banner window
                # may have lapsed (the F154 lineage-window residual),
                # but origin does not expire at act time.
                return PROVENANCE_UN_ELEVATED, "pre_write_shaped_ingestion"
        except LedgerUnverifiableError:
            return PROVENANCE_UN_ELEVATED, "provenance_unverifiable"
        return PROVENANCE_AGENT_CLEAN, "agent_clean"

    # -- read tracking ----------------------------------------------------

    def note_read(self, run_id, principal, mem_key, content):
        """Classify one governed read and track it when un-elevated.
        Returns ``(provenance_class, detail)``. Deduped per
        (run_id, mem_key, digest): re-reading the same bytes does not
        grow the working set."""
        pclass, detail = self.classify_read(principal, mem_key, content)
        if pclass == PROVENANCE_UN_ELEVATED:
            digest = _sha256_hex(content)
            if not any(r["run_id"] == run_id
                       and r["mem_key"] == mem_key
                       and r["content_sha256"] == digest
                       for r in self._reads):
                self._reads.append({
                    "run_id": run_id,
                    "principal": principal,
                    "mem_key": mem_key,
                    "content_sha256": digest,
                    "provenance_class": pclass,
                    "detail": detail,
                    "ts": time.time(),
                })
        return pclass, detail

    def un_elevated_reads(self, run_id):
        """The run's current un-elevated reads (the gate's decision
        surface)."""
        return [dict(r) for r in self._reads if r["run_id"] == run_id]

    def summarize(self, run_id):
        """Queue-time disclosure snapshot: JSON-safe list of the run's
        un-elevated reads. Stamped into the approval record's
        policy_context (MAC-bound) and rendered in the WYSINWYS packet
        so the human's grant is informed."""
        return [
            {
                "principal": r["principal"],
                "mem_key": r["mem_key"],
                "content_sha256": r["content_sha256"],
                "provenance_class": r["provenance_class"],
                "detail": r["detail"],
            }
            for r in self._reads if r["run_id"] == run_id
        ]

    # -- M3: corroboration -------------------------------------------------

    def attest(self, principal, mem_key, content, attesting_principal,
               now=None):
        """Corroborate a memory fact: binds the attestation to the
        fact's CURRENT ledger bytes (digest mismatch with the latest
        ledger entry refuses -- a corroboration must name the bytes it
        blesses). Returns the chained attestation record (M4)."""
        digest = _sha256_hex(content)
        entry = self.firewall.ledger.latest_entry(principal, mem_key)
        if entry is None or entry.get("content_sha256") != digest:
            raise AttestationError(
                "attest refused: no ledger entry for the presented "
                "bytes (principal=%r mem_key=%r) -- corroboration "
                "binds exact bytes" % (principal, mem_key))
        return self.store.attest(
            principal, mem_key, digest, attesting_principal,
            writer_agent_id=(entry.get("writer_agent_id")
                             or entry.get("reviewer")),
            now=now)

    def is_elevated(self, principal, mem_key, content):
        """True when the fact's current bytes carry the corroboration
        quorum (M3)."""
        return self.store.is_elevated(principal, mem_key,
                                      _sha256_hex(content))

    # -- M1: execution-boundary enforcement --------------------------------

    def _still_un_elevated(self, read):
        """Re-verify one tracked read at sweep time. Elevation is
        monotonic (attestations are append-only; a trusted release only
        supersedes), so a read that was un-elevated when taken but is
        elevated now no longer belongs to the gate's decision surface.
        Returns True when the read is STILL un-elevated. Fail-closed:
        unverifiable ledgers keep the read in the suspect set."""
        try:
            entry = self.firewall.ledger.latest_entry(
                read["principal"], read["mem_key"])
        except LedgerUnverifiableError:
            return True
        if entry is None or (entry.get("content_sha256")
                             != read["content_sha256"]):
            return True  # bytes changed or vanished: still suspect
        if (entry.get("writer_agent_id") in self.trusted_principals
                or entry.get("reviewer") in self.trusted_principals):
            return False
        try:
            if self.store.is_elevated(read["principal"],
                                      read["mem_key"],
                                      read["content_sha256"]):
                return False
        except LedgerUnverifiableError:
            return True
        return True

    def check_execution(self, run_id, record):
        """Act-time gate for one approved record. Returns
        ``(ok, reason)``.

        Every *currently* un-elevated read of this run must have been
        disclosed in the record's queue-time ``policy_context``
        (same mem_key AND same content digest): a read taken during the
        human-pending window was never shown to the approver, so the
        execution refuses fail-closed. A disclosed-then-granted read is
        informed human authorization -- the execution proceeds.

        Records without a policy_context (executor-internal synthetic
        approvals, never agent-driven tool calls) carry no disclosure
        surface and skip the check.
        """
        policy_context = record.get("policy_context")
        if policy_context is None:
            return True, None
        disclosed = {
            (d.get("mem_key"), d.get("content_sha256"))
            for d in (policy_context.get("memory_provenance") or [])
            if isinstance(d, dict)
        }
        # Only reads that are STILL un-elevated at sweep time can
        # refuse: a fact corroborated (or trust-released) during the
        # pending window no longer carries the risk the gate guards.
        # Elevation is monotonic, so this re-verification can only
        # shrink the suspect set, never grow it past what was tracked.
        undisclosed = [
            r for r in self._reads
            if r["run_id"] == run_id
            and self._still_un_elevated(r)
            and (r["mem_key"], r["content_sha256"]) not in disclosed
        ]
        if undisclosed:
            names = ", ".join(
                "%s (%s)" % (r["mem_key"], r["detail"])
                for r in undisclosed)
            return False, (
                "un-elevated memory read(s) not disclosed at approval "
                "time: %s -- the approver never saw this provenance; "
                "re-approval required under the current memory state "
                "(memory act-time gate)" % names)
        return True, None
