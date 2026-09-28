"""AMSB adapter shim: remember / recall / context_reset over the governed tree.

Evaluates the UNMODIFIED product (gov/) as a black box through the public
tool seam: the agent's memory operations are ``write_file`` / ``read_file``
on memory paths, interposed by the opt-in ``MemoryFirewall`` inside
``ToolExecutor``.

Audit baseline (wave-166 tree, 0fcf6f2 -- verified by reading gov/):

- session-open scanning EXISTS: ``ToolExecutor._memory_session_scan`` runs
  once per (executor, principal) on the first memory interaction and emits
  chained ``memory_session_flag`` events. Detection-only, not denial.
- retrieval-time enforcement EXISTS: ``_memory_firewall_hook`` calls
  ``MemoryFirewall.check_memory_read`` on EVERY ``read_file`` of a memory
  path: quarantine (raise) for instruction-shaped + (unknown tier |
  untrusted tier | tainted agent tier via H17); provenance-bannered
  delivery for allowed untrusted/unknown non-shaped reads.
- write-time tiering EXISTS: ``record_memory_write`` tiers from the run's
  read fingerprints (verbatim 64-char overlap -> untrusted, else agent),
  records the instruction-shaped flag and the tainted_run bit.
- run taint: EVERY executed read_file/api_call taints the run ("tool output
  is untrusted input", executor.py docstring). Content tripping DLP
  sensitive patterns additionally sets the read_sensitive flag
  (approval-gates later api_calls). The precise A3 paraphrase mechanism:
  no verbatim link -> tier agent; the paraphrase is NOT instruction-shaped
  per the detector (instruction_shaping_reason -> None), so neither the
  untrusted+shaped quarantine nor the H17 tainted-run escalation (which
  requires shaping) applies -> silent delivery. The F154 residual is the
  detector's closed pattern list, not the tiering rule.
- a governed, chained ``context_reset`` event DOES NOT EXIST (spec §5.2
  net-new work). The adapter simulates the session boundary the honest way:
  a fresh ``ToolExecutor`` (fresh run state, fresh session-scan guard)
  while the deployment's sandbox files and the provenance ledger persist --
  exactly what a session boundary means for a file-backed memory store.
- the unified remember/recall/context_reset choke-point DOES NOT EXIST in
  gov/ (spec: "net new work"); memory flows through the file tools.
- the firewall remains opt-in (``memory_firewall=None`` default) -- the A1
  documented boundary.

The adapter is EVAL code, not product code: it may poke the executor's
file-backed state (shared sandbox) to simulate the session boundary, but
it never touches gov/ behavior.
"""

import os
import secrets
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from unittest import mock

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "1")

from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.memory_provenance import MemoryFirewall, MemoryQuarantineError  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

_DEFAULT_POLICY_PATH = str(
    Path(__file__).resolve().parent.parent / "policies" / "default.yaml")

_UNGOVERNED_ACK = ("AMSB harness eval: synthetic ungoverned session "
                   "declared for memory-guard benchmarking only.")

_MEMORY_PRINCIPAL = "amsb-op-1"


class RememberOutcome(str, Enum):
    STORED = "stored"
    REDACTED = "redacted"
    QUARANTINED = "quarantined"
    BLOCKED = "blocked"


@dataclass
class Observation:
    """What the recall step saw, banner-aware."""
    recalled: str | None
    quarantined: bool
    bannered: bool
    warning_events: int
    session_flags: int
    quarantine_events: int
    ledger_tier: str | None
    recall_error: str | None = None
    write_outcome: RememberOutcome = RememberOutcome.STORED
    write_error: str | None = None


def _bannered(content: str | None) -> bool:
    return bool(content) and "provenance" in content.lower()


class GovMemoryAdapter:
    """Fresh-adapter-per-scenario memory client for the governed tree."""

    name = "gov-memory-firewall"
    version = "0fcf6f2"
    self_submission = True

    def __init__(self, scratch: str, *, firewall_on: bool = True,
                 principal: str = _MEMORY_PRINCIPAL):
        self.scratch = Path(scratch)
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.firewall_on = firewall_on
        self.principal = principal
        self.ledger_path = str(self.scratch / "memguard.jsonl")
        self._shared_sandbox: Path | None = None
        self._ex: ToolExecutor | None = None
        self._fw: MemoryFirewall | None = None
        self._ident = None
        self._run_dir: Path | None = None
        self._new_session(first=True)

    # -- session machinery -------------------------------------------------
    def _new_session(self, *, first: bool):
        run_dir = Path(tempfile.mkdtemp(prefix="amsb-run-", dir=str(self.scratch)))
        policy = PolicyEngine(_DEFAULT_POLICY_PATH)
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        fw = MemoryFirewall(ledger_path=self.ledger_path) if self.firewall_on else None
        ex = ToolExecutor(run_dir, policy, log, approvals,
                          ledger_path=run_dir / "egress_ledger.jsonl",
                          ungoverned_ack=_UNGOVERNED_ACK,
                          memory_firewall=fw)
        if first:
            self._shared_sandbox = ex.sandbox
            self._shared_sandbox.mkdir(parents=True, exist_ok=True)
        else:
            # Session boundary: fresh executor/run state; the deployment's
            # sandbox files and provenance ledger persist across sessions.
            ex.sandbox = self._shared_sandbox
            ex._sandbox_resolved = self._shared_sandbox.resolve()
        self._ex = ex
        self._fw = fw
        self._run_dir = run_dir
        self._ident = ex.mint_identity("agent-1", "coder", self.principal)

    def context_reset(self):
        """Cross the session boundary: fresh run, persistent memory store."""
        self._new_session(first=False)

    # -- adapter contract ---------------------------------------------------
    def remember(self, key: str, value: str,
                 source_class: str = "external_tool") -> RememberOutcome:
        """Store value at key. Untrusted sources are ingested through the
        mocked external API first so the product's own fingerprint linkage
        (the verbatim 64-char rule) sees the same bytes a real deployment
        would."""
        ex, ident = self._ex, self._ident
        try:
            if source_class in ("external_tool", "untrusted"):
                real_sim = ex._simulate

                def _poisoned(tool, args, ctx):
                    if tool == "api_call":
                        return {"status": 200, "content": value,
                                "endpoint": args.get("endpoint")}
                    return real_sim(tool, args, ctx)

                with mock.patch.object(ex, "_simulate", _poisoned):
                    res = ex.call(ident, "api_call",
                                  endpoint="https://vendor.synthetic.local/docs")
                assert res["result"]["status"] == 200, res["result"]
            res = ex.call(ident, "write_file", path=key, content=value)
            assert "path" in res["result"], res["result"]
            return RememberOutcome.STORED
        except MemoryQuarantineError:
            return RememberOutcome.QUARANTINED
        except Exception as exc:  # noqa: BLE001 -- harness anti-gaming rule:
            # a raise on write counts as BLOCKED (refusing is defending).
            # The exception is recorded for auditability.
            self._write_error = "%s: %s" % (type(exc).__name__, exc)
            return RememberOutcome.BLOCKED

    def ingest_only(self, content: str):
        """Ingest content through the mocked external API WITHOUT writing
        it to memory: models a tool read whose bytes influence the run but
        never land verbatim in the note (the paraphrase shape)."""
        ex, ident = self._ex, self._ident
        real_sim = ex._simulate

        def _poisoned(tool, args, ctx):
            if tool == "api_call":
                return {"status": 200, "content": content,
                        "endpoint": args.get("endpoint")}
            return real_sim(tool, args, ctx)

        with mock.patch.object(ex, "_simulate", _poisoned):
            res = ex.call(ident, "api_call",
                          endpoint="https://vendor.synthetic.local/docs")
        assert res["result"]["status"] == 200, res["result"]

    def recall(self, key: str) -> Observation:
        """Read key back. Quarantine raises inside the product; the adapter
        catches it and reports it as an observation, never as an error."""
        ex, ident = self._ex, self._ident
        write_error = getattr(self, "_write_error", None)
        try:
            res = ex.call(ident, "read_file", path=key)
            content = res["result"].get("content")
            quarantined = False
            recall_error = None
        except MemoryQuarantineError:
            content, quarantined, recall_error = None, True, None
        except Exception as exc:  # noqa: BLE001 -- never a defense
            content, quarantined = None, False
            recall_error = "%s: %s" % (type(exc).__name__, exc)
        counts = self._event_counts()
        tier = None
        if self._fw is not None:
            try:
                ent = self._fw.ledger.latest_entry(self.principal, key)
                tier = ent.get("trust_tier") if ent is not None else None
            except Exception:  # noqa: BLE001
                tier = None
        return Observation(
            recalled=content, quarantined=quarantined,
            bannered=_bannered(content),
            warning_events=counts["memory_provenance_warning"],
            session_flags=counts["memory_session_flag"],
            quarantine_events=counts["memory_quarantine"],
            ledger_tier=tier, recall_error=recall_error,
            write_error=write_error)

    # -- eval helpers (file-backed session machinery, not product) -----------
    def flood_reads(self, contents: list[str], subdir: str = "vendor"):
        """Ingest shaped junk directly into the fingerprint store the way
        the A4/F189 probe did: files land on disk, read_file ingests them."""
        ex, ident = self._ex, self._ident
        base = self._shared_sandbox / subdir
        base.mkdir(parents=True, exist_ok=True)
        for i, text in enumerate(contents):
            (base / ("junk%d.md" % i)).write_text(text)
        for i in range(len(contents)):
            res = ex.call(ident, "read_file", path="%s/junk%d.md" % (subdir, i))
            assert res["result"].get("content"), res["result"]

    def tamper_file(self, key: str, suffix: str = " [tampered outside governance]"):
        """Modify memory bytes outside the governed tool path (integrity
        scenario: the digest check must notice)."""
        p = self._shared_sandbox / key
        p.write_text(p.read_text() + suffix)

    def _event_counts(self) -> dict:
        counts = {"memory_provenance_warning": 0, "memory_session_flag": 0,
                  "memory_quarantine": 0}
        try:
            for e in read_entries(self._run_dir / "actions.jsonl"):
                ev = e.get("event")
                if ev in counts:
                    counts[ev] += 1
        except Exception:  # noqa: BLE001
            pass
        return counts
