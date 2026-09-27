#!/usr/bin/env python3
"""Break-first probes for wave-141 row-13 automatic read observation.

Row-13 residual: ``note_read_output`` is explicit-only — a harness
that never reports a read leaves the tracker blind to bytes the
agent verifiably received through the governed tool boundary. This
battery pins the automatic seam: a successful governed ``read_file``
whose result is REAL sandbox bytes observes itself into the
installed ``RareTokenTracker`` on both the direct
``ToolExecutor.call`` path and the approved-execution path, with no
explicit harness call.

Honest ceilings (documented, not tested away):
- Only REAL reads are observed (``result["source"] == "sandbox"``).
  Synthetic content is never fed to the tracker — it must not learn
  tokens the agent never actually saw. Reads that return no content
  (refused/escaping) observe nothing.
- Direct filesystem access OUTSIDE the governed API stays invisible
  by construction (pinned EXPECTED, r5): the executor only sees
  what crosses its boundary. In-process agents with raw ``open()``
  are outside the threat model of this seam.
- The auto observation is best-effort: it never raises and never
  breaks the read (the read already succeeded). A tracker/ledger
  failure skips the observation silently; the harness's explicit
  ``note_read_output`` keeps its fail-closed ledger semantics.
- The auto path emits NO audit event (log-spam control, privacy by
  construction): token strings never enter the chain from this
  seam. The tracker's in-memory token sets and the taint ledger's
  opaque commitments are the only stores, as before.
- Idempotence with the explicit path holds when the source IDs
  match: the auto source ID is ``read:auto:<sandbox-relative-path>``;
  an explicit ``note_read_output`` with the same ID replaces the
  auto observation (no double count). Different IDs are different
  sources (r3 documents the contract; the harness owns the ID).

$0 spend, stdlib only, deterministic (no RNG; the tracker caps
tokens deterministically by order).
"""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import tempfile
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# The harness's declared ungoverned_ack is refused in production mode,
# so the battery provisions an explicit key through the same env
# backend production uses (wave-81: no dev key, no fallback).
import secrets  # noqa: E402
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "read-observation")

from gov import rare_token as rt  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402

_UNGOVERNED_ACK = "read-observation-probes-synthetic"
_PRINCIPAL = "user-1"
_AGENT = "coder-1"

# Rare-token-bearing document (same vocabulary as
# evals/rare_token_probes.py so the overlap bar is comparable).
DOC = ("Customer account review \u2014 Zephyrcorp Industries.\n"
       "Account reference ZX-88142, renewal code QX-22901.\n"
       "Primary contact: Marlowe Finch.\n"
       "Escalation: Brigadier Oswald Thornberry, Hartlepool office.\n"
       "Contract value 480000, renewal due Q3.")
# One rare token, for the log-privacy scan (lowercased: the doc
# capitalizes it).
RARE_PROBE = "zephyrcorp"
# Fluent paraphrase preserving the rare tokens (trips the K>=3 bar).
PARAPHRASE = ("Please process the renewal for Zephyrcorp Industries "
              "(account ZX-88142). Marlowe Finch confirmed renewal code "
              "QX-22901; contract value 480000.")


def _tmp():
    return os.environ.get("TMPDIR") or None


def _policy(run_dir, queue_reads):
    src = Path(REPO_ROOT) / "policies" / "default.yaml"
    text = src.read_text(encoding="utf-8")
    if queue_reads:
        text += ("\n  - id: battery-queue-all-reads\n"
                 "    description: Battery-only rule to queue every read_file.\n"
                 "    effect: require_approval\n"
                 "    match:\n"
                 "      tool: [read_file]\n"
                 "    reason: Battery drives the approved-execution path.\n")
    p = run_dir / "policy.yaml"
    p.write_text(text, encoding="utf-8")
    return PolicyEngine(str(p))


def _session(queue_reads=False):
    run_dir = Path(tempfile.mkdtemp(prefix="govreadobs-", dir=_tmp()))
    policy = _policy(run_dir, queue_reads)
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    tracker = rt.RareTokenTracker()
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      rare_token_tracker=tracker,
                      ungoverned_ack=_UNGOVERNED_ACK)
    (run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    (run_dir / "sandbox" / "doc.txt").write_text(DOC, encoding="utf-8")
    return {"run_dir": run_dir, "ex": ex, "tracker": tracker,
            "approvals": approvals}


def _identity(ex):
    return ex.mint_identity(_AGENT, "coder", _PRINCIPAL)


def _observed(tracker, agent=_AGENT):
    return len(tracker._docs.get(agent, {}))


def _main():
    results = []
    held = broke = expected = errors = 0

    def record(name, verdict, expect, ok):
        results.append((name, verdict, expect, ok))

    # --- r1: direct path — governed read auto-observes, no explicit call ---
    try:
        ctx = _session()
        ex, tracker = ctx["ex"], ctx["tracker"]
        ident = _identity(ex)
        r = ex.call(ident, "read_file", path="doc.txt")
        n = _observed(tracker)
        eg = tracker.check_egress(
            _AGENT, "send_email",
            {"to": "ops@synthetic.local", "body": PARAPHRASE},
            payload_text=PARAPHRASE)
        ok = (r.get("status") == "executed" and n == 1
              and eg["verdict"] == "require_approval")
        record("r1", "auto-direct observed=%d egress=%s" % (n, eg["verdict"]),
               "HELD", ok)
        held, broke = (held + 1, broke) if ok else (held, broke + 1)
    except Exception as e:  # noqa: BLE001
        record("r1", "ERROR %r" % e, "HELD", False)
        errors += 1

    # --- r2: approved path — approved read_file auto-observes ---
    try:
        ctx = _session(queue_reads=True)
        ex, tracker = ctx["ex"], ctx["tracker"]
        ident = _identity(ex)
        r = ex.call(ident, "read_file", path="doc.txt")
        queued = r.get("status") == "queued"
        aid = None
        for rec in ctx["approvals"].pending():
            if rec.get("tool") == "read_file":
                aid = rec.get("approval_id") or rec.get("id")
                break
        if aid is not None:
            ctx["approvals"].decide(aid, True, reason="battery",
                                    decided_by="human-operator")
            ex.execute_approved()
        n = _observed(tracker)
        ok = queued and aid is not None and n == 1
        record("r2", "auto-approved queued=%s observed=%d" % (queued, n),
               "HELD", ok)
        held, broke = (held + 1, broke) if ok else (held, broke + 1)
    except Exception as e:  # noqa: BLE001
        record("r2", "ERROR %r" % e, "HELD", False)
        errors += 1

    # --- r3: explicit + automatic with matching source ID = one observation ---
    try:
        ctx = _session()
        ex, tracker = ctx["ex"], ctx["tracker"]
        ident = _identity(ex)
        ex.call(ident, "read_file", path="doc.txt")
        n_auto = _observed(tracker)
        # The harness reports the same document with the auto source-ID
        # format (documented contract): replacement, not a second source.
        res = ex.note_read_output(_AGENT, "read:auto:doc.txt", DOC)
        n_both = _observed(tracker)
        ok = (n_auto == 1 and n_both == 1 and res.get("observed")
              and res.get("source_id") == "read:auto:doc.txt")
        record("r3", "auto=%d explicit+auto=%d" % (n_auto, n_both),
               "HELD", ok)
        held, broke = (held + 1, broke) if ok else (held, broke + 1)
    except Exception as e:  # noqa: BLE001
        record("r3", "ERROR %r" % e, "HELD", False)
        errors += 1

    # --- r4: synthetic content is never observed ---
    try:
        ctx = _session()
        ex, tracker = ctx["ex"], ctx["tracker"]
        ident = _identity(ex)
        r = ex.call(ident, "read_file", path="missing.txt")
        n = _observed(tracker)
        ok = n == 0
        record("r4", "missing-file read observed=%d (%s)"
               % (n, r.get("source", r.get("status"))), "HELD", ok)
        held, broke = (held + 1, broke) if ok else (held, broke + 1)
    except Exception as e:  # noqa: BLE001
        record("r4", "ERROR %r" % e, "HELD", False)
        errors += 1

    # --- r5: direct filesystem access outside the governed API: invisible ---
    # (pinned EXPECTED — the executor only sees what crosses its
    # boundary; raw open() by an in-process agent is outside this
    # seam's threat model).
    try:
        ctx = _session()
        tracker = ctx["tracker"]
        with open(ctx["run_dir"] / "sandbox" / "doc.txt",
                  encoding="utf-8") as fh:
            _ = fh.read()
        n = _observed(tracker)
        ok = n == 0
        record("r5", "raw-open observed=%d (invisible by construction)"
               % n, "EXPECTED", ok)
        expected, broke = (expected + 1, broke) if ok else (expected, broke + 1)
    except Exception as e:  # noqa: BLE001
        record("r5", "ERROR %r" % e, "EXPECTED", False)
        errors += 1

    # --- r6: privacy — no token strings enter the audit chain ---
    try:
        ctx = _session()
        ex = ctx["ex"]
        ident = _identity(ex)
        ex.call(ident, "read_file", path="doc.txt")
        events = [e for e in read_entries(
            ctx["run_dir"] / "actions.jsonl") if isinstance(e, dict)]
        blob = repr(events).lower()
        leaked = RARE_PROBE in blob
        auto_events = [e for e in events
                       if e.get("event") == "read_tokens_observed"]
        ok = (not leaked) and not auto_events
        record("r6", "token-in-chain=%s auto-audit-events=%d"
               % (leaked, len(auto_events)), "HELD", ok)
        held, broke = (held + 1, broke) if ok else (held, broke + 1)
    except Exception as e:  # noqa: BLE001
        record("r6", "ERROR %r" % e, "HELD", False)
        errors += 1

    # --- r7: deterministic ×2 ---
    try:
        verdicts = []
        for _ in range(2):
            ctx = _session()
            ex, tracker = ctx["ex"], ctx["tracker"]
            ident = _identity(ex)
            ex.call(ident, "read_file", path="doc.txt")
            eg = tracker.check_egress(
                _AGENT, "send_email",
                {"to": "ops@synthetic.local", "body": PARAPHRASE},
                payload_text=PARAPHRASE)
            verdicts.append((_observed(tracker), eg["verdict"]))
        ok = verdicts[0] == verdicts[1] == (1, "require_approval")
        record("r7", "runs=%r" % (verdicts,), "HELD", ok)
        held, broke = (held + 1, broke) if ok else (held, broke + 1)
    except Exception as e:  # noqa: BLE001
        record("r7", "ERROR %r" % e, "HELD", False)
        errors += 1

    print("probe  verdict                         expect")
    for name, verdict, expect, ok in results:
        if expect == "EXPECTED":
            tag = "EXPECTED" if ok else "BREAK"
        else:
            tag = "HELD" if ok else "BREAK"
        print("  %-4s %-31s %-10s %s" % (name, verdict, expect, tag))
    print("read_observation_probes: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, broke, expected, errors))
    return 0 if (broke == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(_main())
