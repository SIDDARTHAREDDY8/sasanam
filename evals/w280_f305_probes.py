"""Wave-280 F305 closure battery: concurrent decide()/elicit_decision calls
must never double-decide one approval record.

Finding F305 (MEDIUM, renumbered from F303 at the wave-279 merge): the
decision path is check-then-act with no serialization between the status
check and the queue rewrite. Two synchronized declines produced TWO
``approval_decision`` events for one approval (deterministic 4/4 with a
write-gated interleaving, also reproduced ungated); a concurrent
accept+decline pair yielded nondeterministic terminal status (4x
approved / 3x rejected over 10 ungated trials). The race is pre-existing
in ``decide()``; the wave-278 elicitation lane inherits it.

The close-when: serialize decisions per approval record so one record
gets exactly one terminal ``approval_decision`` event under
concurrency; the loser observes the record as already-decided and is
refused instead of double-emitting.

Red-first: on the pristine wave-279 tree every concurrency probe here is
BREAK (two decision events / inconsistent terminal state); after the
per-record decision lock lands they are HELD.

Determinism: the adversarial interleaving is forced white-box (test
only) by gating ``ApprovalQueue._rewrite`` on a barrier so both threads
reach the write together -- a schedule the OS may produce on its own;
``gov/`` is untouched by the gating.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g280-f305 && TMPDIR=/var/tmp/g280-f305 \
    ~/workspace/.gov-venv/bin/python evals/w280_f305_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g280-f305b \
    ~/workspace/.gov-venv/bin/python evals/w280_f305_probes.py
"""

import json
import os
import re
import sys
import tempfile
import threading

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

_TMP = os.environ.get("TMPDIR") or "/var/tmp"
os.makedirs(_TMP, exist_ok=True)

from harness import make_run  # noqa: E402

TAXONOMY_PIN = 2070 # Wave-279 merge. No new codes for F305.; Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2070 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*). # Wave-333 lane 4: pin 2062 -> 2070 (+8 revocation-push-*).




def _held(name, note):
    return ("HELD", "%s: %s" % (name, note))


def _broken(name, detail):
    return ("BREAK", "%s: %s" % (name, detail))


def _error(name, detail):
    return ("ERROR", "%s: %s" % (name, detail))


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001 -- never let a probe crash the run
        return (pid, "ERROR", repr(exc)[:200], expected)
    ok = (verdict == expected)
    return (pid, verdict, note, "OK" if ok else "MISMATCH(expected %s)" % expected)


# ---------------------------------------------------------------------------
# Taxonomy pin (wave-260/269 lessons: raw source literals, every form).
# ---------------------------------------------------------------------------

def _pin_check():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK", "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    return "HELD", "taxonomy pin 1588: 1588 unique literals"


# ---------------------------------------------------------------------------
# Shared fixtures.
# ---------------------------------------------------------------------------

def _queue_one(run, agent_id="agent-1"):
    ident = run["executor"].mint_identity(agent_id, "support", agent_id)
    res = run["executor"].call(
        ident, "send_email", to="victim@synthetic.local",
        subject="hello", body="hello")
    assert res["status"] == "queued", res
    return res["approval_id"]


def _gated_queue(q, timeout=3):
    """Return orig_rewrite, gating _rewrite on a barrier.

    The gate makes both threads reach the write together -- the
    deterministic adversarial schedule. Barrier timeouts keep a fixed
    tree from hanging: on the fixed tree the loser's write never
    arrives, so the winner's gate times out and proceeds normally.
    """
    orig_rewrite = q._rewrite
    gate = threading.Barrier(2)

    def _gated(fn):
        try:
            gate.wait(timeout=timeout)
        except threading.BrokenBarrierError:
            pass
        return orig_rewrite(fn)

    q._rewrite = _gated
    return orig_rewrite


def _decision_events(run, aid):
    return [e for e in run["read_log"]()
            if e.get("event") == "approval_decision"
            and e.get("approval_id") == aid]


def _record_status(run, aid):
    for r in run["approvals"].all():
        if r["id"] == aid:
            return r["status"]
    return None


# ---------------------------------------------------------------------------
# F305 probes (all BREAK on the pristine wave-279 tree).
# ---------------------------------------------------------------------------

def f305_concurrent_elicit_decline_no_double():
    """Two concurrent decline elicitations must emit exactly one
    approval_decision event (F305 -- the red-team's deterministic
    reproducer, adapted)."""
    name = "f305-concurrent-elicit-decline-no-double"
    try:
        run = make_run()
        aid = _queue_one(run)
        q = run["approvals"]
        orig = _gated_queue(q)
        start = threading.Barrier(2)
        outcomes = []

        def _elicit():
            start.wait(timeout=10)
            try:
                q.elicit_decision(
                    aid, "decline",
                    rationale={"reason": "concurrent", "category": "other"})
                outcomes.append("decided")
            except ValueError:
                outcomes.append("refused")
            except Exception as exc:  # noqa: BLE001
                outcomes.append("error:%r" % (exc,))

        try:
            threads = [threading.Thread(target=_elicit) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)
        finally:
            q._rewrite = orig
        events = _decision_events(run, aid)
        if len(events) > 1:
            return _broken(
                name, "F305: %d approval_decision events for one approval "
                      "(outcomes=%r): concurrent elicitations double-decide"
                % (len(events), outcomes))
        if outcomes.count("decided") != 1 or outcomes.count("refused") != 1:
            return _broken(
                name, "F305: expected one winner + one refusal, got "
                      "outcomes=%r (events=%d)" % (outcomes, len(events)))
        return _held(name, "exactly one decision event; loser refused "
                           "(outcomes=%r)" % (outcomes,))
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def f305_concurrent_elicit_accept_decline_single_terminal():
    """Concurrent accept+decline elicitations: exactly one terminal
    decision event and a status consistent with it (F305)."""
    name = "f305-concurrent-elicit-accept-decline-single-terminal"
    try:
        run = make_run()
        aid = _queue_one(run)
        q = run["approvals"]
        orig = _gated_queue(q)
        start = threading.Barrier(2)
        outcomes = []

        def _elicit(response):
            start.wait(timeout=10)
            try:
                q.elicit_decision(
                    aid, response,
                    rationale={"reason": "concurrent", "category": "other"})
                outcomes.append(response + ":decided")
            except ValueError:
                outcomes.append(response + ":refused")
            except Exception as exc:  # noqa: BLE001
                outcomes.append(response + ":error:%r" % (exc,))

        try:
            threads = [threading.Thread(target=_elicit, args=(r,))
                       for r in ("accept", "decline")]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)
        finally:
            q._rewrite = orig
        events = _decision_events(run, aid)
        status = _record_status(run, aid)
        if len(events) != 1:
            return _broken(
                name, "F305: %d approval_decision events for one approval "
                      "(outcomes=%r, status=%r)" % (len(events), outcomes,
                                                   status))
        want = {"approved": "approved", "rejected": "rejected"}
        if status != want.get(events[0]["decision"], None):
            return _broken(
                name, "F305: terminal status %r inconsistent with decision "
                      "event %r (outcomes=%r)"
                      % (status, events[0]["decision"], outcomes))
        return _held(name, "one decision event, consistent status=%r "
                           "(outcomes=%r)" % (status, outcomes))
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def f305_concurrent_decide_direct_no_double():
    """Two concurrent decide() calls (the pre-existing race the
    elicitation lane inherits): exactly one approval_decision event."""
    name = "f305-concurrent-decide-direct-no-double"
    try:
        run = make_run()
        aid = _queue_one(run)
        q = run["approvals"]
        orig = _gated_queue(q)
        start = threading.Barrier(2)
        outcomes = []

        def _decide(approved):
            start.wait(timeout=10)
            try:
                q.decide(aid, approved, "concurrent race probe",
                         decided_by="human-operator")
                outcomes.append("approved" if approved else "rejected")
            except ValueError:
                outcomes.append("refused")
            except Exception as exc:  # noqa: BLE001
                outcomes.append("error:%r" % (exc,))

        try:
            threads = [threading.Thread(target=_decide, args=(a,))
                       for a in (True, False)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)
        finally:
            q._rewrite = orig
        events = _decision_events(run, aid)
        if len(events) != 1:
            return _broken(
                name, "F305: %d approval_decision events for one approval "
                      "(outcomes=%r)" % (len(events), outcomes))
        return _held(name, "one decision event (outcomes=%r)"
                           % (outcomes,))
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def f305_concurrent_cancel_vs_decide_consistent():
    """A cancel racing a decide must not leave the record and the audit
    trail inconsistent: at most one terminal disposition (a decision
    event XOR a cancel event) and a status consistent with it.

    On the pristine tree this is schedule-dependent per trial (the
    bad interleave needs decide's internal read to land before the
    cancel's rewrite), so the probe runs 8 gated trials and BREAKs if
    ANY trial is inconsistent -- overwhelmingly likely on base. On the
    fixed tree the per-record lock serializes the two paths, so every
    trial is consistent (deterministic HELD).
    """
    name = "f305-concurrent-cancel-vs-decide-consistent"
    try:
        bad = []
        for trial in range(8):
            run = make_run()
            aid = _queue_one(run, "agent-cancel-%d" % trial)
            q = run["approvals"]
            orig = _gated_queue(q)
            start = threading.Barrier(2)

            def _cancel():
                start.wait(timeout=10)
                try:
                    q.elicit_decision(aid, "cancel")
                except ValueError:
                    pass
                except Exception:  # noqa: BLE001
                    pass

            def _accept():
                start.wait(timeout=10)
                try:
                    q.elicit_decision(
                        aid, "accept",
                        rationale={"reason": "concurrent",
                                   "category": "other"})
                except ValueError:
                    pass
                except Exception:  # noqa: BLE001
                    pass

            try:
                threads = [threading.Thread(target=_cancel),
                           threading.Thread(target=_accept)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=60)
            finally:
                q._rewrite = orig
            log = run["read_log"]()
            decisions = [e for e in log
                         if e.get("event") == "approval_decision"
                         and e.get("approval_id") == aid]
            cancels = [e for e in log
                       if e.get("event") == "elicitation_cancelled"
                       and e.get("approval_id") == aid]
            status = _record_status(run, aid)
            if len(decisions) > 1:
                bad.append("trial %d: %d decision events" % (trial,
                                                             len(decisions)))
            elif decisions and cancels:
                bad.append("trial %d: decision AND cancel events "
                           "(status=%r)" % (trial, status))
            elif decisions and status not in ("approved", "rejected"):
                bad.append("trial %d: decision event but status=%r"
                           % (trial, status))
            elif cancels and not decisions and status != "cancelled":
                bad.append("trial %d: cancel event but status=%r"
                           % (trial, status))
        if bad:
            return _broken(name, "F305: %s" % "; ".join(bad[:3]))
        return _held(name, "8/8 trials consistent: exactly one terminal "
                           "disposition per record")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def f305_sequential_path_unchanged():
    """The sequential path is byte-for-byte the old behavior: decide
    works, a second decide is refused, elicitation still decides."""
    name = "f305-sequential-path-unchanged"
    try:
        run = make_run()
        aid = _queue_one(run)
        q = run["approvals"]
        rec, _entry = q.decide(aid, True, "sequential approve",
                               decided_by="human-operator")
        if rec["status"] != "approved":
            return _broken(name, "sequential decide broken: %r"
                           % (rec["status"],))
        try:
            q.decide(aid, False, "second decide",
                     decided_by="human-operator")
            return _broken(name, "second decide on decided record did not "
                                 "raise")
        except ValueError:
            pass
        aid2 = _queue_one(run)
        rec2, _e2 = q.elicit_decision(
            aid2, "decline",
            rationale={"reason": "sequential", "category": "other"})
        if rec2["status"] != "rejected":
            return _broken(name, "sequential elicitation broken: %r"
                           % (rec2["status"],))
        events = [e for e in run["read_log"]()
                  if e.get("event") == "approval_decision"
                  and e.get("approval_id") in (aid, aid2)]
        if len(events) != 2:
            return _broken(name, "sequential path emitted %d decision "
                                 "events, want 2" % len(events))
        return _held(name, "decide + refuse-second + elicitation all "
                           "behave as before")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def f305_decision_lock_registry_bounded():
    """The per-record lock registry must not grow: after decisions
    complete, no locks remain registered (F305 memory discipline)."""
    name = "f305-decision-lock-registry-bounded"
    try:
        run = make_run()
        q = run["approvals"]
        reg = getattr(q, "_decision_locks", None)
        if reg is None:
            return _broken(name, "F305: no _decision_locks registry on the "
                                 "queue")
        aids = [_queue_one(run, "agent-%d" % i) for i in range(5)]
        for i, aid in enumerate(aids):
            q.decide(aid, bool(i % 2), "bounded probe %d" % i,
                     decided_by="human-operator")
        guard = getattr(q, "_decision_locks_guard", None)
        if guard is None:
            return _broken(name, "F305: no _decision_locks_guard on the "
                                 "queue")
        with guard:
            remaining = len(q._decision_locks)
        if remaining != 0:
            return _broken(name, "F305: lock registry leaked %d entries "
                                 "after 5 decided records" % remaining)
        return _held(name, "registry empty after 5 terminal decisions")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


def f305_lock_released_on_refusal():
    """A refused decision (already decided) must not leak its lock
    entry either -- the registry stays empty across refusals."""
    name = "f305-lock-released-on-refusal"
    try:
        run = make_run()
        q = run["approvals"]
        aid = _queue_one(run)
        q.decide(aid, True, "first", decided_by="human-operator")
        for _ in range(3):
            try:
                q.decide(aid, False, "refused", decided_by="human-operator")
            except ValueError:
                pass
        guard = getattr(q, "_decision_locks_guard", None)
        reg = getattr(q, "_decision_locks", None)
        if guard is None or reg is None:
            return _broken(name, "F305: no decision-lock registry on the "
                                 "queue")
        with guard:
            remaining = len(reg)
        if remaining != 0:
            return _broken(name, "F305: registry holds %d entries after "
                                 "refused decisions" % remaining)
        return _held(name, "refused decisions leave no lock entries")
    except Exception as exc:  # noqa: BLE001
        return _error(name, repr(exc))


PROBES = [
    ("taxonomy-pin", "HELD", _pin_check),
    ("f305-concurrent-elicit-decline-no-double", "HELD",
     f305_concurrent_elicit_decline_no_double),
    ("f305-concurrent-elicit-accept-decline-single-terminal", "HELD",
     f305_concurrent_elicit_accept_decline_single_terminal),
    ("f305-concurrent-decide-direct-no-double", "HELD",
     f305_concurrent_decide_direct_no_double),
    ("f305-concurrent-cancel-vs-decide-consistent", "HELD",
     f305_concurrent_cancel_vs_decide_consistent),
    ("f305-sequential-path-unchanged", "HELD",
     f305_sequential_path_unchanged),
    ("f305-decision-lock-registry-bounded", "HELD",
     f305_decision_lock_registry_bounded),
    ("f305-lock-released-on-refusal", "HELD",
     f305_lock_released_on_refusal),
]


# ---------------------------------------------------------------------------
# Depth-1 green checks (wave-28 lesson: GOV_SKIP_GREEN honored).
# ---------------------------------------------------------------------------

def green_check():
    """Adjacent-battery green checks, depth-1.

    Runs the neighboring batteries' mains with GOV_SKIP_GREEN=1 so their
    own green checks do not recurse. Records skips, never spawns.
    """
    notes = []
    if SKIP_GREEN:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1: nested green check skipped")]
    import subprocess
    neighbors = [
        "evals/w278_approvalv2_probes.py",
        "evals/w279_remediation_probes.py",
        "evals/w279_triad_probes.py",
    ]
    for rel in neighbors:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            notes.append((rel, "SKIP", "battery absent"))
            continue
        tmpd = tempfile.mkdtemp(prefix="g280-green-", dir=_TMP)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600, cwd=REPO)
        except Exception as exc:  # noqa: BLE001
            notes.append((rel, "ERROR", repr(exc)[:120]))
            continue
        tail = (p.stdout or "").strip().splitlines()
        last = tail[-1] if tail else ""
        if _neighbor_green(last, p.returncode):
            notes.append((rel, "GREEN", last[:120]))
        else:
            notes.append((rel, "RED",
                          "%s rc=%d" % (last[:100], p.returncode)))
    return notes


def _neighbor_green(last, rc):
    if rc != 0:
        return False
    if "MISMATCH" in last:
        return False
    for pat in (r"(\d+)\s+BREAK", r"(\d+)\s+ERROR",
                r"mismatches:\s*(\d+)", r"(\d+)\s+MISMATCH"):
        m = re.search(pat, last)
        if m and int(m.group(1)) != 0:
            return False
    return True


def main():
    print("wave-280 F305 closure battery: %d probes" % len(PROBES))
    results = []
    for pid, expected, fn in PROBES:
        rid, verdict, note, status = _run(pid, expected, fn)
        results.append((rid, verdict, note, status))
        print("[%s] %s: %s" % (verdict, rid, note[:160]))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in green_check():
        print("[%s] %s: %s" % (verdict, name, note[:160]))
    held = sum(1 for r in results if r[1] == "HELD")
    broke = sum(1 for r in results if r[1] == "BREAK")
    errs = sum(1 for r in results if r[1] == "ERROR")
    mism = sum(1 for r in results if r[3].startswith("MISMATCH"))
    print("summary: %d HELD / %d BREAK / %d ERROR / %d MISMATCH"
          % (held, broke, errs, mism))
    out = os.path.join(_TMP, "w280_f305_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump([{"probe": r[0], "verdict": r[1], "note": r[2],
                    "status": r[3]} for r in results], f, indent=2)
    print("results: %s" % out)
    return 1 if mism or errs else 0


if __name__ == "__main__":
    sys.exit(main())
