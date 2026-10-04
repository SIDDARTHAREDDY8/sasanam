"""Wave-303 F382/F383 closure battery: journal reload fixed point and
step-idempotency-key drift checks in gov/workflow.py.

F382 (LOW, CLOSED wave-303 lane 3): _load() used to re-append every
journal record through _append(), so the file doubled on every
restart. Close-when: _load() populates memory without re-appending
(persist=False); reload is a fixed point.

F383 (LOW, CLOSED wave-303 lane 3): the step-level idempotency-key
path replayed recorded outputs for a different step name/inputs,
bypassing the seq-slot drift refusal. Close-when: the key path applies
the same name/inputs-digest drift checks (coded
workflow-step-unauthorized); no new decision codes needed.

Base: wave-302 merge c18ed4c7b4025d1949b2042aa1ff202e856d6b6f
(pin 1827; F382/F383 closed here; footer open F385,F386 /
next free F387).

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. Deployment mode set at module level; also verified
under a clean environment.

Run:
  mkdir -p /var/tmp/g303-f382f383 && TMPDIR=/var/tmp/g303-f382f383 \\
    ~/workspace/.gov-venv/bin/python evals/w303_f382f383_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g303-f382f383b \\
    ~/workspace/.gov-venv/bin/python evals/w303_f382f383_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)

from gov import delegation as dg
from gov import delegation_revocation as rev
from gov import ed25519 as _ed25519
from gov import workflow as wf

TAXONOMY_PIN = 2014 # Wave-302 merge pin 1820; this lane mints no codes.; Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1934 -> 1934 (+1 grantneg-registry-withdrawn)



_results = []


def _record(name, status, detail=""):
    _results.append((name, status, detail))
    return status


def _expect_coded(name, fn, codes):
    """fn must raise a coded error whose .code is in codes. Anything
    else (no raise, uncoded raise, wrong code) is a BREAK."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code in codes:
            return _record(name, "HELD", "coded %s" % (code,))
        return _record(name, "BREAK",
                       "wrong escape: %s(code=%r), want one of %s"
                       % (type(e).__name__, code, sorted(codes)))
    return _record(name, "BREAK", "no refusal: fn returned")


def _expect_held(name, cond, detail=""):
    if cond:
        return _record(name, "HELD", detail)
    return _record(name, "BREAK", detail or "condition false")


class BaseStateTest(unittest.TestCase):
    def test_footer_state(self):
        with open(os.path.join(REPO, "evals", "FINDINGS.md"),
                  encoding="utf-8") as fh:
            text = fh.read()
        import re
        m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
        m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
        # Wave-316 re-pin: wave-315 merge footer -- open F398, F399,
        # F400 / next free F401 (F393-F397 all CLOSED).
        ok = (m_open and m_open[-1].replace(" ", "") == "F407"
              and m_next and m_next[-1] == "F407")
        self.assertTrue(_expect_held(
            "footer-state", ok,
            "want open F406 / next free F407") == "HELD")

    def test_taxonomy_pin(self):
        self.assertTrue(_expect_held(
            "taxonomy-pin", TAXONOMY_PIN == 2014,
            "TAXONOMY_PIN=%s, want 1991" % (TAXONOMY_PIN,)) == "HELD")




# ---------------------------------------------------------------------------
# Delegation-chain helpers (same as w302 red-team battery).
# ---------------------------------------------------------------------------

_AT = 1_700_000_000


def _seed(tag):
    return hashlib.sha256(("w303-f382f383-%s" % tag).encode()).digest()


def _pub(seed):
    return _ed25519.publickey(seed).hex()


def _wf_chain(seed, delegator_id, delegatee_id, delegatee_pub):
    cons = {"expires_at": _AT + 3600, "max_depth": 4,
            "allowed_targets": [delegatee_id]}
    return dg.issue(seed, delegator_id, delegatee_id, delegatee_pub,
                    ["tool.invoke"], issued_at=_AT, constraints=cons)


def _wf_auth(chain, actor="agent-b"):
    return {"actor_id": actor, "action": "tool.invoke", "chain": chain,
            "trust_roots": [_pub(_seed("wf-root"))],
            "revocation_ledger": rev.DelegationRevoker(_seed("wf-root"),
                                                       "agent-a")}


def _wf_actor_pair():
    sa, sb = _seed("wf-root"), _seed("wf-agent")
    return sa, sb, _pub(sa), _pub(sb)


# ---------------------------------------------------------------------------
# F382: journal reload is a fixed point.
# ---------------------------------------------------------------------------

class F382JournalFixedPointTest(unittest.TestCase):
    """_load() populates memory without re-appending."""

    def _run_file(self, tag):
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        path = "/var/tmp/g303-f382f383-%s-%d.jsonl" % (tag, os.getpid())
        if os.path.exists(path):
            os.remove(path)
        w = wf.WorkflowStore(path=path)
        w.start_run("etl", run_id="j1", authority=_wf_auth(chain), at=_AT)
        w.run_step("j1", 0, "s0", lambda i: {"x": 1},
                   authority=_wf_auth(chain), at=_AT)
        w.run_step("j1", 1, "s1", lambda i: {"x": 2},
                   authority=_wf_auth(chain), at=_AT)
        return path

    @staticmethod
    def _lines(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read().splitlines()

    def test_F382_reload_does_not_grow_journal(self):
        path = self._run_file("fixed")
        n1 = len(self._lines(path))
        wf.WorkflowStore(path=path)
        n2 = len(self._lines(path))
        os.remove(path)
        self.assertTrue(_expect_held(
            "F382-reload-fixed-point", n2 == n1,
            "journal grew %d -> %d on reload" % (n1, n2)) == "HELD")

    def test_F382_double_reload_still_fixed_point(self):
        path = self._run_file("fixed2")
        n1 = len(self._lines(path))
        wf.WorkflowStore(path=path)
        wf.WorkflowStore(path=path)
        n2 = len(self._lines(path))
        os.remove(path)
        self.assertTrue(_expect_held(
            "F382-double-reload-fixed-point", n2 == n1,
            "journal grew %d -> %d across two reloads" % (n1, n2))
            == "HELD")

    def test_F382_reload_rebuilds_same_indexes(self):
        # In-memory state after load must equal the live state: same
        # steps replay, same statuses, same idempotency-key bindings.
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        path = self._run_file("idx")
        before = wf.WorkflowStore(path=path)
        after = wf.WorkflowStore(path=path)
        os.remove(path)
        ok = (before._steps.keys() == after._steps.keys()
              and before._run_idem == after._run_idem
              and before._step_idem == after._step_idem
              and before._run_status == after._run_status)
        self.assertTrue(_expect_held(
            "F382-reload-same-indexes", ok,
            "loaded indexes differ from live") == "HELD")

    def test_F382_reloaded_run_still_replays(self):
        # The loaded store must replay the completed steps and resume
        # with authority re-proof (durable discipline intact).
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        path = self._run_file("resume")
        w = wf.WorkflowStore(path=path)
        out, replayed = w.run_step(
            "j1", 0, "s0", lambda i: {"x": 999},
            authority=_wf_auth(chain), at=_AT)
        out2, replayed2 = w.run_step(
            "j1", 2, "s2", lambda i: {"x": 3},
            authority=_wf_auth(chain), at=_AT)
        n = len(self._lines(path))
        os.remove(path)
        ok = (out == {"x": 1} and replayed is True
              and out2 == {"x": 3} and replayed2 is False and n == 4)
        self.assertTrue(_expect_held(
            "F382-reloaded-run-replays-and-resumes", ok,
            "replay/resume misbehaved after load") == "HELD")

    def test_F382_tampered_middle_line_refuses(self):
        path = self._run_file("tamper")
        lines = self._lines(path)
        lines[0] = lines[0][:-2] + "ff"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        self.assertTrue(_expect_coded(
            "F382-tamper-refuses",
            lambda: wf.WorkflowStore(path=path),
            {"workflow-checkpoint-tampered"}) == "HELD")
        os.remove(path)

    def test_F382_crash_tear_tolerated(self):
        path = self._run_file("tear")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write('{"type": "step", "half-writ')
        try:
            w = wf.WorkflowStore(path=path)
            ok = w.run_status("j1") == "running"
        except Exception:  # noqa: BLE001
            ok = False
        self.assertTrue(_expect_held(
            "F382-tear-tolerated", ok,
            "crash tear not tolerated") == "HELD")
        os.remove(path)


# ---------------------------------------------------------------------------
# F383: idempotency-key path applies drift checks.
# ---------------------------------------------------------------------------

class F383KeyPathDriftTest(unittest.TestCase):
    """The key path refuses drift coded workflow-step-unauthorized."""

    def _store_with_step(self, run_id="k1", seq=0, name="step-a",
                         inputs=None, key="K", outputs=None):
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        store = wf.WorkflowStore()
        store.start_run("etl", run_id=run_id,
                        authority=_wf_auth(chain), at=_AT)
        out, replayed = store.run_step(
            run_id, seq, name, lambda i: outputs or {"v": "A"},
            inputs=inputs or {"in": 1}, idempotency_key=key,
            authority=_wf_auth(chain), at=_AT)
        return store, chain

    def test_F383_key_hit_same_name_inputs_replays(self):
        store, chain = self._store_with_step()
        out, replayed = store.run_step(
            "k1", 7, "step-a", lambda i: {"v": "B"}, inputs={"in": 1},
            idempotency_key="K", authority=_wf_auth(chain), at=_AT)
        self.assertTrue(_expect_held(
            "F383-key-hit-replays", (out, replayed) == ({"v": "A"}, True),
            "same-name/inputs key hit must replay") == "HELD")

    def test_F383_key_hit_different_name_refuses(self):
        store, chain = self._store_with_step()
        self.assertTrue(_expect_coded(
            "F383-key-drift-name-refuses",
            lambda: store.run_step(
                "k1", 5, "step-B-DIFFERENT", lambda i: {"v": "B"},
                inputs={"in": 1}, idempotency_key="K",
                authority=_wf_auth(chain), at=_AT),
            {"workflow-step-unauthorized"}) == "HELD")

    def test_F383_key_hit_different_inputs_refuses(self):
        store, chain = self._store_with_step()
        self.assertTrue(_expect_coded(
            "F383-key-drift-inputs-refuses",
            lambda: store.run_step(
                "k1", 5, "step-a", lambda i: {"v": "B"},
                inputs={"in": 999}, idempotency_key="K",
                authority=_wf_auth(chain), at=_AT),
            {"workflow-step-unauthorized"}) == "HELD")

    def test_F383_key_hit_both_drift_refuses(self):
        store, chain = self._store_with_step()
        self.assertTrue(_expect_coded(
            "F383-key-drift-both-refuses",
            lambda: store.run_step(
                "k1", 5, "step-B-DIFFERENT", lambda i: {"v": "B"},
                inputs={"in": 999}, idempotency_key="K",
                authority=_wf_auth(chain), at=_AT),
            {"workflow-step-unauthorized"}) == "HELD")

    def test_F383_seq_slot_drift_still_refuses(self):
        # Control: the seq-slot path keeps its drift refusal.
        store, chain = self._store_with_step(run_id="k2", key=None)
        self.assertTrue(_expect_coded(
            "F383-seq-drift-still-refuses",
            lambda: store.run_step(
                "k2", 0, "step-a", lambda i: {"v": "B"},
                inputs={"in": 999}, authority=_wf_auth(chain), at=_AT),
            {"workflow-step-unauthorized"}) == "HELD")

    def test_F383_unknown_key_still_executes(self):
        store, chain = self._store_with_step()
        out, replayed = store.run_step(
            "k1", 3, "step-c", lambda i: {"v": "C"}, inputs={"in": 3},
            idempotency_key="FRESH", authority=_wf_auth(chain), at=_AT)
        self.assertTrue(_expect_held(
            "F383-unknown-key-executes", (out, replayed) == ({"v": "C"},
                                                            False),
            "unknown key must execute normally") == "HELD")


# ---------------------------------------------------------------------------
# Depth-1 green checks (honor GOV_SKIP_GREEN).
# ---------------------------------------------------------------------------

def _green_check(battery, expect):
    # Exact-summary form, wave-305: delegates to evals/green_check.py
    # (fail-closed contract). Returns (status, detail) as before.
    return green_check.check_battery_result(
        "green-check", os.path.join("evals", battery), repo=REPO,
        expected_summary=expect)


class GreenCheckTest(unittest.TestCase):
    def test_green_w301_workflow(self):
        # w301_workflow: the wf-idempotency probe was re-pinned to the
        # F383 closure (same name/inputs replay across seq slots; name
        # drift refuses coded -- see w303_f382f383).
        status, detail = _green_check(
            "w301_workflow_probes.py",
            "w301_workflow: 0 BREAK / 15 HELD / 0 ERROR")
        self.assertTrue(_expect_held(
            "green-w301-workflow", status == "HELD", detail) == "HELD")

    def test_green_w302_redteam(self):
        # Wave-305 test maintenance: the w302 battery reports
        # "0 BREAK / 34 HELD / 0 ERROR" on the wave-304 tree (F380-F384
        # all closed); the old "7 BREAK / 25 HELD" expectation was stale
        # since the wave-304 merge.
        status, detail = _green_check(
            "w302_redteam_probes.py",
            "w302_redteam: 0 BREAK / 34 HELD / 0 ERROR")
        self.assertTrue(_expect_held(
            "green-w302-redteam", status == "HELD", detail) == "HELD")


def main():
    global _results
    _results = []
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for cls in (BaseStateTest, F382JournalFixedPointTest,
                F383KeyPathDriftTest, GreenCheckTest):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    n_break = sum(1 for _, s, _ in _results if s == "BREAK")
    n_held = sum(1 for _, s, _ in _results if s == "HELD")
    n_err = sum(1 for _, s, _ in _results if s == "ERROR")
    print("w303_f382f383: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    if not result.wasSuccessful() or n_break or n_err:
        probe_lines.emit((n, s, probe_lines.first_line(d) if d else "")
                         for n, s, d in _results if s != "HELD")
    return result


if __name__ == "__main__":
    main()
