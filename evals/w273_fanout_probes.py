"""Wave-273 fan-out loss-accounting battery (red-first).

Threat model: an evidence producer (or a backend outage) floods the
async anchor fan-out path. Today ``Anchorer`` hands jobs to an UNBOUNDED
``queue.Queue`` with no drop accounting: under flood the queue grows
without bound, and jobs that die (non-retryable failure, retry
exhaustion, close-time abandonment) leave only a stderr warning -- there
is no operator-visible loss counter.

Red phase (FANOUT_PHASE=red, run on the pre-fix base): attacks a01/a02
demonstrate the gap -> BREAK.
Green phase (default, run after the fix): attacks g01..g06 assert the
fix holds -> HELD. Deterministic (blocking backends, no wall-clock
assertions). Fresh /var/tmp/g273* TMPDIRs. No in-repo git subprocesses.
"""

import contextlib
import json
import os
import sys
import tempfile
import threading
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import harness  # noqa: E402
from gov import anchor_backend as ab_mod  # noqa: E402
from gov import anchorer as anchorer_mod  # noqa: E402
from gov import ed25519 as ed_mod  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov.log import ActionLog  # noqa: E402

RESULTS = []
SITUATIONS = {}

_KEY_ENV = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
            "GOV_DEPLOYMENT_MODE", "GOV_KEYRING_FILE")


def situation(sid, title, verdict, detail=""):
    SITUATIONS[sid] = {"title": title, "verdict": verdict,
                       "detail": detail}
    RESULTS.append((sid, verdict))


def _seed(n):
    return bytes([n & 0xFF]) * 32


def _anchor_key(n=7):
    seed = _seed(n)
    pub = ab_mod.anchor_pubkey(seed)
    return {"seed": seed, "key_id": ab_mod.anchor_key_id(pub),
            "pubkey_hex": pub.hex(), "dev": True}


@contextlib.contextmanager
def _dev_keys():
    import secrets as _secrets
    saved = {n: os.environ.get(n) for n in (
        "GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")}
    os.environ["GOV_LOG_KEY"] = _secrets.token_hex(32)
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    try:
        yield
    finally:
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v


class BlockingBackend(ab_mod.AnchorBackend):
    """submit() blocks on an event until released; then behaves per mode."""

    def __init__(self, mode="good"):
        self.mode = mode
        self._gate = threading.Event()
        self.submits = 0
        self._lock = threading.Lock()

    def release(self):
        self._gate.set()

    def submit(self, anchor_hash):
        with self._lock:
            self.submits += 1
        self._gate.wait(timeout=30)
        if self.mode == "down":
            raise ab_mod.WitnessDownError("witness down")
        if self.mode == "config-fail":
            raise ab_mod.RekorConfigError("bad backend config")
        return {"backend": "blocking-test", "uuid": "u-%d" % self.submits}

    def verify_receipt(self, receipt, *, anchor_hash):
        ok = isinstance(receipt, dict) and receipt.get("uuid") is not None
        return (ok, "" if ok else "bad receipt")


class Ctx:
    def __init__(self):
        self.dirs = []
        self.anchorers = []
        tmp = os.environ.get("TMPDIR") or "/tmp"
        self.root = Path(tempfile.mkdtemp(prefix="g273-fanout-",
                                          dir="/var/tmp"
                                          if os.path.isdir("/var/tmp")
                                          else tmp))
        self.dirs.append(self.root)

    def close(self):
        for a in self.anchorers:
            try:
                a.close(timeout=15)
            except Exception:
                pass
        self.anchorers = []
        import shutil
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def make_log(self, n=0):
        d = self.root / ("lg-%d" % len(self.dirs))
        d.mkdir(parents=True, exist_ok=True)
        self.dirs.append(d)
        lg = ActionLog(str(d / "actions.jsonl"))
        for i in range(1, n + 1):
            lg.append({"event": "tool_call", "n": i, "principal": "p",
                       "agent_id": "a"})
        return lg, d

    def make_anchorer(self, lg, backend, **kw):
        kw.setdefault("policy", anchorer_mod.AnchorPolicy(
            records_per_epoch=10 ** 9, seconds_per_epoch=None,
            anchor_on_close=False))
        kw.setdefault("anchor_key", _anchor_key())
        kw.setdefault("warn", lambda m: None)
        a = anchorer_mod.Anchorer(lg, backend, **kw)
        self.anchorers.append(a)
        return a

    def entries(self, d):
        p = d / "actions.jsonl"
        return [json.loads(l) for l in p.read_text(encoding="utf-8")
                .splitlines() if l.strip()]


# ----------------------------------------------------------------------
# Red phase: demonstrate the gap on the pre-fix implementation
# ----------------------------------------------------------------------

def red_a01_flood_has_no_backpressure():
    """Unbounded fan-out queue: a producer flood grows memory without
    limit and nothing refuses or counts it."""
    ctx = Ctx()
    try:
        with _dev_keys():
            lg, d = ctx.make_log(n=1)
            be = BlockingBackend(mode="good")  # worker blocks in submit
            a = ctx.make_anchorer(lg, be)
            n = 40
            for i in range(n):
                lg.append({"event": "tool_call", "n": 100 + i})
                r = a.maybe_anchor(force=True)
                assert r == "queued", r
            depth = a._queue.qsize()
            maxsize = getattr(a._queue, "maxsize", 0)
            # GAP: no bound at all (maxsize 0 == infinite) and the queue
            # absorbed the whole flood.
            if maxsize == 0 and depth >= n - 5:
                situation("a01", "flood has no backpressure: %d jobs "
                          "queued, maxsize=%r" % (depth, maxsize),
                          "BREAK")
            else:
                situation("a01", "queue unexpectedly bounded "
                          "(depth=%d maxsize=%r)" % (depth, maxsize),
                          "HELD")
            be.release()
    finally:
        ctx.close()


def red_a02_dead_jobs_have_no_loss_counter():
    """Jobs that die (non-retryable backend failure) leave only a stderr
    warning: no operator-visible drop/loss counter exists."""
    ctx = Ctx()
    try:
        with _dev_keys():
            lg, d = ctx.make_log(n=2)
            be = BlockingBackend(mode="config-fail")
            be.release()  # fail fast
            a = ctx.make_anchorer(lg, be)
            assert a.maybe_anchor(force=True) == "queued"
            a._queue.join()
            has_counter = hasattr(a, "fanout_stats") or hasattr(
                a, "_dropped") or hasattr(a, "_queue_lost")
            unanchored = [e for e in ctx.entries(d)
                          if e.get("event")
                          == anchorer_mod.ANCHOR_UNANCHORED_EVENT]
            # GAP: the job died and the ONLY operator-visible trace of
            # loss is a stderr warning; no counter distinguishes dead
            # jobs from completed ones.
            if not has_counter and unanchored:
                situation("a02", "dead anchor job leaves no loss "
                          "counter (only stderr warning)",
                          "BREAK")
            else:
                situation("a02", "loss counter exists", "HELD")
    finally:
        ctx.close()


def red_c01_happy_path():
    ctx = Ctx()
    try:
        with _dev_keys():
            lg, d = ctx.make_log(n=3)
            be = BlockingBackend(mode="good")
            be.release()
            a = ctx.make_anchorer(lg, be)
            assert a.maybe_anchor(force=True) == "queued"
            a._queue.join()
            receipts = [e for e in ctx.entries(d)
                        if e.get("event")
                        == anchorer_mod.ANCHOR_RECEIPT_EVENT]
            if receipts:
                situation("c01", "happy-path anchor still works", "HELD")
            else:
                situation("c01", "happy-path anchor broken", "BREAK")
    finally:
        ctx.close()


def red_c02_pin():
    import re
    src = (REPO_ROOT / "gov" / "decision_codes.py").read_text()
    codes = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    # Wave-316 re-pin: 1700 -> 1888 (wave-315 merge pin; +10 vsa-packet-*
    # codes). Expectation pin only -- taxonomy pin value itself is the
    # lane lead's job.
    if len(codes) == 1990 and len(set(codes)) == 1990:
        situation("c02", "pin 1990/1990/0", "HELD")
    else:
        situation("c02", "pin drift: %d/%d" % (len(codes),
                                               len(set(codes))), "BREAK")


def run_red():
    red_a01_flood_has_no_backpressure()
    red_a02_dead_jobs_have_no_loss_counter()
    red_c01_happy_path()
    red_c02_pin()
    green_check()


# ----------------------------------------------------------------------
# Green phase: the fix holds
# ----------------------------------------------------------------------

def green_g01_bounded_queue_counts_drops():
    from gov import evidence_fanout as fanout_mod
    ctx = Ctx()
    try:
        with _dev_keys():
            lg, d = ctx.make_log(n=1)
            be = BlockingBackend(mode="good")  # worker blocks in submit
            a = ctx.make_anchorer(lg, be, fanout_maxsize=8,
                                  fanout_policy="counted-drop")
            n = 50
            results = []
            for i in range(n):
                lg.append({"event": "tool_call", "n": 200 + i})
                results.append(a.maybe_anchor(force=True))
            st = a.fanout_stats()
            ok = (st["maxsize"] == 8 and st["depth"] <= 8
                  and st["accepted"] + st["dropped"] == n
                  and st["dropped"] > 0
                  and results.count("dropped") == st["dropped"])
            if ok:
                situation("g01", "bounded queue: depth<=8, %d dropped "
                          "counted" % st["dropped"], "HELD")
            else:
                situation("g01", "bad fanout stats: %r" % (st,),
                          "BREAK")
            be.release()
    finally:
        ctx.close()


def green_g02_dropped_jobs_are_recoverable():
    """A queue-full drop chains an unanchored record (reason fanout-full)
    so recover() requeues it: nothing is silently lost."""
    ctx = Ctx()
    try:
        with _dev_keys():
            lg, d = ctx.make_log(n=1)
            be = BlockingBackend(mode="good")
            a = ctx.make_anchorer(lg, be, fanout_maxsize=4,
                                  fanout_policy="counted-drop")
            for i in range(12):
                lg.append({"event": "tool_call", "n": 300 + i})
                a.maybe_anchor(force=True)
            st = a.fanout_stats()
            assert st["dropped"] > 0, st
            be.release()
            a._queue.join()
            # Dropped epochs have chained unanchored records:
            n_unanchored = len([e for e in ctx.entries(d)
                                if e.get("event")
                                == anchorer_mod.ANCHOR_UNANCHORED_EVENT])
            n_recovered = a.recover()
            a._queue.join()
            receipts = [e for e in ctx.entries(d)
                        if e.get("event")
                        == anchorer_mod.ANCHOR_RECEIPT_EVENT]
            ok = n_unanchored > 0 and n_recovered > 0 and len(
                receipts) == 12
            if ok:
                situation("g02", "dropped jobs recovered and anchored "
                          "(%d unanchored records, %d requeued, 12 "
                          "receipts)" % (n_unanchored, n_recovered),
                          "HELD")
            else:
                situation("g02", "recovery incomplete: unanchored=%d "
                          "requeued=%d receipts=%d"
                          % (n_unanchored, n_recovered, len(receipts)),
                          "BREAK")
    finally:
        ctx.close()


def green_g03_fail_closed_policy():
    from gov import evidence_fanout as fanout_mod
    q = fanout_mod.FanoutQueue(maxsize=2, policy="fail-closed")
    q.submit("a")
    q.submit("b")
    try:
        q.submit("c")
        situation("g03", "fail-closed queue accepted over maxsize",
                  "BREAK")
        return
    except fanout_mod.FanoutFullError:
        pass
    ctx = Ctx()
    try:
        with _dev_keys():
            lg, d = ctx.make_log(n=1)
            be = BlockingBackend(mode="good")
            a = ctx.make_anchorer(lg, be, fanout_maxsize=2,
                                  fanout_policy="fail-closed")
            # Worker pickup is asynchronous, so do not assume job 1 is
            # already in flight: fill until the first refusal. At the
            # refusal instant the queue is exactly full (maxsize); the
            # worker is blocked in submit so the depth cannot change
            # between the refusal and the stats read.
            accepted = 0
            for n in range(401, 420):
                lg.append({"event": "tool_call", "n": n})
                try:
                    r = a.maybe_anchor(force=True)
                except fanout_mod.FanoutFullError:
                    break
                assert r == "queued", r
                accepted += 1
            else:
                situation("g03", "fail-closed anchorer never refused",
                          "BREAK")
                return
            st = a.fanout_stats()
            if not (2 <= accepted <= 3 and st["depth"] == 2
                    and st["accepted"] == accepted):
                situation("g03", "refusal accounting wrong: accepted=%d "
                          "stats=%r" % (accepted, st), "BREAK")
                return
            st = a.fanout_stats()
            if st["dropped"] != 0 or st["dropped_by_reason"]:
                situation("g03", "fail-closed must not count drops: %r"
                          % (st,), "BREAK")
                return
            be.release()
            a._queue.join()
            if a._queue.qsize() != 0:
                situation("g03", "queue not drained after release",
                          "BREAK")
                return
            situation("g03", "fail-closed policy refuses loudly at "
                      "maxsize, drains cleanly after release", "HELD")
    finally:
        ctx.close()


def green_g04_close_drains_full_queue():
    """The stop sentinel bypasses the bound: close() cannot deadlock on
    a full queue."""
    ctx = Ctx()
    try:
        with _dev_keys():
            lg, d = ctx.make_log(n=1)
            be = BlockingBackend(mode="good")
            a = ctx.make_anchorer(lg, be, fanout_maxsize=2,
                                  fanout_policy="counted-drop")
            for i in range(10):
                lg.append({"event": "tool_call", "n": 500 + i})
                a.maybe_anchor(force=True)
            be.release()  # let the worker drain, then close must exit
            a.close(timeout=15)
            alive = a._thread.is_alive()
            if not alive:
                situation("g04", "close() drains and exits on full "
                          "queue", "HELD")
            else:
                situation("g04", "worker thread still alive after "
                          "close", "BREAK")
            ctx.anchorers.remove(a)
    finally:
        ctx.close()


def green_g05_stats_shape():
    ctx = Ctx()
    try:
        with _dev_keys():
            lg, d = ctx.make_log(n=1)
            be = BlockingBackend(mode="good")
            be.release()
            a = ctx.make_anchorer(lg, be, fanout_maxsize=16)
            st = a.fanout_stats()
            want = {"maxsize", "policy", "depth", "accepted", "dropped",
                    "dropped_by_reason", "high_water", "last_drop_wall",
                    "completed", "failed", "retried", "abandoned"}
            if want <= set(st):
                situation("g05", "operator-visible stats complete",
                          "HELD")
            else:
                situation("g05", "stats missing keys: %r"
                          % (want - set(st),), "BREAK")
    finally:
        ctx.close()


def green_g06_failed_jobs_are_counted():
    """Non-retryable failures are counted in the loss accounting, not
    just stderr-warned."""
    ctx = Ctx()
    try:
        with _dev_keys():
            lg, d = ctx.make_log(n=2)
            be = BlockingBackend(mode="config-fail")
            be.release()
            a = ctx.make_anchorer(lg, be)
            assert a.maybe_anchor(force=True) == "queued"
            a._queue.join()
            st = a.fanout_stats()
            if st["failed"] == 1 and st["completed"] == 0:
                situation("g06", "dead job counted in loss accounting",
                          "HELD")
            else:
                situation("g06", "failed-job accounting wrong: %r"
                          % (st,), "BREAK")
    finally:
        ctx.close()


def green_check():
    """Depth-1: adjacent anchor batteries stay green (honor
    GOV_SKIP_GREEN)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        situation("green-check", "skipped (GOV_SKIP_GREEN=1)", "HELD")
        return
    import subprocess
    py = sys.executable
    ok = True
    for bat in ("evals/w72_probes.py", "evals/w73_probes.py",
                "evals/w75_probes.py"):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            r = subprocess.run(
                [py, str(REPO_ROOT / bat)], capture_output=True,
                text=True, timeout=600, cwd=str(REPO_ROOT), env=env)
            if r.returncode != 0:
                ok = False
        except Exception:
            ok = False
    situation("green-check",
              "adjacent anchor batteries rc=0" if ok else
              "adjacent battery failed", "HELD" if ok else "BREAK")


def run_green():
    green_g01_bounded_queue_counts_drops()
    green_g02_dropped_jobs_are_recoverable()
    green_g03_fail_closed_policy()
    green_g04_close_drains_full_queue()
    green_g05_stats_shape()
    green_g06_failed_jobs_are_counted()
    red_c02_pin()
    green_check()


def main():
    phase = os.environ.get("FANOUT_PHASE", "green")
    if phase == "red":
        run_red()
    else:
        run_green()
    held = sum(1 for _, v in RESULTS if v == "HELD")
    brk = sum(1 for _, v in RESULTS if v == "BREAK")
    err = sum(1 for _, v in RESULTS if v == "ERROR")
    print("== wave-273 fanout battery (%s phase) ==" % phase)
    for sid, v in RESULTS:
        s = SITUATIONS[sid]
        print("[%s] %s: %s %s" % (v, sid, s["title"], s["detail"]))
    print("%d HELD / %d BREAK / %d ERROR" % (held, brk, err))
    return 0 if err == 0 and (brk == 0 or phase == "red") else 1


if __name__ == "__main__":
    sys.exit(main())
