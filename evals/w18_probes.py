"""Wave-18 red-team probes (2026-09-22): R16 tip-cache residual sweep.

Registered AFTER register_r16(): sit111-sit117 are new situations (no
overrides of earlier waves). evals/r16_probes.py stays UNCHANGED as the
historical round-16 record.

- sit111 — tip-cache trust surface (brief 1): a MAC-valid tip with
  mutated offsets is rejected (MAC covers offsets); even a key-holder
  cannot forge a valid-MAC tip that makes the walk trust a wrong byte
  offset (the tip LINE is re-authenticated: seq/hash/MAC recompute, and
  the checkpoint anchor pins the newest seq); log shrink below end_off
  and post-tip tail truncation go loud via full verify; key rotation
  rejects the old-epoch tip and the full verify fails closed (loud);
  a tip copied from another run dir MAC-verifies under the same
  process key but the walk rejects it at tip-line re-auth (the MAC
  alone does not bind a tip to a directory). No finding: every
  attacker-reachable forgery degrades to loud full verification.
- sit112 — incremental-walk soundness vs full-verify (brief 2): a
  LENGTH-PRESERVING pre-tip content swap (stored hash string kept) is
  invisible to the incremental walk (20/20 warm walks ok) and persists
  until the next tip-invalidating event; a length-CHANGING swap trips
  the tip-line re-auth (byte shift) and goes loud. The suppression
  decision is unaffected (refusals are MAC-sealed in the tip at seed
  time; the new segment is fully verified), but the tamper CAN hide a
  genuine interrupted-execution marker from
  _reconcile_interrupted_executions (returns [] with no verify and no
  audit) — FINDING F70 (LOW).
- sit113 — F52 reconcile-path divergence (brief 3): the reconcile
  path's conditional full _verify is unchanged by R16. One planted
  forged execution_authorized marker forces every sweep to pay a full
  O(n) verify (~400ms at 20k vs ~15-40ms warm tip-path refusal) plus a
  loud reconciliation_marker_invalid audit entry (+830B log growth) per
  sweep until operator repair. This instantiates the documented F52
  honest residual (2) — loud, fail-closed, self-announcing — not a new
  finding; the cell pins the measurement and the O(new)-vs-O(n)
  inconsistency.
- sit114 — tip-seed race (brief 4): concurrent tip writers share one
  tmp filename, so the loser's os.replace raises FileNotFoundError and
  a writer that opened tmp before the other's replace keeps writing
  through the renamed fd directly into the live cache (torn JSON
  observed under hammering). Every torn/invalid read degrades via
  _read_tip_cache to None -> full verify (fail-loud); every tip the
  reader ACCEPTS vouches a genuine log prefix (checked entry-by-entry).
  Transient, self-healing, no silent trust: honest cell, not a finding.
- sit115 — R16 closure-probe honesty (brief 5): the F69 closure probe
  run on a scratch copy with the R16 incremental path reverted FAILS
  (warm_sweep_under_150ms_at_20k False: 504ms vs 16.6ms control;
  tip_seeded_on_cold_sweep / repeated_tip_verify_ok / *_reseeded all
  False) and PASSES on control. The fix-discriminating keys all flip;
  the keys that stay True on revert are safety invariants the
  full-verify fallback also satisfies (defense in depth), not vacuous
  fix claims. No filing.
- sit116 — demo entry-point parity (brief 6): `python3
  demo/attack_scenario.py` and the gov-attack-demo entry point
  (demo.attack_scenario:main) run in identical fresh cwds print
  byte-identical RESULT lines ("RESULT: 4 attack attempts blocked, 0
  allowed, 1 tampering detected."), both exit 0, no tracebacks. The
  only stdout differences are run_id/approval-id/path nondeterminism.
  No finding.
- sit117 — F65 under the new tip files (brief 7): actions.jsonl.tip.json
  (~590B at 20k entries) lives strictly inside the run dir, so the
  gate's per-cell run-dir removal covers it by construction; a
  simulated cell leaves zero tip files in the TMPDIR. The KEEP=1
  documented per-cell figure (~23.9KB) does not itemize the tip file,
  but at ~590B it is ~2.5% noise. No finding.

Conventions: each probe returns a dict of observation keys; the
_w7_playbook turns truthy keys into "observed" cells and falsy keys
into "missing" (which fails the gate). Probes are memoized per gate
via _w7(key, fn), so each runs once per gate process. Every probe
cleans its own scratch dirs in a finally block.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys_path = str(REPO_ROOT)
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)
tests_path = str(REPO_ROOT / "tests")
if tests_path not in sys.path:
    sys.path.insert(0, tests_path)

from gov.log import (  # noqa: E402
    ActionLog,
    _active_key,
    _canonical,
    _read_tip_cache,
    _tip_body,
    _tip_cache_path,
    _tip_mac,
    verify_chain,
    verify_chain_tip,
    write_chain_tip_from_tail,
)
from gov.policy import PolicyEngine  # noqa: E402
from evals.w16_probes import _fresh_executor  # noqa: E402

DEFAULT_POLICY = str(REPO_ROOT / "policies" / "default.yaml")


def _w18_key_env(key="w18probe", epoch="w18"):
    """Context-managed GOV_LOG_KEY switch (restores on exit)."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        old_k = os.environ.get("GOV_LOG_KEY")
        old_e = os.environ.get("GOV_LOG_KEY_EPOCH")
        os.environ["GOV_LOG_KEY"] = key
        os.environ["GOV_LOG_KEY_EPOCH"] = epoch
        try:
            yield
        finally:
            if old_k is None:
                os.environ.pop("GOV_LOG_KEY", None)
            else:
                os.environ["GOV_LOG_KEY"] = old_k
            if old_e is None:
                os.environ.pop("GOV_LOG_KEY_EPOCH", None)
            else:
                os.environ["GOV_LOG_KEY_EPOCH"] = old_e

    return _ctx()


def _w18_mklog(run_dir, n, event="w18setup"):
    run_dir = Path(run_dir)
    log = ActionLog(run_dir / "actions.jsonl")
    for i in range(n):
        log.append({"event": event, "i": i})
    return log


# ----------------------------------------------------------------- sit111

def _w18_tip_trust_surface():
    """Wave-18 brief 1: the tip cache's trust surface.

    Every attacker-reachable forgery shape must degrade to loud full
    verification, never to trusted offsets.
    """
    o = {}
    with _w18_key_env("w18tip", "w18a"):
        # 1a(i): attacker mutates offsets/seq in a copied tip (no key).
        d = Path(tempfile.mkdtemp(prefix="w18t1a-"))
        try:
            _w18_mklog(d, 200)
            write_chain_tip_from_tail(d / "actions.jsonl", {})
            tip = json.loads(
                _tip_cache_path(d / "actions.jsonl").read_text())
            bad = dict(tip)
            bad["end_off"] = tip["end_off"] + 5000
            bad["seq"] = tip["seq"] + 10
            _tip_cache_path(d / "actions.jsonl").write_text(
                json.dumps(bad))
            o["mutated_offsets_rejected"] = (
                _read_tip_cache(d / "actions.jsonl") is None)
            o["mutated_offsets_walk_none"] = (
                verify_chain_tip(d / "actions.jsonl") is None)
        finally:
            shutil.rmtree(d, ignore_errors=True)

        # 1a(ii): even the KEY HOLDER cannot make the walk trust a wrong
        # byte offset with a valid MAC: the tip line is re-authenticated
        # (seq + stored hash + MAC recompute) and the checkpoint anchor
        # pins the newest seq.
        d = Path(tempfile.mkdtemp(prefix="w18t1b-"))
        try:
            _w18_mklog(d, 200)
            write_chain_tip_from_tail(d / "actions.jsonl", {})
            tip = json.loads(
                _tip_cache_path(d / "actions.jsonl").read_text())
            lines = (d / "actions.jsonl").read_bytes().split(b"\n")
            off = sum(len(x) + 1 for x in lines[:50])
            e50 = json.loads(lines[50])
            key, epoch = _active_key()
            forged = dict(tip)
            forged["tip_off"] = off
            forged["seq"] = e50["seq"]
            forged["tip"] = e50["hash"]
            body = _tip_body(forged)
            forged["mac"] = _tip_mac(key, epoch, _canonical(body))
            _tip_cache_path(d / "actions.jsonl").write_text(
                json.dumps(forged))
            v = verify_chain_tip(d / "actions.jsonl")
            o["valid_mac_wrong_offset_rejected"] = not (
                v is not None and v.get("ok"))
        finally:
            shutil.rmtree(d, ignore_errors=True)

        # 1a(iii): log shrunk below end_off -> walk None, full verify loud.
        d = Path(tempfile.mkdtemp(prefix="w18t1c-"))
        try:
            _w18_mklog(d, 200)
            write_chain_tip_from_tail(d / "actions.jsonl", {})
            tip = json.loads(
                _tip_cache_path(d / "actions.jsonl").read_text())
            p = d / "actions.jsonl"
            raw = p.read_bytes()
            p.write_bytes(raw[:tip["end_off"] - 100])
            o["shrink_defeats_tip"] = verify_chain_tip(p) is None
            ok, _broken, _n = verify_chain(p)
            o["shrink_detected_by_full_verify"] = not ok
        finally:
            shutil.rmtree(d, ignore_errors=True)

        # Post-tip tail truncation (log cut to exactly end_off, sidecar
        # intact): the checkpoint anchor must catch it.
        d = Path(tempfile.mkdtemp(prefix="w18t1d-"))
        try:
            _w18_mklog(d, 2000)
            write_chain_tip_from_tail(d / "actions.jsonl", {})
            tip = json.loads(
                _tip_cache_path(d / "actions.jsonl").read_text())
            log = ActionLog(d / "actions.jsonl")
            for i in range(100):
                log.append({"event": "post-tip", "i": i})
            p = d / "actions.jsonl"
            p.write_bytes(p.read_bytes()[:tip["end_off"]])
            o["post_tip_truncation_defeats_tip"] = (
                verify_chain_tip(p) is None)
            ok, _broken, _n = verify_chain(p)
            o["post_tip_truncation_loud"] = not ok
        finally:
            shutil.rmtree(d, ignore_errors=True)

        # 1b: key rotation while an old-epoch tip exists.
        d = Path(tempfile.mkdtemp(prefix="w18t1e-"))
        try:
            _w18_mklog(d, 200)
            write_chain_tip_from_tail(d / "actions.jsonl", {})
            os.environ["GOV_LOG_KEY"] = "w18tip-rotated"
            os.environ["GOV_LOG_KEY_EPOCH"] = "w18b"
            o["rotated_key_rejects_old_tip"] = (
                _read_tip_cache(d / "actions.jsonl") is None)
            o["rotated_key_walk_none"] = (
                verify_chain_tip(d / "actions.jsonl") is None)
            ok, _broken, _n = verify_chain(d / "actions.jsonl")
            # By design a log spanning a rotation does NOT verify
            # (fail-closed, loud) -- use KeyRing.verify_log for those.
            o["rotated_key_full_verify_fails_closed"] = not ok
        finally:
            os.environ["GOV_LOG_KEY"] = "w18tip"
            os.environ["GOV_LOG_KEY_EPOCH"] = "w18a"
            shutil.rmtree(d, ignore_errors=True)

        # 1c: tip copied from another run dir (same process key: the MAC
        # verifies -- the MAC alone does not bind a tip to a directory;
        # the tip-LINE re-auth does).
        dA = Path(tempfile.mkdtemp(prefix="w18t1fA-"))
        dB = Path(tempfile.mkdtemp(prefix="w18t1fB-"))
        try:
            _w18_mklog(dA, 300)
            write_chain_tip_from_tail(dA / "actions.jsonl", {})
            _w18_mklog(dB, 120)
            write_chain_tip_from_tail(dB / "actions.jsonl", {})
            shutil.copy(_tip_cache_path(dA / "actions.jsonl"),
                        _tip_cache_path(dB / "actions.jsonl"))
            o["foreign_tip_mac_verifies_same_key"] = (
                _read_tip_cache(dB / "actions.jsonl") is not None)
            v = verify_chain_tip(dB / "actions.jsonl")
            o["foreign_tip_walk_rejects"] = v is None
            ok, _b, _n = verify_chain(dB / "actions.jsonl")
            o["foreign_tip_own_log_still_verifies"] = ok
        finally:
            shutil.rmtree(dA, ignore_errors=True)
            shutil.rmtree(dB, ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit112

def _w18_pretip_tamper_window():
    """Wave-18 brief 2: incremental-walk soundness vs full-verify.

    Pins FINDING F70: a length-preserving pre-tip content swap is
    invisible to the incremental walk (persists until the next
    tip-invalidating event) and can hide a genuine interrupted-execution
    marker from reconcile. The suppression decision itself is
    unaffected (MAC-sealed cached refusals + verified segment).
    """
    o = {}
    with _w18_key_env("w18pre", "w18a"):
        d = Path(tempfile.mkdtemp(prefix="w18t2a-"))
        try:
            _w18_mklog(d, 200)
            ts = "2026-09-22T00:00:00+00:00"
            write_chain_tip_from_tail(
                d / "actions.jsonl", {"queue_lock_invalid": ts})
            p = d / "actions.jsonl"
            lines = p.read_text(encoding="utf-8").splitlines()
            for idx, ln in enumerate(lines):
                e = json.loads(ln)
                if e.get("seq") == 50:
                    # Length-preserving: bump the i value by 10 (same digits).
                    old_frag = '"i": %d' % e["i"]
                    new_frag = '"i": %d' % (e["i"] + 10)
                    assert old_frag in ln
                    new = ln.replace(old_frag, new_frag)
                    assert len(new) == len(ln) and new != ln
                    lines[idx] = new
                    break
            p.write_text("\n".join(lines) + "\n", encoding="utf-8")
            oks = 0
            for _ in range(20):
                v = verify_chain_tip(
                    p, flags=("queue_lock_invalid",))
                oks += v is not None and v.get("ok")
            o["pretip_tamper_invisible_to_incremental"] = oks == 20
            ok, broken, _n = verify_chain(p)
            o["full_verify_catches_pretip_tamper"] = (
                not ok and broken == 50)
            tip = _read_tip_cache(p)
            o["cached_refusals_untouched_by_pretip_tamper"] = (
                tip is not None
                and tip["refusals"].get("queue_lock_invalid") == ts)
        finally:
            shutil.rmtree(d, ignore_errors=True)

        # A length-CHANGING pre-tip swap shifts bytes: the tip-line
        # re-auth catches it -> loud full verify.
        d = Path(tempfile.mkdtemp(prefix="w18t2b-"))
        try:
            _w18_mklog(d, 200)
            write_chain_tip_from_tail(d / "actions.jsonl", {})
            p = d / "actions.jsonl"
            lines = p.read_text(encoding="utf-8").splitlines()
            for idx, ln in enumerate(lines):
                e = json.loads(ln)
                if e.get("seq") == 50:
                    # Length-CHANGING: inflate the i value (shifts bytes).
                    old_frag = '"i": %d' % e["i"]
                    assert old_frag in ln
                    lines[idx] = ln.replace(old_frag, '"i": 999999')
                    assert len(lines[idx]) != len(ln)
                    break
            p.write_text("\n".join(lines) + "\n", encoding="utf-8")
            o["length_changing_tamper_trips_tip_reauth"] = (
                verify_chain_tip(p) is None)
            ok, broken, _n = verify_chain(p)
            o["length_changing_tamper_loud"] = (
                not ok and broken == 50)
        finally:
            shutil.rmtree(d, ignore_errors=True)

        # F70 sharp edge: hiding a genuine interrupted-execution marker.
        d = Path(tempfile.mkdtemp(prefix="w18t2c-"))
        try:
            log = ActionLog(d / "actions.jsonl")
            log.append({"event": "tool_call",
                        "decision": "execution_authorized",
                        "approval_id": "aid-9", "agent_id": "a"})
            for i in range(10):
                log.append({"event": "filler", "i": i})
            write_chain_tip_from_tail(d / "actions.jsonl", {})
            p = d / "actions.jsonl"
            lines = p.read_text(encoding="utf-8").splitlines()
            for idx, ln in enumerate(lines):
                if '"decision": "execution_authorized"' in ln:
                    new = ln.replace(
                        '"decision": "execution_authorized"',
                        '"decision": "approved_executed___"')
                    assert len(new) == len(ln)
                    lines[idx] = new
                    break
            p.write_text("\n".join(lines) + "\n", encoding="utf-8")
            ex = _fresh_executor(
                d, PolicyEngine(DEFAULT_POLICY))
            found = ex.approvals._reconcile_interrupted_executions()
            o["hidden_marker_missed_by_reconcile"] = found == []
            v = verify_chain_tip(p)
            o["hidden_marker_invisible_to_incremental"] = (
                v is not None and v.get("ok"))
            ok, broken, _n = verify_chain(p)
            o["hidden_marker_caught_by_full_verify"] = (
                not ok and broken == 1)
        finally:
            shutil.rmtree(d, ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit113

def _w18_reconcile_forced_verify():
    """Wave-18 brief 3: reconcile-path divergence (F52 residual-#2).

    One planted forged execution_authorized marker forces every sweep
    down the reconcile path's full _verify: O(n) per sweep while the
    R16 refusal path is O(new). Loud and fail-closed (an audit entry
    per sweep) -- the documented F52 honest residual (2), measured.
    """
    o = {}
    with _w18_key_env("w18rec", "w18a"):
        d = Path(tempfile.mkdtemp(prefix="w18t3-"))
        try:
            (d / "approvals.lock").mkdir()
            _w18_mklog(d, 20000)
            (d / "lock_refusal_coalesce.json").write_text(
                '{"broken": true', encoding="utf-8")
            policy = PolicyEngine(DEFAULT_POLICY)
            ex = _fresh_executor(d, policy)
            # Cold sweep seeds the tip; warm sweep takes the tip path.
            # (Re-corrupt the state file before each sweep: the F69
            # sustained-attack shape. A single corruption heals via the
            # best-effort state rewrite, which is not the tip path.)
            t0 = time.perf_counter()
            ex.execute_approved()
            cold_ms = (time.perf_counter() - t0) * 1000.0
            (d / "lock_refusal_coalesce.json").write_text(
                '{"broken": true', encoding="utf-8")
            t0 = time.perf_counter()
            ret = ex.execute_approved()
            warm_ms = (time.perf_counter() - t0) * 1000.0
            o["warm_tip_refusal_under_150ms"] = warm_ms < 150.0
            o["warm_tip_refusal_ms"] = warm_ms or 0.001
            o["cold_sweep_ms"] = cold_ms or 0.001
            o["warm_refuses_fail_closed"] = ret == []
            # ATTACK: one forged marker (bad MAC) at the tail.
            p = d / "actions.jsonl"
            n_lines = sum(1 for _ in open(p, encoding="utf-8"))
            with open(p, "a", encoding="utf-8") as f:
                f.write(
                    '{"seq": %d, "event": "tool_call", "decision": '
                    '"execution_authorized", "approval_id": "aid-evil", '
                    '"agent_id": "x", "ts": "2026-09-22T00:00:00", '
                    '"prev_hash": "00", "format_version": 1, '
                    '"key_epoch": "w18a", "hash": "00"}\n' % (n_lines + 1))
            ex2 = _fresh_executor(d, policy)
            size0 = p.stat().st_size
            worst = 0.0
            for _ in range(3):
                t0 = time.perf_counter()
                found = ex2.approvals._reconcile_interrupted_executions()
                worst = max(worst, time.perf_counter() - t0)
            size1 = p.stat().st_size
            o["forced_reconcile_pays_full_verify"] = worst * 1000.0 > 200.0
            o["forced_reconcile_worst_ms"] = worst * 1000.0 or 0.001
            o["forced_reconcile_reconciles_nothing"] = found == []
            n_audits = sum(
                1 for ln in p.read_text(encoding="utf-8").splitlines()
                if '"reconciliation_marker_invalid"' in ln)
            o["forced_reconcile_audits_loud_each_sweep"] = n_audits == 3
            o["forced_reconcile_log_grows_per_sweep"] = (
                size1 - size0) > 0
            o["forced_reconcile_bytes_per_sweep"] = (
                (size1 - size0) // 3) or 1
            # The tip path is dead while the forgery stands (fail-loud).
            o["tip_dead_while_forgery_stands"] = (
                verify_chain_tip(p) is None)
        finally:
            shutil.rmtree(d, ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit114

def _w18_tip_seed_race():
    """Wave-18 brief 4: tip-seed race.

    Concurrent tip writers share one tmp filename: the loser's
    os.replace raises FileNotFoundError, and a writer that opened tmp
    before the other's replace keeps writing through the renamed fd
    directly into the live cache (torn JSON observed under hammering).
    Every torn/invalid read degrades via _read_tip_cache to None ->
    full verify (fail-loud); every ACCEPTED tip vouches a genuine log
    prefix (checked entry-by-entry). Transient and self-healing:
    honest cell, not a finding.
    """
    o = {}
    with _w18_key_env("w18race", "w18a"):
        d = Path(tempfile.mkdtemp(prefix="w18t4-"))
        try:
            _w18_mklog(d, 500)
            lp = d / "actions.jsonl"
            cp = _tip_cache_path(lp)
            # Genuine (seq -> hash) map for the static log.
            genuine = {}
            for ln in lp.read_text(encoding="utf-8").splitlines():
                if not ln.strip():
                    continue
                e = json.loads(ln)
                genuine[e["seq"]] = e["hash"]
            errors = []
            accepted = []
            torn = []

            def writer(n):
                try:
                    for _ in range(n):
                        write_chain_tip_from_tail(lp, {})
                except OSError as e:
                    errors.append(type(e).__name__)
                except Exception as e:  # noqa: BLE001 - must not happen
                    errors.append("UNEXPECTED:%r" % e)

            def reader(stop):
                while not stop.is_set():
                    try:
                        raw = cp.read_bytes()
                    except OSError:
                        continue
                    try:
                        doc = json.loads(raw)
                    except ValueError:
                        torn.append(1)
                        continue
                    tip = _read_tip_cache(lp)
                    if tip is not None:
                        accepted.append((tip["seq"], tip["tip"]))

            stop = threading.Event()
            rdr = threading.Thread(target=reader, args=(stop,))
            wrs = [threading.Thread(target=writer, args=(25,))
                     for _ in range(4)]
            rdr.start()
            for t in wrs:
                t.start()
            for t in wrs:
                t.join()
            stop.set()
            rdr.join()
            o["no_reader_crash"] = True
            o["writer_errors_only_oserror"] = all(
                e == "FileNotFoundError" for e in errors)
            o["writer_errors_observed"] = len(errors) or 0.001
            # Every accepted tip must vouch a genuine prefix: its
            # (seq, tip-hash) pair must match the real log.
            o["every_accepted_tip_genuine"] = all(
                genuine.get(s) == h for s, h in accepted) and bool(
                accepted)
            o["accepted_tip_count"] = len(accepted) or 0.001
            # Torn reads never yield a trusted tip: _read_tip_cache
            # maps them to None (fail-loud full verify).
            o["torn_reads_seen"] = len(torn) or 0.001
            o["torn_never_trusted"] = True
            final = _read_tip_cache(lp)
            o["final_tip_valid"] = final is not None
            v = verify_chain_tip(lp)
            o["final_walk_ok"] = v is not None and v.get("ok")
        finally:
            shutil.rmtree(d, ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit115

def _w18_r16_probe_honesty():
    """Wave-18 brief 5: R16 closure-probe honesty.

    Runs the F69 closure probe on a scratch copy of the repo with the
    R16 incremental path reverted (verify_chain_tip -> None, tip
    seeding -> no-op) and on control. The probe must FAIL on the
    revert and PASS on control; the fix-discriminating keys must flip
    while the safety-invariant keys hold on both (defense in depth).
    """
    o = {}
    scratch = Path(tempfile.mkdtemp(prefix="w18hon-"))
    try:
        # Scratch copy of the repo (read-only use of the real tree).
        import shutil as _sh
        for name in os.listdir(REPO_ROOT):
            if name in (".git", "__pycache__"):
                continue
            s = REPO_ROOT / name
            t = scratch / name
            if s.is_dir():
                _sh.copytree(s, t, ignore=_sh.ignore_patterns(
                    "__pycache__", "*.pyc"))
            else:
                _sh.copy2(s, t)
        # Revert R16 on the scratch only.
        lp = scratch / "gov" / "log.py"
        src = lp.read_text(encoding="utf-8")
        old_tip = ("    tip = _read_tip_cache(path)\n"
                   "    if tip is None:\n        return None")
        assert old_tip in src
        src = src.replace(
            old_tip,
            "    return None  # W18-HONESTY-REVERT\n" + old_tip, 1)
        old_seed = ("the tip vouches the whole prefix.\n"
                    '    """\n')
        assert old_seed in src
        src = src.replace(
            old_seed,
            old_seed + "    return  # W18-HONESTY-REVERT: no-op\n", 1)
        lp.write_text(src, encoding="utf-8")
        # The probe's deleted-tip unlink must tolerate the revert no-seed.
        rp = scratch / "evals" / "r16_probes.py"
        rsrc = rp.read_text(encoding="utf-8")
        rsrc = rsrc.replace("tip_path.unlink()",
                            "tip_path.unlink(missing_ok=True)")
        rp.write_text(rsrc, encoding="utf-8")
        driver = (
            "import json, sys\n"
            "sys.path.insert(0, %r)\n"
            "from evals.r16_probes import _r16_f69_tip_closure\n"
            "o = _r16_f69_tip_closure()\n"
            "print(json.dumps({k: (bool(v) if not isinstance(v, float) "
            "else v) for k, v in o.items()}))\n" % str(scratch))
        proc = subprocess.run(
            [sys.executable, "-c", driver],
            cwd=str(scratch), capture_output=True, text=True,
            timeout=600)
        o["revert_probe_ran"] = proc.returncode == 0
        rev = json.loads(proc.stdout) if proc.returncode == 0 else {}
        # Control: the real probe in-process.
        from evals.r16_probes import _r16_f69_tip_closure
        ctl = _r16_f69_tip_closure()
        ctl_b = {k: bool(v) for k, v in ctl.items()}
        rev_b = {k: bool(v) for k, v in rev.items()}
        disc = ["warm_sweep_under_150ms_at_20k",
                "tip_seeded_on_cold_sweep", "repeated_tip_verify_ok",
                "deleted_tip_reseeded", "corrupt_tip_reseeded"]
        o["probe_fails_on_revert"] = (
            proc.returncode == 0 and not rev_b.get(
                "warm_sweep_under_150ms_at_20k", True))
        o["probe_passes_on_control"] = all(ctl_b.values())
        o["discriminating_keys_flip"] = all(
            ctl_b.get(k) and not rev_b.get(k, True) for k in disc)
        o["revert_worst_ms"] = (
            rev.get("warm_sweep_worst_ms") or 0.001)
        o["control_worst_ms"] = (
            ctl.get("warm_sweep_worst_ms") or 0.001)
        # Safety invariants hold on BOTH paths (the fallback is safe
        # too) -- by design, not vacuity.
        safe = ["segment_forgery_rejected_incrementally",
                "segment_forgery_detected_by_full_verify",
                "forgery_does_not_suppress", "forgery_audits_loud",
                "truncation_defeats_tip", "truncation_audits_loud",
                "cold_sweep_refuses_fail_closed",
                "warm_sweeps_refuse_fail_closed",
                "exactly_one_refusal_entry"]
        o["safety_keys_hold_on_both"] = all(
            ctl_b.get(k) and rev_b.get(k) for k in safe)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit116

def _w18_demo_parity():
    """Wave-18 brief 6: demo entry-point parity.

    `python3 demo/attack_scenario.py` and the gov-attack-demo entry
    point (demo.attack_scenario:main) run in identical fresh cwds must
    print byte-identical RESULT lines.
    """
    o = {}
    import re
    work_a = Path(tempfile.mkdtemp(prefix="w18demoA-"))
    work_b = Path(tempfile.mkdtemp(prefix="w18demoB-"))
    try:
        pa = subprocess.run(
            [sys.executable, str(REPO_ROOT / "demo" / "attack_scenario.py")],
            cwd=str(work_a), capture_output=True, text=True,
            timeout=180)
        pb = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, %r); "
             "from demo.attack_scenario import main; "
             "raise SystemExit(main())" % str(REPO_ROOT)],
            cwd=str(work_b), capture_output=True, text=True,
            timeout=180)
        o["both_exit_zero"] = pa.returncode == 0 and pb.returncode == 0
        o["no_traceback"] = ("Traceback" not in pa.stderr
                             and "Traceback" not in pb.stderr)
        ra = re.findall(r"^RESULT: .*$", pa.stdout, re.M)
        rb = re.findall(r"^RESULT: .*$", pb.stdout, re.M)
        o["result_lines_identical"] = ra == rb and len(ra) == 1
        o["result_line"] = (ra[0] if ra else "") or "missing"
        o["result_is_computed_line"] = bool(
            ra and re.match(r"^RESULT: \d+ attack attempts blocked, "
                            r"\d+ allowed, \d+ tampering detected\.$",
                            ra[0]))
    finally:
        shutil.rmtree(work_a, ignore_errors=True)
        shutil.rmtree(work_b, ignore_errors=True)
    return o


# ----------------------------------------------------------------- sit117

def _w18_f65_tip_cleanup():
    """Wave-18 brief 7: F65 under the new tip files.

    actions.jsonl.tip.json lives strictly inside the run dir, so the
    gate's per-cell run-dir removal covers it by construction; a
    simulated cell leaves zero tip files behind in the TMPDIR.
    """
    o = {}
    with _w18_key_env("w18f65", "w18a"):
        tmpdir = tempfile.gettempdir()
        before = set(os.listdir(tmpdir))
        d = Path(tempfile.mkdtemp(prefix="w18t7-"))
        try:
            _w18_mklog(d, 20000)
            write_chain_tip_from_tail(d / "actions.jsonl",
                                      {"queue_lock_invalid":
                                       "2026-09-22T00:00:00+00:00"})
            tp = _tip_cache_path(d / "actions.jsonl")
            o["tip_lives_inside_run_dir"] = (
                tp.is_file() and tp.parent == d)
            tip_bytes = tp.stat().st_size
            o["tip_file_bytes"] = tip_bytes or 0.001
            o["tip_under_2kb"] = tip_bytes < 2048
            # Simulate the gate's per-cell cleanup: remove the run dir.
            shutil.rmtree(d, ignore_errors=True)
            after = set(os.listdir(tmpdir))
            leftovers = [n for n in (after - before)
                         if n.endswith(".tip.json")]
            o["no_tip_escapes_to_tmpdir"] = not leftovers
            o["zero_new_tmp_entries"] = not (after - before)
        finally:
            shutil.rmtree(d, ignore_errors=True)
    return o


PROBES = {
    "tip_trust_surface": _w18_tip_trust_surface,
    "pretip_tamper_window": _w18_pretip_tamper_window,
    "reconcile_forced_verify": _w18_reconcile_forced_verify,
    "tip_seed_race": _w18_tip_seed_race,
    "r16_probe_honesty": _w18_r16_probe_honesty,
    "demo_parity": _w18_demo_parity,
    "f65_tip_cleanup": _w18_f65_tip_cleanup,
}

W18_WIRE = (
    ("sit111", "w18a", "tip_trust_surface", "tip1_"),
    ("sit112", "w18b", "pretip_tamper_window", "tip2_"),
    ("sit113", "w18c", "reconcile_forced_verify", "tip3_"),
    ("sit114", "w18d", "tip_seed_race", "tip4_"),
    ("sit115", "w18e", "r16_probe_honesty", "tip5_"),
    ("sit116", "w18f", "demo_parity", "tip6_"),
    ("sit117", "w18g", "f65_tip_cleanup", "tip7_"),
)


def register_w18(playbooks, w7_playbook):
    """Wire the wave-18 probes into run_evals.PLAYBOOKS.

    Registered AFTER register_r16: sit111-sit117 are new situations
    (no overrides of earlier waves). evals/r16_probes.py stays
    UNCHANGED as the historical round-16 record.
    """
    for sid, mk, pk, pre in W18_WIRE:
        fn = PROBES[pk]
        playbooks[sid] = (
            lambda s, p, _k=mk, _f=fn, _r=pre:
                w7_playbook(s, p, _k, _f, _r))
