"""Wave-114 Lane 2: adversarial rerun against the wave-112 F69 pin_off change.

Target: gov/log.py's incremental replay-freshness scan. Wave-112 changed
the F72 freshness scan in _read_tip_cache from JSON-parsing the ENTIRE
checkpoint sidecar to scanning only cp_bytes[tip["pin_off"]:] (O(new
bytes)), and changed the F69 warm-sweep bound to assert on
time.process_time() instead of time.perf_counter().

Threat model (F52): the attacker is a run-dir writer WITHOUT the log
key. They can append/truncate/rewrite checkpoints.jsonl and the
.tip.json file, but cannot mint a MAC. "Genuine" artifacts in the
probes are built through the real code paths (simulating legitimate
concurrent writers); attacker artifacts are raw file surgery with no
key use.

Attack shapes:
  (a) concurrent-writer interleavings -- smuggle an attacker/newer pin
      past the incremental scan;
  (b) pin_off forgery -- bit-flips, cross-tip transplantation;
  (c) sidecar shrink/grow games around the prefix-hash checks;
  (d) multi-ActionLog shared-checkpoints.jsonl interference (fail-OPEN
      attempts);
  plus (t) the F69 process_time() metric change itself.

Verdicts: HELD (attack stopped / residual confirmed benign), BREAK
(attacker goal achieved -- file as F173+), CONTROL (threat-model
boundary demonstration), ERROR.

Standalone: python evals/f69_pin_off_adversarial.py
(exit 0 iff no BREAK and no ERROR).
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))
from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

import gov.log as gov_log  # noqa: E402
from gov.log import (  # noqa: E402
    ActionLog,
    _append_tip_gen_pin,
    _read_tip_cache,
    _tip_cache_path,
    verify_chain,
    verify_chain_tip,
    write_chain_tip_from_tail,
)

RESULTS = []


def check(name, verdict, detail):
    RESULTS.append((name, verdict, detail))
    print("PROBE %-52s %s -- %s" % (name, verdict, detail))


def fresh_dir():
    d = Path(tempfile.mkdtemp(prefix="gov-pinadv-"))
    (d / "approvals.lock").mkdir()
    return d


def cleanup(d):
    shutil.rmtree(d, ignore_errors=True)


def append_n(log, n, event="adv"):
    for i in range(n):
        log.append({"event": event, "i": i})


def read_tip_json(log_path):
    return json.loads(_tip_cache_path(log_path).read_text(
        encoding="utf-8"))


def attacker_write_tip_json(log_path, doc):
    """Raw tip-file rewrite WITHOUT re-MACing (the attacker's write)."""
    _tip_cache_path(log_path).write_text(
        json.dumps(doc, ensure_ascii=True, sort_keys=True),
        encoding="utf-8")


# ---------------------------------------------------------------- (a)
def a1_forged_pin_with_huge_gen_ignored():
    """Attacker mints a pin line with tip_gen=99999 but no key.

    Goal: make the live tip read stale (DoS) or confuse the scan.
    Expect: the scan skips MAC-invalid lines; tip stays fresh; the
    sweep verdict is correct.
    """
    name = "a1_forged_pin_with_huge_gen_ignored"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 10)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        tip = _read_tip_cache(d / "actions.jsonl")
        assert tip is not None and tip["gen"] == 1
        key, epoch = gov_log._active_key()
        forged = {"seq": 10, "hash": "f" * 64, "key_epoch": epoch,
                  "format_version": gov_log.FORMAT_VERSION,
                  "tip_gen": 99999, "mac": "0" * 64}
        with open(d / "checkpoints.jsonl", "a",
                  encoding="utf-8") as f:
            f.write(json.dumps(forged) + "\n")
        tip2 = _read_tip_cache(d / "actions.jsonl")
        if tip2 is None:
            check(name, "BREAK",
                  "forged pin made the genuine tip read stale (DoS)")
            return
        v = verify_chain_tip(d / "actions.jsonl")
        # The forged line sits in the NEW sidecar region: the anchor
        # parse must fail closed on the MAC-invalid shape.
        if v is not None:
            check(name, "BREAK",
                  "sweep accepted with a forged pin line in the "
                  "sidecar tail (ok=%s)" % v.get("ok"))
            return
        check(name, "HELD",
              "forged pin ignored by the scan (tip fresh); sweep "
              "fails closed on the forged tail line")
    finally:
        cleanup(d)


def a2_racy_genuine_pin_before_pin_off_benign():
    """The documented residual, end to end: a genuine newer pin lands
    BEFORE the tip's pin_off measurement (racy concurrent writer), so
    the stale-but-genuine tip is accepted.

    Goal: show this escalates -- i.e. the accepted stale tip lets a
    tampered tail through. Expect: the tip is accepted (residual is
    real) BUT the tail is still fully re-verified, so tampering the
    new tail fails closed. Residual confirmed benign, not escalated.
    """
    name = "a2_racy_genuine_pin_before_pin_off_benign"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 10)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        t1 = _read_tip_cache(d / "actions.jsonl")
        assert t1["gen"] == 1
        # "Writer B" (legitimate concurrent sweeper, no new entries):
        # two tip advances -> genuine pins gen 2 and 3, same log.
        _append_tip_gen_pin(d / "actions.jsonl", 10, "b" * 64, 2)
        _append_tip_gen_pin(d / "actions.jsonl", 10, "b" * 64, 3)
        # "Writer A" won the race with a stale in-memory tip: it
        # advances gen 1 -> 2, measures pin_off AFTER B's pins landed,
        # appends its own genuine pin gen 2. Craft exactly what that
        # racy sweep would have written (re-MACed via the write path).
        _append_tip_gen_pin(d / "actions.jsonl", 10, "a" * 64, 2)
        cp_bytes = (d / "checkpoints.jsonl").read_bytes()
        racy = dict(t1)
        racy["gen"] = 2
        # pin_off = the true pre-A-pin size: A's own pin is the last
        # sidecar line, so subtract its length (+ newline).
        racy["pin_off"] = len(cp_bytes) - len(
            (d / "checkpoints.jsonl").read_bytes()
            .split(b"\n")[-2]) - 1
        racy["cp_size"] = len(cp_bytes)
        racy["cp_digest"] = hashlib.sha256(cp_bytes).hexdigest()
        del racy["mac"]
        gov_log._write_tip_cache(d / "actions.jsonl", racy)
        # Sanity: B's pin gen 3 really does sit before A's pin_off.
        raw = read_tip_json(d / "actions.jsonl")
        scan_max = gov_log._max_pinned_tip_gen(
            cp_bytes[raw["pin_off"]:], *gov_log._active_key())
        full_max = gov_log._max_pinned_tip_gen(
            cp_bytes, *gov_log._active_key())
        assert full_max == 3, full_max
        tip = _read_tip_cache(d / "actions.jsonl")
        if tip is None:
            check(name, "ERROR",
                  "setup wrong: racy tip should read fresh "
                  "(scan_max=%s)" % scan_max)
            return
        # The residual is REAL: accepted despite a newer genuine pin.
        v = verify_chain_tip(d / "actions.jsonl")
        if v is None or not v.get("ok") or v["entries"] != 10:
            check(name, "BREAK",
                  "stale-but-genuine tip broke the sweep: %r" % (v,))
            return
        # Escalation attempt: tamper a NEW tail entry (post-tip). The
        # accepted stale tip must still fully re-verify the tail.
        log.append({"event": "adv_tail", "i": 10})
        log.append({"event": "adv_tail", "i": 11})
        lines = (d / "actions.jsonl").read_text(
            encoding="utf-8").splitlines()
        e = json.loads(lines[-1])
        e["hash"] = "0" * 64  # break the tail MAC
        lines[-1] = json.dumps(e)
        (d / "actions.jsonl").write_text("\n".join(lines) + "\n",
                                         encoding="utf-8")
        v2 = verify_chain_tip(d / "actions.jsonl")
        if v2 is not None:
            check(name, "BREAK",
                  "stale tip accepted AND tampered tail verified ok "
                  "-- residual escalated to a replay hole")
            return
        check(name, "HELD",
              "residual real (scan_max=%d < full_max=%d, tip "
              "accepted) but benign: tail fully re-verified, "
              "tamper fails closed" % (scan_max, full_max))
    finally:
        cleanup(d)


def a3_truncate_to_cp_size_blinds_scan():
    """Attacker truncates the sidecar to EXACTLY a stale tip's cp_size
    and replays that tip's file.

    Goal: blind the freshness scan, then get a wrong verdict.
    Expect: _read_tip_cache DOES accept (scan blinded -- the blinding
    is real and asserted), but verify_chain_tip still returns the
    CORRECT verdict (the whole live tail is re-verified), and a
    tampered tail entry still fails closed. Blinding != hole.
    """
    name = "a3_truncate_to_cp_size_blinds_scan"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 10)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        t1 = _read_tip_cache(d / "actions.jsonl")
        t1_file = _tip_cache_path(
            d / "actions.jsonl").read_bytes()
        s1 = t1["cp_size"]
        append_n(log, 10, event="adv2")
        v = verify_chain_tip(d / "actions.jsonl")
        assert v is not None and v["ok"] and v["entries"] == 20
        full_log = (d / "actions.jsonl").read_bytes()
        full_cp = (d / "checkpoints.jsonl").read_bytes()
        assert len(full_cp) > s1

        def attack(tamper_seq=None):
            # Attacker (no key): truncate the sidecar to the STALE
            # tip's pinned size and replay the stale tip file;
            # optionally also tamper one tail entry (1-based seq).
            (d / "checkpoints.jsonl").write_bytes(full_cp[:s1])
            _tip_cache_path(d / "actions.jsonl").write_bytes(t1_file)
            if tamper_seq is not None:
                lines = full_log.decode("utf-8").splitlines()
                e = json.loads(lines[tamper_seq - 1])
                e["hash"] = "1" * 64
                lines[tamper_seq - 1] = json.dumps(e)
                (d / "actions.jsonl").write_bytes(
                    ("\n".join(lines) + "\n").encode("utf-8"))
            else:
                (d / "actions.jsonl").write_bytes(full_log)

        # Round 1: blind the scan, no tamper. The scan IS blinded
        # (stale tip accepted -- assert it), but the verdict must be
        # CORRECT: the whole live tail is re-verified.
        attack()
        if _read_tip_cache(d / "actions.jsonl") is None:
            check(name, "ERROR",
                  "setup wrong: truncated scan should accept the "
                  "stale tip")
            return
        v = verify_chain_tip(d / "actions.jsonl")
        if v is None or not v.get("ok"):
            check(name, "ERROR",
                  "unexpected fail-closed on exact-cp_size "
                  "truncation: %r" % (v,))
            return
        if v["entries"] != 20:
            check(name, "BREAK",
                  "wrong verdict after scan blinding: entries=%s "
                  "(log has 20)" % v["entries"])
            return
        # Round 2: blind the scan AND plant a tamper in the tail
        # (seq 15, inside the segment the stale tip must re-verify)
        # BEFORE the sweep. Must fail closed.
        attack(tamper_seq=15)
        if _read_tip_cache(d / "actions.jsonl") is None:
            check(name, "ERROR",
                  "setup wrong: scan should still be blinded with "
                  "a tampered tail")
            return
        v2 = verify_chain_tip(d / "actions.jsonl")
        if v2 is not None:
            check(name, "BREAK",
                  "blinded scan + replayed tip verified a tampered "
                  "tail -- replay hole")
            return
        ok, broken, _ = verify_chain(d / "actions.jsonl")
        if ok:
            check(name, "BREAK",
                  "full verification missed the planted tail "
                  "tamper")
            return
        if broken != 15:
            check(name, "ERROR",
                  "full verify broke at seq %r, expected 15" %
                  (broken,))
            return
        check(name, "HELD",
              "scan truly blinded (stale tip accepted) but verdict "
              "correct (20/20 re-verified); tail tamper planted "
              "pre-sweep fails closed incrementally (None) and "
              "loudly on full verify (broken at seq 15)")
    finally:
        cleanup(d)


# ---------------------------------------------------------------- (b)
def b1_tip_pin_off_bitflip():
    """Flip pin_off inside the tip file (no re-MAC: attacker's write)."""
    name = "b1_tip_pin_off_bitflip"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 5)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        doc = read_tip_json(d / "actions.jsonl")
        assert doc["pin_off"] > 10
        doc["pin_off"] = doc["pin_off"] - 10  # attacker's bit-flip
        attacker_write_tip_json(d / "actions.jsonl", doc)
        if _read_tip_cache(d / "actions.jsonl") is not None:
            check(name, "BREAK",
                  "tip with forged pin_off accepted (MAC not "
                  "covering pin_off?)")
            return
        check(name, "HELD",
              "pin_off bit-flip breaks the tip MAC -> fail-closed")
    finally:
        cleanup(d)


def b2_cross_tip_pin_off_transplant():
    """Splice tip A's pin_off into tip B's tip file (keep B's MAC)."""
    name = "b2_cross_tip_pin_off_transplant"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 5)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        p1 = read_tip_json(d / "actions.jsonl")["pin_off"]
        append_n(log, 5, event="adv2")
        verify_chain_tip(d / "actions.jsonl")  # advance -> gen 2
        doc2 = read_tip_json(d / "actions.jsonl")
        assert doc2["pin_off"] != p1
        doc2["pin_off"] = p1  # transplant, keep doc2's MAC
        attacker_write_tip_json(d / "actions.jsonl", doc2)
        if _read_tip_cache(d / "actions.jsonl") is not None:
            check(name, "BREAK",
                  "cross-tip pin_off transplant accepted")
            return
        check(name, "HELD",
              "transplanted pin_off breaks the tip MAC -> "
              "fail-closed")
    finally:
        cleanup(d)


def b3_sidecar_prefix_bitflip():
    """Flip one byte inside the tip's pinned sidecar prefix."""
    name = "b3_sidecar_prefix_bitflip"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 5)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        v0 = verify_chain_tip(d / "actions.jsonl")
        assert v0 is not None and v0["ok"]
        cp = d / "checkpoints.jsonl"
        raw = bytearray(cp.read_bytes())
        raw[10] ^= 0x01  # inside the pinned prefix
        cp.write_bytes(bytes(raw))
        # The freshness scan itself does not check the prefix hash...
        # ...but the sweep must still fail closed.
        if verify_chain_tip(d / "actions.jsonl") is not None:
            check(name, "BREAK",
                  "rewritten sidecar prefix verified ok")
            return
        check(name, "HELD",
              "prefix rewrite fails closed via the pinned "
              "cp_digest check")
    finally:
        cleanup(d)


# ---------------------------------------------------------------- (c)
def c1_grow_garbage():
    """Attacker appends non-JSON garbage to the sidecar."""
    name = "c1_grow_garbage"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 5)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        with open(d / "checkpoints.jsonl", "a",
                  encoding="utf-8") as f:
            f.write("NOT JSON{{{\n")
        # Scan layer tolerates (skips) the garbage line...
        if _read_tip_cache(d / "actions.jsonl") is None:
            check(name, "ERROR",
                  "setup wrong: scan should skip one garbage line")
            return
        # ...but the sweep must fail closed, never trust.
        if verify_chain_tip(d / "actions.jsonl") is not None:
            check(name, "BREAK",
                  "sweep trusted a sidecar with a corrupt tail line")
            return
        check(name, "HELD",
              "garbage tail line: scan skips, sweep fails closed "
              "(n_bad)")
    finally:
        cleanup(d)


def c2_grow_forged_pin_shape():
    """Attacker appends a well-formed pin-shaped line (bad MAC)."""
    name = "c2_grow_forged_pin_shape"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 5)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        _, epoch = gov_log._active_key()
        forged = {"seq": 99999, "hash": "a" * 64,
                  "key_epoch": epoch,
                  "format_version": gov_log.FORMAT_VERSION,
                  "tip_gen": 99999, "mac": "b" * 64}
        with open(d / "checkpoints.jsonl", "a",
                  encoding="utf-8") as f:
            f.write(json.dumps(forged) + "\n")
        if _read_tip_cache(d / "actions.jsonl") is None:
            check(name, "ERROR",
                  "setup wrong: forged-shape line should be "
                  "scan-skipped")
            return
        if verify_chain_tip(d / "actions.jsonl") is not None:
            check(name, "BREAK",
                  "sweep accepted a sidecar whose newest line is a "
                  "forged pin shape")
            return
        check(name, "HELD",
              "forged pin shape: scan skips (bad MAC), newest-line "
              "MAC check fails closed")
    finally:
        cleanup(d)


def c3_shrink_below_cp_size():
    """Attacker truncates 10 bytes off the sidecar tail."""
    name = "c3_shrink_below_cp_size"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 5)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        v0 = verify_chain_tip(d / "actions.jsonl")
        assert v0 is not None and v0["ok"]
        cp = d / "checkpoints.jsonl"
        raw = cp.read_bytes()
        cp.write_bytes(raw[:-10])
        if verify_chain_tip(d / "actions.jsonl") is not None:
            check(name, "BREAK", "shrunk sidecar verified ok")
            return
        check(name, "HELD",
              "shrink below cp_size fails closed (shrink check)")
    finally:
        cleanup(d)


def c3b_truncate_below_pin_off():
    """Attacker truncates the sidecar to BELOW the tip's pin_off.

    _read_tip_cache alone then scans b"" and accepts; the security
    boundary must be verify_chain_tip's shrink check.
    """
    name = "c3b_truncate_below_pin_off"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 5)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        tip = _read_tip_cache(d / "actions.jsonl")
        cp = d / "checkpoints.jsonl"
        cp.write_bytes(cp.read_bytes()[:tip["pin_off"] - 10])
        layer_tip = _read_tip_cache(d / "actions.jsonl")
        sweep = verify_chain_tip(d / "actions.jsonl")
        if sweep is not None:
            check(name, "BREAK",
                  "sweep accepted a sidecar truncated below pin_off")
            return
        check(name, "HELD",
              "_read_tip_cache accepted=%s on empty scan window, "
              "but verify_chain_tip fails closed (shrink check) -- "
              "the scan is not the boundary" % (layer_tip is not None))
    finally:
        cleanup(d)


def c4_replay_old_sidecar_prefix():
    """Attacker restores an older GENUINE sidecar prefix and replays
    the matching older tip (log left intact / longer).

    Expect: accepted (self-consistent past state) but the verdict is
    CORRECT -- the whole live tail is re-verified, so this is
    redundant work, not a replay hole.
    """
    name = "c4_replay_old_sidecar_prefix"
    d = fresh_dir()
    try:
        log = ActionLog(d / "actions.jsonl")
        append_n(log, 10)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        old_sidecar = (d / "checkpoints.jsonl").read_bytes()
        old_tip_file = _tip_cache_path(
            d / "actions.jsonl").read_bytes()
        append_n(log, 10, event="adv2")
        v = verify_chain_tip(d / "actions.jsonl")
        assert v is not None and v["ok"] and v["entries"] == 20
        # Attacker: restore old sidecar prefix + old tip file.
        (d / "checkpoints.jsonl").write_bytes(old_sidecar)
        _tip_cache_path(d / "actions.jsonl").write_bytes(old_tip_file)
        if _read_tip_cache(d / "actions.jsonl") is None:
            check(name, "ERROR",
                  "setup wrong: consistent old state should read")
            return
        v = verify_chain_tip(d / "actions.jsonl")
        if v is None or not v.get("ok"):
            check(name, "ERROR",
                  "unexpected fail-closed on consistent old state: "
                  "%r" % (v,))
            return
        if v["entries"] != 20:
            check(name, "BREAK",
                  "wrong verdict on replayed prefix: entries=%s" %
                  v["entries"])
            return
        check(name, "HELD",
              "old-prefix replay accepted but verdict correct "
              "(20/20 re-verified) -- redundant work, not a hole")
    finally:
        cleanup(d)


# ---------------------------------------------------------------- (d)
def d1_cross_log_anchor_fail_closed():
    """Two ActionLogs share one checkpoints.jsonl; log B is LONGER.

    Attack goal: log A's sweep vouches B's anchor or accepts
    something about A's bytes it shouldn't. Expect: fail-closed
    (verify_chain_tip -> None; full verify -> loud ok=False).
    """
    name = "d1_cross_log_anchor_fail_closed"
    d = fresh_dir()
    try:
        loga = ActionLog(d / "actions.jsonl")
        logb = ActionLog(d / "other.jsonl")
        append_n(loga, 5, event="a")
        append_n(logb, 20, event="b")
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        v = verify_chain_tip(d / "actions.jsonl")
        if v is not None:
            check(name, "BREAK",
                  "A's sweep returned ok with B's longer anchor "
                  "newest: %r" % (v,))
            return
        vf_ok, _, _ = verify_chain(d / "actions.jsonl")
        if vf_ok:
            check(name, "BREAK",
                  "full verify blessed A against B's longer sidecar")
            return
        check(name, "HELD",
              "B-longer-than-A: incremental None, full verify loud "
              "ok=False (tail-truncation) -- fail-closed")
    finally:
        cleanup(d)


def d2_shared_gen_staleness_fail_closed():
    """B's tip writes advance the SHARED pin gen; A's old tip must
    read stale and reseed cleanly (fail-closed, self-healing)."""
    name = "d2_shared_gen_staleness_fail_closed"
    d = fresh_dir()
    try:
        loga = ActionLog(d / "actions.jsonl")
        append_n(loga, 5, event="a")
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        ta = _read_tip_cache(d / "actions.jsonl")
        assert ta["gen"] == 1
        # "Writer B": two genuine tip pins on the shared sidecar.
        _append_tip_gen_pin(d / "other.jsonl", 0, "b" * 64, 2)
        _append_tip_gen_pin(d / "other.jsonl", 0, "b" * 64, 3)
        if _read_tip_cache(d / "actions.jsonl") is not None:
            check(name, "BREAK",
                  "A's tip not stale after B advanced the shared gen")
            return
        # Reseed heals: new gen follows the shared max.
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        ta2 = _read_tip_cache(d / "actions.jsonl")
        v = verify_chain_tip(d / "actions.jsonl")
        if ta2 is None or ta2["gen"] != 4 or v is None or not v[
                "ok"]:
            check(name, "BREAK",
                  "reseed after shared-gen staleness broken: %r %r"
                  % (ta2, v))
            return
        check(name, "HELD",
              "A stale on B's pins (fail-closed); reseed gen=4, "
              "sweep ok")
    finally:
        cleanup(d)


def d3_wave112_delta_shared_pin_before_pin_off():
    """Wave-112 behavior delta, shared sidecar: B's newer pin sits
    BEFORE A's pin_off (A advanced from a stale in-memory tip).

    Pre-112 (whole-sidecar scan) this tip read STALE; post-112 it
    reads fresh. Expect: accepted AND the verdict for A's log is
    still correct -- the delta is benign.
    """
    name = "d3_wave112_delta_shared_pin_before_pin_off"
    d = fresh_dir()
    try:
        loga = ActionLog(d / "actions.jsonl")
        append_n(loga, 5, event="a")
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        ta = _read_tip_cache(d / "actions.jsonl")
        assert ta["gen"] == 1
        # B advances the shared gen twice (pins only, seq=0 so they
        # never become the truncation anchor).
        _append_tip_gen_pin(d / "other.jsonl", 0, "b" * 64, 2)
        _append_tip_gen_pin(d / "other.jsonl", 0, "b" * 64, 3)
        # A's racy advance from its stale tip: gen 1 -> 2, pin_off
        # measured after B's pins, own genuine pin appended.
        _append_tip_gen_pin(d / "actions.jsonl", 5, "a" * 64, 2)
        cp_bytes = (d / "checkpoints.jsonl").read_bytes()
        pin_lines = cp_bytes.split(b"\n")
        a_pin_len = len(pin_lines[-2]) + 1
        racy = dict(ta)
        racy["gen"] = 2
        racy["pin_off"] = len(cp_bytes) - a_pin_len
        racy["cp_size"] = len(cp_bytes)
        racy["cp_digest"] = hashlib.sha256(cp_bytes).hexdigest()
        del racy["mac"]
        gov_log._write_tip_cache(d / "actions.jsonl", racy)
        raw = read_tip_json(d / "actions.jsonl")
        scan_max = gov_log._max_pinned_tip_gen(
            cp_bytes[raw["pin_off"]:], *gov_log._active_key())
        full_max = gov_log._max_pinned_tip_gen(
            cp_bytes, *gov_log._active_key())
        assert full_max == 3 and scan_max == 2, (full_max, scan_max)
        # Pre-112 whole-sidecar scan WOULD have rejected (3 > 2).
        tip = _read_tip_cache(d / "actions.jsonl")
        if tip is None:
            check(name, "ERROR",
                  "setup wrong: post-112 scan should accept")
            return
        v = verify_chain_tip(d / "actions.jsonl")
        if v is None or not v.get("ok") or v["entries"] != 5:
            check(name, "BREAK",
                  "delta accept broke A's sweep: %r" % (v,))
            return
        check(name, "HELD",
              "delta confirmed (full-scan max=3 would reject, "
              "pin_off-scan max=2 accepts) and benign: A's verdict "
              "correct (5/5)")
    finally:
        cleanup(d)


# ---------------------------------------------------------------- (t)
def _build_20k(d):
    log = ActionLog(d / "actions.jsonl")
    for i in range(20000):
        log.append({"event": "t", "i": i})
    return log


def t1_bound_still_discriminates_amplifier():
    """Pre-R16 shape (every sweep pays FULL verification because the
    tip is missing) must still trip the 150ms process_time bound.

    This is the amplifier the bound pins; the metric change must not
    have neutered it.
    """
    name = "t1_bound_still_discriminates_amplifier"
    d = fresh_dir()
    try:
        _build_20k(d)
        # Cold sweep seeds the tip (full verify, unbounded by design).
        v = verify_chain_tip(d / "actions.jsonl")
        assert v is None  # no tip yet -> None
        ok, _, _ = verify_chain(d / "actions.jsonl")
        assert ok
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        # Pre-R16 simulation: delete the tip before each sweep so
        # every sweep pays the full verification.
        dts = []
        for _ in range(3):
            _tip_cache_path(d / "actions.jsonl").unlink()
            t0 = time.process_time()
            ok, _, _ = verify_chain(d / "actions.jsonl")
            dts.append(time.process_time() - t0)
            assert ok
            write_chain_tip_from_tail(d / "actions.jsonl", {})
        worst = max(dts)
        if worst <= 0.150:
            check(name, "BREAK",
                  "full-verify amplifier no longer trips the bound "
                  "(worst %.0fms) -- metric change neutered the pin"
                  % (worst * 1000))
            return
        check(name, "HELD",
              "pre-R16 full-verify shape trips the bound: worst "
              "%.0fms CPU vs 150ms" % (worst * 1000))
    finally:
        cleanup(d)


def t1b_scan_amplifier_shape_visible_to_metric():
    """The O(sidecar) scan term the wave-112 change removed must be
    visible to process_time (else the metric couldn't pin it)."""
    name = "t1b_scan_amplifier_shape_visible_to_metric"
    d = fresh_dir()
    try:
        _build_20k(d)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        sidecar_len = (d / "checkpoints.jsonl").stat().st_size
        assert sidecar_len > 1_000_000, sidecar_len
        # Warm sweep, post-fix scan.
        t0 = time.process_time()
        v = verify_chain_tip(d / "actions.jsonl")
        dt_post = time.process_time() - t0
        assert v is not None and v["ok"]
        # Pre-F69 scan: force the whole-sidecar parse.
        full = (d / "checkpoints.jsonl").read_bytes()
        real = gov_log._max_pinned_tip_gen
        gov_log._max_pinned_tip_gen = (
            lambda b, k, e: real(full, k, e))
        try:
            t0 = time.process_time()
            v2 = verify_chain_tip(d / "actions.jsonl")
            dt_pre = time.process_time() - t0
        finally:
            gov_log._max_pinned_tip_gen = real
        assert v2 is not None and v2["ok"]
        if dt_pre < 3 * dt_post:
            check(name, "ERROR",
                  "setup wrong: whole-sidecar scan not costlier "
                  "(pre=%.0fms post=%.0fms)" %
                  (dt_pre * 1000, dt_post * 1000))
            return
        check(name, "HELD",
              "scan amplifier visible to process_time: whole-sidecar "
              "%.0fms vs pin_off %.0fms (%.1fx)" %
              (dt_pre * 1000, dt_post * 1000, dt_pre / dt_post))
    finally:
        cleanup(d)


def t2_warm_sweep_green_under_saturation():
    """Re-verify the wave-112 claim: warm sweeps stay under the
    150ms PROCESS-CPU bound with 2 CPUs saturated."""
    name = "t2_warm_sweep_green_under_saturation"
    d = fresh_dir()
    burners = []
    try:
        _build_20k(d)
        write_chain_tip_from_tail(d / "actions.jsonl", {})
        v = verify_chain_tip(d / "actions.jsonl")
        assert v is not None and v["ok"]
        for _ in range(2):
            burners.append(subprocess.Popen(
                [sys.executable, "-c", "while True: pass"]))
        time.sleep(1.0)  # let the burners saturate (wall only)
        worst = 0.0
        for k in range(6):
            t0 = time.process_time()
            v = verify_chain_tip(d / "actions.jsonl")
            dt = time.process_time() - t0
            worst = max(worst, dt)
            if v is None or not v.get("ok"):
                check(name, "BREAK",
                      "warm sweep %d failed under saturation" % k)
                return
            if dt > 0.150:
                check(name, "BREAK",
                      "warm sweep %d blew the bound under saturation: "
                      "%.0fms CPU" % (k, dt * 1000))
                return
        check(name, "HELD",
              "6/6 warm sweeps green under 2-CPU saturation, worst "
              "%.0fms CPU vs 150ms bound" % (worst * 1000))
    finally:
        for p in burners:
            p.kill()
        for p in burners:
            p.wait()
        cleanup(d)


def main():
    probes = [
        a1_forged_pin_with_huge_gen_ignored,
        a2_racy_genuine_pin_before_pin_off_benign,
        a3_truncate_to_cp_size_blinds_scan,
        b1_tip_pin_off_bitflip,
        b2_cross_tip_pin_off_transplant,
        b3_sidecar_prefix_bitflip,
        c1_grow_garbage,
        c2_grow_forged_pin_shape,
        c3_shrink_below_cp_size,
        c3b_truncate_below_pin_off,
        c4_replay_old_sidecar_prefix,
        d1_cross_log_anchor_fail_closed,
        d2_shared_gen_staleness_fail_closed,
        d3_wave112_delta_shared_pin_before_pin_off,
        t1_bound_still_discriminates_amplifier,
        t1b_scan_amplifier_shape_visible_to_metric,
        t2_warm_sweep_green_under_saturation,
    ]
    for probe in probes:
        try:
            probe()
        except Exception as e:  # noqa: BLE001
            check(probe.__name__, "ERROR", "%r" % (e,))
    held = sum(1 for _, v, _ in RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in RESULTS if v == "ERROR")
    print("RESULT: %d HELD / %d BREAK / %d ERROR of %d" % (
        held, brk, err, len(RESULTS)))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
