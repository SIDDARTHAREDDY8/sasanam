#!/usr/bin/env python3
"""Wave-179 lane B: receipt-swap / digest-pointer pressure on decision-packet
digest chaining (in-toto MATCH probe, wave-178 PROSPECTUS.md §1.2).

Break-first battery per the diagnosing-bugs skill: each probe attacks a
concrete seam and reports BREAK (gap demonstrated) or HELD (defense held).
The product code is UNMODIFIED; every probe runs against the pristine tree.

Falsifiable question (PROSPECTUS §1.2, steal-worthy #2): "swap two
receipts' outputs between consecutive decisions in a trajectory and check
whether decision-packet verification catches it. If it does not, our
chaining is opaque-digest chaining, not MATCH chaining."

Probe plan (real modules, real HMAC-chained log, real Ed25519 signatures;
a two-decision trajectory: decision -> decision_packet -> invocation_receipt,
twice):
  V0 sanity: untampered trajectory verifies everywhere (A/B/C/D all PASS).
  V1 field-level output swap: outcome.result_digest swapped between the two
     receipts -> HELD (receipt Ed25519 signatures + keyed chain catch it;
     packet verification and the offline core are blind -- receipts are
     outside their scope).
  V2 whole-receipt transplant: the two receipt dicts swap entries, entry
     envelopes (seq/prev_hash/hash) kept in place -> HELD (F196 closure):
     the packet verifier's packet<->receipt pairing check fails closed
     because the transplanted receipt's inner approval_id no longer
     matches the packet it answers; the keyed chain walk catches it too.
  V3 entry reorder (whole entries swap positions) -> HELD (seq/pointer
     walk + keyed chain).
  V4 entry drop -> HELD (seq-gap detection + keyed chain).
  V5 decision_digest pointer swap at mint time (key-holding executor or
     minting bug: packet 1 carries decision 2's decision_digest) -> HELD
     (F196 closure): the packet verifier re-derives decision_digest from
     the chained decision entry named by evidence.head_digest and fails
     closed on mismatch.
  V6 receipt misattribution at mint time (key-holding executor or minting
     bug: the receipt chained as decision 1's carries decision 2's
     approval_id/challenge/result, with valid MACs/signatures) -> HELD
     (F196 closure): the packet verifier's pairing check fails closed
     when the answering receipt's inner approval_id differs from the
     packet's.
     (F196): NO verifier correlates a receipt with its decision packet;
     approval_id/challenge are unchecked strings.

Verifier suite per variant:
  A. verify_decision_packet(packet, entries) -- the packet seam
  B. verify_receipt(receipt)                 -- the receipt seam
  C. offline core: seq contiguity + prev_hash pointer walk + standalone
     receipt verification (mirrors gov/evidence_verify v9/v17; the
     offline auditor holds no HMAC key, so entry MACs are NOT checked --
     exactly like the real offline path)
  D. verify_chain(log file)                  -- the keyed online path

Deterministic; synthetic/local only; $0. Exit nonzero only on harness
errors or green-check failures -- BREAK is the expected red-team outcome
(F196 filed), not a battery failure.
"""

import copy
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

TREE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TREE))

# Fresh keys per run: the battery must not depend on ambient key config.
os.environ["GOV_LOG_KEY"] = secrets.token_hex(32)
os.environ["GOV_LOG_KEY_EPOCH"] = "receiptswap-battery"
os.environ["GOV_DECISION_PACKET_KEY"] = "ab" * 32
os.environ["GOV_RECEIPT_KEY"] = "cd" * 32

from gov import log as _log
from gov import decision_packet as _dp
from gov import decision_bom as _bommod
from gov import invocation_receipts as _rc

_records = []


def _record(name, outcome, detail):
    _records.append((name, outcome, detail))


def _bom_for(*, head_digest, approval_id):
    """Decision BOM consistent with this battery's packets (wave-180:
    the packet builder requires it). The approval record digest is a
    deterministic fixture -- this battery tests packet<->receipt
    attribution, not approval HMAC validity."""
    record_digest = None
    if approval_id is not None:
        record_digest = hashlib.sha256(
            ("approval-record:%s" % approval_id).encode()).hexdigest()
    return _bommod.build_bom(
        policy_id="pol", policy_version="1",
        policy_digest="ab" * 32,
        evidence_head_digest=head_digest,
        principal={"agent_id": "ag", "role": "coder",
                   "principal": "p", "run_id": "run1"},
        approval_id=approval_id,
        approval_record_digest=record_digest)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode()


def _build_trajectory(run_dir, *, p1_digest_override=None,
                      r1_attribution_override=None):
    """Real two-decision trajectory. Returns (log_path, entries)."""
    log_path = str(Path(run_dir) / "audit.jsonl")
    alog = _log.ActionLog(log_path)
    rkey = _rc.resolve_receipt_key(explicit="cd" * 32)
    for i in (1, 2):
        aid = "A%d" % i
        pol_decision = {"policy_id": "pol", "decision": "allow",
                        "tool": "write_file",
                        "target": "/data/out%d.txt" % i,
                        "approval_id": aid, "decision_seq": i}
        e_dec = alog.append({"event": "decision",
                             "approval_id": aid,
                             "decision_seq": i,
                             "tool": "write_file",
                             "decision": "allow",
                             "policy_decision": pol_decision})
        dd = _sha(_canonical(pol_decision))
        if i == 1 and p1_digest_override is not None:
            dd = p1_digest_override
        body = _dp.build_decision_packet(
            decision="allow", boundary_declared=False,
            policy_id="pol", policy_version="1",
            matched_rules=["r1"], policy_flag=None,
            decision_digest=dd,
            canonical_target="/data/out%d.txt" % i,
            preview_digest=_sha(b"preview%d" % i),
            approval_id=aid, decision_seq=i,
            evidence_head_digest=e_dec["hash"],
            identity={"agent_id": "ag", "role": "coder",
                      "principal": "p", "run_id": "run1"},
            policy_bundle_digest="ab" * 32,
            bill_of_materials=_bom_for(head_digest=e_dec["hash"],
                                       approval_id=aid))
        packet = _dp.sign_packet(body, bytes.fromhex("ab" * 32))
        alog.append({"event": "decision_packet",
                     "approval_id": aid,
                     "decision_seq": i,
                     "packet_digest": _dp.packet_digest(packet),
                     "packet": packet})
        att = {"approval_id": aid, "challenge": aid,
               "result": "output-of-decision-%d" % i}
        if i == 1 and r1_attribution_override is not None:
            att = dict(r1_attribution_override)
        rbody = _rc.build_receipt(
            holder={"agent_id": "ag", "role": "coder",
                    "principal": "p", "run_id": "run1"},
            challenge=att["challenge"],
            action_tool="write_file",
            action_args={"path": "/data/out%d.txt" % i},
            canonical_target="/data/out%d.txt" % i,
            policy_decision="execution_authorized",
            approval_id=att["approval_id"],
            policy_id="pol",
            preview_text="preview%d" % i,
            outcome_status="executed",
            result=att["result"],
            key_id=rkey["key_id"], pubkey_hex=rkey["pubkey_hex"])
        receipt = _rc.countersign(rbody, bytes.fromhex("cd" * 32))
        alog.append({"event": "invocation_receipt",
                     "approval_id": aid,
                     "decision_seq": i,
                     "receipt": receipt})
    return log_path, _log.read_entries(log_path)


def _offline_core(entries):
    """V9-equivalent: seq contiguity + prev_hash pointer walk (no HMAC:
    the offline auditor holds no key)."""
    if not entries:
        return False, "empty"
    seqs = [e.get("seq") for e in entries]
    if seqs != list(range(seqs[0], seqs[0] + len(seqs))):
        return False, "seq not contiguous"
    for prev, cur in zip(entries, entries[1:]):
        if cur.get("prev_hash") != prev.get("hash"):
            return False, "pointer break seq %s->%s" % (
                prev.get("seq"), cur.get("seq"))
    return True, "ok"


def _run_suite(entries, log_path=None):
    out = {}
    packets = [e["packet"] for e in entries
               if e.get("event") == "decision_packet"]
    receipts = [(e.get("seq"), e.get("receipt")) for e in entries
                if e.get("event") == "invocation_receipt"]
    a_ok, a_r = True, []
    for p in packets:
        ok, reason = _dp.verify_decision_packet(p, entries)
        a_ok = a_ok and ok
        a_r.append(reason)
    out["A"] = (a_ok, "; ".join(a_r))
    b_ok, b_r = True, []
    for seq, r in receipts:
        ok, reason = _rc.verify_receipt(r)
        b_ok = b_ok and ok
        if not ok:
            b_r.append("seq %s: %s" % (seq, reason))
    out["B"] = (b_ok, "; ".join(b_r) or "ok")
    out["C"] = _offline_core(entries)
    if log_path is not None:
        ok, broken, _n = _log.verify_chain(log_path)
        out["D"] = (ok, "ok" if ok else "broken at seq %s" % (broken,))
    return out


def _fmt(suite):
    return " ".join("%s=%s" % (k, "PASS" if v[0] else "FAIL")
                    for k, v in suite.items())


def _fresh_dir():
    return tempfile.mkdtemp(prefix="g179rs-", dir="/var/tmp")


def _write_entries(path, entries):
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, separators=(",", ":"),
                               ensure_ascii=True, default=str) + "\n")


def p_v0_baseline():
    """Sanity: untampered trajectory verifies everywhere."""
    d = _fresh_dir()
    log_path, entries = _build_trajectory(d)
    suite = _run_suite(entries, log_path)
    ok = all(v[0] for v in suite.values())
    _record("V0 baseline", "HELD" if ok else "ERROR", _fmt(suite))
    return not ok


def p_v1_field_swap():
    """Swap outcome.result_digest between the two receipts (entries
    rewritten). Expect HELD: receipt signatures + keyed chain catch it."""
    d = _fresh_dir()
    _lp, entries = _build_trajectory(d)
    t = copy.deepcopy(entries)
    rs = [e for e in t if e.get("event") == "invocation_receipt"]
    o1 = rs[0]["receipt"]["outcome"]["result_digest"]
    rs[0]["receipt"]["outcome"]["result_digest"] = \
        rs[1]["receipt"]["outcome"]["result_digest"]
    rs[1]["receipt"]["outcome"]["result_digest"] = o1
    tp = str(Path(_fresh_dir()) / "t.jsonl")
    _write_entries(tp, t)
    suite = _run_suite(t, tp)
    held = (not suite["B"][0] and not suite["D"][0])
    _record("V1 field-level output swap", "HELD" if held else "BREAK",
            "%s -- receipt sigs + keyed chain catch it; packet verify "
            "and offline core blind (receipts out of scope)" % _fmt(suite))
    return not held


def p_v2_transplant():
    """Swap whole receipt dicts between the two receipt entries
    (envelopes kept). Expect HELD (F196 closure): the packet verifier's
    pairing check fails closed on the transplanted receipt's inner
    approval_id; the keyed chain (D) catches it too."""
    d = _fresh_dir()
    _lp, entries = _build_trajectory(d)
    t = copy.deepcopy(entries)
    rs = [e for e in t if e.get("event") == "invocation_receipt"]
    rs[0]["receipt"], rs[1]["receipt"] = \
        rs[1]["receipt"], rs[0]["receipt"]
    tp = str(Path(_fresh_dir()) / "t.jsonl")
    _write_entries(tp, t)
    suite = _run_suite(t, tp)
    offline_blind = suite["A"][0] and suite["B"][0] and suite["C"][0]
    _record("V2 whole-receipt transplant",
            "BREAK" if offline_blind else "HELD",
            "%s -- F196 pairing check + keyed chain catch the transplant"
            % _fmt(suite))
    return offline_blind


def p_v3_reorder():
    """Swap positions of two adjacent whole entries. Expect HELD."""
    d = _fresh_dir()
    _lp, entries = _build_trajectory(d)
    t = copy.deepcopy(entries)
    t[2], t[3] = t[3], t[2]
    tp = str(Path(_fresh_dir()) / "t.jsonl")
    _write_entries(tp, t)
    suite = _run_suite(t, tp)
    held = (not suite["D"][0] and not suite["C"][0])
    _record("V3 entry reorder", "HELD" if held else "BREAK", _fmt(suite))
    return not held


def p_v4_drop():
    """Delete one receipt entry. Expect HELD."""
    d = _fresh_dir()
    _lp, entries = _build_trajectory(d)
    t = [e for e in copy.deepcopy(entries)
         if not (e.get("event") == "invocation_receipt"
                 and e.get("decision_seq") == 1)]
    tp = str(Path(_fresh_dir()) / "t.jsonl")
    _write_entries(tp, t)
    suite = _run_suite(t, tp)
    held = (not suite["D"][0] and not suite["C"][0])
    _record("V4 entry drop", "HELD" if held else "BREAK", _fmt(suite))
    return not held


def p_v5_digest_pointer():
    """Mint-time: packet 1 carries decision 2's decision_digest
    (key-holding executor / minting bug). Expect HELD (F196 closure):
    the verifier re-derives decision_digest from the chained decision
    entry and fails closed on mismatch."""
    d = _fresh_dir()
    d2_pol = {"policy_id": "pol", "decision": "allow",
              "tool": "write_file", "target": "/data/out2.txt",
              "approval_id": "A2", "decision_seq": 2}
    log_path, entries = _build_trajectory(
        d, p1_digest_override=_sha(_canonical(d2_pol)))
    suite = _run_suite(entries, log_path)
    blind = all(v[0] for v in suite.values())
    _record("V5 decision_digest pointer swap", "BREAK" if blind else "HELD",
            "%s -- F196: decision_digest re-derived from the chained "
            "decision entry (MATCH binding)" % _fmt(suite))
    return blind


def p_v6_misattribution():
    """Mint-time: receipt chained as decision 1's carries decision 2's
    approval_id/challenge/result (key-holding executor / minting bug).
    Expect HELD (F196 closure): the verifier's packet<->receipt pairing
    check fails closed on the inner/outer approval_id mismatch."""
    d = _fresh_dir()
    log_path, entries = _build_trajectory(
        d, r1_attribution_override={"approval_id": "A2",
                                    "challenge": "A2",
                                    "result": "output-of-decision-2"})
    suite = _run_suite(entries, log_path)
    blind = all(v[0] for v in suite.values())
    _record("V6 receipt misattribution", "BREAK" if blind else "HELD",
            "%s -- F196: packet<->receipt pairing on "
            "(approval_id, decision_seq)" % _fmt(suite))
    return blind


# -- green check (depth-1) --------------------------------------------------

def _green_check():
    """Run the adjacent decision-packet battery as a canary (child env
    GOV_SKIP_GREEN=1, depth-1 per convention)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green_check", "SKIP",
                "GOV_SKIP_GREEN=1; standalone run still checks itself")
        return
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    p = subprocess.run(
        [sys.executable, str(TREE / "evals/decision_packet_probes.py")],
        cwd=str(TREE), env=env, capture_output=True, text=True,
        timeout=600)
    tail = (p.stdout + p.stderr).strip().splitlines()[-3:]
    _record("green_check_decision_packet_probes",
            "PASS" if p.returncode == 0 else "FAIL",
            "exit=%d tail=%r" % (p.returncode, " | ".join(tail)))


def main():
    probes = [p_v0_baseline, p_v1_field_swap, p_v2_transplant,
              p_v3_reorder, p_v4_drop, p_v5_digest_pointer,
              p_v6_misattribution]
    for probe in probes:
        try:
            probe()
        except Exception as e:  # noqa: BLE001 -- red must be loud
            _record(probe.__name__, "ERROR", "%s: %s" % (
                type(e).__name__, e))
    _green_check()
    print("== receipt-swap probes: decision-packet digest chaining ==")
    n_break = n_held = n_err = n_skip = n_pass = 0
    for name, outcome, detail in _records:
        print("%-38s %-6s %s" % (name, outcome, detail))
        if outcome == "BREAK":
            n_break += 1
        elif outcome == "HELD":
            n_held += 1
        elif outcome == "SKIP":
            n_skip += 1
        elif outcome == "PASS":
            n_pass += 1
        else:
            n_err += 1
    print("breaks=%d held=%d canaries_pass=%d errors=%d skipped=%d" % (
        n_break, n_held, n_pass, n_err, n_skip))
    # Exit nonzero only on harness errors or green-check failures;
    # BREAK is the expected red-team outcome (F196 filed), not a
    # battery failure.
    bad = any(o not in ("BREAK", "HELD", "SKIP", "PASS")
              for _, o, _ in _records)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
