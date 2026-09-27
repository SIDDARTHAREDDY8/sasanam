"""Evidence-retention tiering break battery (RED-FIRST).

Gap under test: the hash-chained audit log (gov/log.py) has NO retention
story. The operator's only options today are:

  (a) keep every entry forever (the file grows; LogFullError eventually
      says "archive the log and start a fresh one");
  (b) archive + start fresh -- the archived log and the fresh log verify
      alone, but there is NO verifiable cryptographic continuity between
      them (the seam is unaudited);
  (c) truncate/rotate the file -- _verify fails closed (seq gap), with no
      legitimate, audited, recoverable path.

There is no policy mechanism (per-event-class TTLs), no summarization
with cryptographic continuity, no audited retire() operation.

Break = the retention gap is demonstrated (pre-seam), or a tiering
guarantee fails (post-seam).
Held = the tiering seam enforces the guarantee.

Probes:
  p1  retire seam exists (RetentionPolicy + retire_hot importable)
  p2  archive-and-fresh-start seam is unverifiable (pre) / retire_hot
      keeps continuity verifiable (post)
  p3  TTL enforcement: unexpired entries are never retired
  p4  warm summary commits to the exact retired set (digest chain +
      Merkle root; inclusion proof for a kept copy; tampered copy fails)
  p5  verify_tiered passes on a retired log (hot suffix + warm chain +
      marker<->summary cross-links)
  p6  deleting hot entries WITHOUT a covering summary is LOUD
  p7  crash ordering: summary-before-truncation; recovery is idempotent
      (no double summary, no second marker)
  p8  warm projections are a strict field subset; no secretish fields
  p9  warm->cold: retire_warm writes a checkpoint anchor; verify_tiered
      still passes with a truncated warm file
  p10 retirement is itself audited (chained evidence_retired event) and a
      never-retired log verifies identically under verify_tiered/_verify
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import json
import secrets
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "evidence-tier-battery")

from gov.log import ActionLog, LogFullError, _verify

try:
    from gov import evidence_tiers as et
    _HAVE_ET = True
except ImportError:
    et = None
    _HAVE_ET = False

RESULTS = []


def _record(name, held, note):
    RESULTS.append((name, "HELD" if held else "BREAK", note))
    print("  %-38s %-6s %s" % (name, "HELD" if held else "BREAK", note),
          flush=True)


def _mk_tmp():
    return tempfile.mkdtemp(prefix="evtier-",
                            dir=os.environ.get("TMPDIR", "/tmp"))


def _fresh_log(tmp, name="actions.jsonl"):
    return ActionLog(os.path.join(tmp, name))


def _policy(**kw):
    kw.setdefault("policy_id", "battery-policy")
    kw.setdefault("hot_ttl_by_event", {"*": 30 * 86400})
    kw.setdefault("warm_fields_by_event", {"*": ["event", "seq", "ts"]})
    kw.setdefault("warm_ttl_seconds", 365 * 86400)
    return et.RetentionPolicy(**kw)


def p1_retire_seam_exists():
    name = "p1_retire_seam_exists"
    if not _HAVE_ET:
        _record(name, False, "no retention-tiering seam: gov.evidence_tiers "
                "is not importable; retire_hot/RetentionPolicy do not exist")
        return
    ok = (hasattr(et, "retire_hot") and hasattr(et, "retire_warm")
          and hasattr(et, "verify_tiered") and hasattr(et, "RetentionPolicy"))
    _record(name, ok, "retire_hot/retire_warm/verify_tiered/RetentionPolicy "
            "present" if ok else "seam present but API incomplete")


def p2_continuity_seam():
    name = "p2_continuity_seam"
    if not _HAVE_ET:
        # Pre-seam: demonstrate the gap behaviorally. The documented
        # LogFullError recovery ("archive the log and start a fresh one")
        # yields two logs with no verifiable continuity between them.
        tmp = _mk_tmp()
        log = ActionLog(os.path.join(tmp, "actions.jsonl"), max_bytes=400)
        try:
            for i in range(50):
                log.append({"event": "probe", "i": i})
            _record(name, False, "expected LogFullError, log stayed small")
            return
        except LogFullError:
            pass
        # Operator follows the advice: archive + fresh start.
        archive = os.path.join(tmp, "actions.jsonl")
        fresh_path = os.path.join(tmp, "fresh.jsonl")
        v_old = _verify(archive)
        ActionLog(fresh_path).append({"event": "probe", "i": "new"})
        v_new = _verify(fresh_path)
        linked = False  # no mechanism links the two logs
        _record(name, linked,
                "archive verifies=%s fresh verifies=%s but continuity "
                "between them is unverifiable: no seam links archive to "
                "fresh log (BREAK = the gap)" % (v_old["ok"], v_new["ok"]))
        return
    # Post-seam: retire_hot keeps the chain verifiable end-to-end.
    tmp = _mk_tmp()
    log = _fresh_log(tmp)
    for i in range(6):
        log.append({"event": "probe", "i": i})
    path = os.path.join(tmp, "actions.jsonl")
    entries = et._read_hot_entries(path)
    now = et._parse_ts(entries[-1]["ts"]) + timedelta(days=31)
    res = et.retire_hot(path, _policy(), now=now)
    v = et.verify_tiered(path, _policy())
    _record(name, bool(v["ok"]) and res["retired"] == 6,
            "retired=%s verify_tiered ok=%s (%s)"
            % (res["retired"], v["ok"], v.get("error")))


def p3_ttl_enforcement():
    name = "p3_ttl_enforcement"
    if not _HAVE_ET:
        _record(name, False, "no TTL policy mechanism exists: per-event-class "
                "retention cannot even be expressed, let alone enforced")
        return
    tmp = _mk_tmp()
    log = _fresh_log(tmp)
    for i in range(4):
        log.append({"event": "debug", "i": i})       # 1-day TTL
    for i in range(4):
        log.append({"event": "approval", "i": i})    # 30-day TTL
    path = os.path.join(tmp, "actions.jsonl")
    entries = et._read_hot_entries(path)
    base = et._parse_ts(entries[0]["ts"])
    policy = _policy(hot_ttl_by_event={"*": 30 * 86400, "debug": 86400})
    # now = base + 2 days: debug expired, approval not.
    res = et.retire_hot(path, policy, now=base + timedelta(days=2))
    remaining = et._read_hot_entries(path)
    kinds = [e.get("event") for e in remaining if not e.get("event", "")
             .startswith("evidence_")]
    ok = (res["retired"] == 4 and kinds == ["approval"] * 4)
    # Negative: now = base + 12h -> nothing eligible -> no-op, file intact.
    tmp2 = _mk_tmp()
    log2 = _fresh_log(tmp2)
    for i in range(3):
        log2.append({"event": "approval", "i": i})
    path2 = os.path.join(tmp2, "actions.jsonl")
    e2 = et._read_hot_entries(path2)
    n_before = len(e2)
    res2 = et.retire_hot(path2, policy,
                         now=et._parse_ts(e2[0]["ts"]) + timedelta(hours=12))
    n_after = len(et._read_hot_entries(path2))
    ok = ok and res2["retired"] == 0 and n_before == n_after
    _record(name, ok, "expired-prefix retired=%s, unexpired untouched "
            "(early retire no-op retired=%s)" % (res["retired"],
                                                res2["retired"]))


def p4_summary_commitment():
    name = "p4_summary_commitment"
    if not _HAVE_ET:
        _record(name, False, "seam absent: no warm summary commitment to test")
        return
    tmp = _mk_tmp()
    log = _fresh_log(tmp)
    for i in range(8):
        log.append({"event": "probe", "i": i, "note": "keep"})
    path = os.path.join(tmp, "actions.jsonl")
    entries = et._read_hot_entries(path)
    kept = [dict(e) for e in entries]  # operator backup of retired entries
    now = et._parse_ts(entries[-1]["ts"]) + timedelta(days=31)
    res = et.retire_hot(path, _policy(), now=now)
    warm_path = os.path.join(tmp, "warm.jsonl")
    summaries = et._read_tier_entries(warm_path)
    if len(summaries) != 1:
        _record(name, False, "expected 1 warm summary, got %d"
                % len(summaries))
        return
    s = summaries[0]
    fields_ok = all(k in s for k in ("first_seq", "last_seq", "count",
                                    "entry_digest_chain", "merkle_root",
                                    "truncation_hash", "summary_digest"))
    chain_ok = (s["first_seq"] == 1 and s["last_seq"] == 8
                and s["count"] == 8
                and s["truncation_hash"] == kept[-1]["hash"])
    # Recompute the chained digest from the kept copies: must match.
    recomputed = et._entry_digest_chain(
        1, [e["hash"] for e in kept])
    digest_ok = (recomputed == s["entry_digest_chain"])
    # Inclusion proof for a kept copy; tampered copy must fail.
    idx = 3
    proof = et.prove_inclusion_in_summary(kept[idx], idx, kept)
    inc_ok = et.verify_inclusion_in_summary(kept[idx], idx, proof, s)
    tampered = dict(kept[idx])
    tampered["note"] = "forged"
    tamper_ok = not et.verify_inclusion_in_summary(tampered, idx, proof, s)
    ok = fields_ok and chain_ok and digest_ok and inc_ok and tamper_ok
    _record(name, ok, "fields=%s range=%s digest_recompute=%s inclusion=%s "
            "tamper_rejected=%s" % (fields_ok, chain_ok, digest_ok, inc_ok,
                                   tamper_ok))


def p5_verify_tiered_green():
    name = "p5_verify_tiered_green"
    if not _HAVE_ET:
        _record(name, False, "seam absent: no tiered verifier to test")
        return
    tmp = _mk_tmp()
    log = _fresh_log(tmp)
    for i in range(5):
        log.append({"event": "probe", "i": i})
    path = os.path.join(tmp, "actions.jsonl")
    entries = et._read_hot_entries(path)
    now = et._parse_ts(entries[-1]["ts"]) + timedelta(days=31)
    et.retire_hot(path, _policy(), now=now)
    # Append post-retirement entries: the suffix must keep chaining.
    log2 = ActionLog(path)
    for i in range(3):
        log2.append({"event": "probe", "i": "post-%d" % i})
    v = et.verify_tiered(path, _policy())
    ok = bool(v["ok"]) and not v.get("error")
    # Second retirement on the grown log must also verify.
    entries2 = et._read_hot_entries(path)
    now2 = et._parse_ts(entries2[-1]["ts"]) + timedelta(days=31)
    et.retire_hot(path, _policy(), now=now2)
    v2 = et.verify_tiered(path, _policy())
    ok = ok and bool(v2["ok"])
    _record(name, ok, "verify after retire+append ok=%s, after 2nd retire "
            "ok=%s (%s)" % (v["ok"], v2["ok"], v2.get("error")))


def p6_deletion_without_summary_loud():
    name = "p6_deletion_without_summary_loud"
    if not _HAVE_ET:
        _record(name, False, "seam absent: tiered deletion has no detector")
        return
    tmp = _mk_tmp()
    log = _fresh_log(tmp)
    for i in range(6):
        log.append({"event": "probe", "i": i})
    path = os.path.join(tmp, "actions.jsonl")
    entries = et._read_hot_entries(path)
    now = et._parse_ts(entries[-1]["ts"]) + timedelta(days=31)
    et.retire_hot(path, _policy(), now=now)
    # Grow the live region again, then delete entries WITHOUT a
    # covering summary.
    log2 = ActionLog(path)
    for i in range(4):
        log2.append({"event": "probe", "i": "live-%d" % i})
    lines = open(path, encoding="utf-8").read().splitlines()
    # lines[0] = marker, lines[1..4] = live entries. Drop 2 middles.
    assert len(lines) == 5, len(lines)
    evil = [lines[0], lines[1], lines[4]]
    open(path, "w", encoding="utf-8").write("\n".join(evil) + "\n")
    v = et.verify_tiered(path, _policy())
    loud_hot = (not v["ok"]) and bool(v.get("error"))
    # Adversary: tamper with a warm summary's commitment.
    tmp2 = _mk_tmp()
    log2 = _fresh_log(tmp2)
    for i in range(4):
        log2.append({"event": "probe", "i": i})
    path2 = os.path.join(tmp2, "actions.jsonl")
    e2 = et._read_hot_entries(path2)
    et.retire_hot(path2, _policy(),
                  now=et._parse_ts(e2[-1]["ts"]) + timedelta(days=31))
    warm_path2 = os.path.join(tmp2, "warm.jsonl")
    wlines = open(warm_path2, encoding="utf-8").read().splitlines()
    w = json.loads(wlines[0])
    w["merkle_root"] = "00" * 32
    wlines[0] = json.dumps(w)
    open(warm_path2, "w", encoding="utf-8").write("\n".join(wlines) + "\n")
    v2 = et.verify_tiered(path2, _policy())
    loud_warm = (not v2["ok"]) and bool(v2.get("error"))
    # Neither detector may raise: verdicts, not exceptions.
    _record(name, loud_hot and loud_warm,
            "hot deletion loud=%s (%s); warm tamper loud=%s (%s)"
            % (loud_hot, v.get("error"), loud_warm, v2.get("error")))


def p7_crash_idempotency():
    name = "p7_crash_idempotency"
    if not _HAVE_ET:
        _record(name, False, "seam absent: no crash-safe retire to test")
        return
    tmp = _mk_tmp()
    log = _fresh_log(tmp)
    for i in range(6):
        log.append({"event": "probe", "i": i})
    path = os.path.join(tmp, "actions.jsonl")
    entries = et._read_hot_entries(path)
    now = et._parse_ts(entries[-1]["ts"]) + timedelta(days=31)
    policy = _policy()
    # Crash simulation 1: summary written, process dies before the marker.
    cand = et._eligible_prefix_for_retire(path, policy, now)
    summary = et._build_warm_summary(cand, policy, now)
    et._append_warm_summary(os.path.join(tmp, "warm.jsonl"), summary)
    n_warm_before = len(et._read_tier_entries(os.path.join(tmp, "warm.jsonl")))
    res = et.retire_hot(path, policy, now=now)  # must reuse, not duplicate
    n_warm_after = len(et._read_tier_entries(os.path.join(tmp, "warm.jsonl")))
    no_dup = (n_warm_after == n_warm_before)
    # Crash simulation 2: marker appended, process dies before truncation.
    tmp2 = _mk_tmp()
    log2 = _fresh_log(tmp2)
    for i in range(6):
        log2.append({"event": "probe", "i": i})
    path2 = os.path.join(tmp2, "actions.jsonl")
    e2 = et._read_hot_entries(path2)
    now2 = et._parse_ts(e2[-1]["ts"]) + timedelta(days=31)
    cand2 = et._eligible_prefix_for_retire(path2, policy, now2)
    s2 = et._build_warm_summary(cand2, policy, now2)
    w2 = et._append_warm_summary(os.path.join(tmp2, "warm.jsonl"), s2)
    et._append_retirement_marker(path2, policy, cand2, w2, now2)
    n_hot_before = len(et._read_hot_entries(path2))
    res2 = et.retire_hot(path2, policy, now=now2)  # must complete truncation
    hot_after = et._read_hot_entries(path2)
    n_markers = sum(1 for e in hot_after
                    if e.get("event") == "evidence_retired")
    completed = (len(hot_after) == 1 and n_markers == 1
                 and res2.get("recovered") is True)
    # Re-running a completed retire is a safe no-op.
    res3 = et.retire_hot(path, policy, now=now)
    noop = (res3["retired"] == 0)
    v = et.verify_tiered(path2, policy)
    ok = no_dup and completed and noop and bool(v["ok"])
    _record(name, ok, "orphan-summary reused (no dup)=%s; marker-crash "
            "completed=%s; rerun no-op=%s; verify ok=%s"
            % (no_dup, completed, noop, v["ok"]))


def p8_warm_subset():
    name = "p8_warm_subset"
    if not _HAVE_ET:
        _record(name, False, "seam absent: no warm schema to test")
        return
    tmp = _mk_tmp()
    log = _fresh_log(tmp)
    for i in range(5):
        log.append({"event": "approval",
                    "principal": "agent-%d" % i,
                    "action": "read",
                    "api_secret_donotinclude": "sekrit-%d" % i})
    path = os.path.join(tmp, "actions.jsonl")
    entries = et._read_hot_entries(path)
    now = et._parse_ts(entries[-1]["ts"]) + timedelta(days=31)
    # A policy asking for a secretish field must be refused at build time.
    refused = False
    try:
        et.RetentionPolicy(policy_id="evil",
                           hot_ttl_by_event={"*": 1},
                           warm_fields_by_event={"*": ["event",
                                                       "api_secret_donotinclude"]},
                           warm_ttl_seconds=10)
    except ValueError:
        refused = True
    et.retire_hot(path, _policy(), now=now)
    summaries = et._read_tier_entries(os.path.join(tmp, "warm.jsonl"))
    s = summaries[0]
    subset_ok = True
    for proj, orig in zip(s["projections"], entries):
        if not set(proj.keys()) <= set(orig.keys()):
            subset_ok = False
        if not set(proj.keys()) < set(orig.keys()):
            subset_ok = False  # must be STRICT
    leak = any("sekrit" in json.dumps(p) or "api_secret" in json.dumps(p)
               for p in s["projections"])
    ok = refused and subset_ok and not leak
    _record(name, ok, "secretish policy refused=%s; projections strict "
            "subset=%s; no secret material=%s" % (refused, subset_ok,
                                                 not leak))


def p9_cold_anchor():
    name = "p9_cold_anchor"
    if not _HAVE_ET:
        _record(name, False, "seam absent: no cold anchoring to test")
        return
    tmp = _mk_tmp()
    log = _fresh_log(tmp)
    for i in range(6):
        log.append({"event": "probe", "i": i})
    path = os.path.join(tmp, "actions.jsonl")
    entries = et._read_hot_entries(path)
    now = et._parse_ts(entries[-1]["ts"]) + timedelta(days=31)
    policy = _policy(warm_ttl_seconds=10)  # warm ages fast for the test
    et.retire_hot(path, policy, now=now)
    warm_path = os.path.join(tmp, "warm.jsonl")
    n_warm_before = len(et._read_tier_entries(warm_path))
    # Age the warm summaries past the warm TTL, then anchor to cold.
    res = et.retire_warm(path, policy,
                         now=et._parse_ts(
                             et._read_tier_entries(warm_path)[-1]["ts"])
                         + timedelta(seconds=11))
    cold = et._read_tier_entries(os.path.join(tmp, "cold.jsonl"))
    v = et.verify_tiered(path, policy)
    ok = (res["anchored"] == n_warm_before and len(cold) == 1
          and bool(v["ok"]))
    # The anchor commits to the warm summaries it replaced.
    a = cold[0]
    anchor_ok = all(k in a for k in ("first_warm_seq", "last_warm_seq",
                                    "merkle_root", "warm_head_hash"))
    _record(name, ok and anchor_ok,
            "anchored=%s cold_entries=%s verify ok=%s anchor_fields=%s (%s)"
            % (res["anchored"], len(cold), v["ok"], anchor_ok,
               v.get("error")))


def p10_retirement_audited_and_passthrough():
    name = "p10_retirement_audited_and_passthrough"
    if not _HAVE_ET:
        _record(name, False, "seam absent: nothing to audit")
        return
    tmp = _mk_tmp()
    log = _fresh_log(tmp)
    for i in range(4):
        log.append({"event": "probe", "i": i})
    path = os.path.join(tmp, "actions.jsonl")
    entries = et._read_hot_entries(path)
    now = et._parse_ts(entries[-1]["ts"]) + timedelta(days=31)
    policy = _policy()
    et.retire_hot(path, policy, now=now)
    hot = et._read_hot_entries(path)
    markers = [e for e in hot if e.get("event") == "evidence_retired"]
    audited = (len(markers) == 1
               and markers[0]["first_seq"] == 1
               and markers[0]["last_seq"] == 4
               and markers[0]["tier_policy"] == "battery-policy"
               and "summary_digest" in markers[0])
    # A never-retired log verifies identically under both verifiers.
    tmp2 = _mk_tmp()
    log2 = _fresh_log(tmp2)
    for i in range(3):
        log2.append({"event": "probe", "i": i})
    path2 = os.path.join(tmp2, "actions.jsonl")
    v_old = _verify(path2)
    v_new = et.verify_tiered(path2, policy)
    passthrough = (v_old["ok"] and v_new["ok"]
                   and v_old["entries"] == v_new["hot"]["entries"])
    _record(name, audited and passthrough,
            "retirement chained+audit fields=%s; passthrough entries=%s/%s"
            % (audited, v_old["entries"], v_new["hot"]["entries"]))


def main():
    print("evidence_tier_probes: gov.evidence_tiers %s"
          % ("PRESENT" if _HAVE_ET else "ABSENT (pre-seam red)"), flush=True)
    for probe in (p1_retire_seam_exists,
                  p2_continuity_seam,
                  p3_ttl_enforcement,
                  p4_summary_commitment,
                  p5_verify_tiered_green,
                  p6_deletion_without_summary_loud,
                  p7_crash_idempotency,
                  p8_warm_subset,
                  p9_cold_anchor,
                  p10_retirement_audited_and_passthrough):
        try:
            probe()
        except Exception as e:  # loud, never silent
            _record(probe.__name__, False, "ERROR %r" % e)
    n_break = sum(1 for _, s, _ in RESULTS if s == "BREAK")
    n_held = sum(1 for _, s, _ in RESULTS if s == "HELD")
    n_err = sum(1 for _, s, _ in RESULTS if s == "ERROR")
    print("evidence_tier_probes: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err), flush=True)
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
