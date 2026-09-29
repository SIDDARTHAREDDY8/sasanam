#!/usr/bin/env python3
"""Red-first break battery for wave-202 lane D: decision-log event shape v2.

The gap (pristine tree): decision verdicts are logged to the hash-chained
audit log with a ``decision_trace`` (v1) that carries NO content-derived
identity, NO self-recorded redaction discipline (nothing proves WHAT was
withheld from the log), and NO replay-capture contract an auditor can
re-run. A producer can log a decision whose redaction claims are
unverifiable, and nothing binds the event's sections together.
``gov.decision_log_v2`` does not exist on the pristine tree.

Pristine expectation: P0 BREAK (the gap), P1-P9 EXPECTED (cannot run
without the module -- recorded, not faked green).
Fixed expectation: P0-P9 HELD.

Stdlib only. Deterministic (no clock, no randomness). Sets
GOV_DEPLOYMENT_MODE=staging at module level; verify standalone under
``env -u GOV_DEPLOYMENT_MODE``. Honors GOV_SKIP_GREEN=1 (green check is
depth-1: the adjacent unit suite only, never nested battery mains).
"""

import copy
import importlib.util
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json  # noqa: E402
import secrets  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402

# The battery touches the real hash-chained audit log (P5/P6): provision
# an explicit throwaway key through the same env backend production
# uses (adaptive_drift_probes.py precedent). Nothing shared, nothing
# public, no fallback.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "decision-log-v2-battery")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"
_HAS_MODULE = importlib.util.find_spec("gov.decision_log_v2") is not None

MARKER = "SENSITIVE-REQUEST-CONTENT-MARKER-202D"


def _honest_event():
    from gov import decision_log_v2 as dlv
    decision = {"kind": "tool_call", "effect": "deny",
                "policy_id": "p1", "reason": "rule r1 matched"}
    raw = {"agent_id": "a1", "ssn": "121-34-5678",
           "note": "request %s payload" % MARKER,
           "nested": {"token": "sekret-%s" % MARKER, "level": 3}}
    inputs = {"rules": [{"id": "r1", "effect": "deny",
                         "match": {"role": "intern"}}],
              "request": {"role": "intern", "tool": "read"}}
    verdict = {"effect": "deny", "matched_rule": "r1",
               "reason": "deny-first: rule r1 matched"}
    event = dlv.build_event(
        decision=decision, raw_body=raw,
        erased=["/ssn"], masked=["/nested/token"],
        replay_fn="deny_first_rules",
        replay_inputs=inputs, replay_verdict=verdict)
    return dlv, event, raw


def _reid(dlv, event):
    forged = copy.deepcopy(event)
    forged["decision_id"] = dlv._decision_id_for(forged)
    return forged


def p0_module_present():
    if not _HAS_MODULE:
        return "BREAK", "gov.decision_log_v2 absent (the gap)"
    dlv, event, _ = _honest_event()
    try:
        dlv.verify_event(event)
    except Exception as e:  # noqa: BLE001
        return "BREAK", "honest event does not verify: %r" % (e,)
    return "HELD", "module present; honest event verifies"


def p1_redaction_lie_dropped_pointer():
    if not _HAS_MODULE:
        return "EXPECTED", "needs gov.decision_log_v2"
    dlv, event, _ = _honest_event()
    # The forger's move: drop /ssn from erased, restore the value into
    # the body, recompute decision_id. The committed sensitive digest
    # must betray them -- loudly, naming the pointer.
    forged = copy.deepcopy(event)
    forged["erased"] = []
    forged["body"]["ssn"] = "121-34-5678"
    forged = _reid(dlv, forged)
    try:
        dlv.verify_event(forged)
    except dlv.RedactionLieError as e:
        if "/ssn" in str(e):
            return "HELD", "lie named: %s" % (e,)
        return "BREAK", "lie caught but pointer not named: %s" % (e,)
    except dlv.DecisionEventError as e:  # noqa: BLE001
        return "BREAK", "wrong error class: %r" % (e,)
    return "BREAK", "redaction lie NOT caught"


def p2_capture_time_lie_caught_with_raw():
    if not _HAS_MODULE:
        return "EXPECTED", "needs gov.decision_log_v2"
    dlv, event, raw = _honest_event()
    # Producer built from a sanitized copy; the true raw differs. The
    # event is internally consistent (offline verify passes) but the
    # auditor holding the true raw must catch the digest mismatch.
    true_raw = copy.deepcopy(raw)
    true_raw["ssn"] = "999-99-9999"
    try:
        dlv.verify_event(event)
    except Exception as e:  # noqa: BLE001
        return "BREAK", "honest event failed offline: %r" % (e,)
    try:
        dlv.verify_redaction(event, true_raw)
    except dlv.RedactionLieError as e:
        return "HELD", "capture-time lie caught with raw: %s" % (e,)
    except dlv.DecisionEventError as e:  # noqa: BLE001
        return "BREAK", "wrong error class: %r" % (e,)
    return "BREAK", "capture-time lie NOT caught"


def p3_replay_omission_diverges():
    if not _HAS_MODULE:
        return "EXPECTED", "needs gov.decision_log_v2"
    dlv, event, _ = _honest_event()
    # Drop the material input request.role; forger recomputes the id.
    # Replay must DIVERGE (default-deny, no matched rule) -- loudly.
    forged = copy.deepcopy(event)
    del forged["replay"]["inputs"]["request"]["role"]
    forged = _reid(dlv, forged)
    try:
        dlv.verify_event(forged)
    except dlv.ReplayDivergenceError as e:
        if "DIVERGED" in str(e):
            return "HELD", "divergence named: %s" % (e,)
        return "BREAK", "divergence not explicit: %s" % (e,)
    except dlv.DecisionEventError as e:  # noqa: BLE001
        return "BREAK", "wrong error class: %r" % (e,)
    return "BREAK", "replay omission NOT caught"


def p4_forged_decision_id_refused():
    if not _HAS_MODULE:
        return "EXPECTED", "needs gov.decision_log_v2"
    dlv, event, _ = _honest_event()
    forged = copy.deepcopy(event)
    forged["body"]["note"] = "edited after id"
    try:
        dlv.verify_event(forged)
    except dlv.EventVerifyError as e:
        if "MISMATCH" in str(e):
            return "HELD", "id mismatch refused: %s" % (e,)
        return "BREAK", "refused but not as id mismatch: %s" % (e,)
    except dlv.DecisionEventError as e:  # noqa: BLE001
        return "BREAK", "wrong error class: %r" % (e,)
    forged2 = copy.deepcopy(event)
    forged2["decision_id"] = "0" * 64
    try:
        dlv.verify_event(forged2)
    except dlv.EventVerifyError:
        return "HELD", "hand-forged id refused"
    except dlv.DecisionEventError as e:  # noqa: BLE001
        return "BREAK", "wrong error class: %r" % (e,)
    return "BREAK", "forged decision_id NOT refused"


def p5_v1_events_still_verify():
    if not _HAS_MODULE:
        return "EXPECTED", "needs gov.decision_log_v2"
    from gov import decision_log_v2 as dlv
    from gov.log import ActionLog, read_entries, verify_chain
    tmp = tempfile.mkdtemp(prefix="g202d-p5-")
    path = os.path.join(tmp, "audit.jsonl")
    log = ActionLog(path, deployment_mode="staging")
    # A v1-style entry (yesterday's shape) appends and reads back fine;
    # the v2 discriminator must not claim it.
    log.append({"decision": "execution_authorized",
                "decision_trace": {"trace_version": 1}})
    entries = read_entries(path)
    if entries[0]["decision"] != "execution_authorized":
        return "BREAK", "v1 entry did not round-trip"
    if dlv.is_v2_event(entries[0]):
        return "BREAK", "v1 entry misclassified as v2"
    try:
        dlv.verify_event(entries[0])
        return "BREAK", "v1 entry passed v2 verification"
    except dlv.EventVerifyError:
        pass
    ok, _, _ = verify_chain(path)
    if not ok:
        return "BREAK", "chain with v1 entry does not verify"
    return "HELD", "v1 entries untouched; discriminator correct"


def p6_chained_into_audit_log():
    if not _HAS_MODULE:
        return "EXPECTED", "needs gov.decision_log_v2"
    dlv, event, _ = _honest_event()
    from gov.log import ActionLog, verify_chain
    tmp = tempfile.mkdtemp(prefix="g202d-p6-")
    path = os.path.join(tmp, "audit.jsonl")
    log = ActionLog(path, deployment_mode="staging")
    entry = dlv.append_event(log, event)
    audit = event.get("audit")
    if not audit or audit["seq"] != entry["seq"]:
        return "BREAK", "audit seq not stamped"
    if audit["entry_hash"] != entry["hash"]:
        return "BREAK", "audit entry_hash not stamped"
    try:
        dlv.verify_event(event)
    except Exception as e:  # noqa: BLE001
        return "BREAK", "event fails verify after chaining: %r" % (e,)
    ok, _, _ = verify_chain(path)
    if not ok:
        return "BREAK", "chain does not verify after append_event"
    return "HELD", "v2 event chained; audit binding stamped; chain green"


def p7_mask_and_erase_enforced():
    if not _HAS_MODULE:
        return "EXPECTED", "needs gov.decision_log_v2"
    dlv, event, _ = _honest_event()
    if "ssn" in event["body"]:
        return "BREAK", "erased leaf present in body"
    if event["body"]["nested"]["token"] != {"$masked": True}:
        return "BREAK", "masked leaf not the placeholder"
    # Erased-but-present: the erasure claim is false.
    forged = copy.deepcopy(event)
    forged["body"]["ssn"] = "121-34-5678"
    forged = _reid(dlv, forged)
    try:
        dlv.verify_event(forged)
        return "BREAK", "erased-but-present NOT caught"
    except dlv.RedactionLieError:
        pass
    # Masked-but-raw: placeholder replaced by the raw value.
    forged = copy.deepcopy(event)
    forged["body"]["nested"]["token"] = "sekret-%s" % MARKER
    forged = _reid(dlv, forged)
    try:
        dlv.verify_event(forged)
        return "BREAK", "masked-but-raw NOT caught"
    except dlv.RedactionLieError:
        pass
    # The redacted VALUES must not appear anywhere in the recorded
    # body: erased and masked leaves are the only carriers. (The MARKER
    # also sits in the legitimately-unredacted "note" field -- that is
    # non-sensitive content by construction, not a leak.)
    blob = json.dumps(event["body"], sort_keys=True)
    for secret in ("121-34-5678", "sekret-%s" % MARKER):
        if secret in blob:
            return "BREAK", "redacted value leaked into recorded body"
    return "HELD", "erase/mask enforced; redacted values absent"


def p8_bom_binds_event():
    if not _HAS_MODULE:
        return "EXPECTED", "needs gov.decision_log_v2"
    dlv, event, _ = _honest_event()
    from gov import decision_bom as bom
    kwargs = dict(policy_id="p1", policy_version="v1",
                  policy_digest="a" * 64,
                  evidence_head_digest="b" * 64,
                  principal={"agent_id": "a1"})
    b = bom.build_bom(**kwargs, decision_event_v2=event)
    ok, reason = bom.check_bom_shape(b)
    if not ok:
        return "BREAK", "bom shape bad: %s" % (reason,)
    section = b["inputs"].get("decision_event")
    if not section:
        return "BREAK", "bom has no decision_event section"
    if section["decision_id"] != event["decision_id"]:
        return "BREAK", "bom decision_id != event decision_id"
    if section["event_digest"] != dlv.event_digest(event):
        return "BREAK", "bom event_digest != recomputed"
    # A tampered event must not bind.
    tampered = copy.deepcopy(event)
    tampered["body"]["note"] = "x"
    try:
        bom.build_bom(**kwargs, decision_event_v2=tampered)
        return "BREAK", "tampered event bound into BOM"
    except bom.BomError:
        pass
    # Absence keeps the BOM byte-identical to before.
    b2 = bom.build_bom(**kwargs)
    if "decision_event" in b2["inputs"]:
        return "BREAK", "section present without event"
    return "HELD", "BOM binds event by digest; tampered refused"


def p9_determinism():
    if not _HAS_MODULE:
        return "EXPECTED", "needs gov.decision_log_v2"
    dlv, event, _ = _honest_event()
    _, event2, _ = _honest_event()
    b1 = json.dumps(event, sort_keys=True)
    b2 = json.dumps(event2, sort_keys=True)
    if b1 != b2:
        return "BREAK", "two builds differ"
    return "HELD", "byte-identical builds; decision_id=%s..." \
        % event["decision_id"][:16]


PROBES = [
    ("P0", "module-present", p0_module_present),
    ("P1", "redaction-lie-dropped-pointer", p1_redaction_lie_dropped_pointer),
    ("P2", "capture-time-lie-with-raw", p2_capture_time_lie_caught_with_raw),
    ("P3", "replay-omission-diverges", p3_replay_omission_diverges),
    ("P4", "forged-decision-id-refused", p4_forged_decision_id_refused),
    ("P5", "v1-events-still-verify", p5_v1_events_still_verify),
    ("P6", "chained-into-audit-log", p6_chained_into_audit_log),
    ("P7", "mask-and-erase-enforced", p7_mask_and_erase_enforced),
    ("P8", "bom-binds-event", p8_bom_binds_event),
    ("P9", "determinism", p9_determinism),
]


def main():
    held = brk = expected = errors = 0
    for pid, name, fn in PROBES:
        outcomes = set()
        detail = ""
        for _ in range(2):
            try:
                status, detail = fn()
            except Exception as e:  # noqa: BLE001
                status, detail = "ERROR", "%r" % (e,)
            outcomes.add(status)
        if len(outcomes) != 1:
            status = "ERROR"
            detail = "non-deterministic: %r" % (outcomes,)
        print("%s %-28s %s -- %s" % (pid, name, status, detail))
        if status == "HELD":
            held += 1
        elif status == "BREAK":
            brk += 1
        elif status == "EXPECTED":
            expected += 1
        else:
            errors += 1
    print("summary: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, expected, errors))
    green_ok = _green_check()
    if errors or not green_ok:
        return 1
    return 0


def _green_check():
    """Depth-1 green check: the adjacent unit suite only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip; skips
    gracefully on trees where the wave-202 suite does not exist."""
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    if importlib.util.find_spec("tests.test_decision_log_v2") is None:
        print("GREEN CHECK: skipped (tests.test_decision_log_v2 absent "
              "on this tree)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_decision_log_v2"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
    print("GREEN CHECK unit suite: rc=%d %s"
          % (r.returncode, " | ".join(tail)))
    return r.returncode == 0


if __name__ == "__main__":
    sys.exit(main())
