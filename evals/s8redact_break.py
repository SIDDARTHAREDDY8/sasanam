"""S8 break battery: deferred-effect scanner raw-value leak (wave-90).

Pre-fix, ``scan_deferred_effect()`` read RAW kwargs and each trigger
carried ``"value"`` with up to 200 chars of raw payload content. That
dict rode — verbatim — into the audit log's ``deferred_effect_detected``
entry AND the MAC-bound approval record's ``deferred_effect`` field:
a second, unredacted copy of payload content in the retained evidence,
bypassing DLP entirely (DLP only governs ``redacted_args``). Worst
case: a PII/secret-shaped trigger value that DLP scrubbed from ``args``
was REINTRODUCED into the evidence by the scanner — a redaction bypass.

Post-fix, the scanner still reads raw kwargs (redaction must not
destroy trigger evidence pre-detection) but emits structured
DESCRIPTORS — shape/position/fingerprint — never raw values.

Verdicts:
- CLOSED  = leak absent AND detection preserved
- BREAK   = canary found where it must not be, or a trigger kind that
            fired pre-fix no longer fires (detection loss)
- CONTROL = documents an existing, designed behavior that must keep
            holding (the formal classification of the residual boundary)
- ERROR   = probe/instrumentation problem, not a verdict

Detection parity is asserted against the frozen pre-fix contract
(kind sets per input shape, documented in the S5 suite and the
scanner docstring): the fix changes the trigger *payload*, never the
*decision* to fire. One deliberate, documented change: dedup is now
position-aware (identical fragments on different lines are distinct
triggers — position is part of a descriptor's identity).

FORMAL CLASSIFICATION (the residual boundary, encoded as CONTROL
probes, not buried): a trigger value that is neither credential-shaped
nor PII-shaped remains visible in the DLP-governed ``args`` surface of
the audit log and approval record. That surface is (a) DLP's
jurisdiction, (b) what the human reviewer reads to judge WHAT the
action does, and (c) what EXECUTES — F12's "preview, digest, and
execution all agree" means masking it there would break execution of
legitimate deferred actions. The scanner no longer DUPLICATES such
values into evidence structures outside DLP's governance. This probe
file asserts both halves.

Run: TMPDIR=/tmp/gov-run-s8 ~/workspace/.gov-venv/bin/python evals/s8redact_break.py
"""

import base64
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tests.harness import make_run  # noqa: E402
from gov import tool_continuity as tc  # noqa: E402

# PII-shaped canary: DLP scrubs it from args ([REDACTED:pii-phone]) but
# does NOT block the call, so the deferred scanner (raw kwargs) still
# sees it. Pre-fix the scanner reintroduced it verbatim into the
# evidence — the redaction bypass this battery closes.
PII_CANARY = "415-555-0132"

# Operationally sensitive but NOT credential/PII-shaped: DLP passes it
# through into args by design (reviewer visibility + execution). Used
# to prove the scanner's own channel is clean and to pin the
# args-channel boundary as a documented CONTROL.
OP_CANARY = "nightingale-7392-xqzt-internal"


def _events(run):
    return list(run["read_log"]())


def _governance_text(run):
    """Every governance record surface: the full audit log plus every
    approval record (including MAC-bound fields), serialized as stored."""
    blob = json.dumps(_events(run), sort_keys=True, default=str)
    blob += json.dumps(run["approvals"].all(), sort_keys=True, default=str)
    return blob


def _deferred_effect_blobs(run):
    """Only the deferred_effect structures — the scanner's channel."""
    blobs = []
    for e in _events(run):
        if "deferred_effect" in e:
            blobs.append(json.dumps(e["deferred_effect"], default=str))
    for rec in run["approvals"].all():
        if rec.get("deferred_effect"):
            blobs.append(json.dumps(rec["deferred_effect"], default=str))
    return blobs


def _deferred_entries(run):
    return [e for e in _events(run)
            if e.get("decision") == "deferred_effect_detected"]


def _kinds(run):
    kinds = set()
    for e in _deferred_entries(run):
        for t in e.get("deferred_effect", {}).get("triggers", []):
            kinds.add(t["kind"])
    return kinds


def _approve_and_execute(run, approval_id):
    run["approvals"].decide(approval_id, True, reason="s8 battery",
                            decided_by="human-operator")
    return run["executor"].execute_approved()


def probe_pii_redaction_bypass_closed():
    """PII trigger value: DLP scrubs it from args; the scanner must not
    reintroduce it. Full approve->scan->execute path, whole-record grep.

    Pre-fix: the raw PII sat verbatim in the audit entry's
    deferred_effect AND the MAC-bound record's deferred_effect even
    though DLP had scrubbed it from args — a redaction bypass.
    Post-fix expectation: CLOSED — the PII is absent from EVERY
    governance record, detection and quarantine intact.
    """
    run = make_run()
    ident = run["identities"]["coder"]
    r = run["executor"].call(
        ident, "write_file", path="op.sh", content="x",
        schedule="call %s at window" % PII_CANARY)
    if r["status"] != "queued":
        return ("BREAK", "quarantine lost: status=%r" % (r["status"],))
    if len(_deferred_entries(run)) != 1:
        return ("BREAK", "detection lost: deferred_effect_detected=%d"
                % len(_deferred_entries(run)))
    _approve_and_execute(run, r["approval_id"])
    blob = _governance_text(run)
    if PII_CANARY in blob:
        return ("BREAK", "PII canary present in governance records "
                         "post-fix (redaction bypass still open)")
    if "[REDACTED:pii-phone]" not in blob:
        return ("BREAK", "DLP scrub marker missing — harness changed?")
    trigs = _deferred_entries(run)[0]["deferred_effect"]["triggers"]
    if not any(t["kind"] == "deferred_arg"
               and t["descriptor"]["shape"] == "deferred_arg_name"
               and "value" not in t for t in trigs):
        return ("BREAK", "descriptor malformed: %r" % (trigs,))
    return ("CLOSED",
            "PII absent from all records; DLP scrub held; descriptor-only "
            "trigger; quarantine held")


def probe_codename_absent_from_scanner_channel():
    """Non-PII canary as a deferred_arg value: the scanner's channel.

    Asserts the canary is absent from EVERY deferred_effect structure
    in the audit log and approval records (the fixed channel), while
    detection (deferred_effect_detected) and quarantine (queued)
    hold. The DLP args surface is classified separately (CONTROL).
    """
    run = make_run()
    ident = run["identities"]["coder"]
    r = run["executor"].call(
        ident, "write_file", path="op.sh", content="x",
        schedule="activate operation %s at window" % OP_CANARY)
    if r["status"] != "queued" or len(_deferred_entries(run)) != 1:
        return ("BREAK", "detection/quarantine lost: status=%r n=%d"
                % (r["status"], len(_deferred_entries(run))))
    for b in _deferred_effect_blobs(run):
        if OP_CANARY in b:
            return ("BREAK", "canary in a deferred_effect structure")
        if '"value"' in b:
            return ("BREAK", "raw 'value' key survived in a "
                             "deferred_effect structure")
    _approve_and_execute(run, r["approval_id"])
    for b in _deferred_effect_blobs(run):
        if OP_CANARY in b or '"value"' in b:
            return ("BREAK", "canary/value-key in deferred_effect "
                             "structure after approve+execute")
    return ("CLOSED", "scanner channel clean end to end; detection + "
                       "quarantine held")


def probe_args_channel_boundary():
    """CONTROL: the formal classification of the residual boundary.

    A trigger value that is neither credential- nor PII-shaped stays
    visible in the DLP-governed ``args`` surface — by design: the human
    reviewer judges WHAT the action does from it, and F12 ("preview,
    digest, and execution all agree") means the executed action IS
    those args, so masking them there would break legitimate deferred
    actions. What changed in wave-90: the scanner no longer duplicates
    such values into evidence structures outside DLP's governance.
    This probe pins both halves so the boundary can't silently drift.
    """
    run = make_run()
    ident = run["identities"]["coder"]
    r = run["executor"].call(
        ident, "write_file", path="op.sh", content="x",
        schedule="window %s" % OP_CANARY)
    assert r["status"] == "queued"
    in_args = any(OP_CANARY in json.dumps(e.get("args", ""), default=str)
                  for e in _events(run))
    in_scanner_channel = any(OP_CANARY in b
                             for b in _deferred_effect_blobs(run))
    if in_args and not in_scanner_channel:
        return ("CONTROL",
                "boundary holds: non-sensitive trigger value visible in "
                "DLP-governed args (reviewer/execution surface), absent "
                "from every deferred_effect structure (scanner channel)")
    return ("BREAK", "boundary drifted: in_args=%r in_scanner_channel=%r"
            % (in_args, in_scanner_channel))


def probe_canary_cron_line():
    """Canary embedded in a bare crontab line inside a summary field."""
    run = make_run()
    ident = run["identities"]["coder"]
    line = "0 3 * * * /opt/run.sh --tag %s" % OP_CANARY
    r = run["executor"].call(ident, "write_file", path="cron.sh",
                             content="# job\n%s\n" % line)
    if r["status"] != "queued" or len(_deferred_entries(run)) != 1:
        return ("BREAK", "detection/quarantine lost: status=%r n=%d"
                % (r["status"], len(_deferred_entries(run))))
    if _kinds(run) != {"cron_expression"}:
        return ("BREAK", "kind set changed: %r" % (_kinds(run),))
    _approve_and_execute(run, r["approval_id"])
    if OP_CANARY in _governance_text(run):
        return ("BREAK", "CANARY present in governance records post-fix")
    trigs = _deferred_entries(run)[0]["deferred_effect"]["triggers"]
    d = trigs[0]["descriptor"]
    if d.get("shape") != "cron_line" or d.get("line") != 2 \
            or "value" in trigs[0]:
        return ("BREAK", "descriptor malformed: %r" % (trigs,))
    return ("CLOSED", "cron_line descriptor carries shape/line/fingerprint "
                       "only; canary absent from all records")


def probe_canary_future_timestamp():
    """Canary adjacent to a future ISO timestamp (trigger-word line)."""
    run = make_run()
    ident = run["identities"]["coder"]
    r = run["executor"].call(
        ident, "write_file", path="plan.txt",
        content="activate after 2027-06-01T03:00 for %s rollout\n" % OP_CANARY)
    if r["status"] != "queued" or len(_deferred_entries(run)) != 1:
        return ("BREAK", "detection/quarantine lost")
    if _kinds(run) != {"future_timestamp"}:
        return ("BREAK", "kind set changed: %r" % (_kinds(run),))
    _approve_and_execute(run, r["approval_id"])
    if OP_CANARY in _governance_text(run):
        return ("BREAK", "CANARY present in governance records post-fix")
    return ("CLOSED", "future_iso descriptor only; canary absent")


def probe_canary_nested_list_b64():
    """Canary in nested kwargs, list kwargs, and a base64-ish blob.

    The scanner is top-level only (documented residual: nested
    triggers are a detection gap, not a leak vector). Nothing nested
    may reach a deferred_effect structure, and nothing may crash.
    The base64-ish blob under a deferred key IS a deferred_arg hit —
    its descriptor must carry length/fingerprint, never content.
    (The b64 TEXT never contains the literal canary; the nested dict
    and list reach the DLP args surface per the CONTROL boundary.)
    """
    run = make_run()
    ident = run["identities"]["coder"]
    blob = base64.b64encode(("exfil %s" % OP_CANARY).encode()).decode()
    assert OP_CANARY not in blob
    try:
        run["executor"].call(
            ident, "write_file", path="n.sh", content="x",
            config={"schedule": "0 3 * * * %s" % OP_CANARY},
            tags=["t1", OP_CANARY],
            run_at=blob)
    except Exception as e:  # noqa: BLE001 - the probe asserts no crash
        return ("BREAK", "scanner crashed on nested/list/b64 input: %r" % (e,))
    for b in _deferred_effect_blobs(run):
        if OP_CANARY in b or blob in b or '"value"' in b:
            return ("BREAK", "leak into a deferred_effect structure from "
                             "nested/list/b64 input")
    trigs = []
    for e in _deferred_entries(run):
        trigs.extend(e.get("deferred_effect", {}).get("triggers", []))
    b64hits = [t for t in trigs if t["source"] == "arg:run_at"]
    if len(b64hits) != 1 or "value" in b64hits[0] \
            or "value_sha256" not in b64hits[0]["descriptor"]:
        return ("BREAK", "b64 deferred_arg descriptor malformed: %r"
                % (b64hits,))
    return ("CLOSED", "nested/list/b64: no crash, scanner channel clean, "
                       "b64 hit is descriptor-only")


def probe_detection_parity():
    """Frozen pre-fix detection contract: identical kind sets in/out.

    Each row: (kwargs, expected kind set). The fix may change trigger
    payloads but must not change the decision to fire.
    """
    rows = [
        ({"schedule": "tonight"}, {"deferred_arg"}),
        ({"Schedule": "x", "CRON_EXPRESSION": "y"}, {"deferred_arg"}),
        ({"delay_seconds": 3600}, {"deferred_arg"}),
        ({"delay_seconds": 0}, set()),          # empty-ish value: no hit
        ({"schedule": ""}, set()),
        ({"content": "0 3 * * * /bin/true"}, {"cron_expression"}),
        ({"content": 'cron: "0 3 * * *" done'}, {"cron_expression"}),
        ({"content": "run_at: 2027-01-01T00:00:00Z"},
         {"future_timestamp"}),
        ({"content": "cron_link"}, set()),      # w23: no hit
        ({"content": "meeting at 10:00"}, set()),
        ({"content": "1 2 3 4 5"}, set()),      # no trigger word: no hit
        ({"content": "every day at dawn"}, set()),  # word but no shape
        ({"path": "/tmp/x", "content": "benign"}, set()),
    ]
    for kwargs, expected in rows:
        d = tc.scan_deferred_effect("write_file", kwargs)
        got = {t["kind"] for t in d["triggers"]} if d else set()
        if got != expected:
            return ("BREAK",
                    "detection changed for %r: got %r want %r"
                    % (kwargs, got, expected))
        if d:
            for t in d["triggers"]:
                if "value" in t:
                    return ("BREAK", "raw 'value' key survived in %r"
                            % (t,))
                if set(t["descriptor"]) - {
                        "shape", "line", "match_len", "match_sha256",
                        "value_len", "value_sha256"}:
                    return ("BREAK", "descriptor has unknown keys: %r"
                            % (t["descriptor"],))
    return ("CLOSED", "%d input shapes: kind sets identical to pre-fix "
                       "contract, zero raw values" % len(rows))


def probe_dedup_position_aware():
    """Deliberate, documented change: dedup is now position-aware.

    Pre-fix, identical (source, kind, value) triples collapsed even
    across lines. Post-fix the signature includes the descriptor's
    line/shape, so identical fragments on DIFFERENT lines are distinct
    triggers — position is part of a descriptor's identity, and
    collapsing across positions would discard the location the
    descriptor was designed to carry. Detection (fire/no-fire, kinds)
    is unchanged; only duplicate-trigger collapsing is finer.
    """
    d = tc.scan_deferred_effect(
        "write_file", {"content": "0 3 * * * /bin/a\n0 3 * * * /bin/a\n"})
    n_same = len(d["triggers"]) if d else 0
    d2 = tc.scan_deferred_effect(
        "write_file", {"content": "0 3 * * * /bin/a\n0 4 * * * /bin/b\n"})
    n_diff = len(d2["triggers"]) if d2 else 0
    lines = sorted(t["descriptor"]["line"] for t in d["triggers"]) if d else []
    if n_same == 2 and lines == [1, 2] and n_diff == 2:
        return ("CLOSED", "position-aware: identical fragments on lines "
                           "1,2 stay distinct; distinct fragments -> 2")
    return ("BREAK", "dedup semantics unexpected: same->%d diff->%d "
                     "lines=%r" % (n_same, n_diff, lines))


def probe_banner_unchanged():
    """The human-facing banner still names the kinds (its only input)."""
    d = tc.scan_deferred_effect(
        "write_file",
        {"content": 'cron: "0 3 * * *"\nrun_at: 2027-01-01T00:00:00Z\n'})
    banner = tc.deferred_preview_banner(d)
    if "cron_expression" in banner and "future_timestamp" in banner \
            and banner.startswith("DEFERRED-EFFECT"):
        return ("CLOSED", "banner intact: %r" % (banner[:60],))
    return ("BREAK", "banner changed: %r" % (banner,))


def probe_bypass_key_spellings():
    """Adversarial key spellings: what detects, what doesn't, no leaks.

    - Case variants ("Schedule") detect (lower() match) — descriptor-only.
    - Fullwidth unicode ("ｓchedule") does NOT detect: same homoglyph
      class as F82 (StruQ NFKC gap). Documented residual, not a leak:
      an undetected trigger writes nothing to deferred_effect.
    """
    run = make_run()
    ident = run["identities"]["coder"]
    run["executor"].call(ident, "write_file", path="u.sh",
                         content="x", Schedule="window %s" % OP_CANARY)
    kinds = _kinds(run)
    leaked = any(OP_CANARY in b for b in _deferred_effect_blobs(run))
    uni = tc.scan_deferred_effect("write_file",
                                  {"\uff53chedule": "x %s" % OP_CANARY})
    notes = []
    ok = True
    if kinds != {"deferred_arg"}:
        ok = False
        notes.append("case-variant detection changed: %r" % (kinds,))
    if leaked:
        ok = False
        notes.append("CANARY leaked into scanner channel via case-variant")
    if uni is not None:
        notes.append("UNEXPECTED: fullwidth key detected (re-verify)")
        ok = False
    else:
        notes.append("fullwidth 'ｓchedule' undetected — residual "
                     "(F82-class NFKC gap), scanner channel clean either way")
    if ok:
        return ("CLOSED", "; ".join(notes))
    return ("BREAK", "; ".join(notes))


def probe_deeply_nested_no_crash():
    """10-deep nested dict carrying the canary: no crash, no leak.

    Documents the nested-scan detection residual: the scanner is
    top-level only, so a nested cron shape is a false negative today.
    What must hold: no exception, and no canary in any
    deferred_effect structure.
    """
    run = make_run()
    ident = run["identities"]["coder"]
    nested = cur = {}
    for _ in range(10):
        cur["lvl"] = {}
        cur = cur["lvl"]
    cur["cron"] = "0 3 * * * %s" % OP_CANARY
    try:
        run["executor"].call(ident, "write_file", path="deep.sh",
                             content="x", config=nested)
    except Exception as e:  # noqa: BLE001
        return ("BREAK", "crashed on deeply nested input: %r" % (e,))
    leaked = any(OP_CANARY in b for b in _deferred_effect_blobs(run))
    if leaked:
        return ("BREAK", "canary leaked from nested structure")
    return ("CLOSED", "no crash, no leak; nested-trigger detection gap "
                       "remains a documented residual")


PROBES = [
    ("pii_redaction_bypass_closed", probe_pii_redaction_bypass_closed),
    ("codename_absent_from_scanner_channel",
     probe_codename_absent_from_scanner_channel),
    ("args_channel_boundary", probe_args_channel_boundary),
    ("canary_cron_line", probe_canary_cron_line),
    ("canary_future_timestamp", probe_canary_future_timestamp),
    ("canary_nested_list_b64", probe_canary_nested_list_b64),
    ("detection_parity", probe_detection_parity),
    ("dedup_position_aware", probe_dedup_position_aware),
    ("banner_unchanged", probe_banner_unchanged),
    ("bypass_key_spellings", probe_bypass_key_spellings),
    ("deeply_nested_no_crash", probe_deeply_nested_no_crash),
]


def main():
    results = []
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - probe bug, not a verdict
            verdict, detail = ("ERROR", "probe raised: %r" % (e,))
        results.append((name, verdict, detail))
        print("%-34s %-8s %s" % (name, verdict, detail))
    n_good = sum(1 for _, v, _ in results if v in ("CLOSED", "CONTROL"))
    bad = [(n, v, d) for n, v, d in results
           if v not in ("CLOSED", "CONTROL")]
    print("S8-BATTERY: %d/%d CLOSED-or-CONTROL" % (n_good, len(results)))
    if bad:
        print("FAILURES:")
        for n, v, d in bad:
            print("  %s %s %s" % (n, v, d))
        sys.exit(1)
    print("S8-BATTERY: GREEN")


if __name__ == "__main__":
    main()
