"""Adversarial battery: offline evidence bundle exporter + standalone verifier.

Adapted from attenu-io/attenu-guard's offline evidence bundle design
(``export_bundle`` / ``verify_bundle``, Apache-2.0 — credited in
``gov/offline_bundle.py``): the bundle must be verifiable by an auditor
WITHOUT our engine, against three invariants —

  I1 INTEGRITY: the export hash chain recomputes from the bundle's ledger
     AND the chain tip matches the signed anchor receipt. This is the
     attenu-guard property that catches FULL REWRITES: an attacker who
     rewrites the whole ledger and recomputes the (unkeyed) export chain
     still cannot forge the anchor signature.
  I2 MONOTONICITY: sequence numbers strictly increase by 1.
  I3 CONTAINMENT: the window [from_seq, to_seq] is fully present — no
     gaps, no duplicates, no out-of-window entries.

plus R1 REDACTION-HONESTY: the redaction report discloses everything
withheld. Every entry either carries a valid per-entry Ed25519 signature
or is listed in the report with its redacted fields — a silently-redacted
entry has neither, so the lie is caught.

Probes (break-first; BREAK = vulnerability, file as F178+):
  b1_full_rewrite   rewrite every entry + recompute export chain + update
                    manifest digests, keep the original anchor receipt.
                    Must REJECT (anchor binding).
  b2_entry_tamper   flip one payload field, recompute nothing.
                    Must REJECT (export chain).
  b3_entry_drop     delete one ledger line -> seq gap. Must REJECT
                    (containment).
  b4_forged_receipt rewrite ledger + rechain + staple a forged anchor
                    receipt (statement patched, garbage log_sig).
                    Must REJECT (anchor signature).
  b5_redaction_lie  redact a field, drop its ed_sig, do NOT list it in
                    the redaction report. Must REJECT (sig-or-listed).

Controls:
  c1_honest_pinned   honest bundle + both pins -> VERIFIED (exit 0).
  c2_honest_unpinned honest bundle, no pins -> SELF_CONSISTENT (exit 2).
  c3_honest_redacted honest bundle with a legitimate field redaction +
                    pins -> VERIFIED, report lists the redaction.

The verifier is executed as a subprocess with PYTHONPATH scrubbed and
cwd=/tmp, proving it works from the bundle alone with no repo imports.

Verdicts are honest: HELD = attack stopped / control behaved.
"""

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import log as _log                      # noqa: E402
from gov.log import ActionLog                    # noqa: E402
from gov.signing import Ed25519Signer            # noqa: E402
from gov.anchor_adapter import FakeLogAdapter    # noqa: E402
from gov import offline_bundle as ob             # noqa: E402

VERIFIER = os.path.join(REPO_ROOT, "tools", "offline-verify")

RESULTS = []

LOG_PUB = None
ENTRY_PUB = None


def _report(name, verdict, detail):
    RESULTS.append((name, verdict, detail))
    print("  %-24s %s  %s" % (name, verdict, detail), flush=True)


def _setup(tmp):
    """Build a signed 8-entry audit log; return (log_path, signer, adapter)."""
    os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
    signer = Ed25519Signer(
        hashlib.sha256(b"offline-bundle-battery-entry-signer").digest())
    log_path = os.path.join(tmp, "audit.jsonl")
    lg = ActionLog(log_path, signer=signer)
    events = [
        {"event": "tool_call", "tool": "read_file",
         "target": "/etc/app.conf"},
        {"event": "approval_decision", "ticket": "t1", "decision": "allow"},
        {"event": "tool_call", "tool": "http_post",
         "target": "https://api.example.com/v1"},
        {"event": "policy_eval", "rule": "egress.allowlist",
         "verdict": "allow"},
        {"event": "tool_call", "tool": "write_file",
         "target": "/tmp/out.txt"},
        {"event": "citation_check", "citation": "c1",
         "verdict": "accepted"},
        {"event": "tool_call", "tool": "http_post",
         "target": "https://api.example.com/v2",
         "note": "summary of user data"},
        {"event": "approval_decision", "ticket": "t2", "decision": "deny"},
    ]
    for e in events:
        lg.append(e)
    adapter = FakeLogAdapter(
        hashlib.sha256(b"offline-bundle-battery-log").digest())
    return log_path, signer, adapter


def _export(tmp, log_path, signer, adapter, name="bundle", **kw):
    bundle_dir = os.path.join(tmp, name)
    ob.export_offline_bundle(
        log_path, bundle_dir, adapter,
        entry_signer_pubkey=signer.public_key, **kw)
    return bundle_dir


def _read_ledger(bundle_dir):
    with open(os.path.join(bundle_dir, "ledger.jsonl"),
              encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _write_ledger(bundle_dir, entries):
    with open(os.path.join(bundle_dir, "ledger.jsonl"), "w",
              encoding="utf-8") as f:
        for e in entries:
            f.write(ob._canonical(e).decode("utf-8") + "\n")


def _rechain(entries):
    """Recompute the export chain (the attacker knows the unkeyed
    algorithm — Kerckhoffs). Returns the new tip."""
    prev = ob.EXPORT_GENESIS
    for e in entries:
        body = {k: v for k, v in e.items() if k != "export_hash"}
        prev = ob._chain_hash(prev, ob._canonical(body))
        e["export_hash"] = prev
    return prev


def _refresh_digest(bundle_dir):
    from gov.safeguard_bundle import compute_bundle_digest
    digest = compute_bundle_digest(bundle_dir)
    with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"), "w",
              encoding="utf-8") as f:
        f.write(digest + "\n")


def _tamper_dir(tmp, bundle_dir, name):
    """Copy the bundle so each attack starts from a pristine original."""
    dest = os.path.join(tmp, name)
    if os.path.exists(dest):
        shutil.rmtree(dest)
    shutil.copytree(bundle_dir, dest)
    return dest


def _run_verifier(bundle_dir, pins=True):
    cmd = [sys.executable, VERIFIER, bundle_dir, "--format", "text"]
    if pins:
        cmd += ["--pin-log-pubkey", LOG_PUB,
                "--pin-entry-pubkey", ENTRY_PUB]
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    p = subprocess.run(cmd, cwd="/tmp", env=env,
                       capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout, p.stderr


# -- attacks ---------------------------------------------------------------

def b1_full_rewrite(tmp, bundle_dir):
    """Attacker rewrites every entry's payload and recomputes the export
    chain (algorithm is unkeyed and public), updates the manifest digests,
    keeps the original anchor receipt. The anchor must catch it."""
    name = "b1_full_rewrite"
    d = _tamper_dir(tmp, bundle_dir, "b1")
    entries = _read_ledger(d)
    for e in entries:
        if e.get("decision") == "allow":
            e["decision"] = "deny"
        if e.get("verdict") == "allow":
            e["verdict"] = "deny"
        # The rewrite changes content, so the original per-entry sigs
        # can no longer verify — drop them like a careful attacker would.
        e.pop("ed_sig", None)
        e.pop("sig_key_id", None)
        e["redacted"] = False
    new_tip = _rechain(entries)
    _write_ledger(d, entries)
    with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["ledger_digest"] = new_tip
    with open(os.path.join(d, "manifest.json"), "w",
              encoding="utf-8") as f:
        f.write(ob._canonical(manifest).decode("utf-8") + "\n")
    _refresh_digest(d)
    rc, out, _ = _run_verifier(d)
    if rc == 1:
        _report(name, "HELD",
                "full rewrite rejected (anchor binding holds)")
    else:
        _report(name, "BREAK",
                "full rewrite ACCEPTED by verifier (rc=%d)" % rc)


def b2_entry_tamper(tmp, bundle_dir):
    """Flip one payload field, recompute nothing."""
    name = "b2_entry_tamper"
    d = _tamper_dir(tmp, bundle_dir, "b2")
    entries = _read_ledger(d)
    entries[1]["decision"] = "deny"  # was "allow"
    _write_ledger(d, entries)
    _refresh_digest(d)
    rc, out, _ = _run_verifier(d)
    if rc == 1:
        _report(name, "HELD", "single-entry tamper rejected (chain)")
    else:
        _report(name, "BREAK",
                "single-entry tamper ACCEPTED (rc=%d)" % rc)


def b3_entry_drop(tmp, bundle_dir):
    """Delete one ledger line -> sequence gap 3->5."""
    name = "b3_entry_drop"
    d = _tamper_dir(tmp, bundle_dir, "b3")
    entries = _read_ledger(d)
    del entries[3]
    _write_ledger(d, entries)
    _refresh_digest(d)
    rc, out, _ = _run_verifier(d)
    if rc == 1:
        _report(name, "HELD", "dropped entry rejected (containment)")
    else:
        _report(name, "BREAK",
                "dropped entry ACCEPTED (rc=%d)" % rc)


def b4_forged_receipt(tmp, bundle_dir):
    """Rewrite + rechain (as b1), then staple a forged anchor receipt:
    the statement is patched to the new tip but log_sig is garbage.
    The verifier must check the anchor signature, not just the
    statement hash."""
    name = "b4_forged_receipt"
    d = _tamper_dir(tmp, bundle_dir, "b4")
    entries = _read_ledger(d)
    for e in entries:
        e["note"] = "attacker was here"
        e.pop("ed_sig", None)
        e.pop("sig_key_id", None)
    new_tip = _rechain(entries)
    _write_ledger(d, entries)
    with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["ledger_digest"] = new_tip
    # Recompute the redaction digest (unchanged report, but recompute
    # honestly) and the anchor input the receipt must commit to.
    anchor_input = ob._anchor_input(manifest)
    forged_statement = {
        "statement_version": 1,
        "bundle_hash": ob._anchor_statement_hash(anchor_input),
    }
    from gov.anchor_adapter import _statement_hash as _aa_stmt_hash
    receipt = {
        "adapter": "fake-log",
        "log_id": manifest["anchor"]["log_id"],
        "statement": forged_statement,
        "statement_hash": _aa_stmt_hash(forged_statement),
        "log_index": 0,
        "tree_size": 1,
        "inclusion_proof": [],
        "log_root": _aa_stmt_hash(forged_statement),
        "log_sig": "00" * 64,  # garbage: no such signature exists
    }
    with open(os.path.join(d, "anchor_receipt.json"), "w",
              encoding="utf-8") as f:
        f.write(ob._canonical(receipt).decode("utf-8") + "\n")
    with open(os.path.join(d, "manifest.json"), "w",
              encoding="utf-8") as f:
        f.write(ob._canonical(manifest).decode("utf-8") + "\n")
    _refresh_digest(d)
    rc, out, _ = _run_verifier(d)
    if rc == 1:
        _report(name, "HELD",
                "forged anchor receipt rejected (signature checked)")
    else:
        _report(name, "BREAK",
                "forged anchor receipt ACCEPTED (rc=%d)" % rc)


def b5_redaction_lie(tmp, bundle_dir, adapter):
    """Redact a field but do NOT list it in the redaction report (and
    drop the now-unverifiable ed_sig). The bundle is then RE-ANCHORED
    with the real log key (the battery holds the seed), so the anchor
    binding is satisfied and the ONLY defect is the undisclosed
    redaction. The sig-or-listed rule must catch the lie."""
    name = "b5_redaction_lie"
    d = _tamper_dir(tmp, bundle_dir, "b5")
    entries = _read_ledger(d)
    victim = entries[0]
    del victim["target"]          # withheld...
    victim.pop("ed_sig", None)    # ...sig dropped, as a real redaction would
    victim.pop("sig_key_id", None)
    # ...but the report is left claiming nothing was redacted.
    new_tip = _rechain(entries)
    _write_ledger(d, entries)
    with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["ledger_digest"] = new_tip
    with open(os.path.join(d, "manifest.json"), "w",
              encoding="utf-8") as f:
        f.write(ob._canonical(manifest).decode("utf-8") + "\n")
    # Re-anchor legitimately: the anchor binding now holds, isolating
    # the redaction rule as the deciding check. A fresh bundle_id, as a
    # real (re-)export would mint (the log refuses two statements for
    # one id).
    manifest["bundle_id"] = "ob-" + new_tip[:16]
    receipt = adapter.anchor(ob._anchor_input(manifest))
    with open(os.path.join(d, "anchor_receipt.json"), "w",
              encoding="utf-8") as f:
        f.write(ob._canonical(receipt).decode("utf-8") + "\n")
    with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["anchor"]["log_id"] = receipt["log_id"]
    with open(os.path.join(d, "manifest.json"), "w",
              encoding="utf-8") as f:
        f.write(ob._canonical(manifest).decode("utf-8") + "\n")
    _refresh_digest(d)
    # JSON output for a precise assertion: R1 (the sig-or-listed rule)
    # must be the failing check.
    cmd = [sys.executable, VERIFIER, d, "--format", "json",
           "--pin-log-pubkey", LOG_PUB, "--pin-entry-pubkey", ENTRY_PUB]
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    p = subprocess.run(cmd, cwd="/tmp", env=env,
                       capture_output=True, text=True, timeout=120)
    r1_failed = False
    try:
        doc = json.loads(p.stdout)
        r1_failed = any(c["id"] == "R1" and not c["ok"]
                        for c in doc.get("checks", []))
    except (ValueError, KeyError):
        r1_failed = False
    if p.returncode == 1 and r1_failed:
        _report(name, "HELD",
                "undisclosed redaction rejected (R1 sig-or-listed rule)")
    elif p.returncode == 1:
        _report(name, "HELD",
                "undisclosed redaction rejected (not via R1 — "
                "investigate)")
    else:
        _report(name, "BREAK",
                "undisclosed redaction ACCEPTED (rc=%d)" % p.returncode)


# -- controls ----------------------------------------------------------------

def c1_honest_pinned(tmp, bundle_dir):
    name = "c1_honest_pinned"
    rc, out, err = _run_verifier(bundle_dir, pins=True)
    if rc == 0 and "VERIFIED" in out:
        _report(name, "HELD", "honest bundle verifies pinned (exit 0)")
    else:
        _report(name, "BREAK",
                "honest bundle FAILED pinned verification (rc=%d) %s %s"
                % (rc, out[-200:], err[-200:]))


def c2_honest_unpinned(tmp, bundle_dir):
    name = "c2_honest_unpinned"
    rc, out, err = _run_verifier(bundle_dir, pins=False)
    if rc == 2 and "SELF_CONSISTENT" in out:
        _report(name, "HELD",
                "honest bundle self-consistent unpinned (exit 2)")
    else:
        _report(name, "BREAK",
                "honest bundle wrong unpinned verdict (rc=%d)" % rc)


def c3_honest_redacted(tmp, log_path, signer, adapter):
    name = "c3_honest_redacted"
    d = _export(tmp, log_path, signer, adapter, name="bundle_red",
                redact_fields=("note",))
    with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    rr = manifest["redaction_report"]
    listed = [r for r in rr["field_redactions"]
              if "note" in r["fields"]]
    rc, out, err = _run_verifier(d, pins=True)
    if rc == 0 and listed:
        _report(name, "HELD",
                "legit redaction verifies; report lists %d entries"
                % len(listed))
    else:
        _report(name, "BREAK",
                "legit redaction failed (rc=%d, listed=%d)"
                % (rc, len(listed)))


def main():
    global LOG_PUB, ENTRY_PUB
    tmp = tempfile.mkdtemp(prefix="ob_adv_")
    try:
        log_path, signer, adapter = _setup(tmp)
        LOG_PUB = adapter.public_key.hex()
        ENTRY_PUB = signer.public_key.hex()
        bundle_dir = _export(tmp, log_path, signer, adapter)

        print("probes (expect HELD):")
        b1_full_rewrite(tmp, bundle_dir)
        b2_entry_tamper(tmp, bundle_dir)
        b3_entry_drop(tmp, bundle_dir)
        b4_forged_receipt(tmp, bundle_dir)
        b5_redaction_lie(tmp, bundle_dir, adapter)
        print("controls (expect HELD):")
        c1_honest_pinned(tmp, bundle_dir)
        c2_honest_unpinned(tmp, bundle_dir)
        c3_honest_redacted(tmp, log_path, signer, adapter)

        n_break = sum(1 for _, v, _ in RESULTS if v == "BREAK")
        print("----")
        print("%d/%d HELD" % (len(RESULTS) - n_break, len(RESULTS)))
        return 1 if n_break else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
