#!/usr/bin/env python3
"""Break-first battery for wave-175 lane 1: countersigned invocation receipts.

R7 shortlist #7 (Sigil shape): every consequential tool invocation should
produce a receipt countersigned by the executor over what ACTUALLY
executed (tool, args digest, canonical target, policy decision, preview
digest), hash-chained into the audit log and verifiable offline.

RED on the unmodified tree (no gov/invocation_receipts, no executor seam,
no V17): probes 1-4, 8, 10 fail because nothing mints receipts.
GREEN after the lane: all probes pass.

Deterministic: fresh random keys per run, but no assertion depends on key
material, timestamps, or run ids. main() runs the battery twice and
requires identical results.

Conventions: module-level GOV_DEPLOYMENT_MODE=staging; verify standalone
under `env -u GOV_DEPLOYMENT_MODE`; GOV_SKIP_GREEN honored; green check is
depth-1 (adjacent unit module only, child env GOV_SKIP_GREEN=1).
"""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TREE = REPO_ROOT  # this battery lives in the tree it tests
sys.path.insert(0, TREE)
sys.path.insert(0, os.path.join(TREE, "tests"))

from keyfixture import provision_test_key  # noqa: E402
from harness import make_run, plant_file  # noqa: E402


def _set_receipt_key():
    """Configure a fresh receipt-signing key via the env backend. Returns
    (pubkey_hex, restore) where restore() puts the env back."""
    prev_key = os.environ.get("GOV_RECEIPT_KEY")
    prev_file = os.environ.get("GOV_RECEIPT_KEY_FILE")
    seed = os.urandom(32)
    os.environ["GOV_RECEIPT_KEY"] = seed.hex()
    os.environ.pop("GOV_RECEIPT_KEY_FILE", None)
    sys.path.insert(0, TREE)
    from gov import ed25519 as _ed
    pub = _ed.publickey(seed).hex()

    def restore():
        if prev_key is None:
            os.environ.pop("GOV_RECEIPT_KEY", None)
        else:
            os.environ["GOV_RECEIPT_KEY"] = prev_key
        if prev_file is None:
            os.environ.pop("GOV_RECEIPT_KEY_FILE", None)
        else:
            os.environ["GOV_RECEIPT_KEY_FILE"] = prev_file

    return pub, restore


def _scrub_receipt_key():
    prev_key = os.environ.get("GOV_RECEIPT_KEY")
    prev_file = os.environ.get("GOV_RECEIPT_KEY_FILE")
    os.environ.pop("GOV_RECEIPT_KEY", None)
    os.environ.pop("GOV_RECEIPT_KEY_FILE", None)

    def restore():
        if prev_key is not None:
            os.environ["GOV_RECEIPT_KEY"] = prev_key
        if prev_file is not None:
            os.environ["GOV_RECEIPT_KEY_FILE"] = prev_file

    return restore


def _receipt_entries(entries):
    return [e for e in entries if e.get("event") == "invocation_receipt"]


def probe_direct_path_receipt():
    """A consequential direct-path execution (delete_file, irreversible
    registry) mints exactly one countersigned receipt bound to the
    write-ahead entry."""
    provision_test_key(epoch="test")
    _, restore = _set_receipt_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(run, "data/x.txt", "bye")
        r = ex.call(ident, "delete_file", path="data/x.txt")
        assert r["status"] == "executed", r
        entries = run["read_log"]()
        receipts = _receipt_entries(entries)
        assert len(receipts) == 1, \
            "expected 1 receipt, got %d" % len(receipts)
        entry = receipts[0]
        receipt = entry["receipt"]
        # Offline verification of the countersignature.
        from gov import invocation_receipts as ir
        ok, reason = ir.verify_receipt(receipt)
        assert ok, reason
        # Challenge binds the write-ahead execution_authorized entry.
        auth = [e for e in entries
                if e.get("event") == "tool_call"
                and e.get("decision") == "execution_authorized"]
        assert auth, "no write-ahead execution_authorized entry"
        assert receipt["challenge"] == "direct:%s" % auth[-1]["seq"], \
            receipt["challenge"]
        # Args digest binds the exact executed (sentinel-form) args.
        from gov import precommit as pc
        assert receipt["action"]["args_digest"] == pc.args_digest(
            "delete_file", {"path": "data/x.txt"}), "args digest mismatch"
        assert receipt["action"]["tool"] == "delete_file"
        # The receipt event itself is hash-chained like every entry.
        assert entry.get("hash") and entry.get("seq") is not None
        return "PASS", "direct delete_file receipt countersigned, " \
            "challenge=%s" % receipt["challenge"]
    finally:
        restore()


def probe_approved_path_receipt():
    """An approved-sweep consequential execution (send_email) mints exactly
    one countersigned receipt bound to the approval."""
    provision_test_key(epoch="test")
    _, restore = _set_receipt_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["identities"]["researcher"]
        send = ex.call(ident, "send_email", to="u@synthetic.local",
                       subject="s", body="hello")
        assert send["status"] == "queued", send
        aid = send["approval_id"]
        run["approvals"].decide(aid, True, "ok")
        done = ex.execute_approved()
        assert len(done) == 1, done
        entries = run["read_log"]()
        receipts = _receipt_entries(entries)
        assert len(receipts) == 1, \
            "expected 1 receipt, got %d" % len(receipts)
        receipt = receipts[0]["receipt"]
        from gov import invocation_receipts as ir
        ok, reason = ir.verify_receipt(receipt)
        assert ok, reason
        assert receipt["challenge"] == aid, receipt["challenge"]
        assert receipt["policy"]["approval_id"] == aid
        assert receipt["action"]["tool"] == "send_email"
        return "PASS", "approved send_email receipt countersigned, " \
            "challenge=%s" % aid
    finally:
        restore()


def probe_offline_standalone():
    """The receipt verifies in a subprocess that can see ONLY a copy of
    gov/evidence_verify.py (stdlib) — no repo, no gov.invocation_receipts.
    This is the true offline path."""
    provision_test_key(epoch="test")
    _, restore = _set_receipt_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(run, "data/x.txt", "bye")
        r = ex.call(ident, "delete_file", path="data/x.txt")
        assert r["status"] == "executed", r
        receipts = _receipt_entries(run["read_log"]())
        assert len(receipts) == 1
        receipt = receipts[0]["receipt"]

        tmp = tempfile.mkdtemp(prefix="receipt-offline-")
        try:
            shutil.copy(os.path.join(TREE, "gov", "evidence_verify.py"),
                        os.path.join(tmp, "evidence_verify.py"))
            with open(os.path.join(tmp, "receipt.json"), "w",
                       encoding="utf-8") as f:
                json.dump(receipt, f)
            script = (
                "import sys, json, os\n"
                "sys.path.insert(0, %r)\n"
                "assert 'gov' not in sys.modules\n"
                "import evidence_verify as ev\n"
                "assert ev.__file__.startswith(%r), ev.__file__\n"
                "receipt = json.load(open(os.path.join(%r, 'receipt.json')))\n"
                "ok, reason = ev._verify_receipt_standalone(receipt)\n"
                "print('standalone:', ok, reason)\n"
                "assert ok, reason\n"
                "assert 'gov.invocation_receipts' not in sys.modules\n"
                "print('OFFLINE_OK')\n"
            ) % (tmp, tmp, tmp)
            env = {k: v for k, v in os.environ.items()
                   if k != "PYTHONPATH"}
            env["GOV_SKIP_GREEN"] = "1"
            p = subprocess.run(
                [sys.executable, "-c", script], capture_output=True,
                text=True, timeout=120, cwd=tmp, env=env)
            assert "OFFLINE_OK" in p.stdout, \
                "stdout=%r stderr=%r" % (p.stdout[-2000:], p.stderr[-2000:])
            return "PASS", "vendored verifier confirms countersignature " \
                "with no repo on sys.path"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    finally:
        restore()


def _tamper_cases(receipt):
    """Yield (name, mutated_receipt) for the four bound fields."""
    cases = []
    r = copy.deepcopy(receipt)
    r["action"]["args_digest"] = "0" * 64
    cases.append(("args_digest", r))
    r = copy.deepcopy(receipt)
    r["action"]["canonical_target"] = "/etc/shadow-synthetic"
    cases.append(("canonical_target", r))
    r = copy.deepcopy(receipt)
    r["policy"]["decision"] = "execution_refused"
    cases.append(("policy_decision", r))
    r = copy.deepcopy(receipt)
    r["preview_digest"] = "f" * 64
    cases.append(("preview_digest", r))
    return cases


def probe_tamper_fails():
    """Mutating any bound field (args digest, canonical target, policy
    decision, preview digest) breaks the countersignature — in-repo and in
    the standalone verifier."""
    provision_test_key(epoch="test")
    _, restore = _set_receipt_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(run, "data/x.txt", "bye")
        r = ex.call(ident, "delete_file", path="data/x.txt")
        assert r["status"] == "executed", r
        receipts = _receipt_entries(run["read_log"]())
        assert len(receipts) == 1
        receipt = receipts[0]["receipt"]
        from gov import invocation_receipts as ir
        from gov import evidence_verify as ev
        for name, mutated in _tamper_cases(receipt):
            ok, _ = ir.verify_receipt(mutated)
            assert not ok, "in-repo verifier accepted tampered %s" % name
            ok2, _ = ev._verify_receipt_standalone(mutated)
            assert not ok2, \
                "standalone verifier accepted tampered %s" % name
        return "PASS", "4/4 tampered fields refused by both verifiers"
    finally:
        restore()


def probe_chained_linkage():
    """The invocation_receipt event is part of the hash chain: the log
    replays clean end-to-end with the receipt entry included."""
    provision_test_key(epoch="test")
    _, restore = _set_receipt_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(run, "data/x.txt", "bye")
        r = ex.call(ident, "delete_file", path="data/x.txt")
        assert r["status"] == "executed", r
        from gov.log import verify_chain
        ok, broken, count = verify_chain(
            str(run["run_dir"] / "actions.jsonl"))
        assert ok, "chain broken at seq %s" % (broken,)
        receipts = _receipt_entries(run["read_log"]())
        assert len(receipts) == 1 and count > 0
        return "PASS", "chain replays clean over %d entries incl. receipt" \
            % count
    finally:
        restore()


def probe_denied_no_receipt():
    """A denied consequential invocation produces NO receipt: nothing
    executed, so there is nothing to countersign."""
    provision_test_key(epoch="test")
    _, restore = _set_receipt_key()
    try:
        from gov import precommit as pc
        gate = pc.PrecommitGate()
        run = make_run(precommit_gate=gate)
        ex = run["executor"]
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(run, "data/x.txt", "bye")
        r = ex.call(ident, "delete_file", path="data/x.txt")
        assert r["status"] == "denied", r
        receipts = _receipt_entries(run["read_log"]())
        assert not receipts, "denied invocation minted a receipt"
        return "PASS", "denied delete_file left zero receipts"
    finally:
        restore()


def probe_benign_no_receipt():
    """A non-consequential benign invocation (read_file) executes normally
    with no receipt and no refusal: receipts are evidence of consequential
    execution, not a per-read tax."""
    provision_test_key(epoch="test")
    _, restore = _set_receipt_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["identities"]["researcher"]
        plant_file(run, "data/n.txt", "hello")
        r = ex.call(ident, "read_file", path="data/n.txt")
        assert r["status"] == "executed", r
        entries = run["read_log"]()
        receipts = _receipt_entries(entries)
        assert not receipts, "benign read minted a receipt"
        failed = [e for e in entries
                  if e.get("event") == "invocation_receipt_failed"]
        assert not failed, "benign read raised a receipt failure"
        return "PASS", "read_file executed, zero receipts, zero failures"
    finally:
        restore()


def probe_missing_key_fail_closed():
    """Fail-closed: a deployment that EXPRESSED receipt intent but whose
    custody is broken gets NoReceiptKeyError during executor construction
    — before any side effect can happen. No executor exists, so nothing
    can execute."""
    provision_test_key(epoch="test")
    from gov import invocation_receipts as ir
    # (a) env-configured but malformed key: make_run must raise.
    prev = os.environ.get("GOV_RECEIPT_KEY")
    prev_file = os.environ.get("GOV_RECEIPT_KEY_FILE")
    os.environ["GOV_RECEIPT_KEY"] = "zz"
    os.environ.pop("GOV_RECEIPT_KEY_FILE", None)
    try:
        try:
            make_run()
            raise AssertionError(
                "make_run with malformed GOV_RECEIPT_KEY did not raise")
        except ir.NoReceiptKeyError:
            pass
    finally:
        if prev is None:
            os.environ.pop("GOV_RECEIPT_KEY", None)
        else:
            os.environ["GOV_RECEIPT_KEY"] = prev
        if prev_file is not None:
            os.environ["GOV_RECEIPT_KEY_FILE"] = prev_file
    # (b) explicit malformed seed resolves fail-closed too.
    for bad in ("not-hex", "00" * 31):
        try:
            ir.resolve_receipt_key(explicit=bad)
            raise AssertionError(
                "explicit bad seed %r did not raise" % bad)
        except ir.NoReceiptKeyError:
            pass
    return "PASS", "broken custody raises NoReceiptKeyError before execution"


def probe_no_key_loud_disabled():
    """No key configured (opt-in off): one loud chained
    invocation_receipts_disabled event, executions proceed, zero receipts.
    Never silent."""
    provision_test_key(epoch="test")
    restore = _scrub_receipt_key()
    try:
        run = make_run()
        ex = run["executor"]
        entries = run["read_log"]()
        disabled = [e for e in entries
                    if e.get("event") == "invocation_receipts_disabled"]
        assert len(disabled) == 1, \
            "expected 1 loud disabled event, got %d" % len(disabled)
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(run, "data/x.txt", "bye")
        r = ex.call(ident, "delete_file", path="data/x.txt")
        assert r["status"] == "executed", r
        entries = run["read_log"]()
        assert not _receipt_entries(entries), \
            "receipt minted with no key configured"
        return "PASS", "loud disabled event; execution unblocked; " \
            "zero receipts"
    finally:
        restore()


def probe_v17_verifier():
    """V17 (evidence-bundle verifier extension): ok self-consistent without
    a pin, ok authorship with the pinned key, fail on a wrong pin, n/a when
    the window has no receipts."""
    provision_test_key(epoch="test")
    pub, restore = _set_receipt_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(run, "data/x.txt", "bye")
        r = ex.call(ident, "delete_file", path="data/x.txt")
        assert r["status"] == "executed", r
        entries = run["read_log"]()
        receipts = _receipt_entries(entries)
        assert len(receipts) == 1

        from types import SimpleNamespace
        from gov import evidence_verify as ev

        ctx = SimpleNamespace(slice_entries=receipts, receipt_pins=[])
        c = ev.v17_invocation_receipts(ctx)
        assert c.status == "pass", (c.status, c.detail)
        assert "NOT established" in c.detail, c.detail

        ctx = SimpleNamespace(slice_entries=receipts,
                              receipt_pins=[pub])
        c = ev.v17_invocation_receipts(ctx)
        assert c.status == "pass", (c.status, c.detail)
        assert "pinned" in c.detail, c.detail

        ctx = SimpleNamespace(slice_entries=receipts,
                              receipt_pins=["ab" * 32])
        c = ev.v17_invocation_receipts(ctx)
        assert c.status == "fail", (c.status, c.detail)

        ctx = SimpleNamespace(slice_entries=[], receipt_pins=[])
        c = ev.v17_invocation_receipts(ctx)
        assert c.status == "not_applicable", (c.status, c.detail)
        return "PASS", "V17 pass/pass-pinned/fail-wrong-pin/na-empty"
    finally:
        restore()


PROBES = [
    ("direct_path_receipt", probe_direct_path_receipt),
    ("approved_path_receipt", probe_approved_path_receipt),
    ("offline_standalone", probe_offline_standalone),
    ("tamper_fails", probe_tamper_fails),
    ("chained_linkage", probe_chained_linkage),
    ("denied_no_receipt", probe_denied_no_receipt),
    ("benign_no_receipt", probe_benign_no_receipt),
    ("missing_key_fail_closed", probe_missing_key_fail_closed),
    ("no_key_loud_disabled", probe_no_key_loud_disabled),
    ("v17_verifier", probe_v17_verifier),
]


def run_battery():
    results = []
    for name, fn in PROBES:
        try:
            status, detail = fn()
        except Exception as e:  # noqa: BLE001 - battery reports, not raises
            import traceback
            status = "FAIL"
            detail = "%s: %s" % (type(e).__name__, e)
            traceback.print_exc()
        results.append((name, status, detail))
    return results


def green_check():
    """Depth-1 green check: the adjacent unit module only.

    Honors GOV_SKIP_GREEN (parent sets it; we record the skip and return).
    Never spawns another battery.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_invocation_receipts",
         "-q"], cwd=TREE, env=env,
        capture_output=True, text=True, timeout=600)
    ok = r.returncode == 0
    print("green_check: adjacent invocation-receipt unit tests %s"
          % ("PASS" if ok else "FAIL"))
    if not ok:
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
    return ok


def main():
    first = run_battery()
    second = run_battery()
    # Determinism: identical pass/fail outcomes across two runs (details
    # may differ in run-specific ids; statuses must not).
    det_ok = [s for _, s, _ in first] == [s for _, s, _ in second]
    width = max(len(n) for n, _, _ in first)
    reds = 0
    for name, status, detail in first:
        if status != "PASS":
            reds += 1
        print("%-*s %s  %s" % (width, name, status, detail))
    print("determinism x2: %s" % ("IDENTICAL" if det_ok else "DIVERGED"))
    if not green_check():
        print("GREEN CHECK FAILED")
        return 1
    if reds or not det_ok:
        print("%d probe(s) failing" % reds)
        return 1
    print("ALL %d PROBES PASS" % len(first))
    return 0


if __name__ == "__main__":
    sys.exit(main())
