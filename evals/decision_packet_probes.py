#!/usr/bin/env python3
"""Break-first probes for wave-176 candidate: constructive decision packets
(OpenShell prospectus steal #2).

Every consequential policy decision should emit a SIGNED, SELF-DESCRIBING
decision packet at the policy decision seam -- decision (allow/deny/queue),
the authority-proof outcome (or "no boundary configured"), canonical target,
preview digest, capability-manifest digest, memory act-gate tier, carrier
disclosures, and the evidence-chain head digest it appends under. Every
field names its producer and version; verification needs no engine.

RED on the unmodified tree (no gov/decision_packet.py, no executor seam):
all probes fail because nothing emits or verifies decision packets.
GREEN after the lane: all probes pass.

Usage:
  python3 evals/decision_packet_probes.py --red-phase   # expect all RED,
                                                       # exit 0 = gap shown
  python3 evals/decision_packet_probes.py               # expect all PASS

Deterministic: fresh random keys per run, but no assertion depends on key
material, timestamps, or run ids. main() runs the battery twice and
requires identical statuses.

Conventions: module-level GOV_DEPLOYMENT_MODE=staging; verify standalone
under `env -u GOV_DEPLOYMENT_MODE`; GOV_SKIP_GREEN honored; green check is
depth-1 (adjacent unit module only, child env GOV_SKIP_GREEN=1); the
battery never touches the shared tree -- TREE is the tree it lives in.
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


def _dp():
    """Import the lane module, or raise ImportError on the unmodified tree."""
    from gov import decision_packet as dp
    return dp


def _bom(**over):
    """A Decision BOM consistent with the probe's minimal packets."""
    from gov import decision_bom as bom_mod
    kw = dict(policy_id="default", policy_version="unversioned",
              policy_digest="ab" * 32,
              evidence_head_digest="GENESIS",
              principal={"agent_id": None, "role": None,
                         "principal": None, "run_id": None})
    kw.update(over)
    return bom_mod.build_bom(**kw)


def _set_packet_key():
    """Configure a fresh packet-signing key via the env backend. Returns
    (seed_hex, restore)."""
    prev_key = os.environ.get("GOV_DECISION_PACKET_KEY")
    prev_file = os.environ.get("GOV_DECISION_PACKET_KEY_FILE")
    seed = os.urandom(32)
    os.environ["GOV_DECISION_PACKET_KEY"] = seed.hex()
    os.environ.pop("GOV_DECISION_PACKET_KEY_FILE", None)

    def restore():
        if prev_key is None:
            os.environ.pop("GOV_DECISION_PACKET_KEY", None)
        else:
            os.environ["GOV_DECISION_PACKET_KEY"] = prev_key
        if prev_file is None:
            os.environ.pop("GOV_DECISION_PACKET_KEY_FILE", None)
        else:
            os.environ["GOV_DECISION_PACKET_KEY_FILE"] = prev_file

    return seed.hex(), restore


def _packet_entries(entries):
    return [e for e in entries if e.get("event") == "decision_packet"]


# -- probes ---------------------------------------------------------------

def probe_module_importable():
    try:
        dp = _dp()
    except ImportError:
        return "FAIL", "gov.decision_packet absent (gap)"
    for name in ("build_decision_packet", "sign_packet",
                 "verify_decision_packet", "resolve_packet_key",
                 "DECISION_PACKET_VERSION"):
        assert hasattr(dp, name), "missing %s" % name
    assert dp.DECISION_PACKET_VERSION == 1
    return "PASS", "module present, builder/signer/verifier exported"


def probe_executor_emits_on_allow():
    try:
        dp = _dp()
    except ImportError:
        return "FAIL", "gov.decision_packet absent (gap)"
    provision_test_key(epoch="test")
    _, restore = _set_packet_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(run, "data/x.txt", "bye")
        r = ex.call(ident, "delete_file", path="data/x.txt")
        assert r["status"] == "executed", r
        entries = run["read_log"]()
        pkts = _packet_entries(entries)
        assert len(pkts) == 1, \
            "expected 1 decision_packet entry, got %d" % len(pkts)
        packet = pkts[0]["packet"]
        ok, reason = dp.verify_decision_packet(packet, entries)
        assert ok, reason
        assert packet["decision"]["value"] == "allow", packet["decision"]
        assert pkts[0]["packet_digest"] == dp.packet_digest(packet)
        return "PASS", "allow-path packet emitted, signed, chain-linked"
    finally:
        restore()


def probe_executor_emits_on_deny():
    try:
        dp = _dp()
    except ImportError:
        return "FAIL", "gov.decision_packet absent (gap)"
    provision_test_key(epoch="test")
    _, restore = _set_packet_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        # A POLICY-level deny (deny-delete-outside-sandbox) -- this reaches
        # the final deny routing. Pre-decision fail-closed gates (unknown
        # tool, role-allowlist) return before the decision seam and carry
        # no packet by design (their chained denial entry is the record).
        r = ex.call(ident, "delete_file",
                    path="/tmp/definitely-outside-sandbox-dp.txt")
        assert r["status"] == "denied", r
        entries = run["read_log"]()
        pkts = _packet_entries(entries)
        assert len(pkts) == 1, \
            "expected 1 decision_packet entry, got %d" % len(pkts)
        packet = pkts[0]["packet"]
        ok, reason = dp.verify_decision_packet(packet, entries)
        assert ok, reason
        assert packet["decision"]["value"] == "deny", packet["decision"]
        return "PASS", "deny-path packet emitted, signed, chain-linked"
    finally:
        restore()


def probe_executor_emits_on_queue():
    try:
        dp = _dp()
    except ImportError:
        return "FAIL", "gov.decision_packet absent (gap)"
    provision_test_key(epoch="test")
    _, restore = _set_packet_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        # quarantine-outside-writes: coder may use write_file, but an
        # outside-sandbox write requires approval -- reaches the final
        # queue routing (send_email is role-denied for coder, so it never
        # reaches the seam).
        r = ex.call(ident, "write_file",
                    path="/tmp/definitely-outside-sandbox-dp.txt",
                    content="hello")
        assert r["status"] == "queued", r
        entries = run["read_log"]()
        pkts = _packet_entries(entries)
        assert len(pkts) == 1, \
            "expected 1 decision_packet entry, got %d" % len(pkts)
        packet = pkts[0]["packet"]
        ok, reason = dp.verify_decision_packet(packet, entries)
        assert ok, reason
        assert packet["decision"]["value"] == "queue", packet["decision"]
        assert packet["approval_id"]["value"] == r["approval_id"], \
            packet["approval_id"]
        return "PASS", "queue-path packet emitted alongside approval queue"
    finally:
        restore()


def _one_signed_packet():
    """Build one real executor-emitted packet plus its chain entries."""
    dp = _dp()
    provision_test_key(epoch="test")
    _, restore = _set_packet_key()
    try:
        run = make_run()
        ex = run["executor"]
        ident = run["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(run, "data/x.txt", "bye")
        r = ex.call(ident, "delete_file", path="data/x.txt")
        assert r["status"] == "executed", r
        entries = run["read_log"]()
        pkts = _packet_entries(entries)
        assert len(pkts) == 1
        return copy.deepcopy(pkts[0]["packet"]), entries
    finally:
        restore()


def probe_tamper_detected():
    try:
        dp = _dp()
    except ImportError:
        return "FAIL", "gov.decision_packet absent (gap)"
    packet, _ = _one_signed_packet()
    cases = []
    p = copy.deepcopy(packet)
    p["decision"]["value"] = "deny"
    cases.append(("decision", p))
    p = copy.deepcopy(packet)
    p["preview_digest"]["value"] = "f" * 64
    cases.append(("preview_digest", p))
    p = copy.deepcopy(packet)
    p["canonical_target"]["value"] = "/etc/shadow-synthetic"
    cases.append(("canonical_target", p))
    for name, mutated in cases:
        ok, _ = dp.verify_decision_packet(mutated)
        assert not ok, "verifier accepted tampered %s" % name
    return "PASS", "3/3 tampered fields refused (signature binds body)"


def probe_missing_proof_refused():
    """A packet that claims a boundary is configured but carries no
    authority proof is refused -- at build time AND at verify time."""
    try:
        dp = _dp()
    except ImportError:
        return "FAIL", "gov.decision_packet absent (gap)"
    seed_hex, restore = _set_packet_key()
    try:
        try:
            dp.build_decision_packet(
                decision="allow", boundary_declared=True,
                authority_proof=None, evidence_head_digest="GENESIS",
                policy_bundle_digest="ab" * 32,
                bill_of_materials=_bom())
            return "FAIL", "build accepted proof-less packet with " \
                "boundary declared"
        except dp.PacketError:
            pass
        # Forged: flip boundary_declared on a no-boundary packet, re-sign,
        # then verify must refuse on the proof rule (not just the sig).
        body = dp.build_decision_packet(
            decision="allow", boundary_declared=False,
            authority_proof=None, evidence_head_digest="GENESIS",
            policy_bundle_digest="ab" * 32,
            bill_of_materials=_bom())
        body["boundary_declared"]["value"] = True
        forged = dp.sign_packet(body, bytes.fromhex(seed_hex))
        ok, reason = dp.verify_decision_packet(forged)
        assert not ok, "verifier accepted proof-less declared-boundary packet"
        assert "authority" in reason.lower() or "proof" in reason.lower(), \
            reason
        return "PASS", "proof-less declared-boundary packet refused x2"
    finally:
        restore()


def probe_stale_head_detected():
    try:
        dp = _dp()
    except ImportError:
        return "FAIL", "gov.decision_packet absent (gap)"
    packet, entries = _one_signed_packet()
    stale = copy.deepcopy(packet)
    stale["evidence"]["value"]["head_digest"] = "0" * 64
    # Re-sign under the stale head so the failure is the LINKAGE, not
    # the signature: the packet is well-formed but names a head the
    # chain never had.
    seed_hex, restore = _set_packet_key()
    try:
        body = {k: v for k, v in stale.items() if k != "signature"}
        body.pop("authority", None)
        resealed = dp.sign_packet(body, bytes.fromhex(seed_hex))
    finally:
        restore()
    ok, reason = dp.verify_decision_packet(resealed, entries)
    assert not ok, "verifier accepted stale evidence-head digest"
    assert "head" in reason.lower() or "link" in reason.lower(), reason
    return "PASS", "stale evidence-head digest refused at linkage"


def probe_deterministic():
    try:
        dp = _dp()
    except ImportError:
        return "FAIL", "gov.decision_packet absent (gap)"
    seed = bytes.fromhex("22" * 32)
    kw = dict(decision="allow", boundary_declared=False,
              authority_proof=None, evidence_head_digest="GENESIS",
              issued_at="2026-09-28T00:00:00+00:00",
              policy_bundle_digest="ab" * 32,
              bill_of_materials=_bom())
    a = dp.sign_packet(dp.build_decision_packet(**kw), seed)
    b = dp.sign_packet(dp.build_decision_packet(**kw), seed)
    assert dp.canonical_bytes(a) == dp.canonical_bytes(b), \
        "identical inputs diverged"
    return "PASS", "build+sign deterministic x2"


def probe_fields_name_producers():
    """Every packet field is self-describing: value + producer + version."""
    try:
        dp = _dp()
    except ImportError:
        return "FAIL", "gov.decision_packet absent (gap)"
    packet, _ = _one_signed_packet()
    assert packet["decision_packet_version"] == 1
    wrapped = ("decision", "boundary_declared", "authority_proof", "policy",
               "canonical_target", "preview_digest",
               "capability_manifest", "memory_actgate", "carriers",
               "evidence", "identity", "approval_id", "bill_of_materials",
               "issued_at")
    for name in wrapped:
        section = packet.get(name)
        assert isinstance(section, dict), "missing section %s" % name
        assert "value" in section, "no value in %s" % name
        assert section.get("producer"), "no producer in %s" % name
        assert section.get("producer_version"), \
            "no producer_version in %s" % name
    assert packet["authority"]["pubkey"] and packet["authority"]["kid"]
    assert packet["signature"]
    return "PASS", "%d sections all name producer+version" % len(wrapped)


def probe_offline_verify():
    """A subprocess that can see ONLY copies of decision_packet.py,
    decision_bom.py and ed25519.py (stdlib) verifies a signed packet --
    no engine, no gov package. This is the true offline path."""
    try:
        dp = _dp()
    except ImportError:
        return "FAIL", "gov.decision_packet absent (gap)"
    packet, _ = _one_signed_packet()
    tmp = tempfile.mkdtemp(prefix="dpacket-offline-")
    try:
        for leaf in ("decision_packet.py", "decision_bom.py",
                     "ed25519.py"):
            shutil.copy(os.path.join(TREE, "gov", leaf),
                        os.path.join(tmp, leaf))
        with open(os.path.join(tmp, "packet.json"), "w",
                   encoding="utf-8") as f:
            json.dump(packet, f)
        script = (
            "import sys, json, os\n"
            "sys.path.insert(0, %r)\n"
            "assert 'gov' not in sys.modules\n"
            "import decision_packet as dp\n"
            "assert dp.__file__.startswith(%r), dp.__file__\n"
            "packet = json.load(open(os.path.join(%r, 'packet.json')))\n"
            "ok, reason = dp.verify_decision_packet(packet)\n"
            "print('standalone:', ok, reason)\n"
            "assert ok, reason\n"
            "assert 'gov.decision_packet' not in sys.modules\n"
            "print('OFFLINE_OK')\n"
        ) % (tmp, tmp, tmp)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["GOV_SKIP_GREEN"] = "1"
        p = subprocess.run(
            [sys.executable, "-c", script], capture_output=True,
            text=True, timeout=120, cwd=tmp, env=env)
        assert "OFFLINE_OK" in p.stdout, \
            "stdout=%r stderr=%r" % (p.stdout[-2000:], p.stderr[-2000:])
        return "PASS", "standalone verifier confirms signature, no engine"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


PROBES = [
    ("module_importable", probe_module_importable),
    ("executor_emits_on_allow", probe_executor_emits_on_allow),
    ("executor_emits_on_deny", probe_executor_emits_on_deny),
    ("executor_emits_on_queue", probe_executor_emits_on_queue),
    ("tamper_detected", probe_tamper_detected),
    ("missing_proof_refused", probe_missing_proof_refused),
    ("stale_head_detected", probe_stale_head_detected),
    ("deterministic", probe_deterministic),
    ("fields_name_producers", probe_fields_name_producers),
    ("offline_verify", probe_offline_verify),
]


def _run_once():
    results = []
    for name, fn in PROBES:
        try:
            status, detail = fn()
        except AssertionError as e:
            status, detail = "FAIL", "assertion: %s" % (e,)
        except Exception as e:  # noqa: BLE001 - probes must not crash
            status, detail = "FAIL", "%s: %s" % (type(e).__name__, e)
        results.append((name, status, detail))
    return results


def _green_check():
    """Depth-1: adjacent unit module only, child env GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="dpacket-green-")
    env["TMPDIR"] = tmp
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest",
             "tests.test_decision_packet", "-v"],
            capture_output=True, text=True, timeout=600, cwd=TREE, env=env)
        tail = (p.stdout + p.stderr)[-1500:]
        print("green check (tests/test_decision_packet):\n%s" % tail)
        return p.returncode == 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    red_phase = "--red-phase" in argv
    first = _run_once()
    second = _run_once()
    det_ok = ([(n, s) for n, s, _ in first]
              == [(n, s) for n, s, _ in second])
    width = max(len(n) for n, _, _ in first)
    print("== decision_packet probes (%s) =="
          % ("RED-PHASE: gap demonstration" if red_phase else "GREEN-PHASE"))
    for name, status, detail in first:
        print("%-*s %s  %s" % (width, name, status, detail))
    print("determinism x2: %s" % ("IDENTICAL" if det_ok else "DIVERGED"))
    if red_phase:
        # Gap demonstration: EVERY probe must be RED. Exit 0 = gap shown.
        reds = sum(1 for _, s, _ in first if s != "PASS")
        if reds == len(first) and det_ok:
            print("GAP SHOWN: %d/%d probes RED, statuses identical x2"
                  % (reds, len(first)))
            return 0
        print("RED-PHASE INCONCLUSIVE: %d/%d RED" % (reds, len(first)))
        return 1
    if not _green_check():
        print("GREEN CHECK FAILED")
        return 1
    bad = [(n, d) for n, s, d in first if s != "PASS"]
    if bad or not det_ok:
        print("%d probe(s) failing" % len(bad))
        return 1
    print("ALL %d PROBES PASS" % len(first))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
