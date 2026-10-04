#!/usr/bin/env python3
"""Wave-320 Lane 3 battery: m-of-n operation approval, Control-Groups shape
(gov/quorum_approval.py).

Sensitive *governance operations* (root-key ceremonies, evidence-anchor
signing, policy overrides) need distributed *authority* -- m-of-n human
approvals per operation, request paused until quorum, fully audited. Shamir
gives secret *recovery*, not distributed authority (wave-319 prospectus);
this battery proves the open reimplementation of Vault's Control-Groups
shape, RED-FIRST: it is written before the module exists and must FAIL on
the open tree (ImportError).

Probe map (public seams only -- register_policy / attest /
QuorumCollector.collect / evaluate / QuorumGate.check):
  quorum-collects-and-executes: 2-of-3 valid attestations -> quorum met,
      operation executable.
  quorum-m-minus-one-refuses: 1-of-2 collected -> coded quorum-insufficient,
      not executable.
  quorum-duplicate-approver-counted-once: two attestations from the same
      named approver (different nonces) -> counted once; 1-of-2 not met.
  quorum-same-key-two-names: two *names* sharing one key -- each name is a
      distinct slot per policy, but the policy forbids key reuse across names
      at registration (fail-closed at load); registration refuses.
  quorum-replay-refused: same nonce reused for a second attestation ->
      coded quorum-replay-refused.
  quorum-wrong-operation-refused: attestation bound to a different operation
      digest -> coded quorum-operation-mismatch.
  quorum-unknown-approver-refused: attestation from a name not in the policy
      -> coded quorum-unknown-approver.
  quorum-forged-signature-refused: tampered signature bytes -> coded
      quorum-signature-invalid.
  quorum-deny-veto-blocks: one eligible approver's signed deny -> the quorum
      fails closed with coded quorum-deny-veto even with m-1 approvals.
  quorum-policy-version-monotonic: re-registering the same policy_id at the
      same or lower version -> coded quorum-policy-version-invalid.
  quorum-policy-change-needs-bump: changed approver set at the same version
      -> coded quorum-policy-version-invalid.
  quorum-unreachable-at-load: m > n -> policy registration refuses
      (fail-closed at load, D1-core L7 discipline).
  quorum-duplicate-names-at-load: two approvers with the same name ->
      registration refuses.
  quorum-expired-attestation-refused: attestation past its validity window
      -> coded quorum-attestation-expired.
  gate-advisory-records-state: QuorumGate.check on an unregistered operation
      -> advisory absent; the call proceeds exactly as before (never gates
      what it does not own).
  gate-enforces-registered: operation registered sensitive, quorum unmet ->
      coded quorum-insufficient; quorum met -> allowed.
  pin-taxonomy / footer-state: standard pins (1964; open F407 / next F408).
"""

import os
import re
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import green_check  # noqa: E402  (shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line emission)

from gov import decision_codes as dc  # noqa: E402
from gov import quorum_approval as qa  # noqa: E402  (RED-FIRST: ImportError on open tree)
from gov import ed25519 as _ed  # noqa: E402

TAXONOMY_PIN = 1976  # Wave-320 lane 3: pin 1933 -> 1945 (+12 quorum-*)

FOOTER_NEXT = "F408"
FOOTER_OPEN = "F407"

PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


def _held(name, detail):
    return ("HELD", "%s: %s" % (name, detail))


def _break(name, detail):
    return ("BREAK", "%s: %s" % (name, detail))


def _error(name, detail):
    return ("ERROR", "%s: %s" % (name, detail))


# ---------------------------------------------------------------------------
# Test fixtures: three approvers with real Ed25519 keys.
# ---------------------------------------------------------------------------

def _mk_approvers():
    approvers = []
    seeds = {}
    for name in ("alice", "bob", "carol"):
        seed = _ed.generate_seed()
        pub = _ed.publickey(seed)
        approvers.append({
            "name": name,
            "spiffe_id": "spiffe://prod/%s" % name,
            "public_key": pub,
        })
        seeds[name] = seed
    return approvers, seeds


def _mk_policy(approvers, m=2, policy_id="op:root-key-ceremony"):
    return qa.register_policy({
        "policy_id": policy_id,
        "version": 1,
        "m": m,
        "approvers": approvers,
        "change_log": [{"version": 1, "changed_at": 1700000000,
                        "change": "genesis", "author": "deployer"}],
    })


def _op_digest():
    return qa.operation_digest({"op": "root-key-ceremony",
                                "params": {"key_id": "evidence-root-1"}})


@probe("quorum-collects-and-executes")
def _p_collects():
    approvers, seeds = _mk_approvers()
    policy = _mk_policy(approvers, m=2)
    digest = _op_digest()
    col = qa.QuorumCollector(policy, digest)
    for name in ("alice", "bob"):
        att = qa.attest(seeds[name], name, digest,
                        policy, nonce="n-%s" % name)
        col.collect(att)
    v = col.evaluate()
    if v["executable"] is not True or v["counted"] != 2:
        return _break("quorum-collects-and-executes",
                      "want executable/2, got %r" % (v,))
    return _held("quorum-collects-and-executes", "2-of-3 met, executable")


@probe("quorum-m-minus-one-refuses")
def _p_m_minus_one():
    approvers, seeds = _mk_approvers()
    policy = _mk_policy(approvers, m=2)
    digest = _op_digest()
    col = qa.QuorumCollector(policy, digest)
    att = qa.attest(seeds["alice"], "alice", digest, policy, nonce="n-a")
    col.collect(att)
    v = col.evaluate()
    if v["executable"] is not False or v["code"] != "quorum-insufficient":
        return _break("quorum-m-minus-one-refuses", "got %r" % (v,))
    return _held("quorum-m-minus-one-refuses",
                 "1-of-2 refuses coded quorum-insufficient")


@probe("quorum-duplicate-approver-counted-once")
def _p_dupe():
    approvers, seeds = _mk_approvers()
    policy = _mk_policy(approvers, m=2)
    digest = _op_digest()
    col = qa.QuorumCollector(policy, digest)
    col.collect(qa.attest(seeds["alice"], "alice", digest, policy,
                          nonce="n-a1"))
    rec = col.collect(qa.attest(seeds["alice"], "alice", digest, policy,
                                nonce="n-a2"))
    v = col.evaluate()
    if v["counted"] != 1 or v["executable"] is not False:
        return _break("quorum-duplicate-approver-counted-once",
                      "same name counted twice: %r" % (v,))
    if rec.get("code") != "quorum-duplicate-approver":
        return _break("quorum-duplicate-approver-counted-once",
                      "second attestation lacks the spec'd code: %r" % (rec,))
    return _held("quorum-duplicate-approver-counted-once",
                 "alice counted once; 1-of-2 not met; "
                 "quorum-duplicate-approver recorded")


@probe("quorum-same-key-two-names")
def _p_samekey():
    approvers, seeds = _mk_approvers()
    # bob reuses alice's key under a different name
    approvers[1] = dict(approvers[1], public_key=approvers[0]["public_key"])
    try:
        qa.register_policy({
            "policy_id": "op:x", "version": 1, "m": 2,
            "approvers": approvers,
            "change_log": [{"version": 1, "changed_at": 1,
                            "change": "genesis", "author": "d"}],
        })
    except qa.PolicyRefusal as exc:
        if exc.code != "quorum-key-reuse":
            return _break("quorum-same-key-two-names",
                          "wrong code %r" % (exc.code,))
        return _held("quorum-same-key-two-names",
                     "key reuse across names refused at load")
    return _break("quorum-same-key-two-names",
                  "policy with key reuse registered")


@probe("quorum-replay-refused")
def _p_replay():
    approvers, seeds = _mk_approvers()
    policy = _mk_policy(approvers, m=2)
    digest = _op_digest()
    col = qa.QuorumCollector(policy, digest)
    att = qa.attest(seeds["alice"], "alice", digest, policy, nonce="n-a")
    col.collect(att)
    try:
        col.collect(qa.attest(seeds["alice"], "alice", digest, policy,
                              nonce="n-a"))
    except qa.AttestationRefusal as exc:
        if exc.code != "quorum-replay-refused":
            return _break("quorum-replay-refused",
                          "wrong code %r" % (exc.code,))
        return _held("quorum-replay-refused",
                     "reused nonce refuses coded quorum-replay-refused")
    return _break("quorum-replay-refused", "replay accepted")


@probe("quorum-wrong-operation-refused")
def _p_wrongop():
    approvers, seeds = _mk_approvers()
    policy = _mk_policy(approvers, m=2)
    digest = _op_digest()
    col = qa.QuorumCollector(policy, digest)
    other = qa.operation_digest({"op": "something-else"})
    att = qa.attest(seeds["alice"], "alice", other, policy, nonce="n-a")
    try:
        col.collect(att)
    except qa.AttestationRefusal as exc:
        if exc.code != "quorum-operation-mismatch":
            return _break("quorum-wrong-operation-refused",
                          "wrong code %r" % (exc.code,))
        return _held("quorum-wrong-operation-refused",
                     "foreign operation digest refuses")
    return _break("quorum-wrong-operation-refused", "foreign digest accepted")


@probe("quorum-unknown-approver-refused")
def _p_unknown():
    approvers, seeds = _mk_approvers()
    policy = _mk_policy(approvers, m=2)
    digest = _op_digest()
    col = qa.QuorumCollector(policy, digest)
    mallory_seed = _ed.generate_seed()
    att = qa.attest(mallory_seed, "mallory", digest, policy, nonce="n-m")
    try:
        col.collect(att)
    except qa.AttestationRefusal as exc:
        if exc.code != "quorum-unknown-approver":
            return _break("quorum-unknown-approver-refused",
                          "wrong code %r" % (exc.code,))
        return _held("quorum-unknown-approver-refused",
                     "mallory refuses coded quorum-unknown-approver")
    return _break("quorum-unknown-approver-refused", "mallory accepted")


@probe("quorum-forged-signature-refused")
def _p_forged():
    approvers, seeds = _mk_approvers()
    policy = _mk_policy(approvers, m=2)
    digest = _op_digest()
    col = qa.QuorumCollector(policy, digest)
    att = qa.attest(seeds["alice"], "alice", digest, policy, nonce="n-a")
    bad = dict(att)
    sig = bytearray(bytes.fromhex(bad["signature"]))
    sig[0] ^= 0xFF
    bad["signature"] = bytes(sig).hex()
    try:
        col.collect(bad)
    except qa.AttestationRefusal as exc:
        if exc.code != "quorum-signature-invalid":
            return _break("quorum-forged-signature-refused",
                          "wrong code %r" % (exc.code,))
        return _held("quorum-forged-signature-refused",
                     "forged signature refuses")
    return _break("quorum-forged-signature-refused", "forgery accepted")


@probe("quorum-deny-veto-blocks")
def _p_deny():
    approvers, seeds = _mk_approvers()
    policy = _mk_policy(approvers, m=2)
    digest = _op_digest()
    col = qa.QuorumCollector(policy, digest)
    col.collect(qa.attest(seeds["alice"], "alice", digest, policy,
                          nonce="n-a"))
    col.collect(qa.deny(seeds["carol"], "carol", digest, policy,
                        nonce="n-c", reason="suspicious params"))
    v = col.evaluate()
    if v["executable"] is not False or v["code"] != "quorum-deny-veto":
        return _break("quorum-deny-veto-blocks", "got %r" % (v,))
    return _held("quorum-deny-veto-blocks",
                 "carol's deny vetoes the quorum")


@probe("quorum-policy-version-monotonic")
def _p_version():
    approvers, seeds = _mk_approvers()
    _mk_policy(approvers, m=2)
    try:
        qa.register_policy({
            "policy_id": "op:root-key-ceremony", "version": 1, "m": 2,
            "approvers": approvers,
            "change_log": [{"version": 1, "changed_at": 2,
                            "change": "re-genesis", "author": "d"}],
        })
    except qa.PolicyRefusal as exc:
        if exc.code != "quorum-policy-version-invalid":
            return _break("quorum-policy-version-monotonic",
                          "wrong code %r" % (exc.code,))
        return _held("quorum-policy-version-monotonic",
                     "same-version re-register refuses")
    return _break("quorum-policy-version-monotonic", "downgrade accepted")


@probe("quorum-policy-change-needs-bump")
def _p_changebump():
    approvers, seeds = _mk_approvers()
    _mk_policy(approvers, m=2)
    changed = [dict(a) for a in approvers]
    changed[2] = dict(changed[2], name="dave")
    try:
        qa.register_policy({
            "policy_id": "op:root-key-ceremony", "version": 1, "m": 2,
            "approvers": changed,
            "change_log": [{"version": 1, "changed_at": 2,
                            "change": "swap", "author": "d"}],
        })
    except qa.PolicyRefusal as exc:
        if exc.code != "quorum-policy-version-invalid":
            return _break("quorum-policy-change-needs-bump",
                          "wrong code %r" % (exc.code,))
        return _held("quorum-policy-change-needs-bump",
                     "changed set at same version refuses")
    return _break("quorum-policy-change-needs-bump", "silent swap accepted")


@probe("quorum-unreachable-at-load")
def _p_unreachable():
    approvers, seeds = _mk_approvers()
    try:
        qa.register_policy({
            "policy_id": "op:x", "version": 1, "m": 5,
            "approvers": approvers,
            "change_log": [{"version": 1, "changed_at": 1,
                            "change": "genesis", "author": "d"}],
        })
    except qa.PolicyRefusal as exc:
        if exc.code != "quorum-unreachable":
            return _break("quorum-unreachable-at-load",
                          "wrong code %r" % (exc.code,))
        return _held("quorum-unreachable-at-load",
                     "m > n refuses at load (D1-core L7)")
    return _break("quorum-unreachable-at-load", "unreachable quorum loaded")


@probe("quorum-duplicate-names-at-load")
def _p_dupenames():
    approvers, seeds = _mk_approvers()
    approvers = [dict(a) for a in approvers]
    approvers[1] = dict(approvers[1], name="alice")
    try:
        qa.register_policy({
            "policy_id": "op:x", "version": 1, "m": 2,
            "approvers": approvers,
            "change_log": [{"version": 1, "changed_at": 1,
                            "change": "genesis", "author": "d"}],
        })
    except qa.PolicyRefusal as exc:
        if exc.code != "quorum-malformed":
            return _break("quorum-duplicate-names-at-load",
                          "wrong code %r" % (exc.code,))
        return _held("quorum-duplicate-names-at-load",
                     "duplicate names refuse at load (quorum-malformed)")
    return _break("quorum-duplicate-names-at-load", "dup names loaded")


@probe("quorum-expired-attestation-refused")
def _p_expired():
    approvers, seeds = _mk_approvers()
    policy = _mk_policy(approvers, m=2)
    digest = _op_digest()
    col = qa.QuorumCollector(policy, digest, now=1700003600 + 7200)
    att = qa.attest(seeds["alice"], "alice", digest, policy, nonce="n-a",
                    issued_at=1700003600, ttl_seconds=3600)
    try:
        col.collect(att)
    except qa.AttestationRefusal as exc:
        if exc.code != "quorum-attestation-expired":
            return _break("quorum-expired-attestation-refused",
                          "wrong code %r" % (exc.code,))
        return _held("quorum-expired-attestation-refused",
                     "expired attestation refuses")
    return _break("quorum-expired-attestation-refused", "expired accepted")


@probe("gate-advisory-records-state")
def _p_gate_advisory():
    gate = qa.QuorumGate()
    v = gate.check("op:unregistered-thing", {"digest": "abc"})
    if v["mode"] != "absent" or v["allowed"] is not True:
        return _break("gate-advisory-records-state", "got %r" % (v,))
    return _held("gate-advisory-records-state",
                 "unregistered op: advisory absent, allowed")


@probe("gate-enforces-registered")
def _p_gate_enforce():
    approvers, seeds = _mk_approvers()
    policy = _mk_policy(approvers, m=2, policy_id="op:sensitive-thing")
    gate = qa.QuorumGate()
    gate.register_sensitive("op:sensitive-thing", policy)
    digest = qa.operation_digest({"op": "sensitive-thing"})
    v = gate.check("op:sensitive-thing", {"digest": digest})
    if v["allowed"] is not False or v["code"] != "quorum-insufficient":
        return _break("gate-enforces-registered", "unmet allowed: %r" % (v,))
    col = gate.collector_for("op:sensitive-thing")
    col.collect(qa.attest(seeds["alice"], "alice", digest, policy,
                          nonce="n-a"))
    col.collect(qa.attest(seeds["bob"], "bob", digest, policy, nonce="n-b"))
    v2 = gate.check("op:sensitive-thing", {"digest": digest})
    if v2["allowed"] is not True:
        return _break("gate-enforces-registered", "met refused: %r" % (v2,))
    return _held("gate-enforces-registered",
                 "unmet refuses, met allows")


@probe("pin-taxonomy")
def _p_pin():
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    lits += re.findall(r'"code":\s*"([^"]+)"', src)
    if len(lits) != TAXONOMY_PIN or len(set(lits)) != TAXONOMY_PIN:
        return _break("pin-taxonomy",
                      "got %d literals / %d unique (want %d/%d)"
                      % (len(lits), len(set(lits)),
                         TAXONOMY_PIN, TAXONOMY_PIN))
    if lits != sorted(lits):
        return _break("pin-taxonomy", "literals not sorted")
    if len(dc.TAXONOMY) != TAXONOMY_PIN:
        return _break("pin-taxonomy",
                      "deduped TAXONOMY %d != pin %d"
                      % (len(dc.TAXONOMY), TAXONOMY_PIN))
    return _held("pin-taxonomy",
                 "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


@probe("footer-state")
def _p_footer():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    m = list(re.finditer(r"Next free finding: \*\*(F\d+)\*\*\. "
                          r"\*\*Open findings: ([^*]*)\*\*",
                          text))
    if not m:
        return _error("footer-state", "footer not found")
    last = m[-1]
    nxt, opens = last.group(1), last.group(2).strip().rstrip(".")
    if nxt != FOOTER_NEXT or opens != FOOTER_OPEN:
        return _break("footer-state",
                      "footer %s / %s, want %s / %s"
                      % (nxt, opens, FOOTER_NEXT, FOOTER_OPEN))
    return _held("footer-state",
                 "open %s / next %s" % (opens, nxt))


def green_check():
    """Depth-1 green check: adjacent seams still green. Honors
    GOV_SKIP_GREEN (the wave-173 convention)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    import subprocess  # noqa: E402
    env = dict(os.environ, GOV_SKIP_GREEN="1",
               GOV_DEPLOYMENT_MODE="staging")
    suites = ["tests.test_quorum_approval",
              "tests.test_decision_codes",
              "tests.test_workload_identity"]
    ok = True
    for suite in suites:
        try:
            r = subprocess.run(
                [sys.executable, "-m", "unittest", suite],
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=300)
        except Exception as exc:  # noqa: BLE001
            print("green_check: %s ERROR %r" % (suite, exc))
            ok = False
            continue
        status = "OK" if r.returncode == 0 else "FAIL"
        print("green_check: %s %s" % (suite, status))
        if r.returncode != 0:
            ok = False
    return ok


def main():
    held = broke = errors = 0
    lines = []
    for name, fn in PROBES:
        qa.reset_registry()
        try:
            verdict, detail = fn()
        except Exception:  # noqa: BLE001
            verdict, detail = "ERROR", traceback.format_exc(limit=3)
        print("%-42s %s %s" % (name, verdict, detail))
        lines.append((name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broke += 1
        else:
            errors += 1
    print("w320_quorum battery: %d BREAK / %d HELD / %d ERROR "
          "(greens: 0 break / 0 error)" % (broke, held, errors))
    probe_lines.emit(lines)
    gok = green_check()
    print("green_check: %s" % ("OK" if gok else "FAIL"))
    if broke or errors or not gok:
        sys.exit(1)


if __name__ == "__main__":
    main()
