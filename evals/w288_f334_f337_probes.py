"""Wave-288 red-first battery: close F334 and F337.

F334 (LOW): ``suppress_with_exception`` (gov/tool_call_policy.py) takes
the exception scope as a free caller parameter and never binds it to
the suppressed alert: a tool-b DENY alert records SKIPPED under a
tool-a exception scope. The fix binds the scope in code: ("tool", X)
must name (fnmatch-cover) the alert's tool; ("policy", P) must name the
compiled policy (name or digest); anything else refuses LOUD and coded.

F337 (LOW): ``bind_receipt`` (gov/evidence_receipt.py) signs anchor
tuples it never re-verifies: a swapped bundle_digest mints an
operator-signed receipt that verify_receipt_offline rejects (issuance
confusion). The fix re-verifies the inclusion proof (digest -> root)
before signing and refuses LOUD and coded on mismatch.

Run:
  mkdir -p /var/tmp/g288-f334 && TMPDIR=/var/tmp/g288-f334 \
    ~/workspace/.gov-venv/bin/python evals/w288_f334_f337_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g288-f334b \
    ~/workspace/.gov-venv/bin/python evals/w288_f334_f337_probes.py
"""

import os
import re
import secrets
import subprocess
import sys
import tempfile
import time

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-288 lane 1: pin 1684 -> 1685 (+1 toolcall-exception-scope-mismatch).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*)
TAXONOMY_PIN = 1743  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (TAXONOMY_PIN,
                                                        TAXONOMY_PIN))


# ---------------------------------------------------------------------------
# F334: scope binding on suppress_with_exception
# ---------------------------------------------------------------------------

def _f334_store():
    from gov import governed_exceptions as ge
    reg = ge.CheckRegistry()
    reg.register("W288CHECK", "w288 check", category="cat",
                 severity="low",
                 rationale="a proper rationale text",
                 resource_types=["t"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["alice"])
    return store


def _f334_comp():
    from gov import tool_call_policy as tp
    doc = {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w288pol",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "DENY", "tool": "tool-b", "operation": "exec",
             "severity": 9, "tags": []},
        ],
    }
    return tp.compile_policy(doc)


def _f334_deny(comp):
    caller = {"authenticated": True, "identity": "agent-1"}
    d = comp.decide(caller, "tool-b", "exec", args={})
    assert d.verdict == "DENY", "expected DENY, got %r" % (d.verdict,)
    return d


def _f334_grant(store, scope):
    now = time.time()
    store.grant("W288CHECK", scope=scope,
                justification="business need documented here",
                approver="alice", expiry_ts=now + 3600, created_at=now)


def p_f334_scope_not_bound():
    """The defect: tool-b DENY suppressed under a tool-a scope."""
    from gov import tool_call_policy as tp
    store = _f334_store()
    _f334_grant(store, ("tool", "tool-a"))
    comp = _f334_comp()
    d = _f334_deny(comp)
    try:
        rec = tp.suppress_with_exception(
            comp, d.alert["runtime_identity_hash"], store,
            "W288CHECK", ("tool", "tool-a"))
    except Exception as e:  # noqa: BLE001
        return _record("f334-scope-not-bound", "HELD",
                       "scope/alert binding refused: %s"
                       % getattr(e, "code", type(e).__name__))
    sup = rec.get("suppressed_alert", {})
    if rec.get("action") == "SKIPPED" and sup.get("tool") == "tool-b":
        return _record("f334-scope-not-bound", "BREAK",
                       "tool-b DENY alert recorded SKIPPED under a "
                       "tool-a exception scope -- scope not bound")
    _record("f334-scope-not-bound", "HELD",
            "suppression bound to the alert's own scope")


def p_f334_matching_tool_scope_ok():
    """Positive control: a scope that names the alert's tool works."""
    from gov import tool_call_policy as tp
    store = _f334_store()
    _f334_grant(store, ("tool", "tool-b"))
    comp = _f334_comp()
    d = _f334_deny(comp)
    try:
        rec = tp.suppress_with_exception(
            comp, d.alert["runtime_identity_hash"], store,
            "W288CHECK", ("tool", "tool-b"))
    except Exception as e:  # noqa: BLE001
        return _record("f334-tool-scope-ok", "BREAK",
                       "matching tool scope refused: %s"
                       % getattr(e, "code", type(e).__name__))
    if rec.get("action") == "SKIPPED":
        return _record("f334-tool-scope-ok", "HELD",
                       "matching tool scope suppresses")
    _record("f334-tool-scope-ok", "BREAK",
            "unexpected record: %r" % (rec.get("action"),))


def p_f334_policy_scope_ok():
    """Positive control: a scope naming the policy works."""
    from gov import tool_call_policy as tp
    store = _f334_store()
    _f334_grant(store, ("policy", "w288pol"))
    comp = _f334_comp()
    d = _f334_deny(comp)
    try:
        rec = tp.suppress_with_exception(
            comp, d.alert["runtime_identity_hash"], store,
            "W288CHECK", ("policy", "w288pol"))
    except Exception as e:  # noqa: BLE001
        return _record("f334-policy-scope-ok", "BREAK",
                       "matching policy scope refused: %s"
                       % getattr(e, "code", type(e).__name__))
    if rec.get("action") == "SKIPPED":
        return _record("f334-policy-scope-ok", "HELD",
                       "policy scope suppresses")
    _record("f334-policy-scope-ok", "BREAK",
            "unexpected record: %r" % (rec.get("action"),))


def p_f334_policy_scope_digest_ok():
    """Positive control: the policy digest also names the policy."""
    from gov import tool_call_policy as tp
    store = _f334_store()
    comp = _f334_comp()
    _f334_grant(store, ("policy", comp.digest))
    d = _f334_deny(comp)
    try:
        rec = tp.suppress_with_exception(
            comp, d.alert["runtime_identity_hash"], store,
            "W288CHECK", ("policy", comp.digest))
    except Exception as e:  # noqa: BLE001
        return _record("f334-policy-digest-ok", "BREAK",
                       "policy digest scope refused: %s"
                       % getattr(e, "code", type(e).__name__))
    if rec.get("action") == "SKIPPED":
        return _record("f334-policy-digest-ok", "HELD",
                       "policy digest scope suppresses")
    _record("f334-policy-digest-ok", "BREAK",
            "unexpected record: %r" % (rec.get("action"),))


def p_f334_wrong_policy_scope_refused():
    """Negative control: a policy scope naming another policy refuses."""
    from gov import tool_call_policy as tp
    store = _f334_store()
    _f334_grant(store, ("policy", "other-policy"))
    comp = _f334_comp()
    d = _f334_deny(comp)
    try:
        tp.suppress_with_exception(
            comp, d.alert["runtime_identity_hash"], store,
            "W288CHECK", ("policy", "other-policy"))
    except Exception as e:  # noqa: BLE001
        return _record("f334-wrong-policy-refused", "HELD",
                       "wrong policy scope refused: %s"
                       % getattr(e, "code", type(e).__name__))
    _record("f334-wrong-policy-refused", "BREAK",
            "scope naming another policy was accepted")


def p_f334_glob_tool_scope_ok():
    """fnmatch coverage: an approver-granted glob still binds by name."""
    from gov import tool_call_policy as tp
    store = _f334_store()
    _f334_grant(store, ("tool", "tool-*"))
    comp = _f334_comp()
    d = _f334_deny(comp)
    try:
        rec = tp.suppress_with_exception(
            comp, d.alert["runtime_identity_hash"], store,
            "W288CHECK", ("tool", "tool-*"))
    except Exception as e:  # noqa: BLE001
        return _record("f334-glob-tool-ok", "BREAK",
                       "glob tool scope refused: %s"
                       % getattr(e, "code", type(e).__name__))
    if rec.get("action") == "SKIPPED":
        return _record("f334-glob-tool-ok", "HELD",
                       "glob scope covering the alert's tool suppresses")
    _record("f334-glob-tool-ok", "BREAK",
            "unexpected record: %r" % (rec.get("action"),))


# ---------------------------------------------------------------------------
# F337: bind_receipt re-verifies the inclusion tuple before signing
# ---------------------------------------------------------------------------

def p_f337_bind_no_reverify():
    """The defect: a swapped bundle_digest mints a dead signed receipt."""
    from gov import evidence_anchor as ea
    from gov import evidence_receipt as er
    d = tempfile.mkdtemp(prefix="w288-f337-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w288origin", signer_keyid="op1",
                             signer_seed=seed)
    anchored = ea.anchor(log, secrets.token_bytes(32).hex())
    bad = dict(anchored)
    bad["bundle_digest"] = secrets.token_bytes(32).hex()
    try:
        er.bind_receipt(bad, seed)
    except Exception as e:  # noqa: BLE001
        return _record("f337-bind-no-reverify", "HELD",
                       "bind re-verified the inclusion tuple: %s"
                       % getattr(e, "code", type(e).__name__))
    _record("f337-bind-no-reverify", "BREAK",
            "bind_receipt signed a receipt over a swapped digest "
            "without re-verifying the inclusion proof")


def p_f337_genuine_anchor_binds():
    """Positive control: a genuine anchor receipt still binds."""
    from gov import evidence_anchor as ea
    from gov import evidence_receipt as er
    from gov import ed25519
    d = tempfile.mkdtemp(prefix="w288-f337-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w288origin", signer_keyid="op1",
                             signer_seed=seed)
    anchored = ea.anchor(log, secrets.token_bytes(32).hex())
    try:
        receipt = er.bind_receipt(anchored, seed)
    except Exception as e:  # noqa: BLE001
        return _record("f337-genuine-binds", "BREAK",
                       "genuine anchor refused: %s"
                       % getattr(e, "code", type(e).__name__))
    ok = er.verify_receipt_offline(receipt, ed25519.publickey(seed))
    if ok is True:
        return _record("f337-genuine-binds", "HELD",
                       "genuine anchor binds and verifies offline")
    _record("f337-genuine-binds", "BREAK",
            "receipt issued but offline verify failed")


def p_f337_swapped_proof_hashes_refused():
    """Variant: swapped sibling hashes in the proof refuse too."""
    from gov import evidence_anchor as ea
    from gov import evidence_receipt as er
    d = tempfile.mkdtemp(prefix="w288-f337-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w288origin", signer_keyid="op1",
                             signer_seed=seed)
    ea.anchor(log, secrets.token_bytes(32).hex())
    anchored = ea.anchor(log, secrets.token_bytes(32).hex())
    bad = dict(anchored)
    badp = dict(bad["inclusion_proof"])
    badp["hashes"] = [secrets.token_bytes(32).hex()
                      for _ in badp["hashes"]] or [secrets.token_bytes(32).hex()]
    bad["inclusion_proof"] = badp
    try:
        er.bind_receipt(bad, seed)
    except Exception as e:  # noqa: BLE001
        return _record("f337-swapped-hashes-refused", "HELD",
                       "forged proof refused: %s"
                       % getattr(e, "code", type(e).__name__))
    _record("f337-swapped-hashes-refused", "BREAK",
            "bind_receipt signed over forged proof hashes")


def p_f337_nonhex_digest_refused_coded():
    """Variant: a non-hex bundle_digest refuses LOUD and coded (the
    module's coded-refusal contract), never a raw ValueError."""
    from gov import evidence_anchor as ea
    from gov import evidence_receipt as er
    d = tempfile.mkdtemp(prefix="w288-f337-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w288origin", signer_keyid="op1",
                             signer_seed=seed)
    anchored = ea.anchor(log, secrets.token_bytes(32).hex())
    bad = dict(anchored)
    bad["bundle_digest"] = "zz" * 32
    try:
        er.bind_receipt(bad, seed)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", type(e).__name__)
        if type(e).__name__ == "ValueError" and not hasattr(e, "code"):
            return _record("f337-nonhex-digest-coded", "BREAK",
                           "raw ValueError escaped (uncoded)")
        return _record("f337-nonhex-digest-coded", "HELD",
                       "non-hex digest refused coded: %s" % code)
    _record("f337-nonhex-digest-coded", "BREAK",
            "bind_receipt signed over non-hex bundle_digest")


# ---------------------------------------------------------------------------
# Depth-1 green checks: the wave-287 lane batteries stay all-HELD, and
# the w287 red-team battery flips f334/f337 to HELD (8 BREAK remain).
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        # (battery, expected BREAKs, label)
        ("evals/w287_redteam_probes.py", 0, "f334-f342-closed"),
        ("evals/w287_tsa_probes.py", 0, "tsa"),
        ("evals/w285_tessera_probes.py", 0, "tessera"),
        ("evals/w286_receipts_probes.py", 0, "receipts"),
        ("evals/w286_toolpolicy_probes.py", 0, "toolpolicy"),
        ("evals/w285_exceptions_probes.py", 0, "exceptions"),
    ]
    for rel, expected, label in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w288-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record("green-" + label, "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        # Take the LAST "N BREAK" match: the footer, not probe notes.
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak == expected:
            _record("green-" + label, "HELD",
                    "%s: %d BREAK as expected" % (rel, nbreak))
        else:
            _record("green-" + label, "BREAK",
                    "%s: %d BREAK, expected %d" % (rel, nbreak,
                                                   expected))


def main():
    p_taxonomy_pin()
    p_f334_scope_not_bound()
    p_f334_matching_tool_scope_ok()
    p_f334_policy_scope_ok()
    p_f334_policy_scope_digest_ok()
    p_f334_wrong_policy_scope_refused()
    p_f334_glob_tool_scope_ok()
    p_f337_bind_no_reverify()
    p_f337_genuine_anchor_binds()
    p_f337_swapped_proof_hashes_refused()
    p_f337_nonhex_digest_refused_coded()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w288_f334_f337: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
