#!/usr/bin/env python3
"""Break-first battery for the wave-279 sealer-as-authority lane.

Gap (Chainloop PR #3465, stolen Apache-2.0 pattern): ``seal_evidence``
verifies the *signature* on an evidence bundle but imposes zero content
requirements on the artifact body -- a cert-holder can seal an arbitrary,
contract-empty JSON body and the signature attests compliance it never
checked. Signature != compliance. The sealer must verify contract
completeness server-side at seal time, and the assembler-side pre-check
must share the sealer's validator so the two cannot drift.

Desired end state (every probe asserts this; all BREAK on the base):
  sc01 contract-empty body of a declared invocation class -> refused
       ``evbundle-contract-refused`` at seal time
  sc02 unknown invocation class -> refused
  sc03 fully compliant body -> still seals (defense pin)
  sc04 assembler pre-check and sealer agree on N crafted bodies
       (no-drift: the shared-validator property)
  sc05 malformed material shapes (non-hex digests) -> refused
  sc06 decision outside the class verdict vocabulary -> refused
  sc07 unclassed (legacy) body -> still seals (documented path)

Module-level staging default; deterministic (fixed seeds, fixed time);
depth-1 green checks honoring GOV_SKIP_GREEN=1; no in-repo git
subprocesses; TMPDIR is inherited from the runner (fresh /var/tmp
per suite per convention).
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Audit-log HMAC chain key: fixed fixture (deterministic across runs;
# the wave-243 convention forbids per-run secrets.token_hex here).
os.environ.setdefault("GOV_LOG_KEY", "d" * 64)
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w279-sealer-battery")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

from gov import ed25519 as ed  # noqa: E402
from gov import evidence_certs as ec  # noqa: E402
from gov import evidence_bundle_v2 as eb2  # noqa: E402
from gov import kms as kms_mod  # noqa: E402

try:
    from gov import evidence_contract as _contract_mod
except Exception:  # base tree: the validator does not exist yet
    _contract_mod = None

CONTRACT_CODE = "evbundle-contract-refused"

NOW = 1790860000
POP_DOMAIN = b"evcert-pop-v1"
ARC = "1.3.6.1.4.1.99999"
APPROVAL = "a" * 32
INTENT = "d" * 64
ISSUER = "https://issuer.example.com"

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _keypair(byte):
    seed = bytes([byte & 0xFF]) * 32
    return seed, ed.publickey(seed)


class _SealFixture(object):
    """Audited evidence-cert ceremony (fixed seeds) for seal probes."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="w279-sealer-")
        self.audit_path = os.path.join(self.tmp, "audit.jsonl")
        self.fake = kms_mod.FakeKmsProvider(["ca-key-1"])
        approvals = {APPROVAL: {"decider": "alice", "state": "pending"}}
        self.ca = ec.EvidenceCA(
            kms_provider=self.fake, ca_key_id="ca-key-1",
            ca_public_key=self.fake.test_signing_public_key("ca-key-1"),
            issuers=[ISSUER], approval_lookup=approvals.get,
            audit_log_path=self.audit_path, anchor_reachable=lambda: True,
            oid_arc=ARC, now=lambda: NOW)
        self.seed, self.pub = _keypair(0x01)
        chal = (POP_DOMAIN + APPROVAL.encode("utf-8")
                + hashlib.sha256(self.pub).digest())
        req = {"identity_assertion": {"iss": ISSUER, "sub": "alice",
                                     "exp": NOW + 3600},
               "ephemeral_pub": self.pub,
               "pop_sig": ed.sign(self.seed, chal),
               "approval_id": APPROVAL,
               "intent_digest": INTENT}
        self.cert, _entry = self.ca.issue(**req)
        self.ca_pub = self.fake.test_signing_public_key("ca-key-1")

    def seal(self, body, **over):
        sig = ed.sign(self.seed, _canonical(body))
        kw = dict(artifact_body=body, cert=self.cert,
                  artifact_signature=bytes(sig),
                  approval_id=APPROVAL, intent_digest=INTENT,
                  ca_public_key=bytes(self.ca_pub), verify_time=NOW)
        kw.update(over)
        return eb2.seal_evidence(**kw)


def _seal_verdict(fix, body):
    """Return ('sealed', None) or ('refused', code) for a seal attempt."""
    try:
        fix.seal(body)
        return "sealed", None
    except eb2.EvidenceBundleV2Error as e:
        return "refused", e.code
    except Exception as e:  # noqa: BLE001 -- never silently swallow
        return "error", "%s: %s" % (type(e).__name__, e)


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def p_sc01_contract_empty_body(fix):
    """A contract-empty body of a declared class must not seal."""
    body = {"invocation_class": "tool_execution"}
    verdict, code = _seal_verdict(fix, body)
    if verdict == "refused" and code == CONTRACT_CODE:
        _record("sc01", "HELD",
                "contract-empty tool_execution refused %s" % code)
    elif verdict == "sealed":
        _record("sc01", "BREAK",
                "contract-empty body sealed: signature != compliance")
    else:
        _record("sc01", "ERROR", "verdict=%r code=%r" % (verdict, code))


def p_sc02_unknown_class(fix):
    """An unknown invocation class must not seal."""
    body = {"invocation_class": "nope_not_a_class", "foo": "bar"}
    verdict, code = _seal_verdict(fix, body)
    if verdict == "refused" and code == CONTRACT_CODE:
        _record("sc02", "HELD", "unknown class refused %s" % code)
    elif verdict == "sealed":
        _record("sc02", "BREAK", "unknown class sealed")
    else:
        _record("sc02", "ERROR", "verdict=%r code=%r" % (verdict, code))


def p_sc03_compliant_body_seals(fix):
    """Defense pin: a fully compliant body must still seal."""
    body = _compliant_tool_execution()
    verdict, code = _seal_verdict(fix, body)
    if verdict == "sealed":
        _record("sc03", "HELD", "compliant body seals")
    else:
        _record("sc03", "BREAK",
                "compliant body refused: verdict=%r code=%r"
                % (verdict, code))


def _compliant_tool_execution():
    return {
        "invocation_class": "tool_execution",
        "approval_id": APPROVAL,
        "intent_digest": INTENT,
        "tool_output_digest": "e" * 64,
        "decision": "decline",
        "policy_version": "policy.v42",
    }


def p_sc04_no_drift(fix):
    """Assembler pre-check and sealer must agree on every crafted body.

    The Chainloop #3465 drift class: two implementations of the same
    check. The fix is ONE shared validator; this probe fails if the
    pre-check and the sealer ever disagree.
    """
    if _contract_mod is None:
        _record("sc04", "BREAK",
                "shared validator absent: assembler/sealer drift class open")
        return
    bodies = [
        {"invocation_class": "tool_execution"},
        _compliant_tool_execution(),
        dict(_compliant_tool_execution(), tool_output_digest="not-hex"),
        dict(_compliant_tool_execution(), decision="maybe"),
        {"invocation_class": "approval_decision"},
        {"invocation_class": "approval_decision",
         "approval_id": APPROVAL, "decision": "approve",
         "decider": "alice", "rationale": "looks fine"},
        {"invocation_class": "redteam_probe"},
        {"invocation_class": "redteam_probe", "probe_id": "p1",
         "battery_digest": "f" * 64, "expected": "BREAK",
         "actual": "BREAK"},
        {"invocation_class": "nope_not_a_class"},
        {"no_class_at_all": True},
    ]
    mismatches = []
    for i, body in enumerate(bodies):
        try:
            pre = _contract_mod.precheck_artifact(artifact_body=body)
            pre_ok = bool(pre.get("ok"))
        except Exception as e:  # noqa: BLE001
            pre_ok = False
            pre_note = "%s: %s" % (type(e).__name__, e)
        else:
            pre_note = ""
        seal_v, seal_code = _seal_verdict(fix, body)
        agree = pre_ok == (seal_v == "sealed")
        if not agree:
            mismatches.append("body#%d pre_ok=%r%s seal=(%r,%r)"
                              % (i, pre_ok,
                                  (" " + pre_note) if pre_note else "",
                                  seal_v, seal_code))
    if not mismatches:
        _record("sc04", "HELD",
                "%d bodies: pre-check and sealer agree" % len(bodies))
    else:
        _record("sc04", "BREAK", "drift: %s" % "; ".join(mismatches))


def p_sc05_bad_digest_shape(fix):
    """Materials with malformed digest shapes must be refused."""
    body = dict(_compliant_tool_execution(), tool_output_digest="not-hex")
    verdict, code = _seal_verdict(fix, body)
    if verdict == "refused" and code == CONTRACT_CODE:
        _record("sc05", "HELD", "malformed digest refused %s" % code)
    elif verdict == "sealed":
        _record("sc05", "BREAK", "malformed digest sealed")
    else:
        _record("sc05", "ERROR", "verdict=%r code=%r" % (verdict, code))


def p_sc06_wrong_vocabulary(fix):
    """A decision outside the class verdict vocabulary must be refused."""
    body = dict(_compliant_tool_execution(), decision="maybe")
    verdict, code = _seal_verdict(fix, body)
    if verdict == "refused" and code == CONTRACT_CODE:
        _record("sc06", "HELD", "out-of-vocabulary decision refused")
    elif verdict == "sealed":
        _record("sc06", "BREAK", "out-of-vocabulary decision sealed")
    else:
        _record("sc06", "ERROR", "verdict=%r code=%r" % (verdict, code))


def p_sc07_unclassed_body_seals(fix):
    """Documented path: a body declaring no class seals as before."""
    body = {"decision": "deny"}
    verdict, code = _seal_verdict(fix, body)
    if verdict == "sealed":
        _record("sc07", "HELD", "unclassed body seals (legacy path)")
    else:
        _record("sc07", "BREAK",
                "unclassed body refused: verdict=%r code=%r"
                % (verdict, code))


def green_check():
    """Depth-1: run the new unit suite (GOV_SKIP_GREEN=1 in the child
    env) so the battery never nests another battery's full main."""
    if GREEN_SKIP:
        return [("GOV_SKIP_GREEN=1: recorded, not recursing", "HELD",
                 "skip")]
    results = []
    tmp = tempfile.mkdtemp(prefix="g279-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest",
             "tests.test_evidence_contract", "-v"],
            cwd=REPO, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=600, text=True)
        ok = p.returncode == 0 and "FAILED" not in p.stdout
        results.append(("unit-tests-evidence-contract",
                        "HELD" if ok else "BREAK",
                        "rc=%d" % p.returncode))
        p2 = subprocess.run(
            [sys.executable, "-m", "unittest", "tests.test_evbundle", "-v"],
            cwd=REPO, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=600, text=True)
        ok2 = p2.returncode == 0 and "FAILED" not in p2.stdout
        results.append(("unit-tests-evbundle-unbroken",
                        "HELD" if ok2 else "BREAK",
                        "rc=%d" % p2.returncode))
    except Exception as exc:  # noqa: BLE001
        results.append(("green-check", "ERROR", "%s" % exc))
    return results


def main():
    fix = _SealFixture()
    p_sc01_contract_empty_body(fix)
    p_sc02_unknown_class(fix)
    p_sc03_compliant_body_seals(fix)
    p_sc04_no_drift(fix)
    p_sc05_bad_digest_shape(fix)
    p_sc06_wrong_vocabulary(fix)
    p_sc07_unclassed_body_seals(fix)
    green = green_check()

    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("== w279 sealer-as-authority probes ==")
    for pid, verdict, note in _results:
        print("%-8s %-5s %s" % (pid, verdict, note))
    print("-- green checks --")
    for pid, verdict, note in green:
        print("%-32s %-5s %s" % (pid, verdict, note))
        if verdict == "BREAK":
            n_break += 1
        elif verdict == "ERROR":
            n_err += 1
    print("probes: %d BREAK / %d HELD / %d ERROR"
          % (n_break, len(_results) - n_break - n_err, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
