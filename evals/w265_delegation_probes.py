"""Break-first red-team battery for UCAN-style attenuation-only signed
delegation chains (wave-265 feature lane).

Target: gov/delegation_chain.py -- signed delegation chains where every
hop can only NARROW its parent's authority (attenuation-only), the root
is pinned to deployment trust anchors, and the verifier mints signed
invocation receipts.

Every probe attacks a PUBLIC seam, never product internals. The battery
imports the implementation via GOV_DELEGATION_IMPL (default
"gov.delegation_chain"); against the permissive stub
(GOV_DELEGATION_IMPL=delegation_stub_mod,
PYTHONPATH=/tmp/w265_delegation_stub) every attack probe must BREAK,
proving the probes are real. Against the real module every probe must
HELD, in staging and under `env -u GOV_DEPLOYMENT_MODE`.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. A probe returns (ok, detail); ok=True means HELD (attack
refused with the expected machine code / gap is a documented residual),
ok=False means BREAK (genuine defect) or harness ERROR.

Stdlib only. Deterministic. No in-repo git subprocesses (wave-36
supply-chain probe: fail closed). Green checks are depth-1 and honor
GOV_SKIP_GREEN=1.
"""

import importlib
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

TAXONOMY_PIN = 2077 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*)



MOD_NAME = os.environ.get("GOV_DELEGATION_IMPL",
                           "gov.delegation_chain")
dc = importlib.import_module(MOD_NAME)

from gov import ed25519  # noqa: E402 -- key material for both backends

NOW = 4000000000.0


def _seed():
    return ed25519.generate_seed()


def _pub(seed):
    return ed25519.publickey(seed).hex()


def _caps(with_, cans):
    return [{"with": with_, "can": list(cans)}]


def _delegate(seed, held, audience, caps, parent=None,
              not_before=NOW - 100.0, not_after=NOW + 3600.0):
    # Wave-292 merge: delegate() requires an explicit ttl; derive it
    # from the caller's window (not_after == issued_at + ttl).
    return dc.delegate(seed, held, {
        "audience": _pub(audience),
        "capabilities": caps,
        "not_before": not_before,
        "not_after": not_after,
        "ttl": not_after - not_before,
        "parent": parent,
    })


def _chain():
    """A valid 3-hop chain: R -> A -> B -> C, narrowing each hop."""
    r, a, b, c = _seed(), _seed(), _seed(), _seed()
    root = _delegate(r, None, a, _caps("fs:/", ["read", "write"]))
    mid = _delegate(a, _caps("fs:/", ["read", "write"]), b,
                    _caps("fs:/docs", ["read"]), parent=root)
    leaf = _delegate(b, _caps("fs:/docs", ["read"]), c,
                     _caps("fs:/docs", ["read"]), parent=mid)
    action = {"with": "fs:/docs/report.txt", "can": "read"}
    return r, a, b, c, [root, mid, leaf], action


def _verifier(root_seed, vseed=None):
    return dc.DelegationVerifier([_pub(root_seed)],
                                 seed=vseed or _seed())


def _expect(fn, want_code):
    """HELD iff fn raises DelegationError with want_code."""
    try:
        fn()
    except dc.DelegationError as e:
        if e.code == want_code:
            return True, "HELD (%s)" % want_code
        return False, "BREAK: code %s, wanted %s" % (e.code,
                                                    want_code)
    except Exception as e:  # noqa: BLE001 -- harness must not mask
        return False, "ERROR: unexpected %r" % (e,)
    return False, "BREAK: no refusal (wanted %s)" % want_code


def p_issue_widening_refused():
    """delegate() is asked to grant MORE than the issuer holds."""
    r, a = _seed(), _seed()
    held = _caps("fs:/docs", ["read"])
    req = {"audience": _pub(a),
           "capabilities": _caps("fs:/", ["read"]),
           "not_before": NOW - 100.0, "not_after": NOW + 3600.0,
           "parent": None}
    return _expect(lambda: dc.delegate(r, held, req),
                   "delegation-would-widen")


def p_chain_attenuation_inverted():
    """A middle hop widens its parent's scope; verify must refuse."""
    r, a, b, c = _seed(), _seed(), _seed(), _seed()
    root = _delegate(r, None, a, _caps("fs:/docs", ["read"]))
    # The issuer lies about what it holds: held claims fs:/, so the
    # widening hop gets signed. Verification must still catch it.
    mid = _delegate(a, _caps("fs:/", ["read"]), b,
                    _caps("fs:/", ["read"]), parent=root)
    leaf = _delegate(b, _caps("fs:/", ["read"]), c,
                     _caps("fs:/", ["read"]), parent=mid)
    v = _verifier(r)
    action = {"with": "fs:/docs/x", "can": "read"}
    return _expect(lambda: v.verify([root, mid, leaf], action,
                                    now=NOW),
                   "delegation-attenuation-inverted")


def p_chain_break():
    """The leaf's parent_digest is spliced to another chain."""
    r, a, b, c, chain, action = _chain()
    import copy
    bad = copy.deepcopy(chain)
    bad[2]["delegation"]["parent_digest"] = "ff" * 32
    v = _verifier(r)
    return _expect(lambda: v.verify(bad, action, now=NOW),
                   "delegation-parent-mismatch")


def p_signature_forgery():
    """The leaf signature is replaced with a signature over garbage."""
    r, a, b, c, chain, action = _chain()
    import copy
    bad = copy.deepcopy(chain)
    forged = ed25519.sign(b, b"forged-bytes").hex()
    bad[2]["signature"] = forged
    v = _verifier(r)
    return _expect(lambda: v.verify(bad, action, now=NOW),
                   "delegation-signature-invalid")


def p_wrong_context():
    """A chain scoped to fs:/docs is presented for fs:/etc."""
    r, a, b, c, chain, action = _chain()
    v = _verifier(r)
    evil = {"with": "fs:/etc/passwd", "can": "read"}
    return _expect(lambda: v.verify(chain, evil, now=NOW),
                   "delegation-action-refused")


def p_replay():
    """The same (chain, action) verified twice: second is a replay."""
    r, a, b, c, chain, action = _chain()
    v = _verifier(r)
    v.verify(chain, action, now=NOW)
    return _expect(lambda: v.verify(chain, action, now=NOW),
                   "delegation-replay")


def p_expired():
    """The leaf delegation's window closed before verification."""
    r, a, b, c = _seed(), _seed(), _seed(), _seed()
    root = _delegate(r, None, a, _caps("fs:/", ["read", "write"]))
    mid = _delegate(a, _caps("fs:/", ["read", "write"]), b,
                    _caps("fs:/docs", ["read"]), parent=root)
    leaf = _delegate(b, _caps("fs:/docs", ["read"]), c,
                     _caps("fs:/docs", ["read"]), parent=mid,
                     not_before=NOW - 200.0, not_after=NOW - 100.0)
    v = _verifier(r)
    action = {"with": "fs:/docs/report.txt", "can": "read"}
    return _expect(lambda: v.verify([root, mid, leaf], action,
                                    now=NOW),
                   "delegation-expired")


def p_root_untrusted():
    """The chain is rooted at a key the deployment never pinned."""
    r2, a, b, c = _seed(), _seed(), _seed(), _seed()
    root = _delegate(r2, None, a, _caps("fs:/", ["read", "write"]))
    leaf = _delegate(a, _caps("fs:/", ["read", "write"]), b,
                     _caps("fs:/docs", ["read"]), parent=root)
    v = _verifier(_seed())  # anchors pin an unrelated key
    action = {"with": "fs:/docs/report.txt", "can": "read"}
    return _expect(lambda: v.verify([root, leaf], action, now=NOW),
                   "delegation-root-untrusted")


def p_version_mismatch():
    """A delegation with an unknown type version, signed or not."""
    r, a, b, c, chain, action = _chain()
    import copy
    bad = copy.deepcopy(chain)
    bad[1]["delegation"]["type"] = "delegation.ucan.99"
    v = _verifier(r)
    return _expect(lambda: v.verify(bad, action, now=NOW),
                   "delegation-version-mismatch")


def p_end_to_end():
    """Control: a valid 3-hop chain verifies and mints a receipt."""
    r, a, b, c, chain, action = _chain()
    vseed = _seed()
    v = _verifier(r, vseed=vseed)
    try:
        receipt = v.verify(chain, action, now=NOW)
    except Exception as e:  # noqa: BLE001
        return False, "BREAK: valid chain refused: %r" % (e,)
    if not isinstance(receipt, dict) or\
            receipt.get("decision") != "ok":
        return False, "BREAK: no ok receipt: %r" % (receipt,)
    if receipt.get("type") != dc.RECEIPT_TYPE:
        return False, "BREAK: wrong receipt type: %r" % (
            receipt.get("type"),)
    sig = receipt.get("signature")
    if isinstance(sig, str) and sig:
        body = {k: v for k, v in receipt.items()
                if k != "signature"}
        import json
        canon = json.dumps(body, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
        if ed25519.verify(bytes.fromhex(_pub(vseed)),
                          b"gov-delegation-receipt/v1\x00" + canon,
                          bytes.fromhex(sig)) is not True:
            return False, "BREAK: receipt signature invalid"
    return True, "HELD (valid chain verified, receipt minted)"


def p_taxonomy_pin():
    """The 9 delegation-* codes are in the taxonomy, pin matches, and
    no code literal is duplicated in the raw source (wave-260)."""
    new_codes = ("delegation-malformed",
                 "delegation-version-mismatch",
                 "delegation-signature-invalid",
                 "delegation-parent-mismatch",
                 "delegation-root-untrusted",
                 "delegation-attenuation-inverted",
                 "delegation-action-refused",
                 "delegation-replay",
                 "delegation-expired")
    import gov.decision_codes as dcd
    missing = [c for c in new_codes if c not in dcd.TAXONOMY]
    if missing:
        return False, "BREAK: codes missing: %r" % missing
    if len(dcd.TAXONOMY) != TAXONOMY_PIN:
        return False, "BREAK: taxonomy %d != pin %d" % (
            len(dcd.TAXONOMY), TAXONOMY_PIN)
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, "..", "gov",
                            "decision_codes.py")).read()
    dupes = [c for c in new_codes
             if src.count('"code": \'%s\'' % c) != 1]
    if dupes:
        return False, "BREAK: duplicated/missing literals: %r" % dupes
    return True, "HELD (pin %d, 9 new codes)" % TAXONOMY_PIN


PROBES = [
    ("issue-widening-refused", p_issue_widening_refused),
    ("chain-attenuation-inverted", p_chain_attenuation_inverted),
    ("chain-break", p_chain_break),
    ("signature-forgery", p_signature_forgery),
    ("wrong-context", p_wrong_context),
    ("replay", p_replay),
    ("expired", p_expired),
    ("root-untrusted", p_root_untrusted),
    ("version-mismatch", p_version_mismatch),
    ("end-to-end", p_end_to_end),
    ("taxonomy-pin", p_taxonomy_pin),
]


def _green_check():
    """Depth-1: run adjacent batteries' mains with GOV_SKIP_GREEN=1 in
    the child env (no combinatorial nesting). Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "skipped (GOV_SKIP_GREEN=1)")]
    here = os.path.dirname(os.path.abspath(__file__))
    adjacent = ["w264_mandate_probes.py"]
    notes = []
    for battery in adjacent:
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            notes.append((battery, "absent -- skipped"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="w265-green-")
        os.makedirs(env["TMPDIR"], exist_ok=True)
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600)
        except Exception as e:  # noqa: BLE001
            notes.append((battery, "ERROR: %s" % e))
            continue
        tail = (proc.stdout or "").strip().splitlines()[-1:]
        notes.append((battery, "exit=%d %s"
                      % (proc.returncode,
                         tail[0][:100] if tail else "")))
    return notes


def main():
    held, broke, errored = 0, 0, 0
    for name, fn in PROBES:
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001
            ok, detail = False, "ERROR: %r" % (e,)
        tag = "HELD" if ok else (
            "ERROR" if detail.startswith("ERROR") else "BREAK")
        if tag == "HELD":
            held += 1
        elif tag == "ERROR":
            errored += 1
        else:
            broke += 1
        print("%-26s %s -- %s" % (name, tag, detail))
    for name, note in _green_check():
        print("%-26s GREEN -- %s" % (name, note))
    print("RESULT %d/%d HELD, %d BREAK, %d ERROR [impl=%s]" % (
        held, len(PROBES), broke, errored, MOD_NAME))
    return 0 if (broke == 0 and errored == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
