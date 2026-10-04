"""Break-first red-team battery for AP2-style bounded mandates
(wave-264 feature lane 1).

Target: gov/bounded_mandates.py -- open mandates (approver-signed
bounds: tool allowlist, spend cap, time window, data scopes) and closed
mandates (agent-produced, hash-bound to actual tool calls); the audit
seam verifies closed ⊆ open.

Every probe attacks a PUBLIC seam, never product internals. The battery
imports the implementation via GOV_MANDATE_IMPL (default
"gov.bounded_mandates"); against the permissive stub
(GOV_MANDATE_IMPL=mandate_stub_mod, PYTHONPATH=/tmp/mandate_stub) every
attack probe must BREAK, proving the probes are real. Against the real
module every probe must HELD, in staging and under
`env -u GOV_DEPLOYMENT_MODE`.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. A probe returns (ok, detail); ok=True means HELD (attack
refused / gap is a documented residual), ok=False means BREAK (genuine
defect) or harness ERROR.

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

TAXONOMY_PIN = 1933 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)

MOD_NAME = os.environ.get("GOV_MANDATE_IMPL", "gov.bounded_mandates")
bm = importlib.import_module(MOD_NAME)

NOW = 4000000000.0
KEY = b"w264-mandate-test-key-32-bytes-0000"


def _open(constraints=None, **kw):
    cons = {"tools": ["read_file", "list_dir"],
            "spend_cap": 10,
            "not_before": NOW - 100.0,
            "not_after": NOW + 3600.0,
            "data_scopes": ["fs:read"]}
    cons.update(constraints or {})
    args = {"subject": "agent-a-subject-digest", "constraints": cons,
            "now": NOW}
    args.update(kw)
    return bm.MandateIssuer(KEY).issue_open(**args)


def _close(open_m, tool="read_file", args=None, cost=3,
           executed_at=NOW, prev=None):
    return bm.MandateExecutor(KEY).close_action(
        open_m, tool=tool, args=args or {"path": "/tmp/x"},
        cost=cost, executed_at=executed_at, prev_digest=prev)


def _expect(fn, want_code):
    """Run fn; HELD iff it raises a MandateError with want_code."""
    try:
        fn()
    except bm.MandateError as e:
        if e.code == want_code:
            return True, "HELD (%s)" % want_code
        return False, "BREAK: code %s, wanted %s" % (e.code,
                                                    want_code)
    except Exception as e:  # noqa: BLE001 -- harness must not mask
        return False, "ERROR: unexpected %r" % (e,)
    return False, "BREAK: no refusal (wanted %s)" % want_code


def p_tool_allowlist():
    """Closed mandate names a tool outside the open allowlist."""
    open_m = _open()
    closed = _close(open_m, tool="exec_shell")
    v = bm.MandateVerifier(KEY)
    return _expect(lambda: v.verify(open_m, closed, now=NOW),
                   "mandate-constraint-exceeded")


def p_spend_cap():
    """Two individually-cheap closes whose cumulative cost exceeds
    the spend cap."""
    open_m = _open()
    v = bm.MandateVerifier(KEY)
    c1 = _close(open_m, cost=6)
    v.verify(open_m, c1, now=NOW)
    c2 = _close(open_m, cost=6,
                prev=bm.mandate_digest(c1))
    return _expect(lambda: v.verify(open_m, c2, now=NOW),
                   "mandate-constraint-exceeded")


def p_time_window():
    """Closed mandate executed after the open mandate's not_after."""
    open_m = _open()
    closed = _close(open_m, executed_at=NOW + 7200.0)
    v = bm.MandateVerifier(KEY)
    return _expect(lambda: v.verify(open_m, closed, now=NOW + 7200.0),
                   "mandate-expired")


def p_replay():
    """The same closed mandate verified twice: second is a replay."""
    open_m = _open()
    closed = _close(open_m)
    v = bm.MandateVerifier(KEY)
    v.verify(open_m, closed, now=NOW)
    return _expect(lambda: v.verify(open_m, closed, now=NOW),
                   "mandate-replay")


def p_malformed_open():
    """Open mandate with a negative spend cap is refused at issue."""
    try:
        _open(constraints={"spend_cap": -5})
    except bm.MandateError as e:
        if e.code == "mandate-malformed":
            return True, "HELD (mandate-malformed)"
        return False, "BREAK: code %s" % e.code
    except Exception as e:  # noqa: BLE001
        return False, "ERROR: unexpected %r" % (e,)
    return False, "BREAK: malformed open mandate issued"


def p_version_mismatch():
    """A MAC-valid mandate carrying an unknown future type version is
    refused as a version mismatch, never misinterpreted."""
    open_m = _open()
    # Re-seal with a future type using the documented wire format.
    body = dict(open_m)
    body.pop("mac", None)
    body["type"] = "mandate.open.2"
    future = dict(body)
    future["mac"] = bm.seal_body(body, bm.OPEN_DOMAIN, KEY)
    v = bm.MandateVerifier(KEY)
    closed = _close(open_m)
    try:
        v.verify(future, closed, now=NOW)
    except bm.MandateError as e:
        if e.code == "mandate-version-mismatch":
            return True, "HELD (mandate-version-mismatch)"
        return False, "BREAK: code %s" % e.code
    except Exception as e:  # noqa: BLE001
        return False, "ERROR: unexpected %r" % (e,)
    return False, "BREAK: future-version open mandate accepted"


def p_tampered_closed():
    """Closed mandate with cost flipped after sealing: MAC break."""
    open_m = _open()
    closed = _close(open_m, cost=3)
    tampered = dict(closed)
    tampered["action"] = dict(closed["action"], cost=300)
    v = bm.MandateVerifier(KEY)
    return _expect(lambda: v.verify(open_m, tampered, now=NOW),
                   "mandate-tampered")


def p_unknown_open():
    """A closed mandate bound to open-A presented with open-B: the
    authority is unknown to this verifier."""
    open_a = _open()
    open_b = _open(now=NOW + 1.0)
    assert open_a["id"] != open_b["id"]
    closed = _close(open_a)
    v = bm.MandateVerifier(KEY)
    return _expect(lambda: v.verify(open_b, closed, now=NOW),
                   "mandate-unknown")


def p_chain_break():
    """Second closed mandate whose prev does not link the first."""
    open_m = _open()
    v = bm.MandateVerifier(KEY)
    c1 = _close(open_m, cost=2)
    v.verify(open_m, c1, now=NOW)
    c2 = _close(open_m, cost=2, prev="0" * 64)
    return _expect(lambda: v.verify(open_m, c2, now=NOW),
                   "mandate-tampered")


def p_selective_disclosure():
    """verifier_view discloses only constraints relevant to the
    presented closed mandates -- unused allowlist tools stay hidden."""
    open_m = _open(constraints={"tools": ["read_file", "exec_shell",
                                          "net_fetch"]})
    closed = _close(open_m, tool="read_file")
    v = bm.MandateVerifier(KEY)
    v.verify(open_m, closed, now=NOW)
    view = v.verifier_view(open_m, [closed])
    leaked = [t for t in ("exec_shell", "net_fetch")
              if t in view.get("tools", [])]
    if leaked:
        return False, "BREAK: unused tools disclosed: %r" % leaked
    if "read_file" not in view.get("tools", []):
        return False, "BREAK: used tool missing from view"
    return True, "HELD (selective disclosure)"


def p_end_to_end():
    """Control: a fully in-bounds open/closed pair verifies clean."""
    open_m = _open()
    v = bm.MandateVerifier(KEY)
    c1 = _close(open_m, cost=4)
    verdict = v.verify(open_m, c1, now=NOW)
    c2 = _close(open_m, tool="list_dir", cost=5,
                prev=bm.mandate_digest(c1))
    v.verify(open_m, c2, now=NOW)
    if not verdict.get("ok"):
        return False, "BREAK: valid pair refused: %r" % (verdict,)
    # receipt() re-verifies internally, so mint it on a fresh
    # verifier (the pair above is already consumed on v).
    v2 = bm.MandateVerifier(KEY)
    v2.verify(open_m, c1, now=NOW)
    receipt = v2.receipt(open_m, c2, now=NOW)
    if not receipt.get("mac"):
        return False, "BREAK: receipt unsigned"
    return True, "HELD (valid end-to-end + receipt)"


def p_taxonomy_pin():
    """The 7 mandate-* codes are in the taxonomy, pin matches, and no
    code literal is duplicated in the raw source (wave-260 lesson)."""
    new_codes = ("mandate-malformed", "mandate-version-mismatch",
                 "mandate-tampered", "mandate-unknown",
                 "mandate-expired", "mandate-constraint-exceeded",
                 "mandate-replay")
    import gov.decision_codes as dc
    missing = [c for c in new_codes if c not in dc.TAXONOMY]
    if missing:
        return False, "BREAK: codes missing: %r" % missing
    if len(dc.TAXONOMY) != TAXONOMY_PIN:
        return False, "BREAK: taxonomy %d != pin %d" % (
            len(dc.TAXONOMY), TAXONOMY_PIN)
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, "..", "gov",
                            "decision_codes.py")).read()
    dupes = [c for c in new_codes
             if src.count('"code": \'%s\'' % c) != 1]
    if dupes:
        return False, "BREAK: duplicated/missing literals: %r" % dupes
    return True, "HELD (pin %d, 7 new codes)" % TAXONOMY_PIN


PROBES = [
    ("tool-allowlist", p_tool_allowlist),
    ("spend-cap", p_spend_cap),
    ("time-window", p_time_window),
    ("replay", p_replay),
    ("malformed-open", p_malformed_open),
    ("version-mismatch", p_version_mismatch),
    ("tampered-closed", p_tampered_closed),
    ("unknown-open", p_unknown_open),
    ("chain-break", p_chain_break),
    ("selective-disclosure", p_selective_disclosure),
    ("end-to-end", p_end_to_end),
    ("taxonomy-pin", p_taxonomy_pin),
]


def _green_check():
    """Depth-1: run adjacent batteries' mains with GOV_SKIP_GREEN=1 in
    the child env (no combinatorial nesting). Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "skipped (GOV_SKIP_GREEN=1)")]
    here = os.path.dirname(os.path.abspath(__file__))
    adjacent = ["durable_approval_probes.py",
                "decision_packet_probes.py"]
    notes = []
    for battery in adjacent:
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            notes.append((battery, "absent -- skipped"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="w264-green-")
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
        print("%-22s %s -- %s" % (name, tag, detail))
    for name, note in _green_check():
        print("%-22s GREEN -- %s" % (name, note))
    print("RESULT %d/%d HELD, %d BREAK, %d ERROR [impl=%s]" % (
        held, len(PROBES), broke, errored, MOD_NAME))
    return 0 if (broke == 0 and errored == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
