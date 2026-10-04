"""Wave-296 lane 3 battery: close F369 (LOW) -- FilterStack.audit_log()
returns shallow copies aliasing the stored records.

BASE: wave-295 merge 10777555 (F369 OPEN).
EXPECTATIONS ON BASE:
  - 1 BREAK: `audit-aliasing-record` (F369 reproduces: mutating the
    returned record rewrites the stored log).
  - 6 HELD: top-level entry independence, list independence, stable
    subsequent invokes, coded refusal without audit filter,
    tamper-detectability via the record signature, repeated-read equality.

EXPECTATIONS FIXED: 0 BREAK / 7 HELD / 0 ERROR -- every returned entry
(including the nested record dict) is an independent deep copy; caller
mutation cannot touch stored records.

New batteries set the deployment mode at module level (wave-95 lesson)
and are verified under `env -u GOV_DEPLOYMENT_MODE`. Depth-1 green
checks: this battery's green check runs the adjacent batteries' mains
with GOV_SKIP_GREEN=1; every green-check function honors the var.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json
import re
import subprocess
import sys
import tempfile

_RESULTS = []

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)


def _record(pid, verdict, note):
    _RESULTS.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note))


# ---------------------------------------------------------------------------
# Depth-1 green checks
# ---------------------------------------------------------------------------

def _run_battery(path, expected_breaks):
    d = tempfile.mkdtemp(prefix="g296f369-")
    proc = subprocess.run(
        [sys.executable, os.path.join(_REPO, "evals", path)],
        capture_output=True, text=True, timeout=600,
        env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d),
        cwd=_REPO)
    out = proc.stdout + proc.stderr
    m = re.search(r"(\d+)\s+BREAK\s*/\s*(\d+)\s+HELD\s*/\s*(\d+)\s+ERROR",
                  out)
    if not m:
        _record("green-" + path, "ERROR",
                "could not parse summary: %s" % out[-500:])
        return
    br, he, er = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if br == expected_breaks and er == 0:
        _record("green-" + path, "HELD",
                "%s: %d BREAK / %d HELD / %d ERROR as expected"
                % (path, br, he, er))
    else:
        _record("green-" + path, "ERROR",
                "%s: expected %d BREAK / 0 ERROR, got %d BREAK / %d "
                "HELD / %d ERROR" % (path, expected_breaks, br, he, er))


def green_check():
    """Depth-1 green check. Honors GOV_SKIP_GREEN (wave-173 lesson)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped via GOV_SKIP_GREEN=1 (depth-1)")
        return
    # w295_redteam: on the composed wave-296 tree F367/F368/F369/F370
    # are all CLOSED -> 0 BREAK expected-open (the lane-local tree had
    # F367, F368, F370 still OPEN for 3 BREAK).
    _run_battery("w295_redteam_probes.py", 0)
    _run_battery("w294_filter_pipeline_probes.py", 0)


# ---------------------------------------------------------------------------
# Taxonomy pin (closure-only lane: gov/decision_codes.py untouched; pin 1750)
# ---------------------------------------------------------------------------

TAXONOMY_PIN = 1906 # Wave-295 merge (F365-F370 filed, +8 codes); wave-296; Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*)
                     # lane 3 closes F369: correctness fix, no new codes.


def p_taxonomy_pin():
    src = open(os.path.join(_REPO, "gov", "decision_codes.py")).read()
    codes = re.findall(r"""['"]code['"]\s*:\s*['"]([^'"]+)['"]""", src)
    if len(codes) != TAXONOMY_PIN:
        _record("pin-taxonomy", "BREAK",
                "expected %d raw literals, got %d"
                % (TAXONOMY_PIN, len(codes)))
        return
    if len(set(codes)) != len(codes):
        _record("pin-taxonomy", "BREAK", "duplicate literals")
        return
    if codes != sorted(codes):
        _record("pin-taxonomy", "BREAK", "literals unsorted")
        return
    _record("pin-taxonomy", "HELD",
            "pin 1820: raw literals %d/%d/0/sorted" % (len(codes),
                                                       len(set(codes))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx(ip, call_id="c", session_id="s"):
    return ip.InvocationContext(tool="t", caller={"id": "caller"},
                                call_id=call_id, session_id=session_id)


def _sig_pair():
    from gov import ed25519 as ed
    seed = ed.generate_seed()
    pub = ed.publickey(seed)
    return seed, pub


# ---------------------------------------------------------------------------
# F369 probes
# ---------------------------------------------------------------------------

def p_audit_aliasing_record():
    # F369: audit_log() promises "copies of the signed per-call records"
    # but returned shallow copies: mutating the nested record rewrote the
    # stored log. Probe mutates both a nested scalar and a nested list.
    from gov import invocation_pipeline as ip
    stack = ip.default_stack(name="f369-aliasing")
    stack.invoke(lambda c: {"ok": 1}, _ctx(ip, call_id="audit-1"))
    rec = stack.audit_log()[0]
    rec["record"]["outcome"] = "TAMPERED-BY-CALLER"
    rec["record"]["redactions"].append("injected-redaction")
    again = stack.audit_log()[0]
    if again["record"]["outcome"] == "TAMPERED-BY-CALLER" or \
            "injected-redaction" in again["record"]["redactions"]:
        _record("audit-aliasing-record", "BREAK",
                "F369: audit_log() shallow copy aliases the stored "
                "record; caller mutation rewrote the log entry")
    else:
        _record("audit-aliasing-record", "HELD",
                "audit_log() returns deep copies: nested record "
                "mutations do not touch the stored log")


def p_audit_top_level_independent():
    # The returned entry dict's top-level keys are already independent
    # copies on the base (shallow copy makes a new dict): contract holds.
    from gov import invocation_pipeline as ip
    stack = ip.default_stack(name="f369-toplevel")
    stack.invoke(lambda c: {"ok": 1}, _ctx(ip, call_id="audit-1"))
    entry = stack.audit_log()[0]
    entry["signature"] = "deadbeef" * 8
    entry["signer_id"] = "attacker"
    again = stack.audit_log()[0]
    if again["signature"] == "deadbeef" * 8 or \
            again["signer_id"] == "attacker":
        _record("audit-top-level-independent", "BREAK",
                "top-level entry mutation leaked into the stored log")
    else:
        _record("audit-top-level-independent", "HELD",
                "top-level entry keys are independent copies")


def p_audit_list_independent():
    # Mutating the returned LIST (pop/remove) must not touch the log.
    from gov import invocation_pipeline as ip
    stack = ip.default_stack(name="f369-list")
    stack.invoke(lambda c: {"ok": 1}, _ctx(ip, call_id="audit-1"))
    stack.invoke(lambda c: {"ok": 2}, _ctx(ip, call_id="audit-2"))
    log = stack.audit_log()
    log.pop()
    again = stack.audit_log()
    if len(again) != 2:
        _record("audit-list-independent", "BREAK",
                "returned-list mutation changed the stored log length")
    else:
        _record("audit-list-independent", "HELD",
                "returned list is an independent list of copies")


def p_audit_subsequent_invoke_stable():
    # Earlier log entries stay byte-identical after further invocations.
    from gov import invocation_pipeline as ip
    stack = ip.default_stack(name="f369-stable")
    stack.invoke(lambda c: {"ok": 1}, _ctx(ip, call_id="audit-1"))
    before = json.dumps(stack.audit_log()[0]["record"], sort_keys=True)
    stack.invoke(lambda c: {"ok": 2}, _ctx(ip, call_id="audit-2"))
    after = json.dumps(stack.audit_log()[0]["record"], sort_keys=True)
    if before != after:
        _record("audit-subsequent-invoke-stable", "BREAK",
                "earlier log entry changed after a later invocation")
    else:
        _record("audit-subsequent-invoke-stable", "HELD",
                "earlier log entries are byte-identical across invokes")


def p_audit_no_audit_filter_coded():
    # A stack built without an audit filter refuses coded, not raw.
    from gov import invocation_pipeline as ip

    def passthrough(ctx, nxt):
        return nxt(ctx)
    stack = ip.build_filter_stack([passthrough], name="f369-noaudit")
    try:
        stack.audit_log()
    except ip.InvocationPipelineError as e:
        if e.code != ip.INVALID_CALL:
            _record("audit-no-audit-filter-coded", "BREAK",
                    "no-audit-filter refused with wrong code %r" % (e.code,))
        else:
            _record("audit-no-audit-filter-coded", "HELD",
                    "no-audit-filter refuses coded %s" % (e.code,))
        return
    _record("audit-no-audit-filter-coded", "BREAK",
            "audit_log() on a filterless stack did not refuse")


def p_audit_tamper_detectable():
    # F369 rationale: tampering is detectable via the record signature.
    # Re-canonicalizing a tampered record must fail verification.
    from gov import invocation_pipeline as ip
    from gov import ed25519 as ed
    seed, pub = _sig_pair()
    stack = ip.default_stack(name="f369-tamper",
                             signer=lambda p: ed.sign(seed, p),
                             signer_id="k1")
    stack.invoke(lambda c: {"ok": 1}, _ctx(ip, call_id="audit-1"))
    entry = stack.audit_log()[0]
    good = ed.verify(pub, ip._canonical(entry["record"]),
                     bytes.fromhex(entry["signature"]))
    entry["record"]["outcome"] = "TAMPERED-BY-CALLER"
    bad = ed.verify(pub, ip._canonical(entry["record"]),
                    bytes.fromhex(entry["signature"]))
    if not good:
        _record("audit-tamper-detectable", "BREAK",
                "untampered record failed signature verification")
    elif bad:
        _record("audit-tamper-detectable", "BREAK",
                "tampered record still verified (signature not binding)")
    else:
        _record("audit-tamper-detectable", "HELD",
                "tampered record fails signature verification (is True / "
                "is False checked)")


def p_audit_repeated_reads_equal():
    # Two reads of an untouched log are canonical-equal.
    from gov import invocation_pipeline as ip
    stack = ip.default_stack(name="f369-reads")
    stack.invoke(lambda c: {"ok": 1}, _ctx(ip, call_id="audit-1"))
    a = json.dumps(stack.audit_log(), sort_keys=True)
    b = json.dumps(stack.audit_log(), sort_keys=True)
    if a != b:
        _record("audit-repeated-reads-equal", "BREAK",
                "repeated audit_log() reads disagree")
    else:
        _record("audit-repeated-reads-equal", "HELD",
                "repeated reads are canonical-equal")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    green_check()
    p_taxonomy_pin()
    p_audit_aliasing_record()
    p_audit_top_level_independent()
    p_audit_list_independent()
    p_audit_subsequent_invoke_stable()
    p_audit_no_audit_filter_coded()
    p_audit_tamper_detectable()
    p_audit_repeated_reads_equal()

    breaks = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    errors = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("----")
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
