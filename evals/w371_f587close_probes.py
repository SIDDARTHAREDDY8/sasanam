#!/usr/bin/env python3
"""Wave-371 lane 4: close F587 (new Proxy member-read receivers).

F587 (LOW, filed 2026-10-07 by wave-370 lane 8, attack round 38): the
decoder missed three member-read spellings over new-expression Proxy
constructions while node v24.20.0 evaluates all of them to the exact
credential:
- new Proxy({c:'A'},{get:(t,k)=>t[k]}).c+'B'  (unparenthesized get-trap)
- (new Proxy({c:'A'},{}).c)+'B'               (empty handler, paren)
- new Proxy({c:'A'},{}).c+'B'                 (empty handler, unparen)
Controls (already blocked): (new Proxy(T,{get:(t,k)=>t[k]})).c (F535,
parenthesized get-trap); new Proxy(T,{}) as a DISPATCH receiver (F489).

Closure: the decoder resolves Proxy member-read receivers node-exactly
in both paren spellings -- the direct-passthrough get-trap (F535
grammar) and the empty-handler form (engine-identical target
forwarding) -- such that find_credential flags them; non-identity traps
and non-literal targets still fail closed (documented).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g371-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (grep-verified).  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane; Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    # fail-closed boundary: decoder must NOT flag (no variants).
    return dlp.find_credential(payload) is None


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer -- open F583-F586, F588-F596 / next F597."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F762**" in text  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
          and "Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761." in text)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# --------------------------------------- filed shapes now decode (must block)

@_t
def test_p1_f587_unparen_gettrap():
    """F587: unparenthesized get-trap proxy member read blocks."""
    hit = _blocked("new Proxy({c:'%s'},{get:(t,k)=>t[k]}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f587_paren_empty():
    """F587: parenthesized empty-handler proxy member read blocks."""
    hit = _blocked("(new Proxy({c:'%s'},{}).c)+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f587_unparen_empty():
    """F587: unparenthesized empty-handler proxy member read blocks."""
    hit = _blocked("new Proxy({c:'%s'},{}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f587_bracket_read():
    """F587: bracket-string member read on unparen empty proxy blocks."""
    hit = _blocked("new Proxy({c:'%s'},{} )['c']+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f587_nested_member():
    """F587: nested member chain on get-trap proxy blocks."""
    hit = _blocked("new Proxy({x:{c:'%s'}},{get:(t,k)=>t[k]}).x.c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p1_f587_whitespace():
    """F587: whitespace-tolerant empty-handler form blocks."""
    hit = _blocked("new  Proxy( {c:'%s'} , {} ).c + '%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- closed-neighbor regressions

@_t
def test_p2_f535_paren_gettrap():
    """F535 CLOSED: parenthesized get-trap proxy member read still blocks."""
    hit = _blocked("(new Proxy({c:'%s'},{get:(t,k)=>t[k]})).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f489_dispatch_recv():
    """F489 CLOSED: empty-handler proxy as dispatch receiver still blocks."""
    hit = _blocked("Array.prototype.join.call(new Proxy({length:2,0:'%s',1:'%s'},{}),'-')" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


@_t
def test_p2_f535_literal_member():
    """F535 CLOSED: plain literal member read still blocks."""
    hit = _blocked("({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if hit else "BREAK", "hit=%s" % hit)


# ------------------------------------------------- fail-closed boundaries

@_t
def test_p3_nonpassthrough_trap():
    """Boundary: computing get-trap body fails closed (miss)."""
    ok = _quiet("new Proxy({c:'%s'},{get:(t,k)=>t[k]+''}).c+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_extra_handler_key():
    """Boundary: handler with extra keys fails closed (miss)."""
    ok = _quiet("new Proxy({c:'%s'},{get:(t,k)=>t[k],set:(t,k,v)=>1}).c+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_method_form_trap():
    """Boundary: method-form get trap fails closed (miss)."""
    ok = _quiet("new Proxy({c:'%s'},{get(t,k){return t[k];}}).c+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_nonliteral_target():
    """Boundary: non-literal target fails closed (miss)."""
    ok = _quiet("new Proxy(x,{}).c+'%s'" % (_A,))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_missing_handler():
    """Boundary: missing handler argument fails closed (miss)."""
    ok = _quiet("new Proxy({c:'%s'}).c+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_swapped_trap_params():
    """Boundary: trap body with swapped params fails closed (miss)."""
    ok = _quiet("new Proxy({c:'%s'},{get:(t,k)=>k[t]}).c+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_trap_other_member():
    """Boundary: reading an unmodeled member still fails closed (miss)."""
    ok = _quiet("new Proxy({c:'%s'},{}).zzz+'%s'" % (_A, _B))
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p3_junk_quiet():
    """Boundary: no credential in proxy shape stays quiet."""
    ok = _quiet("new Proxy({c:'ab'},{}).c+'cd'")
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------- node differential

def _node_out(expr):
    p = subprocess.run(["node", "-e", "console.log(" + expr + ")"],
                       capture_output=True, text=True, timeout=30)
    return p.stdout.strip()


@_t
def test_p4_node_differential():
    """Node v24.20.0 differential: decoder flags exactly what node
    evaluates to the exact credential (filed shapes)."""
    shapes = [
        "new Proxy({c:'%s'},{get:(t,k)=>t[k]}).c+'%s'" % (_A, _B),
        "(new Proxy({c:'%s'},{}).c)+'%s'" % (_A, _B),
        "new Proxy({c:'%s'},{}).c+'%s'" % (_A, _B),
        "(new Proxy({c:'%s'},{get:(t,k)=>t[k]})).c+'%s'" % (_A, _B),
    ]
    bad = []
    for s in shapes:
        node_val = _node_out(s)
        if node_val != _CRED:
            bad.append(("node-not-cred", s))
            continue
        if not _blocked(s):
            bad.append(("decoder-miss", s))
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%r" % (bad,))


@_t
def test_p4_node_boundary_differential():
    """Node differential: fail-closed boundaries agree with node reads.

    The computing-trap shape evaluates to a credential in node, but the
    decoder deliberately refuses it (documented static-analysis
    boundary) -- verify node DOES produce the credential there so the
    boundary is honest about what it refuses."""
    s = "new Proxy({c:'%s'},{get:(t,k)=>t[k]+''}).c+'%s'" % (_A, _B)
    node_val = _node_out(s)
    ok = node_val == _CRED and _quiet(s)
    return ("HELD" if ok else "BREAK", "node=%r quiet=%s" % (node_val, _quiet(s)))


# ---------------------------------------------------------------- green check

def _green_check():
    """Depth-1 green check: run the wave-370 attack battery with
    GOV_SKIP_GREEN=1 in the child env (tolerating only its stale footer
    pin). The battery's F587 probe is now test_p1_f587_closed (flipped
    by this lane) -- a BREAK there is a real regression, not tolerated."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    tmp = tempfile.mkdtemp(prefix="g371-4-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w370_attack_probes.py")],
        capture_output=True, text=True, env=env, timeout=900, cwd=REPO_ROOT)
    out = (p.stdout or "") + (p.stderr or "")
    real_break = 0
    footer_break = 0
    for line in out.splitlines():
        if line.startswith("test_b0_footer_state: BREAK"):
            footer_break = 1
        if line.startswith("tally:"):
            parts = line.split()
            try:
                real_break = int(parts[1])
            except (IndexError, ValueError):
                pass
    # w370's footer pin is stale by design (wave-371 lane 4 repoints at
    # merge). Merge-time repoint (wave-305/306 class). Tolerated.
    real_break -= footer_break
    ok = real_break == 0
    return ("HELD" if ok else "BREAK",
            "green(w370_attack): %d real BREAK (%d tolerated footer)"
            % (real_break, footer_break))


@_t
def test_p9_green_check():
    """Green check: wave-370 attack battery stays green (depth-1)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=None)
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    probe_breaks = set()
    for fn in TESTS:
        if args.probe and args.probe not in fn.__name__:
            continue
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, note))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
            probe_breaks.add(fn.__name__)
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    print("BREAKS:", sorted(probe_breaks))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
