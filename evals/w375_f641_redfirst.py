#!/usr/bin/env python3
"""Red-first for F641: deferred-callback fragment assembly.

F618 (CLOSED) models Promise.all/Promise.race .then callbacks and F638 (OPEN)
the catch/finally/allSettled continuations, but the scheduling primitives
themselves -- queueMicrotask() and setTimeout() -- have no modeled path: the
fragments are pushed inside deferred callbacks and joined after an await that
flushes them, which node evaluates exactly.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B

SHAPES = [
    ("microtask-assembly",
     "(async()=>{var p=[];queueMicrotask(()=>p.push('%s'));queueMicrotask(()=>p.push('%s'));queueMicrotask(()=>p.push('%s'));await null;return p.join('');})()"
     % (_F1, _F2, _F3), True),
    ("microtask-nested",
     "(async()=>{var p=[];queueMicrotask(()=>{p.push('%s');queueMicrotask(()=>p.push('%s'+'%s'));});await null;await null;return p.join('');})()"
     % (_F1, _F2, _F3), True),
    ("microtask-promise-flush",
     "(async()=>{var s='';queueMicrotask(()=>{s+='%s';});queueMicrotask(()=>{s+='%s'+'%s';});await Promise.resolve();return s;})()"
     % (_F1, _F2, _F3), True),
    ("timeout-assembly",
     "(async()=>{var p=[];setTimeout(()=>p.push('%s'),0);setTimeout(()=>p.push('%s'),0);setTimeout(()=>p.push('%s'),0);await new Promise(r=>setTimeout(r,20));return p.join('');})()"
     % (_F1, _F2, _F3), True),
]

CONTROLS = [
    # F618 (CLOSED) still blocks -- closure control.
    ("f618-still-blocks",
     "Promise.all([Promise.resolve('%s'),Promise.resolve('%s'),Promise.resolve('%s')]).then(a=>a.join(''))"
     % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
        is_break = recovers and not hit
        print("%s: %s" % (name, "BREAK(miss)" if is_break else "HELD(blocks)"))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, want_hit in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == want_hit
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
