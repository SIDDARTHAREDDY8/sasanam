#!/usr/bin/env python3
"""Red-first for F1078 + F1080/F1081/F1082: top-level scheduling-primitive
accumulation (F641 residual family).

F641 (CLOSED wave-376) models queueMicrotask/setTimeout deferred callbacks
through the async-arrow-IIFE event-loop simulation. A TOP-LEVEL scheduling
call -- no IIFE wrapper, no flush await -- assembles node-exactly
(v24.20.0; each primitive runs its callback before process exit,
observable via the callback's own output) while find_credential MISSES:

- F1078 (filed 2026-10-10 10:43 UTC, wave-398 round 66): queueMicrotask.
- F1080 (filed 2026-10-10 11:25 UTC, wave-399 lane 3): setTimeout twin.
- F1081 (filed 2026-10-10 11:25 UTC, wave-399 lane 3): setImmediate twin.
- F1082 (filed 2026-10-10 11:25 UTC, wave-399 lane 3): process.nextTick twin.

The spread-form twin inside queueMicrotask blocks coded (AA control).
Prints BREAK on the open tree.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _sched(kind, body):
    if kind == "microtask":
        return "queueMicrotask(()=>{%s});" % body
    if kind == "timeout0":
        return "setTimeout(()=>{%s},0);" % body
    if kind == "timeout-bare":
        return "setTimeout(()=>{%s});" % body
    if kind == "immediate":
        return "setImmediate(()=>{%s});" % body
    if kind == "nexttick":
        return "process.nextTick(()=>{%s});" % body
    raise AssertionError(kind)


def _body(acc_kw="var", loop_kw="var"):
    return ("%s S='';for(%s i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}"
            "var RESULT=S;" % (acc_kw, loop_kw))


def _shapes():
    out = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        out.append(("f1078-%s-microtask" % tag,
                    "var C=%s;%s" % (c, _sched("microtask", _body()))))
    for tag, kind in (("f1080", "timeout0"), ("f1080b", "timeout-bare"),
                      ("f1081", "immediate"), ("f1082", "nexttick")):
        out.append(("%s-%s" % (tag, kind),
                    "var C=%s;%s" % (_codes(SECRET_S),
                                     _sched(kind, _body()))))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: the spread-form twin inside queueMicrotask is modeled -- blocks coded.
    ("aa-microtask-spread-blocks",
     "var C=%s;queueMicrotask(()=>{var RESULT=String.fromCharCode(...C);});"
     % _codes(SECRET_S), True),
    # F641's IIFE-wrapped production still blocks (disjoint, no regression;
    # real F641 shape from evals/w375_f641_redfirst.py).
    ("aa-f641-iife-blocks",
     "(async()=>{var p=[];queueMicrotask(()=>p.push('xoxb-'));"
     "queueMicrotask(()=>p.push('123'));"
     "queueMicrotask(()=>p.push('456789abcdef'));await null;"
     "return p.join('');})()", True),
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("FAIL " if hit else "BREAK ") + name)
        if hit:
            fails.append(name)
    for name, payload, expect_block in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == expect_block
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS),
                                               len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
