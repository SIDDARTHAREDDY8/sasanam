#!/usr/bin/env python3
"""Red-first for F477: implicit String() coercion of non-string arguments.
[Renumbered F475->F477 at wave-355 merge: lane 3 kept F475 (filter over-decode); attack lane deferred per parent decision.]

Real JS engines coerce non-string arguments via String() in several
decoder-modeled methods, but the static decoder fails closed on all of
them:

- ['x'].concat(123456789,'y'): numeric concat args are stringified by the
  engine; the decoder's concat branch accepts only string/spread args.
- 'x'.padStart(22,['z']): padString=String(['z'])='z'; the decoder's
  padStart accepts only literal pad strings (F465).
- 'a,b'.replace(/,/g,['']): replacement=String([''])=''; the decoder's
  replace accepts only literal-string replacements (F464).
- String(['a','b']).replace(/,/g,''): the decoder models .toString() on
  arrays (F464) but not the String() constructor call.

All four node-evaluate to the credential while the decoder produces no
variant. Distinct from F473 (array RECEIVER fail-closed) and F474
(TypeError on _JSArr args -- these shapes fail closed silently, no raise).

Dropped from the first draft (2026-10-06 takeover validation): two
repeat-coercion shapes whose receivers were the verbatim credential --
they trip the raw-text rule (HELD), so they cannot demonstrate a bypass;
a non-verbatim repeat-coercion cannot build the 21-char non-periodic
credential, documented as a scope note. The draft padStart shape was
also reworked: the original used a verbatim-credential receiver (no
padding needed, coercion unexercised); the filed shape
'123456789abcdef'.padStart(21,['xoxb-0']) forces real String(['xoxb-0])
coercion to build the credential.

Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0"
A2 = "123456789"
A3 = "abcdef"

SHAPES = [
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("concat-numeric-arg",
     "['%s'].concat(%s,'%s').join('')" % (A1, A2, A3), True),
    ("padstart-array-pad",
     "'%s'.padStart(21,['%s'])" % (A2 + A3, A1), True),
    ("replace-array-repl",
     "'%s,%s%s'.replace(/,/g,[''])" % (A1, A2, A3), True),
    ("string-ctor-array",
     "String(['%s','%s']).replace(/,/g,'')" % (A1 + A2[:4], A2[4:] + A3), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "['ab'].concat(12,'cd').join('')", False),
    ("neighbor-f462-closed", "\"\".concat(...['%s','%s'])" % (A1 + A2, A3), True),
    ("neighbor-padstart-lit", "'%s'.padStart(21,'%s')" % (A2 + A3, A1), True),
    ("neighbor-string-tostring", "['%s','%s'].toString().replace(/,/g,'')" % (A1 + A2[:4], A2[4:] + A3), True),
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
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
