#!/usr/bin/env python3
"""Red-first for F475: implicit String() coercion of non-string arguments.

Real JS engines coerce non-string arguments via String() in several
decoder-modeled methods, but the static decoder fails closed on all of
them:

- ['x'].concat(123456789,'y'): numeric concat args are stringified by the
  engine; the decoder's concat branch accepts only string/spread args.
- 'xy'.repeat([2]) / 'xy'.repeat('2'): ToNumber('2')=2, ToNumber([2])=2;
  the decoder models only integer-literal paren counts (F472: literal-only
  tag templates).
- 'x'.padStart(22,['z']): padString=String(['z'])='z'; the decoder's
  padStart accepts only literal pad strings (F465).
- 'a,b'.replace(/,/g,['']): replacement=String([''])=''; the decoder's
  replace accepts only literal-string replacements (F464).
- String(['a','b']).replace(/,/g,''): the decoder models .toString() on
  arrays (F464) but not the String() constructor call.

All six node-evaluate to the credential while the decoder produces no
variant. Distinct from F473 (array RECEIVER fail-closed) and F474
(TypeError on _JSArr args -- these shapes fail closed silently, no raise).

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
    ("repeat-array-count",
     "'%s%s%s'.repeat([1])" % (A1, A2, A3), True),
    ("repeat-string-count",
     "'%s%s%s'.repeat('1')" % (A1, A2, A3), True),
    ("padstart-array-pad",
     "'%s%s%s'.padStart(21,['z'])" % (A1, A2, A3), True),
    ("replace-array-repl",
     "'%s,%s%s'.replace(/,/g,[''])" % (A1, A2, A3), True),
    ("string-ctor-array",
     "String(['%s','%s']).replace(/,/g,'')" % (A1 + A2[:4], A2[4:] + A3), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "['ab'].concat(12,'cd').join('')", False),
    ("neighbor-f462-closed", "\"\".concat(...['%s','%s'])" % (A1 + A2, A3), True),
    ("neighbor-repeat-lit", "'%s%s%s'.repeat(1)" % (A1, A2, A3), True),
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
