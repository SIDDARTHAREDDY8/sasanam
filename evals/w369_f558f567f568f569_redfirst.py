#!/usr/bin/env python3
"""Red-first for wave-369 lane 7: F558, F567, F568, F569.

- F558: object-pattern destructuring in Reflect.apply targets misses (BREAK=miss).
- F568: entries/values-idiom bodies in function-valued Reflect.apply targets miss.
- F569: call-indirect (Reflect.apply.call) arguments-enumerating bodies miss.
- F567: identifier-suffixed anchors (xJSON.parse, xstructuredClone) flag HIT while
  node throws ReferenceError -- BREAK=false-positive present.
Prints BREAK on the open tree, HELD when closed.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

SHAPES = [
    # F558: object-pattern destructuring in Reflect.apply targets
    ('f558-const',
     'Reflect.apply(function(){const {0:a,1:b}=arguments;return a+b;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, 'miss'),
    ('f558-var',
     'Reflect.apply(function(){var {0:x,1:y}=arguments;return x+y;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, 'miss'),
    # F568: entries/values idiom bodies in Reflect.apply targets
    ('f568-entries',
     'Reflect.apply(function(){var a=arguments;return Object.entries(a).map(e=>e[1]).join(\'\');},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, 'miss'),
    ('f568-values',
     'Reflect.apply(function(){var a=arguments;return Object.values(a).join(\'\');},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, 'miss'),
    ('f568-values-map',
     'Reflect.apply(function(){var a=arguments;return Object.values(a).map(x=>x).join(\'\');},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, 'miss'),
    # F569: call-indirect arguments-enumerating Reflect.apply targets
    ('f569-bare-alias',
     'Reflect.apply.call(Reflect,function(){var a=arguments;return a[0]+a[1];},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, 'miss'),
    ('f569-forof',
     'Reflect.apply.call(Reflect,function(){var a=arguments;var s=\'\';for(var x of a){s+=x;}return s;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, 'miss'),
    ('f569-forin',
     'Reflect.apply.call(Reflect,function(){var a=arguments;var s=\'\';for(var i in a){s+=a[i];}return s;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, 'miss'),
    ('f569-spread-alias',
     'Reflect.apply.call(Reflect,function(){var a=arguments;return a[0]+a[1];},null,[...[\'%(A1)s\',\'%(A2)s\']])'
     % {"A1": A1, "A2": A2}, 'miss'),
    # F567: identifier-suffixed anchors must NOT flag (node throws ReferenceError)
    ('f567-json',
     'xJSON.parse(\'{"x":["%(A1)s","%(A2)s"]}\').x.join(\'\')'
     % {"A1": A1, "A2": A2}, 'quiet'),
    ('f567-clone',
     'xstructuredClone({c:\'%(A1)s\'}).c+\'%(A2)s\''
     % {"A1": A1, "A2": A2}, 'quiet'),
]

CONTROLS = [
    ('f546-closed-direct',
     'Reflect.apply(function(){var a=arguments;return a[0]+a[1];},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, True),
    ('f544-closed-callindirect',
     'Reflect.apply.call(Reflect,function(a,b){return a+b;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, True),
    ('f541-closed-json',
     'JSON.parse(\'{"x":["%(A1)s","%(A2)s"]}\').x.join(\'\')'
     % {"A1": A1, "A2": A2}, True),
    ('honest-json-text',
     'the config was updated by the admin yesterday', False),
    ('junk-quiet',
     'Reflect.apply(function(){const {0:a,1:b}=arguments;return a+b;},null,[\'zz\',\'yy\'])', False),
]


def main():
    breaks, held = 0, 0
    for name, payload, kind in SHAPES:
        hit = find_credential(payload) is not None
        if kind == 'miss':
            is_break = not hit
            label = "BREAK(miss)" if is_break else "HELD(blocks)"
        else:
            is_break = hit  # false positive present
            label = "BREAK(false-positive)" if is_break else "HELD(quiet)"
        print("%s: %s" % (name, label))
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
