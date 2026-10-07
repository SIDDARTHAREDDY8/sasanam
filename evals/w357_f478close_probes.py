#!/usr/bin/env python3
"""Wave-357 F478 closure battery (lane 1).

F478 (LOW, filed 2026-10-06 wave-356 attack round 24): `.call` /
`.apply` / `.bind` dispatch on prototype methods bypasses the bounded
static JS-expression decoder. Every shape below node-evaluates
(v24.20.0) to the exact credential while the decoder produced zero
variants on the open tree:

  Array.prototype.concat.call([], 'f1', 'f2').join('')
  String.prototype.concat.call('f1','f2')
  [].concat.call([], 'f1', 'f2').join('')
  Array.prototype.join.call(['f1','f2'], '')
  Array.prototype.slice.call(['f1','f2'],0,2).join('')
  Array.prototype.concat.apply([], ['f1','f2']).join('')
  Array.prototype.reduce.call(['f1','f2'], (acc,curr)=>acc+curr, '')
  Array.prototype.filter.call(['f1','f2',''], x=>x!=='').join('')
  String.prototype.concat.bind('f1')('f2')
  [].map.call(['f1','f2'], String).join('')
  String.prototype.replace.call('f1,f2', /,/g, '')

Distinct from F469 (Reflect.apply -- the Reflect API dispatch path).

Closure design (gov/dlp.py, F478):
  * `_js_apply_method` refactored: the argument-list core is now
    `_js_apply_method_at(text, i, ...)` (i at the first arg, not the
    paren); the public entry passes j+1. No behavior change.
  * New `_js_parse_prototype_dispatch`: the `X.prototype.METHOD` target
    form (X = Array | String), parsed in `_js_parse_primary` before the
    Array/String branches. The (X, METHOD) pairing is validated --
    `Array.prototype.replace` is undefined in node (TypeError), so an
    unvalidated desugar would mis-decode.
  * New `_js_parse_postfix_dispatch`: the `EXPR.METHOD` target form,
    checked in `_js_parse_postfix` before the method-name loop. EXPR's
    parsed type selects the pairing table; the dispatch's thisArg
    becomes the receiver (the target's base is only how the function
    is referenced).
  * Desugar: `.call(R, args...)` is exactly `R.M(args...)` via
    `_js_apply_method_at` -- same grammar, bounds, fail-closed as the
    direct form (F462 spread, F477 numeric coercion, F474 guards).
    `.apply(R, argsArray)` / `.bind(R, ...)(...)` supply arguments as
    values via the new `_js_concat_values` (concat only -- the filed
    shapes), mirroring the F462/F473/F474 branches exactly.
  * `_JS_EXPR_START` anchor extended with the X.prototype alternatives
    (ws-tolerant, character class only -- the F468 precedent).
  * Fail closed: invalid (X, METHOD) pairing; `.bind` without an
    immediate call; `.call` on non-modeled methods (ends chain, F461);
    `.apply`/`.bind` on non-concat (documented residual); non-array
    argsArray; third apply arg; unparseable thisArg; `new` on bound
    functions; Reflect-nested call/apply; left-boundary
    (`fooArray.prototype...`).

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 11 filed shapes block (node-exact decode checked);
      generalizations (ws tolerance, zero-arg, bound+call args,
      F476 composition, reduceRight) block node-exactly.
  P2  fail-closed boundaries: invalid pairing, bind-no-call,
      non-modeled methods, non-concat apply/bind, non-array argsArray,
      junk quiet, F469/F473 neighbors intact.
  P3  decoder pins: node byte-fidelity differential (subprocess); no
      new regexes (re.compile count + anchor pattern string); F430
      bounds honored.
  P4  pin + footer (F478, F479 CLOSED; open F482-F488 / next F489).  # Wave-358 merge: F480, F481 CLOSED
"""

import os
import sys
import subprocess
import argparse
import re

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_REPO)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-357 lane 1: F478 closed; no new decision codes
FOOTER_OPEN = "F506, F507, F508, F509, F510, F511"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-357 lane 1: F478 CLOSED locally (merge finalizes tree-wide)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 lane 2: F481 CLOSED locally  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)
