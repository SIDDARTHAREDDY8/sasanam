#!/usr/bin/env python3
"""Wave-357 F479 closure battery (lane 2).

F479 (LOW, filed 2026-10-06 wave-356 lane 3, continuous real-model
attack round 24): join() coercion of non-string array elements bypasses
the bounded static JS-expression decoder. The array parser failed closed
on literals containing null / undefined / nested-array elements, but the
real engine coerces them inside .join(''):

  ['f1','f2',null].join('')        null -> "" (dropped)
  ['f1','f2',undefined].join('')   undefined -> "" (dropped)
  ['f1',['f2']].join('')           nested array -> its toString
  ['f1',null,'f2'].join('')        null mid-array -> ""

(node ground truths verified on node v24.20.0; red-first
evals/w356_f479_redfirst.py: 4 BREAK on base -> 0 BREAK / 7 HELD here.)

Distinct from F477 (implicit String() coercion of non-string *arguments*
-- a different parser path) and F475 (filter over-decode on mixed-type
arrays -- the opposite direction: over-decode vs fail-closed miss).

Closure design (gov/dlp.py, F479):
  * `_js_parse_array_element`: array-literal elements now accept the
    null/undefined/true/false keywords (ident-boundary checked; parsed
    as _JSNil/_JSBool markers -- NOT added to _js_parse_primary, so
    every other primary position still fails closed) and single-level
    nested array literals (via _js_parse_nested_array, which forbids
    deeper nesting; factories trip the outer in_array guard).
  * `_js_join_element`: engine-exact per-element coercion --
    null/undefined -> "", booleans -> "true"/"false" (node-verified),
    nested arrays -> comma-joined toString (one level), strings and
    _JSNumStr -> as-is (F475 numeric repr rules compose unchanged).
  * Applied at the join, toString, tag-join, and F477 String()
    (_js_stringify_coercible) sites.
  * Filter interaction: type-dependent predicates (plen/match/ccmp)
    fail closed on every non-plain-str element (_js_has_nonstr_element
    supersedes the bare isinstance(_JSNumStr) checks --
    behavior-identical on the pre-F479 type universe); truthiness
    (_js_truthy_keep) drops _JSNil/_JSBool(false) engine-exactly;
    the F467 null-comparison spec splits into ("all-null",) (drops
    _JSNil) while ()=>true ("all",) keeps everything; reduce and
    map(String) fail closed on marker elements.

Documented fail-closed boundaries (NOT bypasses, disclosed here):
  * Doubly-nested arrays, objects, holes, factories inside arrays,
    additive chains over keywords (null+'x') -- fail closed.
  * `['a',null].filter(x=>x.length>0)` etc. -- type-dependent
    predicates fail closed on marker elements (F475 direction kept).
  * `['a'].concat(...['b',null])` -- F473's spread-element guard still
    fails closed on non-string spread elements (pre-existing).
  * `['a',null].map(String)` -- String(null) is 'null', not '' --
    fails closed rather than mis-decode.

$0 SPEND BY CONSTRUCTION: canned payloads only, no model calls. Do NOT
add ModelDriver/SpendLedger usage here.

Probes:
  P1  closure: the 4 filed shapes block; generalizations (booleans,
      nested mixed/empty, default-sep join, toString, String()
      agreement, concat composition, filter truthy/all-null) block
      node-exactly.
  P2  controls: literal forms still decode; junk quiet; F475 guard
      intact (numeric AND marker elements under plen/match/ccmp);
      F467 spec distinction; honest text unaffected.
  P3  decoder pins: node byte-fidelity on the differential set
      (subprocess); no new regexes (re.compile count); _JSNumStr
      provenance pin; F441 ordering untouched.
  P4  discrimination: FP corpus identical; innocent mixed arrays quiet.
  P5  pin + footer (2135; F478, F479 CLOSED; open F482-F488 / next F489).  # Wave-358 merge: F480, F481 CLOSED
"""

import os
import sys
import subprocess
import argparse
import re
import glob

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_REPO = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_REPO)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-357: F479 closed; no new decision codes
FOOTER_OPEN = "F489, F490, F491, F492, F493, F494, F495"  # Wave-357 lane 2: F479 CLOSED locally (merge finalizes tree-wide)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 lane 2: F481 CLOSED locally  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN
