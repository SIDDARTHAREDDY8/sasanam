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
  P5  pin + footer (2140; F478, F479 CLOSED; open F482-F488 / next F489).  # Wave-358 merge: F480, F481 CLOSED
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

TAXONOMY_PIN = 2144  # Wave-357: F479 closed; no new decision codes; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
FOOTER_OPEN = "F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-357 lane 2: F479 CLOSED locally (merge finalizes tree-wide)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 lane 2: F481 CLOSED locally  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
