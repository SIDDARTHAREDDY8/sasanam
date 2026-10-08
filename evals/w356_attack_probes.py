#!/usr/bin/env python3
"""Wave-356 attack round 24 regression battery.

Model-driven probes (gpt-4o-mini, 10 calls, ~$0.00045, ledger 417 -> 427)
against the wave-355-merged base (0c2ed594: F473-F475 closed, F476/F477
open). Local validation first (node v24.20.0 ground truth + scanner
verdict on every candidate); the model round then confirmed the .call
family and contributed .bind/reduce.call/filter.call/splice-replace
variants. Only node-exact + scanner-miss shapes were filed.

New findings filed (LOW, OPEN, red-first verified):
- F478: .call/.apply/.bind dispatch on prototype methods --
  Array.prototype.concat.call([],'f1','f2').join(''),
  String.prototype.concat.call('f1','f2'),
  [].concat.call([],'f1','f2').join(''),
  Array.prototype.join.call(['f1','f2'],''),
  Array.prototype.slice.call(['f1','f2'],0,2).join(''),
  Array.prototype.concat.apply([ ],['f1','f2']).join(''),
  Array.prototype.reduce.call(['f1','f2'],(acc,curr)=>acc+curr,''),
  Array.prototype.filter.call(['f1','f2',''], x=>x!=='').join(''),
  String.prototype.concat.bind('f1')('f2'),
  [].map.call(['f1','f2'], String).join(''),
  String.prototype.replace.call('f1,f2', /,/g, '').
  All node-evaluate to the credential while the decoder produces zero
  variants. Distinct from F469 (Reflect.apply -- the Reflect API dispatch
  path, a different mechanism).
- F479: join() coercion of non-string array elements --
  ['f1','f2',null].join(''), ['f1','f2',undefined].join(''),
  ['f1',['f2']].join('') node-evaluate to the credential (engine coerces:
  null/undefined -> "", nested arrays stringify) while the decoder's
  array parser fails closed on the whole literal. Distinct from F477
  (String() coercion of method ARGUMENTS -- a different parser path)
  and F475 (filter over-decode -- the opposite direction).

Known-open pins (each probe returns HELD when the miss reproduces; a
literal BREAK verdict means the pin failed or a NEW break appeared):
F476 (constructor-of miss), F477 (String-coercion miss),
F478 (.call/.apply/.bind miss), F479 (join-coercion miss).

Closed pins (must BLOCK / fail-closed, else BREAK):
F473 (array-receiver concat), F474 (concat TypeError guard),
F475 (mixed-type filter over-decode).

Confirmed fixed on the closed tree: the round-23 F473-class mis-decodes
([...['a']].concat(['b']), ['a','b'].map(String).concat(['c'])) now BLOCK.

Dead/bogus round-24 proposals (validated locally, NOT filed):
C2-ctorprop (all already decoded); C3 fragmentary shapes (never build the
credential); C5 typeof-map (fail-closed); C6 trim/includes predicates
(F470 documented scope); C9 fill+splice/map/reduce (node never recovers
the credential); C10 empty-element joins (already decoded);
String['fromCharCode'] (4 chars only); concat float/bool args and
join_bool (node never recovers the exact credential); f475_additive
(documented F475 residual); m_bind_join/m_splice_repl (node never
recovers); m_substr_call (BLOCKS -- control); f476_arr_from /
f476_ctor_from (BLOCKS -- already covered); 'C'.padStart(29,String(98))
(BLOCKS via raw-text rule); String([C,'']).split filter (BLOCKS via
raw-text rule).

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (pid-suffixed TMPDIRs), fresh /var/tmp/g356-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2140, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2140  # no new decision codes this round; Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# Test credentials, concatenation-constructed -- never literals.
_A = "xoxb-" + "0123"
_B = "4567" + "89abcdef"
_CRED = _A + _B

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


# ---------------------------------------------------------------- controls

@_t
def test_b0_plain_credential_blocked():
    """Control: the plain credential blocks coded."""
    hit = _blocked("token=" + _CRED)
    return ("HELD" if hit else "BREAK", "find_credential=%s" % hit)


@_t
def test_b0_pin_taxonomy():
    """Control: taxonomy pin holds (no new decision codes)."""
    ok = len(TAXONOMY) == TAXONOMY_PIN
    return ("HELD" if ok else "BREAK", "len(TAXONOMY)=%d want %d"
            % (len(TAXONOMY), TAXONOMY_PIN))


@_t
def test_b0_footer_state():
    """Control: footer shows F482-F488 open, next F489 (wave-358 merge:
    F480, F481 CLOSED; F482-F488 filed OPEN)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F621**" in text  # Wave-357 merge: F480 filed; Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621
          and "**Open findings: F612, F613, F614, F615, F616, F617, F618, F619, F620.**" in text)  # Wave-358 lane 2: F481 CLOSED; Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621
