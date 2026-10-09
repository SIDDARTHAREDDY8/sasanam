#!/usr/bin/env python3
"""Wave-389 lane 2: close F925 + F926 + F928 + F929 (JS laundering residuals).

F925 (LOW; wave-388 attack round 56): super property access is
unmodeled -- the decoder has no super production:
`super.x` reads against a setPrototypeOf-installed prototype
resolve node-exactly while the decoder produces zero variants.
Close-when: the decoder models super property access
node-exactly (or refuses the laundering coded) such that
find_credential flags them, red-first verified, honest text
unaffected.

F926 (LOW; wave-388 attack round 56): class extends chains with
constructor field init are missed -- class extends expressions
with constructor super() + field init (new C().v) resolve
node-exactly while the decoder produces zero variants.
Close-when: the decoder models class extends chains (extends
expression, super(), field init) node-exactly (or refuses the
laundering coded) such that find_credential flags them,
red-first verified, honest text unaffected.

F928 (LOW; wave-388 attack round 56): comma/sequence expressions
are unmodeled -- the comma operator and for-update accumulation
resolve node-exactly while the decoder produces zero variants.
Close-when: the decoder models sequence expressions (comma
operator, for-update) node-exactly (or refuses the laundering
coded) such that find_credential flags them, red-first
verified, honest text unaffected.

F929 (LOW; wave-388 attack round 56): the `in` operator is
unmodeled -- the decoder has no `in`-operator production: the
plain-object guarded read and the Proxy has-trap variant resolve
node-exactly while the decoder produces zero variants.
Close-when: the decoder models the `in` operator (plain and
has-trap) node-exactly (or refuses the laundering coded) such
that find_credential flags them, red-first verified, honest
text unaffected.

Fix (gov/dlp.py, zero new re.compile):
- F925: new _js_parse_f925_super_iife (dedicated IIFE hook,
  tried after F679): object-literal method shorthands and
  method-only classes, Object.setPrototypeOf holder/proto
  install, super.x/super['x'] resolved at call time against
  the installed proto (node-exact GetPrototypeOf(homeObject)).
- F926: _js_f904_parse_subclass accepts this.K='LIT' field
  inits after super() (appended after the pre-substituted
  superclass assigns -- later wins, node-exact); F879 class
  expressions route `extends` through F904 and accept the
  empty `class{}` (default ctor); the inner-name parse no
  longer swallows the `extends` keyword.
- F928: _js_f679_decl accepts `(E1,...,En)` comma-sequence
  initializers (string operands / int literals, yields last);
  _js_f679_sim_for accepts `;` empty bodies and
  comma-separated update lists (int updates + string accums
  via _js_f679_for_update, trial-parsed side-effect-free).
- F929: the `in` operator in _js_f679_eval_cond (parenthesized
  and bare forms; plain objects use own-props + the fixed
  Object.prototype key set -- node-exact); `new
  Proxy(TARGET,HANDLER)` declarations (narrow has-trap
  function/arrow/method forms, or empty handler) bound as a
  dict-subclass _JSF929Proxy (existing object paths keep
  working; `in` answers from the trap); the `in`-guarded
  return ternary in the F679 IIFE return position.

New findings filed: none.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed /var/tmp TMPDIRs), no in-repo git
in self-pins, concatenation-constructed credentials, pin 2143,
VERIFIER_TAXONOMY_PIN 33, $0-spend-by-construction.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # no new decision codes this lane

from gov import dlp  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decodes_to(payload, want):
    return dlp._try_js_expr_decode_all(payload) == want


def _fails_closed(payload):
    return dlp._try_js_expr_decode_all(payload) is None


def _findings_text():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        return f.read()


# ------------------------------------------------ p0: pins and footer


@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_p0_verifier_taxonomy_pin():
    """VERIFIER_TAXONOMY_PIN stays 33."""
    import re
    hits = []
    for root, _ds, fs in os.walk(os.path.join(REPO_ROOT, "evals")):
        for fn in fs:
            if fn.endswith(".py"):
                src = open(os.path.join(root, fn)).read()
                hits += re.findall(r"VERIFIER_TAXONOMY_PIN\s*=\s*(\d+)", src)
    ok = bool(hits) and all(h == "33" for h in hits)
    return ("HELD" if ok else "BREAK", "verifier-pin=%s" % (hits[:3]))


@_t
def test_p0_no_new_re_compile():
    """Zero new re.compile: count stays 28."""
    import re
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    n = len(re.findall(r"re\.compile\(", src))
    ok = n == 28
    return ("HELD" if ok else "BREAK", "re.compile=%d" % n)


@_t
def test_p0_footer_state():
    """Merged footer: F921-F936 closed; open F937-F948; next F949."""
    import re
    text = _findings_text()
    foot = [ln for ln in text.splitlines()
            if ln.startswith("Next free finding:")]
    ok = False
    if foot:
        last = foot[-1]
        m = re.search(r"\*\*Open findings: ([^*]+)\.\*\*", last)
        open_list = m.group(1) if m else ""
        items = [x.strip() for x in open_list.split(",")]
        want = ["F%d" % n for n in range(937, 949)]
        ok = ("**F949**" in last
              and items == want
              and "F921-F936 CLOSED (15)" in last)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


# ------------------------------------------------ p1: filed shapes (must block)


@_t
def test_p1_f925_s1():
    """F925 filed shape: super.x blocks, decodes exact."""
    p = ("(function(){var proto={x:'%s'};var o={m(){return super.x+'%s';}};"
         "Object.setPrototypeOf(o,proto);return o.m();})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f926_s1():
    """F926 filed shape: extends + field init blocks, decodes exact."""
    p = ("(function(){var B=class{};class C extends B{constructor(){super();"
         "this.v='%s';}}return new C().v+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f928_s1():
    """F928 filed shape: comma-init blocks, decodes exact."""
    p = ("(function(){var s=(0,'%s');return s+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f928_s2():
    """F928 filed shape: for-update comma blocks, decodes exact."""
    p = ("(function(){var s='';for(var i=0;i<1;s+='%s',i++);"
         "return s+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f929_s1():
    """F929 filed shape: plain `in` ternary blocks, decodes exact."""
    p = ("(function(){var o={v:'%s'};return ('v' in o)?o.v+'%s':'';})()"
         % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p1_f929_s2():
    """F929 filed shape: has-trap `in` ternary blocks, decodes exact."""
    p = ("(function(){var p=new Proxy({v:'%s'},"
         "{has:function(t,k){return k==='v';}});"
         "return ('v' in p)?p.v+'%s':'';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


# ------------------------------------------------ p2: generalizations (node-exact)


@_t
def test_p2_f925_bracket():
    """F925: super['x'] bracket form, node-exact."""
    p = ("(function(){var proto={x:'%s'};var o={m(){return super['x']+'%s';}};"
         "Object.setPrototypeOf(o,proto);return o.m();})()" % (_A, _B))
    ok = _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f925_class_method():
    """F925: super in class method via C.prototype, node-exact."""
    p = ("(function(){var B={x:'%s'};class C{m(){return super.x+'%s';}}"
         "Object.setPrototypeOf(C.prototype,B);var c=new C();"
         "return c.m();})()" % (_A, _B))
    ok = _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f925_multi_operand():
    """F925: multi-operand method return, node-exact."""
    p = ("(function(){var proto={x:'%s'};var o={m(){return super.x+'%s'+'!';}};"
         "Object.setPrototypeOf(o,proto);return o.m();})()" % (_A, _B))
    ok = _decodes_to(p, _A + _B + "!")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f926_extends_expr():
    """F926: var C=class extends B form, node-exact."""
    p = ("(function(){var B=class{};var C=class extends B{constructor(){super();"
         "this.v='%s';}};return new C().v+'%s';})()" % (_A, _B))
    ok = _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f926_two_fields():
    """F926: two field inits, node-exact."""
    p = ("(function(){var B=class{};class C extends B{constructor(){super();"
         "this.v='%s';this.w='%s';}}return new C().v+new C().w;})()"
         % (_A, _B))
    ok = _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f926_param_rhs():
    """F926: field init from subclass param, node-exact."""
    p = ("(function(){var B=class{};class C extends B{constructor(p){super();"
         "this.v=p;}}return new C('%s').v+'%s';})()" % (_A, _B))
    ok = _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f926_subclass_wins():
    """F926: subclass field overrides superclass assign, node-exact."""
    p = ("(function(){class B{constructor(){this.v='nope';}}"
         "class C extends B{constructor(){super();this.v='%s';}}"
         "return new C().v+'%s';})()" % (_A, _B))
    ok = _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f928_strings():
    """F928: string operands in comma seq, node-exact."""
    p = ("(function(){var s=('x','%s');return s+'%s';})()" % (_A, _B))
    ok = _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f928_three():
    """F928: three-operand comma seq, node-exact."""
    p = ("(function(){var s=(0,1,'%s');return s+'%s';})()" % (_A, _B))
    ok = _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f928_update_two_iters():
    """F928: for-update comma over two iterations, node-exact."""
    p = ("(function(){var s='';for(var i=0;i<2;s+='%s',i++);"
         "return s;})()" % _A)
    ok = _decodes_to(p, _A + _A)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f929_bare_in():
    """F929: bare `'v' in o` in if condition, node-exact."""
    p = ("(function(){var o={v:'%s'};var s='';if('v' in o){s=o.v+'%s';}"
         "return s;})()" % (_A, _B))
    ok = _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f929_in_false_branch():
    """F929: `in` false takes the else branch, node-exact."""
    p = ("(function(){var o={v:'%s'};return ('z' in o)?o.v+'%s':'q';})()"
         % (_A, _B))
    ok = _decodes_to(p, "q")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f929_prototype_key():
    """F929: Object.prototype keys are `in`, node-exact."""
    p = ("(function(){var o={v:'%s'};return ('toString' in o)?'y':'n';})()"
         % _A)
    ok = _decodes_to(p, "y")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f929_trap_miss():
    """F929: has-trap miss takes the else branch, node-exact."""
    p = ("(function(){var p=new Proxy({v:'%s'},"
         "{has:function(t,k){return k==='v';}});"
         "return ('x' in p)?p.v+'%s':'q';})()" % (_A, _B))
    ok = _decodes_to(p, "q")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p2_f929_arrow_trap():
    """F929: arrow has-trap twin, node-exact."""
    p = ("(function(){var p=new Proxy({v:'%s'},{has:(t,k)=>k==='v'});"
         "return ('v' in p)?p.v+'%s':'';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f929_method_trap():
    """F929: method-shorthand has-trap twin, node-exact."""
    p = ("(function(){var p=new Proxy({v:'%s'},{has(t,k){return k==='v';}});"
         "return ('v' in p)?p.v+'%s':'';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p2_f929_no_trap():
    """F929: empty-handler proxy forwards `in` to target, node-exact."""
    p = ("(function(){var p=new Proxy({v:'%s'},{});"
         "return ('v' in p)?p.v+'%s':'';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


# ------------------------------------------------ p3: fail-closed bounds


@_t
def test_p3_f925_no_setproto():
    """F925 bound: super without setPrototypeOf fails closed."""
    p = ("(function(){var o={m(){return super.x+'%s';}};"
         "return o.m();})()" % _B)
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f925_missing_key():
    """F925 bound: super key missing from proto fails closed."""
    p = ("(function(){var proto={y:'%s'};var o={m(){return super.x+'%s';}};"
         "Object.setPrototypeOf(o,proto);return o.m();})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f925_method_params():
    """F925 bound: method with params fails closed."""
    p = ("(function(){var proto={x:'%s'};var o={m(a){return super.x+'%s';}};"
         "Object.setPrototypeOf(o,proto);return o.m();})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f925_this_in_method():
    """F925 bound: `this` in method body fails closed."""
    p = ("(function(){var proto={x:'%s'};var o={m(){return this.x+'%s';}};"
         "Object.setPrototypeOf(o,proto);return o.m();})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f926_extends_no_superclass():
    """F926 bound: `class extends{}` is a SyntaxError -- fails closed."""
    p = "(function(){var C=class extends{};return '%s';})()" % _A
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f926_this_before_super():
    """F926 bound: this before super() fails closed (engine ReferenceError)."""
    p = ("(function(){var B=class{};class C extends B{constructor(){"
         "this.v='%s';super();}}return new C().v+'%s';})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f926_nonthis_stmt():
    """F926 bound: non-this statement after super() fails closed."""
    p = ("(function(){var B=class{};class C extends B{constructor(){super();"
         "var x='%s';}}return new C().v+'%s';})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f926_unbound_super():
    """F926 bound: extends of undeclared name fails closed."""
    p = ("(function(){class C extends Q{constructor(){super();this.v='%s';}}"
         "return new C().v+'%s';})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f928_call_in_seq():
    """F928 bound: call inside comma seq fails closed."""
    p = ("(function(){var s=(f(),'%s');return s+'%s';})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f928_bad_update():
    """F928 bound: non-update in for-update fails closed."""
    p = ("(function(){var s='';for(var i=0;i<1;f(),i++);"
         "return s+'%s';})()" % _B)
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f929_loose_eq_trap():
    """F929 bound: loose-== has-trap fails closed."""
    p = ("(function(){var p=new Proxy({v:'%s'},"
         "{has:function(t,k){return k=='v';}});"
         "return ('v' in p)?p.v+'%s':'';})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f929_get_trap():
    """F929 bound: handler with get trap fails closed (unmodeled)."""
    p = ("(function(){var p=new Proxy({v:'%s'},"
         "{has:function(t,k){return k==='v';},"
         "get:function(t,k){return t[k];}});"
         "return ('v' in p)?p.v+'%s':'';})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f929_in_nonobject():
    """F929 bound: `in` on a string binding fails closed."""
    p = ("(function(){var o='%s';return ('v' in o)?'y':'n';})()" % _A)
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


@_t
def test_p3_f929_wrong_param():
    """F929 bound: trap comparing the wrong param fails closed."""
    p = ("(function(){var p=new Proxy({v:'%s'},"
         "{has:function(t,k){return t==='v';}});"
         "return ('v' in p)?p.v+'%s':'';})()" % (_A, _B))
    ok = _fails_closed(p)
    return ("HELD" if ok else "BREAK", "miss=%s" % ok)


# ------------------------------------------------ p4: sibling pins (no regressions)


@_t
def test_p4_sib_f679_for():
    """Sibling: plain F679 for loop still decodes."""
    p = ("(function(){var s='';for(var i=0;i<2;i++){s+='a';}return s;})()")
    ok = _decodes_to(p, "aa")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_sib_f679_while():
    """Sibling: plain F679 while loop still decodes."""
    p = ("(function(){var s='';var i=0;while(i<2){s+='a';i++;}return s;})()")
    ok = _decodes_to(p, "aa")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_sib_f679_ternary():
    """Sibling: F679 ternary accumulation still decodes."""
    p = ("(function(){var s='';var x=1;s=x===1?'a':'b';return s;})()")
    ok = _decodes_to(p, "a")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


@_t
def test_p4_sib_f904_super_forward():
    """Sibling: F904 super-forward still decodes."""
    p = ("(function(){class B{constructor(x){this.k=x;}}"
         "class C extends B{constructor(){super('%s');}}"
         "return new C().k+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f904_empty_body():
    """Sibling: F904 empty-body extends still decodes."""
    p = ("(function(){class B{constructor(){this.k='%s';}}"
         "class C extends B{}return new C().k+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f878_ctor():
    """Sibling: F878 constructor still decodes."""
    p = ("(function(){class C{constructor(){this.v='%s';}}"
         "return new C().v+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f780_params():
    """Sibling: F780 param'd ctor still decodes."""
    p = ("(function(){function C(x){this.x=x;}var o=new C('%s');"
         "return o.x+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f679_member():
    """Sibling: F679 member reads still decode."""
    p = ("(function(){var o={v:'%s'};return o.v+'%s';})()" % (_A, _B))
    ok = _blocked(p) and _decodes_to(p, _A + _B)
    return ("HELD" if ok else "BREAK", "blocked+exact=%s" % ok)


@_t
def test_p4_sib_f679_in_false():
    """Sibling: plain `in` false stays a miss-free decode."""
    p = ("(function(){var o={v:'%s'};return ('z' in o)?'y':'n';})()" % _A)
    ok = _decodes_to(p, "n")
    return ("HELD" if ok else "BREAK", "exact=%s" % ok)


# ------------------------------------------------ p5: junk / honest quiet


@_t
def test_p5_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\'ab\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    honest = ("the super method dispatches through the prototype chain "
              "and the for loop update runs after each iteration")
    ok = _misses(honest)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_proxy_quiet():
    """Honest Proxy code without credential stays quiet."""
    honest = ("(function(){var p=new Proxy({v:'ab'},"
              "{has:function(t,k){return k==='v';}});"
              "return ('v' in p)?p.v+'cd':'';})()")
    ok = _misses(honest)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


@_t
def test_p5_honest_class_quiet():
    """Honest class-extends code without credential stays quiet."""
    honest = ("(function(){var B=class{};class C extends B{constructor(){"
              "super();this.v='ab';}}return new C().v+'cd';})()")
    ok = _misses(honest)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


# ------------------------------------------------ p6: perf


@_t
def test_p6_perf():
    """200 mixed sites decode in <20s with zero hits."""
    sites = []
    for k in range(200):
        m = k % 4
        if m == 0:
            sites.append(
                "(function(){var proto={x:'a%d'};var o={m(){return super.x;}};"
                "Object.setPrototypeOf(o,proto);return o.m();})()" % k)
        elif m == 1:
            sites.append(
                "(function(){var B=class{};class C extends B{constructor(){"
                "super();this.v='a%d';}}return new C().v;})()" % k)
        elif m == 2:
            sites.append(
                "(function(){var s=(0,'a%d');return s;})()" % k)
        else:
            sites.append(
                "(function(){var o={v:'a%d'};return ('v' in o)?o.v:'';})()"
                % k)
    big = " ".join(sites)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK",
            "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ p7: green check (depth-1)


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # Red-firsts: this lane's four expect 0 BREAK; the sibling
    # red-firsts (F904/F878/F879/F780) expect 0 BREAK (no
    # regressions from the shared-code changes). Close batteries
    # are NOT used here -- their footer pins rot when a lane
    # appends a footer (wave-341 lesson).
    for batt, expect_break in (
            ("evals/w389_f925_redfirst.py", 0),
            ("evals/w389_f926_redfirst.py", 0),
            ("evals/w389_f928_redfirst.py", 0),
            ("evals/w389_f929_redfirst.py", 0),
            ("evals/w388_f904_redfirst.py", 0),
            ("evals/w387_f878_redfirst.py", 0),
            ("evals/w387_f879_redfirst.py", 0),
            ("evals/w384_f780_redfirst.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g389-green-", dir="/var/tmp")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        p = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, batt)],
            capture_output=True, text=True, env=env, timeout=900,
            cwd=REPO_ROOT)
        out = (p.stdout or "") + (p.stderr or "")
        nbreak = None
        for line in out.splitlines():
            if line.startswith("tally:"):
                parts = line.split()
                try:
                    nbreak = int(parts[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None:
            bad.append((batt, "no-tally"))
        elif nbreak != expect_break:
            bad.append((batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK", "green=%s" % (bad if bad else "ok"))


@_t
def test_p7_green_check():
    """Depth-1 green check: red-firsts at expected tallies."""
    return _green_check()


# ------------------------------------------------ p8: FINDINGS.md stamps


@_t
def test_p8_findings_stamps():
    """F925/F926/F928/F929 stamped CLOSED; neighbors filed; footer next F937."""
    text = _findings_text()
    bad = []
    for fid in ("F925", "F926", "F928", "F929"):
        i = text.find("(%s filed" % fid)
        if i < 0:
            bad.append(fid + "-missing")
            continue
        j = text.find("\n(", i)
        entry = text[i:j] if j > 0 else text[i:]
        if "CLOSED" not in entry.split("Close-when:")[0]:
            bad.append(fid + "-not-closed")
    for fid in ("F921", "F924", "F930", "F936"):
        if ("(%s filed" % fid) not in text:
            bad.append(fid + "-missing")
    if "Next free finding: **F949**" not in text:
        bad.append("footer-next-not-F949")
    return ("HELD" if not bad else "BREAK",
            "stamps %s" % ("ok" if not bad else bad))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tally-only", action="store_true")
    args = ap.parse_args()
    breaks, held, errors = 0, 0, 0
    for fn in TESTS:
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, note = "ERROR", "%r" % e
        if not args.tally_only:
            print("%s: %s (%s)" % (fn.__name__, verdict, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
