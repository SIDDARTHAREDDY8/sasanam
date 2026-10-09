#!/usr/bin/env python3
"""Wave-385 lane 13: close F786 + F787 + F788.

F786 (LOW, filed 2026-10-09 by wave-384 attack round 52): F602
(CLOSED, wave-372) models for-of accumulation, but a `continue`
guard inside the loop misses: the skipped element never
accumulates node-exactly while the decoder produces zero
variants. Node-exact (v24.20.0): the loop iterates the
string-literal elements in order; each `if(EQ)continue;` guard
skips the matching (`===`/`==`) or non-matching (`!==`/`!=`)
elements; the accumulator joins the rest. For-of source is an
inline `[LITS]` or a bound `var|let ARR=[LITS]`; the C-style twin
is `for(var|let I=0;I<ARR.length;I++|++I|I+=1)`. Guards may be
yoda-ordered, loose, braced, and multiple.

F787 (LOW, filed 2026-10-09 by wave-384 attack round 52): F750
(CLOSED, wave-384) covers Error `.message` reads, but `.cause`
misses: `new Error('x',{cause:'f1'})` and assigned `e.cause='f1'`
resolve node-exactly while the decoder produces zero variants.
Node-exact (v24.20.0): the options object's `cause` installs as
an own data property; the catch binds the parameter to the
thrown error; `C.cause` / `C['cause']` reads the installed
literal; the return additive concatenates plain strings
(`.message` terms resolve to the known message literal).

F788 (LOW, filed 2026-10-09 by wave-384 attack round 52): the
decoder has no AggregateError production. Node-exact
(v24.20.0): the errors array literal is copied element-wise
into the fresh `.errors` array (string-literal elements only);
the message is the second argument or `''`; the return additive
resolves `e.errors[INT]` (in-range), `e.errors.join('SEP')` /
`e.errors.join()` (default `,`), a bare `e.errors`
(Array-toString, `,`-joined), and `e.message`. `[new]` optional.

Fix (gov/dlp.py, zero new re.compile -- 28 stays):
- _js_parse_f786_continue_accum_iife (+ _js_f786_parse_guard,
  _js_f786_parse_operand, _js_f786_charge), hooked after F757
  with the parts/ops snapshot-restore discipline (wave-383
  F733 lesson). Disjoint: no earlier route accepts a `for(`
  head with a continue guard (F602/F719/F651/F646 require
  Set/iterator/forEach sources and guard-free bodies; F679's
  statement simulation fails closed on these shapes --
  red-first verified: 2 BREAK on the open tree).
- _js_parse_f787_cause_trycatch_iife and
  _js_parse_f787_assigned_cause_iife (+ _js_f787_parse_error_new,
  _js_f787_parse_cause_options, _js_f787_parse_additive,
  _js_f787_join_terms), hooked after F786. Disjoint from F750:
  F750's `[new] CTOR('LIT'|)` grammar fails closed on the
  two-argument options form and its return additive fails
  closed on `.cause` terms (red-first verified: 2 BREAK on the
  open tree); this requires the cause.
- _js_parse_f788_aggerrors_iife, hooked after F787. Disjoint:
  no earlier route has an AggregateError production (red-first
  verified: 2 BREAK on the open tree).
All results bounded by _MAX_DECODE_BYTES; F452 per-attempt
budget charging with snapshot/restore on every miss.

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g385-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction.
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


# ---------------------------------------------------------------- controls

@_t
def test_p0_pin_taxonomy():
    """Pin stays 2143; registry loads."""
    ok = TAXONOMY_PIN == 2143 and len(TAXONOMY) > 0
    return ("HELD" if ok else "BREAK", "pin=%s" % TAXONOMY_PIN)


@_t
def test_b0_footer_state():
    """Control: lane-local footer (F786/F787/F788 CLOSED; open F762-F785, F789-F794; next F795)."""
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    ok = ("Next free finding: **F921**" in text  # Wave-385 lane 13: F786/F787/F788 CLOSED; open F762-F785, F789-F794 (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F789, F790, F791, F792, F793, F794." in text)  # Wave-385 lane 13: F786/F787/F788 CLOSED; open F762-F785, F789-F794 (next F795)
    return ("HELD" if ok else "BREAK", "footer=%s" % ok)


@_t
def test_p9_junk_quiet():
    """Junk stays quiet (no false positives)."""
    quiet = _misses("'(function(){var s=\\\\'ab\\\\' ;return s;})()'")
    return ("HELD" if quiet else "BREAK", "quiet=%s" % quiet)


# ------------------------------------------------------- filed shapes (p1)

@_t
def test_p1_f786_s1():
    """F786 filed shape 1 (for-of, === guard) blocks."""
    ok = _blocked(
        "(function(){var r='';for(var x of ['%s','xx','%s'])"
        "{if(x==='xx')continue;r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f786-s1=%s" % ok)


@_t
def test_p1_f786_s2():
    """F786 filed shape 2 (C-style, === guard) blocks."""
    ok = _blocked(
        "(function(){var r='';var a=['%s','xx','%s'];"
        "for(var i=0;i<a.length;i++){if(a[i]==='xx')continue;"
        "r+=a[i];}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f786-s2=%s" % ok)


@_t
def test_p1_f787_s1():
    """F787 filed shape 1 (try/catch, options cause) blocks."""
    ok = _blocked(
        "(function(){try{throw new Error('x',{cause:'%s'});}"
        "catch(e){return e.cause+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f787-s1=%s" % ok)


@_t
def test_p1_f787_s2():
    """F787 filed shape 2 (assigned cause) blocks."""
    ok = _blocked(
        "(function(){var e=new Error('x');e.cause='%s';"
        "return e.cause+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f787-s2=%s" % ok)


@_t
def test_p1_f788_s1():
    """F788 filed shape 1 (errors[0]) blocks."""
    ok = _blocked(
        "(function(){var e=new AggregateError(['%s'],'x');"
        "return e.errors[0]+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f788-s1=%s" % ok)


@_t
def test_p1_f788_s2():
    """F788 filed shape 2 (errors.join('')) blocks."""
    ok = _blocked(
        "(function(){var e=new AggregateError(['%s','%s'],'x');"
        "return e.errors.join('');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f788-s2=%s" % ok)


# ---------------------------------------------------- generalizations (p2)

@_t
def test_p2_f786_neq_guard():
    """F786: !== guard accumulates only the matching element."""
    dec = dlp._try_js_expr_decode_all(
        "(function(){var r='';for(var x of ['%s','xx'])"
        "{if(x!=='xx')continue;r+=x;}return r;})()" % _A)
    ok = dec is not None and "xx" in dec
    return ("HELD" if ok else "BREAK", "neq=%s" % ok)


@_t
def test_p2_f786_yoda():
    """F786: yoda guard blocks."""
    ok = _blocked(
        "(function(){var r='';for(var x of ['%s','xx','%s'])"
        "{if('xx'===x)continue;r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "yoda=%s" % ok)


@_t
def test_p2_f786_loose():
    """F786: loose == guard blocks."""
    ok = _blocked(
        "(function(){var r='';for(var x of ['%s','xx','%s'])"
        "{if(x=='xx')continue;r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "loose=%s" % ok)


@_t
def test_p2_f786_braced():
    """F786: braced {continue;} blocks."""
    ok = _blocked(
        "(function(){var r='';for(var x of ['%s','xx','%s'])"
        "{if(x==='xx'){continue;}r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "braced=%s" % ok)


@_t
def test_p2_f786_bound_array():
    """F786: for-of over a bound array blocks."""
    ok = _blocked(
        "(function(){var r='';var a=['%s','xx','%s'];for(var x of a)"
        "{if(x==='xx')continue;r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bound=%s" % ok)


@_t
def test_p2_f786_preinc():
    """F786: C-style ++i blocks."""
    ok = _blocked(
        "(function(){var r='';var a=['%s','xx','%s'];"
        "for(var i=0;i<a.length;++i){if(a[i]==='xx')continue;"
        "r+=a[i];}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "preinc=%s" % ok)


@_t
def test_p2_f786_ipe1():
    """F786: C-style i+=1 blocks."""
    ok = _blocked(
        "(function(){var r='';var a=['%s','xx','%s'];"
        "for(var i=0;i<a.length;i+=1){if(a[i]==='xx')continue;"
        "r+=a[i];}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "ipe1=%s" % ok)


@_t
def test_p2_f786_let_const():
    """F786: let accumulator and const loopvar block."""
    ok = _blocked(
        "(function(){let r='';for(const x of ['%s','xx','%s'])"
        "{if(x==='xx')continue;r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "letconst=%s" % ok)


@_t
def test_p2_f786_two_guards():
    """F786: two guards union their skip sets."""
    ok = _blocked(
        "(function(){var r='';for(var x of ['%s','qq','xx','%s'])"
        "{if(x==='xx')continue;if(x==='qq')continue;r+=x;}return r;})()"
        % (_A, _B))
    return ("HELD" if ok else "BREAK", "twoguard=%s" % ok)


@_t
def test_p2_f787_bare_error():
    """F787: bare Error('x',{cause}) (no new) blocks."""
    ok = _blocked(
        "(function(){try{throw Error('x',{cause:'%s'});}"
        "catch(e){return e.cause+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bare=%s" % ok)


@_t
def test_p2_f787_bracket():
    """F787: e['cause'] bracket read blocks."""
    ok = _blocked(
        "(function(){try{throw new Error('x',{cause:'%s'});}"
        "catch(e){return e['cause']+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "bracket=%s" % ok)


@_t
def test_p2_f787_assign_bracket():
    """F787: e['cause']='..' bracket write blocks."""
    ok = _blocked(
        "(function(){var e=new Error('x');e['cause']='%s';"
        "return e.cause+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "assignbr=%s" % ok)


@_t
def test_p2_f787_var_options():
    """F787: var-bound with constructor options blocks."""
    ok = _blocked(
        "(function(){var e=new Error('x',{cause:'%s'});"
        "return e.cause+'%s';})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "varopt=%s" % ok)


@_t
def test_p2_f787_message_term():
    """F787: e.message term resolves to the message literal."""
    dec = dlp._try_js_expr_decode_all(
        "(function(){try{throw new Error('x',{cause:'%s'});}"
        "catch(e){return e.message+e.cause;}})()" % _A)
    ok = dec is not None and ("x" + _A) in dec
    return ("HELD" if ok else "BREAK", "msgterm=%s" % ok)


@_t
def test_p2_f787_typeerror():
    """F787: TypeError constructor blocks."""
    dec = dlp._try_js_expr_decode_all(
        "(function(){try{throw new TypeError('x',{cause:'%s'});}"
        "catch(e){return e.cause;}})()" % _A)
    ok = dec is not None and _A in dec
    return ("HELD" if ok else "BREAK", "typeerror=%s" % ok)


@_t
def test_p2_f787_string_key():
    """F787: {'cause':'..'} string-key options blocks."""
    dec = dlp._try_js_expr_decode_all(
        "(function(){try{throw new Error('x',{'cause':'%s'});}"
        "catch(e){return e.cause;}})()" % _A)
    ok = dec is not None and _A in dec
    return ("HELD" if ok else "BREAK", "strkey=%s" % ok)


@_t
def test_p2_f788_no_new():
    """F788: AggregateError without new blocks."""
    dec = dlp._try_js_expr_decode_all(
        "(function(){var e=AggregateError(['%s'],'x');"
        "return e.errors[0];})()" % _A)
    ok = dec is not None and _A in dec
    return ("HELD" if ok else "BREAK", "nonew=%s" % ok)


@_t
def test_p2_f788_no_message():
    """F788: missing message decodes (message '')."""
    dec = dlp._try_js_expr_decode_all(
        "(function(){var e=new AggregateError(['%s']);"
        "return e.errors[0]+'|'+e.message;})()" % _A)
    ok = dec is not None and (_A + "|") in dec
    return ("HELD" if ok else "BREAK", "nomsg=%s" % ok)


@_t
def test_p2_f788_bracket():
    """F788: e['errors'][0] bracket read blocks."""
    dec = dlp._try_js_expr_decode_all(
        "(function(){var e=new AggregateError(['%s'],'x');"
        "return e['errors'][0];})()" % _A)
    ok = dec is not None and _A in dec
    return ("HELD" if ok else "BREAK", "bracket=%s" % ok)


@_t
def test_p2_f788_join_sep():
    """F788: join('-') separator blocks."""
    ok = _blocked(
        "(function(){var e=new AggregateError(['%s','%s'],'x');"
        "return e.errors.join('-');})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "joinsep=%s" % ok)


@_t
def test_p2_f788_join_default():
    """F788: join() defaults to ','."""
    dec = dlp._try_js_expr_decode_all(
        "(function(){var e=new AggregateError(['%s','%s'],'x');"
        "return e.errors.join();})()" % (_A, _B))
    ok = dec is not None and (_A + "," + _B) in dec
    return ("HELD" if ok else "BREAK", "joindef=%s" % ok)


@_t
def test_p2_f788_idx1():
    """F788: errors[1] in-range index blocks."""
    dec = dlp._try_js_expr_decode_all(
        "(function(){var e=new AggregateError(['%s','%s'],'x');"
        "return e.errors[1];})()" % (_A, _B))
    ok = dec is not None and _B in dec
    return ("HELD" if ok else "BREAK", "idx1=%s" % ok)


@_t
def test_p2_f788_message():
    """F788: e.message resolves to the message literal."""
    dec = dlp._try_js_expr_decode_all(
        "(function(){var e=new AggregateError(['%s'],'mg');"
        "return e.message;})()" % _A)
    ok = dec is not None and "mg" in dec
    return ("HELD" if ok else "BREAK", "msg=%s" % ok)


@_t
def test_p2_f786_yoda_spaces():
    """F786: yoda guard with spaces blocks."""
    ok = _blocked(
        "(function(){var r='';for(var x of ['%s','xx','%s'])"
        "{if('xx' === x)continue;r+=x;}return r;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "yodasp=%s" % ok)


@_t
def test_p3_f786_const_cstyle():
    """F786: const C-style counter throws in node -- fails closed."""
    ok = _misses(
        "(function(){var r='';var a=['%s'];"
        "for(const i=0;i<a.length;i++){r+=a[i];}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "constc=%s" % ok)


# ---------------------------------------------------- fail-closed bounds (p3)

@_t
def test_p3_f786_guard_other_var():
    """F786: guard on another variable fails closed."""
    ok = _misses(
        "(function(){var r='';var y='xx';for(var x of ['%s','xx'])"
        "{if(y==='xx')continue;r+=x;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "othervar=%s" % ok)


@_t
def test_p3_f786_else():
    """F786: else on the guard fails closed."""
    ok = _misses(
        "(function(){var r='';for(var x of ['%s','xx'])"
        "{if(x==='xx')continue;else r+=x;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "else=%s" % ok)


@_t
def test_p3_f786_set_source():
    """F786: new Set source is F602's territory -- fails closed here."""
    ok = _misses(
        "(function(){var r='';for(var x of new Set(['%s','xx']))"
        "{if(x==='xx')continue;r+=x;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "setsrc=%s" % ok)


@_t
def test_p3_f786_nonliteral_element():
    """F786: non-literal element fails closed."""
    ok = _misses(
        "(function(){var r='';for(var x of ['%s',y])"
        "{if(x==='xx')continue;r+=x;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "nonlit=%s" % ok)


@_t
def test_p3_f786_hole():
    """F786: array hole fails closed."""
    ok = _misses(
        "(function(){var r='';for(var x of ['%s',,'xx'])"
        "{if(x==='xx')continue;r+=x;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "hole=%s" % ok)


@_t
def test_p3_f786_shadow():
    """F786: loopvar shadowing the accumulator fails closed."""
    ok = _misses(
        "(function(){var r='';for(var r of ['%s'])"
        "{if(r==='xx')continue;r+=r;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "shadow=%s" % ok)


@_t
def test_p3_f786_labeled():
    """F786: labeled continue fails closed."""
    ok = _misses(
        "(function(){var r='';outer:for(var x of ['%s'])"
        "{if(x==='xx')continue outer;r+=x;}return r;})()" % _A)
    return ("HELD" if ok else "BREAK", "labeled=%s" % ok)


@_t
def test_p3_f787_no_cause():
    """F787: throw without options -- .cause undefined, fails closed."""
    ok = _misses(
        "(function(){try{throw new Error('x');}"
        "catch(e){return e.cause+'%s';}})()" % _B)
    return ("HELD" if ok else "BREAK", "nocause=%s" % ok)


@_t
def test_p3_f787_numeric_cause():
    """F787: non-literal cause fails closed."""
    ok = _misses(
        "(function(){try{throw new Error('x',{cause:42});}"
        "catch(e){return e.cause;}})()")
    return ("HELD" if ok else "BREAK", "numcause=%s" % ok)


@_t
def test_p3_f787_extra_option():
    """F787: extra options property fails closed."""
    ok = _misses(
        "(function(){try{throw new Error('x',{cause:'%s',z:1});}"
        "catch(e){return e.cause;}})()" % _A)
    return ("HELD" if ok else "BREAK", "extraopt=%s" % ok)


@_t
def test_p3_f787_bare_error_term():
    """F787: bare error term (object stringification) fails closed."""
    ok = _misses(
        "(function(){try{throw new Error('x',{cause:'%s'});}"
        "catch(e){return e;}})()" % _A)
    return ("HELD" if ok else "BREAK", "bareterm=%s" % ok)


@_t
def test_p3_f787_wrong_member():
    """F787: non-cause/message member fails closed."""
    ok = _misses(
        "(function(){try{throw new Error('x',{cause:'%s'});}"
        "catch(e){return e.stack;}})()" % _A)
    return ("HELD" if ok else "BREAK", "wrongmem=%s" % ok)


@_t
def test_p3_f787_two_assignments():
    """F787: a second cause write fails closed."""
    ok = _misses(
        "(function(){var e=new Error('x');e.cause='a';e.cause='%s';"
        "return e.cause;})()" % _A)
    return ("HELD" if ok else "BREAK", "twoassign=%s" % ok)


@_t
def test_p3_f787_delete():
    """F787: delete e.cause fails closed."""
    ok = _misses(
        "(function(){var e=new Error('x',{cause:'%s'});"
        "delete e.cause;return e.cause;})()" % _A)
    return ("HELD" if ok else "BREAK", "delete=%s" % ok)


@_t
def test_p3_f787_non_error_ctor():
    """F787: non-Error constructor fails closed."""
    ok = _misses(
        "(function(){try{throw new Foo('x',{cause:'%s'});}"
        "catch(e){return e.cause;}})()" % _A)
    return ("HELD" if ok else "BREAK", "nonerr=%s" % ok)


@_t
def test_p3_f788_oob():
    """F788: out-of-range index fails closed."""
    ok = _misses(
        "(function(){var e=new AggregateError(['%s'],'x');"
        "return e.errors[5];})()" % _A)
    return ("HELD" if ok else "BREAK", "oob=%s" % ok)


@_t
def test_p3_f788_nonliteral_source():
    """F788: non-literal errors source fails closed."""
    ok = _misses(
        "(function(){var e=new AggregateError([y],'x');"
        "return e.errors[0];})()")
    return ("HELD" if ok else "BREAK", "nonlit=%s" % ok)


@_t
def test_p3_f788_hole():
    """F788: errors hole fails closed."""
    ok = _misses(
        "(function(){var e=new AggregateError(['%s',,'x']);"
        "return e.errors[0];})()" % _A)
    return ("HELD" if ok else "BREAK", "hole=%s" % ok)


@_t
def test_p3_f788_reassign():
    """F788: reassigned .errors fails closed."""
    ok = _misses(
        "(function(){var e=new AggregateError(['%s'],'x');"
        "e.errors=['q'];return e.errors[0];})()" % _A)
    return ("HELD" if ok else "BREAK", "reassign=%s" % ok)


@_t
def test_p3_f788_bad_member():
    """F788: non-errors/message member fails closed."""
    ok = _misses(
        "(function(){var e=new AggregateError(['%s'],'x');"
        "return e.name;})()" % _A)
    return ("HELD" if ok else "BREAK", "badmem=%s" % ok)


@_t
def test_p3_f788_not_aggregate():
    """F788: plain Error has no .errors -- fails closed."""
    ok = _misses(
        "(function(){var e=new Error('x');return e.errors;})()")
    return ("HELD" if ok else "BREAK", "notagg=%s" % ok)


# -------------------------------------------------------- sibling pins (p4)

@_t
def test_p4_f602_forof():
    """Sibling pin: F602 for-of over new Set still blocks."""
    ok = _blocked(
        "(function(){var s='';for(var x of new Set(['%s','%s']))"
        "{s+=x;}return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f602=%s" % ok)


@_t
def test_p4_f750_message():
    """Sibling pin: F750 .message still blocks."""
    ok = _blocked(
        "(function(){try{throw new Error('%s');}"
        "catch(e){return e.message+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f750=%s" % ok)


@_t
def test_p4_f750_bracket():
    """Sibling pin: F750 e['message'] still blocks."""
    ok = _blocked(
        "(function(){try{throw new Error('%s');}"
        "catch(e){return e['message']+'%s';}})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f750br=%s" % ok)


@_t
def test_p4_f651_values():
    """Sibling pin: F651 .values() still blocks."""
    ok = _blocked(
        "(function(){var s='';for(var x of ['%s','%s'].values())"
        "{s+=x;}return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f651=%s" % ok)


@_t
def test_p4_f646_foreach():
    """Sibling pin: F646 forEach still blocks."""
    ok = _blocked(
        "(function(){var s='';['%s','%s'].forEach(function(x){s+=x;});"
        "return s;})()" % (_A, _B))
    return ("HELD" if ok else "BREAK", "f646=%s" % ok)


@_t
def test_p4_f679_not_stolen():
    """Sibling pin: F679's C-style simulation still owns its shapes (base-identical)."""
    ok = _blocked(
        "(function(){var r='';for(var i=0;i<2;i++){r+='%s';}return r;})()"
        % _A)
    return ("HELD" if ok else "BREAK", "f679=%s" % ok)


# ------------------------------------------------- honest-text controls (p5)

@_t
def test_p5_honest_prose():
    """Honest text stays quiet."""
    ok = _misses("the quick brown fox jumps over the lazy dog")
    return ("HELD" if ok else "BREAK", "prose=%s" % ok)


@_t
def test_p5_honest_iife():
    """Honest IIFE without a credential stays quiet."""
    ok = _misses(
        "(function(){var s='';for(var i=0;i<3;i++){s+='a';}return s;})()")
    return ("HELD" if ok else "BREAK", "iife=%s" % ok)


@_t
def test_p5_f786_all_skip_quiet():
    """F786 shape that skips everything decodes to '' -- quiet."""
    ok = _misses(
        "(function(){var r='';for(var x of ['xx'])"
        "{if(x==='xx')continue;r+=x;}return r;})()")
    return ("HELD" if ok else "BREAK", "allskip=%s" % ok)


# ---------------------------------------------------------------- perf (p6)

@_t
def test_p6_perf_200_sites():
    """Perf: 200 mixed sites scan in bounded time."""
    sites = []
    for k in range(200):
        if k % 4 == 0:
            sites.append(
                "(function(){var r='';for(var x of ['%s','xx'])"
                "{if(x==='xx')continue;r+=x;}return r;})()" % _A)
        elif k % 4 == 1:
            sites.append(
                "(function(){try{throw new Error('x',{cause:'%s'});}"
                "catch(e){return e.cause;}})()" % _A)
        elif k % 4 == 2:
            sites.append(
                "(function(){var e=new AggregateError(['%s'],'x');"
                "return e.errors[0];})()" % _A)
        else:
            sites.append("lorem ipsum dolor sit amet %d" % k)
    text = " ".join(sites)
    t0 = time.time()
    dlp.find_credential(text)
    dt = time.time() - t0
    ok = dt < 60
    return ("HELD" if ok else "BREAK", "perf=%.2fs" % dt)


# ------------------------------------------------------------ green check (p7)

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    # (battery, expected BREAKs): the w385 red-firsts demonstrate the
    # closures (0 BREAK on the closed tree). The w384 attack battery
    # filed F786/F787/F788, so its 6 r52 open-probes now BLOCK (the
    # closure, wave-306 class -- merge owns the probe maintenance)
    # and its footer pin is stale by design (lane-local repoint).
    for batt, expect_break in (("evals/w385_f786_redfirst.py", 0),
                               ("evals/w385_f787_redfirst.py", 0),
                               ("evals/w385_f788_redfirst.py", 0),
                               ("evals/w384_attack_probes.py", 7)):
        tmp = tempfile.mkdtemp(prefix="g385-green-", dir="/var/tmp")
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
    """Depth-1 green check: red-firsts + wave-384 attack battery (documented BREAKs)."""
    return _green_check()


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
