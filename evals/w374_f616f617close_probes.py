#!/usr/bin/env python3
"""Wave-374 lane 5 close probes: F616 + F617 (URLSearchParams mutation family).

Wave-375 lane 5 update (2026-10-08): F627 (var-bound VALUES) folded
into the F616 production -- bindings are role-agnostic string
constants; F635 (var-bound NAMES on the searchParams receiver) folded
into the F617 production via the F616-style name-binding section. The
p2/p4 variant lists and p3/p6 bound lists below reflect the folded
close-whens; the lane-local footer is open F621-F625, F628-F634,
F636-F639 / next F640.

F616 (LOW, filed attack round 41): variable-bound (non-literal) parameter
names in URLSearchParams statement-form mutations. F599/F606/F610 (all
CLOSED) model the statement-form mutation model with LITERAL parameter
names and fail the whole shape closed on a non-literal name, so the
name-binding axis escaped:
  (function(){var p=new URLSearchParams('');var q='q';p.append(q,'f1');p.append(q,'f2');return p.getAll(q).join('');})()
  the literal-terminal twin with var-bound appends, and the set/get twin
  (function(){var p=new URLSearchParams('q=xx');var k='q';p.set(k,'f1');return p.get(k)+'f2';})()
all node-evaluate to the exact credential (v24.20.0) while the decoder
produces zero variants. Closed by _js_parse_f616_varname_mutation_iife:
the F599/F606/F610 statement-form union with `var|const|let X='LIT'`
binding decls (role-agnostic: names and -- since wave-375 lane 5,
F627 -- values); unbound idents fail closed (engine throws
ReferenceError); >=1 mutation required so the zero-mutation
F576-domain control stays quiet; getAll (F599/F606) and
get+additive-literal-tail (F610) terminals.

F617 (LOW, filed attack round 41): `new URL(...).searchParams`
set/append/delete + get/getAll laundering. F599 (CLOSED) models the
URLSearchParams CONSTRUCTOR receiver and documents `new URL(...)`
bindings as a fail-closed residual -- but that claim was INACCURATE for
the searchParams receiver (re-verified on the wave-372 tree):
`u.searchParams` is a LIVE binding (node: u.searchParams===u.searchParams),
so statement-form mutations through it launder exactly like the
constructor receiver. Closed by _js_parse_f617_url_searchparams_iife:
initial pairs from the URL query (F576's parse_qsl), append/set/delete
engine-exact, get (F610 read path) and getAll (F599 read path) terminals;
names may be literals or bound idents (F635 folded in 2026-10-08
wave-375 lane 5); values stay literal-only (documented residual).

Seams under test (tdd): find_credential at the public seam for every
probe; node v24.20.0 differential (subprocess) for engine-exactness.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import os
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

TAXONOMY_PIN = 2143  # Wave-373 merge: pin 2143 (F595, F606-F611 closed); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _quiet(payload):
    return dlp.find_credential(payload) is None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


# ---------------------------------------------------------- P1: F616 filed
def p1_f616_filed_shapes():
    """The three filed F616 shapes must decode (HELD after closure)."""
    shapes = [
        "(function(){var p=new URLSearchParams('');var q='q';"
        "p.append(q,'%s');p.append(q,'%s');return p.getAll(q).join('');})()"
        % (_A1, _A2),
        "(function(){var p=new URLSearchParams('');var q='q';"
        "p.append(q,'%s');p.append(q,'%s');return p.getAll('q').join('');})()"
        % (_A1, _A2),
        "(function(){var p=new URLSearchParams('q=xx');var k='q';"
        "p.set(k,'%s');return p.get(k)+'%s';})()" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return (("HELD", "3/3 F616 filed shapes decode") if not bad
            else ("BREAK", "miss: %r" % ([b[:50] for b in bad],)))


# ---------------------------------------------------------- P2: F616 variants
def p2_f616_variants():
    """Node-exact twins of the F616 shapes (all verified v24.20.0)."""
    variants = [
        # const/let name decls bind identically
        ("const", "(function(){const p=new URLSearchParams('');let q='q';"
         "p.append(q,'%s');p.append(q,'%s');return p.getAll(q).join('');})()"
         % (_A1, _A2)),
        # double-quoted name literal
        ("dq", '(function(){var p=new URLSearchParams("");var q="q";'
         'p.append(q,"%s");p.append(q,"%s");return p.getAll(q).join("");})()'
         % (_A1, _A2)),
        # ws-tolerant
        ("ws", "(function(){var p = new URLSearchParams( '' ) ; var q = 'q' ; "
         "p.append( q , '%s' ) ; p.append( q , '%s' ) ; "
         "return p.getAll( q ).join( '' ) ; })()" % (_A1, _A2)),
        # duplicate name decl rebinds (last wins, engine-exact)
        ("rebind", "(function(){var p=new URLSearchParams('');var q='z';"
         "var q='q';p.append(q,'%s');p.append(q,'%s');"
         "return p.getAll(q).join('');})()" % (_A1, _A2)),
        # unused name decl: all-literal uses still decode node-exactly
        ("unused-decl", "(function(){var p=new URLSearchParams('');"
         "var q='q';p.append('q','%s');p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2)),
        # sort/delete with var-bound names (F606's union, name axis)
        ("sort", "(function(){var p=new URLSearchParams('q=b');var q='q';"
         "p.append(q,'%s');p.append(q,'%s');p.sort();"
         "return p.getAll(q).join('');})()" % (_A1, _A2)),
        ("delete", "(function(){var p=new URLSearchParams('z=zz&q=yy');"
         "var q='q';p.delete('z');p.set(q,'%s');"
         "return p.get(q)+'%s';})()" % (_A1, _A2)),
        # two distinct name bindings
        ("two-names", "(function(){var p=new URLSearchParams('');var a='q';"
         "var b='q';p.append(a,'%s');p.append(b,'%s');"
         "return p.getAll(a).join('');})()" % (_A1, _A2)),
        # set/get twin with bracket-string member reads
        ("bracket", "(function(){var p=new URLSearchParams('q=xx');var k='q';"
         "p['set'](k,'%s');return p['get'](k)+'%s';})()" % (_A1, _A2)),
        # additive tail twin of the get terminal
        ("get-tail", "(function(){var p=new URLSearchParams('');var k='k';"
         "p.set(k,'%s');return p.get(k)+'%s';})()" % (_A1, _A2)),
        # var-bound VALUE: CLOSED 2026-10-08 wave-375 lane 5 (F627 folded
        # into the F616 production -- bindings are role-agnostic
        # string constants; the same bound ident may serve as a
        # mutation name in one statement and a value in another)
        ("var-value", "(function(){var p=new URLSearchParams('');var q='q';"
         "var v='%s';p.append(q,v);p.append(q,'%s');"
         "return p.getAll(q).join('');})()" % (_A1, _A2)),
        # var-bound value with set/get twin
        ("var-value-set", "(function(){var p=new URLSearchParams('q=xx');"
         "var v='%s';p.set('q',v);return p.get('q')+'%s';})()" % (_A1, _A2)),
    ]
    bad = [n for n, s in variants if not _blocked(s)]
    return (("HELD", "%d/%d F616 variants decode" % (len(variants), len(variants)))
            if not bad else ("BREAK", "miss: %r" % (bad,)))


# ---------------------------------------------------------- P3: F616 bounds
def p3_f616_bounds():
    """F616 boundaries must stay fail-closed (quiet)."""
    bounds = [
        # unbound name ident: engine throws ReferenceError -- fail closed
        ("unbound", "(function(){var p=new URLSearchParams('');"
         "p.append(q,'%s');return p.getAll('q').join('');})()" % _A1),
        # duplicate let/const (or var-then-let): SyntaxError in the
        # engine -- fail closed (node v24.20.0 verified)
        ("dup-let", "(function(){var p=new URLSearchParams('');"
         "let q='z';let q='q';p.append(q,'%s');"
         "return p.getAll(q).join('');})()" % _A1),
        ("dup-const", "(function(){var p=new URLSearchParams('');"
         "const q='z';const q='q';p.append(q,'%s');"
         "return p.getAll(q).join('');})()" % _A1),
        ("var-then-let", "(function(){var p=new URLSearchParams('');"
         "var q='z';let q='q';p.append(q,'%s');"
         "return p.getAll(q).join('');})()" % _A1),
        # non-string name RHS: fail closed (documented residual)
        ("nonstring-rhs", "(function(){var p=new URLSearchParams('');var q=1;"
         "p.append(q,'%s');return p.getAll('q').join('');})()" % _A1),
        # name decl AFTER the first mutation: fail closed (residual)
        ("decl-after-mut", "(function(){var p=new URLSearchParams('');"
         "p.append('q','%s');var q='q';return p.getAll(q).join('');})()"
         % _A1),
        # zero mutations + var-bound get, credential raw in the ctor
        # string: the RAW scan fires (red-first convention -- the decoder
        # path itself must add nothing, verified by zero-mut-getall-split)
        ("zero-mut-get-raw", "(function(){var p=new URLSearchParams('q=%s%s');"
         "var k='q';return p.get(k);})()" % (_A1, _A2)),
        # zero mutations + var-bound getAll, credential SPLIT across pairs
        # so no raw/encoding layer can fire: the DECODER must stay quiet
        ("zero-mut-getall-split", "(function(){var p=new URLSearchParams('q=%s&q=%s');"
         "var k='q';return p.getAll(k).join('');})()" % (_A1, _A2)),
        # var-bound VALUE: CLOSED 2026-10-08 wave-375 lane 5 (F627 folded
        # into the F616 production) -- the probe moved to p2 variants
        # has-guard with var-bound name: documented residual
        ("has-guard", "(function(){var p=new URLSearchParams('');var q='q';"
         "p.append(q,'%s');if(p.has(q)){return p.getAll(q).join('');}"
         "return '';})()" % _A1),
        # name decl colliding with the params ident: fail closed
        ("name-is-pname", "(function(){var p=new URLSearchParams('');"
         "var p='q';p.append('q','%s');return p.getAll('q').join('');})()"
         % _A1),
        # non-literal additive tail: fail closed
        ("tail-nonliteral", "(function(){var p=new URLSearchParams('q=xx');"
         "var k='q';p.set(k,'%s');return p.get(k)+x;})()" % _A1),
        # get of missing var-bound name: JS null -- fail closed
        ("get-missing", "(function(){var p=new URLSearchParams('');var k='z';"
         "p.append('q','%s');return p.get(k)+'%s';})()" % (_A1, _A2)),
    ]
    raw_hit = [n for n, s in bounds
               if n == "zero-mut-get-raw" and not _blocked(s)]
    quiet_bad = [n for n, s in bounds
                 if n != "zero-mut-get-raw" and not _quiet(s)]
    bad = raw_hit + quiet_bad
    return (("HELD", "%d/%d F616 bounds hold" % (len(bounds), len(bounds)))
            if not bad else ("BREAK", "bad: %r" % (bad,)))


# ---------------------------------------------------------- P4: F617 filed
def p4_f617_filed_shapes():
    """The three filed F617 shapes must decode (HELD after closure)."""
    shapes = [
        "(function(){var u=new URL('http://x/?q=xx');"
        "u.searchParams.set('q','%s');return u.searchParams.get('q')+'%s';})()"
        % (_A1, _A2),
        "(function(){var u=new URL('http://x/');"
        "u.searchParams.append('q','%s');u.searchParams.append('q','%s');"
        "return u.searchParams.getAll('q').join('');})()" % (_A1, _A2),
        "(function(){var u=new URL('http://x/?q=xx');"
        "u.searchParams.delete('q');u.searchParams.set('q','%s');"
        "return u.searchParams.get('q')+'%s';})()" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return (("HELD", "3/3 F617 filed shapes decode") if not bad
            else ("BREAK", "miss: %r" % ([b[:50] for b in bad],)))


# ---------------------------------------------------------- P5: F617 variants
def p5_f617_variants():
    """Node-exact twins of the F617 shapes (all verified v24.20.0)."""
    variants = [
        # bracket-string receiver (F576 precedent)
        ("bracket", "(function(){var u=new URL('http://x/?q=xx');"
         "u['searchParams'].set('q','%s');"
         "return u['searchParams'].get('q')+'%s';})()" % (_A1, _A2)),
        # append-then-set ordering
        ("append-set", "(function(){var u=new URL('http://x/?q=a');"
         "u.searchParams.set('q','%s');u.searchParams.append('q','%s');"
         "return u.searchParams.getAll('q').join('');})()" % (_A1, _A2)),
        # percent-encoded query (F576's parse_qsl, node-identical)
        ("pct-query", "(function(){var u=new URL('http://x/?q=%%66%%31');"
         "u.searchParams.set('q','%s');return u.searchParams.get('q')+'%s';})()"
         % (_A1, _A2)),
        # empty query + double append (live binding, no initial pairs)
        ("empty-q", "(function(){var u=new URL('http://x/');"
         "u.searchParams.append('q','%s');"
         "return u.searchParams.get('q')+'%s';})()" % (_A1, _A2)),
        # const/let decl, ws-tolerant
        ("ws", "(function(){const u = new URL( 'http://x/?q=xx' ) ; "
         "u.searchParams.set( 'q' , '%s' ) ; "
         "return u.searchParams.get( 'q' ) + '%s' ; })()" % (_A1, _A2)),
        # set twice: last wins (engine-exact)
        ("set-twice", "(function(){var u=new URL('http://x/');"
         "u.searchParams.set('q','zz');u.searchParams.set('q','%s');"
         "return u.searchParams.get('q')+'%s';})()" % (_A1, _A2)),
        # delete of a SIBLING name keeps the credential pair
        ("delete-sib", "(function(){var u=new URL('http://x/?a=1&q=xx');"
         "u.searchParams.delete('a');u.searchParams.set('q','%s');"
         "return u.searchParams.get('q')+'%s';})()" % (_A1, _A2)),
        # getAll with postfix slice (F599 read path through postfix)
        ("getall-slice", "(function(){var u=new URL('http://x/');"
         "u.searchParams.append('q','zz');u.searchParams.append('q','%s');"
         "u.searchParams.append('q','%s');"
         "return u.searchParams.getAll('q').slice(1).join('');})()"
         % (_A1, _A2)),
        # port + fragment in the URL (query still parses)
        ("port-frag", "(function(){var u=new URL('http://x:8443/p?q=xx#frag');"
         "u.searchParams.set('q','%s');return u.searchParams.get('q')+'%s';})()"
         % (_A1, _A2)),
        # var-bound NAME on the searchParams receiver: CLOSED
        # 2026-10-08 wave-375 lane 5 (F635 folded into the F617
        # production -- the F616-style name-binding section)
        ("var-name", "(function(){var u=new URL('http://x/');var q='q';"
         "u.searchParams.append(q,'%s');u.searchParams.append(q,'%s');"
         "return u.searchParams.getAll(q).join('');})()" % (_A1, _A2)),
        # var-bound name with set/get + additive tail twin
        ("var-name-set", "(function(){var u=new URL('http://x/?q=xx');var k='q';"
         "u.searchParams.set(k,'%s');return u.searchParams.get(k)+'%s';})()"
         % (_A1, _A2)),
    ]
    bad = [n for n, s in variants if not _blocked(s)]
    return (("HELD", "%d/%d F617 variants decode" % (len(variants), len(variants)))
            if not bad else ("BREAK", "miss: %r" % (bad,)))


# ---------------------------------------------------------- P6: F617 bounds
def p6_f617_bounds():
    """F617 boundaries must stay fail-closed (quiet)."""
    bounds = [
        # sort() on the searchParams receiver: documented F617 residual
        ("sort", "(function(){var u=new URL('http://x/?q=%s');"
         "u.searchParams.sort();"
         "return u.searchParams.getAll('q').join('');})()" % _A1),
        # var-bound name on the searchParams receiver: CLOSED 2026-10-08
        # wave-375 lane 5 (F635 folded into the F617 production) --
        # the probe moved to p4 variants
        # bare `u.get(...)` without .searchParams: engine throws
        ("no-receiver", "(function(){var u=new URL('http://x/?q=%s');"
         "return u.get('q');})()" % _A1),
        # two-arg URL form: F576 fails closed (documented)
        ("two-arg", "(function(){var u=new URL('?q=xx','http://x/');"
         "u.searchParams.set('q','%s');"
         "return u.searchParams.get('q')+'%s';})()" % (_A1, _A2)),
        # relative URL: engine throws -- fail closed
        ("relative", "(function(){var u=new URL('/?q=xx');"
         "u.searchParams.set('q','%s');"
         "return u.searchParams.get('q')+'%s';})()" % (_A1, _A2)),
        # non-literal query arg: fail closed
        ("nonliteral-arg", "(function(){var u=new URL(x);"
         "u.searchParams.set('q','%s');"
         "return u.searchParams.get('q')+'%s';})()" % (_A1, _A2)),
        # non-literal mutation name: fail closed
        ("nonliteral-name", "(function(){var u=new URL('http://x/');"
         "u.searchParams.append(q,'%s');"
         "return u.searchParams.getAll('q').join('');})()" % _A1),
        # non-literal mutation value: fail closed
        ("nonliteral-value", "(function(){var u=new URL('http://x/');"
         "u.searchParams.append('q',x);"
         "return u.searchParams.getAll('q').join('');})()"),
        # get of missing name: JS null -- fail closed (documented)
        ("get-missing", "(function(){var u=new URL('http://x/');"
         "u.searchParams.set('q','%s');"
         "return u.searchParams.get('z')+'%s';})()" % (_A1, _A2)),
        # has-terminal: documented residual
        ("has-terminal", "(function(){var u=new URL('http://x/');"
         "u.searchParams.append('q','%s');"
         "return u.searchParams.has('q');})()" % _A1),
        # .slice() on the get STRING: was fail-closed by design pre-wave-375;
        # now decodes via the F624 (string-slice) + F617 (get) composition,
        # node-exact (wave-375 merge). Removed from bounds; pinned by the
        # F624 close battery's composition section.
    ]
    bad = [n for n, s in bounds if not _quiet(s)]
    return (("HELD", "%d/%d F617 bounds quiet" % (len(bounds), len(bounds)))
            if not bad else ("BREAK", "fired: %r" % (bad,)))


# ---------------------------------------------------------- P7: compositions
def p7_compositions():
    """Neighbor findings stay HELD; nothing absorbed by the closures."""
    held = [
        # F576: .get on constructor strings, literal name
        ("f576-get", "new URLSearchParams('q=%s').get('q')+'%s'" % (_A1, _A2)),
        # F599: literal-name append/getAll statement form
        ("f599-append", "(function(){var p=new URLSearchParams('');"
         "p.append('q','%s');p.append('q','%s');"
         "return p.getAll('q').join('');})()" % (_A1, _A2)),
        # F606: sort/delete with literal names
        ("f606-sort", "(function(){var p=new URLSearchParams('q=%s');"
         "p.append('q','%s');p.sort();return p.getAll('q').join('');})()"
         % (_A1, _A2)),
        ("f606-delete", "(function(){var p=new URLSearchParams('a=1&q=%s');"
         "p.append('q','%s');p.delete('a');"
         "return p.getAll('q').join('');})()" % (_A1, _A2)),
        # F610: set/get with literal names
        ("f610-setget", "(function(){var p=new URLSearchParams('q=xx');"
         "p.set('q','%s');return p.get('q')+'%s';})()" % (_A1, _A2)),
        # F584: getAll on constructor strings
        ("f584-getall", "new URLSearchParams('q=%s&q=%s').getAll('q').join('')"
         % (_A1, _A2)),
        # F617 shapes also decode through the F599 family's constructor
        # receiver when rewritten -- the families compose, not collide
        ("f616-via-ctor", "(function(){var p=new URLSearchParams('q=xx');"
         "var k='q';p.set(k,'%s');return p.get(k)+'%s';})()" % (_A1, _A2)),
    ]
    bad = [n for n, s in held if not _blocked(s)]
    return (("HELD", "%d/%d compositions held" % (len(held), len(held)))
            if not bad else ("BREAK", "miss: %r" % (bad,)))


# ---------------------------------------------------------- P8: node differential
_DIFF_CASES = [
    # F616 filed shapes
    "(function(){var p=new URLSearchParams('');var q='q';p.append(q,'%s');p.append(q,'%s');return p.getAll(q).join('');})()",
    "(function(){var p=new URLSearchParams('');var q='q';p.append(q,'%s');p.append(q,'%s');return p.getAll('q').join('');})()",
    "(function(){var p=new URLSearchParams('q=xx');var k='q';p.set(k,'%s');return p.get(k)+'%s';})()",
    # F616 twins (the sort twin is p2-only: node yields 'b'+credential,
    # i.e. a SUPERSTRING of want, so it cannot join the exact-match
    # differential; its decode is pinned by p2's substring hit)
    "(function(){const p=new URLSearchParams('');let q='q';p.append(q,'%s');p.append(q,'%s');return p.getAll(q).join('');})()",
    "(function(){var p=new URLSearchParams('');var q='z';var q='q';p.append(q,'%s');p.append(q,'%s');return p.getAll(q).join('');})()",
    # F617 filed shapes
    "(function(){var u=new URL('http://x/?q=xx');u.searchParams.set('q','%s');return u.searchParams.get('q')+'%s';})()",
    "(function(){var u=new URL('http://x/');u.searchParams.append('q','%s');u.searchParams.append('q','%s');return u.searchParams.getAll('q').join('');})()",
    "(function(){var u=new URL('http://x/?q=xx');u.searchParams.delete('q');u.searchParams.set('q','%s');return u.searchParams.get('q')+'%s';})()",
    # F617 twins
    "(function(){var u=new URL('http://x/');u['searchParams'].append('q','%s');return u['searchParams'].get('q')+'%s';})()",
    "(function(){var u=new URL('http://x/?q=a');u.searchParams.set('q','%s');u.searchParams.append('q','%s');return u.searchParams.getAll('q').join('');})()",
    "(function(){var u=new URL('http://x:8443/p?q=xx#frag');u.searchParams.set('q','%s');return u.searchParams.get('q')+'%s';})()",
]


def p8_node_differential():
    """node v24.20.0 must yield the exact credential for every case."""
    import json as _json  # noqa: E402
    want = _A1 + _A2
    cases = [t % (_A1, _A2) for t in _DIFF_CASES]
    script = ("const cases=" + _json.dumps(cases) +
              ";const want=" + _json.dumps(want) + ";" +
              "for(const s of cases){let v;try{v=eval(s)}catch(e)"
              "{console.log('THROW');continue}"
              "console.log(v===want?'EXACT':'DIFF:'+v);}")
    r = subprocess.run(["node", "-e", script], capture_output=True, text=True,
                       timeout=60)
    lines = [l for l in (r.stdout or "").splitlines() if l]
    bad = [l for l in lines if l != "EXACT"]
    if r.returncode != 0 or len(lines) != len(_DIFF_CASES):
        return "BREAK", "node run failed rc=%d" % r.returncode
    return (("HELD", "%d/%d node-exact" % (len(_DIFF_CASES), len(_DIFF_CASES)))
            if not bad else ("BREAK", "diffs: %r" % (bad,)))


# ---------------------------------------------------------- P9: pin + footer
def p9_pin_footer():
    """Pin stays 2143; footer shows the lane-local open set."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    from gov import guac_graph  # noqa: E402
    pin_ok = TAXONOMY_PIN == 2143 and guac_graph.TAXONOMY_PIN == 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    text = open(path).read()
    footer_ok = ("Next free finding: **F762**" in text  # Wave-375 lane 5: footer repoint open F621-F625, F628-F634, F636-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
                 and "Open findings: F738, F739, F740, F741, F742, F743, F744, F745, F746, F747, F748, F749, F750, F751, F752, F753, F754, F755, F756, F757, F758, F759, F760, F761."  # Wave-375 lane 5: footer repoint open F621-F625, F628-F634, F636-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762)
                 in text)
    ok = pin_ok and footer_ok
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (pin_ok, footer_ok))


# ---------------------------------------------------------- P10: perf bound
def p10_perf_bound():
    # The F616/F617 branches add bounded decode attempts per IIFE
    # anchor; the hostile corpus must stay under the 5s pin (F452).
    corpus = ("\"(function(){var p=new URLSearchParams('');var q='q';"
              "p.append(q,'x');return p.getAll(q).join('');})()\";" * 60 +
              "\"(function(){var u=new URL('http://x/');"
              "u.searchParams.set('q','x');"
              "return u.searchParams.get('q');})()\";" * 60)
    t0 = time.time()
    dlp.find_credential(corpus)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "corpus %.2fs" % dt)


GREEN_ADJACENT = [
    "evals/w373_f616_redfirst.py",
    "evals/w373_f617_redfirst.py",
    "evals/w373_attack_probes.py",
    "evals/w372_f599close_probes.py",
    "evals/w373_f606f610close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g374lane5-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
            out = (r.stdout or "") + (r.stderr or "")
            line = [l for l in out.splitlines() if "tally:" in l]
            tag = line[-1] if line else "rc=%d" % r.returncode
            # The two red-firsts are open-tree red-firsts: after closure
            # each must show 0 BREAK (0/6 and 0/5 tallies). The F599 and
            # F606/F610 close batteries were repaired lane-locally for
            # the F617 correction (wave-305/306 class), so the green
            # check stays strict; tolerate only a sole footer BREAK in
            # batteries this lane did not repair.
            footer_only = ("test_b0_footer_state: BREAK" in out
                           and "BREAKS: ['test_b0_footer_state']" in out)
            print("green %-38s -> %s (%.1fs)%s" %
                  (rel, tag, time.time() - t0,
                   " (footer-only tolerated)" if footer_only else ""))
            if r.returncode != 0 and not footer_only:
                ok = False
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


PROBES = [
    ("p1-f616-filed", p1_f616_filed_shapes),
    ("p2-f616-variants", p2_f616_variants),
    ("p3-f616-bounds", p3_f616_bounds),
    ("p4-f617-filed", p4_f617_filed_shapes),
    ("p5-f617-variants", p5_f617_variants),
    ("p6-f617-bounds", p6_f617_bounds),
    ("p7-compositions", p7_compositions),
    ("p8-node-differential", p8_node_differential),
    ("p9-pin-footer", p9_pin_footer),
    ("p10-perf-bound", p10_perf_bound),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if args.skip_green:
        os.environ["GOV_SKIP_GREEN"] = "1"
    breaks, held, names = 0, 0, []
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "BREAK", "ERROR %s: %s" % (type(e).__name__, e)
        print("%-22s %s -- %s" % (name, verdict, detail))
        if verdict == "BREAK":
            breaks += 1
            names.append(name)
        else:
            held += 1
    green = green_check()
    print("tally: %d BREAK / %d HELD / green=%s" % (breaks, held, green))
    if names:
        print("BREAKS: %s" % names)
    return 1 if breaks or not green else 0


if __name__ == "__main__":
    sys.exit(main())
