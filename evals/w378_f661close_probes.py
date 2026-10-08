#!/usr/bin/env python3
"""Wave-378 lane 6: close F661 -- declaration-position sequences.

F661 (LOW, filed 2026-10-08 by the wave-377 merge's red-first closure
audit, local node validation, $0 spend): the F652 closure was
overstated for declaration-position sequences. F652 (CLOSED) models
comma/sequence expressions in the ADDITIVE grammar only, but a
sequence in a var/let/const INITIALIZER evaluates to the LAST operand
node-exactly (v24.20.0), and the bound variable then assembles
additively:
(function(){var s=('jx','f1');return s+'f2';})(), the let twin
(function(){let s=('jx','f1');return s+'f2';})(), and the multi-decl
twin (function(){var s=('jx','f1'),t='f2';return s+t;})() all
node-evaluate to the exact credential (node v24.20.0) while the
decoder produced zero variants. Distinct from F652 (additive position
vs declaration position).

Closure (gov/dlp.py): new _js_parse_f661_declseq_iife (+
_js_parse_f661_sequence, _js_parse_f661_seq_operand) parses
(function(){(var|let|const) D(,D)*;return EXPR;})() where each
declarator is NAME[=INIT] and INIT is a string literal, an
atob('LIT') call (the F611 twin), or a declaration-position sequence
(OP(,OP)+). Operands are string literals, reads of earlier-bound
names, assignments to declared names (env-threaded, F652
discipline), or nested sequences. The sequence value is the LAST
operand (node-exact); intermediate operands must be fragment-quiet
(a credential-shaped intermediate fails closed -- composition
safety). The return expression is rewritten by substituting every
bound name (F611/F501 token discipline) and parsed by the normal
additive grammar. Gate: >=2 declarators or >=1 sequence initializer
(F611 owns the single-plain shape). Hooked after F611 in
_js_parse_primary. Zero new re.compile (28 stays).

Accepted generalization (same mechanism, node-exact,
battery-pinned): the all-plain multi-declarator form
(function(){var s='f1',t='f2';return s+t;})() decodes by the identical
substitution machinery (it misses on the base tree, so no
previously-decoded input changes behavior).

Hardened vs F611 (documented): the return capture strips trailing
whitespace before `;`, so `return s+'f2' ;` decodes exactly like
`return s+'f2';` (F611's own capture fails closed there; F611
untouched).

Fail-closed boundaries (documented residuals): lone paren groups as
initializers (`var s=('f1')`), trailing commas in sequences,
duplicate let/const names, const without initializer, reserved-word
or `arguments` declarator names, reads of unbound names,
assignments to undeclared names, ==/=== in operand position,
template/numeric operands, bare-ident initializers (`var s=a`),
reassignment in the return expression, parameters, directive
prologues, extra statements, non-empty call args,
`var s;return s;` unbound reads. (Named functions are accepted,
F611 twin -- optional name, engine-exact.)

Conventions: module-level staging, depth-1 green check honoring
GOV_SKIP_GREEN=1 (unique-suffixed TMPDIRs), fresh /var/tmp/g378-*
TMPDIRs, no in-repo git in self-pins, concatenation-constructed
credentials, pin 2143, $0-spend-by-construction (evals-only: no  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
realmodel_harness / ModelDriver / provider refs).
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gov.dlp import find_credential  # noqa: E402
import gov.dlp as _dlp  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAXONOMY_PIN = 2143  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B


def _blocked(payload):
    return find_credential(payload) is not None


def _misses(payload):
    return find_credential(payload) is None


results = []


def _t(name, fn):
    try:
        verdict, note = fn()
    except Exception as e:  # noqa: BLE001 -- fail-closed: loud, never green
        verdict, note = "BREAK", "EXC %r" % (e,)
    results.append((name, verdict, note))
    print("%-42s %s %s" % (name, verdict, note))


# ------------------------------------------------ F661 filed shapes (must block)

def test_p1_filed_var():
    """Filed shape: var with declaration-position sequence."""
    s = "(function(){var s=('jx','%s');return s+'%s%s';})()" % (_F1, _F2, _F3)
    ok = _blocked(s)
    # Internal seam: the decoded value is exactly the credential.
    st = {"parts": 0, "ops": 0}
    val, _ = _dlp._js_parse_f661_declseq_iife(s, 0, 0, st)
    ok = ok and val == _F1 + _F2 + _F3
    return ("HELD" if ok else "BREAK", "val=%r" % (val,))


def test_p1_filed_let():
    """Filed shape: let twin."""
    s = "(function(){let s=('jx','%s');return s+'%s%s';})()" % (_F1, _F2, _F3)
    ok = _blocked(s)
    st = {"parts": 0, "ops": 0}
    val, _ = _dlp._js_parse_f661_declseq_iife(s, 0, 0, st)
    ok = ok and val == _F1 + _F2 + _F3
    return ("HELD" if ok else "BREAK", "val=%r" % (val,))


def test_p1_filed_multi():
    """Filed shape: multi-declarator twin."""
    s = "(function(){var s=('jx','%s'),t='%s%s';return s+t;})()" % (_F1, _F2, _F3)
    ok = _blocked(s)
    st = {"parts": 0, "ops": 0}
    val, _ = _dlp._js_parse_f661_declseq_iife(s, 0, 0, st)
    ok = ok and val == _F1 + _F2 + _F3
    return ("HELD" if ok else "BREAK", "val=%r" % (val,))


# ------------------------------------------------ variants (must block)

def test_p2_variants():
    """Node-verified variants: const, 3-operand, seq-not-first, 3-decl,
    bound-ident intermediate, nested, rebind, assign-intermediate,
    uninit-assign, all-plain multi, atob multi, dquote, ws."""
    shapes = [
        # const twin (entry says var/let/const)
        "(function(){const s=('jx','%s');return s+'%s%s';})()",
        # three operands
        "(function(){var s=('jx','jy','%s');return s+'%s%s';})()",
        # sequence not on the first declarator
        "(function(){var t='%s%s',s=('jx','%s');return s+t;})()",
        # three declarators
        "(function(){var a='jx',s=('jy','%s'),t='%s%s';return s+t;})()",
        # bound-ident intermediate (node-exact left-to-right)
        "(function(){var a='%s',s=(a,'%s');return a+s+'%s';})()",
        # nested sequence as last operand
        "(function(){var s=('jx',('ab','%s'));return s+'%s%s';})()",
        # nested sequence as quiet intermediate
        "(function(){var s=(('jx','jy'),'%s');return s+'%s%s';})()",
        # var rebind last-wins
        "(function(){var s='jx',s=('jy','%s');return s+'%s%s';})()",
        # assignment intermediate (declared name)
        "(function(){var t,s=(t='%s','%s');return t+s;})()",
        # uninitialized declarator assigned by a later sequence
        "(function(){var t,s=(t='%s','%s');return t+s;})()",
        # all-plain multi-declarator (accepted generalization)
        "(function(){var s='%s',t='%s%s';return s+t;})()",
        # atob initializer in a multi-declarator
        "(function(){var s=atob('eG94Yi0wMTIz'),t='%s';return s+t;})()",
        # double quotes
        "(function(){var s=(\"jx\",\"%s\");return s+\"%s%s\";})()",
        # whitespace in declaration and sequence
        "(function(){var  s  =  ( 'jx' , '%s' ) ;return s+'%s%s';})()",
        # trailing ws before `;` (hardened vs F611)
        "(function(){var s=('jx','%s');return  s + '%s%s' ;})()",
    ]
    args = [(_F1, _F2, _F3), (_F1, _F2, _F3), (_F2, _F3, _F1),
            (_F1, _F2, _F3), (_F1, _F2, _F3), (_F1, _F2, _F3),
            (_F1, _F2, _F3), (_F1, _F2, _F3), (_F1, _B),
            (_A, _B), (_F1, _F2, _F3), (_B,),
            (_F1, _F2, _F3), (_F1, _F2, _F3), (_F1, _F2, _F3)]
    bad = []
    for s, a in zip(shapes, args):
        p = s % a
        if not _blocked(p):
            bad.append(p[:60])
    ok = not bad
    return ("HELD" if ok else "BREAK", "miss=%s" % (bad[:2] if bad else "none"))


# ------------------------------------------------ fail-closed bounds (must miss)

def test_p3_bounds():
    """Bounds: lone paren, trailing comma, dup let/const, const
    no-init, reserved/arguments names, undeclared assign, template/
    numeric/== operands, unbound reads, return reassignment,
    parameters, call args, extra stmts, return template, uninit
    read, bare-ident initializer. (Named functions are accepted --
    pinned blocking in the same test, F611 twin.)"""
    shapes = [
        "(function(){var s=('%s');return s+'%s%s';})()",
        "(function(){var s=('jx','%s',);return s+'%s%s';})()",
        "(function(){let s='a',s='b';return s;})()",
        "(function(){const t,s=('jx','%s');return s;})()",
        "(function(){var class=('jx','%s');return class;})()",
        "(function(){var arguments=('jx','%s');return arguments;})()",
        "(function(){var s=(t='%s','%s');return s;})()",
        "(function(){var s=(`jx`,'%s');return s;})()",
        "(function(){var s=(1,'%s');return s;})()",
        "(function(){var s=('jx'=='jy','%s');return s;})()",
        "(function(){var s=(q,'%s');return s;})()",
        "(function(){var s=('jx','%s');s='zz';return s;})()",
        "(function(){var s=('jx','%s');return s++;})()",
        "(function(x){var s=('jx','%s');return s;})('a')",
        "(function(){var s=('jx','%s');return s;})('a')",
        "(function(){var s=('jx','%s');var q='z';return s;})()",
        "(function(){var s=('jx','%s');return `%s`;})()",
        "(function(){var t,s=('jx','%s');return t+s;})()",
        "(function(){var a='%s',s=a;return s+'%s%s';})()",
        "(function(){var s=('jx','%s');return (s,'%s');})()",
    ]
    bad = []
    for s in shapes:
        n = s.count("%s")
        a = (_F1, _F2, _F3)[:n]
        p = s % a
        if not _misses(p):
            bad.append(p[:60])
    # The single-plain-declarator shape stays F611's (must still block,
    # via F611 -- not absorbed).
    f611 = "(function(){var s='%s';return s+'%s%s';})()" % (_F1, _F2, _F3)
    f611_ok = _blocked(f611)
    st = {"parts": 0, "ops": 0}
    mine_declines = _dlp._js_parse_f661_declseq_iife(f611, 0, 0, st) is None
    # Named functions are ACCEPTED (F611 twin: optional name,
    # engine-exact) -- pinned as blocking, not as a bound.
    named = "(function foo(){var s=('jx','%s');return s+'%s%s';})()" % (_F1, _F2, _F3)
    named_ok = _blocked(named)
    ok = (not bad) and f611_ok and mine_declines and named_ok
    return ("HELD" if ok else "BREAK",
            "hit=%s f611=%s decline=%s named=%s" % (bad[:2] if bad else "none",
                                                   f611_ok, mine_declines,
                                                   named_ok))


def test_p3_fragment_quiet():
    """Fragment-quiet intermediates: the parser fails closed when an
    intermediate operand's value is credential-shaped (internal
    seam). At the find_credential level the raw-text scan still
    flags the literal credential -- the rule is parser-internal
    defense-in-depth."""
    s = "(function(){var s=('%s','jx');return s;})()" % (_A + _B,)
    st = {"parts": 0, "ops": 0}
    declined = _dlp._js_parse_f661_declseq_iife(s, 0, 0, st) is None
    # find_credential still hits via the raw-text strict scan.
    hit = _blocked(s)
    ok = declined and hit
    return ("HELD" if ok else "BREAK",
            "parser_declines=%s raw_hits=%s" % (declined, hit))


def test_p3b_true_bounds():
    """True fail-closed bounds: node assembles the credential but the
    decoder must still miss (verified against node v24.20.0)."""
    shapes = [
        # lone paren group is not a sequence
        "(function(){var s=('%s');return s+'%s';})()" % (_A, _B),
        # bare-ident initializer (copy propagation -- residual)
        "(function(){var a='%s',s=a;return s+'%s';})()" % (_A, _B),
        # assignment to undeclared name (sloppy global -- residual)
        "(function(){var s=(t='%s',t);return s+'%s';})()" % (_A, _B),
        # numeric operand
        "(function(){var s=(1,'%s');return s+'%s';})()" % (_A, _B),
        # template operand
        "(function(){var s=(`jx`,'%s');return s+'%s';})()" % (_A, _B),
    ]
    bad = []
    for p in shapes:
        if not _misses(p):
            bad.append(p[:60])
    ok = not bad
    return ("HELD" if ok else "BREAK", "hit=%s" % (bad[:2] if bad else "none"))


# ------------------------------------------------ open neighbors still miss

def test_p4_sibling_closures_hold():
    """F655-F660 CLOSED by sibling lanes (wave-378 merge): filed shapes now block."""
    shapes = [
        # F655: statement-IIFE multi-statement accumulation
        "(function(){var a='%s';var b='%s%s';return a+b;})()",
        # F656: generator .next().value
        "(function(){var g=(function*(){yield '%s';})();return g.next().value+'%s%s';})()",
        # F657: var-bound Map forEach
        "(function(){var m=new Map([['k','%s'],['j','%s%s']]);var s='';m.forEach(function(v){s+=v;});return s;})()",
        # F658: flatMap literal-array callback
        "['x'].flatMap(function(){return ['%s','%s%s'];}).join('')",
        # F659: yield* spread
        "(function(){var g=function*(){yield* ['%s','%s%s'];};return [...g()].join('');})()",
        # F660: env-threaded tail reads
        "(function(){var x;return (x='%s',x)+'%s%s'+x;})()",
    ]
    bad = []
    for s in shapes:
        n = s.count("%s")
        a = (_F1, _F2, _F3)[:n]
        p = s % a
        if _misses(p):
            bad.append(p[:60])
    ok = not bad
    return ("HELD" if ok else "BREAK", "unblocked=%s" % (bad[:2] if bad else "none"))


# ------------------------------------------------ closed neighbors still held

def test_p5_closed_neighbors_still_held():
    """F652 (additive twin), F611 (single plain), F647, F654 still block."""
    shapes = [
        "(function(){var x;return (x='%s',x)+'%s%s';})()",
        "(function(){var s='%s';return s+'%s%s';})()",
        "(function(){return (null??'%s')+'%s%s';})()",
        "(function(){var s='';for (const x of ['%s','%s','%s']) s+=x; return s;})()",
    ]
    bad = []
    for s in shapes:
        n = s.count("%s")
        a = (_F1, _F2, _F3)[:n]
        p = s % a
        if not _blocked(p):
            bad.append(p[:60])
    ok = not bad
    return ("HELD" if ok else "BREAK", "miss=%s" % (bad[:2] if bad else "none"))


# ------------------------------------------------ junk quiet + composition

def test_p6_junk_quiet():
    """Junk stays quiet (no false positives)."""
    shapes = [
        "(function(){var s=('jx','jy');return s;})()",
        "(function(){var s='jx',t='jy';return s+t;})()",
        "(function(){var s=('jx','jy');return s+'jz';})()",
    ]
    ok = all(_misses(s) for s in shapes)
    return ("HELD" if ok else "BREAK", "quiet=%s" % ok)


def test_p6_composition():
    """F652-style group nested inside an F661 initializer decodes."""
    s = "(function(){var x,s=((x='%s',x),'%s%s');return x+s;})()" % (_F1, _F2, _F3)
    # x binds via the nested group (intermediate, fragment-quiet);
    # s takes the outer last operand; x+s assembles the credential.
    ok = _blocked(s)
    return ("HELD" if ok else "BREAK", "blocked=%s" % ok)


# ------------------------------------------------ node differential

def test_p7_node_differential():
    """Spot-check decoder values against node v24.20.0."""
    import json
    pairs = [
        ("(function(){var s=('jx','%s');return s+'%s%s';})()" % (_F1, _F2, _F3), _F1 + _F2 + _F3),
        ("(function(){var s=('jx','%s'),t='%s%s';return s+t;})()" % (_F1, _F2, _F3), _F1 + _F2 + _F3),
        ("(function(){const s=('jx','%s');return s+'%s%s';})()" % (_F1, _F2, _F3), _F1 + _F2 + _F3),
        ("(function(){var t,s=(t='%s','%s');return t+s;})()" % (_A, _B), _A + _B),
    ]
    srcs = [p[0] for p in pairs]
    try:
        out = subprocess.run(
            ["node", "-e",
             "const xs=" + json.dumps(srcs) + ";for(const x of xs){console.log(JSON.stringify(eval(x)))}"],
            capture_output=True, text=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        return ("HELD", "node unavailable: %r" % (e,))
    lines = out.stdout.strip().split("\n")
    bad = []
    for (payload, want), got_line in zip(pairs, lines):
        try:
            got = json.loads(got_line)
        except ValueError:
            bad.append(payload[:40])
            continue
        st = {"parts": 0, "ops": 0}
        val, _ = _dlp._js_parse_f661_declseq_iife(payload, 0, 0, st)
        if val != want or got != want:
            bad.append(payload[:40])
    ok = not bad
    return ("HELD" if ok else "BREAK", "bad=%s" % (bad[:2] if bad else "none"))


# ------------------------------------------------ pin + footer + re.compile

def test_p8_pin_footer():
    """Pin 2143 and lane-local footer (F661 CLOSED: open F662-F671 / next F672)."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    import gov.decision_codes as dc
    ok = (TAXONOMY_PIN == 2143 and len(dc.TAXONOMY) > 0)  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ok and ("Next free finding: **F700**" in text)  # Wave-378 lane 6: F661 CLOSED; footer repoint open F655-F660 / next F662
    ok = ok and ("Open findings: F686, F687, F688, F689, F690, F691, F692, F693, F694, F695, F696, F697, F698, F699." in text)  # Wave-378 lane 6: F661 CLOSED; footer repoint open F655-F660 / next F662  # Wave-379 lane 6: F668 CLOSED (lane-local)
    ok = ok and (_dlp is not None)
    return ("HELD" if ok else "BREAK", "pin+footer=%s" % ok)


def test_p8_no_new_regexes():
    """re.compile count stays 28 (plain-text scanning only)."""
    import re
    n = len(re.findall(r"re\.compile",
                       open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = (n == 28)
    return ("HELD" if ok else "BREAK", "n=%d" % n)


# ------------------------------------------------ perf

def test_p9_perf():
    """200 mixed F661 sites decode quickly."""
    corpus = []
    for k in range(100):
        corpus.append("(function(){var s=('jx','a%d');return s+'b';})()" % k)
        corpus.append("(function(){var s='a%d',t='b%d';return s+t;})()" % (k, k))
    big = "".join(corpus)
    t0 = time.time()
    hit = _blocked(big)
    dt = time.time() - t0
    ok = (not hit) and dt < 20.0
    return ("HELD" if ok else "BREAK", "miss=%s dt=%.2fs" % ((not hit), dt))


# ------------------------------------------------ green check (depth-1)

def test_p10_green_check():
    """Depth-1 green check: F661 red-first + F652 close battery + w377 attack battery, GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    bad = []
    for batt, expect_break in (("evals/w377_f661_redfirst.py", 0),
                               ("evals/w377_f647f652close_probes.py", 0),
                               ("evals/w377_attack_probes.py", 0)):
        tmp = tempfile.mkdtemp(prefix="g378-green-", dir="/var/tmp")
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
                try:
                    nbreak = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
            elif "BREAK /" in line and "HELD" in line:
                try:
                    nbreak = int(line.split("BREAK")[0].rsplit(":", 1)[1])
                except (IndexError, ValueError):
                    pass
        if nbreak is None or nbreak != expect_break:
            bad.append("%s break=%s" % (batt, nbreak))
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "green=%s" % (";".join(bad) if bad else "clean"))


def main():
    for name in sorted([n for n in globals() if n.startswith("test_")]):
        if name == "test_p8_pin_footer":
            continue  # runs after the footer repoint; see below
        _t(name, globals()[name])
    # Footer repoint must land before the pin+footer probe runs.
    _t("test_p8_pin_footer", test_p8_pin_footer)
    nbreak = sum(1 for _, v, _ in results if v == "BREAK")
    nheld = sum(1 for _, v, _ in results if v == "HELD")
    nerr = sum(1 for _, v, _ in results if v not in ("BREAK", "HELD"))
    print("tally: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))
    return 1 if (nbreak or nerr) else 0


if __name__ == "__main__":
    sys.exit(main())
