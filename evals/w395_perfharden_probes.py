"""Wave-395 lane 5: perf-hardening / second-reviewer audit battery.

Scope (base c7270731f, wave-394 merge):
  A. ReDoS pins: the w344/w345/w347 P5 hostile corpora must stay fast
     and exception-free (no performance drift since their pins).
  B. Budget-interaction (wave-383 class): whole-text hooks added by
     wave-394 charge no shared scan budget (mechanism check), and a
     junk-prefix starvation probe still decodes the real expression
     (symptom check).
  C. Sibling disjointness of the wave-394 hooks (F1005-F1023; F1024 is
     the instruction_provenance.py seam fix, no dlp hook): no filed
     shape decodes through two hooks with different results (filed
     shapes imported from the w394 red-first batteries).
  D. _MAX_CANDIDATES tail guards on every per-wave hook loop
     (wave-379 class) and tail statements in hook-dispatch blocks.

$0 spend by construction. Standalone. Green checks: N/A -- this
battery spawns no subprocesses, so there is nothing to depth-limit.

Section A methodology: the absolute 5s pin threshold is
environment-sensitive (this VM is slower than the pin-recording
environment: the corpora take ~10s here on BOTH the wave-393 base and
this tree). The regression check is RELATIVE: the current tree must
not be slower than the wave-393 base (7a69b6185) measured in the same
run, base timed FIRST (conservative: warmup bias favors the base).
The base tree is loaded from the /var/tmp/g395-basecheck worktree --
created once per lane run via:
  git worktree add /var/tmp/g395-basecheck 7a69b6185
If the worktree is absent (e.g. at merge time), the relative check
records a skip and the no-raise checks stand. The embedded corpus
copies are verified byte-identical against the canonical
p5_redos_pins() sources at runtime (AST-extracted), so hand-copy
drift fails loudly instead of silently testing the wrong inputs.
"""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import ast
import re
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov import dlp

CHECKS = []

# >2x slowdown vs the wave-393 base (same machine, same run) is a
# genuine performance regression; anything less is environmental noise.
RATIO_BAR = 2.0


def _check(name, ok, detail=""):
    CHECKS.append((name, bool(ok), str(detail)))
    return bool(ok)


# ---------------------------------------------------------- A: ReDoS pins
W344_HOSTILE = [
    '"' * 5000,
    '("a" + ' * 2000,
    '"a"' + ' + "a"' * 5000,
    "String.fromCharCode(" + "65," * 5000 + "65)",
    '"a".repeat(' + "9" * 5000 + ")",
    "(" * 5000,
    '"\\' * 5000,
    "`" + "${" * 2000,
    '"a".concat(' * 2000,
    "String.fromCharCode(0x" + "f" * 5000,
    '"a".repeat(' + "9" * 10000 + ")",
]
W345_HOSTILE = [
    "[" * 5000,
    "['a'," * 2000,
    "[" + "['a']," * 2000,
    "['a'].join(" * 1000,
    "['" + "a" * 5000 + "'].join(",
    "[" + "'a'," * 5000 + "]",
    "['a'].join('" + "x" * 5000 + "')",
    "[String.fromCharCode(" + "65," * 5000 + "65)].join('')",
    "[" * 200 + "]" * 200,
    "['a'" + " + 'b'" * 2000 + "].join('')",
]
W347_HOSTILE = [
    "[" * 5000,
    "['a','b'].reduce(" + "(" * 5000,
    "['a','b'].reduce((a,b)=>a+b" + ")" * 5000,
    ".reduce(" * 2000,
    "['a','b'].reduce((a,b)=>a+b)." * 500,
    "['a','b'].reduce(function(a,b){return a+b;" + "}" * 2000,
    "[" + "'x'," * 2000,
    "['a','b'].map(" + "(" * 5000,
    "['a','b'].filter(" + "(" * 5000,
    "['a','b'].reduce((" + "a," * 2000,
    "['a','b'].reduce((a,b)=>" + "a+" * 2000 + "b)",
]
CORPORA = (("w344", "evals/w344_f430close_probes.py", W344_HOSTILE),
           ("w345", "evals/w345_f434close_probes.py", W345_HOSTILE),
           ("w347", "evals/w347_f437close_probes.py", W347_HOSTILE))


def _ast_eval_str(node):
    """Safe evaluator for the corpus expression grammar: string
    literals composed with * (int) and + (str)."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        l, r = _ast_eval_str(node.left), _ast_eval_str(node.right)
        if isinstance(l, str) and isinstance(r, int):
            return l * r
        if isinstance(r, str) and isinstance(l, int):
            return r * l
        raise ValueError("bad mult")
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _ast_eval_str(node.left) + _ast_eval_str(node.right)
    raise ValueError("unsupported node %r" % type(node))


def _canonical_corpus(src_path):
    """AST-extract the hostile list from a p5_redos_pins() battery."""
    with open(os.path.join(REPO_ROOT, src_path)) as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and \
                node.name == "p5_redos_pins":
            for st in ast.walk(node):
                if isinstance(st, ast.Assign):
                    for t in st.targets:
                        if isinstance(t, ast.Name) and t.id == "hostile":
                            return [_ast_eval_str(e) for e in st.value.elts]
    return None


def _time_corpus(find_fn, hostile, tag):
    t0 = time.time()
    ok = True
    for h in hostile:
        try:
            find_fn("token=" + h)
        except Exception as e:  # noqa: BLE001 - must fail closed, never loud
            ok = _check("A-%s no-raise len=%d" % (tag, len(h)), False,
                        type(e).__name__) and ok
    return time.time() - t0, ok


def p5_redos_relative():
    """Relative perf check: current tree vs wave-393 base, base FIRST."""
    ok = True
    # 1. embedded copies must match the canonical pin sources exactly
    for tag, src_path, hostile in CORPORA:
        canon = _canonical_corpus(src_path)
        same = canon is not None and list(canon) == list(hostile)
        ok = _check("A-%s corpus matches pin source" % tag, same,
                    "%s: %d inputs" % (src_path,
                                       len(canon) if canon else -1)) and ok
    # 2. load the base tree (optional worktree; skip gracefully)
    base_path = "/var/tmp/g395-basecheck/gov/dlp.py"
    dlp_base = None
    if os.path.exists(base_path):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dlp_base393", base_path)
        dlp_base = importlib.util.module_from_spec(spec)
        sys.modules["dlp_base393"] = dlp_base
        old_path = list(sys.path)
        sys.path.insert(0, "/var/tmp/g395-basecheck")
        try:
            spec.loader.exec_module(dlp_base)
        finally:
            sys.path[:] = old_path
    # 3. time base first (conservative), then current; compare
    for tag, _src, hostile in CORPORA:
        if dlp_base is None:
            dt_cur, ok_cur = _time_corpus(dlp.find_credential, hostile,
                                          tag + "-cur")
            ok = ok_cur and ok
            _check("A-%s relative skipped (no base worktree)" % tag, True,
                   "cur=%.2fs, no-raise held" % dt_cur)
            continue
        dt_base, ok_base = _time_corpus(dlp_base.find_credential, hostile,
                                        tag + "-base")
        dt_cur, ok_cur = _time_corpus(dlp.find_credential, hostile,
                                      tag + "-cur")
        ok = ok_base and ok_cur and ok
        ratio = dt_cur / dt_base if dt_base > 0 else float("inf")
        ok = _check("A-%s no perf regression vs wave-393 base" % tag,
                    ratio <= RATIO_BAR,
                    "cur=%.2fs base=%.2fs ratio=%.2f (bar %.1f)"
                    % (dt_cur, dt_base, ratio, RATIO_BAR)) and ok
    return ok


# --------------------------------- B: budget-interaction (wave-383 class)
W394_HOOK_FNS = [
    "_js_f1005_stmt_decode", "_js_f1006_stmt_decode",
    "_js_f1007_stmt_decode", "_js_f1008_stmt_decode",
    "_js_f1009_stmt_decode", "_js_f1010_stmt_decode",
    "_js_f1011_stmt_decode", "_js_f1012_stmt_decode",
    "_js_f1013_stmt_decode", "_js_f1014_stmt_decode",
    "_js_f1015_stmt_decode", "_js_f1016_stmt_decode",
    "_js_f1017_stmt_decode", "_js_f1018_stmt_decode",
    "_js_f1019_stmt_decode", "_js_f1020_stmt_decode",
    "_js_f1021_stmt_decode", "_js_f1022_stmt_decode",
    "_js_f1023_stmt_decode",
]
# NOTE: F1024 is the instruction_provenance.py seam fix, not a dlp
# whole-text hook -- excluded from the dlp hook audit by design.


def b_mechanism_no_shared_charging():
    """Mechanism check: no wave-394 hook function (or its helpers)
    charges the SHARED scan budget. Rule per function: any
    `state["parts"|"ops"] +=` must be backed by a `state` that is
    either a parameter (helper, filled by the hook's local dict) or a
    locally-constructed dict -- never a module-global or an outer
    scope. Additionally, every `_stmt_decode` hook itself must be
    state-free at the dispatch level (takes only `text`)."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for n in range(1005, 1024):
        for m in re.finditer(r"def (_js_f%d\w+)\(([^)]*)\):" % n, src):
            name, params = m.group(1), m.group(2)
            start = m.end()
            nxt = src.find("\ndef ", start)
            body = src[start:nxt]
            pnames = [p.strip() for p in params.split(",") if p.strip()]
            takes_state = "state" in pnames
            charges = bool(re.search(
                r'state\["(?:parts|ops)"\]\s*\+=', body))
            local_init = bool(re.search(r'state\s*=\s*\{', body))
            backed = (not charges) or takes_state or local_init
            ok = _check("B mechanism F%d %s charging backed"
                        % (n, name), backed,
                        "takes_state=%s charges=%s local=%s"
                        % (takes_state, charges, local_init)) and ok
            if name.endswith("_stmt_decode"):
                ok = _check("B mechanism F%d %s dispatch state-free"
                            % (n, name), not takes_state,
                            "params=%s" % params) and ok
                # strip the docstring and # comments: prose mentions of
                # "state" (e.g. "statement") are not code references
                code = re.sub(r'"""[\s\S]*?"""', '', body, count=1)
                code = re.sub(r"#[^\n]*", "", code)
                uses_state = "state" in code
                ok = _check("B mechanism F%d %s state is local"
                            % (n, name),
                            (not uses_state) or local_init,
                            "uses_state=%s local=%s"
                            % (uses_state, local_init)) and ok
    return ok


def b_starvation_probe():
    """Symptom check: fail-closed junk statements ahead of a real
    decodable shape. The known-decodable join shape must still block
    after 64 and 200 junk statements (the wave-383 F733 class)."""
    ok = True
    shape = "['xoxb-0123','456789abcdef'].join('')"
    r0 = dlp.find_credential(shape)
    ok = _check("B baseline decodes", r0 is not None, repr(r0)) and ok
    for n in (64, 200):
        junk = "".join('var j%d = "noise%d";\n' % (k, k) for k in range(n))
        r = dlp.find_credential(junk + shape)
        ok = _check("B junk%d-prefix: real still decodes" % n,
                    r is not None, repr(r)) and ok
    return ok


# ------------------- C: sibling disjointness of wave-394 hooks
def c_sibling_disjointness():
    """Each filed F1005-F1023 shape (from the w394 red-first batteries)
    must decode through at most one wave-394 hook with a distinct
    result; identical outputs are benign duplication, differing
    outputs are a genuine break."""
    ok = True
    hooks = [(name, getattr(dlp, name)) for name in W394_HOOK_FNS]
    # F1005-F1023 only: F1024 is the instruction_provenance.py fix and
    # its red-first battery has a different format (no SHAPES list).
    for n in range(1005, 1024):
        mod_path = os.path.join(REPO_ROOT, "evals", "w394_f%d_redfirst.py" % n)
        if not os.path.exists(mod_path):
            ok = _check("C shapes F%d present" % n, False, "missing") and ok
            continue
        g = {"__file__": mod_path, "__name__": "w394_redfirst_shapes"}
        with open(mod_path) as f:
            exec(compile(f.read(), mod_path, "exec"), g)
        shapes = g.get("SHAPES", [])
        if not shapes:
            ok = _check("C shapes F%d nonempty" % n, False, "empty") and ok
            continue
        for sname, shape in shapes:
            decoded = {}
            for hname, hfn in hooks:
                try:
                    r = hfn(shape)
                except Exception:  # noqa: BLE001 - hook must fail closed
                    r = None
                if r is not None:
                    decoded.setdefault(r, []).append(hname)
            if len(decoded) > 1:
                ok = _check("C F%d %s single-decoder" % (n, sname), False,
                            "two hooks differ: %s" % decoded) and ok
        ok = _check("C F%d filed shapes disjoint" % n, True,
                    "%d shapes" % len(shapes)) and ok
    return ok


# ---------------- D: tail guards + tail statements (wave-379 class)
# Pinned count: 31 per-wave _stmtdec loops (wave-398 merge's 21
# + wave-399 lane 1's F1074/F1075 loop + lane 2's F1076/F1077 loop
# + lane 3's F1078/F1080/F1081/F1082 loop + wave-400 lane 1's
# F1083/F1084 loop + lane 2's F1086/F1087/F1088 loop + lane 3's
# F1089 loop + wave-401 lane 1's F1090/F1091/F1097 loop + lane 2's
# F1092/F1093/F1094/F1099 loop + lane 3's F1095/F1096 loop +
# lane 5's F1100/F1101/F1102 loop -- real code-count change,
# wave-385 rule: repoint is justified by the added loops;
# asserted by counting the dispatch loops on the merged tree).
# Wave-402 lane 3: +1 F1110 loop (real code-count change) -> 32.
# Wave-402 merge: +1 F1103/F1104/F1108 loop (lane 1) +1 F1105/F1106/F1107 loop (lane 2) -> 34 (real code-count change, wave-385; asserted by count).
# Wave-403 lane 3: +1 F1117/F1118/F1119 loop (real code-count change) -> 35.
# Wave-403 lane 4: +1 F1121/F1122 loop (real code-count change) -> 35.
# Wave-403 merge: lanes 1-4 loops merged (34 base + 4) -> 38 (real code-count change, wave-385; asserted by count).
# Wave-404 lane 2: +1 F1124-F1130 loop (real code-count change) -> 39.
# Wave-404 lane 3: +1 F1131-F1137 loop (real code-count change) -> 39.
# Wave-404 lane 4: +1 F1138/F1139/F1140/F1141 loop (real code-count change) -> 39.
# Wave-404 merge: lanes 2-4 loops merged (38 base + 3; lane 1 added none) -> 41 (real code-count change, wave-385; asserted by count).
# Wave-405 lane 2: +1 F1147-F1150/F1153-F1155 loop (real code-count change) -> 42.
# Wave-405 merge: lanes 1-2 loops merged (41 base + 2; lanes 3-4 added none) -> 43 (real code-count change, wave-385; asserted by count).
# Wave-406 lane 1: +1 F1159-F1165 loop (real code-count change) -> 44.
# Wave-406 lane 2: +1 F1166-F1173 loop (real code-count change) -> 44.
# Wave-406 lane 3: +1 F1174-F1179 loop (real code-count change) -> 44.
# Wave-406 merge: lanes 1-3 loops merged (43 base + 3) -> 46 (real code-count change, wave-385; asserted by count).
# Wave-407 lanes 1+2+3: 46 + 3 new loops (real code-count change) -> 49.
# Wave-408 lane 1: +1 F1199-F1205 loop (real code-count change) -> 50.
# Wave-408 lane 2: 49 + 1 new loop (real code-count change) -> 50.
# Wave-408 lane 3: 49 + 1 new loop (F1213-F1219 dispatch; real code-count change) -> 50.
# Wave-408 lane 4: +1 F1220-F1228 loop (real code-count change) -> 53.
# Wave-409 lane 1: +1 F1229-F1235 loop (real code-count change) -> 54.
# Wave-409 lane 2: +1 F1236-F1242 loop (real code-count change) -> 54.
# Wave-409 lane 3: +1 F1243-F1249 loop (real code-count change) -> 54.
# Wave-409 lane 4: +1 F1250-F1259 loop (real code-count change) -> 57.
# Wave-409 merge: lanes 1-4 loops merged (53 base + 4) -> 57 (real code-count change, wave-385; asserted by count).
# Wave-410 lane 2: +1 F1267-F1273 loop (real code-count change) -> 58.
# Wave-410 lane 3: +1 F1274-F1280 loop (real code-count change) -> 58.
# Wave-410 merge: lanes 1-3 loops merged (57 base + 3) -> 60 (real code-count change, wave-385; asserted by count).
# Wave-410 lane 4: +1 F1281-F1282 loop (real code-count change) -> 58.
# Wave-410 merge: lanes 1-4 loops merged (57 base + 4) -> 61 (real code-count change, wave-385; asserted by count).
# Wave-411 lane 2: +1 F1296-F1302 loop (real code-count change) -> 62.
# Wave-411 merge: lanes 1-2 loops merged (61 base + 2) -> 63 (real code-count change, wave-385; asserted by count).
# Wave-411 lane 3: +1 F1303-F1308/F1316-F1318 loop (real code-count change) -> 64.
# Wave-411 merge: lanes 1-3 loops merged (61 base + 3) -> 64 (real code-count change, wave-385; asserted by count).
# Wave-411 lane 4: +1 F1319-F1322 loop (real code-count change) -> 65.
# Wave-411 merge: lanes 1-4 loops merged (61 base + 4) -> 65 (real code-count change, wave-385; asserted by count).
# Wave-418 merge: lanes 1-4 loops merged (84 base + 4) -> 88 (real code-count change, wave-385; asserted by count).
# Wave-419 merge: lanes 1-4 loops merged (88 base + 4) -> 92 (real code-count change, wave-385; asserted by count).
# Wave-437 lane A: +1 F1907-F1915 loop (real code-count change).
# Wave-437 lane B: +1 F1916-F1924 dispatch loop (real code-count change).
# Wave-437 lane C: +1 F1925-F1933 loop (real code-count change).
# Wave-437 lane D: +1 F1934-F1942 dispatch loop (real code-count change).
N_STMTDEC_LOOPS = 193  # wave-448 lane A: 192 + 1 (F2455-F2467 dispatch loop, real code-count change, wave-385; asserted by count). 191 (actual at wave-446 base, pin was stale at 189) + 1 (F2381-F2417 lane A dispatch loop, real code-count change, wave-385; asserted by count).

def d_tail_guards():
    """Every per-wave `_stmtdec` dispatch loop in _decode_layer keeps
    its _MAX_CANDIDATES tail guard; every branch of a hook-dispatch
    block ends with its tail statement (no dropped returns)."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = list(re.finditer(r"for _stmtdec in \(([^)]*)\):", body,
                             re.DOTALL))
    ok = _check("D stmtdec loop count pinned", len(loops) == N_STMTDEC_LOOPS,
                "%d loops (pin %d)" % (len(loops), N_STMTDEC_LOOPS)) and ok
    for i, lp in enumerate(loops):
        names = [x.strip() for x in lp.group(1).split(",") if x.strip()]
        tail = body[lp.end():lp.end() + 400]
        guarded = ("len(variants) >= _MAX_CANDIDATES" in tail
                   and "return variants" in tail)
        ok = _check("D loop %d guarded (%d hooks)" % (i, len(names)),
                    guarded, names[0] if names else "?") and ok
    # tail statements: every `if _sdec is not None:` block returns variants
    tails = re.findall(r"if _sdec is not None:\s*\n\s*_add\(_sdec\)\s*\n"
                       r"\s*if len\(variants\) >= _MAX_CANDIDATES:\s*\n"
                       r"\s*return variants", body)
    ok = _check("D tail statements intact", len(tails) == len(loops),
                "%d tails / %d loops" % (len(tails), len(loops))) and ok
    return ok


def main():
    ok = True
    ok = p5_redos_relative() and ok
    ok = b_mechanism_no_shared_charging() and ok
    ok = b_starvation_probe() and ok
    ok = c_sibling_disjointness() and ok
    ok = d_tail_guards() and ok
    bad = [(n, d) for n, p, d in CHECKS if not p]
    print("w395_perfharden_probes: %d/%d HELD" % (len(CHECKS) - len(bad),
                                                  len(CHECKS)))
    for n, d in bad:
        print("  BREAK:", n, d)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
