#!/usr/bin/env python3
"""Codemod: migrate eval batteries to the canonical probe-line form.

See evals/SUMMARY_FORM_MIGRATION.md for the spec.

CANONICAL CONSOLIDATED COPY (wave-312 lane B). This is the reference
tooling set for all future summary-form migration waves. Provenance:
  - wave-309 lane F: original codemod; _summary_print_span paren-aware
    fix (iterate ALL summary-pattern matches, take the first that is
    actually a print( statement).
  - wave-310 lane D: generalized S2 loop pattern (LOOP_S2_GEN_RE:
    any (pid, verdict, note) loop vars over {_results,_RESULTS,results},
    canonical (verdict, pid, note) print args, optional
    `if <verdict> != "HELD":` guard, note wrapped in .split("\n")[0] or
    .splitlines()[0]); summary-count variable names extracted from the
    summary's % (...) tuple for the coherence snippet (refuses when
    unextractable).
  - wave-311 lane B: list-name-aware coherence snippet (captures the
    matched loop list name via lst_name_holder; was hardcoded
    _results, NameError'd on _RESULTS loops); driver summary_counts
    regex allows spaced name prefixes.
  - wave-312 lane B: canonical consolidation (no behavioral change);
    S3 generalization (LOOP_S3_GEN_RE over rarer columnar widths,
    var-name-aware coherence for S3); extended import anchors for old
    batteries (TREE-anchor extension).

Usage:
    codemod_summary_form.py --check evals/w297_supervision_probes.py
        Classify the battery's probe-line shape (S1..S5); no changes.
    codemod_summary_form.py --migrate evals/w297_supervision_probes.py
        Apply the mechanical migration (S2/S3/S4 with the standard
        _results structure only). Refuses anything it does not
        recognise exactly.

The migration:
  1. inserts `import probe_lines` after the evals sys.path import block,
  2. replaces the probe print loop with `probe_lines.emit(_results)`,
  3. inserts the advisory coherence check after the summary counts are
     computed.

It never touches probe logic, verdicts, counts, or exit codes: verify
with `git diff` (only print-loop + import lines may move) and by
before/after runs (summary line and rc byte-identical).
"""

import re
import sys

# --- shape classifiers -------------------------------------------------

# Canonical: [VERDICT] pid: note at line start (no indent).
S1_RE = re.compile(r'print\("\[%s\] %s: %s"')
# Indented canonical: two-space indent.
S2_RE = re.compile(r'print\("  \[%s\] %s: %s"')
# Columnar: pid VERDICT note, %-width fields, no brackets.
S3_RES = [
    re.compile(r'print\("%-34s %-6s %s"'),
    re.compile(r'print\("%-42s %s %s"'),
    re.compile(r'print\("%-48s %s  %s"'),
    re.compile(r'print\("%-62s %s  %s"'),
    re.compile(r'print\("%-\*s %s  %s"'),
    re.compile(r'print\("%-32s %s %s"'),
]
# Conditional policy: probe lines printed only for non-HELD verdicts.
S4_RE = re.compile(r'if\s+v(?:erdict)?\s*!=\s*"HELD"\s*:')

SUMMARY_RE = re.compile(r'%d BREAK / %d HELD / %d ERROR')
# Wave-312: HELD-first summary order (w281_f307, w275_egress_close,
# w215_identity_policy, ...).
SUMMARY_RE_HBE = re.compile(r'%d HELD / %d BREAK / %d ERROR')


def classify(path):
    """Return (shape, details) for a battery file."""
    src = open(path).read()
    has_summary = bool(SUMMARY_RE.search(src) or SUMMARY_RE_HBE.search(src))
    s1 = bool(S1_RE.search(src))
    s2 = bool(S2_RE.search(src))
    s3 = any(r.search(src) for r in S3_RES)
    s4 = bool(S4_RE.search(src))
    bracket = s1 or s2
    if s1 and not s4:
        return "S1", "canonical already"
    if s2 and not s1:
        return ("S2+S4" if s4 else "S2",
                "indented canonical" + (", non-HELD-only policy" if s4 else ""))
    if s1 and s4:
        return "S1+S4", "canonical format, non-HELD-only policy"
    if s3:
        return "S3", "columnar pid/VERDICT/note, no brackets"
    if has_summary and not bracket:
        return "S5", "summary present, no bracketed probe lines"
    if not has_summary:
        return "S5", "no standard summary line"
    return "S5", "unrecognised probe-line idiom"


# --- migration ---------------------------------------------------------

IMPORT_ANCHOR_RE = re.compile(r'^import green_check.*$', re.M)
SYS_PATH_RE = re.compile(r'^sys\.path\.insert\(0, os\.path\.join\(REPO, "evals"\)\)$',
                         re.M)

# w297-style: indented print, conditional on non-HELD.
LOOP_S2_COND_RE = re.compile(
    r'    for pid, v, note in _results:\n'
    r'        if v != "HELD":\n'
    r'        +print\("  \[%s\] %s: %s" % \(v, pid, note\.splitlines\(\)\[0\]\)\)\n'
)
# w303_f388-style: columnar print of all probes.
LOOP_S3_ALL_RE = re.compile(
    r'    for pid, verdict, note in _results:\n'
    r'        print\("%-34s %-6s %s" % \(pid, verdict, note\)\)\n'
)

# Generalized S2 (wave-310 lane D extension): print-all (or conditional on
# non-HELD) indented probe lines with (pid, verdict, note) triples in
# canonical arg order. Safe because probe_lines.emit takes (pid, verdict,
# note) triples and first-lines the note — the output is identical modulo
# indentation for single-line notes, and the canonical spec mandates
# first-line notes. Requires: distinct loop vars, print args exactly
# (verdict, pid, note) referencing the loop vars (note may be wrapped in
# .split("\n")[0] or .splitlines()[0], both equivalent to first_line),
# list in {_results, _RESULTS, results}, no truncation or other
# transformation of note.
# The optional `if <verdict> != "HELD":` guard is the S4 policy, which the
# migration intentionally removes (emit prints all probes).
LOOP_S2_GEN_RE = re.compile(
    r'^(?P<indent> *)for (?P<pid>[A-Za-z_]\w*), (?P<verdict>[A-Za-z_]\w*), '
    r'(?P<note>[A-Za-z_]\w*) in (?P<lst>_results|_RESULTS|results|RESULTS):\n'
    r'(?P=indent)    (?:if (?P=verdict) != "HELD":\n(?P=indent)        )?'
    r'print\("  \[%s\] %s: %s" % \((?P=verdict), (?P=pid), (?P=note)'
    r'(?:\.split\("\\n"\)\[0\]|\.splitlines\(\)\[0\])?\)\)\n',
    re.M,
)

# Generalized S3 (wave-312): columnar print-all with any of the known
# columnar widths (the S3_RES classifier set), generalized loop vars over
# {_results,_RESULTS,results,RESULTS}, canonical (pid, verdict, note) arg
# order (pid first for columnar), optional first-line note wrapper
# (equivalent to probe_lines.first_line), optional `%-*s` width arg.
# The optional `if <verdict> != "HELD":` guard is the S4 policy, which
# the migration intentionally removes (emit prints all probes).
_S3_FMTS = (
    r"%-34s %-6s %s",
    r"%-42s %s %s",
    r"%-48s %s  %s",
    r"%-62s %s  %s",
    r"%-\*s %s  %s",
    r"%-32s %s %s",
)
LOOP_S3_GEN_RE = re.compile(
    r'^(?P<indent> *)for (?P<pid>[A-Za-z_]\w*), (?P<verdict>[A-Za-z_]\w*), '
    r'(?P<note>[A-Za-z_]\w*) in (?P<lst>_results|_RESULTS|results|RESULTS):\n'
    r'(?P=indent)    (?:if (?P=verdict) != "HELD":\n(?P=indent)        )?'
    r'print\("(?P<fmt>' + "|".join(_S3_FMTS) + r')" % \((?:[A-Za-z_]\w*, )?'
    r'(?P=pid), (?P=verdict), (?P=note)'
    r'(?:\.split\("\\n"\)\[0\]|\.splitlines\(\)\[0\])?\)\)\n',
    re.M,
)

def _summary_print_span(src):
    """Return (line_start, stmt_end, indent, order) of the summary print.

    The summary print takes three surface forms across batteries:
      print("name: %d BREAK / %d HELD / %d ERROR" % (b, h, e))      (BHE)
      print("%d BREAK / %d HELD / %d ERROR" % (b, h, e))            (BHE)
      print("name: %d HELD / %d BREAK / %d ERROR" % (h, b, e))      (HBE)
    A paren-aware scan finds the statement end in each case. `order`
    is "BHE" or "HBE" so the caller can map the `% (...)` tuple to
    (break, held, err) correctly.

    Wave-309 fix: iterate over ALL regex matches and take the first that
    is actually a print( statement. The old code took the first regex
    match unconditionally, so a battery with an earlier non-print
    occurrence of the summary pattern (e.g. a "%s regressed: %d BREAK
    ..." assertion string) was refused even though its real summary
    print exists. Wave-312: the BREAK-first form is preferred when both
    exist (it is the canonical order).
    """
    for pat, order in ((SUMMARY_RE, "BHE"), (SUMMARY_RE_HBE, "HBE")):
        for m in pat.finditer(src):
            line_start = src.rfind("\n", 0, m.start()) + 1
            _im = re.match(r"[ \t]*", src[line_start:])
            indent = _im.group(0) if _im else ""
            # The anchor must be a real print( statement, not a comment or a
            # format string embedded in other code.
            if not src[line_start + len(indent):].startswith("print("):
                continue
            p = src.find("(", line_start)
            if p < 0:
                continue
            depth, instr, q = 0, False, p
            closed = False
            while q < len(src):
                c = src[q]
                if instr:
                    if c == "\\":
                        q += 2
                        continue
                    if c == '"':
                        instr = False
                else:
                    if c == '"':
                        instr = True
                    elif c == "(":
                        depth += 1
                    elif c == ")":
                        depth -= 1
                        if depth == 0:
                            closed = True
                            break
                q += 1
            if closed:
                return line_start, q + 1, indent, order
    return None


def _hbe_count_vars(stmt):
    """Extract (break, held, err) var names from a HELD-first summary stmt.

    Returns None (refuse) unless the extraction is exact:
    - the three %d conversions for HELD/BREAK/ERROR are the FIRST
      conversions in the format string, so they correspond positionally
      to the tuple's first three elements (a preceding conversion, e.g.
      "RESULT %s: %d HELD ...", would silently misalign the mapping);
    - the tuple's first three elements are plain names (trailing extra
      elements, e.g. a display-only TMPDIR or GAP/SKIP counts, are OK).
    """
    m = re.search(r'%d HELD / %d BREAK / %d ERROR', stmt)
    if not m:
        return None
    head = stmt[:m.start()].replace('%%', '')
    convs = re.findall(
        r'%(?:\([^)]*\))?[+#\- 0]*(?:\d+|\*)?(?:\.\d+)?[diuoxXeEfFgGcrs]',
        head)
    if convs:
        return None
    tm = re.search(r'%\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*,'
                   r'\s*([A-Za-z_]\w*)\s*[,)]', stmt)
    if not tm:
        return None
    h, b, e = tm.groups()
    return (b, h, e)


COHERENCE_SNIPPET_NAMED = (
    '    _coh_ok, _coh_diags = probe_lines.check_coherence(\n'
    '        _results, n_break, n_held, n_err)\n'
    '    if not _coh_ok:\n'
    '        print("coherence-WARNING: %s" % "; ".join(_coh_diags))\n'
)
COHERENCE_SNIPPET_BHE = (
    '    _coh_ok, _coh_diags = probe_lines.check_coherence(\n'
    '        _results, b, h, e)\n'
    '    if not _coh_ok:\n'
    '        print("coherence-WARNING: %s" % "; ".join(_coh_diags))\n'
)


REPO_DEF_RE = re.compile(
    r'^REPO = os\.path\.dirname\(os\.path\.dirname\(os\.path\.abspath\(__file__\)\)\)$',
    re.M)

# Wave-312 TREE-anchor extension: old batteries (w72-w85 era,
# decision_packet/provisioner/token_claims, w215-w287 era) compute the
# tree root as REPO_ROOT (os.path or pathlib flavor) or inline the
# sys.path expression instead of the standard REPO/green_check idioms.
# Each anchor below is an exact line; the insertion only appends the
# evals dir to sys.path (which the battery did not have) and imports
# probe_lines. Anchors are tried after the standard three; a battery
# matching a standard anchor keeps the standard insertion.
TREE_OSPATH_RE = re.compile(
    r'^REPO_ROOT = os\.path\.dirname\(os\.path\.dirname\(os\.path\.abspath\(__file__\)\)\)$',
    re.M)
TREE_PATHLIB_RE = re.compile(
    r'^REPO_ROOT = Path\(__file__\)\.resolve\(\)\.parent\.parent$', re.M)
TREE_INLINE_RE = re.compile(
    r'^sys\.path\.insert\(0, (os\.path\.join\(os\.path\.dirname\(__file__\), "\.\."\)'
    r'|os\.path\.dirname\(os\.path\.dirname\(os\.path\.abspath\(__file__\)\)\))\)$',
    re.M)
TREE_REPO_INSERT_RE = re.compile(r'^sys\.path\.insert\(0, REPO\)$', re.M)

_IMPORT_SUFFIX = ("\nimport probe_lines  # noqa: E402"
                 "  (canonical probe-line form)")


def _has_import(modname, prefix):
    """True if `import <modname>` (or a from-import of it) precedes."""
    return bool(re.search(r'^import %s$' % modname, prefix, re.M)
                or re.search(r'^from %s import ' % modname, prefix, re.M))


def _add_import(src):
    if "import probe_lines" in src:
        return src, False
    # Preferred anchor: the green_check import (batteries already using the
    # shared helper import probe_lines the same way).
    m = IMPORT_ANCHOR_RE.search(src)
    if m:
        return (src[:m.end()] + "\nimport probe_lines  # noqa: E402"
                "  (canonical probe-line form)" + src[m.end():], True)
    # Fallback anchor: the uniform REPO definition. The battery file lives
    # in evals/, so inserting it on sys.path makes `import probe_lines`
    # work whether the battery runs as a script or is imported.
    m = REPO_DEF_RE.search(src)
    if m:
        return (src[:m.end()] +
                "\nsys.path.insert(0, os.path.join(REPO, \"evals\"))"
                "\nimport probe_lines  # noqa: E402"
                "  (canonical probe-line form)" + src[m.end():], True)
    m = SYS_PATH_RE.search(src)
    if m:
        return (src[:m.end()] + "\nimport probe_lines  # noqa: E402"
                "  (canonical probe-line form)" + src[m.end():], True)
    # Wave-312 TREE anchors (see above). Each insertion reuses the
    # battery's own tree-root expression; sys/os/Path availability is
    # verified in the text preceding the anchor, else refuse.
    m = TREE_OSPATH_RE.search(src)
    if m:
        if not _has_import("sys", src[:m.start()]):
            raise SystemExit("codemod: TREE os.path anchor without "
                             "preceding import sys")
        return (src[:m.end()]
                + '\nsys.path.insert(0, os.path.join(REPO_ROOT, "evals"))'
                + _IMPORT_SUFFIX + src[m.end():], True)
    m = TREE_PATHLIB_RE.search(src)
    if m:
        prefix = src[:m.start()]
        if not (_has_import("sys", prefix)
                and _has_import("pathlib", prefix)):
            raise SystemExit("codemod: TREE pathlib anchor without "
                             "preceding import sys/pathlib")
        return (src[:m.end()]
                + '\nsys.path.insert(0, str(REPO_ROOT / "evals"))'
                + _IMPORT_SUFFIX + src[m.end():], True)
    m = TREE_INLINE_RE.search(src)
    if m:
        # The anchor line itself uses sys.path.insert and os.path, so
        # both modules are necessarily imported above it.
        return (src[:m.end()]
                + '\nsys.path.insert(0, os.path.join(%s, "evals"))'
                % m.group(1) + _IMPORT_SUFFIX + src[m.end():], True)
    m = TREE_REPO_INSERT_RE.search(src)
    if m:
        prefix = src[:m.start()]
        if not (_has_import("sys", prefix) and _has_import("os", prefix)):
            raise SystemExit("codemod: TREE REPO-insert anchor without "
                             "preceding import sys/os")
        return (src[:m.end()]
                + '\nsys.path.insert(0, os.path.join(REPO, "evals"))'
                + _IMPORT_SUFFIX + src[m.end():], True)
    raise SystemExit("codemod: no import anchor (green_check import, REPO "
                     "definition, evals sys.path insert, or TREE root) found")


def migrate(path):
    src = open(path).read()
    shape, _ = classify(path)
    if shape not in ("S2", "S2+S4", "S3"):
        raise SystemExit("codemod: refusing to migrate shape %s for %s "
                         "(mechanical migration covers S2/S2+S4/S3 only)"
                         % (shape, path))
    # Every pid must be inside the load-bearing class before migration.
    bad = [p for p in set(re.findall(
        r'\(\s*"([A-Za-z0-9_.\- ]{2,80})"\s*,\s*"(?:BREAK|HELD|ERROR|SKIP)"',
        src)) if not re.fullmatch(r"[A-Za-z0-9_.\-]+", p)]
    if bad:
        raise SystemExit("codemod: nonconforming pids %r -- fix pids first"
                         % (bad,))
    # Wave-312: refuse non-canonical verdicts. probe_lines.emit would
    # print e.g. "[GAP] pid: note", which parse_line cannot parse and
    # which the canonical spec does not define. Mapping GAP/RESIDUAL/
    # BROKEN needs a policy decision, not a codemod. (SKIP is canonical
    # and allowed.)
    bad_v = set(re.findall(
        r',\s*[\'"](GAP|RESIDUAL|BROKEN|PENDING)[\'"]\s*[,)]', src))
    bad_v.update(re.findall(
        r'return\s+[\'"](GAP|RESIDUAL|BROKEN|PENDING)[\'"]\s*,', src))
    if bad_v:
        raise SystemExit("codemod: non-canonical verdicts %r -- needs "
                         "policy decision, not a codemod" % (sorted(bad_v),))

    src, added = _add_import(src)
    coherence = None
    lst_name_holder = []
    if shape in ("S2", "S2+S4"):
        new_loop, n = LOOP_S2_COND_RE.subn(
            "    probe_lines.emit(_results)\n", src, count=1)
        if n != 1:
            # Fall back to the generalized S2 pattern (wave-310): print-all
            # (or conditional) with canonical (pid, verdict, note) triples.
            # The replacement preserves the loop's indentation and list name.
            def _gen_repl(m):
                pid, verdict, note = (m.group("pid"), m.group("verdict"),
                                      m.group("note"))
                if len({pid, verdict, note}) != 3:
                    # Not distinct loop vars -- refuse by returning the
                    # original text unchanged (n will be 0).
                    return m.group(0)
                lst_name_holder.append(m.group("lst"))
                return "%sprobe_lines.emit(%s)\n" % (m.group("indent"),
                                                     m.group("lst"))
            new_loop, n = LOOP_S2_GEN_RE.subn(_gen_repl, src, count=1)
            # subn counts a replacement even if _gen_repl returned the
            # original; verify the text actually changed.
            if new_loop == src:
                n = 0
        if n != 1:
            raise SystemExit("codemod: S2 print loop pattern not found "
                             "exactly once in %s" % path)
        src = new_loop
        coherence = COHERENCE_SNIPPET_NAMED
    elif shape == "S3":
        new_loop, n = LOOP_S3_ALL_RE.subn(
            "    probe_lines.emit(_results)\n", src, count=1)
        if n != 1:
            # Fall back to the generalized S3 pattern (wave-312): any of
            # the known columnar widths, generalized loop vars/lists,
            # canonical (pid, verdict, note) arg order, optional
            # first-line note wrapper. Mirrors the S2 fallback above.
            def _s3_gen_repl(m):
                pid, verdict, note = (m.group("pid"), m.group("verdict"),
                                      m.group("note"))
                if len({pid, verdict, note}) != 3:
                    return m.group(0)
                lst_name_holder.append(m.group("lst"))
                return "%sprobe_lines.emit(%s)\n" % (m.group("indent"),
                                                     m.group("lst"))
            new_loop, n = LOOP_S3_GEN_RE.subn(_s3_gen_repl, src, count=1)
            if new_loop == src:
                n = 0
        if n != 1:
            raise SystemExit("codemod: S3 print loop pattern not found "
                             "exactly once in %s" % path)
        src = new_loop
        coherence = COHERENCE_SNIPPET_BHE

    # Insert the advisory coherence check right after the summary print
    # statement (paren-aware: handles both single-line and split forms,
    # and both BREAK-first and HELD-first summary orders).
    span = _summary_print_span(src)
    if not span:
        raise SystemExit("codemod: summary print anchor not found in %s"
                         % path)
    _line_start, stmt_end, indent, order = span
    # Extract the battery's actual summary-count variable names so the
    # coherence snippet references the right variables (batteries use
    # n_break/n_held/n_err, nbreak/nheld/nerr, b/h/e, held_n/... etc.).
    # Refuse if the names cannot be extracted exactly.
    _stmt = src[_line_start:stmt_end]
    if order == "BHE":
        _cm = re.search(r"%\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*,"
                        r"\s*([A-Za-z_]\w*)\s*\)", _stmt)
        if not _cm:
            raise SystemExit("codemod: summary count variables not found "
                             "in %s" % path)
        _cb, _ch, _ce = _cm.groups()
    else:
        _hbe = _hbe_count_vars(_stmt)
        if not _hbe:
            raise SystemExit("codemod: HELD-first summary count variables "
                             "not extractable exactly in %s" % path)
        _cb, _ch, _ce = _hbe
    # The generalized S2/S3 paths may iterate _RESULTS, results, or
    # RESULTS; the coherence snippet must reference the actual list
    # name, else the migrated battery raises NameError at runtime
    # (wave-311: w294_redteam_probes).
    coh_lst = lst_name_holder[0] if lst_name_holder else "_results"
    if coherence in (COHERENCE_SNIPPET_NAMED, COHERENCE_SNIPPET_BHE):
        coherence = (
            '    _coh_ok, _coh_diags = probe_lines.check_coherence(\n'
            '        %s, %s, %s, %s)\n'
            '    if not _coh_ok:\n'
            '        print("coherence-WARNING: %%s" %% "; ".join(_coh_diags))\n'
        ) % (coh_lst, _cb, _ch, _ce)
    # Rebase the snippet's relative indentation onto the anchor's
    # indent: keep each line's offset from the snippet's own base
    # indent, then prefix the anchor indent.
    _lines = coherence.splitlines(keepends=True)
    _indents = [len(l) - len(l.lstrip()) for l in _lines if l.strip()]
    _base = min(_indents) if _indents else 0
    snippet = "".join(
        (indent + l[_base:] if l.strip() else l) for l in _lines
    )
    src = src[:stmt_end] + "\n" + snippet.rstrip("\n") + src[stmt_end:]
    open(path, "w").write(src)
    return shape


def main(argv):
    if len(argv) != 3 or argv[1] not in ("--check", "--migrate"):
        print(__doc__)
        return 2
    mode, path = argv[1], argv[2]
    if mode == "--check":
        shape, details = classify(path)
        print("%s: %s (%s)" % (path, shape, details))
        return 0
    shape = migrate(path)
    print("%s: migrated (%s)" % (path, shape))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
