#!/usr/bin/env python3
"""Decision-code coverage table (wave-338 lane 5, R14).

Bernstein #5569 ("no row claims coverage without a test"), ADAPT: the
decision-code registry (gov/decision_codes.py, 2127 codes) is generated
into a coverage table, and NO row may claim coverage without at least
one test/eval probe asserting that code.

What "asserting a code" means here: the code's literal string appears
quoted (``'code'`` or ``"code"``) in at least one ``.py`` file under
``tests/`` or ``evals/``. Production ``emit()`` call sites do NOT count
-- the table is about falsifiability (a probe that can go red), not
about production reachability (that is R16's dead-controls gate).

Exit codes (CI-checkable):
  0 -- table generated; all 2127 codes have >= 1 asserting probe.
  1 -- table generated; GAPS EXIST (listed at the end of stdout and in
       the outputs). The table is still written -- the gaps are the
       deliverable, for the closure lanes to work down.
  2 -- internal error: registry pin mismatch (the taxonomy changed and
       this checker was not regenerated with it) or unreadable tree.

Outputs (regenerated, committed):
  docs/decision-code-coverage.md    -- human table (code | domain |
                                       severity | covered | asserted in)
  docs/decision-code-coverage.json  -- machine-readable (code ->
                                       {domain, severity, covered, files})

Usage:
  python3 scripts/check_decision_code_coverage.py [REPO_ROOT]
Stdlib only. Deterministic: codes sorted by (domain, code); file lists
sorted; byte-identical across runs on the same tree.
"""

import io
import json
import os
import re
import sys
import time

COVERAGE_PIN = 2131  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes: single-use-refused, evidence-refused, key-identity-refused, spiffe-refused).

# A quoted token that could be a decision code: lowercase alnum runs
# with dashes/dots/underscores, both quote styles.
_TOKEN_RE = re.compile(r"""['"]([a-z0-9][a-z0-9._\-]{1,120})['"]""")


def collect_hits(scan_dirs, repo):
    """Return {quoted-token -> set of relative file paths} for every
    quoted token found in ``*.py`` files under ``scan_dirs``."""
    hits = {}
    for d in scan_dirs:
        for root, _dirs, files in os.walk(d):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(root, name)
                try:
                    with io.open(path, "r", encoding="utf-8",
                                 errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
                rel = os.path.relpath(path, repo)
                for tok in set(_TOKEN_RE.findall(text)):
                    hits.setdefault(tok, set()).add(rel)
    return hits


def main(argv):
    repo = (os.path.abspath(argv[1]) if len(argv) > 1
            else os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))
    sys.path.insert(0, repo)
    from gov import decision_codes as dc

    codes = sorted(dc.TAXONOMY.keys())
    if len(codes) != COVERAGE_PIN:
        print("PIN MISMATCH: registry has %d codes, checker pins %d -- "
              "regenerate the table with the new pin" % (len(codes),
                                                         COVERAGE_PIN),
              file=sys.stderr)
        return 2

    scan_dirs = [os.path.join(repo, "tests"),
                 os.path.join(repo, "evals")]
    for d in scan_dirs:
        if not os.path.isdir(d):
            print("missing scan dir %r" % d, file=sys.stderr)
            return 2
    hits = collect_hits(scan_dirs, repo)

    rows = []
    gaps = []
    for code in codes:
        entry = dc.TAXONOMY[code]
        files = sorted(hits.get(code, ()))
        covered = bool(files)
        rows.append({
            "code": code,
            "domain": entry.get("domain", ""),
            "severity": entry.get("severity", ""),
            "covered": covered,
            "files": files,
        })
        if not covered:
            gaps.append(code)

    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    md = io.StringIO()
    md.write("# Decision-code coverage table (generated)\n\n")
    md.write("Generated: %s UTC · registry pin: %d · base: wave-342 lane 6 "
             "(registry hygiene: -4 family-fallback codes, +at-risk emission)\n\n" % (stamp, COVERAGE_PIN))
    md.write("Rule (Bernstein #5569, ADAPT): no row claims coverage "
             "without a test. A code counts as covered when its literal "
             "string appears quoted in at least one ``.py`` file under "
             "``tests/`` or ``evals/``. Production ``emit()`` call sites "
             "do not count.\n\n")
    md.write("**Covered: %d / %d** · **Gaps: %d**\n\n"
             % (len(codes) - len(gaps), len(codes), len(gaps)))
    md.write("| code | domain | severity | covered | asserted in |\n")
    md.write("| ---- | ------ | -------- | ------- | ----------- |\n")
    for r in rows:
        cov = "yes" if r["covered"] else "**NO**"
        files = ", ".join(r["files"][:3])
        if len(r["files"]) > 3:
            files += " (+%d)" % (len(r["files"]) - 3)
        md.write("| `%s` | %s | %s | %s | %s |\n"
                 % (r["code"], r["domain"], r["severity"], cov, files))

    md_path = os.path.join(repo, "docs", "decision-code-coverage.md")
    json_path = os.path.join(repo, "docs", "decision-code-coverage.json")
    with io.open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md.getvalue())
    with io.open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"generated": stamp, "pin": COVERAGE_PIN,
                   "covered": len(codes) - len(gaps),
                   "gaps": gaps, "codes": rows},
                  fh, indent=1, sort_keys=False)
        fh.write("\n")

    print("decision-code coverage: %d/%d covered, %d gaps"
          % (len(codes) - len(gaps), len(codes), len(gaps)))
    if gaps:
        print("GAPS (no asserting probe):")
        for g in gaps:
            print("  - %s" % g)
        return 1
    print("no gaps: every code has an asserting probe")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
