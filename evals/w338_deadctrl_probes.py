#!/usr/bin/env python3
"""Wave-338 lane 3: dead-controls CI gate (Bernstein R16 STEAL) regression.

Base: `6cdf5fdd` (wave-337 merge). Pin 2131. Footer open none / next F430.

What this battery pins:

P1 (real tree): the gate passes on the shipped tree -- 0 orphans, 0 dead
  codes, entry-point set exactly {"gov.approve"}.
P2 (pin): TAXONOMY_PIN == 2135 and the registry holds 2131 codes.
P3 (footer): open none / next F430.
P4 (synthetic, red-capable): an orphan gov module fails the gate and is
  named; a module imported only by an orphan is also orphan (fixpoint).
P5 (synthetic, red-capable): a registered code raised nowhere fails the
  gate and is named; a raised code passes.
P6 (synthetic, red-capable): a `__main__` module with a documented
  `python -m` invocation is a live entry point; an undocumented one is
  an orphan and fails.
P7 (synthetic, red-capable): an orphan with a written reason + a real
  finding passes the gate (allowlist path).
P8 (synthetic, red-capable): allowlist violations fail -- missing/short
  reason, neither finding nor expiry, both, expired expiry, unknown
  finding, newly-reachable entry, stale (nonexistent) entry.
P9 (synthetic, red-capable): shrink-only -- removing an entry without a
  Removed log line fails; with the log line it passes.
P10 (synthetic, red-capable): a code raised via a module-level
  NAME = "<code>" constant counts as live (registry idiom 2).
P11 (synthetic, red-capable): registry `"code":` entries alone do not
  keep a code live (registration is not raising).

Verdicts: HELD = behavior matches the pin; BREAK = genuine gate defect;
ERROR = probe/harness problem. No findings manufactured.

$0 spend; synthetic/local; no model calls.

Run:
  mkdir -p /var/tmp/g338-deadctrl
  TMPDIR=/var/tmp/g338-deadctrl ~/workspace/.gov-venv/bin/python evals/w338_deadctrl_probes.py
Clean env:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g338-deadctrlb ~/workspace/.gov-venv/bin/python evals/w338_deadctrl_probes.py
Single probe:
  ~/workspace/.gov-venv/bin/python evals/w338_deadctrl_probes.py P4
"""

import os
import re
import shutil
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import no_dead_controls as gate  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)

_EXPECTED_BREAKS = set()  # never {} (wave-331 lesson); breaks documented above

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LONG_REASON = ("Documented operator CLI entry point for the approval queue; "
               "thin __main__ shim, unimported by design.")


# --------------------------------------------------------------------------
# Synthetic tree builder
# --------------------------------------------------------------------------

def make_tree(modules, codes, tests=None, allowlist=None, findings=None,
              entry_doc=None):
    """Build a synthetic repo tree. modules: {dotted: source}. codes: list.
    tests: {filename: source} under tests/. allowlist: allowlist file text.
    findings: FINDINGS.md text. entry_doc: {relpath: text} extra docs."""
    root = tempfile.mkdtemp(prefix="deadctrl-")
    gov = os.path.join(root, "gov")
    os.makedirs(gov)
    open(os.path.join(gov, "__init__.py"), "w").write("")
    for dotted, source in modules.items():
        parts = dotted.split(".")
        assert parts[0] == "gov"
        path = os.path.join(root, *parts) + ".py"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write(source)
    with open(os.path.join(gov, "decision_codes.py"), "w") as handle:
        handle.write("TAXONOMY = {\n")
        for code in codes:
            handle.write("    %r: {'code': %r, 'domain': 'x'},\n"
                         % (code, code))
        handle.write("}\n")
    tests_dir = os.path.join(root, "tests")
    os.makedirs(tests_dir)
    for filename, source in (tests or {}).items():
        with open(os.path.join(tests_dir, filename), "w") as handle:
            # The registry is imported across the real tree; mirror that so
            # the synthetic decision_codes module is not itself an orphan.
            handle.write("import gov.decision_codes\n" + source)
    evals_dir = os.path.join(root, "evals")
    os.makedirs(evals_dir)
    with open(os.path.join(evals_dir, "dead_controls_allowlist.md"),
              "w") as handle:
        handle.write(allowlist if allowlist is not None
                     else "## Active\n\n## Removed\n")
    with open(os.path.join(evals_dir, "FINDINGS.md"), "w") as handle:
        handle.write(findings if findings is not None else "")
    for relpath, text in (entry_doc or {}).items():
        path = os.path.join(root, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write(text)
    return root


def allowlist_entry(kind, name, reason=LONG_REASON, finding="",
                    expiry=""):
    line = "- kind: %s | name: %s | reason: %s" % (kind, name, reason)
    if finding:
        line += " | finding: %s" % finding
    if expiry:
        line += " | expiry: %s" % expiry
    return "## Active\n\n%s\n\n## Removed\n" % line


def cleanup(root):
    shutil.rmtree(root, ignore_errors=True)


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------

def p1_gate_green_real_tree():
    """Gate passes on the shipped tree; no unexcused orphans; the single
    dead code (honesty-mutant-inconclusive) is allowlisted with reason +
    expiry; entry points exactly {gov.approve}."""
    try:
        result = gate.evaluate(REPO_ROOT)
    except Exception:
        return "ERROR", "P1", traceback.format_exc(limit=3)
    problems = []
    if not result.passed:
        problems.append("gate refused: %s" % result.violations[:3])
    if result.orphans:
        problems.append("orphans: %s" % result.orphans)
    if set(result.dead_codes) != {"honesty-mutant-inconclusive"}:
        problems.append("dead codes: %s" % result.dead_codes)
    if result.allowlist_active != 1:
        problems.append("allowlist active: %d, want 1"
                        % result.allowlist_active)
    if set(result.entry_points) != {"gov.approve"}:
        problems.append("entry points: %s" % sorted(result.entry_points))
    if problems:
        return "BREAK", "P1", "; ".join(problems)
    return "HELD", "P1", ("gate PASS on real tree: %d modules, %d reached, "
                          "entry point gov.approve, %d/%d codes live, "
                          "honesty-mutant-inconclusive allowlisted w/ expiry"
                          % (result.module_count, result.reached_count,
                             result.live_code_count, result.code_count))


def p2_pin():
    """TAXONOMY_PIN == 2135 and the registry holds 2131 codes."""
    try:
        codes = gate.registered_codes(REPO_ROOT)
    except Exception:
        return "ERROR", "P2", traceback.format_exc(limit=3)
    if TAXONOMY_PIN != 2135:
        return "BREAK", "P2", "TAXONOMY_PIN = %r, want 2135" % TAXONOMY_PIN
    if len(codes) != 2135:
        return "BREAK", "P2", "registry has %d codes, want 2135" % len(codes)
    return "HELD", "P2", "pin 2131; registry 2131 codes"


def p3_footer():
    """Footer: open F513-F520 / next F521 (raw literals, wave-331 lesson).
    Repointed wave-363 merge (footer-state probe audit)."""
    try:
        text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md"),
                    encoding="utf-8").read()
    except OSError:
        return "ERROR", "P3", "FINDINGS.md unreadable"
    lines = text.splitlines()
    last = ([ln for ln in lines if "Next free finding:" in ln] or [""])[-1]  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531) (footer is not the last line; entries follow)
    if "Next free finding: **F537**" not in last:  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)
        return "BREAK", "P3", "footer next-free is not F521"
    if not re.search(r"\*\*Open findings: F526, F527, F528, F529, F530\.\*\*", last):  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)
        return "BREAK", "P3", "footer open findings is not F513-F520"
    return "HELD", "P3", "footer open F526-F530 / next F531"


def p4_orphan_module_fails():
    """Synthetic: orphan module fails the gate and is named; a module
    imported only by an orphan is also orphan (fixpoint)."""
    mods = {"gov.live": "VALUE = 1\nraise Exception('syn-code-a')\n",
            "gov.orphan": "VALUE = 2\n",
            "gov.orphan_child": "from gov.orphan import VALUE\n"}
    root = make_tree(modules=mods, codes=["syn-code-a"],
                     tests={"test_x.py": "from gov.live import VALUE\n"})
    try:
        result = gate.evaluate(root)
    except Exception:
        cleanup(root)
        return "ERROR", "P4", traceback.format_exc(limit=3)
    cleanup(root)
    if result.passed:
        return "BREAK", "P4", "gate passed with orphan modules present"
    named = [v for v in result.violations if "gov.orphan" in v]
    if not any("gov.orphan'" in v or ": gov.orphan " in v or
               v.rstrip().endswith("gov.orphan") for v in result.violations):
        return "BREAK", "P4", ("orphan not named; violations: %s"
                               % result.violations)
    if "gov.orphan_child" not in result.orphans:
        return "BREAK", "P4", ("fixpoint missed: gov.orphan_child not "
                               "flagged; orphans=%s" % result.orphans)
    return "HELD", "P4", ("orphan + orphan-child refused and named; "
                          "fixpoint holds")


def p5_dead_code_fails():
    """Synthetic: a registered code raised nowhere fails and is named;
    a raised code passes."""
    root = make_tree(
        modules={"gov.live": "raise Exception('syn-live-code')\n"},
        codes=["syn-live-code", "syn-dead-code"],
        tests={"test_x.py": "from gov.live import *\n"},
    )
    try:
        result = gate.evaluate(root)
    except Exception:
        cleanup(root)
        return "ERROR", "P5", traceback.format_exc(limit=3)
    cleanup(root)
    if result.passed:
        return "BREAK", "P5", "gate passed with a dead code present"
    if "syn-dead-code" not in result.dead_codes:
        return "BREAK", "P5", "dead code not identified: %s" % result.dead_codes
    if "syn-live-code" in result.dead_codes:
        return "BREAK", "P5", "live code misclassified as dead"
    return "HELD", "P5", "dead code refused and named; live code held"


def p6_entry_point_rule():
    """Synthetic: __main__ + documented `python -m` is a live entry
    point; undocumented __main__ is an orphan and fails."""
    main_src = ("\"\"\"CLI.\"\"\"\nfrom gov.live import VALUE\n"
                "if __name__ == \"__main__\":\n    print(VALUE)\n")
    root = make_tree(
        modules={"gov.live": "VALUE = 1\nraise Exception('syn-code-a')\n",
                 "gov.cli": main_src,
                 "gov.sneaky": main_src},
        codes=["syn-code-a"],
        tests={"test_x.py": "from gov.live import VALUE\n"},
        entry_doc={"docs/CLI.md": "Run `python -m gov.cli` to start.\n"},
    )
    try:
        result = gate.evaluate(root)
    except Exception:
        cleanup(root)
        return "ERROR", "P6", traceback.format_exc(limit=3)
    cleanup(root)
    if result.passed:
        return "BREAK", "P6", ("gate passed with undocumented __main__ "
                              "module gov.sneaky present")
    if "gov.cli" in result.orphans:
        return "BREAK", "P6", "documented entry point misclassified orphan"
    if "gov.sneaky" not in result.orphans:
        return "BREAK", "P6", ("undocumented __main__ not flagged; orphans=%s"
                               % result.orphans)
    return "HELD", "P6", ("documented entry point live; undocumented "
                          "__main__ refused")


def p7_allowlist_admits():
    """Synthetic: orphan with written reason + real finding passes."""
    root = make_tree(
        modules={"gov.live": "VALUE = 1\nraise Exception('syn-code-a')\n",
                 "gov.orphan": "VALUE = 2\n"},
        codes=["syn-code-a"],
        tests={"test_x.py": "from gov.live import VALUE\n"},
        allowlist=allowlist_entry("module", "gov.orphan", finding="F999"),
        findings="**F999 (filed 2026-10-05, synthetic).**\n",
    )
    try:
        result = gate.evaluate(root)
    except Exception:
        cleanup(root)
        return "ERROR", "P7", traceback.format_exc(limit=3)
    cleanup(root)
    if not result.passed:
        return "BREAK", "P7", ("valid allowlist entry refused: %s"
                               % result.violations)
    return "HELD", "P7", "orphan with reason + finding admitted"


def p8_allowlist_violations():
    """Synthetic: each allowlist violation shape fails the gate."""
    base_modules = {"gov.live": "VALUE = 1\nraise Exception('syn-code-a')\n",
                    "gov.orphan": "VALUE = 2\n"}
    base_tests = {"test_x.py": "from gov.live import VALUE\n"}
    findings = "**F999 (filed 2026-10-05, synthetic).**\n"
    cases = [
        ("missing reason",
         allowlist_entry("module", "gov.orphan", reason="", finding="F999")),
        ("short reason",
         allowlist_entry("module", "gov.orphan", reason="legacy",
                         finding="F999")),
        ("no finding-or-expiry",
         allowlist_entry("module", "gov.orphan")),
        ("both finding and expiry",
         allowlist_entry("module", "gov.orphan", finding="F999",
                         expiry="2099-01-01")),
        ("expired expiry",
         allowlist_entry("module", "gov.orphan", expiry="2020-01-01")),
        ("unknown finding",
         allowlist_entry("module", "gov.orphan", finding="F12345")),
        ("stale module",
         allowlist_entry("module", "gov.gone", finding="F999")),
    ]
    for label, allowlist in cases:
        root = make_tree(modules=dict(base_modules), codes=["syn-code-a"],
                         tests=dict(base_tests), allowlist=allowlist,
                         findings=findings)
        try:
            result = gate.evaluate(root)
        except Exception:
            cleanup(root)
            return "ERROR", "P8", "%s: %s" % (label,
                                              traceback.format_exc(limit=3))
        cleanup(root)
        if result.passed:
            return "BREAK", "P8", "violation admitted: %s" % label
    # Newly-reachable entry: orphan becomes imported -> entry must go.
    root = make_tree(
        modules={"gov.live": "from gov.orphan import VALUE\n"
                             "raise Exception('syn-code-a')\n",
                 "gov.orphan": "VALUE = 2\n"},
        codes=["syn-code-a"],
        tests={"test_x.py": "from gov.live import VALUE\n"},
        allowlist=allowlist_entry("module", "gov.orphan", finding="F999"),
        findings=findings)
    try:
        result = gate.evaluate(root)
    except Exception:
        cleanup(root)
        return "ERROR", "P8", "newly-reachable: %s" % traceback.format_exc(
            limit=3)
    cleanup(root)
    if result.passed:
        return "BREAK", "P8", "newly-reachable allowlist entry admitted"
    return "HELD", "P8", "8 violation shapes refused (incl. newly-reachable)"


def p9_shrink_only():
    """Synthetic: removing an entry without a Removed log line fails;
    with the log line it passes."""
    now_without_log = "## Active\n\n## Removed\n"
    now_with_log = ("## Active\n\n## Removed\n\n"
                    "- kind: module | name: gov.old | removed_wave: wave-339 "
                    "| removed_reason: now imported by tests/test_x.py\n")
    base = allowlist_entry("module", "gov.old", finding="F999")
    for label, now_text, want_violation in [
            ("unlogged removal", now_without_log, True),
            ("logged removal", now_with_log, False)]:
        root = make_tree(
            modules={"gov.live": "VALUE = 1\nraise Exception('syn-code-a')\n"},
            codes=["syn-code-a"],
            tests={"test_x.py": "from gov.live import VALUE\n"},
            allowlist=now_text)
        try:
            with open(os.path.join(root, "evals",
                                   "dead_controls_allowlist.md"),
                      "w") as handle:
                handle.write(now_text)
            violations, _ = gate.check_shrink_against_base(root, base)
        except Exception:
            cleanup(root)
            return "ERROR", "P9", "%s: %s" % (label,
                                              traceback.format_exc(limit=3))
        cleanup(root)
        if want_violation and not violations:
            return "BREAK", "P9", "unlogged removal admitted"
        if not want_violation and violations:
            return "BREAK", "P9", "logged removal refused: %s" % violations
    return "HELD", "P9", "shrink-only enforced; logged removal admitted"


def p10_constant_raised_code():
    """Synthetic: NAME = "<code>" + Name load counts as raising."""
    root = make_tree(
        modules={"gov.live": ("MY_CODE = 'syn-const-code'\n"
                              "def f():\n"
                              "    raise Exception(MY_CODE)\n")},
        codes=["syn-const-code"],
        tests={"test_x.py": "from gov.live import f\n"},
    )
    try:
        result = gate.evaluate(root)
    except Exception:
        cleanup(root)
        return "ERROR", "P10", traceback.format_exc(limit=3)
    cleanup(root)
    if not result.passed or result.dead_codes:
        return "BREAK", "P10", ("constant-raised code misclassified: %s"
                                % (result.dead_codes or result.violations))
    return "HELD", "P10", "constant-raised code live"


def p11_registration_is_not_raising():
    """Synthetic: registry `"code":` entries alone do not keep a code
    live."""
    root = make_tree(
        modules={"gov.live": "VALUE = 1\n"},
        codes=["syn-reg-only"],
        tests={"test_x.py": "from gov.live import VALUE\n"},
    )
    try:
        result = gate.evaluate(root)
    except Exception:
        cleanup(root)
        return "ERROR", "P11", traceback.format_exc(limit=3)
    cleanup(root)
    if result.passed:
        return "BREAK", "P11", "registration-only code counted as live"
    if "syn-reg-only" not in result.dead_codes:
        return "BREAK", "P11", "registration-only code not flagged dead"
    return "HELD", "P11", "registration is not raising; code flagged dead"


PROBES = [
    ("P1", p1_gate_green_real_tree),
    ("P2", p2_pin),
    ("P3", p3_footer),
    ("P4", p4_orphan_module_fails),
    ("P5", p5_dead_code_fails),
    ("P6", p6_entry_point_rule),
    ("P7", p7_allowlist_admits),
    ("P8", p8_allowlist_violations),
    ("P9", p9_shrink_only),
    ("P10", p10_constant_raised_code),
    ("P11", p11_registration_is_not_raising),
]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    only = argv[0] if argv else None
    breaks = held = errors = 0
    for pid, probe in PROBES:
        if only and pid != only:
            continue
        try:
            verdict, _pid, detail = probe()
        except Exception:
            verdict, detail = "ERROR", traceback.format_exc(limit=5)
        print("[%s] %s: %s" % (verdict, pid, detail))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
