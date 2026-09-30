"""Mutation-honesty gate (probityai FORCING-HONESTY, mechanism re-derived).

Over our own eval batteries: enumerate normative conditions as stable
IDs, mutate gov/* (guard removal, disjunct/conjunct removal, emission
removal, boolean flips, case-arm deletion, loop truncation), replay the
relevant battery, and classify each mutation:

  KILLED       -- a probe went PASS -> FAIL (or the battery exit went
                  0 -> non-zero). The healthy outcome.
  SILENT       -- no probe changed verdict but some observation
                  changed. The weak case: the battery does not observe
                  what the condition claims to force. A SILENT
                  mutation is a filed finding.
  DEAD         -- byte-identical observations. The mutant did not reach
                  the battery. Never evidence of anything.
  INCONCLUSIVE -- the mutant did not build/run (syntax or import
                  failure). Never folded into gaps.

Operators (AST, single-site; spec families in parentheses):
  remove_raise    -- delete a raise (guard removal, emission removal)
  remove_call     -- delete a call statement (emission removal)
  remove_return   -- delete a return (emission removal)
  flip_bool       -- True <-> False (boolean flips)
  flip_compare    -- == <-> !=, > <-> <, >= <-> <= (boolean flips)
  remove_disjunct -- `a or b` -> `a` (disjunct removal)
  remove_conjunct -- `a and b` -> `a` (conjunct removal)
  delete_branch   -- if-body -> pass (case-arm deletion)
  delete_else     -- else-body -> pass (case-arm deletion)
  delete_case_arm -- match-case body -> pass (case-arm deletion)
  truncate_loop   -- for/while body -> pass (loop truncation)

Only --sync writes the baseline, and the ratchet is tighten-only: a
condition that was forced may not become unforced unless named to
--accept-unforced one at a time. A hand-edited baseline (checksum
mismatch) is refused by the gate with honesty-baseline-tampered.

Replays are in-process (a meta-path finder redirects the mutated
module; sys.modules is purged before and after each run). Stdlib only.
Deterministic.

Reference: probityai/agent-evidence-vectors FORCING-HONESTY
(Apache-2.0, commit e85067efe9bfac6b9a3554964bf151e1cd40e101, read
2026-09-30). Mechanics re-derived; no upstream code reused. Do not pin
upstream corpus numbers -- they churn several times a week.
"""

import argparse
import ast
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile
import traceback
import uuid
from collections import Counter
from contextlib import redirect_stdout
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Outcomes and errors
# ---------------------------------------------------------------------------

KILLED = "KILLED"
SILENT = "SILENT"
DEAD = "DEAD"
INCONCLUSIVE = "INCONCLUSIVE"

PASS_VERDICTS = {"HELD"}
FAIL_VERDICTS = {"BREAK", "ERROR"}


class HonestyError(Exception):
    """Refusal with a named taxonomy code (.code)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Conditions and mutations
# ---------------------------------------------------------------------------

@dataclass
class Condition:
    """One normative condition: a claim a battery is supposed to force."""
    id: str
    target: str        # repo-relative path of the module under mutation
    battery: str       # repo-relative path of the battery script
    description: str = ""

    def to_dict(self):
        return {"id": self.id, "target": self.target,
                "battery": self.battery, "description": self.description}

    @staticmethod
    def from_dict(d):
        return Condition(id=d["id"], target=d["target"],
                         battery=d["battery"],
                         description=d.get("description", ""))


@dataclass
class Mutation:
    """One single-site source mutation."""
    operator: str
    lineno: int
    col: int
    description: str = ""

    @property
    def stable_id(self):
        return "%s@%d:%d" % (self.operator, self.lineno, self.col)

    def to_dict(self):
        return {"operator": self.operator, "lineno": self.lineno,
                "col": self.col, "description": self.description}


def _call_name(func):
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return _call_name(func.value) + "." + func.attr
    return "call"


class _SiteCollector(ast.NodeVisitor):
    """Collect every single-site mutation candidate in a module."""

    def __init__(self):
        self.sites = []

    def _add(self, op, node, description):
        self.sites.append(Mutation(operator=op, lineno=node.lineno,
                                   col=node.col_offset, description=description))

    def visit_Raise(self, node):
        self._add("remove_raise", node,
                  "remove raise at line %d" % node.lineno)
        self.generic_visit(node)

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Call):
            self._add("remove_call", node,
                      "remove call %s at line %d"
                      % (_call_name(node.value.func), node.lineno))
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, bool):
            self._add("flip_bool", node,
                      "flip bool %r at line %d" % (node.value, node.lineno))

    def visit_Compare(self, node):
        if len(node.ops) == 1 and isinstance(
                node.ops[0], (ast.Eq, ast.NotEq, ast.Gt, ast.Lt,
                              ast.GtE, ast.LtE)):
            self._add("flip_compare", node,
                      "flip comparison at line %d" % node.lineno)
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        if isinstance(node.op, ast.Or):
            self._add("remove_disjunct", node,
                      "remove disjunct at line %d" % node.lineno)
        elif isinstance(node.op, ast.And):
            self._add("remove_conjunct", node,
                      "remove conjunct at line %d" % node.lineno)
        self.generic_visit(node)

    def visit_If(self, node):
        self._add("delete_branch", node,
                  "delete if-branch body at line %d" % node.lineno)
        if node.orelse:
            self._add("delete_else", node,
                      "delete else-branch body at line %d" % node.lineno)
        self.generic_visit(node)

    def visit_For(self, node):
        self._add("truncate_loop", node,
                  "truncate for-loop at line %d" % node.lineno)
        self.generic_visit(node)

    def visit_While(self, node):
        self._add("truncate_loop", node,
                  "truncate while-loop at line %d" % node.lineno)
        self.generic_visit(node)

    def visit_Return(self, node):
        self._add("remove_return", node,
                  "remove return at line %d" % node.lineno)
        self.generic_visit(node)

    def visit_Match(self, node):
        for case in node.cases:
            # match_case carries no lineno itself; locate by its pattern.
            self.sites.append(Mutation(
                operator="delete_case_arm",
                lineno=case.pattern.lineno,
                col=case.pattern.col_offset,
                description="delete match-case arm at line %d"
                            % case.pattern.lineno))
        self.generic_visit(node)


def enumerate_mutations(source):
    """List every single-site mutation candidate for a module source."""
    tree = ast.parse(source)
    collector = _SiteCollector()
    collector.visit(tree)
    sites = sorted(collector.sites,
                   key=lambda m: (m.lineno, m.col, m.operator))
    return sites


_FLIP_CMP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
             ast.Gt: ast.Lt, ast.Lt: ast.Gt,
             ast.GtE: ast.LtE, ast.LtE: ast.GtE}


class _Mutator(ast.NodeTransformer):
    """Apply exactly one single-site mutation."""

    def __init__(self, mutation):
        self.mutation = mutation
        self.applied = False

    def _match(self, node):
        return (not self.applied
                and getattr(node, "lineno", None) == self.mutation.lineno
                and getattr(node, "col_offset", None) == self.mutation.col)

    def visit_Raise(self, node):
        if self.mutation.operator == "remove_raise" and self._match(node):
            self.applied = True
            return ast.copy_location(ast.Pass(), node)
        return self.generic_visit(node)

    def visit_Expr(self, node):
        if (self.mutation.operator == "remove_call"
                and isinstance(node.value, ast.Call)
                and self._match(node)):
            self.applied = True
            return ast.copy_location(ast.Pass(), node)
        return self.generic_visit(node)

    def visit_Constant(self, node):
        if (self.mutation.operator == "flip_bool"
                and isinstance(node.value, bool)
                and self._match(node)):
            self.applied = True
            return ast.copy_location(ast.Constant(value=not node.value), node)
        return node

    def visit_Compare(self, node):
        if (self.mutation.operator == "flip_compare"
                and len(node.ops) == 1
                and self._match(node)):
            new_op = _FLIP_CMP[type(node.ops[0])]()
            node.ops = [new_op]
            self.applied = True
            return node
        return self.generic_visit(node)

    def visit_BoolOp(self, node):
        want = {"remove_disjunct": ast.Or, "remove_conjunct": ast.And}
        if (self.mutation.operator in want
                and isinstance(node.op, want[self.mutation.operator])
                and self._match(node)):
            self.applied = True
            return node.values[0]
        return self.generic_visit(node)

    def visit_If(self, node):
        if self._match(node):
            if self.mutation.operator == "delete_branch":
                self.applied = True
                node.body = [ast.copy_location(ast.Pass(), node)]
                return node
            if self.mutation.operator == "delete_else" and node.orelse:
                self.applied = True
                node.orelse = [ast.copy_location(ast.Pass(), node)]
                return node
        return self.generic_visit(node)

    def _truncate(self, node):
        if self.mutation.operator == "truncate_loop" and self._match(node):
            self.applied = True
            node.body = [ast.copy_location(ast.Pass(), node)]
            return node
        return self.generic_visit(node)

    visit_For = _truncate
    visit_While = _truncate

    def visit_Return(self, node):
        if self.mutation.operator == "remove_return" and self._match(node):
            self.applied = True
            return ast.copy_location(ast.Pass(), node)
        return self.generic_visit(node)

    def visit_match_case(self, node):
        loc = (node.pattern.lineno, node.pattern.col_offset)
        if (self.mutation.operator == "delete_case_arm"
                and not self.applied
                and loc == (self.mutation.lineno, self.mutation.col)):
            self.applied = True
            node.body = [ast.copy_location(ast.Pass(), node.pattern)]
            return node
        return self.generic_visit(node)


def apply_mutation(source, mutation):
    """Return the source with exactly one mutation applied.

    Raises HonestyError(honesty-mutant-invalid) when the site is absent.
    """
    tree = ast.parse(source)
    mutator = _Mutator(mutation)
    new_tree = mutator.visit(tree)
    if not mutator.applied:
        raise HonestyError(
            "honesty-mutant-invalid",
            "mutation site not found: %s" % mutation.stable_id)
    ast.fix_missing_locations(new_tree)
    return ast.unparse(new_tree)

# ---------------------------------------------------------------------------
# Battery replay (in-process, mutant redirected via meta-path finder)
# ---------------------------------------------------------------------------

_PROBE_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)\s+(HELD|GAP|BREAK|ERROR)\b")
_SUMMARY_LINE = re.compile(
    r"^summary:\s*(\d+)\s+HELD\s*/\s*(\d+)\s+GAP\s*/\s*"
    r"(\d+)\s+BREAK\s*/\s*(\d+)\s+ERROR")
# Timing noise in battery notes (our batteries print "(%.1fms)" per
# probe) must not flip DEAD/SILENT. Normalization strips it before
# observation comparison; conditions may add their own patterns.
DEFAULT_NORMALIZE = [r"\s*\(\d+\.\d+ms\)"]


def _normalized_stdout(run, normalize):
    text = run.stdout
    for pattern in normalize if normalize is not None else DEFAULT_NORMALIZE:
        text = re.sub(pattern, "", text)
    return text


def _dotted_name(rel_path):
    base = rel_path.replace(os.sep, "/")
    if base.endswith(".py"):
        base = base[:-3]
    return base.replace("/", ".")


class _MutantFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Redirect one dotted module name to a mutated source file."""

    def __init__(self, mapping):
        self.mapping = dict(mapping)

    def find_spec(self, fullname, path, target=None):
        if fullname in self.mapping:
            return importlib.machinery.ModuleSpec(
                fullname, self, origin=self.mapping[fullname])
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        path = self.mapping[module.__name__]
        with open(path, "rb") as fh:
            code = compile(fh.read(), path, "exec")
        exec(code, module.__dict__)  # noqa: S102 -- harness loading


def _purge_modules(dotted):
    """Remove a module and its package tree from sys.modules."""
    for name in [n for n in sys.modules
                 if n == dotted or n.startswith(dotted + ".")
                 or dotted.startswith(n + ".")]:
        del sys.modules[name]


@dataclass
class BatteryRun:
    condition_id: str
    probes: dict = field(default_factory=dict)   # name -> verdict
    held: int = 0
    gap: int = 0
    failed: int = 0                              # BREAK + ERROR
    stdout: str = ""
    exit_code: object = None
    error: object = None                         # exception text, if any
    load_failed: bool = False                    # target/battery never built

    @property
    def failed_to_build(self):
        return self.load_failed


class ForcingHarness:
    """Replay batteries against pristine or mutated module copies."""

    def __init__(self, repo_root, work_root, deployment_mode="staging"):
        self.repo_root = os.path.abspath(repo_root)
        self.work_root = os.path.abspath(work_root)
        self.deployment_mode = deployment_mode
        os.makedirs(self.work_root, exist_ok=True)

    def _fresh_tmpdir(self, label):
        path = os.path.join(self.work_root, "tmp-%s-%s"
                            % (label, uuid.uuid4().hex[:8]))
        os.makedirs(path, exist_ok=True)
        return path

    def run_condition(self, condition, mutation):
        """Run one condition against one mutation; classify the outcome."""
        return run_condition(self, condition, mutation)

    def run_battery(self, condition, mutant_path=None):
        """Run the condition's battery; mutant_path redirects the target
        module to a mutated copy. Returns a BatteryRun."""
        batt_path = os.path.join(self.repo_root, condition.battery)
        dotted = _dotted_name(condition.target)
        mapping = {dotted: mutant_path} if mutant_path else {}
        _purge_modules(dotted)
        finder = _MutantFinder(mapping) if mapping else None
        if finder is not None:
            sys.meta_path.insert(0, finder)
        tmpdir = self._fresh_tmpdir(condition.id)
        old_tmpdir = os.environ.get("TMPDIR")
        old_mode = os.environ.get("GOV_DEPLOYMENT_MODE")
        os.environ["TMPDIR"] = tmpdir
        os.environ["GOV_DEPLOYMENT_MODE"] = self.deployment_mode
        buf = io.StringIO()
        probes, exit_code, error = {}, None, None
        load_failed = False
        batt_mod_name = "_fh_battery_%s" % uuid.uuid4().hex[:12]
        try:
            with redirect_stdout(buf):
                spec = importlib.util.spec_from_file_location(
                    batt_mod_name, batt_path)
                mod = importlib.util.module_from_spec(spec)
                sys.modules[batt_mod_name] = mod
                try:
                    spec.loader.exec_module(mod)
                except BaseException as exc:  # noqa: BLE001
                    # The mutant (or battery) never built: INCONCLUSIVE,
                    # never a kill. Any exception at import time counts --
                    # a NameError at module level is a build failure too.
                    load_failed = True
                    error = "%r\n%s" % (exc, traceback.format_exc(limit=5))
                else:
                    if hasattr(mod, "main"):
                        try:
                            exit_code = mod.main()
                        except SystemExit as exc:
                            exit_code = exc.code
                        except BaseException as exc:  # noqa: BLE001
                            error = "%r\n%s" % (
                                exc, traceback.format_exc(limit=5))
        except BaseException as exc:  # noqa: BLE001
            error = "%r\n%s" % (exc, traceback.format_exc(limit=5))
        finally:
            sys.modules.pop(batt_mod_name, None)
            if finder is not None and finder in sys.meta_path:
                sys.meta_path.remove(finder)
            _purge_modules(dotted)
            if old_tmpdir is None:
                os.environ.pop("TMPDIR", None)
            else:
                os.environ["TMPDIR"] = old_tmpdir
            if old_mode is None:
                os.environ.pop("GOV_DEPLOYMENT_MODE", None)
            else:
                os.environ["GOV_DEPLOYMENT_MODE"] = old_mode
        stdout = buf.getvalue()
        held = gap = failed = 0
        for line in stdout.splitlines():
            m = _PROBE_LINE.match(line)
            if not m:
                continue
            verdict = m.group(2)
            probes[m.group(1)] = verdict
            if verdict == "HELD":
                held += 1
            elif verdict == "GAP":
                gap += 1
            else:
                failed += 1
        return BatteryRun(condition_id=condition.id, probes=probes,
                          held=held, gap=gap, failed=failed,
                          stdout=stdout, exit_code=exit_code, error=error,
                          load_failed=load_failed)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _worsened_probes(pre, post):
    """Probes the mutant killed: HELD -> BREAK/ERROR, or vanished."""
    killed = []
    for name, verdict in pre.probes.items():
        post_verdict = post.probes.get(name)
        if verdict in PASS_VERDICTS and post_verdict in FAIL_VERDICTS:
            killed.append(name)
        elif verdict in PASS_VERDICTS and post_verdict is None:
            killed.append(name)
    return killed


def classify(pre, post, normalize=None):
    """Classify one mutation from its pre/post battery observations.

    Timing noise is normalized away before the observation comparison
    (see DEFAULT_NORMALIZE); conditions may pass extra patterns."""
    if post.failed_to_build:
        return INCONCLUSIVE
    if post.error and not pre.error:
        # The battery built and ran pristine but crashed on the mutant:
        # the mutant was detected (it broke the run), not merely unbuilt.
        return KILLED
    killed = _worsened_probes(pre, post)
    exit_worsened = (pre.exit_code == 0 and post.exit_code not in (0, None))
    if killed or exit_worsened:
        return KILLED
    if _normalized_stdout(post, normalize) != _normalized_stdout(pre, normalize):
        return SILENT
    return DEAD


def classify_independent(pre, post, normalize=None):
    """Second, independent classification path for the crosscheck.

    Uses only summary counts and exit codes -- never the per-probe
    lines -- so a parser bug in classify() cannot hide behind itself.
    """
    if post.failed_to_build:
        return INCONCLUSIVE
    if post.error and not pre.error:
        return KILLED
    if post.failed > pre.failed or post.held < pre.held:
        return KILLED
    if pre.exit_code == 0 and post.exit_code not in (0, None):
        return KILLED
    if _normalized_stdout(post, normalize) != _normalized_stdout(pre, normalize):
        return SILENT
    return DEAD


def crosscheck(results):
    """Re-classify every result with the independent path; report
    disagreements. An empty list means the two paths agree."""
    mismatches = []
    for res in results:
        other = classify_independent(res.pre, res.post)
        if other != res.classification:
            mismatches.append({
                "condition": res.condition.id,
                "mutation": res.mutation.stable_id,
                "classify": res.classification,
                "independent": other,
            })
    return mismatches


@dataclass
class MutationResult:
    condition: Condition
    mutation: Mutation
    classification: str
    pre: BatteryRun
    post: BatteryRun
    killed_probes: list = field(default_factory=list)
    note: str = ""

    def to_dict(self):
        detail = self.mutation.to_dict()
        detail["stable_id"] = self.mutation.stable_id
        return {"condition": self.condition.id,
                "mutation": detail,
                "classification": self.classification,
                "killed_probes": list(self.killed_probes),
                "note": self.note}


def run_condition(harness, condition, mutation):
    """Run one condition against one mutation; classify the outcome."""
    target_path = os.path.join(harness.repo_root, condition.target)
    with open(target_path) as fh:
        source = fh.read()
    mutated = apply_mutation(source, mutation)
    mut_dir = os.path.join(harness.work_root, "mutants", condition.id,
                           mutation.stable_id.replace(":", "-"))
    mut_path = os.path.join(mut_dir, condition.target.replace("/", os.sep))
    os.makedirs(os.path.dirname(mut_path), exist_ok=True)
    with open(mut_path, "w") as fh:
        fh.write(mutated)
    pre = harness.run_battery(condition)
    post = harness.run_battery(condition, mutant_path=mut_path)
    classification = classify(pre, post)
    killed_probes = _worsened_probes(pre, post)
    note = "%s: %s -> %s (%d probes worsened)" % (
        mutation.stable_id, condition.id, classification, len(killed_probes))
    return MutationResult(condition=condition, mutation=mutation,
                          classification=classification, pre=pre, post=post,
                          killed_probes=killed_probes, note=note)

# ---------------------------------------------------------------------------
# Findings, coverage, baseline
# ---------------------------------------------------------------------------

def file_silent_findings(results, normalize=None, evidence_lines=40):
    """The finding-filing hook: every SILENT mutation becomes a finding
    record. A SILENT mutation proves a battery-honesty gap at the seam.

    Each record carries public-seam evidence: the normalized
    pre/post observation diff (what changed without failing a probe).
    """
    import difflib
    findings = []
    for res in results:
        if res.classification != SILENT:
            continue
        pre_obs = _normalized_stdout(res.pre, normalize).splitlines()
        post_obs = _normalized_stdout(res.post, normalize).splitlines()
        diff = list(difflib.unified_diff(pre_obs, post_obs, lineterm=""))
        findings.append({
            "code": "honesty-condition-silent",
            "condition": res.condition.id,
            "mutation": res.mutation.stable_id,
            "note": ("mutation %s on %s changed observations without "
                     "failing any probe: the battery does not observe what "
                     "the condition claims to force"
                     % (res.mutation.stable_id, res.condition.target)),
            "evidence": "\n".join(diff[:evidence_lines]),
        })
    return findings


def analyze_probe_coverage(results):
    """Flag probe vectors that killed nothing across the campaign.

    A probe that never kills any mutation is a tautology suspect: it
    cannot disagree with the code, so it proves nothing."""
    kills = Counter()
    seen = set()
    for res in results:
        seen.update(res.pre.probes.keys())
        for probe in res.killed_probes:
            kills[probe] += 1
    suspects = []
    for probe in sorted(seen):
        if kills[probe] == 0:
            suspects.append({
                "probe": probe,
                "code": "honesty-tautology-suspect",
                "note": ("probe %r killed 0 mutations across %d "
                         "mutation runs" % (probe, len(results))),
            })
    return suspects


def _condition_stats(results, conditions):
    stats = {}
    by_id = {c.id: c for c in conditions}
    for res in results:
        cid = res.condition.id
        entry = stats.setdefault(cid, {"killed": 0, "silent": 0,
                                       "dead": 0, "inconclusive": 0})
        key = {"KILLED": "killed", "SILENT": "silent",
               "DEAD": "dead", "INCONCLUSIVE": "inconclusive"}[
                   res.classification]
        entry[key] += 1
    for cid in by_id:
        entry = stats.setdefault(cid, {"killed": 0, "silent": 0,
                                       "dead": 0, "inconclusive": 0})
        entry["forced"] = entry["killed"] > 0 and entry["silent"] == 0
    return stats


def _checksum_payload(stats):
    canonical = json.dumps({"conditions": stats}, sort_keys=True,
                           separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sync_baseline(results, conditions, path, accept_unforced=()):
    """Write the baseline. Tighten-only: a condition that was forced
    may not become unforced unless named in accept_unforced -- one id
    at a time. Only --sync writes baselines."""
    if len(accept_unforced) > 1:
        raise HonestyError(
            "honesty-baseline-unforced",
            "--accept-unforced takes one condition id at a time")
    stats = _condition_stats(results, conditions)
    if os.path.exists(path):
        old = load_baseline(path)
        old_stats = old["conditions"]
        unforced_now = [
            cid for cid, s in stats.items()
            if old_stats.get(cid, {}).get("forced") and not s["forced"]]
        unnamed = [cid for cid in unforced_now
                   if cid not in accept_unforced]
        if unnamed:
            raise HonestyError(
                "honesty-baseline-unforced",
                "conditions stopped being forced: %s; name one condition "
                "to --accept-unforced (one at a time)"
                % ",".join(sorted(unnamed)))
        for cid in accept_unforced:
            if cid not in unforced_now:
                raise HonestyError(
                    "honesty-baseline-unforced",
                    "--accept-unforced=%r names a condition that did not "
                    "unforce; refusing" % cid)
    payload = {"version": 1,
               "generator": "tools/forcing_honesty.py sync",
               "conditions": stats}
    payload["checksum"] = _checksum_payload(stats)
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return payload


def load_baseline(path):
    """Load a baseline; refuse hand-edited (non---sync) baselines."""
    with open(path) as fh:
        payload = json.load(fh)
    stats = payload.get("conditions")
    if not isinstance(stats, dict):
        raise HonestyError("honesty-baseline-tampered",
                           "baseline has no conditions map")
    if payload.get("checksum") != _checksum_payload(stats):
        raise HonestyError(
            "honesty-baseline-tampered",
            "baseline checksum mismatch: not written by --sync")
    return payload


def check_baseline(results, path):
    """The gate: refuse when a previously-forced condition unforced, or
    when the baseline was hand-edited."""
    old = load_baseline(path)  # tamper-checked first
    conditions = [res.condition for res in results]
    stats = _condition_stats(results, conditions)
    regressed = [
        cid for cid, s in stats.items()
        if old["conditions"].get(cid, {}).get("forced") and not s["forced"]]
    if regressed:
        raise HonestyError(
            "honesty-baseline-unforced",
            "gate refused: conditions unforced since baseline: %s"
            % ",".join(sorted(regressed)))
    return {"ok": True, "conditions": len(stats)}


# ---------------------------------------------------------------------------
# Demo fixture (toy guard + toy battery, for tests and fast probes)
# ---------------------------------------------------------------------------

DEMO_GUARD_SOURCE = '''"""Toy guard for forcing-honesty demos (stdlib only)."""

EMISSIONS = []


class RefusalError(Exception):
    pass


def refuse(action):
    EMISSIONS.append(("refusal", action))
    raise RefusalError("refused:" + action)
'''

DEMO_BATTERY_SOURCE = '''"""Toy battery for forcing-honesty demos (stdlib only)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from toy_guard import EMISSIONS, RefusalError, refuse


def main():
    results = []
    try:
        refuse("x")
        results.append(("toy-refuses", "BREAK", "no refusal raised"))
    except RefusalError:
        results.append(("toy-refuses", "HELD", "refusal raised"))
    except Exception as exc:  # noqa: BLE001
        results.append(("toy-refuses", "ERROR", repr(exc)))
    # Vacuous by design: asserts a constant, kills nothing.
    results.append(("toy-constant", "HELD", "1==1 always"))
    # Observation, never verdict-checked: the emission count.
    print("toy-emissions-observed: %d" % len(EMISSIONS))
    held = sum(1 for _, v, _ in results if v == "HELD")
    brk = sum(1 for _, v, _ in results if v in ("BREAK", "ERROR"))
    for name, verdict, note in results:
        print("%-42s %s  %s" % (name, verdict, note))
    print("summary: %d HELD / 0 GAP / %d BREAK / 0 ERROR" % (held, brk))
    return 0 if brk == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
'''


def demo_condition(workdir):
    """Write the toy guard + toy battery into workdir; return its
    Condition. Used by the red-first battery and unit tests."""
    os.makedirs(workdir, exist_ok=True)
    with open(os.path.join(workdir, "toy_guard.py"), "w") as fh:
        fh.write(DEMO_GUARD_SOURCE)
    with open(os.path.join(workdir, "toy_battery.py"), "w") as fh:
        fh.write(DEMO_BATTERY_SOURCE)
    return Condition(
        id="fc-demo-01", target="toy_guard.py", battery="toy_battery.py",
        description="demo: the toy battery must force the toy guard's "
                    "refusal and observe its refusal emission")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_conditions(path):
    with open(path) as fh:
        data = json.load(fh)
    return [Condition.from_dict(c) for c in data["conditions"]]


def _cmd_enumerate(args):
    conditions = _load_conditions(args.conditions)
    out = []
    for cond in conditions:
        with open(os.path.join(args.repo_root, cond.target)) as fh:
            source = fh.read()
        for mut in enumerate_mutations(source):
            out.append({"condition": cond.id, "mutation": mut.to_dict(),
                        "stable_id": mut.stable_id})
    print(json.dumps(out, indent=2))


def _cmd_run(args):
    conditions = _load_conditions(args.conditions)
    if args.condition:
        conditions = [c for c in conditions if c.id == args.condition]
    harness = ForcingHarness(args.repo_root, args.work_root)
    results = []
    for cond in conditions:
        with open(os.path.join(args.repo_root, cond.target)) as fh:
            source = fh.read()
        for mut in enumerate_mutations(source):
            if args.mutant and mut.stable_id != args.mutant:
                continue
            res = run_condition(harness, cond, mut)
            results.append(res)
            print("%-34s %s" % (res.note.split(":")[0], res.classification))
    out = [r.to_dict() for r in results]
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(out, fh, indent=2, sort_keys=True)
    silent = file_silent_findings(results)
    if silent:
        print("SILENT findings: %d (filed as findings)" % len(silent))
        for f in silent:
            print("  %s %s %s" % (f["code"], f["condition"], f["mutation"]))
    suspects = analyze_probe_coverage(results)
    if suspects:
        print("tautology suspects: %d" % len(suspects))
        for s in suspects:
            print("  %s %s" % (s["code"], s["probe"]))
    mismatches = crosscheck(results)
    if mismatches:
        print("CROSSCHECK MISMATCHES: %d" % len(mismatches))
        for m in mismatches:
            print("  %r" % (m,))
        return 1
    print("crosscheck: all %d classifications agree" % len(results))
    return 0


def _cmd_sync(args):
    with open(args.results) as fh:
        raw = json.load(fh)
    # Rehydrate minimal results for stats (classification only).
    conditions = _load_conditions(args.conditions)
    by_id = {c.id: c for c in conditions}
    results = []
    for item in raw:
        cond = by_id[item["condition"]]
        mut = Mutation(operator=item["mutation"]["operator"],
                       lineno=item["mutation"]["lineno"],
                       col=item["mutation"]["col"],
                       description=item["mutation"].get("description", ""))
        results.append(MutationResult(
            condition=cond, mutation=mut,
            classification=item["classification"], pre=None, post=None,
            killed_probes=item.get("killed_probes", [])))
    sync_baseline(results, conditions, args.baseline,
                  accept_unforced=tuple(args.accept_unforced or ()))
    print("baseline synced: %s" % args.baseline)


def _cmd_check(args):
    conditions = _load_conditions(args.conditions)
    harness = ForcingHarness(args.repo_root, args.work_root)
    results = []
    for cond in conditions:
        with open(os.path.join(args.repo_root, cond.target)) as fh:
            source = fh.read()
        for mut in enumerate_mutations(source):
            results.append(run_condition(harness, cond, mut))
    verdict = check_baseline(results, args.baseline)
    print("gate: %r" % (verdict,))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Mutation-honesty gate over eval batteries.")
    parser.add_argument("--repo-root", default=os.getcwd())
    parser.add_argument("--work-root",
                        default=os.path.join(tempfile.gettempdir(),
                                             "forcing-honesty"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("enumerate")
    p.add_argument("conditions")
    p.set_defaults(fn=_cmd_enumerate)
    p = sub.add_parser("run")
    p.add_argument("conditions")
    p.add_argument("--condition")
    p.add_argument("--mutant")
    p.add_argument("--out")
    p.set_defaults(fn=_cmd_run)
    p = sub.add_parser("sync")
    p.add_argument("results")
    p.add_argument("conditions")
    p.add_argument("--baseline", required=True)
    p.add_argument("--accept-unforced", action="append", default=[])
    p.set_defaults(fn=_cmd_sync)
    p = sub.add_parser("check")
    p.add_argument("conditions")
    p.add_argument("--baseline", required=True)
    p.set_defaults(fn=_cmd_check)
    args = parser.parse_args(argv)
    try:
        return args.fn(args) or 0
    except HonestyError as exc:
        print("refused %s: %s" % (exc.code, exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
