"""Policy-change CI gate: impact analysis + targeted battery selection.

Wave-346 lane 3. STEAL (mechanism only) from Archestra's CI-gated policy
testing (``describe --check`` / ``replay`` as required CI): a policy
change must pass the evidence tests that pin its affected decision
signals BEFORE it lands. This module is the static half -- given
old/new policy texts it enumerates the affected rules, flags
(decision signals), and selects the ``evals/`` batteries that pin
them. ``scripts/policy_ci_gate.py`` is the running half: it executes
the selected batteries and fails closed.

Surfaces covered:
  * ``policies/*.yaml`` -- rule adds/removes/modifications map to the
    rules' ``flag`` values (the machine signals the engine logs, e.g.
    ``secret_access_attempt``) and rule ids; both are looked up as
    quoted literals in ``evals/`` batteries (the same "pinning"
    definition as ``scripts/check_decision_code_coverage.py``).
    Risk classification reuses ``gov.policy_delta_gate``.
  * ``gov/policy_observe.py`` -- the observe/enforce lifecycle module;
    any change selects batteries pinning the ``policy_mode`` /
    ``deploy_observe`` signals.
  * ``gov/decision_codes.py`` ("pin policy") -- any change selects the
    dedicated pin batteries (filename contains "pin"); the full
    canonical suite remains the complete check (noted, not run).

Stdlib only. Deterministic: every output list is sorted; no clock,
no network, no subprocesses. Anything malformed raises
:class:`PolicyGateError` -- never a vacuous pass.
"""

from __future__ import annotations

import ast
import json
import os
import re

from .yamlmini import parse as parse_yaml
from . import policy_delta_gate as _delta

__all__ = [
    "PolicyGateError",
    "POLICY_YAML_PREFIX",
    "OBSERVE_MODULE",
    "PIN_REGISTRY",
    "OBSERVE_KEYWORDS",
    "SUMMARY_PATTERNS",
    "classify_path",
    "changed_surfaces",
    "policy_yaml_impact",
    "observe_module_impact",
    "pin_registry_impact",
    "build_battery_index",
    "select_batteries",
]

POLICY_YAML_PREFIX = "policies/"
OBSERVE_MODULE = "gov/policy_observe.py"
PIN_REGISTRY = "gov/decision_codes.py"

# Signals whose presence in a battery marks it as an observe-lifecycle
# evidence test (wave-343 lane 5 vocabulary).
OBSERVE_KEYWORDS = ("policy_mode", "deploy_observe", "would_deny")

# Canonical battery verdict-summary shapes, shared with
# scripts/policy_ci_gate.py (single source -- the shapes must agree).
# Each entry: (compiled pattern, (held_group, break_group, err_group)).
SUMMARY_PATTERNS = (
    (re.compile(r"(\d+)\s+HELD\s*/\s*(\d+)\s+BREAK\s*/\s*(\d+)\s+ERROR"),
     (0, 1, 2)),
    (re.compile(r"(\d+)\s+BREAK\s*/\s*(\d+)\s+HELD\s*/\s*(\d+)\s+ERROR"),
     (1, 0, 2)),
    (re.compile(r"HELD\s*=\s*(\d+)\s+BREAK\s*=\s*(\d+)\s+ERROR\s*=\s*(\d+)"),
     (0, 1, 2)),
)

_SUMMARY_RES = SUMMARY_PATTERNS

_DEF_RE = re.compile(r"^\s*(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)",
                    re.MULTILINE)


class PolicyGateError(Exception):
    """Loud policy-gate failure. The gate fails closed on this."""


# --------------------------------------------------------------------------
# Path classification
# --------------------------------------------------------------------------

def classify_path(path):
    """Map a repo-relative path to its policy surface (or None)."""
    p = path.replace("\\", "/").lstrip("./")
    if p.startswith(POLICY_YAML_PREFIX) and p.endswith((".yaml", ".yml")):
        return "policy-yaml"
    if p == OBSERVE_MODULE:
        return "observe-lifecycle"
    if p == PIN_REGISTRY:
        return "pin-registry"
    return None


def changed_surfaces(paths):
    """Sorted unique policy surfaces touched by an iterable of paths."""
    return sorted({s for s in (classify_path(p) for p in paths) if s})


# --------------------------------------------------------------------------
# YAML helpers
# --------------------------------------------------------------------------

def _load_yaml(which, text):
    try:
        cfg = parse_yaml(text)
    except Exception as e:  # noqa: BLE001 - fail closed, keep the cause
        raise PolicyGateError("policy-gate: %s policy text is not parseable: %s"
                              % (which, e))
    if not isinstance(cfg, dict):
        raise PolicyGateError("policy-gate: %s policy text is not a mapping"
                              % which)
    return cfg


def _rule_map(which, text):
    cfg = _load_yaml(which, text)
    raw = cfg.get("policies", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise PolicyGateError("policy-gate: %s 'policies' is not a list" % which)
    rules = {}
    for i, rule in enumerate(raw):
        if not isinstance(rule, dict):
            raise PolicyGateError("policy-gate: %s rule %d is not a mapping"
                                  % (which, i))
        rid = rule.get("id", "rule-%d" % i)
        if not isinstance(rid, str):
            raise PolicyGateError("policy-gate: %s rule %d id is not a string"
                                  % (which, i))
        if rid in rules:
            raise PolicyGateError("policy-gate: %s duplicate rule id %r"
                                  % (which, rid))
        rules[rid] = rule
    return rules


def _canon(obj):
    return json.dumps(obj, sort_keys=True, default=str)


def policy_yaml_impact(old_text, new_text):
    """Impact of a policies/*.yaml change.

    Returns a dict with sorted ``added`` / ``removed`` / ``modified``
    rule ids, sorted ``flags`` (machine signals) touched, sorted
    ``sections_changed`` (non-rule top-level keys whose canonical form
    changed), and the ``gov.policy_delta_gate`` risk ``findings``
    (informational -- the gate reports them; battery selection uses
    flags/rule ids).
    """
    old_rules = _rule_map("old", old_text)
    new_rules = _rule_map("new", new_text)
    old_ids, new_ids = set(old_rules), set(new_rules)
    added = sorted(new_ids - old_ids)
    removed = sorted(old_ids - new_ids)
    modified = sorted(rid for rid in old_ids & new_ids
                      if _canon(old_rules[rid]) != _canon(new_rules[rid]))
    flags = set()
    for rid in added + removed + modified:
        for rule in (old_rules.get(rid), new_rules.get(rid)):
            if isinstance(rule, dict) and rule.get("flag"):
                flags.add(rule["flag"])
    old_cfg = _load_yaml("old", old_text)
    new_cfg = _load_yaml("new", new_text)
    sections_changed = sorted(
        k for k in set(old_cfg) | set(new_cfg)
        if k != "policies" and _canon(old_cfg.get(k)) != _canon(new_cfg.get(k)))
    try:
        delta = _delta.analyze_policy_delta(old_text, new_text)
    except _delta.PolicyDeltaError as e:
        raise PolicyGateError("policy-gate: delta analysis refused: %s" % e)
    return {
        "surface": "policy-yaml",
        "added": added,
        "removed": removed,
        "modified": modified,
        "flags": sorted(flags),
        "rule_ids": sorted(set(added + removed + modified)),
        # Affected DECISION CODES: the delta-gate risk classes are
        # registered decision codes (policy-delta-*). Known boundary
        # (F437): the delta gate does not model ladder `mode`
        # changes, so a deny->observe flip yields no code here -- the
        # rule still counts as modified and its flag still selects
        # the pinning batteries, so the gate catches it anyway.
        "codes": sorted({f["risk_class"] for f in delta["risk_findings"]}),
        "sections_changed": sections_changed,
        "delta_verdict": delta["verdict"],
        "delta_findings": [
            {"risk_class": f["risk_class"], "severity": f["severity"],
             "section": f["section"], "rule_id": f["rule_id"]}
            for f in delta["risk_findings"]
        ],
    }


# --------------------------------------------------------------------------
# observe-lifecycle + pin-registry impacts
# --------------------------------------------------------------------------

def _defined_names(text):
    return set(_DEF_RE.findall(text))


def observe_module_impact(old_text, new_text):
    """Impact of a gov/policy_observe.py change.

    Any change selects the observe-lifecycle evidence tests; the
    changed definition names are reported for the audit trail.
    """
    old_names = _defined_names(old_text)
    new_names = _defined_names(new_text)
    return {
        "surface": "observe-lifecycle",
        "changed": old_text != new_text,
        "defs_added": sorted(new_names - old_names),
        "defs_removed": sorted(old_names - new_names),
        "keywords": list(OBSERVE_KEYWORDS),
    }


def pin_registry_impact(old_text, new_text):
    """Impact of a gov/decision_codes.py change: boolean, fail-safe."""
    return {
        "surface": "pin-registry",
        "changed": old_text != new_text,
    }


# --------------------------------------------------------------------------
# Battery index
# --------------------------------------------------------------------------

def _string_literals(source):
    """Quoted string literals in a Python source file (best effort)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # Fallback: bare quoted tokens (identifiers/hyphenated codes).
        return set(re.findall(r"""['"]([A-Za-z0-9_\-./]+)['"]""", source))
    return {n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _is_runnable(source):
    """Heuristic: the source prints a machine-readable verdict summary.

    Batteries print their summary through format strings (``%d`` /
    ``{0}`` / f-string placeholders), so placeholders are normalized
    to digits before matching -- the match is on the summary SHAPE,
    not on literal digits (which only exist at runtime).
    """
    norm = re.sub(r"%[ds]", "0", source)
    norm = re.sub(r"\{[0-9]*\}", "0", norm)
    norm = re.sub(r"\{[A-Za-z_][^}]*\}", "0", norm)
    return any(rx.search(norm) for rx, _order in _SUMMARY_RES)


def build_battery_index(repo_root):
    """Map pinning signals to runnable evals batteries.

    Returns ``{"literals": {literal: [battery, ...]}, "observe": [...],
    "pin": [...], "files": [all evals .py files]}`` -- every list
    sorted. ``literals`` covers every quoted string literal (policy
    flags, rule ids, decision codes alike); ``observe`` lists
    batteries pinning the observe-lifecycle keywords; ``pin`` lists
    the dedicated pin batteries (filename contains "pin").
    """
    evals_dir = os.path.join(repo_root, "evals")
    if not os.path.isdir(evals_dir):
        raise PolicyGateError("policy-gate: no evals/ under %s" % repo_root)
    literals = {}
    per_file = {}
    runnable = set()
    for fn in sorted(os.listdir(evals_dir)):
        if not fn.endswith(".py"):
            continue
        src = open(os.path.join(evals_dir, fn), encoding="utf-8",
                   errors="replace").read()
        lits = _string_literals(src)
        per_file[fn] = lits
        for lit in lits:
            literals.setdefault(lit, set()).add(fn)
        if _is_runnable(src):
            runnable.add(fn)
    literals = {k: sorted(v) for k, v in literals.items()}
    observe = sorted(fn for fn, lits in per_file.items()
                     if any(k in lits for k in OBSERVE_KEYWORDS)
                     and fn in runnable)
    pin = sorted(fn for fn in per_file
                 if "pin" in fn.lower() and fn in runnable)
    return {
        "literals": literals,
        "observe": observe,
        "pin": pin,
        "runnable": sorted(runnable),
        "files": sorted(per_file),
    }


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------

def select_batteries(impacts, index):
    """Select runnable batteries covering every impact.

    Returns ``{"batteries": [...], "unpinned": [...], "notes": [...]}``.
    ``unpinned`` lists affected flags/rule ids no battery pins -- the
    gate treats a non-empty ``unpinned`` as FAIL (a policy signal with
    no evidence test cannot land without adding one).
    """
    lits = index["literals"]
    selected = set()
    unpinned = set()
    notes = []
    for imp in impacts:
        surface = imp["surface"]
        if surface == "policy-yaml":
            terms = (set(imp["flags"]) | set(imp["rule_ids"])
                     | set(imp.get("codes", [])))
            for term in sorted(terms):
                files = lits.get(term, [])
                if files:
                    selected.update(files)
                else:
                    unpinned.add(term)
            for section in imp["sections_changed"]:
                files = lits.get(section, [])
                if files:
                    selected.update(files)
                    notes.append("section '%s' -> %d batteries by keyword"
                                 % (section, len(files)))
                else:
                    notes.append("section '%s' changed; no battery pins it"
                                 % section)
        elif surface == "observe-lifecycle":
            if imp["changed"]:
                selected.update(index["observe"])
                notes.append("observe-lifecycle changed -> %d observe batteries"
                             % len(index["observe"]))
        elif surface == "pin-registry":
            if imp["changed"]:
                selected.update(index["pin"])
                notes.append("pin registry changed -> %d pin batteries "
                             "(full canonical suite remains the complete check)"
                             % len(index["pin"]))
    runnable = set(index["runnable"])
    skipped = sorted(selected - runnable)
    if skipped:
        # Note-only, not FAIL: these files matched a literal but are not
        # runnable batteries (red-first scripts, orchestrators like
        # matrix.py). Excluding them is correct; the note keeps it
        # honest. Contrast `unpinned` above: an affected signal with no
        # pinning battery at all IS a hard FAIL -- that is the forcing
        # function, and it is where "never a vacuous pass" bites.
        notes.append("selected but not runnable (no verdict summary): %s"
                     % ", ".join(skipped))
    return {
        "batteries": sorted(selected & runnable),
        "unpinned": sorted(unpinned),
        "notes": notes,
    }
