"""Fixture-driven policy test harness (conftest-adapted shape).

Wave-251 lane 2. Stdlib only.

The open-policy-agent/conftest ADAPT (Apache-2.0 -- the harness SHAPE
only: policy dir + fixtures + expected outcomes + CI output; OPA as
an engine stays SKIP, and the direction is inverted: we test policies
against fixtures, not fixtures against policies): a policy author
drops a policy SET plus request fixtures plus expected outcomes into
one directory and gets a deterministic verdict.

A harness directory contains:

  policies/   one *.yaml/*.yml policy file per policy in the set
              (each parsed by PolicyEngine.from_text)
  fixtures/   one *.json request per fixture: {"action": {...},
              "context": {...}}
  expected/   one *.json per fixture, same name:
              {"effect": "allow"|"require_approval"|"deny",
               "code": "<optional combiner code>"}

``run_harness()`` evaluates every fixture against EVERY policy
(PolicyEngine.evaluate, telemetry off) and combines the per-policy
decisions with policy_combine.combine() -- so the harness tests the
forbid-overrides-permit guarantee, not just single-policy behavior.

``diff_policies(old_dir, new_dir)`` is the policy-delta primitive: it
runs old_dir's fixtures against both policy sets and reports outcome
changes -- "this policy edit flips 3 fixtures from ALLOW to DENY".

Fail-closed: malformed fixtures/expected/policies, a fixture with no
expected outcome, an empty policies dir, or a non-YAML file in
policies/ all raise HarnessError (with a policy-harness-* machine
code) -- never a silent skip.
"""

import json
import os
import sys

from .policy import PolicyEngine
from . import policy_combine

__all__ = [
    "HarnessError",
    "FixtureResult",
    "HarnessReport",
    "DeltaReport",
    "run_harness",
    "diff_policies",
    "main",
]

# Machine decision codes emitted by this module (also in
# gov/decision_codes.py under domain "policy-harness").
MALFORMED_CODE = "policy-harness-malformed"
MISSING_EXPECTED_CODE = "policy-harness-missing-expected"
NO_POLICIES_CODE = "policy-harness-no-policies"
UNKNOWN_FORMAT_CODE = "policy-harness-unknown-format"

_VALID_EFFECTS = ("allow", "require_approval", "deny")
_POLICY_SUFFIXES = (".yaml", ".yml")


class HarnessError(Exception):
    """The harness input is unusable. Fail-closed: carries a
    policy-harness-* machine code; the message leads with the code."""

    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise HarnessError(
            MALFORMED_CODE, "cannot read %s: %s" % (path, exc))
    try:
        obj = json.loads(text)
    except ValueError as exc:
        raise HarnessError(
            MALFORMED_CODE, "malformed JSON in %s: %s" % (path, exc))
    if not isinstance(obj, dict):
        raise HarnessError(
            MALFORMED_CODE, "top-level JSON in %s must be an object, "
            "got %s" % (path, type(obj).__name__))
    return obj


def _load_policies(policies_dir):
    """Load every policy file (sorted) into (name, PolicyEngine)."""
    if not os.path.isdir(policies_dir):
        raise HarnessError(
            NO_POLICIES_CODE,
            "policies dir %s missing" % (policies_dir,))
    names = sorted(os.listdir(policies_dir))
    engines = []
    for name in names:
        path = os.path.join(policies_dir, name)
        if not os.path.isfile(path):
            continue
        lower = name.lower()
        if not lower.endswith(_POLICY_SUFFIXES):
            raise HarnessError(
                UNKNOWN_FORMAT_CODE,
                "policies/%s: unknown policy format (expected *.yaml "
                "or *.yml)" % (name,))
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            raise HarnessError(
                MALFORMED_CODE, "cannot read %s: %s" % (path, exc))
        try:
            engine = PolicyEngine.from_text(
                text, source_label="harness:" + name)
        except Exception as exc:  # noqa: BLE001 - engine is fail-closed
            raise HarnessError(
                MALFORMED_CODE,
                "policies/%s refused by PolicyEngine: %s" % (name, exc))
        engines.append((name, engine))
    if not engines:
        raise HarnessError(
            NO_POLICIES_CODE,
            "policies dir %s has no loadable policy files"
            % (policies_dir,))
    return engines


def _load_fixtures(fixtures_dir, expected_dir):
    """Load (name, action, context, expected) sorted by name."""
    if not os.path.isdir(fixtures_dir):
        raise HarnessError(
            MALFORMED_CODE, "fixtures dir %s missing" % (fixtures_dir,))
    if not os.path.isdir(expected_dir):
        raise HarnessError(
            MALFORMED_CODE, "expected dir %s missing" % (expected_dir,))
    out = []
    for name in sorted(os.listdir(fixtures_dir)):
        if not name.endswith(".json"):
            raise HarnessError(
                UNKNOWN_FORMAT_CODE,
                "fixtures/%s: unknown fixture format (expected "
                "*.json)" % (name,))
        fixture = _read_json(os.path.join(fixtures_dir, name))
        action = fixture.get("action")
        if not isinstance(action, dict):
            raise HarnessError(
                MALFORMED_CODE,
                "fixtures/%s: 'action' must be an object, got %r"
                % (name, action))
        context = fixture.get("context", {})
        if not isinstance(context, dict):
            raise HarnessError(
                MALFORMED_CODE,
                "fixtures/%s: 'context' must be an object, got %r"
                % (name, context))
        expected_path = os.path.join(expected_dir, name)
        if not os.path.isfile(expected_path):
            raise HarnessError(
                MISSING_EXPECTED_CODE,
                "fixtures/%s has no expected/%s" % (name, name))
        expected = _read_json(expected_path)
        effect = expected.get("effect")
        if effect not in _VALID_EFFECTS:
            raise HarnessError(
                MALFORMED_CODE,
                "expected/%s: 'effect' must be one of %s, got %r"
                % (name, list(_VALID_EFFECTS), effect))
        code = expected.get("code")
        if code is not None and not isinstance(code, str):
            raise HarnessError(
                MALFORMED_CODE,
                "expected/%s: 'code' must be a string, got %r"
                % (name, code))
        out.append((name, action, context, effect, code))
    if not out:
        raise HarnessError(
            MALFORMED_CODE,
            "fixtures dir %s has no fixture files" % (fixtures_dir,))
    return out


def _evaluate_all(engines, action, context):
    """Evaluate one request against every policy, then combine."""
    decisions = [engine.evaluate(action, context,
                                 record_telemetry=False)
                 for _name, engine in engines]
    return policy_combine.combine(decisions)


class FixtureResult:
    """One fixture's verdict: pass/fail with actual vs expected."""

    def __init__(self, name, passed, expected_effect, actual_effect,
                 expected_code, actual_code, diff):
        self.name = name
        self.passed = passed
        self.expected_effect = expected_effect
        self.actual_effect = actual_effect
        self.expected_code = expected_code
        self.actual_code = actual_code
        self.diff = diff

    def to_dict(self):
        return {
            "fixture": self.name,
            "passed": self.passed,
            "expected_effect": self.expected_effect,
            "actual_effect": self.actual_effect,
            "expected_code": self.expected_code,
            "actual_code": self.actual_code,
            "diff": self.diff,
        }


class HarnessReport:
    """The deterministic result of one run_harness() call."""

    def __init__(self, harness_dir, results):
        self.harness_dir = harness_dir
        self.results = tuple(results)
        self.passed = sum(1 for r in results if r.passed)
        self.failed = sum(1 for r in results if not r.passed)
        self.total = len(results)

    def to_dict(self):
        return {
            "harness": self.harness_dir,
            "passed": self.passed,
            "failed": self.failed,
            "total": self.total,
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self):
        # Canonical: sorted keys, no whitespace variance -- two runs
        # of the same harness dir are byte-identical.
        return json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":"))


def run_harness(harness_dir):
    """Run the harness: per-fixture verdicts + summary. Fail-closed."""
    policies = _load_policies(os.path.join(harness_dir, "policies"))
    fixtures = _load_fixtures(os.path.join(harness_dir, "fixtures"),
                              os.path.join(harness_dir, "expected"))
    results = []
    for name, action, context, want_effect, want_code in fixtures:
        combined = _evaluate_all(policies, action, context)
        got_effect = combined.effect
        got_code = combined.code
        effect_ok = (got_effect == want_effect)
        code_ok = (want_code is None or got_code == want_code)
        passed = effect_ok and code_ok
        diff = ""
        if not passed:
            parts = []
            if not effect_ok:
                parts.append("effect: expected %r, got %r"
                             % (want_effect, got_effect))
            if not code_ok:
                parts.append("code: expected %r, got %r"
                             % (want_code, got_code))
            diff = "; ".join(parts)
        results.append(FixtureResult(
            name, passed, want_effect, got_effect,
            want_code, got_code, diff))
    return HarnessReport(harness_dir, results)


class DeltaReport:
    """The deterministic result of one diff_policies() call."""

    def __init__(self, old_dir, new_dir, entries, expected):
        self.old_dir = old_dir
        self.new_dir = new_dir
        self.entries = tuple(entries)
        self.flips = tuple(e for e in entries if e["old"] != e["new"])
        self.changed = len(self.flips)
        self.new_denials = sum(
            1 for e in self.flips
            if e["new"] == "deny" and e["old"] != "deny")
        self.new_allows = sum(
            1 for e in self.flips
            if e["new"] == "allow" and e["old"] != "allow")
        self.new_approvals = sum(
            1 for e in self.flips
            if e["new"] == "require_approval"
            and e["old"] != "require_approval")
        # Regression: a fixture whose NEW outcome no longer matches
        # the expected outcome the old set satisfied.
        self.regressions = tuple(
            e["fixture"] for e in entries
            if e["new"] != expected[e["fixture"]])

    def to_dict(self):
        return {
            "old": self.old_dir,
            "new": self.new_dir,
            "changed": self.changed,
            "new_denials": self.new_denials,
            "new_allows": self.new_allows,
            "new_approvals": self.new_approvals,
            "flips": [dict(f) for f in self.flips],
            "regressions": list(self.regressions),
            "entries": [dict(e) for e in self.entries],
        }

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":"))


def diff_policies(old_dir, new_dir):
    """Run old_dir's fixtures against both policy sets; report flips.

    old_dir's fixtures+expected are the stable test corpus; new_dir
    contributes its policies/ only (its fixtures, if any, are
    ignored -- the comparison must run the SAME requests).
    """
    old_policies = _load_policies(os.path.join(old_dir, "policies"))
    new_policies = _load_policies(os.path.join(new_dir, "policies"))
    fixtures = _load_fixtures(os.path.join(old_dir, "fixtures"),
                              os.path.join(old_dir, "expected"))
    entries = []
    expected = {}
    for name, action, context, want_effect, _want_code in fixtures:
        expected[name] = want_effect
        old_effect = _evaluate_all(old_policies, action, context).effect
        new_effect = _evaluate_all(new_policies, action, context).effect
        entries.append({
            "fixture": name,
            "old": old_effect,
            "new": new_effect,
            "expected": want_effect,
        })
    return DeltaReport(old_dir, new_dir, entries, expected)


def main(argv=None):
    """CI entry point: run_harness(<dir>), print the canonical JSON
    report, exit non-zero on any failure or harness error."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: policy_harness <harness-dir>", file=sys.stderr)
        return 2
    try:
        report = run_harness(args[0])
    except HarnessError as exc:
        print(json.dumps({"error": str(exc), "code": exc.code},
                         sort_keys=True),
              file=sys.stderr)
        return 2
    print(report.to_json())
    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
