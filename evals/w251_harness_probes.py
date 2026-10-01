"""Break-first red battery: fixture-driven policy test harness (wave-251
lane 2; open-policy-agent/conftest ADAPT -- harness shape only, never
the OPA engine).

The gap under test: policy changes are tested ad-hoc; the tree ships
NO standard harness where a policy author drops a policy set +
fixtures + expected outcomes and gets a deterministic verdict. There
is also no policy-delta primitive ("this policy edit flips 3 fixtures
from ALLOW to DENY").

On the pristine wave-250 base every probe reports GAP (the module
does not exist). After the build, every probe must report HELD under
both staging and a clean environment.

Synthetic/local only. Deterministic: fixed fixtures, sorted
assertions, no wall clock in asserted values. Stdlib only, no
in-repo git subprocesses. Fresh TMPDIR per process is the caller's
concern; this battery writes nothing outside the stdlib tempdir.
"""

import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Repo root (this file lives in evals/) so `gov` is importable when the
# battery is run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# ------------------------------------------------------------------
# probe harness
# ------------------------------------------------------------------

RESULTS = []


def _record(name, verdict, detail=""):
    RESULTS.append({"probe": name, "verdict": verdict, "detail": detail})
    return verdict


def load_harness_module():
    """Return (gov.policy_harness, None) or (None, reason)."""
    try:
        from gov import policy_harness
        return policy_harness, None
    except ImportError as exc:  # noqa: BLE001 - importability is the gap
        return None, str(exc)


# --- fixture corpus -------------------------------------------------

PERMIT_YAML = """\
version: "1"
policies:
  - id: allow-send
    effect: allow
    match:
      tool: send_email
"""

FORBID_YAML = """\
version: "1"
policies:
  - id: deny-send
    effect: deny
    match:
      tool: send_email
"""

APPROVAL_YAML = """\
version: "1"
policies:
  - id: approval-send
    effect: require_approval
    match:
      tool: send_email
"""


def _make_harness_dir(base, policies, fixtures, expected):
    """Build a harness dir: policies/, fixtures/, expected/."""
    import pathlib
    root = pathlib.Path(base)
    pdir = root / "policies"
    fdir = root / "fixtures"
    edir = root / "expected"
    for d in (pdir, fdir, edir):
        d.mkdir(parents=True, exist_ok=True)
    for name, text in policies.items():
        (pdir / name).write_text(text, encoding="utf-8")
    for name, obj in fixtures.items():
        (fdir / name).write_text(
            json.dumps(obj, sort_keys=True), encoding="utf-8")
    for name, obj in expected.items():
        (edir / name).write_text(
            json.dumps(obj, sort_keys=True), encoding="utf-8")
    return root


FIXTURE_SEND = {"action": {"tool": "send_email",
                           "args": {"to": "a@example.com"}}}
FIXTURE_READ = {"action": {"tool": "read_file",
                           "args": {"path": "/tmp/x"}}}


def probe_harness_exists():
    mod, reason = load_harness_module()
    if mod is None:
        return _record("harness/exists", "GAP",
                       "gov.policy_harness not importable: %s" % reason)
    for fn in ("run_harness", "diff_policies"):
        if not callable(getattr(mod, fn, None)):
            return _record("harness/exists", "GAP",
                           "gov.policy_harness.%s missing" % fn)
    return _record("harness/exists", "HELD",
                   "run_harness + diff_policies present")


def probe_run_allow(tmp):
    mod, reason = load_harness_module()
    if mod is None:
        return _record("harness/run-allow", "GAP", reason)
    root = _make_harness_dir(
        os.path.join(tmp, "allow"),
        {"p1.yaml": PERMIT_YAML},
        {"f1.json": FIXTURE_SEND},
        {"f1.json": {"effect": "allow"}})
    report = mod.run_harness(str(root))
    if report.passed == 1 and report.failed == 0 and report.total == 1:
        return _record("harness/run-allow", "HELD", "1/1 pass")
    return _record("harness/run-allow", "GAP",
                   "unexpected report: %s" % (report.to_dict(),))


def probe_run_forbid_overrides(tmp):
    """The harness must exercise the FULL path: per-policy engines +
    policy_combine.combine(), so the forbid-overrides guarantee is
    tested, not just single-policy behavior."""
    mod, reason = load_harness_module()
    if mod is None:
        return _record("harness/run-forbid-overrides", "GAP", reason)
    root = _make_harness_dir(
        os.path.join(tmp, "forbid"),
        {"p1.yaml": PERMIT_YAML, "p2.yaml": FORBID_YAML},
        {"f1.json": FIXTURE_SEND},
        {"f1.json": {"effect": "deny",
                     "code": "combine-forbid-overrides"}})
    report = mod.run_harness(str(root))
    fx = report.results[0]
    if report.passed == 1 and fx.actual_effect == "deny" \
            and fx.actual_code == "combine-forbid-overrides":
        return _record("harness/run-forbid-overrides", "HELD",
                       "forbid-overrides verified through harness")
    return _record("harness/run-forbid-overrides", "GAP",
                   "unexpected report: %s" % (report.to_dict(),))


def probe_run_mismatch_detected(tmp):
    """An expected outcome that does NOT match actual must FAIL the
    fixture (with a diff), not pass silently."""
    mod, reason = load_harness_module()
    if mod is None:
        return _record("harness/run-mismatch-detected", "GAP", reason)
    root = _make_harness_dir(
        os.path.join(tmp, "mismatch"),
        {"p1.yaml": FORBID_YAML},
        {"f1.json": FIXTURE_SEND},
        {"f1.json": {"effect": "allow"}})
    report = mod.run_harness(str(root))
    if report.failed == 1 and report.passed == 0:
        fx = report.results[0]
        if fx.actual_effect == "deny" and fx.expected_effect == "allow" \
                and fx.diff:
            return _record("harness/run-mismatch-detected", "HELD",
                           "mismatch fails with diff")
    return _record("harness/run-mismatch-detected", "GAP",
                   "unexpected report: %s" % (report.to_dict(),))


def probe_malformed_fixture_refused(tmp):
    """Fail-closed: malformed fixture JSON must ERROR, not skip."""
    mod, reason = load_harness_module()
    if mod is None:
        return _record("harness/malformed-fixture-refused", "GAP", reason)
    import pathlib
    root = pathlib.Path(tmp) / "malformed"
    (root / "policies").mkdir(parents=True)
    (root / "fixtures").mkdir(parents=True)
    (root / "expected").mkdir(parents=True)
    (root / "policies" / "p1.yaml").write_text(
        PERMIT_YAML, encoding="utf-8")
    (root / "fixtures" / "f1.json").write_text(
        "{not json", encoding="utf-8")
    (root / "expected" / "f1.json").write_text(
        json.dumps({"effect": "allow"}), encoding="utf-8")
    try:
        mod.run_harness(str(root))
    except Exception as exc:  # noqa: BLE001 - any fail-closed error
        if "policy-harness-malformed" in str(exc):
            return _record("harness/malformed-fixture-refused", "HELD",
                           "refused: %s" % exc)
        return _record("harness/malformed-fixture-refused", "GAP",
                       "refused without harness code: %s" % exc)
    return _record("harness/malformed-fixture-refused", "GAP",
                   "malformed fixture did not raise")


def probe_missing_expected_refused(tmp):
    """Fail-closed: a fixture with no expected outcome must ERROR."""
    mod, reason = load_harness_module()
    if mod is None:
        return _record("harness/missing-expected-refused", "GAP", reason)
    root = _make_harness_dir(
        os.path.join(tmp, "missing"),
        {"p1.yaml": PERMIT_YAML},
        {"f1.json": FIXTURE_SEND, "f2.json": FIXTURE_READ},
        {"f1.json": {"effect": "allow"}})
    try:
        mod.run_harness(str(root))
    except Exception as exc:  # noqa: BLE001 - any fail-closed error
        if "policy-harness-missing-expected" in str(exc):
            return _record("harness/missing-expected-refused", "HELD",
                           "refused: %s" % exc)
        return _record("harness/missing-expected-refused", "GAP",
                       "refused without harness code: %s" % exc)
    return _record("harness/missing-expected-refused", "GAP",
                   "missing expected did not raise")


def probe_delta_flip(tmp):
    """diff_policies(old, new) must report a verdict flip when a
    policy edit changes an outcome."""
    mod, reason = load_harness_module()
    if mod is None:
        return _record("harness/delta-flip", "GAP", reason)
    old = _make_harness_dir(
        os.path.join(tmp, "old"),
        {"p1.yaml": PERMIT_YAML},
        {"f1.json": FIXTURE_SEND},
        {"f1.json": {"effect": "allow"}})
    new = _make_harness_dir(
        os.path.join(tmp, "new"),
        {"p1.yaml": PERMIT_YAML, "p2.yaml": FORBID_YAML},
        {"f1.json": FIXTURE_SEND},
        {"f1.json": {"effect": "deny"}})
    delta = mod.diff_policies(str(old), str(new))
    flips = [f for f in delta.flips
             if f["fixture"] == "f1.json"
             and f["old"] == "allow" and f["new"] == "deny"]
    if delta.changed == 1 and flips and delta.new_denials == 1:
        return _record("harness/delta-flip", "HELD",
                       "allow->deny flip reported")
    return _record("harness/delta-flip", "GAP",
                   "unexpected delta: %s" % (delta.to_dict(),))


def probe_deterministic(tmp):
    """Two runs of the same harness dir must produce byte-identical
    canonical reports."""
    mod, reason = load_harness_module()
    if mod is None:
        return _record("harness/deterministic", "GAP", reason)
    root = _make_harness_dir(
        os.path.join(tmp, "det"),
        {"p1.yaml": PERMIT_YAML, "p2.yaml": APPROVAL_YAML},
        {"f1.json": FIXTURE_SEND, "f2.json": FIXTURE_READ},
        {"f1.json": {"effect": "require_approval"},
         # f2 matches no rule: both engines fail closed (deny), so the
         # combiner reports forbid-overrides, not default-deny.
         "f2.json": {"effect": "deny",
                     "code": "combine-forbid-overrides"}})
    r1 = mod.run_harness(str(root)).to_json()
    r2 = mod.run_harness(str(root)).to_json()
    if r1 == r2:
        return _record("harness/deterministic", "HELD",
                       "byte-identical reports")
    return _record("harness/deterministic", "GAP",
                   "reports differ across runs")


def main():
    import tempfile
    tmp = tempfile.mkdtemp(prefix="w251-harness-")
    probes = [
        probe_harness_exists,
        probe_run_allow,
        probe_run_forbid_overrides,
        probe_run_mismatch_detected,
        probe_malformed_fixture_refused,
        probe_missing_expected_refused,
        probe_delta_flip,
        probe_deterministic,
    ]
    for probe in probes:
        try:
            if probe.__code__.co_argcount == 1:
                probe(tmp)
            else:
                probe()
        except Exception as exc:  # noqa: BLE001 - battery never dies
            _record(probe.__name__, "ERROR", "%r" % (exc,))
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    gap = sum(1 for r in RESULTS if r["verdict"] == "GAP")
    err = sum(1 for r in RESULTS if r["verdict"] == "ERROR")
    print("w251_harness_probes: %d/%d HELD (%d GAP, %d ERROR)"
          % (held, len(RESULTS), gap, err))
    for r in RESULTS:
        print("  [%s] %s %s" % (r["verdict"], r["probe"], r["detail"]))
    return 0 if (gap == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
