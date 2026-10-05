"""Wave-295 closure battery for F365 (Lane 1): tool_rules secret-shape
gate must refuse coded when its scan cannot complete within bounds.

Base: wave-294 merge commit 5a88d9fa4bd3723eda72f1fc0f8dee26cd060002
(verified via git rev-parse HEAD after clone; ls-remote agrees).

F365 (LOW): gov/tool_rules.py's secret-shape gate scans arg values with
two hard bounds -- MAX_SECRET_DEPTH = 4 and a 64KB scan budget
(MAX_SECRET_SCAN_BYTES). When args exceeded either bound the scan simply
stopped and the call was ALLOWED: a secret nested at depth 5
({"a":{"b":{"c":{"d":{"e":"sk-..."}}}}}) was never scanned, and a secret
placed past byte 65536 of a single large string arg was never scanned.
Both returned {"allowed": True} on the wave-294 base. The module's own
convention for scan bounds is to refuse beyond-bound input coded --
_check_history_shape refuses an over-long session history with
toolcall-sequence-violated instead of silently evaluating a prefix. The
secret gate did the opposite: the documented bound WAS the bypass for
anyone reading the open product code.

Close-when: (1) both bypass probes flip to HELD (refused coded, loud --
ToolRuleError with a non-None code); (2) the refusal reason is the new
code toolcall-secret-scan-incomplete (the refusal reason is genuinely
different from a detected secret -- unevaluatable, not found -- and
lets operators distinguish a tripped tripwire from a missed scan);
(3) adjacent batteries stay green.

Expected: base 3 BREAK (2 bypass + pin 1743) / 10+ HELD / 0 ERROR;
fixed 0 BREAK / 13+ HELD / 0 ERROR. Deterministic under staging and
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g295-f365 && TMPDIR=/var/tmp/g295-f365 \
    ~/workspace/.gov-venv/bin/python evals/w295_f365_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g295-f365b \
    ~/workspace/.gov-venv/bin/python evals/w295_f365_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete).
TAXONOMY_PIN = 2062 #; Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).



SK = "sk-abcdefghijklmnop0123456789"

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    silent pass."""
    before = len(_results)
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "unexpected exception: %s" % (e,))
        return
    if len(_results) == before:
        _record(pid, "ERROR", "probe recorded nothing")


def p_taxonomy_pin():
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'''['"]code['"]\s*:\s*['"]([^'"]+)['"]''', src)
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "raw literals %d, expected %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "2062/2062/0 sorted")




# ---------------------------------------------------------------------------
# F365 probes: beyond-bound secret scans must refuse coded, never allow
# ---------------------------------------------------------------------------

def _rule_set():
    from gov import tool_rules as tr
    doc = {
        "format": "sasanam-tool-rule-set/v1",
        "name": "f365-rules",
        "tools": ["tool_a"],
        "predicates": {},
        "rules": [],
    }
    return tr.compile_rule_set(doc)


def _expect_coded(pid, args, code):
    """HELD iff check_call refuses with a loud coded ToolRuleError of
    the expected code. An allowed call or a wrong-code refusal is BREAK
    (the finding's close-when criterion)."""
    from gov import tool_rules as tr
    rs = _rule_set()
    try:
        rec = rs.check_call("tool_a", args=args)
    except tr.ToolRuleError as e:
        if e.code == code:
            return _record(pid, "HELD",
                           "refused coded %s" % (e.code,))
        return _record(pid, "BREAK",
                       "refused but wrong code %r (want %r)" % (e.code, code))
    return _record(pid, "BREAK",
                   "call ALLOWED despite unevaluatable secret scan: %r" % (rec,))


def p_depth5_secret_bypass():
    # A secret nested at depth 5 exceeds MAX_SECRET_DEPTH = 4: the base
    # silently allows it; the fix must refuse coded.
    args = {"a": {"b": {"c": {"d": {"e": SK}}}}}
    _expect_coded("f365-depth5-secret", args,
                  "toolcall-secret-scan-incomplete")


def p_budget_secret_bypass():
    # A secret past byte 65536 of a single string arg exceeds the 64KB
    # scan budget: the base silently allows it; the fix must refuse coded.
    args = {"big": "x" * 70000 + SK}
    _expect_coded("f365-budget-secret", args,
                  "toolcall-secret-scan-incomplete")


def p_clean_args_allowed():
    from gov import tool_rules as tr
    rs = _rule_set()
    rec = rs.check_call("tool_a", args={"q": "hello", "n": 42})
    if rec.get("allowed") is True:
        _record("f365-clean-args", "HELD", "clean args still allowed")
    else:
        _record("f365-clean-args", "BREAK",
                "clean args refused: %r" % (rec,))


def p_secret_depth0_refused():
    _expect_coded("f365-secret-depth0", {"data": SK},
                  "toolcall-secret-in-args")


def p_secret_depth4_refused():
    # At the boundary depth 4 the scan still completes, so a present
    # secret must refuse with the detected-secret code, not the
    # incomplete-scan code.
    args = {"a": {"b": {"c": {"d": SK}}}}
    _expect_coded("f365-secret-depth4", args, "toolcall-secret-in-args")


def p_secret_name_refused():
    _expect_coded("f365-secret-name", {"api_key": "not-a-shape"},
                  "toolcall-secret-in-args")


def p_history_over_bound_still_refused():
    # The module's own bound convention (history shape) must not regress.
    from gov import tool_rules as tr
    rs = _rule_set()
    history = [{"tool": "tool_a"}] * 4097
    try:
        rs.check_call("tool_a", args={}, history=history)
    except tr.ToolRuleError as e:
        if e.code == "toolcall-sequence-violated":
            return _record("f365-history-bound", "HELD",
                           "over-bound history still refused coded")
        return _record("f365-history-bound", "BREAK",
                       "wrong code %r" % (e.code,))
    _record("f365-history-bound", "BREAK", "over-bound history allowed")


def p_undeclared_tool_refused():
    from gov import tool_rules as tr
    rs = _rule_set()
    try:
        rs.check_call("undeclared", args={})
    except tr.ToolRuleError as e:
        if e.code == "toolcall-sequence-violated":
            return _record("f365-undeclared", "HELD",
                           "undeclared tool still refused coded")
        return _record("f365-undeclared", "BREAK", "wrong code %r" % (e.code,))
    _record("f365-undeclared", "BREAK", "undeclared tool allowed")


def p_exact_budget_boundary_allowed():
    # Exactly 65536 clean bytes: the scan completes (budget hits 0 only
    # after the last byte is consumed), so the call must still be allowed.
    # This guards against an over-aggressive fail-closed that refuses
    # every large-but-clean arg.
    from gov import tool_rules as tr
    rs = _rule_set()
    rec = rs.check_call("tool_a", args={"big": "x" * 65536})
    if rec.get("allowed") is True:
        _record("f365-exact-budget", "HELD",
                "exactly-64KB clean arg still allowed")
    else:
        _record("f365-exact-budget", "BREAK",
                "exactly-64KB clean arg refused: %r" % (rec,))


def p_depth4_clean_allowed():
    # Nesting at depth 4 that is fully scanned and clean must be allowed.
    from gov import tool_rules as tr
    rs = _rule_set()
    rec = rs.check_call("tool_a", args={"a": {"b": {"c": {"d": "clean"}}}})
    if rec.get("allowed") is True:
        _record("f365-depth4-clean", "HELD",
                "depth-4 clean nesting still allowed")
    else:
        _record("f365-depth4-clean", "BREAK",
                "depth-4 clean nesting refused: %r" % (rec,))


def p_deep_clean_refused():
    # Clean nesting at depth 5 is also unevaluatable: fail-closed means
    # refused coded, even though no secret is present.
    args = {"a": {"b": {"c": {"d": {"e": "perfectly clean"}}}}}
    _expect_coded("f365-deep-clean", args,
                  "toolcall-secret-scan-incomplete")


# ---------------------------------------------------------------------------
# Depth-1 green checks (honor GOV_SKIP_GREEN; lane-local stale pins noted)
# ---------------------------------------------------------------------------

def _run_battery(path, allowed_break_ids):
    d = tempfile.mkdtemp(prefix="g295-f365gc-")
    proc = subprocess.run(
        [sys.executable, path],
        env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d),
        capture_output=True, text=True, timeout=900, cwd=REPO)
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", proc.stdout)
    if not m:
        return None, "no summary line; rc=%d tail=%r" \
            % (proc.returncode, proc.stdout[-300:])
    breaks = int(m.group(1))
    errors = int(m.group(3))
    break_ids = re.findall(r"\[BREAK\] ([A-Za-z0-9_.-]+)", proc.stdout)
    unexpected = [b for b in break_ids if b not in allowed_break_ids]
    if errors or unexpected:
        return None, "%s: errors=%d unexpected-BREAKs=%r (tail=%r)" \
            % (path, errors, unexpected, proc.stdout[-300:])
    return (breaks, m.group(2)), None


def g_w293_tool_rules():
    # w293_tool_rules pins 1726 lane-locally; on this tree only its
    # pin-taxonomy probe may BREAK (merge repoints it).
    res, err = _run_battery("evals/w293_tool_rules_probes.py",
                            {"pin-taxonomy"})
    if err:
        return _record("green-w293-tool-rules", "BREAK", err)
    _record("green-w293-tool-rules", "HELD",
            "w293_tool_rules green (only stale pin-taxonomy BREAK allowed)")


def g_w294_redteam():
    # w294_redteam filed F365 OPEN: its tr-depth5-secret-bypass and
    # tr-64kb-secret-bypass probes must now be HELD (expectation
    # corrected for the closure). Its pin and w293-repin probes carry
    # stale lane-local pins; they may BREAK pending the merge repoint.
    # ks-advance-record-not-atomic is F366's probe (OPEN, owned by
    # another lane -- not this lane's work).
    allowed = {"pin-taxonomy", "ks-advance-record-not-atomic"}
    d = tempfile.mkdtemp(prefix="g295-f365gc-")
    proc = subprocess.run(
        [sys.executable, "evals/w294_redteam_probes.py"],
        env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d),
        capture_output=True, text=True, timeout=1200, cwd=REPO)
    break_ids = re.findall(r"\[BREAK\] ([A-Za-z0-9_.-]+)", proc.stdout)
    for pid in ("tr-depth5-secret-bypass", "tr-64kb-secret-bypass"):
        if pid in break_ids:
            return _record("green-w294-redteam", "BREAK",
                           "F365 probe still BREAK: %s" % (pid,))
        if not re.search(r"\[HELD\] %s" % (pid,), proc.stdout):
            return _record("green-w294-redteam", "ERROR",
                           "F365 probe %s missing from output" % (pid,))
    unexpected = [b for b in break_ids
                  if b not in allowed and not b.startswith("repin-")]
    if unexpected:
        return _record("green-w294-redteam", "BREAK",
                       "unexpected BREAKs: %r" % (unexpected,))
    _record("green-w294-redteam", "HELD",
            "F365 probes flipped to HELD; only stale pin/repin BREAKs remain")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    _safe("f365-depth5-secret", p_depth5_secret_bypass)
    _safe("f365-budget-secret", p_budget_secret_bypass)
    _safe("f365-clean-args", p_clean_args_allowed)
    _safe("f365-secret-depth0", p_secret_depth0_refused)
    _safe("f365-secret-depth4", p_secret_depth4_refused)
    _safe("f365-secret-name", p_secret_name_refused)
    _safe("f365-history-bound", p_history_over_bound_still_refused)
    _safe("f365-undeclared", p_undeclared_tool_refused)
    _safe("f365-exact-budget", p_exact_budget_boundary_allowed)
    _safe("f365-depth4-clean", p_depth4_clean_allowed)
    _safe("f365-deep-clean", p_deep_clean_refused)
    if SKIP_GREEN:
        _record("green-w293-tool-rules", "NOTE",
                "skipped under GOV_SKIP_GREEN=1 (depth-1)")
        _record("green-w294-redteam", "NOTE",
                "skipped under GOV_SKIP_GREEN=1 (depth-1)")
    else:
        _safe("green-w293-tool-rules", g_w293_tool_rules)
        _safe("green-w294-redteam", g_w294_redteam)
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    held = sum(1 for _, v, _ in _results if v == "HELD")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w295_f365: %d BREAK / %d HELD / %d ERROR"
          % (breaks, held, errors))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, breaks, held, errors)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    return 1 if breaks or errors else 0


if __name__ == "__main__":
    sys.exit(main())
