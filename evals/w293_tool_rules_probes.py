"""Wave-293 lane 2 red-first battery: declared tool rules (sequence grammar).

Builds gov/tool_rules.py (letta-ai/letta ADAPT, Apache-2.0, mechanism only,
stdlib only): Init/Child/Terminal/Conditional sequence grammar, closed tool
inventory, compile-time freeze, secret-shape gate, and opt-in composition
with gov/tool_call_policy.py's decide seam.

Base: wave-292 push 36176e57508aa24c23159e3e6ff44d842b74ed5a
(verified via git rev-parse HEAD before work).

Pin 1742 -> 1742 (+3 toolcall-*: sequence-violated, secret-in-args,
rule-compile-invalid); the repoint is tree-wide (value-token-only,
code/comment splitter, history comments extended), so adjacent batteries'
own pin probes stay green.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g293-tr && TMPDIR=/var/tmp/g293-tr \
    ~/workspace/.gov-venv/bin/python evals/w293_tool_rules_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g293-trb \
    ~/workspace/.gov-venv/bin/python evals/w293_tool_rules_probes.py
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

# Wave-293 lane 2: pin 1723 -> 1726 (+3 toolcall-*: sequence-violated,
# secret-in-args, rule-compile-invalid).
TAXONOMY_PIN = 1964 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

try:
    from gov import tool_rules as TR
except ImportError:
    TR = None

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _have_tr(pid):
    if TR is None:
        _record(pid, "BREAK", "gov.tool_rules absent (feature not built)")
        return False
    return True


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (TAXONOMY_PIN,
                                                       TAXONOMY_PIN))


def _rules_doc(**over):
    doc = {
        "format": "sasanam-tool-rule-set/v1",
        "name": "w293-probe-rules",
        "tools": ["read_file", "write_file", "shell"],
        "predicates": {
            "approved": {"kind": "flag", "flag": "human_approved"},
            "read_twice": {"kind": "history", "tool": "read_file",
                           "min_calls": 2},
        },
        "rules": [
            {"kind": "Init", "tool": "read_file"},
            {"kind": "Child", "tool": "write_file", "parent": "read_file"},
            {"kind": "Terminal", "tool": "shell"},
        ],
    }
    doc.update(over)
    return doc


def _expect_coded(pid, fn, code):
    """fn must raise with .code == code -> HELD; anything else -> BREAK."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        got = getattr(e, "code", None)
        if got == code:
            return _record(pid, "HELD", "refused coded %s" % (code,))
        return _record(pid, "BREAK",
                       "refused with code=%r, want %r (%r)" % (got, code, e))
    _record(pid, "BREAK", "no refusal raised; want coded %s" % (code,))


# ---------------------------------------------------------------------------
# compile_rule_set
# ---------------------------------------------------------------------------

def p_compile_valid():
    if not _have_tr("tr-compile-valid"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    rs2 = TR.compile_rule_set(_rules_doc())
    if rs.digest != rs2.digest or not rs.digest:
        return _record("tr-compile-valid", "BREAK", "digest unstable")
    if set(rs.tools) != {"read_file", "write_file", "shell"}:
        return _record("tr-compile-valid", "BREAK", "inventory wrong")
    _record("tr-compile-valid", "HELD",
            "valid rule set compiles; digest stable; inventory closed")


def p_compile_rejects_unknown_kind():
    if not _have_tr("tr-compile-unknown-kind"):
        return
    doc = _rules_doc(rules=[{"kind": "Explode", "tool": "shell"}])
    _expect_coded("tr-compile-unknown-kind",
                  lambda: TR.compile_rule_set(doc),
                  "toolcall-rule-compile-invalid")


def p_compile_rejects_bad_shape():
    if not _have_tr("tr-compile-bad-shape"):
        return
    bad_docs = [
        ["not", "a", "dict"],
        {"format": "wrong-format/v9", "name": "x", "tools": ["a"],
         "rules": []},
        dict(_rules_doc(), **{"bogus_top_level_key": 1}),
        dict(_rules_doc(), tools=["read_file", "read_file"]),  # dup tool
        dict(_rules_doc(),
             rules=[{"kind": "Child", "tool": "write_file",
                     "parent": "nope-not-a-tool"}]),
        dict(_rules_doc(),
             rules=[{"kind": "Conditional", "tool": "shell",
                     "when": "nope-not-a-predicate"}]),
    ]
    for i, doc in enumerate(bad_docs):
        try:
            TR.compile_rule_set(doc)
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) != "toolcall-rule-compile-invalid":
                return _record("tr-compile-bad-shape", "BREAK",
                               "doc %d refused with wrong code %r"
                               % (i, getattr(e, "code", None)))
        else:
            return _record("tr-compile-bad-shape", "BREAK",
                           "doc %d compiled; want coded refusal" % (i,))
    _record("tr-compile-bad-shape", "HELD",
            "6 malformed docs all refuse coded toolcall-rule-compile-invalid")


def p_compile_frozen():
    if not _have_tr("tr-compile-frozen"):
        return
    doc = _rules_doc()
    rs = TR.compile_rule_set(doc)
    # Mutating the caller's doc after compile must not change decisions.
    doc["rules"].append({"kind": "Terminal", "tool": "read_file"})
    doc["tools"].append("evil_tool")
    try:
        rs.check_call("read_file", {}, [])
    except Exception as e:  # noqa: BLE001
        return _record("tr-compile-frozen", "BREAK",
                       "post-compile caller mutation changed decisions: %r"
                       % (e,))
    # The compiled internals themselves must resist in-process mutation.
    try:
        rs._doc["rules"] = ()
    except TypeError:
        _record("tr-compile-frozen", "HELD",
                "caller-doc mutation inert; compiled doc frozen")
    else:
        _record("tr-compile-frozen", "BREAK",
                "compiled rule-set internals mutable in-process")


# ---------------------------------------------------------------------------
# check_call: sequence grammar
# ---------------------------------------------------------------------------

def p_init_first_ok():
    if not _have_tr("tr-init-first-ok"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    rec = rs.check_call("read_file", {}, [])
    if rec.get("allowed") is True:
        return _record("tr-init-first-ok", "HELD",
                       "Init tool allowed as first call")
    _record("tr-init-first-ok", "BREAK", "Init tool refused first: %r" % (rec,))


def p_init_late_violated():
    if not _have_tr("tr-init-late"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    _expect_coded(
        "tr-init-late",
        lambda: rs.check_call("read_file", {},
                              [{"tool": "read_file"}]),
        "toolcall-sequence-violated")


def p_child_ok():
    if not _have_tr("tr-child-ok"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    rec = rs.check_call("write_file", {"path": "/tmp/x"},
                        [{"tool": "read_file"}])
    if rec.get("allowed") is True:
        return _record("tr-child-ok", "HELD",
                       "Child tool allowed directly after parent")
    _record("tr-child-ok", "BREAK", "Child after parent refused: %r" % (rec,))


def p_child_before_parent():
    if not _have_tr("tr-child-before-parent"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    _expect_coded(
        "tr-child-before-parent",
        lambda: rs.check_call("write_file", {}, []),
        "toolcall-sequence-violated")
    _expect_coded(
        "tr-child-after-stranger",
        lambda: rs.check_call("write_file", {},
                              [{"tool": "shell"}]),
        "toolcall-sequence-violated")


def p_terminal_closes():
    if not _have_tr("tr-terminal-closes"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    rec = rs.check_call("shell", {"cmd": "true"}, [{"tool": "read_file"}])
    if rec.get("allowed") is not True:
        return _record("tr-terminal-closes", "BREAK",
                       "Terminal tool itself refused: %r" % (rec,))
    _expect_coded(
        "tr-terminal-closes",
        lambda: rs.check_call("read_file", {}, [{"tool": "shell"}]),
        "toolcall-sequence-violated")


def p_conditional_flag():
    if not _have_tr("tr-conditional-flag"):
        return
    doc = _rules_doc(rules=[{"kind": "Conditional", "tool": "shell",
                             "when": "approved"}])
    rs = TR.compile_rule_set(doc)
    _expect_coded(
        "tr-conditional-flag",
        lambda: rs.check_call("shell", {}, []),
        "toolcall-sequence-violated")
    rec = rs.check_call("shell", {}, [],
                        context_flags={"human_approved": True})
    if rec.get("allowed") is True:
        return _record("tr-conditional-flag", "HELD",
                       "flag predicate gates the Conditional tool")
    _record("tr-conditional-flag", "BREAK",
            "flag-set call refused: %r" % (rec,))


def p_conditional_history():
    if not _have_tr("tr-conditional-history"):
        return
    doc = _rules_doc(rules=[{"kind": "Conditional", "tool": "write_file",
                             "when": "read_twice"}])
    rs = TR.compile_rule_set(doc)
    _expect_coded(
        "tr-conditional-history",
        lambda: rs.check_call("write_file", {},
                              [{"tool": "read_file"}]),
        "toolcall-sequence-violated")
    rec = rs.check_call("write_file", {},
                        [{"tool": "read_file"}, {"tool": "read_file"}])
    if rec.get("allowed") is True:
        return _record("tr-conditional-history", "HELD",
                       "history predicate (min_calls=2) gates the tool")
    _record("tr-conditional-history", "BREAK",
            "satisfied history predicate refused: %r" % (rec,))


def p_undeclared_tool():
    if not _have_tr("tr-undeclared-tool"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    _expect_coded(
        "tr-undeclared-tool",
        lambda: rs.check_call("nmap", {}, []),
        "toolcall-sequence-violated")


# ---------------------------------------------------------------------------
# check_call: secret-shape gate
# ---------------------------------------------------------------------------

def p_secret_value():
    if not _have_tr("tr-secret-value"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    _expect_coded(
        "tr-secret-value",
        lambda: rs.check_call("read_file",
                              {"path": "/tmp/x",
                               "token": "sk-abcdefghijklmnop123456"},
                              []),
        "toolcall-secret-in-args")


def p_secret_nested():
    if not _have_tr("tr-secret-nested"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    _expect_coded(
        "tr-secret-nested",
        lambda: rs.check_call(
            "read_file", {"opts": {"auth": {"key": "ghp_" + "z" * 24}}}, []),
        "toolcall-secret-in-args")


def p_secret_name():
    if not _have_tr("tr-secret-name"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    _expect_coded(
        "tr-secret-name",
        lambda: rs.check_call("read_file",
                              {"path": "/tmp/x",
                               "api_key": "not-a-real-key-but-named"},
                              []),
        "toolcall-secret-in-args")


def p_benign_args_pass():
    if not _have_tr("tr-benign-args"):
        return
    rs = TR.compile_rule_set(_rules_doc())
    rec = rs.check_call("read_file", {"path": "/tmp/x",
                                      "mode": "read-only"}, [])
    if rec.get("allowed") is True:
        return _record("tr-benign-args", "HELD",
                       "benign args pass the secret gate")
    _record("tr-benign-args", "BREAK",
            "benign args refused: %r (false positive)" % (rec,))


# ---------------------------------------------------------------------------
# Composition with gov/tool_call_policy.py decide
# ---------------------------------------------------------------------------

def _policy_doc():
    return {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w293-tr-compose",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "ALLOW", "tool": "*", "operation": "run",
             "severity": 1, "tags": []},
        ],
    }


def _caller():
    return {"authenticated": True, "identity": "agent-1"}


def p_compose_decide_sequence():
    if not _have_tr("tr-compose-seq"):
        return
    from gov import tool_call_policy as tp
    rs = TR.compile_rule_set(_rules_doc())
    comp = tp.compile_policy(_policy_doc())
    comp.bind_rule_set(rs)
    d = comp.decide(_caller(), "write_file", "run", args={},
                    history=[])
    if d.verdict != "DENY" or d.code != "toolcall-sequence-violated":
        return _record("tr-compose-seq", "BREAK",
                       "child-before-parent via decide: verdict=%r code=%r"
                       % (d.verdict, d.code))
    d2 = comp.decide(_caller(), "read_file", "run", args={}, history=[])
    d3 = comp.decide(_caller(), "write_file", "run", args={},
                     history=[{"tool": "read_file"}])
    if d2.verdict == "ALLOW" and d3.verdict == "ALLOW":
        return _record("tr-compose-seq", "HELD",
                       "bound rule set enforced inside decide "
                       "(DENY coded; legal sequence ALLOWs)")
    _record("tr-compose-seq", "BREAK",
            "legal sequence denied: %r %r" % (d2.verdict, d3.verdict))


def p_compose_decide_secret():
    if not _have_tr("tr-compose-secret"):
        return
    from gov import tool_call_policy as tp
    rs = TR.compile_rule_set(_rules_doc())
    comp = tp.compile_policy(_policy_doc())
    comp.bind_rule_set(rs)
    d = comp.decide(_caller(), "read_file", "run",
                    args={"token": "sk-abcdefghijklmnop123456"},
                    history=[])
    if d.verdict == "DENY" and d.code == "toolcall-secret-in-args":
        return _record("tr-compose-secret", "HELD",
                       "secret args DENY coded inside decide")
    _record("tr-compose-secret", "BREAK",
            "secret args via decide: verdict=%r code=%r"
            % (d.verdict, d.code))


def p_compose_optin():
    if not _have_tr("tr-compose-optin"):
        return
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_policy_doc())
    # No rule set bound: the sequence checker must not run; the policy
    # ALLOW rule decides alone.
    d = comp.decide(_caller(), "write_file", "run", args={}, history=[])
    if d.verdict == "ALLOW":
        return _record("tr-compose-optin", "HELD",
                       "unbound policy decides without the sequence layer")
    _record("tr-compose-optin", "BREAK",
            "unbound decide denied: %r %r" % (d.verdict, d.code))


def p_binding_auto_history():
    if not _have_tr("tr-binding-history"):
        return
    from gov import tool_call_policy as tp
    rs = TR.compile_rule_set(_rules_doc())
    comp = tp.compile_policy(_policy_doc())
    comp.bind_rule_set(rs)
    binding = tp.bind(comp, comp.digest)
    caller = _caller()
    d1 = binding.decide(caller, "read_file", "run", args={})
    if d1.verdict != "ALLOW":
        return _record("tr-binding-history", "BREAK",
                       "first call denied: %r" % (d1.verdict,))
    # No explicit history: the binding derives it from ALLOW decisions.
    d2 = binding.decide(caller, "write_file", "run", args={})
    if d2.verdict != "ALLOW":
        return _record("tr-binding-history", "BREAK",
                       "child after parent denied via auto-history: %r %r"
                       % (d2.verdict, d2.code))
    d3 = binding.decide(caller, "shell", "run", args={})
    d4 = binding.decide(caller, "read_file", "run", args={})
    if d3.verdict == "ALLOW" and d4.verdict == "DENY" and \
            d4.code == "toolcall-sequence-violated":
        return _record("tr-binding-history", "HELD",
                       "binding auto-history enforces the sequence")
    _record("tr-binding-history", "BREAK",
            "auto-history wrong: shell=%r post-terminal=%r/%r"
            % (d3.verdict, d4.verdict, d4.code))


# ---------------------------------------------------------------------------
# Depth-1 green checks: adjacent batteries must stay green. The lane's
# tree-wide pin repoint (1742 -> 1742) keeps every adjacent battery's own
# pin probe green, so expectations are the batteries' intrinsic counts.
# ---------------------------------------------------------------------------

def _run_battery(rel, expected_breaks, label):
    path = os.path.join(REPO, rel)
    d = tempfile.mkdtemp(prefix="w293-green-")
    try:
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=900,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("green-" + label, "ERROR", "subprocess: %r" % (e,))
        return
    out = proc.stdout + proc.stderr
    ms = re.findall(r"(\d+)\s+BREAK", out)
    nbreak = int(ms[-1]) if ms else -1
    if nbreak == expected_breaks:
        _record("green-" + label, "HELD",
                "%s: %d BREAK as expected" % (rel, nbreak))
    else:
        _record("green-" + label, "BREAK",
                "%s: %d BREAK, expected %d" % (rel, nbreak, expected_breaks))


def _green_checks():
    if SKIP_GREEN:
        return
    # w288_f338_f339 (tool_call_policy): 0 BREAK expected (its pin was
    # repointed tree-wide with the lane).
    _run_battery("evals/w288_f338_f339_probes.py", 0, "w288f338f339")
    # w292_redteam: 0 BREAK expected on the composed tree (F360 closed by
    # wave-293 lane 1; its pin and its repin batteries were repointed
    # tree-wide with the lane).
    _run_battery("evals/w292_redteam_probes.py", 0, "w292redteam")


def main():
    p_taxonomy_pin()
    p_compile_valid()
    p_compile_rejects_unknown_kind()
    p_compile_rejects_bad_shape()
    p_compile_frozen()
    p_init_first_ok()
    p_init_late_violated()
    p_child_ok()
    p_child_before_parent()
    p_terminal_closes()
    p_conditional_flag()
    p_conditional_history()
    p_undeclared_tool()
    p_secret_value()
    p_secret_nested()
    p_secret_name()
    p_benign_args_pass()
    p_compose_decide_sequence()
    p_compose_decide_secret()
    p_compose_optin()
    p_binding_auto_history()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w293_tool_rules: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
