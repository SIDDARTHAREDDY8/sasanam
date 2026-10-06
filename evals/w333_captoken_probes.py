#!/usr/bin/env python3
"""Wave-333 lane 3 regression battery: context-bound capability tokens
(gov/capability_token.py).

Break-first probes at the public seams (mint_context_token /
verify_context_token). The red battery (evals/w333_captoken_red.py)
proved the gap on the base tree; this battery pins the fix:

Verdicts:
  HELD  = behavior matches the pin (attack refused coded / legitimate
          use accepted);
  BREAK = behavior changed vs the pin, or an unexpected miss;
  ERROR = probe/harness problem.

Probe map:
  mint-verify-roundtrip: mint + verify in the same context succeeds and
      returns the bound context.
  refuse-agent-mismatch: different presenting agent ->
      capability-token-agent-mismatch.
  refuse-mission-mismatch: different mission ->
      capability-token-mission-mismatch.
  refuse-tools-mismatch: widened/narrowed/substituted tool set ->
      capability-token-tools-mismatch; reordered presentation of the
      SAME set still verifies (order-insensitive binding).
  refuse-policy-stale: rotated policy version ->
      capability-token-policy-stale.
  refuse-tampered: edited context / swapped inner token / edited MAC ->
      capability-token-tampered.
  refuse-expired: past expires_at -> capability-token-expired.
  refuse-malformed: missing fields, bad version, empty tool set,
      non-string agent, unknown fields -> capability-token-malformed.
  inner-binding-preserved: the wrapped approval token's own refusals
      still propagate (argument substitution ->
      approval-token-argument-mismatch; capability substitution ->
      approval-token-capability-mismatch).
  digest-binds-all-four: the context digest changes when exactly one of
      the four bound inputs changes, and is stable for identical inputs.
  pin-taxonomy / footer-state: standard pins (2100; open none / next F419).

Deterministic across 2 runs; $0 spend; synthetic/local. Stdlib only
apart from gov/capability_token.py + gov/approval_tokens.py (real
product code, no stubs).

Run:
  mkdir -p /var/tmp/g333-cap
  TMPDIR=/var/tmp/g333-cap ~/workspace/.gov-venv/bin/python evals/w333_captoken_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g333-capb ~/workspace/.gov-venv/bin/python evals/w333_captoken_probes.py
Single-probe mode:
  ~/workspace/.gov-venv/bin/python evals/w333_captoken_probes.py refuse-tampered
"""

import copy
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import capability_token as CT  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
# (agent/mission/tools/policy-stale/malformed/tampered/expired).

_NOW = 1798765432
_AGENT = "agent-A"
_MISSION = "mission-X"
_TOOLS = ["send_email"]
_POLICY = "policy-v3"
_BENIGN = {"to": "teammate@synthetic.local", "body": "weekly report"}
_HARMFUL = {"to": "external-drop@synthetic.local", "body": "weekly report"}

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))
    print("[%s] %s: %s" % (verdict, pid, note.split("\n")[0][:160]))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a dead
    battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _key():
    # Standalone battery runs do not import the tests package, so
    # provision a key here when absent. Test-only.
    if "GOV_LOG_KEY" not in os.environ:
        try:
            from tests.keyfixture import provision_test_key
        except ImportError:
            from keyfixture import provision_test_key
        provision_test_key()


def _mint(**kw):
    base = {"agent_id": _AGENT, "mission_id": _MISSION,
            "tool_set": list(_TOOLS), "policy_version": _POLICY,
            "capability": "send_email",
            "argument_binding": {"mode": "exact", "args": dict(_BENIGN)},
            "issuer": "human-operator", "ttl_seconds": 3600,
            "issued_at": _NOW}
    base.update(kw)
    return CT.mint_context_token(**base)


def _verify(token, **kw):
    base = {"agent_id": _AGENT, "mission_id": _MISSION,
            "tool_set": list(_TOOLS), "policy_version": _POLICY,
            "capability": "send_email", "args": dict(_BENIGN),
            "now": _NOW}
    base.update(kw)
    return CT.verify_context_token(token, **base)


def _code_of(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        # Both CapabilityTokenError and the inner ApprovalTokenError are
        # code-first (self.code); anything else is a harness problem.
        return getattr(e, "code", "UNEXPECTED:%r" % (e,))
    return None


def _expect(pid, fn, code, note):
    got = _code_of(fn)
    if got == code:
        _record(pid, "HELD", "%s: refused coded %s" % (note, code))
    else:
        _record(pid, "BREAK", "%s: expected %s, got %r" % (note, code, got))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def mint_verify_roundtrip():
    _key()
    tok = _mint()
    assert tok["v"] == 1, tok
    assert tok["context"]["tool_set"] == ["send_email"], tok
    assert len(tok["context_digest"]) == 64, tok
    assert len(tok["mac"]) == 64, tok
    ctx = _verify(tok)
    assert ctx == {"agent_id": _AGENT, "mission_id": _MISSION,
                   "tool_set": ["send_email"],
                   "policy_version": _POLICY}, ctx
    _record("mint-verify-roundtrip", "HELD",
            "same-context mint+verify round-trips; bound context returned")


def refuse_agent_mismatch():
    _key()
    tok = _mint()
    _expect("refuse-agent-mismatch",
            lambda: _verify(tok, agent_id="agent-B"),
            "capability-token-agent-mismatch",
            "agent-A token presented by agent-B")


def refuse_mission_mismatch():
    _key()
    tok = _mint()
    _expect("refuse-mission-mismatch",
            lambda: _verify(tok, mission_id="mission-Y"),
            "capability-token-mission-mismatch",
            "mission-X token presented for mission-Y")


def refuse_tools_mismatch():
    _key()
    tok = _mint()
    _expect("refuse-tools-widened",
            lambda: _verify(tok, tool_set=["send_email", "delete_file"]),
            "capability-token-tools-mismatch",
            "tool set widened after mint")
    _expect("refuse-tools-narrowed",
            lambda: _verify(tok, tool_set=[] or ["other_tool"]),
            "capability-token-tools-mismatch",
            "tool set narrowed after mint")
    _expect("refuse-tools-substituted",
            lambda: _verify(tok, tool_set=["delete_file"]),
            "capability-token-tools-mismatch",
            "tool set substituted after mint")
    # Order-insensitive: the SAME set in a different order verifies.
    _key()
    tok2 = _mint(tool_set=["b-tool", "a-tool"])
    try:
        CT.verify_context_token(
            tok2, agent_id=_AGENT, mission_id=_MISSION,
            tool_set=["a-tool", "b-tool"], policy_version=_POLICY,
            capability="send_email", args=dict(_BENIGN), now=_NOW)
        _record("tools-order-insensitive", "HELD",
                "same tool set in different order verifies (set binding)")
    except CT.CapabilityTokenError as e:
        _record("tools-order-insensitive", "BREAK",
                "same set reordered refused: %s" % (e.code,))


def refuse_policy_stale():
    _key()
    tok = _mint()
    _expect("refuse-policy-stale",
            lambda: _verify(tok, policy_version="policy-v4"),
            "capability-token-policy-stale",
            "policy-v3 token presented after rotation to policy-v4")


def refuse_tampered():
    _key()
    tok = _mint()
    edited = copy.deepcopy(tok)
    edited["context"]["agent_id"] = "agent-B"
    _expect("refuse-tampered-context",
            lambda: _verify(edited),
            "capability-token-tampered",
            "edited context with stale MAC")
    swapped = copy.deepcopy(tok)
    other = _mint(agent_id="agent-Z")
    swapped["inner"] = other["inner"]
    _expect("refuse-tampered-inner-swap",
            lambda: _verify(swapped),
            "capability-token-tampered",
            "inner token swapped under the outer seal")
    bad_mac = copy.deepcopy(tok)
    bad_mac["mac"] = "00" + bad_mac["mac"][2:]
    _expect("refuse-tampered-mac",
            lambda: _verify(bad_mac),
            "capability-token-tampered",
            "edited MAC")


def refuse_expired():
    _key()
    tok = _mint()
    _expect("refuse-expired",
            lambda: _verify(tok, now=_NOW + 7200),
            "capability-token-expired",
            "presented after expires_at")


def refuse_malformed():
    _key()
    tok = _mint()

    def _try_mut(pid, mutate, note):
        bad = copy.deepcopy(tok)
        mutate(bad)
        _expect(pid, lambda: _verify(bad),
                "capability-token-malformed", note)

    _try_mut("refuse-malformed-no-mac",
             lambda b: b.pop("mac"), "missing mac")
    _try_mut("refuse-malformed-version",
             lambda b: b.update(v=2), "bad version")
    _try_mut("refuse-malformed-empty-tools",
             lambda b: b["context"].update(tool_set=[]),
             "empty tool set")
    _try_mut("refuse-malformed-agent-type",
             lambda b: b["context"].update(agent_id=123),
             "non-string agent_id")
    _try_mut("refuse-malformed-extra-field",
             lambda b: b.update(surprise=1), "unknown top-level field")
    _try_mut("refuse-malformed-no-context",
             lambda b: b.pop("context"), "missing context")
    # Mint-time malformed: unbindable values fail closed at issue.
    for pid, kwargs, note in [
            ("mint-malformed-empty-agent", {"agent_id": ""}, "empty agent"),
            ("mint-malformed-empty-tools", {"tool_set": []},
             "empty tool set"),
            ("mint-malformed-tool-type", {"tool_set": ["ok", 7]},
             "non-string tool name")]:
        got = _code_of(lambda: _mint(**kwargs))
        if got == "capability-token-malformed":
            _record(pid, "HELD", "%s: refused at mint coded %s" % (note, got))
        else:
            _record(pid, "BREAK",
                    "%s: expected capability-token-malformed, got %r"
                    % (note, got))


def inner_binding_preserved():
    _key()
    tok = _mint()
    _expect("inner-argument-substitution",
            lambda: _verify(tok, args=dict(_HARMFUL)),
            "approval-token-argument-mismatch",
            "harmful args under a benign-args token")
    _expect("inner-capability-substitution",
            lambda: _verify(tok, capability="delete_file",
                            args=dict(_BENIGN)),
            "approval-token-capability-mismatch",
            "delete_file presented on a send_email token")


def digest_binds_all_four():
    _key()
    base = _mint()
    d0 = base["context_digest"]
    variants = [
        ({"agent_id": "agent-B"}, "agent_id"),
        ({"mission_id": "mission-Y"}, "mission_id"),
        ({"tool_set": ["send_email", "x"]}, "tool_set"),
        ({"policy_version": "policy-v4"}, "policy_version"),
    ]
    ok = True
    for kw, name in variants:
        d = _mint(**kw)["context_digest"]
        if d == d0:
            _record("digest-binds-%s" % name, "BREAK",
                    "context digest unchanged when %s changed" % name)
            ok = False
    if ok:
        _record("digest-binds-all-four", "HELD",
                "digest differs when exactly one bound input changes")
    # Stability: identical inputs -> identical digest (no randomness in
    # the binding; only the nonce varies).
    d_again = _mint()["context_digest"]
    if d_again == d0:
        _record("digest-stable", "HELD",
                "identical context mints the identical digest")
    else:
        _record("digest-stable", "BREAK",
                "identical context minted different digests")


def pin_taxonomy():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    if n != TAXONOMY_PIN:
        _record("pin-taxonomy", "BREAK",
                "taxonomy literals %d != pin %d" % (n, TAXONOMY_PIN))
    else:
        _record("pin-taxonomy", "HELD",
                "taxonomy pin %d holds" % TAXONOMY_PIN)


def footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    # Wave-341 merge footer: F428 OPEN (filed wave-341 lane C, LOW); next F429.
    # Footer lines repeat through history; the LAST one is current.
    m_open = re.findall(r"Open findings: ([^*]*)\.", text)
    ok = ("Next free finding: **F480**" in text  # Wave-356 merge: footer repoint
          and m_open and m_open[-1].strip() == "F476, F477")
    if ok:
        _record("footer-state", "HELD", "footer: open F436 / next F437")
    else:
        _record("footer-state", "BREAK",
                "footer mismatch vs open F429 / next F430")


_PROBES = [("mint-verify-roundtrip", mint_verify_roundtrip),
           ("refuse-agent-mismatch", refuse_agent_mismatch),
           ("refuse-mission-mismatch", refuse_mission_mismatch),
           ("refuse-tools-mismatch", refuse_tools_mismatch),
           ("refuse-policy-stale", refuse_policy_stale),
           ("refuse-tampered", refuse_tampered),
           ("refuse-expired", refuse_expired),
           ("refuse-malformed", refuse_malformed),
           ("inner-binding-preserved", inner_binding_preserved),
           ("digest-binds-all-four", digest_binds_all_four),
           ("pin-taxonomy", pin_taxonomy),
           ("footer-state", footer_state)]

# No expected BREAKs: every attack shape above is refused coded.
# Never {} (wave-331 lesson).
_EXPECTED_BREAKS = set()


def _run_root():
    d = os.path.join(tempfile.gettempdir(), "w333cap")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


def _run_child_output(battery, timeout=600):
    """Run a prior battery as a subprocess; return its raw stdout.

    GOV_SKIP_GREEN=1 in the child env (depth-1 green checks), fresh
    TMPDIR per child. Raises on timeout; returns text otherwise.
    """
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    tmpd = tempfile.mkdtemp(prefix="w333capchild-", dir=_run_root())
    env["TMPDIR"] = tmpd
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "evals", battery)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, cwd=REPO)
    return proc.stdout.decode("utf-8", "replace")


# Battery -> BREAK probe IDs that are NOT regressions on this tree.
# w313_aptokens is the adjacent seam (approval tokens). Its
# footer-state probe is stale (checks F413/F412; wave-319-class drift,
# pre-existing on base); its pin-taxonomy probe asserts 2069 and this
# lane moves the pin to 2069 (merge repoints) -- everything else must
# hold.
_CHILD_EXPECTED = {
    "w313_aptokens_probes.py": {"footer-state", "pin-taxonomy"},
}


def _green_check():
    """Depth-1 green check on the adjacent seam battery (fail-closed).

    Honors GOV_SKIP_GREEN (records a skip instead of spawning). Never
    spawns a battery that spawns another: depth-1 only.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    for battery, expected in _CHILD_EXPECTED.items():
        try:
            out = _run_child_output(battery)
        except Exception as exc:  # noqa: BLE001
            _record("green-check", "ERROR", "%s: %s" % (battery, exc))
            continue
        breaks = set(re.findall(r"^\s*\[BREAK\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        errors = set(re.findall(r"^\s*\[ERROR\]\s+([A-Za-z0-9_.\-]+)",
                                out, re.M))
        m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
        if m2:
            try:
                import ast as _ast
                breaks.update(_ast.literal_eval(m2.group(1)))
            except Exception:  # noqa: BLE001
                pass
        outside = breaks - expected
        if errors or outside:
            _record("green-check", "BREAK",
                    "%s: non-expected %s" % (battery, sorted(outside | errors)[:4]))
        else:
            _record("green-check", "HELD",
                    "%s: %d breaks, all expected" % (battery, len(breaks)))


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    # Collect EVERY record each probe emits (probes record multiple
    # sub-results); tallying only the last record per probe would miss
    # a BREAK buried mid-probe.
    del _results[:]
    for pid, fn in _PROBES:
        if only and only not in pid:
            continue
        _safe(pid, fn)
    first = list(_results)
    green = None
    if only is None:
        _green_check()
        green = _results[-1]
    del _results[:]
    for pid, fn in _PROBES:
        if only and only not in pid:
            continue
        _safe(pid, fn)
    second = list(_results)
    # Determinism compares probe verdicts only; the green-check record
    # is a single-runner observation, not a probe.
    det = ([v for _, v, _ in first] == [v for _, v, _ in second])
    tallied = first + ([green] if green else [])
    n_break = sum(1 for _, v, _ in tallied if v == "BREAK")
    n_held = sum(1 for _, v, _ in tallied if v == "HELD")
    n_err = sum(1 for _, v, _ in tallied if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in tallied
                    if v == "BREAK" and pid != "green-check"}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("----")
    print("w333_captoken battery: %d BREAK / %d HELD / %d ERROR "
          "(deterministic across 2 runs: %s)"
          % (n_break, n_held, n_err, det))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    if not det:
        print("NON-DETERMINISTIC across runs -- do not trust")
        return 2
    if n_err:
        print("ERRORs present -- battery failed closed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
