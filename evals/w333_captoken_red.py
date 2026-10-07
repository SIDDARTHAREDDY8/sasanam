#!/usr/bin/env python3
"""Wave-333 lane 3 RED battery: cross-context approval replay on the BASE tree.

Prospectus ADAPT #1 (EmpowerID/Omada): bind every approval to
SHA256(agent_id || mission_id || tool set || policy version). This
battery proves the gap FIRST, at the public seam, before the fix
lands: on the base tree the approval-token seam
(``gov/approval_tokens.py`` -- the portable approval artifact) binds
capability + arguments + issuer + key epoch, but NOT the presenting
agent, the mission, the mission's tool set, or the policy version. A
token minted for agent A / mission X verifies byte-identically for
agent B / mission Y, after a policy rotation, and after the tool set
drifts.

Verdicts:
  HELD  = behavior matches the pin (attack refused coded);
  BREAK = the replay SUCCEEDS (the documented gap -- expected here);
  ERROR = probe/harness problem.

These BREAKs are EXPECTED (``_EXPECTED_BREAKS`` below): they document
the known prospectus gap, not a new finding -- no F-number is filed
for them. The answer is the new ``gov/capability_token.py`` module
(regression battery ``evals/w333_captoken_probes.py``); the old
``approval_tokens`` seam is intentionally untouched by this lane, so
these probes still BREAK after the lane lands (documented residual).

Probe map:
  P1a-cross-agent-replay: token minted for agent A verifies for agent B.
  P1b-cross-mission-replay: token minted for mission X verifies for
      mission Y.
  P1c-post-policy-rotation-replay: token minted under policy-v3 verifies
      after rotation to policy-v4.
  P1d-tool-set-drift-replay: token minted when the mission allowed
      {send_email} verifies after the tool set widened to
      {send_email, delete_file}.
  pin-taxonomy / footer-state: standard pins (2100; open none / next F419).

Deterministic across 2 runs; $0 spend; synthetic/local. Stdlib only
apart from gov/approval_tokens.py (real product code, no stubs).

Run:
  mkdir -p /var/tmp/g333-red
  TMPDIR=/var/tmp/g333-red ~/workspace/.gov-venv/bin/python evals/w333_captoken_red.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g333-redb ~/workspace/.gov-venv/bin/python evals/w333_captoken_red.py
Single-probe mode:
  ~/workspace/.gov-venv/bin/python evals/w333_captoken_red.py P1a
"""

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

from gov import approval_tokens as AT  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
# lane 3. The 4 red probes still BREAK (documented prospectus gap); the
# old approval_tokens seam is untouched by this lane.
# (agent/mission/tools/policy-stale/malformed/tampered/expired), wave-333
# lane 3. The 4 red probes still BREAK (documented prospectus gap); the
# old approval_tokens seam is untouched by this lane.

_NOW = 1798765432
_BENIGN = {"to": "teammate@synthetic.local", "body": "weekly report"}

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


def _mint(agent, mission, policy_version, tool_set):
    """Mint an approval token in a documented context. The context is
    recorded OUTSIDE the token (the gap): the token itself carries no
    agent/mission/policy/tool-set binding, so the docstring context is
    the only thing distinguishing the mint contexts below."""
    _key()
    return AT.issue_token(
        capability="send_email",
        argument_binding={"mode": "exact", "args": dict(_BENIGN)},
        issuer=agent, ttl_seconds=3600, issued_at=_NOW)


def _replay_ok(token):
    """True when the token verifies at the public seam with NO presenter
    context at all -- verify_token takes no agent, mission, policy, or
    tool-set parameter."""
    try:
        AT.verify_token(token, capability="send_email",
                        args=dict(_BENIGN), now=_NOW)
        return True
    except AT.ApprovalTokenError:
        return False


# ---------------------------------------------------------------------------
# Red probes: each demonstrates a cross-context replay SUCCEEDING on base.
# ---------------------------------------------------------------------------

def P1a():
    # Minted for agent A (mission X, policy v3, tools {send_email});
    # presented by agent B. No agent parameter exists at the seam.
    tok = _mint("agent-A", "mission-X", "policy-v3", ["send_email"])
    if _replay_ok(tok):
        _record("P1a", "BREAK",
                "cross-agent replay SUCCEEDS on base: agent-A approval "
                "token verifies for agent-B presenter (no agent binding)")
    else:
        _record("P1a", "HELD",
                "agent-A token refused for agent-B presenter")


def P1b():
    # Minted for mission X; presented for mission Y. No mission binding.
    tok = _mint("agent-A", "mission-X", "policy-v3", ["send_email"])
    if _replay_ok(tok):
        _record("P1b", "BREAK",
                "cross-mission replay SUCCEEDS on base: mission-X approval "
                "token verifies for mission-Y presenter (no mission binding)")
    else:
        _record("P1b", "HELD",
                "mission-X token refused for mission-Y presenter")


def P1c():
    # Minted under policy-v3; presented after rotation to policy-v4.
    # The key epoch binds the HMAC key, not the policy version.
    tok = _mint("agent-A", "mission-X", "policy-v3", ["send_email"])
    if _replay_ok(tok):
        _record("P1c", "BREAK",
                "post-rotation replay SUCCEEDS on base: policy-v3 approval "
                "token verifies under policy-v4 (no policy binding)")
    else:
        _record("P1c", "HELD",
                "policy-v3 token refused under policy-v4")


def P1d():
    # Minted when the mission's tool set was {send_email}; presented
    # after the tool set widened to {send_email, delete_file}. The
    # token binds one capability, not the mission's tool set.
    tok = _mint("agent-A", "mission-X", "policy-v3", ["send_email"])
    if _replay_ok(tok):
        _record("P1d", "BREAK",
                "tool-set-drift replay SUCCEEDS on base: token minted for "
                "tool set {send_email} verifies after widening to "
                "{send_email, delete_file} (no tool-set binding)")
    else:
        _record("P1d", "HELD",
                "token refused after tool-set widening")


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
    # This lane files no findings. Footer lines repeat through history;
    # the LAST one is current.
    m_open = re.findall(r"Open findings: ([^*]*)\.", text)
    ok = ("Next free finding: **F570**" in text  # Wave-356 merge: footer repoint  # Wave-357 merge: F478, F479 CLOSED (next F481); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
          and m_open and m_open[-1].strip() == "F547, F548, F549, F550, F551, F552, F553, F554, F555, F556, F557, F558, F559, F560, F561, F562, F563, F564, F565, F566, F567, F568, F569")  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
    if ok:
        _record("footer-state", "HELD", "footer: open F436 / next F437")
    else:
        _record("footer-state", "BREAK",
                "footer mismatch vs open F429 / next F430")


_PROBES = [("P1a", P1a), ("P1b", P1b), ("P1c", P1c), ("P1d", P1d),
           ("pin-taxonomy", pin_taxonomy), ("footer-state", footer_state)]

# Expected BREAKs: the documented prospectus gap (EmpowerID/Omada ADAPT
# #1). The new gov/capability_token.py module is the answer; the old
# approval_tokens seam is untouched by this lane, so these stay BREAK
# after the lane lands. Never {} (wave-331 lesson).
_EXPECTED_BREAKS = {"P1a", "P1b", "P1c", "P1d"}


def _run_root():
    d = os.path.join(tempfile.gettempdir(), "w333red")
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
    tmpd = tempfile.mkdtemp(prefix="w333redchild-", dir=_run_root())
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
    first = []
    for pid, fn in _PROBES:
        if only and only not in pid:
            continue
        _safe(pid, fn)
        first.append(_results[-1])
    green = None
    if only is None:
        _green_check()
        green = _results[-1]
    second = []
    for pid, fn in _PROBES:
        if only and only not in pid:
            continue
        n0 = len(_results)
        _safe(pid, fn)
        second.append(_results[-1])
        del _results[n0:]
    # Determinism compares probe verdicts only; the green-check record
    # is a single-runner observation, not a probe.
    det = ([v for _, v, _ in first] == [v for _, v, _ in second])
    tallied = first + ([green] if green else [])
    n_break = sum(1 for _, v, _ in tallied if v == "BREAK")
    n_held = sum(1 for _, v, _ in tallied if v == "HELD")
    n_err = sum(1 for _, v, _ in tallied if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in tallied
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("----")
    print("w333_captoken_red battery: %d BREAK / %d HELD / %d ERROR "
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
