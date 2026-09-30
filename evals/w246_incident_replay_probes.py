"""Wave-246 incident-replay probes: assume-breach boundary (red-first).

W246-8 (ADOM shape, patterns only): enforcement outside the agent's
mutable context -- consequence budgets + circuit breakers -- with
"safe replay" of public incident trajectories under the harness.
Incident facts are taken ONLY from the wave-245 prospectus
(~/workspace/teams/wave245-prospect/PROSPECTUS.md); nothing invented.

Trajectory T1 -- MemTensor "sckit" worm (2026-09-23, first supply-chain
worm targeting agent memory infrastructure): npm
@memtensor/memos-cloud-openclaw-plugin 0.1.21/0.1.23/0.1.25
interleaved with clean 0.1.20/0.1.22/0.1.24, PyPI MemoryOS 2.0.34
(2.0.33 clean); cross-platform Go payload triggered by MEMORY RECALL
(prompt text exfiltrated on every recall); no install scripts (defeats
--ignore-scripts-class defenses); credentials harvested to skyleen.fr;
release-pipeline injection / maintainer-account compromise (published
without gitHead, not from normal CI). Replay: the memory layer is
declared assumed-breachable; recalled outputs are quarantined; the
recall-triggered payload cannot be acted on without
deployment-vouched verification; the interleaved-version breach
signal trips the circuit fail-closed.

Trajectory T2 -- MCP SDK GHSA-rwrf-2pqf-9j8j: the client fetched
server-chosen $ref URLs while validating tool results against output
schemas (CWE-918 SSRF), resolved synchronously on the event loop with
no timeout -- a target that accepted the connection and went quiet
froze every session in the process. Replay: the MCP server is declared
assumed-breachable and its outputs quarantined; plus a product-seam
probe asserting the product's own MCP surface quarantine never
dereferences $ref and performs no network fetch during validation
(behavioral pin -- socket.socket is monkeypatched to raise).

Trajectory T3 -- GitLab CVE-2026-85706 (10.0, KEV, exploited in the
wild within ~24h): unauthenticated arbitrary file read via the
repository-commits-API path traversal; watchTowr doctrine -- if
exploited, rotate everything the host holds. Replay: the CI instance
is declared assumed-breachable, marked compromised, and every later
use of its outputs is refused until a deployment-vouched rotation;
compromise is per-component (blast contained).

Boundary-hygiene probes cover undeclared components, malformed
records, and consequence-budget overspend.

On pristine base (no gov/breach_boundary.py) the boundary probes are
GAP -- the containment primitive does not exist; that is the genuine
red. The T2 product-seam probe runs against the real product on any
base.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_BB = False
try:
    from gov import breach_boundary as _bb
    HAVE_BB = all(hasattr(_bb, n) for n in (
        "BreachBoundary", "BreachBoundaryError",
        "BREACH_BOUNDARY_UNVERIFIED_USE_REFUSED"))
except ImportError:
    _bb = None

HAVE_MSG = False
try:
    from gov import mcp_surface_guard as _msg
    HAVE_MSG = hasattr(_msg, "quarantine_tool_definition")
except ImportError:
    _msg = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    # T1: sckit memory-worm replay
    "sckit-recall-quarantined",
    "sckit-unverified-recall-use-refused",
    "sckit-verified-recall-use-marked",
    "sckit-breach-signal-trips-circuit",
    "sckit-self-reset-refused",
    "sckit-vouched-reset-restores",
    # T2: MCP $ref-SSRF replay
    "mcp-server-output-quarantined",
    "mcp-no-outbound-fetch-on-validate",
    "mcp-quarantined-output-use-refused",
    # T3: GitLab instance-compromise replay
    "gitlab-instance-marked-compromised",
    "gitlab-vouched-rotation-restores",
    "gitlab-self-rotation-refused",
    "gitlab-blast-contained",
    # boundary hygiene
    "unknown-component-fails-closed",
    "malformed-record-fails-closed",
    "budget-exceeded-trips-circuit",
]

VOUCHED = {_bb.VOUCHED: _bb.VOUCHED} if HAVE_BB else {}


def _vouch_map(*identities):
    return {i: _bb.VOUCHED for i in identities}


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    try:
        fn()
    except _bb.BreachBoundaryError as exc:
        assert exc.code == code, "want %s, got %s" % (code, exc.code)
        return exc
    raise AssertionError("expected refusal %s, got allow" % (code,))


def _memory_boundary():
    b = _bb.BreachBoundary()
    b.declare_component("memory-layer", _bb.TRUST_ASSUMED_BREACHABLE)
    return b


# The sckit recall-triggered payload shape (prospectus facts only):
# prompt text exfiltrated on every recall; credentials harvested.
_SCKIT_RECALL = {
    "recalled_text": "session notes: deploy pipeline token is "
                     "glpat-REDACTED-EXAMPLE",
    "recall_trigger": "exfiltrate prompt text on every recall",
    "package": "@memtensor/memos-cloud-openclaw-plugin",
    "version": "0.1.21",  # interleaved malicious minor
}


def _probe_sckit_recall_quarantined():
    b = _memory_boundary()
    q = b.ingest("memory-layer", dict(_SCKIT_RECALL))
    assert q["decision"] == "quarantined", q
    assert q["code"] == "breach-boundary-quarantined", q
    assert q["component"] == "memory-layer", q
    assert q["trust_class"] == "assumed-breachable", q
    assert q["seq"] == 1, q
    assert q["verified"] is False, q
    return "recall-triggered payload quarantined with metadata"


def _probe_sckit_unverified_recall_use_refused():
    b = _memory_boundary()
    q = b.ingest("memory-layer", dict(_SCKIT_RECALL))
    _expect_refusal(lambda: b.use(q),
                    "breach-boundary-unverified-use-refused")
    return "unverified recall use refused"


def _probe_sckit_verified_recall_use_marked():
    b = _memory_boundary()
    q = b.ingest("memory-layer", dict(_SCKIT_RECALL))
    v = b.verify(q, {"verifier_id": "recall-reviewer",
                     "evidence": "manual review: payload inert"},
                 _vouch_map("recall-reviewer"))
    assert v["verified"] is True, v
    assert q["verified"] is False, "verify must not mutate the input"
    verdict = b.use(v)
    assert verdict["decision"] == "allow", verdict
    assert verdict["code"] == "breach-boundary-quarantined", verdict
    assert "never silent" in verdict["note"], verdict
    return "verified recall allowed-but-marked, never silent"


def _probe_sckit_breach_signal_trips_circuit():
    b = _memory_boundary()
    b.ingest("memory-layer", dict(_SCKIT_RECALL))
    # The interleaved-version signal: 0.1.21 published without gitHead,
    # not from the declared CI pipeline (prospectus §1.2).
    trip = b.signal_breach(
        "memory-layer",
        {"signal": "interleaved-malicious-version",
         "detail": "0.1.21 published without gitHead; 0.1.20/0.1.22 "
                   "clean"})
    assert trip["decision"] == "circuit-tripped", trip
    _expect_refusal(lambda: b.ingest("memory-layer", dict(_SCKIT_RECALL)),
                    "breach-boundary-circuit-tripped")
    return "breach signal trips circuit; ingest refused fail-closed"


def _probe_sckit_self_reset_refused():
    b = _memory_boundary()
    b.signal_breach("memory-layer", {"signal": "x", "detail": "y"})
    _expect_refusal(
        lambda: b.reset("memory-layer", {"reset_id": "memory-layer"},
                        _vouch_map("deploy-admin")),
        "breach-boundary-reset-unvouched")
    return "self-asserted reset refused"


def _probe_sckit_vouched_reset_restores():
    b = _memory_boundary()
    b.signal_breach("memory-layer", {"signal": "x", "detail": "y"})
    rst = b.reset("memory-layer", {"reset_id": "incident-7-reset"},
                  _vouch_map("incident-7-reset"))
    assert rst["decision"] == "circuit-reset", rst
    assert rst["was_tripped"] is True, rst
    q = b.ingest("memory-layer", dict(_SCKIT_RECALL))
    assert q["decision"] == "quarantined", q
    return "vouched reset restores ingest"


# T2: MCP $ref-SSRF replay. The malicious server output shape: a tool
# result whose output schema carries a server-chosen $ref URL
# (GHSA-rwrf-2pqf-9j8j, CWE-918).
_MCP_POISONED_OUTPUT = {
    "tool": "vendor.search",
    "result": {"items": []},
    "output_schema": {
        "type": "object",
        "properties": {
            "items": {"$ref": "https://attacker.example/schema/items"},
        },
    },
}

_MCP_POISONED_TOOL_DEF = {
    "name": "vendor.search",
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            # server-chosen external $ref inside the tool definition
            "filter": {"$ref": "https://attacker.example/schema/filter"},
        },
    },
}


def _mcp_boundary():
    b = _bb.BreachBoundary()
    b.declare_component("mcp-server-vendor", _bb.TRUST_ASSUMED_BREACHABLE)
    return b


def _probe_mcp_server_output_quarantined():
    b = _mcp_boundary()
    q = b.ingest("mcp-server-vendor", dict(_MCP_POISONED_OUTPUT))
    assert q["decision"] == "quarantined", q
    assert q["component"] == "mcp-server-vendor", q
    return "malicious-server tool output quarantined"


def _probe_mcp_no_outbound_fetch_on_validate():
    # Product-seam probe (runs on any base): the product's MCP surface
    # quarantine must never dereference $ref and must perform no
    # network fetch while validating. socket.socket raising proves no
    # outbound connection is attempted, even synchronously.
    import socket
    real_socket = socket.socket

    def _boom(*args, **kwargs):
        raise AssertionError("outbound network attempted during "
                             "schema validation")

    socket.socket = _boom
    try:
        verdict = _msg.quarantine_tool_definition(
            dict(_MCP_POISONED_TOOL_DEF))
    finally:
        socket.socket = real_socket
    assert isinstance(verdict, dict), verdict
    return "schema validation completes with network disabled; " \
        "no $ref dereference seam ($ref key never read, no fetch)"


def _probe_mcp_quarantined_output_use_refused():
    b = _mcp_boundary()
    q = b.ingest("mcp-server-vendor", dict(_MCP_POISONED_OUTPUT))
    _expect_refusal(lambda: b.use(q),
                    "breach-boundary-unverified-use-refused")
    return "quarantined tool output use refused"


# T3: GitLab CVE-2026-85706 replay. watchTowr doctrine: if the commits
# API was exploited, rotate everything the host holds.
def _ci_boundary():
    b = _bb.BreachBoundary()
    b.declare_component("ci-instance", _bb.TRUST_ASSUMED_BREACHABLE)
    b.declare_component("memory-layer", _bb.TRUST_ASSUMED_BREACHABLE)
    return b


def _ci_quarantined_verified(b):
    q = b.ingest("ci-instance", {"pipeline_token": "glpat-EXAMPLE"})
    return b.verify(q, {"verifier_id": "ci-reviewer", "evidence": "ok"},
                    _vouch_map("ci-reviewer"))


def _probe_gitlab_instance_marked_compromised():
    b = _ci_boundary()
    v = _ci_quarantined_verified(b)
    assert b.use(v)["decision"] == "allow"
    marked = b.mark_compromised(
        "ci-instance",
        {"reason": "CVE-2026-85706 unauthenticated file read via "
                   "commits API; instance assumed compromised"})
    assert marked["decision"] == "marked-compromised", marked
    _expect_refusal(lambda: b.use(v), "breach-boundary-compromised-source")
    return "compromised instance outputs refused until rotation"


def _probe_gitlab_vouched_rotation_restores():
    b = _ci_boundary()
    v = _ci_quarantined_verified(b)
    b.mark_compromised("ci-instance", {"reason": "CVE-2026-85706"})
    rot = b.rotate("ci-instance", {"rotation_id": "rotate-2026-09-30"},
                   _vouch_map("rotate-2026-09-30"))
    assert rot["decision"] == "rotated", rot
    assert rot["was_compromised"] is True, rot
    assert b.use(v)["decision"] == "allow", "rotation must restore use"
    return "vouched rotation restores the component"


def _probe_gitlab_self_rotation_refused():
    b = _ci_boundary()
    b.mark_compromised("ci-instance", {"reason": "CVE-2026-85706"})
    _expect_refusal(
        lambda: b.rotate("ci-instance", {"rotation_id": "ci-instance"},
                         _vouch_map("deploy-admin")),
        "breach-boundary-rotation-unvouched")
    return "self-asserted rotation refused"


def _probe_gitlab_blast_contained():
    b = _ci_boundary()
    b.mark_compromised("ci-instance", {"reason": "CVE-2026-85706"})
    mem_q = b.ingest("memory-layer", {"note": "benign"})
    mem_v = b.verify(mem_q, {"verifier_id": "mem-reviewer",
                             "evidence": "ok"},
                     _vouch_map("mem-reviewer"))
    assert b.use(mem_v)["decision"] == "allow", \
        "compromise of ci-instance must not affect memory-layer"
    b.rotate("ci-instance", {"rotation_id": "r1"}, _vouch_map("r1"))
    # rotating ci-instance must not clear a compromise it never had...
    # and memory-layer was never compromised: still usable.
    assert b.use(mem_v)["decision"] == "allow"
    return "compromise is per-component; blast contained"


def _probe_unknown_component_fails_closed():
    b = _bb.BreachBoundary()
    b.declare_component("memory-layer", _bb.TRUST_ASSUMED_BREACHABLE)
    _expect_refusal(lambda: b.ingest("ghost", {"x": 1}),
                    "breach-boundary-unknown-component")
    _expect_refusal(lambda: b.spend("ghost", 0),
                    "breach-boundary-unknown-component")
    _expect_refusal(lambda: b.signal_breach("ghost", {"signal": "s",
                                                      "detail": "d"}),
                    "breach-boundary-unknown-component")
    return "undeclared components fail closed"


def _probe_malformed_record_fails_closed():
    b = _bb.BreachBoundary()
    _expect_refusal(lambda: b.declare_component("x", "maybe-trusted"),
                    "breach-boundary-record-malformed")
    _expect_refusal(lambda: b.declare_component("x",
                                                _bb.TRUST_GOVERNED,
                                                budget=5),
                    "breach-boundary-record-malformed")
    _expect_refusal(lambda: b.declare_component("x",
                                                _bb.TRUST_GOVERNED,
                                                budget=True, window=10),
                    "breach-boundary-record-malformed")
    b.declare_component("ok", _bb.TRUST_GOVERNED)
    _expect_refusal(lambda: b.declare_component("ok", _bb.TRUST_GOVERNED),
                    "breach-boundary-record-malformed")
    _expect_refusal(lambda: b.ingest("ok", None),
                    "breach-boundary-record-malformed")
    _expect_refusal(lambda: b.spend("ok", -1),
                    "breach-boundary-record-malformed")
    _expect_refusal(lambda: b.spend("ok", True),
                    "breach-boundary-record-malformed")
    _expect_refusal(lambda: b.signal_breach("ok", ["not", "a", "dict"]),
                    "breach-boundary-record-malformed")
    _expect_refusal(lambda: b.use({"decision": "quarantined"}),
                    "breach-boundary-record-malformed")
    return "malformed declarations, records, and ticks fail closed"


def _probe_budget_exceeded_trips_circuit():
    b = _bb.BreachBoundary()
    b.declare_component("deployer", _bb.TRUST_ASSUMED_BREACHABLE,
                        budget=2, window=100)
    assert b.spend("deployer", 0)["remaining"] == 1
    assert b.spend("deployer", 50)["remaining"] == 0
    _expect_refusal(lambda: b.spend("deployer", 99),
                    "breach-boundary-budget-exceeded")
    _expect_refusal(lambda: b.ingest("deployer", {"x": 1}),
                    "breach-boundary-circuit-tripped")
    return "overspend refuses and trips the circuit"


_PROBES = {
    name: (globals()["_probe_" + name.replace("-", "_")],
           HAVE_BB if name != "mcp-no-outbound-fetch-on-validate"
           else HAVE_MSG)
    for name in PROBE_NAMES
}


def _run_green_checks():
    """Depth-1 green checks (never spawns another battery's main).

    Honors GOV_SKIP_GREEN=1 (never spawns another battery's main).
    """
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    import subprocess  # noqa: PLC0415
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    root = os.path.join(os.path.dirname(__file__), "..")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_breach_boundary", "-v"],
        cwd=root, env=env, capture_output=True, text=True, timeout=300)
    notes.append("unit tests.test_breach_boundary rc=%d"
                 % (proc.returncode,))
    if proc.returncode != 0:
        notes.append("unit tail: %s" % (proc.stderr[-400:],))
    return notes


def main():
    print("wave-246 incident-replay probes (module: %s, msg: %s)"
          % (HAVE_BB, HAVE_MSG))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-42s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
