#!/usr/bin/env python3
"""Wave-176 lane: AuthorityProof-style authority-boundary contract battery.

Steal verdict #1 from the NVIDIA OpenShell prospectus
(teams/prospecting-nvidia-openshell/PROSPECTUS_NVIDIA.md): the explicit
proof-result contract -- within_boundary / exceeds_boundary /
unsupported / inconclusive + coverage domains + counterexample, with
unknown/unsupported failing closed.

The product seam: gov.authority_proof.check(action, ctx, boundary) is a
pure, deterministic, stdlib-only checker over what the policy engine
actually models (filesystem paths via ctx["path_resolved"] / declared
path, egress hosts via url/endpoint/to). It is wired at the executor's
policy pre-decision path AND the approved sweep (same layering as the
F190 canonical-target and wave-174 display=execution checks):

  * boundary declared  -> enforcing: exceeds/unsupported/inconclusive
                         refuse FAIL-CLOSED (loud audit), before any
                         side effect. within_boundary proceeds under
                         the normal policy verdict (it never upgrades
                         a deny).
  * boundary None      -> advisory: the proof is attached to the
                         decision record with uncovered domains, the
                         policy verdict stands. (Refusing every action
                         for a boundary the operator never wrote would
                         be the governor DoS-ing its own deployment.)

Probes:
  within_boundary_filesystem   -- write inside the declared prefixes ->
                                 within_boundary, no counterexample.
  exceeds_boundary_counterexample -- write outside -> exceeds_boundary
                                 with a concrete counterexample naming
                                 the exact path + nearest boundary rule.
  exceeds_egress_counterexample   -- http_post to a non-allowlisted host
                                 -> exceeds_boundary + counterexample.
  unsupported_escape_shape     -- "../../etc/passwd" style escape is
                                 unsupported, NEVER silently normalized
                                 into an allowed path.
  unsupported_unparseable_url  -- unparseable egress URL -> unsupported.
  inconclusive_no_boundary     -- boundary=None -> inconclusive with
                                 all domains uncovered; the executor
                                 does NOT refuse (advisory), but the
                                 proof is attached to the record.
  inconclusive_budget_cap      -- max_accesses=0 forces inconclusive
                                 (bounded evaluation, no hangs).
  boundary_load_rejects_malformed -- relative prefixes / wildcard hosts
                                 raise BoundaryError at load, loud.
  executor_refuses_exceeds     -- end-to-end: declared boundary +
                                 outside write -> denied, flag
                                 authority_boundary_refused, file NOT
                                 created (fail-closed, no side effect).
  executor_within_proceeds     -- boundary covers the path -> the
                                 normal allow path runs, file created,
                                 audit carries the within proof.
  executor_unsupported_refuses -- declared boundary + escape path ->
                                 denied (unsupported fails closed).
  sweep_refuses_exceeds        -- TOCTOU: record queued + approved while
                                 the boundary allows it, boundary then
                                 tightened -> the sweep refuses with
                                 authority_boundary_exceeded, file NOT
                                 created.
  contract_legibility          -- every proof carries covered_domains +
                                 uncovered_domains; the module exposes
                                 no allow/permit API (a proof can never
                                 grant authority by itself).
  determinism                  -- the whole battery runs twice
                                 in-process; verdicts must agree.

Deterministic; synthetic/local only; $0.
"""

import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "authority-proof-battery")

REPO_ROOT = str(Path(__file__).resolve().parents[1])
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from gov import authority_proof  # noqa: E402
    HAVE_MODULE = True
    IMPORT_ERROR = None
except Exception as e:  # noqa: BLE001 -- red phase must be loud
    authority_proof = None
    HAVE_MODULE = False
    IMPORT_ERROR = e

from harness import make_run  # noqa: E402
from gov.policy import PolicyDecision  # noqa: E402

_records = []


def _record(name, verdict, detail):
    _records.append((name, verdict, detail))


def _require_module(name):
    if not HAVE_MODULE:
        return ("FAIL", "gov.authority_proof unavailable: %r" % (IMPORT_ERROR,))
    return None


def _boundary(fs_read=(), fs_write=(), egress=()):
    return authority_proof.boundary_from_dict({
        "boundary_id": "battery-boundary",
        "version": "1",
        "fs_read_prefixes": list(fs_read),
        "fs_write_prefixes": list(fs_write),
        "egress_hosts": list(egress),
    })


def _action(tool, args):
    return {"tool": tool, "args": dict(args),
            "agent_id": "battery-agent", "role": "coder"}


def p_within_boundary_filesystem():
    """Write inside the declared prefixes -> within_boundary."""
    name = "within_boundary_filesystem"
    miss = _require_module(name)
    if miss:
        return miss
    b = _boundary(fs_write=("/allowed",))
    proof = authority_proof.check(
        _action("write_file", {"path": "/allowed/sub/file.txt"}),
        {"path_resolved": "/allowed/sub/file.txt"}, b)
    ok = (proof.verdict == "within_boundary"
          and proof.counterexample is None
          and "filesystem" in proof.covered_domains
          and "process_identity" in proof.uncovered_domains)
    return ("PASS" if ok else "FAIL",
            "verdict=%s covered=%s uncovered=%s" % (
                proof.verdict, proof.covered_domains,
                proof.uncovered_domains))


def p_exceeds_boundary_counterexample():
    """Write outside the boundary -> exceeds + concrete counterexample."""
    name = "exceeds_boundary_counterexample"
    miss = _require_module(name)
    if miss:
        return miss
    b = _boundary(fs_write=("/allowed",))
    proof = authority_proof.check(
        _action("write_file", {"path": "/etc/cron.d/evil"}),
        {"path_resolved": "/etc/cron.d/evil"}, b)
    ce = proof.counterexample
    ok = (proof.verdict == "exceeds_boundary"
          and ce is not None
          and ce.domain == "filesystem"
          and ce.access == "/etc/cron.d/evil"
          and ce.nearest_rule == "/allowed")
    return ("PASS" if ok else "FAIL",
            "verdict=%s counterexample=%r" % (proof.verdict, ce))


def p_exceeds_egress_counterexample():
    """Egress to a non-boundary host -> exceeds + counterexample."""
    name = "exceeds_egress_counterexample"
    miss = _require_module(name)
    if miss:
        return miss
    b = _boundary(egress=("api.internal",))
    proof = authority_proof.check(
        _action("http_post",
                {"url": "https://exfil.example/collect"}),
        {}, b)
    ce = proof.counterexample
    ok = (proof.verdict == "exceeds_boundary"
          and ce is not None
          and ce.domain == "egress"
          and ce.access == "exfil.example")
    return ("PASS" if ok else "FAIL",
            "verdict=%s counterexample=%r" % (proof.verdict, ce))


def p_unsupported_escape_shape():
    """A '..' escape is unsupported, never silently normalized-allowed."""
    name = "unsupported_escape_shape"
    miss = _require_module(name)
    if miss:
        return miss
    b = _boundary(fs_write=("/allowed",))
    proof = authority_proof.check(
        _action("write_file", {"path": "/allowed/../../etc/passwd"}),
        {}, b)
    ok = (proof.verdict == "unsupported")
    return ("PASS" if ok else "FAIL",
            "verdict=%s detail=%r" % (proof.verdict, proof.detail))


def p_unsupported_unparseable_url():
    """An unparseable egress URL -> unsupported (fail-closed shape)."""
    name = "unsupported_unparseable_url"
    miss = _require_module(name)
    if miss:
        return miss
    b = _boundary(egress=("api.internal",))
    proof = authority_proof.check(
        _action("http_post", {"url": "::::not-a-url"}), {}, b)
    ok = (proof.verdict == "unsupported")
    return ("PASS" if ok else "FAIL",
            "verdict=%s detail=%r" % (proof.verdict, proof.detail))


def p_inconclusive_no_boundary():
    """No declared boundary -> inconclusive, all domains uncovered."""
    name = "inconclusive_no_boundary"
    miss = _require_module(name)
    if miss:
        return miss
    proof = authority_proof.check(
        _action("write_file", {"path": "/anywhere/x"}), {}, None)
    ok = (proof.verdict == "inconclusive"
          and proof.covered_domains == ()
          and set(proof.uncovered_domains)
          == {"filesystem", "egress", "process_identity"}
          and proof.counterexample is None)
    return ("PASS" if ok else "FAIL",
            "verdict=%s uncovered=%s" % (
                proof.verdict, proof.uncovered_domains))


def p_inconclusive_budget_cap():
    """Bounded evaluation: max_accesses=0 forces inconclusive."""
    name = "inconclusive_budget_cap"
    miss = _require_module(name)
    if miss:
        return miss
    b = _boundary(fs_write=("/allowed",))
    proof = authority_proof.check(
        _action("write_file", {"path": "/allowed/x"}),
        {"path_resolved": "/allowed/x"}, b, max_accesses=0)
    ok = (proof.verdict == "inconclusive"
          and "budget" in proof.detail.lower())
    return ("PASS" if ok else "FAIL",
            "verdict=%s detail=%r" % (proof.verdict, proof.detail))


def p_boundary_load_rejects_malformed():
    """Malformed operator boundaries fail LOUD at load, never silent."""
    name = "boundary_load_rejects_malformed"
    miss = _require_module(name)
    if miss:
        return miss
    bad = 0
    try:
        authority_proof.boundary_from_dict({
            "boundary_id": "bad", "version": "1",
            "fs_write_prefixes": ["relative/nope"]})
    except authority_proof.BoundaryError:
        bad += 1
    try:
        authority_proof.boundary_from_dict({
            "boundary_id": "bad", "version": "1",
            "egress_hosts": ["*.example"]})
    except authority_proof.BoundaryError:
        bad += 1
    try:
        authority_proof.boundary_from_dict({
            "boundary_id": "", "version": "1"})
    except authority_proof.BoundaryError:
        bad += 1
    ok = (bad == 3)
    return ("PASS" if ok else "FAIL", "rejected=%d/3 malformed" % bad)


def _policy():
    src = Path(REPO_ROOT, "policies", "default.yaml").read_text()
    src = src.replace("max_identical_calls: 10",
                      "max_identical_calls: 100000")
    src = src.replace("max_writes_per_run: 50",
                      "max_writes_per_run: 100000")
    path = Path(tempfile.mkdtemp(dir=os.environ["TMPDIR"]), "policy.yaml")
    path.write_text(src)
    return str(path)


def _setup(tag):
    ctx = make_run(policy_path=_policy())
    ident = ctx["executor"].mint_identity("authproof-%s" % tag, "coder",
                                         "authproof-p")
    return ctx, ident


def _refusals(ctx, flag):
    return [e for e in ctx["read_log"]()
            if isinstance(e, dict)
            and e.get("event") == "approval_execution_refused"
            and e.get("flag") == flag]


def _denied_entries(ctx):
    return [e for e in ctx["read_log"]()
            if isinstance(e, dict)
            and e.get("decision") == "denied"
            and e.get("flag") == "authority_boundary_refused"]


def p_executor_refuses_exceeds():
    """Declared boundary + outside write -> denied, no side effect."""
    name = "executor_refuses_exceeds"
    miss = _require_module(name)
    if miss:
        return miss
    ctx, ident = _setup("refuse")
    ex = ctx["executor"]
    ex.set_authority_boundary(_boundary(fs_write=("/allowed",)))
    target = str(Path(ex.sandbox) / "authproof-outside.txt")
    r = ex.call(ident, "write_file", path=target, content="nope")
    denied = _denied_entries(ctx)
    landed = Path(target).exists()
    ok = (r.get("status") == "denied"
          and r.get("policy_id") == "authority-boundary"
          and len(denied) == 1
          and denied[0].get("authority_proof", {}).get("verdict")
          == "exceeds_boundary"
          and not landed)
    return ("PASS" if ok else "FAIL",
            "status=%r denials=%d landed=%s" % (
                r.get("status"), len(denied), landed))


def p_executor_within_proceeds():
    """Boundary covers the path -> normal allow path runs."""
    name = "executor_within_proceeds"
    miss = _require_module(name)
    if miss:
        return miss
    ctx, ident = _setup("within")
    ex = ctx["executor"]
    ex.set_authority_boundary(_boundary(fs_write=(str(ex.sandbox),)))
    target = str(Path(ex.sandbox) / "authproof-inside.txt")
    r = ex.call(ident, "write_file", path=target, content="yes")
    ok = (r.get("status") in ("allowed", "executed")
          and Path(target).exists())
    return ("PASS" if ok else "FAIL",
            "status=%r file_exists=%s" % (
                r.get("status"), Path(target).exists()))


def p_executor_unsupported_refuses():
    """Declared boundary + escape-shaped path -> denied (fail-closed).

    Note: the executor pre-resolves the escape through
    ``_resolved_path_for_policy`` (F146/F147), so the seam sees the
    attested outside target and reports exceeds_boundary rather than
    unsupported -- both are non-within and both refuse. The pure
    unsupported-escape shape is covered by
    p_unsupported_escape_shape at the checker seam.
    """
    name = "executor_unsupported_refuses"
    miss = _require_module(name)
    if miss:
        return miss
    ctx, ident = _setup("unsup")
    ex = ctx["executor"]
    ex.set_authority_boundary(_boundary(fs_write=(str(ex.sandbox),)))
    target = str(Path(ex.sandbox) / "authproof-escape.txt")
    r = ex.call(ident, "write_file",
                path=str(Path(ex.sandbox) / ".." / ".." / "etc" / "x"),
                content="nope")
    denied = _denied_entries(ctx)
    proof = (denied[0].get("authority_proof", {}) if denied else {})
    ok = (r.get("status") == "denied"
          and len(denied) == 1
          and proof.get("verdict") in ("unsupported", "exceeds_boundary")
          and not Path(target).exists())
    return ("PASS" if ok else "FAIL",
            "status=%r denials=%d proof_verdict=%r" % (
                r.get("status"), len(denied), proof.get("verdict")))


def _queue_direct(ctx, ident, tool, args, preview):
    return ctx["approvals"].queue(
        {"tool": tool, "args": args,
         "identity": ident.as_dict(),
         "agent_justification": "authority-proof battery",
         "redactions": []},
        PolicyDecision("require_approval", "battery write",
                       policy_id="battery", flag="battery"),
        "agent_direct", preview,
        policy_hash=ctx["executor"].policy.policy_hash,
        caller_identity=ident)


def _approve_and_sweep(ctx, aid):
    ctx["approvals"].decide(aid, True, reason="looks fine",
                           decided_by="human-operator")
    done = ctx["executor"].execute_approved()
    return [d for d in done if isinstance(d, dict)]


def p_sweep_refuses_exceeds():
    """TOCTOU: boundary tightened after approval -> sweep refuses."""
    name = "sweep_refuses_exceeds"
    miss = _require_module(name)
    if miss:
        return miss
    ctx, ident = _setup("sweep")
    ex = ctx["executor"]
    target = str(Path(ex.sandbox) / "authproof-sweep.txt")
    args = {"path": target, "content": "sweep-bytes"}
    # Queue + approve while the boundary ALLOWS the write ...
    ex.set_authority_boundary(_boundary(fs_write=(str(ex.sandbox),)))
    preview = ex._preview("write_file", args)
    aid = _queue_direct(ctx, ident, "write_file", args, preview)
    ctx["approvals"].decide(aid, True, reason="looks fine",
                           decided_by="human-operator")
    # ... then the operator tightens the boundary before the sweep.
    ex.set_authority_boundary(_boundary(fs_write=("/allowed",)))
    done = ex.execute_approved()
    executed = [d for d in done if isinstance(d, dict)]
    refusals = _refusals(ctx, "authority_boundary_exceeded")
    landed = Path(target).exists()
    ok = (len(refusals) == 1 and not executed and not landed)
    return ("PASS" if ok else "FAIL",
            "sweep_refusals=%d executed=%d landed=%s" % (
                len(refusals), len(executed), landed))


def p_contract_legibility():
    """Every proof names its coverage; a proof can never grant."""
    name = "contract_legibility"
    miss = _require_module(name)
    if miss:
        return miss
    b = _boundary(fs_write=("/allowed",))
    proof = authority_proof.check(
        _action("write_file", {"path": "/allowed/x"}),
        {"path_resolved": "/allowed/x"}, b)
    d = proof.to_dict()
    ok = (set(("covered_domains", "uncovered_domains", "verdict",
               "counterexample", "boundary_id", "detail")) <= set(d)
          and not hasattr(authority_proof, "allow")
          and not hasattr(authority_proof, "permit")
          and not hasattr(proof, "allowed"))
    return ("PASS" if ok else "FAIL",
            "keys=%s" % sorted(d))


PROBES = [
    p_within_boundary_filesystem,
    p_exceeds_boundary_counterexample,
    p_exceeds_egress_counterexample,
    p_unsupported_escape_shape,
    p_unsupported_unparseable_url,
    p_inconclusive_no_boundary,
    p_inconclusive_budget_cap,
    p_boundary_load_rejects_malformed,
    p_executor_refuses_exceeds,
    p_executor_within_proceeds,
    p_executor_unsupported_refuses,
    p_sweep_refuses_exceeds,
    p_contract_legibility,
]


def _run_once():
    _records.clear()
    for probe in PROBES:
        try:
            verdict, detail = probe()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, detail = "ERROR", "%s: %s" % (
                type(e).__name__, e)
        _record(probe.__name__, verdict, detail)
    return list(_records)


def _green_check_adjacent():
    """Depth-1 green check: adjacent unit tests, GOV_SKIP_GREEN honored."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                "tests/test_authority_proof.py standalone for depth")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_authority_proof",
         "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    ok = (r.returncode == 0)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if ok else "FAIL",
            "tests.test_authority_proof rc=%d %s" % (r.returncode, tail[0]))


def main():
    first = _run_once()
    second = _run_once()  # determinism: identical verdicts twice
    det_ok = ([(n, v) for n, v, _ in first]
              == [(n, v) for n, v, _ in second])
    _record("determinism",
            "PASS" if det_ok else "FAIL",
            "two in-process runs agree on all %d probes" % len(PROBES)
            if det_ok else "MISMATCH between run 1 and run 2")
    gv, gd = _green_check_adjacent()
    _record("green_check_adjacent_units", gv, gd)
    npass = sum(1 for _, v, _ in _records if v == "PASS")
    nfail = sum(1 for _, v, _ in _records if v in ("FAIL", "ERROR"))
    print("== authority_proof battery ==")
    for n, v, d in _records:
        print("[%s] %s -- %s" % (v, n, d))
    print("PASS=%d FAIL/ERROR=%d" % (npass, nfail))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
