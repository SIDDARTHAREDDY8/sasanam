#!/usr/bin/env python3
"""Red-first break battery for wave-199: PolicyReport-shaped telemetry.

The gap (pristine tree): the graduation ladder keeps its violation
telemetry in an in-memory ModeLedger and the executor's hash-chained
audit log. An offline auditor holding ONLY the evidence-bundle
artifacts has no signed, per-rule, PolicyReport-shaped telemetry to
attribute a warning to its (policy, rule) -- they must correlate
scattered log entries by hand, with no canonical record and no
signature. ``gov.policy_report`` does not exist on the pristine tree.

Pristine expectation: P0-P1 BREAK (the gap), P2-P9 EXPECTED (cannot
run without the module -- recorded, not faked green).
Fixed expectation: P0-P9 HELD.

Stdlib only. Deterministic (seeded clock; fixed synthetic traffic).
Sets GOV_DEPLOYMENT_MODE=staging at module level; verify standalone
under ``env -u GOV_DEPLOYMENT_MODE``. Honors GOV_SKIP_GREEN=1 (green
check is depth-1: the adjacent unit suite only, never nested battery
mains).
"""

import importlib.util
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"
_HAS_MODULE = importlib.util.find_spec("gov.policy_report") is not None

MARKER = "SENSITIVE-REQUEST-CONTENT-MARKER-199"


def _ledger_with_traffic():
    """ModeLedger with observe hits, warn hits, and a mode change.

    Seeded clock for determinism. request content carries MARKER so
    the material-free probe can prove it never lands in the report.
    """
    from gov import mode_ledger as ml
    t = [1700000000.0]

    def clock():
        t[0] += 1.0
        return t[0]

    ledger = ml.ModeLedger(clock=clock)
    ledger.register_rule("r-observe", mode="observe")
    ledger.register_rule("r-warn", mode="warn")
    ledger.register_rule("r-deny", mode="deny")
    ledger.register_rule("r-note", mode="warn")
    digest_o = "reqdigest-" + "0" * 56
    digest_w = "reqdigest-" + "1" * 56
    ledger.observe("r-observe", mode="observe", matched=True,
                   nominal_effect="deny", request_digest=digest_o)
    ledger.observe("r-observe", mode="observe", matched=False)
    ledger.observe("r-warn", mode="warn", matched=True,
                   nominal_effect="queue", request_digest=digest_w)
    ledger.observe("r-deny", mode="deny", matched=True,
                   nominal_effect="deny", request_digest=digest_o)
    # Canary: an extra payload field on a chained record. The
    # projector whitelists fields; P4 proves this canary never
    # reaches the report bytes.
    ledger._append("violation", "r-note", {
        "mode": "warn", "nominal_effect": "allow",
        "request_digest": "d-note", "note": MARKER})
    return ledger, digest_o, digest_w


def _sealed(ledger, policy_name="policy:genesis"):
    from gov import policy_report as pr
    from gov.signing import Ed25519Signer
    signer = Ed25519Signer(bytes(range(32)))
    report = pr.build_report(ledger, policy_name=policy_name,
                             policy_version="v3")
    envelope = pr.seal_report(report, signer)
    return pr, signer, report, envelope


# ---------------------------------------------------------------- probes

def p0_projector_present():
    """gov.policy_report exists with the full public seam."""
    if not _HAS_MODULE:
        return "BREAK", "gov.policy_report absent (pristine gap)"
    from gov import policy_report as pr
    for name in ("build_report", "seal_report", "verify_report",
                 "emit_policy_report", "project_result",
                 "PolicyReportError"):
        if not hasattr(pr, name):
            return "BREAK", "missing seam %r" % (name,)
    return "HELD", "full seam present"


def p1_auditor_attribution():
    """Auditor can attribute every warning to (policy, rule), signed."""
    if not _HAS_MODULE:
        return "BREAK", ("auditor has no signed per-rule telemetry: "
                         "no projector on pristine tree")
    pr, signer, report, envelope = _sealed(_ledger_with_traffic()[0])
    if not pr.verify_report(envelope, signer.public_key):
        return "BREAK", "sealed report does not verify"
    by_rule = {}
    for r in envelope["report"]["results"]:
        by_rule.setdefault(r["rule"], []).append(r["result"])
    if by_rule.get("r-observe") != ["skip"]:
        return "BREAK", "observe hit not attributed as skip: %r" % (by_rule,)
    if by_rule.get("r-warn") != ["warn"]:
        return "BREAK", "warn hit not attributed as warn: %r" % (by_rule,)
    for r in envelope["report"]["results"]:
        if r["policy"] != "policy:genesis" or not r["rule"]:
            return "BREAK", " unattributed result: %r" % (r,)
    return "HELD", "every warning attributed to (policy, rule), signed"


def p2_result_shape():
    """Every result carries the Kyverno-adapted shape, material-free."""
    if not _HAS_MODULE:
        return "EXPECTED", "module absent on pristine tree"
    pr, signer, report, envelope = _sealed(_ledger_with_traffic()[0])
    need = {"source", "policy", "rule", "resources", "result",
            "severity", "category", "message", "timestamp", "properties"}
    for r in envelope["report"]["results"]:
        missing = need - set(r)
        if missing:
            return "BREAK", "missing keys %r" % (missing,)
        for res in r["resources"]:
            if set(res) != {"kind", "uid"} or \
                    res["kind"] != "sasanam/request":
                return "BREAK", "resource not request-identity: %r" % (res,)
    return "HELD", "shape complete; resources are request digests only"


def p3_mode_mapping():
    """observe->skip, warn->warn, mode_change->pass (documented map)."""
    if not _HAS_MODULE:
        return "EXPECTED", "module absent on pristine tree"
    pr = importlib.import_module("gov.policy_report")
    from gov import mode_ledger as ml
    t = [1700000000.0]
    ledger = ml.ModeLedger(clock=lambda: t.__setitem__(0, t[0] + 1.0)
                           or t[0])
    ledger.register_rule("o", mode="observe")
    ledger.register_rule("w", mode="warn")
    ledger.observe("o", mode="observe", matched=True,
                   nominal_effect="deny", request_digest="d-o")
    ledger.observe("w", mode="warn", matched=True,
                   nominal_effect="allow", request_digest="d-w")
    recs = [r for r in ledger._chain if r["kind"] == "violation"]
    got = {r["rule_id"]: pr.project_result(
        r, policy_name="p")["result"] for r in recs}
    if got != {"o": "skip", "w": "warn"}:
        return "BREAK", "mapping wrong: %r" % (got,)
    return "HELD", "observe->skip, warn->warn"


def p4_material_free():
    """Request content never lands in the report bytes."""
    if not _HAS_MODULE:
        return "EXPECTED", "module absent on pristine tree"
    pr, signer, report, envelope = _sealed(_ledger_with_traffic()[0])
    blob = json.dumps(envelope, sort_keys=True)
    if MARKER in blob:
        return "BREAK", "request content leaked into report"
    return "HELD", "material-free: only digests"


def p5_seal_tamper():
    """Tampered / wrong-key / malformed envelopes fail closed."""
    if not _HAS_MODULE:
        return "EXPECTED", "module absent on pristine tree"
    import copy
    pr, signer, report, envelope = _sealed(_ledger_with_traffic()[0])
    from gov.signing import Ed25519Signer
    other = Ed25519Signer(bytes([7]) * 32)
    bad = copy.deepcopy(envelope)
    bad["report"]["results"].append({"source": "x"})
    cases = [
        ("tampered payload", bad, signer.public_key, False),
        ("wrong key", envelope, other.public_key, False),
        ("short key", envelope, b"short", False),
        ("malformed", {"nope": 1}, signer.public_key, False),
        ("valid", envelope, signer.public_key, True),
    ]
    for name, env, key, want in cases:
        got = pr.verify_report(env, key)
        if got != want:
            return "BREAK", "%s: want %r got %r" % (name, want, got)
    return "HELD", "tamper/wrong-key/malformed fail closed"


def p6_window_filter():
    """Audit-window bounds are inclusive-start / exclusive-end."""
    if not _HAS_MODULE:
        return "EXPECTED", "module absent on pristine tree"
    pr = importlib.import_module("gov.policy_report")
    ledger, _, _ = _ledger_with_traffic()
    # Seeded clock: violations at 1700000003.0 (r-observe),
    # 1700000004.0 (r-warn), 1700000005.0 (r-note).
    full = pr.build_report(ledger, policy_name="p")
    if len(full["results"]) != 3:
        return "BREAK", "expected 3 violation results, got %d" \
            % len(full["results"])
    win = pr.build_report(ledger, policy_name="p",
                          window_start=1700000004.0,
                          window_end=1700000005.0)
    if len(win["results"]) != 1 or \
            win["results"][0]["rule"] != "r-warn":
        return "BREAK", "window filter wrong: %r" \
            % ([r["rule"] for r in win["results"]],)
    return "HELD", "window bounds correct"


def p7_signer_required():
    """emit without a signer and without an anchor key refuses loudly."""
    if not _HAS_MODULE:
        return "EXPECTED", "module absent on pristine tree"
    pr = importlib.import_module("gov.policy_report")
    ledger, _, _ = _ledger_with_traffic()
    saved = {}
    for var in ("GOV_ANCHOR_KEY", "GOV_ANCHOR_KEY_FILE"):
        saved[var] = os.environ.pop(var, None)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                pr.emit_policy_report(ledger, policy_name="p",
                                      out_dir=tmp)
            except pr.PolicyReportError:
                return "HELD", "unsigned report refused loudly"
            return "BREAK", "emit succeeded without any signer"
    finally:
        for var, val in saved.items():
            if val is not None:
                os.environ[var] = val


def p8_determinism_and_chain():
    """Two builds are byte-identical; the ledger chain still verifies."""
    if not _HAS_MODULE:
        return "EXPECTED", "module absent on pristine tree"
    pr = importlib.import_module("gov.policy_report")
    ledger, _, _ = _ledger_with_traffic()
    a = pr.build_report(ledger, policy_name="p")
    b = pr.build_report(ledger, policy_name="p")
    if json.dumps(a, sort_keys=True) != json.dumps(b, sort_keys=True):
        return "BREAK", "builds not deterministic"
    for rid in ("r-observe", "r-warn"):
        if not ledger.verify_rule_chain(rid):
            return "BREAK", "rule chain %r broken by projection" % (rid,)
    return "HELD", "deterministic; per-rule chains intact"


def p9_emit_roundtrip():
    """emit writes a sealed artifact the offline auditor can verify."""
    if not _HAS_MODULE:
        return "EXPECTED", "module absent on pristine tree"
    pr = importlib.import_module("gov.policy_report")
    from gov.signing import Ed25519Signer
    signer = Ed25519Signer(bytes(range(32)))
    ledger, _, _ = _ledger_with_traffic()
    with tempfile.TemporaryDirectory() as tmp:
        path = pr.emit_policy_report(
            ledger, policy_name="genesis", signer=signer, out_dir=tmp,
            window_end=1700000100.0)
        envelope = json.loads(open(path, "rb").read().decode("utf-8"))
        if not pr.verify_report(envelope, signer.public_key):
            return "BREAK", "emitted artifact does not verify"
        if "policy-report-genesis" not in path:
            return "BREAK", "unexpected artifact name %r" % (path,)
    return "HELD", "artifact emitted and auditor-verifiable"


def p10_rule_stats():
    """ruleStats covers every registered rule, incl. zero-violation."""
    if not _HAS_MODULE:
        return "EXPECTED", "module absent on pristine tree"
    pr = importlib.import_module("gov.policy_report")
    from gov import mode_ledger as ml
    t = [1700000000.0]
    ledger = ml.ModeLedger(
        clock=lambda: t.__setitem__(0, t[0] + 1.0) or t[0])
    ledger.register_rule("quiet", mode="observe")
    ledger.register_rule("noisy", mode="warn")
    for _ in range(5):
        ledger.observe("quiet", mode="observe", matched=False)
    ledger.observe("noisy", mode="warn", matched=True,
                   nominal_effect="allow", request_digest="d-n")
    ledger.record_warnings("noisy", 3)
    report = pr.build_report(ledger, policy_name="p")
    stats = report.get("ruleStats", {})
    q = stats.get("quiet")
    n = stats.get("noisy")
    if q is None or n is None:
        return "BREAK", "ruleStats missing rules: %r" % (sorted(stats),)
    if not (q["evaluated"] == 5 and q["violations"] == 0):
        return "BREAK", "zero-violation rule not auditable: %r" % (q,)
    if n["warnings_surfaced"] != 3:
        return "BREAK", "warnings_surfaced not accounted: %r" % (n,)
    if not any(r["rule"] == "noisy" for r in report["results"]):
        return "BREAK", "noisy rule has no results"
    return "HELD", "ruleStats covers all rules incl. zero-violation"


PROBES = [
    ("P0", "projector-present", p0_projector_present),
    ("P1", "auditor-attribution", p1_auditor_attribution),
    ("P2", "result-shape", p2_result_shape),
    ("P3", "mode-mapping", p3_mode_mapping),
    ("P4", "material-free", p4_material_free),
    ("P5", "seal-tamper", p5_seal_tamper),
    ("P6", "window-filter", p6_window_filter),
    ("P7", "signer-required", p7_signer_required),
    ("P8", "determinism-and-chain", p8_determinism_and_chain),
    ("P9", "emit-roundtrip", p9_emit_roundtrip),
    ("P10", "rule-stats", p10_rule_stats),
]


def main():
    held = brk = expected = errors = 0
    for pid, name, fn in PROBES:
        outcomes = set()
        detail = ""
        for _ in range(2):
            try:
                status, detail = fn()
            except Exception as e:  # noqa: BLE001
                status, detail = "ERROR", "%r" % (e,)
            outcomes.add(status)
        if len(outcomes) != 1:
            status = "ERROR"
            detail = "non-deterministic: %r" % (outcomes,)
        print("%s %-22s %s -- %s" % (pid, name, status, detail))
        if status == "HELD":
            held += 1
        elif status == "BREAK":
            brk += 1
        elif status == "EXPECTED":
            expected += 1
        else:
            errors += 1
    print("summary: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, expected, errors))
    green_ok = _green_check()
    if errors or not green_ok:
        return 1
    return 0


def _green_check():
    """Depth-1 green check: the adjacent unit suite only (never nested
    battery mains). Honors GOV_SKIP_GREEN by recording a skip; skips
    gracefully on trees where the wave-199 suite does not exist."""
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    if importlib.util.find_spec("tests.test_policy_report") is None:
        print("GREEN CHECK: skipped (tests.test_policy_report absent "
              "on this tree)")
        return True
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_policy_report"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
    print("GREEN CHECK unit suite: rc=%d %s"
          % (r.returncode, " | ".join(tail)))
    return r.returncode == 0


if __name__ == "__main__":
    sys.exit(main())
