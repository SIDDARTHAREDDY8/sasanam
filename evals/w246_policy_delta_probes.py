"""Wave-246 policy-change risky-delta gate probes (red-first).

W246-1 (OpenShell shape): gov/policy_change.py governs the policy-change
CEREMONY (two-person rule, chaining, break-glass) and computes a
structural diff, but nothing in the tree verifies whether the DELTA is
risky. This battery falsifies the absence of that check at the
analyze_policy_delta seam:

  role-gains-tool-refused -- a role gaining a tool widens capability
      -> refuse policy-delta-widening.
  forbid-removed-refused -- a deny rule deleted outright
      -> refuse policy-delta-forbid-removed.
  allow-without-forbid-flagged -- a new allow rule no deny rule covers
      (tool-overlap heuristic) -> pass WITH a
      policy-delta-allow-unforbidden flag (advisory, not a refusal).
  noop-passes -- byte-different but semantically identical policies
      (comments/whitespace only) -> pass, zero findings.
  tighten-only-passes -- role loses a tool AND a new deny rule added
      -> pass, zero findings.
  deny-to-allow-flip-refused -- deny-secret-reads flipped to allow
      -> refuse policy-delta-effect-weakened.
  forbid-narrowed-refused -- deny rule's match.tool list shrinks
      (provable coverage loss) -> refuse policy-delta-forbid-narrowed.
  budget-increased-refused -- max_sends_per_run 10 -> 20
      -> refuse policy-delta-widening.
  egress-allowlist-widened-refused -- domain_allowlist gains a domain
      -> refuse policy-delta-widening.
  malformed-fails-closed -- unparseable new text, non-mapping old
      text, duplicate rule ids -> PolicyDeltaError policy-delta-malformed.
  allow-with-forbid-passes -- a new allow rule for send_email while a
      deny rule covers send_email (forbid priority guards it) -> pass.
  delegation-enabled-refused -- approvals.delegation.enabled
      false -> true -> refuse policy-delta-widening.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_PDG = False
try:
    from gov import policy_delta_gate as _pdg
    HAVE_PDG = all(hasattr(_pdg, n) for n in (
        "analyze_policy_delta", "check_policy_delta",
        "PolicyDeltaError"))
except ImportError:
    _pdg = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "role-gains-tool-refused",
    "forbid-removed-refused",
    "allow-without-forbid-flagged",
    "noop-passes",
    "tighten-only-passes",
    "deny-to-allow-flip-refused",
    "forbid-narrowed-refused",
    "budget-increased-refused",
    "egress-allowlist-widened-refused",
    "malformed-fails-closed",
    "allow-with-forbid-passes",
    "delegation-enabled-refused",
]

BASE = """\
version: 2
roles:
  support: [read_file, send_email]
  coder: [read_file, write_file]
rate_limit:
  max_sends_per_run: 10
egress:
  domain_allowlist: [synthetic.local]
approvals:
  ttl_hours: 24
  batch_excluded_queue_reasons: [dlp, egress_violation]
  delegation:
    enabled: false
    max_hops: 1
policies:
  - id: deny-secret-reads
    effect: deny
    match:
      tool: [read_file, write_file]
      path_contains_any: [secret, credentials, token]
    reason: test fixture
  - id: deny-egress-unallowlisted
    effect: deny
    match:
      tool: [send_email]
      domain_allowlisted: false
    reason: test fixture
"""


def _swap(old, new):
    assert old in BASE, "fixture drift: %r" % old[:40]
    return BASE.replace(old, new)


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


def _expect_refusal(old, new, code):
    try:
        _pdg.check_policy_delta(old, new)
    except _pdg.PolicyDeltaError as exc:
        assert exc.code == code, "want %s, got %s" % (code, exc.code)
        return exc
    raise AssertionError("expected refusal %s, got pass" % (code,))


def _expect_pass(old, new):
    report = _pdg.analyze_policy_delta(old, new)
    assert report["verdict"] == "pass", report
    return report


def _probe_role_gains_tool_refused():
    new = _swap("support: [read_file, send_email]",
                "support: [read_file, send_email, api_call]")
    _expect_refusal(BASE, new, "policy-delta-widening")
    return "role capability widening refused"


def _probe_forbid_removed_refused():
    lines = [ln for ln in BASE.splitlines(keepends=True)
             if "deny-secret-reads" not in ln]
    # drop the whole deny-secret-reads rule block (id line + 5 more lines)
    out, skip = [], 0
    for ln in BASE.splitlines(keepends=True):
        if skip:
            skip -= 1
            continue
        if "id: deny-secret-reads" in ln:
            skip = 5
            continue
        out.append(ln)
    new = "".join(out)
    assert "deny-secret-reads" not in new
    _expect_refusal(BASE, new, "policy-delta-forbid-removed")
    return "forbid removal refused"


def _probe_allow_without_forbid_flagged():
    new = BASE + ("  - id: allow-install\n"
                  "    effect: allow\n"
                  "    match:\n"
                  "      tool: [install_package]\n"
                  "    reason: test fixture\n")
    report = _expect_pass(BASE, new)
    codes = [f["risk_class"] for f in report["risk_findings"]]
    assert "policy-delta-allow-unforbidden" in codes, report
    return "unguarded allow flagged, verdict still pass"


def _probe_noop_passes():
    new = "# a comment change only\n" + BASE.replace(
        "version: 2", "version: 2  # trailing comment")
    report = _expect_pass(BASE, new)
    assert report["risk_findings"] == [], report
    return "semantic no-op passes with zero findings"


def _probe_tighten_only_passes():
    new = _swap("support: [read_file, send_email]",
                "support: [read_file]")
    new += ("  - id: deny-new-exfil\n"
            "    effect: deny\n"
            "    match:\n"
            "      tool: [http_post]\n"
            "    reason: test fixture\n")
    report = _expect_pass(BASE, new)
    assert report["risk_findings"] == [], report
    return "tighten-only delta passes"


def _probe_deny_to_allow_flip_refused():
    new = _swap("  - id: deny-secret-reads\n    effect: deny",
                "  - id: deny-secret-reads\n    effect: allow")
    _expect_refusal(BASE, new, "policy-delta-effect-weakened")
    return "deny->allow flip refused"


def _probe_forbid_narrowed_refused():
    new = _swap("      tool: [read_file, write_file]",
                "      tool: [read_file]")
    _expect_refusal(BASE, new, "policy-delta-forbid-narrowed")
    return "provable forbid narrowing refused"


def _probe_budget_increased_refused():
    new = _swap("max_sends_per_run: 10", "max_sends_per_run: 20")
    _expect_refusal(BASE, new, "policy-delta-widening")
    return "budget increase refused"


def _probe_egress_allowlist_widened_refused():
    new = _swap("domain_allowlist: [synthetic.local]",
                "domain_allowlist: [synthetic.local, evil.example]")
    _expect_refusal(BASE, new, "policy-delta-widening")
    return "egress allowlist widening refused"


def _probe_malformed_fails_closed():
    for old, new, label in (
            (BASE, ":\n: bad", "unparseable new"),
            (["not", "a", "mapping"], BASE, "non-mapping old"),
            (BASE, BASE.replace("id: deny-egress-unallowlisted",
                                "id: deny-secret-reads"),
             "duplicate rule ids")):
        try:
            _pdg.analyze_policy_delta(old, new)
        except _pdg.PolicyDeltaError as exc:
            assert exc.code == "policy-delta-malformed", \
                "%s: want policy-delta-malformed, got %s" % (label,
                                                            exc.code)
        else:
            raise AssertionError("%s: expected malformed refusal" % label)
    return "malformed inputs fail closed"


def _probe_allow_with_forbid_passes():
    new = BASE + ("  - id: allow-support-email\n"
                  "    effect: allow\n"
                  "    match:\n"
                  "      tool: [send_email]\n"
                  "      domain_allowlisted: true\n"
                  "    reason: test fixture\n")
    report = _expect_pass(BASE, new)
    assert report["risk_findings"] == [], report
    return "allow guarded by forbid priority passes"


def _probe_delegation_enabled_refused():
    new = _swap("    enabled: false", "    enabled: true")
    _expect_refusal(BASE, new, "policy-delta-widening")
    return "delegation enablement refused"


_PROBES = {
    name: (globals()["_probe_" + name.replace("-", "_")], HAVE_PDG)
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
         "tests.test_policy_delta_gate", "-v"],
        cwd=root, env=env, capture_output=True, text=True, timeout=300)
    notes.append("unit tests.test_policy_delta_gate rc=%d"
                 % (proc.returncode,))
    if proc.returncode != 0:
        notes.append("unit tail: %s" % (proc.stderr[-400:],))
    return notes


def main():
    print("wave-246 policy-delta probes (module: %s)" % (HAVE_PDG,))
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
