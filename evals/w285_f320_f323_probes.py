"""Wave-285 lane-4 closure battery: F320, F321, F322, F323 (all LOW).

Red-first: on the wave-284 base these 4 probes BREAK (defects present);
after the closure fixes they must all HELD.

  mkdir -p /var/tmp/g285-f320 && TMPDIR=/var/tmp/g285-f320 \\
    ~/workspace/.gov-venv/bin/python evals/w285_f320_f323_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g285-f320b \\
    ~/workspace/.gov-venv/bin/python evals/w285_f320_f323_probes.py

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.
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
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-285 lane 4 adds +1 inventory-identity-collision code (1621 -> 1622).; Wave-285 lane 4: pin 1621 -> 1622 (+1 inventory-identity-collision).
TAXONOMY_PIN = 1812  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


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
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted"
            % (TAXONOMY_PIN, TAXONOMY_PIN))


def _iq_registry():
    from gov import inventory_query as iq
    return iq, iq.QueryRegistry()


def _fl_registry():
    from gov import finding_lifecycle as fl
    return fl, fl.FindingRegistry()


# ---------------------------------------------------------------------------
# F320: one report entry per query; every entry carries 'released'; no
# doubled withdrawals.
# ---------------------------------------------------------------------------

def f_f320_pack_report_integrity():
    iq, reg = _iq_registry()
    reg.register_table_rows("agent_tools", [
        {"agent_host": "h1", "scope": "global", "tool_name": "tool-a",
         "definition_digest": "d1"}])
    pack = reg.pin_query_pack(
        {"pack_name": "p", "queries": [{"table": "agent_tools",
                                       "name": "q1"}]})
    rep = reg.run_query_pack(pack)
    problems = []
    if len(rep["queries"]) != len(pack["queries"]):
        problems.append("%d report entries for %d queries"
                        % (len(rep["queries"]), len(pack["queries"])))
    for qrep in rep["queries"]:
        if "released" not in qrep:
            problems.append("entry %r missing 'released'"
                            % qrep.get("name"))
    # Withdrawal accounting: drop the row, re-run, the withdrawn identity
    # must appear exactly once.
    reg.register_table_rows("agent_tools", [])
    rep2 = reg.run_query_pack(pack)
    qrep = rep2["queries"][0] if len(rep2["queries"]) == 1 else None
    if qrep is None:
        problems.append("withdrawal re-run: %d entries (want 1)"
                        % len(rep2["queries"]))
    else:
        idents = [str(x) for x in qrep.get("withdrawn", [])]
        if len(idents) != len(set(idents)):
            problems.append("withdrawn identities doubled: %r" % (idents,))
        if len(idents) != 1:
            problems.append("withdrawn count %d (want 1)" % len(idents))
    if problems:
        _record("f320-pack-report-integrity", "BREAK",
                "F320: " + "; ".join(problems))
    else:
        _record("f320-pack-report-integrity", "HELD",
                "one entry per query, 'released' present, withdrawals "
                "counted once")


# ---------------------------------------------------------------------------
# F321: duplicate identities in one seed/fetch must refuse LOUD.
# ---------------------------------------------------------------------------

def f_f321_identity_collision_loud():
    iq, reg = _iq_registry()
    try:
        reg.register_table_rows("agents", [
            {"agent_id": "a1", "name": "first", "trust_tier": "low"},
            {"agent_id": "a1", "name": "second", "trust_tier": "high"}])
    except iq.InventoryError:
        pass
    else:
        _record("f321-identity-collision-loud", "BREAK",
                "F321: register_table_rows silently shadowed duplicate "
                "identities")
        return
    # Extension fetch path: a degenerate provider returning colliding
    # identities must also refuse loudly on observation.
    class EvilProvider:
        def table_names(self):
            return ["evil"]
        def fetch(self, table_name):
            return [{"k": "same", "v": 1}, {"k": "same", "v": 2}]
        def identity_columns(self, table_name):
            return ("k",)
    reg.register_extension("evil", 1, EvilProvider())
    try:
        reg.run_query({"table": "evil", "columns": ["k", "v"]})
    except iq.InventoryError:
        _record("f321-identity-collision-loud", "HELD",
                "duplicate identities refused with InventoryError on "
                "both seed and extension-fetch paths")
    else:
        _record("f321-identity-collision-loud", "BREAK",
                "F321: _extension_rows silently shadowed provider "
                "identity collision")


# ---------------------------------------------------------------------------
# F322: severity-aware dedup -- a HIGH filing must not inherit a LOW
# canonical's SLA.
# ---------------------------------------------------------------------------

def f_f322_severity_aware_dedup():
    fl, reg = _fl_registry()
    n1, _ = reg.file_finding(
        "t1", "seam-x", "shape-y", "close-z", "low", "plant", 283)
    n2, kind = reg.file_finding(
        "t2", "seam-x", "shape-y", "close-z", "high", "lane", 284)
    f = reg.get(n1)
    if kind == "duplicate" and f.severity == "low":
        _record("f322-severity-aware-dedup", "BREAK",
                "F322: HIGH filing deduped onto LOW canonical; severity "
                "stays 'low' (3-wave SLA)")
    elif f.severity != "high":
        _record("f322-severity-aware-dedup", "BREAK",
                "F322: post-dedup severity %r (want 'high')" % f.severity)
    else:
        _record("f322-severity-aware-dedup", "HELD",
                "severity mismatch escalates canonical (kind=%s, "
                "severity=%s)" % (kind, f.severity))


# ---------------------------------------------------------------------------
# F323: marker-less legacy entries must not import as verified.
# ---------------------------------------------------------------------------

def f_f323_md_import_no_silent_close():
    import tempfile as _tf
    fl = _fl_registry()[0]
    md = ("## F900: some old defect (MEDIUM)\n\n"
          "This legacy entry has no explicit status marker.\n")
    d = _tf.mkdtemp(prefix="w285-f323-")
    p = os.path.join(d, "FINDINGS.md")
    with open(p, "w") as fh:
        fh.write(md)
    reg = fl.load_findings_md(p)
    states = {f.number: f.state for f in reg.all()}
    if states.get("F900") == "verified":
        _record("f323-md-import-no-silent-close", "BREAK",
                "F323: marker-less entry imported as verified "
                "(silently closed)")
    else:
        _record("f323-md-import-no-silent-close", "HELD",
                "marker-less entry imports as %s" % states.get("F900"))


# ---------------------------------------------------------------------------
# Depth-1 green checks
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        # (battery, expected_breaks_or_None, must_have_no_break)
        # Wave-285 merge: F316-F324 all CLOSED; w284_redteam re-pinned
        # BREAK->HELD at merge (wave-281 precedent).
        ("evals/w284_redteam_probes.py", 0, True),
        ("evals/w284_f312_315_probes.py", 0, True),
        ("evals/w283_redteam_probes.py", 0, True),
        ("evals/w283_osquery_probes.py", 0, True),
        ("evals/w283_defectdojo_probes.py", 0, True),  # exercises load_findings_md
    ]
    for rel, expected_breaks, no_break in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w285-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if no_break and nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        elif expected_breaks is not None and nbreak != expected_breaks:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)"
                    % (nbreak, expected_breaks))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % nbreak)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

_PROBES = [
    p_taxonomy_pin,
    f_f320_pack_report_integrity,
    f_f321_identity_collision_loud,
    f_f322_severity_aware_dedup,
    f_f323_md_import_no_silent_close,
]


def main():
    for probe in _PROBES:
        try:
            probe()
        except Exception:  # noqa: BLE001 - a probe must never die
            import traceback
            _record(probe.__name__, "ERROR",
                    traceback.format_exc()[-500:])
    _green_checks()

    breaks = [r for r in _results if r[1] == "BREAK"]
    held = [r for r in _results if r[1] == "HELD"]
    errors = [r for r in _results if r[1] == "ERROR"]
    print("wave-285 lane-4: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note[:160]))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
