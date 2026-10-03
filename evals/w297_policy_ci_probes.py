"""Wave-297 lane 3 red-first battery: policy CI (single-source / derived artifacts).

Builds gov/policy_ci.py (plexsystems/konstraint STEAL, Apache-2.0,
mechanism only, stdlib only): single declared policy source
(wave-253 authored filters/actions schema, reused), derived artifacts
with digest manifests, mandatory change-note + probe-battery companions,
and dryrun-then-enforce rollout with signed dryrun reports.

Base: wave-296 push 5fd40f0133918de1b881440d7da1aad857462d5f
(verified via git rev-parse HEAD before work).

Pin 1753 -> 1757 (+4 policy-ci-*: companion-missing, derived-tampered,
dryrun-skipped, invalid); the repoint is tree-wide (value-token-only,
code/comment splitter, history comments extended), so adjacent batteries'
own pin probes stay green.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g297-pci && TMPDIR=/var/tmp/g297-pci \
    ~/workspace/.gov-venv/bin/python evals/w297_policy_ci_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g297-pci2 \
    ~/workspace/.gov-venv/bin/python evals/w297_policy_ci_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
from types import MappingProxyType

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-297 lane 3: pin 1753 -> 1757 (+4 policy-ci-*).
TAXONOMY_PIN = 1780

try:
    from gov import policy_ci as PCI
    from gov import policy_authoring as PA
    from gov import ed25519 as ED
except ImportError:
    PCI = None
    PA = None
    ED = None

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _have(pid):
    if PCI is None or PA is None or ED is None:
        _record(pid, "BREAK", "gov.policy_ci absent (feature not built)")
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
    for code in ("policy-ci-derived-tampered", "policy-ci-companion-missing",
                 "policy-ci-dryrun-skipped", "policy-ci-invalid"):
        if code not in lits:
            return _record("pin-taxonomy", "BREAK", "missing %s" % code)
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (TAXONOMY_PIN,
                                                       TAXONOMY_PIN))


SOURCE = """version: 1
policies:
  - name: block-secret-reads
    description: Deny reads of secret-like paths.
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: read_file
      - type: value-filter
        key: path
        op: contains-any
        value: [secret, credentials]
    actions:
      - type: deny
        reason: Secret-like read denied.
        flag: secret_access_attempt
"""


def _good_artifact(**over):
    kw = dict(author="w297-probe", change_note="probe change note",
              probes=["p-source-compiles", "p-derived-digest-stable"])
    kw.update(over)
    return PCI.derive(SOURCE, **kw)


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


def p_derive_happy():
    if not _have("derive-happy"):
        return
    art = _good_artifact()
    if not isinstance(art, MappingProxyType):
        return _record("derive-happy", "BREAK", "artifact not frozen")
    if art["source_digest"] != PCI._source_digest(SOURCE):
        return _record("derive-happy", "BREAK", "source_digest mismatch")
    if set(art["derived"]) != {"policy.native.yaml", "policy.manifest.json"}:
        return _record("derive-happy", "BREAK", "derived files %r"
                       % (sorted(art["derived"]),))
    _record("derive-happy", "HELD", "artifact frozen, digests recorded")


def p_artifact_frozen():
    if not _have("artifact-frozen"):
        return
    art = _good_artifact()
    try:
        art["author"] = "mallory"
    except TypeError:
        return _record("artifact-frozen", "HELD", "frozen MappingProxyType")
    _record("artifact-frozen", "BREAK", "artifact is mutable")


def p_tampered_derived():
    if not _have("tampered-derived"):
        return
    art = _good_artifact()
    evil = dict(art)
    evil["derived"] = dict(evil["derived"])
    evil["derived"]["policy.native.yaml"] = (
        evil["derived"]["policy.native.yaml"].replace("deny", "allow"))
    _expect_coded("tampered-derived",
                  lambda: PCI.load_artifact(evil), "policy-ci-derived-tampered")


def p_stale_artifact():
    if not _have("stale-artifact"):
        return
    art = _good_artifact()
    other = SOURCE + "# a comment changes the source bytes\n"
    _expect_coded("stale-artifact",
                  lambda: PCI.check(other, art), "policy-ci-derived-tampered")


def p_missing_note():
    if not _have("missing-note"):
        return
    art = _good_artifact(change_note="")
    _expect_coded("missing-note",
                  lambda: PCI.check(SOURCE, art), "policy-ci-companion-missing")


def p_missing_probes():
    if not _have("missing-probes"):
        return
    art = _good_artifact(probes=[])
    _expect_coded("missing-probes",
                  lambda: PCI.check(SOURCE, art), "policy-ci-companion-missing")


def p_check_happy():
    if not _have("check-happy"):
        return
    art = _good_artifact()
    got = PCI.check(SOURCE, art)
    if not isinstance(got, MappingProxyType):
        return _record("check-happy", "BREAK", "check did not return artifact")
    _record("check-happy", "HELD", "companions present, artifact fresh")


def p_malformed_source():
    if not _have("malformed-source"):
        return
    _expect_coded("malformed-source",
                  lambda: PCI.derive("not: [valid"),
                  "policy-ci-invalid")


def p_load_path_wiring():
    if not _have("load-path-wiring"):
        return
    art = _good_artifact()
    # Valid artifact at the load path compiles fine (wired, additive).
    compiled = PA.compile_authoring(SOURCE, artifact=art)
    if "block-secret-reads" not in compiled.native_text:
        return _record("load-path-wiring", "BREAK", "native text lost")
    # Tampered artifact at the load path refuses coded.
    evil = dict(art)
    evil["derived"] = dict(evil["derived"])
    evil["derived"]["policy.manifest.json"] = "{}"
    _expect_coded("load-path-wiring",
                  lambda: PA.compile_authoring(SOURCE, artifact=evil),
                  "policy-ci-derived-tampered")


def _full_rollout(**over):
    art = _good_artifact()
    rec = PCI.begin_rollout(art, observation_seconds=60, now=1000.0)
    rec = PCI.observe(rec, [{"decision": "deny", "tool": "read_file"}])
    seed = ED.generate_seed()
    report, sig = PCI.sign_report(seed, rec)
    pub = ED.publickey(seed)
    kw = dict(report=report, signature=sig, pubkey=pub, now=1070.0)
    kw.update(over)
    return PCI.promote(rec, **kw), rec, seed, report, sig


def p_dryrun_happy():
    if not _have("dryrun-happy"):
        return
    final, rec, seed, report, sig = _full_rollout()
    if PCI.status(final) != "enforcing":
        return _record("dryrun-happy", "BREAK", "not enforcing")
    if PCI.status(rec) != "dryrun":
        return _record("dryrun-happy", "BREAK", "rollout record mutated")
    _record("dryrun-happy", "HELD", "dryrun -> enforcing after window+report")


def p_dryrun_skip_no_rollout():
    if not _have("dryrun-skip-no-rollout"):
        return
    _expect_coded("dryrun-skip-no-rollout",
                  lambda: PCI.promote("not-a-record", report=b"x",
                                      signature=b"y" * 64, pubkey=b"z" * 32),
                  "policy-ci-invalid")


def p_promote_without_report():
    if not _have("promote-without-report"):
        return
    art = _good_artifact()
    rec = PCI.begin_rollout(art, observation_seconds=60, now=1000.0)
    _expect_coded("promote-without-report",
                  lambda: PCI.promote(rec, report=None, signature=b"y" * 64,
                                      pubkey=b"z" * 32, now=1070.0),
                  "policy-ci-dryrun-skipped")


def p_window_not_elapsed():
    if not _have("window-not-elapsed"):
        return
    art = _good_artifact()
    rec = PCI.begin_rollout(art, observation_seconds=60, now=1000.0)
    seed = ED.generate_seed()
    report, sig = PCI.sign_report(seed, rec)
    pub = ED.publickey(seed)
    _expect_coded("window-not-elapsed",
                  lambda: PCI.promote(rec, report=report, signature=sig,
                                      pubkey=pub, now=1005.0),
                  "policy-ci-dryrun-skipped")


def p_forged_report():
    if not _have("forged-report"):
        return
    art = _good_artifact()
    rec = PCI.begin_rollout(art, observation_seconds=60, now=1000.0)
    rec = PCI.observe(rec, [{"decision": "deny"}])
    seed = ED.generate_seed()
    report, sig = PCI.sign_report(seed, rec)
    wrong_pub = ED.publickey(ED.generate_seed())
    _expect_coded("forged-report",
                  lambda: PCI.promote(rec, report=report, signature=sig,
                                      pubkey=wrong_pub, now=1070.0),
                  "policy-ci-invalid")


def p_report_mismatch():
    if not _have("report-mismatch"):
        return
    art = _good_artifact()
    rec = PCI.begin_rollout(art, observation_seconds=60, now=1000.0)
    seed = ED.generate_seed()
    report, sig = PCI.sign_report(seed, rec)
    pub = ED.publickey(seed)
    # Report signed for a DIFFERENT rollout (more observations) is refused.
    rec2 = PCI.observe(rec, [{"decision": "allow"}])
    _expect_coded("report-mismatch",
                  lambda: PCI.promote(rec2, report=report, signature=sig,
                                      pubkey=pub, now=1070.0),
                  "policy-ci-invalid")


def p_unknown_state():
    if not _have("unknown-state"):
        return
    bogus = MappingProxyType({
        "format": PCI.ROLLOUT_FORMAT, "state": "quantum",
        "artifact_digest": "x", "source_digest": "y",
        "observation_seconds": 60, "started_at": 1000.0,
        "decisions_digest": "z", "decisions_count": 0})
    _expect_coded("unknown-state",
                  lambda: PCI.status(bogus), "policy-ci-invalid")
    _expect_coded("unknown-state",
                  lambda: PCI.observe(bogus, []), "policy-ci-invalid")


def p_ed25519_contract():
    if not _have("ed25519-contract"):
        return
    seed = ED.generate_seed()
    msg = b"policy-ci-contract-pin"
    pub = ED.publickey(seed)
    good = ED.sign(seed, msg)
    if ED.verify(pub, msg, good) is not True:
        return _record("ed25519-contract", "BREAK", "good sig not is True")
    forged = ED.sign(ED.generate_seed(), msg)
    if ED.verify(pub, msg, forged) is not False:
        return _record("ed25519-contract", "BREAK", "forged sig not is False")
    _record("ed25519-contract", "HELD", "verify is True / is False")


def p_circular_decisions():
    if not _have("circular-decisions"):
        return
    art = _good_artifact()
    rec = PCI.begin_rollout(art, observation_seconds=60, now=1000.0)
    evil = {}
    evil["self"] = evil
    _expect_coded("circular-decisions",
                  lambda: PCI.observe(rec, [evil]), "policy-ci-invalid")


PROBES = [
    ("pin-taxonomy", p_taxonomy_pin),
    ("derive-happy", p_derive_happy),
    ("artifact-frozen", p_artifact_frozen),
    ("tampered-derived", p_tampered_derived),
    ("stale-artifact", p_stale_artifact),
    ("missing-note", p_missing_note),
    ("missing-probes", p_missing_probes),
    ("check-happy", p_check_happy),
    ("malformed-source", p_malformed_source),
    ("load-path-wiring", p_load_path_wiring),
    ("dryrun-happy", p_dryrun_happy),
    ("dryrun-skip-no-rollout", p_dryrun_skip_no_rollout),
    ("promote-without-report", p_promote_without_report),
    ("window-not-elapsed", p_window_not_elapsed),
    ("forged-report", p_forged_report),
    ("report-mismatch", p_report_mismatch),
    ("unknown-state", p_unknown_state),
    ("ed25519-contract", p_ed25519_contract),
    ("circular-decisions", p_circular_decisions),
]


def _green_check(battery):
    # Depth-1 green check (wave-173 lesson): adjacent batteries run with
    # GOV_SKIP_GREEN=1 in the child env; every green-check honors the var.
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    path = os.path.join(REPO, "evals", battery)
    if not os.path.exists(path):
        return ("SKIP", "battery %s not present" % battery)
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO)
    except subprocess.TimeoutExpired:
        return ("ERROR", "timeout")
    tail = (out.stdout + out.stderr).strip().splitlines()
    summary = tail[-1] if tail else "(no output)"
    if "0 BREAK" in out.stdout and "0 ERROR" in out.stdout:
        return ("HELD", summary)
    return ("BREAK", summary)


def main():
    for name, fn in PROBES:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 -- probe harness
            _record(name, "ERROR", "%r" % (e,))
    brk = sum(1 for _, v, _ in _results if v == "BREAK")
    held = sum(1 for _, v, _ in _results if v == "HELD")
    err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w297_policy_ci: %d BREAK / %d HELD / %d ERROR over %d probes"
          % (brk, held, err, len(PROBES)))
    for name, verdict, why in _results:
        if verdict != "HELD":
            print("  %s -> %s: %s" % (name, verdict, why))
    if not SKIP_GREEN:
        for battery in ("w296_decision_trace_probes.py",
                        "w293_tool_rules_probes.py"):
            status, summary = _green_check(battery)
            print("green-check %-32s %s: %s" % (battery, status, summary))
    if brk or err:
        sys.exit(1)


if __name__ == "__main__":
    main()
