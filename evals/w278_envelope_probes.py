"""Wave-278 evidence-envelope battery (break-first, red-first).

Attacks the evidence-envelope machinery itself (gov/battery_envelope.py
+ tools/envelope-verify): every probe forges an envelope against the
published schema and asserts the verifier REFUSES it. The positive
control asserts an honestly-emitted envelope VERIFIES. This is the
terminal-bench two-sided oracle discipline applied to the evidence
layer: the verifier must accept the golden envelope and reject every
forged variant.

Red-first note: on the wave-277 base there is no envelope machinery at
all, so "the verifier accepts a tampered envelope" is trivially true.
Red-first here means: every forgery below is constructed against the
NEW schema and shown to be refused by the NEW verifier. A verifier that
accepted any of these would be a vacuous evidence layer.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (fixed inputs, no random);
fresh unique /var/tmp/g278* TMPDIR (`mkdir -p` first); depth-1 green
checks honoring GOV_SKIP_GREEN=1; no in-repo git subprocesses; stdlib
only.
"""

import copy
import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TMP = tempfile.mkdtemp(prefix="g278-envelope-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import battery_envelope as be  # noqa: E402

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


def _honest_envelope():
    """Golden envelope: one violating oracle (BREAK), one clean (HELD)."""
    b = be.RunBuilder("w278-envelope-selftest", "278.0")
    b.record("ee-violating-case", oracle="violating", expected="BREAK",
             verdict="BREAK", note="golden attack case reproduces")
    b.record("ee-clean-case", oracle="clean", expected="HELD",
             verdict="HELD", note="golden benign case holds")
    return b.seal()


def _refuses(envelope):
    """True when BOTH verifiers refuse the envelope."""
    try:
        be.verify_envelope(envelope)
        return False, "in-repo verifier accepted a forgery"
    except be.BatteryEnvelopeError:
        pass
    path = os.path.join(_TMP, "forged.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(envelope, f)
    p = subprocess.run(
        [sys.executable, os.path.join(REPO, "tools", "envelope-verify"),
         path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        timeout=120)
    if p.returncode == 0:
        return False, "standalone verifier accepted a forgery"
    return True, "both verifiers refused"


# ---------------------------------------------------------------------------
# Forgery probes (all expected HELD: the defense holds).
# ---------------------------------------------------------------------------

def ee_honest_verifies():
    """Positive control: an honestly-emitted envelope verifies."""
    env = _honest_envelope()
    try:
        hdr = be.verify_envelope(env)
    except be.BatteryEnvelopeError as exc:
        return "BREAK", "honest envelope refused in-repo: %s" % exc
    if hdr["sample_count"] != 2:
        return "BREAK", "honest envelope lost samples"
    return "HELD", "honest envelope verifies (2 samples)"


def ee_forge_verdict_flip():
    """Tamper: flip one sample's verdict, leave digests stale."""
    env = _honest_envelope()
    env["samples"][0]["verdict"] = "HELD"
    ok, note = _refuses(env)
    return ("HELD" if ok else "BREAK",
            "verdict flip %s" % ("refused" if ok else "ACCEPTED: " + note))


def ee_forge_verdict_expected_joint():
    """Joint forgery: flip verdict AND expected consistently on the
    violating-oracle sample (oracle still says 'violating')."""
    env = _honest_envelope()
    env["samples"][0]["verdict"] = "HELD"
    env["samples"][0]["expected"] = "HELD"
    ok, note = _refuses(env)
    return ("HELD" if ok else "BREAK",
            "joint verdict+expected forgery %s"
            % ("refused (oracle re-derivation)" if ok
               else "ACCEPTED: " + note))


def ee_forge_verdict_mismatch():
    """Tamper: verdict differs from the recorded expectation
    (verdicts do not match re-computed expectations)."""
    env = _honest_envelope()
    env["samples"][1]["verdict"] = "BREAK"  # expected stays HELD
    ok, note = _refuses(env)
    return ("HELD" if ok else "BREAK",
            "verdict/expected mismatch %s"
            % ("refused" if ok else "ACCEPTED: " + note))


def ee_forge_run_digest():
    """Tamper: flip the run digest."""
    env = _honest_envelope()
    env["header"]["run_digest"] = "0" * 64
    ok, note = _refuses(env)
    return ("HELD" if ok else "BREAK",
            "run-digest forgery %s"
            % ("refused" if ok else "ACCEPTED: " + note))


def ee_forge_sample_digest_recompute():
    """Tamper: flip a verdict and recompute ONLY the sample chain,
    leaving the run digest stale (partial re-seal)."""
    import hashlib
    env = _honest_envelope()
    env["samples"][0]["verdict"] = "HELD"
    env["samples"][0]["expected"] = "HELD"
    env["samples"][0]["oracle"] = "clean"
    prev = "SAMPLE-GENESIS"
    for s in env["samples"]:
        body = {k: v for k, v in s.items() if k != "sample_digest"}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, default=str).encode("utf-8")
        d = hashlib.sha256(
            b"battery-envelope-sample/v1\x00"
            + prev.encode("utf-8") + b"\x00" + raw).hexdigest()
        s["sample_digest"] = d
        prev = d
    ok, note = _refuses(env)
    return ("HELD" if ok else "BREAK",
            "partial re-seal %s"
            % ("refused (run digest)" if ok else "ACCEPTED: " + note))


def ee_forge_unknown_schema():
    """Tamper: claim an unknown schema version."""
    env = _honest_envelope()
    env["schema_version"] = "9.9"
    ok, note = _refuses(env)
    return ("HELD" if ok else "BREAK",
            "unknown schema %s"
            % ("refused" if ok else "ACCEPTED: " + note))


def ee_forge_bad_oracle():
    """Tamper: oracle outside the vocabulary."""
    env = _honest_envelope()
    env["samples"][0]["oracle"] = "suspicious"
    ok, note = _refuses(env)
    return ("HELD" if ok else "BREAK",
            "bad oracle %s"
            % ("refused" if ok else "ACCEPTED: " + note))


def ee_forge_extra_sample():
    """Tamper: append a sample without updating header/sample_count."""
    env = _honest_envelope()
    extra = copy.deepcopy(env["samples"][1])
    extra["sample_id"] = "ee-injected"
    extra["sample_seq"] = 3
    env["samples"].append(extra)
    ok, note = _refuses(env)
    return ("HELD" if ok else "BREAK",
            "injected sample %s"
            % ("refused" if ok else "ACCEPTED: " + note))


def ee_emitter_rejects_bad_oracle_mapping():
    """Emission-time guard: oracle='violating' with expected='HELD'
    must refuse at record() time (the oracle contract is enforced at
    emission, not just verification)."""
    b = be.RunBuilder("w278-envelope-selftest", "278.0")
    try:
        b.record("ee-bad", oracle="violating", expected="HELD",
                 verdict="HELD", note="contract violation")
    except be.BatteryEnvelopeError:
        return "HELD", "emitter refused oracle/expected contradiction"
    return "BREAK", "emitter accepted oracle/expected contradiction"


def ee_w277_artifact_verifies():
    """Integration: the wired w277 battery's emitted artifact verifies
    under the standalone verifier."""
    artifact = os.path.join(REPO, "evals", "artifacts",
                            "w277_redteam.envelope.json")
    if not os.path.isfile(artifact):
        return "ERROR", "w277 artifact missing: run w277 battery first"
    p = subprocess.run(
        [sys.executable, os.path.join(REPO, "tools", "envelope-verify"),
         artifact],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        timeout=120)
    if p.returncode != 0:
        return "BREAK", "w277 artifact failed standalone verify: %s" % (
            p.stdout.strip().splitlines()[0] if p.stdout else "?")
    return "HELD", "w277 artifact verifies standalone"


def ee_schema_prints():
    """The published schema prints and names the format/version."""
    schema = be.envelope_schema()
    if schema.get("format") != be.FORMAT:
        return "BREAK", "schema misnames format"
    if schema.get("schema_version") != be.SCHEMA_VERSION:
        return "BREAK", "schema misnames version"
    p = subprocess.run(
        [sys.executable, "-m", "gov.battery_envelope", "--schema"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=120)
    if p.returncode != 0:
        return "BREAK", "--schema exited %d" % p.returncode
    try:
        printed = json.loads(p.stdout)
    except ValueError:
        return "BREAK", "--schema output is not JSON"
    if printed.get("schema_version") != be.SCHEMA_VERSION:
        return "BREAK", "--schema version mismatch"
    return "HELD", "schema prints (format %s v%s)" % (
        be.FORMAT, be.SCHEMA_VERSION)


PROBES = [
    ("ee-honest-verifies", "HELD", ee_honest_verifies),
    ("ee-forge-verdict-flip", "HELD", ee_forge_verdict_flip),
    ("ee-forge-verdict-expected-joint", "HELD",
     ee_forge_verdict_expected_joint),
    ("ee-forge-verdict-mismatch", "HELD", ee_forge_verdict_mismatch),
    ("ee-forge-run-digest", "HELD", ee_forge_run_digest),
    ("ee-forge-sample-digest-recompute", "HELD",
     ee_forge_sample_digest_recompute),
    ("ee-forge-unknown-schema", "HELD", ee_forge_unknown_schema),
    ("ee-forge-bad-oracle", "HELD", ee_forge_bad_oracle),
    ("ee-forge-extra-sample", "HELD", ee_forge_extra_sample),
    ("ee-emitter-rejects-bad-oracle-mapping", "HELD",
     ee_emitter_rejects_bad_oracle_mapping),
    ("ee-w277-artifact-verifies", "HELD", ee_w277_artifact_verifies),
    ("ee-schema-prints", "HELD", ee_schema_prints),
]


def green_check():
    """Depth-1: re-run the wired w277 battery (GOV_SKIP_GREEN=1 in the
    child env) and verify its freshly-emitted artifact standalone."""
    if GREEN_SKIP:
        return [("GOV_SKIP_GREEN=1: recorded, not recursing", "HELD",
                 "skip")]
    results = []
    tmp = tempfile.mkdtemp(prefix="g278-green-w277-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
    try:
        p = subprocess.run(
            [sys.executable, "evals/w277_redteam_probes.py"], cwd=REPO,
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600, text=True)
        emitted = "[envelope] emitted" in p.stdout
        results.append(("w277-emits-envelope",
                        "HELD" if (p.returncode == 0 and emitted)
                        else "BREAK",
                        "rc=%d emitted=%s"
                        % (p.returncode, emitted)))
        artifact = os.path.join(REPO, "evals", "artifacts",
                                "w277_redteam.envelope.json")
        v = subprocess.run(
            [sys.executable, os.path.join(REPO, "tools",
                                         "envelope-verify"),
             artifact],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=120)
        results.append(("w277-artifact-verifies",
                        "HELD" if v.returncode == 0 else "BREAK",
                        "rc=%d" % v.returncode))
    except Exception as exc:  # noqa: BLE001
        results.append(("w277-green", "BREAK", "%s" % exc))
    return results


def main():
    for pid, expected, fn in PROBES:
        _run(pid, expected, fn)
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    n_mismatch = sum(1 for r in _RESULTS if not r[3])
    for pid, expected, verdict, ok, note in _RESULTS:
        print("[%s] %-38s expected=%-5s got=%-5s %s"
              % ("ok " if ok else "FAIL", pid, expected, verdict, note))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in green_check():
        print("[%s] %s %s" % ("ok " if verdict == "HELD" else "FAIL",
                              name, note))
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, n_mismatch))
    return 0 if (n_err == 0 and n_mismatch == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
