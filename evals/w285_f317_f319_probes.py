"""Wave-285 closure battery: F317 (decode-layer evasion) + F319 (campaign
evidence emission echo).

Base: wave-284 merge 0f13ce1d9f1e01b32a6a237f297e6364fa993b9c.

Close-when criteria:
  F317: (1) triple-nested and binary-padded encodings of credential
      shapes are detected; (2) probes flip to HELD; (3) adjacent
      batteries stay green.
  F319: (1) campaign-start/step records route attacker-influenced free
      text (args_map, executor_note, parser_note) through the
      secret_canonicalizer seam before writing; (2) probe flips to
      HELD; (3) adjacent batteries stay green.

Red-first: on the wave-284 base every closure probe BREAKs; after the
fix every probe HELDs. Regression probes (single-layer decode,
plaintext, benign silence, hex layer) HELD on both.

$0 spend, synthetic/local, deterministic (fixed fixtures, no
wall-clock equality assertions). Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g285-f317f319 && TMPDIR=/var/tmp/g285-f317f319 \
    ~/workspace/.gov-venv/bin/python evals/w285_f317_f319_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g285-f317f319b \
    ~/workspace/.gov-venv/bin/python evals/w285_f317_f319_probes.py
"""

import base64
import json
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
sys.path.insert(0, os.path.join(REPO, "evals"))

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-284 merge: pin 1587 -> 1621. No new decision codes in this lane.
TAXONOMY_PIN = 1945 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 3: pin 1933 -> 1945 (+12 quorum-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


SECRET = "AKIAIOSFODNN7EXAMPLE"  # synthetic shape-only canary (same as _w284_helpers)


def _b64nest(data, layers):
    out = data
    for _ in range(layers):
        out = base64.b64encode(out.encode() if isinstance(out, str)
                               else out).decode()
    return out


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
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (len(lits), len(lits)))


# ---------------------------------------------------------------------------
# F317: decode-layer evasion
# ---------------------------------------------------------------------------

def f317_depth_triple_b64():
    """F317(a): triple-nested base64 of a credential shape must be detected."""
    from gov import secret_canonicalizer as sc
    blob = "blob " + _b64nest(SECRET, 3)
    if sc.credential_material_present(blob):
        _record("f317-depth-triple-b64", "HELD", "triple-nested base64 detected")
    else:
        _record("f317-depth-triple-b64", "BREAK",
                "F317: triple-nested base64 evades credential_material_present")


def f317_depth_quad_b64():
    """F317(a): four-nested base64 must be detected (recursion, not a fixed cap)."""
    from gov import secret_canonicalizer as sc
    blob = "blob " + _b64nest(SECRET, 4)
    if sc.credential_material_present(blob):
        _record("f317-depth-quad-b64", "HELD", "four-nested base64 detected")
    else:
        _record("f317-depth-quad-b64", "BREAK",
                "F317: four-nested base64 evades credential_material_present")


def f317_binary_padded_b64():
    """F317(b): single base64 of a credential padded with binary bytes."""
    from gov import secret_canonicalizer as sc
    padded = base64.b64encode((SECRET + "\x00\xff" * 16).encode(
        "latin-1")).decode()
    if sc.credential_material_present("blob " + padded):
        _record("f317-binary-padded-b64", "HELD",
                "binary-padded base64 detected")
    else:
        _record("f317-binary-padded-b64", "BREAK",
                "F317: binary-padded base64 evades credential_material_present")


def f317_over_deep_failclosed():
    """F317: nesting beyond the bounded depth must fail CLOSED (present)."""
    from gov import secret_canonicalizer as sc
    blob = "blob " + _b64nest(SECRET, sc.MAX_DECODE_DEPTH + 5)
    if sc.credential_material_present(blob):
        _record("f317-over-deep-failclosed", "HELD",
                "over-deep nesting fails closed (detected)")
    else:
        _record("f317-over-deep-failclosed", "BREAK",
                "F317: over-deep nesting silently undetected")


def f317_single_b64_regression():
    """Regression: single-layer base64 detection keeps working."""
    from gov import secret_canonicalizer as sc
    blob = "blob " + base64.b64encode(SECRET.encode()).decode()
    if sc.credential_material_present(blob):
        _record("f317-single-b64-regression", "HELD",
                "single-layer base64 still detected")
    else:
        _record("f317-single-b64-regression", "BREAK",
                "REGRESSION: single-layer base64 no longer detected")


def f317_plaintext_regression():
    """Regression: plaintext credential shape keeps working."""
    from gov import secret_canonicalizer as sc
    if sc.credential_material_present("the key is " + SECRET + " here"):
        _record("f317-plaintext-regression", "HELD",
                "plaintext shape still detected")
    else:
        _record("f317-plaintext-regression", "BREAK",
                "REGRESSION: plaintext shape no longer detected")


def f317_hex_regression():
    """Regression: hex-encoded credential shape keeps working."""
    from gov import secret_canonicalizer as sc
    blob = "blob " + SECRET.encode().hex()
    if sc.credential_material_present(blob):
        _record("f317-hex-regression", "HELD", "hex layer still detected")
    else:
        _record("f317-hex-regression", "BREAK",
                "REGRESSION: hex layer no longer detected")


def f317_benign_silent():
    """Regression: benign text stays silent (no detection explosion)."""
    from gov import secret_canonicalizer as sc
    benign = ("runbook 7f3a2b1c-9d4e-4f8a-b1c2-3d4e5f6a7b8c deploy "
              "the quarterly report to the shared drive")
    if not sc.credential_material_present(benign):
        _record("f317-benign-silent", "HELD", "benign text silent")
    else:
        _record("f317-benign-silent", "BREAK",
                "REGRESSION: benign text now flagged")


def f317_decode_span_redacted():
    """sanitize() must redact the whole encoded span for nested layers."""
    from gov import secret_canonicalizer as sc
    blob = "blob " + _b64nest(SECRET, 3)
    redacted, findings = sc.sanitize(blob, location="test")
    if SECRET not in redacted and _b64nest(SECRET, 1) not in redacted\
            and findings:
        _record("f317-decode-span-redacted", "HELD",
                "nested encoded span fully redacted, no decodable fragment")
    else:
        _record("f317-decode-span-redacted", "BREAK",
                "F317: nested encoding survives sanitize()")


# ---------------------------------------------------------------------------
# F319: campaign evidence emission echo
# ---------------------------------------------------------------------------

def _run_campaign(args_map, specs, d):
    from gov import campaign as cp
    reg = {}
    cp.register_campaign_atomics(reg, specs)
    path = os.path.join(d, "e.jsonl")
    cp.CampaignRunner(reg).run(
        "emit-test", atomics=[specs[0]["name"]],
        planner_id="minimize-to-first-break",
        objectives=[], seed_facts={},
        args_map=args_map, evidence_path=path)
    with open(path, encoding="utf-8") as fh:
        blob = fh.read()
    return blob, path


def _clean_executor(ctx):
    return "HELD", "clean"


def _clean_spec():
    return {"name": "probe", "description": "clean atomic",
            "input_arguments": {"target": {"type": "str", "default": ""}},
            "dependencies": [],
            "executor": {"run": _clean_executor, "cleanup": None,
                         "elevation_required": False}}


def _leak_spec_with_args():
    """Like _w284_helpers.leak_spec but declares the arg, so the
    executor genuinely runs (the red-team probe's construction was
    refused at arg validation and never executed the executor)."""
    def _run(ctx):
        return "BREAK", "saw %s in response" % SECRET

    return {"name": "probe", "description": "emission probe atomic",
            "input_arguments": {"target": {"type": "str", "default": ""}},
            "dependencies": [],
            "executor": {"run": _run, "cleanup": None,
                         "elevation_required": False}}


def f319_argsmap_echo():
    """F319: raw credential-shaped args must not land in the evidence JSONL."""
    d = tempfile.mkdtemp(prefix="w285-f319-args-")
    blob, _ = _run_campaign({"probe": {"target": SECRET}}, [_clean_spec()], d)
    if SECRET in blob:
        _record("f319-argsmap-echo", "BREAK",
                "F319: raw credential-shaped args_map in campaign evidence")
    else:
        _record("f319-argsmap-echo", "HELD", "args_map sanitized before write")


def f319_executor_note_echo():
    """F319: raw credential-shaped executor notes must not land in evidence."""
    d = tempfile.mkdtemp(prefix="w285-f319-note-")
    blob, path = _run_campaign({"probe": {"target": "clean"}},
                               [_leak_spec_with_args()], d)
    import json as _json
    step = [ _json.loads(ln) for ln in open(path).read().splitlines()
             if _json.loads(ln)["record_type"] == "campaign-step"][0]
    genuine = step.get("verdict") == "BREAK"  # executor really ran
    if SECRET in blob:
        _record("f319-executor-note-echo", "BREAK",
                "F319: raw credential-shaped executor_note in evidence")
    elif not genuine:
        _record("f319-executor-note-echo", "ERROR",
                "probe vacuous: executor did not run")
    else:
        _record("f319-executor-note-echo", "HELD",
                "executor_note sanitized before write")


def f319_parser_note_echo():
    """F319: parser refusal notes embed raw values -- must be sanitized."""
    d = tempfile.mkdtemp(prefix="w285-f319-parser-")

    def _run(ctx):
        return "HELD", "clean"

    def _parser(result):
        # Mistyped parser value: the refusal note embeds the raw value.
        return [{"fact": "tool.available", "value": "got " + SECRET}]

    spec = {"name": "pprobe", "description": "parser probe",
            "input_arguments": {}, "dependencies": [],
            "executor": {"run": _run, "cleanup": None,
                         "elevation_required": False},
            "fact_parser": _parser,
            "produces": [{"fact": "tool.available", "value": True,
                          "type": "bool", "on": "held"}]}
    blob, _ = _run_campaign({"pprobe": {}}, [spec], d)
    if SECRET in blob:
        _record("f319-parser-note-echo", "BREAK",
                "F319: raw credential-shaped parser_note in evidence")
    else:
        _record("f319-parser-note-echo", "HELD",
                "parser_note sanitized before write")


def f319_redaction_marked():
    """Redaction is marked ([REDACTED:<kind>]), never silent elision;
    args_map keeps its dict structure and keys."""
    d = tempfile.mkdtemp(prefix="w285-f319-marked-")
    blob, path = _run_campaign({"probe": {"target": SECRET}}, [_clean_spec()], d)
    start = json.loads(open(path).read().splitlines()[0])
    args_map = start.get("args_map")
    ok = (isinstance(args_map, dict) and "probe" in args_map
          and "[REDACTED:" in blob and SECRET not in blob)
    if ok:
        _record("f319-redaction-marked", "HELD",
                "redaction marked, args_map structure preserved")
    else:
        _record("f319-redaction-marked", "BREAK",
                "F319: redaction not marked or args_map structure lost")


def f319_argsmap_digest_recorded():
    """The original args still have tamper evidence: args_map_digest."""
    import hashlib
    d = tempfile.mkdtemp(prefix="w285-f319-digest-")
    args_map = {"probe": {"target": SECRET}}
    _, path = _run_campaign(args_map, [_clean_spec()], d)
    start = json.loads(open(path).read().splitlines()[0])
    want = hashlib.sha256(
        json.dumps(args_map, sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest()
    if start.get("args_map_digest") == want:
        _record("f319-argsmap-digest-recorded", "HELD",
                "args_map_digest binds the original args")
    else:
        _record("f319-argsmap-digest-recorded", "BREAK",
                "F319: no tamper evidence for the original args_map")


def f319_encoded_args_echo():
    """Composition: triple-nested-b64 credential in args must not echo either."""
    d = tempfile.mkdtemp(prefix="w285-f319-enc-")
    nested = _b64nest(SECRET, 3)
    blob, _ = _run_campaign({"probe": {"target": nested}}, [_clean_spec()], d)
    if SECRET in blob or nested in blob:
        _record("f319-encoded-args-echo", "BREAK",
                "F319: encoded credential-shaped args in evidence")
    else:
        _record("f319-encoded-args-echo", "HELD",
                "encoded args sanitized before write")


# ---------------------------------------------------------------------------
# Depth-1 green checks (adjacent batteries; GOV_SKIP_GREEN honored)
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        # Wave-285 merge: F316-F324 all CLOSED (lanes 1-4); w284_redteam
        # re-pinned BREAK->HELD at merge (wave-281 precedent).
        ("evals/w284_redteam_probes.py", 0),
        ("evals/w284_f312_315_probes.py", 0),
        ("evals/w283_f311_probes.py", 0),
        ("evals/w283_redteam_probes.py", 0),
        ("evals/w283_gitleaks_probes.py", 0),  # canonicalizer-adjacent
    ]
    for rel, expected_breaks in checks:
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
        if nbreak != expected_breaks:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected %d)"
                    % (nbreak, expected_breaks))
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: %d BREAK as expected" % nbreak)


_PROBES = [
    p_taxonomy_pin,
    f317_depth_triple_b64,
    f317_depth_quad_b64,
    f317_binary_padded_b64,
    f317_over_deep_failclosed,
    f317_single_b64_regression,
    f317_plaintext_regression,
    f317_hex_regression,
    f317_benign_silent,
    f317_decode_span_redacted,
    f319_argsmap_echo,
    f319_executor_note_echo,
    f319_parser_note_echo,
    f319_redaction_marked,
    f319_argsmap_digest_recorded,
    f319_encoded_args_echo,
]


def main():
    for probe in _PROBES:
        try:
            probe()
        except Exception as e:  # noqa: BLE001 -- a probe error is data
            _record(probe.__name__, "ERROR", "probe raised: %r" % (e,))
    _green_checks()
    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w285_f317_f319_probes: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    for pid, verdict, note in _results:
        if verdict != "HELD":
            print("  %s %s: %s" % (verdict, pid, note))
    return 1 if (nbreak or nerr) else 0


if __name__ == "__main__":
    sys.exit(main())
