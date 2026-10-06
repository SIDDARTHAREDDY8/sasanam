#!/usr/bin/env python3
"""Wave-338 lane 5 battery: Bernstein-advisory regression pins + VSA
not-verified list + coverage-table check (w337 prospectus R13/R14/R15).

Base: 6cdf5fdd (wave-337 merge). Pin: 2124->2126 at the wave-338 merge (+2 oci-*).
Footer unchanged: open none / next F430 (no findings filed here).

R13 (Bernstein GHSA-xw82-w5hr-hrm2, GHSA-4r8r-jx5c-w954 -- SKIP the
fixes, ADAPT the pins): the tree is structurally defended on all three
advisory classes (tree-checked in w337). These probes are regression
PINS -- red-first on the base (all three shapes refused, see REPORT.md)
-- that keep the defenses falsifiable:
  P1  self-issued identity record refused (GHSA-xw82 part 1): an
      Identity "issued" by the attacker's own key is NOT believed --
      verify_credential is False and authorize() raises IdentityError
      naming the pinned issuer key.
  P2  empty decision refused (GHSA-xw82 part 2): the operator-decision
      seam (web console decide handler) refuses an empty/whitespace
      reason with 400 ("the decision was NOT recorded"); the record
      stays pending and the refusal is audit-logged.
  P3  key-carrying receipt refused (GHSA-4r8r): a decision packet
      self-signed by the attacker's key (its own kid/pubkey carried in
      the authority block) refuses "untrusted-key" against the pinned
      trust root -- the carried key is never consulted.
R15 (Bernstein #5069 "the panel lists what a run did not cover"):
  P4  VSA notVerified list: the offline-verifier report names the
      stages it did NOT evaluate (trust-chain, witness,
      witness-consistency, schema-2.0 extension; predicate-content
      under existence-only) and the transcript prints them.
R14 (Bernstein #5569 "no row claims coverage without a test"):
  P5  coverage checker runs, writes the generated table, and reports
      honestly: exit 1 with the gap list (gaps are the deliverable --
      NOT hand-closed this lane), exit 2 on a pin mismatch.
P6  Pin/taxonomy honesty (2134/2134/0 sorted-unique, footer state).
P7  Green check (depth-1): tests/test_evidence_verify_offline as a
    child with GOV_SKIP_GREEN=1.

gov/ changes in this lane: gov/evidence_verify_offline.py (R15
notVerified list). New: evals/w338_honesty_probes.py,
scripts/check_decision_code_coverage.py (+ generated docs table),
tests/test_evidence_verify_offline.py (TestNotVerifiedList).
Findings: none filed.

Deterministic: fresh random keys per run; no assertion depends on key
material, timestamps, or ports. main() runs probes once; the battery
never touches the shared tree -- REPO is the tree it lives in.
"""

import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from urllib.parse import urlencode

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))
sys.path.insert(0, os.path.join(REPO, "evals"))

TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)
FOOTER_OPEN = ("F437", "F438", "F439", "F440", "F441", "F442")
FOOTER_NEXT = "F443"

_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        fn()
    except AssertionError as exc:
        _record(pid, "BREAK", "assertion: %s" % (exc,))
    except Exception as exc:  # noqa: BLE001
        _record(pid, "ERROR", "%s: %s\n%s"
                % (type(exc).__name__, exc, traceback.format_exc()[-600:]))


def _tmpd(prefix):
    base = os.environ.get("TMPDIR") or tempfile.gettempdir()
    d = tempfile.mkdtemp(prefix=prefix, dir=base)
    return d


# ---------------------------------------------------------------------------
# R13 pins.
# ---------------------------------------------------------------------------

@_probe("P1a-self-issued-identity-not-believed")
def _p1a():
    from gov import attested_identity as ai
    from gov.signing import Ed25519Signer
    issuer = Ed25519Signer(os.urandom(32))
    attacker = Ed25519Signer(os.urandom(32))
    attester = ai.Attester(issuer)
    now = int(time.time())
    claims = {"agent_id": "mallory", "kind": "forged-bootstrap"}
    body = ai.credential_body(ai.TIER_ATTESTED, claims, now + 600)
    forged = ai.Identity(
        tier=ai.TIER_ATTESTED, claims=claims,
        credential_sig=attacker.sign(ai.credential_signing_bytes(body)),
        expires_at=now + 600)
    assert attester.verify_credential(forged) is False, \
        "self-issued credential verified (GHSA-xw82 class open)"
    _held("P1a-self-issued-identity-not-believed",
          "verify_credential False on attacker-signed credential")


@_probe("P1b-self-issued-identity-authorize-refuses")
def _p1b():
    from gov import attested_identity as ai
    from gov.signing import Ed25519Signer
    issuer = Ed25519Signer(os.urandom(32))
    attacker = Ed25519Signer(os.urandom(32))
    attester = ai.Attester(issuer)
    now = int(time.time())
    claims = {"agent_id": "mallory", "kind": "forged-bootstrap"}
    body = ai.credential_body(ai.TIER_ATTESTED, claims, now + 600)
    forged = ai.Identity(
        tier=ai.TIER_ATTESTED, claims=claims,
        credential_sig=attacker.sign(ai.credential_signing_bytes(body)),
        expires_at=now + 600)
    try:
        attester.authorize(forged, "emit_telemetry")
    except ai.IdentityError as exc:
        assert "pinned" in str(exc), "refusal must name the pinned key"
        _held("P1b-self-issued-identity-authorize-refuses",
              "authorize raised IdentityError (pinned issuer key)")
        return
    raise AssertionError("authorize() accepted a self-issued identity")


@_probe("P2-empty-decision-refused")
def _p2():
    from keyfixture import provision_test_key
    provision_test_key()
    from gov.approval_web import make_server
    from harness import make_run
    d = _tmpd("w338p2-")
    prev_run_root = os.environ.get("GOV_RUN_ROOT")
    os.environ["GOV_RUN_ROOT"] = os.path.join(d, "gov-run")
    try:
        ctx = make_run()
    finally:
        if prev_run_root is None:
            os.environ.pop("GOV_RUN_ROOT", None)
        else:
            os.environ["GOV_RUN_ROOT"] = prev_run_root
    server = make_server(ctx["run_dir"], token="w338-p2-token")
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        def req(method, path, body=None, cookie=None):
            conn = http.client.HTTPConnection("127.0.0.1", port,
                                              timeout=10)
            h = {}
            if cookie:
                h["Cookie"] = cookie
            if body is not None:
                h["Content-Type"] = "application/x-www-form-urlencoded"
            conn.request(method, path, body=body, headers=h)
            resp = conn.getresponse()
            data = resp.read().decode("utf-8", "replace")
            status = resp.status
            hdrs = dict(resp.getheaders())
            conn.close()
            return status, data, hdrs

        aid = ctx["executor"].call(
            ctx["identities"]["support"], "send_email",
            to="victim@synthetic.local", subject="s", body="b",
            justification="routine vendor invoice")["approval_id"]
        st, _, hdrs = req("POST", "/login",
                          body=urlencode({"token": "w338-p2-token"}))
        assert st == 302, "login failed"
        cookie = "session=" + re.search(
            r"session=([^;]+)", hdrs.get("Set-Cookie", "")).group(1)
        st, page, _ = req("GET", "/approvals/%s" % aid, cookie=cookie)
        assert st == 200, "detail page did not render"
        csrf = re.search(
            r'''name=['"]csrf['"] value=['"]([^'"]+)['"]''',
            page).group(1)
        # Empty and whitespace-only reasons on both decision values.
        for decision, reason in (("approve", ""), ("deny", "   ")):
            fields = {"decision": decision, "reason": reason,
                      "csrf": csrf}
            status, data, _ = req(
                "POST", "/approvals/%s/decide" % aid,
                body=urlencode(fields), cookie=cookie)
            assert status == 400, \
                "empty %s reason gave HTTP %d" % (decision, status)
            assert "the decision was NOT recorded" in data, \
                "empty %s reason: refusal banner missing" % decision
        assert ctx["approvals"].get(aid)["status"] == "pending", \
            "record decided despite empty-reason refusal"
        refused = [e for e in ctx["read_log"]()
                   if e.get("event") == "web_decision_refused"
                   and e.get("approval_id") == aid
                   and e.get("reason") == "empty reason refused"]
        assert len(refused) == 2, \
            "expected 2 audit-logged refusals, got %d" % len(refused)
        _held("P2-empty-decision-refused",
              "400 + NOT recorded + pending + audited (approve/deny)")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


@_probe("P3-carried-key-receipt-refused")
def _p3():
    from gov import decision_bom as bom_mod
    from gov import decision_packet as dp
    from gov import ed25519 as _ed
    from gov import trust_material as tm
    attacker_seed = os.urandom(32)
    attacker_pub = _ed.publickey(attacker_seed)
    legit_seed = os.urandom(32)
    legit_pub = _ed.publickey(legit_seed)
    root = tm.TrustRoot({"legit-issuer": legit_pub})
    bom = bom_mod.build_bom(
        policy_id="default", policy_version="unversioned",
        policy_digest="ab" * 32, evidence_head_digest="GENESIS",
        principal={"agent_id": None, "role": None,
                   "principal": None, "run_id": None})
    body = dp.build_decision_packet(decision="allow",
                                    boundary_declared=False,
                                    bill_of_materials=bom)
    # Attacker signs with its OWN key and names it as the authority --
    # the GHSA-4r8r shape: the receipt verifies under its carried key.
    packet = dp.sign_packet(body, attacker_seed)
    ok, reason = dp.verify_decision_packet(packet, trust_root=root)
    assert ok is False, "carried-key receipt VERIFIED (GHSA-4r8r open)"
    assert "untrusted" in reason, \
        "refusal must be the untrusted-key refusal, got %r" % reason
    _held("P3-carried-key-receipt-refused",
          "untrusted-key; carried key never consulted")


# ---------------------------------------------------------------------------
# R15: VSA notVerified list.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# R15: VSA notVerified list (fixtures reused from the unit module --
# deterministic fixed seeds, no ambient key needed: the verifier uses
# its compiled-in trust root).
# ---------------------------------------------------------------------------

@_probe("P4a-vsa-names-skipped-stages")
def _p4a():
    from datetime import datetime, timezone
    from gov import evidence_verify_offline as v
    from tests.test_evidence_verify_offline import _good_bundle as _gb
    vb, bb = _gb()
    now = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
    rep = v.verify(bb, vb, time_source=v.FixedClock("t", now))
    assert rep["verificationResult"] == "PASSED"
    stages = {s["stage"] for s in rep["notVerified"]}
    want = {"trust-chain", "trust-chain-expiry", "witness",
            "witness-consistency", "schema-2.0-extension"}
    assert stages == want, "notVerified want %r, got %r" % (want, stages)
    for s in rep["notVerified"]:
        assert s["stage"] and s["reason"], "entry must name stage+reason"
    _held("P4a-vsa-names-skipped-stages",
          "notVerified lists 5 bypassed stages with reasons")


@_probe("P4b-vsa-transcript-and-existence-only")
def _p4b():
    from datetime import datetime, timezone
    from gov import evidence_verify_offline as v
    from tests.test_evidence_verify_offline import _good_bundle as _gb
    vb, bb = _gb()
    now = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
    clock = v.FixedClock("t", now)
    rep = v.verify(bb, vb, time_source=clock)
    text = v.render_transcript(rep)
    assert "NOT verified by this run" in text, \
        "transcript does not name its blind spots"
    assert "[skip] witness:" in text
    assert "PASSED != ALLOW" in text
    rep2 = v.verify(bb, vb, time_source=clock, existence_only=True)
    stages = {s["stage"] for s in rep2["notVerified"]}
    assert "predicate-content" in stages, \
        "existence-only must mark predicate-content not verified"
    _held("P4b-vsa-transcript-and-existence-only",
          "transcript prints [skip] list; existence-only labels "
          "predicate-content")


# ---------------------------------------------------------------------------
# R14: coverage-table check.
# ---------------------------------------------------------------------------

@_probe("P5-coverage-checker-reports-honestly")
def _p5():
    proc = subprocess.run(
        [sys.executable,
         os.path.join(REPO, "scripts", "check_decision_code_coverage.py"),
         REPO],
        capture_output=True, text=True, timeout=600, cwd=REPO)
    md = os.path.join(REPO, "docs", "decision-code-coverage.md")
    js = os.path.join(REPO, "docs", "decision-code-coverage.json")
    assert os.path.isfile(md) and os.path.isfile(js), \
        "checker did not write the generated table"
    doc = json.load(open(js, encoding="utf-8"))
    assert doc["pin"] == TAXONOMY_PIN == 2134, "table pin mismatch"
    assert len(doc["codes"]) == 2134
    gaps = doc["gaps"]
    if proc.returncode == 1:
        assert gaps, "exit 1 must come with a gap list"
        _held("P5-coverage-checker-reports-honestly",
              "exit 1; %d gaps listed honestly (not closed this lane)"
              % len(gaps))
    elif proc.returncode == 0:
        assert not gaps, "exit 0 with gaps is dishonest"
        _held("P5-coverage-checker-reports-honestly",
              "exit 0; all 2131 codes covered")
    else:
        raise AssertionError("checker exit %d: %s"
                             % (proc.returncode, proc.stderr[-400:]))


# ---------------------------------------------------------------------------
# P6: pin/taxonomy/footer honesty.
# ---------------------------------------------------------------------------

@_probe("P6a-taxonomy-pin")
def _p6a():
    from gov import decision_codes as dc
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    assert len(lits) == TAXONOMY_PIN == 2134, \
        "literal count %d != pin %d" % (len(lits), TAXONOMY_PIN)
    assert len(set(lits)) == TAXONOMY_PIN, "duplicate code literals"
    assert lits == sorted(lits), "literals not sorted"
    assert len(dc.TAXONOMY) == TAXONOMY_PIN
    _held("P6a-taxonomy-pin", "2134/2134/0 sorted-unique literals")


@_probe("P6b-footer")
def _p6b():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    assert "Open findings: F437, F438, F439, F440, F441, F442." in text, "footer open findings"
    assert "Next free finding: **F443**" in text, "footer next free"
    _held("P6b-footer", "footer open none / next F430 (unchanged)")


# ---------------------------------------------------------------------------
# P7: green check (depth-1).
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs on the fixed tree.


def _run_child_output(args, timeout):
    d = _tmpd("w338honesty-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(args, capture_output=True, text=True,
                          timeout=timeout, env=env, cwd=REPO)
    return proc.returncode, proc.stdout + proc.stderr


def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        rc, out = _run_child_output(
            [sys.executable, "-m", "unittest",
             "tests.test_evidence_verify_offline", "-v"], timeout=900)
    except Exception as exc:
        _record("green-check", "ERROR", "test_evidence_verify_offline: %s"
                % exc)
        return
    bad = re.findall(r"^(FAIL|ERROR):", out, re.M)
    if rc != 0 or bad or "OK" not in out:
        _record("green-check", "BREAK",
                "test_evidence_verify_offline non-green rc=%d: %s"
                % (rc, out[-400:]))
    else:
        _record("green-check", "HELD", "test_evidence_verify_offline green")


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w338_honesty battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
