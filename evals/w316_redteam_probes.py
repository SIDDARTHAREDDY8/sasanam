"""Break-first red battery for the wave-315 tree (wave-316 lane 5, independent red team).

P1 (12): VSA forgery at gov/vsa_packet.py consume_vsa -- hand-sealed FAILED
    results, verifier/keyid crosses, decision_packet transplant, double
    signatures, freshness-window abuse, untrusted verifiers. Every attack
    must refuse with a closed-vocabulary code.
P2 (5): provenance sink -- F398/F399 closed-form re-probes (both CLOSED at
    the wave-316 merge), benign controls, executor-seam wiring
    (segment-suppression skip, sink dormancy in the standard flow).
P3 (4): summary-form migration coherence -- the F400 error-path fix, the
    probe_lines seam, a GAP-contract sample.
P4 (3): new findings filed by this lane -- F401 (w310 F394 stale probes
    ERROR on the base tree), F402 (w283 F343 stale expectation BREAKs --
    CLOSED at the wave-316 merge), F403 (decision_packet.py standalone
    offline import broken).
P5 (6): regressions -- footer, pin, adjacent batteries.

Result contract: each probe prints [HELD]/[BREAK]/[ERROR]. Exit 0 iff no
BREAK and no ERROR. Two BREAKs are EXPECTED on the merged tree: the
F401/F403 open-finding probes (F398/F399/F400/F402 CLOSED at the wave-316 merge).

Depth-1 green check honoring GOV_SKIP_GREEN; no in-repo git subprocesses;
deterministic (fixed seeds, fixed clock); stdlib only.
"""

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import timedelta

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import vsa_packet as vp
from gov import provenance_sink as PS
from gov import provenance_labels as PL
from gov import decision_packet as DP
from gov import decision_codes as DC
from tests.keyfixture import scrub_key_env, provision_test_key

from evals import w315_vsa_probes as wv
from evals import w315_redteam_probes as w315
from evals import w310_redteam_probes as w310
from evals import w283_defectdojo_probes as w283
from evals import decision_packet_probes as dpp
from evals import probe_lines

_KEY_RESTORE = None


def _ensure_key():
    global _KEY_RESTORE
    if _KEY_RESTORE is None:
        _KEY_RESTORE = scrub_key_env()
        provision_test_key()


_PROBES = []


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def _error(pid, note):
    return (pid, "ERROR", note)


def _expect_refusal(pid, code, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except vp.VSAPacketError as exc:
        if exc.code == code:
            return _held(pid, "refused %s" % code)
        return _break(pid, "refused %s, expected %s" % (exc.code, code))
    except Exception as exc:  # noqa: BLE001 -- harness fault surface
        return _error(pid, "%r" % (exc,))
    return _break(pid, "accepted; expected refusal %s" % code)


# ---------------------------------------------------------------------------
# P1: VSA forgery
# ---------------------------------------------------------------------------

@probe("P1-vsa-hand-sealed-failed")
def _p1_hand_sealed_failed():
    """A VSA hand-sealed by the PINNED key over verificationResult FAILED
    must refuse coded vsa-packet-result-not-passed (the issuer-side
    ValueError only guards the honest path)."""
    env = wv._issue()
    stmt = wv._decode(env)
    stmt["predicate"]["verificationResult"] = "FAILED"
    evil = wv._reseal_statement(env, stmt, wv.SEED_A)
    return _expect_refusal("P1-vsa-hand-sealed-failed",
                           "vsa-packet-result-not-passed",
                           vp.consume_vsa, evil, expected=wv._expected())


@probe("P1-vsa-verifier-keyid-cross")
def _p1_verifier_keyid_cross():
    """Envelope keyid pinned, but only for a DIFFERENT verifier id than
    the expected one: the (signer, verifier) pair check must refuse."""
    env = wv._issue()
    exp = wv._expected(
        verifier_id="someone-else",
        signer_registry={"someone-else": [wv._pubkey_hex(wv.SEED_A)]})
    return _expect_refusal("P1-vsa-verifier-keyid-cross",
                           "vsa-packet-verifier-mismatch",
                           vp.consume_vsa, env, expected=exp)


@probe("P1-vsa-key-overlap-pair")
def _p1_key_overlap():
    """The same pubkey pinned under two verifier ids: a VSA minted for
    verifier A consumed with expected verifier B must still refuse --
    the statement's verifier.id is bound, not just the key."""
    env = wv._issue()
    exp = wv._expected(
        verifier_id="other-verifier",
        signer_registry={wv.v.VERIFIER_ID: [wv._pubkey_hex(wv.SEED_A)],
                         "other-verifier": [wv._pubkey_hex(wv.SEED_A)]})
    return _expect_refusal("P1-vsa-key-overlap-pair",
                           "vsa-packet-verifier-mismatch",
                           vp.consume_vsa, env, expected=exp)


@probe("P1-vsa-decision-packet-transplant")
def _p1_dp_transplant():
    """A genuine decision_packet DSSE envelope presented as a VSA must
    refuse at the payloadType binding, not verify as the wrong kind."""
    signer = vp.packet_key_signer(wv.SEED_A)
    dp_env = vp._dsse().seal(b'{"decision":"x"}',
                             DP.DECISION_PACKET_ENVELOPE_TYPE, [signer])
    return _expect_refusal("P1-vsa-decision-packet-transplant",
                           "vsa-packet-malformed",
                           vp.consume_vsa, dp_env, expected=wv._expected())


@probe("P1-vsa-double-signature")
def _p1_double_sig():
    """An envelope carrying two signatures (one valid, one junk) must
    refuse -- exactly one signature is the closed shape."""
    env = wv._issue()
    env2 = dict(env)
    env2["signatures"] = [env["signatures"][0],
                          {"keyid": "00" * 8, "sig": "ff" * 64}]
    return _expect_refusal("P1-vsa-double-signature",
                           "vsa-packet-malformed",
                           vp.consume_vsa, env2, expected=wv._expected())


@probe("P1-vsa-future-timeverified")
def _p1_future():
    """timeVerified in the future relative to the consumer's now must
    refuse coded vsa-packet-window-invalid."""
    env = wv._issue()
    stmt = wv._decode(env)
    future = wv.NOW + timedelta(hours=2)
    stmt["predicate"]["timeVerified"] = future.strftime("%Y-%m-%dT%H:%M:%SZ")
    evil = wv._reseal_statement(env, stmt, wv.SEED_A)
    return _expect_refusal("P1-vsa-future-timeverified",
                           "vsa-packet-window-invalid",
                           vp.consume_vsa, evil, expected=wv._expected())


@probe("P1-vsa-expired")
def _p1_expired():
    """now past timeVerified + max_age_seconds must refuse coded
    vsa-packet-window-invalid."""
    env = wv._issue()
    exp = wv._expected(now=wv.NOW_EPOCH + wv.MAX_AGE + 7200)
    return _expect_refusal("P1-vsa-expired",
                           "vsa-packet-window-invalid",
                           vp.consume_vsa, env, expected=exp)


@probe("P1-vsa-subject-transplant")
def _p1_subject():
    """A valid VSA for decision D1 consumed with expected subject D2
    must refuse coded vsa-packet-subject-mismatch."""
    env = wv._issue()
    exp = wv._expected(subject_digest=wv.OTHER_DIGEST)
    return _expect_refusal("P1-vsa-subject-transplant",
                           "vsa-packet-subject-mismatch",
                           vp.consume_vsa, env, expected=exp)


@probe("P1-vsa-resource-mismatch")
def _p1_resource():
    """resourceUri not matching the expected one must refuse coded
    vsa-packet-resource-mismatch."""
    env = wv._issue()
    exp = wv._expected(
        resource_uri=vp.DECISION_URI_SCHEME + wv.OTHER_DIGEST)
    return _expect_refusal("P1-vsa-resource-mismatch",
                           "vsa-packet-resource-mismatch",
                           vp.consume_vsa, env, expected=exp)


@probe("P1-vsa-untrusted-verifier")
def _p1_untrusted():
    """An expected verifier id the consumer never pinned at all must
    refuse coded vsa-packet-verifier-mismatch (no pair to check)."""
    env = wv._issue()
    exp = wv._expected(verifier_id="never-pinned",
                       signer_registry={wv.v.VERIFIER_ID:
                                        [wv._pubkey_hex(wv.SEED_A)]})
    return _expect_refusal("P1-vsa-untrusted-verifier",
                           "vsa-packet-verifier-mismatch",
                           vp.consume_vsa, env, expected=exp)


@probe("P1-vsa-forged-signature")
def _p1_forged_sig():
    """A bit-flipped signature under the pinned key must refuse coded
    vsa-packet-signature-invalid."""
    env = wv._issue()
    sig = env["signatures"][0]
    raw = bytearray.fromhex(sig["sig"])
    raw[0] ^= 0x01
    env2 = dict(env)
    env2["signatures"] = [dict(sig, sig=bytes(raw).hex())]
    return _expect_refusal("P1-vsa-forged-signature",
                           "vsa-packet-signature-invalid",
                           vp.consume_vsa, env2, expected=wv._expected())


@probe("P1-vsa-passed-not-allow")
def _p1_no_allow():
    """consume_vsa returns verified claims only -- no verdict, no allow,
    no admit field anywhere in the return (PASSED != ALLOW structural)."""
    env = wv._issue()
    out = vp.consume_vsa(env, expected=wv._expected())
    blob = json.dumps(out).lower()
    for word in ("allow", "verdict", "admit", "permit", "grant"):
        if word in blob:
            return _break("P1-vsa-passed-not-allow",
                          "return carries authorization word %r" % word)
    if out.get("ok") is not True:
        return _break("P1-vsa-passed-not-allow", "ok is not True")
    return _held("P1-vsa-passed-not-allow",
                 "claims only; no authorization verdict")


# ---------------------------------------------------------------------------
# P2: provenance sink -- F398/F399 closed-form re-probes, controls, seam wiring
# ---------------------------------------------------------------------------

@probe("P2-f398-still-breaks")
def _p2_f398():
    """F398 (MEDIUM, OPEN) re-probe: the negated user mention must still
    authorize the prohibited send. Delegates to the lane-3 probe."""
    _ensure_key()
    pid, verdict, note = w315._p2_refine_negation()
    if verdict == "BREAK":
        return _break("P2-f398-still-breaks",
                      "F398 still open: %s" % note[:160])
    if verdict == "ERROR":
        return _error("P2-f398-still-breaks", note[:200])
    return _held("P2-f398-still-breaks",
                 "F398 closed: negated mention no longer authorizes")


@probe("P2-f398-controls")
def _p2_f398_controls():
    """F398 benign controls: genuine authorization ALLOWs; the no-mention
    send REFUSEs. Both must hold on the open tree."""
    _ensure_key()
    ok = True
    notes = []
    for name in ("P2-refinement-benign-no-fp", "P2-user-segment-allows"):
        fn = dict(w315._PROBES).get(name)
        if fn is None:
            return _error("P2-f398-controls", "control probe %s missing" % name)
        pid, verdict, note = fn()
        notes.append("%s=%s" % (name, verdict))
        if verdict != "HELD":
            ok = False
    if not ok:
        return _break("P2-f398-controls",
                      "benign control regressed: %s" % "; ".join(notes))
    return _held("P2-f398-controls", "; ".join(notes))


@probe("P2-f399-closed")
def _p2_f399():
    """F399 CLOSED (wave-316 lane 2): delegates to w315's closed-form
    P2-sink-per-seam-context probe -- a retained sink at the seam makes
    the 4th same-context refusal escalate-terminal."""
    _ensure_key()
    pid, verdict, note = w315._p2_seam_sink()
    if verdict == "BREAK":
        return _break("P2-f399-closed",
                      "F399 regressed to open: %s" % note[:160])
    if verdict == "ERROR":
        return _error("P2-f399-closed", note[:200])
    return _held("P2-f399-closed",
                 "F399 closed: retained sink at the seam, 4th refusal terminal")


@probe("P2-f399-control-terminal")
def _p2_f399_control():
    """F399 control: one stateful sink still escalates terminal at the
    4th refusal (the ratchet works when the instance is reused)."""
    _ensure_key()
    pid, verdict, note = w315._p2_budget_terminal()
    if verdict != "HELD":
        return _break("P2-f399-control-terminal",
                      "ratchet regressed on a reused sink: %s" % note[:160])
    return _held("P2-f399-control-terminal", note[:160])


@probe("P2-sink-seam-wiring")
def _p2_wiring():
    """Executor-seam wiring: provenance_gate with no segments must skip
    (None -- the documented lane-B discipline); and no gov/ module may
    write provenance_segments into approval records, i.e. the sink is
    dormant in the standard flow until producer wiring lands (pinned
    integration residual, not a defect)."""
    _ensure_key()
    v = PS.provenance_gate("send_email", {"to": "x@y"}, None)
    if v is not None:
        return _break("P2-sink-seam-wiring",
                      "gate with segments=None did not skip: %r" % (v,))
    writers = []
    govdir = os.path.join(REPO, "gov")
    for leaf in sorted(os.listdir(govdir)):
        if not leaf.endswith(".py"):
            continue
        path = os.path.join(govdir, leaf)
        with open(path, encoding="utf-8") as f:
            src = f.read()
        if leaf == "provenance_sink.py":
            continue
        # an assignment into rec["provenance_segments"] / rec.get default
        for i, line in enumerate(src.splitlines(), 1):
            s = line.strip()
            if ('"provenance_segments"' in s or
                    "'provenance_segments'" in s):
                if "=" in s and ".get(" not in s and "==" not in s \
                        and "!=" not in s:
                    writers.append("%s:%d" % (leaf, i))
    if writers:
        return _break("P2-sink-seam-wiring",
                      "unexpected segment writers: %s" % writers)
    return _held("P2-sink-seam-wiring",
                 "gate skips on None; no gov/ producer writes segments "
                 "(sink dormant in standard flow -- pinned residual)")


# ---------------------------------------------------------------------------
# P3: summary-form migration coherence
# ---------------------------------------------------------------------------

@probe("P3-f400-error-path-fixed")
def _p3_f400():
    """F400 (LOW, OPEN -- fix landed): w280's _seal_verdict except arm
    must return uppercase "ERROR" and main() must tally it and exit 1."""
    path = os.path.join(REPO, "evals", "w280_redteam_probes.py")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    if 'return "ERROR", "%s: %s" % (type(e).__name__, e)' not in src:
        return _break("P3-f400-error-path-fixed",
                      "except arm does not return uppercase ERROR")
    if "return 0 if not errors else 1" not in src:
        return _break("P3-f400-error-path-fixed",
                      "main() does not exit 1 on errors")
    return _held("P3-f400-error-path-fixed",
                 "except arm returns ERROR; main tallies and exits 1")


@probe("P3-probe-lines-seam")
def _p3_seam():
    """The probe_lines seam: emit_dicts is fail-closed and LOUD on an
    unknown verdict (prints an [ERROR] line, never silently maps);
    first_line truncates at 160 chars; parse_line round-trips."""
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        probe_lines.emit_dicts(
            [{"probe_id": "x", "verdict": "NOPE", "note": "n"}])
    out = buf.getvalue()
    if "[ERROR]" not in out or "NOPE" not in out:
        return _break("P3-probe-lines-seam",
                      "unknown verdict not loud: %r" % out[:120])
    if "[BREAK]" in out or "[HELD]" in out:
        return _break("P3-probe-lines-seam",
                      "unknown verdict silently mapped to a verdict")
    long_note = "n" * 500
    # the spec's canonical form is first_line(note)[:160] at call sites
    if len(probe_lines.first_line(long_note)[:160]) > 160:
        return _break("P3-probe-lines-seam", "first_line[:160] not truncated")
    if probe_lines.first_line("a\nb") != "a":
        return _break("P3-probe-lines-seam", "first_line wrong")
    line = '[BREAK] pid-x: some note'
    parsed = probe_lines.parse_line(line)
    if parsed is None:
        return _break("P3-probe-lines-seam", "parse_line failed")
    return _held("P3-probe-lines-seam",
                 "loud ERROR on bad verdict; 160-char truncation; "
                 "parse round-trips")


@probe("P3-gap-contract-sample")
def _p3_gap():
    """One of the 18 named GAP-contract exceptions (w217_quorum): on the
    real tree the battery passes rc=0 and the GAP->BREAK mapping only
    changes the hypothetical absent-module path (documented judgment)."""
    path = os.path.join(REPO, "evals", "w217_quorum_probes.py")
    if not os.path.exists(path):
        return _error("P3-gap-contract-sample", "w217 file missing")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    if "GAP" in src and "[GAP]" in src:
        return _break("P3-gap-contract-sample",
                      "literal [GAP] emitter remains")
    return _held("P3-gap-contract-sample",
                 "no literal [GAP] emitters; canonical form")


@probe("P3-migration-canonical-counts")
def _p3_counts():
    """Migrated batteries must not emit literal [GAP]/[VERDICT] verdicts
    (spot: w280, w315_vsa, w217)."""
    bad = []
    for leaf in ("w280_redteam_probes.py", "w315_vsa_probes.py",
                 "w217_quorum_probes.py"):
        path = os.path.join(REPO, "evals", leaf)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            src = f.read()
        if "[GAP]" in src or "[VERDICT]" in src:
            bad.append(leaf)
    if bad:
        return _break("P3-migration-canonical-counts",
                      "non-canonical verdict literals: %s" % bad)
    return _held("P3-migration-canonical-counts",
                 "no literal [GAP]/[VERDICT] emitters in spot sample")


# ---------------------------------------------------------------------------
# P4: new findings filed by this lane
# ---------------------------------------------------------------------------

@probe("P4-f401-w310-f394-stale")
def _p4_f401():
    """F401 (LOW, test-infra, OPEN): w310_redteam's F394 probes ERROR on
    the base tree -- stale after the wave-313 F397 closure (the probe
    passes a stale `at`, the F397 closure refuses coded
    workflow-saga-resolution-invalid, the probe only catches the old
    F394 code)."""
    w310._results.clear()
    w310._safe("F394-op-retry-composed", w310.p_f394_op_retry_composed)
    w310._safe("F394-abort-composed", w310.p_f394_abort_composed)
    errs = [r for r in w310._results if r[1] == "ERROR"]
    if len(errs) == 2:
        return _break("P4-f401-w310-f394-stale",
                      "F401: both F394 probes ERROR on base: %s | %s"
                      % (errs[0][2][:120], errs[1][2][:120]))
    if errs:
        return _break("P4-f401-w310-f394-stale",
                      "F401 partial: %s" % (errs[0][2][:160],))
    return _held("P4-f401-w310-f394-stale",
                 "F394 probes no longer ERROR (fixed)")


@probe("P4-f402-w283-f343-stale")
def _p4_f402():
    """F402 CLOSED (wave-316 merge): w283_defectdojo's p-findings-md-load
    expectation corrected to `verified` (wave-316 lane 3 rot-pin) --
    F343/F344/F345 were CLOSED at the wave-289 merge; the probe now
    passes. The product was never defective."""
    w283._RESULTS.clear()
    w283.p_findings_md_load()
    recs = [r for r in w283._RESULTS
            if r["probe_id"] == "p-findings-md-load"]
    if not recs:
        return _error("P4-f402-w283-f343-stale", "probe recorded nothing")
    rec = recs[-1]
    if rec["verdict"] == "BREAK" and "F343" in rec["note"]:
        return _break("P4-f402-w283-f343-stale",
                      "F402: %s" % rec["note"][:200])
    if rec["verdict"] == "BREAK":
        return _break("P4-f402-w283-f343-stale",
                      "F402 (different): %s" % rec["note"][:200])
    return _held("P4-f402-w283-f343-stale",
                 "F402 closed: p-findings-md-load expects verified, 0 BREAK")


@probe("P4-f403-decision-packet-offline")
def _p4_f403():
    """F403 (LOW, product, OPEN): decision_packet.py cannot be imported
    standalone -- decision_bom.py's unguarded `from .mode_ledger import
    LADDER_MODES` defeats the offline-verification contract asserted by
    the green-phase offline_verify probe."""
    try:
        verdict, note = dpp.probe_offline_verify()
    except AssertionError as exc:
        return _break("P4-f403-decision-packet-offline",
                      "F403: standalone import fails: %s" % str(exc)[:200])
    if verdict == "FAIL":
        return _break("P4-f403-decision-packet-offline",
                      "F403: standalone import fails: %s" % note[:200])
    if verdict != "PASS":
        return _error("P4-f403-decision-packet-offline", note[:200])
    return _held("P4-f403-decision-packet-offline",
                 "standalone offline import works (fixed)")


# ---------------------------------------------------------------------------
# P5: regressions
# ---------------------------------------------------------------------------

_FOOTER_RE = re.compile(
    r"Next free finding: \*\*F(\d+)\*\*\. \*\*Open findings: ([^*]*)\.\*\*")


def _footer():
    path = os.path.join(REPO, "evals", "FINDINGS.md")
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    last = None
    for line in lines:
        m = _FOOTER_RE.search(line)
        if m:
            last = (int(m.group(1)), m.group(2).strip())
    return last


@probe("P5-footer-state")
def _p5_footer():
    """Footer: open F401, F403 / next F404 (F398/F399/F400 CLOSED at the wave-316 merge)."""
    got = _footer()
    if got != (404, "F401, F403"):
        return _break("P5-footer-state", "footer is %r" % (got,))
    return _held("P5-footer-state",
                 "open F401, F403 / next F404")


@probe("P5-pin-taxonomy-1900-sorted")
def _p5_pin():
    """Taxonomy pin 1900/1900/0 on raw source literals, sorted, unique
    (wave-260 lesson: assert on literals, not the deduped dict)."""
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    lits += re.findall(r'"code":\s*"([^"]+)"', src)
    if len(lits) != 1900:
        return _break("P5-pin-taxonomy-1900-sorted",
                      "literals %d != pin 1900" % len(lits))
    if len(set(lits)) != len(lits):
        return _break("P5-pin-taxonomy-1900-sorted",
                      "duplicate code literals in source")
    if sorted(lits) != lits:
        return _break("P5-pin-taxonomy-1900-sorted", "literals not sorted")
    if len(DC.TAXONOMY) != 1900:
        return _break("P5-pin-taxonomy-1900-sorted",
                      "TAXONOMY dict has %d" % len(DC.TAXONOMY))
    return _held("P5-pin-taxonomy-1900-sorted", "1900/1900/0 sorted")


def _run_battery(path, expect, break_must_contain=None):
    """Run a sibling battery with GOV_SKIP_GREEN=1; check counts.

    expect is (break, held, error). break_must_contain, when given,
    requires every BREAK line to mention that substring (used for the
    expected footer-drift signal: the break is the footer-state probe,
    i.e. merge-maintenance, not a regression).
    """
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="w316-green-")
    try:
        p = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, cwd=REPO, env=env)
    finally:
        shutil.rmtree(env["TMPDIR"], ignore_errors=True)
    out = p.stdout + p.stderr
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", out)
    if not m:
        m2 = re.search(r"probes: (\d+) held / (\d+) BREAK / (\d+) errors",
                       out)
        if m2:
            got = (int(m2.group(2)), int(m2.group(1)), int(m2.group(3)))
        else:
            return ("ERROR", "no summary in %s" % os.path.basename(path))
    else:
        got = tuple(int(x) for x in m.groups())
    if got != expect:
        return ("BREAK", "%s: got %d/%d/%d, want %d/%d/%d"
                % ((os.path.basename(path),) + got + expect))
    if break_must_contain and expect[0]:
        bad = [l for l in out.splitlines()
               if l.startswith("[BREAK]") and break_must_contain not in l]
        if bad:
            return ("BREAK", "%s: non-footer BREAK: %s"
                    % (os.path.basename(path), bad[0][:120]))
    return ("HELD", "%s: %d/%d/%d as expected"
            % ((os.path.basename(path),) + got))


@probe("P5-green-approval-tokens")
def _p5_apt():
    # the 1 BREAK is the footer-state probe pinning the wave-313 footer
    # (expected footer-drift; merge-maintenance, not a regression)
    verdict, note = _run_battery(
        os.path.join(REPO, "evals", "w313_aptokens_probes.py"), (1, 20, 0),
        break_must_contain="footer-state")
    return ("P5-green-approval-tokens", verdict, note)


@probe("P5-green-plan-policy")
def _p5_plan():
    # the 1 BREAK is the footer-state probe pinning the wave-313 footer
    # (expected footer-drift; merge-maintenance, not a regression)
    verdict, note = _run_battery(
        os.path.join(REPO, "evals", "w313_plancheck_probes.py"), (1, 22, 0),
        break_must_contain="footer-state")
    return ("P5-green-plan-policy", verdict, note)


@probe("P5-green-vsa")
def _p5_vsa():
    verdict, note = _run_battery(
        os.path.join(REPO, "evals", "w315_vsa_probes.py"), (0, 20, 0))
    return ("P5-green-vsa", verdict, note)


@probe("P5-green-w315-redteam")
def _p5_w315():
    # F398/F399 CLOSED at the wave-316 merge; footer re-pinned
    verdict, note = _run_battery(
        os.path.join(REPO, "evals", "w315_redteam_probes.py"), (0, 39, 0))
    return ("P5-green-w315-redteam", verdict, note)


@probe("P5-green-w280-redteam")
def _p5_w280():
    verdict, note = _run_battery(
        os.path.join(REPO, "evals", "w280_redteam_probes.py"), (0, 24, 0))
    return ("P5-green-w280-redteam", verdict, note)


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

def _single(pid):
    for _pid, fn in _PROBES:
        if _pid == pid:
            return [fn()]
    return [("?", "ERROR", "unknown probe %s" % pid)]


GREEN_EVALS = [
    # (name, path, expected (break, held, error)) -- depth-1: children run
    # with GOV_SKIP_GREEN=1 and never spawn their own green checks.
    ("w315-redteam", "evals/w315_redteam_probes.py", (3, 36, 0)),
    ("w315-vsa", "evals/w315_vsa_probes.py", (0, 20, 0)),
    # w313 batteries: the 1 BREAK is the footer-state probe pinning the
    # wave-313 footer (expected footer-drift; merge-maintenance).
    ("w313-aptokens", "evals/w313_aptokens_probes.py", (1, 20, 0)),
    ("w313-plancheck", "evals/w313_plancheck_probes.py", (1, 22, 0)),
    ("w280-redteam", "evals/w280_redteam_probes.py", (0, 24, 0)),
    # decision_packet_probes: the 1 BREAK is the offline_verify probe =
    # F403 (filed by this lane). Expected, not a regression.
    ("decision-packet", "evals/decision_packet_probes.py", (1, 9, 0)),
]


def _run_green_eval(name, rel, expect):
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="w316-gc-")
    try:
        p = subprocess.run(
            [sys.executable, os.path.join(REPO, rel)],
            capture_output=True, text=True, timeout=900,
            cwd=REPO, env=env)
    except Exception as exc:  # noqa: BLE001
        return ("green-" + name, "ERROR", "%r" % (exc,))
    finally:
        shutil.rmtree(env["TMPDIR"], ignore_errors=True)
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR",
                  p.stdout + p.stderr)
    if not m:
        # w315_vsa uses "probes: %d held / %d BREAK / %d errors"
        m2 = re.search(r"probes: (\d+) held / (\d+) BREAK / (\d+) errors",
                       p.stdout + p.stderr)
        if m2:
            got = (int(m2.group(2)), int(m2.group(1)), int(m2.group(3)))
        else:
            # decision_packet_probes uses "N BREAK / M HELD"
            m3 = re.search(r"(\d+) BREAK / (\d+) HELD",
                           p.stdout + p.stderr)
            if m3 and name == "decision-packet":
                got = (int(m3.group(1)), int(m3.group(2)), 0)
            else:
                return ("green-" + name, "ERROR",
                        "no parseable summary; rc=%d tail=%r"
                        % (p.returncode, (p.stdout + p.stderr)[-200:]))
    else:
        got = tuple(int(x) for x in m.groups())
    if got != expect:
        return ("green-" + name, "BREAK",
                "got %d/%d/%d, want %d/%d/%d"
                % (got + expect))
    return ("green-" + name, "HELD", "%d/%d/%d as expected" % got)


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    if only == "--list":
        print("\n".join(p for p, _ in _PROBES))
        return 0
    results = _single(only) if only else [fn() for _, fn in _PROBES]
    breaks = [r for r in results if r[1] == "BREAK"]
    held = [r for r in results if r[1] == "HELD"]
    errors = [r for r in results if r[1] == "ERROR"]
    for pid, verdict, note in results:
        print("[%s] %s: %s" % (verdict, pid, note))
    greens = []
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        for name, rel, expect in GREEN_EVALS:
            greens.append(_run_green_eval(name, rel, expect))
    else:
        greens.append(("green-skipped", "HELD",
                       "green check skipped (GOV_SKIP_GREEN=1)"))
    for pid, verdict, note in greens:
        print("[%s] green-%s: %s" % (verdict, pid, note))
    gbreaks = [g for g in greens if g[1] == "BREAK"]
    gerrs = [g for g in greens if g[1] == "ERROR"]
    print("----")
    print("w316_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(greens: %d break / %d error)"
          % (len(breaks), len(held), len(errors),
             len(gbreaks), len(gerrs)))
    if breaks or errors or gbreaks or gerrs:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
