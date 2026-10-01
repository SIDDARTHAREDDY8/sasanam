"""Break-first red-team battery for the wave-259/wave-260 seams.

Wave-260 independent red-team lane. Stdlib only. Deterministic across
runs (staging + `env -u GOV_DEPLOYMENT_MODE`). No in-repo git
subprocesses (wave-36 supply-chain probe: fail closed).

Targets (base 0b7e1d28, taxonomy pin 1092):
- gov/transparency_log.py -- tail-truncation invisibility to
  verify_log (F230), detect_equivocation counting unsigned/forged
  heads as conflicts (F231), raw OSError escapes on the operator
  path (F232).
- gov/key_groups.py -- quorum/scope-confusion games, journal
  leakage, the documented crypto-duplication seam (all HELD).
- gov/svid_issuer.py -- usage field signed but never enforced
  (F233), F228-shaped path-dependent `now` validation in
  SvidVerifier.verify / TestSvidIssuer.issue (F234).
- F227/F228/F229 seams: cross-checked only (filed OPEN, dedicated
  closure lanes). Probes reproduce the defect on this base as
  BASELINE -- not new findings.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / gap documented as an
honest residual), BREAK (genuine defect -> filed as a finding
F230+), BASELINE (filed-open finding reproduced, or accepted
documented behavior -- NOT a new finding), ERROR (harness bug --
fix the harness, never the product).
"""

import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import key_groups as kg  # noqa: E402
from gov import svid_issuer as sv  # noqa: E402
from gov import transparency_log as tl  # noqa: E402

# Wave-260 base pin: no taxonomy codes added or removed by this lane.
# If the count moves, the delta must be explained by a landed taxonomy
# change -- never repoint blindly (replace the VALUE only).
TAXONOMY_PIN = 1299  # Wave-268 merge: pin -> 1299.

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    return tempfile.mkdtemp(prefix="w260rt-", dir="/var/tmp")


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _baseline(detail=""):
    return ("BASELINE", detail)


def _svid_pair():
    seed = bytes.fromhex("aa" * 32)
    issuer = sv.TestSvidIssuer(issuer_seed=seed)
    verifier = sv.SvidVerifier({issuer.key_id: issuer.issuer_public_key},
                               "example.org")
    return issuer, verifier


def _svid_code(fn):
    try:
        fn()
    except sv.SvidError as e:
        return e.code
    return "NO-RAISE"


def _kg_code(fn):
    try:
        fn()
    except kg.KeyGroupError as e:
        return e.code
    return "NO-RAISE"


# ---------------------------------------------------------------------------
# F230: tail truncation invisible to verify_log / detect_equivocation
# ---------------------------------------------------------------------------

@probe("transparency/tail-truncation-invisible-to-verify-log")
def _p_f230():
    # Wave-261 closure: verify_log grew a witnessed-state comparison
    # (expected_head / expected_size). The probe now witnesses the
    # latest signed head BEFORE truncation and checks the truncated
    # log against it -- keyless (auditor mode). Pin-probe updated by
    # the wave-261 lane A closure; the no-arg self-consistency check
    # cannot see truncation by design (documented residual).
    seed = bytes.fromhex("cc" * 32)
    d = _tmpdir()
    log = tl.TransparencyLog(d, signing_key=seed)
    for tag in ("aa", "bb", "cc", "dd", "ee"):
        log.append(tag * 32)
    witness = log.latest_head()  # witnessed out-of-band (size 5)
    ok_before, _ = tl.TransparencyLog(
        d, public_key=bytes.fromhex(log._log_id)).verify_log(
            expected_head=witness)
    if not ok_before:
        return ("ERROR", "pristine log did not verify before tampering")
    # Attacker with write access to the log directory (no signing key)
    # deletes the tail of both files.
    for fname in (tl.LEAVES_FILE, tl.HEADS_FILE):
        path = os.path.join(d, fname)
        with open(path, encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[:-1]) + "\n")
    reopened = tl.TransparencyLog(
        d, public_key=bytes.fromhex(log._log_id))
    ok, detail = reopened.verify_log(expected_head=witness)
    if ok:
        return _break(
            "verify_log(expected_head=witness)=True (%s) after "
            "deleting the last append from both files" % detail)
    return _held("truncation detected vs witnessed head: %s"
                 % detail[:80])


# ---------------------------------------------------------------------------
# F231: detect_equivocation counts unsigned/forged heads as conflicts
# ---------------------------------------------------------------------------

@probe("transparency/equivocation-unsigned-head-counts-as-conflict")
def _p_f231():
    seed = bytes.fromhex("cc" * 32)
    d = _tmpdir()
    log = tl.TransparencyLog(d, signing_key=seed)
    head = log.append("ab" * 32)
    forged = dict(head)
    forged["root_hash"] = "ff" * 32
    forged["signature"] = "00" * 128  # 64 zero bytes: not a real sig
    assert not tl.verify_tree_head(forged, log._log_id)
    conflicts = log.detect_equivocation([head, forged])
    if conflicts:
        return _break(
            "conflict reported from an UNSIGNED head "
            "(verify_tree_head=False): %s" % conflicts[0]["note"][:80])
    return _held("unsigned head ignored by detect_equivocation")


# ---------------------------------------------------------------------------
# F232: raw OSError escapes on the transparency-log operator path
# ---------------------------------------------------------------------------

@probe("transparency/operator-path-raw-oserror-escapes")
def _p_f232():
    seed = bytes.fromhex("cc" * 32)
    raw = []

    # (a) log path exists as a file, not a directory
    fd, fpath = tempfile.mkstemp(prefix="w260rt-file-", dir="/var/tmp")
    os.close(fd)
    try:
        tl.TransparencyLog(fpath, signing_key=seed)
        raw.append("init-path-is-file: no exception")
    except tl.TransparencyLogError:
        pass
    except Exception as e:  # noqa: BLE001 -- the defect under test
        raw.append("init-path-is-file: raw %s" % type(e).__name__)
    finally:
        os.unlink(fpath)

    # (b) append I/O failure (leaves.jsonl replaced by a directory)
    d = _tmpdir()
    log = tl.TransparencyLog(d, signing_key=seed)
    log.append("ab" * 32)
    os.remove(os.path.join(d, tl.LEAVES_FILE))
    os.mkdir(os.path.join(d, tl.LEAVES_FILE))
    try:
        log.append("cd" * 32)
        raw.append("append-io-failure: no exception")
    except tl.TransparencyLogError:
        pass
    except Exception as e:  # noqa: BLE001 -- the defect under test
        raw.append("append-io-failure: raw %s" % type(e).__name__)

    if raw:
        return _break("; ".join(raw))
    return _held("all operator-path I/O failures raise "
                 "TransparencyLogError")


# ---------------------------------------------------------------------------
# F233 (CLOSED wave-261 lane B): SVID usage now enforced at both seams.
# The probe pins the closure: mismatches must refuse with machine codes.
# ---------------------------------------------------------------------------

@probe("svid/usage-never-enforced-by-verifier-or-mesh")
def _p_f233():
    issuer, verifier = _svid_pair()
    wk = "bb" * 32
    workload_svid = issuer.issue("spiffe://example.org/workload/agent1",
                                 wk, 5, profile="workload")
    mesh_svid = issuer.issue("spiffe://example.org/workload/agent1",
                             wk, 5, profile="mesh-control")
    assert workload_svid["usage"] == ["workload-auth"]
    assert mesh_svid["usage"] == ["mesh-control"]
    # (a) verifier seam: expected usage not covered by the SVID's
    # signed usage list -> svid-usage-mismatch.
    vcode = _svid_code(lambda: verifier.verify(
        mesh_svid, expected_usage="workload-auth"))
    # (b) admit seam: MeshControl binds allowed usages per policy ->
    # svid-acl-denied.
    mesh_acl = sv.MeshControl(
        verifier,
        {"allow": ["spiffe://example.org/workload"],
         "usages": ["workload-auth"]})
    acode = _svid_code(lambda: mesh_acl.admit(mesh_svid))
    # (c) per-call expected_usage threads through admit() to the
    # verifier seam.
    pcode = _svid_code(lambda: sv.MeshControl(
        verifier,
        {"allow": ["spiffe://example.org/workload"]}).admit(
            mesh_svid, expected_usage="workload-auth"))
    if vcode == sv.SVID_USAGE_MISMATCH_CODE and\
            acode == sv.SVID_ACL_DENIED_CODE and\
            pcode == sv.SVID_USAGE_MISMATCH_CODE:
        return _held("usage mismatch refused at both seams "
                     "(svid-usage-mismatch / svid-acl-denied)")
    return _break("usage enforcement gap: verify=%s admit-usages=%s "
                  "admit-expected=%s" % (vcode, acode, pcode))


# ---------------------------------------------------------------------------
# F234: svid_issuer `now` validation is path-dependent (F228 shape)
# ---------------------------------------------------------------------------

@probe("svid/now-validation-path-dependent")
def _p_f234():
    issuer, verifier = _svid_pair()
    good = issuer.issue("spiffe://example.org/w/a", "bb" * 32, 5)
    bad_sig = dict(good)
    bad_sig["issuer_signature"] = "00" * 64  # 128 hex chars, wrong sig
    good_path = _svid_code(
        lambda: verifier.verify(good, now="yesterday"))
    refusal_path = _svid_code(
        lambda: verifier.verify(bad_sig, now="yesterday"))
    missing_path = _svid_code(
        lambda: verifier.verify(None, now="yesterday"))
    issue_refusal = _svid_code(
        lambda: issuer.issue("not-a-spiffe-id", "bb" * 32, 5,
                             now="yesterday"))
    issue_good = _svid_code(
        lambda: issuer.issue("spiffe://example.org/w/a", "bb" * 32, 5,
                             now="yesterday"))
    # The module documents svid-malformed as the F224 _validate_now
    # refusal code; it must not depend on SVID validity.
    bad = []
    if good_path != sv.SVID_MALFORMED_CODE:
        bad.append("good-path=%s" % good_path)
    for label, got in (("bad-sig", refusal_path),
                       ("missing", missing_path),
                       ("issue-refusal", issue_refusal),
                       ("issue-good", issue_good)):
        if got != sv.SVID_MALFORMED_CODE:
            bad.append("%s=%s" % (label, got))
    if bad:
        return _break("non-numeric `now` refused as: " + ", ".join(bad))
    return _held("`now` validated before every refusal decision")


# ---------------------------------------------------------------------------
# F227/F228/F229 cross-checks (filed OPEN -- BASELINE, not new findings)
# ---------------------------------------------------------------------------

@probe("baseline/f227-malformed-results-missing-control-id-keyerror")
def _b_f227():
    from gov import control_profiles as cp
    # Same shape as the wave-259 standing pin probe.
    fake = {"profile_id": "P1", "profile_title": "t",
            "profile_digest": "00" * 32, "success": False,
            "results": [{
                "status": "fail", "impact": 0.9, "severity": "high",
                "check": "f", "check_version": "1", "reason": "x",
                "exception_info": None, "digest": "11" * 32,
                # no "control_id"
            }]}
    try:
        cp.emit_profile_results(fake, fmt="json")
        return ("ERROR", "no exception on malformed results")
    except KeyError as e:
        return _baseline("raw KeyError(%s) still escapes (F227 open)"
                         % (e,))
    except cp.ControlProfileError as e:
        return _held("machine-coded refusal: %s" % e.code)


@probe("baseline/f228-credentials-now-validation-path-dependent")
def _p_f228x():
    from gov import short_lived_credentials as slc
    iss = slc.CredentialIssuer(
        os.path.join(_tmpdir(), "c.journal"), key=b"0" * 32)
    c = iss.issue("agent-a", "read:docs", 60)
    cid, sec = c["credential_id"], c["secret"]
    def code_of(fn):
        try:
            fn()
        except slc.CredentialError as e:
            return e.code
        return "NO-RAISE"
    unknown = code_of(
        lambda: iss.verify("no-such-id", "x", now="yesterday"))
    mismatch = code_of(
        lambda: iss.verify(cid, "wrong-secret", now="yesterday"))
    if unknown != "short-lived-credential-malformed" or\
            mismatch != "short-lived-credential-malformed":
        return _baseline(
            "F228 open: unknown=%s mismatch=%s (want malformed on "
            "both)" % (unknown, mismatch))
    return _held("`now` validated on all verify() paths")


@probe("baseline/f229-hostile-deepcopy-runtimeerror-raw-escape")
def _p_f229x():
    from gov import evidence_quality as eq
    class Hostile(object):
        def __deepcopy__(self, memo):
            raise RuntimeError("boom-from-deepcopy")
    exps = [{"expectation_type": "expect_evidence_monotonic",
             "kwargs": {}}]
    try:
        eq.evaluate(exps, [{"seq": 1, "obj": Hostile()}])
        return ("ERROR", "no exception on hostile deepcopy")
    except RuntimeError:
        return _baseline("raw RuntimeError still escapes evaluate() "
                         "(F229 open)")
    except eq.EvidenceQualityError as e:
        return _held("machine-coded refusal: %s" % e.code)


# ---------------------------------------------------------------------------
# HELD: key_groups seams probed, no gap
# ---------------------------------------------------------------------------

@probe("keygroups/crypto-duplication-seam-holds")
def _h_kg_dup():
    # The documented duplication seam: key_groups re-implements the
    # HMAC-CTR + encrypt-then-MAC construction instead of importing it.
    # A divergence would be a finding; verify identical modulo domain.
    from gov import encrypted_envelopes as ee
    import inspect
    k = b"k" * 32
    a, b = kg._kdf(k, b"payload-enc", 32), ee._kdf(k, b"payload-enc", 32)
    same_shape = (inspect.getsource(kg._kdf)
                  .replace("sasanam-keygroup/v1/", "D") ==
                  inspect.getsource(ee._kdf)
                  .replace("sasanam-envelope/v1/", "D"))
    if a != b and same_shape:
        return _held("constructions identical; domains separate "
                     "(no cross-decryption)")
    return _break("KDF divergence across the duplication seam")


@probe("keygroups/journal-carries-no-key-material-or-plaintext")
def _h_kg_journal():
    d = _tmpdir()
    v = kg.GroupVault(os.path.join(d, "j.jsonl"))
    m1 = bytes.fromhex("11" * 16)
    g = kg.KeyGroup([kg.KeyShare("alice", m1)], quorum=1)
    env = v.seal(b"secret-payload", [g], scope="payments")
    try:
        v.open(env, {"alice": b"wrong-wrong-wrong!"}, scope="payments")
    except kg.KeyGroupError:
        pass
    with open(os.path.join(d, "j.jsonl"), encoding="utf-8") as f:
        blob = f.read()
    if m1.hex() in blob or "secret-payload" in blob:
        return _break("key material or plaintext present in the journal")
    # key ids + scopes are wire-public by documented design.
    if '"alice"' in blob and '"payments"' in blob:
        return _held("journal is digest-only + wire-public ids/scopes")
    return ("ERROR", "expected journal entries missing")


@probe("keygroups/scope-gating-exact-bytes")
def _h_kg_scope():
    d = _tmpdir()
    v = kg.GroupVault(os.path.join(d, "j.jsonl"))
    m1, m2 = bytes.fromhex("11" * 16), bytes.fromhex("22" * 16)
    g = kg.KeyGroup([kg.KeyShare("alice", m1, scope="refunds"),
                     kg.KeyShare("bob", m2)], quorum=1)
    env = v.seal(b"payload", [g], scope="payments")
    cross = _kg_code(
        lambda: v.open(env, {"alice": m1}, scope="payments"))
    right = _kg_code(
        lambda: v.open(env, {"alice": m1}, scope="refunds"))
    if cross == "keygroup-open-refused" and right == "NO-RAISE":
        return _held("cross-scope use refused; declared-scope use opens")
    return _break("scope gating wrong: cross=%s right=%s" % (cross, right))


# ---------------------------------------------------------------------------
# BASELINE: documented svid boundaries, verified on base
# ---------------------------------------------------------------------------

@probe("baseline/svid-degenerate-allow-prefix-bounded-by-verify")
def _b_svid_allow():
    issuer, verifier = _svid_pair()
    s = issuer.issue("spiffe://example.org/anything/deep", "bb" * 32, 5)
    mc = sv.MeshControl(verifier, {"allow": ["spiffe://"]})
    # Degenerate entry admits everything -- but only inside the
    # verifier's already-enforced trust domain (verify-first).
    try:
        admitted = mc.admit(s)
    except sv.SvidError as e:
        return ("ERROR", "degenerate allow refused: %s" % e.code)
    foreign = dict(s)
    foreign["spiffe_id"] = "spiffe://evil.example/x"
    fcode = _svid_code(lambda: mc.admit(foreign))
    if admitted and fcode == sv.SVID_TRUST_DOMAIN_MISMATCH_CODE:
        return _baseline(
            "'spiffe://' admits all in-domain ids; foreign trust "
            "domain still refused (verify-first bounds the shape)")
    return ("ERROR", "unexpected admit behavior")


@probe("baseline/svid-no-not-before-claim")
def _b_svid_nb():
    import time
    issuer, verifier = _svid_pair()
    future = issuer.issue("spiffe://example.org/w/a", "bb" * 32, 5,
                          now=time.time() + 86400)
    try:
        claims = verifier.verify(future)
    except sv.SvidError as e:
        return ("ERROR", "future-dated SVID refused: %s" % e.code)
    # The module claims no not-before: issuance time is the issuer's,
    # and the issuer is the trust root. Documented boundary.
    return _baseline("future issued_at verifies (%s...); no not-before "
                     "in the fail-closed order" % claims["spiffe_id"][:24])


@probe("baseline/svid-test-issuer-enrollment-less-by-design")
def _b_svid_enroll():
    issuer, _ = _svid_pair()
    s = issuer.issue("spiffe://example.org/never-enrolled/x",
                     "bb" * 32, 5)
    # The TEST issuer mints for any well-formed id: production issuer
    # wiring is deployment-owned per the honest residuals.
    if s["spiffe_id"] == "spiffe://example.org/never-enrolled/x":
        return _baseline("TEST issuer mints without enrollment "
                         "(documented honest residual)")
    return ("ERROR", "unexpected issuance behavior")


# ---------------------------------------------------------------------------
# Green check (depth-1; honors GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def _green_check():
    """Depth-1: adjacent wave-259 batteries still green. Honors
    GOV_SKIP_GREEN (records skip, never spawns).
    """
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED (GOV_SKIP_GREEN=1)")]
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w259_transparency_probes.py",
                    "evals/w259_keygroups_probes.py",
                    "evals/w259_identity_probes.py",
                    "evals/w259_redteam_probes.py"):
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(repo, battery)],
                capture_output=True, text=True, timeout=600,
                env=env, cwd=repo)
            tail = (p.stdout or "").strip().splitlines()[-1:] or [""]
            notes.append((battery,
                          "exit=%d %s" % (p.returncode, tail[0][:60])))
        except Exception as e:  # noqa: BLE001 -- green-check report
            notes.append((battery, "ERROR %s" % e))
    return notes


def main():
    if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
        print("PIN MISMATCH: taxonomy has %d keys, pin is %d" %
              (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
        return 2
    held = breaks = baselines = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s" %
                               (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d "
          "over %d probes" % (held, breaks, baselines, errors,
                               len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
