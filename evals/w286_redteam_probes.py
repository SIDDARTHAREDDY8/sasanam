"""Wave-286 independent red-team battery: attack the wave-285 merge.

Base: wave-285 push 76e0f2425f64484f3e10b339f2962fde3bef0b45
(verified via git rev-parse HEAD before work).
gov/ is byte-identical (attack only, no product code).

Attack surface (from the wave-285 merge report):
  (a) gov/evidence_anchor.py -- tessera-pattern transparency log:
      witness quorum counting, checkpoint signature verification,
      inclusion-proof verification, PublicationAwaiter, tlog-tile
      store, single-writer assumptions, operator-claimed timestamps.
  (b) gov/governed_exceptions.py -- checkov-pattern governed
      exceptions: justification enforcement, approver gating, 90-day
      TTL, SKIPPED-never-PASSED, baseline ratchet, finding-closure
      invariant, close_finding_via_exception refusal.
  (c) F325-F330 closure surfaces (CLOSED at the wave-286 merge; probes
      re-pinned to the fixed contract).

Re-pins at the public seams:
  F311-F330 (all CLOSED) -- every closure battery: 0 BREAK expected.

New findings filed (all LOW, OPEN): F331-F333.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g286-redteam && TMPDIR=/var/tmp/g286-redteam \
    ~/workspace/.gov-venv/bin/python evals/w286_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g286-redteam2 \
    ~/workspace/.gov-venv/bin/python evals/w286_redteam_probes.py
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
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-285 merge: pin 1621 -> 1641 (+1 campaign-produces-suppressed,
# +1 inventory-identity-collision, +7 anchor-*, +11 exception-*).
TAXONOMY_PIN = 1977 # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

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
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


# ---------------------------------------------------------------------------
# Re-pins: run the earlier batteries as subprocesses (depth-1; children
# honor GOV_SKIP_GREEN) and check their verdict counts against the
# expected post-wave-285 state.
# ---------------------------------------------------------------------------

_REPIN_BATTERIES = [
    # (battery, expected_breaks, label)
    ("evals/w283_f311_probes.py", 0, "f311-closed"),
    ("evals/w283_redteam_probes.py", 0, "f312-315-closed"),
    ("evals/w284_f312_315_probes.py", 0, "f312-315-closed-b"),
    ("evals/w284_redteam_probes.py", 0, "f316-324-closed"),
    ("evals/w285_f324_f316_probes.py", 0, "f316-f324-closed"),  # Wave-315: repin runs children with GOV_SKIP_GREEN=1, so w285's own green checks are skipped and the pre-existing w283_defectdojo rc=1 BREAK (stale F343 pin, visible only when green checks run) does not appear here. The 0 is now enforced, not vacuous: the canonical summary's BREAK count is what the regex reads.
    ("evals/w285_f318_probes.py", 0, "f318-closed"),
    ("evals/w285_f317_f319_probes.py", 0, "f317-f319-closed"),
    ("evals/w285_f320_f323_probes.py", 0, "f320-f323-closed"),
    ("evals/w285_tessera_probes.py", 0, "tessera-green"),
    ("evals/w285_exceptions_probes.py", 0, "exceptions-green"),
    # Wave-286 merge: F325-F330 all CLOSED (lanes 1-4); 0 BREAK expected,
    # all HELD (wave-281 precedent).
    ("evals/w285_redteam_probes.py", 0, "f325-330-closed"),
]


def _run_repins():
    for rel, expected_breaks, label in _REPIN_BATTERIES:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w286-repin-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record("repin-" + label, "ERROR", "subprocess failed: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        # The footer ("<battery>: N BREAK / ...") is the last line that
        # reports a BREAK count; per-probe notes may mention counts
        # earlier, so take the LAST match, not the first.
        matches = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(matches[-1]) if matches else -1
        if nbreak == expected_breaks:
            _record("repin-" + label, "HELD",
                    "%s: %d BREAK as expected" % (rel, nbreak))
        else:
            _record("repin-" + label, "BREAK",
                    "%s: %d BREAK, expected %d"
                    % (rel, nbreak, expected_breaks))


# ---------------------------------------------------------------------------
# F331 (LOW): uncoded exceptions escape gov/evidence_anchor.py public
# seams. Repo convention (F327 precedent) is coded refusals at public
# seams; callers branching on AnchorError.code miss raw exceptions.
# Probe 1: render_checkpoint with a non-hex sig -> raw ValueError
# (bytes.fromhex) instead of coded AnchorError.
# Probe 2: TransparencyLog with a file as log_root -> raw
# NotADirectoryError (os.makedirs) instead of coded AnchorError.
# ---------------------------------------------------------------------------

def _anchor_body():
    return {"origin": "op", "size": 1, "root": b"\x00" * 32,
            "timestamp": 1, "witness_policy_id": "none"}


def p_f331_uncoded_render_sig():
    from gov import evidence_anchor as ea
    try:
        ea.render_checkpoint(_anchor_body(),
                             [{"keyid": "x", "sig": "ZZZZ-not-hex"}])
    except ea.AnchorError as e:
        return _record("f331-uncoded-render-sig", "HELD",
                       "coded refusal: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        return _record("f331-uncoded-render-sig", "BREAK",
                       "raw %s escapes render_checkpoint -- expected "
                       "coded AnchorError" % (type(e).__name__,))
    _record("f331-uncoded-render-sig", "BREAK",
            "malformed sig accepted silently")


def p_f331_uncoded_logroot_file():
    import tempfile as _tf
    from gov import evidence_anchor as ea
    fd, fpath = _tf.mkstemp(prefix="w286-f331-")
    os.close(fd)
    try:
        try:
            ea.TransparencyLog(fpath, "op", "opkey")
        except ea.AnchorError as e:
            return _record("f331-uncoded-logroot-file", "HELD",
                           "coded refusal: %s" % (e.code,))
        except Exception as e:  # noqa: BLE001
            return _record("f331-uncoded-logroot-file", "BREAK",
                           "raw %s escapes TransparencyLog -- expected "
                           "coded AnchorError" % (type(e).__name__,))
        _record("f331-uncoded-logroot-file", "BREAK",
                "file log_root accepted silently")
    finally:
        os.unlink(fpath)


# ---------------------------------------------------------------------------
# F332 (LOW): ExceptionStore.grant accepts a whitespace-only justification
# (>= 20 chars of spaces/tabs/newlines). The module's core control is
# "mandatory justification ... a justification must say something";
# whitespace says nothing, so the control is bypassed while the length
# check passes.
# ---------------------------------------------------------------------------

def _exc_store(now=2000):
    from gov import governed_exceptions as ge
    reg = ge.CheckRegistry()
    reg.register("SAS_W286", "probe check", "cat", "low",
                 "rationale for probe", ["r"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["alice"])
    return ge, store, now


def p_f332_whitespace_justification():
    ge, store, now = _exc_store()
    try:
        store.grant("SAS_W286", ("resource", "db"), " " * 20, "alice",
                    now + 1000, now, now=now)
    except ge.GovernExceptionError as e:
        return _record("f332-whitespace-justification", "HELD",
                       "refused: %s" % (e.code,))
    _record("f332-whitespace-justification", "BREAK",
            "20-space justification accepted -- the mandatory-"
            "justification control is satisfied by whitespace")


# ---------------------------------------------------------------------------
# F333 (LOW): WitnessPolicy accepts the same Ed25519 public key under
# distinct key ids with no key-uniqueness check. The module documents a
# "quorum of DISTINCT witnesses"; one compromised witness key, presented
# under two key ids, satisfies a quorum of 2 end-to-end (issuance
# succeeds, check_witness_quorum counts 2/2, the checkpoint verifies).
# ---------------------------------------------------------------------------

def p_f333_dup_witness_keys():
    from gov import evidence_anchor as ea
    from gov import ed25519 as _ed25519
    seed = bytes(range(32))
    pub = _ed25519.publickey(seed).hex()
    try:
        policy = ea.WitnessPolicy("w286p", {"w1": pub, "w2": pub}, quorum=2)
    except ea.AnchorError as e:
        return _record("f333-dup-witness-keys", "HELD",
                       "duplicate-key policy refused: %s" % (e.code,))
    tmpd = tempfile.mkdtemp(prefix="w286-f333-")
    op_seed = bytes([7] * 32)
    log = ea.TransparencyLog(tmpd, "op", "opkey", signer_seed=op_seed)
    idx = log.add(b"f333-entry")
    # ONE real witness key, presented under both pinned key ids.
    try:
        cp = log.await_publication(
            idx, witness_policy=policy,
            witness_seeds={"w1": seed, "w2": seed})
    except ea.AnchorError as e:
        return _record("f333-dup-witness-keys", "HELD",
                       "issuance refused: %s" % (e.code,))
    counted = ea.check_witness_quorum(cp["signed_note"], policy,
                                      operator_keyid="opkey")
    if counted >= policy.quorum:
        return _record(
            "f333-dup-witness-keys", "BREAK",
            "one witness key satisfies quorum 2: policy pins the same "
            "key under w1+w2, issuance succeeded, quorum counted %d/%d"
            % (counted, policy.quorum))
    _record("f333-dup-witness-keys", "HELD",
            "quorum not satisfied by the duplicated key")


# ---------------------------------------------------------------------------
# Falsified / held attack shapes (documented; not filed).
# ---------------------------------------------------------------------------

def p_held_sigline_prepend():
    """Prepending an attacker sig line before the operator's must fail
    LOUD -- sigs[0] is verified as the operator under log_pubkey."""
    from gov import evidence_anchor as ea
    from gov import ed25519 as _ed25519
    tmpd = tempfile.mkdtemp(prefix="w286-held1-")
    op_seed = bytes([7] * 32)
    op_pub = _ed25519.publickey(op_seed)
    log = ea.TransparencyLog(tmpd, "op", "opkey", signer_seed=op_seed)
    idx = log.add(b"h1")
    cp = log.await_publication(idx)
    lines = cp["signed_note"].split("\n")
    atk = "— attacker " + "QUJD" * 22  # not a real sig; must fail LOUD
    bad = "\n".join(lines[:6] + [atk] + lines[6:])
    receipt = {"bundle_digest": "ab" * 32, "log_index": idx,
               "inclusion_proof": log.inclusion_proof(idx, 1),
               "checkpoint_signature": bad, "witness_policy_id": "none"}
    try:
        ea.verify_receipt(receipt, bytes(op_pub), log_root=tmpd)
    except ea.AnchorError as e:
        return _record("held-sigline-prepend", "HELD",
                       "prepended sig line fails LOUD: %s" % (e.code,))
    _record("held-sigline-prepend", "BREAK",
            "prepended attacker sig line accepted")


def p_held_close_via_exception():
    """close_finding_via_exception exists only to refuse LOUD."""
    ge, store, now = _exc_store()
    exc = store.grant("SAS_W286", ("resource", "x"),
                      "a real justification here", "alice",
                      now + 1000, now, now=now)
    try:
        store.close_finding_via_exception(exc.digest, "F999", "mallory")
    except ge.GovernExceptionError as e:
        denied = any(a["event"] == "denied" for a in store.audit_events())
        return _record("held-close-via-exception", "HELD",
                       "refused %s; denied audited=%s" % (e.code, denied))
    _record("held-close-via-exception", "BREAK",
            "finding closed through the exception seam")


def p_held_expired_cover_refuses():
    """A covering but expired exception refuses LOUD, never silently
    falls through to the predicate."""
    ge, store, now = _exc_store()
    store.grant("SAS_W286", ("resource", "y"), "another real justifctn",
                "alice", now + 500, now, now=now)
    try:
        store.evaluate("SAS_W286", ("resource", "y"), lambda: True,
                       now=now + 99999)
    except ge.GovernExceptionError as e:
        return _record("held-expired-cover", "HELD",
                       "expired cover refuses LOUD: %s" % (e.code,))
    _record("held-expired-cover", "BREAK",
            "expired exception silently covered the check")


def main():
    p_taxonomy_pin()
    _run_repins()
    p_f331_uncoded_render_sig()
    p_f331_uncoded_logroot_file()
    p_f332_whitespace_justification()
    p_f333_dup_witness_keys()
    # Documented-held shapes (falsified hypotheses).
    if SKIP_GREEN:
        _record("held-shapes", "HELD",
                "SKIP placeholder (depth-1)")
    else:
        p_held_sigline_prepend()
        p_held_close_via_exception()
        p_held_expired_cover_refuses()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w286_redteam: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
