"""Wave-287 lane 3 battery: F333 -- WitnessPolicy must dedupe witness keys
by public-key material.

Close-when (F333): (1) WitnessPolicy refuses duplicate public keys across
key ids with a coded anchor-witness-quorum-failed refusal (or canonicalizes
by key); (2) the w286_redteam f333 probe flips to HELD; (3) adjacent
batteries stay green.

Run:
  mkdir -p /var/tmp/g287-f333 && TMPDIR=/var/tmp/g287-f333 \
    ~/workspace/.gov-venv/bin/python evals/w287_f333_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g287-f333b \
    ~/workspace/.gov-venv/bin/python evals/w287_f333_probes.py
"""

import os
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

# Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*).
TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def p_taxonomy_pin():
    import gov.decision_codes as dc
    codes = list(dc.TAXONOMY.keys())
    if len(codes) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d, want %d"
                       % (len(codes), TAXONOMY_PIN))
    if len(set(codes)) != len(codes):
        return _record("pin-taxonomy", "BREAK", "duplicate codes")
    if codes != sorted(codes):
        return _record("pin-taxonomy", "BREAK", "codes unsorted")
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


def p_policy_rejects_dup_keys():
    """Duplicate public keys under distinct key ids must be refused LOUD
    with the coded anchor-witness-quorum-failed refusal."""
    from gov import evidence_anchor as ea
    from gov import ed25519 as _ed25519
    seed = bytes(range(32))
    pub = _ed25519.publickey(seed).hex()
    try:
        ea.WitnessPolicy("w287p", {"w1": pub, "w2": pub}, quorum=2)
    except ea.AnchorError as e:
        code = getattr(e, "code", None)
        if code == "anchor-witness-quorum-failed":
            return _record("f333-policy-rejects-dup-keys", "HELD",
                           "duplicate-key policy refused LOUD: %s" % code)
        return _record("f333-policy-rejects-dup-keys", "ERROR",
                       "refused with unexpected code: %r" % (code,))
    _record("f333-policy-rejects-dup-keys", "BREAK",
            "WitnessPolicy ACCEPTS the same public key under w1+w2 "
            "(quorum=2) -- one compromised key satisfies the quorum")


def p_end_to_end_one_key_quorum():
    """The red-team's end-to-end exploit: one real witness key pinned
    under w1+w2, issuance with both seeds, quorum counted 2/2. After the
    fix the policy must fail at construction (issuance never happens)."""
    from gov import evidence_anchor as ea
    from gov import ed25519 as _ed25519
    seed = bytes(range(32))
    pub = _ed25519.publickey(seed).hex()
    try:
        policy = ea.WitnessPolicy("w287pe2e", {"w1": pub, "w2": pub},
                                  quorum=2)
    except ea.AnchorError:
        return _record("f333-end-to-end-one-key-quorum", "HELD",
                       "exploit blocked at policy construction")
    tmpd = tempfile.mkdtemp(prefix="w287-f333-e2e-")
    op_seed = bytes([7] * 32)
    log = ea.TransparencyLog(tmpd, "op", "opkey", signer_seed=op_seed)
    idx = log.add(b"f333-e2e-entry")
    cp = log.await_publication(idx, witness_policy=policy,
                               witness_seeds={"w1": seed, "w2": seed})
    counted = ea.check_witness_quorum(cp["signed_note"], policy,
                                      operator_keyid="opkey")
    if counted >= policy.quorum:
        return _record("f333-end-to-end-one-key-quorum", "BREAK",
                       "one witness key satisfied quorum 2 (counted %d) -- "
                       "compromise threshold voided" % counted)
    _record("f333-end-to-end-one-key-quorum", "HELD",
            "quorum NOT satisfied by the duplicated key (counted %d)"
            % counted)


def p_distinct_keys_quorum2_works():
    """Guard against over-refusal: two GENUINELY distinct witness keys
    with quorum=2 must still issue and verify."""
    from gov import evidence_anchor as ea
    from gov import ed25519 as _ed25519
    seed1 = bytes(range(32))
    seed2 = bytes([9] * 32)
    pub1 = _ed25519.publickey(seed1).hex()
    pub2 = _ed25519.publickey(seed2).hex()
    assert pub1 != pub2
    policy = ea.WitnessPolicy("w287p-ok", {"w1": pub1, "w2": pub2},
                              quorum=2)
    tmpd = tempfile.mkdtemp(prefix="w287-f333-ok-")
    op_seed = bytes([7] * 32)
    log = ea.TransparencyLog(tmpd, "op", "opkey", signer_seed=op_seed)
    idx = log.add(b"f333-ok-entry")
    cp = log.await_publication(idx, witness_policy=policy,
                               witness_seeds={"w1": seed1, "w2": seed2})
    counted = ea.check_witness_quorum(cp["signed_note"], policy,
                                      operator_keyid="opkey")
    if counted == 2:
        return _record("f333-distinct-keys-quorum2-works", "HELD",
                       "2-of-2 with distinct keys still issues and "
                       "verifies (no over-refusal)")
    _record("f333-distinct-keys-quorum2-works", "ERROR",
            "distinct-key quorum broke: counted %d" % counted)


def p_single_witness_still_works():
    """A single-witness policy (quorum=1) must keep working."""
    from gov import evidence_anchor as ea
    from gov import ed25519 as _ed25519
    seed = bytes(range(32))
    pub = _ed25519.publickey(seed).hex()
    policy = ea.WitnessPolicy("w287p-1", {"w1": pub}, quorum=1)
    tmpd = tempfile.mkdtemp(prefix="w287-f333-1-")
    op_seed = bytes([7] * 32)
    log = ea.TransparencyLog(tmpd, "op", "opkey", signer_seed=op_seed)
    idx = log.add(b"f333-1-entry")
    cp = log.await_publication(idx, witness_policy=policy,
                               witness_seeds={"w1": seed})
    counted = ea.check_witness_quorum(cp["signed_note"], policy,
                                      operator_keyid="opkey")
    if counted == 1:
        return _record("f333-single-witness-still-works", "HELD",
                       "quorum=1 policy unaffected")
    _record("f333-single-witness-still-works", "ERROR",
            "quorum=1 broke: counted %d" % counted)


# ---------------------------------------------------------------------------
# Depth-1 green checks: the anchor/receipt batteries must stay all-HELD.
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    for rel in ("evals/w285_tessera_probes.py", "evals/w286_receipts_probes.py"):
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w287-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=900,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        import re
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_taxonomy_pin()
    p_policy_rejects_dup_keys()
    p_end_to_end_one_key_quorum()
    p_distinct_keys_quorum2_works()
    p_single_witness_still_works()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w287_f333: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
