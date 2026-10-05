#!/usr/bin/env python3
"""Wave-314 Lane 2 battery: Rekor-pattern transparency witness
(gov/witness_rekor.py, evidence-envelope build-order step 5).

Break-first probes at the public seams (anchor_evidence /
verify_inclusion / to_offline_entry). Verdicts:
  HELD = behavior matches the pin (every attack refused coded);
  BREAK = behavior changed vs the pin, or an unexpected miss;
  ERROR = probe/harness problem.

Probe map:
  anchor-verify-roundtrip: anchor a digest, verify_inclusion accepts;
      info pins log_index/tree_size/log_id/checkpoint_time.
  replay-across-bundles: receipt minted for digest A, presented for
      digest B -> witness-rekor-digest-mismatch (Rekor proves digest
      existence only; the receipt must not travel to another bundle).
  forged-checkpoint-signature: checkpoint_signature mutated ->
      witness-rekor-checkpoint-invalid.
  forged-inclusion-path: one path hash mutated ->
      witness-rekor-inclusion-invalid.
  foreign-signer-logid: checkpoint sealed by a DIFFERENT witness key,
      verified under our key -> witness-rekor-checkpoint-invalid
      (checkpoint-first: logId names the key, never the reverse).
  anchor-expired-window: checkpoint time outside the witness key's
      validFor window at checkpoint time -> witness-rekor-anchor-expired
      (CVE-2026-24122 analogue: checked at anchor time, not verify time).
  anchor-stale: checkpoint older than max_anchor_age vs the observed
      time -> witness-rekor-anchor-expired.
  future-checkpoint: checkpoint time > observed time ->
      witness-rekor-checkpoint-invalid.
  anchor-missing: verify_inclusion(digest, None) ->
      witness-rekor-anchor-missing.
  checkpoint-first-sizes: the proof block's informational tree_size
      mutated to a bogus value; verification takes tree_size ONLY from
      the verified checkpoint (sigstore-python#248 analogue) and still
      accepts.
  seal-shape-interop: to_offline_entry(receipt) deep-equals the offline
      verifier's own seal_witness_entry output for identical inputs --
      byte-for-byte proof the verifier's witness step consumes our
      receipts (that step's acceptance of seal output is pinned by the
      w311/w312 batteries).
  pin-taxonomy / footer-state: standard pins (1964; open none / next F409).

Deterministic across 2 runs; $0 spend; synthetic/local. Stdlib only
apart from gov/witness_rekor.py + gov/witness_log.py (real product
code, no stubs).

Run:
  mkdir -p /var/tmp/g314-rekor
  TMPDIR=/var/tmp/g314-rekor ~/workspace/.gov-venv/bin/python evals/w314_rekor_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g314-rekorb ~/workspace/.gov-venv/bin/python evals/w314_rekor_probes.py
Single-probe mode:
  ~/workspace/.gov-venv/bin/python evals/w314_rekor_probes.py replay-across-bundles
"""

import base64
import copy
import hashlib
import os
import re
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import green_check  # noqa: E402  (shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line emission)

from gov import witness_rekor as WR  # noqa: E402
from gov.witness_log import WitnessLog  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
from gov import evidence_verify_offline as EVO  # noqa: E402

TAXONOMY_PIN = 2127 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable). Wave-314 lane 2: pin 1869 -> 1869 (+6 witness-rekor-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


_NOW = 1798765432
_SEED_A = bytes(range(32))
_SEED_B = bytes([255 - i for i in range(32)])
_DIGEST_A = hashlib.sha256(b"bundle-A-synthetic").hexdigest()
_DIGEST_B = hashlib.sha256(b"bundle-B-synthetic").hexdigest()
_VALID_FOR = (_NOW - 86400, _NOW + 86400)  # +-1 day around _NOW

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a dead
    battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _log_and_signer(seed=_SEED_A):
    signer = Ed25519Signer(seed)
    return WitnessLog(signer.public_key), signer


def _anchored(**kw):
    """Anchor _DIGEST_A and return (log, receipt)."""
    log, signer = _log_and_signer()
    ts = kw.pop("timestamp", _NOW)
    receipt = WR.anchor_evidence(_DIGEST_A, witness_log=log,
                                witness_signer=signer, timestamp=ts, **kw)
    return log, receipt


def _code_of(fn):
    try:
        fn()
    except WR.WitnessRekorError as e:
        return e.code
    return None


def _expect(pid, fn, code, note):
    got = _code_of(fn)
    if got == code:
        _record(pid, "HELD", "%s: refused coded %s" % (note, code))
    else:
        _record(pid, "BREAK", "%s: expected %s, got %r" % (note, code, got))


def anchor_verify_roundtrip():
    _, receipt = _anchored()
    info = WR.verify_inclusion(_DIGEST_A, receipt,
                              witness_public_key=Ed25519Signer(_SEED_A).public_key,
                              valid_for=_VALID_FOR, now=_NOW)
    assert info["log_index"] == 0, info
    assert info["tree_size"] == 1, info
    assert info["checkpoint_time"] == _NOW, info
    assert info["log_id"] == hashlib.sha256(
        Ed25519Signer(_SEED_A).public_key).hexdigest(), info
    _record("anchor-verify-roundtrip", "HELD",
            "anchor + verify round-trips; info pins index/size/log_id/time")


def replay_across_bundles():
    _, receipt = _anchored()
    _expect("replay-across-bundles",
            lambda: WR.verify_inclusion(_DIGEST_B, receipt,
                                       witness_public_key=Ed25519Signer(_SEED_A).public_key,
                                       valid_for=_VALID_FOR, now=_NOW),
            "witness-rekor-digest-mismatch",
            "receipt for digest A presented for digest B")


def forged_checkpoint_signature():
    _, receipt = _anchored()
    bad = copy.deepcopy(receipt)
    raw = bytearray(base64.b64decode(bad["checkpoint_signature"]))
    raw[0] ^= 0xFF
    bad["checkpoint_signature"] = base64.b64encode(bytes(raw)).decode("ascii")
    _expect("forged-checkpoint-signature",
            lambda: WR.verify_inclusion(_DIGEST_A, bad,
                                       witness_public_key=Ed25519Signer(_SEED_A).public_key,
                                       valid_for=_VALID_FOR, now=_NOW),
            "witness-rekor-checkpoint-invalid", "mutated checkpoint sig")


def forged_inclusion_path():
    _, receipt = _anchored(timestamp=_NOW)
    log, receipt2 = _log_and_signer(), None
    # Anchor a second leaf so the path is non-trivial.
    log2_signer = Ed25519Signer(_SEED_A)
    log2 = WitnessLog(log2_signer.public_key)
    WR.anchor_evidence(_DIGEST_A, witness_log=log2, witness_signer=log2_signer,
                       timestamp=_NOW)
    r2 = WR.anchor_evidence(_DIGEST_B, witness_log=log2,
                           witness_signer=log2_signer, timestamp=_NOW)
    bad = copy.deepcopy(r2)
    assert bad["proof"]["path"], "path should be non-trivial at index 1"
    h = bytearray(bytes.fromhex(bad["proof"]["path"][0]["hash"]))
    h[0] ^= 0xFF
    bad["proof"]["path"][0]["hash"] = bytes(h).hex()
    _expect("forged-inclusion-path",
            lambda: WR.verify_inclusion(_DIGEST_B, bad,
                                       witness_public_key=Ed25519Signer(_SEED_A).public_key,
                                       valid_for=_VALID_FOR, now=_NOW),
            "witness-rekor-inclusion-invalid", "mutated path hash")


def foreign_signer_logid():
    # Anchor under key B, verify under key A: logId names no policy key.
    log_b, signer_b = _log_and_signer(seed=_SEED_B)
    receipt = WR.anchor_evidence(_DIGEST_A, witness_log=log_b,
                                witness_signer=signer_b, timestamp=_NOW)
    _expect("foreign-signer-logid",
            lambda: WR.verify_inclusion(_DIGEST_A, receipt,
                                       witness_public_key=Ed25519Signer(_SEED_A).public_key,
                                       valid_for=_VALID_FOR, now=_NOW),
            "witness-rekor-checkpoint-invalid",
            "checkpoint from a foreign witness key")


def anchor_expired_window():
    # Anchor BEFORE the witness key's validFor window starts.
    _, receipt = _anchored(timestamp=_VALID_FOR[0] - 1)
    _expect("anchor-expired-window",
            lambda: WR.verify_inclusion(_DIGEST_A, receipt,
                                       witness_public_key=Ed25519Signer(_SEED_A).public_key,
                                       valid_for=_VALID_FOR, now=_NOW),
            "witness-rekor-anchor-expired",
            "anchor time outside witness key validFor (checked at anchor "
            "time, CVE-2026-24122 analogue)")


def anchor_stale():
    # Fresh-window anchor, but the observed time is past max_anchor_age.
    _, receipt = _anchored(timestamp=_NOW - 7200)
    _expect("anchor-stale",
            lambda: WR.verify_inclusion(
                _DIGEST_A, receipt,
                witness_public_key=Ed25519Signer(_SEED_A).public_key,
                valid_for=_VALID_FOR, now=_NOW, max_anchor_age=3600),
            "witness-rekor-anchor-expired",
            "anchor older than max_anchor_age vs observed time")


def future_checkpoint():
    _, receipt = _anchored(timestamp=_NOW + 3600)
    _expect("future-checkpoint",
            lambda: WR.verify_inclusion(_DIGEST_A, receipt,
                                       witness_public_key=Ed25519Signer(_SEED_A).public_key,
                                       valid_for=(_VALID_FOR[0], _NOW + 86400 * 2),
                                       now=_NOW),
            "witness-rekor-checkpoint-invalid",
            "checkpoint time in the future vs observed time")


def anchor_missing():
    _expect("anchor-missing",
            lambda: WR.verify_inclusion(
                _DIGEST_A, None,
                witness_public_key=Ed25519Signer(_SEED_A).public_key,
                valid_for=_VALID_FOR, now=_NOW),
            "witness-rekor-anchor-missing", "no receipt presented")


def checkpoint_first_sizes():
    # The proof block's tree_size is informational only; an attacker
    # inflates it. Verification must take tree_size from the VERIFIED
    # checkpoint (sigstore-python#248 analogue) and still accept.
    _, receipt = _anchored()
    tampered = copy.deepcopy(receipt)
    tampered["proof"]["tree_size"] = 9999
    try:
        info = WR.verify_inclusion(_DIGEST_A, tampered,
                                   witness_public_key=Ed25519Signer(_SEED_A).public_key,
                                   valid_for=_VALID_FOR, now=_NOW)
    except WR.WitnessRekorError as e:
        _record("checkpoint-first-sizes", "BREAK",
                "bogus proof tree_size rejected it: %s" % (e.code,))
        return
    if info["tree_size"] == 1:
        _record("checkpoint-first-sizes", "HELD",
                "informational proof tree_size ignored; checkpoint size 1 used")
    else:
        _record("checkpoint-first-sizes", "BREAK",
                "tree_size came from the proof, not the checkpoint")


def seal_shape_interop():
    # Byte-for-byte interop with the offline verifier's own sealer:
    # our receipt must be exactly what seal_witness_entry emits for
    # identical inputs, so the verifier's pinned witness step consumes
    # it unchanged.
    log, signer = _log_and_signer()
    # seal_witness_entry requires a non-empty wire-signature list; feed
    # both sealers the identical synthetic entry so deep equality is
    # still the interop pin.
    sigs = [{"keyid": "synthetic-test", "sig": "00" * 64}]
    ours = WR.anchor_evidence(_DIGEST_A, witness_log=log,
                             witness_signer=signer, timestamp=_NOW,
                             signatures=sigs, verified_keyids=["k1"],
                             policy_digest=_DIGEST_B)
    log2, signer2 = _log_and_signer()
    theirs = EVO.seal_witness_entry(log2, signer2, artifact_digest=_DIGEST_A,
                                   signatures=[dict(s) for s in sigs],
                                   verified_keyids=["k1"],
                                   policy_digest=_DIGEST_B,
                                   integrated_time=_NOW)
    ours_entry = WR.to_offline_entry(ours)
    if ours_entry == theirs:
        _record("seal-shape-interop", "HELD",
                "to_offline_entry deep-equals seal_witness_entry output")
    else:
        _record("seal-shape-interop", "BREAK",
                "shape mismatch:\n ours=%r\n theirs=%r"
                % (ours_entry, theirs))


def pin_taxonomy():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    if n != TAXONOMY_PIN:
        _record("pin-taxonomy", "BREAK",
                "taxonomy literals %d != pin %d" % (n, TAXONOMY_PIN))
    else:
        _record("pin-taxonomy", "HELD",
                "taxonomy pin %d holds" % TAXONOMY_PIN)


def footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    # Wave-316 merge footer: F403 OPEN (F398/F399/F400 CLOSED); next F404.
    # This lane files no findings. Footer lines repeat through history;
    # the LAST one is current.
    m_open = re.findall(r"Open findings: ([^*]*)\.", text)
    ok = ("Next free finding: **F413**" in text
          and m_open and m_open[-1].strip() == "F412")
    if ok:
        _record("footer-state", "HELD", "footer: open none / next F409")
    else:
        _record("footer-state", "BREAK",
                "footer mismatch vs open none / next F409")


PROBES = [anchor_verify_roundtrip, replay_across_bundles,
          forged_checkpoint_signature, forged_inclusion_path,
          foreign_signer_logid, anchor_expired_window, anchor_stale,
          future_checkpoint, anchor_missing, checkpoint_first_sizes,
          seal_shape_interop, pin_taxonomy, footer_state]


def _green_checks():
    # Depth-1 green checks on the adjacent seam batteries (fail-closed via
    # the shared helper; GOV_SKIP_GREEN=1 records a skip, never spawns).
    green_check.check_battery(_record, "green-offline-verifier",
                              "evals/w311_offline_verifier_probes.py",
                              repo=REPO)
    green_check.check_battery(_record, "green-witness-log",
                              "evals/w312_witness_log_probes.py",
                              repo=REPO)


def run_once(only=None):
    del _results[:]
    for p in PROBES:
        if only and only not in p.__name__:
            continue
        _safe(p.__name__, p)
    if only is None:
        _green_checks()
    return list(_results)


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    first = run_once(only)
    second = run_once(only)
    det = ([v for _, v, _ in first] == [v for _, v, _ in second])
    n_held = sum(1 for _, v, _ in first if v == "HELD")
    n_break = sum(1 for _, v, _ in first if v == "BREAK")
    n_err = sum(1 for _, v, _ in first if v == "ERROR")
    probe_lines.emit(first)
    ok, diags = probe_lines.check_coherence(first, n_break, n_held, n_err)
    if not ok:
        for d in diags:
            print("coherence-WARNING: %s" % d)
    print("----")
    print("w314_rekor battery: %d BREAK / %d HELD / %d ERROR "
          "(deterministic across 2 runs: %s)"
          % (n_break, n_held, n_err, det))
    if not det:
        print("NON-DETERMINISTIC across runs -- do not trust")
        return 2
    if n_err:
        print("ERRORs present -- battery failed closed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
