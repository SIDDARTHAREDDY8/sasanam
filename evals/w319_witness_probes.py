#!/usr/bin/env python3
"""Wave-319 Lane 3 battery: witness consistency + fail-closed gossip
(gov/witness_consistency.py, evidence-envelope direction-brief item 1).

Break-first probes at the public seams (issue_checkpoint_note /
cosign_note / require_cosignatures / verify_checkpoint_consistency /
check_freshness / gossip / verify_witness_policy). Verdicts:
  HELD = behavior matches the pin (every attack refused coded);
  BREAK = behavior changed vs the pin, or an unexpected miss;
  ERROR = probe/harness problem.

Probe map:
  consistency-only-grew: notes at size 3 and size 5 from one log key;
      proof 3->5 verifies (the log only grew).
  consistency-fork-detected: two notes from the SAME log key at size 3
      with different roots -> witness-consistency-fork-detected
      (the prospectus acceptance: two STHs, same size, different
      roots = cryptographic proof of log misbehavior).
  consistency-tampered-proof: valid notes, one proof hash mutated ->
      witness-consistency-invalid.
  consistency-chain-binds-receipt: old note whose (size, root) does not
      match the anchored receipt checkpoint -> witness-consistency-invalid
      (CVE-2026-22703: proofs bind to the receipt's checkpoint).
  quorum-2of3: operator note + 3 witness cosignatures, k=2 -> verifies.
  quorum-unmet: only 1 cosignature, k=2 -> witness-quorum-unmet.
  cosignature-invalid: a CONFIGURED witness's cosignature line with a
      bad signature -> witness-cosignature-invalid (unknown keys are
      ignored per the signed-note collision rules; a known key's bad
      signature is a refusal, never an accept).
  gossip-conflict: two witnesses reporting different roots at the same
      size -> witness-gossip-conflict.
  gossip-unreachable: a configured witness reports no view ->
      witness-unreachable (the Tessera fail-open anti-pattern inverted:
      silence refuses, never passes).
  checkpoint-stale: note older than max_age -> witness-checkpoint-stale.
  checkpoint-future: note timestamp > now -> witness-checkpoint-stale.
  policy-fail-closed: verifier policy with witness_consistency but the
      bundle carries no consistency evidence -> witness-consistency-missing
      (optional-but-fail-closed: configured means required).
  pin-taxonomy / footer-state: standard pins (1916; open none / next F405).

Deterministic across 2 runs; $0 spend; synthetic/local. Stdlib only
apart from gov/witness_consistency.py + gov/witness_log.py +
gov/checkpoint_note.py (real product code, no stubs).

Run:
  mkdir -p /var/tmp/g319-witness
  TMPDIR=/var/tmp/g319-witness ~/workspace/.gov-venv/bin/python evals/w319_witness_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g319-witnessb ~/workspace/.gov-venv/bin/python evals/w319_witness_probes.py
Single-probe mode:
  ~/workspace/.gov-venv/bin/python evals/w319_witness_probes.py gossip-conflict
"""

import base64
import copy
import hashlib
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import green_check  # noqa: E402  (shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line emission)

from gov import witness_consistency as WC  # noqa: E402
from gov.witness_log import WitnessLog  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
from gov import checkpoint_note as CN  # noqa: E402

TAXONOMY_PIN = 1916  # Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*)

_NOW = 1798765432
_SEED_OP = bytes(range(32))
_SEED_W1 = bytes([255 - i for i in range(32)])
_SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
_SEED_W3 = bytes([(i * 13 + 5) % 256 for i in range(32)])
_ORIGIN = "sasanam-witness-test/v1"

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


def _signer(seed):
    return Ed25519Signer(seed)


def _vkey(name, signer):
    return CN.vkey_string(name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519,
                                                signer.public_key),
                          CN.SIG_TYPE_ED25519, signer.public_key)


def _log(n, seed=_SEED_OP, tag=b"leaf"):
    signer = _signer(seed)
    log = WitnessLog(signer.public_key)
    for i in range(n):
        log.append(tag + b"-%d" % i)
    return log, signer


def _new_log():
    """A fresh, independent log with its own operator signer."""
    signer = _signer(bytes([i for i in range(32)]))
    return WitnessLog(signer.public_key), signer


def _log_with_notes():
    """A 5-leaf log with checkpoint notes issued at size 3 (old) and
    size 5 (new) -- notes are issued as the log grows, the real flow."""
    signer = _signer(_SEED_OP)
    log = WitnessLog(signer.public_key)
    for i in range(3):
        log.append(b"leaf-%d" % i)
    old = WC.issue_checkpoint_note(log, _ORIGIN, "op", signer,
                                   timestamp=_NOW - 100)
    for i in range(3, 5):
        log.append(b"leaf-%d" % i)
    new = WC.issue_checkpoint_note(log, _ORIGIN, "op", signer,
                                   timestamp=_NOW)
    return log, signer, old, new


def _op_vkeys():
    return [_vkey("op", _signer(_SEED_OP))]


def _witness_vkeys():
    return {"w1": _vkey("w1", _signer(_SEED_W1)),
            "w2": _vkey("w2", _signer(_SEED_W2)),
            "w3": _vkey("w3", _signer(_SEED_W3))}


def _code_of(fn):
    try:
        fn()
    except WC.WitnessConsistencyError as e:
        return e.code
    return None


def _expect(pid, fn, code, note):
    got = _code_of(fn)
    if got == code:
        _record(pid, "HELD", "%s: refused coded %s" % (note, code))
    else:
        _record(pid, "BREAK", "%s: expected %s, got %r" % (note, code, got))


def consistency_only_grew():
    log, _, old, new = _log_with_notes()
    proof = log.consistency_proof(3, 5)["hashes"]
    out = WC.verify_checkpoint_consistency(old, new, proof,
                                           operator_vkeys=_op_vkeys())
    assert out["old_size"] == 3 and out["new_size"] == 5, out
    _record("consistency-only-grew", "HELD",
            "3->5 with a valid proof verifies; the log only grew")


def consistency_fork_detected():
    log, signer, old, _ = _log_with_notes()
    # A forked log: the SAME operator key signs a DIFFERENT root at
    # size 3. The operator's own journal would refuse this; the fork
    # is the attack, so the note is built by hand (the battery
    # constructs attack artifacts; the product never emits these).
    fork_root = hashlib.sha256(b"forked-tree").digest()
    text = WC.note_text(_ORIGIN, 3, fork_root, _NOW)
    key_id = CN.derive_key_id("op", CN.SIG_TYPE_ED25519,
                              signer.public_key)
    sig = signer.sign(text)
    forked = (text + b"\n" + ("\u2014 op " + base64.b64encode(
        key_id + sig).decode("ascii") + "\n").encode("utf-8"))
    # Sanity: the forged note verifies as the operator's own note
    # (the fork is well-formed; only consistency can catch it).
    CN.verify_checkpoint(forked, _op_vkeys())
    proof = log.consistency_proof(3, 5)["hashes"]
    _expect("consistency-fork-detected",
            lambda: WC.verify_checkpoint_consistency(
                old, forked, proof, operator_vkeys=_op_vkeys()),
            "witness-consistency-fork-detected",
            "same size, different roots from one key")


def consistency_tampered_proof():
    log, _, old, new = _log_with_notes()
    proof = log.consistency_proof(3, 5)["hashes"]
    bad = list(proof)
    h = bytearray(bytes.fromhex(bad[0]))
    h[0] ^= 0xFF
    bad[0] = bytes(h).hex()
    _expect("consistency-tampered-proof",
            lambda: WC.verify_checkpoint_consistency(
                old, new, bad, operator_vkeys=_op_vkeys()),
            "witness-consistency-invalid",
            "mutated proof hash does not recompute the roots")


def consistency_chain_binds_receipt():
    # The receipt's checkpoint is (size 5, root R) of the main log; the
    # consistency old note is (size 3, root R') of a DIFFERENT log --
    # the proof cannot chain the receipt to the head.
    log, signer, _, new = _log_with_notes()
    other, _ = _log(3, seed=_SEED_W1)
    old = WC.issue_checkpoint_note(other, _ORIGIN, "op", signer,
                                   timestamp=_NOW - 100)
    proof = log.consistency_proof(3, 5)["hashes"]
    receipt_cp = {"treeSize": 5, "rootHash": log.root_hash().hex()}
    _expect("consistency-chain-binds-receipt",
            lambda: WC.verify_consistency_chain(
                receipt_cp, old, new, proof, operator_vkeys=_op_vkeys()),
            "witness-consistency-invalid",
            "old note does not match the anchored receipt checkpoint")


def quorum_2of3():
    log, signer = _log(5)
    note = WC.issue_checkpoint_note(log, _ORIGIN, "op", signer,
                                    timestamp=_NOW)
    for seed, name in ((_SEED_W1, "w1"), (_SEED_W2, "w2"),
                       (_SEED_W3, "w3")):
        note = WC.cosign_note(note, name, _signer(seed))
    out = WC.require_cosignatures(note, operator_vkeys=_op_vkeys(),
                                  witness_vkeys=_witness_vkeys(),
                                  quorum_k=2)
    assert out["cosignatures"] >= 2, out
    _record("quorum-2of3", "HELD",
            "3 witness cosignatures meet k=2 (verified %d)"
            % out["cosignatures"])


def quorum_unmet():
    log, signer = _log(5)
    note = WC.issue_checkpoint_note(log, _ORIGIN, "op", signer,
                                    timestamp=_NOW)
    note = WC.cosign_note(note, "w1", _signer(_SEED_W1))
    _expect("quorum-unmet",
            lambda: WC.require_cosignatures(
                note, operator_vkeys=_op_vkeys(),
                witness_vkeys=_witness_vkeys(), quorum_k=2),
            "witness-quorum-unmet",
            "1 cosignature against k=2")


def cosignature_invalid():
    log, signer = _log(5)
    note = WC.issue_checkpoint_note(log, _ORIGIN, "op", signer,
                                    timestamp=_NOW)
    note = WC.cosign_note(note, "w1", _signer(_SEED_W1))
    # Corrupt the w1 signature bytes in place (a known key's bad
    # signature is a refusal, never an accept; unknown keys are the
    # ones the collision rules ignore).
    lines = note.decode("utf-8").split("\n")
    for i, ln in enumerate(lines):
        if ln.startswith("\u2014 w1 "):
            raw = bytearray(base64.b64decode(ln.split(" ")[2],
                                             validate=True))
            raw[4] ^= 0xFF
            lines[i] = "\u2014 w1 " + base64.b64encode(bytes(raw)).decode(
                "ascii")
    bad = "\n".join(lines).encode("utf-8")
    _expect("cosignature-invalid",
            lambda: WC.require_cosignatures(
                bad, operator_vkeys=_op_vkeys(),
                witness_vkeys=_witness_vkeys(), quorum_k=1),
            "witness-cosignature-invalid",
            "configured witness w1's bad cosignature")


def gossip_conflict():
    log_a, _ = _log(5)
    # A different log history: same size, a different root (the fork).
    log_b, _ = _log(5, seed=_SEED_W2, tag=b"forked-leaf")
    # Two witnesses assert different roots at the same tree size; the
    # third configured witness agrees with one of them.
    v1 = {"witness_name": "w1",
          "note": WC.issue_checkpoint_note(log_a, _ORIGIN, "w1",
                                           _signer(_SEED_W1),
                                           timestamp=_NOW)}
    v2 = {"witness_name": "w2",
          "note": WC.issue_checkpoint_note(log_b, _ORIGIN, "w2",
                                           _signer(_SEED_W2),
                                           timestamp=_NOW)}
    v3 = {"witness_name": "w3",
          "note": WC.issue_checkpoint_note(log_a, _ORIGIN, "w3",
                                           _signer(_SEED_W3),
                                           timestamp=_NOW)}
    assert v1["note"] != v2["note"]
    _expect("gossip-conflict",
            lambda: WC.gossip([v1, v2, v3],
                              witness_vkeys=_witness_vkeys()),
            "witness-gossip-conflict",
            "w1 and w2 report different roots at size 5")


def gossip_unreachable():
    log, _ = _log(5)
    v1 = {"witness_name": "w1",
          "note": WC.issue_checkpoint_note(log, _ORIGIN, "w1",
                                           _signer(_SEED_W1),
                                           timestamp=_NOW)}
    v2 = {"witness_name": "w2",
          "note": WC.issue_checkpoint_note(log, _ORIGIN, "w2",
                                           _signer(_SEED_W2),
                                           timestamp=_NOW)}
    # w3 is configured but reports no view: silence refuses, never
    # passes (the Tessera fail-open anti-pattern, inverted).
    _expect("gossip-unreachable",
            lambda: WC.gossip([v1, v2],
                              witness_vkeys=_witness_vkeys()),
            "witness-unreachable",
            "configured witness w3 silent")


def checkpoint_stale():
    log, signer = _log(5)
    note = WC.issue_checkpoint_note(log, _ORIGIN, "op", signer,
                                    timestamp=_NOW - 7200)
    fields = CN.verify_checkpoint(note, _op_vkeys())
    _expect("checkpoint-stale",
            lambda: WC.check_freshness(fields, now=_NOW, max_age=3600),
            "witness-checkpoint-stale",
            "2h-old checkpoint against a 1h freshness window")


def checkpoint_future():
    log, signer = _log(5)
    note = WC.issue_checkpoint_note(log, _ORIGIN, "op", signer,
                                    timestamp=_NOW + 600)
    fields = CN.verify_checkpoint(note, _op_vkeys())
    _expect("checkpoint-future",
            lambda: WC.check_freshness(fields, now=_NOW, max_age=3600),
            "witness-checkpoint-stale",
            "future-dated checkpoint vs the observed time")


def policy_fail_closed():
    # The signed policy configures witness_consistency; the bundle
    # carries no consistency evidence: optional-but-fail-closed --
    # configured means required.
    log, signer, old, _ = _log_with_notes()
    policy = {"operator_vkeys": _op_vkeys(),
              "witness_vkeys": _witness_vkeys(),
              "quorum_k": 2,
              "max_checkpoint_age": 3600,
              "accepted_head": {"note": old}}
    _expect("policy-fail-closed",
            lambda: WC.verify_witness_policy(policy, {}, now=_NOW),
            "witness-consistency-missing",
            "configured mode with no consistency evidence")


def policy_roundtrip():
    log, signer, old, head = _log_with_notes()
    for seed, name in ((_SEED_W1, "w1"), (_SEED_W2, "w2")):
        head = WC.cosign_note(head, name, _signer(seed))
    policy = {"operator_vkeys": _op_vkeys(),
              "witness_vkeys": _witness_vkeys(),
              "quorum_k": 2,
              "max_checkpoint_age": 3600,
              "accepted_head": {"note": old}}
    evidence = {"head_note": head,
                "consistency_proof": log.consistency_proof(3, 5)["hashes"]}
    out = WC.verify_witness_policy(policy, evidence, now=_NOW)
    assert out["growth"]["old_size"] == 3, out
    assert out["growth"]["new_size"] == 5, out
    assert out["cosignatures"] >= 2, out
    _record("policy-roundtrip", "HELD",
            "full mode verifies: quorum 2/2, fresh, 3->5 consistent")


def policy_steady_state():
    # accepted_head is optional: no pinned head -> quorum + freshness
    # enforced, growth skipped (no proof needed).
    log, signer, old, head = _log_with_notes()
    for seed, name in ((_SEED_W1, "w1"), (_SEED_W2, "w2")):
        head = WC.cosign_note(head, name, _signer(seed))
    policy = {"operator_vkeys": _op_vkeys(),
              "witness_vkeys": _witness_vkeys(),
              "quorum_k": 2,
              "max_checkpoint_age": 3600}
    evidence = {"head_note": head}
    out = WC.verify_witness_policy(policy, evidence, now=_NOW)
    assert out["growth"] is None, out
    assert out["cosignatures"] >= 2, out
    _record("policy-steady-state", "HELD",
            "no accepted_head: quorum + freshness hold, growth skipped")


def policy_transplanted_proof():
    # CVE-2026-22703: the growth proof must bind the receipt's
    # checkpoint. An old note from a different log refuses even with a
    # well-formed proof.
    log, signer, old, head = _log_with_notes()
    for seed, name in ((_SEED_W1, "w1"), (_SEED_W2, "w2")):
        head = WC.cosign_note(head, name, _signer(seed))
    other_log, other_signer = _new_log()
    other_log.append(b"foreign-leaf")
    foreign = WC.issue_checkpoint_note(other_log, "test-origin", "op",
                                       other_signer, timestamp=_NOW - 50)
    policy = {"operator_vkeys": _op_vkeys(),
              "witness_vkeys": _witness_vkeys(),
              "quorum_k": 2,
              "max_checkpoint_age": 3600,
              "accepted_head": {"note": foreign}}
    # The receipt anchors the REAL log's head (size 5).
    fields = WC._verified_fields(head, _op_vkeys(), role="head")
    receipt_cp = {"treeSize": fields["tree_size"],
                  "rootHash": bytes(fields["root_hash"]).hex()}
    evidence = {"head_note": head,
                "consistency_proof": log.consistency_proof(3, 5)["hashes"]}
    _expect("policy-transplanted-proof",
            lambda: WC.verify_witness_policy(
                policy, evidence, now=_NOW,
                receipt_checkpoint=receipt_cp),
            "witness-consistency-invalid",
            "proof for a foreign checkpoint refuses (CVE-2026-22703)")


def pin_taxonomy():
    from gov import decision_codes as DC  # noqa: E402
    n = len(DC.TAXONOMY)
    if n != TAXONOMY_PIN:
        _record("pin-taxonomy", "BREAK",
                "taxonomy %d != pin %d" % (n, TAXONOMY_PIN))
    else:
        _record("pin-taxonomy", "HELD",
                "taxonomy pins at %d" % TAXONOMY_PIN)


def footer_state():
    import re  # noqa: E402
    path = os.path.join(REPO, "evals", "FINDINGS.md")
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    # This lane files no findings. Footer lines repeat through history;
    # the LAST one is current (w314 convention).
    m_open = re.findall(r"Open findings: ([^*]*)\.", text)
    ok = ("Next free finding: **F405**" in text
          and m_open and m_open[-1].strip() == "none")
    if ok:
        _record("footer-state", "HELD", "footer: open none / next F405")
    else:
        _record("footer-state", "BREAK",
                "footer mismatch vs open none / next F405")


PROBES = [consistency_only_grew, consistency_fork_detected,
          consistency_tampered_proof, consistency_chain_binds_receipt,
          quorum_2of3, quorum_unmet, cosignature_invalid,
          gossip_conflict, gossip_unreachable, checkpoint_stale,
          checkpoint_future, policy_fail_closed, policy_roundtrip,
          policy_steady_state, policy_transplanted_proof,
          pin_taxonomy, footer_state]


def _green_checks():
    # Depth-1 green checks on the adjacent seam batteries (fail-closed via
    # the shared helper; GOV_SKIP_GREEN=1 records a skip, never spawns).
    green_check.check_battery(_record, "green-witness-log",
                              "evals/w312_witness_log_probes.py",
                              repo=REPO)
    green_check.check_battery(_record, "green-rekor",
                              "evals/w314_rekor_probes.py",
                              repo=REPO)
    green_check.check_battery(_record, "green-offline-verifier",
                              "evals/w311_offline_verifier_probes.py",
                              repo=REPO)
    green_check.check_battery(_record, "green-evidence-schema",
                              "evals/w318_evidence_schema_probes.py",
                              repo=REPO)
    # w318_trustroot_probes.py is NOT green-checkable via the shared
    # helper: it emits "probes: N held / ..." instead of the "N BREAK /
    # M HELD / K ERROR" contract line (pre-existing wave-318 format, no
    # other battery consumes it). It is run directly as a regression
    # check instead; its pin-taxonomy and footer-state probes are
    # covered by pin_taxonomy and footer_state above.


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
    print("w319_witness battery: %d BREAK / %d HELD / %d ERROR "
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
