#!/usr/bin/env python3
"""Wave-342 R37 run-receipt battery (lane 2): COSE_Sign1 run receipts.

Steal target: sipyourdrink-ltd/bernstein PR #6392 (Apache-2.0), ADAPT
patterns only — clean-room reimplementation in gov/run_receipt.py.
Spec: research/r37-cose-run-receipt-2026-10-05.md.

$0 SPEND BY CONSTRUCTION: this battery makes NO model calls. Every probe
uses canned inputs and local keys — never a live provider. Do NOT add
ModelDriver/SpendLedger usage here.

Red-first note: every tamper probe asserts the CURRENT fail-closed
behavior (status "tampered" with a coded reason). If a future change
makes any tamper probe verify, that probe goes BREAK by design — the
tripwire working, not a false alarm.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w342_r37_receipt_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import hashlib
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2143  # Wave-341 merge: pin stays 2131, no new codes; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*); Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)

from gov import run_receipt as _rr  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
from gov.witness_log import WitnessLog  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

# ---------------------------------------------------------------- fixtures

_VICTIM_SEED = bytes([0x42]) * 32
_ATTACKER_SEED = bytes([0x99]) * 32
_OTHER_SEED = bytes([0x07]) * 32


def _signer(seed):
    return Ed25519Signer(seed)


def _journal_head(label):
    """Deterministic 32-byte journal-tip fixture (the audit-log
    chain-tip analog for this battery)."""
    return hashlib.sha256(b"w342-r37-journal-tip:" + label).digest()


def _witness_spine(n_leaves, timestamp):
    """Real WitnessLog machinery: the spine head is a genuine checkpoint
    projection, not a canned dict."""
    wkey = _signer(bytes([0x5A]) * 32)
    log = WitnessLog(wkey.public_key)
    for i in range(n_leaves):
        log.append(b"leaf-%d" % i)
    sealed = log.sealed_checkpoint(timestamp, wkey)
    cp = sealed["checkpoint"]
    return {"tree_size": cp["treeSize"],
            "root_hash": bytes.fromhex(cp["rootHash"]),
            "timestamp": cp["timestamp"],
            "log_id": cp["logId"]}


def _expected(jh, sh):
    return {"journal_head": jh, "spine_head": sh}


def _honest_envelope():
    signer = _signer(_VICTIM_SEED)
    jh = _journal_head(b"run-1")
    sh = _witness_spine(3, 1700000000)
    env = _rr.build_run_receipt(journal_head=jh, spine_head=sh,
                                signer=signer)
    return signer, jh, sh, env


def _rebuild_envelope(protected_b, unprotected, payload_b, signature,
                      tag=18):
    """Test-only envelope surgery via the module's own codec."""
    return _rr._cbor_encode(_rr._CborTag(tag, [protected_b, unprotected,
                                              payload_b, signature]))


def _resign(signer, protected_b, payload_b):
    sig_structure = _rr._cbor_encode(["Signature1", protected_b, b"",
                                      payload_b])
    return signer.sign(sig_structure)


# ---------------------------------------------------------------- probes
# Each returns (verdict, detail): verdict "BREAK" (product failed the
# red-team assertion) or "HELD" (product held / fail-closed as designed).

def test_r1_honest_receipt_verifies():
    signer, jh, sh, env = _honest_envelope()
    r = _rr.verify_run_receipt(env, public_key=signer.public_key,
                               expected=_expected(jh, sh))
    ok = (r.status == "verified" and r.cose_verified is True
          and r.binding_compared is True and r.tampered_reason is None)
    return ("HELD" if ok else "BREAK",
            "honest receipt must verify with binding compared: %r" % (r,))


def test_r2_pin_taxonomy():
    ok = (isinstance(TAXONOMY, dict) and len(TAXONOMY) == TAXONOMY_PIN
          and "deadctrl-subject-mutated" in TAXONOMY)
    return ("HELD" if ok else "BREAK",
            "taxonomy pin 2131: %d codes" % len(TAXONOMY))


def test_r3_footer_state():
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(path) as f:
        last = ([ln for ln in f.read().splitlines() if "Next free finding:" in ln] or [""])[-1]  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531) (footer is not the last line; entries follow)
    ok = ("Next free finding: **F921**" in last  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
          and "Open findings: F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794." in last)  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
    return ("HELD" if ok else "BREAK",
            "footer must read open F429 / next F430")


def test_r4_single_bit_flips_all_tampered():
    """Any single-bit mutation anywhere in the envelope is tampered."""
    signer, jh, sh, env = _honest_envelope()
    bad = []
    for off in range(0, len(env), 17):
        for bit in (0, 7):
            mut = bytearray(env)
            mut[off] ^= (1 << bit)
            r = _rr.verify_run_receipt(bytes(mut),
                                       public_key=signer.public_key,
                                       expected=_expected(jh, sh))
            if r.status != "tampered":
                bad.append((off, bit, r.status))
    return ("HELD" if not bad else "BREAK",
            "single-bit flips must all be tampered, failures: %r" % (bad,))


def test_r5_signature_byte_flip():
    signer, jh, sh, env = _honest_envelope()
    mut = bytearray(env)
    mut[-1] ^= 0x01
    r = _rr.verify_run_receipt(bytes(mut), public_key=signer.public_key,
                               expected=_expected(jh, sh))
    ok = r.status == "tampered" and r.tampered_reason == "signature"
    return ("HELD" if ok else "BREAK",
            "flipped signature byte must be tampered/signature: %r" % (r,))


def test_r6_wrong_content_type():
    """The audit-receipt content type (Bernstein's mutant) is refused."""
    signer, jh, sh = _honest_envelope()[:3]
    env = _rr.build_run_receipt(
        journal_head=jh, spine_head=sh, signer=signer,
        content_type="application/vnd.sasanam.audit-receipt+cbor")
    r = _rr.verify_run_receipt(env, public_key=signer.public_key,
                               expected=_expected(jh, sh))
    ok = r.status == "tampered" and r.tampered_reason == "content-type"
    return ("HELD" if ok else "BREAK",
            "non-run-receipt content type must be tampered: %r" % (r,))


def test_r7_digest_instead_of_binding():
    """A mere digest as payload (Bernstein's killed mutant) is refused."""
    signer, jh, sh, env = _honest_envelope()
    dec = _rr._cbor_decode(env)
    protected_b, _u, _p, _s = dec.value
    digest_payload = hashlib.sha256(b"binding").digest()
    sig = _resign(signer, protected_b, digest_payload)
    evil = _rebuild_envelope(protected_b, {}, digest_payload, sig)
    r = _rr.verify_run_receipt(evil, public_key=signer.public_key)
    ok = r.status == "tampered" and \
        r.tampered_reason == "payload-malformed"
    return ("HELD" if ok else "BREAK",
            "digest-instead-of-binding must be tampered: %r" % (r,))


def test_r8_truncated_envelope():
    signer, jh, sh, env = _honest_envelope()
    r = _rr.verify_run_receipt(env[:-10], public_key=signer.public_key,
                               expected=_expected(jh, sh))
    ok = r.status == "tampered"
    return ("HELD" if ok else "BREAK",
            "truncated envelope must be tampered: %r" % (r,))


def test_r9_no_rollback_old_receipt_new_head():
    """An older valid receipt presented against a newer pinned head is
    tampered (payload-mismatch): the no-rollback property."""
    signer = _signer(_VICTIM_SEED)
    jh1 = _journal_head(b"run-old")
    sh1 = _witness_spine(3, 1700000000)
    env_old = _rr.build_run_receipt(journal_head=jh1, spine_head=sh1,
                                     signer=signer)
    jh2 = _journal_head(b"run-new")
    sh2 = _witness_spine(5, 1700000060)
    r = _rr.verify_run_receipt(env_old, public_key=signer.public_key,
                               expected=_expected(jh2, sh2))
    ok = r.status == "tampered" and \
        r.tampered_reason == "payload-mismatch"
    return ("HELD" if ok else "BREAK",
            "stale receipt vs new head must be tampered: %r" % (r,))


def test_r10_new_receipt_old_head():
    """Forward presentation is caught too: a newer receipt against an
    older pinned head is tampered."""
    signer = _signer(_VICTIM_SEED)
    jh1 = _journal_head(b"run-old")
    sh1 = _witness_spine(3, 1700000000)
    jh2 = _journal_head(b"run-new")
    sh2 = _witness_spine(5, 1700000060)
    env_new = _rr.build_run_receipt(journal_head=jh2, spine_head=sh2,
                                     signer=signer)
    r = _rr.verify_run_receipt(env_new, public_key=signer.public_key,
                               expected=_expected(jh1, sh1))
    ok = r.status == "tampered" and \
        r.tampered_reason == "payload-mismatch"
    return ("HELD" if ok else "BREAK",
            "new receipt vs old head must be tampered: %r" % (r,))


def test_r11_edit_one_journal_event():
    """Edit one journal event afterwards: the registered statement no
    longer matches what the artifacts recompute to."""
    signer, jh, sh, env = _honest_envelope()
    edited = bytearray(jh)
    edited[0] ^= 0xFF
    r = _rr.verify_run_receipt(env, public_key=signer.public_key,
                               expected=_expected(bytes(edited), sh))
    ok = r.status == "tampered" and \
        r.tampered_reason == "payload-mismatch"
    return ("HELD" if ok else "BREAK",
            "edited journal head must be tampered: %r" % (r,))


def test_r12_kid_spoof_ignored():
    """kid is a hint, never authority: an unprotected kid naming the
    victim changes nothing; verification uses the pinned key."""
    victim = _signer(_VICTIM_SEED)
    attacker = _signer(_ATTACKER_SEED)
    jh = _journal_head(b"run-1")
    sh = _witness_spine(3, 1700000000)
    evil = _rr.build_run_receipt(journal_head=jh, spine_head=sh,
                                 signer=attacker)
    dec = _rr._cbor_decode(evil)
    protected_b, _u, payload_b, sig = dec.value
    spoofed = _rebuild_envelope(protected_b, {4: victim.key_id},
                                payload_b, sig)
    r = _rr.verify_run_receipt(spoofed, public_key=victim.public_key,
                               expected=_expected(jh, sh))
    ok = r.status == "tampered" and r.tampered_reason == "signature"
    return ("HELD" if ok else "BREAK",
            "kid spoof must not bypass the pinned key: %r" % (r,))


def test_r13_algorithm_confusion():
    """alg != -8 (EdDSA) refuses, even when the signature is 'valid'
    for the altered protected header."""
    signer, jh, sh, env = _honest_envelope()
    dec = _rr._cbor_decode(env)
    protected_b, _u, payload_b, _s = dec.value
    evil_protected = _rr._cbor_encode({1: -7, 3: _rr.DEFAULT_CONTENT_TYPE})
    sig = _resign(signer, evil_protected, payload_b)
    evil = _rebuild_envelope(evil_protected, {}, payload_b, sig)
    r = _rr.verify_run_receipt(evil, public_key=signer.public_key,
                               expected=_expected(jh, sh))
    ok = r.status == "tampered" and r.tampered_reason == "algorithm"
    return ("HELD" if ok else "BREAK",
            "non-EdDSA alg must be tampered/algorithm: %r" % (r,))


def test_r14_tag_confusion():
    """COSE_Sign (tag 98) and untagged arrays are not COSE_Sign1."""
    signer, jh, sh, env = _honest_envelope()
    dec = _rr._cbor_decode(env)
    body = dec.value
    evil98 = _rr._cbor_encode(_rr._CborTag(98, body))
    evil_plain = _rr._cbor_encode(body)
    r1 = _rr.verify_run_receipt(evil98, public_key=signer.public_key,
                                expected=_expected(jh, sh))
    r2 = _rr.verify_run_receipt(evil_plain, public_key=signer.public_key,
                                expected=_expected(jh, sh))
    ok = (r1.status == "tampered" and r2.status == "tampered"
          and r1.tampered_reason == "envelope-malformed"
          and r2.tampered_reason == "envelope-malformed")
    return ("HELD" if ok else "BREAK",
            "tag 98 / untagged must be envelope-malformed: %r %r"
            % (r1, r2))


def test_r15_unprotected_cty_override_ignored():
    """The content type is read from the PROTECTED header only."""
    signer, jh, sh, env = _honest_envelope()
    dec = _rr._cbor_decode(env)
    protected_b, _u, payload_b, sig = dec.value
    evil = _rebuild_envelope(protected_b, {3: "application/evil"},
                             payload_b, sig)
    r = _rr.verify_run_receipt(evil, public_key=signer.public_key,
                               expected=_expected(jh, sh))
    ok = r.status == "verified"
    return ("HELD" if ok else "BREAK",
            "unprotected cty override must be ignored: %r" % (r,))


def test_r16_nil_payload():
    """A nil payload cannot be registered as a statement on its own."""
    signer, jh, sh, env = _honest_envelope()
    dec = _rr._cbor_decode(env)
    protected_b, _u, _p, _s = dec.value
    sig = _resign(signer, protected_b, None)
    evil = _rebuild_envelope(protected_b, {}, None, sig)
    r = _rr.verify_run_receipt(evil, public_key=signer.public_key)
    ok = r.status == "tampered" and \
        r.tampered_reason == "payload-malformed"
    return ("HELD" if ok else "BREAK",
            "nil payload must be tampered: %r" % (r,))


def test_r17_forgery_attacker_key():
    """Attacker mints a receipt claiming the victim's journal head with
    the attacker's key: refused under the victim's pinned key."""
    victim = _signer(_VICTIM_SEED)
    attacker = _signer(_ATTACKER_SEED)
    jh = _journal_head(b"victim-run")
    sh = _witness_spine(3, 1700000000)
    forged = _rr.build_run_receipt(journal_head=jh, spine_head=sh,
                                   signer=attacker)
    r = _rr.verify_run_receipt(forged, public_key=victim.public_key,
                               expected=_expected(jh, sh))
    ok = r.status == "tampered" and r.tampered_reason == "signature"
    return ("HELD" if ok else "BREAK",
            "forgery under wrong key must be tampered: %r" % (r,))


def test_r18_wrong_key_verify():
    other = _signer(_OTHER_SEED)
    signer, jh, sh, env = _honest_envelope()
    r = _rr.verify_run_receipt(env, public_key=other.public_key,
                               expected=_expected(jh, sh))
    ok = r.status == "tampered" and r.tampered_reason == "signature"
    return ("HELD" if ok else "BREAK",
            "verify under wrong key must be tampered: %r" % (r,))


def test_r19_no_envelope():
    signer = _signer(_VICTIM_SEED)
    r = _rr.verify_run_receipt(None, public_key=signer.public_key)
    ok = r.status == "no-envelope" and r.cose_verified is None
    return ("HELD" if ok else "BREAK",
            "missing envelope must be no-envelope, never 'verified': %r"
            % (r,))


def test_r20_missing_public_key_raises():
    """Usage error, not a content verdict: no pinned key refuses."""
    _signer, jh, sh, env = _honest_envelope()
    try:
        _rr.verify_run_receipt(env, public_key=None)
    except _rr.RunReceiptError:
        return ("HELD", "missing public key raises RunReceiptError")
    return ("BREAK", "missing public key must raise, not verify")


def test_r21_binding_not_compared_is_loud():
    """Signature-only verification cannot be misread as a binding
    comparison."""
    signer, jh, sh, env = _honest_envelope()
    r = _rr.verify_run_receipt(env, public_key=signer.public_key)
    ok = r.status == "verified" and r.binding_compared is False
    return ("HELD" if ok else "BREAK",
            "expected=None must verify loud with binding_compared=False: "
            "%r" % (r,))


def test_r22_committed_vector():
    """Byte-pinned vector: any change to headers, CBOR mode, or binding
    canonicalization fails the build instead of silently invalidating
    receipts already handed to an auditor."""
    seed = bytes([0x42]) * 32
    signer = _signer(seed)
    jh = bytes([0x11]) * 32
    sh = {"tree_size": 7, "root_hash": bytes([0x22]) * 32,
          "timestamp": 1700000000, "log_id": "ab" * 32}
    env = _rr.build_run_receipt(journal_head=jh, spine_head=sh,
                                signer=signer)
    want = (
        "d284582ea201270378286170706c69636174696f6e2f766e642e736173616e61"
        "6d2e72756e2d726563656970742b63626f72a058a3a3016d72756e2d72656365"
        "6970742f31025820111111111111111111111111111111111111111111111111"
        "111111111111111103a401070258202222222222222222222222222222222222"
        "222222222222222222222222222222031a6553f1000478406162616261626162"
        "6162616261626162616261626162616261626162616261626162616261626162"
        "616261626162616261626162616261626162616261626162584055395a236374"
        "9659ef317ac6aa4a1b85ea79f50f56809e0827598b59bd7cc3748b509042f076"
        "475589e3bebd5c01a7c1edc7c041cad3bc9d13944c1c6e98130b"
    )
    ok = env.hex() == want
    return ("HELD" if ok else "BREAK",
            "committed vector must be byte-identical (got %d bytes)"
            % len(env))


TESTS = [test_r1_honest_receipt_verifies, test_r2_pin_taxonomy,
         test_r3_footer_state, test_r4_single_bit_flips_all_tampered,
         test_r5_signature_byte_flip, test_r6_wrong_content_type,
         test_r7_digest_instead_of_binding, test_r8_truncated_envelope,
         test_r9_no_rollback_old_receipt_new_head,
         test_r10_new_receipt_old_head, test_r11_edit_one_journal_event,
         test_r12_kid_spoof_ignored, test_r13_algorithm_confusion,
         test_r14_tag_confusion, test_r15_unprotected_cty_override_ignored,
         test_r16_nil_payload, test_r17_forgery_attacker_key,
         test_r18_wrong_key_verify, test_r19_no_envelope,
         test_r20_missing_public_key_raises,
         test_r21_binding_not_compared_is_loud, test_r22_committed_vector]

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere


def _green_check():
    """Depth-1 green check: one sibling battery only, with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w341_jsfuck_probes.py",):
        tmp = "/var/tmp/g342-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        tail = (r.stdout + r.stderr)[-300:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    n_break = n_held = n_err = 0
    probe_breaks = set()
    for fn in TESTS:
        if args.only and fn.__name__ != args.only:
            continue
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - loud, never a skip
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%-6s %-42s %s" % (verdict, fn.__name__, detail))
        if verdict == "BREAK":
            n_break += 1
            probe_breaks.add(fn.__name__)
        elif verdict == "HELD":
            n_held += 1
        else:
            n_err += 1
    print("result: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held,
                                                    n_err))
    if probe_breaks ^ _EXPECTED_BREAKS:
        raise SystemExit("BREAK set mismatch: got %s, expected %s"
                         % (sorted(probe_breaks),
                            sorted(_EXPECTED_BREAKS)))
    if n_err:
        raise SystemExit("ERRORs present")
    if n_break:
        raise SystemExit("BREAKs present")


if __name__ == "__main__":
    main()
