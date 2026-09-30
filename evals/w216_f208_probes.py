#!/usr/bin/env python3
"""Wave-216 lane A: F208 break-first audit battery — the GHSA-fx35-mq7g-6g98
verification-bypass class ("verification bypass using an unexpected public
key in a legacy bundle") against the homegrown DSSE/bundle verifier.

Seam under audit: EVERY path where an untrusted bundle carries a public-key
hint (envelope ``keyid``, ``key_id``, receipt ``authority.pubkey``, operator
key envelope) must NEVER let that hint select the verification key — the
verifier accepts keys ONLY from the caller-pinned keyset / out-of-band pins.
Any bundle-embedded key-hint bypass = BREAK (F208 demonstrated).

Method (diagnosing-bugs): attack shapes at the PUBLIC seams, deterministic,
minimal, against pristine wave-215 HEAD eb66966651a93d026c2731d11afe51e6ea801dae.

Verdicts: HELD / BREAK / RESIDUAL / ERROR. Any BREAK proves F208 live.
Exit 1 on any BREAK/ERROR.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g216a
  TMPDIR=/var/tmp/g216a ~/workspace/.gov-venv/bin/python evals/w216_f208_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g216a-u \
      ~/workspace/.gov-venv/bin/python evals/w216_f208_probes.py
"""

import base64
import copy
import hashlib
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/var/tmp/g216a-%d" % os.getpid())

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

from gov import dsse_envelope as dsse           # noqa: E402
from gov import signature_envelope_v2 as env2   # noqa: E402
from gov import scan_verdicts as sv             # noqa: E402
from gov import evidence_verify as ev           # noqa: E402
from gov import invocation_receipts as ir       # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-52s %-9s %s" % (name, verdict, detail))


# ---------------------------------------------------------------------------
# Key material: fixed seeds -> deterministic battery (two runs identical)
# ---------------------------------------------------------------------------
_TRUSTED_SIGNER = Ed25519Signer(bytes.fromhex("11" * 32))
_TRUSTED_VERIFIER = Ed25519Verifier(_TRUSTED_SIGNER.public_key,
                                    _TRUSTED_SIGNER.key_id)
_ATTACKER_SIGNER = Ed25519Signer(bytes.fromhex("22" * 32))
_ATTACKER_VERIFIER = Ed25519Verifier(_ATTACKER_SIGNER.public_key,
                                     _ATTACKER_SIGNER.key_id)

_PTYPE = "application/vnd.sasanam.test+json"
_NOW = 1790000000  # fixed "now" for scan-verdict emission/verification


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _dsse_pae_sig(payload_bytes, payload_type, signer):
    return signer.sign(dsse.pae(payload_type, payload_bytes))


# ---------------------------------------------------------------------------
# DSSE open_envelope probes (pinned-verifier seam)
# ---------------------------------------------------------------------------

def _dsse_valid_env():
    return dsse.seal(b'{"probe": "f208"}', _PTYPE, [_TRUSTED_SIGNER])


@_probe("dsse/valid-pinned-passes")
def _p_dsse_valid():
    """Control: pinned-keyset verification of a genuine envelope passes."""
    try:
        got = dsse.open_envelope(_dsse_valid_env(), b'{"probe": "f208"}',
                                 _PTYPE, [_TRUSTED_VERIFIER])
        if got["key_ids"] == [_TRUSTED_VERIFIER.key_id]:
            _record("dsse/valid-pinned-passes", "HELD",
                    "pinned key verifies")
        else:
            _record("dsse/valid-pinned-passes", "ERROR",
                    "unexpected key_ids %r" % (got["key_ids"],))
    except Exception as exc:  # noqa: BLE001
        _record("dsse/valid-pinned-passes", "ERROR", "%s: %s"
                % (type(exc).__name__, exc))


@_probe("dsse/unknown-keyid-attacker-sig-refused")
def _p_dsse_unknown_kid():
    """GHSA-class shape 1: envelope names an ATTACKER keyid and carries
    the attacker's signature. The verifier must refuse even though the
    signature is cryptographically valid under the named key."""
    payload = b'{"probe": "f208"}'
    sig = _dsse_pae_sig(payload, _PTYPE, _ATTACKER_SIGNER)
    env = {"payload": _b64(payload), "payloadType": _PTYPE,
           "signatures": [{"keyid": _ATTACKER_VERIFIER.key_id,
                           "sig": sig.hex()}]}
    try:
        dsse.open_envelope(env, payload, _PTYPE, [_TRUSTED_VERIFIER])
        _record("dsse/unknown-keyid-attacker-sig-refused", "BREAK",
                "attacker-keyed envelope VERIFIED against pinned keyset")
    except dsse.EnvelopeError:
        _record("dsse/unknown-keyid-attacker-sig-refused", "HELD",
                "refused: keyid not in pinned keyset")
    except Exception as exc:  # noqa: BLE001
        _record("dsse/unknown-keyid-attacker-sig-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("dsse/spoofed-pinned-keyid-refused")
def _p_dsse_spoofed_kid():
    """GHSA-class shape 2 (the exact CVE shape): envelope claims the
    PINNED key id but the signature is the attacker's. The keyid label
    must never upgrade an untrusted key into the trust set."""
    payload = b'{"probe": "f208"}'
    sig = _dsse_pae_sig(payload, _PTYPE, _ATTACKER_SIGNER)
    env = {"payload": _b64(payload), "payloadType": _PTYPE,
           "signatures": [{"keyid": _TRUSTED_VERIFIER.key_id,
                           "sig": sig.hex()}]}
    try:
        dsse.open_envelope(env, payload, _PTYPE, [_TRUSTED_VERIFIER])
        _record("dsse/spoofed-pinned-keyid-refused", "BREAK",
                "spoofed pinned keyid VERIFIED (key-hint bypass!)")
    except dsse.EnvelopeError:
        _record("dsse/spoofed-pinned-keyid-refused", "HELD",
                "refused: signature does not verify under pinned key")
    except Exception as exc:  # noqa: BLE001
        _record("dsse/spoofed-pinned-keyid-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("dsse/keyid-less-attacker-sig-refused")
def _p_dsse_nokeyid():
    """GHSA-class shape 3: keyid-less signature by the attacker. The
    try-every-verifier fallback must only ever try PINNED verifiers."""
    payload = b'{"probe": "f208"}'
    sig = _dsse_pae_sig(payload, _PTYPE, _ATTACKER_SIGNER)
    env = {"payload": _b64(payload), "payloadType": _PTYPE,
           "signatures": [{"sig": sig.hex()}]}
    try:
        dsse.open_envelope(env, payload, _PTYPE, [_TRUSTED_VERIFIER])
        _record("dsse/keyid-less-attacker-sig-refused", "BREAK",
                "attacker sig verified against pinned keyset (impossible)")
    except dsse.EnvelopeError:
        _record("dsse/keyid-less-attacker-sig-refused", "HELD",
                "refused: no pinned verifier matched")
    except Exception as exc:  # noqa: BLE001
        _record("dsse/keyid-less-attacker-sig-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("dsse/threshold2-one-pinned-one-spoofed-refused")
def _p_dsse_threshold2():
    """Threshold=2 with one genuine pinned sig and one spoofed
    (attacker sig claiming the pinned kid). Distinct-KEY counting must
    not double-count."""
    payload = b'{"probe": "f208"}'
    good = _dsse_pae_sig(payload, _PTYPE, _TRUSTED_SIGNER)
    spoof = _dsse_pae_sig(payload, _PTYPE, _ATTACKER_SIGNER)
    env = {"payload": _b64(payload), "payloadType": _PTYPE,
           "signatures": [{"keyid": _TRUSTED_VERIFIER.key_id,
                           "sig": good.hex()},
                          {"keyid": _TRUSTED_VERIFIER.key_id,
                           "sig": spoof.hex()}]}
    try:
        dsse.open_envelope(env, payload, _PTYPE, [_TRUSTED_VERIFIER],
                           threshold=2)
        _record("dsse/threshold2-one-pinned-one-spoofed-refused", "BREAK",
                "threshold=2 met with only one pinned key")
    except dsse.EnvelopeError:
        _record("dsse/threshold2-one-pinned-one-spoofed-refused", "HELD",
                "refused: only 1 distinct pinned key verified")
    except Exception as exc:  # noqa: BLE001
        _record("dsse/threshold2-one-pinned-one-spoofed-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("dsse/extra-unknown-sig-ignored-honest-pass")
def _p_dsse_extra_junk():
    """Honest discipline check (NOT a break): an unknown junk signature
    appended to a genuinely-pinned envelope must be ignored, not fatal —
    the threshold is still met by the pinned key."""
    payload = b'{"probe": "f208"}'
    env = _dsse_valid_env()
    env["signatures"] = list(env["signatures"]) + [
        {"keyid": "junk-attacker-kid", "sig": "ab" * 64}]
    try:
        got = dsse.open_envelope(env, payload, _PTYPE,
                                 [_TRUSTED_VERIFIER])
        if got["key_ids"] == [_TRUSTED_VERIFIER.key_id]:
            _record("dsse/extra-unknown-sig-ignored-honest-pass", "HELD",
                    "pinned sig passes; junk sig ignored")
        else:
            _record("dsse/extra-unknown-sig-ignored-honest-pass", "ERROR",
                    "unexpected key_ids %r" % (got["key_ids"],))
    except Exception as exc:  # noqa: BLE001
        _record("dsse/extra-unknown-sig-ignored-honest-pass", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("dsse/threshold2-same-key-twice-refused")
def _p_dsse_same_key_twice():
    """Two signatures from the SAME pinned key must count once."""
    payload = b'{"probe": "f208"}'
    env = dsse.seal(payload, _PTYPE, [_TRUSTED_SIGNER, _TRUSTED_SIGNER])
    try:
        dsse.open_envelope(env, payload, _PTYPE, [_TRUSTED_VERIFIER],
                           threshold=2)
        _record("dsse/threshold2-same-key-twice-refused", "BREAK",
                "same pinned key counted twice toward threshold")
    except dsse.EnvelopeError:
        _record("dsse/threshold2-same-key-twice-refused", "HELD",
                "refused: distinct-key counting")
    except Exception as exc:  # noqa: BLE001
        _record("dsse/threshold2-same-key-twice-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("dsse/open-statement-spoofed-keyid-refused")
def _p_dsse_statement():
    """Statement envelope seam: spoofed pinned keyid refused."""
    env = dsse.seal_statement("ab" * 32, None, ["f208"], [_TRUSTED_SIGNER])
    payload = base64.b64decode(env["payload"])
    spoof = _dsse_pae_sig(payload, env["payloadType"], _ATTACKER_SIGNER)
    env["signatures"] = [{"keyid": _TRUSTED_VERIFIER.key_id,
                          "sig": spoof.hex()}]
    try:
        dsse.open_statement(env, "ab" * 32, None, ["f208"],
                            [_TRUSTED_VERIFIER])
        _record("dsse/open-statement-spoofed-keyid-refused", "BREAK",
                "statement verified under spoofed keyid")
    except dsse.EnvelopeError:
        _record("dsse/open-statement-spoofed-keyid-refused", "HELD",
                "refused")
    except Exception as exc:  # noqa: BLE001
        _record("dsse/open-statement-spoofed-keyid-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


# ---------------------------------------------------------------------------
# Legacy v2 envelope (open_any migration path)
# ---------------------------------------------------------------------------

@_probe("v2/valid-passes")
def _p_v2_valid():
    """Control: genuine v2 envelope opens under its own verifier."""
    env = env2.seal("ab" * 32, _TRUSTED_SIGNER, ["f208"],
                    provenance_digest=None)
    try:
        env2.open_envelope(env, "ab" * 32, _TRUSTED_VERIFIER,
                           expected_provenance_digest=None)
        _record("v2/valid-passes", "HELD", "genuine v2 opens")
    except Exception as exc:  # noqa: BLE001
        _record("v2/valid-passes", "ERROR", "%s: %s"
                % (type(exc).__name__, exc))


@_probe("v2/attacker-keyid-refused")
def _p_v2_attacker():
    """v2 envelope sealed by the attacker must not open under the
    pinned verifier (key_id binding)."""
    env = env2.seal("ab" * 32, _ATTACKER_SIGNER, ["f208"],
                    provenance_digest=None)
    try:
        env2.open_envelope(env, "ab" * 32, _TRUSTED_VERIFIER,
                           expected_provenance_digest=None)
        _record("v2/attacker-keyid-refused", "BREAK",
                "attacker v2 envelope opened under pinned verifier")
    except env2.EnvelopeError:
        _record("v2/attacker-keyid-refused", "HELD",
                "refused: key_id does not match verifier")
    except Exception as exc:  # noqa: BLE001
        _record("v2/attacker-keyid-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("v2/keyid-label-lie-refused")
def _p_v2_label_lie():
    """Attacker rewrites the envelope's key_id label to the pinned id.
    The signature body binds key_id, so the lie must fail on the
    signature path."""
    env = env2.seal("ab" * 32, _ATTACKER_SIGNER, ["f208"],
                    provenance_digest=None)
    env = dict(env)
    env["key_id"] = _TRUSTED_VERIFIER.key_id
    try:
        env2.open_envelope(env, "ab" * 32, _TRUSTED_VERIFIER,
                           expected_provenance_digest=None)
        _record("v2/keyid-label-lie-refused", "BREAK",
                "key_id label lie verified under pinned key")
    except env2.EnvelopeError:
        _record("v2/keyid-label-lie-refused", "HELD",
                "refused: signature binds key_id")
    except Exception as exc:  # noqa: BLE001
        _record("v2/keyid-label-lie-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("v2/open-any-attacker-refused")
def _p_v2_open_any():
    """open_any migration seam: attacker legacy envelope refused."""
    env = env2.seal("ab" * 32, _ATTACKER_SIGNER, ["f208"],
                    provenance_digest=None)
    try:
        dsse.open_any(env, "ab" * 32, None, ["f208"],
                      [_TRUSTED_VERIFIER])
        _record("v2/open-any-attacker-refused", "BREAK",
                "open_any accepted attacker legacy envelope")
    except Exception:  # noqa: BLE001
        _record("v2/open-any-attacker-refused", "HELD", "refused")


# ---------------------------------------------------------------------------
# Scan verdicts (pinned scanner keyset)
# ---------------------------------------------------------------------------

def _valid_verdict():
    return sv.emit_scan_verdict(
        scanner_name="f208-scanner", scanner_version="1",
        scan_target_digest="sha256:" + "cd" * 32, verdict="pass",
        ruleset_digest="sha256:" + "ef" * 32, scanned_at=_NOW,
        expires_at=_NOW + 3600, signer=_TRUSTED_SIGNER, now=_NOW)


def _sv_target():
    return "sha256:" + "cd" * 32


@_probe("scanverdict/valid-passes")
def _p_sv_valid():
    """Control: genuine verdict under pinned keyset verifies."""
    try:
        got = sv.verify_scan_verdict(
            _valid_verdict(), verifiers=[_TRUSTED_VERIFIER],
            scanner_name="f208-scanner", scan_target_digest=_sv_target(),
            now=_NOW)
        _record("scanverdict/valid-passes", "HELD",
                "verified_key_ids=%s" % (got["verified_key_ids"],))
    except Exception as exc:  # noqa: BLE001
        _record("scanverdict/valid-passes", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("scanverdict/attacker-signed-refused")
def _p_sv_attacker():
    """Verdict signed by the attacker (its own keyid), presented for a
    scanner whose pinned keyset is the trusted key -> refused."""
    bad = sv.emit_scan_verdict(
        scanner_name="f208-scanner", scanner_version="1",
        scan_target_digest=_sv_target(), verdict="pass",
        ruleset_digest="sha256:" + "ef" * 32, scanned_at=_NOW,
        expires_at=_NOW + 3600, signer=_ATTACKER_SIGNER, now=_NOW)
    try:
        sv.verify_scan_verdict(
            bad, verifiers=[_TRUSTED_VERIFIER],
            scanner_name="f208-scanner", scan_target_digest=_sv_target(),
            now=_NOW)
        _record("scanverdict/attacker-signed-refused", "BREAK",
                "attacker-signed verdict verified against pinned keyset")
    except sv.ScanVerdictError:
        _record("scanverdict/attacker-signed-refused", "HELD",
                "refused: no pinned key verified")
    except Exception as exc:  # noqa: BLE001
        _record("scanverdict/attacker-signed-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("scanverdict/spoofed-pinned-keyid-refused")
def _p_sv_spoofed():
    """Attacker re-signs the same payload, claims the PINNED keyid."""
    env = _valid_verdict()
    payload = base64.b64decode(env["payload"])
    spoof = _dsse_pae_sig(payload, env["payloadType"], _ATTACKER_SIGNER)
    env["signatures"] = [{"keyid": _TRUSTED_VERIFIER.key_id,
                          "sig": spoof.hex()}]
    try:
        sv.verify_scan_verdict(
            env, verifiers=[_TRUSTED_VERIFIER],
            scanner_name="f208-scanner", scan_target_digest=_sv_target(),
            now=_NOW)
        _record("scanverdict/spoofed-pinned-keyid-refused", "BREAK",
                "spoofed pinned keyid verified")
    except sv.ScanVerdictError:
        _record("scanverdict/spoofed-pinned-keyid-refused", "HELD",
                "refused")
    except Exception as exc:  # noqa: BLE001
        _record("scanverdict/spoofed-pinned-keyid-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


# ---------------------------------------------------------------------------
# Receipt countersignature pin (pinned operator key)
# ---------------------------------------------------------------------------

def _receipt_by(signer):
    import hashlib
    pub = signer.public_key
    kid = hashlib.sha256(pub).digest()[:16].hex()
    body = ir.build_receipt(
        holder={"agent_id": "f208-agent", "role": "agent",
                "principal": "f208", "run_id": "f208-run"},
        challenge="f208-challenge", action_tool="f208-tool",
        action_args=[], canonical_target="f208-target",
        policy_decision="allow", approval_id="ap-1",
        policy_id="pol-1", preview_text="f208 preview",
        outcome_status="ok", result={"status": "ok"},
        key_id=kid, pubkey_hex=pub.hex())
    # countersign takes a seed; sign with the same key bytes.
    return ir.countersign(body, bytes(pub) and _seed_of(signer))


def _seed_of(signer):
    # Recover the seed from the module-level fixed keypairs.
    if signer is _TRUSTED_SIGNER:
        return bytes.fromhex("11" * 32)
    return bytes.fromhex("22" * 32)


@_probe("receipt/pinned-key-attacker-countersign-refused")
def _p_receipt_pin():
    """GHSA-class shape: a receipt countersigned by the ATTACKER key,
    audited with the TRUSTED key pinned. Must fail closed."""
    receipt = _receipt_by(_ATTACKER_SIGNER)
    pin = _TRUSTED_SIGNER.public_key.hex()
    ok, reason = ev._verify_receipt_pinned_standalone(receipt, pin)
    if not ok:
        _record("receipt/pinned-key-attacker-countersign-refused",
                "HELD", "refused: %s" % (reason,))
    else:
        _record("receipt/pinned-key-attacker-countersign-refused",
                "BREAK", "attacker-countersigned receipt passed the pin")


@_probe("receipt/pinned-key-genuine-passes")
def _p_receipt_pin_valid():
    """Control: genuine countersignature under the pinned key passes."""
    receipt = _receipt_by(_TRUSTED_SIGNER)
    pin = _TRUSTED_SIGNER.public_key.hex()
    ok, reason = ev._verify_receipt_pinned_standalone(receipt, pin)
    if ok:
        _record("receipt/pinned-key-genuine-passes", "HELD",
                "genuine countersignature passes pin")
    else:
        _record("receipt/pinned-key-genuine-passes", "ERROR",
                "refused: %s" % (reason,))


# ---------------------------------------------------------------------------
# End-to-end: evidence bundle, attacker-signed operator vs trusted pin
# ---------------------------------------------------------------------------

def _build_bundle(signer, tmp_root, log_signer):
    """Assemble a full evidence bundle sealed by ``signer`` (the operator
    envelope claims ``signer``'s key). Returns (bundle_dir, op_key_hex)."""
    from gov.log import ActionLog
    from gov.evidence_bundle import (EvidenceBundle,
                                     log_evidence_bundle_receipt)
    log_path = os.path.join(tmp_root, "audit.log")
    log = ActionLog(log_path, signer=log_signer,
                    deployment_mode="staging")
    log.append({"event": "policy_loaded", "policy_version": "p1",
                "policy_hash": "h" * 16, "policy_path": "policies/p1.yaml",
                "pinned": True})
    for i in range(3):
        log.append({"event": "tool_call", "decision": "allow",
                    "tool": "tool-%d" % i})
    eb = EvidenceBundle(log_path, exported_at="2026-09-26T00:00:00+00:00",
                        operator_id="f208-battery")
    payload = eb.build()
    manifest = eb.seal(payload, signer=signer)
    log_evidence_bundle_receipt(
        manifest, ActionLog(log_path, signer=signer,
                            deployment_mode="staging"),
        signer=signer)
    op = {"key_id": signer.key_id,
          "public_key_hex": signer.public_key.hex()}
    out = os.path.join(tmp_root, "bundle")
    eb.assemble(payload, manifest, operator_key=op,
                checkpoint_keys=[dict(op)], out_dir=out)
    return out, signer.public_key.hex()


@_probe("bundle/attacker-operator-vs-trusted-pin-refused")
def _p_bundle_attacker_pin():
    """End-to-end GHSA shape: the whole bundle is sealed by the ATTACKER
    (its operator envelope names the attacker key), but the auditor pins
    the TRUSTED key. V6 authorship must fail closed."""
    try:
        from tests.keyfixture import provision_test_key, scrub_key_env
        restore = scrub_key_env()
        provision_test_key()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                bundle_dir, _ = _build_bundle(_ATTACKER_SIGNER, tmp,
                                              _ATTACKER_SIGNER)
                code, checks, _summary = ev.verify_bundle(
                    bundle_dir, pins=[_TRUSTED_SIGNER.public_key.hex()])
                v6 = [c for c in checks if c.id == "V6"]
                failed = [c for c in checks if c.status == "fail"]
                v6_failed = any(c.status == "fail" for c in v6)
                if code == 1 and v6_failed:
                    _record("bundle/attacker-operator-vs-trusted-pin-refused",
                            "HELD",
                            "V6 authorship pin failed closed (exit 1)")
                else:
                    _record("bundle/attacker-operator-vs-trusted-pin-refused",
                            "BREAK",
                            "exit=%s v6_failed=%s fails=%s"
                            % (code, v6_failed,
                               [(c.id, c.detail) for c in failed][:3]))
        finally:
            restore()
    except Exception as exc:  # noqa: BLE001
        _record("bundle/attacker-operator-vs-trusted-pin-refused", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("bundle/genuine-operator-trusted-pin-passes")
def _p_bundle_trusted_pin():
    """Control: trusted-sealed bundle + trusted pin -> VERIFIED."""
    try:
        from tests.keyfixture import provision_test_key, scrub_key_env
        restore = scrub_key_env()
        provision_test_key()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                bundle_dir, _ = _build_bundle(_TRUSTED_SIGNER, tmp,
                                              _TRUSTED_SIGNER)
                code, checks, summary = ev.verify_bundle(
                    bundle_dir, pins=[_TRUSTED_SIGNER.public_key.hex()])
                failed = [c for c in checks if c.status == "fail"]
                if code == 0 and not failed:
                    _record("bundle/genuine-operator-trusted-pin-passes",
                            "HELD", "VERIFIED")
                else:
                    _record("bundle/genuine-operator-trusted-pin-passes",
                            "ERROR",
                            "exit=%s fails=%s"
                            % (code, [(c.id, c.detail)
                                      for c in failed][:3]))
        finally:
            restore()
    except Exception as exc:  # noqa: BLE001
        _record("bundle/genuine-operator-trusted-pin-passes", "ERROR",
                "%s: %s" % (type(exc).__name__, exc))


@_probe("bundle/attacker-operator-unpinned-self-consistent-labeled")
def _p_bundle_self_consistent():
    """Honest-boundary control: WITHOUT pins, the attacker bundle is
    self-consistent, never VERIFIED — the documented posture, loud in
    the summary. This documents the residual, it is not a break."""
    try:
        from tests.keyfixture import provision_test_key, scrub_key_env
        restore = scrub_key_env()
        provision_test_key()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                bundle_dir, _ = _build_bundle(_ATTACKER_SIGNER, tmp,
                                              _ATTACKER_SIGNER)
                code, checks, summary = ev.verify_bundle(bundle_dir)
            failed = [c for c in checks if c.status == "fail"]
            if code == 2 and not failed and \
                    summary.get("verdict") == "SELF_CONSISTENT" and \
                    not summary.get("authorship", {}).get("pinned"):
                _record("bundle/attacker-operator-unpinned-self-consistent-labeled",
                        "HELD",
                        "self-consistent, authorship NOT established")
            else:
                _record("bundle/attacker-operator-unpinned-self-consistent-labeled",
                        "ERROR",
                        "exit=%s verdict=%s fails=%s"
                        % (code, summary.get("verdict"),
                           [(c.id, c.detail) for c in failed][:3]))
        finally:
            restore()
    except Exception as exc:  # noqa: BLE001
        _record("bundle/attacker-operator-unpinned-self-consistent-labeled",
                "ERROR", "%s: %s" % (type(exc).__name__, exc))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _green_check():
    if GREEN_SKIP:
        _record("green-check", "HELD", "skipped (GOV_SKIP_GREEN=1)")
        return
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    import subprocess
    adj = [
        ["evals/w215_identity_policy_probes.py"],
        ["evals/w214_agentcard_probes.py"],
        ["evals/w214_measurement_policy_probes.py"],
    ]
    ok = True
    for battery in adj:
        try:
            r = subprocess.run(
                [sys.executable, battery[0]], cwd=REPO, env=env,
                capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                ok = False
                _record("green-check", "ERROR",
                        "%s -> rc %d" % (battery[0], r.returncode))
        except Exception as exc:  # noqa: BLE001
            ok = False
            _record("green-check", "ERROR",
                    "%s -> %s" % (battery[0], exc))
    if ok:
        _record("green-check", "HELD", "3 adjacent batteries green")


def main():
    print("F208 break-first battery: bundle-embedded key-hint class")
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    first = [(n, v, d) for (n, v, d) in _RESULTS]
    # Determinism pass: run everything again, verdicts must be identical.
    _RESULTS[:] = []
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    if [(n, v) for (n, v, d) in _RESULTS] != [(n, v) for (n, v, d) in first]:
        print("DETERMINISM: FAIL")
        return 2
    print("DETERMINISM: PASS (%d/%d probes verdict-identical)"
          % (len(_RESULTS), len(first)))
    _green_check()
    held = sum(1 for _n, v, _d in _RESULTS if v == "HELD")
    breaks = sum(1 for _n, v, _d in _RESULTS if v == "BREAK")
    errors = sum(1 for _n, v, _d in _RESULTS if v == "ERROR")
    res = sum(1 for _n, v, _d in _RESULTS if v == "RESIDUAL")
    print("SUMMARY: %d HELD / %d BREAK / %d RESIDUAL / %d ERROR"
          % (held, breaks, res, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
