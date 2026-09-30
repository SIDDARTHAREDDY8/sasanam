#!/usr/bin/env python3
"""Wave-218 lane C: bundle-admissibility battery — the EMILIA ADAPT.

Seam under test: gov/bundle_admissibility.py — verification outcomes
are classified (admissible | missing_evidence | stale | conflicted |
unverifiable) for a relying party's admissibility policy, and each
verification is replay-bound to {policy, normalized_facts, as_of}.

Attack shapes: stale replay under a rotated policy, replay under
altered facts, replay under a different as_of, stale-record replay,
conflicted chains admitted silently, missing evidence admitted
silently, digest-role confusion in the replay binding.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pristine wave-217 HEAD
aa92522b1a683b9608d50810ca8984dcdebc102b.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g218c
  TMPDIR=/var/tmp/g218c ~/workspace/.gov-venv/bin/python evals/w218_admissibility_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g218c-u \\
      ~/workspace/.gov-venv/bin/python evals/w218_admissibility_probes.py
"""

import copy
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w218-admiss-probes")
# Wave-112: the TMPDIR fallback must exist, or tempfile silently
# degrades to /tmp.
_TMPDIR_FALLBACK = "/var/tmp/g218c-%d" % os.getpid()
os.environ.setdefault("TMPDIR", _TMPDIR_FALLBACK)
try:
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
except OSError:
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import bundle_admissibility as ba  # noqa: E402
    from gov import evidence_bundle as _eb  # noqa: E402
    from gov.signing import Ed25519Signer  # noqa: E402
    from gov.log import ActionLog  # noqa: E402
    _IMPORT_OK = True
    _IMPORT_ERR = None
except Exception as exc:  # noqa: BLE001 - pristine run has no module
    ba = None
    _IMPORT_OK = False
    _IMPORT_ERR = exc

_RESULTS = []
_PROBE_FNS = {}

EXPORTED_AT = "2026-09-26T00:00:00+00:00"


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))


def _held(name, detail=""):
    _record(name, "HELD", detail)


def _break(name, detail=""):
    _record(name, "BREAK", detail)


def _gap(name):
    _record(name, "GAP", "module absent on pristine tree")


# ----------------------------------------------------------------------
# Harness helpers (only meaningful when the module is present).
# ----------------------------------------------------------------------

def _signer(seed_byte="7c"):
    return Ed25519Signer(bytes.fromhex(seed_byte * 32))


def _build_log(path, signer):
    log = ActionLog(path, signer=signer, deployment_mode="staging")
    log.append({"event": "policy_loaded", "policy_version": "p1",
                "policy_hash": "h" * 16, "policy_path": "policies/p1.yaml",
                "pinned": True})
    for i in range(3):
        log.append({"event": "tool_call", "decision": "allow",
                    "tool": "tool-%d" % i})
    return log


def _rewrite(bundle_dir, rel, obj):
    p = os.path.join(bundle_dir, rel)
    with open(p, "w", encoding="utf-8") as f:
        f.write(_eb.canonical(obj).decode("utf-8") + "\n")


def _redigest(bundle_dir):
    from gov.safeguard_bundle import compute_bundle_digest
    digest = compute_bundle_digest(bundle_dir)
    with open(os.path.join(bundle_dir, "BUNDLE_DIGEST.sha256"), "w") as f:
        f.write(digest + "\n")
    return digest


def _assemble_bundle(tmp, name, signer, exported_at=EXPORTED_AT,
                     mutate_payload=None, hmac_only=False):
    """Build/seal/receipt/assemble a bundle. mutate_payload(payload)
    runs between build() and seal() (the bundle_id is recomputed and
    the manifest re-signed, so V4/V7 hold while V11-class checks see
    the mutation). hmac_only=True builds the operator-declared
    degraded bundle (no signed checkpoints -> coverage 0/N)."""
    from gov.evidence_bundle import (
        EvidenceBundle, log_evidence_bundle_receipt)
    d = os.path.join(tmp, name)
    os.mkdir(d)
    lp = os.path.join(d, "audit.log")
    if hmac_only:
        log = ActionLog(lp, signer=None, deployment_mode="staging")
        log.append({"event": "policy_loaded", "policy_version": "p1",
                    "policy_hash": "h" * 16,
                    "policy_path": "policies/p1.yaml", "pinned": True})
        for i in range(3):
            log.append({"event": "tool_call", "decision": "allow",
                        "tool": "tool-%d" % i})
    else:
        _build_log(lp, signer)
    eb = EvidenceBundle(lp, exported_at=exported_at,
                        operator_id="admiss-probes")
    payload = eb.build()
    if mutate_payload is not None:
        mutate_payload(payload)
        payload["bundle_meta"]["bundle_id"] = None
        payload["bundle_meta"]["bundle_id"] = (
            "EVB-" + hashlib.sha256(
                _eb.canonical(payload)).hexdigest()[:16])
    manifest = eb.seal(payload, signer=signer)
    log_evidence_bundle_receipt(
        manifest,
        ActionLog(lp, signer=None if hmac_only else signer,
                  deployment_mode="staging"),
        signer=signer)
    op = {"key_id": signer.key_id,
          "public_key_hex": signer.public_key.hex()}
    out = os.path.join(d, "bundle")
    eb.assemble(payload, manifest, operator_key=op,
                checkpoint_keys=[dict(op)], out_dir=out)
    return out


def _expect(name, cond, detail_ok, detail_bad):
    if cond:
        _held(name, detail_ok)
    else:
        _break(name, detail_bad)


# ----------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------

@_probe("happy-admissible-auditor")
def _p_happy():
    if not _IMPORT_OK:
        return _gap("happy-admissible-auditor")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        bdir = _assemble_bundle(tmp, "b1", _signer())
        res = ba.admit(bdir, ba.AdmissibilityPolicy.auditor_strict(),
                       as_of="2026-09-26T01:00:00+00:00")
        _expect("happy-admissible-auditor",
                res["outcome"] == "admissible" and res["accepted"]
                and res["code"] == "admissible",
                "auditor admits a fresh, fully-evidenced bundle",
                "got %r" % res)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("stale-bounded-by-asof")
def _p_stale():
    if not _IMPORT_OK:
        return _gap("stale-bounded-by-asof")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        bdir = _assemble_bundle(tmp, "b1", _signer())
        res = ba.classify(bdir, as_of="2026-09-28T00:00:00+00:00",
                          max_age_seconds=3600)
        _expect("stale-bounded-by-asof",
                res["outcome"] == "stale" and any(
                    "max_age_seconds" in r for r in res["reasons"]),
                "2-day-old bundle is stale under a 1h bound",
                "got %r" % res["outcome"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("monitor-lax-accepts-stale-with-warning")
def _p_lax_stale():
    if not _IMPORT_OK:
        return _gap("monitor-lax-accepts-stale-with-warning")
    d = ba.AdmissibilityPolicy.monitor_lax().decide("stale", ["old"])
    _expect("monitor-lax-accepts-stale-with-warning",
            d["accepted"] and d["code"] == "tolerated_stale"
            and d["warning"] == "bundle_stale_accepted",
            "monitor tolerates stale with a named warning code",
            "got %r" % d)


@_probe("auditor-strict-refuses-stale")
def _p_strict_stale():
    if not _IMPORT_OK:
        return _gap("auditor-strict-refuses-stale")
    d = ba.AdmissibilityPolicy.auditor_strict().decide("stale", ["old"])
    _expect("auditor-strict-refuses-stale",
            not d["accepted"] and d["code"] == "rejected_stale",
            "auditor refuses stale",
            "got %r" % d)


@_probe("conflicted-chains-refused-by-default")
def _p_conflicted():
    if not _IMPORT_OK:
        return _gap("conflicted-chains-refused-by-default")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        def mutate(payload):
            payload["policy"]["policy_version"]["value"] = "p999"
        bdir = _assemble_bundle(tmp, "b1", _signer(),
                                mutate_payload=mutate)
        res = ba.classify(bdir, as_of="2026-09-26T01:00:00+00:00")
        strict = ba.admit(bdir, ba.AdmissibilityPolicy.auditor_strict(),
                          as_of="2026-09-26T01:00:00+00:00")
        lax = ba.admit(bdir, ba.AdmissibilityPolicy.monitor_lax(),
                       as_of="2026-09-26T01:00:00+00:00")
        _expect("conflicted-chains-refused-by-default",
                res["outcome"] == "conflicted"
                and not strict["accepted"]
                and not lax["accepted"],
                "payload/slice policy disagreement is conflicted and "
                "refused by both default policies",
                "outcome=%r strict=%r lax=%r"
                % (res["outcome"], strict["accepted"], lax["accepted"]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("missing-evidence-degraded-coverage")
def _p_missing_cov():
    if not _IMPORT_OK:
        return _gap("missing-evidence-degraded-coverage")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        bdir = _assemble_bundle(tmp, "b1", _signer(), hmac_only=True)
        res = ba.classify(bdir, as_of="2026-09-26T01:00:00+00:00")
        strict = ba.admit(bdir, ba.AdmissibilityPolicy.auditor_strict(),
                          as_of="2026-09-26T01:00:00+00:00")
        lax = ba.admit(bdir, ba.AdmissibilityPolicy.monitor_lax(),
                       as_of="2026-09-26T01:00:00+00:00")
        _expect("missing-evidence-degraded-coverage",
                res["outcome"] == "missing_evidence"
                and not strict["accepted"]
                and not lax["accepted"],
                "honestly-degraded 0/N coverage classifies as "
                "missing_evidence, refused by both default policies",
                "outcome=%r strict=%r lax=%r"
                % (res["outcome"], strict["accepted"], lax["accepted"]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("missing-required-file")
def _p_missing_file():
    if not _IMPORT_OK:
        return _gap("missing-required-file")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        bdir = _assemble_bundle(tmp, "b1", _signer())
        os.remove(os.path.join(bdir, "checkpoints.jsonl"))
        _redigest(bdir)
        res = ba.classify(bdir, as_of="2026-09-26T01:00:00+00:00")
        _expect("missing-required-file",
                res["outcome"] == "missing_evidence",
                "absent required file classifies as missing_evidence",
                "got %r" % res["outcome"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("tampered-payload-unverifiable")
def _p_tamper():
    if not _IMPORT_OK:
        return _gap("tampered-payload-unverifiable")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        bdir = _assemble_bundle(tmp, "b1", _signer())
        p = os.path.join(bdir, "evidence.json")
        payload = json.loads(open(p, encoding="utf-8").read())
        payload["decisions"]["by_event"]["tool_call"] = 999
        _rewrite(bdir, "evidence.json", payload)
        _redigest(bdir)
        res = ba.classify(bdir, as_of="2026-09-26T01:00:00+00:00")
        _expect("tampered-payload-unverifiable",
                res["outcome"] == "unverifiable",
                "post-seal payload tamper is unverifiable",
                "got %r" % res["outcome"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("replay-happy")
def _p_replay_happy():
    if not _IMPORT_OK:
        return _gap("replay-happy")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        bdir = _assemble_bundle(tmp, "b1", _signer())
        pol = ba.AdmissibilityPolicy.auditor_strict()
        rec = ba.bind_verification(
            bdir, pol, as_of="2026-09-26T01:00:00+00:00")
        chk = ba.check_replay(
            rec, policy=pol, now="2026-09-26T02:00:00+00:00")
        _expect("replay-happy",
                chk["outcome"] == "admissible" and chk["code"] == "replay_ok",
                "same policy/facts/as_of replays clean",
                "got %r" % chk)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("replay-rotated-policy-unverifiable")
def _p_replay_policy():
    if not _IMPORT_OK:
        return _gap("replay-rotated-policy-unverifiable")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        bdir = _assemble_bundle(tmp, "b1", _signer())
        rec = ba.bind_verification(
            bdir, ba.AdmissibilityPolicy.auditor_strict(),
            as_of="2026-09-26T01:00:00+00:00")
        chk = ba.check_replay(
            rec, policy=ba.AdmissibilityPolicy.monitor_lax(),
            now="2026-09-26T02:00:00+00:00")
        _expect("replay-rotated-policy-unverifiable",
                chk["outcome"] == "unverifiable"
                and chk["code"] == "replay_binding_mismatch",
                "replay under a rotated policy is unverifiable",
                "got %r" % chk)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("replay-altered-facts-unverifiable")
def _p_replay_facts():
    if not _IMPORT_OK:
        return _gap("replay-altered-facts-unverifiable")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        bdir = _assemble_bundle(tmp, "b1", _signer())
        pol = ba.AdmissibilityPolicy.auditor_strict()
        rec = ba.bind_verification(
            bdir, pol, as_of="2026-09-26T01:00:00+00:00")
        facts = dict(rec["facts"])
        facts["outcome"] = "unverifiable"  # attacker-altered fact set
        chk = ba.check_replay(rec, policy=pol, facts=facts,
                              now="2026-09-26T02:00:00+00:00")
        _expect("replay-altered-facts-unverifiable",
                chk["outcome"] == "unverifiable"
                and chk["code"] == "replay_binding_mismatch",
                "replay under altered facts is unverifiable",
                "got %r" % chk)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("replay-asof-mismatch-unverifiable")
def _p_replay_asof():
    if not _IMPORT_OK:
        return _gap("replay-asof-mismatch-unverifiable")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        bdir = _assemble_bundle(tmp, "b1", _signer())
        pol = ba.AdmissibilityPolicy.auditor_strict()
        rec = ba.bind_verification(
            bdir, pol, as_of="2026-09-26T01:00:00+00:00")
        chk = ba.check_replay(rec, policy=pol,
                              as_of="2026-09-27T01:00:00+00:00",
                              now="2026-09-27T02:00:00+00:00")
        _expect("replay-asof-mismatch-unverifiable",
                chk["outcome"] == "unverifiable"
                and chk["code"] == "replay_binding_mismatch",
                "replay under a different as_of is unverifiable",
                "got %r" % chk)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("replay-stale-record")
def _p_replay_stale():
    if not _IMPORT_OK:
        return _gap("replay-stale-record")
    tmp = tempfile.mkdtemp(prefix="w218-adm-")
    try:
        bdir = _assemble_bundle(tmp, "b1", _signer())
        pol = ba.AdmissibilityPolicy(
            accept=("admissible", "stale"), warn=("stale",),
            max_age_seconds=3600, name="hourly")
        rec = ba.bind_verification(
            bdir, pol, as_of="2026-09-26T01:00:00+00:00")
        chk = ba.check_replay(rec, policy=pol,
                              now="2026-09-28T01:00:00+00:00")
        _expect("replay-stale-record",
                chk["outcome"] == "stale"
                and chk["code"] == "verification_record_stale",
                "an old verification record replays as stale, not "
                "admissible",
                "got %r" % chk)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@_probe("conflicted-accept-requires-acknowledge")
def _p_ack():
    if not _IMPORT_OK:
        return _gap("conflicted-accept-requires-acknowledge")
    try:
        ba.AdmissibilityPolicy(accept=("conflicted",))
        _break("conflicted-accept-requires-acknowledge",
               "accepting conflicted without acknowledge_risk succeeded")
        return
    except ba.PolicyAuthoringError:
        pass
    try:
        ba.AdmissibilityPolicy(accept=("missing_evidence",))
        _break("conflicted-accept-requires-acknowledge",
               "accepting missing_evidence without acknowledge_risk "
               "succeeded")
        return
    except ba.PolicyAuthoringError:
        pass
    p = ba.AdmissibilityPolicy(
        accept=("conflicted", "missing_evidence"),
        warn=("conflicted", "missing_evidence"),
        acknowledge_risk=True)
    d = p.decide("conflicted", ["explicitly tolerated"])
    _expect("conflicted-accept-requires-acknowledge",
            d["accepted"] and d["code"] == "tolerated_conflicted"
            and d["warning"] == "bundle_conflicted_accepted",
            "risky classes pass only with explicit acknowledgment, "
            "and even then with a warning code",
            "got %r" % d)


@_probe("malformed-record-unverifiable")
def _p_malformed():
    if not _IMPORT_OK:
        return _gap("malformed-record-unverifiable")
    pol = ba.AdmissibilityPolicy.auditor_strict()
    chk = ba.check_replay({"format": "bogus"}, policy=pol)
    _expect("malformed-record-unverifiable",
            chk["outcome"] == "unverifiable"
            and chk["code"] == "malformed_record",
            "a forged record is unverifiable, never admissible",
            "got %r" % chk)


def _green_check():
    if not _IMPORT_OK:
        _record("green-check", "GAP", "module absent on pristine tree")
        return
    if GREEN_SKIP:
        _record("green-check", "HELD", "skipped (GOV_SKIP_GREEN=1)")
        return
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    adj = [
        ["evals/w217_receipt_probes.py"],
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
        _record("green-check", "HELD", "1 adjacent battery green")


def main():
    print("Admissibility battery: classified outcomes + replay binding")
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    first = [(n, v) for (n, v, d) in _RESULTS]
    _RESULTS[:] = []
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    if [(n, v) for (n, v, d) in _RESULTS] != first:
        print("DETERMINISM: FAIL")
        return 2
    print("DETERMINISM: PASS (%d/%d probes verdict-identical)"
          % (len(_RESULTS), len(first)))
    _green_check()
    held = sum(1 for _n, v, _d in _RESULTS if v == "HELD")
    gaps = sum(1 for _n, v, _d in _RESULTS if v == "GAP")
    breaks = sum(1 for _n, v, _d in _RESULTS if v == "BREAK")
    errors = sum(1 for _n, v, _d in _RESULTS if v == "ERROR")
    res = sum(1 for _n, v, _d in _RESULTS if v == "RESIDUAL")
    print("SUMMARY: %d HELD / %d GAP / %d BREAK / %d RESIDUAL / %d ERROR"
          % (held, gaps, breaks, res, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
