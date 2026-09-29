#!/usr/bin/env python3
"""Wave-200: red-first battery for the OPA-style pack activation layer.

RED-FIRST: run against the PRISTINE tree first. Every probe imports
gov.pack_loader / the PERM trust-domain parameters -- all absent
there -- so the pristine run is uniformly ERROR (missing public
seams), and the fixed tree holds. Probes:

  pl_activate_ok               -- well-formed pack activates.
  pl_extra_member              -- extra file beyond the manifest ->
                                 refused, nothing active.
  pl_omitted_member            -- manifest member not presented ->
                                 refused.
  pl_digest_mismatch           -- tampered member bytes -> refused.
  pl_signature_stripped        -- signatures removed -> refused.
  pl_threshold_unmet           -- 1 valid signature, threshold 2 ->
                                 refused.
  pl_stale_version             -- rollback below the floor -> refused.
  pl_expired                   -- expired pack -> refused.
  pl_guard_approval            -- guard require_approval -> refused,
                                 pending human.
  pl_failed_candidate_keeps_prior -- a bad v2 leaves v1 active +
                                 telemetry records the failure.
  pl_perm_domain_distinct      -- a PERM pack verifies under the
                                 PERM purpose/format and is REJECTED
                                 as a rule pack (and vice versa).
  pl_perm_loader_trust_domain  -- a detection-domain ActivePack is
                                 refused by the PERM loader even
                                 when its members are named like
                                 PERM members.
  pl_wrong_keyset_purpose      -- a keyset minted for another purpose
                                 cannot back a pack loader.
"""

import hashlib
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

_records = []


def _record(name, verdict, detail):
    _records.append((name, verdict, detail))


_SEED1 = bytes.fromhex("41" * 32)
_SEED2 = bytes.fromhex("42" * 32)
ISSUED = "2026-09-01T00:00:00+00:00"
EXPIRES = "2030-01-01T00:00:00+00:00"
NOW = "2026-10-01T00:00:00+00:00"
MEMBERS = {"rules/a.yml": b"rules:\n  - {name: a}\n",
           "rules/b.yml": b"rules:\n  - {name: b}\n"}


def _setup():
    from gov import pack_loader as pl
    from gov import rule_pack as rp
    from gov.keyset import (new_keyset, keyset_signer_for_version,
                            rotate_keyset)
    from gov.signing import Ed25519Signer
    return pl, rp, new_keyset, keyset_signer_for_version, \
        rotate_keyset, Ed25519Signer


def _digests(members):
    return {mid: "sha256:" + hashlib.sha256(data).hexdigest()
            for mid, data in members.items()}


def _mint(rp, keyset, signers, members=MEMBERS, version=1,
          threshold=1, **kw):
    kw.setdefault("issued_at", ISSUED)
    kw.setdefault("expires_at", EXPIRES)
    kw.setdefault("threshold", threshold)
    return rp.mint_rule_pack(keyset, signers,
                             rules=_digests(members),
                             pack_version=version, **kw)


def _loader(pl, keyset, pack_id="t"):
    return pl.PackLoader(keyset, pack_id)


def p_activate_ok():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    loader = _loader(pl, ks)
    active = loader.present(
        _mint(rp, ks, [ksfv(ks, 1, _SEED1)]), dict(MEMBERS),
        now=NOW)
    ok = (active.version == 1
          and active.member("rules/a.yml") == MEMBERS["rules/a.yml"]
          and loader.current is active)
    return ("PASS" if ok else "FAIL", "version=%s" % active.version)


def p_extra_member():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    loader = _loader(pl, ks)
    files = dict(MEMBERS)
    files["rules/evil.yml"] = b"evil: true\n"
    try:
        loader.present(_mint(rp, ks, [ksfv(ks, 1, _SEED1)]),
                       files, now=NOW)
        return ("FAIL", "extra member activated")
    except pl.PackActivationError as e:
        ok = (e.code == "pack-member-extra"
              and loader.current is None)
        return ("PASS" if ok else "FAIL", "code=%s" % e.code)


def p_omitted_member():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    loader = _loader(pl, ks)
    try:
        loader.present(_mint(rp, ks, [ksfv(ks, 1, _SEED1)]),
                       {"rules/a.yml": MEMBERS["rules/a.yml"]},
                       now=NOW)
        return ("FAIL", "omitted member activated")
    except pl.PackActivationError as e:
        return ("PASS" if e.code == "pack-member-omitted" else "FAIL",
                "code=%s" % e.code)


def p_digest_mismatch():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    loader = _loader(pl, ks)
    files = dict(MEMBERS)
    files["rules/a.yml"] = b"tampered\n"
    try:
        loader.present(_mint(rp, ks, [ksfv(ks, 1, _SEED1)]),
                       files, now=NOW)
        return ("FAIL", "tampered member activated")
    except pl.PackActivationError as e:
        return ("PASS" if e.code == "pack-member-digest-mismatch"
                else "FAIL", "code=%s" % e.code)


def p_signature_stripped():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    loader = _loader(pl, ks)
    doc = _mint(rp, ks, [ksfv(ks, 1, _SEED1)])
    doc["signatures"] = []
    try:
        loader.present(doc, dict(MEMBERS), now=NOW)
        return ("FAIL", "unsigned pack activated")
    except pl.PackActivationError as e:
        return ("PASS", "code=%s" % e.code)


def p_threshold_unmet():
    pl, rp, new_keyset, _ksfv, rot, Ed25519Signer = _setup()
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    ks, _ = rot(ks, _SEED2, _SEED1)
    signers = [Ed25519Signer(_SEED2), Ed25519Signer(_SEED1)]
    doc = _mint(rp, ks, signers, threshold=2)
    doc["signatures"][1]["sig"] = "00" * 64
    try:
        _loader(pl, ks).present(doc, dict(MEMBERS), now=NOW)
        return ("FAIL", "threshold-unmet pack activated")
    except pl.PackActivationError as e:
        return ("PASS" if e.code == "pack-threshold-unmet" else "FAIL",
                "code=%s" % e.code)


def p_stale_version():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    loader = _loader(pl, ks)
    loader.present(_mint(rp, ks, [ksfv(ks, 1, _SEED1)], version=3),
                   dict(MEMBERS), now=NOW)
    try:
        loader.present(
            _mint(rp, ks, [ksfv(ks, 1, _SEED1)], version=2),
            dict(MEMBERS), now=NOW)
        return ("FAIL", "rollback activated")
    except pl.PackActivationError as e:
        ok = (e.code == "pack-stale"
              and loader.current.version == 3)
        return ("PASS" if ok else "FAIL", "code=%s" % e.code)


def p_expired():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    loader = _loader(pl, ks)
    try:
        loader.present(
            _mint(rp, ks, [ksfv(ks, 1, _SEED1)],
                  expires_at="2026-09-15T00:00:00+00:00"),
            dict(MEMBERS), now=NOW)
        return ("FAIL", "expired pack activated")
    except pl.PackActivationError as e:
        return ("PASS" if e.code == "pack-pack-expired" else "FAIL",
                "code=%s" % e.code)


def p_guard_approval():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    loader = _loader(pl, ks)

    def guard(_snapshot):
        return "require_approval", "needs a human"

    try:
        loader.present(_mint(rp, ks, [ksfv(ks, 1, _SEED1)]),
                       dict(MEMBERS), guard=guard, now=NOW)
        return ("FAIL", "guard require_approval activated")
    except pl.PackActivationError as e:
        ok = (e.code == "pack-activation-approval-required"
              and loader.current is None)
        return ("PASS" if ok else "FAIL", "code=%s" % e.code)


def p_failed_candidate_keeps_prior():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    ks, _ = new_keyset(_SEED1, purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    loader = _loader(pl, ks)
    good = loader.present(
        _mint(rp, ks, [ksfv(ks, 1, _SEED1)], version=1),
        dict(MEMBERS), now=NOW)
    files = dict(MEMBERS)
    files["rules/a.yml"] = b"tampered\n"
    try:
        loader.present(_mint(rp, ks, [ksfv(ks, 1, _SEED1)],
                             version=2), files, now=NOW)
        return ("FAIL", "bad v2 activated")
    except pl.PackActivationError:
        failures = loader.activation_failures
        ok = (loader.current is good and len(failures) == 1
              and failures[0]["code"] == "pack-member-digest-mismatch")
        return ("PASS" if ok else "FAIL",
                "failures=%d" % len(failures))


def _mint_perm(rp, keyset, signers, version=1):
    members = {"perm-model.yml": b"model: 1\n",
               "perm-policy.yml": b"policy: 1\n"}
    doc = rp.mint_rule_pack(
        keyset, signers, rules=_digests(members),
        pack_version=version, issued_at=ISSUED,
        expires_at=EXPIRES, threshold=1,
        purpose=rp.KEYSET_PURPOSE_PERM_PACK,
        format_tag=rp.PERM_PACK_FORMAT)
    return doc, members


def p_perm_domain_distinct():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    rule_ks, _ = new_keyset(_SEED1,
                            purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    perm_ks, _ = new_keyset(_SEED2,
                            purpose=rp.KEYSET_PURPOSE_PERM_PACK)
    doc, _m = _mint_perm(
        rp, perm_ks, [ksfv(perm_ks, 1, _SEED2)])
    # A PERM pack verifies in its own domain...
    try:
        rp.verify_rule_pack(
            doc, perm_ks, now=NOW,
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
    except rp.RulePackError as e:
        return ("FAIL", "perm pack rejected in own domain: %s"
                % e.code)
    # ...and is refused as a rule pack (and vice versa).
    bad = 0
    try:
        rp.verify_rule_pack(doc, perm_ks, now=NOW)
    except rp.RulePackError:
        bad += 1
    rule_doc = _mint(rp, rule_ks, [ksfv(rule_ks, 1, _SEED1)])
    try:
        rp.verify_rule_pack(
            rule_doc, rule_ks, now=NOW,
            purpose=rp.KEYSET_PURPOSE_PERM_PACK,
            format_tag=rp.PERM_PACK_FORMAT)
    except rp.RulePackError:
        bad += 1
    return ("PASS" if bad == 2 else "FAIL",
            "cross-domain refusals=%d/2" % bad)


def p_perm_loader_trust_domain():
    pl, rp, new_keyset, ksfv, _rot, _es = _setup()
    from gov import perm_loader as pml
    rule_ks, _ = new_keyset(_SEED1,
                            purpose=rp.KEYSET_PURPOSE_RULE_PACK)
    members = {"perm-model.yml": b"model: x\n",
               "perm-policy.yml": b"policy: x\n"}
    doc = rp.mint_rule_pack(
        rule_ks, [ksfv(rule_ks, 1, _SEED1)],
        rules=_digests(members), pack_version=1,
        issued_at=ISSUED, expires_at=EXPIRES, threshold=1)
    active = pl.PackLoader(rule_ks, "detection").present(
        doc, dict(members), now=NOW)
    try:
        pml.load_perm_from_active_pack(active)
        return ("FAIL", "detection pack accepted as PERM")
    except pml.PermError as e:
        return ("PASS" if "trust domain" in str(e) else "FAIL",
                str(e)[:80])


def p_wrong_keyset_purpose():
    pl, rp, new_keyset, _ksfv, _rot, _es = _setup()
    other, _ = new_keyset(_SEED2, purpose="sasanam-test-other/v1")
    try:
        pl.PackLoader(other, "x")
        return ("FAIL", "wrong-purpose keyset accepted")
    except pl.PackActivationError as e:
        return ("PASS" if e.code == "wrong-keyset-purpose"
                else "FAIL", "code=%s" % e.code)


PROBES = [
    p_activate_ok,
    p_extra_member,
    p_omitted_member,
    p_digest_mismatch,
    p_signature_stripped,
    p_threshold_unmet,
    p_stale_version,
    p_expired,
    p_guard_approval,
    p_failed_candidate_keeps_prior,
    p_perm_domain_distinct,
    p_perm_loader_trust_domain,
    p_wrong_keyset_purpose,
]


def _run_once():
    _records.clear()
    for probe in PROBES:
        try:
            verdict, detail = probe()
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            verdict, detail = "ERROR", "%s: %s" % (
                type(e).__name__, e)
        _record(probe.__name__, verdict, detail)
    return list(_records)


def _green_check_adjacent():
    """Depth-1 green check: adjacent unit tests, GOV_SKIP_GREEN honored."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("SKIP",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                "tests/test_pack_loader.py standalone")
    import subprocess  # noqa: E402
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="pl-green-")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_pack_loader",
         "-v"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=600)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return ("PASS" if r.returncode == 0 else "FAIL",
            "tests.test_pack_loader rc=%d %s"
            % (r.returncode, tail[0]))


def main():
    first = _run_once()
    second = _run_once()  # determinism: identical verdicts twice
    det_ok = ([(n, v) for n, v, _ in first]
              == [(n, v) for n, v, _ in second])
    _record("determinism",
            "PASS" if det_ok else "FAIL",
            "two in-process runs agree on all %d probes" % len(PROBES)
            if det_ok else "MISMATCH between run 1 and run 2")
    gv, gd = _green_check_adjacent()
    _record("green_check_adjacent_units", gv, gd)
    npass = sum(1 for _, v, _ in _records if v == "PASS")
    nfail = sum(1 for _, v, _ in _records if v in ("FAIL", "ERROR"))
    skipped = sum(1 for _, v, _ in _records if v == "SKIP")
    print("== pack-loader battery ==")
    for n, v, d in _records:
        print("[%s] %s -- %s" % (v, n, d))
    print("PASS=%d FAIL/ERROR=%d SKIP=%d" % (npass, nfail, skipped))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
