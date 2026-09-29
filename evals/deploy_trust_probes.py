"""Break-first probes for the deploy-time trust configuration layer
(wave-202 lane C).

Red-first contract: on pristine ``8d8ad47`` the ``gov.deploy_trust_config``
seam does not exist, so ``main()`` reports ``SEAM ABSENT`` (expected).
On the fixed tree every probe must HELD, each double-run for
determinism.

Probes:
  P0  seam presence (import).
  P1  no trust config activated -> TrustedPackLoader.present refuses
      with code ``no-trust-config``.
  P2  pack signed by a key that is NOT a trust root for the class ->
      refused with ``trust-root-unknown``.
  P3  unsigned pack under ``signed-only`` policy -> refused with
      ``unsigned-refused``.
  P4  unsigned pack under ``loud-opt-out`` policy: activates ONLY with
      two DISTINCT operator acks; the opt-out audit log carries the
      record (both operators, member digests); single ack refused;
      same operator twice refused.
  P5  revoked trust root: config v2 names the kid in ``revoked_kids``;
      a pack signed by it is refused LOUDLY with ``trust-root-revoked``
      even though the kid signed packs fine under v1.
  P6  tampered trust config (body byte flipped, signatures intact):
      ``activate`` refuses; a fresh registry stays config-less and the
      loader refuses. A config with a valid body but a forged
      signature is refused at ``verify_rule_pack``.
  P7  root rotation: v2 with changed trust roots and NO handoff ->
      refused ``handoff-required``; v2 WITH old-root-signed handoff ->
      activates; old-root-signed packs accepted during the grace
      window (``grace_roots``/``grace_until``), refused after it.
  P8  rollback: activating v1 after v2 -> ``config-stale``.
  P9  unknown bundle class -> ``trust-class-unknown``.
  P10 skill-manifest trust helper: non-root signer refused,
      trust-root signer allowed.
  P11 expired config -> ``activate`` refuses with ``config-expired``.

$0 spend, synthetic/local deterministic only. No network.
"""

import hashlib
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_SEED_ROOT = bytes.fromhex("51" * 32)
_SEED_PACK = bytes.fromhex("52" * 32)
_SEED_PACK2 = bytes.fromhex("53" * 32)
_SEED_EVIL = bytes.fromhex("54" * 32)

ISSUED = "2026-09-01T00:00:00+00:00"
EXPIRES = "2030-01-01T00:00:00+00:00"
NOW = "2026-10-01T00:00:00+00:00"
LATER = "2027-01-01T00:00:00+00:00"
PAST = "2026-01-01T00:00:00+00:00"

MEMBERS = {
    "rules/a.yml": b"rules:\n  - {name: a}\n",
    "rules/b.yml": b"rules:\n  - {name: b}\n",
}


def _member_digests(members):
    return {mid: "sha256:" + hashlib.sha256(data).hexdigest()
            for mid, data in members.items()}


def main():
    try:
        from gov import deploy_trust_config as dtc  # noqa
        from gov import rule_pack as rp  # noqa
        from gov.keyset import new_keyset, keyset_signer_for_version  # noqa
    except ImportError as exc:
        print("SEAM ABSENT (expected on pristine): %s" % (exc,))
        return 2

    failures = []

    def run(name, fn):
        for attempt in (1, 2):
            try:
                fn()
            except AssertionError as exc:
                failures.append("%s[run%d]: %s" % (name, attempt, exc))
                return
            except Exception as exc:  # noqa: BLE001 -- a probe must
                # never error: an unexpected exception is a BREAK.
                failures.append("%s[run%d]: ERROR %s: %s"
                                % (name, attempt, type(exc).__name__, exc))
                return
        print("HELD %s" % (name,))

    # -- fixture builders -------------------------------------------------
    def make_env():
        root_keyset, _ = new_keyset(_SEED_ROOT,
                                    purpose=dtc.KEYSET_PURPOSE_DEPLOY_TRUST)
        root_signer = keyset_signer_for_version(root_keyset, 1, _SEED_ROOT)
        pack_keyset, _ = new_keyset(_SEED_PACK,
                                    purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        pack_signer = keyset_signer_for_version(pack_keyset, 1, _SEED_PACK)
        return root_keyset, root_signer, pack_keyset, pack_signer

    def pack_kid(keyset, seed):
        return keyset_signer_for_version(keyset, 1, seed).key_id

    def pack_pubhex(keyset, seed):
        return keyset_signer_for_version(
            keyset, 1, seed).public_key.hex()

    def mint_config(root_keyset, root_signer, body, version=1,
                    threshold=1):
        body_bytes = dtc.canonical_trust_config_json(body).encode("utf-8")
        doc = dtc.mint_trust_config(
            root_keyset, [root_signer], body=body,
            pack_version=version, issued_at=ISSUED, expires_at=EXPIRES,
            threshold=threshold)
        return doc, body_bytes

    def base_body(pack_keyset, policy="signed-only", **kw):
        classes = {
            "capability_rules": dtc.make_class_config(
                policy=policy,
                trust_roots=[dtc.make_trust_root(
                    pack_kid(pack_keyset, _SEED_PACK), 1,
                    pack_pubhex(pack_keyset, _SEED_PACK))],
                threshold=1),
        }
        body = dtc.make_config_body(config_version=1, issued_at=ISSUED,
                                    expires_at=EXPIRES, classes=classes,
                                    **kw)
        return body

    def mint_pack(pack_keyset, pack_signer, members=MEMBERS, version=1,
                  seed=_SEED_PACK):
        signer = (pack_signer if seed == _SEED_PACK
                  else keyset_signer_for_version(pack_keyset, 1, seed))
        return rp.mint_rule_pack(
            pack_keyset, [signer], rules=_member_digests(members),
            pack_version=version, issued_at=ISSUED, expires_at=EXPIRES,
            threshold=1)

    def trusted_loader(pack_keyset, registry,
                       pack_class="capability_rules"):
        return dtc.TrustedPackLoader(
            pack_keyset, "probe-pack", registry=registry,
            pack_class=pack_class)

    def expect_code(fn, code):
        try:
            fn()
        except dtc.TrustConfigError as exc:
            assert exc.code == code, \
                "expected code %r, got %r (%s)" % (code, exc.code,
                                                   exc.detail)
            return
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                "expected TrustConfigError(%r), got %s: %s"
                % (code, type(exc).__name__, exc))
        raise AssertionError("expected TrustConfigError(%r), no error"
                             % (code,))

    # -- P1: no trust config ----------------------------------------------
    def p1():
        root_keyset, _, pack_keyset, pack_signer = make_env()
        registry = dtc.TrustConfigRegistry(root_keyset)
        loader = trusted_loader(pack_keyset, registry)
        expect_code(lambda: loader.present(
            mint_pack(pack_keyset, pack_signer), dict(MEMBERS), now=NOW),
            "no-trust-config")
    run("P1", p1)

    # -- P2: non-root signer refused --------------------------------------
    # Realistic shape: ONE pack-signing keyset holding two keys (v1 and
    # a rotated v2); the trust config authorizes only v1's kid for the
    # class. A pack signed by v2's key verifies against the keyset but
    # is refused at the trust layer.
    def p2():
        root_keyset, root_signer, pack_keyset, pack_signer = make_env()
        from gov.keyset import rotate_keyset
        pack_keyset2, pack_signer2 = rotate_keyset(
            pack_keyset, _SEED_PACK2, _SEED_PACK)
        doc, body_bytes = mint_config(root_keyset, root_signer,
                                      base_body(pack_keyset))
        registry = dtc.TrustConfigRegistry(root_keyset)
        registry.activate(doc, body_bytes, now=NOW)
        loader = trusted_loader(pack_keyset2, registry)
        other_doc = rp.mint_rule_pack(
            pack_keyset2, [pack_signer2],
            rules=_member_digests(MEMBERS), pack_version=1,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=1)
        expect_code(lambda: loader.present(other_doc, dict(MEMBERS),
                                           now=NOW),
                    "trust-root-unknown")
        # and the trust-root-signed pack still activates
        active = loader.present(mint_pack(pack_keyset2, pack_signer),
                                dict(MEMBERS), now=NOW)
        assert active.member("rules/a.yml") == MEMBERS["rules/a.yml"]
    run("P2", p2)

    # -- P3: unsigned under signed-only refused ---------------------------
    def p3():
        root_keyset, root_signer, pack_keyset, _ = make_env()
        doc, body_bytes = mint_config(root_keyset, root_signer,
                                      base_body(pack_keyset, "signed-only"))
        registry = dtc.TrustConfigRegistry(root_keyset)
        registry.activate(doc, body_bytes, now=NOW)
        loader = trusted_loader(pack_keyset, registry)
        with tempfile.TemporaryDirectory(
                prefix="g202c-p3-") as tmp:
            log = dtc.UnsignedOptOutLog(
                os.path.join(tmp, "optout.jsonl"))
            expect_code(lambda: loader.present_unsigned(
                dict(MEMBERS), operators=("alice", "bob"),
                opt_out_log=log, now=NOW),
                "unsigned-refused")
    run("P3", p3)

    # -- P4: loud opt-out ceremony ----------------------------------------
    def p4():
        root_keyset, root_signer, pack_keyset, _ = make_env()
        doc, body_bytes = mint_config(
            root_keyset, root_signer,
            base_body(pack_keyset, policy="loud-opt-out"))
        registry = dtc.TrustConfigRegistry(root_keyset)
        registry.activate(doc, body_bytes, now=NOW)
        loader = trusted_loader(pack_keyset, registry)
        with tempfile.TemporaryDirectory(
                prefix="g202c-p4-") as tmp:
            log = dtc.UnsignedOptOutLog(
                os.path.join(tmp, "optout.jsonl"))
            # single ack is not enough
            expect_code(lambda: loader.present_unsigned(
                dict(MEMBERS), operators=("alice",),
                opt_out_log=log, now=NOW),
                "opt-out-quorum-unmet")
            # same operator twice is refused
            expect_code(lambda: loader.present_unsigned(
                dict(MEMBERS), operators=("alice", "alice"),
                opt_out_log=log, now=NOW),
                "opt-out-self-ack")
            # two distinct operators: activates
            active = loader.present_unsigned(
                dict(MEMBERS), operators=("alice", "bob"),
                opt_out_log=log, now=NOW)
            assert active.member("rules/a.yml") == MEMBERS["rules/a.yml"]
            records = log.read_all()
            # Two records: the refused single-ack attempt (audit-worthy)
            # plus the allowed two-operator activation.
            assert len(records) == 2, records
            assert records[0]["outcome"] == "refused:quorum-unmet", \
                records[0]
            rec = records[1]
            assert rec["outcome"] == "allowed", rec
            assert sorted(rec["operators"]) == ["alice", "bob"], rec
            assert rec["pack_class"] == "capability_rules", rec
            assert log.verify(), "opt-out log chain must verify"
    run("P4", p4)

    # -- P5: revoked trust root refused LOUDLY ----------------------------
    def p5():
        root_keyset, root_signer, pack_keyset, pack_signer = make_env()
        kid = pack_kid(pack_keyset, _SEED_PACK)
        doc1, body1 = mint_config(root_keyset, root_signer,
                                  base_body(pack_keyset))
        registry = dtc.TrustConfigRegistry(root_keyset)
        registry.activate(doc1, body1, now=NOW)
        loader = trusted_loader(pack_keyset, registry)
        # sanity: works under v1
        loader.present(mint_pack(pack_keyset, pack_signer),
                       dict(MEMBERS), now=NOW)
        # v2 revokes the kid (trust roots UNCHANGED, so no handoff
        # needed; supersedes chain still enforced)
        body2 = base_body(pack_keyset)
        body2["config_version"] = 2
        body2["supersedes"] = 1
        body2["revoked_kids"] = [{"kid": kid, "reason": "compromise"}]
        doc2, body2_bytes = mint_config(root_keyset, root_signer, body2,
                                        version=2)
        registry.activate(doc2, body2_bytes, now=NOW)
        expect_code(lambda: loader.present(
            mint_pack(pack_keyset, pack_signer, version=2),
            dict(MEMBERS), now=NOW),
            "trust-root-revoked")
    run("P5", p5)

    # -- P6: tampered trust config ----------------------------------------
    def p6():
        root_keyset, root_signer, pack_keyset, _ = make_env()
        doc, body_bytes = mint_config(root_keyset, root_signer,
                                      base_body(pack_keyset))
        registry = dtc.TrustConfigRegistry(root_keyset)
        # flip a byte in the body; the pack doc's digest pin breaks
        tampered = bytearray(body_bytes)
        tampered[20] ^= 0x01
        expect_code(lambda: registry.activate(doc, bytes(tampered),
                                              now=NOW),
                    "config-body-mismatch")
        assert registry.current is None
        # forged signature over a valid body
        evil_keyset, _ = new_keyset(_SEED_EVIL,
                                    purpose=dtc.KEYSET_PURPOSE_DEPLOY_TRUST)
        evil_signer = keyset_signer_for_version(evil_keyset, 1, _SEED_EVIL)
        forged_doc, _ = mint_config(evil_keyset, evil_signer,
                                    base_body(pack_keyset))
        try:
            registry.activate(forged_doc, body_bytes, now=NOW)
        except dtc.TrustConfigError as exc:
            assert exc.code.startswith("config-"), exc.code
        else:
            raise AssertionError("forged trust config activated")
        assert registry.current is None
        # the loader refuses while the registry is config-less
        loader = trusted_loader(pack_keyset, registry)
        expect_code(lambda: loader.present(
            mint_pack(pack_keyset,
                      keyset_signer_for_version(pack_keyset, 1,
                                                _SEED_PACK)),
            dict(MEMBERS), now=NOW),
                    "no-trust-config")
    run("P6", p6)

    # -- P7: root rotation with handoff ceremony --------------------------
    def p7():
        root_keyset, root_signer, pack_keyset, pack_signer = make_env()
        kid_old = pack_kid(pack_keyset, _SEED_PACK)
        pub_old = pack_pubhex(pack_keyset, _SEED_PACK)
        # new pack-signing keyset
        pack2_keyset, _ = new_keyset(_SEED_PACK2,
                                     purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        pack2_signer = keyset_signer_for_version(pack2_keyset, 1,
                                                 _SEED_PACK2)
        kid_new = pack2_signer.key_id
        pub_new = pack2_signer.public_key.hex()
        doc1, body1 = mint_config(root_keyset, root_signer,
                                  base_body(pack_keyset))
        registry = dtc.TrustConfigRegistry(root_keyset)
        registry.activate(doc1, body1, now=NOW)
        # v2 changes trust roots WITHOUT handoff -> refused
        body2 = dtc.make_config_body(
            config_version=2, issued_at=ISSUED, expires_at=EXPIRES,
            supersedes=1,
            classes={
                "capability_rules": dtc.make_class_config(
                    policy="signed-only",
                    trust_roots=[dtc.make_trust_root(kid_new, 1,
                                                     pub_new)],
                    grace_roots=[dtc.make_trust_root(kid_old, 1,
                                                     pub_old)],
                    grace_until=LATER,
                    threshold=1),
            })
        doc2, body2_bytes = mint_config(root_keyset, root_signer, body2,
                                        version=2)
        expect_code(lambda: registry.activate(doc2, body2_bytes,
                                              now=NOW),
                    "handoff-required")
        # sign the handoff with the OLD pack-signing key, over the
        # digest of the body WITHOUT the handoff attached (a
        # signature cannot cover its own carrier)
        handoff = dtc.sign_handoff(
            pack_signer,
            prev_config_version=1,
            new_body_digest=dtc.body_digest_for_handoff(body2))
        body2["handoff"] = handoff
        doc2b, body2b_bytes = mint_config(root_keyset, root_signer,
                                          body2, version=2)
        registry.activate(doc2b, body2b_bytes, now=NOW)
        # new-root pack activates on a loader keyed to the new keyset
        loader2 = dtc.TrustedPackLoader(
            pack2_keyset, "probe-pack", registry=registry,
            pack_class="capability_rules")
        pack2_doc = rp.mint_rule_pack(
            pack2_keyset, [pack2_signer],
            rules=_member_digests(MEMBERS), pack_version=1,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=1)
        loader2.present(pack2_doc, dict(MEMBERS), now=NOW)
        # old-root pack still accepted inside the grace window
        loader_old = trusted_loader(pack_keyset, registry)
        loader_old.present(mint_pack(pack_keyset, pack_signer,
                                     version=2),
                           dict(MEMBERS), now=NOW)
        # ...but refused after the grace window closes
        expect_code(lambda: loader_old.present(
            mint_pack(pack_keyset, pack_signer, version=3),
            dict(MEMBERS), now="2028-01-01T00:00:00+00:00"),
            "trust-root-unknown")
    run("P7", p7)

    # -- P8: rollback refused ---------------------------------------------
    def p8():
        root_keyset, root_signer, pack_keyset, _ = make_env()
        doc1, body1 = mint_config(root_keyset, root_signer,
                                  base_body(pack_keyset))
        body2 = base_body(pack_keyset)
        body2["config_version"] = 2
        body2["supersedes"] = 1
        doc2, body2_bytes = mint_config(root_keyset, root_signer, body2,
                                        version=2)
        registry = dtc.TrustConfigRegistry(root_keyset)
        registry.activate(doc1, body1, now=NOW)
        registry.activate(doc2, body2_bytes, now=NOW)
        expect_code(lambda: registry.activate(doc1, body1, now=NOW),
                    "config-stale")
        assert registry.current.config_version == 2
    run("P8", p8)

    # -- P9: unknown class -------------------------------------------------
    def p9():
        root_keyset, root_signer, pack_keyset, pack_signer = make_env()
        doc, body_bytes = mint_config(root_keyset, root_signer,
                                      base_body(pack_keyset))
        registry = dtc.TrustConfigRegistry(root_keyset)
        registry.activate(doc, body_bytes, now=NOW)
        loader = trusted_loader(pack_keyset, registry,
                                pack_class="no-such-class")
        expect_code(lambda: loader.present(
            mint_pack(pack_keyset, pack_signer), dict(MEMBERS), now=NOW),
            "trust-class-unknown")
    run("P9", p9)

    # -- P10: skill-manifest trust helper ----------------------------------
    def p10():
        root_keyset, root_signer, pack_keyset, _ = make_env()
        kid = pack_kid(pack_keyset, _SEED_PACK)
        doc, body_bytes = mint_config(root_keyset, root_signer,
                                      base_body(pack_keyset))
        registry = dtc.TrustConfigRegistry(root_keyset)
        registry.activate(doc, body_bytes, now=NOW)
        # trust-root signer: allowed (returns None)
        assert dtc.check_manifest_trust(
            registry, "capability_rules", [kid]) is None
        # stranger signer: refused
        evil_keyset, _ = new_keyset(_SEED_EVIL,
                                    purpose=rp.KEYSET_PURPOSE_RULE_PACK)
        evil_kid = keyset_signer_for_version(
            evil_keyset, 1, _SEED_EVIL).key_id
        expect_code(lambda: dtc.check_manifest_trust(
            registry, "capability_rules", [evil_kid]),
            "trust-root-unknown")
        # no config: refused
        empty = dtc.TrustConfigRegistry(root_keyset)
        expect_code(lambda: dtc.check_manifest_trust(
            empty, "capability_rules", [kid]),
            "no-trust-config")
    run("P10", p10)

    # -- P11: expired config refused ---------------------------------------
    def p11():
        root_keyset, root_signer, pack_keyset, _ = make_env()
        body = base_body(pack_keyset)
        # Shape-valid but expired relative to NOW: issued before the
        # (past) expiry so minting succeeds and activation refuses.
        body["issued_at"] = "2025-06-01T00:00:00+00:00"
        body["expires_at"] = PAST
        doc, body_bytes = mint_config(root_keyset, root_signer, body)
        registry = dtc.TrustConfigRegistry(root_keyset)
        expect_code(lambda: registry.activate(doc, body_bytes, now=NOW),
                    "config-expired")
        assert registry.current is None
    run("P11", p11)

    print("----")
    if failures:
        print("BREAK: %d probe failure(s)" % len(failures))
        for f in failures:
            print("  " + f)
        return 1
    print("ALL PROBES HELD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
