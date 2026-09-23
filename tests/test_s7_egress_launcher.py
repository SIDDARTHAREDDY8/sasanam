"""S7-stream unit tests: filtered-egress launcher (F136 productization).

Fast hermetic tests for the pinning/verification/launcher machinery;
the adversarial battery lives in evals/s7egress_break.py.
"""

import fcntl
import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.delegation_tokens import DelegationTrust  # noqa: E402
from gov.ed25519 import generate_seed as _gen_seed  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
from gov.egress_launcher import (  # noqa: E402
    DEFAULT_ALGOS,
    EgressLaunchRefused,
    FakePacketFilter,
    FilteredEgressLauncher,
    SimulatedWallFixture,
    SimulatedWallProvider,
    WallComponentInventory,
    WallPinRefused,
    WALL_COMPONENTS,
    component_digests,
    install_simulated_wall,
    negotiate_algo,
    repin_after_fixture_fixup,
)


def _mk_tmp():
    return tempfile.mkdtemp(prefix="s7unit-",
                            dir=os.environ.get("TMPDIR", "/tmp"))


class DigestTests(unittest.TestCase):
    def test_digest_deterministic(self):
        self.assertEqual(component_digests(b"abc"),
                         component_digests(b"abc"))
        self.assertNotEqual(component_digests(b"abc"),
                            component_digests(b"abd"))

    def test_digest_covers_all_default_algos(self):
        d = component_digests(b"x")
        self.assertEqual(set(d), set(DEFAULT_ALGOS))

    def test_negotiate_prefers_strongest_common(self):
        self.assertEqual(negotiate_algo(["sha256", "sha512"],
                                        ["sha256", "sha512"]), "sha512")
        self.assertEqual(negotiate_algo(["sha256"], ["sha256", "sha512"]),
                         "sha256")

    def test_negotiate_none_when_disjoint(self):
        self.assertIsNone(negotiate_algo(["sha512"], ["sha256"]))
        self.assertIsNone(negotiate_algo([], ["sha256"]))


class InventoryTests(unittest.TestCase):
    def _install(self, tmp, **kw):
        sim = os.path.join(tmp, "wall")
        return (sim,) + install_simulated_wall(sim, **kw)

    def test_install_pins_all_components(self):
        tmp = _mk_tmp()
        sim, inv, paths = self._install(tmp)
        manifest, checked = inv.verify()
        self.assertEqual(
            sorted(e["name"] for e in manifest["components"]),
            sorted(WALL_COMPONENTS))
        self.assertEqual(sorted(checked), sorted(WALL_COMPONENTS))
        self.assertEqual(manifest["format"], "egress-wall-pins/2")
        # F138: every install carries a pin record + ledger entry.
        self.assertIn("pin_record", manifest)
        self.assertTrue(manifest["pin_record"]["author_key_ids"])

    def test_receipt_binds_manifest(self):
        tmp = _mk_tmp()
        sim, inv, paths = self._install(tmp)
        receipt = json.load(open(paths["receipt"], encoding="utf-8"))
        blob = open(paths["manifest"], "rb").read()
        import hashlib
        self.assertEqual(receipt["manifest_sha256"],
                         hashlib.sha256(blob).hexdigest())

    def test_install_requires_all_components(self):
        tmp = _mk_tmp()
        # F138: the bare call is refused on authorship before any
        # component validation runs.
        with self.assertRaises(WallPinRefused) as cm:
            WallComponentInventory.install(
                {}, "/tmp/x.json", "/tmp/y.json")
        self.assertIn("pin_authorship_invalid", str(cm.exception))

    def test_byte_flip_detected(self):
        tmp = _mk_tmp()
        sim, inv, paths = self._install(tmp)
        p = os.path.join(sim, "conf", "dns_config.txt")
        with open(p, "ab") as f:
            f.write(b" ")
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv.verify()
        self.assertIn("component_tampered", str(cm.exception))
        self.assertIn("dns_config", str(cm.exception))

    def test_missing_component_detected(self):
        tmp = _mk_tmp()
        sim, inv, paths = self._install(tmp)
        os.remove(os.path.join(sim, "conf", "seccomp_config.txt"))
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv.verify()
        self.assertIn("component_tampered", str(cm.exception))

    def test_manifest_edit_detected_via_receipt(self):
        tmp = _mk_tmp()
        sim, inv, paths = self._install(tmp)
        data = open(paths["manifest"], encoding="utf-8").read()
        open(paths["manifest"], "w", encoding="utf-8").write(
            data.replace("egress-wall-pins/2", "egress-wall-pins/3"))
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv.verify()
        self.assertIn("receipt_unverifiable", str(cm.exception))

    def test_receipt_missing_detected(self):
        tmp = _mk_tmp()
        sim, inv, paths = self._install(tmp)
        os.remove(paths["receipt"])
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv.verify()
        self.assertIn("receipt_unverifiable", str(cm.exception))

    def test_symlink_swap_detected(self):
        tmp = _mk_tmp()
        sim, inv, paths = self._install(tmp)
        p = os.path.join(sim, "conf", "allowlist.txt")
        evil = os.path.join(sim, "evil.txt")
        open(evil, "w").write("evil.example:443\n")
        os.remove(p)
        os.symlink(evil, p)
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv.verify()
        self.assertIn("component_tampered", str(cm.exception))

    def test_weaker_digest_mismatch_still_refuses(self):
        # All listed digests must match: a mismatch in the weaker algo
        # is tamper evidence, not a downgrade signal. F138: a hand-edited
        # manifest (even with a re-minted receipt) now dies EARLIER, at
        # the pin-record binding layer — the pin record commits the exact
        # payload the human authorized.
        tmp = _mk_tmp()
        sim = os.path.join(tmp, "wall")
        inv, paths = install_simulated_wall(sim, wall_id="t")
        manifest = json.load(open(paths["manifest"], encoding="utf-8"))
        for e in manifest["components"]:
            e["digests"]["sha256"] = "0" * 64
        blob = json.dumps(manifest, sort_keys=True, indent=2,
                          ensure_ascii=True).encode("utf-8")
        open(paths["manifest"], "wb").write(blob)
        import hashlib
        receipt = {"format": "egress-wall-receipt/1",
                   "manifest_sha256": hashlib.sha256(blob).hexdigest(),
                   "installed_at": manifest["installed_at"]}
        json.dump(receipt, open(paths["receipt"], "w"))
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv.verify()
        self.assertIn("pin_authorship_invalid", str(cm.exception))


class PacketFilterTests(unittest.TestCase):
    def test_allows_pinned_services_drops_rest(self):
        rules = ("ALLOW tcp wall:proxy\n"
                 "ALLOW tcp wall:dns\n"
                 "DROP *\n")
        eps = {"proxy": ["127.0.0.1", 18443],
               "dns": ["127.0.0.1", 15353]}
        f = FakePacketFilter(rules, eps)
        self.assertFalse(f.would_drop("127.0.0.1", 18443))
        self.assertFalse(f.would_drop("127.0.0.1", 15353))
        self.assertTrue(f.would_drop("127.0.0.1", 9999))
        self.assertTrue(f.would_drop("127.0.0.1", 18443, proto="udp"))
        self.assertTrue(f.would_drop("10.9.9.9", 443))

    def test_comments_and_blank_lines_ignored(self):
        f = FakePacketFilter("# nothing\n\n", {})
        self.assertTrue(f.would_drop("127.0.0.1", 80))


class LauncherUnitTests(unittest.TestCase):
    def _up_wall(self):
        tmp = _mk_tmp()
        sim = os.path.join(tmp, "wall")
        install_simulated_wall(sim, wall_id="s7unit")
        fix = SimulatedWallFixture(sim)
        fix.__enter__()
        inv = repin_after_fixture_fixup(sim)
        fix.inventory = inv
        self.addCleanup(fix.__exit__)
        events = []
        launcher = FilteredEgressLauncher(
            manifest_path=os.path.join(sim, "wall_pins.json"),
            receipt_path=os.path.join(sim, "wall_receipt.json"),
            wall_provider=fix.provider(), audit=events.append,
            trust=inv.trust)
        return sim, fix, inv, events, launcher

    def test_launch_emits_audit_event(self):
        sim, fix, inv, events, launcher = self._up_wall()
        cp = launcher.run_child([sys.executable, "-c", "pass"],
                                capture_output=True)
        self.assertEqual(cp.returncode, 0)
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(len(launches), 1)
        self.assertEqual(sorted(launches[0]["components"]),
                         sorted(WALL_COMPONENTS))

    def test_refusal_emits_audit_event(self):
        tmp = _mk_tmp()
        sim = os.path.join(tmp, "wall")
        inv, paths = install_simulated_wall(sim, wall_id="s7ref")
        events = []
        launcher = FilteredEgressLauncher(
            manifest_path=paths["manifest"],
            receipt_path=paths["receipt"],
            wall_provider=SimulatedWallProvider(sim, inv),
            audit=events.append, trust=inv.trust)
        with self.assertRaises(EgressLaunchRefused):
            launcher.run_child([sys.executable, "-c", "pass"],
                               capture_output=True)
        refusals = [e for e in events
                    if e["event"] == "egress_wall_launch_refused"]
        self.assertEqual(len(refusals), 1)
        self.assertIn("wall_not_up", refusals[0]["reason"])

    def test_flapping_wall_aborts_before_exec(self):
        from gov.egress_launcher import FlappingWallProvider, \
            PREEXEC_ABORT_CODE
        sim, fix, inv, events, _ = self._up_wall()
        launcher = FilteredEgressLauncher(
            manifest_path=os.path.join(sim, "wall_pins.json"),
            receipt_path=os.path.join(sim, "wall_receipt.json"),
            wall_provider=FlappingWallProvider(sim, inv),
            audit=events.append, trust=inv.trust)
        sentinel = os.path.join(sim, "sentinel")
        with self.assertRaises(EgressLaunchRefused) as cm:
            launcher.run_child(
                [sys.executable, "-c",
                 "open(%r, 'w').write('x')" % sentinel],
                capture_output=True)
        self.assertIn("preexec_recheck_failed", str(cm.exception))
        self.assertFalse(os.path.exists(sentinel))
        self.assertEqual(PREEXEC_ABORT_CODE, 99)

    def test_popen_kwargs_helper_scrubs_and_marks(self):
        sim, fix, inv, events, launcher = self._up_wall()
        kw = launcher.popen_kwargs(
            env={"http_proxy": "http://evil/", "A": "b"})
        self.assertNotIn("http_proxy", kw["env"])
        self.assertEqual(kw["env"]["EGRESS_WALL_ACTIVE"], "1")
        self.assertEqual(kw["env"]["A"], "b")
        self.assertTrue(callable(kw["preexec_fn"]))

    def test_lock_file_created_next_to_manifest(self):
        sim, fix, inv, events, launcher = self._up_wall()
        launcher.run_child([sys.executable, "-c", "pass"],
                           capture_output=True)
        self.assertTrue(
            os.path.exists(os.path.join(sim, "wall_pins.json.lock")))


class PinAuthorshipTests(unittest.TestCase):
    """F138 unit tests: re-pinning requires a roster-human Ed25519
    authorship token; pins chain through the operator-held ledger."""

    def _roster(self, signers):
        filler = [Ed25519Signer(_gen_seed()) for _ in range(2)]
        return DelegationTrust(
            human_keys={s.key_id: s.public_key for s in signers},
            authority_keys={filler[0].key_id: filler[0].public_key},
            user_issuer_keys={filler[1].key_id: filler[1].public_key})

    def _wall(self, signers, tier="dev", wall_id="f138unit"):
        tmp = _mk_tmp()
        sim = os.path.join(tmp, "wall")
        trust = self._roster(signers)
        inv, paths = install_simulated_wall(
            sim, wall_id=wall_id, trust=trust,
            operator_signers=signers, tier=tier)
        return sim, inv, paths, trust

    def _comp_paths(self, sim):
        conf = os.path.join(sim, "conf")
        return {
            "nft_ruleset": os.path.join(conf, "agent0.nft.sim"),
            "proxy_allowlist": os.path.join(conf, "allowlist.txt"),
            "dns_config": os.path.join(conf, "dns_config.txt"),
            "dns_zone": os.path.join(conf, "dns_hosts.txt"),
            "proxy_impl": os.path.join(conf, "proxy_impl.txt"),
            "seccomp_config": os.path.join(conf, "seccomp_config.txt"),
        }

    def _signed_install(self, sim, paths, trust, signers, tier="dev"):
        prop = WallComponentInventory.proposal(
            self._comp_paths(sim), paths["manifest"], tier=tier,
            ledger_path=paths["ledger"])
        sigs = [s.sign(prop["body"]).hex() for s in signers]
        kids = [s.key_id for s in signers]
        return WallComponentInventory.install(
            self._comp_paths(sim), paths["manifest"], paths["receipt"],
            trust=trust, author_key_id=kids[0],
            authorship_sig_hex=sigs[0], ts=prop["ts"], tier=tier,
            second_author_key_id=kids[1] if len(kids) > 1 else None,
            second_authorship_sig_hex=sigs[1] if len(sigs) > 1 else None,
            ledger_path=paths["ledger"])

    def test_bare_install_refused_no_trust(self):
        s1 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        with self.assertRaises(WallPinRefused) as cm:
            WallComponentInventory.install(
                self._comp_paths(sim), paths["manifest"],
                paths["receipt"])
        self.assertIn("pin_authorship_invalid", str(cm.exception))

    def test_install_refused_without_token(self):
        s1 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        with self.assertRaises(WallPinRefused) as cm:
            WallComponentInventory.install(
                self._comp_paths(sim), paths["manifest"], paths["receipt"],
                trust=trust, ledger_path=paths["ledger"])
        self.assertIn("pin_authorship_invalid", str(cm.exception))

    def test_install_unknown_author_key_refused(self):
        s1 = Ed25519Signer(_gen_seed())
        attacker = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        prop = WallComponentInventory.proposal(
            self._comp_paths(sim), paths["manifest"], tier="dev",
            ledger_path=paths["ledger"])
        with self.assertRaises(WallPinRefused) as cm:
            WallComponentInventory.install(
                self._comp_paths(sim), paths["manifest"], paths["receipt"],
                trust=trust, author_key_id=attacker.key_id,
                authorship_sig_hex=attacker.sign(prop["body"]).hex(),
                ts=prop["ts"], tier="dev", ledger_path=paths["ledger"])
        self.assertIn("unknown author key", str(cm.exception))

    def test_install_bad_signature_refused(self):
        s1 = Ed25519Signer(_gen_seed())
        wrong = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        prop = WallComponentInventory.proposal(
            self._comp_paths(sim), paths["manifest"], tier="dev",
            ledger_path=paths["ledger"])
        with self.assertRaises(WallPinRefused) as cm:
            WallComponentInventory.install(
                self._comp_paths(sim), paths["manifest"], paths["receipt"],
                trust=trust, author_key_id=s1.key_id,
                authorship_sig_hex=wrong.sign(prop["body"]).hex(),
                ts=prop["ts"], tier="dev", ledger_path=paths["ledger"])
        self.assertIn("bad authorship signature", str(cm.exception))

    def test_install_missing_components_still_value_error(self):
        # With VALID authorship, malformed input is still a ValueError
        # (programmer error), not a security refusal.
        s1 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        # Sign a proposal over the real paths, then install with an
        # empty component map: payload building must raise ValueError.
        prop = WallComponentInventory.proposal(
            self._comp_paths(sim), paths["manifest"], tier="dev",
            ledger_path=paths["ledger"])
        with self.assertRaises(ValueError):
            WallComponentInventory.install(
                {}, paths["manifest"], paths["receipt"],
                trust=trust, author_key_id=s1.key_id,
                authorship_sig_hex=s1.sign(prop["body"]).hex(),
                ts=prop["ts"], tier="dev", ledger_path=paths["ledger"])

    def test_dev_single_human_install_verifies(self):
        s1 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        manifest, _ = inv.verify()
        rec = manifest["pin_record"]
        self.assertEqual(rec["tier"], "dev")
        self.assertEqual(rec["author_key_ids"], [s1.key_id])
        self.assertIsNone(rec["prev_pin_record_sha256"])  # genesis

    def test_production_requires_two_distinct_humans(self):
        s1 = Ed25519Signer(_gen_seed())
        s2 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1, s2], tier="dev")
        prop = WallComponentInventory.proposal(
            self._comp_paths(sim), paths["manifest"], tier="production",
            ledger_path=paths["ledger"])
        sig = s1.sign(prop["body"]).hex()
        # single approval
        with self.assertRaises(WallPinRefused) as cm:
            WallComponentInventory.install(
                self._comp_paths(sim), paths["manifest"], paths["receipt"],
                trust=trust, author_key_id=s1.key_id,
                authorship_sig_hex=sig, ts=prop["ts"],
                tier="production", ledger_path=paths["ledger"])
        self.assertIn("two distinct human approvals", str(cm.exception))
        # same key twice
        with self.assertRaises(WallPinRefused) as cm:
            WallComponentInventory.install(
                self._comp_paths(sim), paths["manifest"], paths["receipt"],
                trust=trust, author_key_id=s1.key_id,
                authorship_sig_hex=sig, ts=prop["ts"],
                tier="production", second_author_key_id=s1.key_id,
                second_authorship_sig_hex=sig,
                ledger_path=paths["ledger"])
        self.assertIn("two DISTINCT keys", str(cm.exception))
        # two distinct: accepted
        manifest = WallComponentInventory.install(
            self._comp_paths(sim), paths["manifest"], paths["receipt"],
            trust=trust, author_key_id=s1.key_id,
            authorship_sig_hex=sig, ts=prop["ts"],
            tier="production", second_author_key_id=s2.key_id,
            second_authorship_sig_hex=s2.sign(prop["body"]).hex(),
            ledger_path=paths["ledger"])
        self.assertEqual(
            sorted(manifest["pin_record"]["author_key_ids"]),
            sorted([s1.key_id, s2.key_id]))

    def test_repin_chains_to_previous(self):
        s1 = Ed25519Signer(_gen_seed())
        s2 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1, s2])
        trust2 = self._roster([s1, s2])
        inv2 = repin_after_fixture_fixup(
            sim, trust=trust2, operator_signers=[s2], tier="dev")
        manifest, _ = inv2.verify()
        records = [json.loads(l) for l in
                   open(paths["ledger"], encoding="utf-8")
                   .read().splitlines() if l.strip()]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["prev_pin_record_sha256"],
                         records[0]["record_sha256"])
        self.assertEqual(records[1]["record_sha256"],
                         manifest["pin_record"]["record_sha256"])
        self.assertEqual(records[1]["author_key_ids"], [s2.key_id])

    def test_verify_detects_dropped_ledger_record(self):
        s1 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        inv2 = repin_after_fixture_fixup(
            sim, trust=trust, operator_signers=[s1], tier="dev")
        inv2.verify()  # sane before tamper
        records = [json.loads(l) for l in
                   open(paths["ledger"], encoding="utf-8")
                   .read().splitlines() if l.strip()]
        self.assertEqual(len(records), 2)
        with open(paths["ledger"], "w", encoding="utf-8") as f:
            f.write(json.dumps(records[1], sort_keys=True) + "\n")
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv2.verify()
        self.assertIn("pin_chain_broken", str(cm.exception))

    def test_verify_detects_missing_ledger(self):
        s1 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        os.remove(paths["ledger"])
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv.verify()
        self.assertIn("pin_chain_broken", str(cm.exception))

    def test_verify_detects_payload_edit_after_pinning(self):
        s1 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        manifest = json.load(open(paths["manifest"], encoding="utf-8"))
        manifest["components"][0]["digests"]["sha256"] = "0" * 64
        blob = json.dumps(manifest, sort_keys=True, indent=2,
                          ensure_ascii=True).encode("utf-8")
        open(paths["manifest"], "wb").write(blob)
        import hashlib
        receipt = {"format": "egress-wall-receipt/1",
                   "manifest_sha256": hashlib.sha256(blob).hexdigest(),
                   "installed_at": manifest["installed_at"]}
        json.dump(receipt, open(paths["receipt"], "w", encoding="utf-8"),
                  sort_keys=True, indent=2)
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv.verify()
        self.assertIn("pin_authorship_invalid", str(cm.exception))

    def test_verify_refuses_legacy_manifest(self):
        s1 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        manifest = json.load(open(paths["manifest"], encoding="utf-8"))
        manifest["format"] = "egress-wall-pins/1"
        del manifest["pin_record"]
        blob = json.dumps(manifest, sort_keys=True, indent=2,
                          ensure_ascii=True).encode("utf-8")
        open(paths["manifest"], "wb").write(blob)
        import hashlib
        receipt = {"format": "egress-wall-receipt/1",
                   "manifest_sha256": hashlib.sha256(blob).hexdigest(),
                   "installed_at": manifest["installed_at"]}
        json.dump(receipt, open(paths["receipt"], "w", encoding="utf-8"),
                  sort_keys=True, indent=2)
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv.verify()
        self.assertIn("pin_authorship_invalid", str(cm.exception))
        self.assertIn("legacy manifest", str(cm.exception))

    def test_verify_without_trust_refuses(self):
        s1 = Ed25519Signer(_gen_seed())
        sim, inv, paths, trust = self._wall([s1])
        naked = WallComponentInventory(paths["manifest"], paths["receipt"])
        with self.assertRaises(EgressLaunchRefused) as cm:
            naked.verify()
        self.assertIn("pin_authorship_invalid", str(cm.exception))
        self.assertIn("no trust roster", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
