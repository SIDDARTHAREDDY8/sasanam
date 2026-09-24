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
    NetnsWallProvider,
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


def _nft_baseline(text):
    """sha256 of the normalized ruleset text (fog decision 1)."""
    from gov.egress_launcher import _digest_bytes, _normalize_nft_ruleset
    return _digest_bytes(
        _normalize_nft_ruleset(text).encode("utf-8"), "sha256")


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

    def test_flapping_wall_emits_no_launch_event(self):
        # F148: the egress_wall_launch audit event is witnessed, not
        # predicted. A child that dies in the preexec re-check (wall
        # flapped between the parent check and fork) must leave a
        # refusal event only -- never a launch event for a child that
        # never exec'd.
        from gov.egress_launcher import FlappingWallProvider
        sim, fix, inv, events, _ = self._up_wall()
        launcher = FilteredEgressLauncher(
            manifest_path=os.path.join(sim, "wall_pins.json"),
            receipt_path=os.path.join(sim, "wall_receipt.json"),
            wall_provider=FlappingWallProvider(sim, inv),
            audit=events.append, trust=inv.trust)
        with self.assertRaises(EgressLaunchRefused) as cm:
            launcher.run_child([sys.executable, "-c", "pass"],
                               capture_output=True)
        self.assertIn("preexec_recheck_failed", str(cm.exception))
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(launches, [])
        refusals = [e for e in events
                    if e["event"] == "egress_wall_launch_refused"]
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["reason"], "preexec_recheck_failed")

    def test_f149_chain_failure_raises_no_launch_event(self):
        # F149: a child that dies in the embedder preexec_chain (after
        # the F148 ack) must not leave a false egress_wall_launch
        # event. launch() refuses (fail-closed, like the pre-ack EOF
        # path) with a truthful preexec_chain_failed reason -- never
        # preexec_recheck_failed (the re-check passed; the chain
        # failed).
        from gov.egress_launcher import PREEXEC_CHAIN_ABORT_CODE
        sim, fix, inv, events, launcher = self._up_wall()

        def _boom():
            raise RuntimeError("simulated chain failure")

        sentinel = os.path.join(sim, "sentinel")
        with self.assertRaises(EgressLaunchRefused) as cm:
            launcher.launch(
                [sys.executable, "-c",
                 "open(%r, 'w').write('x')" % sentinel],
                preexec_chain=(_boom,))
        self.assertIn("preexec_chain_failed", str(cm.exception))
        self.assertNotIn("preexec_recheck_failed", str(cm.exception))
        self.assertFalse(os.path.exists(sentinel))
        self.assertEqual(PREEXEC_CHAIN_ABORT_CODE, 98)
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(launches, [])
        refusals = [e for e in events
                    if e["event"] == "egress_wall_launch_refused"]
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["reason"], "preexec_chain_failed")

    def test_f149_run_child_slow_chain_failure_truthful_reason(self):
        # F149 slow path: Popen.__init__ blocks on its preexec error
        # pipe until the chain completes, so even a slow chain failure
        # is definitive by the time launch() regains control -- no
        # launch event is emitted, only the truthful refusal.
        # run_child() must refuse with preexec_chain_failed, never
        # mislabel it preexec_recheck_failed.
        import time
        sim, fix, inv, events, launcher = self._up_wall()

        def _slow_boom():
            time.sleep(1.0)
            raise RuntimeError("slow simulated chain failure")

        with self.assertRaises(EgressLaunchRefused) as cm:
            launcher.run_child(
                [sys.executable, "-c", "pass"],
                preexec_chain=(_slow_boom,), capture_output=True)
        self.assertIn("preexec_chain_failed", str(cm.exception))
        self.assertNotIn("preexec_recheck_failed", str(cm.exception))
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(len(launches), 0)
        refusals = [e for e in events
                    if e["event"] == "egress_wall_launch_refused"]
        reasons = [r["reason"] for r in refusals]
        self.assertIn("preexec_chain_failed", reasons)

    def test_f149_healthy_chain_still_emits_launch(self):
        # Control: a healthy chain still yields exactly one launch
        # event and the child exec's. (The chain runs in the child
        # post-fork, so it signals via a file, not a parent list.)
        sim, fix, inv, events, launcher = self._up_wall()
        chain_marker = os.path.join(sim, "chain_marker")

        def _ok():
            with open(chain_marker, "w") as f:
                f.write("x")

        cp = launcher.run_child([sys.executable, "-c", "pass"],
                                preexec_chain=(_ok,),
                                capture_output=True)
        self.assertEqual(cp.returncode, 0)
        self.assertTrue(os.path.exists(chain_marker))
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(len(launches), 1)

    def test_f150_chain_direct_exit127_no_launch_event(self):
        # F150: a chain entry that terminates via a DIRECT os._exit(127)
        # (the sandbox's documented fail-closed shape) must not leave a
        # false egress_wall_launch event. The F149 98-conversion only
        # catches raised exceptions; the parent cannot distinguish a
        # chain _exit(127) from an exec'd child that exited 127, so the
        # conversion has to happen child-side in the wrapper.
        sim, fix, inv, events, launcher = self._up_wall()

        def _halt():
            os._exit(127)

        sentinel = os.path.join(sim, "sentinel")
        with self.assertRaises(EgressLaunchRefused) as cm:
            launcher.launch(
                [sys.executable, "-c",
                 "open(%r, 'w').write('x')" % sentinel],
                preexec_chain=(_halt,))
        self.assertIn("preexec_chain_failed", str(cm.exception))
        self.assertNotIn("preexec_recheck_failed", str(cm.exception))
        self.assertFalse(os.path.exists(sentinel))
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(launches, [])
        refusals = [e for e in events
                    if e["event"] == "egress_wall_launch_refused"]
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["reason"], "preexec_chain_failed")

    def test_f150_run_child_direct_exit127_truthful_reason(self):
        # F150 via run_child(): the direct-_exit(127) chain must refuse
        # truthfully (preexec_chain_failed) -- never a bare
        # CompletedProcess(rc=127) as if the child executed, and never
        # mislabeled preexec_recheck_failed.
        sim, fix, inv, events, launcher = self._up_wall()

        def _halt():
            os._exit(127)

        sentinel = os.path.join(sim, "sentinel")
        with self.assertRaises(EgressLaunchRefused) as cm:
            launcher.run_child(
                [sys.executable, "-c",
                 "open(%r, 'w').write('x')" % sentinel],
                preexec_chain=(_halt,), capture_output=True)
        self.assertIn("preexec_chain_failed", str(cm.exception))
        self.assertNotIn("preexec_recheck_failed", str(cm.exception))
        self.assertFalse(os.path.exists(sentinel))
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(launches, [])

    def test_f150_chain_raise_abort_contract_converts_to_98(self):
        # F150 contract: a chain entry aborts by RAISING the dedicated
        # PreexecChainAbort (never by calling os._exit() directly); the
        # wrapper converts it to PREEXEC_CHAIN_ABORT_CODE (98) with a
        # truthful refusal and no launch event.
        from gov.egress_launcher import PreexecChainAbort, \
            PREEXEC_CHAIN_ABORT_CODE
        sim, fix, inv, events, launcher = self._up_wall()

        def _refuse():
            raise PreexecChainAbort(
                127, "simulated fail-closed layer refusal")

        sentinel = os.path.join(sim, "sentinel")
        with self.assertRaises(EgressLaunchRefused) as cm:
            launcher.launch(
                [sys.executable, "-c",
                 "open(%r, 'w').write('x')" % sentinel],
                preexec_chain=(_refuse,))
        self.assertIn("preexec_chain_failed", str(cm.exception))
        self.assertEqual(PREEXEC_CHAIN_ABORT_CODE, 98)
        self.assertFalse(os.path.exists(sentinel))
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(launches, [])
        refusals = [e for e in events
                    if e["event"] == "egress_wall_launch_refused"]
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["reason"], "preexec_chain_failed")

    def test_f150_forked_grandchild_exit_not_intercepted(self):
        # F150 regression guard: the child-side os._exit interception is
        # scoped to the chain-running process. A chain entry that forks
        # (the sandbox pidns intermediate pattern) keeps the real
        # os._exit in the forked descendant, so the grandchild's exit
        # code is preserved and the healthy launch still yields exactly
        # one launch event.
        sim, fix, inv, events, launcher = self._up_wall()

        def _fork_and_exit():
            pid = os.fork()
            if pid == 0:
                os._exit(42)
            _, status = os.waitpid(pid, 0)
            assert os.waitstatus_to_exitcode(status) == 42, status

        cp = launcher.run_child([sys.executable, "-c", "pass"],
                                preexec_chain=(_fork_and_exit,),
                                capture_output=True)
        self.assertEqual(cp.returncode, 0)
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(len(launches), 1)

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
            "seccomp_helper": os.path.join(conf, "run_seccomp.py"),
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

    def test_live_baseline_skew_between_proposal_and_install_refuses(self):
        # Fog decision 1 / authorship binding: the live baseline is
        # part of the signed pin body. Signing one baseline and
        # installing with another must refuse — the baseline cannot
        # be re-based without fresh roster authorship.
        signers = [Ed25519Signer(_gen_seed())]
        sim, inv, paths, trust = self._wall(signers)
        comp_paths = self._comp_paths(sim)
        prop = WallComponentInventory.proposal(
            comp_paths, paths["manifest"], tier="dev",
            ledger_path=paths["ledger"],
            live_digests={"nft_ruleset": "a" * 64})
        sig = signers[0].sign(prop["body"]).hex()
        with self.assertRaises(WallPinRefused) as cm:
            WallComponentInventory.install(
                comp_paths, paths["manifest"], paths["receipt"],
                trust=trust, author_key_id=signers[0].key_id,
                authorship_sig_hex=sig, ts=prop["ts"], tier="dev",
                ledger_path=paths["ledger"],
                live_digests={"nft_ruleset": "b" * 64})
        self.assertIn("pin_authorship_invalid", str(cm.exception))


class SeccompHelperPinTests(unittest.TestCase):
    """F81 launcher wave: the seccomp helper is the 7th pinned wall
    component (spec D7). The sim fixture gains a dummy helper file;
    the real deployment pins the vendored run_seccomp.py bytes."""

    def test_wall_components_includes_seccomp_helper(self):
        self.assertIn("seccomp_helper", WALL_COMPONENTS)
        self.assertEqual(len(WALL_COMPONENTS), 7)

    def test_sim_install_pins_helper_bytes(self):
        sim = os.path.join(_mk_tmp(), "wall")
        inv, paths = install_simulated_wall(sim, wall_id="f81unit")
        manifest, checked = inv.verify()
        names = [e["name"] for e in manifest["components"]]
        self.assertIn("seccomp_helper", names)
        self.assertIn("seccomp_helper", checked)
        helper_path = os.path.join(sim, "conf", "run_seccomp.py")
        with open(helper_path, "rb") as f:
            want = component_digests(f.read())
        entry = [e for e in manifest["components"]
                 if e["name"] == "seccomp_helper"][0]
        self.assertEqual(entry["digests"], want)

    def test_helper_tamper_refuses_verify(self):
        sim = os.path.join(_mk_tmp(), "wall")
        inv, paths = install_simulated_wall(sim, wall_id="f81unit")
        inv.verify()  # sane before tamper
        helper_path = os.path.join(sim, "conf", "run_seccomp.py")
        with open(helper_path, "r+b") as f:
            data = bytearray(f.read())
            data[0] ^= 0x01
            f.seek(0)
            f.write(data)
        with self.assertRaises(EgressLaunchRefused) as cm:
            inv.verify()
        self.assertIn("component_tampered", str(cm.exception))
        self.assertIn("seccomp_helper", str(cm.exception))

    def test_vendored_helper_is_never_imported_artifact(self):
        # The vendored helper is data, not code: it must exist as a
        # file carrying the lab's filter semantics (known-good
        # literals), and nothing in gov may import it.
        helper = os.path.join(REPO_ROOT, "gov", "data", "run_seccomp.py")
        with open(helper, encoding="utf-8") as f:
            src = f.read()
        for literal in ("AF_PACKET", "CLONE_NEWNET", "setns",
                        "os.execvp", "python3-seccomp"):
            self.assertIn(literal, src)


class WrapArgvSeamTests(unittest.TestCase):
    """F81 launcher wave, spec D2: the namespace-entry seam.

    wrap_argv(argv) -> argv is the provider seam that places the
    child in the wall. The default is identity (the sim keeps
    working; zero behavior change for existing callers)."""

    def test_base_provider_wrap_argv_is_identity(self):
        from gov.egress_launcher import WallStateProvider
        argv = ["/bin/true", "--flag", "value"]
        self.assertEqual(WallStateProvider().wrap_argv(argv), argv)

    def test_sim_provider_wrap_argv_is_identity(self):
        sim = os.path.join(_mk_tmp(), "wall")
        inv, paths = install_simulated_wall(sim, wall_id="f81unit")
        provider = SimulatedWallProvider(sim, inv)
        argv = ["/usr/bin/agent", "--run-id", "abc"]
        self.assertEqual(provider.wrap_argv(argv), argv)


class NetnsWallProviderTests(unittest.TestCase):
    """F81 launcher wave, spec D2/D5: the production provider.

    The unit seam is a fake `ip` executable: the tests control the
    namespace topology without privileges. (Real netns/nftables is
    the privileged battery's job — evals/f81launcher_privileged.py.)"""

    def _wall(self, wall_id="f81unit", live_digests=None):
        sim = os.path.join(_mk_tmp(), "wall")
        inv, paths = install_simulated_wall(sim, wall_id=wall_id,
                                            live_digests=live_digests)
        return sim, inv, paths

    def _provider(self, inv, **kw):
        kw.setdefault("ip_path", "/fake/ip")
        kw.setdefault("helper_path", "/wall/run_seccomp.py")
        return NetnsWallProvider(inv, **kw)

    def test_wrap_argv_prefix_shape(self):
        # Spec D2 (name locked): ["ip", "netns", "exec", "agent0",
        # <helper_path>, *argv] — netns entry, then the seccomp
        # helper, then the agent argv (D3 order).
        _, inv, _ = self._wall()
        provider = self._provider(inv)
        self.assertEqual(
            provider.wrap_argv(["/usr/bin/agent", "--run-id", "abc"]),
            ["/fake/ip", "netns", "exec", "agent0",
             "/wall/run_seccomp.py",
             "/usr/bin/agent", "--run-id", "abc"])

    def test_wrap_argv_honors_netns_name(self):
        _, inv, _ = self._wall()
        provider = self._provider(inv, netns_name="f81test0")
        self.assertEqual(provider.wrap_argv(["/bin/true"])[3], "f81test0")

    def test_describe_names_provider_and_pins_ip_path(self):
        _, inv, _ = self._wall()
        provider = self._provider(inv)
        desc = provider.describe()
        self.assertEqual(desc["provider"], "NetnsWallProvider")
        self.assertEqual(desc["netns"], "agent0")
        self.assertEqual(desc["ip"], "/fake/ip")
        self.assertEqual(desc["helper"], "/wall/run_seccomp.py")

    def test_child_env_extra_carries_in_ns_endpoints(self):
        # Story 13: the child sees the in-namespace proxy endpoint.
        _, inv, _ = self._wall()
        provider = self._provider(inv)
        extra = provider.child_env_extra()
        self.assertEqual(extra["EGRESS_PROXY_ADDR"], "10.200.0.1:8080")
        self.assertEqual(extra["EGRESS_DNS_ADDR"], "10.200.0.1:53")

    # -- fake `ip` shim ------------------------------------------------
    # The unit seam for the provider: a fake `ip` executable whose
    # `netns list` and in-ns `nft list ruleset` answers are scripted
    # via the environment. Real netns/nftables is the privileged
    # battery's job (evals/f81launcher_privileged.py).

    FAKE_IP_SCRIPT = (
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['netns', 'list']:\n"
        "    for name in os.environ.get('FAKE_IP_NETNS', '').split():\n"
        "        print('%s (id: 3)' % name)\n"
        "elif args[:2] == ['netns', 'exec']:\n"
        "    rest = args[3:]\n"
        "    if rest == ['nft', 'list', 'ruleset']:\n"
        "        p = os.environ.get('FAKE_IP_RULESET_FILE', '')\n"
        "        sys.stdout.write(open(p, encoding='utf-8').read()\n"
        "                         if p else '')\n"
        "    else:\n"
        "        sys.exit(1)\n"
        "else:\n"
        "    sys.exit(1)\n"
    )

    def _fake_ip(self, netns_names=(), ruleset_text=""):
        d = _mk_tmp()
        ip = os.path.join(d, "ip")
        with open(ip, "w", encoding="utf-8") as f:
            f.write(self.FAKE_IP_SCRIPT)
        os.chmod(ip, 0o755)
        ruleset_file = os.path.join(d, "ruleset.txt")
        with open(ruleset_file, "w", encoding="utf-8") as f:
            f.write(ruleset_text)
        env = {"FAKE_IP_NETNS": " ".join(netns_names),
               "FAKE_IP_RULESET_FILE": ruleset_file,
               "PATH": d + os.pathsep + "/usr/bin:/bin"}
        return ip, env

    def _empty_netns_dir(self):
        return _mk_tmp()

    def test_ip_path_resolved_once_at_construction(self):
        # Fog decision 3: construction-time resolution, pinned and
        # observable via describe(); a later PATH change cannot swap
        # the binary mid-deployment.
        _, inv, _ = self._wall()
        ip, env = self._fake_ip()
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = env["PATH"]
        try:
            provider = NetnsWallProvider(inv, helper_path="/w/h.py")
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(provider.ip_path, ip)
        self.assertEqual(provider.describe()["ip"], ip)

    def test_missing_ip_binary_refuses_at_construction(self):
        _, inv, _ = self._wall()
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = "/nonexistent-path-dir"
        try:
            with self.assertRaises(EgressLaunchRefused) as cm:
                NetnsWallProvider(inv, helper_path="/w/h.py")
        finally:
            os.environ["PATH"] = old_path
        self.assertIn("ip_not_found", str(cm.exception))

    def _check_with(self, provider, env):
        import unittest.mock as _mock
        with _mock.patch.dict(os.environ, env, clear=False):
            return provider.check()

    def test_check_wall_down_when_netns_absent(self):
        # Spec D4/D5-step-1, close-when 1: no netns -> WALL_DOWN,
        # and launch() must refuse with wall_not_up (slice 9).
        from gov.egress_launcher import WALL_DOWN
        _, inv, _ = self._wall()
        ip, env = self._fake_ip(netns_names=())
        provider = NetnsWallProvider(
            inv, ip_path=ip, helper_path="/w/h.py",
            netns_dir=self._empty_netns_dir())
        report = self._check_with(provider, env)
        self.assertEqual(report.state, WALL_DOWN)
        self.assertEqual(report.detail.get("reason"),
                         "netns_missing_or_unprivileged")

    def test_check_wall_down_when_ip_fails(self):
        # `ip` failing (unprivileged) is indistinguishable from a
        # missing netns: fail closed the same way (D4).
        from gov.egress_launcher import WALL_DOWN
        _, inv, _ = self._wall()
        d = _mk_tmp()
        dead = os.path.join(d, "ip")
        with open(dead, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(dead, 0o755)
        provider = NetnsWallProvider(
            inv, ip_path=dead, helper_path="/w/h.py",
            netns_dir=self._empty_netns_dir())
        report = provider.check()
        self.assertEqual(report.state, WALL_DOWN)
        self.assertEqual(report.detail.get("reason"),
                         "netns_missing_or_unprivileged")

    def test_check_degraded_when_helper_tampered(self):
        # Spec D5-step-2: the helper the provider will EXEC must match
        # the pinned digests. Here the deployed component is intact
        # but the staged helper_path copy is tampered -> DEGRADED
        # naming seccomp_helper.
        import shutil
        from gov.egress_launcher import WALL_DEGRADED
        _, inv, paths = self._wall()
        installed = os.path.join(paths["conf_dir"], "run_seccomp.py")
        staged = os.path.join(_mk_tmp(), "run_seccomp.py")
        shutil.copyfile(installed, staged)
        with open(staged, "ab") as f:
            f.write(b"X")
        ip, env = self._fake_ip(netns_names=("agent0",))
        provider = NetnsWallProvider(inv, ip_path=ip,
                                     helper_path=staged)
        report = self._check_with(provider, env)
        self.assertEqual(report.state, WALL_DEGRADED)
        self.assertEqual(report.detail.get("reason"), "component_tampered")
        self.assertEqual(report.detail.get("component"), "seccomp_helper")

    def test_check_wall_down_when_installed_helper_tampered_in_place(self):
        # Tampering the deployed component itself trips the pin chain:
        # verify() fails -> WALL_DOWN, with pin_verify naming the
        # component (fail-closed before the helper check is reached).
        from gov.egress_launcher import WALL_DOWN
        _, inv, paths = self._wall()
        installed = os.path.join(paths["conf_dir"], "run_seccomp.py")
        with open(installed, "ab") as f:
            f.write(b"X")
        ip, env = self._fake_ip(netns_names=("agent0",))
        provider = NetnsWallProvider(inv, ip_path=ip,
                                     helper_path=installed)
        report = self._check_with(provider, env)
        self.assertEqual(report.state, WALL_DOWN)
        self.assertIn("seccomp_helper",
                      report.detail.get("pin_verify", ""))

    def test_check_degraded_when_helper_unreadable(self):
        from gov.egress_launcher import WALL_DEGRADED
        _, inv, _ = self._wall()
        ip, env = self._fake_ip(netns_names=("agent0",))
        provider = NetnsWallProvider(inv, ip_path=ip,
                                     helper_path="/no/such/helper.py")
        report = self._check_with(provider, env)
        self.assertEqual(report.state, WALL_DEGRADED)
        self.assertEqual(report.detail.get("reason"), "component_tampered")
        self.assertEqual(report.detail.get("component"), "seccomp_helper")

    def test_check_degraded_when_manifest_lacks_helper(self):
        # Spec D7: a v2 (pre-productization, 6-component) manifest is
        # refused by the real provider — never a silent partial wall.
        from gov.egress_launcher import WALL_DEGRADED

        class NoHelperInventory:
            def verify(self):
                return ({"components": [
                    {"name": "nft_ruleset",
                     "digests": {"sha256": "abc"}}]}, {})

        ip, env = self._fake_ip(netns_names=("agent0",))
        provider = NetnsWallProvider(NoHelperInventory(), ip_path=ip,
                                     helper_path="/w/h.py")
        report = self._check_with(provider, env)
        self.assertEqual(report.state, WALL_DEGRADED)
        self.assertEqual(report.detail.get("reason"), "helper_not_pinned")

    def test_check_degraded_when_helper_not_configured(self):
        from gov.egress_launcher import WALL_DEGRADED
        _, inv, _ = self._wall()
        ip, env = self._fake_ip(netns_names=("agent0",))
        provider = NetnsWallProvider(inv, ip_path=ip, helper_path=None)
        report = self._check_with(provider, env)
        self.assertEqual(report.state, WALL_DEGRADED)
        self.assertEqual(report.detail.get("reason"),
                         "helper_not_configured")

    # -- nft drift (fog decision 1) ----------------------------------
    RULESET_DESIRED = (
        "table inet agent0 {\n"
        "    chain egress {\n"
        "        type filter hook output priority 0; policy drop;\n"
        "        ip daddr 10.200.0.1 tcp dport 8080 accept\n"
        "        ip daddr 10.200.0.1 udp dport 53 accept\n"
        "    }\n"
        "}\n"
    )
    RULESET_CHURNED = (
        "# generated 2026-09-24; do not hand-edit\n"
        "table inet agent0 { # the wall\n"
        "    chain egress {  \n"
        "        type filter hook output priority 0; policy drop; handle 12\n"
        "        ip daddr 10.200.0.1 tcp dport 8080 accept handle 13\n"
        "        ip daddr 10.200.0.1 udp dport 53 accept\n"
        "    }\n"
        "}\n"
    )

    def _baseline(self, text):
        return _nft_baseline(text)

    def _netns_provider(self, inv, paths, ip, **kw):
        kw.setdefault("helper_path",
                      os.path.join(paths["conf_dir"], "run_seccomp.py"))
        return NetnsWallProvider(inv, ip_path=ip, **kw)

    def test_normalize_nft_ruleset_bridges_formatting_churn(self):
        # Fog decision 1: comments, handle tokens, and whitespace
        # churn must not read as drift.
        from gov.egress_launcher import _normalize_nft_ruleset
        self.assertEqual(_normalize_nft_ruleset(self.RULESET_DESIRED),
                         _normalize_nft_ruleset(self.RULESET_CHURNED))

    def test_normalize_nft_ruleset_preserves_semantic_change(self):
        from gov.egress_launcher import _normalize_nft_ruleset
        changed = self.RULESET_DESIRED.replace("tcp dport 8080",
                                               "tcp dport 9090")
        self.assertNotEqual(_normalize_nft_ruleset(self.RULESET_DESIRED),
                            _normalize_nft_ruleset(changed))

    def test_install_with_live_digests_pins_baseline_on_manifest(self):
        sim, inv, paths = self._wall(
            live_digests={"nft_ruleset":
                          self._baseline(self.RULESET_DESIRED)})
        manifest, _ = inv.verify()  # the signed pin covers the baseline
        entry = next(e for e in manifest["components"]
                     if e["name"] == "nft_ruleset")
        self.assertEqual(entry["live_sha256"],
                         self._baseline(self.RULESET_DESIRED))

    def test_check_degraded_when_ruleset_drifts(self):
        # Fog decision 1 / spec D5-step-3: a SEMANTIC ruleset change
        # (port 8080 -> 9090) fails the normalized digest comparison.
        from gov.egress_launcher import WALL_DEGRADED
        _, inv, paths = self._wall(
            live_digests={"nft_ruleset":
                          self._baseline(self.RULESET_DESIRED)})
        drifted = self.RULESET_DESIRED.replace("tcp dport 8080",
                                               "tcp dport 9090")
        ip, env = self._fake_ip(netns_names=("agent0",),
                                ruleset_text=drifted)
        provider = self._netns_provider(inv, paths, ip)
        report = self._check_with(provider, env)
        self.assertEqual(report.state, WALL_DEGRADED)
        self.assertEqual(report.detail.get("reason"), "ruleset_drift")

    def test_check_degraded_when_ruleset_unreadable(self):
        from gov.egress_launcher import WALL_DEGRADED
        _, inv, paths = self._wall(
            live_digests={"nft_ruleset":
                          self._baseline(self.RULESET_DESIRED)})
        ip, env = self._fake_ip(netns_names=("agent0",),
                                ruleset_text=self.RULESET_DESIRED)
        env["FAKE_IP_RULESET_FILE"] = os.path.join(_mk_tmp(), "nope.txt")
        provider = self._netns_provider(inv, paths, ip)
        report = self._check_with(provider, env)
        self.assertEqual(report.state, WALL_DEGRADED)
        self.assertEqual(report.detail.get("reason"), "ruleset_unreadable")

    def test_check_degraded_when_baseline_missing(self):
        # A wall installed before baselines existed cannot validate
        # the live ruleset: DEGRADED, never a silent pass.
        from gov.egress_launcher import WALL_DEGRADED
        _, inv, paths = self._wall()  # no live_digests
        ip, env = self._fake_ip(netns_names=("agent0",),
                                ruleset_text=self.RULESET_DESIRED)
        provider = self._netns_provider(inv, paths, ip)
        report = self._check_with(provider, env)
        self.assertEqual(report.state, WALL_DEGRADED)
        self.assertEqual(report.detail.get("reason"),
                         "ruleset_baseline_missing")

    # -- listener liveness (spec D5-step-4) --------------------------
    def _closed_port(self):
        import socket as _socket
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def _wall_ready_for_listeners(self):
        """A wall whose netns/pin/helper/ruleset steps all pass, so
        check() reaches the listener probes."""
        _, inv, paths = self._wall(
            live_digests={"nft_ruleset":
                          self._baseline(self.RULESET_DESIRED)})
        ip, env = self._fake_ip(netns_names=("agent0",),
                                ruleset_text=self.RULESET_DESIRED)
        return inv, paths, ip, env

    def test_check_degraded_when_proxy_unreachable(self):
        from gov.egress_launcher import WALL_DEGRADED
        import socket as _socket
        from gov.egress_launcher import StubDnsServer
        inv, paths, ip, env = self._wall_ready_for_listeners()
        dns = StubDnsServer(
            os.path.join(paths["conf_dir"], "dns_hosts.txt"))
        dns.start()
        try:
            provider = self._netns_provider(
                inv, paths, ip,
                proxy_addr=("127.0.0.1", self._closed_port()),
                dns_addr=("127.0.0.1", dns.port))
            report = self._check_with(provider, env)
        finally:
            dns.stop()
        self.assertEqual(report.state, WALL_DEGRADED)
        self.assertTrue(any("proxy unreachable" in m
                            for m in report.detail.get("missing", [])),
                        report.detail)

    def test_check_degraded_when_dns_probe_fails(self):
        from gov.egress_launcher import WALL_DEGRADED
        import socket as _socket
        inv, paths, ip, env = self._wall_ready_for_listeners()
        proxy_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        proxy_sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        proxy_sock.bind(("127.0.0.1", 0))
        proxy_sock.listen(5)
        try:
            provider = self._netns_provider(
                inv, paths, ip,
                proxy_addr=("127.0.0.1",
                            proxy_sock.getsockname()[1]),
                dns_addr=("127.0.0.1", self._closed_port()))
            report = self._check_with(provider, env)
        finally:
            proxy_sock.close()
        self.assertEqual(report.state, WALL_DEGRADED)
        self.assertTrue(any("dns probe failed" in m
                            for m in report.detail.get("missing", [])),
                        report.detail)

    def test_check_up_with_ruleset_formatting_churn(self):
        # Full UP path: formatting churn in the live ruleset still
        # matches the baseline, and the listeners answer on loopback.
        # (The stub DNS server + a bare listening socket are used
        # directly — SimulatedWallFixture rewrites conf files, which
        # would trip the pin chain before the provider is reached.)
        import socket as _socket
        from gov.egress_launcher import (
            WALL_UP, StubDnsServer)
        sim, inv, paths = self._wall(
            live_digests={"nft_ruleset":
                          self._baseline(self.RULESET_DESIRED)})
        ip, env = self._fake_ip(netns_names=("agent0",),
                                ruleset_text=self.RULESET_CHURNED)
        dns = StubDnsServer(
            os.path.join(paths["conf_dir"], "dns_hosts.txt"))
        dns.start()
        proxy_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        proxy_sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        proxy_sock.bind(("127.0.0.1", 0))
        proxy_sock.listen(5)
        try:
            provider = self._netns_provider(
                inv, paths, ip,
                proxy_addr=("127.0.0.1",
                            proxy_sock.getsockname()[1]),
                dns_addr=("127.0.0.1", dns.port))
            report = self._check_with(provider, env)
        finally:
            dns.stop()
            proxy_sock.close()
        self.assertEqual(report.state, WALL_UP)
        self.assertEqual(report.detail.get("netns"), "agent0")
        self.assertIn("proxy", report.detail)
        self.assertIn("dns", report.detail)


class NetnsLauncherLaunchTests(unittest.TestCase):
    """launch() with the production provider (spec D2/D3/D8).

    A spawn-logging fake `ip` observes the exact exec'd argv without
    privilege: `netns list` / in-ns `nft list ruleset` are answered
    for check(); the agent spawn itself is logged and exits 0."""

    RULESET = NetnsWallProviderTests.RULESET_DESIRED

    SPAWN_IP_TEMPLATE = (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "NETNS = %(netns)r\n"
        "RULESET = %(ruleset)r\n"
        "SPAWN_LOG = %(log)r\n"
        "args = sys.argv[1:]\n"
        "if args[:2] == ['netns', 'exec'] and args[3:5] != ['nft', 'list']:\n"
        "    open(SPAWN_LOG, 'a').write(' '.join(args) + chr(10))\n"
        "    sys.exit(0)\n"
        "if args[:2] == ['netns', 'list']:\n"
        "    for _n in NETNS.split():\n"
        "        print('%%s (id: 3)' %% _n)\n"
        "elif args[:2] == ['netns', 'exec']:\n"
        "    sys.stdout.write(RULESET)\n"
        "else:\n"
        "    sys.exit(1)\n"
    )

    def _ready(self, netns_names=("agent0",), live_ruleset_text=None):
        """All-D5-green wall + provider + launcher. Returns
        (launcher, events, ctx) where ctx carries the spawn log path
        and helper path.

        The pinned baseline is always RULESET; live_ruleset_text
        overrides what the fake `ip` reports (drift simulation).
        The fake `ip` has its answers baked in as literals: the
        child's preexec re-check runs under the wall's scrubbed env,
        so nothing may depend on ambient environment variables."""
        import socket as _socket
        from gov.egress_launcher import (
            FilteredEgressLauncher, NetnsWallProvider, StubDnsServer)
        tmp = _mk_tmp()
        sim = os.path.join(tmp, "wall")
        live_text = (self.RULESET if live_ruleset_text is None
                     else live_ruleset_text)
        inv, paths = install_simulated_wall(
            sim, wall_id="f81launch",
            live_digests={"nft_ruleset": _nft_baseline(self.RULESET)})
        ipd = _mk_tmp()
        ip = os.path.join(ipd, "ip")
        spawn_log = os.path.join(ipd, "spawn.log")
        with open(ip, "w", encoding="utf-8") as f:
            f.write(self.SPAWN_IP_TEMPLATE % {
                "netns": " ".join(netns_names),
                "ruleset": live_text,
                "log": spawn_log})
        os.chmod(ip, 0o755)
        helper = os.path.join(paths["conf_dir"], "run_seccomp.py")
        dns = StubDnsServer(
            os.path.join(paths["conf_dir"], "dns_hosts.txt"))
        dns.start()
        proxy_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        proxy_sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        proxy_sock.bind(("127.0.0.1", 0))
        proxy_sock.listen(5)
        provider = NetnsWallProvider(
            inv, ip_path=ip, helper_path=helper,
            proxy_addr=("127.0.0.1", proxy_sock.getsockname()[1]),
            dns_addr=("127.0.0.1", dns.port))
        events = []
        launcher = FilteredEgressLauncher(
            manifest_path=paths["manifest"],
            receipt_path=paths["receipt"],
            wall_provider=provider, audit=events.append,
            trust=inv.trust)

        def _teardown():
            dns.stop()
            proxy_sock.close()

        self.addCleanup(_teardown)
        return launcher, events, {
            "spawn_log": spawn_log, "helper": helper}

    def test_launch_spawns_prefixed_argv(self):
        # Spec D2/D3: the spawned argv is [ip, netns, exec, agent0,
        # <helper>, *agent_argv] — observed end to end via the
        # spawn-logging fake `ip`.
        launcher, events, ctx = self._ready()
        proc = launcher.launch(["/usr/bin/agent", "--run-id", "9"])
        self.assertEqual(proc.wait(timeout=30), 0)
        with open(ctx["spawn_log"], encoding="utf-8") as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        parts = lines[0].split(" ")
        self.assertEqual(parts[0:3], ["netns", "exec", "agent0"])
        self.assertEqual(parts[3], ctx["helper"])
        self.assertEqual(parts[4:], ["/usr/bin/agent", "--run-id", "9"])

    def test_launch_audit_binds_wall_proof_and_identity(self):
        # Spec D8: the launch event carries the manifest / receipt /
        # pin-tip, the provider description, and the agent/principal/
        # run identity (nulls stay visible, not omitted).
        launcher, events, ctx = self._ready()
        proc = launcher.launch(
            ["/usr/bin/agent"], agent_id="agent-1",
            principal="op@example", run_id="run-9")
        self.assertEqual(proc.wait(timeout=30), 0)
        launches = [e for e in events
                    if e["event"] == "egress_wall_launch"]
        self.assertEqual(len(launches), 1)
        ev = launches[0]
        self.assertEqual(ev["wall_id"], "f81launch")
        self.assertEqual(ev["agent_id"], "agent-1")
        self.assertEqual(ev["principal"], "op@example")
        self.assertEqual(ev["run_id"], "run-9")
        self.assertEqual(ev["provider"]["provider"], "NetnsWallProvider")
        self.assertEqual(ev["provider"]["netns"], "agent0")
        self.assertEqual(ev["spawn_argv0"], "ip")
        self.assertEqual(ev["argv0"], "agent")
        for key in ("manifest_sha256", "receipt_sha256", "pin_record_sha256"):
            self.assertIn(key, ev)
            self.assertEqual(len(ev[key]), 64)

    def test_launch_audit_null_identity_stays_visible(self):
        launcher, events, ctx = self._ready()
        proc = launcher.launch(["/usr/bin/agent"])
        self.assertEqual(proc.wait(timeout=30), 0)
        ev = [e for e in events
              if e["event"] == "egress_wall_launch"][0]
        self.assertIn("agent_id", ev)
        self.assertIsNone(ev["agent_id"])
        self.assertIsNone(ev["principal"])
        self.assertIsNone(ev["run_id"])

    def test_launch_refuses_when_wall_down_and_spawns_nothing(self):
        # Spec close-when 1: no netns -> wall_not_up refusal; the
        # spawn log proves nothing was exec'd.
        from gov.egress_launcher import EgressLaunchRefused
        launcher, events, ctx = self._ready(netns_names=())
        with self.assertRaises(EgressLaunchRefused):
            launcher.launch(["/usr/bin/agent"])
        self.assertFalse(os.path.exists(ctx["spawn_log"]))
        refusals = [e for e in events
                    if e["event"] == "egress_wall_launch_refused"]
        self.assertEqual(len(refusals), 1)
        self.assertIn("wall_not_up", refusals[0]["reason"])

    def test_launch_refuses_when_ruleset_drifts(self):
        # Spec close-when 2: drifted ruleset -> wall_degraded refusal.
        from gov.egress_launcher import EgressLaunchRefused
        drifted = self.RULESET.replace("tcp dport 8080", "tcp dport 9090")
        launcher, events, ctx = self._ready(live_ruleset_text=drifted)
        with self.assertRaises(EgressLaunchRefused):
            launcher.launch(["/usr/bin/agent"])
        self.assertFalse(os.path.exists(ctx["spawn_log"]))
        refusals = [e for e in events
                    if e["event"] == "egress_wall_launch_refused"]
        self.assertEqual(len(refusals), 1)
        self.assertIn("wall_degraded", refusals[0]["reason"])
