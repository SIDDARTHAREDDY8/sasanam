"""Break-first probes for the deploy-trust wiring into verify_skill_manifest
(wave-211 lane A).

Red-first contract: on pristine ``33922d1`` the ``trust_registry`` kwarg
does not exist on ``gov.capability_manifests.verify_skill_manifest``,
so P0 reports ``SEAM ABSENT`` (expected) and the process exits RED.
On the fixed tree every probe must HELD, each double-run for
determinism.

Probes:
  P0  seam presence: the kwarg exists and is keyword-only.
  P1  manifest signed by an UNTRUSTED (non-trust-root) signer is
      refused with ``manifest-trust-trust-root-unknown`` when the
      trust registry is wired -- even though the signature verifies
      against the pinned manifest store.
  P2  the same untrusted-signer manifest, verified WITHOUT the
      trust registry, keeps today's behavior: ``(True, "clean")``
      -- legacy path untouched.
  P3  tampered trust config: body byte flipped -> ``activate``
      refuses; the registry stays config-less and the wired
      manifest check fails closed with
      ``manifest-trust-no-trust-config``.
  P4  manifest signed by a trust-root signer admits with
      ``(True, "clean|trust-checked")`` -- the suffix proves the
      trust config was consulted.
  P5  empty trust config (no registry passed) = today's behavior:
      detail is exactly ``"clean"``, byte-identical to pristine.
  P6  registry wired but no pack_class -> fail-closed
      ``manifest-trust-class-missing`` (there is no class to
      authorize against).
  P7  revoked trust root: a kid named in ``revoked_kids`` is
      refused LOUDLY with ``manifest-trust-trust-root-revoked``
      even though its signature verifies.
  P8  unknown class -> ``manifest-trust-trust-class-unknown``
      (default-deny).
  P9  determinism: full verdict equality across two runs.

$0 spend, synthetic/local deterministic only. No network.
"""

import hashlib
import inspect
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

try:
    from gov import capability_manifests as cm
    from gov import deploy_trust_config as dtc
    from gov import ed25519 as _ed
    from gov import rule_pack as rp
    from gov.keyset import new_keyset, keyset_signer_for_version
    HAVE_SEAM = True
except ImportError as exc:  # noqa: BLE001
    HAVE_SEAM = False
    _IMPORT_ERROR = exc

_RESULTS = []

_SEED = hashlib.sha256(b"trust-wiring-battery-test-key").digest()
_SEED_EVIL = hashlib.sha256(b"trust-wiring-battery-attacker-key").digest()
_SEED_ROOT = hashlib.sha256(b"trust-wiring-battery-deploy-root").digest()
_KID = "trust-wiring-key-1"
_KID_EVIL = "trust-wiring-evil-1"
_PUB = _ed.publickey(_SEED) if HAVE_SEAM else None
_PUB_EVIL = _ed.publickey(_SEED_EVIL) if HAVE_SEAM else None

CLASS = "capability_skills"

ISSUED = "2026-09-01T00:00:00+00:00"
EXPIRES = "2030-01-01T00:00:00+00:00"
NOW = "2026-10-01T00:00:00+00:00"

BENIGN_FS = (b"def tool_read(path):\n"
             b"    with open(path) as f:\n"
             b"        return f.read()\n")
CAPS_FS_ONLY = {"tools": ["tool_read"], "egress": [],
                "filesystem": ["/data"], "exec": [],
                "env": [], "secrets": []}


def _record(name, verdict, note=""):
    _RESULTS.append((name, verdict, note))
    print("[%s] %s %s" % (verdict, name, note))


def _trust_env():
    root_keyset, _ = new_keyset(_SEED_ROOT,
                                purpose=dtc.KEYSET_PURPOSE_DEPLOY_TRUST)
    root_signer = keyset_signer_for_version(root_keyset, 1, _SEED_ROOT)
    return root_keyset, root_signer


def _config_body(trusted_kids, revoked_kids=()):
    classes = {
        CLASS: dtc.make_class_config(
            policy="signed-only",
            trust_roots=[dtc.make_trust_root(
                kid, 1, (_ed.publickey(
                    _SEED if kid == _KID else _SEED_EVIL)).hex())
                for kid in trusted_kids],
            threshold=1),
    }
    return dtc.make_config_body(
        config_version=1, issued_at=ISSUED, expires_at=EXPIRES,
        classes=classes,
        revoked_kids=[{"kid": k, "reason": "probe-revoked"} for k in
                      revoked_kids])


def _activate(body, root_keyset, root_signer, now=NOW):
    doc = dtc.mint_trust_config(
        root_keyset, [root_signer], body=body, pack_version=1,
        issued_at=ISSUED, expires_at=EXPIRES, threshold=1)
    body_bytes = dtc.canonical_trust_config_json(body).encode("utf-8")
    registry = dtc.TrustConfigRegistry(root_keyset)
    registry.activate(doc, body_bytes, now=now)
    return registry


def _store_for(manifests, keys=None):
    keys = keys or {_KID: _PUB, _KID_EVIL: _PUB_EVIL}
    return cm.ManifestStore(keys=keys, manifests=manifests)


def _manifest(kid, seed, skill_id="fs1"):
    return cm.make_manifest(skill_id, BENIGN_FS,
                            capabilities=CAPS_FS_ONLY,
                            kid=kid, seed=seed)


def _run(name, fn):
    for attempt in (1, 2):
        try:
            fn()
        except AssertionError as exc:
            _record(name, "BROKEN", "run%d: %s" % (attempt, exc))
            return
        except Exception as exc:  # noqa: BLE001 -- a probe must never
            # error: an unexpected exception is a BREAK.
            _record(name, "ERROR", "run%d: %s: %s"
                    % (attempt, type(exc).__name__, exc))
            return
    _record(name, "HELD", "")


def main():
    if not HAVE_SEAM:
        print("SEAM ABSENT (expected on pristine): %s" % (_IMPORT_ERROR,))
        return 2
    params = inspect.signature(cm.verify_skill_manifest).parameters
    if "trust_registry" not in params:
        print("SEAM ABSENT (expected on pristine): no trust_registry "
              "kwarg on verify_skill_manifest")
        return 2
    if params["trust_registry"].kind not in (
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD):
        _record("P0", "BROKEN", "trust_registry is not a normal kwarg")
    else:
        _record("P0", "HELD", "trust_registry kwarg present")

    def expect_refusal(ok, detail, prefix):
        assert ok is False, "expected refusal, got ok with %r" % (detail,)
        assert detail.startswith(prefix), \
            "expected detail starting %r, got %r" % (prefix, detail)

    # -- P1: untrusted signer refused when wired -------------------------
    def p1():
        root_keyset, root_signer = _trust_env()
        registry = _activate(_config_body([_KID]), root_keyset,
                             root_signer)
        store = _store_for({"fs1": _manifest(_KID_EVIL, _SEED_EVIL)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class=CLASS, trust_now=NOW)
        expect_refusal(ok, detail, "manifest-trust-trust-root-unknown")
    _run("P1", p1)

    # -- P2: same input, unwired -> today's behavior ----------------------
    def p2():
        store = _store_for({"fs1": _manifest(_KID_EVIL, _SEED_EVIL)})
        ok, detail = cm.verify_skill_manifest("fs1", BENIGN_FS, store)
        assert (ok, detail) == (True, "clean"), \
            "legacy path changed: got %r" % ((ok, detail),)
    _run("P2", p2)

    # -- P3: tampered trust config fails closed ----------------------------
    def p3():
        root_keyset, root_signer = _trust_env()
        body = _config_body([_KID])
        body_bytes = bytearray(
            dtc.canonical_trust_config_json(body).encode("utf-8"))
        body_bytes[len(body_bytes) // 2] ^= 0x01
        doc = dtc.mint_trust_config(
            root_keyset, [root_signer], body=body, pack_version=1,
            issued_at=ISSUED, expires_at=EXPIRES, threshold=1)
        registry = dtc.TrustConfigRegistry(root_keyset)
        try:
            registry.activate(doc, bytes(body_bytes), now=NOW)
        except dtc.TrustConfigError:
            pass
        else:
            raise AssertionError("tampered config activated")
        store = _store_for({"fs1": _manifest(_KID, _SEED)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class=CLASS, trust_now=NOW)
        expect_refusal(ok, detail, "manifest-trust-no-trust-config")
    _run("P3", p3)

    # -- P4: trust-root signer admits, suffix proves consultation ----------
    def p4():
        root_keyset, root_signer = _trust_env()
        registry = _activate(_config_body([_KID]), root_keyset,
                             root_signer)
        store = _store_for({"fs1": _manifest(_KID, _SEED)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class=CLASS, trust_now=NOW)
        assert (ok, detail) == (True, "clean|trust-checked"), \
            "expected trust-checked admission, got %r" % ((ok, detail),)
    _run("P4", p4)

    # -- P5: empty trust config = today's behavior ------------------------
    def p5():
        store = _store_for({"fs1": _manifest(_KID, _SEED)})
        ok, detail = cm.verify_skill_manifest("fs1", BENIGN_FS, store)
        assert (ok, detail) == (True, "clean"), \
            "unwired call must be byte-identical to pristine: got %r" \
            % ((ok, detail),)
    _run("P5", p5)

    # -- P6: registry without pack_class -> fail-closed --------------------
    def p6():
        root_keyset, root_signer = _trust_env()
        registry = _activate(_config_body([_KID]), root_keyset,
                             root_signer)
        store = _store_for({"fs1": _manifest(_KID, _SEED)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            trust_now=NOW)
        expect_refusal(ok, detail, "manifest-trust-class-missing")
    _run("P6", p6)

    # -- P7: revoked trust root refused loudly -----------------------------
    def p7():
        root_keyset, root_signer = _trust_env()
        registry = _activate(_config_body([_KID], [_KID_EVIL]),
                             root_keyset, root_signer)
        store = _store_for({"fs1": _manifest(_KID_EVIL, _SEED_EVIL)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class=CLASS, trust_now=NOW)
        expect_refusal(ok, detail, "manifest-trust-trust-root-revoked")
    _run("P7", p7)

    # -- P8: unknown class default-deny ------------------------------------
    def p8():
        root_keyset, root_signer = _trust_env()
        registry = _activate(_config_body([_KID]), root_keyset,
                             root_signer)
        store = _store_for({"fs1": _manifest(_KID, _SEED)})
        ok, detail = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class="no-such-class", trust_now=NOW)
        expect_refusal(ok, detail, "manifest-trust-trust-class-unknown")
    _run("P8", p8)

    # -- P9: determinism across runs ---------------------------------------
    def p9():
        root_keyset, root_signer = _trust_env()
        registry = _activate(_config_body([_KID]), root_keyset,
                             root_signer)
        store = _store_for({"fs1": _manifest(_KID, _SEED)})
        first = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class=CLASS, trust_now=NOW)
        second = cm.verify_skill_manifest(
            "fs1", BENIGN_FS, store, trust_registry=registry,
            pack_class=CLASS, trust_now=NOW)
        assert first == second, "verdict not deterministic"
    _run("P9", p9)

    held = [r for r in _RESULTS if r[1] == "HELD"]
    bad = [r for r in _RESULTS if r[1] != "HELD"]
    print("----")
    print("%d/%d HELD" % (len(held), len(_RESULTS)))

    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK SKIPPED (GOV_SKIP_GREEN=1)")
        return 0 if not bad else 1

    # Depth-1 green check: adjacent manifest battery must stay green.
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for cmd, label in (
            ([sys.executable, "evals/capability_manifest_battery.py"],
             "capability_manifest_battery"),
            ([sys.executable, "-m", "unittest",
              "tests.test_capability_manifests"],
             "test_capability_manifests"),
            ([sys.executable, "-m", "unittest",
              "tests.test_deploy_trust_config"],
             "test_deploy_trust_config")):
        proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env,
                              capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            print("GREEN CHECK FAILED (%s): rc=%d\n%s" %
                  (label, proc.returncode, proc.stdout[-2000:] +
                   proc.stderr[-2000:]))
            return 1
    print("GREEN CHECK PASS (depth-1)")

    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
