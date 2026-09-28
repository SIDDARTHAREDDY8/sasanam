"""capability_manifest_battery.py — break-first battery for signed capability
manifests (smithmark shape, R6 stream-2).

RED-first: on the unmodified tree ``gov.capability_manifests`` does not
exist, so this battery FAILS (exit 1, RED) there. On the built tree it
runs 12 probes + a depth-1 green check.

Probes:
  p_valid_manifest_loads        valid signed manifest -> use allowed
  p_digest_mismatch_refused     manifest bound to other bytes -> refuse
  p_egress_drift_refused        undeclared socket use -> refuse
  p_tool_drift_refused          undeclared tool_ def -> refuse
  p_secret_drift_refused        undeclared getpass use -> refuse
  p_signature_forgery_refused   wrong-key / unknown-kid -> refuse
  p_replay_refused              manifest for skill A presented for B
  p_tampered_manifest_fails_closed  edited post-signing -> refuse
  p_jku_never_fetched           protected header naming jku -> refuse
  p_missing_manifest_advisory   no manifest -> advisory, use allowed
  p_no_store_keeps_behavior     no store -> today's behavior
  p_determinism_x2              identical verdicts across runs
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

try:
    from gov import capability_manifests as cm
    from gov import ed25519 as _ed
    from gov import skill_watch
    HAVE_SEAM = True
except ImportError as exc:
    HAVE_SEAM = False
    _IMPORT_ERROR = exc

_RESULTS = []


def _record(name, verdict, note=""):
    _RESULTS.append((name, verdict, note))
    print("[%s] %s %s" % (verdict, name, note))


# Test-only key material (never production). Deterministic so the
# battery is reproducible run to run.
_SEED = hashlib.sha256(b"capability-manifest-battery-test-key").digest()
_SEED2 = hashlib.sha256(b"capability-manifest-battery-attacker-key").digest()
_KID = "test-key-1"
_PUB = _ed.publickey(_SEED) if HAVE_SEAM else None

ORIGIN = {"registry_url": "https://registry.synthetic.local/s/x",
          "installer_identity": "battery",
          "installed_at": "2026-09-28T00:00:00Z"}

BENIGN_FS = (b"def tool_read(path):\n"
             b"    with open(path) as f:\n"
             b"        return f.read()\n")
NET_DRIFT = (BENIGN_FS +
             b"def lookup(host):\n"
             b"    import socket\n"
             b"    s = socket.create_connection((host, 443))\n"
             b"    return s.recv(1024)\n")
SECRET_DRIFT = (BENIGN_FS +
                b"def login():\n"
                b"    import getpass\n"
                b"    return getpass.getpass('pw: ')\n")
TOOL_DRIFT = (BENIGN_FS +
              b"def tool_write_file(path, data):\n"
              b"    pass\n")

CAPS_FS_ONLY = {"tools": ["tool_read"], "egress": [], "filesystem": ["/data"],
                "exec": [], "env": [], "secrets": []}


class _BytesSource(skill_watch.ContentSource if HAVE_SEAM else object):
    def __init__(self, data):
        self._data = data

    def read_bytes(self):
        return self._data

    def stat_hint(self):
        return None


def _store_for(manifests):
    return cm.ManifestStore(keys={_KID: _PUB}, manifests=manifests)


def _watch_with(store):
    return skill_watch.SkillWatch(manifest_store=store)


def p_valid_manifest_loads():
    name = "p_valid_manifest_loads"
    man = cm.make_manifest("fs1", BENIGN_FS, capabilities=CAPS_FS_ONLY,
                           kid=_KID, seed=_SEED)
    store = _store_for({"fs1": man})
    ok, detail = cm.verify_skill_manifest("fs1", BENIGN_FS, store)
    if not (ok and detail == "clean"):
        _record(name, "FAIL", "module check: %r %r" % (ok, detail))
        return
    w = _watch_with(store)
    w.register_skill("fs1", _BytesSource(BENIGN_FS), origin=ORIGIN)
    ok, verified, detail = w.fetch_verified_at_use("fs1")
    if ok and verified == BENIGN_FS and detail == "clean":
        _record(name, "PASS", "signed manifest, bound digest, "
                "declared surface -> use allowed")
    else:
        _record(name, "FAIL", "watcher: %r %r" % (ok, detail))


def p_digest_mismatch_refused():
    name = "p_digest_mismatch_refused"
    man = cm.make_manifest("fs1", BENIGN_FS, capabilities=CAPS_FS_ONLY,
                           kid=_KID, seed=_SEED)
    store = _store_for({"fs1": man})
    ok, detail = cm.verify_skill_manifest("fs1", NET_DRIFT, store)
    if not ok and detail == "manifest-digest-mismatch":
        _record(name, "PASS", "stale attestation replayed against new "
                "bytes -> refused")
    else:
        _record(name, "FAIL", "got %r %r" % (ok, detail))


def p_egress_drift_refused():
    name = "p_egress_drift_refused"
    man = cm.make_manifest("net1", NET_DRIFT, capabilities=CAPS_FS_ONLY,
                           kid=_KID, seed=_SEED)
    store = _store_for({"net1": man})
    ok, detail = cm.verify_skill_manifest("net1", NET_DRIFT, store)
    if not ok and detail.startswith("capability-drift:egress"):
        w = _watch_with(store)
        w.register_skill("net1", _BytesSource(NET_DRIFT), origin=ORIGIN)
        wok, _, wdetail = w.fetch_verified_at_use("net1")
        if not wok and wdetail.startswith("capability-drift:egress"):
            _record(name, "PASS",
                    "undeclared socket use refused at use time")
            return
        _record(name, "FAIL", "module refused but watcher let it "
                "through: %r" % (wdetail,))
    else:
        _record(name, "FAIL", "got %r %r" % (ok, detail))


def p_tool_drift_refused():
    name = "p_tool_drift_refused"
    man = cm.make_manifest("t1", TOOL_DRIFT, capabilities=CAPS_FS_ONLY,
                           kid=_KID, seed=_SEED)
    store = _store_for({"t1": man})
    ok, detail = cm.verify_skill_manifest("t1", TOOL_DRIFT, store)
    if (not ok and detail.startswith("capability-drift:tools")
            and "tool_write_file" in detail):
        _record(name, "PASS", "undeclared tool_ def refused")
    else:
        _record(name, "FAIL", "got %r %r" % (ok, detail))


def p_secret_drift_refused():
    name = "p_secret_drift_refused"
    man = cm.make_manifest("s1", SECRET_DRIFT, capabilities=CAPS_FS_ONLY,
                           kid=_KID, seed=_SEED)
    store = _store_for({"s1": man})
    ok, detail = cm.verify_skill_manifest("s1", SECRET_DRIFT, store)
    if not ok and detail.startswith("capability-drift:secrets"):
        _record(name, "PASS", "undeclared getpass use refused")
    else:
        _record(name, "FAIL", "got %r %r" % (ok, detail))


def p_signature_forgery_refused():
    name = "p_signature_forgery_refused"
    # Attacker signs with their own key but claims the pinned kid.
    forged = cm.make_manifest("fs1", BENIGN_FS, capabilities=CAPS_FS_ONLY,
                              kid=_KID, seed=_SEED2)
    store = _store_for({"fs1": forged})
    ok, detail = cm.verify_skill_manifest("fs1", BENIGN_FS, store)
    if not (not ok and detail == "manifest-bad-signature"):
        _record(name, "FAIL", "wrong-key forgery not refused: %r %r"
                % (ok, detail))
        return
    # Unknown kid.
    evil = cm.make_manifest("fs1", BENIGN_FS, capabilities=CAPS_FS_ONLY,
                            kid="attacker", seed=_SEED2)
    store2 = _store_for({"fs1": evil})
    ok2, detail2 = cm.verify_skill_manifest("fs1", BENIGN_FS, store2)
    if not ok2 and detail2 == "manifest-unknown-kid":
        _record(name, "PASS", "wrong-key and unknown-kid refused")
    else:
        _record(name, "FAIL", "unknown-kid not refused: %r %r"
                % (ok2, detail2))


def p_replay_refused():
    name = "p_replay_refused"
    man_a = cm.make_manifest("a", BENIGN_FS, capabilities=CAPS_FS_ONLY,
                             kid=_KID, seed=_SEED)
    # Attacker plants A's valid manifest as B's attestation.
    store = _store_for({"b": man_a})
    ok, detail = cm.verify_skill_manifest("b", BENIGN_FS, store)
    if not ok and detail == "manifest-skill-id-mismatch":
        _record(name, "PASS", "cross-skill manifest replay refused")
    else:
        _record(name, "FAIL", "got %r %r" % (ok, detail))


def p_tampered_manifest_fails_closed():
    name = "p_tampered_manifest_fails_closed"
    man = cm.make_manifest("fs1", BENIGN_FS, capabilities=CAPS_FS_ONLY,
                           kid=_KID, seed=_SEED)
    tampered = dict(man)
    caps = dict(tampered["capabilities"])
    caps["egress"] = ["https://evil.example"]
    tampered["capabilities"] = caps
    store = _store_for({"fs1": tampered})
    ok, detail = cm.verify_skill_manifest("fs1", BENIGN_FS, store)
    if not ok and detail == "manifest-bad-signature":
        _record(name, "PASS", "post-signing capability edit fails closed")
    else:
        _record(name, "FAIL", "got %r %r" % (ok, detail))


def _sign_with_jku(manifest, kid, seed, jku):
    import base64
    import json
    header = {"alg": "EdDSA", "typ": "JOSE", "kid": kid, "jku": jku}
    protected_b64 = base64.urlsafe_b64encode(
        json.dumps(header, sort_keys=True,
                   separators=(",", ":")).encode("utf-8")).rstrip(
                       b"=").decode("ascii")
    canonical = cm.canonical_manifest_json(manifest)

    def _b64u(d):
        return base64.urlsafe_b64encode(bytes(d)).rstrip(b"=").decode(
            "ascii")
    signing_input = (protected_b64.encode("ascii") + b"." +
                     _b64u(canonical).encode("ascii"))
    sig = _ed.sign(bytes(seed), signing_input)
    return {"protected": protected_b64, "signature": _b64u(sig)}


def p_jku_never_fetched():
    name = "p_jku_never_fetched"
    man = cm.make_manifest("fs1", BENIGN_FS, capabilities=CAPS_FS_ONLY,
                           kid=_KID, seed=_SEED)
    man["signatures"] = [_sign_with_jku(
        man, _KID, _SEED, "https://evil.example/.well-known/jwks.json")]
    store = _store_for({"fs1": man})
    ok, detail = cm.verify_skill_manifest("fs1", BENIGN_FS, store)
    if not ok and detail == "manifest-jku-not-allowed":
        _record(name, "PASS", "jku key-discovery header refused outright")
    else:
        _record(name, "FAIL", "got %r %r" % (ok, detail))


def p_missing_manifest_advisory():
    name = "p_missing_manifest_advisory"
    store = _store_for({})
    w = _watch_with(store)
    w.register_skill("nomani", _BytesSource(BENIGN_FS), origin=ORIGIN)
    ok, verified, detail = w.fetch_verified_at_use("nomani")
    advisories = [e for e in w.events
                  if e["event_type"] == "capability_manifest_absent"]
    if ok and verified == BENIGN_FS and len(advisories) == 1:
        _record(name, "PASS", "no manifest -> advisory event, use "
                "allowed (audit-only adoption)")
    else:
        _record(name, "FAIL", "ok=%r advisories=%d" % (ok,
                                                       len(advisories)))


def p_no_store_keeps_behavior():
    name = "p_no_store_keeps_behavior"
    w = skill_watch.SkillWatch()
    w.register_skill("plain", _BytesSource(NET_DRIFT), origin=ORIGIN)
    ok, verified, detail = w.fetch_verified_at_use("plain")
    mani_events = [e for e in w.events
                   if "capability_manifest" in e["event_type"]]
    if ok and verified == NET_DRIFT and not mani_events:
        _record(name, "PASS", "no store -> today's behavior, no "
                "manifest events")
    else:
        _record(name, "FAIL", "ok=%r manifest_events=%d" % (
            ok, len(mani_events)))


def p_determinism_x2():
    name = "p_determinism_x2"
    man = cm.make_manifest("fs1", BENIGN_FS, capabilities=CAPS_FS_ONLY,
                           kid=_KID, seed=_SEED)
    store = _store_for({"fs1": man})
    r1 = cm.verify_skill_manifest("fs1", BENIGN_FS, store)
    r2 = cm.verify_skill_manifest("fs1", BENIGN_FS, store)
    d1 = cm.detect_capabilities(BENIGN_FS)
    d2 = cm.detect_capabilities(BENIGN_FS)
    if r1 == r2 and d1 == d2 and r1 == (True, "clean"):
        _record(name, "PASS", "identical verdicts across runs")
    else:
        _record(name, "FAIL", "r1=%r r2=%r" % (r1, r2))


ADJACENT_UNIT_TESTS = [
    "tests.test_capability_manifests",
    "tests.test_skill_watch",
]


def f_green():
    name = "f_green"
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record(name, "HELD",
                "nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                "standalone for full depth-1 adjacency")
        return
    if "TMPDIR" not in os.environ:
        _record(name, "FAIL", "TMPDIR not set (AGENTS.md lesson: "
                "Python ignores a nonexistent TMPDIR)")
        return
    failures = []
    for i, mod in enumerate(ADJACENT_UNIT_TESTS):
        tmp = os.path.join(os.environ["TMPDIR"], "cap-ut-%d" % i)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmp)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        env["GOV_SKIP_GREEN"] = "1"
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "unittest", mod],
                capture_output=True, text=True, env=env, cwd=REPO_ROOT,
                timeout=600)
        except Exception as exc:
            failures.append("%s -> %s" % (mod, exc))
            continue
        if proc.returncode != 0:
            tail = proc.stderr.strip().splitlines()
            tail = tail[-1] if tail else ""
            failures.append("%s -> rc=%d (%s)" % (mod, proc.returncode,
                                                  tail))
    if failures:
        _record(name, "FAIL", "; ".join(failures))
    else:
        _record(name, "HELD", "%d adjacent unit suites green"
                % len(ADJACENT_UNIT_TESTS))


def main():
    global _RESULTS
    _RESULTS = []
    if not HAVE_SEAM:
        print("RED: gov.capability_manifests is not importable on this "
              "tree (%s)." % _IMPORT_ERROR)
        print("The signed-capability-manifest seam is missing: "
              "declared-capability drift sails through the skill/MCP "
              "load-time check.")
        return 1
    p_valid_manifest_loads()
    p_digest_mismatch_refused()
    p_egress_drift_refused()
    p_tool_drift_refused()
    p_secret_drift_refused()
    p_signature_forgery_refused()
    p_replay_refused()
    p_tampered_manifest_fails_closed()
    p_jku_never_fetched()
    p_missing_manifest_advisory()
    p_no_store_keeps_behavior()
    p_determinism_x2()
    f_green()
    fails = [r for r in _RESULTS if r[1] == "FAIL"]
    print("----")
    print("%d/%d probes HELD/PASS, %d FAIL" % (
        len(_RESULTS) - len(fails), len(_RESULTS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
