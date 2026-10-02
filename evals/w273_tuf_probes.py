"""Red-first break battery for wave-273 lane E (TUF bundle delivery).

Attacks the public seams of gov/bundle_delivery.py break-first: every
red probe asserts the attack is REFUSED with the exact coded refusal.
Controls assert the honest paths still work. Pin 1541 (wave-279 lane 2:
1493 + 1 new code: evbundle-contract-refused).
"""
import hashlib
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import shutil
import sys
import tempfile
import traceback
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import bundle_delivery as bd
from gov.bundle_refresh import (BundleRefresher, FetchNotFound, RefreshError,
                                seal_role)
from gov.signing import Ed25519Signer

TAXONOMY_PIN = 1743  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete)

FUTURE = (datetime.now(timezone.utc)
          + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
PAST = (datetime.now(timezone.utc)
        - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
NOW = datetime.now(timezone.utc)

RESULTS = []
PROBES = []


def keypair(n):
    return Ed25519Signer(bytes([n % 250]) * 32)


def keyval(s):
    return {"keytype": "ed25519", "keyval": {"public": s.public_key.hex()}}


def role(name, signer, paths=None, prefixes=None, threshold=1,
         terminating=False):
    kid = "kid-" + name
    return bd.DelegatedRole(name, [kid], threshold, paths=paths,
                            path_hash_prefixes=prefixes,
                            terminating=terminating,
                            keys={kid: keyval(signer)})


def seal(name, signer, targets, expires=FUTURE):
    doc = {"_type": "delegated-targets", "version": 1, "expires": expires,
           "targets": targets}
    return bd.seal_delegated_targets(doc, [("kid-" + name, signer)])


def top_doc(delegations, top_targets=None):
    doc = {"_type": "targets", "version": 1, "expires": FUTURE,
           "targets": top_targets or {}}
    if delegations:
        keys = {}
        roles = []
        for r in delegations:
            keys.update(r.keys)
            entry = {"name": r.name, "keyids": r.keyids,
                     "threshold": r.threshold,
                     "terminating": r.terminating}
            if r.paths is not None:
                entry["paths"] = r.paths
            else:
                entry["path_hash_prefixes"] = r.path_hash_prefixes
            roles.append(entry)
        doc["delegations"] = {"keys": keys, "roles": roles}
    return doc


def digest_of(data):
    return hashlib.sha256(data).hexdigest()


def entry(digest_hex, length=1):
    return {"length": length, "hashes": {"sha256": digest_hex}}


def probe(name):
    def deco(fn):
        def run():
            try:
                detail = fn()
                RESULTS.append((name, True, detail or "ok"))
            except AssertionError as exc:
                RESULTS.append((name, False, "ASSERT: %s" % exc))
            except Exception as exc:  # noqa: BLE001 - battery harness
                RESULTS.append((name, False, "ERROR %r\n%s"
                                % (exc, traceback.format_exc(limit=3))))
        run.__name__ = name
        PROBES.append((name, run))
        return run
    return deco


def expect_refusal(fn, code):
    try:
        fn()
    except bd.DeliveryError as exc:
        assert exc.code == code, "want %s, got %s (%s)" % (
            code, exc.code, exc.detail)
        return "refused %s" % code
    except RefreshError as exc:
        got = getattr(exc, "code", type(exc).__name__)
        assert got == code, "want %s, got %s" % (code, got)
        return "refused %s" % code
    raise AssertionError("attack was NOT refused (wanted %s)" % code)


# ---------------------------------------------------------------- red ----

@probe("R01 terminating-shadowing-delegation-is-reported-not-silent")
def _():
    term = role("term", keypair(1), paths=["bundles/*"], terminating=True)
    later = role("later", keypair(2), paths=["bundles/x"])
    return expect_refusal(
        lambda: bd.resolve_target(
            "bundles/x", top_doc([term, later]),
            lambda n: (_ for _ in ()).throw(FetchNotFound()), NOW),
        "bundle-delivery-shadowed-delegation")


@probe("R02 stale-metadata-at-versioned-url-refused")
def _():
    import base64
    import json
    doc = {"version": 2}
    wire = json.dumps({
        "payload": base64.b64encode(
            json.dumps(doc).encode()).decode(),
        "payloadType": "t"}).encode()
    return expect_refusal(
        lambda: bd.verify_consistent_metadata("targets", 1, wire),
        "bundle-delivery-mirror-stale")


@probe("R03 swapped-target-bytes-at-hash-url-refused")
def _():
    good = digest_of(b"real bundle bytes")
    return expect_refusal(
        lambda: bd.verify_consistent_target("x.bin", good, b"evil bytes"),
        "bundle-delivery-mirror-stale")


@probe("R04 expired-delegated-metadata-is-never-an-authority")
def _():
    s = keypair(4)
    r = role("leaf", s, paths=["bundles/*"])
    wire = seal("leaf", s, {"bundles/x": entry(digest_of(b"x"))},
                expires=PAST)
    return expect_refusal(
        lambda: bd.resolve_target("bundles/x", top_doc([r]),
                                  lambda n: wire, NOW),
        "bundle-delivery-expired-authority-refused")


@probe("R05 delegation-cycle-fails-closed")
def _():
    s = keypair(5)
    r = role("a", s, paths=["bundles/*"])
    doc = {"_type": "delegated-targets", "version": 1, "expires": FUTURE,
           "targets": {},
           "delegations": {"keys": r.keys,
                           "roles": [{"name": "a",
                                      "keyids": r.keyids,
                                      "threshold": 1,
                                      "paths": ["bundles/*"]}]}}
    wire = bd.seal_delegated_targets(doc, [("kid-a", s)])
    return expect_refusal(
        lambda: bd.resolve_target("bundles/x", top_doc([r]),
                                  lambda n: wire, NOW),
        "bundle-delivery-delegation-cycle")


@probe("R06 delegation-walk-cap-enforced")
def _():
    chain = [role("r%d" % i, keypair(60 + i), paths=["bundles/*"])
             for i in range(40)]
    top = top_doc(chain)
    wires = {}
    for i, r in enumerate(chain):
        nxt = [{"name": chain[i + 1].name,
                "keyids": chain[i + 1].keyids, "threshold": 1,
                "paths": ["bundles/*"]}] if i + 1 < len(chain) else []
        keys = {}
        for c in chain:
            keys.update(c.keys)
        doc = {"_type": "delegated-targets", "version": 1,
               "expires": FUTURE, "targets": {}}
        if nxt:
            doc["delegations"] = {"keys": keys, "roles": nxt}
        wires[r.name] = bd.seal_delegated_targets(
            doc, [("kid-" + r.name, keypair(60 + i))])
    return expect_refusal(
        lambda: bd.resolve_target("bundles/x", top,
                                  lambda n: wires[n], NOW),
        "bundle-delivery-delegation-cap-exceeded")


@probe("R07 forged-delegation-signature-refused")
def _():
    s = keypair(7)
    r = role("leaf", s, paths=["bundles/*"])
    # signed by the WRONG key but declared as the right keyid
    wire = seal("leaf", keypair(8),
                {"bundles/x": entry(digest_of(b"x"))}, )
    return expect_refusal(
        lambda: bd.resolve_target("bundles/x", top_doc([r]),
                                  lambda n: wire, NOW),
        "bundle-delivery-delegation-unverified")


@probe("R08 unmet-threshold-refused")
def _():
    s1, s2, s3 = keypair(81), keypair(82), keypair(83)
    kids = ["k1", "k2", "k3"]
    keys = {"k1": keyval(s1), "k2": keyval(s2), "k3": keyval(s3)}
    r = bd.DelegatedRole("leaf", kids, 2, paths=["bundles/*"], keys=keys)
    wire = seal("leaf", s1, {"bundles/x": entry(digest_of(b"x"))})
    # only k1 signed; threshold is 2
    return expect_refusal(
        lambda: bd.resolve_target("bundles/x", top_doc([r]),
                                  lambda n: wire, NOW),
        "bundle-delivery-delegation-unverified")


@probe("R09 noncanonical-delegated-envelope-refused")
def _():
    s = keypair(9)
    r = role("leaf", s, paths=["bundles/*"])
    wire = seal("leaf", s, {"bundles/x": entry(digest_of(b"x"))})
    tampered = wire.replace(b'"payloadType"', b' "payloadType"')
    assert tampered != wire
    return expect_refusal(
        lambda: bd.resolve_target("bundles/x", top_doc([r]),
                                  lambda n: tampered, NOW),
        "bundle-delivery-delegation-malformed")


@probe("R10 missing-eligible-delegated-metadata-refused")
def _():
    s = keypair(10)
    r = role("leaf", s, paths=["bundles/*"])
    return expect_refusal(
        lambda: bd.resolve_target(
            "bundles/x", top_doc([r]),
            lambda n: (_ for _ in ()).throw(FetchNotFound()), NOW),
        "bundle-delivery-delegation-unverified")


@probe("R11 wrong-bin-target-not-routed-to-delegation")
def _():
    digest = digest_of(b"secret")
    s = keypair(11)
    r = role("bins", s, prefixes=[digest[:8]])
    wire = seal("bins", s, {"secret": entry(digest)})
    return expect_refusal(
        lambda: bd.resolve_target("other", top_doc([r]),
                                  lambda n: wire, NOW),
        "bundle-delivery-target-not-found")


@probe("R12 expired-intermediate-cannot-authorize-rollback")
def _():
    s = keypair(12)
    keys = {"kid-r": keyval(s)}
    info = {"keyids": ["kid-r"], "threshold": 1}
    expired = ({"version": 2, "expires": PAST}, info, keys)
    replay = {"version": 1, "expires": FUTURE}
    wire = seal_role("root", replay, [("kid-r", s)])

    def verify(role_name, role_info, keys, wire, where):
        import base64
        import json
        return json.loads(base64.b64decode(
            json.loads(bytes(wire).decode())["payload"]))
    boot = bd.ExpiredBootstrap(verify)
    return expect_refusal(
        lambda: boot.adopt("root", expired, [(wire, replay)], NOW),
        "bundle-delivery-expired-bootstrap-refused")


@probe("R13 impostor-successor-during-bootstrap-refused")
def _():
    s = keypair(13)
    keys = {"kid-r": keyval(s)}
    info = {"keyids": ["kid-r"], "threshold": 1}
    expired = ({"version": 1, "expires": PAST}, info, keys)
    impostor = {"version": 2, "expires": FUTURE}
    wire = seal_role("root", impostor, [("kid-r", keypair(14))])

    def verify(role_name, role_info, keys, wire, where):
        from gov.bundle_refresh import PAYLOAD_TYPES
        from gov.dsse_envelope import pae
        from gov.signing import Ed25519Verifier
        import base64
        import json
        env = json.loads(bytes(wire).decode("utf-8"))
        payload = base64.b64decode(env["payload"].encode("ascii"))
        pae_bytes = pae(PAYLOAD_TYPES[role_name], payload)
        seen = set()
        for e in env["signatures"]:
            kid = e.get("keyid")
            if kid in seen or kid not in role_info["keyids"]:
                continue
            pub = bytes.fromhex(keys[kid]["keyval"]["public"])
            if Ed25519Verifier(pub, key_id=kid).verify(
                    pae_bytes, bytes.fromhex(e["sig"])):
                seen.add(kid)
        if len(seen) < role_info["threshold"]:
            raise bd.DeliveryError(
                "bundle-delivery-expired-bootstrap-refused",
                "threshold not met")
        return json.loads(payload.decode("utf-8"))
    boot = bd.ExpiredBootstrap(verify)
    return expect_refusal(
        lambda: boot.adopt("root", expired, [(wire, impostor)], NOW),
        "bundle-delivery-expired-bootstrap-refused")


@probe("R14 concurrent-locked-cache-refused")
def _():
    tmp = tempfile.mkdtemp(prefix="w273r14-")
    try:
        s = keypair(15)
        kid = "kid-root"
        role_info = {"keyids": [kid], "threshold": 1}
        keys = {kid: keyval(s)}
        now = datetime.now(timezone.utc)
        root_doc = {"_type": "root", "version": 1, "expires": FUTURE,
                    "consistent_snapshot": True,
                    "roles": {r: dict(role_info)
                              for r in ("root", "timestamp", "snapshot",
                                        "targets")},
                    "keys": keys}
        root_wire = seal_role("root", root_doc, [(kid, s)])
        first = BundleRefresher(root_wire,
                                lambda role, ver: (_ for _ in ()
                                                  ).throw(FetchNotFound()),
                                tmp, clock=lambda: now, cache_lock=True)
        try:
            def second():
                BundleRefresher(root_wire,
                                lambda role, ver: (_ for _ in ()
                                                  ).throw(FetchNotFound()),
                                tmp, clock=lambda: now, cache_lock=True)
            return expect_refusal(second, "bundle-delivery-cache-locked")
        finally:
            first.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@probe("R15 stale-refresher-cannot-serve-delegation")
def _():
    from gov.bundle_refresh import SuspendedError

    class R:
        def verified_targets_doc(self):
            raise SuspendedError("suspended: test")
    try:
        bd.resolve_pin(R(), "b/x", None, NOW)
    except SuspendedError:
        return "refused: refresher not trusted"
    raise AssertionError("stale refresher served a targets document")


# ------------------------------------------------------------ controls ----

@probe("C01 happy-two-level-delegation-resolves")
def _():
    s = keypair(20)
    r = role("leaf", s, paths=["bundles/*"])
    dgst = digest_of(b"bundle bytes")
    wire = seal("leaf", s, {"bundles/x": entry(dgst, length=12)})
    res = bd.resolve_target("bundles/x", top_doc([r]), lambda n: wire,
                            NOW)
    assert res.digest == dgst and res.role == "leaf" and res.length == 12
    return "resolved via leaf"


@probe("C02 disjoint-terminating-delegation-does-not-block")
def _():
    s_t, s_l = keypair(21), keypair(22)
    term = role("term", s_t, paths=["bundles/a/*"], terminating=True)
    leaf = role("leaf", s_l, paths=["bundles/*"])
    dgst = digest_of(b"leaf bytes")
    leaf_wire = seal("leaf", s_l, {"bundles/bx": entry(dgst)})
    seen = []

    def fetch(n):
        seen.append(n)
        assert n == "leaf", "disjoint terminating role must not be walked"
        return leaf_wire
    res = bd.resolve_target("bundles/bx", top_doc([term, leaf]), fetch,
                            NOW)
    assert res.role == "leaf" and res.digest == dgst
    assert seen == ["leaf"]
    return "leaf served; term untouched"


@probe("C03 top-level-target-never-touches-delegation-fetch")
def _():
    s = keypair(23)
    r = role("leaf", s, paths=["bundles/*"])
    dgst = digest_of(b"top bytes")
    top = top_doc([r], {"bundles/x": entry(dgst)})
    calls = []

    def fetch(n):
        calls.append(n)
        raise FetchNotFound()
    res = bd.resolve_target("bundles/x", top, fetch, NOW)
    assert res.role == "targets" and res.digest == dgst and not calls
    return "top-level hit"


@probe("C04 hash-bin-delegation-resolves-without-names")
def _():
    data = b"secret bundle"
    dgst = digest_of(data)
    bin_prefix = hashlib.sha256(b"secret").hexdigest()[:8]
    s = keypair(24)
    r = role("bins", s, prefixes=[bin_prefix])
    wire = seal("bins", s, {"secret": entry(dgst)})
    res = bd.resolve_target("secret", top_doc([r]), lambda n: wire, NOW)
    assert res.role == "bins" and res.digest == dgst
    return "bin-routed"


@probe("C05 potential-shadow-is-warning-not-refusal")
def _():
    s_t, s_l = keypair(25), keypair(26)
    term = role("term", s_t, paths=["skills/a/*"], terminating=True)
    later = role("later", s_l, paths=["skills/*/x"])
    dgst = digest_of(b"later bytes")
    wire = seal("later", s_l, {"skills/b/x": entry(dgst)})
    res = bd.resolve_target("skills/b/x", top_doc([term, later]),
                            lambda n: wire, NOW)
    assert res.role == "later" and res.digest == dgst
    assert any(w.startswith("potential-shadow") for w in res.warnings),\
        "expected a potential-shadow warning, got %r" % res.warnings
    return "resolved with warning"


@probe("C06 expired-intermediate-bootstraps-successor")
def _():
    s = keypair(27)
    keys = {"kid-r": keyval(s)}
    info = {"keyids": ["kid-r"], "threshold": 1}
    expired = ({"version": 1, "expires": PAST}, info, keys)
    succ = {"version": 2, "expires": FUTURE}
    wire = seal_role("root", succ, [("kid-r", s)])

    def verify(role_name, role_info, keys, wire, where):
        from gov.bundle_refresh import PAYLOAD_TYPES
        from gov.dsse_envelope import pae
        from gov.signing import Ed25519Verifier
        import base64
        import json
        env = json.loads(bytes(wire).decode("utf-8"))
        payload = base64.b64decode(env["payload"].encode("ascii"))
        pae_bytes = pae(PAYLOAD_TYPES[role_name], payload)
        seen = set()
        for e in env["signatures"]:
            kid = e.get("keyid")
            if kid in seen or kid not in role_info["keyids"]:
                continue
            pub = bytes.fromhex(keys[kid]["keyval"]["public"])
            if Ed25519Verifier(pub, key_id=kid).verify(
                    pae_bytes, bytes.fromhex(e["sig"])):
                seen.add(kid)
        if len(seen) < role_info["threshold"]:
            raise bd.DeliveryError(
                "bundle-delivery-expired-bootstrap-refused",
                "threshold not met")
        return json.loads(payload.decode("utf-8"))
    adopted = bd.ExpiredBootstrap(verify).adopt(
        "root", expired, [(wire, succ)], NOW)
    assert adopted["version"] == 2
    return "bootstrapped v2"


@probe("C07 consistent-snapshot-urls-bind-version-and-digest")
def _():
    assert bd.snapshot_metadata_url("targets", 7) == "v7.targets.json"
    dgst = digest_of(b"bytes")
    assert bd.snapshot_target_url("x.bin", dgst) == "%s.x.bin" % dgst
    assert bd.verify_consistent_target("x.bin", dgst, b"bytes") == b"bytes"
    return "url mapping binds"


@probe("C08 resolve-pin-shape-fits-skill-update-gate")
def _():
    dgst = digest_of(b"pin bytes")
    doc = top_doc([], {"b/x": entry(dgst)})

    class R:
        def verified_targets_doc(self):
            return doc
    pin = bd.resolve_pin(R(), "b/x", None, NOW)
    clean = bd.strip_provenance(pin)
    assert clean == {"digest": dgst, "chain_state": "trusted"}, clean
    assert pin["_provenance_role"] == "targets"
    return "pin shape ok"


@probe("C09 taxonomy-carries-all-ten-codes")
def _():
    from gov import decision_codes as dc
    codes = ["bundle-delivery-cache-locked",
             "bundle-delivery-delegation-cap-exceeded",
             "bundle-delivery-delegation-cycle",
             "bundle-delivery-delegation-malformed",
             "bundle-delivery-delegation-unverified",
             "bundle-delivery-expired-authority-refused",
             "bundle-delivery-expired-bootstrap-refused",
             "bundle-delivery-mirror-stale",
             "bundle-delivery-shadowed-delegation",
             "bundle-delivery-target-not-found"]
    for c in codes:
        assert c in dc.TAXONOMY, "missing %s" % c
        assert dc.TAXONOMY[c]["severity"] in ("high", "medium"), c
    return "10/10 codes present"


@probe("C10 pin-1458")
def _():
    import re
    lits = re.findall(r'"code": \'([^\']*)\'',
                      open(os.path.join(os.path.dirname(__file__), "..",
                                        "gov", "decision_codes.py"),
                           encoding="utf-8").read())
    assert len(lits) == TAXONOMY_PIN, "%d != %d" % (len(lits),
                                                    TAXONOMY_PIN)
    assert len(set(lits)) == len(lits), "duplicate code literals"
    return "%d codes, unique" % len(lits)


@probe("C11 clean-delegation-list-lints-clean")
def _():
    term = role("term", keypair(28), paths=["bundles/a/*"],
                terminating=True)
    later = role("later", keypair(29), paths=["bundles/b/*"])
    findings = bd.lint_delegations([term, later])
    assert findings == [], "expected a clean lint, got %r" % findings
    return "clean lint"


def green_check():
    """Depth-1 green check: run the adjacent refresh battery's main with
    GOV_SKIP_GREEN=1 so nested green checks cannot recurse."""
    import subprocess
    adj = os.path.join(os.path.dirname(__file__),
                       "bundle_refresh_probes.py")
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    proc = subprocess.run([sys.executable, adj], capture_output=True,
                          text=True, timeout=600, env=env, cwd=os.path.join(
                              os.path.dirname(__file__), ".."))
    if proc.returncode != 0:
        raise AssertionError("adjacent battery failed:\n%s\n%s"
                             % (proc.stdout[-2000:], proc.stderr[-2000:]))
    return "adjacent battery green"


def main():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        RESULTS.append(("GREEN-CHECK", True,
                        "skipped (GOV_SKIP_GREEN=1)"))
    else:
        try:
            note = green_check()
        except Exception as exc:  # noqa: BLE001 - harness
            RESULTS.append(("GREEN-CHECK", False, str(exc)))
        else:
            RESULTS.append(("GREEN-CHECK", True, note))
    runs = list(PROBES)
    for _name, _run in runs:
        _run()
    failed = [r for r in RESULTS if not r[1]]
    print("w273_tuf_probes: %d/%d passed"
          % (sum(1 for r in RESULTS if r[1]), len(RESULTS)))
    for name, ok, detail in RESULTS:
        print("[%s] %s: %s" % ("PASS" if ok else "FAIL", name,
                               (detail or "").splitlines()[0]))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
