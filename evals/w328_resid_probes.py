"""Break-first probes for the wave-328 residual-hardening lane.

Hardens the documented "Hardening observations (not findings)" left by the
wave-326 and wave-327 independent red teams:

Wave-327 observations:
 R1. register_skill silently re-baselines an already-registered skill ->
     re-registration is now refused LOUD
     (supplychain-scan-already-registered); an explicit
     update_skill_registration covers legitimate TTL/interval changes.
 R2. missed_intervals was built linearly in the clock gap (unbounded) ->
     the report list is capped at MAX_MISSED_INTERVALS_REPORTED with a
     truncation flag and the true total carried LOUD.
 R3. run_scan's `now` is caller-supplied -> the clock-trust assumption is
     now stated LOUD in the report schema (clock_trust field) and in code.
 R4. standing_of's supersedes-walk skipped an agreeing concurrent voice ->
     the chain now includes every knowledge entry for the digest.
 R5. OSV doc/code mismatch on asserted_standing="revoked" -> the docstring
     is corrected to the code (the feed-key signature is the trust anchor;
     "revoked" is the operator's signed assertion). Behavior pinned.

Wave-326 observations:
 R6. supersede() same-version ties were first-wins/order-dependent ->
     an exact version tie is now refused LOUD (advisory-version-tie),
     consistent with the standing store's known_since tie refusal.
 R7. check_package trusted any hand-built pinned dict -> only
     bind_advisory_input-sealed inputs (PinnedAdvisory) are accepted;
     anything else is refused LOUD (advisory-input-unpinned).

Red-first: every R-probe below asserts the HARDENED behavior, so each one
BREAKs on the unhardened base tree (54cdac0d) and flips to HELD after the
fix. R5 pins behavior that does not change (doc-only fix); it HOLDS
before and after, proving the docstring correction describes reality.

Staging default is set at module level (the harness refuses the declared
ungoverned_ack in production mode).
"""

import hashlib
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2056  # Wave-327 merge: pin 2035 -> 2044 (+9 policy-channel-*); Wave-328 lane 2: pin 2044 -> 2047 (+3: 1 supplychain-scan-already-registered + 1 advisory-version-tie + 1 advisory-input-unpinned); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _error(pid, note):
    _record(pid, "ERROR", note)


def probe(pid):
    def deco(fn):
        def run():
            try:
                fn()
            except AssertionError as exc:
                _break(pid, "assertion failed: %s" % (exc,))
            except Exception as exc:  # noqa: BLE001
                _error(pid, "%s: %s" % (type(exc).__name__, exc))
        run.__name__ = pid
        return run
    return deco


def _expect_code(pid, fn, code):
    """fn() must raise an error whose .code == code; anything else BREAKs."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "code", None)
        if got == code:
            _held(pid, "refused coded %s" % (code,))
        else:
            _break(pid, "wrong refusal: code=%r (%s: %s)"
                   % (got, type(exc).__name__, exc))
        return
    _break(pid, "no refusal (expected coded %s)" % (code,))


# ---------------------------------------------------------------------------
# Imports.
# ---------------------------------------------------------------------------

from gov import background_scan as BS  # noqa: E402
from gov import skill_supply_chain as SC  # noqa: E402
from gov import advisory_binding as AB  # noqa: E402
from gov import standing_verdicts as SV  # noqa: E402
from gov import knowledge_ingest as KI  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
from gov import ed25519 as ED  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures (fixed seeds: deterministic keys across runs).
# ---------------------------------------------------------------------------

def _seed(tag):
    return (tag + "-seed").ljust(32, "0")[:32].encode("ascii")


_R1 = Ed25519Signer(_seed("resid-r1"))
_P1 = Ed25519Signer(_seed("resid-p1"))
_F1 = Ed25519Signer(_seed("resid-feed"))

FUTURE = "2030-01-01T00:00:00Z"
T0 = 1800000000

SKILL = "skills/pay/x"
BYTES_V1 = b"skill-content-v1"


def _keyinfo(signer):
    return {"keytype": "ed25519",
            "keyval": {"public": signer.public_key.hex()}}


KEYS = {"r1": _keyinfo(_R1), "pay-k1": _keyinfo(_P1)}
ROOT_TRUST = {"keys": KEYS, "root": {"keyids": ["r1"], "threshold": 1}}


def _deleg_wire(version=1):
    doc = {"version": version, "expires": FUTURE,
           "delegations": [{"name": "pay", "keyids": ["pay-k1"],
                            "threshold": 1, "paths": ["skills/pay/*"],
                            "terminating": False}]}
    return SC.seal_document("delegations", doc, [("r1", _R1)])


def _authz_wire(skill_bytes, version=1):
    doc = {"skill": SKILL, "version": version,
           "digest": hashlib.sha256(skill_bytes).hexdigest(),
           "expires": FUTURE}
    return SC.seal_document("link", doc, [("pay-k1", _P1)])


def _tmp_state():
    d = tempfile.mkdtemp(prefix="resid-")
    return os.path.join(d, "state.json")


def _register(sp, now=T0, interval=900, ttl=3600):
    return BS.register_skill(
        sp, skill_path=SKILL, delegation_wire=_deleg_wire(),
        authz_wire=_authz_wire(BYTES_V1), skill_bytes=BYTES_V1,
        ttl_seconds=ttl, scan_interval_seconds=interval, now=now)


def _inv():
    return [{"skill_path": SKILL, "skill_bytes": BYTES_V1,
             "delegation_wire": _deleg_wire(),
             "authz_wire": _authz_wire(BYTES_V1)}]


D1 = "sha256:" + "aa" * 32


def _knowledge(standing="quarantined", justification="j", origin="o",
               collector="c", known_since=100, supersedes=None):
    return {"artifact_digest": D1, "asserted_standing": standing,
            "justification": justification, "origin": origin,
            "collector": collector, "known_since": known_since,
            "supersedes": supersedes}


def _adv_policy(pub_b64, threshold=1, freshness=3600):
    return {"advisory_policy_input": "adv-pol",
            "signature_threshold": threshold,
            "freshness_seconds": freshness,
            "trusted_keys": [pub_b64]}


def _adv_keypair(seed_byte=11):
    sk = bytes([seed_byte]) * 32
    pub = ED.publickey(sk)
    import base64
    return sk, pub, base64.b64encode(pub).decode("ascii")


def _signed_snapshot(flags, version, seed_byte=11, fetched_at=1700000000):
    import base64
    import hashlib as _hl
    import json as _json
    sk, pub, pub_b64 = _adv_keypair(seed_byte)
    snap = {"advisory_id": "ADV-1", "version": version, "issuer": "feed",
            "fetched_at": fetched_at, "flags": dict(flags)}
    canon = _json.dumps(snap, sort_keys=True,
                        separators=(",", ":")).encode("utf-8")
    sig = ED.sign(sk, canon)
    snap["canonical_bytes"] = canon
    snap["digest"] = _hl.sha256(canon).hexdigest()
    snap["signatures"] = [{"key": pub_b64,
                           "sig": base64.b64encode(sig).decode("ascii")}]
    snap["_pub_b64"] = pub_b64
    return snap


def _pin_snapshot(snapshot):
    return AB.bind_advisory_input(
        _adv_policy(snapshot.pop("_pub_b64")), snapshot, 1700000000)


# ---------------------------------------------------------------------------
# R1: register_skill re-registration guard.
# ---------------------------------------------------------------------------

@probe("R1a-reregister-refused-loud")
def _r1a():
    """A second register_skill for the same skill must be refused LOUD.

    RED on the base tree: the second call silently re-baselined.
    """
    sp = _tmp_state()
    _register(sp, now=T0)
    _expect_code(
        "R1a-reregister-refused-loud",
        lambda: _register(sp, now=T0 + 10),
        "supplychain-scan-already-registered")


@probe("R1b-update-registration-config-path")
def _r1b():
    """Legitimate TTL/interval changes go through update_skill_registration.

    It must refuse unknown skills LOUD and never touch the scan-owned
    baseline fields (digest, delegations_version).

    RED on the base tree: no update_skill_registration at all (BREAK).
    """
    pid = "R1b-update-registration-config-path"
    upd_fn = getattr(BS, "update_skill_registration", None)
    if upd_fn is None:
        return _break(pid, "no update_skill_registration entry point")
    sp = _tmp_state()
    rec = _register(sp, now=T0, ttl=3600, interval=900)
    old_digest = rec["digest"]
    upd = upd_fn(sp, skill_path=SKILL, ttl_seconds=7200,
                 scan_interval_seconds=300)
    assert upd["ttl_seconds"] == 7200, upd
    assert upd["scan_interval_seconds"] == 300, upd
    assert upd["digest"] == old_digest, "baseline digest must be untouched"
    _expect_code(
        "R1b-update-registration-config-path-unknown",
        lambda: upd_fn(sp, skill_path="skills/nope", ttl_seconds=1),
        "supplychain-scan-malformed")
    _held(pid, "config updated; unknown skill refused; baseline untouched")


# ---------------------------------------------------------------------------
# R2: missed_intervals bound.
# ---------------------------------------------------------------------------

@probe("R2-missed-intervals-bounded")
def _r2():
    """A pathological clock gap must not build an unbounded missed list.

    RED on the base tree: len(missed) == 9999 for a 1M-second gap
    (BREAK -- on the base tree the cap constant and the LOUD total
    fields are absent, which is itself the demonstrated gap).
    """
    pid = "R2-missed-intervals-bounded"
    cap = getattr(BS, "MAX_MISSED_INTERVALS_REPORTED", None)
    sp = _tmp_state()
    _register(sp, now=T0, interval=100)
    huge_now = T0 + 100 * 10000  # 1M seconds ~ 9999 missed intervals
    r = BS.run_scan(sp, _inv(), ROOT_TRUST, now=huge_now)[0]
    if cap is None:
        return _break(pid, "no MAX_MISSED_INTERVALS_REPORTED cap")
    if len(r["missed_intervals"]) > cap:
        return _break(pid, "unbounded missed list: %d entries"
                      % (len(r["missed_intervals"]),))
    if r.get("missed_intervals_truncated") is not True:
        return _break(pid, "truncation not flagged LOUD")
    if r.get("missed_intervals_total") != 9999:
        return _break(pid, "true total not carried LOUD: %r"
                      % (r.get("missed_intervals_total"),))
    if not any("truncated" in n for n in r["notes"]):
        return _break(pid, "truncation not noted LOUD")
    _held(pid, "capped at %d; total 9999 carried LOUD" % cap)


# ---------------------------------------------------------------------------
# R3: clock-trust assumption stated LOUD.
# ---------------------------------------------------------------------------

@probe("R3-clock-trust-in-report")
def _r3():
    """Every report must state the clock-trust assumption machine-readably.

    RED on the base tree: no clock_trust field exists.
    """
    sp = _tmp_state()
    _register(sp, now=T0)
    r = BS.run_scan(sp, _inv(), ROOT_TRUST, now=T0)[0]
    assert "clock_trust" in r, "report has no clock_trust field"
    assert "caller" in r["clock_trust"], r["clock_trust"]
    _held("R3-clock-trust-in-report",
          "clock_trust=%r" % (r["clock_trust"],))


# ---------------------------------------------------------------------------
# R4: standing_of chain completeness.
# ---------------------------------------------------------------------------

@probe("R4-chain-includes-agreeing-voice")
def _r4():
    """An agreeing concurrent attach must appear in the justification chain.

    RED on the base tree: the supersedes-walk skips the agreeing tip.
    """
    d = tempfile.mkdtemp(prefix="resid-sv-")
    store = SV.StandingStore(os.path.join(d, "j.jsonl"))
    store.register_artifact(D1, "inv")
    store.attach_knowledge(_knowledge(standing="trusted", supersedes=None))
    store.attach_knowledge(_knowledge(standing="trusted", supersedes=1,
                                      known_since=200))
    # Agreeing concurrent write: supersedes the tip's parent (seq 1), not
    # the tip (seq 2). The old code's walk skipped seq 2.
    store.attach_knowledge(_knowledge(standing="trusted", supersedes=1,
                                      known_since=300,
                                      justification="third voice"))
    chain = store.standing_of(D1)["chain"]
    seqs = [e["seq"] for e in chain]
    assert seqs == [1, 2, 3], "chain omits a voice: %r" % (seqs,)
    assert any(e["justification"] == "third voice" for e in chain), chain
    _held("R4-chain-includes-agreeing-voice",
          "chain seqs %r: every knowledge voice present" % (seqs,))


# ---------------------------------------------------------------------------
# R5: OSV doc/code mismatch (behavior pin; doc-only fix).
# ---------------------------------------------------------------------------

@probe("R5-osv-revoked-is-signed-operator-assertion")
def _r5():
    """A feed-key-signed OSV envelope asserting revoked applies as revoked.

    Pins the corrected docstring: the signature is the trust anchor; the
    OSV record itself only says "vulnerable", so "revoked" is the feed
    operator's signed judgment, recorded as such.
    """
    import base64
    import json as _json
    feed_sk = bytes([77]) * 32
    feed_pub = ED.publickey(feed_sk)
    feed_dir = tempfile.mkdtemp(prefix="resid-feed-")
    cfg = KI.FeedConfig(feed_dir, feed_pub, "c")
    osv = {"id": "GHSA-1", "summary": "s", "details": "d",
           "published": "2026-01-01T00:00:00Z",
           "affected": [{"package": {"ecosystem": "npm", "name": "leftpad"}}]}
    doc = {"schema": "osv/v1", "osv": osv, "artifact_digest": D1,
           "asserted_standing": "revoked", "supersedes": None}
    canon = _json.dumps(doc, sort_keys=True,
                        separators=(",", ":")).encode("utf-8")
    doc["signature"] = base64.b64encode(ED.sign(feed_sk, canon)).decode()
    path = os.path.join(feed_dir, "a.json")
    with open(path, "w", encoding="utf-8") as fh:
        _json.dump(doc, fh)
    got = KI.ingest_file(path, cfg)
    assert got["asserted_standing"] == "revoked", got
    assert got["origin"] == "osv.dev", got
    _held("R5-osv-revoked-is-signed-operator-assertion",
          "feed-signed revoked applies; docstring corrected to match")


# ---------------------------------------------------------------------------
# R6: supersede() same-version tie refused LOUD.
# ---------------------------------------------------------------------------

@probe("R6-supersede-tie-refused-loud")
def _r6():
    """Two different advisories at the same version: refused, not first-wins.

    RED on the base tree: order-dependent first-wins, silently.
    """
    s1 = _signed_snapshot({"pkg-a": "allow"}, version=3, seed_byte=21)
    s2 = _signed_snapshot({"pkg-a": "flagged"}, version=3, seed_byte=22)
    p1, p2 = _pin_snapshot(s1), _pin_snapshot(s2)
    _expect_code("R6-supersede-tie-refused-loud",
                 lambda: AB.supersede([p1, p2]), "advisory-version-tie")
    # Distinct versions still resolve newest-wins.
    s3 = _signed_snapshot({"pkg-a": "flagged"}, version=4, seed_byte=23)
    p3 = _pin_snapshot(s3)
    assert AB.supersede([p1, p3])["version"] == 4
    _held("R6-supersede-tie-refused-loud",
          "tie refused coded; newest-wins still works")


# ---------------------------------------------------------------------------
# R7: check_package only accepts sealed pinned inputs.
# ---------------------------------------------------------------------------

@probe("R7-unpinned-dict-refused-loud")
def _r7():
    """A hand-built pinned dict is refused; only bind_advisory_input output
    (PinnedAdvisory) is accepted.

    RED on the base tree: the hand-built dict was honored (caller-trusted).
    """
    pinned = {
        "advisory_policy_input": "handbuilt",
        "advisory_id": "handbuilt",
        "version": 9,
        "issuer": "handbuilt",
        "fetched_at": 1700000000,
        "freshness_seconds": 3600,
        "signature_threshold": 1,
        "valid_signatures": 99,
        "flags": {"pkg-h": "allow"},
        "digest": "ab" * 32,
    }
    _expect_code("R7-unpinned-dict-refused-loud",
                 lambda: AB.check_package(pinned, "pkg-h", 1700000100),
                 "advisory-input-unpinned")
    # The sealed path still works end to end.
    s = _signed_snapshot({"pkg-h": "allow"}, version=2, seed_byte=24)
    p = _pin_snapshot(s)
    assert isinstance(p, AB.PinnedAdvisory), type(p)
    assert AB.check_package(p, "pkg-h", 1700000100)["verdict"] \
        == "advisory-clear", "sealed path broke"
    _held("R7-unpinned-dict-refused-loud",
          "plain dict refused coded; sealed path verifies")


# ---------------------------------------------------------------------------
# Pin + footer probes.
# ---------------------------------------------------------------------------

@probe("P8-pin-taxonomy-2056-sorted")
def _p8():
    from gov import decision_codes as DC
    codes = sorted(DC.TAXONOMY)
    assert len(codes) == len(set(codes)) == TAXONOMY_PIN, \
        "taxonomy not unique/pinned: %d vs pin %d" % (len(codes),
                                                     TAXONOMY_PIN)
    assert list(DC.TAXONOMY) == codes, "taxonomy not sorted"
    want = {"supplychain-scan-already-registered": "supplychain",
            "advisory-version-tie": "authority",
            "advisory-input-unpinned": "authority"}
    for code, domain in sorted(want.items()):
        assert DC.TAXONOMY[code]["domain"] == domain, code
    _held("P8-pin-taxonomy-2056-sorted", "2056/2056/0 sorted; new codes ok")


@probe("P9-footer-open-F412-next-F413")
def _p9():
    path = os.path.join(REPO, "evals", "FINDINGS.md")
    src = open(path, encoding="utf-8").read()
    assert "Next free finding: **F414**" in src, "next-free footer"
    assert "**Open findings: F413.**" in src, "open-F413 footer"
    _held("P9-footer-open-F412-next-F413",
          "footer: open F413 / next F414 (F413 filed by wave-328 lane 4; F412 closed)")


# ---------------------------------------------------------------------------
# Green checks (depth-1: children run with GOV_SKIP_GREEN=1).
# ---------------------------------------------------------------------------

_GREEN_CHILDREN = [
    "evals/w326_sched_probes.py",
    "evals/w326_standing_probes.py",
    "evals/w244_treeship_advisory_probes.py",
]
_KNOWN_CHILD_BREAKS = set()


def _green():
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-skip", "HELD", "green checks skipped (child mode)")
        return
    for child in _GREEN_CHILDREN:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(REPO, child)],
                capture_output=True, text=True, timeout=900, env=env,
                cwd=REPO)
        except Exception as exc:  # noqa: BLE001
            _record("green-" + child, "ERROR", "%s" % (exc,))
            continue
        out = proc.stdout + proc.stderr
        bad = [ln for ln in out.splitlines()
               if ln.startswith("[BREAK]")]
        ok = True
        for ln in bad:
            pid = ln.split("]")[1].split(":")[0].strip()
            if pid not in _KNOWN_CHILD_BREAKS:
                ok = False
        if "[ERROR]" in out or proc.returncode != 0:
            ok = False
        _record("green-" + child, "HELD" if ok else "BREAK",
                "child %s ran; unexpected breaks/errors fail this check"
                % child)


def main(argv):
    probes = [v for k, v in sorted(globals().items())
              if k.startswith("_r") and k[2:3].isdigit() and callable(v)]
    probes += [v for k, v in sorted(globals().items())
               if k.startswith("_p") and k[2:3].isdigit() and callable(v)]
    for fn in probes:
        fn()
    _green()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    print("w328_resid battery: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    green_ok = all(v != "BREAK" and v != "ERROR"
                   for pid, v, _ in _results
                   if pid.startswith("green-") and pid != "green-skip")
    if green_ok:
        print("GREEN")
    return 0 if (n_break == 0 and n_err == 0) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
