"""Break-first probes for the wave-327 policy-update distribution channel.

Red-first: gov/policy_channel.py is new in this lane, so "red" is
demonstrated two ways: (1) every probe below FAILS on the base tree
(542c5cee) with ImportError (the module does not exist there); (2) the
product was mutated during development (signature verification neutered,
rollback floor removed) and each mutation made exactly the corresponding
probes BREAK -- the battery is genuinely coupled to the behavior, not to
the module's existence.

What the battery pins:
1. Unsigned/tampered policy documents are refused coded
   (policy-channel-unsigned); verification is exact ``is True``.
2. A replayed older version is refused coded (policy-channel-rollback);
   the active policy is untouched.
3. A version skip beyond the bounded window is refused coded
   (policy-channel-version-skip) -- the freeze/DoS bound.
4. A revoked/superseded version is never re-applied
   (policy-channel-superseded).
5. Activation is atomic: an orphaned activation tmp (crash mid-activation)
   is reported LOUD (policy-channel-activation-failed) and the previous
   policy stays in force.
6. Every applied policy cites the knowledge that motivated it
   (origin/collector/known_since); policy_provenance traces
   policy version -> advisory -> standing flip.
7. The channel's wire is compatible with the wave-326 background scanner's
   best-effort version read, so a delivered policy fires the scanner's
   policy-change trigger (documented seam, no import coupling in product).
8. Feed-dir escape (symlink pointing outside the feed) is refused coded
   (policy-channel-feed-escape); unknown policy names are refused coded
   (policy-channel-unknown-policy); malformed envelopes are refused coded
   (policy-channel-malformed).
9. Staleness: exceeding the max-staleness budget without refresh is a loud
   stale verdict (policy-channel-stale), never silent continued trust.

Staging default is set at module level (the harness refuses the declared
ungoverned_ack in production mode).
"""

import base64
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2128 # Wave-326 merge pin; wave-327 lane 3 repoints to 2044 (+9 policy-channel-*); Wave-328 lane 2: pin 2044 -> 2047 (+3: 1 supplychain-scan-already-registered + 1 advisory-version-tie + 1 advisory-input-unpinned); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)
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


# ---------------------------------------------------------------------------
# Test fixtures: a signed policy feed in a temp dir.
# ---------------------------------------------------------------------------

def _keys():
    from gov import ed25519
    seed = ed25519.generate_seed()
    return seed, ed25519.publickey(seed)


def _config(feed_dir, pub, policy_name="agent-policy", max_skip=4,
            max_staleness_seconds=86400):
    from gov import policy_channel
    return policy_channel.ChannelConfig(
        feed_dir=feed_dir, feed_public_key=pub, policy_name=policy_name,
        max_skip=max_skip, max_staleness_seconds=max_staleness_seconds)


def _mot():
    return [{"origin": "test", "collector": "test",
             "known_since": 1700000000}]


def _doc(version, seed, policy_name="agent-policy", body=None, revokes=None,
         motivated_by="default", issued_at=1700000000):
    from gov import ed25519
    from gov.bundle_refresh import tuf_canonical_json
    if motivated_by == "default":
        motivated_by = _mot()
    payload = {
        "schema": "sasanam-policy-document/v1",
        "policy_name": policy_name,
        "version": version,
        "body": {"rules": ["r%d" % version]} if body is None else body,
        "revokes": [] if revokes is None else list(revokes),
        "motivated_by": list(motivated_by),
        "issued_at": issued_at,
    }
    raw = tuf_canonical_json(payload)
    sig = ed25519.sign(seed, raw)
    envelope = {
        "payload": base64.b64encode(raw).decode("ascii"),
        "signature": base64.b64encode(sig).decode("ascii"),
    }
    return envelope


def _write_feed(feed_dir, envelope, version, policy_name="agent-policy"):
    name = "%s.v%d.json" % (policy_name, version)
    path = os.path.join(feed_dir, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh)
    return path


def _fresh(feed_extra=None):
    """A temp feed dir + state dir + config + keys. Returns dict."""
    from gov import policy_channel
    feed_dir = tempfile.mkdtemp(prefix="polfeed-")
    state_dir = tempfile.mkdtemp(prefix="polstate-")
    seed, pub = _keys()
    cfg = _config(feed_dir, pub)
    if feed_extra:
        feed_extra(feed_dir, seed, pub)
    return {"feed_dir": feed_dir, "state_dir": state_dir, "seed": seed,
            "pub": pub, "cfg": cfg, "channel": policy_channel}


@probe("P1a-unsigned-refused")
def _p1a():
    """A tampered-signature policy document is refused coded."""
    fx = _fresh()
    pc = fx["channel"]
    env = _doc(1, fx["seed"])
    bad = dict(env)
    raw = base64.b64decode(env["payload"])
    badsig = bytearray(base64.b64decode(env["signature"]))
    badsig[0] ^= 0xFF
    bad["signature"] = base64.b64encode(bytes(badsig)).decode("ascii")
    _write_feed(fx["feed_dir"], bad, 1)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is False, "unsigned policy applied: %r" % (rep,)
    assert rep["code"] == "policy-channel-unsigned", \
        "wrong code: %r" % (rep["code"],)
    assert pc.current_version(fx["cfg"], fx["state_dir"]) == 0, \
        "state advanced on unsigned input"
    _held("P1a-unsigned-refused", "tampered signature refused coded")


@probe("P1b-rollback-refused")
def _p1b():
    """A replayed older version is refused coded; active policy untouched."""
    fx = _fresh()
    pc = fx["channel"]
    _write_feed(fx["feed_dir"], _doc(1, fx["seed"]), 1)
    _write_feed(fx["feed_dir"], _doc(2, fx["seed"]), 2)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is True and rep["version"] == 2, \
        "expected v2 applied, got %r" % (rep,)
    # Direct apply-layer replay: version <= floor is refused loudly.
    raw = json.dumps(_doc(1, fx["seed"])).encode("utf-8")
    try:
        pc.apply_document(fx["cfg"], fx["state_dir"], raw)
    except pc.PolicyChannelError as exc:
        assert exc.code == "policy-channel-rollback", \
            "wrong code: %r" % (exc.code,)
        _held("P1b-rollback-refused", "replay refused coded rollback")
        return
    _break("P1b-rollback-refused", "replayed v1 was applied")


@probe("P1c-version-skip-refused")
def _p1c():
    """A version jump beyond the bounded window is refused coded."""
    fx = _fresh()
    pc = fx["channel"]
    _write_feed(fx["feed_dir"], _doc(1, fx["seed"]), 1)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is True
    # max_skip=4: v1 -> v6 is beyond the window (1+4=5 < 6).
    _write_feed(fx["feed_dir"], _doc(6, fx["seed"]), 6)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is False, "skip applied: %r" % (rep,)
    assert rep["code"] == "policy-channel-version-skip", \
        "wrong code: %r" % (rep["code"],)
    assert pc.current_version(fx["cfg"], fx["state_dir"]) == 1
    # Within the window (v1 -> v5) applies.
    os.remove(os.path.join(fx["feed_dir"], "agent-policy.v6.json"))
    _write_feed(fx["feed_dir"], _doc(5, fx["seed"]), 5)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is True and rep["version"] == 5, \
        "in-window skip refused: %r" % (rep,)
    _held("P1c-version-skip-refused", "skip bounded, in-window applies")


@probe("P1d-revoked-never-reapplied")
def _p1d():
    """A revoked version is never re-applied, even when served later."""
    fx = _fresh()
    pc = fx["channel"]
    _write_feed(fx["feed_dir"], _doc(1, fx["seed"]), 1)
    # v2 revokes v3 pre-emptively (v3 was published, then found bad).
    _write_feed(fx["feed_dir"], _doc(2, fx["seed"], revokes=[3]), 2)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is True and rep["version"] == 2
    _write_feed(fx["feed_dir"], _doc(3, fx["seed"]), 3)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is False, "revoked v3 applied: %r" % (rep,)
    assert rep["code"] == "policy-channel-superseded", \
        "wrong code: %r" % (rep["code"],)
    assert pc.current_version(fx["cfg"], fx["state_dir"]) == 2
    _held("P1d-revoked-never-reapplied", "revoked v3 refused superseded")


@probe("P1e-activation-atomic")
def _p1e():
    """Crash mid-activation: orphaned tmp is LOUD, old policy stays."""
    fx = _fresh()
    pc = fx["channel"]
    _write_feed(fx["feed_dir"], _doc(1, fx["seed"]), 1)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is True
    body_before = pc.current_body(fx["cfg"], fx["state_dir"])
    # Simulate a crash: an activation tmp left behind by a dead process.
    tmp = os.path.join(fx["state_dir"], ".policy-activate-orphan.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("partial")
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["code"] == "policy-channel-activation-failed", \
        "orphaned tmp not reported LOUD: %r" % (rep,)
    assert pc.current_version(fx["cfg"], fx["state_dir"]) == 1, \
        "version moved on failed activation"
    assert pc.current_body(fx["cfg"], fx["state_dir"]) == body_before, \
        "active policy changed on failed activation"
    assert not os.path.exists(tmp), "orphaned tmp not cleaned"
    _held("P1e-activation-atomic", "crash LOUD, old policy in force")


@probe("P1f-provenance-traceable")
def _p1f():
    """Applied policy cites the motivating knowledge; provenance traces."""
    fx = _fresh()
    pc = fx["channel"]
    mot = [{"origin": "osv.dev", "collector": "nightly-feed",
            "known_since": 1700000100}]
    _write_feed(fx["feed_dir"], _doc(1, fx["seed"], motivated_by=mot), 1)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is True
    assert rep["provenance"] == mot, "provenance not carried: %r" % (rep,)
    prov = pc.policy_provenance(fx["cfg"], fx["state_dir"], 1)
    assert prov == mot, "provenance query wrong: %r" % (prov,)
    _held("P1f-provenance-traceable", "version -> advisory traceable")


@probe("P1g-scanner-trigger-fires")
def _p1g():
    """The channel wire feeds the scanner's policy-change trigger."""
    fx = _fresh()
    pc = fx["channel"]
    from gov import background_scan
    _write_feed(fx["feed_dir"], _doc(1, fx["seed"]), 1)
    pc.poll(fx["cfg"], fx["state_dir"])
    wire_v1 = pc.current_wire(fx["cfg"], fx["state_dir"])
    _write_feed(fx["feed_dir"], _doc(2, fx["seed"]), 2)
    pc.poll(fx["cfg"], fx["state_dir"])
    wire_v2 = pc.current_wire(fx["cfg"], fx["state_dir"])
    # The scanner's best-effort version read works on our envelope.
    assert background_scan._delegation_version(wire_v1) == 1
    assert background_scan._delegation_version(wire_v2) == 2
    # And the version bump fires the policy-change trigger.
    rec = {"digest": "d", "delegations_version": 1,
           "scan_interval_seconds": 3600, "next_scan_at": 10**12}
    trigger, _missed, _total = background_scan._evaluate_triggers(
        rec, digest_now="d", deleg_version_now=2, now=10**12 - 1)
    assert trigger == "policy-change", "trigger=%r" % (trigger,)
    _held("P1g-scanner-trigger-fires", "policy bump -> policy-change trigger")


@probe("P1h-feed-escape-refused")
def _p1h():
    """A feed file that is a symlink outside the feed is refused coded."""
    fx = _fresh()
    pc = fx["channel"]
    outside = tempfile.NamedTemporaryFile(
        prefix="evil-", suffix=".json", delete=False)
    outside.write(json.dumps(_doc(1, fx["seed"])).encode("utf-8"))
    outside.close()
    link = os.path.join(fx["feed_dir"], "agent-policy.v1.json")
    os.symlink(outside.name, link)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is False, "escaped feed file applied: %r" % (rep,)
    assert rep["code"] == "policy-channel-feed-escape", \
        "wrong code: %r" % (rep["code"],)
    os.unlink(outside.name)
    _held("P1h-feed-escape-refused", "symlink escape refused coded")


@probe("P1i-unknown-policy-refused")
def _p1i():
    """A document for an unknown policy name is refused coded.

    Feed discovery only reads this channel's own files (other policies'
    files are not ours to judge); the refusal lives at the apply layer.
    """
    fx = _fresh()
    pc = fx["channel"]
    raw = json.dumps(_doc(1, fx["seed"], policy_name="other")).encode("utf-8")
    try:
        pc.apply_document(fx["cfg"], fx["state_dir"], raw)
    except pc.PolicyChannelError as exc:
        assert exc.code == "policy-channel-unknown-policy", \
            "wrong code: %r" % (exc.code,)
        assert pc.current_version(fx["cfg"], fx["state_dir"]) == 0
        _held("P1i-unknown-policy-refused", "unknown policy name refused")
        return
    _break("P1i-unknown-policy-refused", "unknown policy was applied")


@probe("P1j-malformed-refused")
def _p1j():
    """Malformed envelopes are refused coded, never applied."""
    fx = _fresh()
    pc = fx["channel"]
    bad = {"payload": "!!!not-base64!!!", "signature": "e30="}
    _write_feed(fx["feed_dir"], bad, 1)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is False
    assert rep["code"] == "policy-channel-malformed", \
        "wrong code: %r" % (rep["code"],)
    assert pc.current_version(fx["cfg"], fx["state_dir"]) == 0
    _held("P1j-malformed-refused", "malformed envelope refused coded")


@probe("P1k-stale-loud")
def _p1k():
    """Exceeding the staleness budget without refresh is a loud stale."""
    fx = _fresh()
    pc = fx["channel"]
    cfg = _config(fx["feed_dir"], fx["pub"], max_staleness_seconds=100)
    _write_feed(fx["feed_dir"], _doc(1, fx["seed"], issued_at=1700000000), 1)
    rep = pc.poll(cfg, fx["state_dir"], now=1700000000 + 50)
    assert rep["applied"] is True and rep["stale"] is False
    # No new version; budget exceeded -> LOUD stale, last verified served.
    rep = pc.poll(cfg, fx["state_dir"], now=1700000000 + 101)
    assert rep["stale"] is True, "stale not loud: %r" % (rep,)
    assert rep["code"] == "policy-channel-stale", \
        "wrong code: %r" % (rep["code"],)
    assert pc.current_version(cfg, fx["state_dir"]) == 1, \
        "stale verdict dropped the last verified policy"
    _held("P1k-stale-loud", "stale budget exceeded LOUD")


@probe("P1l-monotonic-happy-path")
def _p1l():
    """v1 -> v2 -> v3 apply in order; state pins the floor."""
    fx = _fresh()
    pc = fx["channel"]
    for v in (1, 2, 3):
        _write_feed(fx["feed_dir"], _doc(v, fx["seed"]), v)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is True and rep["version"] == 3, \
        "expected v3, got %r" % (rep,)
    assert pc.current_version(fx["cfg"], fx["state_dir"]) == 3
    body = pc.current_body(fx["cfg"], fx["state_dir"])
    assert body == {"rules": ["r3"]}, "wrong active body: %r" % (body,)
    _held("P1l-monotonic-happy-path", "v1->v2->v3 applied in order")


@probe("P1m-citation-mandatory")
def _p1m():
    """A policy without cited knowledge is refused coded."""
    fx = _fresh()
    pc = fx["channel"]
    _write_feed(fx["feed_dir"], _doc(1, fx["seed"], motivated_by=[]), 1)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is False, "citation-free policy applied: %r" % (rep,)
    assert rep["code"] == "policy-channel-malformed", \
        "wrong code: %r" % (rep["code"],)
    assert pc.current_version(fx["cfg"], fx["state_dir"]) == 0
    _held("P1m-citation-mandatory", "empty motivated_by refused")


@probe("P1n-crash-between-writes-heals-loud")
def _p1n():
    """Crash between active-replace and state-store heals forward LOUD."""
    fx = _fresh()
    pc = fx["channel"]
    _write_feed(fx["feed_dir"], _doc(1, fx["seed"]), 1)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is True
    # Simulate the crash: signed v2 wire is active, state still says v1.
    raw_v2 = json.dumps(_doc(2, fx["seed"])).encode("utf-8")
    active = os.path.join(fx["state_dir"], "active_policy.json")
    with open(active, "wb") as fh:
        fh.write(raw_v2)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["code"] == "policy-channel-activation-failed", \
        "crash not reported LOUD: %r" % (rep,)
    assert pc.current_version(fx["cfg"], fx["state_dir"]) == 2, \
        "state did not heal forward: %r" % (rep,)
    assert pc.current_body(fx["cfg"], fx["state_dir"]) == {"rules": ["r2"]}
    _held("P1n-crash-between-writes-heals-loud",
          "mid-activation crash healed forward LOUD")


@probe("P1o-noncanonical-refused")
def _p1o():
    """A correctly-signed but non-canonical payload is refused."""
    fx = _fresh()
    pc = fx["channel"]
    from gov import ed25519
    payload = {
        "schema": "sasanam-policy-document/v1",
        "policy_name": "agent-policy",
        "version": 1,
        "body": {"rules": ["r1"]},
        "revokes": [],
        "motivated_by": _mot(),
        "issued_at": 1700000000,
    }
    # Non-canonical encoding: spaces after separators.
    raw = json.dumps(payload, separators=(", ", ": ")).encode("utf-8")
    sig = ed25519.sign(fx["seed"], raw)
    env = {"payload": base64.b64encode(raw).decode("ascii"),
           "signature": base64.b64encode(sig).decode("ascii")}
    _write_feed(fx["feed_dir"], env, 1)
    rep = pc.poll(fx["cfg"], fx["state_dir"])
    assert rep["applied"] is False, "non-canonical applied: %r" % (rep,)
    assert rep["code"] == "policy-channel-malformed", \
        "wrong code: %r" % (rep["code"],)
    _held("P1o-noncanonical-refused", "non-canonical payload refused")


# ---------------------------------------------------------------------------
# P2: pin + footer state.
# ---------------------------------------------------------------------------

@probe("P2a-pin-taxonomy-2128")
def _p2a():
    from gov.decision_codes import TAXONOMY
    assert len(TAXONOMY) == TAXONOMY_PIN, \
        "taxonomy %d != pin %d" % (len(TAXONOMY), TAXONOMY_PIN)
    _held("P2a-pin-taxonomy-2128", "taxonomy matches pin")


@probe("P2b-footer-open-none-next-f427")
def _p2b():
    path = os.path.join(REPO, "evals", "FINDINGS.md")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    assert "Next free finding: **F427**" in text, "footer next-free wrong"
    assert "**Open findings: none.**" in text, "footer open set wrong"
    _held("P2b-footer-open-none-next-f427", "footer open none / next F427")


# ---------------------------------------------------------------------------
# Green checks (depth-1: children run with GOV_SKIP_GREEN=1).
# ---------------------------------------------------------------------------

def _green():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-skip", "HELD", "green checks skipped (child mode)")
        return
    import subprocess
    children = [["-m", "unittest", "tests.test_policy_channel", "-v"]]
    for child in children:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        try:
            proc = subprocess.run(
                [sys.executable] + child,
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=300)
            ok = proc.returncode == 0 and "OK" in (proc.stdout + proc.stderr)
            note = (proc.stdout + proc.stderr)[-500:]
        except Exception as exc:  # noqa: BLE001
            ok = False
            note = "%s" % (exc,)
        _record("green-" + ".".join(child[1:3]), "HELD" if ok else "BREAK",
                "%s: %s" % ("ok" if ok else "FAILED", note))


def main(argv):
    for name, fn in sorted(list(globals().items())):
        if name.startswith("_p") and callable(fn) and hasattr(fn, "__name__"):
            if fn.__name__.startswith("P"):
                fn()
    _green()
    breaks = sum(1 for _pid, v, _n in _results if v == "BREAK")
    held = sum(1 for _pid, v, _n in _results if v == "HELD")
    errors = sum(1 for _pid, v, _n in _results if v == "ERROR")
    print("w327_polchan battery: %d BREAK / %d HELD / %d ERROR" %
          (breaks, held, errors))
    for pid, verdict, note in _results:
        if verdict != "HELD":
            print("  [%s] %s: %s" % (verdict, pid, note))
    green_ok = all(v != "BREAK" and v != "ERROR"
                   for pid, v, _n in _results
                   if pid.startswith("green-") and pid != "green-skip")
    if not green_ok:
        print("GREEN CHECKS FAILED")
    return 1 if (breaks or errors or not green_ok) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
