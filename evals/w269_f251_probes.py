"""Break-first closure battery for F251.

F251 (LOW): peer-attestation TOFU bindings do not survive a restart --
``PeerAttestationTable.__init__`` opens the durable journal but never
replays it, so a post-restart ``register_peer`` for an already-bound
peer id (or a bound anchor key) SUCCEEDS silently: no
``federation-double-join``, no incident, and the legitimate owner's
later re-registration is the one refused (confused attribution).

Red phase: run this battery against the pristine wave-268 merge tree --
the ``restart/*`` probes BREAK (genuine F251 evidence). Green phase:
after the replay-on-init fix, all probes HELD, in staging AND under
``env -u GOV_DEPLOYMENT_MODE``.

Stdlib only. Deterministic (fixed key seeds, explicit ``now`` values).
Depth-1 green check honoring GOV_SKIP_GREEN=1. No in-repo git
subprocesses.
"""

import hashlib
import json
import os
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import ed25519  # noqa: E402
from gov import peer_attestation as pa  # noqa: E402

TAXONOMY_PIN = 1990 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)
assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (
    "taxonomy pin drift: %d != %d"
    % (len(decision_codes.TAXONOMY), TAXONOMY_PIN))

PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


# ---------------------------------------------------------------- helpers

def _seed(tag):
    """Deterministic 32-byte seed (no os.urandom in probes)."""
    return hashlib.sha256(b"w269-f251-" + tag.encode("utf-8")).digest()


def _keys(tag):
    seed = _seed(tag)
    return seed, ed25519.publickey(seed).hex()


def _scratch(prefix):
    base = "/var/tmp"
    os.makedirs(base, exist_ok=True)
    return tempfile.mkdtemp(prefix=prefix, dir=base)


def _table(td, **kw):
    return pa.PeerAttestationTable(
        os.path.join(td, "journal.db"), "example.com", **kw)


def _possession_sig(seed, nonce_hex, peer_id):
    msg = (b"sasanam-peer-possession/v1:" + bytes.fromhex(nonce_hex)
           + b":" + peer_id.encode("utf-8"))
    return ed25519.sign(seed, msg)


def _incidents(td):
    """Raw journal records of type peer-double-join-incident."""
    path = os.path.join(td, "journal.db")
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("type") == "peer-double-join-incident":
                out.append(rec)
    return out


def _refuses(fn, code):
    """Run fn; return (True, detail) iff it refuses with `code`."""
    try:
        fn()
    except pa.PeerAttestationError as exc:
        if exc.code == code:
            return True, "refused %s" % (code,)
        return False, "wrong code %r (want %r)" % (exc.code, code)
    except Exception as exc:  # never mask a crash
        return False, "raised %r" % (exc,)
    return False, "silently accepted"


# ---------------------------------------------------------------- probes

@probe
def restart_peer_id_double_join_refused():
    """F251 close-when (1): post-restart re-registration of a bound
    peer id refuses federation-double-join."""
    _, anchor_a = _keys("alice")
    _, attacker_anchor = _keys("attacker")
    td = _scratch("g269-f251-")
    t1 = _table(td)
    t1.register_peer("alice", anchor_a, now=1000)
    t2 = _table(td)  # simulated restart: new table, same journal
    ok, why = _refuses(
        lambda: t2.register_peer("alice", attacker_anchor, now=2000),
        "federation-double-join")
    return "HELD" if ok else "BREAK(%s)" % (why,)


@probe
def restart_anchor_key_reuse_refused():
    """F251 close-when (1): post-restart reuse of a bound anchor key
    under a different peer id refuses federation-double-join."""
    _, anchor_a = _keys("alice")
    td = _scratch("g269-f251-")
    t1 = _table(td)
    t1.register_peer("alice", anchor_a, now=1000)
    t2 = _table(td)
    ok, why = _refuses(
        lambda: t2.register_peer("mallory", anchor_a, now=2000),
        "federation-double-join")
    return "HELD" if ok else "BREAK(%s)" % (why,)


@probe
def restart_double_join_incident_loud():
    """F251 close-when (1)+(5): the post-restart refusal journals a
    LOUD incident naming the correct party (bound victim as
    bound_peer_id, attacker's key as presented_anchor -- no confused
    victim-as-attacker attribution)."""
    _, anchor_a = _keys("alice")
    _, attacker_anchor = _keys("attacker")
    td = _scratch("g269-f251-")
    t1 = _table(td)
    t1.register_peer("alice", anchor_a, now=1000)
    t2 = _table(td)
    try:
        t2.register_peer("alice", attacker_anchor, now=2000)
    except pa.PeerAttestationError:
        pass
    incidents = _incidents(td)
    if not incidents:
        return "BREAK(no incident journaled)"
    body = incidents[-1]["body"]
    if body.get("security_incident") is not True:
        return "BREAK(incident not marked security_incident)"
    if body.get("kind") != "peer-id-rebind":
        return "BREAK(kind %r)" % (body.get("kind"),)
    if body.get("bound_peer_id") != "alice":
        return "BREAK(bound_peer_id %r)" % (body.get("bound_peer_id"),)
    if body.get("presented_anchor") != attacker_anchor:
        return "BREAK(presented_anchor mismatch)"
    return "HELD"


@probe
def restart_ban_survives():
    """F251 close-when (2): bans survive restart --
    federation-peer-banned on post-restart registration."""
    _, anchor_a = _keys("alice")
    _, anchor_b = _keys("alice-new")
    td = _scratch("g269-f251-")
    t1 = _table(td)
    t1.register_peer("alice", anchor_a, now=1000)
    t1.ban_peer("alice", "sybil probe", now=1100)
    t2 = _table(td)
    if not t2.is_banned("alice"):
        return "BREAK(is_banned False after restart)"
    ok, why = _refuses(
        lambda: t2.register_peer("alice", anchor_b, now=2000),
        "federation-peer-banned")
    return "HELD" if ok else "BREAK(%s)" % (why,)


@probe
def restart_remove_then_reregister():
    """F251 close-when (3): peer-removed replays correctly --
    post-removal re-registration under a new key SUCCEEDS (no phantom
    binding), and the new binding is a real TOFU binding."""
    _, anchor_a = _keys("alice")
    _, anchor_b = _keys("alice-new")
    _, anchor_c = _keys("alice-third")
    td = _scratch("g269-f251-")
    t1 = _table(td)
    t1.register_peer("alice", anchor_a, now=1000)
    t1.remove_peer("alice", now=1200)
    t2 = _table(td)
    try:
        res = t2.register_peer("alice", anchor_b, now=2100)
    except Exception as exc:
        return "BREAK(reregister raised %r)" % (exc,)
    if not res.get("registered"):
        return "BREAK(reregister did not confirm)"
    # The new binding must be a genuine TOFU binding: a third key for
    # the same peer id now refuses double-join.
    ok, why = _refuses(
        lambda: t2.register_peer("alice", anchor_c, now=2200),
        "federation-double-join")
    return "HELD" if ok else "BREAK(new binding not enforced: %s)" % (why,)


@probe
def restart_identity_mapping_survives():
    """Identity mapping replays: post-restart peer_record carries the
    deployment-authored identities (attestation can still select)."""
    _, anchor_a = _keys("alice")
    td = _scratch("g269-f251-")
    t1 = _table(td)
    t1.register_peer("alice", anchor_a, now=1000)
    t1.author_identity("alice", ["spiffe://example.com/agent"])
    t2 = _table(td)
    rec = t2.peer_record("alice")
    if rec is None:
        return "BREAK(peer record missing after restart)"
    if rec["identities"] != ["spiffe://example.com/agent"]:
        return "BREAK(identities %r)" % (rec["identities"],)
    if rec["anchor_public_key"] != anchor_a:
        return "BREAK(anchor key mismatch after restart)"
    return "HELD"


@probe
def restart_attest_after_restart():
    """Post-restart attestation still works end to end: binding +
    mapping + possession replayed correctly."""
    seed_a, anchor_a = _keys("alice")
    td = _scratch("g269-f251-")
    t1 = _table(td)
    t1.register_peer("alice", anchor_a, now=1000)
    t1.author_identity("alice", ["spiffe://example.com/agent"])
    t2 = _table(td)
    ch = t2.issue_challenge("alice", now=2000)
    sig = _possession_sig(seed_a, ch["nonce"], "alice")
    try:
        res = t2.attest("alice", "spiffe://example.com/agent",
                        ch["nonce"], sig, now=2100)
    except Exception as exc:
        return "BREAK(attest raised %r)" % (exc,)
    if not res.get("attested"):
        return "BREAK(attest did not confirm)"
    return "HELD"


@probe
def restart_fresh_journal_empty():
    """Replay on a nonexistent journal is a no-op: no phantom state."""
    td = _scratch("g269-f251-")
    t = _table(td)
    if t.peer_record("nobody") is not None:
        return "BREAK(phantom peer record)"
    if t.is_banned("nobody"):
        return "BREAK(phantom ban)"
    return "HELD"


@probe
def regression_within_process_double_join():
    """Control: in-memory TOFU behavior unchanged by the fix."""
    _, anchor_a = _keys("alice")
    _, attacker_anchor = _keys("attacker")
    td = _scratch("g269-f251-")
    t = _table(td)
    t.register_peer("alice", anchor_a, now=1000)
    ok, why = _refuses(
        lambda: t.register_peer("alice", attacker_anchor, now=1100),
        "federation-double-join")
    return "HELD" if ok else "BREAK(%s)" % (why,)


@probe
def pin_taxonomy_1299():
    """This lane mints no new decision codes."""
    n = len(decision_codes.TAXONOMY)
    if n != TAXONOMY_PIN:
        return "BREAK(pin %d != %d)" % (n, TAXONOMY_PIN)
    return "HELD"


def _run_w268_restart_probe():
    """Run the w268 red-team battery depth-1 and check its standing
    F251 regression pin (federation/restart-tofu-race) HELDs."""
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    td = _scratch("g269-f251-green-")
    env["TMPDIR"] = td
    cmd = [sys.executable, "evals/w268_redteam_probes.py"]
    r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                       text=True, timeout=600)
    out = r.stdout + r.stderr
    for line in out.splitlines():
        if line.startswith("federation/restart-tofu-race"):
            if "HELD" in line:
                return "HELD"
            return "BREAK(%s)" % (line.strip(),)
    return "BREAK(probe line not found)"


@probe
def regression_w268_restart_tofu_race():
    """F251 close-when (4b): the w268 red-team standing regression pin
    HELDs post-fix."""
    return _run_w268_restart_probe()


def green_check():
    """Depth-1 adjacent check: w267_peerattest_probes with
    GOV_SKIP_GREEN=1 in the child env. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    td = _scratch("g269-f251-green-")
    env["TMPDIR"] = td
    cmd = [sys.executable, "evals/w267_peerattest_probes.py"]
    r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                       text=True, timeout=900)
    out = r.stdout + r.stderr
    import re
    brk = len(re.findall(r"(?m)^BREAK", out))
    err = len(re.findall(r"(?m)^ERROR", out))
    if r.returncode == 0 and brk == 0 and err == 0:
        print("GREEN CHECK: w267_peerattest_probes green")
        return True
    print("GREEN CHECK FAILED: w267_peerattest_probes "
          "(BREAK=%s ERROR=%s)" % (brk, err))
    print(out[-1500:])
    return False


@probe
def adjacent_w267_peerattest_green():
    """F251 close-when (4a): adjacent w267 battery stays green."""
    if green_check():
        return "HELD"
    return "BREAK(adjacent battery red)"


def main():
    results = []
    for p in PROBES:
        try:
            results.append((p.__name__, p()))
        except Exception as exc:  # never mask a crash
            results.append((p.__name__, "BREAK(%r)" % (exc,)))
    held = sum(1 for _, v in results if v == "HELD")
    brk = sum(1 for _, v in results if v.startswith("BREAK"))
    for name, verdict in results:
        print("%-38s %s" % (name, verdict))
    print("HELD %d / BREAK %d of %d" % (held, brk, len(results)))
    return 1 if brk else 0


if __name__ == "__main__":
    sys.exit(main())
