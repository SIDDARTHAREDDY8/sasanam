"""Break-first probes for gov/witness_publish (wave-322 lane 3).

Red-first: on the open tree this battery dies at import
(ModuleNotFoundError: gov.witness_publish). On the lane tree every
attack below must refuse with the coded reason.

Staging default is set at module level (the harness refuses the
declared ungoverned_ack in production mode).
"""

import base64
import os
import re
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2088  # 1967 + 3 witness-publish-*/witness-checkpoint-*; Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 1: pin 2020 -> 2021 (+1 witness-alert-state-lost); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*)



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
# Fixtures.
# ---------------------------------------------------------------------------

SEED_OP = bytes(range(32))
SEED_W1 = bytes([255 - i for i in range(32)])
SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
SEED_W1_NEW = bytes([(i * 13) % 256 for i in range(32)])
SEED_EVIL = bytes([(i * 29 + 5) % 256 for i in range(32)])
ORIGIN = "sasanam-witpub-test/v1"
NOW = 1798765432


def _mod():
    from gov import witness_publish as wp
    from gov import checkpoint_note as cn
    from gov.witness_log import WitnessLog
    from gov.signing import Ed25519Signer
    return wp, cn, WitnessLog, Ed25519Signer


def _vkey(cn, name, signer):
    # Witness vkeys pin signature type 0x04 (cosignature/v1): the key
    # ID binds the type, so a 0x04 vkey differs from the same key's
    # 0x01 vkey. The operator vkey stays 0x01 (note-text signatures).
    return cn.vkey_string(
        name, cn.derive_key_id(name, cn.SIG_TYPE_ED25519_COSIGNATURE_V1,
                               signer.public_key),
        cn.SIG_TYPE_ED25519_COSIGNATURE_V1, signer.public_key)


def _op_vkey(cn, name, signer):
    return cn.vkey_string(
        name, cn.derive_key_id(name, cn.SIG_TYPE_ED25519,
                               signer.public_key),
        cn.SIG_TYPE_ED25519, signer.public_key)


def _world(sizes=(5,)):
    wp, cn, WitnessLog, Ed25519Signer = _mod()
    op = Ed25519Signer(SEED_OP)
    w1 = Ed25519Signer(SEED_W1)
    w2 = Ed25519Signer(SEED_W2)
    log = WitnessLog(op.public_key)
    for i in range(max(sizes)):
        log.append(b"leaf-%d" % i)
    op_vk = [_op_vkey(cn, "op", op)]
    wit_vk = {"w1": _vkey(cn, "w1", w1), "w2": _vkey(cn, "w2", w2)}
    return wp, cn, op, w1, w2, log, op_vk, wit_vk


def _publish(wp, log, op, w1, w2, op_vk, wit_vk, ts, quorum_k=2,
             origin=ORIGIN, signers=None):
    if signers is None:
        signers = [("w1", w1), ("w2", w2)]
    return wp.publish_checkpoint(
        log, origin, "op", op, signers, operator_vkeys=op_vk,
        witness_vkeys=wit_vk, quorum_k=quorum_k, timestamp=ts)


def _verify(wp, note, op_vk, wit_vk, quorum_k=2, origins=(ORIGIN,),
            now=NOW, max_age=3600, last_seen=None):
    return wp.verify_published_checkpoint(
        note, operator_vkeys=op_vk, witness_vkeys=wit_vk,
        quorum_k=quorum_k, allowed_origins=set(origins), now=now,
        max_age=max_age, last_seen=last_seen)


# ---------------------------------------------------------------------------
# P1: publish + verify round trip (the happy path holds).
# ---------------------------------------------------------------------------

@probe("P1-publish-verify-roundtrip")
def _p1():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    out = _verify(wp, note, op_vk, wit_vk,
                  last_seen=(5, log.root_hash()))
    assert out["tree_size"] == 5, out
    assert sorted(out["witnesses"]) == ["w1", "w2"], out
    assert out["origin"] == ORIGIN, out
    _held("P1-publish-verify-roundtrip",
          "5-leaf head published, quorum 2/2, verified")


# ---------------------------------------------------------------------------
# P2: forged operator signature -> witness-consistency-invalid.
# ---------------------------------------------------------------------------

@probe("P2-forged-operator-signature")
def _p2():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    body_root = base64.b64encode(log.root_hash()).decode("ascii")
    evil_root = base64.b64encode(bytes([9]) * 32).decode("ascii")
    forged = note.replace(body_root.encode("ascii"),
                          evil_root.encode("ascii"), 1)
    assert forged != note
    _expect_code("P2-forged-operator-signature",
                 lambda: _verify(wp, forged, op_vk, wit_vk),
                 "witness-consistency-invalid")


# ---------------------------------------------------------------------------
# P3: forged cosignature (matching key id, bad signature bytes) ->
# witness-cosignature-invalid. A different key under a configured name
# is IGNORED as unknown (MUST-ignore), tested in P3b.
# ---------------------------------------------------------------------------

def _tamper_cosig(note, witness_name):
    """Flip a byte in the named witness's signature (key id intact)."""
    lines = note.decode("utf-8").split("\n")
    out = []
    hit = False
    for ln in lines:
        parts = ln.split(" ")
        if len(parts) == 3 and parts[1] == witness_name and not hit:
            blob = base64.b64decode(parts[2])
            # cosignature/v1: keyID(4) || u64BE time(8) || sig(64)
            assert len(blob) == 76, len(blob)
            bad = bytearray(blob)
            bad[20] ^= 0xFF  # inside the signature, key id + time intact
            parts[2] = base64.b64encode(bytes(bad)).decode("ascii")
            ln = " ".join(parts)
            hit = True
        out.append(ln)
    assert hit, "witness line not found"
    return "\n".join(out).encode("utf-8")


@probe("P3-forged-cosignature")
def _p3():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    forged = _tamper_cosig(note, "w1")
    _expect_code("P3-forged-cosignature",
                 lambda: _verify(wp, forged, op_vk, wit_vk),
                 "witness-cosignature-invalid")


@probe("P3b-unknown-key-cosignature-ignored")
def _p3b():
    # A valid signature from a key that is NOT in the pinned set is
    # ignored per the signed-note collision rules (the rotation
    # enabler) -- the note still verifies on the pinned witnesses.
    from gov import witness_consistency as WC
    from gov.signing import Ed25519Signer
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    evil = Ed25519Signer(SEED_EVIL)
    note2 = WC.cosign_note_v1(note, "mallory", evil, timestamp=NOW - 100)
    out = _verify(wp, note2, op_vk, wit_vk)
    assert sorted(out["witnesses"]) == ["w1", "w2"], out
    _held("P3b-unknown-key-cosignature-ignored",
          "unknown-key line ignored, pinned quorum still verifies")


@probe("P3c-legacy-0x01-witness-line-ignored")
def _p3c():
    # A legacy 0x01 witness line (signature over the note text) under
    # a CONFIGURED name is an unknown key: the key ID binds the
    # signature type, so the 0x04-pinned vkey does not match it. It
    # neither verifies nor counts toward quorum (MUST-ignore across
    # signature types).
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100,
                    signers=[("w2", w2)], quorum_k=1)
    note_text = note.split(b"\n\n")[0]  # before the blank separator
    key_id = cn.derive_key_id("w1", cn.SIG_TYPE_ED25519, w1.public_key)
    sig = w1.sign(note_text)
    legacy = "— w1 %s\n" % base64.b64encode(key_id + sig).decode("ascii")
    mixed = note + legacy.encode("utf-8")
    out = _verify(wp, mixed, op_vk, wit_vk, quorum_k=1)
    assert out["witnesses"] == ["w2"], out
    _expect_code("P3c-legacy-0x01-witness-line-ignored",
                 lambda: _verify(wp, mixed, op_vk, wit_vk, quorum_k=2),
                 "witness-quorum-unmet")


# ---------------------------------------------------------------------------
# P4: below-threshold cosignatures -> witness-quorum-unmet.
# ---------------------------------------------------------------------------

@probe("P4-below-threshold-refused")
def _p4():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100,
                    signers=[("w1", w1)], quorum_k=1)
    _expect_code("P4-below-threshold-refused",
                 lambda: _verify(wp, note, op_vk, wit_vk, quorum_k=2),
                 "witness-quorum-unmet")


# ---------------------------------------------------------------------------
# P5: publish-time quorum shortfall -> witness-publish-quorum-unmet
# (fail-closed at the source, never published).
# ---------------------------------------------------------------------------

@probe("P5-publish-quorum-unmet")
def _p5():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    _expect_code("P5-publish-quorum-unmet",
                 lambda: _publish(wp, log, op, w1, w2, op_vk, wit_vk,
                                  NOW - 100, signers=[("w1", w1)],
                                  quorum_k=2),
                 "witness-publish-quorum-unmet")


# ---------------------------------------------------------------------------
# P6: rollback (smaller than last_seen) -> witness-publish-rollback.
# ---------------------------------------------------------------------------

@probe("P6-rollback-refused")
def _p6():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    _expect_code("P6-rollback-refused",
                 lambda: _verify(wp, note, op_vk, wit_vk,
                                 last_seen=(10, bytes([7]) * 32)),
                 "witness-publish-rollback")


# ---------------------------------------------------------------------------
# P7: equivocation (same size, different root) ->
# witness-consistency-fork-detected.
# ---------------------------------------------------------------------------

@probe("P7-equivocation-refused")
def _p7():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    _expect_code("P7-equivocation-refused",
                 lambda: _verify(wp, note, op_vk, wit_vk,
                                 last_seen=(5, bytes([7]) * 32)),
                 "witness-consistency-fork-detected")


# ---------------------------------------------------------------------------
# P8: malformed note -> witness-note-malformed.
# ---------------------------------------------------------------------------

@probe("P8-malformed-note")
def _p8():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    _expect_code("P8-malformed-note",
                 lambda: _verify(wp, b"this is not a checkpoint note\n",
                                 op_vk, wit_vk),
                 "witness-note-malformed")


# ---------------------------------------------------------------------------
# P9: unknown origin -> witness-checkpoint-unknown-origin.
# ---------------------------------------------------------------------------

@probe("P9-unknown-origin")
def _p9():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100,
                    origin="evil-log/v9")
    _expect_code("P9-unknown-origin",
                 lambda: _verify(wp, note, op_vk, wit_vk),
                 "witness-checkpoint-unknown-origin")


# ---------------------------------------------------------------------------
# P10: freshness -- stale and future timestamps refuse
# witness-checkpoint-stale.
# ---------------------------------------------------------------------------

@probe("P10a-stale-timestamp")
def _p10a():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 7200)
    _expect_code("P10a-stale-timestamp",
                 lambda: _verify(wp, note, op_vk, wit_vk,
                                 now=NOW, max_age=3600),
                 "witness-checkpoint-stale")


@probe("P10b-future-timestamp")
def _p10b():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW + 600)
    _expect_code("P10b-future-timestamp",
                 lambda: _verify(wp, note, op_vk, wit_vk,
                                 now=NOW, max_age=3600),
                 "witness-checkpoint-stale")


# ---------------------------------------------------------------------------
# P11: key rotation -- grace (old+new both verify) and drop (old alone
# no longer meets quorum) .
# ---------------------------------------------------------------------------

@probe("P11a-rotation-grace")
def _p11a():
    wp, cn, WitnessLog, Ed25519Signer = (_mod()[0], _mod()[1], _mod()[2],
                                         _mod()[3])
    op = Ed25519Signer(SEED_OP)
    w1 = Ed25519Signer(SEED_W1)
    w1n = Ed25519Signer(SEED_W1_NEW)
    w2 = Ed25519Signer(SEED_W2)
    log = WitnessLog(op.public_key)
    for i in range(5):
        log.append(b"leaf-%d" % i)
    op_vk = [_op_vkey(cn, "op", op)]
    # Overlap window: both the old and the new w1 key are pinned.
    wit_vk = {"w1": _vkey(cn, "w1", w1n),
              "w1-old": _vkey(cn, "w1-old", w1),
              "w2": _vkey(cn, "w2", w2)}
    note_new = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100,
                        signers=[("w1", w1n), ("w2", w2)])
    note_old = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100,
                        signers=[("w1-old", w1), ("w2", w2)])
    o1 = _verify(wp, note_new, op_vk, wit_vk)
    o2 = _verify(wp, note_old, op_vk, wit_vk)
    assert "w1" in o1["witnesses"] and "w1-old" in o2["witnesses"]
    _held("P11a-rotation-grace",
          "old and new keys both verify during the overlap window")


@probe("P11b-rotation-drop")
def _p11b():
    # After rotation the set pins only the new key: a checkpoint
    # cosigned by the OLD key alone no longer meets quorum. Publish
    # against the overlap set (so the checkpoint exists), then verify
    # against the post-rotation set.
    wp, cn, WitnessLog, Ed25519Signer = (_mod()[0], _mod()[1], _mod()[2],
                                         _mod()[3])
    op = Ed25519Signer(SEED_OP)
    w1 = Ed25519Signer(SEED_W1)
    w1n = Ed25519Signer(SEED_W1_NEW)
    w2 = Ed25519Signer(SEED_W2)
    log = WitnessLog(op.public_key)
    for i in range(5):
        log.append(b"leaf-%d" % i)
    op_vk = [_op_vkey(cn, "op", op)]
    wit_vk_both = {"w1": _vkey(cn, "w1", w1n),
                   "w1-old": _vkey(cn, "w1-old", w1),
                   "w2": _vkey(cn, "w2", w2)}
    wit_vk_new = {"w1": _vkey(cn, "w1", w1n),
                  "w2": _vkey(cn, "w2", w2)}
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk_both, NOW - 100,
                    signers=[("w1-old", w1)], quorum_k=1)
    _expect_code("P11b-rotation-drop",
                 lambda: _verify(wp, note, op_vk, wit_vk_new,
                                 quorum_k=2),
                 "witness-quorum-unmet")


# ---------------------------------------------------------------------------
# P12: determinism -- identical inputs give byte-identical notes.
# ---------------------------------------------------------------------------

@probe("P12-deterministic-emission")
def _p12():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    a = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    b = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    assert a == b, "same head+timestamp must give identical bytes"
    _held("P12-deterministic-emission",
          "%d bytes, byte-identical across runs" % (len(a),))


# ---------------------------------------------------------------------------
# P13: endpoint contract -- exact production shape.
# ---------------------------------------------------------------------------

@probe("P13-endpoint-contract")
def _p13():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    c = wp.endpoint_contract(note)
    assert c["method"] == "GET", c
    assert c["path"] == "/checkpoint", c
    assert c["content_type"] == "text/plain; charset=utf-8", c
    assert c["cache_control"] == "no-cache", c
    import hashlib
    assert c["note_sha256"] == hashlib.sha256(note).hexdigest(), c
    assert c["etag"] == '"%s"' % (c["note_sha256"],), c
    _held("P13-endpoint-contract", "GET /checkpoint, exact headers")


# ---------------------------------------------------------------------------
# P14: static-file writer -- atomic, byte-identical, no residue.
# ---------------------------------------------------------------------------

@probe("P14-atomic-file-write")
def _p14():
    wp, cn, op, w1, w2, log, op_vk, wit_vk = _world()
    note = _publish(wp, log, op, w1, w2, op_vk, wit_vk, NOW - 100)
    d = tempfile.mkdtemp(prefix="witpub-")
    p = os.path.join(d, "checkpoint")
    wp.write_checkpoint_file(note, p)
    with open(p, "rb") as fh:
        assert fh.read() == note, "written bytes must match"
    leftovers = [f for f in os.listdir(d) if f.endswith(".tmp")]
    assert not leftovers, leftovers
    _held("P14-atomic-file-write", "byte-identical, no tmp residue")


# ---------------------------------------------------------------------------
# P15: regressions -- pin taxonomy + footer state.
# ---------------------------------------------------------------------------

@probe("P15-pin-taxonomy-2088-sorted")


def _p15():
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code":\s*\'([^\']+)\'', src)
    lits += re.findall(r'"code":\s*"([^"]+)"', src)
    ok = (len(lits) == TAXONOMY_PIN == 2088#Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*)
          and lits == sorted(lits) and len(set(lits)) == len(lits))
    if ok:
        _held("P15-pin-taxonomy-2088-sorted", "2088/2088/0 sorted")
    else:
        _break("P15-pin-taxonomy-2088-sorted",


               "got %d literals" % (len(lits),))


@probe("P15-footer-state")
def _p15b():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    # The footer is the LAST such line; history lines carry older
    # states and must not match.
    opens = re.findall(r"Open findings: ([A-Za-z0-9, ]*)\.", text)
    nexts = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
    if opens and nexts and opens[-1] == "F412" and nexts[-1] == "F413":
        _held("P15-footer-state", "open F412 / next F413")
    else:
        _break("P15-footer-state", "footer=%r next=%r"
               % (opens[-1] if opens else None,
                  nexts[-1] if nexts else None))


# ---------------------------------------------------------------------------
# Green check (depth-1): adjacent batteries, GOV_SKIP_GREEN honored.
# ---------------------------------------------------------------------------

# Child-mode tallies (GOV_SKIP_GREEN=1): the green check spawns each
# battery with green checks skipped, so expectations are the
# probes-only + green-skipped-row counts -- NOT the parent-with-green
# numbers (wave-321 lane-3 tally lesson).
GREEN_EVALS = [
    ("w321-sigstore", "evals/w321_sigstore_probes.py", (0, 20, 0)),
    ("w321-oci", "evals/w321_oci_probes.py", (0, 9, 0)),
    ("w321-redteam", "evals/w321_redteam_probes.py", (0, 36, 0)),
    ("w320-redteam", "evals/w320_redteam_probes.py", (0, 25, 0)),
]


def _run_green_eval(name, rel, expect):
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="w322-gc-")
    try:
        p = subprocess.run(
            [sys.executable, os.path.join(REPO, rel)],
            env=env, capture_output=True, text=True, timeout=900)
    except Exception as e:  # noqa: BLE001
        return (name, "ERROR", "spawn failed: %r" % (e,))
    out = p.stdout + p.stderr
    m = re.search(r"(\d+)\s+BREAK\s*/\s*(\d+)\s+HELD\s*/\s*(\d+)\s+ERROR",
                  out)
    if not m:
        m = re.search(r"(\d+)\s+HELD\s*/\s*(\d+)\s+BREAK\s*/\s*(\d+)\s+ERROR",
                      out)
        if m:
            got = (int(m.group(2)), int(m.group(1)), int(m.group(3)))
        else:
            return (name, "ERROR", "no summary parsed")
    else:
        got = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if got == expect:
        return (name, "HELD", "%d/%d/%d" % got)
    return (name, "BREAK", "got %d/%d/%d want %d/%d/%d"
            % (got + expect))


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-skipped",
                "HELD", "green check skipped (GOV_SKIP_GREEN=1)")
        return
    for name, rel, expect in GREEN_EVALS:
        n, v, note = _run_green_eval(name, rel, expect)
        _record("green-" + n, v, note)


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    # Probes are the @probe-decorated functions: the decorator rebinds
    # __name__ to the probe id, so a helper (whose __name__ still
    # matches its global name) is never picked up.
    probes = [(v.__name__, v) for k, v in globals().items()
              if callable(v) and getattr(v, "__name__", k) != k]
    for pid, fn in sorted(probes):
        if only is not None and pid != only:
            continue
        fn()
    if only is None:
        green_check()
    breaks = errors = 0
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "ERROR":
            errors += 1
    print("w322_witpub battery: %d BREAK / %d HELD / %d ERROR "
          % (breaks, len(_results) - breaks - errors, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
