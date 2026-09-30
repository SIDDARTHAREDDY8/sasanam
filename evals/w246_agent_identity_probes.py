#!/usr/bin/env python3
"""Wave-246 lane 7: did:key identity + ledger-recomputable reputation probes.

W246-7 (Kredent shape, patterns only): inter-agent identity today is
deployment-issued (gov/agent_identity.py KeyIssuanceRegistry) -- agents
cannot self-assert a stable, key-derived identity, and reputation is not
a pure function of a signed ledger. This battery pins the new
did:key-style primitive and the reputation ledger:

  did:key (gov/agent_identity.py, new section):
    distinct-keys-distinct-ids -- two keys resolve to different ids
    resolve-deterministic -- same key resolves to the same id twice
    valid-binding-accepted -- good signature verifies (is True)
    forged-binding-refused -- forged signature -> False (is False)
    malformed-did-fails-closed -- garbage did -> False, parse raises
    wrong-method-refused -- did:example:... -> method-unsupported
    truncated-payload-refused -- short key payload -> malformed
    base58-round-trip -- leading-zero bytes survive encode/decode

  reputation ledger (gov/reputation_ledger.py, new module):
    reputation-recomputes-equal -- claimed == recomputed from ledger
    ledger-tamper-diverges -- flipped weight -> import refuses
        reputation-ledger-tampered
    signature-tamper-refused -- corrupted sig -> import refuses
    chain-break-refused -- broken prev linkage -> refuses
    event-kind-unknown-refused -- unknown kind -> refused
    entry-malformed-refused -- missing fields -> refused
    export-import-round-trip -- export -> import keeps head+scores
    reporter-key-mismatch-refused -- sig by key != reporter did -> refused

Red-first: on pristine base both capabilities are absent and every probe
reports GAP. Stdlib only. Deterministic (fixed seeds, no randomness).
No in-repo git subprocesses.
"""

import hashlib
import json
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_DIDKEY = False
HAVE_REPLEDGER = False
_ai = None
_rl = None
try:
    from gov import agent_identity as _ai
    HAVE_DIDKEY = all(hasattr(_ai, n) for n in (
        "did_key_from_pubkey", "pubkey_from_did_key", "resolve",
        "verify_binding", "DidKeyError", "b58encode", "b58decode"))
except ImportError:
    _ai = None
try:
    from gov import reputation_ledger as _rl
    HAVE_REPLEDGER = all(hasattr(_rl, n) for n in (
        "ReputationLedger", "ReputationLedgerError", "make_event",
        "sign_event", "compute_reputation"))
except ImportError:
    _rl = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "distinct-keys-distinct-ids",
    "resolve-deterministic",
    "valid-binding-accepted",
    "forged-binding-refused",
    "malformed-did-fails-closed",
    "wrong-method-refused",
    "truncated-payload-refused",
    "base58-round-trip",
    "reputation-recomputes-equal",
    "ledger-tamper-diverges",
    "signature-tamper-refused",
    "chain-break-refused",
    "event-kind-unknown-refused",
    "entry-malformed-refused",
    "export-import-round-trip",
    "reporter-key-mismatch-refused",
]


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _seed(label):
    return hashlib.sha256(("w246-lane7:" + label).encode()).digest()


def _pubkey(seed):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gov"))
    from gov import ed25519 as _ed
    return _ed.publickey(seed)


def _sign(seed, msg):
    from gov import ed25519 as _ed
    return _ed.sign(seed, msg)


# --- did:key probes -----------------------------------------------------

def _probe_distinct_keys_distinct_ids():
    a = _ai.resolve(_pubkey(_seed("agent-a")))
    b = _ai.resolve(_pubkey(_seed("agent-b")))
    assert a != b, "two keys resolved to the same id: %s" % a
    assert a.startswith("did:key:z"), a
    assert b.startswith("did:key:z"), b
    return "distinct keys -> distinct did:key ids"


def _probe_resolve_deterministic():
    pub = _pubkey(_seed("agent-a"))
    assert _ai.resolve(pub) == _ai.resolve(pub), "resolve not deterministic"
    assert _ai.resolve(pub) == _ai.did_key_from_pubkey(pub)
    return "resolve is deterministic"


def _probe_valid_binding_accepted():
    seed = _seed("agent-a")
    did = _ai.resolve(_pubkey(seed))
    msg = b"hello governance"
    sig = _sign(seed, msg)
    result = _ai.verify_binding(did, msg, sig)
    assert result is True, "valid binding did not verify (got %r)" % (result,)
    return "valid signature verifies (is True)"


def _probe_forged_binding_refused():
    seed = _seed("agent-a")
    other = _seed("agent-b")
    did = _ai.resolve(_pubkey(seed))
    msg = b"hello governance"
    forged = _sign(other, msg)
    result = _ai.verify_binding(did, msg, forged)
    assert result is False, "forged binding verified (got %r)" % (result,)
    # wrong message, right key
    sig = _sign(seed, msg)
    result2 = _ai.verify_binding(did, b"tampered", sig)
    assert result2 is False, "wrong-message binding verified"
    return "forged/wrong-message bindings return False (is False)"


def _probe_malformed_did_fails_closed():
    for bad in ("", "not-a-did", "did:key:", "did:key:zzz",
                "did:key:z!invalid*chars", None, 123, b"did:key:zabc"):
        result = _ai.verify_binding(bad, b"m", b"\x00" * 64)
        assert result is False, "malformed did accepted: %r" % (bad,)
    try:
        _ai.pubkey_from_did_key("not-a-did")
    except _ai.DidKeyError as exc:
        assert exc.code == "did-key-malformed", exc.code
    else:
        raise AssertionError("malformed did parsed without error")
    return "malformed dids fail closed (False / DidKeyError)"


def _probe_wrong_method_refused():
    try:
        _ai.pubkey_from_did_key("did:example:1234")
    except _ai.DidKeyError as exc:
        assert exc.code == "did-key-method-unsupported", exc.code
    else:
        raise AssertionError("non-key method parsed without error")
    result = _ai.verify_binding("did:example:1234", b"m", b"\x00" * 64)
    assert result is False
    return "non-did:key methods refused"


def _probe_truncated_payload_refused():
    short = _ai.b58encode(b"\xed\x01" + b"\x00" * 10)
    try:
        _ai.pubkey_from_did_key("did:key:z" + short)
    except _ai.DidKeyError as exc:
        assert exc.code == "did-key-malformed", exc.code
    else:
        raise AssertionError("truncated payload parsed without error")
    # wrong multicodec prefix (not ed25519-pub)
    wrong = _ai.b58encode(b"\x12\x20" + b"\x00" * 32)
    try:
        _ai.pubkey_from_did_key("did:key:z" + wrong)
    except _ai.DidKeyError as exc:
        assert exc.code == "did-key-malformed", exc.code
    else:
        raise AssertionError("non-ed25519 multicodec parsed without error")
    return "truncated/wrong-type payloads refused"


def _probe_base58_round_trip():
    for raw in (b"", b"\x00", b"\x00\x00\x01\x02", b"\xed\x01" + b"\xff" * 32,
                bytes(range(32))):
        assert _ai.b58decode(_ai.b58encode(raw)) == raw, raw
    try:
        _ai.b58decode("0OIl")  # chars outside the btc alphabet
    except _ai.DidKeyError as exc:
        assert exc.code == "did-key-malformed", exc.code
    else:
        raise AssertionError("bad base58 alphabet accepted")
    return "base58 round-trips incl. leading zeros; bad alphabet refused"


# --- reputation ledger probes --------------------------------------------

def _build_ledger():
    seeds = {"alice": _seed("alice"), "bob": _seed("bob"),
             "carol": _seed("carol")}
    dids = {n: _ai.resolve(_pubkey(s)) for n, s in seeds.items()}
    ledger = _rl.ReputationLedger()
    events = [
        ("alice", "bob", "attestation-positive", "vouched onboarding"),
        ("alice", "carol", "attestation-positive", "second vouch"),
        ("bob", "alice", "attestation-negative", "missed checkpoint"),
        ("alice", "carol", "incident-confirmed", "key misuse"),
        ("alice", "bob", "recovery-verified", "rotated key, re-audit"),
    ]
    for subj, rep, kind, detail in events:
        ev = _rl.make_event(ledger.next_seq(), dids[subj], dids[rep],
                            kind, detail, ledger.head_digest())
        ledger.append(_rl.sign_event(ev, seeds[rep]))
    return ledger, dids


def _probe_reputation_recomputes_equal():
    ledger, dids = _build_ledger()
    claimed = ledger.reputation_for(dids["alice"])
    recomputed = _rl.compute_reputation(ledger.entries(), dids["alice"])
    assert claimed == recomputed, (claimed, recomputed)
    # expected: +1 +1 -5 +3 = 0
    assert claimed == 0, "unexpected score %d" % claimed
    assert ledger.reputation_for(dids["bob"]) == -2
    return "claimed == recomputed; scores match hand computation"


def _probe_ledger_tamper_diverges():
    ledger, dids = _build_ledger()
    blob = json.loads(ledger.export().decode())
    blob["entries"][3]["kind"] = "attestation-positive"  # was incident
    tampered = json.dumps(
        blob, sort_keys=True, separators=(",", ":")).encode()
    try:
        _rl.ReputationLedger.import_bytes(tampered)
    except _rl.ReputationLedgerError as exc:
        assert exc.code == "reputation-ledger-tampered", exc.code
    else:
        raise AssertionError("tampered ledger imported without error")
    return "flipped event kind -> reputation-ledger-tampered"


def _probe_signature_tamper_refused():
    ledger, _dids = _build_ledger()
    blob = json.loads(ledger.export().decode())
    sig = blob["entries"][0]["sig"]
    blob["entries"][0]["sig"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    tampered = json.dumps(
        blob, sort_keys=True, separators=(",", ":")).encode()
    try:
        _rl.ReputationLedger.import_bytes(tampered)
    except _rl.ReputationLedgerError as exc:
        assert exc.code in ("reputation-ledger-tampered",
                            "did-key-binding-invalid"), exc.code
    else:
        raise AssertionError("corrupted signature imported without error")
    return "corrupted signature refused on import"


def _probe_chain_break_refused():
    ledger, _dids = _build_ledger()
    blob = json.loads(ledger.export().decode())
    blob["entries"][2]["prev"] = "00" * 32
    tampered = json.dumps(
        blob, sort_keys=True, separators=(",", ":")).encode()
    try:
        _rl.ReputationLedger.import_bytes(tampered)
    except _rl.ReputationLedgerError as exc:
        assert exc.code == "reputation-ledger-tampered", exc.code
    else:
        raise AssertionError("broken chain imported without error")
    return "broken prev linkage -> reputation-ledger-tampered"


def _probe_event_kind_unknown_refused():
    ledger, dids = _build_ledger()
    ev = _rl.make_event(ledger.next_seq(), dids["alice"], dids["bob"],
                        "super-endorsement", "x", ledger.head_digest())
    try:
        ledger.append(_rl.sign_event(ev, _seed("bob")))
    except _rl.ReputationLedgerError as exc:
        assert exc.code == "reputation-event-kind-unknown", exc.code
    else:
        raise AssertionError("unknown kind appended without error")
    return "unknown event kind refused"


def _probe_entry_malformed_refused():
    ledger, _dids = _build_ledger()
    for bad in ({"seq": 99}, {"seq": "x"}, None, "nope", []):
        try:
            ledger.append(bad)
        except _rl.ReputationLedgerError as exc:
            assert exc.code in ("reputation-entry-malformed",
                                "reputation-ledger-tampered"), exc.code
        else:
            raise AssertionError("malformed entry appended: %r" % (bad,))
    return "malformed entries fail closed"


def _probe_export_import_round_trip():
    ledger, dids = _build_ledger()
    clone = _rl.ReputationLedger.import_bytes(ledger.export())
    assert clone.head_digest() == ledger.head_digest()
    for name, did in dids.items():
        assert (clone.reputation_for(did)
                == ledger.reputation_for(did)), name
    return "export/import preserves head digest and all scores"


def _probe_reporter_key_mismatch_refused():
    ledger, dids = _build_ledger()
    # event claims reporter=bob but is signed by carol's key
    ev = _rl.make_event(ledger.next_seq(), dids["alice"], dids["bob"],
                        "attestation-positive", "lie", ledger.head_digest())
    try:
        ledger.append(_rl.sign_event(ev, _seed("carol")))
    except _rl.ReputationLedgerError as exc:
        assert exc.code in ("did-key-binding-invalid",
                            "reputation-ledger-tampered"), exc.code
    else:
        raise AssertionError("reporter/key mismatch appended")
    return "signature by non-reporter key refused"


_PROBES = {
    name: (globals()["_probe_" + name.replace("-", "_")],
           HAVE_DIDKEY if i < 8 else HAVE_REPLEDGER)
    for i, name in enumerate(PROBE_NAMES)
}


def _run_green_checks():
    """Depth-1 green checks (never spawns another battery's main).

    Honors GOV_SKIP_GREEN=1 (never spawns another battery's main).
    """
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    import subprocess  # noqa: PLC0415
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    root = os.path.join(os.path.dirname(__file__), "..")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_agent_identity", "-v"],
        cwd=root, env=env, capture_output=True, text=True, timeout=300)
    notes.append("unit tests.test_agent_identity rc=%d"
                 % (proc.returncode,))
    if proc.returncode != 0:
        notes.append("unit tail: %s" % (proc.stderr[-400:],))
    return notes


def main():
    print("wave-246 agent-identity probes (did:key=%s, repledger=%s)"
          % (HAVE_DIDKEY, HAVE_REPLEDGER))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-38s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
