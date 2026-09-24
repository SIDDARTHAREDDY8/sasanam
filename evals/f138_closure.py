"""F138 closure probes: roster-human authorship + chained pin records.

Proves the fix for F138 (filed 2026-09-23): wall re-pinning now
requires a load-gate-style roster-human Ed25519 authorship token bound
to the newly pinned digest, and every pin appends a chained pin record
(each record links to the previous, so history cannot be rewritten
silently).

Expected: every probe CLOSED (attack refused / legitimate pin
accepted), CONTROL holds. Any BREAK/ERROR reopens F138.

Run: TMPDIR=/tmp/gov-f138-<pid> ~/workspace/.gov-venv/bin/python evals/f138_closure.py
"""

import json
import os
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.delegation_tokens import DelegationTrust  # noqa: E402
from gov.ed25519 import generate_seed  # noqa: E402
from gov.egress_launcher import (  # noqa: E402
    EgressLaunchRefused,
    FilteredEgressLauncher,
    SimulatedWallFixture,
    SimulatedWallProvider,
    WallComponentInventory,
    WallPinRefused,
    install_simulated_wall,
    repin_after_fixture_fixup,
)
from gov.signing import Ed25519Signer  # noqa: E402


def _tmpdir():
    base = os.environ.get("TMPDIR", "/tmp")
    return tempfile.mkdtemp(prefix="f138closure-", dir=base)


def _human():
    return Ed25519Signer(generate_seed())


def _roster(signers):
    filler = [_human(), _human()]
    return DelegationTrust(
        human_keys={s.key_id: s.public_key for s in signers},
        authority_keys={filler[0].key_id: filler[0].public_key},
        user_issuer_keys={filler[1].key_id: filler[1].public_key})


def _comp_paths(sim):
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


def _fresh(sim_id, signers, tier="dev"):
    """Fresh sim wall pinned by the given human signers. Returns
    (sim, inv, paths, trust)."""
    tmp = _tmpdir()
    sim = os.path.join(tmp, "wall")
    trust = _roster(signers)
    inv, paths = install_simulated_wall(
        sim, wall_id=sim_id, trust=trust,
        operator_signers=signers, tier=tier)
    return sim, inv, paths, trust


def _widen_allowlist(sim):
    allow = os.path.join(sim, "conf", "allowlist.txt")
    with open(allow, "a", encoding="utf-8") as f:
        f.write("evil.example:443\n")


def _ledger_records(paths):
    with open(paths["ledger"], encoding="utf-8") as f:
        return [json.loads(l) for l in f.read().splitlines() if l.strip()]


def _expect_refused(fn, code):
    """Run fn; return (CLOSED, detail) iff it raises with the expected
    reason code, else (BREAK/ERROR, detail)."""
    try:
        fn()
    except (WallPinRefused, EgressLaunchRefused) as e:
        if code in str(e):
            return ("CLOSED", "%s: %s" % (type(e).__name__, e))
        return ("ERROR", "refused but wrong code: %r" % (e,))
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "unexpected exception: %r" % (e,))
    return ("BREAK", "attack succeeded — refusal did not fire")


# ------------------------------------------------------- unauthorized pins

def probe_repin_without_token_refused():
    """No authorship token at all (not even an unknown key)."""
    s1 = _human()
    sim, inv, paths, trust = _fresh("f138c1", [s1])
    _widen_allowlist(sim)

    def attack():
        WallComponentInventory.install(
            _comp_paths(sim), paths["manifest"], paths["receipt"],
            trust=trust, ledger_path=paths["ledger"])
    return _expect_refused(attack, "pin_authorship_invalid")


def probe_repin_unknown_roster_key_refused():
    """Attacker holds a valid Ed25519 key — but it is not on the roster."""
    s1 = _human()
    attacker = _human()
    sim, inv, paths, trust = _fresh("f138c2", [s1])
    _widen_allowlist(sim)
    prop = WallComponentInventory.proposal(
        _comp_paths(sim), paths["manifest"], tier="dev",
        ledger_path=paths["ledger"])
    sig = attacker.sign(prop["body"]).hex()

    def attack():
        WallComponentInventory.install(
            _comp_paths(sim), paths["manifest"], paths["receipt"],
            trust=trust, author_key_id=attacker.key_id,
            authorship_sig_hex=sig, ts=prop["ts"], tier="dev",
            ledger_path=paths["ledger"])
    v, d = _expect_refused(attack, "pin_authorship_invalid")
    if v == "CLOSED" and "unknown author key" not in d:
        return ("ERROR", "refused but not for unknown key: %s" % d)
    return v, d


def probe_repin_bad_signature_refused():
    """Attacker claims a roster key id but signs with another seed."""
    s1 = _human()
    wrong = _human()
    sim, inv, paths, trust = _fresh("f138c3", [s1])
    _widen_allowlist(sim)
    prop = WallComponentInventory.proposal(
        _comp_paths(sim), paths["manifest"], tier="dev",
        ledger_path=paths["ledger"])
    sig = wrong.sign(prop["body"]).hex()  # signed by the WRONG seed

    def attack():
        WallComponentInventory.install(
            _comp_paths(sim), paths["manifest"], paths["receipt"],
            trust=trust, author_key_id=s1.key_id,
            authorship_sig_hex=sig, ts=prop["ts"], tier="dev",
            ledger_path=paths["ledger"])
    v, d = _expect_refused(attack, "pin_authorship_invalid")
    if v == "CLOSED" and "bad authorship signature" not in d:
        return ("ERROR", "refused but not for bad signature: %s" % d)
    return v, d


def probe_signature_not_reusable_across_content():
    """A human authorizes policy A; the attacker widens the policy and
    replays the (ts, signature). The body binds the payload digest, so
    the replay dies."""
    s1 = _human()
    sim, inv, paths, trust = _fresh("f138c4", [s1])
    prop = WallComponentInventory.proposal(
        _comp_paths(sim), paths["manifest"], tier="dev",
        ledger_path=paths["ledger"])
    sig = s1.sign(prop["body"]).hex()
    _widen_allowlist(sim)  # policy changes AFTER the human signed

    def attack():
        WallComponentInventory.install(
            _comp_paths(sim), paths["manifest"], paths["receipt"],
            trust=trust, author_key_id=s1.key_id,
            authorship_sig_hex=sig, ts=prop["ts"], tier="dev",
            ledger_path=paths["ledger"])
    return _expect_refused(attack, "pin_authorship_invalid")


def probe_signature_not_transplantable_across_chain_position():
    """A signature authorizing a pin at chain position prev=R1 cannot be
    replayed after the chain tip moved to R2."""
    s1 = _human()
    sim, inv, paths, trust = _fresh("f138c5", [s1])
    # pin P as R1 (capture its authorization)
    prop1 = WallComponentInventory.proposal(
        _comp_paths(sim), paths["manifest"], tier="dev",
        ledger_path=paths["ledger"])
    sig1 = s1.sign(prop1["body"]).hex()
    WallComponentInventory.install(
        _comp_paths(sim), paths["manifest"], paths["receipt"],
        trust=trust, author_key_id=s1.key_id,
        authorship_sig_hex=sig1, ts=prop1["ts"], tier="dev",
        ledger_path=paths["ledger"])
    # pin Q as R2: tip moves
    dns = os.path.join(sim, "conf", "dns_config.txt")
    with open(dns, "a", encoding="utf-8") as f:
        f.write("# operator change\n")
    prop2 = WallComponentInventory.proposal(
        _comp_paths(sim), paths["manifest"], tier="dev",
        ledger_path=paths["ledger"])
    WallComponentInventory.install(
        _comp_paths(sim), paths["manifest"], paths["receipt"],
        trust=trust, author_key_id=s1.key_id,
        authorship_sig_hex=s1.sign(prop2["body"]).hex(),
        ts=prop2["ts"], tier="dev", ledger_path=paths["ledger"])
    # restore P's exact bytes, replay R1's (ts, sig) at the new tip
    with open(dns, "r", encoding="utf-8") as f:
        content = f.read()
    with open(dns, "w", encoding="utf-8") as f:
        f.write(content.replace("# operator change\n", ""))

    def attack():
        WallComponentInventory.install(
            _comp_paths(sim), paths["manifest"], paths["receipt"],
            trust=trust, author_key_id=s1.key_id,
            authorship_sig_hex=sig1, ts=prop1["ts"], tier="dev",
            ledger_path=paths["ledger"])
    return _expect_refused(attack, "pin_authorship_invalid")


# ---------------------------------------------------------- tier rule

def probe_production_single_approval_refused():
    s1 = _human()
    sim, inv, paths, trust = _fresh("f138c6", [s1], tier="dev")
    prop = WallComponentInventory.proposal(
        _comp_paths(sim), paths["manifest"], tier="production",
        ledger_path=paths["ledger"])

    def attack():
        WallComponentInventory.install(
            _comp_paths(sim), paths["manifest"], paths["receipt"],
            trust=trust, author_key_id=s1.key_id,
            authorship_sig_hex=s1.sign(prop["body"]).hex(),
            ts=prop["ts"], tier="production",
            ledger_path=paths["ledger"])
    v, d = _expect_refused(attack, "pin_authorship_invalid")
    if v == "CLOSED" and "two distinct human approvals" not in d:
        return ("ERROR", "refused but not for the nuclear rule: %s" % d)
    return v, d


def probe_production_same_key_twice_refused():
    s1 = _human()
    s2 = _human()
    sim, inv, paths, trust = _fresh("f138c7", [s1, s2], tier="dev")
    prop = WallComponentInventory.proposal(
        _comp_paths(sim), paths["manifest"], tier="production",
        ledger_path=paths["ledger"])
    sig = s1.sign(prop["body"]).hex()

    def attack():
        WallComponentInventory.install(
            _comp_paths(sim), paths["manifest"], paths["receipt"],
            trust=trust, author_key_id=s1.key_id,
            authorship_sig_hex=sig, ts=prop["ts"], tier="production",
            second_author_key_id=s1.key_id,
            second_authorship_sig_hex=sig,
            ledger_path=paths["ledger"])
    v, d = _expect_refused(attack, "pin_authorship_invalid")
    if v == "CLOSED" and "two DISTINCT keys" not in d:
        return ("ERROR", "refused but not for distinct-keys: %s" % d)
    return v, d


# ------------------------------------------------- legitimate pins accepted

def probe_dev_single_human_repin_accepted():
    """A roster human legitimately re-pins a changed policy: accepted,
    and the ledger chains genesis -> new pin."""
    s1 = _human()
    s2 = _human()  # a DIFFERENT on-call human does the re-pin
    sim, inv, paths, trust = _fresh("f138c8", [s1, s2])
    _widen_allowlist(sim)  # operator-approved policy change
    trust2 = _roster([s1, s2])
    inv2 = repin_after_fixture_fixup(
        sim, trust=trust2, operator_signers=[s2], tier="dev")
    try:
        manifest, _ = inv2.verify()
    except EgressLaunchRefused as e:
        return ("ERROR", "human-authorized re-pin refused: %s" % e)
    records = _ledger_records(paths)
    if len(records) != 2:
        return ("ERROR", "ledger should have 2 records, has %d"
                % len(records))
    if records[1]["prev_pin_record_sha256"] != records[0]["record_sha256"]:
        return ("ERROR", "re-pin record does not link to genesis")
    if records[1]["record_sha256"] != \
            manifest["pin_record"]["record_sha256"]:
        return ("ERROR", "ledger tip != manifest pin record")
    if records[1]["author_key_ids"] != [s2.key_id]:
        return ("ERROR", "re-pin authorship misattributed: %r"
                % (records[1]["author_key_ids"],))
    return ("CLOSED",
            "human-authorized re-pin accepted; ledger chains 2 records, "
            "tip matches manifest, author=%s" % s2.key_id[:8])


def probe_production_two_human_repin_accepted():
    s1, s2 = _human(), _human()
    sim, inv, paths, trust = _fresh("f138c9", [s1, s2], tier="production")
    try:
        manifest, _ = inv.verify()
    except EgressLaunchRefused as e:
        return ("ERROR", "two-human production pin refused: %s" % e)
    if sorted(manifest["pin_record"]["author_key_ids"]) != \
            sorted([s1.key_id, s2.key_id]):
        return ("ERROR", "production pin misattributes authors: %r"
                % (manifest["pin_record"]["author_key_ids"],))
    return ("CLOSED", "production two-human pin accepted")


# ---------------------------------------------------------- chain tamper

def _three_pins():
    s1 = _human()
    sim, inv, paths, trust = _fresh("f138ct", [s1])
    inv = repin_after_fixture_fixup(
        sim, trust=trust, operator_signers=[s1], tier="dev")
    dns = os.path.join(sim, "conf", "dns_config.txt")
    with open(dns, "a", encoding="utf-8") as f:
        f.write("# change 2\n")
    inv = repin_after_fixture_fixup(
        sim, trust=trust, operator_signers=[s1], tier="dev")
    return sim, inv, paths, trust


def probe_chain_tamper_dropped_record_detected():
    sim, inv, paths, trust = _three_pins()
    records = _ledger_records(paths)
    assert len(records) == 3
    # drop the middle record: R2.prev no longer matches R0
    with open(paths["ledger"], "w", encoding="utf-8") as f:
        f.write(json.dumps(records[0], sort_keys=True) + "\n")
        f.write(json.dumps(records[2], sort_keys=True) + "\n")

    def check():
        inv.verify()
    return _expect_refused(check, "pin_chain_broken")


def probe_chain_tamper_ledger_truncated_detected():
    sim, inv, paths, trust = _three_pins()
    records = _ledger_records(paths)
    with open(paths["ledger"], "w", encoding="utf-8") as f:
        f.write(json.dumps(records[0], sort_keys=True) + "\n")

    def check():
        inv.verify()
    return _expect_refused(check, "pin_chain_broken")


def probe_chain_tamper_ledger_deleted_detected():
    sim, inv, paths, trust = _three_pins()
    os.remove(paths["ledger"])

    def check():
        inv.verify()
    return _expect_refused(check, "pin_chain_broken")


def probe_chain_tamper_manifest_pin_record_edited_detected():
    """Attacker edits the manifest's pin_record.prev and re-mints the
    receipt (the receipt is self-consistent). The pin record's
    self-hash and authorship no longer hold."""
    import hashlib
    sim, inv, paths, trust = _three_pins()
    manifest = json.load(open(paths["manifest"], encoding="utf-8"))
    manifest["pin_record"]["prev_pin_record_sha256"] = "0" * 64
    blob = json.dumps(manifest, sort_keys=True, indent=2,
                      ensure_ascii=True).encode("utf-8")
    open(paths["manifest"], "wb").write(blob)
    receipt = {"format": "egress-wall-receipt/1",
               "manifest_sha256": hashlib.sha256(blob).hexdigest(),
               "installed_at": manifest["installed_at"]}
    json.dump(receipt, open(paths["receipt"], "w", encoding="utf-8"),
              sort_keys=True, indent=2)

    def check():
        inv.verify()
    v, d = _expect_refused(check, "pin_authorship_invalid")
    if v == "CLOSED" and "self-hash mismatch" not in d:
        return ("ERROR", "refused but not for record tamper: %s" % d)
    return v, d


def probe_legacy_manifest_without_pin_record_refused():
    """A pre-F138 manifest (format /1, no pin record) with a valid
    receipt is refused: re-pin under human authorship is required."""
    import hashlib
    s1 = _human()
    sim, inv, paths, trust = _fresh("f138c10", [s1])
    manifest = json.load(open(paths["manifest"], encoding="utf-8"))
    manifest["format"] = "egress-wall-pins/1"
    del manifest["pin_record"]
    blob = json.dumps(manifest, sort_keys=True, indent=2,
                      ensure_ascii=True).encode("utf-8")
    open(paths["manifest"], "wb").write(blob)
    receipt = {"format": "egress-wall-receipt/1",
               "manifest_sha256": hashlib.sha256(blob).hexdigest(),
               "installed_at": manifest["installed_at"]}
    json.dump(receipt, open(paths["receipt"], "w", encoding="utf-8"),
              sort_keys=True, indent=2)

    def check():
        inv.verify()
    v, d = _expect_refused(check, "pin_authorship_invalid")
    if v == "CLOSED" and "legacy manifest format" not in d:
        return ("ERROR", "refused but not as legacy: %s" % d)
    return v, d


# ---------------------------------------------------------------- CONTROL

def probe_control_launch_after_human_repin():
    """End-to-end: human-authorized re-pin -> verify -> launch works."""
    s1 = _human()
    tmp = _tmpdir()
    sim = os.path.join(tmp, "wall")
    trust = _roster([s1])
    install_simulated_wall(sim, wall_id="f138ctl", trust=trust,
                           operator_signers=[s1], tier="dev")
    fix = SimulatedWallFixture(sim)
    fix.__enter__()
    try:
        inv = repin_after_fixture_fixup(
            sim, trust=trust, operator_signers=[s1], tier="dev")
        fix.inventory = inv
        events = []
        launcher = FilteredEgressLauncher(
            manifest_path=os.path.join(sim, "wall_pins.json"),
            receipt_path=os.path.join(sim, "wall_receipt.json"),
            wall_provider=fix.provider(), audit=events.append,
            trust=trust)
        launcher.verify()
        cp = launcher.run_child(
            [sys.executable, "-c", "print('f138-control')"],
            capture_output=True, text=True)
        if cp.returncode == 0 and "f138-control" in (cp.stdout or ""):
            return ("CONTROL", "human re-pin verifies; launch works")
        return ("ERROR", "launch failed rc=%r out=%r"
                % (cp.returncode, cp.stdout))
    except EgressLaunchRefused as e:
        return ("ERROR", "verify/launch refused: %s" % e)
    finally:
        fix.__exit__()


_PROBES = [
    ("repin_without_token_refused", probe_repin_without_token_refused),
    ("repin_unknown_roster_key_refused",
     probe_repin_unknown_roster_key_refused),
    ("repin_bad_signature_refused", probe_repin_bad_signature_refused),
    ("signature_not_reusable_across_content",
     probe_signature_not_reusable_across_content),
    ("signature_not_transplantable_across_chain_position",
     probe_signature_not_transplantable_across_chain_position),
    ("production_single_approval_refused",
     probe_production_single_approval_refused),
    ("production_same_key_twice_refused",
     probe_production_same_key_twice_refused),
    ("dev_single_human_repin_accepted",
     probe_dev_single_human_repin_accepted),
    ("production_two_human_repin_accepted",
     probe_production_two_human_repin_accepted),
    ("chain_tamper_dropped_record_detected",
     probe_chain_tamper_dropped_record_detected),
    ("chain_tamper_ledger_truncated_detected",
     probe_chain_tamper_ledger_truncated_detected),
    ("chain_tamper_ledger_deleted_detected",
     probe_chain_tamper_ledger_deleted_detected),
    ("chain_tamper_manifest_pin_record_edited_detected",
     probe_chain_tamper_manifest_pin_record_edited_detected),
    ("legacy_manifest_without_pin_record_refused",
     probe_legacy_manifest_without_pin_record_refused),
    ("control_launch_after_human_repin",
     probe_control_launch_after_human_repin),
]


def main():
    results = []
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001
            verdict, detail = "ERROR", "probe raised: %r" % (e,)
        results.append((name, verdict, detail))
        print("%-48s %-8s %s" % (name, verdict, detail))
    n_closed = sum(1 for _, v, _ in results if v == "CLOSED")
    n_control = sum(1 for _, v, _ in results if v == "CONTROL")
    n_bad = sum(1 for _, v, _ in results if v in ("BREAK", "ERROR"))
    print("---")
    print("CLOSED=%d CONTROL=%d BREAK/ERROR=%d"
          % (n_closed, n_control, n_bad))
    return 1 if n_bad else 0


if __name__ == "__main__":
    sys.exit(main())
