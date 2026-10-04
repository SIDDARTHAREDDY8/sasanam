"""Break-first red-team battery for the wave-251 new modules.

Wave-252 lane 2 (red-team). Stdlib only. Deterministic across runs
(staging + `env -u GOV_DEPLOYMENT_MODE`).

Targets (all new in wave-251, base aeac961):
- gov/posture_cards.py -- forged scores, VSA summary tampering,
  dishonest state, threshold confusion.
- gov/policy_harness.py -- malicious policy smuggling, malformed
  fixtures, lenient-YAML tricks, CI exit codes, diff blind spots.
- gov/decision_log.py -- additional break attempts beyond the filed
  F212/F213 (both still OPEN; not re-filed here).
- gov/permit_journal.py -- deeper attempts: snapshot MAC forgery,
  key confusion, journal tampering, non-serializable payloads.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Verdicts: HELD (attack refused / gap documented as an
honest residual) or BREAK (genuine defect -> filed as a finding).

Result: 17 HELD / 2 BREAK (F214, F215) / 0 ERROR on the wave-252
base. Post wave-253 lane 1 (F214/F215 closure): the two break pins
were honestly flipped to HELD regression pins (pre-fix break shapes
documented in the probe comments); 19/19 HELD on fixed code.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import permit_journal as pj  # noqa: E402
from gov import policy_combine  # noqa: E402
from gov import policy_harness as ph  # noqa: E402
from gov import posture_cards as pc  # noqa: E402
from gov.decision_log import (  # noqa: E402
    DecisionLog,
    DecisionLogError,
    MerkleTree,
    empty_root,
    hash_leaf,
)
from gov.policy import PolicyEngine  # noqa: E402

TAXONOMY_PIN = 1915 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 1: pin 1906 -> 1915 (+9 grantneg-*)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _tmpdir():
    path = tempfile.mkdtemp(prefix="w252rt-", dir="/var/tmp")
    return path


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


# ---------------------------------------------------------------------------
# A. posture_cards
# ---------------------------------------------------------------------------

def _full_state():
    key = "ab" * 32
    return {
        "skill_admission": {"authority_pub": key, "admitted_layouts": 2},
        "skill_update": {"pin": {"not_after": "2030-01-01T00:00:00Z"}},
        "assessed_at": "2026-09-30T00:00:00Z",
        "agent_identity": {"connector": "oidc",
                           "subject_source": "sub"},
        "policy": {"combiner_active": True,
                   "decision_log": {"root": "cd" * 32}},
        "evidence": {"enveloped_exports": 3,
                     "graph": {"nodes": 42}},
        "durability": {"permit_journal": {"tip": "ef" * 32}},
    }


@probe("posture/dishonest-state-pass")
def _p_dishonest():
    # A deployment can feed self-serving state (self-generated key,
    # invented counts) and every card passes. This is the lane's
    # documented residual #1: cards prove the check ran against
    # SUPPLIED state, and the docstring labels them evidence, not
    # certification. HELD as documented, not a new break.
    cards = pc.assess(_full_state())
    passed = sum(1 for c in cards if c["probe"] == "pass")
    assert passed == len(cards) == 8, (passed, len(cards))
    return _held("8/8 pass on self-serving state; documented residual")


@probe("posture/summary-tamper-levels")
def _p_tamper():
    cards = pc.assess(_full_state())
    seed = bytes(range(32))
    summary = pc.issue_summary("deploy-1", cards, seed, issuer="op")
    tampered = json.loads(json.dumps(summary))
    tampered["record"]["tracks"][0]["level"] = "absent"
    try:
        pc.verify_summary(tampered)
    except pc.PostureCardError as exc:
        assert exc.code == pc.UNVERIFIABLE, exc.code
        return _held("level tamper -> posture-card-unverifiable")
    return _break("tampered summary verified")


@probe("posture/summary-no-recompute")
def _p_norecompute():
    # verify_summary checks the SIGNATURE, not that the levels match
    # the cards. An issuer can sign levels disconnected from the
    # evidence. Lane residual #3 documents this: an auditor
    # verifying only levels trusts the issuer's computation.
    # HELD as documented, not a new break.
    cards = pc.assess({})
    assert all(c["probe"] == "unavailable" for c in cards)
    seed = bytes(range(32))
    summary = pc.issue_summary("deploy-1", cards, seed, issuer="op")
    assert summary["record"]["tracks"][0]["level"] == "absent"
    rec = pc.verify_summary(summary)
    assert rec["tracks"][0]["level"] == "absent"
    return _held("levels are issuer claims; documented residual")


@probe("posture/non-dict-cards")
def _p_nondict():
    # Pre-fix (wave-253 lane 1): issue_summary promised
    # posture-card-malformed for malformed inputs, but non-dict cards
    # escaped as a raw AttributeError (F215). Fixed: every public
    # path funnels through posture_cards._require_card_dicts.
    seed = bytes(range(32))
    try:
        pc.issue_summary("s", ["not-a-dict"], seed, issuer="me")
    except pc.PostureCardError as exc:
        assert exc.code == pc.MALFORMED, exc.code
        return _held("non-dict cards -> posture-card-malformed")
    return _break("F215: non-dict cards silently accepted")


@probe("posture/track-level-threshold")
def _p_threshold():
    # partial = at least one pass. Coarse by design (lane residual
    # #2); per-track weighting is deployment policy.
    cards = pc.assess(_full_state())
    assert pc.track_level(cards, "supply-chain") == "full"
    cards2 = [dict(c) for c in cards]
    for c in cards2:
        if c["check"] == "tuf-pins-fresh":
            c["probe"] = "fail"
    assert pc.track_level(cards2, "supply-chain") == "partial"
    return _held("1/2 pass -> partial; by design")


# ---------------------------------------------------------------------------
# B. policy_harness
# ---------------------------------------------------------------------------

_PERMIT_YAML = """\
version: "1"
policies:
  - id: allow-send
    effect: allow
    match:
      tool: send_email
"""

_FORBID_YAML = """\
version: "1"
policies:
  - id: deny-send
    effect: deny
    match:
      tool: send_email
"""


def _harness_dir(policies, fixtures, expected):
    root = _tmpdir()
    for sub in ("policies", "fixtures", "expected"):
        os.makedirs(os.path.join(root, sub))
    for name, text in policies.items():
        with open(os.path.join(root, "policies", name), "w",
                  encoding="utf-8") as fh:
            fh.write(text)
    for name, obj in fixtures.items():
        with open(os.path.join(root, "fixtures", name), "w",
                  encoding="utf-8") as fh:
            json.dump(obj, fh, sort_keys=True)
    for name, obj in expected.items():
        with open(os.path.join(root, "expected", name), "w",
                  encoding="utf-8") as fh:
            json.dump(obj, fh, sort_keys=True)
    return root


@probe("harness/fixture-coverage-gap")
def _h_smuggle():
    # A policy that satisfies every fixture can still misbehave on
    # uncovered inputs. Inherent to any fixture harness (lane
    # residual #1: the harness tests policies, not executor wiring).
    # HELD as documented.
    sneaky = """\
version: "1"
policies:
  - id: allow-send
    effect: allow
    match:
      tool: send_email
  - id: allow-everything-else
    effect: allow
    match:
      tool: read_file
"""
    root = _harness_dir(
        {"p.yaml": sneaky},
        {"f1.json": {"action": {"tool": "send_email"},
                     "context": {}}},
        {"f1.json": {"effect": "allow"}})
    try:
        report = ph.run_harness(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    assert report.failed == 0, report.to_dict()
    return _held("uncovered allow-all passes; documented residual")


@probe("harness/malformed-fixture")
def _h_malformed():
    cases = 0
    # JSON array fixture
    root = _harness_dir({"p.yaml": _PERMIT_YAML}, {}, {})
    with open(os.path.join(root, "fixtures", "f.json"), "w") as fh:
        fh.write("[1,2]")
    with open(os.path.join(root, "expected", "f.json"), "w") as fh:
        fh.write('{"effect": "allow"}')
    try:
        ph.run_harness(root)
    except ph.HarnessError as exc:
        assert exc.code == ph.MALFORMED_CODE, exc.code
        cases += 1
    else:
        return _break("array fixture accepted")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    # missing action
    root = _harness_dir(
        {"p.yaml": _PERMIT_YAML},
        {"f.json": {"context": {}}},
        {"f.json": {"effect": "allow"}})
    try:
        ph.run_harness(root)
    except ph.HarnessError as exc:
        assert exc.code == ph.MALFORMED_CODE, exc.code
        cases += 1
    else:
        return _break("action-less fixture accepted")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    # missing expected
    root = _harness_dir(
        {"p.yaml": _PERMIT_YAML},
        {"f.json": {"action": {"tool": "send_email"}}},
        {})
    try:
        ph.run_harness(root)
    except ph.HarnessError as exc:
        assert exc.code == ph.MISSING_EXPECTED_CODE, exc.code
        cases += 1
    else:
        return _break("fixture without expected accepted")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    assert cases == 3
    return _held("3/3 malformed fixtures refused with codes")


@probe("harness/lenient-yaml-smuggle")
def _h_yaml():
    # The stdlib YAML parser tolerates odd syntax. Attempt to smuggle
    # a policy whose parsed semantics differ from its apparent
    # intent (a deny that parses permissive, or vice versa).
    tricks = {
        "unclosed": 'version: [unclosed\npolicies:\n'
                     '  - id: d1\n    effect: deny\n    match:\n'
                     '      tool: send_email\n',
        "indent": 'version: "1"\npolicies:\n'
                  '  - id: d1\n    effect: deny\n   match:\n'
                  '      tool: send_email\n',
    }
    for name, text in tricks.items():
        eng = PolicyEngine.from_text(text, source_label="t:" + name)
        dec = eng.evaluate({"tool": "send_email"}, {},
                           record_telemetry=False)
        if dec.effect != "deny":
            return _break("%s parsed to %s" % (name, dec.effect))
    # strict rejections still hold
    for name, text in {
        "effect-typo": _FORBID_YAML.replace("effect: deny",
                                            "effect: denyy"),
        "match-typo": _FORBID_YAML.replace("tool: send_email",
                                           "toolx: send_email"),
    }.items():
        try:
            PolicyEngine.from_text(text, source_label="t:" + name)
        except ValueError:
            pass
        else:
            return _break("%s accepted" % name)
    return _held("lenient syntax keeps deny semantics; typos refused")


@probe("harness/ci-exit-codes")
def _h_exit():
    root = _harness_dir(
        {"p.yaml": _PERMIT_YAML},
        {"f.json": {"action": {"tool": "send_email"}}},
        {"f.json": {"effect": "allow"}})
    try:
        assert ph.main([root]) == 0
    finally:
        shutil.rmtree(root, ignore_errors=True)
    root = _harness_dir(
        {"p.yaml": _FORBID_YAML},
        {"f.json": {"action": {"tool": "send_email"}}},
        {"f.json": {"effect": "allow"}})
    try:
        assert ph.main([root]) == 1
    finally:
        shutil.rmtree(root, ignore_errors=True)
    assert ph.main(["/nonexistent-dir"]) == 2
    return _held("0 pass / 1 fail / 2 harness-error")


@probe("harness/diff-blind-spot")
def _h_diff():
    # diff_policies ignores new_dir's fixtures by design (the
    # comparison must run the SAME requests). Lane residual #2.
    # HELD as documented.
    old = _harness_dir(
        {"p.yaml": _PERMIT_YAML},
        {"f.json": {"action": {"tool": "send_email"}}},
        {"f.json": {"effect": "allow"}})
    new = _harness_dir(
        {"p.yaml": _FORBID_YAML},
        {"extra.json": {"action": {"tool": "read_file"}}},
        {"extra.json": {"effect": "allow"}})
    try:
        delta = ph.diff_policies(old, new)
    finally:
        shutil.rmtree(old, ignore_errors=True)
        shutil.rmtree(new, ignore_errors=True)
    assert delta.changed == 1
    assert [e["fixture"] for e in delta.entries] == ["f.json"]
    return _held("new_dir fixtures ignored; documented residual")


# ---------------------------------------------------------------------------
# C. decision_log (beyond filed F212/F213)
# ---------------------------------------------------------------------------

def _ref_root(leaves):
    hs = [hash_leaf(l) for l in leaves]

    def node(hs):
        if not hs:
            return empty_root()
        if len(hs) == 1:
            return hs[0]
        k = 1 << ((len(hs) - 1).bit_length() - 1)
        return hashlib.sha256(b"\x01" + node(hs[:k]) +
                              node(hs[k:])).digest()

    return node(hs)


@probe("log/merkle-bruteforce")
def _l_bruteforce():
    # Independent reimplementation cross-check: every inclusion proof
    # and every consistency proof for n=1..16 must verify against
    # independently computed roots.
    for n in range(1, 17):
        leaves = [("leaf-%d" % i).encode() for i in range(n)]
        tree = MerkleTree()
        for leaf in leaves:
            tree.append(leaf)
        r_ref = _ref_root(leaves)
        assert tree.root() == r_ref, n
        for i in range(n):
            proof = tree.inclusion_proof(i)
            ok = MerkleTree.verify_inclusion(
                i, hash_leaf(leaves[i]), n, proof, r_ref)
            assert ok is True, (n, i)
        for s1 in range(1, n + 1):
            proof = tree.consistency_proof(s1)
            r1 = _ref_root(leaves[:s1])
            ok = MerkleTree.verify_consistency(
                s1, n, proof, r1, r_ref)
            assert ok is True, (n, s1)
    return _held("16 sizes x all indices/prefixes verify")


@probe("log/consistency-forgery")
def _l_forgery():
    # Adversarial: no wrong root and no malformed proof may verify.
    import secrets
    tree = MerkleTree()
    leaves = [("leaf-%d" % i).encode() for i in range(8)]
    for leaf in leaves:
        tree.append(leaf)
    proof = tree.consistency_proof(5)
    r2 = tree.root()
    r1 = _ref_root(leaves[:5])
    assert MerkleTree.verify_consistency(5, 8, proof, r1, r2) is True
    for _ in range(200):
        wrong = secrets.token_bytes(32)
        assert MerkleTree.verify_consistency(
            5, 8, proof, wrong, r2) is not True
    for plen in (0, len(proof) - 1, len(proof) + 1):
        bad = (proof[:plen] if plen <= len(proof)
               else proof + [secrets.token_bytes(32)])
        assert MerkleTree.verify_consistency(
            5, 8, bad, r1, r2) is not True
    return _held("200 wrong roots + bad lengths all refused")


@probe("log/epoch-replay")
def _l_replay():
    eng = PolicyEngine.from_text(_PERMIT_YAML, source_label="t")
    log = DecisionLog()
    ra, rb = b"a" * 32, b"b" * 32
    d = eng.evaluate({"tool": "send_email"}, {},
                     record_telemetry=False)
    log.append(policy_combine.combine([d]), ra)
    log.new_epoch(rb)
    log.append(policy_combine.combine([d]), rb)
    try:
        log.append(policy_combine.combine([d]), ra)
    except DecisionLogError as exc:
        assert exc.code == "decision-log-request-mismatch", exc.code
        return _held("old-digest replay -> request-mismatch")
    return _break("epoch replay accepted")


# ---------------------------------------------------------------------------
# D. permit_journal
# ---------------------------------------------------------------------------

@probe("journal/non-serializable-payload")
def _j_payload():
    # Pre-fix (wave-253 lane 1): _build_body MAC'd the payload via
    # json.dumps with no guard, so a set payload escaped as a raw
    # TypeError instead of permit-journal-misuse (F214). Fixed: the
    # event_mac serialization is wrapped in PermitJournalRefusal.
    # No partial write ever occurred (the MAC was computed before
    # append) -- this was a contract violation, not a bypass.
    path = os.path.join(_tmpdir(), "j.jsonl")
    journal = pj.PermitJournal(path, key=b"k" * 32)
    try:
        journal.grant("p1", {"bad": {1, 2, 3}})
    except pj.PermitJournalError as exc:
        assert exc.code == pj.MISUSE_CODE, exc.code
        return _held("non-serializable payload -> misuse code")
    return _break("F214: non-serializable payload silently accepted")


@probe("journal/snapshot-tamper")
def _j_snap_tamper():
    path = os.path.join(_tmpdir(), "j.jsonl")
    journal = pj.PermitJournal(path, key=b"k" * 32)
    journal.grant("p1", {"scope": "read"})
    journal.record_use("p1", {"n": 1})
    ref = journal.take_snapshot()
    journal.compact()
    sidecar = os.path.join(os.path.dirname(path),
                           ref["snapshot_path"])
    with open(sidecar, encoding="utf-8") as fh:
        stored = json.load(fh)
    stored["body"]["states"]["p1"]["state"] = "revoked"
    with open(sidecar, "w", encoding="utf-8") as fh:
        json.dump(stored, fh)
    try:
        pj.PermitJournal(path, key=b"k" * 32)
    except pj.PermitJournalCorrupted:
        return _held("tampered sidecar refused")
    return _break("tampered snapshot accepted")


@probe("journal/stale-sidecar")
def _j_stale():
    # Swap in an older VALID sidecar (correct MAC, stale states).
    # The durable layer binds sidecar bytes via body_hash in the
    # SnapshotLoaded anchor, so the swap must fail.
    path = os.path.join(_tmpdir(), "j.jsonl")
    journal = pj.PermitJournal(path, key=b"k" * 32)
    journal.grant("p1", {"scope": "read"})
    ref1 = journal.take_snapshot()
    journal.record_use("p1", {"n": 1})
    ref2 = journal.take_snapshot()
    journal.compact()
    old_sc = os.path.join(os.path.dirname(path),
                          ref1["snapshot_path"])
    new_sc = os.path.join(os.path.dirname(path),
                          ref2["snapshot_path"])
    shutil.copyfile(old_sc, new_sc)
    try:
        pj.PermitJournal(path, key=b"k" * 32)
    except pj.PermitJournalCorrupted:
        return _held("stale sidecar refused")
    return _break("stale sidecar accepted")


@probe("journal/tail-truncation")
def _j_truncate():
    # Whole-trailing-record removal is silent before any snapshot:
    # the chain still verifies, just shorter. Documented honest
    # residual in the module docstring. HELD as documented.
    path = os.path.join(_tmpdir(), "j.jsonl")
    journal = pj.PermitJournal(path, key=b"k" * 32)
    journal.grant("p1", {"a": 1})
    journal.record_use("p1", {"a": 2})
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines[:-1])
    reopened = pj.PermitJournal(path, key=b"k" * 32)
    state = reopened.permit_state("p1")
    assert state["n_events"] == 1, state
    return _held("truncation silent; documented residual")


@probe("journal/key-confusion")
def _j_key():
    os.environ["GOV_PERMIT_JOURNAL_KEY"] = "not-hex!!"
    try:
        pj.PermitJournal(os.path.join(_tmpdir(), "j.jsonl"))
    except pj.PermitJournalRefusal as exc:
        assert exc.code == pj.KEY_WEAK_CODE, exc.code
    else:
        return _break("non-hex env key accepted")
    finally:
        del os.environ["GOV_PERMIT_JOURNAL_KEY"]
    try:
        pj.PermitJournal(os.path.join(_tmpdir(), "j.jsonl"),
                         key=b"short")
    except pj.PermitJournalRefusal as exc:
        assert exc.code == pj.KEY_WEAK_CODE, exc.code
    else:
        return _break("weak key accepted")
    return _held("non-hex env + weak key refused")


@probe("journal/terminal-resurrection")
def _j_terminal():
    path = os.path.join(_tmpdir(), "j.jsonl")
    journal = pj.PermitJournal(path, key=b"k" * 32)
    journal.grant("p1", {})
    journal.revoke("p1", "r")
    try:
        journal.record_use("p1", {})
    except pj.PermitJournalRefusal as exc:
        assert exc.code == pj.TRANSITION_ILLEGAL_CODE, exc.code
        return _held("use-after-revoke -> transition-illegal")
    return _break("terminal permit resurrected")


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

def main():
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (  # Wave-258 merge: pin -> 1080.
        "taxonomy pin: expected %d, got %d"
        % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))  # Wave-258 merge: pin -> 1080.
    held, broken, errors = 0, 0, 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = ("ERROR", "%r" % (exc,))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broken += 1
        else:
            errors += 1
        print("%-42s %-6s %s" % (name, verdict, detail))
    print("probes=%d held=%d break=%d error=%d"
          % (len(_PROBES), held, broken, errors))
    return 0 if (broken == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
