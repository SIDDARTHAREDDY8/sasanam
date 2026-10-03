"""Wave-251 red-team probes: break-first on the wave-250 new modules.

W251-3: red-team of ``gov/decision_log.py``, ``gov/permit_journal.py``,
``gov/evidence_graph.py`` (all new in wave-250) and the F211 fix in
``gov/skill_update.py``.

Discipline (diagnosing-bugs skill): every probe is a falsifiable break
attempt -- 3-5 ranked hypotheses per module, minimised, deterministic,
agent-runnable. A probe returns HELD when the attack is refused (or the
honest path holds); BREAK when the attack succeeds (or an honest path
is broken). Genuine breaks are filed as findings (F212+); the rest are
HELD pins.

Hypotheses under test:

Wave-252 lane 1 note: F212 and F213 are CLOSED (2026-09-30). The
three break probes (log/post-append-mutation-hides,
log/post-append-mutation-fabricates, log/bogus-proof-index) are now
regression pins asserting the closure: the fabricate probe was
flipped to assert the fixed behavior (it was a pure
break-demonstrator and could never return HELD); the hide and
bogus-index probes flipped automatically.

decision_log
  H1 forged inclusion proof -> verify_proof must raise
       decision-log-proof-invalid (never accept).
  H2 genuine equivocation -> detect_equivocation surfaces a proof that
       verifies (honest-path control).
  H3 post-append mutation of the logged CombinedDecision hides a real
       equivocation from detect_equivocation (the log stores the live
       object reference, not a snapshot).
  H4 post-append mutation fabricates equivocation evidence whose proof
       cryptographically verifies while the effect labels are lies.
  H5 hand-crafted EquivocationProof with an out-of-range leaf index ->
       verify() must return False, never raise.
  H6 STH tampering -> verify_sth False; cross-epoch replay of an old
       request digest -> request-mismatch refusal.

permit_journal
  H7 raw file tamper of a permit event -> chain-broken on reopen.
  H8 terminal permit resurrection (revoke then use) -> refused.
  H9 duplicate event_id -> refused.
  H10 reopen under a different key -> chain-broken.
  H11 snapshot sidecar tamper -> snapshot-tampered on reopen.
  H12 non-JSON-serializable payload -> fail-closed, no partial write.

evidence_graph
  H13 ambiguous selector -> evidence-graph-ambiguous-link.
  H14 unlinked selector -> evidence-graph-unlinked.
  H15 node/edge caps -> evidence-graph-overflow.
  H16 re-adding a node with different attrs silently merges (observed
       behaviour; no adversary at this seam -- documented, not filed).

skill_update (F211 fix)
  H17 legacy {name: int} installed map -> skill-update-malformed.
  H18 same-version reinstall with different bytes -> refused
       (F211 regression control).
  H19 caller mutating their installed dict post-construction does not
       affect the client (no aliasing).
  H20 identical-bytes reinstall stays idempotent (honest path).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import hashlib
import json
import os
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_DL = HAVE_PC = HAVE_PD = HAVE_PJ = HAVE_EG = HAVE_SU = False
try:
    from gov import decision_log as _dl
    HAVE_DL = all(hasattr(_dl, n) for n in (
        "DecisionLog", "DecisionLogError", "EquivocationProof",
        "detect_equivocation", "MerkleTree"))
except ImportError:
    _dl = None
try:
    from gov import policy_combine as _pc
    HAVE_PC = hasattr(_pc, "combine") and hasattr(_pc, "CombinedDecision")
except ImportError:
    _pc = None
try:
    from gov.policy import PolicyDecision as _PD
    HAVE_PD = True
except ImportError:
    _PD = None
try:
    from gov import permit_journal as _pj
    HAVE_PJ = hasattr(_pj, "PermitJournal")
except ImportError:
    _pj = None
try:
    from gov import evidence_graph as _eg
    HAVE_EG = hasattr(_eg, "EvidenceGraph")
except ImportError:
    _eg = None
try:
    from gov import skill_update as _su
    HAVE_SU = hasattr(_su, "SkillUpdateClient")
except ImportError:
    _su = None

HAVE_LOG = HAVE_DL and HAVE_PC and HAVE_PD
HAVE_ALL = HAVE_LOG and HAVE_PJ and HAVE_EG and HAVE_SU

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"


def _run_probe(name, fn, have):
    if not have:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        return name, "BREAK", "GAP: capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


# ------------------------------------------------- helpers: decision log


def _mkpd(effect, pid="pol-a", rev="policy:1", digest=None):
    digest = digest or ("a" * 64)
    return _PD(effect=effect, reason="r:" + effect, policy_id=pid,
               policy_rev_id=rev, policy_digest=digest)


def _mkcd(effect, decisions):
    return _pc.CombinedDecision(
        effect, "reason:" + effect, None, (), (), ("pol-a",), decisions)


def _mktmp():
    base = "/var/tmp/w251-redteam"
    os.makedirs(base, exist_ok=True)
    return tempfile.mkdtemp(prefix="probe-", dir=base)


# ------------------------------------------------- decision_log probes


def probe_log_forged_proof():
    log = _dl.DecisionLog()
    req = b"r" * 32
    log.append(_mkcd("allow", [_mkpd("allow")]), req)
    log.append(_mkcd("deny", [_mkpd("deny")]), req)
    proof = log.inclusion_proof(0)
    bad = list(proof)
    bad[0] = bytes(b ^ 0xFF for b in bad[0])
    try:
        log.verify_proof(0, bad)
    except _dl.DecisionLogError as exc:
        assert exc.code == "decision-log-proof-invalid", exc.code
        return "forged inclusion proof refused (%s)" % exc.code
    raise AssertionError("forged inclusion proof VERIFIED")


def probe_log_equivocation_control():
    log = _dl.DecisionLog()
    req = b"q" * 32
    log.append(_mkcd("allow", [_mkpd("allow")]), req)
    log.append(_mkcd("deny", [_mkpd("deny")]), req)
    found = _dl.detect_equivocation(log)
    assert len(found) == 1, "expected 1 equivocation, got %d" % len(found)
    assert found[0].verify(log) is True, "proof does not verify"
    assert {found[0].effect_a, found[0].effect_b} == {"allow", "deny"}
    return "genuine equivocation detected, proof verifies"


def probe_log_mutation_hides():
    # H3: the log keeps the live CombinedDecision object; mutating it
    # post-append rewrites what detect_equivocation sees.
    log = _dl.DecisionLog()
    req = b"h" * 32
    d_allow = _mkcd("allow", [_mkpd("allow")])
    d_deny = _mkcd("deny", [_mkpd("deny")])
    log.append(d_allow, req)
    log.append(d_deny, req)
    assert len(_dl.detect_equivocation(log)) == 1, "control failed"
    d_allow.effect = "deny"  # post-append mutation
    found = _dl.detect_equivocation(log)
    if len(found) == 0:
        raise AssertionError(
            "post-append mutation HID the equivocation: "
            "detect_equivocation now reports nothing while the leaf "
            "hashes still commit to allow+deny")
    return "mutation did not hide equivocation"


def probe_log_mutation_fabricates():
    # H4 (F212, CLOSED wave-252 lane 1): post-append mutation of a
    # logged CombinedDecision must NOT fabricate equivocation
    # evidence. The log snapshots (request_digest, effect,
    # policy_key) at append; detect_equivocation() reads the
    # snapshots only. Pre-fix break shape (kept as documentation):
    # mutating d2.effect to "deny" made detect_equivocation return
    # a proof that verify(log) ACCEPTED while the leaf bytes still
    # committed to allow/allow.
    log = _dl.DecisionLog()
    req = b"f" * 32
    d1 = _mkcd("allow", [_mkpd("allow")])
    d2 = _mkcd("allow", [_mkpd("allow")])
    # pristine twin of d2's leaf, for the honesty check below
    twin = _mkcd("allow", [_mkpd("allow")])
    twin_bytes = _dl._canonical_leaf_bytes(twin, req)
    log.append(d1, req)
    log.append(d2, req)
    assert _dl.detect_equivocation(log) == [], "control failed"
    leaf_before = log._leaf_hash_at(1)
    d2.effect = "deny"  # post-append mutation: must not fabricate
    found = _dl.detect_equivocation(log)
    assert found == [], \
        "post-append mutation FABRICATED equivocation evidence"
    # The leaf still commits to the true allow bytes.
    assert log._leaf_hash_at(1) == leaf_before
    assert log._leaf_hash_at(1) == _dl.hash_leaf(twin_bytes), \
        "leaf hash no longer matches the true allow bytes"
    return "mutation did not fabricate equivocation (snapshot)"


def probe_log_bogus_index():
    # H5: verify() on a hand-crafted proof must return False, not raise.
    log = _dl.DecisionLog()
    req = b"b" * 32
    log.append(_mkcd("allow", [_mkpd("allow")]), req)
    p = _dl.EquivocationProof(req, (), 0, "allow", [], 999, "deny", [],
                              log.tree_size(), log.root())
    try:
        result = p.verify(log)
    except IndexError as exc:
        raise AssertionError(
            "verify() raised IndexError on bogus index instead of "
            "returning False: %s" % (exc,))
    assert result is False, "bogus index should verify False"
    return "bogus index returns False"


def probe_log_sth_and_epoch():
    from gov import ed25519 as _ed
    log = _dl.DecisionLog()
    req_a = b"A" * 32
    req_b = b"B" * 32
    log.append(_mkcd("allow", [_mkpd("allow")]), req_a)
    seed = b"s" * 32
    pub = _ed.pubkey(seed) if hasattr(_ed, "pubkey") else None
    if pub is None:
        # derive via sign/verify pair only
        sth = log.sign_sth(log.issue_sth(), seed)
        assert log.verify_sth(sth, b"p" * 32) is False
    else:
        sth = log.sign_sth(log.issue_sth(), seed)
        assert log.verify_sth(sth, pub) is True
        tampered = dict(sth)
        root = bytearray(bytes.fromhex(tampered["root"]))
        root[0] ^= 0xFF
        tampered["root"] = bytes(root).hex()
        assert log.verify_sth(tampered, pub) is False, \
            "tampered STH verified"
    # cross-epoch replay of the old digest must refuse
    log.new_epoch(req_b)
    try:
        log.append(_mkcd("allow", [_mkpd("allow")]), req_a)
    except _dl.DecisionLogError as exc:
        assert exc.code == "decision-log-request-mismatch", exc.code
    else:
        raise AssertionError("old request digest accepted after new_epoch")
    # old leaf still inclusion-proves against the current root
    assert log.verify_leaf(0) is True
    return "STH tamper refused; epoch replay refused; old leaf proves"


# ------------------------------------------------- permit_journal probes


def _new_journal(key=None):
    d = _mktmp()
    key = key if key is not None else b"k" * 32
    path = os.path.join(d, "j.jsonl")
    return _pj.PermitJournal(path, key=key), path, d


def probe_journal_forged_mac():
    # H7: flip payload bytes in the raw file; reopen must fail closed.
    j, path, _d = _new_journal()
    j.grant("p1", {"scope": "read"})
    j.record_use("p1", {"tool": "x"})
    with open(path, "rb") as f:
        data = f.read()
    assert b'"scope":"read"' in data, "payload bytes not found"
    tampered = data.replace(b'"scope":"read"', b'"scope":"writ"')
    assert tampered != data
    with open(path, "wb") as f:
        f.write(tampered)
    try:
        _pj.PermitJournal(path, key=b"k" * 32)
    except _pj.PermitJournalCorrupted as exc:
        return "raw file tamper refused (%s)" % exc.code
    raise AssertionError("tampered journal REOPENED clean")


def probe_journal_terminal_resurrection():
    # H8
    j, _p, _d = _new_journal()
    j.grant("p1", {})
    j.revoke("p1", "compromised")
    try:
        j.record_use("p1", {})
    except _pj.PermitJournalRefusal as exc:
        assert exc.code == "permit-journal-transition-illegal", exc.code
        st = j.permit_state("p1")
        assert st["state"] == "revoked"
        return "terminal resurrection refused (%s)" % exc.code
    raise AssertionError("use after revoke ACCEPTED")


def probe_journal_duplicate_event():
    # H9
    j, _p, _d = _new_journal()
    j.grant("p1", {}, event_id="evt-1")
    try:
        j.record_use("p1", {}, event_id="evt-1")
    except _pj.PermitJournalRefusal as exc:
        assert exc.code == "permit-journal-duplicate-event", exc.code
        return "duplicate event_id refused (%s)" % exc.code
    raise AssertionError("duplicate event_id ACCEPTED")


def probe_journal_wrong_key():
    # H10
    j, path, _d = _new_journal(key=b"k" * 32)
    j.grant("p1", {})
    try:
        _pj.PermitJournal(path, key=b"z" * 32)
    except _pj.PermitJournalCorrupted as exc:
        assert exc.code == "permit-journal-chain-broken", exc.code
        return "wrong-key reopen refused (%s)" % exc.code
    raise AssertionError("journal reopened under a WRONG key")


def probe_journal_snapshot_tamper():
    # H11: tamper the snapshot sidecar's folded states; the MAC must
    # catch it on reopen after compact.
    j, path, d = _new_journal(key=b"k" * 32)
    j.grant("p1", {"scope": "read"})
    ref = j.take_snapshot()
    sidecar = os.path.join(d, ref["snapshot_path"])
    with open(sidecar, "r", encoding="utf-8") as f:
        stored = json.load(f)
    stored["body"]["states"]["p1"]["state"] = "revoked"  # the lie
    with open(sidecar, "w", encoding="utf-8") as f:
        json.dump(stored, f)
    # compact() reloads through the tampered sidecar -> must refuse
    try:
        j.compact()
    except _pj.PermitJournalCorrupted as exc:
        assert exc.code == "permit-journal-snapshot-tampered", exc.code
        return "snapshot tamper refused at compact (%s)" % exc.code
    # belt and braces: a fresh reopen must also refuse
    try:
        _pj.PermitJournal(path, key=b"k" * 32)
    except _pj.PermitJournalCorrupted as exc:
        assert exc.code == "permit-journal-snapshot-tampered", exc.code
        return "snapshot tamper refused at reopen (%s)" % exc.code
    raise AssertionError("tampered snapshot ACCEPTED")


def probe_journal_bad_payload():
    # H12: non-serializable payload must fail closed with no write.
    j, _p, _d = _new_journal()
    try:
        j.grant("p1", {"x": object()})
    except Exception as exc:  # noqa: BLE001
        st = j.permit_state("p1")
        assert st["state"] == "unknown", "partial write happened"
        return "fail-closed, no partial write (%s)" % type(exc).__name__
    raise AssertionError("non-serializable payload ACCEPTED")


# ------------------------------------------------- evidence_graph probes


def _new_graph(**kw):
    return _eg.EvidenceGraph(**kw)


def probe_graph_ambiguous():
    # H13
    g = _new_graph()
    g.add_node("skill:abc-1", "skill")
    g.add_node("skill:abc-2", "skill")
    g.add_node("skill:xyz", "skill")
    try:
        g.link("skill:xyz", "skill:abc", "produced_by")
    except _eg.AmbiguousLink as exc:
        assert exc.code == "evidence-graph-ambiguous-link", exc.code
        return "ambiguous selector refused (%s)" % exc.code
    raise AssertionError("ambiguous selector RESOLVED")


def probe_graph_unlinked():
    # H14
    g = _new_graph()
    g.add_node("skill:xyz", "skill")
    try:
        g.link("skill:xyz", "skill:nope", "produced_by")
    except _eg.Unlinked as exc:
        assert exc.code == "evidence-graph-unlinked", exc.code
        return "unlinked selector refused (%s)" % exc.code
    raise AssertionError("unlinked selector RESOLVED")


def probe_graph_overflow():
    # H15
    g = _new_graph(max_nodes=2, max_edges=2)
    g.add_node("skill:a", "skill")
    g.add_node("skill:b", "skill")
    try:
        g.add_node("skill:c", "skill")
    except _eg.GraphOverflow as exc:
        assert exc.code == "evidence-graph-overflow", exc.code
    else:
        raise AssertionError("node cap exceeded silently")
    g.add_edge("skill:a", "skill:b", "produced_by")
    g.add_edge("skill:b", "skill:a", "produced_by")
    try:
        g.add_node("identity:z", "identity")
        g.add_edge("skill:a", "identity:z", "admitted_by")
    except _eg.GraphOverflow as exc:
        assert exc.code == "evidence-graph-overflow", exc.code
        return "node and edge caps refuse (%s)" % exc.code
    raise AssertionError("edge cap exceeded silently")


def probe_graph_attr_merge():
    # H16: re-adding a node with different attrs silently merges.
    g = _new_graph()
    g.add_node("skill:x", "skill", {"layout_id": "x", "v": 1})
    g.add_node("skill:x", "skill", {"v": 2, "extra": True})
    attrs = g._nodes["skill:x"]["attrs"]
    note = "re-add merges attrs -> %r" % (attrs,)
    # No adversary writes to the graph except the auditor's own
    # projections, which use id-consistent attrs; observed, not filed.
    return note + " (no trust boundary; documented)"


# ------------------------------------------------- skill_update probes


def _rec(name, version, digest, expires=9999999999):
    return {"name": name, "version": version, "digest": digest,
            "expires": expires}


def _pin(digest):
    return {"digest": digest, "chain_state": "trusted"}


def probe_update_legacy_map():
    # H17
    for bad in ({"x": 3}, {"x": (3,)}, {"x": ("v", "z" * 64)},
                {"": (1, "a" * 64)}):
        try:
            _su.SkillUpdateClient(bad)
        except _su.SkillUpdateError as exc:
            assert exc.code == "skill-update-malformed", exc.code
        else:
            raise AssertionError("legacy map accepted: %r" % (bad,))
    return "legacy installed maps refused (skill-update-malformed)"


def probe_update_digest_change():
    # H18: F211 regression control.
    b1 = b"bundle-one-bytes"
    b2 = b"bundle-two-bytes"
    d1 = hashlib.sha256(b1).hexdigest()
    d2 = hashlib.sha256(b2).hexdigest()
    c = _su.SkillUpdateClient()
    r1 = c.install(b1, _rec("sk", 1, d1), _pin(d1), 1)
    assert r1["digest"] == d1
    try:
        c.install(b2, _rec("sk", 1, d2), _pin(d2), 2)
    except _su.SkillUpdateError as exc:
        assert exc.code == "skill-update-digest-changed", exc.code
        assert c.installed_digest("sk") == d1, "installed digest moved"
        return "same-version digest change refused (%s)" % exc.code
    raise AssertionError("F211 REGRESSION: digest swap accepted")


def probe_update_no_aliasing():
    # H19
    d1 = hashlib.sha256(b"one").hexdigest()
    owned = {"sk": (1, d1)}
    c = _su.SkillUpdateClient(owned)
    owned["sk"] = (1, "f" * 64)
    owned["other"] = (9, d1)
    assert c.installed_digest("sk") == d1, "client aliased caller dict"
    assert c.installed_version("other") is None
    return "constructor copies installed state (no aliasing)"


def probe_update_idempotent():
    # H20: honest path -- identical bytes reinstall stays allowed.
    b1 = b"same-bytes"
    d1 = hashlib.sha256(b1).hexdigest()
    c = _su.SkillUpdateClient()
    c.install(b1, _rec("sk", 1, d1), _pin(d1), 1)
    r2 = c.install(b1, _rec("sk", 1, d1), _pin(d1), 2)
    assert r2 == {"name": "sk", "version": 1, "digest": d1}
    return "identical-bytes reinstall idempotent"


# ------------------------------------------------- green checks (depth-1)


def _green():
    """Depth-1: run the adjacent wave-250 batteries with
    GOV_SKIP_GREEN=1 and require zero BREAK/ERROR. Honors
    GOV_SKIP_GREEN itself (records skip, never spawns)."""
    import subprocess
    if GREEN_SKIP:
        return ["green checks skipped (GOV_SKIP_GREEN=1)"]
    here = os.path.dirname(os.path.abspath(__file__))
    batteries = [
        "w250_decision_log_probes.py",
        "w250_permit_journal_probes.py",
        "w250_evidence_graph_probes.py",
        "w248_skill_update_probes.py",
    ]
    notes = []
    for bat in batteries:
        path = os.path.join(here, bat)
        if not os.path.exists(path):
            notes.append("%s: missing, skipped" % bat)
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        tmpd = _mktmp()
        env["TMPDIR"] = tmpd
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600, cwd=os.path.join(here, ".."))
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("%s green check failed: %r" % (bat, exc))
        out = (proc.stdout or "") + (proc.stderr or "")
        # D8 (wave-315): match the canonical [BREAK] probe-line form,
        # not the "BREAK" substring (the canonical summary
        # "N BREAK / M HELD / K ERROR" contains it).
        if "[BREAK]" in out or proc.returncode != 0:
            raise AssertionError(
                "%s green check not green (rc=%d):\n%s"
                % (bat, proc.returncode, out[-2000:]))
        notes.append("%s: green" % bat)
    return notes


# ------------------------------------------------- main


PROBES = [
    ("log-forged-inclusion-proof", probe_log_forged_proof, HAVE_LOG),
    ("log-equivocation-detected", probe_log_equivocation_control, HAVE_LOG),
    ("log-post-append-mutation-hides", probe_log_mutation_hides, HAVE_LOG),
    ("log-post-append-mutation-fabricates", probe_log_mutation_fabricates,
     HAVE_LOG),
    ("log-bogus-proof-index", probe_log_bogus_index, HAVE_LOG),
    ("log-sth-tamper-and-epoch-replay", probe_log_sth_and_epoch, HAVE_LOG),
    ("journal-forged-mac", probe_journal_forged_mac, HAVE_PJ),
    ("journal-terminal-resurrection", probe_journal_terminal_resurrection,
     HAVE_PJ),
    ("journal-duplicate-event-id", probe_journal_duplicate_event, HAVE_PJ),
    ("journal-wrong-key-reopen", probe_journal_wrong_key, HAVE_PJ),
    ("journal-snapshot-tamper", probe_journal_snapshot_tamper, HAVE_PJ),
    ("journal-nonserializable-payload", probe_journal_bad_payload, HAVE_PJ),
    ("graph-ambiguous-link", probe_graph_ambiguous, HAVE_EG),
    ("graph-unlinked-selector", probe_graph_unlinked, HAVE_EG),
    ("graph-overflow", probe_graph_overflow, HAVE_EG),
    ("graph-attr-merge-observed", probe_graph_attr_merge, HAVE_EG),
    ("update-legacy-installed-map", probe_update_legacy_map, HAVE_SU),
    ("update-same-version-digest-change", probe_update_digest_change,
     HAVE_SU),
    ("update-no-aliasing", probe_update_no_aliasing, HAVE_SU),
    ("update-identical-bytes-idempotent", probe_update_idempotent, HAVE_SU),
]


def main():
    results = []
    for name, fn, have in PROBES:
        results.append(_run_probe(name, fn, have))
    held = sum(1 for _n, v, _x in results if v == "HELD")
    brk = sum(1 for _n, v, _x in results if v == "BREAK")
    err = sum(1 for _n, v, _x in results if v == "ERROR")
    try:
        for note in _green():
            print("  green: %s" % note)
    except AssertionError as exc:
        print("  GREEN-CHECK FAILED: %s" % (exc,))
        return 2
    _coh_ok, _coh_diags = probe_lines.check_coherence(results, brk, held, err)
    probe_lines.emit(results)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    if brk or err:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
