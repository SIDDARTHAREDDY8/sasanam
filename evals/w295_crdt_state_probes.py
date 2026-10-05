"""Wave-295 lane 4 battery: signed CRDT shared state.

Base: wave-294 merge 5a88d9fa (verified via git rev-parse HEAD before work).

New product surface:
  (a) gov/coordination_state.py -- signed change DAG (automerge
      pattern, authorship gap fixed by Ed25519 over (actor_id, seq,
      payload, parents, author key)). Per-actor seq; replay is
      idempotent; seq-reuse-with-different-content refuses coded
      coord-state-overwrite; merge is union-only and deterministic
      (sorted by (seq, actor_id, digest)); forks are first-class
      (merge returns merged head + fork records);
  (b) 4 new decision codes at true sorted positions; lane pin
      1746 -> 1746.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module); on the fixed tree they must
HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g295-cs && TMPDIR=/var/tmp/g295-cs \
    ~/workspace/.gov-venv/bin/python evals/w295_crdt_state_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g295-cs2 \
    ~/workspace/.gov-venv/bin/python evals/w295_crdt_state_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 2127 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable). Wave-295 lane 4: pin 1742 -> 1746 (+4 coord-state-*); Wave-295 merge: pin 1746 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "code literals not sorted")
    for want in ("coord-state-bound", "coord-state-forgery",
                 "coord-state-invalid", "coord-state-overwrite"):
        if want not in lits:
            return _record("pin-taxonomy", "BREAK",
                           "missing expected code %r" % want)
    _record("pin-taxonomy", "HELD", "1991 raw literals, unique, sorted")




def _import_cs():
    try:
        from gov import coordination_state
        return coordination_state
    except ImportError as e:
        return e


def _need(pid):
    """On the pristine base every functional probe BREAKs (module
    absent). On the fixed tree the import succeeds."""
    cs = _import_cs()
    if isinstance(cs, Exception):
        _record(pid, "BREAK", "gov/coordination_state.py absent: %r" % (cs,))
        return None
    return cs


_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_EVE = bytes(range(97, 129))


def _pub(seed):
    from gov import ed25519
    return ed25519.publickey(seed).hex()


def _set(key, value="v"):
    return {"op": "set", "key": key, "value": value}


def _expect_code(pid, fn, want_code, note):
    """fn must raise with .code == want_code; anything else is BREAK."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != want_code:
            return _record(pid, "BREAK",
                           "wrong code for %s: got %r (%r), want %r"
                           % (note, getattr(e, "code", None), e, want_code))
        return _record(pid, "HELD", "%s -> coded %s" % (note, want_code))
    return _record(pid, "BREAK", "%s accepted (want coded %s)"
                   % (note, want_code))


def p_import():
    cs = _need("cs-import")
    if cs is None:
        return
    for name in ("StateDag", "sign_change", "verify_change",
                 "change_digest", "CoordinationStateError"):
        if not hasattr(cs, name):
            return _record("cs-import", "BREAK",
                           "missing export %r" % name)
    _record("cs-import", "HELD", "module exports present")


def p_sign_ingest_verify():
    cs = _need("cs-sign-ingest-verify")
    if cs is None:
        return
    d = cs.StateDag("r", {_pub(_SEED_A), _pub(_SEED_B)})
    ch = cs.sign_change(_SEED_A, "agent-a", 1, _set("k", "v"))
    out = d.ingest(ch)
    if not (out["applied"] is True and out["digest"] == ch["digest"]):
        return _record("cs-sign-ingest-verify", "BREAK",
                       "ingest shape wrong: %r" % (out,))
    ok, detail = cs.verify_change(ch, {_pub(_SEED_A)})
    if ok is not True or detail["digest"] != ch["digest"]:
        return _record("cs-sign-ingest-verify", "BREAK",
                       "verify_change failed on a good change")
    _record("cs-sign-ingest-verify", "HELD",
            "sign -> ingest -> verify roundtrip")


def p_forged_signature():
    cs = _need("cs-forged-signature")
    if cs is None:
        return
    d = cs.StateDag("r", {_pub(_SEED_A)})
    ch = cs.sign_change(_SEED_A, "agent-a", 1, _set("k"))
    ch["signature"] = "00" * 64
    _expect_code("cs-forged-signature",
                 lambda: d.ingest(ch), "coord-state-forgery",
                 "zeroed signature on a fork")


def p_swapped_key_forgery():
    cs = _need("cs-swapped-key-forgery")
    if cs is None:
        return
    d = cs.StateDag("r", {_pub(_SEED_A), _pub(_SEED_EVE)})
    ch = cs.sign_change(_SEED_EVE, "agent-a", 1, _set("k"))
    ch["author_pubkey"] = _pub(_SEED_A)  # Eve claims to be A
    _expect_code("cs-swapped-key-forgery",
                 lambda: d.ingest(ch), "coord-state-forgery",
                 "Eve's signature under A's claimed key")


def p_unknown_author():
    cs = _need("cs-unknown-author")
    if cs is None:
        return
    d = cs.StateDag("r", {_pub(_SEED_A)})
    ch = cs.sign_change(_SEED_B, "agent-b", 1, _set("k"))
    _expect_code("cs-unknown-author",
                 lambda: d.ingest(ch), "coord-state-invalid",
                 "well-signed change by an untrusted key")


def p_replay_idempotent():
    cs = _need("cs-replay-idempotent")
    if cs is None:
        return
    d = cs.StateDag("r", {_pub(_SEED_A)})
    ch = cs.sign_change(_SEED_A, "agent-a", 1, _set("k"))
    d.ingest(ch)
    out = d.ingest(ch)
    if out["applied"] is not False or out["duplicate"] is not True \
            or len(d) != 1:
        return _record("cs-replay-idempotent", "BREAK",
                       "replay was not an idempotent no-op: %r" % (out,))
    _record("cs-replay-idempotent", "HELD",
            "old change replayed: not re-applied")


def p_seq_reuse_overwrite():
    cs = _need("cs-seq-reuse-overwrite")
    if cs is None:
        return
    d = cs.StateDag("r", {_pub(_SEED_A)})
    d.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k", "v1")))
    other = cs.sign_change(_SEED_A, "agent-a", 1, _set("k", "v2"))
    _expect_code("cs-seq-reuse-overwrite",
                 lambda: d.ingest(other), "coord-state-overwrite",
                 "same (actor, seq) with different content")


def p_seq_gap():
    cs = _need("cs-seq-gap")
    if cs is None:
        return
    d = cs.StateDag("r", {_pub(_SEED_A)})
    d.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k")))
    _expect_code("cs-seq-gap",
                 lambda: d.ingest(cs.sign_change(_SEED_A, "agent-a", 3,
                                                 _set("k"))),
                 "coord-state-invalid", "seq jump 1 -> 3")


def _two_forked_dags(cs):
    da = cs.StateDag("r", {_pub(_SEED_A), _pub(_SEED_B)})
    db = cs.StateDag("r", {_pub(_SEED_A), _pub(_SEED_B)})
    a1 = da.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k"))
                   )["digest"]
    db.ingest(da.get(a1))
    da.ingest(cs.sign_change(_SEED_A, "agent-a", 2, _set("ka", "a"),
                             parents=[a1]))
    db.ingest(cs.sign_change(_SEED_B, "agent-b", 1, _set("kb", "b"),
                             parents=[a1]))
    return da, db


def p_merge_determinism():
    cs = _need("cs-merge-determinism")
    if cs is None:
        return
    da, db = _two_forked_dags(cs)
    h1, f1 = da.merge(db)
    da2, db2 = _two_forked_dags(cs)
    h2, f2 = db2.merge(da2)
    if h1 != h2 or f1 != f2:
        return _record("cs-merge-determinism", "BREAK",
                       "merge order changed the outcome: %r vs %r"
                       % (h1, h2))
    _record("cs-merge-determinism", "HELD",
            "two merge orders -> same head %s" % h1[:16])


def p_fork_record():
    cs = _need("cs-fork-record")
    if cs is None:
        return
    da, db = _two_forked_dags(cs)
    head, forks = da.merge(db)
    if len(da) != 3:
        return _record("cs-fork-record", "BREAK",
                       "merge lost changes: %d" % len(da))
    if len(forks) != 1:
        return _record("cs-fork-record", "BREAK",
                       "expected 1 fork record, got %d" % len(forks))
    fr = forks[0]
    if fr["base"] is None or len(fr["changes"]) != 1:
        return _record("cs-fork-record", "BREAK",
                       "fork record malformed: %r" % (fr,))
    _record("cs-fork-record", "HELD",
            "fork is first-class: tip %.8s base %.8s"
            % (fr["tip"], fr["base"]))


def p_merge_never_deletes():
    cs = _need("cs-merge-never-deletes")
    if cs is None:
        return
    da, db = _two_forked_dags(cs)
    before = {c["digest"] for c in da.all_changes()} | \
             {c["digest"] for c in db.all_changes()}
    da.merge(db)
    after = {c["digest"] for c in da.all_changes()}
    if before != after:
        return _record("cs-merge-never-deletes", "BREAK",
                       "merge deleted or mutated a signed change")
    _record("cs-merge-never-deletes", "HELD",
            "union-only merge: %d changes preserved" % len(after))


def p_payload_over_bound():
    cs = _need("cs-payload-over-bound")
    if cs is None:
        return
    _expect_code("cs-payload-over-bound",
                 lambda: cs.sign_change(_SEED_A, "agent-a", 1,
                                        _set("k", "x" * 5000)),
                 "coord-state-bound", "5000-char value smuggling")


def p_too_many_changes():
    cs = _need("cs-too-many-changes")
    if cs is None:
        return
    old = cs._MAX_CHANGES
    cs._MAX_CHANGES = 2
    try:
        d = cs.StateDag("r", {_pub(_SEED_A), _pub(_SEED_B),
                              _pub(_SEED_C)})
        d.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k1")))
        d.ingest(cs.sign_change(_SEED_B, "agent-b", 1, _set("k2")))
        _expect_code("cs-too-many-changes",
                     lambda: d.ingest(cs.sign_change(
                         _SEED_C, "agent-c", 1, _set("k3"))),
                     "coord-state-bound", "change 3 of max 2")
    finally:
        cs._MAX_CHANGES = old


def p_malformed_change():
    cs = _need("cs-malformed-change")
    if cs is None:
        return
    d = cs.StateDag("r", {_pub(_SEED_A)})
    for bad in (None, [], "x", {"actor_id": "agent-a"},
                {"actor_id": "agent-a", "seq": 1, "parents": [],
                 "payload": {"op": "nuke"}, "author_pubkey": _pub(_SEED_A),
                 "signature": "00" * 64}):
        try:
            d.ingest(bad)
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) not in (
                    "coord-state-invalid", "coord-state-forgery"):
                return _record("cs-malformed-change", "BREAK",
                               "uncoded refusal for %r: %r" % (bad, e))
        else:
            return _record("cs-malformed-change", "BREAK",
                           "malformed change accepted: %r" % (bad,))
    _record("cs-malformed-change", "HELD",
            "non-dict/truncated/bad-op changes refused coded")


def p_circular_payload():
    cs = _need("cs-circular-payload")
    if cs is None:
        return
    evil = {}
    evil["self"] = evil
    _expect_code("cs-circular-payload",
                 lambda: cs.sign_change(_SEED_A, "agent-a", 1, evil),
                 "coord-state-invalid",
                 "circular payload (F351-class: no bare ValueError)")


def p_merge_forged_peer():
    cs = _need("cs-merge-forged-peer")
    if cs is None:
        return
    da = cs.StateDag("r", {_pub(_SEED_A), _pub(_SEED_B)})
    db = cs.StateDag("r", {_pub(_SEED_A), _pub(_SEED_B)})
    da.ingest(cs.sign_change(_SEED_A, "agent-a", 1, _set("k")))
    forged = cs.sign_change(_SEED_EVE, "agent-b", 1, _set("evil"))
    forged["author_pubkey"] = _pub(_SEED_B)
    db._changes[forged["digest"]] = dict(forged)
    _expect_code("cs-merge-forged-peer",
                 lambda: da.merge(db), "coord-state-forgery",
                 "merge of a peer carrying a forged change")


def p_offline_fork_rejoin():
    cs = _need("cs-offline-fork-rejoin")
    if cs is None:
        return
    main = cs.StateDag("r", {_pub(_SEED_A), _pub(_SEED_B)})
    root = main.ingest(cs.sign_change(_SEED_A, "agent-a", 1,
                                      _set("root")))["digest"]
    offline = cs.StateDag("r", {_pub(_SEED_A), _pub(_SEED_B)})
    offline.ingest(main.get(root))
    offline.ingest(cs.sign_change(_SEED_B, "agent-b", 1,
                                  _set("offline-key", "v"),
                                  parents=[root]))
    main.ingest(cs.sign_change(_SEED_A, "agent-a", 2,
                               _set("main-key", "v"), parents=[root]))
    head, forks = main.merge(offline)
    if len(main) != 3 or len(forks) != 1:
        return _record("cs-offline-fork-rejoin", "BREAK",
                       "rejoin wrong: %d changes, %d forks"
                       % (len(main), len(forks)))
    state = main.materialize()
    if state != {"root": "v", "offline-key": "v", "main-key": "v"}:
        return _record("cs-offline-fork-rejoin", "BREAK",
                       "materialized state wrong: %r" % (state,))
    _record("cs-offline-fork-rejoin", "HELD",
            "offline fork rejoined as first-class fork")


def p_key_grammar():
    cs = _need("cs-key-grammar")
    if cs is None:
        return
    _expect_code("cs-key-grammar",
                 lambda: cs.sign_change(_SEED_A, "agent-a", 1,
                                        _set("BAD KEY!")),
                 "coord-state-invalid", "payload key outside grammar")


def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        _record("green-%s" % name, "HELD", "skipped via GOV_SKIP_GREEN=1")
        return
    tmp = tempfile.mkdtemp(prefix="g295-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        # The w293 redteam battery re-pins 9 prior batteries as part of
        # its main probes; it needs ~10 minutes wall-clock.
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=1500, env=env, cwd=REPO).stdout
    except Exception as e:  # noqa: BLE001
        return _record("green-%s" % name, "ERROR",
                       "green check crashed: %r" % (e,))
    bad = [ln for ln in out.splitlines()
           if ln.strip().startswith("[BREAK]")
           and not any(t in ln for t in tolerate)]
    if bad:
        _record("green-%s" % name, "BREAK",
                "unexpected breaks: %s" % "; ".join(bad[:5]))
    else:
        _record("green-%s" % name, "HELD", "green check held")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    for pid, fn in [
        ("cs-import", p_import),
        ("cs-sign-ingest-verify", p_sign_ingest_verify),
        ("cs-forged-signature", p_forged_signature),
        ("cs-swapped-key-forgery", p_swapped_key_forgery),
        ("cs-unknown-author", p_unknown_author),
        ("cs-replay-idempotent", p_replay_idempotent),
        ("cs-seq-reuse-overwrite", p_seq_reuse_overwrite),
        ("cs-seq-gap", p_seq_gap),
        ("cs-merge-determinism", p_merge_determinism),
        ("cs-fork-record", p_fork_record),
        ("cs-merge-never-deletes", p_merge_never_deletes),
        ("cs-payload-over-bound", p_payload_over_bound),
        ("cs-too-many-changes", p_too_many_changes),
        ("cs-malformed-change", p_malformed_change),
        ("cs-circular-payload", p_circular_payload),
        ("cs-merge-forged-peer", p_merge_forged_peer),
        ("cs-offline-fork-rejoin", p_offline_fork_rejoin),
        ("cs-key-grammar", p_key_grammar),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w294_coord_lease_probes.py"),
                 "w294-coord-lease", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w293_redteam_probes.py"),
                 "w293-redteam", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w295_crdt_state: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
