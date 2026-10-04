"""Wave-298 lane 2 battery: bi-temporal agent memory store.

Base: wave-297 merge 5662f8874b63724a1bfd1f4441b470bfe1ba43d8
(verified via git rev-parse HEAD before work).

New product surface:
  (a) gov/memory_store.py -- bi-temporal agent memory store
      (graphiti/cognee pattern): immutable signed episodes,
      bi-temporal semantic facts (valid_at/invalid_at x
      created_at/expired_at), supersession that closes old records
      (never deletes history), retraction as a SIGNED TOMBSTONE
      (no delete API exists), Admiralty reliability grading,
      computed corroboration counts, declared retention schedules;
  (b) 5 new decision codes at true sorted positions; lane pin
      1774 -> 1774; wave-298 merge: pin 1774 -> 1780.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module); on the fixed tree they must
HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g298-ms && TMPDIR=/var/tmp/g298-ms \
    ~/workspace/.gov-venv/bin/python evals/w298_memory_store_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g298-ms2 \
    ~/workspace/.gov-venv/bin/python evals/w298_memory_store_probes.py
"""

import hashlib
import json
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

TAXONOMY_PIN = 1934 # Wave-297 merge: pin 1769; Wave-298 lane 2: pin 1769 -> 1774 (+5 memory-store-*); wave-298 merge: pin 1774 -> 1780 (+11 codes); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

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
    for want in ("memory-store-expired", "memory-store-invalid",
                 "memory-store-retention-lapsed", "memory-store-tombstoned",
                 "memory-store-unsigned-retraction"):
        if want not in lits:
            return _record("pin-taxonomy", "BREAK",
                           "missing expected code %r" % want)
    _record("pin-taxonomy", "HELD", "1916 raw literals, unique, sorted")


def _import_ms():
    try:
        import gov.memory_store as ms
        from gov import ed25519 as ed
        return ms, ed
    except ImportError:
        return None, None


def _need(pid):
    ms, ed = _import_ms()
    if ms is None:
        _record(pid, "BREAK", "feature absent on this tree "
                              "(gov.memory_store missing)")
        return None, None, None
    return ms, ed, True


def _seed(tag):
    return hashlib.sha256(("w298-memorystore-%s" % tag).encode()).digest()


def _pub(ed, seed):
    return ed.publickey(seed).hex()


def _canon(body):
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def _world(ms, ed):
    sa, sb, arch = _seed("a"), _seed("b"), _seed("arch")
    store = ms.MemoryStore(archivists={"chief": _pub(ed, arch)})
    return store, {"a": sa, "b": sb, "arch": arch}


def _episode(ms, ed, store, seed, principal, tag="e", at=1000):
    agent = "agent-%s" % tag
    digest = hashlib.sha256(("content-%s" % tag).encode()).hexdigest()
    body = {"agent_id": agent, "content_digest": digest,
            "source_principal": principal, "source_pubkey": _pub(ed, seed),
            "recorded_at": at}
    sig = ed.sign(seed, _canon(body)).hex()
    return store.record_episode(agent, digest, principal, _pub(ed, seed),
                                sig, at)


def _fact(ms, ed, store, seed, principal, key, stmt, episodes, valid_at=1000,
          recorded_at=1100, retain_until=None, reliability="C",
          credibility=3):
    digest = hashlib.sha256(("stmt-%s" % stmt).encode()).hexdigest()
    body = {"statement_key": key, "statement_digest": digest,
            "source_episode_ids": sorted(episodes),
            "source_principal": principal, "source_pubkey": _pub(ed, seed),
            "valid_at": valid_at, "retain_until": retain_until,
            "reliability": reliability, "credibility": credibility,
            "created_at": recorded_at}
    sig = ed.sign(seed, _canon(body)).hex()
    return store.record_fact(key, digest, episodes, principal,
                             _pub(ed, seed), sig, valid_at, recorded_at,
                             retain_until=retain_until,
                             reliability=reliability, credibility=credibility)


def _retract(ms, ed, store, seed, principal, key, at=3000):
    body = {"statement_key": key, "retractor_principal": principal,
            "retractor_pubkey": _pub(ed, seed), "retracted_at": at}
    sig = ed.sign(seed, _canon(body)).hex()
    return store.retract_fact(key, principal, _pub(ed, seed), sig, at)


def p_import():
    ms, ed, ok = _need("ms-import")
    if not ok:
        return
    _record("ms-import", "HELD", "gov.memory_store imports")


def p_episode():
    ms, ed, ok = _need("ms-episode")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    e1 = _episode(ms, ed, store, seeds["a"], "alice")
    e2 = _episode(ms, ed, store, seeds["a"], "alice")  # idempotent
    if e1 != e2 or not re.match(r"^[0-9a-f]{64}$", e1):
        return _record("ms-episode", "BREAK",
                       "episode id not deterministic: %r %r" % (e1, e2))
    _record("ms-episode", "HELD", "episode recorded, idempotent id")


def p_episode_forged():
    ms, ed, ok = _need("ms-episode-forged")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    try:
        store.record_episode("agent-x", "0" * 64, "mallory",
                             _pub(ed, seeds["a"]),
                             ed.sign(seeds["b"], b"nope").hex(), 1000)
        return _record("ms-episode-forged", "BREAK",
                       "forged episode signature accepted")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_INVALID:
            return _record("ms-episode-forged", "BREAK",
                           "wrong code: %r" % (e.code,))
    _record("ms-episode-forged", "HELD",
            "forged episode refuses memory-store-invalid")


def p_fact_recall():
    ms, ed, ok = _need("ms-fact-recall")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    eid = _episode(ms, ed, store, seeds["a"], "alice")
    _fact(ms, ed, store, seeds["a"], "alice", "sky-color", "blue", [eid])
    got = store.recall("sky-color", 1200)
    for field in ("fact_id", "statement_digest", "source_episode_ids",
                  "source_principal", "valid_at", "invalid_at",
                  "created_at", "expired_at", "reliability_grade",
                  "corroboration_count"):
        if field not in got:
            return _record("ms-fact-recall", "BREAK",
                           "recall view missing %r" % (field,))
    if got["reliability_grade"] != "C3" or got["corroboration_count"] != 1:
        return _record("ms-fact-recall", "BREAK",
                       "grade/corroboration wrong: %r" % (got,))
    _record("ms-fact-recall", "HELD",
            "fact recorded; recall carries provenance+grade+count")


def p_fact_bad_provenance():
    ms, ed, ok = _need("ms-fact-bad-prov")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    try:
        _fact(ms, ed, store, seeds["a"], "alice", "k", "s", ["0" * 64])
        return _record("ms-fact-bad-prov", "BREAK",
                       "fact citing unknown episode accepted")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_INVALID:
            return _record("ms-fact-bad-prov", "BREAK",
                           "wrong code: %r" % (e.code,))
    _record("ms-fact-bad-prov", "HELD",
            "unknown episode reference refuses memory-store-invalid")


def p_fact_bad_grade():
    ms, ed, ok = _need("ms-fact-bad-grade")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    eid = _episode(ms, ed, store, seeds["a"], "alice")
    for kw in ({"reliability": "G"}, {"credibility": 7},
               {"credibility": 0}):
        try:
            _fact(ms, ed, store, seeds["a"], "alice", "k", "s", [eid],
                  **kw)
            return _record("ms-fact-bad-grade", "BREAK",
                           "bad grade accepted: %r" % (kw,))
        except ms.MemoryStoreError as e:
            if e.code != ms.MEM_INVALID:
                return _record("ms-fact-bad-grade", "BREAK",
                               "wrong code: %r" % (e.code,))
    _record("ms-fact-bad-grade", "HELD",
            "out-of-range Admiralty grades refuse memory-store-invalid")


def p_supersession():
    ms, ed, ok = _need("ms-supersession")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    e1 = _episode(ms, ed, store, seeds["a"], "alice")
    e2 = _episode(ms, ed, store, seeds["a"], "alice", tag="e2", at=2000)
    _fact(ms, ed, store, seeds["a"], "alice", "k", "v1", [e1],
          valid_at=1000, recorded_at=1100)
    _fact(ms, ed, store, seeds["a"], "alice", "k", "v2", [e2],
          valid_at=2000, recorded_at=2100)
    hist = store.history("k", 2200)
    if len(hist) != 2:
        return _record("ms-supersession", "BREAK",
                       "history lost records: %d" % len(hist))
    if hist[0]["invalid_at"] != 2000 or hist[0]["expired_at"] != 2100:
        return _record("ms-supersession", "BREAK",
                       "old record not closed: %r" % (hist[0],))
    if hist[1]["invalid_at"] is not None:
        return _record("ms-supersession", "BREAK",
                       "new record wrongly closed")
    old = store.recall("k", 1500)  # bi-temporal: old T -> old claim
    if old["statement_digest"] != hashlib.sha256(b"stmt-v1").hexdigest():
        return _record("ms-supersession", "BREAK",
                       "historical recall wrong")
    new = store.recall("k", 2200)
    if new["statement_digest"] != hashlib.sha256(b"stmt-v2").hexdigest():
        return _record("ms-supersession", "BREAK", "current recall wrong")
    _record("ms-supersession", "HELD",
            "supersession closes old edge; history preserved; "
            "bi-temporal recall correct")


def p_recall_boundaries():
    ms, ed, ok = _need("ms-recall-boundaries")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    eid = _episode(ms, ed, store, seeds["a"], "alice")
    _fact(ms, ed, store, seeds["a"], "alice", "k", "s", [eid],
          valid_at=1000, recorded_at=1100)
    store.recall("k", 1100)  # left-closed: at valid_at/created_at -> OK
    try:
        store.recall("k", 1050)  # before created_at -> expired
        return _record("ms-recall-boundaries", "BREAK",
                       "recall before created_at accepted")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_EXPIRED:
            return _record("ms-recall-boundaries", "BREAK",
                           "wrong code: %r" % (e.code,))
    try:
        store.recall("nope", 1200)  # unknown key -> invalid
        return _record("ms-recall-boundaries", "BREAK",
                       "unknown key accepted")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_INVALID:
            return _record("ms-recall-boundaries", "BREAK",
                           "wrong code: %r" % (e.code,))
    _record("ms-recall-boundaries", "HELD",
            "half-open boundaries + unknown-key refusal coded")


def p_no_delete():
    ms, ed, ok = _need("ms-no-delete")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    for name in ("delete_fact", "remove_fact", "delete", "remove",
                 "purge", "forget"):
        if hasattr(store, name):
            return _record("ms-no-delete", "BREAK",
                           "store grew a %r method" % name)
    try:
        store.delete_fact("k")
        return _record("ms-no-delete", "BREAK", "delete_fact callable")
    except AttributeError:
        pass
    _record("ms-no-delete", "HELD",
            "no delete API exists -- deletion is absent, not governed")


def p_retract_wrong_key():
    ms, ed, ok = _need("ms-retract-wrong-key")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    eid = _episode(ms, ed, store, seeds["a"], "alice")
    _fact(ms, ed, store, seeds["a"], "alice", "k", "s", [eid])
    try:
        _retract(ms, ed, store, seeds["b"], "bob", "k")
        return _record("ms-retract-wrong-key", "BREAK",
                       "unauthorized retraction accepted")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_UNSIGNED_RETRACTION:
            return _record("ms-retract-wrong-key", "BREAK",
                           "wrong code: %r" % (e.code,))
    _record("ms-retract-wrong-key", "HELD",
            "foreign-key retraction refuses memory-store-unsigned-"
            "retraction")


def p_retract_tampered_sig():
    ms, ed, ok = _need("ms-retract-tampered")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    eid = _episode(ms, ed, store, seeds["a"], "alice")
    _fact(ms, ed, store, seeds["a"], "alice", "k", "s", [eid])
    body = {"statement_key": "k", "retractor_principal": "alice",
            "retractor_pubkey": _pub(ed, seeds["a"]), "retracted_at": 3000}
    sig = ed.sign(seeds["a"], _canon(body)).hex()
    bad = ("00" if sig[:2] != "00" else "ff") + sig[2:]
    try:
        store.retract_fact("k", "alice", _pub(ed, seeds["a"]), bad, 3000)
        return _record("ms-retract-tampered", "BREAK",
                       "tampered retraction signature accepted")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_UNSIGNED_RETRACTION:
            return _record("ms-retract-tampered", "BREAK",
                           "wrong code: %r" % (e.code,))
    _record("ms-retract-tampered", "HELD",
            "tampered tombstone refuses memory-store-unsigned-retraction")


def p_retract_source():
    ms, ed, ok = _need("ms-retract-source")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    eid = _episode(ms, ed, store, seeds["a"], "alice")
    _fact(ms, ed, store, seeds["a"], "alice", "k", "s", [eid])
    tid = _retract(ms, ed, store, seeds["a"], "alice", "k")
    if not re.match(r"^[0-9a-f]{64}$", tid):
        return _record("ms-retract-source", "BREAK",
                       "tombstone id malformed")
    try:
        store.recall("k", 1200)  # retracted -> refused at ANY instant
        return _record("ms-retract-source", "BREAK",
                       "retracted fact still recallable")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_TOMBSTONED:
            return _record("ms-retract-source", "BREAK",
                           "wrong code: %r" % (e.code,))
    hist = store.history("k", 3100)
    if len(hist) != 2 or not hist[-1].get("tombstoned"):
        return _record("ms-retract-source", "BREAK",
                       "tombstone missing from history")
    if hist[0]["invalid_at"] != 3000:
        return _record("ms-retract-source", "BREAK",
                       "tombstone did not close validity window")
    _record("ms-retract-source", "HELD",
            "source-key retraction tombstones; history keeps the digest")


def p_retract_archivist():
    ms, ed, ok = _need("ms-retract-archivist")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    eid = _episode(ms, ed, store, seeds["a"], "alice")
    _fact(ms, ed, store, seeds["a"], "alice", "k", "s", [eid])
    _retract(ms, ed, store, seeds["arch"], "chief", "k")
    try:
        store.recall("k", 1200)
        return _record("ms-retract-archivist", "BREAK",
                       "archivist retraction did not take")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_TOMBSTONED:
            return _record("ms-retract-archivist", "BREAK",
                           "wrong code: %r" % (e.code,))
    _record("ms-retract-archivist", "HELD",
            "named archivist may sign retractions")


def p_retract_twice():
    ms, ed, ok = _need("ms-retract-twice")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    eid = _episode(ms, ed, store, seeds["a"], "alice")
    _fact(ms, ed, store, seeds["a"], "alice", "k", "s", [eid])
    _retract(ms, ed, store, seeds["a"], "alice", "k")
    try:
        _retract(ms, ed, store, seeds["a"], "alice", "k", at=3100)
        return _record("ms-retract-twice", "BREAK",
                       "double retraction accepted")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_TOMBSTONED:
            return _record("ms-retract-twice", "BREAK",
                           "wrong code: %r" % (e.code,))
    _record("ms-retract-twice", "HELD",
            "retraction is a tombstone, not a toggle")


def p_retention_lapse():
    ms, ed, ok = _need("ms-retention-lapse")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    eid = _episode(ms, ed, store, seeds["a"], "alice")
    _fact(ms, ed, store, seeds["a"], "alice", "k", "s", [eid],
          recorded_at=1100, retain_until=2000)
    store.recall("k", 1500)
    try:
        store.recall("k", 2000)
        return _record("ms-retention-lapse", "BREAK",
                       "lapsed record still recallable")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_RETENTION_LAPSED:
            return _record("ms-retention-lapse", "BREAK",
                           "wrong code: %r" % (e.code,))
    try:
        store.history("k", 2000)
        return _record("ms-retention-lapse", "BREAK",
                       "lapsed record still in history")
    except ms.MemoryStoreError as e:
        if e.code != ms.MEM_RETENTION_LAPSED:
            return _record("ms-retention-lapse", "BREAK",
                           "wrong code: %r" % (e.code,))
    _record("ms-retention-lapse", "HELD",
            "lapsed retention refuses loud on recall and history")


def p_corroboration():
    ms, ed, ok = _need("ms-corroboration")
    if not ok:
        return
    store, seeds = _world(ms, ed)
    e1 = _episode(ms, ed, store, seeds["a"], "alice")
    e2 = _episode(ms, ed, store, seeds["b"], "bob", tag="e2", at=2000)
    _fact(ms, ed, store, seeds["a"], "alice", "k", "same", [e1],
          valid_at=1000, recorded_at=1100)
    _fact(ms, ed, store, seeds["b"], "bob", "k", "same", [e2],
          valid_at=2000, recorded_at=2100)
    got = store.recall("k", 2200)
    if got["corroboration_count"] != 2:
        return _record("ms-corroboration", "BREAK",
                       "corroboration count wrong: %r" % (got,))
    _record("ms-corroboration", "HELD",
            "corroboration counts distinct source principals")


def p_ed25519_contract():
    ms, ed, ok = _need("ms-ed25519-contract")
    if not ok:
        return
    seed = _seed("contract")
    pub = ed.publickey(seed)
    msg = b"contract"
    sig = ed.sign(seed, msg)
    if ed.verify(pub, msg, sig) is not True:
        return _record("ms-ed25519-contract", "BREAK",
                       "good signature did not verify is True")
    bad = bytearray(sig)
    bad[0] ^= 1
    if ed.verify(pub, msg, bytes(bad)) is not False:
        return _record("ms-ed25519-contract", "BREAK",
                       "forged signature did not verify is False")
    _record("ms-ed25519-contract", "HELD",
            "ed25519.verify contract pinned: is True / is False")


def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        _record("green-%s" % name, "HELD", "skipped via GOV_SKIP_GREEN=1")
        return
    tmp = tempfile.mkdtemp(prefix="g298-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO).stdout
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
        ("ms-import", p_import),
        ("ms-episode", p_episode),
        ("ms-episode-forged", p_episode_forged),
        ("ms-fact-recall", p_fact_recall),
        ("ms-fact-bad-prov", p_fact_bad_provenance),
        ("ms-fact-bad-grade", p_fact_bad_grade),
        ("ms-supersession", p_supersession),
        ("ms-recall-boundaries", p_recall_boundaries),
        ("ms-no-delete", p_no_delete),
        ("ms-retract-wrong-key", p_retract_wrong_key),
        ("ms-retract-tampered", p_retract_tampered_sig),
        ("ms-retract-source", p_retract_source),
        ("ms-retract-archivist", p_retract_archivist),
        ("ms-retract-twice", p_retract_twice),
        ("ms-retention-lapse", p_retention_lapse),
        ("ms-corroboration", p_corroboration),
        ("ms-ed25519-contract", p_ed25519_contract),
    ]:
        _safe(pid, fn)
    # Adjacent batteries, depth-1: tolerate pin-taxonomy drift (this
    # lane's pin repoint) and the expected-open F371 probes.
    _green_check(os.path.join(REPO, "evals", "w297_redteam_probes.py"),
                 "w297-redteam", tolerate=("pin-taxonomy", "371"))
    _green_check(os.path.join(REPO, "evals", "w296_decision_trace_probes.py"),
                 "w296-decision-trace", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w298_memory_store: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
