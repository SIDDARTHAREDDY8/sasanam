"""Break-first probes for gov/standing_verdicts + gov/knowledge_ingest (wave-326 lane 2).

Standing-verdict store + knowledge ingestion (GUAC CertifyBad ADAPT + OSV.dev
ADAPT from the wave-325 supply-chain prospectus): signed advisories from a
local feed directory flip per-artifact standings; flips are journaled with
mandatory provenance; conflicts resolve newest-wins; history is append-only.

Red-first: on the base tree (c819b56) this battery dies at import
(ModuleNotFoundError: gov.standing_verdicts). On the lane tree every attack
below must refuse with the coded reason -- 0 BREAK target.

Staging default is set at module level (the harness refuses the
declared ungoverned_ack in production mode).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))
sys.path.insert(0, os.path.join(REPO, "evals"))
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)

from gov import ed25519 as ed  # noqa: E402
from gov import knowledge_ingest as ki  # noqa: E402
from gov import standing_verdicts as sv  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
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
# Helpers
# ---------------------------------------------------------------------------

import base64  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import tempfile  # noqa: E402

D1 = "sha256:" + "aa" * 32
D2 = "sha256:" + "bb" * 32


def _ctx():
    """Fresh tmp root, feed dir, feed config+seed, and store."""
    root = tempfile.mkdtemp(prefix="w326-standing-")
    feed = os.path.join(root, "feed")
    os.mkdir(feed)
    seed = ed.generate_seed()
    cfg = ki.FeedConfig(feed, ed.publickey(seed), "probe-collector",
                        quarantine_path=os.path.join(root, "q.log"))
    store = sv.StandingStore(os.path.join(root, "journal.jsonl"))
    return root, feed, cfg, seed, store


def _cleanup(root):
    shutil.rmtree(root, ignore_errors=True)


def _sign(seed, doc):
    body = {k: v for k, v in doc.items() if k != "signature"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8")
    return base64.b64encode(ed.sign(seed, canon)).decode("ascii")


def _advisory(seed, digest=D1, standing="quarantined", justification="j",
              origin="o", collector="c", known_since=100, supersedes=None,
              advisory_id="adv-1", schema="sasanam-advisory/v1"):
    doc = {
        "schema": schema,
        "advisory_id": advisory_id,
        "artifact_digest": digest,
        "asserted_standing": standing,
        "justification": justification,
        "origin": origin,
        "collector": collector,
        "known_since": known_since,
        "supersedes": supersedes,
    }
    doc["signature"] = _sign(seed, doc)
    return doc


def _write(feed, name, doc):
    path = os.path.join(feed, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    return path


def _expect_code(pid, fn, code):
    """Run fn; HELD iff it raises a coded error with the exact code."""
    try:
        fn()
    except (ki.IngestError, sv.StandingError) as exc:
        assert exc.code == code, \
            "want code %s, got %s (%s)" % (code, exc.code, exc.detail)
        _held(pid, "refused with %s" % code)
        return
    _break(pid, "no coded refusal (want %s)" % code)


# ---------------------------------------------------------------------------
# Attack probes (0 BREAK target)
# ---------------------------------------------------------------------------

@probe("P1-forged-advisory-sig")
def _p1():
    # Attack: advisory signed by an attacker's key, not the feed key.
    root, feed, cfg, seed, store = _ctx()
    try:
        evil_seed = ed.generate_seed()
        doc = _advisory(evil_seed, standing="revoked",
                        justification="trust me")
        path = _write(feed, "evil.json", doc)
        _expect_code("P1-forged-advisory-sig",
                     lambda: ki.ingest_file(path, cfg),
                     "supplychain-standing-flip-unauthenticated")
        # And the forgery must have been quarantined, never applied.
        with open(cfg.quarantine_path, encoding="utf-8") as fh:
            assert "trust me" in fh.read(), "forgery not quarantined"
    finally:
        _cleanup(root)


@probe("P2-unauthenticated-advisory-application")
def _p2():
    # Attack: bypass ingest and try to apply unsigned knowledge -- the
    # store must still be safe because only ingest-authenticated
    # knowledge reaches it; an ingest under the WRONG feed key refuses.
    root, feed, cfg, seed, store = _ctx()
    try:
        store.register_artifact(D1, "inv")
        other_seed = ed.generate_seed()
        other_cfg = ki.FeedConfig(feed, ed.publickey(other_seed),
                                  "probe-collector")
        doc = _advisory(seed, standing="revoked", justification="flip")
        path = _write(feed, "a.json", doc)
        _expect_code("P2-unauthenticated-advisory-application",
                     lambda: ki.ingest_file(path, other_cfg),
                     "supplychain-standing-flip-unauthenticated")
        assert store.standing_of(D1)["standing"] == "unknown", \
            "unauthenticated advisory moved a standing"
    finally:
        _cleanup(root)


@probe("P3-schema-version-confusion")
def _p3():
    # Attack: a future/unknown schema version must not be parsed as v1.
    root, feed, cfg, seed, store = _ctx()
    try:
        doc = _advisory(seed, schema="sasanam-advisory/v2")
        path = _write(feed, "v2.json", doc)
        _expect_code("P3-schema-version-confusion",
                     lambda: ki.ingest_file(path, cfg),
                     "supplychain-standing-schema-unknown")
    finally:
        _cleanup(root)


@probe("P4-advisory-for-unknown-artifact")
def _p4():
    # Attack (or stale feed): advisory names a digest outside the
    # inventory. It must be recorded as unattached knowledge -- and must
    # never create a standing the inventory doesn't know about.
    root, feed, cfg, seed, store = _ctx()
    try:
        doc = _advisory(seed, digest=D2, standing="revoked",
                        justification="cve")
        path = _write(feed, "u.json", doc)
        knowledge = ki.ingest_file(path, cfg)
        entry = store.attach_knowledge(knowledge)
        assert entry["kind"] == "unattached", \
            "want unattached, got %s" % entry["kind"]
        assert entry["code"] == \
            "supplychain-standing-knowledge-unattached"
        assert store.standing_of(D2)["standing"] == "unknown", \
            "unattached knowledge created a standing"
        _held("P4-advisory-for-unknown-artifact",
              "recorded unattached; no standing created")
    finally:
        _cleanup(root)


@probe("P5-conflicting-advisories")
def _p5():
    # Attack: two advisories race to flip one artifact. Newest-wins by
    # known_since, the conflict journaled, never silent.
    root, feed, cfg, seed, store = _ctx()
    try:
        store.register_artifact(D1, "inv")
        k1 = _advisory(seed, standing="trusted", known_since=100,
                       advisory_id="k1")
        store.attach_knowledge(ki.ingest_file(_write(feed, "k1.json", k1),
                                              cfg))
        k2 = _advisory(seed, standing="revoked", justification="cve",
                       known_since=300, supersedes=None, advisory_id="k2")
        store.attach_knowledge(ki.ingest_file(_write(feed, "k2.json", k2),
                                              cfg))
        assert store.standing_of(D1)["standing"] == "revoked", \
            "newest-wins violated"
        conflicts = [e for e in store.journal_entries()
                     if e["kind"] == "conflict"]
        assert len(conflicts) == 1, "conflict not journaled"
        assert conflicts[0]["winner_standing"] == "revoked"
        _held("P5-conflicting-advisories",
              "newest-wins by known_since; conflict journaled")
    finally:
        _cleanup(root)


@probe("P5b-conflict-tie-refused")
def _p5b():
    # The genuinely ambiguous case: same known_since, different
    # standings. Fail closed, loudly -- a human decides.
    root, feed, cfg, seed, store = _ctx()
    try:
        store.register_artifact(D1, "inv")
        k1 = _advisory(seed, standing="trusted", known_since=100,
                       advisory_id="k1")
        store.attach_knowledge(ki.ingest_file(_write(feed, "k1.json", k1),
                                              cfg))
        k2 = _advisory(seed, standing="revoked", justification="tie",
                       known_since=100, supersedes=None, advisory_id="k2")
        _expect_code("P5b-conflict-tie-refused",
                     lambda: store.attach_knowledge(
                         ki.ingest_file(_write(feed, "k2.json", k2), cfg)),
                     "supplychain-standing-conflict")
    finally:
        _cleanup(root)


@probe("P6-flip-without-justification")
def _p6():
    # Attack: flip a standing with no justification -- the flip must
    # cite origin+collector+known_since AND a justification.
    root, feed, cfg, seed, store = _ctx()
    try:
        store.register_artifact(D1, "inv")
        k1 = _advisory(seed, standing="trusted", known_since=100,
                       advisory_id="k1")
        store.attach_knowledge(ki.ingest_file(_write(feed, "k1.json", k1),
                                              cfg))
        k2 = _advisory(seed, standing="revoked", justification="",
                       known_since=200, supersedes=1, advisory_id="k2")
        _expect_code("P6-flip-without-justification",
                     lambda: store.attach_knowledge(
                         ki.ingest_file(_write(feed, "k2.json", k2), cfg)),
                     "supplychain-standing-flip-unjustified")
        assert store.standing_of(D1)["standing"] == "trusted", \
            "unjustified flip moved the standing"
    finally:
        _cleanup(root)


@probe("P7-history-rewrite")
def _p7():
    # Attack: knowledge that supersedes a non-tip entry -- an attempt to
    # rewrite history instead of attaching at the tip.
    root, feed, cfg, seed, store = _ctx()
    try:
        store.register_artifact(D1, "inv")
        k1 = _advisory(seed, standing="trusted", known_since=100,
                       advisory_id="k1")
        store.attach_knowledge(ki.ingest_file(_write(feed, "k1.json", k1),
                                              cfg))
        k2 = _advisory(seed, standing="quarantined", justification="q",
                       known_since=200, supersedes=1, advisory_id="k2")
        store.attach_knowledge(ki.ingest_file(_write(feed, "k2.json", k2),
                                              cfg))
        # Tip is seq 2; supersedes=0 is neither tip nor tip's parent.
        k3 = _advisory(seed, standing="trusted", justification="rewrite",
                       known_since=50, supersedes=0, advisory_id="k3")
        _expect_code("P7-history-rewrite",
                     lambda: store.attach_knowledge(
                         ki.ingest_file(_write(feed, "k3.json", k3), cfg)),
                     "supplychain-standing-history-rewrite")
        assert store.standing_of(D1)["standing"] == "quarantined", \
            "history rewrite moved the standing"
    finally:
        _cleanup(root)


@probe("P8-blast-radius")
def _p8():
    # The incident-response primitive: every artifact touched by a
    # compromised origin/collector, including conflict losers.
    root, feed, cfg, seed, store = _ctx()
    try:
        for digest in (D1, D2):
            store.register_artifact(digest, "inv")
        k1 = _advisory(seed, digest=D1, standing="revoked",
                       justification="cve", origin="evil-origin",
                       known_since=100, advisory_id="k1")
        store.attach_knowledge(ki.ingest_file(_write(feed, "k1.json", k1),
                                              cfg))
        k2 = _advisory(seed, digest=D2, standing="quarantined",
                       justification="cve", origin="evil-origin",
                       known_since=100, advisory_id="k2")
        store.attach_knowledge(ki.ingest_file(_write(feed, "k2.json", k2),
                                              cfg))
        radius = store.blast_radius(origin="evil-origin")
        assert radius == sorted([D1, D2]), "want [D1, D2], got %r" % radius
        assert store.blast_radius(origin="no-such-origin") == []
        _held("P8-blast-radius",
              "origin query returns exactly the touched artifacts")
    finally:
        _cleanup(root)


@probe("P8b-blast-radius-and-semantics")
def _p8b():
    # Regression (spec review MUST-FIX): with a conflict in history, a
    # two-filter blast_radius query must use AND semantics for conflict
    # losers too -- matching on only one filter must not hit.
    root, feed, cfg, seed, store = _ctx()
    try:
        store.register_artifact(D1, "inv")
        k1 = _advisory(seed, digest=D1, standing="trusted", origin="o-a",
                       collector="c-a", known_since=100, advisory_id="k1")
        store.attach_knowledge(ki.ingest_file(_write(feed, "k1.json", k1),
                                              cfg))
        k2 = _advisory(seed, digest=D1, standing="revoked",
                       justification="j", origin="o-b", collector="c-b",
                       known_since=50, supersedes=None, advisory_id="k2")
        store.attach_knowledge(ki.ingest_file(_write(feed, "k2.json", k2),
                                              cfg))
        assert store.blast_radius(origin="o-b", collector="c-b") == [D1]
        assert store.blast_radius(origin="o-b", collector="c-a") == [], \
            "OR-semantics leak: loser matched on origin alone"
        assert store.blast_radius(origin="o-a", collector="c-b") == [], \
            "OR-semantics leak: loser matched on collector alone"
        _held("P8b-blast-radius-and-semantics",
              "conflict losers use AND semantics like knowledge")
    finally:
        _cleanup(root)


@probe("P9-feed-dir-escape")
def _p9():
    # Attack: an advisory path with ../ escaping the feed directory --
    # the feed dir is the trust boundary.
    root, feed, cfg, seed, store = _ctx()
    try:
        outside = os.path.join(root, "outside.json")
        doc = _advisory(seed)
        with open(outside, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        escaped = os.path.join(feed, "..", "outside.json")
        _expect_code("P9-feed-dir-escape",
                     lambda: ki.ingest_file(escaped, cfg),
                     "supplychain-feed-outside-trust-boundary")
    finally:
        _cleanup(root)


@probe("P10-pin-taxonomy-2140-sorted")
def _p10():
    import re
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    codes = re.findall(r'"code":\s*["\']([^"\']+)["\']', src)
    assert len(codes) == len(set(codes)) == TAXONOMY_PIN, \
        "want %d/%d/0, got %d/%d" % (TAXONOMY_PIN, TAXONOMY_PIN,
                                    len(codes), len(set(codes)))
    assert codes == sorted(codes), "taxonomy not sorted"
    _held("P10-pin-taxonomy-2140-sorted",
          "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


@probe("P11-footer-state")
def _p11():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    # Wave-336 lane 1: repaired stale assertion (never-current text).
    # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)
    # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531) (applies to assertion below)
    # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization); F531, F533-F536 OPEN (next F537)
    # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
    # Wave-372 merge: footer repoint next F612 | Wave-372 merge: footer repoint open F606-F611 / next F612 \
    assert "Next free finding: **F612**. **Open findings: F606, F607, F608, F609, F610, F611.**" in text, \
        "footer mismatch"
    _held("P11-footer-state", "open F444, F445 / next F446")


# ---------------------------------------------------------------------------
# Green checks (depth-1): adjacent unit suites via the fail-closed
# green-check contract. Exact-count form is not applicable to unittest
# suites (they report OK, not counts); check_unittest requires exit 0.
# ---------------------------------------------------------------------------

def _green():
    # Module form (not file form): check_unittest runs with cwd=repo,
    # and file-form invocation puts tests/ (not the repo) on sys.path.
    green_check.check_unittest(_record, "green-test-standing-verdicts",
                               "tests.test_standing_verdicts", repo=REPO)


def main():
    ordered = []
    for i in list(range(1, 10)) + ["5b", "8b", 10, 11]:
        fn = globals().get("_p%s" % i)
        if callable(fn):
            ordered.append(fn)
    for fn in ordered:
        fn()
    _green()
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    print("w326_standing battery: %d BREAK / %d HELD / %d ERROR "
          % (n_break, n_held, n_err))


if __name__ == "__main__":
    main()
