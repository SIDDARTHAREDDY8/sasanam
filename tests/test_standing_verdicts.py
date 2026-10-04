"""Unit tests for gov/standing_verdicts.py and gov/knowledge_ingest.py.

Happy paths, fail-closed edges, and the journal's append-only discipline.
Break-first attacks live in evals/w326_standing_probes.py.
"""

import base64
import json
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import ed25519 as ed
from gov import knowledge_ingest as ki
from gov import standing_verdicts as sv

D1 = "sha256:" + "11" * 32
D2 = "sha256:" + "22" * 32
D3 = "sha256:" + "33" * 32


def _tmpdir(test):
    d = tempfile.mkdtemp(prefix="standing-ut-")
    test.addCleanup(shutil.rmtree, d, True)
    return d


def _knowledge(digest=D1, standing="quarantined", justification="j",
               origin="o", collector="c", known_since=100, supersedes=None):
    return {
        "artifact_digest": digest,
        "asserted_standing": standing,
        "justification": justification,
        "origin": origin,
        "collector": collector,
        "known_since": known_since,
        "supersedes": supersedes,
    }


class StandingStoreTests(unittest.TestCase):
    def test_register_and_initial_standing(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        store.register_artifact(D1, "installed-inventory")
        entry = store.attach_knowledge(_knowledge())
        self.assertEqual(entry["kind"], "knowledge")
        got = store.standing_of(D1)
        self.assertEqual(got["standing"], "quarantined")
        self.assertEqual(len(got["chain"]), 1)
        self.assertEqual(got["chain"][0]["origin"], "o")

    def test_unknown_digest_reports_unknown_never_refuses(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        got = store.standing_of(D2)
        self.assertEqual(got["standing"], "unknown")
        self.assertEqual(got["chain"], [])

    def test_unattached_knowledge_never_creates_standing(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        entry = store.attach_knowledge(_knowledge(digest=D2))
        self.assertEqual(entry["kind"], "unattached")
        self.assertFalse(entry["applied"])
        self.assertEqual(entry["code"],
                         "supplychain-standing-knowledge-unattached")
        self.assertEqual(store.standing_of(D2)["standing"], "unknown")

    def test_flip_requires_justification(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        store.register_artifact(D1, "inv")
        store.attach_knowledge(_knowledge(standing="trusted"))
        with self.assertRaises(sv.StandingError) as ctx:
            store.attach_knowledge(_knowledge(
                standing="revoked", justification="", supersedes=1))
        self.assertEqual(ctx.exception.code,
                         "supplychain-standing-flip-unjustified")
        self.assertEqual(store.standing_of(D1)["standing"], "trusted")

    def test_flip_with_justification_journaled(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        store.register_artifact(D1, "inv")
        store.attach_knowledge(_knowledge(standing="trusted"))
        store.attach_knowledge(_knowledge(
            standing="revoked", justification="CVE-2026-1",
            origin="osv.dev", collector="c", known_since=200,
            supersedes=1))
        got = store.standing_of(D1)
        self.assertEqual(got["standing"], "revoked")
        self.assertEqual(len(got["chain"]), 2)
        self.assertEqual(got["chain"][1]["justification"], "CVE-2026-1")

    def test_history_rewrite_refused(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        store.register_artifact(D1, "inv")
        store.attach_knowledge(_knowledge(standing="trusted"))
        store.attach_knowledge(_knowledge(
            standing="quarantined", justification="j2", supersedes=1))
        # Tip is seq 2 (parent 1). supersedes=0 is neither tip nor the
        # tip's parent -> history rewrite, refused loudly.
        with self.assertRaises(sv.StandingError) as ctx:
            store.attach_knowledge(_knowledge(
                standing="revoked", justification="j3", supersedes=0))
        self.assertEqual(ctx.exception.code,
                         "supplychain-standing-history-rewrite")
        self.assertEqual(store.standing_of(D1)["standing"], "quarantined")

    def test_conflict_newest_wins_and_journaled(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        store.register_artifact(D1, "inv")
        store.attach_knowledge(_knowledge(standing="trusted",
                                          known_since=100))
        # Concurrent write: supersedes=None, the same parent the tip saw
        # (the tip is the first knowledge entry, parent None), with a
        # different standing -> conflict, newest wins.
        entry = store.attach_knowledge(_knowledge(
            standing="revoked", justification="newer knowledge",
            known_since=300, supersedes=None))
        self.assertEqual(entry["kind"], "knowledge")
        self.assertEqual(store.standing_of(D1)["standing"], "revoked")
        kinds = [e["kind"] for e in store.journal_entries()]
        self.assertIn("conflict", kinds)
        conflict = [e for e in store.journal_entries()
                    if e["kind"] == "conflict"][0]
        self.assertEqual(conflict["winner_standing"], "revoked")
        self.assertEqual(conflict["loser_standing"], "trusted")

    def test_conflict_tie_refused_loud(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        store.register_artifact(D1, "inv")
        store.attach_knowledge(_knowledge(standing="trusted",
                                          known_since=100))
        with self.assertRaises(sv.StandingError) as ctx:
            store.attach_knowledge(_knowledge(
                standing="revoked", justification="tie",
                known_since=100, supersedes=None))
        self.assertEqual(ctx.exception.code, "supplychain-standing-conflict")

    def test_blast_radius(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        for digest in (D1, D2):
            store.register_artifact(digest, "inv")
        store.attach_knowledge(_knowledge(digest=D1, origin="evil-src"))
        store.attach_knowledge(_knowledge(digest=D2, origin="evil-src"))
        store.attach_knowledge(_knowledge(digest=D3, origin="fine-src"))
        # D3 unregistered -> unattached, must not appear.
        self.assertEqual(store.blast_radius(origin="evil-src"), [D1, D2])
        self.assertEqual(store.blast_radius(collector="c"), [D1, D2])
        self.assertEqual(store.blast_radius(origin="fine-src"), [])

    def test_journal_survives_reload(self):
        d = _tmpdir(self)
        path = os.path.join(d, "j.jsonl")
        store = sv.StandingStore(path)
        store.register_artifact(D1, "inv")
        store.attach_knowledge(_knowledge(standing="trusted"))
        store2 = sv.StandingStore(path)
        got = store2.standing_of(D1)
        self.assertEqual(got["standing"], "trusted")
        self.assertEqual(len(got["chain"]), 1)

    def test_bad_digest_refused(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        with self.assertRaises(sv.StandingError):
            store.register_artifact("not-a-digest", "inv")

    def test_flip_with_whitespace_justification_refused(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        store.register_artifact(D1, "inv")
        store.attach_knowledge(_knowledge(standing="trusted"))
        with self.assertRaises(sv.StandingError) as ctx:
            store.attach_knowledge(_knowledge(
                standing="revoked", justification="   ", supersedes=1))
        self.assertEqual(ctx.exception.code,
                         "supplychain-standing-flip-unjustified")

    def test_advisory_id_preserved_in_journal(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        store.register_artifact(D1, "inv")
        k = _knowledge()
        k["advisory_id"] = "adv-42"
        entry = store.attach_knowledge(k)
        self.assertEqual(entry["advisory_id"], "adv-42")
        self.assertEqual(store.standing_of(D1)["chain"][0].get("advisory_id"),
                         "adv-42")

    def test_conflict_record_keeps_loser_justification(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        store.register_artifact(D1, "inv")
        store.attach_knowledge(_knowledge(standing="trusted",
                                          justification="looks fine",
                                          known_since=100))
        store.attach_knowledge(_knowledge(
            standing="revoked", justification="cve-2026-1",
            known_since=300, supersedes=None))
        conflict = [e for e in store.journal_entries()
                    if e["kind"] == "conflict"][0]
        self.assertEqual(conflict["loser_justification"], "looks fine")
        self.assertEqual(conflict["winner_justification"], "cve-2026-1")

    def test_blast_radius_and_semantics_with_conflict(self):
        d = _tmpdir(self)
        store = sv.StandingStore(os.path.join(d, "j.jsonl"))
        store.register_artifact(D1, "inv")
        store.attach_knowledge(_knowledge(standing="trusted", origin="o-a",
                                          collector="c-a", known_since=100))
        # Losing concurrent write from a different origin/collector.
        store.attach_knowledge(_knowledge(
            standing="revoked", justification="j", origin="o-b",
            collector="c-b", known_since=50, supersedes=None))
        # AND semantics: must match BOTH to hit via the loser.
        self.assertEqual(store.blast_radius(origin="o-b",
                                            collector="c-b"), [D1])
        self.assertEqual(store.blast_radius(origin="o-b",
                                            collector="c-a"), [])
        self.assertEqual(store.blast_radius(origin="o-a"), [D1])

    def test_tampered_journal_refused_on_reload(self):
        d = _tmpdir(self)
        path = os.path.join(d, "j.jsonl")
        store = sv.StandingStore(path)
        store.register_artifact(D1, "inv")
        store.attach_knowledge(_knowledge(standing="trusted"))
        # Tamper: rewrite the knowledge entry with a bogus standing.
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        tampered = []
        for line in lines:
            entry = json.loads(line)
            if entry.get("kind") == "knowledge":
                entry["asserted_standing"] = "bogus"
            tampered.append(json.dumps(entry, sort_keys=True))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(tampered) + "\n")
        with self.assertRaises(sv.StandingError):
            sv.StandingStore(path)


def _feed(test):
    d = _tmpdir(test)
    feed = os.path.join(d, "feed")
    os.mkdir(feed)
    seed = ed.generate_seed()
    pub = ed.publickey(seed)
    cfg = ki.FeedConfig(feed, pub, "test-collector",
                        quarantine_path=os.path.join(d, "q.log"))
    return feed, cfg, seed


def _sign(seed, doc):
    body = {k: v for k, v in doc.items() if k != "signature"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8")
    return base64.b64encode(ed.sign(seed, canon)).decode("ascii")


def _write(feed, name, doc):
    path = os.path.join(feed, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    return path


class IngestTests(unittest.TestCase):
    def test_ingest_valid_sasanam_advisory(self):
        feed, cfg, seed = _feed(self)
        doc = {
            "schema": "sasanam-advisory/v1",
            "advisory_id": "adv-1",
            "artifact_digest": D1,
            "asserted_standing": "quarantined",
            "justification": "CVE-2026-9",
            "origin": "osv.dev",
            "collector": "test-collector",
            "known_since": 1700000000,
            "supersedes": None,
        }
        doc["signature"] = _sign(seed, doc)
        path = _write(feed, "a1.json", doc)
        k = ki.ingest_file(path, cfg)
        self.assertEqual(k["artifact_digest"], D1)
        self.assertEqual(k["asserted_standing"], "quarantined")
        self.assertEqual(k["known_since"], 1700000000)

    def test_forged_signature_quarantined_never_applied(self):
        feed, cfg, seed = _feed(self)
        other = ed.generate_seed()
        doc = {
            "schema": "sasanam-advisory/v1",
            "advisory_id": "adv-x",
            "artifact_digest": D1,
            "asserted_standing": "revoked",
            "justification": "evil",
            "origin": "evil",
            "collector": "evil",
            "known_since": 1,
            "supersedes": None,
        }
        doc["signature"] = _sign(other, doc)
        path = _write(feed, "evil.json", doc)
        with self.assertRaises(ki.IngestError) as ctx:
            ki.ingest_file(path, cfg)
        self.assertEqual(ctx.exception.code,
                         "supplychain-standing-flip-unauthenticated")
        with open(cfg.quarantine_path, encoding="utf-8") as fh:
            self.assertIn("adv-x", fh.read())

    def test_unknown_schema_refused(self):
        feed, cfg, seed = _feed(self)
        doc = {"schema": "sasanam-advisory/v9", "signature": "x"}
        doc["signature"] = _sign(seed, doc)
        path = _write(feed, "s.json", doc)
        with self.assertRaises(ki.IngestError) as ctx:
            ki.ingest_file(path, cfg)
        self.assertEqual(ctx.exception.code,
                         "supplychain-standing-schema-unknown")

    def test_feed_dir_escape_refused(self):
        feed, cfg, seed = _feed(self)
        outside = os.path.join(os.path.dirname(feed), "outside.json")
        doc = {"schema": "sasanam-advisory/v1"}
        doc["signature"] = _sign(seed, doc)
        _write(os.path.dirname(feed), "outside.json", doc)
        with self.assertRaises(ki.IngestError) as ctx:
            ki.ingest_file(outside, cfg)
        self.assertEqual(ctx.exception.code,
                         "supplychain-feed-outside-trust-boundary")

    def test_osv_shape_mapping(self):
        feed, cfg, seed = _feed(self)
        doc = {
            "schema": "osv/v1",
            "osv": {
                "id": "GHSA-xxxx-yyyy",
                "summary": "bad dep",
                "details": "remote code execution",
                "published": "2026-09-01T12:00:00Z",
                "affected": [
                    {"package": {"ecosystem": "PyPI", "name": "evil-pkg"}},
                ],
            },
            "artifact_digest": D1,
            "supersedes": None,
        }
        doc["signature"] = _sign(seed, doc)
        path = _write(feed, "osv1.json", doc)
        k = ki.ingest_file(path, cfg)
        self.assertEqual(k["origin"], "osv.dev")
        self.assertEqual(k["collector"], "test-collector")
        self.assertEqual(k["asserted_standing"], "quarantined")
        self.assertIn("GHSA-xxxx-yyyy", k["justification"])
        self.assertGreater(k["known_since"], 1700000000)
        self.assertEqual(k["affected_packages"], ["PyPI:evil-pkg"])
        self.assertEqual(k["advisory_id"], "GHSA-xxxx-yyyy")

    def test_schema_unknown_quarantined(self):
        feed, cfg, seed = _feed(self)
        doc = {"schema": "sasanam-advisory/v9", "note": "confused"}
        doc["signature"] = _sign(seed, doc)
        path = _write(feed, "s.json", doc)
        with self.assertRaises(ki.IngestError) as ctx:
            ki.ingest_file(path, cfg)
        self.assertEqual(ctx.exception.code,
                         "supplychain-standing-schema-unknown")
        with open(cfg.quarantine_path, encoding="utf-8") as fh:
            self.assertIn("sasanam-advisory/v9", fh.read())

    def test_ingest_directory_applies_and_reports(self):
        feed, cfg, seed = _feed(self)
        store = sv.StandingStore(os.path.join(feed, "..", "j.jsonl"))
        store.register_artifact(D1, "inv")
        good = {
            "schema": "sasanam-advisory/v1",
            "advisory_id": "g1",
            "artifact_digest": D1,
            "asserted_standing": "quarantined",
            "justification": "cve",
            "origin": "o",
            "collector": "c",
            "known_since": 10,
            "supersedes": None,
        }
        good["signature"] = _sign(seed, good)
        _write(feed, "01-good.json", good)
        bad = dict(good, advisory_id="b1")
        bad["signature"] = "not-base64!!"
        _write(feed, "02-bad.json", bad)
        result = ki.ingest_directory(cfg, store)
        self.assertEqual(len(result["applied"]), 1)
        self.assertEqual(len(result["refused"]), 1)
        self.assertEqual(result["refused"][0]["code"],
                         "supplychain-standing-flip-unauthenticated")
        self.assertEqual(store.standing_of(D1)["standing"], "quarantined")


if __name__ == "__main__":
    unittest.main()
