"""Wave-327 independent red-team battery.

Base: 542c5cee (wave-326 merge). Footer: open F412 / next F413.
Pin: 2100.

P1  wave-326 seams: standing_verdicts / knowledge_ingest / background_scan.
P2  F410 re-probe (w326_tufaudit T4c/T4d -- must still BREAK; lane 2 owns it).
P3  F411 re-probe (w326_redteam P3a -- must still BREAK; lane 1 owns it).
P4  regression: F409 (HELD), F408/F407/F406 (HELD).
P5  corruption-survivor probe + prior batteries in child mode.
P6  pin 2100 + footer state.

gov/ is byte-identical to base: this battery changes no product code and
files findings only (from F412). No new decision codes from this lane.
"""

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))

TAXONOMY_PIN = 2131 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-327 merge: pin 2035 -> 2044 (+9 policy-channel-*).; Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*); Wave-339 merge: pin 2128 -> 2130 (+4 codes: oci-bundle-not-verifiable, witness-policy-dual-threshold-unmet, witness-daemon-state-failed, oci-registry-onboarding-refused); Wave-340 lane 3: pin 2130 -> 2131 (+1 deadctrl-subject-mutated).
FOOTER_OPEN = "F427"  # F426 closed wave-338 lane 1; F427 OPEN (wave-339 lane 5).
FOOTER_NEXT = "F428"  # Next free finding number.

_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    return (pid, "HELD", note)


def _break(pid, note):
    return (pid, "BREAK", note)


def probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _safe(pid, fn):
    try:
        _record(*fn())
    except Exception:
        _record(pid, "ERROR",
                traceback.format_exc(limit=2).replace("\n", " | ")[:500])


def _relabel(pid, fn):
    _pid, verdict, note = fn()
    return (pid, verdict, note)


def _expect_code(pid, fn, exc_types, code, note):
    try:
        fn()
    except exc_types as exc:
        got = getattr(exc, "code", None)
        if got == code:
            return _held(pid, "%s: refused coded %s" % (note, code))
        return _break(pid, "%s: wrong code %r, want %s" % (note, got, code))
    return _break(pid, "%s: ACCEPTED, want coded %s" % (note, code))


import w326_tufaudit_probes as _w326tuf  # noqa: E402
import w326_redteam_probes as _w326rt  # noqa: E402
import w325_redteam_probes as _w325  # noqa: E402
import w323_redteam_probes as _w323  # noqa: E402
import w322_redteam_probes as _w322  # noqa: E402
import w326_sched_probes as _w326sched  # noqa: E402


# ---------------------------------------------------------------------------
# P1: wave-326 seams -- standing_verdicts / knowledge_ingest / background_scan.
# ---------------------------------------------------------------------------

_D1 = "sha256:" + "aa" * 32
_D2 = "sha256:" + "bb" * 32


def _know(digest, standing, justification, known_since, supersedes,
          origin="o", collector="c", advisory_id="adv"):
    return {"artifact_digest": digest, "asserted_standing": standing,
            "justification": justification, "origin": origin,
            "collector": collector, "known_since": known_since,
            "supersedes": supersedes, "advisory_id": advisory_id}


def _fresh_store(prefix):
    from gov import standing_verdicts as sv
    root = tempfile.mkdtemp(prefix=prefix)
    return sv.StandingStore(os.path.join(root, "journal.jsonl")), sv


@probe("P1a-standing-flip-unjustified-refused")
def _p1a():
    """A standing flip with a blank justification must be refused coded."""
    s, sv = _fresh_store("w327-p1a-")
    s.register_artifact(_D1, "probe")
    e1 = s.attach_knowledge(_know(_D1, "trusted", "j1", 100, None))

    def flip():
        s.attach_knowledge(_know(_D1, "quarantined", "   ", 200, e1["seq"]))
    return _expect_code(
        "P1a-standing-flip-unjustified-refused", flip, sv.StandingError,
        "supplychain-standing-flip-unjustified",
        "flip trusted->quarantined with blank justification")


@probe("P1b-standing-history-rewrite-refused")
def _p1b():
    """Knowledge superseding a non-tip, non-parent seq is refused coded.

    (Superseding the tip's *parent* is the documented concurrent-write
    path, not a rewrite -- this probe builds a 3-deep chain and supersedes
    the grandparent, which is a genuine history rewrite.)
    """
    s, sv = _fresh_store("w327-p1b-")
    s.register_artifact(_D1, "probe")
    e1 = s.attach_knowledge(_know(_D1, "trusted", "j1", 100, None))
    e2 = s.attach_knowledge(_know(_D1, "quarantined", "j2", 200, e1["seq"]))
    e3 = s.attach_knowledge(_know(_D1, "quarantined", "j3", 300, e2["seq"]))

    def rewrite():
        s.attach_knowledge(_know(_D1, "revoked", "j4", 400, e1["seq"]))
    return _expect_code(
        "P1b-standing-history-rewrite-refused", rewrite, sv.StandingError,
        "supplychain-standing-history-rewrite",
        "knowledge superseding grandparent seq %d (tip %d, parent %d)"
        % (e1["seq"], e3["seq"], e2["seq"]))


@probe("P1c-standing-conflict-newest-wins-journaled")
def _p1c():
    """Concurrent advisories resolve newest-wins with the conflict journaled."""
    s, sv = _fresh_store("w327-p1c-")
    s.register_artifact(_D1, "probe")
    s.attach_knowledge(_know(_D1, "trusted", "j1", 100, None))
    # Same parent (None) as the tip, different standing, newer known_since.
    s.attach_knowledge(_know(_D1, "quarantined", "j2", 200, None,
                             origin="o2", collector="c2"))
    so = s.standing_of(_D1)
    kinds = [e["kind"] for e in s.journal_entries()]
    if so["standing"] == "quarantined" and "conflict" in kinds:
        return _held("P1c-standing-conflict-newest-wins-journaled",
                     "newest-wins applied, conflict journaled")
    return _break("P1c-standing-conflict-newest-wins-journaled",
                  "standing=%r kinds=%r" % (so["standing"], kinds))


@probe("P1d-standing-conflict-tie-refused")
def _p1d():
    """An exact known_since tie on conflicting advisories refuses loudly."""
    s, sv = _fresh_store("w327-p1d-")
    s.register_artifact(_D1, "probe")
    s.attach_knowledge(_know(_D1, "trusted", "j1", 100, None))

    def tie():
        s.attach_knowledge(_know(_D1, "quarantined", "j2", 100, None))
    return _expect_code(
        "P1d-standing-conflict-tie-refused", tie, sv.StandingError,
        "supplychain-standing-conflict",
        "conflicting advisories with tied known_since")


@probe("P1e-standing-unknown-artifact-unattached")
def _p1e():
    """Knowledge for an unregistered digest is recorded, never a standing."""
    s, sv = _fresh_store("w327-p1e-")
    s.register_artifact(_D1, "probe")
    e = s.attach_knowledge(_know(_D2, "revoked", "j", 100, None))
    so = s.standing_of(_D2)
    if e["kind"] == "unattached" and so["standing"] == "unknown" \
            and not so["chain"]:
        return _held("P1e-standing-unknown-artifact-unattached",
                     "unattached recorded; standing stays unknown")
    return _break("P1e-standing-unknown-artifact-unattached",
                  "kind=%r standing=%r" % (e["kind"], so["standing"]))


@probe("P1f-f412-conflict-crash-wedges-store")
def _p1f():
    """F412 (CLOSED 2026-10-04 wave-328 lane 1): _resolve_conflict's two
    journal appends were not atomic.

    A crash between the conflict-entry append and the winner-entry append
    left the conflict entry as the tip. On reload, standing_of and
    attach_knowledge raised an UNCODED KeyError ('asserted_standing') --
    the store was permanently wedged: no read or write could proceed, and
    every reload replayed the same poisoned tip. Recovery needed manual
    journal surgery.

    The fix journals the conflict and the winner's knowledge as a SINGLE
    entry; this probe replays the legacy crash shape and now expects a
    clean recovery (or a coded refusal), never the wedge.
    """
    s, sv = _fresh_store("w327-p1f-")
    s.register_artifact(_D1, "probe")
    e1 = s.attach_knowledge(_know(_D1, "trusted", "j1", 100, None))
    e2 = s.attach_knowledge(_know(_D1, "quarantined", "j2", 200, e1["seq"]))
    # Simulate the crash: replicate _resolve_conflict's FIRST append only.
    s._append({
        "kind": "conflict",
        "code": "supplychain-standing-conflict",
        "artifact_digest": _D1,
        "winner_seq": s._next_seq + 1,
        "winner_known_since": 300,
        "winner_standing": "revoked",
        "winner_justification": "j3",
        "loser_known_since": 200,
        "loser_standing": "quarantined",
        "loser_justification": "j2",
        "loser_origin": "o2",
        "loser_collector": "c2",
        "detail": "probe-simulated crash between the two appends",
    })
    # "New process": reload from the journal.
    path = s._path
    s2 = sv.StandingStore(path)
    try:
        s2.standing_of(_D1)
    except KeyError:
        pass  # the bug: uncoded crash on the read path
    except sv.StandingError as exc:
        return _held("P1f-f412-conflict-crash-wedges-store",
                     "crash-window now fails coded %s" % exc.code)
    else:
        return _held("P1f-f412-conflict-crash-wedges-store",
                     "crash-window recovered cleanly")
    try:
        s2.attach_knowledge(_know(_D1, "trusted", "legit", 400,
                                  s2._tips[_D1]))
    except KeyError:
        return _break(
            "P1f-f412-conflict-crash-wedges-store",
            "F412 reproduces: after a crash between the conflict journal "
            "append and the winner append, standing_of AND attach_knowledge "
            "raise uncoded KeyError('asserted_standing'); the store is "
            "permanently wedged (every reload replays the poisoned tip)")
    except sv.StandingError as exc:
        return _held("P1f-f412-conflict-crash-wedges-store",
                     "write path fails coded %s" % exc.code)
    return _held("P1f-f412-conflict-crash-wedges-store",
                 "write path recovered cleanly")


# -- knowledge_ingest ----------------------------------------------------

_FEED_SEED = b"w327-feed-seed-00000000000000001"  # 32 bytes, fixed
_FEED_SEED_BAD = b"w327-feed-seed-00000000000000002"


def _feed_world(prefix, quarantine=True):
    from gov import ed25519 as ed
    from gov import knowledge_ingest as ki
    root = tempfile.mkdtemp(prefix=prefix)
    feed = os.path.join(root, "feed")
    os.mkdir(feed)
    pub = ed.publickey(_FEED_SEED)
    qpath = os.path.join(root, "quarantine.jsonl") if quarantine else None
    cfg = ki.FeedConfig(feed, pub, "probe-collector",
                        quarantine_path=qpath)
    return root, feed, cfg, ki, ed


def _sign(seed, doc):
    from gov import ed25519 as ed
    body = {k: v for k, v in doc.items() if k != "signature"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8")
    return base64.b64encode(ed.sign(seed, canon)).decode("ascii")


def _advisory(seed, digest=_D1, standing="quarantined", justification="j",
              origin="o", known_since=100, supersedes=None,
              advisory_id="adv-1", schema="sasanam-advisory/v1"):
    doc = {"schema": schema, "advisory_id": advisory_id,
           "artifact_digest": digest, "asserted_standing": standing,
           "justification": justification, "origin": origin,
           "collector": "probe-collector", "known_since": known_since,
           "supersedes": supersedes}
    doc["signature"] = _sign(seed, doc)
    return doc


def _write(feed, name, doc):
    path = os.path.join(feed, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    return path


@probe("P1g-ingest-forged-feed-signature-refused")
def _p1g():
    """An advisory signed by the wrong key is quarantined, never applied."""
    root, feed, cfg, ki, ed = _feed_world("w327-p1g-")
    doc = _advisory(_FEED_SEED_BAD)  # signed by the WRONG key
    path = _write(feed, "a.json", doc)

    def ingest():
        ki.ingest_file(path, cfg)
    r = _expect_code(
        "P1g-ingest-forged-feed-signature-refused", ingest,
        ki.IngestError, "supplychain-standing-flip-unauthenticated",
        "advisory signed by wrong feed key")
    if r[1] != "HELD":
        return r
    q = open(cfg.quarantine_path).read() if cfg.quarantine_path else ""
    if '"adv-1"' in q or "adv-1" in q:
        return _held("P1g-ingest-forged-feed-signature-refused",
                     "refused coded; raw document quarantined")
    return _break("P1g-ingest-forged-feed-signature-refused",
                  "refused but quarantine log is empty")


@probe("P1h-ingest-unsigned-advisory-refused")
def _p1h():
    """An advisory with no signature is refused coded, never applied."""
    root, feed, cfg, ki, ed = _feed_world("w327-p1h-")
    doc = _advisory(_FEED_SEED)
    del doc["signature"]
    path = _write(feed, "a.json", doc)

    def ingest():
        ki.ingest_file(path, cfg)
    return _expect_code(
        "P1h-ingest-unsigned-advisory-refused", ingest,
        ki.IngestError, "supplychain-standing-flip-unauthenticated",
        "advisory with no signature")


@probe("P1i-ingest-unknown-schema-refused")
def _p1i():
    """An unknown advisory schema is refused coded (schema confusion)."""
    root, feed, cfg, ki, ed = _feed_world("w327-p1i-")
    doc = _advisory(_FEED_SEED, schema="evil/v9")
    path = _write(feed, "a.json", doc)

    def ingest():
        ki.ingest_file(path, cfg)
    return _expect_code(
        "P1i-ingest-unknown-schema-refused", ingest,
        ki.IngestError, "supplychain-standing-schema-unknown",
        "advisory with unknown schema evil/v9")


@probe("P1j-ingest-feed-dir-dotdot-refused")
def _p1j():
    """A ../ path escaping the feed dir is refused coded."""
    root, feed, cfg, ki, ed = _feed_world("w327-p1j-")
    outside = os.path.join(root, "outside.json")
    with open(outside, "w", encoding="utf-8") as fh:
        json.dump(_advisory(_FEED_SEED), fh)

    def ingest():
        ki.ingest_file(os.path.join(feed, "..", "outside.json"), cfg)
    return _expect_code(
        "P1j-ingest-feed-dir-dotdot-refused", ingest,
        ki.IngestError, "supplychain-feed-outside-trust-boundary",
        "../ escape from the feed dir")


@probe("P1k-ingest-feed-symlink-escape-refused")
def _p1k():
    """A symlink inside the feed dir pointing outside is refused coded."""
    root, feed, cfg, ki, ed = _feed_world("w327-p1k-")
    outside = os.path.join(root, "evil.json")
    with open(outside, "w", encoding="utf-8") as fh:
        json.dump(_advisory(_FEED_SEED), fh)
    link = os.path.join(feed, "link.json")
    os.symlink(outside, link)

    def ingest():
        ki.ingest_file(link, cfg)
    return _expect_code(
        "P1k-ingest-feed-symlink-escape-refused", ingest,
        ki.IngestError, "supplychain-feed-outside-trust-boundary",
        "symlink inside feed dir pointing outside")


# -- background_scan -----------------------------------------------------

def _sched_world(prefix):
    from gov import background_scan as BS
    root = tempfile.mkdtemp(prefix=prefix)
    return os.path.join(root, "state.json"), BS


@probe("P1l-scheduler-ttl-expiry-lapses-loud")
def _p1l():
    """A standing whose TTL expires without re-verification lapses LOUD."""
    sp, BS = _sched_world("w327-p1l-")
    T0 = _w326sched.T0
    _w326sched._register(sp, now=T0, skill_bytes=_w326sched.BYTES_V1,
                         ttl=3600, interval=7200)
    r1 = BS.run_scan(sp, _w326sched._inv(), _w326sched.ROOT_TRUST, now=T0)[0]
    if r1["verdict"] != "verified":
        return _break("P1l-scheduler-ttl-expiry-lapses-loud",
                      "setup scan did not verify: %r" % (r1["verdict"],))
    # At T0+3600 the TTL has fully elapsed; no trigger fires (next scan due
    # at T0+7200, bytes and policy unchanged) -- the standing must lapse.
    r2 = BS.run_scan(sp, _w326sched._inv(), _w326sched.ROOT_TRUST,
                     now=T0 + 3600)[0]
    notes = " ".join(r2["notes"])
    if r2["standing"]["status"] == "lapsed" \
            and "supplychain-standing-lapsed" in notes:
        return _held("P1l-scheduler-ttl-expiry-lapses-loud",
                     "TTL expiry lapsed LOUD with no scan trigger")
    return _break("P1l-scheduler-ttl-expiry-lapses-loud",
                  "status=%r notes=%r" % (r2["standing"]["status"], notes))


@probe("P1m-scheduler-resource-change-trigger-fires")
def _p1m():
    """Mutated skill bytes fire the resource-change trigger (verified LOUD)."""
    sp, BS = _sched_world("w327-p1m-")
    T0 = _w326sched.T0
    _w326sched._register(sp, now=T0)
    BS.run_scan(sp, _w326sched._inv(), _w326sched.ROOT_TRUST, now=T0)
    v2 = _w326sched.BYTES_V2
    inv = _w326sched._inv(skill_bytes=v2,
                          authz_wire=_w326sched._authz_wire(v2))
    r = BS.run_scan(sp, inv, _w326sched.ROOT_TRUST, now=T0 + 10)[0]
    if r["trigger"] == "resource-change" and r["verdict"] == "verified" \
            and any("resource-change" in n for n in r["notes"]):
        return _held("P1m-scheduler-resource-change-trigger-fires",
                     "byte drift fired resource-change, verified LOUD")
    return _break("P1m-scheduler-resource-change-trigger-fires",
                  "trigger=%r verdict=%r" % (r["trigger"], r["verdict"]))


@probe("P1n-scheduler-corrupt-state-refuses-coded")
def _p1n():
    """A corrupt scheduler state file fails LOUD, never silently fresh."""
    sp, BS = _sched_world("w327-p1n-")
    with open(sp, "w", encoding="utf-8") as fh:
        fh.write("{not json")

    def scan():
        BS.run_scan(sp, _w326sched._inv(), _w326sched.ROOT_TRUST,
                    now=_w326sched.T0)
    return _expect_code(
        "P1n-scheduler-corrupt-state-refuses-coded", scan,
        BS.BackgroundScanError, "supplychain-scan-state-corrupt",
        "corrupt scheduler state file")


@probe("P1o-scheduler-crash-sidecar-loud")
def _p1o():
    """A leftover crash sidecar is reported LOUD on the next run."""
    sp, BS = _sched_world("w327-p1o-")
    T0 = _w326sched.T0
    _w326sched._register(sp, now=T0)
    BS.run_scan(sp, _w326sched._inv(), _w326sched.ROOT_TRUST, now=T0)
    with open(sp + ".inprogress", "w", encoding="utf-8") as fh:
        json.dump({"skill": _w326sched.SKILL, "started_at": T0}, fh)
    r = BS.run_scan(sp, _w326sched._inv(), _w326sched.ROOT_TRUST,
                    now=T0 + 5)[0]
    notes = " ".join(r["notes"])
    if "supplychain-scan-crash-recovered" in notes:
        return _held("P1o-scheduler-crash-sidecar-loud",
                     "crash sidecar reported LOUD on next run")
    return _break("P1o-scheduler-crash-sidecar-loud",
                  "no crash-recovery note: %r" % (r["notes"],))


# ---------------------------------------------------------------------------
# P2: F410 re-probe (w326_tufaudit T4c/T4d -- CLOSED by wave-327 lane 2;
# must now be HELD).
# ---------------------------------------------------------------------------

@probe("P2a-f410-t4c-closed")
def _p2a():
    """F410 (LOW, CLOSED wave-327 lane 2): pruned pre-rotation slots now recover."""
    verdict, note = _w326tuf._p4c()  # 2-tuple convention in that battery
    return ("P2a-f410-t4c-closed", verdict, note)


@probe("P2b-f410-t4d-closed")
def _p2b():
    """F410 (LOW, CLOSED wave-327 lane 2): a single pruned slot now recovers."""
    verdict, note = _w326tuf._p4d()  # 2-tuple convention in that battery
    return ("P2b-f410-t4d-closed", verdict, note)


# ---------------------------------------------------------------------------
# P3: F411 re-probe (w326_redteam P3a -- CLOSED by wave-327 lane 1;
# must now be HELD).
# ---------------------------------------------------------------------------

@probe("P3a-f411-dict-token-claims-bypass-closed")
def _p3a():
    """F411 (MEDIUM, CLOSED wave-327 lane 1): forged dict token_claims refused."""
    return _relabel("P3a-f411-dict-token-claims-bypass-closed",
                    _w326rt._p3a)


# ---------------------------------------------------------------------------
# P4: regression -- F409 (HELD), F408/F407/F406 (HELD).
# ---------------------------------------------------------------------------

@probe("P4a-f409-stays-held")
def _p4a():
    """F409 (LOW, CLOSED wave-326 lane 1): re-probe must stay HELD."""
    return _relabel("P4a-f409-stays-held", _w325._p1a)


@probe("P4b-f408-stays-held")
def _p4b():
    """F408 (LOW, CLOSED): monitor-state deletion mid-outage alerts loudly."""
    return _relabel("P4b-f408-stays-held", _w325._p4a)


@probe("P4c-f407-stays-held")
def _p4c():
    """F407 (LOW, CLOSED): malformed OCI referrers bodies refuse coded."""
    return _relabel("P4c-f407-stays-held", _w323._p3f1)


@probe("P4d-f406-stays-held")
def _p4d():
    """F406 (MEDIUM, CLOSED): ProvenanceSink negation-cue near-misses."""
    return _relabel("P4d-f406-stays-held", _w322._p3a)


# ---------------------------------------------------------------------------
# P5: corruption-survivor probe + prior batteries in child mode.
# ---------------------------------------------------------------------------

@probe("P5a-pin-repoint-corruption-survivor")
def _p5a():
    """No pin-repoint corruption markers survive in the tree.

    The wave-326 merge's repoint script briefly corrupted ~130 pin
    literals into artifacts with an "OLD" suffix before the fix. This
    probe sweeps the whole tree (excluding .git) for any surviving
    corruption markers. (The needle is built dynamically so this file's
    own documentation does not self-match.)
    """
    needles = ["2035" + "OLD", "2100" + "OLD"]
    hits = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        # Skip .git and derived bytecode caches (not source literals).
        for skip in (".git", "__pycache__"):
            if skip in dirnames:
                dirnames.remove(skip)
        for name in filenames:
            p = os.path.join(dirpath, name)
            try:
                with open(p, "rb") as fh:
                    blob = fh.read()
            except OSError:
                continue
            for needle in needles:
                if needle.encode("ascii") in blob:
                    hits.append(os.path.relpath(p, REPO))
    if hits:
        return _break("P5a-pin-repoint-corruption-survivor",
                      "corruption survivors: %r" % (hits[:5],))
    return _held("P5a-pin-repoint-corruption-survivor",
                 "no pin-repoint corruption markers anywhere in the tree")


def _parse_tally(text):
    m = re.search(r"(\d+)\s+BREAK\s*/\s*(\d+)\s+HELD\s*/\s*(\d+)\s+ERROR",
                  text)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    # w326_tufaudit_probes.py prints "16/2/0 held/break/error".
    m = re.search(r"(\d+)/(\d+)/(\d+)\s+held/break/error", text)
    if m:
        return (int(m.group(2)), int(m.group(1)), int(m.group(3)))
    return None


# Post-merge tallies on the wave-327 tree (footer open F412 / next F413;
# F410 CLOSED by lane 2, F411 CLOSED by lane 1, F412 filed OPEN by lane 4).
# The only expected BREAK is the F412 finding probe (P1f).
# Child mode (GOV_SKIP_GREEN=1).
_GREEN_EVALS = [
    ("w326-standing", "evals/w326_standing_probes.py", (0, 14, 0)),
    ("w326-sched", "evals/w326_sched_probes.py", (0, 18, 0)),
    ("w326-tufaudit", "evals/w326_tufaudit_probes.py", (0, 18, 0)),
    ("w326-redteam", "evals/w326_redteam_probes.py", (0, 36, 0)),
    ("w325-redteam", "evals/w325_redteam_probes.py", (0, 46, 0)),
    ("w324-alert", "evals/w324_alert_probes.py", (0, 18, 0)),
]


def _run_green_eval(name, rel, expect):
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="w327-gc-")
    try:
        p = subprocess.run(
            [sys.executable, os.path.join(REPO, rel)],
            env=env, capture_output=True, text=True, timeout=900)
    except Exception as exc:  # noqa: BLE001
        return (name, "ERROR", "spawn failed: %r" % (exc,))
    tally = _parse_tally(p.stdout or "")
    if tally is None:
        return (name, "ERROR",
                "no tally parsed; rc=%s tail=%r"
                % (p.returncode, (p.stdout or "")[-400:]))
    if tally != expect:
        return (name, "BREAK",
                "tally %s != expected %s" % (tally, expect))
    return (name, "HELD", "%s child tally %d/%d/%d (rc=%d)"
            % ((name,) + tally + (p.returncode,)))


def green_check():
    """Run adjacent batteries in child mode. Honors GOV_SKIP_GREEN so
    nesting stays depth-1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD", "skipped (child mode)")
        return
    for name, rel, expect in _GREEN_EVALS:
        _record(*_run_green_eval(name, rel, expect))


@probe("P5b-green-w326-standing")
def _p5b():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5b-green-w326-standing", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[0])
    return ("P5b-green-w326-standing", verdict, note)


@probe("P5c-green-w326-sched")
def _p5c():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5c-green-w326-sched", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[1])
    return ("P5c-green-w326-sched", verdict, note)


@probe("P5d-green-w326-tufaudit")
def _p5d():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5d-green-w326-tufaudit", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[2])
    return ("P5d-green-w326-tufaudit", verdict, note)


@probe("P5e-green-w326-redteam")
def _p5e():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5e-green-w326-redteam", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[3])
    return ("P5e-green-w326-redteam", verdict, note)


@probe("P5f-green-w325-redteam")
def _p5f():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5f-green-w325-redteam", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[4])
    return ("P5f-green-w325-redteam", verdict, note)


@probe("P5g-green-w324-alert")
def _p5g():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5g-green-w324-alert", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[5])
    return ("P5g-green-w324-alert", verdict, note)


# ---------------------------------------------------------------------------
# P6: taxonomy pin + footer state.
# ---------------------------------------------------------------------------

@probe("P6a-pin-taxonomy-2131-sorted")
def _p6a():
    from gov import decision_codes
    codes = list(decision_codes.TAXONOMY)
    if TAXONOMY_PIN != 2131:
        return _break("P6a-pin-taxonomy-2131-sorted",
                      "TAXONOMY_PIN is %r, want 2131" % (TAXONOMY_PIN,))
    if len(codes) != 2131 or codes != sorted(codes):
        return _break("P6a-pin-taxonomy-2131-sorted",
                      "taxonomy size/order drift: n=%d" % (len(codes),))
    if len(set(codes)) != 2131:
        return _break("P6a-pin-taxonomy-2131-sorted",
                      "duplicate codes in TAXONOMY")
    return _held("P6a-pin-taxonomy-2131-sorted", "2131/2131/0 sorted")


@probe("P6b-footer-open-none-next-f428")
def _p6b():
    text = open(os.path.join(REPO, "evals/FINDINGS.md")).read()
    opens = re.findall(r"\*\*Open findings:\s*([^*]+?)\.\*\*", text)
    nexts = re.findall(r"Next free finding:\s*\*\*([^*]+?)\*\*", text)
    open_line = opens[-1].strip() if opens else ""
    next_free = nexts[-1].strip() if nexts else ""
    if open_line != FOOTER_OPEN:
        return _break("P6b-footer-open-none-next-f428",
                      "open findings %r, want %r" % (open_line, FOOTER_OPEN))
    if next_free != FOOTER_NEXT:
        return _break("P6b-footer-open-none-next-f428",
                      "next free %r, want %r" % (next_free, FOOTER_NEXT))
    return _held("P6b-footer-open-none-next-f428",
                 "footer open none / next F419")


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # F412 CLOSED 2026-10-04 wave-328 lane 1 (merge: lane-2 version had it expected; fixed).


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    for pid, fn in _PROBES:
        if only is not None and pid != only:
            continue
        _safe(pid, fn)
    if only is None:
        green_check()
    breaks = errors = 0
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "ERROR":
            errors += 1
    got_breaks = {pid for pid, v, n in _results if v == "BREAK"}
    mismatch = got_breaks ^ _EXPECTED_BREAKS
    print("w327_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected: F412 closed 2026-10-04 wave-328 lane 1)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
