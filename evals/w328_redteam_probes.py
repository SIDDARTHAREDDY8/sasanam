"""Wave-328 independent red-team battery.

Base: 54cdac0d (wave-327 merge). Footer: open F412, F413 / next F414
(F413 filed by this lane). Wave-329 lane 1 closed F413: footer is now
open none / next F414; P1b/P1c are HELD.
Pin: 2100.

P1  wave-327 policy-channel seams (unsigned, ordering, revocation,
    feed escape, canonicalization, replay).
P2  F412 re-probe (standing-conflict crash wedge -- must still BREAK;
    wave-328 lane 1 owns the closure).
P3  F410/F411 closure-regression probes (all must stay HELD).
P4  regression: F409/F408/F407/F406 (all must stay HELD).
P5  file-integrity probe + prior batteries in child mode.
P6  pin 2100 + footer state.

gov/ is byte-identical to base: this battery changes no product code and
files findings only (from F413). No new decision codes from this lane.
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

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
FOOTER_OPEN = "F595, F606, F607, F609, F610, F611"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # F426-F427 CLOSED (wave-340 lane 1); F428 OPEN (wave-341 lane C).; F442 CLOSED 2026-10-05 wave-347 lane 6; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED


FOOTER_NEXT = "F606"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)



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
import w327_redteam_probes as _w327  # noqa: E402
import w325_redteam_probes as _w325  # noqa: E402
import w323_redteam_probes as _w323  # noqa: E402
import w322_redteam_probes as _w322  # noqa: E402


# ---------------------------------------------------------------------------
# P1: wave-327 policy-channel seams.
# ---------------------------------------------------------------------------

_NOW = 1700000000 + 100  # fixed clock: avoids the stale bound in probes


def _pkeys():
    from gov import ed25519
    seed = ed25519.generate_seed()
    return seed, ed25519.publickey(seed)


def _pdoc(seed, version, policy_name="pol", revokes=(),
          issued_at=1700000000):
    from gov import ed25519
    from gov.bundle_refresh import tuf_canonical_json
    payload = {
        "schema": "sasanam-policy-document/v1",
        "policy_name": policy_name,
        "version": version,
        "body": {"rules": ["r%d" % version]},
        "revokes": list(revokes),
        "motivated_by": [{"origin": "t", "collector": "t",
                          "known_since": 1}],
        "issued_at": issued_at,
    }
    raw = tuf_canonical_json(payload)
    sig = ed25519.sign(seed, raw)
    return {"payload": base64.b64encode(raw).decode("ascii"),
            "signature": base64.b64encode(sig).decode("ascii")}


def _pwrite(feed, envelope, version, policy_name="pol"):
    path = os.path.join(feed, "%s.v%d.json" % (policy_name, version))
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh)
    return path


def _pfresh(policy_name="pol", max_skip=4):
    from gov import policy_channel as pc
    feed = tempfile.mkdtemp(prefix="w328-pfeed-")
    state = tempfile.mkdtemp(prefix="w328-pstate-")
    seed, pub = _pkeys()
    cfg = pc.ChannelConfig(feed, pub, policy_name, max_skip=max_skip)
    return {"feed": feed, "state": state, "seed": seed, "pub": pub,
            "cfg": cfg, "pc": pc}


def _papply(fx, version):
    from gov import policy_channel as pc
    path = os.path.join(fx["feed"], "pol.v%d.json" % version)
    with open(path, "rb") as fh:
        return pc.apply_document(fx["cfg"], fx["state"], fh.read(),
                                 now=_NOW)


@probe("P1a-policy-unsigned-refused")
def _p1a():
    """A tampered-signature policy is refused coded (positive control)."""
    fx = _pfresh()
    pc = fx["pc"]
    env = _pdoc(fx["seed"], 1)
    bad = dict(env)
    sig = bytearray(base64.b64decode(env["signature"]))
    sig[0] ^= 0xFF
    bad["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
    _pwrite(fx["feed"], bad, 1)
    rep = pc.poll(fx["cfg"], fx["state"], now=_NOW)
    if rep["applied"] is False and rep["code"] == "policy-channel-unsigned" \
            and pc.current_version(fx["cfg"], fx["state"]) == 0:
        return _held("P1a-policy-unsigned-refused",
                     "tampered signature refused coded")
    return _break("P1a-policy-unsigned-refused", "report=%r" % (rep,))


@probe("P1b-f413-feed-version-ordering")
def _p1b():
    """F413 (CLOSED 2026-10-04 wave-329 lane 1): _feed_files ordered by
    FILENAME, not version.

    On the open tree, a feed holding {v1, v2, v10} with the floor at v1
    (max_skip 4) tried v10 first (filename sort: "pol.v10.json" <
    "pol.v2.json"), hit coded policy-channel-version-skip, stopped the
    poll, and never applied the valid in-window v2 -- the agent stayed
    on v1 despite an applicable update sitting in the feed.

    The fix sorts feed files numerically by parsed version, so v2 is
    applied first and only then is v10 refused coded version-skip.
    """
    fx = _pfresh()
    pc = fx["pc"]
    for v in (1, 2, 10):
        _pwrite(fx["feed"], _pdoc(fx["seed"], v), v)
    _papply(fx, 1)
    rep = pc.poll(fx["cfg"], fx["state"], now=_NOW)
    current = pc.current_version(fx["cfg"], fx["state"])
    if current == 2 and rep["code"] == "policy-channel-version-skip":
        return _held("P1b-f413-feed-version-ordering",
                     "v2 applied, then v10 refused coded version-skip")
    if current == 1:
        return _break(
            "P1b-f413-feed-version-ordering",
            "F413 reproduces: filename sort tries v10 before v2; "
            "version-skip refusal stops the poll and the valid in-window "
            "v2 is never applied (agent stuck on v1; code=%r)" % rep["code"])
    return _break("P1b-f413-feed-version-ordering",
                  "unexpected state: current=%r code=%r" % (current, rep["code"]))


@probe("P1c-f413-intermediate-revocation-recorded")
def _p1c():
    """F413 (CLOSED 2026-10-04 wave-329 lane 1): an intermediate version's
    revokes were silently dropped.

    On the open tree, a feed holding {v9 (revokes=[12]), v10} with the
    floor at v8 applied v10 first (filename sort), then skipped v9 with
    a bare continue -- no report note, no warning -- leaving
    revoked_versions=[]; a later validly-signed v12 then APPLIED even
    though the publisher had revoked it.

    The fix applies versions in numeric order, so v9's revokes=[12]
    are merged before v10 applies, and a later v12 refuses coded
    policy-channel-superseded (the established revocation refusal;
    the close-when allowed no new codes).
    """
    fx = _pfresh()
    pc = fx["pc"]
    _pwrite(fx["feed"], _pdoc(fx["seed"], 4), 4)
    _pwrite(fx["feed"], _pdoc(fx["seed"], 8), 8)
    _pwrite(fx["feed"], _pdoc(fx["seed"], 9, revokes=(12,)), 9)
    _pwrite(fx["feed"], _pdoc(fx["seed"], 10), 10)
    _papply(fx, 4)
    _papply(fx, 8)
    pc.poll(fx["cfg"], fx["state"], now=_NOW)
    revoked = pc._load_state(fx["state"])["revoked_versions"]
    if 12 in revoked:
        return _held("P1c-f413-intermediate-revocation-recorded",
                     "v9's revocation of v12 recorded (revoked=%r)" % (revoked,))
    # Demonstrate the consequence: the revoked v12 now applies.
    _pwrite(fx["feed"], _pdoc(fx["seed"], 12), 12)
    try:
        _papply(fx, 12)
        applied = True
    except pc.PolicyChannelError:
        applied = False
    if applied:
        return _break(
            "P1c-f413-intermediate-revocation-recorded",
            "F413 reproduces: v9 silently skipped by filename sort, "
            "revoked=%r; the publisher-revoked v12 then APPLIES" % (revoked,))
    return _break("P1c-f413-intermediate-revocation-recorded",
                  "revoked=%r but v12 refused (unexpected)" % (revoked,))


@probe("P1d-policy-feed-escape-refused")
def _p1d():
    """A feed symlink pointing outside the feed dir is refused coded."""
    fx = _pfresh()
    pc = fx["pc"]
    outside = tempfile.mkdtemp(prefix="w328-outside-")
    target = os.path.join(outside, "evil.json")
    with open(target, "w") as fh:
        json.dump(_pdoc(fx["seed"], 1), fh)
    link = os.path.join(fx["feed"], "pol.v1.json")
    os.symlink(target, link)
    rep = pc.poll(fx["cfg"], fx["state"], now=_NOW)
    if rep["applied"] is False and rep["code"] == "policy-channel-feed-escape":
        return _held("P1d-policy-feed-escape-refused",
                     "in-feed symlink escape refused coded")
    return _break("P1d-policy-feed-escape-refused", "report=%r" % (rep,))


@probe("P1e-policy-noncanonical-payload-refused")
def _p1e():
    """A correctly-signed but non-canonical payload is refused (positive
    control for the canonicalization pin)."""
    fx = _pfresh()
    pc = fx["pc"]
    from gov.bundle_refresh import tuf_canonical_json
    from gov import ed25519
    payload = {
        "schema": "sasanam-policy-document/v1",
        "policy_name": "pol",
        "version": 1,
        "body": {"rules": ["r1"]},
        "revokes": [],
        "motivated_by": [{"origin": "t", "collector": "t",
                          "known_since": 1}],
        "issued_at": 1700000000,
    }
    # Non-canonical encoding: pretty-printed with spaces.
    raw = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    assert raw != tuf_canonical_json(payload)
    sig = ed25519.sign(fx["seed"], raw)
    env = {"payload": base64.b64encode(raw).decode("ascii"),
           "signature": base64.b64encode(sig).decode("ascii")}
    _pwrite(fx["feed"], env, 1)
    rep = pc.poll(fx["cfg"], fx["state"], now=_NOW)
    if rep["applied"] is False and rep["code"] == "policy-channel-malformed":
        return _held("P1e-policy-noncanonical-payload-refused",
                     "signed non-canonical payload refused coded")
    return _break("P1e-policy-noncanonical-payload-refused",
                  "report=%r" % (rep,))


@probe("P1f-policy-replay-refused")
def _p1f():
    """A replayed older version is refused coded (positive control)."""
    fx = _pfresh()
    pc = fx["pc"]
    for v in (1, 2):
        _pwrite(fx["feed"], _pdoc(fx["seed"], v), v)
    _papply(fx, 1)
    _papply(fx, 2)

    def replay():
        _papply(fx, 1)
    return _expect_code("P1f-policy-replay-refused", replay,
                        pc.PolicyChannelError, "policy-channel-rollback",
                        "replayed v1 against floor v2")


# ---------------------------------------------------------------------------
# P2: F412 re-probe (must still BREAK; wave-328 lane 1 owns the closure).
# ---------------------------------------------------------------------------

_D1 = "sha256:" + "aa" * 32


def _fresh_store(prefix):
    from gov import standing_verdicts as sv
    root = tempfile.mkdtemp(prefix=prefix)
    return sv.StandingStore(os.path.join(root, "journal.jsonl")), sv


def _know(digest, standing, justification, known_since, supersedes,
          origin="o", collector="c", advisory_id="adv"):
    return {"artifact_digest": digest, "asserted_standing": standing,
            "justification": justification, "origin": origin,
            "collector": collector, "known_since": known_since,
            "supersedes": supersedes, "advisory_id": advisory_id}


@probe("P2a-f412-conflict-crash-wedges-store")
def _p2a():
    """F412 (LOW, OPEN): _resolve_conflict's two journal appends are not
    atomic. A crash between them leaves a conflict entry as the tip;
    on reload, standing_of and attach_knowledge raise an UNCODED
    KeyError -- the store is permanently wedged."""
    s, sv = _fresh_store("w328-p2a-")
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
        return _held("P2a-f412-conflict-crash-wedges-store",
                     "crash-window now fails coded %s" % exc.code)
    else:
        return _held("P2a-f412-conflict-crash-wedges-store",
                     "crash-window recovered cleanly")
    try:
        s2.attach_knowledge(_know(_D1, "trusted", "legit", 400,
                                  s2._tips[_D1]))
    except KeyError:
        return _break(
            "P2a-f412-conflict-crash-wedges-store",
            "F412 reproduces: after a crash between the conflict journal "
            "append and the winner append, standing_of AND attach_knowledge "
            "raise uncoded KeyError('asserted_standing'); the store is "
            "permanently wedged (every reload replays the poisoned tip)")
    except sv.StandingError as exc:
        return _held("P2a-f412-conflict-crash-wedges-store",
                     "write path fails coded %s" % exc.code)
    return _held("P2a-f412-conflict-crash-wedges-store",
                 "write path recovered cleanly")


# ---------------------------------------------------------------------------
# P3: F410/F411 closure-regression probes (all must stay HELD).
# ---------------------------------------------------------------------------

@probe("P3a-f410-t4b-floor-still-enforced")
def _p3a():
    """F410 closure must not regress the pre-rotation rollback floor:
    a below-floor version verifying under the new root stays a loud
    rollback refusal."""
    verdict, note = _w326tuf._p4b()  # 2-tuple convention in that battery
    return ("P3a-f410-t4b-floor-still-enforced", verdict, note)


@probe("P3b-f410-t4c-stays-recovered")
def _p3b():
    """F410 (LOW, CLOSED wave-327 lane 2): pruned pre-rotation slots now
    recover instead of wedging."""
    verdict, note = _w326tuf._p4c()
    return ("P3b-f410-t4c-stays-recovered", verdict, note)


@probe("P3c-f410-t4d-stays-recovered")
def _p3c():
    """F410 (LOW, CLOSED wave-327 lane 2): a single pruned slot now
    recovers instead of wedging."""
    verdict, note = _w326tuf._p4d()
    return ("P3c-f410-t4d-stays-recovered", verdict, note)


@probe("P3d-f410-miss-bound-suspends-loud")
def _p3d():
    """F410 closure residual (documented): a prune window WIDER than the
    32-miss bound still suspends -- but it must suspend LOUD and coded
    (fail-closed), never hang and never trust."""
    from datetime import datetime, timezone
    repo = _w326tuf._base_repo(datetime(2026, 6, 1, 12, tzinfo=timezone.utc))
    r, _ = _w326tuf._refresher(repo, lambda: datetime(
        2026, 6, 1, 12, tzinfo=timezone.utc))
    assert r.refresh().state == "trusted"
    repo.root(2, ["b", "rk3"], "tk2", ["a", "b"], ["b", "rk3"])
    repo.targets(2, "tk2")
    repo.snapshot(2, 2, "tk2")
    for v in (34, 35):
        repo.timestamp(v, 2, "tk2")
    for v in range(1, 34):
        repo.drop("timestamp", v)
    rep = r.refresh()
    reason = (rep.reason or "").lower()
    if rep.state == "suspended" and ("miss" in reason or "stopping" in reason
                                     or "no timestamp version" in reason):
        return _held("P3d-f410-miss-bound-suspends-loud",
                     "33-miss window suspends loud: %s" % rep.reason)
    if rep.state == "trusted":
        return _break("P3d-f410-miss-bound-suspends-loud",
                      "over-bound prune window TRUSTED without recovery")
    return _break("P3d-f410-miss-bound-suspends-loud",
                  "unexpected: state=%s reason=%s" % (rep.state, rep.reason))


@probe("P3e-f411-forged-dict-still-refused")
def _p3e():
    """F411 (MEDIUM, CLOSED wave-327 lane 1): a forged dict token_claims
    must still be refused coded."""
    return _relabel("P3e-f411-forged-dict-still-refused", _w326rt._p3a)


@probe("P3f-f411-verify-token-sealed-type")
def _p3f():
    """F411 closure: verify_token returns the non-forgeable
    VerifiedTokenClaims type bound to the producing verifier."""
    import time as _time
    from gov import federated_identity as fi
    _fi, iss, v = _w326rt._fi_setup()
    token = _w326rt._fi_token(iss, now=int(_time.time()))
    claims = v.verify_token(token)
    if isinstance(claims, fi.VerifiedTokenClaims) and claims.verified_by is v:
        return _held("P3f-f411-verify-token-sealed-type",
                     "verify_token returns VerifiedTokenClaims bound to v")
    return _break("P3f-f411-verify-token-sealed-type",
                  "claims type=%r verified_by=%r"
                  % (type(claims).__name__,
                     getattr(claims, "verified_by", None)))


@probe("P3g-f411-string-token-still-mints")
def _p3g():
    """F411 closure must not break the legitimate string-token path
    (positive control)."""
    return _relabel("P3g-f411-string-token-still-mints", _w326rt._p3l)


# ---------------------------------------------------------------------------
# P4: regression -- F409/F408/F407/F406 (all must stay HELD).
# ---------------------------------------------------------------------------

@probe("P4a-f409-stays-held")
def _p4a():
    """F409 (LOW, CLOSED wave-326 lane 1): re-probe must stay HELD."""
    return _relabel("P4a-f409-stays-held", _w325._p1a)


@probe("P4b-f408-stays-held")
def _p4b():
    """F408 (MEDIUM, CLOSED): monitor-state deletion mid-outage alerts loudly."""
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
# P5: file-integrity probe + prior batteries in child mode.
# ---------------------------------------------------------------------------

@probe("P5a-file-integrity-no-truncation-no-corruption")
def _p5a():
    """No battery/probe file is empty or truncated, and no pin-repoint
    corruption markers survive.

    The wave-327 merge's scripted resolver truncated two probe files to
    0 bytes (caught by a line-count check). This probe sweeps every .py
    file in the tree (excluding .git/__pycache__): none may be empty,
    and no pin literal may carry a corruption suffix. (Needles are built
    dynamically so this file's own documentation does not self-match.)
    """
    needles = ["2035" + "OLD", "2100" + "OLD"]
    empty = []
    corrupt = []
    bad_pin = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        for skip in (".git", "__pycache__"):
            if skip in dirnames:
                dirnames.remove(skip)
        for name in filenames:
            if not name.endswith(".py"):
                continue
            p = os.path.join(dirpath, name)
            try:
                with open(p, "rb") as fh:
                    blob = fh.read()
            except OSError:
                continue
            rel = os.path.relpath(p, REPO)
            # An empty __init__.py is the conventional packaging marker,
            # not a truncation (the wave-327 incident truncated probe
            # files, never __init__.py).
            if len(blob) == 0 and os.path.basename(p) != "__init__.py":
                empty.append(rel)
                continue
            if len(blob) == 0:
                continue
            for needle in needles:
                if needle.encode("ascii") in blob:
                    corrupt.append(rel)
            # A pin literal with a non-digit suffix is a repoint artifact.
            for m in re.finditer(rb"TAXONOMY_PIN\s*=\s*([0-9]+[A-Za-z_]+)",
                                 blob):
                bad_pin.append("%s:%s" % (rel, m.group(1).decode()))
    problems = []
    if empty:
        problems.append("empty .py files: %r" % (empty[:5],))
    if corrupt:
        problems.append("corruption markers: %r" % (corrupt[:5],))
    if bad_pin:
        problems.append("malformed pin literals: %r" % (bad_pin[:5],))
    if problems:
        return _break("P5a-file-integrity-no-truncation-no-corruption",
                      "; ".join(problems))
    return _held("P5a-file-integrity-no-truncation-no-corruption",
                 "no empty .py files, no corruption markers, pins well-formed")


def _parse_tally(text):
    m = re.search(r"(\d+)\s+BREAK\s*/\s*(\d+)\s+HELD\s*/\s*(\d+)\s+ERROR",
                  text)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    # w326_tufaudit_probes.py prints "18/0/0 held/break/error".
    m = re.search(r"(\d+)/(\d+)/(\d+)\s+held/break/error", text)
    if m:
        return (int(m.group(2)), int(m.group(1)), int(m.group(3)))
    return None


# Post-merge tallies on the wave-327 tree (footer open F412 / next F413).
# The expected BREAKs are the open-finding probes: P1b/P1c (F413, this
# battery) and P2a (F412). Child mode (GOV_SKIP_GREEN=1).
#
# NOTE (merge resolution, 2026-10-04): the wave-330 merge re-pinned all
# footer-state probes to the merged footer (open F415 / next F417; F414
# CLOSED by lane 1, F415/F416 OPEN filed by lane 3). The P5x green-chain probes
# are HELD again; the cascade sets were emptied (wave-305 class).
# per the wave-305 lesson. Footer probes re-pinned:
#   evals/w327_redteam_probes.py  P6b + _EXPECTED_BREAKS emptied (F412 closed)
#   evals/w327_polchan_probes.py  P2b (now P2b-footer-open-f415)
#   evals/w326_redteam_probes.py  P1a/P1h rewritten (lane 2 hardening)
#   evals/w326_standing_probes.py P11-footer-state
#   evals/w326_sched_probes.py    footer assertion
# plus transitively w325_redteam / w324_alert / w325_resid / w325_dexid /
# w324_offver / w324_vsa (grandchildren in the green chains).
_GREEN_EVALS = [
    ("w327-redteam", "evals/w327_redteam_probes.py", (0, 32, 0)),
    ("w327-polchan", "evals/w327_polchan_probes.py", (0, 18, 0)),
    ("w326-tufaudit", "evals/w326_tufaudit_probes.py", (0, 18, 0)),
    ("w326-redteam", "evals/w326_redteam_probes.py", (0, 36, 0)),
    ("w326-standing", "evals/w326_standing_probes.py", (0, 14, 0)),
    ("w326-sched", "evals/w326_sched_probes.py", (0, 18, 0)),
]


def _run_green_eval(name, rel, expect):
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tempfile.mkdtemp(prefix="w328-gc-")
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


_GREEN_IDS = {
    "w327-redteam": "P5b-green-w327-redteam",
    "w327-polchan": "P5c-green-w327-polchan",
    "w326-tufaudit": "P5d-green-w326-tufaudit",
    "w326-redteam": "P5e-green-w326-redteam",
    "w326-standing": "P5f-green-w326-standing",
    "w326-sched": "P5g-green-w326-sched",
}


def green_check():
    """Run adjacent batteries in child mode. Honors GOV_SKIP_GREEN so
    nesting stays depth-1. Records under the P5 probe IDs so the
    standalone BREAK set matches _EXPECTED_BREAKS."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD", "skipped (child mode)")
        return
    for name, rel, expect in _GREEN_EVALS:
        _name, verdict, note = _run_green_eval(name, rel, expect)
        _record(_GREEN_IDS[name], verdict, note)


@probe("P5b-green-w327-redteam")
def _p5b():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5b-green-w327-redteam", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[0])
    return ("P5b-green-w327-redteam", verdict, note)


@probe("P5c-green-w327-polchan")
def _p5c():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5c-green-w327-polchan", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[1])
    return ("P5c-green-w327-polchan", verdict, note)


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


@probe("P5f-green-w326-standing")
def _p5f():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5f-green-w326-standing", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[4])
    return ("P5f-green-w326-standing", verdict, note)


@probe("P5g-green-w326-sched")
def _p5g():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        # Depth-1 convention (evals/GREEN_CHECK_CONTRACT.md rule 5): in
        # child mode this probe must not spawn nested battery runs.
        return ("P5g-green-w326-sched", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    name, verdict, note = _run_green_eval(*_GREEN_EVALS[5])
    return ("P5g-green-w326-sched", verdict, note)


# ---------------------------------------------------------------------------
# P6: taxonomy pin + footer state.
# ---------------------------------------------------------------------------

@probe("P6a-pin-taxonomy-2140-sorted")
def _p6a():
    from gov import decision_codes
    codes = list(decision_codes.TAXONOMY)
    if TAXONOMY_PIN != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return _break("P6a-pin-taxonomy-2140-sorted",
                      "TAXONOMY_PIN is %r, want 2140" % (TAXONOMY_PIN,))
    if len(codes) != 2140 or codes != sorted(codes):  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return _break("P6a-pin-taxonomy-2140-sorted",
                      "taxonomy size/order drift: n=%d" % (len(codes),))
    if len(set(codes)) != 2140:  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
        return _break("P6a-pin-taxonomy-2140-sorted",
                      "duplicate codes in TAXONOMY")
    return _held("P6a-pin-taxonomy-2140-sorted", "2140/2140/0 sorted")


@probe("P6b-footer-open-f433-f434-f435-next-f436")
def _p6b():
    text = open(os.path.join(REPO, "evals/FINDINGS.md")).read()
    opens = re.findall(r"\*\*Open findings:\s*([^*]+?)\.\*\*", text)
    nexts = re.findall(r"Next free finding:\s*\*\*([^*]+?)\*\*", text)
    open_line = opens[-1].strip() if opens else ""
    next_free = nexts[-1].strip() if nexts else ""
    if open_line != FOOTER_OPEN:
        return _break("P6b-footer-open-f433-f434-f435-next-f436",
                      "open findings %r, want %r" % (open_line, FOOTER_OPEN))
    if next_free != FOOTER_NEXT:
        return _break("P6b-footer-open-f433-f434-f435-next-f436",
                      "next free %r, want %r" % (next_free, FOOTER_NEXT))
    return _held("P6b-footer-open-f433-f434-f435-next-f436",
                 "footer open none / next F419")


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

# F413 CLOSED by wave-329 lane 1 (P1b/P1c flip to HELD); the expected
# BREAK set is emptied per the wave-305 lesson (no open findings remain).
_EXPECTED_BREAKS = set()


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
    print("w328_redteam battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected: F413 closed 2026-10-04 wave-329 lane 1)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
