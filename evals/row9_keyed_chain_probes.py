#!/usr/bin/env python3
"""Row-9 residual 2: unkeyed chain recomputation — keyed HMAC chains.

``gov/chained_store.py`` (DriftStore, FramingStore) and
``PopulationStore`` (gov/drift.py) chained records with UNKEYED
SHA-256. Anyone with write access to the store files could rewrite
history and recompute the chain: tamper-evident against accidents,
not against an attacker. The fix brings these chains to the audit
log's standard: HMAC-SHA256 with the deployment key (resolved via
``gov.keyprovider``, the same idiom as ``gov.log._active_key`` —
no new key story), domain-separated per store kind.

Scheme versioning (backward compatible): new records carry
``chain_keyed: true`` (+ ``key_epoch``); ``verify_chain`` selects the
scheme per record — old unkeyed records verify under the legacy
scheme, new appends under HMAC. Mixed chains verify.

Probes (each store kind: drift, framing, population):
  k1_history_rewrite_recompute_fails: rewrite a historical
      fingerprint and recompute digests WITHOUT the key -> must NOT
      verify. (Pre-fix: verifies clean -> BREAK.)
  k2_legacy_chain_still_verifies: a hand-built legacy unkeyed chain
      verifies without any key. (HELD pre- and post-fix.)
  k3_no_key_fail_closed: with no key configured, appends raise
      (fail-closed, never silently unkeyed) and a keyed chain does
      not verify. (Pre-fix: append succeeds unkeyed -> BREAK.)
  k4_mixed_chain_verifies: legacy records + new keyed appends verify
      together. (Post-fix only; pre-fix there is no keyed scheme.)
  k5_wrong_key_rejected: a chain keyed under key A does not verify
      under key B. (Post-fix only.)

Verdicts: HELD / BREAK / ERROR (+ SKIP for post-fix-only probes on a
pre-fix tree — detected by probing the scheme, not by version).

$0 spend, synthetic/local, deterministic (no RNG in verdicts; key
material is random per run but behavior is deterministic). Stdlib only.

Run:
  mkdir -p /tmp/gov-row9keyed
  TMPDIR=/tmp/gov-row9keyed ~/workspace/.gov-venv/bin/python \\
      evals/row9_keyed_chain_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-row9keyedb \\
      ~/workspace/.gov-venv/bin/python evals/row9_keyed_chain_probes.py
"""

import copy
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "row9keyed-break")
os.environ.setdefault("TMPDIR", "/tmp/gov-row9keyed-%d" % os.getpid())
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import drift as _drift  # noqa: E402
from gov import framing as _framing  # noqa: E402
from gov.chained_store import canonical as _canonical  # noqa: E402
from gov.chained_store import sha256_hex as _sha256_hex  # noqa: E402
from keyfixture import scrub_key_env  # noqa: E402

_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-46s %-8s %s" % (name, verdict, detail))


def _drift_fp(seq):
    return _drift.RunFingerprint(
        tool_counts={"search": 40 + seq, "summarize": 30, "email": 20,
                     "read_file": 10},
        decisions={"allow": 100 + seq, "require_approval": 0, "deny": 0},
        egress_bytes=4_000, run_seq=seq, run_id="r%d" % seq)


def _framing_fp(seq):
    return _framing.FramingFingerprint(
        {"http_post": {"host:api.example": 40 + seq,
                       "host:vendor.example": 10}},
        run_seq=seq, run_id="r%d" % seq)


def _pop_fp(seq):
    return _drift_fp(seq)


def _kinds():
    """(tag, make_store, append_fn, path_fn)."""
    def _drift_store(tag):
        d = Path(tempfile.mkdtemp(prefix="row9keyed_%s_" % tag,
                                  dir=os.environ["TMPDIR"]))
        return _drift.DriftStore(d)

    def _framing_store(tag):
        d = Path(tempfile.mkdtemp(prefix="row9keyed_%s_" % tag,
                                  dir=os.environ["TMPDIR"]))
        return _framing.FramingStore(d)

    def _pop_store(tag):
        d = Path(tempfile.mkdtemp(prefix="row9keyed_%s_" % tag,
                                  dir=os.environ["TMPDIR"]))
        return _drift.PopulationStore(d / "population")

    return (
        ("drift",
         _drift_store,
         lambda s: [s.record_run("a%d" % i, "p", _drift_fp(i))
                    for i in range(3)],
         lambda s: s._path("a0"),
         "fingerprint"),
        ("framing",
         _framing_store,
         lambda s: [s.record_run("a%d" % i, "p", _framing_fp(i))
                    for i in range(3)],
         lambda s: s._path("a0"),
         "fingerprint"),
        ("population",
         _pop_store,
         lambda s: [s.record_baseline("a%d" % i, "p", _pop_fp(i))
                    for i in range(3)],
         lambda s: s._path(),
         "fingerprint"),
    )


def _is_keyed_scheme():
    """True when the tree writes keyed records (post-fix detection)."""
    d = Path(tempfile.mkdtemp(prefix="row9keyed_detect_",
                              dir=os.environ["TMPDIR"]))
    s = _drift.DriftStore(d)
    s.record_run("probe", "p", _drift_fp(0))
    rec = json.loads(s._path("probe").read_text(
        encoding="utf-8").splitlines()[0])
    return bool(rec.get("chain_keyed"))


def _rewrite_history_without_key(path, fp_key="fingerprint"):
    """Attacker: alter a historical fingerprint, recompute the chain
    with the UNKEYED scheme (no key). Returns nothing; rewrites file."""
    lines = path.read_text(encoding="utf-8").splitlines()
    recs = [json.loads(ln) for ln in lines if ln.strip()]
    # Tamper: bump a tool count in the FIRST record's fingerprint.
    first = recs[0]
    fp = first[fp_key]
    tc = fp.get("tool_counts") or {}
    if tc:
        k = sorted(tc)[0]
        tc[k] = tc[k] + 10_000
    elif "arg_counts" in fp:
        tool = sorted(fp["arg_counts"])[0]
        cat = sorted(fp["arg_counts"][tool])[0]
        fp["arg_counts"][tool][cat] += 10_000
    # Recompute every digest down the chain with the unkeyed scheme
    # (in place — the attacker rewrites the file they control).
    prev = ""
    for rec in recs:
        rec.pop("digest", None)
        rec["prev_digest"] = prev
        rec["digest"] = _sha256_hex(_canonical(rec))
        prev = rec["digest"]
    path.write_text("\n".join(_canonical(r) for r in recs) + "\n",
                    encoding="utf-8")


def _legacy_chain(path, n=3):
    """Hand-build a legacy (unkeyed) chain — the pre-upgrade format."""
    recs = []
    prev = ""
    for i in range(n):
        rec = {"v": 1, "seq": i, "data": "legacy-%d" % i,
               "prev_digest": prev}
        rec["digest"] = _sha256_hex(_canonical(
            {k: v for k, v in rec.items() if k != "digest"}))
        prev = rec["digest"]
        recs.append(rec)
    path.write_text("\n".join(_canonical(r) for r in recs) + "\n",
                    encoding="utf-8")
    return recs


# ---------------------------------------------------------------- probes

def k1_history_rewrite_recompute_fails():
    name = "k1_history_rewrite_recompute_fails"
    for tag, make, append, pathfn, fpkey in _kinds():
        s = make("k1_" + tag)
        append(s)
        _rewrite_history_without_key(pathfn(s), fpkey)
        ok = s.verify_chain("a0") if tag != "population" \
            else s.verify_chain()
        if ok:
            _record(name, "BREAK",
                    "%s: rewritten history + recomputed digests verifies "
                    "clean WITHOUT the key" % tag)
            return
    _record(name, "HELD",
            "off-band rewrite + unkeyed recompute fails verification "
            "on all three store kinds")


def k2_legacy_chain_still_verifies():
    name = "k2_legacy_chain_still_verifies"
    for tag, make, _append, pathfn, _fpkey in _kinds():
        s = make("k2_" + tag)
        _legacy_chain(pathfn(s))
        ok = s.verify_chain("a0") if tag != "population" \
            else s.verify_chain()
        if not ok:
            _record(name, "BREAK",
                    "%s: legacy unkeyed chain no longer verifies" % tag)
            return
    _record(name, "HELD",
            "legacy unkeyed chains verify without a key (backward compat)")


def k3_no_key_fail_closed():
    name = "k3_no_key_fail_closed"
    from gov.keys import NoKeyConfiguredError  # noqa: E402
    restore = scrub_key_env()
    try:
        for tag, make, append, _pathfn, _fpkey in _kinds():
            s = make("k3_" + tag)
            try:
                append(s)
            except NoKeyConfiguredError:
                continue
            _record(name, "BREAK",
                    "%s: append without a configured key succeeded "
                    "(silently unkeyed)" % tag)
            return
    finally:
        restore()
    # And a keyed chain must not verify once the key is gone.
    if _is_keyed_scheme():
        restore2 = scrub_key_env()
        try:
            d = Path(tempfile.mkdtemp(prefix="row9keyed_k3v_",
                                      dir=os.environ["TMPDIR"]))
            s = _drift.DriftStore(d)
            # Re-provision briefly to write, then scrub to verify.
            os.environ["GOV_LOG_KEY"] = secrets.token_hex(32)
            s.record_run("a0", "p", _drift_fp(0))
            for var in ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH"):
                os.environ.pop(var, None)
            if s.verify_chain("a0"):
                _record(name, "BREAK",
                        "keyed chain verified with no key configured")
                return
        finally:
            restore2()
    _record(name, "HELD",
            "no key -> appends refuse loudly; keyed chains do not "
            "verify without the key")


def k4_mixed_chain_verifies():
    name = "k4_mixed_chain_verifies"
    if not _is_keyed_scheme():
        _record(name, "SKIP", "pre-fix tree: no keyed scheme to mix with")
        return
    for tag, make, append, pathfn, _fpkey in _kinds():
        s = make("k4_" + tag)
        _legacy_chain(pathfn(s), n=2)
        # New keyed appends must chain onto the legacy tail.
        try:
            if tag == "population":
                s.record_baseline("fresh", "p", _pop_fp(9))
                ok = s.verify_chain()
            else:
                s.record_run("a0", "p",
                             _drift_fp(9) if tag == "drift"
                             else _framing_fp(9))
                ok = s.verify_chain("a0")
        except Exception as e:  # noqa: BLE001
            _record(name, "BREAK",
                    "%s: keyed append onto legacy chain raised %r" % (tag, e))
            return
        if not ok:
            _record(name, "BREAK",
                    "%s: mixed legacy+keyed chain does not verify" % tag)
            return
    _record(name, "HELD", "legacy records + new keyed appends verify")


def k5_wrong_key_rejected():
    name = "k5_wrong_key_rejected"
    if not _is_keyed_scheme():
        _record(name, "SKIP", "pre-fix tree: no keyed scheme")
        return
    from gov.keys import NoKeyConfiguredError  # noqa: E402  (unused guard)
    d = Path(tempfile.mkdtemp(prefix="row9keyed_k5_",
                              dir=os.environ["TMPDIR"]))
    key_a = secrets.token_hex(32)
    os.environ["GOV_LOG_KEY"] = key_a
    s = _drift.DriftStore(d)
    s.record_run("a0", "p", _drift_fp(0))
    s.record_run("a0", "p", _drift_fp(1))
    # Attacker/operator rotates to an unrelated key: the old chain must
    # not verify under it.
    os.environ["GOV_LOG_KEY"] = secrets.token_hex(32)
    s2 = _drift.DriftStore(d)
    if s2.verify_chain("a0"):
        _record(name, "BREAK", "chain keyed under A verified under key B")
        return
    # Sanity: restoring key A verifies again.
    os.environ["GOV_LOG_KEY"] = key_a
    s3 = _drift.DriftStore(d)
    if not s3.verify_chain("a0"):
        _record(name, "BREAK", "chain does not verify under its own key")
        return
    _record(name, "HELD",
            "wrong-key verification fails; right-key verification holds")


_PROBES = (
    k1_history_rewrite_recompute_fails,
    k2_legacy_chain_still_verifies,
    k3_no_key_fail_closed,
    k4_mixed_chain_verifies,
    k5_wrong_key_rejected,
)


def main():
    print("Row-9 residual 2 probes: keyed chain recomputation")
    for fn in _PROBES:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 -- battery must not die
            _record(fn.__name__, "ERROR", "%r" % (e,))
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    skp = sum(1 for _, v, _ in _RESULTS if v == "SKIP")
    print("%d HELD, %d BREAK, %d ERROR, %d SKIP" % (held, brk, err, skp))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
