"""Wave-273 lane-B phase-2 battery: per-cycle atomic reference time.

The TUF pattern, reimplemented stdlib-only (gov/reference_time.py):
one clock sample per refresh cycle; every expiry check in the cycle
runs against that single reference time. These probes demonstrate
the property at the public seams and pin the honest limit:

  rt01  A mocked clock is sampled exactly ONCE per refresh() --
        however many expiry checks the cycle runs, the source sees
        one sample.
  rt02  Attack: a clock that leaps 10s per call, with every role
        expiring 1s after the cycle's sample. Pre-fix, root is
        judged fresh at t0 while timestamp/snapshot/targets are
        judged expired at t0+10s -- contradictory verdicts inside
        one cycle. Post-fix, all roles are judged against the
        single sample and the refresh is consistently trusted.
  rt03  An AtomicClock used before sample() fails LOUD (ValueError),
        never silently returns None.
  rt04  One AtomicClock sampled once serves an RSL handle AND a
        bundle refresh in the same cycle -- the underlying source is
        sampled exactly once for the whole cycle.
  rt05  Control: a genuinely expired chain is loudly warned and never
        trusted -- atomicity does not mask real expiry.
  rt06  Phase-2 shared-currency contract: ONE AtomicClock over an
        int-epoch source passed DIRECTLY (no adapter lambdas) serves
        an RSL handle AND a bundle refresh -- the refresh cycle
        samples the shared source exactly once and the RSL handle
        reads the frozen sample.

Honest limit (pinned, not a gap): the atomic reference kills
INTRA-CYCLE skew. It does not authenticate the clock -- a skewed
or attacker-controlled source is a deployment trust assumption.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (fixed seeds, fixed
clocks); fresh unique /var/tmp/g273* TMPDIR (`mkdir -p` first);
depth-1 green checks honoring GOV_SKIP_GREEN=1; no in-repo git
subprocesses; stdlib only.
"""

import hashlib
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault(
    "GOV_LOG_KEY",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w273-reftime")

_TMP = tempfile.mkdtemp(prefix="g273-reftime-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import reference_time as rt                    # noqa: E402
from gov import bundle_refresh as br                   # noqa: E402
from gov import bundle_rsl as rsl                      # noqa: E402
import gov.ed25519 as _ed                             # noqa: E402
from gov.signing import Ed25519Signer                  # noqa: E402

TAXONOMY_PIN = 2127  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


def _pin_check():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code": \'([^\']*)\'', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK", "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    return "HELD", "taxonomy pin 1588: 1588 unique literals"


# ---------------------------------------------------------------------------
# fixtures (same shape as tests/test_bundle_refresh.py)
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _signers():
    return {
        "a": Ed25519Signer(b"\x11" * 32),
        "b": Ed25519Signer(b"\x22" * 32),
        "ts": Ed25519Signer(b"\x33" * 32),
    }


_DECLARED = {"a": "kid-alpha", "b": "kid-beta", "ts": "kid-ts"}


def _keys_doc(kids):
    signers = _signers()
    return {_DECLARED[k]: {"keytype": "ed25519",
                          "keyval": {"public": signers[k].public_key.hex()}}
            for k in kids}


def _build_chain(files, expires):
    signers = _signers()
    doc = {"_type": "root", "version": 1,
           "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "keys": _keys_doc(["a", "b", "ts"]),
           "roles": {
               "root": {"keyids": [_DECLARED["a"], _DECLARED["b"]],
                        "threshold": 2},
               "timestamp": {"keyids": [_DECLARED["ts"]], "threshold": 1},
               "snapshot": {"keyids": [_DECLARED["ts"]], "threshold": 1},
               "targets": {"keyids": [_DECLARED["ts"]], "threshold": 1},
           }}
    files[("root", 1)] = br.seal_role(
        "root", doc, [(_DECLARED[k], signers[k]) for k in ("a", "b")])
    tdoc = {"_type": "targets", "version": 1,
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": {"skill:x": {"length": 10, "hashes": {
                "sha256": "ab" * 32}}}}
    files[("targets", 1)] = br.seal_role(
        "targets", tdoc, [(_DECLARED["ts"], signers["ts"])])
    sdoc = {"_type": "snapshot", "version": 1,
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "meta": {"targets.json": {
                "version": 1, "length": len(files[("targets", 1)]),
                "hashes": {"sha256": hashlib.sha256(
                    files[("targets", 1)]).hexdigest()}}}}
    files[("snapshot", 1)] = br.seal_role(
        "snapshot", sdoc, [(_DECLARED["ts"], signers["ts"])])
    tsdoc = {"_type": "timestamp", "version": 1,
             "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "snapshot": {"version": 1,
                          "length": len(files[("snapshot", 1)]),
                          "hashes": {"sha256": hashlib.sha256(
                              files[("snapshot", 1)]).hexdigest()}}}
    files[("timestamp", 1)] = br.seal_role(
        "timestamp", tsdoc, [(_DECLARED["ts"], signers["ts"])])


class _CountingSource(object):
    def __init__(self, start, step):
        self.calls = 0
        self.current = start
        self.step = step

    def __call__(self):
        self.calls += 1
        value = self.current
        self.current = self.current + self.step
        return value


def _refresher(files, cache_dir, clock):
    def fetch(role, version):
        key = (role, version)
        if key not in files:
            raise br.FetchNotFound("no %s v%s" % (role, version))
        return files[key]

    return br.BundleRefresher(
        trusted_root_wire=files[("root", 1)],
        fetch=fetch, cache_dir=cache_dir, clock=clock)


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------

def rt01_one_sample_per_refresh():
    """A mocked clock is sampled exactly ONCE per refresh() --
    however many expiry checks the cycle runs, the source sees one
    sample (plus the constructor's pre-existing pinned-root check)."""
    files = {}
    _build_chain(files, _NOW + timedelta(days=365))
    src = _CountingSource(_NOW, timedelta(seconds=3600))
    cache = tempfile.mkdtemp(prefix="g273-rt01-", dir=_TMP)
    r = _refresher(files, cache, src)
    report = r.refresh()
    if report.state != "trusted":
        return "ERROR", "refresh not trusted: %s" % (report.reason,)
    # 1 construction sample (pre-existing) + 1 cycle sample.
    if src.calls == 2:
        return "HELD", "one sample per refresh cycle (2 calls total)"
    return ("BREAK",
            "clock sampled %d times in one refresh -- expiry checks "
            "do not share a reference time" % src.calls)


def rt02_skew_between_checks_consistent():
    """Attack: a clock leaping 10s per call, every role expiring 1s
    after the cycle's sample. Pre-fix the cycle mixes verdicts (root
    fresh at t0, the rest expired at t0+10s). Post-fix all roles are
    judged against the single sample: consistently trusted, no
    expiry warnings."""
    files = {}
    _build_chain(files, _NOW + timedelta(seconds=1))
    cache = tempfile.mkdtemp(prefix="g273-rt02-", dir=_TMP)
    r = _refresher(files, cache, lambda: _NOW)
    src = _CountingSource(_NOW, timedelta(seconds=10))
    r._clock = src  # white-box: isolate the cycle's sample at t0
    report = r.refresh()
    expired = [w for w in report.warnings if "expired" in w]
    if report.state == "trusted" and not expired and src.calls == 1:
        return ("HELD",
                "all roles judged against one sample: trusted, no "
                "expiry warnings, 1 cycle sample")
    return ("BREAK",
            "intra-cycle skew produced mixed verdicts: state=%s "
            "expired_warnings=%d cycle_samples=%d"
            % (report.state, len(expired), src.calls))


def rt03_unsampled_clock_loud():
    """An AtomicClock used before sample() fails LOUD (ValueError),
    never silently returns None."""
    clock = rt.AtomicClock(lambda: 1)
    try:
        clock()
    except ValueError:
        return "HELD", "un-sampled clock raises ValueError"
    return "BREAK", "un-sampled clock did not fail loudly"


def rt04_shared_clock_one_sample_whole_cycle():
    """One AtomicClock sampled once serves an RSL handle AND a bundle
    refresh in the same cycle -- the underlying source is sampled
    exactly once for the whole cycle."""
    src = _CountingSource(1792000000, 3600)
    epoch_clock = rt.AtomicClock(src)
    epoch_clock.sample()
    seeds = [bytes([0x41]) * 32, bytes([0x42]) * 32]
    principals = {"p1": {"pub": _ed.publickey(seeds[0]).hex()},
                  "p2": {"pub": _ed.publickey(seeds[1]).hex()}}
    wire = rsl.make_rule_file(
        rule_id="rule-rt", bundle="bundle-rt", principals=principals,
        delegations=[{"name": "releasers", "key_ids": ["p1", "p2"],
                      "threshold": 1}],
        terminal_key_id="p1", terminal_seed=seeds[0],
        expires=1792000000 + 3600, now=1792000000)
    path = os.path.join(_TMP, "rsl-rt.jsonl")
    if os.path.exists(path):
        os.remove(path)
    log = rsl.open_log(path, wire, epoch_clock)
    log._check_expiry()
    files = {}
    _build_chain(files, _NOW + timedelta(days=365))
    cache = tempfile.mkdtemp(prefix="g273-rt04-", dir=_TMP)
    r = _refresher(
        files, cache,
        lambda: datetime.fromtimestamp(epoch_clock(), tz=timezone.utc))
    report = r.refresh()
    if report.state != "trusted":
        return "ERROR", "refresh not trusted: %s" % (report.reason,)
    if src.calls == 1:
        return "HELD", "RSL + refresh ran on one sample (1 source call)"
    return ("BREAK",
            "whole cycle used %d samples instead of 1" % src.calls)


def rt06_shared_clock_direct_no_adapters():
    """Phase 2 (shared-currency contract): ONE AtomicClock over an
    int-epoch source passed DIRECTLY -- no adapter lambdas -- serves
    an RSL handle AND a bundle refresh in the same cycle. The cycle
    owner samples once; every consumer (RSL expiry checks, the
    refresher's per-cycle _ref_time, manifest timestamps) reads the
    frozen sample, so the underlying source sees exactly ONE call
    for the whole cycle."""
    src = _CountingSource(1792000000, 3600)
    clock = rt.AtomicClock(src)
    clock.sample()  # THE cycle's single source call
    seeds = [bytes([0x41]) * 32, bytes([0x42]) * 32]
    principals = {"p1": {"pub": _ed.publickey(seeds[0]).hex()},
                  "p2": {"pub": _ed.publickey(seeds[1]).hex()}}
    wire = rsl.make_rule_file(
        rule_id="rule-rt6", bundle="bundle-rt6", principals=principals,
        delegations=[{"name": "releasers", "key_ids": ["p1", "p2"],
                      "threshold": 1}],
        terminal_key_id="p1", terminal_seed=seeds[0],
        expires=1792000000 + 3600, now=1792000000)
    path = os.path.join(_TMP, "rsl-rt6.jsonl")
    if os.path.exists(path):
        os.remove(path)
    try:
        log = rsl.open_log(path, wire, clock)  # direct share, no adapter
        log._check_expiry()
    except Exception as exc:  # noqa: BLE001
        return ("BREAK",
                "direct-shared clock refused by RSL (%s: %s)" % (
                    type(exc).__name__, exc))
    files = {}
    _build_chain(files, _NOW + timedelta(days=365))
    cache = tempfile.mkdtemp(prefix="g273-rt06-", dir=_TMP)
    try:
        r = _refresher(files, cache, clock)  # direct share, no adapter
        report = r.refresh()
    except Exception as exc:  # noqa: BLE001
        return ("BREAK",
                "direct-shared clock refused by refresh (%s: %s)" % (
                    type(exc).__name__, exc))
    if report.state != "trusted":
        return "ERROR", "refresh not trusted: %s" % (report.reason,)
    if src.calls == 1:
        return ("HELD",
                "one shared sample served RSL + refresh: 1 source "
                "call, no adapters")
    return ("BREAK",
            "shared clock touched the source %d times, want exactly 1"
            % src.calls)


def rt05_expired_chain_loud_not_trusted():
    """Control: a genuinely expired chain is loudly warned and never
    trusted -- atomicity does not mask real expiry."""
    files = {}
    _build_chain(files, _NOW - timedelta(seconds=1))
    cache = tempfile.mkdtemp(prefix="g273-rt05-", dir=_TMP)
    r = _refresher(files, cache, lambda: _NOW)
    report = r.refresh()
    if report.state != "trusted" and\
            any("expired" in w for w in report.warnings):
        return ("HELD",
                "expired chain: state=%s with loud expiry warnings"
                % report.state)
    return ("BREAK",
            "expired chain trusted or unwarned: state=%s" % report.state)


_PROBES = [
    ("pin-taxonomy-1458", "HELD", _pin_check),
    ("rt01-one-sample-per-refresh", "HELD", rt01_one_sample_per_refresh),
    ("rt02-skew-between-checks-consistent", "HELD",
     rt02_skew_between_checks_consistent),
    ("rt03-unsampled-clock-loud", "HELD", rt03_unsampled_clock_loud),
    ("rt04-shared-clock-one-sample-whole-cycle", "HELD",
     rt04_shared_clock_one_sample_whole_cycle),
    ("rt05-expired-chain-loud-not-trusted", "HELD",
     rt05_expired_chain_loud_not_trusted),
    ("rt06-shared-clock-direct-no-adapters", "HELD",
     rt06_shared_clock_direct_no_adapters),
]


# ---------------------------------------------------------------------------
# green checks (depth-1; honor GOV_SKIP_GREEN=1)
# ---------------------------------------------------------------------------

_GREEN_BATTERIES = [
    "w273_rslreplay_probes.py",
    "w272_redteam_probes.py",
]


def _green_checks():
    if GREEN_SKIP:
        return [("green", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 convention)")]
    notes = []
    evals_dir = os.path.join(REPO, "evals")
    for battery in _GREEN_BATTERIES:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        try:
            import subprocess
            proc = subprocess.run(
                [sys.executable, os.path.join(evals_dir, battery)],
                env=env, cwd=REPO, capture_output=True, text=True,
                timeout=600)
            tail = (proc.stdout or "").strip().splitlines()[-3:]
            ok = proc.returncode == 0
            notes.append((
                "green", "HELD" if ok else "BREAK",
                "%s rc=%d: %s" % (battery, proc.returncode,
                                  " | ".join(tail))))
        except Exception as exc:  # noqa: BLE001
            notes.append(("green", "ERROR",
                          "%s: %s" % (battery, exc)))
    return notes


def main():
    print("w273 lane-B phase-2 battery: %d probes (TMPDIR=%s)"
          % (len(_PROBES), _TMP))
    failures = 0
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    for pid, expected, verdict, ok, note in _RESULTS:
        flag = "ok " if ok else "FAIL"
        if not ok:
            failures += 1
        print("[%s] %-44s expected=%-5s got=%-5s %s"
              % (flag, pid, expected, verdict, note))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in _green_checks():
        print("[%s] %s %s" % ("ok " if verdict in ("HELD", "SKIP") else "FAIL",
                              name, note))
        if verdict not in ("HELD", "SKIP"):
            failures += 1
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
