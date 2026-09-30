"""Wave-246 flaw-granular advisory-state probes (W246-6, red-first).

The PyJWT lesson (verified 2026-09-30): PyJWT 2.14.0 fixed
GHSA-9v7f-9g4p-ffgj (CVE-2026-102267) but is still affected by
CVE-2026-101918. "Version 2.14.0 is clean" is therefore FALSE; the
honest answer is ``affected-by: CVE-2026-101918`` -- and, explicitly,
``clean-for: CVE-2026-102267``. A version-level "clean" verdict hides
residual flaws.

New primitive (gov/advisory_state), wired to the wave-244
gov/advisory_binding vocabulary (bind_advisory_input pins the
snapshot: digest, signature threshold, supersession, freshness):

  pyjwt-2.14.0-affected-by-open-cve -- PyJWT 2.14.0 against an
      advisory tracking CVE-2026-102267 (fixed in 2.14.0) and
      CVE-2026-101918 (still open, affected <=2.14.0) answers
      affected-by [CVE-2026-101918] AND clean_for [CVE-2026-102267].
      Never a bare clean.
  pyjwt-2.13.0-affected-by-both -- 2.13.0 is inside both affected
      ranges and below the 2.14.0 fix: affected-by both CVEs.
  fixed-version-boundary -- a version exactly at fixed_in is clean
      for that flaw (not affected).
  version-clean-for-all-tracked -- a version above every published
      fix answers clean-for with the EXPLICIT CVE list, never bare
      "clean".
  no-bare-clean-expressible -- the module exposes no bare-clean
      verdict: no "clean" state constant, no function returning one.
  untracked-component-unknown -- a component with no flaw entries
      answers explicit unknown (fail-closed), never a silent pass.
  untracked-version-unknown -- a version outside all tracked ranges
      with no fix knowledge answers unknown, not clean-for.
  unparseable-version-unknown -- a version string the advisory
      cannot evaluate answers unknown (fail-closed), never an
      exception the caller could swallow into a pass.
  malformed-advisory-refused -- caller-supplied advisory data with
      a bad flaw shape refuses advisory-input-malformed, never
      silent.
  stale-advisory-refused -- a pinned snapshot older than its
      freshness bound refuses chain-source-stale (reused code).

Stdlib only (+ in-repo gov.ed25519 for the real bind wire).
Deterministic: no network, no in-repo git subprocesses.
"""

import base64
import hashlib
import json
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_STATE = False
try:
    from gov import advisory_state as _st
    from gov import advisory_binding as _ab
    from gov import ed25519 as _e
    HAVE_STATE = all(hasattr(_st, n) for n in (
        "assess_component", "bind_flaw_snapshot",
        "AdvisoryStateError", "ADVISORY_INPUT_MALFORMED"))
except ImportError:
    _st = None
    _ab = None
    _e = None


def _run_probe(name, fn, have, pin=False):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, ("PIN" if pin else "HELD"), note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    try:
        fn()
    except _st.AdvisoryStateError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


# ---------------------------------------------------------------------------
# Fixture: a real pinned flaw advisory via the advisory_binding wire
# ---------------------------------------------------------------------------

_T_FETCH = 1727731200
_T_NOW = _T_FETCH + 1800
_T_STALE = _T_FETCH + 7200

_SEEDS = [bytes([0xB0 + i]) * 32 for i in range(2)]
_PUBS = None  # built lazily (needs gov.ed25519)


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _pubs():
    global _PUBS
    if _PUBS is None:
        _PUBS = [_e.publickey(s) for s in _SEEDS]
    return _PUBS


def _flaws():
    # The PyJWT case: CVE-2026-102267 fixed in 2.14.0 (GHSA-9v7f-9g4p-ffgj),
    # CVE-2026-101918 still open (affected <=2.14.0, no fix published).
    return [
        {"cve": "CVE-2026-102267", "component": "pyjwt",
         "affected": "<2.14.0", "fixed_in": "2.14.0"},
        {"cve": "CVE-2026-101918", "component": "pyjwt",
         "affected": "<=2.14.0", "fixed_in": None},
    ]


def _bind(flaws=None, fetched_at=_T_FETCH, n_sigs=2):
    pubs = _pubs()
    policy = {
        "advisory_policy_input": "advisory-policy-v1",
        "freshness_seconds": 3600,
        "signature_threshold": 2,
        "trusted_keys": [_b64(p) for p in pubs],
    }
    flaws = _flaws() if flaws is None else flaws
    body = {"advisory_id": "pyjwt-flaw-advisory", "version": 3,
            "issuer": "test-issuer", "fetched_at": fetched_at,
            "flags": {}, "flaws": flaws}
    canon = _canon(body)
    sigs = [{"key": _b64(pubs[i]),
             "sig": _b64(_e.sign(_SEEDS[i], canon))}
            for i in range(n_sigs)]
    snapshot = dict(body)
    snapshot.update({"canonical_bytes": canon,
                     "digest": hashlib.sha256(canon).hexdigest(),
                     "signatures": sigs})
    return _st.bind_flaw_snapshot(policy, snapshot, _T_NOW)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _probe_pyjwt_2140_affected():
    pinned = _bind()
    ans = _st.assess_component(pinned, "pyjwt", "2.14.0", _T_NOW)
    assert ans["state"] == "affected-by", "state %r" % (ans.get("state"),)
    assert ans["cves"] == ["CVE-2026-101918"], "cves %r" % (ans.get("cves"),)
    assert ans["clean_for"] == ["CVE-2026-102267"], \
        "clean_for %r" % (ans.get("clean_for"),)
    assert ans["state"] != "clean", "bare clean expressed"
    return "2.14.0 -> affected-by CVE-2026-101918, clean-for CVE-2026-102267"


def _probe_pyjwt_2130_both():
    pinned = _bind()
    ans = _st.assess_component(pinned, "pyjwt", "2.13.0", _T_NOW)
    assert ans["state"] == "affected-by", "state %r" % (ans.get("state"),)
    assert ans["cves"] == ["CVE-2026-102267", "CVE-2026-101918"], \
        "cves %r" % (ans.get("cves"),)
    return "2.13.0 -> affected-by both CVEs"


def _probe_fixed_boundary():
    pinned = _bind()
    ans = _st.assess_component(pinned, "pyjwt", "2.14.0", _T_NOW)
    # 2.14.0 is exactly fixed_in for CVE-2026-102267: clean for it,
    # but still affected by the open CVE-2026-101918.
    assert "CVE-2026-102267" not in ans["cves"], \
        "fixed version reported affected"
    assert "CVE-2026-102267" in ans["clean_for"], \
        "fixed version not listed clean-for"
    return "fixed_in boundary is clean for that flaw"


def _probe_clean_for_all():
    flaws = [
        {"cve": "CVE-2026-102267", "component": "pyjwt",
         "affected": "<2.14.0", "fixed_in": "2.14.0"},
        {"cve": "CVE-2026-111111", "component": "pyjwt",
         "affected": "<2.10.0", "fixed_in": "2.10.0"},
    ]
    pinned = _bind(flaws=flaws)
    ans = _st.assess_component(pinned, "pyjwt", "2.15.0", _T_NOW)
    assert ans["state"] == "clean-for", "state %r" % (ans.get("state"),)
    assert ans["cves"] == ["CVE-2026-102267", "CVE-2026-111111"], \
        "cves %r (must be the explicit list, never bare clean)" \
        % (ans.get("cves"),)
    assert ans["state"] != "clean", "bare clean expressed"
    return "2.15.0 -> clean-for [CVE-2026-102267, CVE-2026-111111]"


def _probe_no_bare_clean():
    # The module must not be able to express a bare "clean".
    for name in dir(_st):
        if name.startswith("_"):
            continue
        val = getattr(_st, name)
        if isinstance(val, str) and val == "clean":
            raise AssertionError("bare-clean constant %r" % (name,))
    assert not hasattr(_st, "STATE_CLEAN"), "STATE_CLEAN exists"
    assert getattr(_st, "_STATE_CLEAN", None) != "clean", \
        "internal bare-clean state"
    return "no bare-clean verdict expressible"


def _probe_untracked_component():
    pinned = _bind()
    ans = _st.assess_component(pinned, "not-a-real-package", "1.0.0",
                               _T_NOW)
    assert ans["state"] == "unknown", "state %r" % (ans.get("state"),)
    assert ans["reason"] == "component-not-tracked", \
        "reason %r" % (ans.get("reason"),)
    return "untracked component -> explicit unknown (fail-closed)"


def _probe_untracked_version():
    # 9.9.9 is outside every tracked range and above the known fixes
    # for the OPEN flaw (no fix published): no affirmative clean.
    pinned = _bind()
    ans = _st.assess_component(pinned, "pyjwt", "9.9.9", _T_NOW)
    assert ans["state"] == "unknown", "state %r" % (ans.get("state"),)
    assert ans["reason"] == "version-not-covered", \
        "reason %r" % (ans.get("reason"),)
    return "9.9.9 -> unknown, not clean-for (no fix knowledge)"


def _probe_unparseable_version():
    pinned = _bind()
    ans = _st.assess_component(pinned, "pyjwt", "not-a-version", _T_NOW)
    assert ans["state"] == "unknown", "state %r" % (ans.get("state"),)
    assert ans["reason"] == "version-not-evaluable", \
        "reason %r" % (ans.get("reason"),)
    return "unparseable version -> unknown (fail-closed, no swallow)"


def _probe_malformed_advisory():
    bad = [
        {"cve": "not-a-cve", "component": "pyjwt",
         "affected": "<2.14.0", "fixed_in": "2.14.0"},
        {"cve": "CVE-2026-102267", "component": "pyjwt",
         "affected": "bogus-spec", "fixed_in": "2.14.0"},
        {"cve": "CVE-2026-102267", "component": "pyjwt",
         "affected": "<2.14.0", "fixed_in": "tomorrow"},
        {"component": "pyjwt", "affected": "<2.14.0"},
    ]
    for i, flaws in enumerate([bad[0:1], bad[1:2], bad[2:3], bad[3:4]]):
        pubs = _pubs()
        policy = {
            "advisory_policy_input": "advisory-policy-v1",
            "freshness_seconds": 3600,
            "signature_threshold": 2,
            "trusted_keys": [_b64(p) for p in pubs],
        }
        body = {"advisory_id": "bad", "version": 1, "issuer": "t",
                "fetched_at": _T_FETCH, "flags": {}, "flaws": flaws}
        canon = _canon(body)
        sigs = [{"key": _b64(pubs[j]),
                 "sig": _b64(_e.sign(_SEEDS[j], canon))}
                for j in range(2)]
        snapshot = dict(body)
        snapshot.update({"canonical_bytes": canon,
                         "digest": hashlib.sha256(canon).hexdigest(),
                         "signatures": sigs})
        _expect_refusal(
            lambda s=snapshot, p=policy: _st.bind_flaw_snapshot(
                p, s, _T_NOW),
            "advisory-input-malformed")
    return "4 malformed flaw shapes -> advisory-input-malformed"


def _probe_stale_advisory():
    pinned = _bind(fetched_at=_T_FETCH)
    try:
        _st.assess_component(pinned, "pyjwt", "2.14.0", _T_STALE)
    except _st.AdvisoryStateError as exc:
        assert exc.code == "chain-source-stale", \
            "code %r" % (exc.code,)
        return "refused chain-source-stale"
    raise AssertionError("stale advisory assessed without refusal")


_PROBES = [
    ("pyjwt-2.14.0-affected-by-open-cve", _probe_pyjwt_2140_affected,
     "HAVE_STATE", False),
    ("pyjwt-2.13.0-affected-by-both", _probe_pyjwt_2130_both,
     "HAVE_STATE", False),
    ("fixed-version-boundary", _probe_fixed_boundary,
     "HAVE_STATE", False),
    ("version-clean-for-all-tracked", _probe_clean_for_all,
     "HAVE_STATE", False),
    ("no-bare-clean-expressible", _probe_no_bare_clean,
     "HAVE_STATE", False),
    ("untracked-component-unknown", _probe_untracked_component,
     "HAVE_STATE", False),
    ("untracked-version-unknown", _probe_untracked_version,
     "HAVE_STATE", False),
    ("unparseable-version-unknown", _probe_unparseable_version,
     "HAVE_STATE", False),
    ("malformed-advisory-refused", _probe_malformed_advisory,
     "HAVE_STATE", False),
    ("stale-advisory-refused", _probe_stale_advisory,
     "HAVE_STATE", False),
]


def main():
    # This battery spawns no nested green-check subprocesses, so the
    # probes must always run -- a GOV_SKIP_GREEN early return would make
    # the battery a vacuous pass depth-1 (wave-244 merge lesson).
    flags = {"HAVE_STATE": HAVE_STATE}
    results = []
    for name, fn, flag, pin in _PROBES:
        results.append(_run_probe(name, fn, flags[flag], pin=pin))
    held = sum(1 for _, s, _ in results if s in ("HELD", "PIN"))
    total = len(results)
    for name, status, note in results:
        print("%-42s %-6s %s" % (name, status, note.split("\n")[0]))
    print("w246_advisory_state: %d/%d HELD-or-PIN" % (held, total))
    return 0 if held == total else 2


if __name__ == "__main__":
    sys.exit(main())
