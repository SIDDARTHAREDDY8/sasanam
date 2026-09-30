"""Wave-248 install-time skill-update client probes (red-first).

W248-4: build ``gov/skill_update.py`` -- the install-time half of the
TUF-shaped skill distribution story. ``gov/bundle_refresh.py``
(wave-206) already verifies the metadata chain (root/timestamp/
snapshot/targets: signatures, rollback, expiry, thresholds) and serves
verified target pins. What is missing is the *install gate*: the
deployment fetches bundle bytes and must decide install/refuse against
(1) the skill record ``{name, version, digest, expires}``,
(2) the chain's pinned digest for that skill, and
(3) the locally installed version.

A skill that arrived outside the verified metadata chain is
indistinguishable from a plant and is refused at install. Installing on
a stale/suspended chain is refused fail-closed (the refresh path may
serve stale loudly; the install path does not).

Refusals (all taxonomy-coded, domain ``skill-update``):
- ``skill-update-index-untrusted``: no trusted chain pin (stale,
  suspended, or skill unbound from the chain).
- ``skill-update-metadata-expired``: the skill record is past expiry.
- ``skill-update-record-unpinned``: record digest != chain pin
  (mix-and-match / plant).
- ``skill-update-digest-mismatch``: bundle bytes != record digest.
- ``skill-update-version-rollback``: record version < installed.
- ``skill-update-malformed``: malformed record/pin/bundle input.

Red-first: on the pristine base (module absent) every probe reports
GAP. After the build, every probe must report HELD.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import hashlib
import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_SU = False
try:
    from gov import skill_update as _su
    HAVE_SU = all(
        hasattr(_su, n) for n in (
            "SkillUpdateClient", "SkillUpdateError",
            "EXPECTED_CODES"))
except ImportError:
    _su = None

HAVE_ALL = HAVE_SU

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

NOW = 1780000000
FUTURE = NOW + 86400
PAST = NOW - 86400


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _good_pin(digest, chain_state="trusted"):
    return {"digest": digest, "chain_state": chain_state}


def _good_record(name, version, digest, expires=FUTURE):
    return {"name": name, "version": version,
            "digest": digest, "expires": expires}


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(
            limit=3))


def _expect_code(fn, code):
    try:
        fn()
    except _su.SkillUpdateError as exc:
        assert exc.code == code, \
            "expected code %r, got %r (%s)" % (code, exc.code,
                                              exc.detail)
        return "refused with %s" % code
    raise AssertionError("expected refusal %r, install succeeded"
                         % (code,))


def p_rollback_refused():
    bundle = b"skill-bytes-v2"
    digest = _digest(bundle)
    client = _su.SkillUpdateClient(installed={"demo-skill": 2})
    record = _good_record("demo-skill", 1, digest)
    return _expect_code(
        lambda: client.install(bundle, record,
                               _good_pin(digest), NOW),
        "skill-update-version-rollback")


def p_stale_chain_refused():
    bundle = b"skill-bytes-v1"
    digest = _digest(bundle)
    client = _su.SkillUpdateClient()
    record = _good_record("demo-skill", 1, digest)
    return _expect_code(
        lambda: client.install(bundle, record,
                               _good_pin(digest, "stale"), NOW),
        "skill-update-index-untrusted")


def p_suspended_chain_refused():
    bundle = b"skill-bytes-v1"
    digest = _digest(bundle)
    client = _su.SkillUpdateClient()
    record = _good_record("demo-skill", 1, digest)
    return _expect_code(
        lambda: client.install(bundle, record,
                               _good_pin(digest, "suspended"),
                               NOW),
        "skill-update-index-untrusted")


def p_unbound_skill_refused():
    # The skill has no pin from the verified chain: it arrived
    # outside the metadata chain and is refused as a plant.
    bundle = b"skill-bytes-v1"
    digest = _digest(bundle)
    client = _su.SkillUpdateClient()
    record = _good_record("demo-skill", 1, digest)
    return _expect_code(
        lambda: client.install(bundle, record, None, NOW),
        "skill-update-index-untrusted")


def p_tampered_bundle_refused():
    good = b"skill-bytes-v1"
    digest = _digest(good)
    client = _su.SkillUpdateClient()
    record = _good_record("demo-skill", 1, digest)
    return _expect_code(
        lambda: client.install(b"tampered-bytes", record,
                               _good_pin(digest), NOW),
        "skill-update-digest-mismatch")


def p_mix_match_refused():
    # Bundle matches its record, but the record does not match the
    # chain pin: mix-and-match of a record from another version.
    bundle = b"skill-bytes-v2-other"
    record_digest = _digest(bundle)
    pinned_digest = _digest(b"skill-bytes-v2-pinned")
    assert record_digest != pinned_digest
    client = _su.SkillUpdateClient()
    record = _good_record("demo-skill", 2, record_digest)
    return _expect_code(
        lambda: client.install(bundle, record,
                               _good_pin(pinned_digest), NOW),
        "skill-update-record-unpinned")


def p_record_expired_refused():
    bundle = b"skill-bytes-v1"
    digest = _digest(bundle)
    client = _su.SkillUpdateClient()
    record = _good_record("demo-skill", 1, digest, expires=PAST)
    return _expect_code(
        lambda: client.install(bundle, record,
                               _good_pin(digest), NOW),
        "skill-update-metadata-expired")


def p_malformed_refused():
    bundle = b"skill-bytes-v1"
    digest = _digest(bundle)
    client = _su.SkillUpdateClient()
    record = {"name": "demo-skill", "version": 1}  # no digest
    return _expect_code(
        lambda: client.install(bundle, record,
                               _good_pin(digest), NOW),
        "skill-update-malformed")


def p_happy_path_allowed():
    bundle = b"skill-bytes-v1"
    digest = _digest(bundle)
    client = _su.SkillUpdateClient()
    record = _good_record("demo-skill", 1, digest)
    receipt = client.install(bundle, record, _good_pin(digest),
                             NOW)
    assert receipt["name"] == "demo-skill", receipt
    assert receipt["version"] == 1, receipt
    assert receipt["digest"] == digest, receipt
    assert client.installed_version("demo-skill") == 1
    return "installed v1, receipt carries name/version/digest"


def p_reinstall_same_version_allowed():
    # Idempotent reinstall of the identical bytes is not a rollback.
    bundle = b"skill-bytes-v2"
    digest = _digest(bundle)
    client = _su.SkillUpdateClient(installed={"demo-skill": 2})
    record = _good_record("demo-skill", 2, digest)
    receipt = client.install(bundle, record, _good_pin(digest),
                             NOW)
    assert receipt["version"] == 2, receipt
    return "same-version reinstall allowed (idempotent)"


def p_upgrade_allowed():
    bundle = b"skill-bytes-v3"
    digest = _digest(bundle)
    client = _su.SkillUpdateClient(installed={"demo-skill": 2})
    record = _good_record("demo-skill", 3, digest)
    receipt = client.install(bundle, record, _good_pin(digest),
                             NOW)
    assert client.installed_version("demo-skill") == 3
    return "v2 -> v3 upgrade allowed, installed state advanced"


def p_expected_codes_pinned():
    expected = {
        "skill-update-index-untrusted",
        "skill-update-metadata-expired",
        "skill-update-record-unpinned",
        "skill-update-digest-mismatch",
        "skill-update-version-rollback",
        "skill-update-malformed",
    }
    assert set(_su.EXPECTED_CODES) == expected, \
        "code set drift: %r" % (sorted(_su.EXPECTED_CODES),)
    return "6/6 codes pinned"


PROBES = [
    ("rollback-refused", p_rollback_refused),
    ("stale-chain-refused", p_stale_chain_refused),
    ("suspended-chain-refused", p_suspended_chain_refused),
    ("unbound-skill-refused", p_unbound_skill_refused),
    ("tampered-bundle-refused", p_tampered_bundle_refused),
    ("mix-match-refused", p_mix_match_refused),
    ("record-expired-refused", p_record_expired_refused),
    ("malformed-refused", p_malformed_refused),
    ("happy-path-allowed", p_happy_path_allowed),
    ("reinstall-same-version-allowed",
     p_reinstall_same_version_allowed),
    ("upgrade-allowed", p_upgrade_allowed),
    ("expected-codes-pinned", p_expected_codes_pinned),
]


def run_probes():
    results = []
    for name, fn in PROBES:
        results.append(_run_probe(name, fn, HAVE_ALL))
    return results


def _green_check():
    # Depth-1: adjacent unit suite only; honors GOV_SKIP_GREEN.
    import subprocess
    if GREEN_SKIP:
        return "SKIP (GOV_SKIP_GREEN=1)"
    repo = os.path.join(os.path.dirname(__file__), "..")
    tmpdir = os.environ.get("TMPDIR", "/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_skill_update", "-v"],
        cwd=repo, env=env, capture_output=True, text=True,
        timeout=300)
    tail = (proc.stderr or proc.stdout)[-400:]
    if proc.returncode != 0:
        raise AssertionError(
            "adjacent suite tests.test_skill_update failed: %s"
            % tail)
    return "adjacent suite green"


def main():
    results = run_probes()
    held = sum(1 for _, v, _ in results if v == "HELD")
    gap = sum(1 for _, v, _ in results if v == "GAP")
    brk = sum(1 for _, v, _ in results if v == "BREAK")
    err = sum(1 for _, v, _ in results if v == "ERROR")
    print("w248 skill-update probes: %d/%d HELD, %d GAP, %d BREAK, "
          "%d ERROR" % (held, len(results), gap, brk, err))
    for name, verdict, note in results:
        print("  [%s] %s: %s" % (verdict, name, note))
    try:
        gc = _green_check()
        print("green check: %s" % gc)
        green_ok = True
    except AssertionError as exc:
        print("green check FAILED: %s" % exc)
        green_ok = False
    rc = 0 if (brk == 0 and err == 0 and green_ok) else 1
    # Red phase: all GAP is the honest pre-build state.
    if gap == len(results):
        print("RED phase confirmed: capability absent.")
        rc = 0
    return rc


if __name__ == "__main__":
    sys.exit(main())
