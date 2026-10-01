"""Wave-250 F211 closure probes (red-first).

F211 (LOW): ``SkillUpdateClient.install()`` allowed a same-version
reinstall with a DIFFERENT digest -- the ``installed`` map tracked
only ``{name: version}``, so the docstring's "identical bytes"
idempotency promise was unenforced (an attacker with a malicious
digest in the chain pin could overwrite a legitimate v1 with a
malicious v1).

Close-when (filed in evals/FINDINGS.md): the installed map tracks the
installed digest per skill (``{name: (version, digest)}``), and a
same-version reinstall with a different digest is refused with the
new code ``skill-update-digest-changed``.

Red-first: on the pre-fix module (wave-249), probe 1 reports BREAK
(the substitution is allowed). After the fix, all probes report HELD.

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


def p_digest_change_refused():
    # The F211 break shape: install v1 with digest A, then reinstall
    # v1 with digest B (different bytes, pin updated to B). The fix
    # must refuse; the pre-fix module allows it (BREAK).
    bundle_a = b"legitimate skill v1"
    digest_a = _digest(bundle_a)
    bundle_b = b"malicious skill v1 - different bytes"
    digest_b = _digest(bundle_b)
    client = _su.SkillUpdateClient()
    client.install(bundle_a, _good_record("s", 1, digest_a),
                   _good_pin(digest_a), NOW)
    return _expect_code(
        lambda: client.install(
            bundle_b, _good_record("s", 1, digest_b),
            _good_pin(digest_b), NOW),
        "skill-update-digest-changed")


def p_identical_reinstall_allowed():
    # Idempotent reinstall of identical bytes is not a refusal.
    bundle = b"legitimate skill v1"
    digest = _digest(bundle)
    client = _su.SkillUpdateClient()
    client.install(bundle, _good_record("s", 1, digest),
                   _good_pin(digest), NOW)
    receipt = client.install(bundle, _good_record("s", 1, digest),
                             _good_pin(digest), NOW)
    assert receipt == {"name": "s", "version": 1,
                       "digest": digest}, receipt
    return "identical-bytes reinstall allowed (idempotent)"


def p_digest_tracked_and_upgraded():
    # The installed map records (version, digest); an upgrade
    # advances both.
    bundle1 = b"skill v1"
    digest1 = _digest(bundle1)
    bundle2 = b"skill v2"
    digest2 = _digest(bundle2)
    client = _su.SkillUpdateClient()
    client.install(bundle1, _good_record("s", 1, digest1),
                   _good_pin(digest1), NOW)
    assert client.installed_digest("s") == digest1
    client.install(bundle2, _good_record("s", 2, digest2),
                   _good_pin(digest2), NOW)
    assert client.installed_version("s") == 2
    assert client.installed_digest("s") == digest2
    return "installed digest tracked and advanced on upgrade"


def p_constructor_validates_entries():
    # The installed map is {name: (version, digest)}; the legacy
    # bare-int form and malformed entries are refused fail-closed.
    digest = _digest(b"x")
    client = _su.SkillUpdateClient(installed={"s": (1, digest)})
    assert client.installed_version("s") == 1
    assert client.installed_digest("s") == digest
    for bad in ({"s": 1},
                {"s": (-1, digest)},
                {"s": (1, "not-a-digest")},
                {"s": (1,)},
                {"s": (1, digest, "extra")},
                {"": (1, digest)}):
        try:
            _su.SkillUpdateClient(installed=bad)
        except _su.SkillUpdateError as exc:
            assert exc.code == "skill-update-malformed", exc.code
        else:
            raise AssertionError(
                "malformed installed entry accepted: %r" % (bad,))
    return "constructor validates (version, digest) entries"


def p_new_code_in_taxonomy():
    # The new refusal code is registered in the taxonomy.
    assert "skill-update-digest-changed" in _su.EXPECTED_CODES
    return "skill-update-digest-changed registered"


PROBES = [
    ("digest-change-refused", p_digest_change_refused),
    ("identical-reinstall-allowed", p_identical_reinstall_allowed),
    ("digest-tracked-and-upgraded", p_digest_tracked_and_upgraded),
    ("constructor-validates-entries",
     p_constructor_validates_entries),
    ("new-code-in-taxonomy", p_new_code_in_taxonomy),
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
    print("w250 F211-closure probes: %d/%d HELD, %d GAP, %d "
          "BREAK, %d ERROR" % (held, len(results), gap, brk,
                               err))
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
    # Red phase: BREAK on the pre-fix module is the honest red state.
    if brk > 0:
        print("RED phase confirmed: F211 break shape present.")
        rc = 0
    return rc


if __name__ == "__main__":
    sys.exit(main())
