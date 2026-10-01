"""Wave-252 closure probes: F212 + F213 break-first.

W252-1: closure of F212 (DecisionLog trusts caller-held
CombinedDecision mutability) and F213 (EquivocationProof.verify()
raises IndexError on bogus index).

Discipline (tdd skill): red before green. Each probe is a falsifiable
break attempt. A probe returns HELD when the attack is refused (or
the honest path holds); BREAK when the attack succeeds. On the
pristine wave-251 base the five attack probes BREAK (F212 hide,
F212 fabricate, F212 policy-key mutation, F213 bogus index, F213 bad
index); after the fix all probes are HELD.

F212 close-when: snapshot (request_digest, effect, policy_key) at
append; detect_equivocation reads snapshots only.
F213 close-when: bounds-check in EquivocationProof.verify() ->
return False, never raise.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import re
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_ALL = False
try:
    from gov import decision_log as _dl
    from gov import policy_combine as _pc
    from gov.policy import PolicyDecision as _PD
    HAVE_ALL = all(hasattr(_dl, n) for n in (
        "DecisionLog", "DecisionLogError", "EquivocationProof",
        "detect_equivocation", "MerkleTree"))
except ImportError:
    _dl = _pc = _PD = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


# ------------------------------------------------- helpers


def _mkpd(effect, pid="pol-a", rev="policy:1", digest=None):
    digest = digest or ("a" * 64)
    return _PD(effect=effect, reason="r:" + effect, policy_id=pid,
               policy_rev_id=rev, policy_digest=digest)


def _mkcd(effect, decisions):
    return _pc.CombinedDecision(
        effect, "reason:" + effect, None, (), (), ("pol-a",), decisions)


def _mktmp():
    base = "/var/tmp/w252-f212f213"
    os.makedirs(base, exist_ok=True)
    return tempfile.mkdtemp(prefix="probe-", dir=base)


def _verify_no_raise(log, proof):
    """verify() must return a bool, never raise, on any proof."""
    try:
        return proof.verify(log)
    except (IndexError, TypeError) as exc:
        raise AssertionError(
            "verify() raised %r instead of returning False" % (exc,))


# ------------------------------------------------- F212: hide


def probe_f212_hide():
    # Post-append mutation of CombinedDecision.effect must not hide a
    # genuine equivocation from detect_equivocation.
    log = _dl.DecisionLog()
    req = b"h" * 32
    d_allow = _mkcd("allow", [_mkpd("allow")])
    d_deny = _mkcd("deny", [_mkpd("deny")])
    log.append(d_allow, req)
    log.append(d_deny, req)
    assert len(_dl.detect_equivocation(log)) == 1, "control failed"
    d_allow.effect = "deny"  # post-append mutation (the F212 break)
    found = _dl.detect_equivocation(log)
    if len(found) == 0:
        raise AssertionError(
            "F212 OPEN: post-append mutation HID the equivocation; "
            "detect_equivocation reads the live object, not a snapshot")
    assert found[0].verify(log) is True, "snapshot proof must verify"
    assert {found[0].effect_a, found[0].effect_b} == {"allow", "deny"}
    return "mutation did not hide equivocation (snapshot)"


# ------------------------------------------------- F212: fabricate


def probe_f212_fabricate():
    # Post-append mutation must not fabricate equivocation evidence.
    log = _dl.DecisionLog()
    req = b"f" * 32
    d1 = _mkcd("allow", [_mkpd("allow")])
    d2 = _mkcd("allow", [_mkpd("allow")])
    log.append(d1, req)
    log.append(d2, req)
    assert _dl.detect_equivocation(log) == [], "control failed"
    d2.effect = "deny"  # post-append mutation (the F212 break)
    found = _dl.detect_equivocation(log)
    if len(found) != 0:
        raise AssertionError(
            "F212 OPEN: post-append mutation FABRICATED equivocation "
            "evidence (proof verifies while the leaf bytes still "
            "commit to allow/allow)")
    return "mutation did not fabricate equivocation (snapshot)"


# ------------------------------------------------- F212: policy-key mutation


def probe_f212_policy_key_mutation():
    # The policy-revision grouping key must also be snapshotted: a
    # post-append mutation of a decision's policy identity must not
    # move the leaf into a different equivocation group.
    log = _dl.DecisionLog()
    req = b"k" * 32
    dec_a = _mkpd("allow", pid="pol-a")
    dec_b = _mkpd("deny", pid="pol-a")
    log.append(_mkcd("allow", [dec_a]), req)
    log.append(_mkcd("deny", [dec_b]), req)
    assert len(_dl.detect_equivocation(log)) == 1, "control failed"
    dec_a.policy_id = "pol-other"  # post-append identity mutation
    found = _dl.detect_equivocation(log)
    if len(found) == 0:
        raise AssertionError(
            "F212 OPEN: post-append policy-identity mutation split the "
            "equivocation group; the policy key is read live")
    assert found[0].verify(log) is True, "snapshot proof must verify"
    return "policy-identity mutation did not split the group (snapshot)"


# ------------------------------------------------- F213: bogus index


def probe_f213_bogus_index():
    # A hand-crafted EquivocationProof with an out-of-range leaf index
    # must make verify() return False, never raise.
    log = _dl.DecisionLog()
    req = b"b" * 32
    log.append(_mkcd("allow", [_mkpd("allow")]), req)
    p = _dl.EquivocationProof(req, (), 0, "allow", [], 999, "deny", [],
                              log.tree_size(), log.root())
    result = _verify_no_raise(log, p)
    assert result is False, "bogus index should verify False"
    return "bogus index returns False"


def probe_f213_bad_index():
    # Negative and non-integer indices likewise return False.
    log = _dl.DecisionLog()
    req = b"n" * 32
    log.append(_mkcd("allow", [_mkpd("allow")]), req)
    for bad in (-1, "0", None):
        p = _dl.EquivocationProof(req, (), 0, "allow", [], bad, "deny",
                                  [], log.tree_size(), log.root())
        result = _verify_no_raise(log, p)
        assert result is False, "index %r should verify False" % (bad,)
    return "negative/non-integer indices return False"


# ------------------------------------------------- honest-path controls


def probe_control_genuine_equivocation():
    log = _dl.DecisionLog()
    req = b"q" * 32
    log.append(_mkcd("allow", [_mkpd("allow")]), req)
    log.append(_mkcd("deny", [_mkpd("deny")]), req)
    found = _dl.detect_equivocation(log)
    assert len(found) == 1, "expected 1 equivocation, got %d" % len(found)
    assert found[0].verify(log) is True, "proof does not verify"
    assert {found[0].effect_a, found[0].effect_b} == {"allow", "deny"}
    return "genuine equivocation detected, proof verifies"


def probe_control_no_false_positive():
    log = _dl.DecisionLog()
    req = b"z" * 32
    log.append(_mkcd("allow", [_mkpd("allow")]), req)
    log.append(_mkcd("allow", [_mkpd("allow")]), req)
    assert _dl.detect_equivocation(log) == [], "false equivocation"
    return "identical effects are not equivocation"


# ------------------------------------------------- green checks (depth-1)


def _green():
    """Depth-1: run the adjacent decision-log batteries with
    GOV_SKIP_GREEN=1 and require zero BREAK/ERROR. Honors
    GOV_SKIP_GREEN itself (records skip, never spawns)."""
    import subprocess
    if GREEN_SKIP:
        return ["green checks skipped (GOV_SKIP_GREEN=1)"]
    here = os.path.dirname(os.path.abspath(__file__))
    batteries = [
        "w250_decision_log_probes.py",
        "w251_redteam_probes.py",
    ]
    notes = []
    for bat in batteries:
        path = os.path.join(here, bat)
        if not os.path.exists(path):
            notes.append("%s: missing, skipped" % bat)
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        tmpd = _mktmp()
        env["TMPDIR"] = tmpd
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600, cwd=os.path.join(here, ".."))
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("%s green check failed: %r" % (bat, exc))
        out = (proc.stdout or "") + (proc.stderr or "")
        # Belt-and-braces: exit code is the primary signal (every
        # battery exits non-zero unless fully HELD); the token scan
        # catches a non-HELD verdict even if a battery mis-reports
        # its exit status. The lookbehind keeps "0 BREAK" in a
        # summary line from scoring a hit.
        bad = [ln for ln in out.splitlines()
               if re.search(r"(?:^|(?<![0-9])\s)\[?(BREAK|ERROR|GAP)\]?"
                            r"(?=\s|:|$)", ln)]
        if bad or proc.returncode != 0:
            raise AssertionError(
                "%s green check not green (rc=%d, bad=%d):\n%s"
                % (bat, proc.returncode, len(bad), out[-2000:]))
        notes.append("%s: green" % bat)
    return notes


# ------------------------------------------------- main


PROBES = [
    ("f212/hide-refused", probe_f212_hide, HAVE_ALL),
    ("f212/fabricate-refused", probe_f212_fabricate, HAVE_ALL),
    ("f212/policy-key-mutation-refused", probe_f212_policy_key_mutation,
     HAVE_ALL),
    ("f213/bogus-index-returns-false", probe_f213_bogus_index, HAVE_ALL),
    ("f213/bad-index-returns-false", probe_f213_bad_index, HAVE_ALL),
    ("control/genuine-equivocation", probe_control_genuine_equivocation,
     HAVE_ALL),
    ("control/no-false-positive", probe_control_no_false_positive,
     HAVE_ALL),
]


def main():
    results = []
    for name, fn, have in PROBES:
        results.append(_run_probe(name, fn, have))
    held = sum(1 for _n, v, _x in results if v == "HELD")
    brk = sum(1 for _n, v, _x in results if v == "BREAK")
    gap = sum(1 for _n, v, _x in results if v == "GAP")
    err = sum(1 for _n, v, _x in results if v == "ERROR")
    print("w252 f212/f213 closure: %d/%d HELD, %d BREAK, %d GAP, %d ERROR"
          % (held, len(results), brk, gap, err))
    for name, verdict, note in results:
        first = note.splitlines()[0] if note else ""
        print("  [%s] %s: %s" % (verdict, name, first[:160]))
    try:
        for note in _green():
            print("  green: %s" % note)
    except AssertionError as exc:
        print("  GREEN-CHECK FAILED: %s" % (exc,))
        return 2
    if brk or err or gap:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
