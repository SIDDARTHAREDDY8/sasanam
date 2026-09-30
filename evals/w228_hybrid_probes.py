#!/usr/bin/env python3
"""Wave-228 lane A: hybrid family gate + verifier-pinned suite acceptance.

ADAPT (re-derived prose; nothing copied) of the hybrid-family-gate
pattern: a verifier-pinned policy declares which signature suites are
accepted; the FAMILY GATE requires every declared entry to present and
verify — no silent classical fallback, no token-selected suites.

Seams under test:
* gov/hybrid_gate.py — FamilyPolicy(policy_dict): digest-pinned by
  construction (admit() re-derives the pin; mutation refuses
  ``hybrid-policy-tampered``). FamilyGate(policy, key_registry).admit(
  suite_id, presented_entries, message, signatures):
  - suite_id not in the verifier policy refuses
    ``hybrid-suite-not-accepted`` (acceptance is pinned by verifier
    policy, never token-selected);
  - policy declares PQC entries but only classical entries are
    presented refuses ``hybrid-classical-fallback-refused`` (checked
    BEFORE generic completeness);
  - a declared entry with no presented material refuses
    ``hybrid-incomplete``;
  - per entry: registered-key resolution (key-identity-unknown /
    key-identity-revoked propagate); presented key_type must match the
    registered record (``hybrid-entry-mismatch``); MAC-tier entries
    refuse ``hybrid-leg-invalid`` (a family gate is signature-only);
    presented pubkey must digest-bind to the registered pubkey_digest
    (``hybrid-leg-invalid``); a failing signature refuses
    ``hybrid-leg-failed``;
  - entries whose registered record declares ``hybrid_of`` delegate
    to gov/key_identity.verify_hybrid (both legs required, never a
    single-leg fallback);
  - admission records are evidence, never authorization:
    deny_authority_use refuses ``hybrid-gate-not-authorization``.

Attack shapes: token-select an unpinned suite; drop the PQC leg and
present a valid classical-only set; omit one declared entry; present a
bad signature for one leg; claim a different key_type than registered;
mutate the pinned policy between construction and admit; use an
admission record as authority.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic, minimal, against pushed wave-227 HEAD
e42637b61e5c62c7289445e70c8e730ebfe8f4b3.

Verdicts: HELD / GAP / BREAK / RESIDUAL / ERROR. Any BREAK is a real
product defect. Pristine run (module absent) is expected GAP.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g228a
  TMPDIR=/var/tmp/g228a ~/workspace/.gov-venv/bin/python evals/w228_hybrid_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g228a-u \\
      ~/workspace/.gov-venv/bin/python evals/w228_hybrid_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import subprocess
import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import hybrid_gate as _hg
    from gov import key_identity as _ki
    from gov import alg_registry as _alg
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False

ED = "ed25519-rfc8032"

PROBE_NAMES = [
    "hg-01-hybrid-suite-admits",
    "hg-02-unknown-suite-refused",
    "hg-03-missing-entry-incomplete",
    "hg-04-failing-leg-refused",
    "hg-05-classical-fallback-refused",
    "hg-06-classical-suite-admits",
    "hg-07-policy-tamper-refused",
    "hg-08-keytype-claim-mismatch-refused",
    "hg-09-admission-record-digest-bound",
    "hg-10-admission-not-authority",
]


def _refuses(fn, code):
    """True if fn() raises an Exception whose .code == code."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None) == code
    return False


def _ed_keypair():
    reg = _alg.default_registry()
    seed, pub = reg.keygen(ED)
    return reg, seed, pub


def _kreg_with(legs):
    """Register (key_id, ED) leaf keys from [(key_id, pub), ...]."""
    kreg = _ki.KeyRegistry()
    for key_id, pub in legs:
        kreg.register(_ki.RegisteredKey.build(key_id, ED, "sha256", pub))
    return kreg


def _hybrid_world():
    """Full world: classical leaf c1, pqc leaves q1/q2, a registered
    hybrid key 'hyb' over (q1, q2), and three suites:
      hyb-suite      -> [{hyb, pqc}]        (hybrid-record entry)
      twoleaf-suite  -> [{c1, classical}, {q1, pqc}]
      classical-suite-> [{c1, classical}]
    Returns (gate, areg, keys dict, msg)."""
    areg, seed_c1, pub_c1 = _ed_keypair()
    seed_q1, pub_q1 = areg.keygen(ED)
    seed_q2, pub_q2 = areg.keygen(ED)
    kreg = _kreg_with([("c1", pub_c1), ("q1", pub_q1), ("q2", pub_q2)])
    kreg.register(_ki.RegisteredKey.build(
        "hyb", ED, "sha256", pub_q1, hybrid_of=("q1", "q2")))
    policy = _hg.FamilyPolicy({
        "v": 1,
        "accepted_suites": {
            "hyb-suite": {"declared_entries": [
                {"key_id": "hyb", "key_type": ED, "role": "pqc"}]},
            "twoleaf-suite": {"declared_entries": [
                {"key_id": "c1", "key_type": ED, "role": "classical"},
                {"key_id": "q1", "key_type": ED, "role": "pqc"}]},
            "classical-suite": {"declared_entries": [
                {"key_id": "c1", "key_type": ED, "role": "classical"}]},
        },
    })
    gate = _hg.FamilyGate(policy, kreg)
    keys = {"c1": (seed_c1, pub_c1), "q1": (seed_q1, pub_q1),
            "q2": (seed_q2, pub_q2)}
    return gate, areg, keys, b"hybrid family gate test message"


def _leaf_presented(key_id, areg, seed, pub, msg):
    return ([{"key_id": key_id, "key_type": ED}],
            {key_id: {"signature": areg.sign(ED, msg, seed),
                      "pubkey": pub}})


def _hyb_presented(areg, keys, msg, bad_leg=None):
    seed_q1, pub_q1 = keys["q1"]
    seed_q2, pub_q2 = keys["q2"]
    sig_a = b"\x00" * 64 if bad_leg == "a" else areg.sign(ED, msg, seed_q1)
    sig_b = b"\x00" * 64 if bad_leg == "b" else areg.sign(ED, msg, seed_q2)
    presented = [{"key_id": "hyb", "key_type": ED}]
    sigs = {"hyb": {"sig_a": sig_a, "pubkey_a": pub_q1,
                    "sig_b": sig_b, "pubkey_b": pub_q2}}
    return presented, sigs


def _run_once():
    results = []

    def rec(name, verdict, detail=""):
        results.append((name, verdict, detail))

    if not HAVE_MODULE:
        for name in PROBE_NAMES:
            rec(name, "GAP", "gov.hybrid_gate absent on this tree")
        return results

    # hg-01: a valid hybrid suite (hybrid-record entry, both legs
    # honestly signed) admits via the delegated verify_hybrid.
    try:
        gate, areg, keys, msg = _hybrid_world()
        presented, sigs = _hyb_presented(areg, keys, msg)
        rec0 = gate.admit("hyb-suite", presented, msg, sigs,
                          admitted_at=1700000000.0)
        ok = (isinstance(rec0, dict) and rec0.get("suite_id") == "hyb-suite"
              and rec0.get("policy_digest") == gate.policy.digest())
        rec("hg-01-hybrid-suite-admits", "HELD" if ok else "BREAK",
            "admit returned %r" % (type(rec0).__name__,))
    except Exception as exc:  # noqa: BLE001
        rec("hg-01-hybrid-suite-admits", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # hg-02: a suite id that is not verifier-pinned refuses
    # hybrid-suite-not-accepted — acceptance is never token-selected.
    try:
        gate, areg, keys, msg = _hybrid_world()
        presented, sigs = _hyb_presented(areg, keys, msg)
        held = _refuses(
            lambda: gate.admit("attacker-suite", presented, msg, sigs,
                               admitted_at=1700000000.0),
            "hybrid-suite-not-accepted")
        rec("hg-02-unknown-suite-refused", "HELD" if held else "BREAK",
            "unpinned suite refused" if held
            else "unpinned suite did not refuse hybrid-suite-not-accepted")
    except Exception as exc:  # noqa: BLE001
        rec("hg-02-unknown-suite-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # hg-03: twoleaf-suite with the classical entry missing (only the
    # pqc entry presented) refuses hybrid-incomplete — a declared entry
    # is missing. (hg-05 covers the reverse shape: pqc dropped while a
    # valid classical set is presented, which is the named downgrade.)
    try:
        gate, areg, keys, msg = _hybrid_world()
        seed_q1, pub_q1 = keys["q1"]
        presented, sigs = _leaf_presented("q1", areg, seed_q1, pub_q1, msg)
        held = _refuses(
            lambda: gate.admit("twoleaf-suite", presented, msg, sigs,
                               admitted_at=1700000000.0),
            "hybrid-incomplete")
        rec("hg-03-missing-entry-incomplete", "HELD" if held else "BREAK",
            "missing declared entry refused" if held
            else "missing declared entry did not refuse hybrid-incomplete")
    except Exception as exc:  # noqa: BLE001
        rec("hg-03-missing-entry-incomplete", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # hg-04: a hybrid suite with a bad PQC leg signature refuses
    # hybrid-leg-failed (the delegated verify_hybrid code).
    try:
        gate, areg, keys, msg = _hybrid_world()
        presented, sigs = _hyb_presented(areg, keys, msg, bad_leg="b")
        held = _refuses(
            lambda: gate.admit("hyb-suite", presented, msg, sigs,
                               admitted_at=1700000000.0),
            "hybrid-leg-failed")
        rec("hg-04-failing-leg-refused", "HELD" if held else "BREAK",
            "bad leg refused hybrid-leg-failed" if held
            else "bad leg did not refuse hybrid-leg-failed")
    except Exception as exc:  # noqa: BLE001
        rec("hg-04-failing-leg-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # hg-05: twoleaf-suite presented with ONLY the classical entry
    # refuses hybrid-classical-fallback-refused — dropping every PQC
    # leg while presenting a valid classical set is a named downgrade,
    # not generic incompleteness.
    try:
        gate, areg, keys, msg = _hybrid_world()
        seed_c1, pub_c1 = keys["c1"]
        presented, sigs = _leaf_presented("c1", areg, seed_c1, pub_c1, msg)
        held = _refuses(
            lambda: gate.admit("twoleaf-suite", presented, msg, sigs,
                               admitted_at=1700000000.0),
            "hybrid-classical-fallback-refused")
        rec("hg-05-classical-fallback-refused", "HELD" if held else "BREAK",
            "pqc-drop refused hybrid-classical-fallback-refused" if held
            else "pqc-drop did not refuse hybrid-classical-fallback-refused")
    except Exception as exc:  # noqa: BLE001
        rec("hg-05-classical-fallback-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # hg-06: a valid classical-only suite (no hybrid declared) admits.
    try:
        gate, areg, keys, msg = _hybrid_world()
        seed_c1, pub_c1 = keys["c1"]
        presented, sigs = _leaf_presented("c1", areg, seed_c1, pub_c1, msg)
        rec0 = gate.admit("classical-suite", presented, msg, sigs,
                          admitted_at=1700000000.0)
        ok = (isinstance(rec0, dict)
              and rec0.get("suite_id") == "classical-suite"
              and [e["key_id"] for e in rec0.get("admitted_entries", [])]
              == ["c1"])
        rec("hg-06-classical-suite-admits", "HELD" if ok else "BREAK",
            "classical-only suite admitted=%r" % (ok,))
    except Exception as exc:  # noqa: BLE001
        rec("hg-06-classical-suite-admits", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # hg-07: mutating the pinned policy between construction and admit
    # refuses hybrid-policy-tampered — the pin is re-derived at admit.
    try:
        gate, areg, keys, msg = _hybrid_world()
        seed_c1, pub_c1 = keys["c1"]
        presented, sigs = _leaf_presented("c1", areg, seed_c1, pub_c1, msg)
        # sanity: clean admit first
        gate.admit("classical-suite", presented, msg, sigs,
                   admitted_at=1700000000.0)
        # attacker mutates the shared policy object
        gate.policy._suites["classical-suite"]["declared_entries"].append(
            {"key_id": "evil", "key_type": ED, "role": "pqc"})
        held = _refuses(
            lambda: gate.admit("classical-suite", presented, msg, sigs,
                               admitted_at=1700000000.0),
            "hybrid-policy-tampered")
        rec("hg-07-policy-tamper-refused", "HELD" if held else "BREAK",
            "mutated policy refused" if held
            else "mutated policy did not refuse hybrid-policy-tampered")
    except Exception as exc:  # noqa: BLE001
        rec("hg-07-policy-tamper-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # hg-08: a presented entry claiming a different key_type than the
    # registered record refuses hybrid-entry-mismatch.
    try:
        gate, areg, keys, msg = _hybrid_world()
        seed_c1, pub_c1 = keys["c1"]
        presented = [{"key_id": "c1", "key_type": "hmac-sha256-mac"}]
        sigs = {"c1": {"signature": areg.sign(ED, msg, seed_c1),
                       "pubkey": pub_c1}}
        held = _refuses(
            lambda: gate.admit("classical-suite", presented, msg, sigs,
                               admitted_at=1700000000.0),
            "hybrid-entry-mismatch")
        rec("hg-08-keytype-claim-mismatch-refused",
            "HELD" if held else "BREAK",
            "key_type claim mismatch refused" if held
            else "key_type claim mismatch did not refuse "
                 "hybrid-entry-mismatch")
    except Exception as exc:  # noqa: BLE001
        rec("hg-08-keytype-claim-mismatch-refused", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # hg-09: the admission record is digest-bound — message_digest and
    # policy_digest recompute independently.
    try:
        gate, areg, keys, msg = _hybrid_world()
        seed_c1, pub_c1 = keys["c1"]
        presented, sigs = _leaf_presented("c1", areg, seed_c1, pub_c1, msg)
        rec0 = gate.admit("classical-suite", presented, msg, sigs,
                          admitted_at=1700000000.0)
        ok = (rec0.get("message_digest") == hashlib.sha256(msg).hexdigest()
              and rec0.get("policy_digest") == gate.policy.digest()
              and rec0.get("admitted_at") == 1700000000.0)
        rec("hg-09-admission-record-digest-bound",
            "HELD" if ok else "BREAK",
            "record digests recompute=%r" % (ok,))
    except Exception as exc:  # noqa: BLE001
        rec("hg-09-admission-record-digest-bound", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    # hg-10: an admission record is evidence, never authority.
    try:
        gate, areg, keys, msg = _hybrid_world()
        seed_c1, pub_c1 = keys["c1"]
        presented, sigs = _leaf_presented("c1", areg, seed_c1, pub_c1, msg)
        rec0 = gate.admit("classical-suite", presented, msg, sigs,
                          admitted_at=1700000000.0)
        held = _refuses(lambda: gate.deny_authority_use(rec0),
                        "hybrid-gate-not-authorization")
        rec("hg-10-admission-not-authority", "HELD" if held else "BREAK",
            "authority-shaped use refused" if held
            else "authority-shaped use did not refuse "
                 "hybrid-gate-not-authorization")
    except Exception as exc:  # noqa: BLE001
        rec("hg-10-admission-not-authority", "ERROR",
            "%r %s" % (exc, traceback.format_exc(limit=2)))

    return results


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    for unit in ("tests/test_key_identity.py",
                 "tests/test_kms_signer.py",
                 "tests/test_alg_registry.py"):
        path = os.path.join(REPO, unit)
        if not os.path.exists(path):
            notes.append((unit, "SKIP", "unit test not present"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", unit.replace("/", ".")[:-3]],
            env=env, cwd=REPO,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=600)
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode == 0:
            notes.append((unit, "PASS", "adjacent unit suite green"))
        else:
            tail = out[-400:] if out else "no output"
            notes.append((unit, "FAIL", tail))
    return notes


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    print("w228 hybrid-gate probes: %d HELD / %d GAP / %d BREAK / %d ERROR "
          "of %d; determinism %s"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in first:
        print("  [%s] %s %s" % (verdict, name, detail))
    for name, status, detail in green:
        print("  [%s] %s %s" % (status, name, detail))
    bad = [n for n, v, _d in first if v in ("BREAK", "ERROR")]
    sys.exit(1 if bad or not det_ok else 0)


if __name__ == "__main__":
    main()
