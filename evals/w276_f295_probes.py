"""Wave-276 F295 closure battery: attestor selector matching must be
type-strict (bool != int).

F295 (LOW): `AttestedRegistry.match` tested selector subset with
`facts.get(k) == v`; Python's `True == 1` made selector {"debug": 1}
match fact {"debug": True}. Close-when: (1) selector matching is
type-strict; (2) at01 flips to HELD, at01b stays HELD; (3) existing
attestor battery stays green.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic; fresh /var/tmp/g276-f295
TMPDIR (`mkdir -p` first); depth-1 green checks honoring
GOV_SKIP_GREEN=1; no in-repo git subprocesses; stdlib only.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TMP = tempfile.mkdtemp(prefix="g276-f295-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import gov.attestors as at  # noqa: E402
import gov.ed25519 as _ed  # noqa: E402

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    _RESULTS.append((pid, expected, verdict, verdict == expected, note))


def _registry_with_selector(selector, entry_id="e1"):
    """Ceremony-backed registry holding one entry with `selector`."""
    cseed = bytes([0xC0]) * 32
    cpub = _ed.publickey(cseed)
    kid = hashlib.sha256(cpub).hexdigest()[:16]
    reg = at.AttestedRegistry(ceremony_keys={kid: cpub})
    entry = {"entry_id": entry_id, "attestor_id": "static-test",
             "selector": dict(selector), "producer_sub": "alice",
             "scopes": ["mint"]}
    body = {k: v for k, v in entry.items() if k != "ceremony"}
    canon = json.dumps(body, sort_keys=True,
                       separators=(",", ":")).encode("utf-8")
    sig = base64.b64encode(_ed.sign(cseed, canon)).decode("ascii")
    reg.register_entry(entry, ceremony={"signer": kid, "signature": sig})
    return reg


def _matched(reg, facts):
    """True iff some entry matches `facts` (no raise)."""
    try:
        reg.match(dict(facts), attestor_id="static-test")
    except Exception:  # noqa: BLE001
        return False
    return True


def p01_int_selector_bool_fact():
    """F295 break: {"debug": 1} must NOT match {"debug": True}."""
    reg = _registry_with_selector({"debug": 1})
    if _matched(reg, {"debug": True}):
        return "BREAK", "int selector matched bool fact (conflation)"
    return "HELD", "int selector did not match bool fact"


def p02_bool_selector_int_fact():
    """Reverse direction: {"debug": True} must NOT match {"debug": 1}."""
    reg = _registry_with_selector({"debug": True})
    if _matched(reg, {"debug": 1}):
        return "BREAK", "bool selector matched int fact (conflation)"
    return "HELD", "bool selector did not match int fact"


def p03_false_vs_zero():
    """{"flag": 0} must NOT match {"flag": False}."""
    reg = _registry_with_selector({"flag": 0})
    if _matched(reg, {"flag": False}):
        return "BREAK", "int 0 selector matched False fact (conflation)"
    return "HELD", "int 0 selector did not match False fact"


def p04_exact_int_still_matches():
    """Control: {"debug": 1} still matches {"debug": 1}."""
    reg = _registry_with_selector({"debug": 1})
    if _matched(reg, {"debug": 1}):
        return "HELD", "exact int match works"
    return "BREAK", "exact int match stopped working (regression)"


def p05_exact_bool_still_matches():
    """Control: {"debug": True} still matches {"debug": True}."""
    reg = _registry_with_selector({"debug": True})
    if _matched(reg, {"debug": True}):
        return "HELD", "exact bool match works"
    return "BREAK", "exact bool match stopped working (regression)"


def p06_str_vs_int():
    """{"level": "1"} must NOT match {"level": 1} (was already HELD)."""
    reg = _registry_with_selector({"level": "1"})
    if _matched(reg, {"level": 1}):
        return "BREAK", "str selector matched int fact (conflation)"
    return "HELD", "str selector did not match int fact"


def p07_multikey_one_conflated():
    """Multi-key selector: one conflated key must sink the whole match."""
    reg = _registry_with_selector({"debug": 1, "mode": "prod"})
    if _matched(reg, {"debug": True, "mode": "prod"}):
        return "BREAK", "conflated key did not sink multi-key match"
    return "HELD", "conflated key sank multi-key match"


def p08_missing_fact():
    """Missing fact key must not match (was already unmatched)."""
    reg = _registry_with_selector({"debug": 1})
    if _matched(reg, {"other": 1}):
        return "BREAK", "missing fact key matched (regression)"
    return "HELD", "missing fact key did not match"


_PROBES = [
    ("f295-01-int-selector-bool-fact", "HELD", p01_int_selector_bool_fact),
    ("f295-02-bool-selector-int-fact", "HELD", p02_bool_selector_int_fact),
    ("f295-03-false-vs-zero", "HELD", p03_false_vs_zero),
    ("f295-04-exact-int-still-matches", "HELD", p04_exact_int_still_matches),
    ("f295-05-exact-bool-still-matches", "HELD", p05_exact_bool_still_matches),
    ("f295-06-str-vs-int", "HELD", p06_str_vs_int),
    ("f295-07-multikey-one-conflated", "HELD", p07_multikey_one_conflated),
    ("f295-08-missing-fact", "HELD", p08_missing_fact),
]


def _green_checks():
    """Depth-1: run the adjacent attestor battery with GOV_SKIP_GREEN=1
    (it records the skip and does not recurse)."""
    if GREEN_SKIP:
        return [("green-checks", "SKIP",
                 "GOV_SKIP_GREEN=1: recorded, not recursing")]
    out = []
    name = "w274_attestor_probes"
    path = os.path.join(REPO, "evals", name + ".py")
    if not os.path.exists(path):
        return [(name, "SKIP", "battery absent")]
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    try:
        p = subprocess.run([sys.executable, path], env=env,
                           capture_output=True, text=True, timeout=600)
    except Exception as exc:  # noqa: BLE001
        return [(name, "BREAK", "green check failed: %s" % (exc,))]
    tail = (p.stdout or "").strip().split("\n")[-1] if p.stdout else ""
    out.append((name, "HELD" if p.returncode == 0 else "BREAK",
                "%s rc=%d" % (tail[:120], p.returncode)))
    return out


def main():
    print("w276 F295 battery: %d probes (TMPDIR=%s)" % (len(_PROBES), _TMP))
    failures = 0
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    for pid, expected, verdict, ok, note in _RESULTS:
        flag = "ok " if ok else "FAIL"
        if not ok:
            failures += 1
        print("[%s] %-34s expected=%-5s got=%-5s %s"
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
