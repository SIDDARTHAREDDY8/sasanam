"""Wave-272 red-first battery: F253 + F254 closure (gov/tool_grant.py).

F253 (LOW): `enforce` consumed `max_calls` budget BEFORE the nonce replay
check, so a REFUSED replay still decremented the victim grant's counter --
a budget-griefing primitive. Close-when: the nonce replay check runs before
usage consumption; a refused replay is budget-neutral; a legitimate first
presentation still consumes exactly one call and marks the nonce.

F254 (LOW): `make_pop_proof`'s default nonce was
`sha256(canonical([method, uri, now]))[:16]` -- deterministic Ed25519 made
two same-second proofs byte-identical, so the second legitimate call was
refused as `ptgrant-jti-reused`. Close-when: there is NO silent deterministic
default -- `nonce` is a required, non-empty, caller-supplied unique string
(the module claims "never randomness", so ambient randomness is not an
acceptable fix).

Red-first discipline: every probe below is written against the FIXED
contract. On the pre-fix base they BREAK (demonstrating the findings);
after the fix they HELD.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (fixed seeds, explicit `now`);
fresh unique /var/tmp/g272* TMPDIR (`mkdir -p` first); depth-1 green
checks honoring GOV_SKIP_GREEN=1; no in-repo git subprocesses; stdlib only.
"""

import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TMP = tempfile.mkdtemp(prefix="g272-f253f254-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import tool_grant  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402

# Wave-272 merge pin 1443 (base 0a90e4f pin 1411 + 32 codes; neither fix adds
# decision codes -- ptgrant-jti-reused, ptgrant-max-calls-exhausted,
# ptgrant-pop-invalid already exist). Counted on quoted source literals
# per the wave-260 lesson.
TAXONOMY_PIN = 1915 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 1: pin 1906 -> 1915 (+9 grantneg-*)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _run(pid, expected, fn):
    """Run one probe; verdict must equal expected (BREAK or HELD)."""
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001 -- probe harness
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))
    return ok


def _pin_check():
    import re
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'\"code\":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK", "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    return "HELD", "taxonomy pin 1588: 1588 unique literals"


def _seed(i):
    return bytes([i & 0xFF]) * 32


_TG_ISS_SEED = _seed(0x01)
_TG_ISS_PUB = _ed.publickey(_TG_ISS_SEED)
_TG_HOLDER_SEED = _seed(0x02)
_TG_HOLDER_PUB = _ed.publickey(_TG_HOLDER_SEED)
_TG_NOW = 1790000000
_TG_AUD = "https://mcp.example.internal/fileserver"
_TG_SUB = "spiffe://trust-domain/ns/prod/sa/agent-7"
_TG_LINK = "sha256:" + "ab" * 32


def _tg_details(tool="read", **kw):
    d = {
        "type": tool_grant.GRANT_TYPE,
        "locations": [_TG_AUD],
        "actions": ["call"],
        "identifier": "fileserver::" + tool,
        "arg_bounds": {
            "path": {"predicate": "prefix",
                     "params": {"prefix": "/data/shared/"}},
        },
        "supply_chain": {"link_digest": _TG_LINK, "delegation_ok": True},
        "max_calls": 3,
    }
    d.update(kw)
    return d


def _tg_grant(details_list, **kw):
    params = dict(sub=_TG_SUB, aud=_TG_AUD, proof_pub=_TG_HOLDER_PUB,
                  mandate_id="m1", mandate_version=1,
                  details=details_list, lifetime_s=600, now=_TG_NOW)
    params.update(kw)
    issuer = tool_grant.Issuer(tool_grant.GRANT_ISSUER, _TG_ISS_SEED,
                               lambda mid: {"version": 1})
    return issuer.issue(**params)


def _tg_env(store, **kw):
    env = dict(issuer_pub=_TG_ISS_PUB, server_name="fileserver",
               server_uri=_TG_AUD, tool="read",
               args={"path": "/data/shared/x"}, now=_TG_NOW,
               usage_store=store,
               mandate_version_provider=lambda mid: 1,
               link_verifier=lambda t: _TG_LINK)
    env.update(kw)
    return env


def _tg_proof(grant, seed=_TG_HOLDER_SEED, nonce="probe-n1", **kw):
    params = dict(method="POST", uri=_TG_AUD + "/tools/call",
                  now=_TG_NOW, nonce=nonce)
    params.update(kw)
    return tool_grant.make_pop_proof(seed, grant, **params)


# --- F253: replayed proofs must be budget-neutral --------------------------


def f253_replay_is_budget_neutral():
    """F253 close-when: replay refused as ptgrant-jti-reused AND the
    usage counter is unchanged by the refused replay."""
    grant = _tg_grant([_tg_details()])
    jti = grant["body"]["jti"]
    store = tool_grant.UsageStore()
    proof = _tg_proof(grant, nonce="f253-n1")
    r1 = tool_grant.enforce(grant, proof=proof, **_tg_env(store))
    assert r1["code"] == "ptgrant-ok", r1
    used1 = store.status(jti, 3)["calls_used"]
    r2 = tool_grant.enforce(grant, proof=proof, **_tg_env(store))
    used2 = store.status(jti, 3)["calls_used"]
    if r2["code"] != "ptgrant-jti-reused":
        return "ERROR", "replay not refused: %r" % (r2["code"],)
    if used2 != used1:
        return ("BREAK",
                "F253: refused replay burned budget (used %d -> %d); "
                "consume() runs before the nonce check" % (used1, used2))
    return "HELD", "replay refused as ptgrant-jti-reused, budget unchanged"


def f253_first_presentation_consumes_one():
    """F253 close-when (3): a legitimate first presentation consumes
    exactly one call and marks the nonce (no double-spend)."""
    grant = _tg_grant([_tg_details()])
    jti = grant["body"]["jti"]
    store = tool_grant.UsageStore()
    r1 = tool_grant.enforce(grant, proof=_tg_proof(grant, nonce="f253-n2"),
                            **_tg_env(store))
    used = store.status(jti, 3)["calls_used"]
    if r1["code"] != "ptgrant-ok" or used != 1:
        return "ERROR", "first call: %r used=%d" % (r1["code"], used)
    r2 = tool_grant.enforce(grant, proof=_tg_proof(grant, nonce="f253-n2"),
                            **_tg_env(store))
    used2 = store.status(jti, 3)["calls_used"]
    if r2["code"] != "ptgrant-jti-reused" or used2 != 1:
        return "ERROR", "replay: %r used=%d" % (r2["code"], used2)
    return "HELD", "first presentation consumed exactly one call"


def f253_budget_griefing_closed():
    """F253 griefing primitive: replaying a captured proof N times must
    not drain the victim's grant."""
    grant = _tg_grant([_tg_details(max_calls=4)])
    jti = grant["body"]["jti"]
    store = tool_grant.UsageStore()
    proof = _tg_proof(grant, nonce="f253-n3")
    r1 = tool_grant.enforce(grant, proof=proof, **_tg_env(store))
    assert r1["code"] == "ptgrant-ok", r1
    for _ in range(2):
        r = tool_grant.enforce(grant, proof=proof, **_tg_env(store))
        if r["code"] != "ptgrant-jti-reused":
            return "ERROR", "replay not refused: %r" % (r["code"],)
    used = store.status(jti, 4)["calls_used"]
    if used != 1:
        return ("BREAK",
                "F253: 2 refused replays burned %d call(s); grant drained"
                % (used - 1,))
    r2 = tool_grant.enforce(grant, proof=_tg_proof(grant, nonce="f253-n4"),
                            **_tg_env(store))
    if r2["code"] != "ptgrant-ok":
        return "ERROR", "legitimate second call refused: %r" % (r2["code"],)
    return "HELD", "griefing primitive closed; legitimate calls unaffected"


# --- F254: no silent deterministic nonce default ----------------------------


def f254_nonce_is_required():
    """F254 close-when: there is no silent deterministic default -- minting
    without a nonce raises (ptgrant-pop-invalid)."""
    grant = _tg_grant([_tg_details()])
    try:
        tool_grant.make_pop_proof(_TG_HOLDER_SEED, grant, method="POST",
                                  uri=_TG_AUD + "/tools/call", now=_TG_NOW)
    except tool_grant.GrantError as exc:
        if getattr(exc, "code", None) == "ptgrant-pop-invalid":
            return "HELD", "minting without nonce refused ptgrant-pop-invalid"
        return "ERROR", "wrong refusal code: %r" % (getattr(exc, "code", None),)
    return ("BREAK",
            "F254: minting without nonce silently defaulted -- same-second "
            "proofs can still be byte-identical")


def f254_explicit_nonce_no_collision():
    """F254 close-when: caller-supplied unique nonces make same-second
    proofs distinct and both enforceable."""
    grant = _tg_grant([_tg_details(max_calls=2)])
    store = tool_grant.UsageStore()
    p1 = _tg_proof(grant, nonce="f254-a")
    p2 = _tg_proof(grant, nonce="f254-b")
    if p1 == p2:
        return "ERROR", "explicit-nonce proofs identical (unexpected)"
    r1 = tool_grant.enforce(grant, proof=p1, **_tg_env(store))
    r2 = tool_grant.enforce(grant, proof=p2, **_tg_env(store))
    if r1["code"] == "ptgrant-ok" and r2["code"] == "ptgrant-ok":
        return "HELD", "two same-second explicit-nonce proofs both enforced"
    return ("BREAK", "second legitimate call refused: %r" % (r2["code"],))


def f254_empty_nonce_refused():
    """F254 edge: an empty nonce is not a valid uniqueness claim --
    refused at mint time, same as a missing nonce."""
    grant = _tg_grant([_tg_details()])
    for bad in ("", None):
        try:
            tool_grant.make_pop_proof(_TG_HOLDER_SEED, grant, method="POST",
                                      uri=_TG_AUD + "/tools/call",
                                      now=_TG_NOW, nonce=bad)
        except tool_grant.GrantError as exc:
            if getattr(exc, "code", None) != "ptgrant-pop-invalid":
                return "ERROR", "wrong code for %r" % (bad,)
            continue
        return ("BREAK",
                "F254: empty/None nonce accepted -- uniqueness claim void")
    return "HELD", "empty/None nonce refused at mint time"


# --- runner -----------------------------------------------------------------

# Adjacent battery for the depth-1 green check (spawned with
# GOV_SKIP_GREEN=1 in the child env; never nested).
_GREEN_BATTERIES = ["evals/w270_ptgrant_probes.py"]


def _green_checks():
    if GREEN_SKIP:
        return [("green", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 convention)")]
    notes = []
    for battery in _GREEN_BATTERIES:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(REPO, battery)],
                env=env, cwd=REPO, capture_output=True, text=True,
                timeout=600)
            tail = (proc.stdout or "").strip().splitlines()[-2:]
            ok = proc.returncode == 0
            notes.append((
                "green", "HELD" if ok else "BREAK",
                "%s rc=%d: %s" % (battery, proc.returncode,
                                  " | ".join(tail))))
        except Exception as exc:  # noqa: BLE001 -- probe harness
            notes.append(("green", "ERROR",
                          "%s: %s" % (battery, exc)))
    return notes


def main():
    probes = [
        ("control_c0_pin_check", "HELD", _pin_check),
        ("f253_replay_is_budget_neutral", "HELD", f253_replay_is_budget_neutral),
        ("f253_first_presentation_consumes_one", "HELD",
         f253_first_presentation_consumes_one),
        ("f253_budget_griefing_closed", "HELD", f253_budget_griefing_closed),
        ("f254_nonce_is_required", "HELD", f254_nonce_is_required),
        ("f254_explicit_nonce_no_collision", "HELD",
         f254_explicit_nonce_no_collision),
        ("f254_empty_nonce_refused", "HELD", f254_empty_nonce_refused),
    ]
    all_ok = True
    for pid, expected, fn in probes:
        all_ok &= _run(pid, expected, fn)
    for _name, verdict, note in _green_checks():
        ok = verdict in ("HELD", "SKIP")
        all_ok &= ok
        print("  [green ] %-8s %s" % (verdict, note))
    held = sum(1 for r in _RESULTS if r[2] == "HELD")
    brk = sum(1 for r in _RESULTS if r[2] == "BREAK")
    err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    print("w272_f253f254: %d HELD / %d BREAK / %d ERROR" % (held, brk, err))
    for pid, expected, verdict, ok, note in _RESULTS:
        if not ok:
            print("  %-38s expected %s, got %s: %s"
                  % (pid, expected, verdict, note))
    print("RESULT", "OK" if all_ok else "FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
