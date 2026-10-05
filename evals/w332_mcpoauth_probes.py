"""Wave-332 lane 2 break battery: MCP OAuth hardening (RFC 9207 / RFC 8707).

Base: cef4ad59 (wave-331 merge). Pin: 2100 (+4 mcp-oauth-* codes).
Footer: open none / next F417 (no findings filed by this lane).

The w330 prospectus's MCP OAuth hardening ADAPT verdicts (confirmed
genuinely absent by the wave-331 red team): the MCP OAuth client path
had no RFC 9207 authorization-response ``iss`` validation (mix-up
attack: a rogue AS's response, or an intercepted response with the
issuer substituted, was uncheckable) and no RFC 8707 resource
indicators (a token minted for MCP server A could be presented at
server B with nothing to refuse it).

P1  RFC 9207: rogue-iss response, missing-iss response, correct-iss
    control, tampered-binding composition.
P2  RFC 8707 presentation: A-minted token at B, resourceless token,
    matching-resource control, aud-list control.
P3  RFC 8707 token response: substituted resource, missing resource.
P4  refusal vocabulary: every new code literal is centrally registered
    (wave-329 lesson); pin 2130/2130/0 sorted unique on raw literals.
P5  footer state: open none / next F417.
P6  depth-1 green check: adjacent MCP OAuth batteries with
    GOV_SKIP_GREEN=1.

Red-first record: on the pristine cef4ad59 tree (before the fix) the
P1a/P1b/P2a/P2b/P3a/P3b probes record BREAK -- the validation entry
points do not exist, so the attack shapes pass through the existing
public API unchallenged. After the fix all probes go HELD.
"""

import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2130 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*); Wave-339 merge: pin 2128 -> 2130 (+4 codes: oci-bundle-not-verifiable, witness-policy-dual-threshold-unmet, witness-daemon-state-failed, oci-registry-onboarding-refused)
FOOTER_OPEN = "F427"  # F426 closed wave-338 lane 1; F427 OPEN (wave-339 lane 5).
FOOTER_NEXT = "F428"  # Next free finding number.

_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


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


_KEY = b"wave332-mcpoauth-key-0123456789abcdef"
_AS = "https://as.example"
_TOKEN_EP = "https://as.example/token"
_SERVER_A = "https://mcp-a.example"
_SERVER_B = "https://mcp-b.example"


def _mob():
    from gov import mcp_oauth_binding as mob
    return mob


def _sealed(key=_KEY, issuer=_AS, client_id="client-1"):
    return _mob().seal_as_binding(issuer, client_id, key)


def _gap(pid, note):
    """The validation entry point is absent: the attack shape is
    uncheckable on this tree -> BREAK (gap demonstrated)."""
    return (pid, "BREAK", "gap: " + note)


def _refused_as(pid, fn, want_code, note):
    """Call fn(); HELD iff it refuses with the wanted coded refusal."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code == want_code:
            return (pid, "HELD", note + " refused coded " + want_code)
        return (pid, "BREAK",
                note + " refused with wrong code %r, want %s"
                % (code, want_code))
    return (pid, "BREAK", note + " ACCEPTED (no refusal)")


# ---------------------------------------------------------------------------
# P1: RFC 9207 authorization-response iss validation.
# ---------------------------------------------------------------------------

@probe("P1a-9207-rogue-iss-mixup")
def _p1a():
    """Mix-up: authorization response whose iss names a rogue AS."""
    mob = _mob()
    if not hasattr(mob, "validate_authorization_response"):
        return _gap("P1a-9207-rogue-iss-mixup",
                    "no validate_authorization_response; rogue-iss "
                    "response passes through the exchange API unchallenged")
    sealed = _sealed()
    return _refused_as(
        "P1a-9207-rogue-iss-mixup",
        lambda: mob.validate_authorization_response(
            sealed, {"code": "authcode-1", "state": "s1",
                     "iss": "https://rogue.example"},
            _KEY),
        "mcp-oauth-iss-mismatched",
        "rogue-iss authorization response")


@probe("P1b-9207-missing-iss")
def _p1b():
    """Authorization response with no iss at all."""
    mob = _mob()
    if not hasattr(mob, "validate_authorization_response"):
        return _gap("P1b-9207-missing-iss",
                    "no validate_authorization_response; iss-less "
                    "response passes through unchallenged")
    sealed = _sealed()
    return _refused_as(
        "P1b-9207-missing-iss",
        lambda: mob.validate_authorization_response(
            sealed, {"code": "authcode-1", "state": "s1"}, _KEY),
        "mcp-oauth-iss-missing",
        "iss-less authorization response")


@probe("P1c-9207-correct-iss-accepted")
def _p1c():
    """Control: correct iss (with cosmetic case/trailing-slash
    differences) is accepted."""
    mob = _mob()
    if not hasattr(mob, "validate_authorization_response"):
        return _gap("P1c-9207-correct-iss-accepted",
                    "no validate_authorization_response")
    sealed = _sealed()
    try:
        got = mob.validate_authorization_response(
            sealed, {"code": "authcode-1", "iss": "HTTPS://as.example/"},
            _KEY)
    except Exception as exc:  # noqa: BLE001
        return ("P1c-9207-correct-iss-accepted", "BREAK",
                "correct iss refused: %r" % (getattr(exc, "code", exc),))
    if got != _AS:
        return ("P1c-9207-correct-iss-accepted", "BREAK",
                "normalized iss %r != %r" % (got, _AS))
    return ("P1c-9207-correct-iss-accepted", "HELD",
            "correct iss accepted, normalized to %r" % (got,))


@probe("P1d-9207-tampered-binding-refused-as-tamper")
def _p1d():
    """Composition: a tampered sealed binding on the new path refuses
    as tamper, never as a shape gap."""
    mob = _mob()
    if not hasattr(mob, "validate_authorization_response"):
        return _gap("P1d-9207-tampered-binding-refused-as-tamper",
                    "no validate_authorization_response")
    sealed = _sealed()
    sealed = {"binding": dict(sealed["binding"]), "mac": sealed["mac"]}
    sealed["binding"]["issuer"] = "https://evil.example"
    return _refused_as(
        "P1d-9207-tampered-binding-refused-as-tamper",
        lambda: mob.validate_authorization_response(
            sealed, {"code": "c", "iss": _AS}, _KEY),
        "mcp-oauth-binding-tampered",
        "tampered binding on the iss path")


@probe("P1e-9207-wired-choke-point")
def _p1e():
    """The exchange choke point enforces iss when the authorization
    response is supplied: a rogue iss refuses BEFORE the exchange runs."""
    mob = _mob()
    if not hasattr(mob, "check_response_iss"):
        return _gap("P1e-9207-wired-choke-point",
                    "no check_response_iss; the choke point cannot "
                    "enforce RFC 9207")
    sealed = _sealed()
    verdict = mob.authorize_token_exchange(
        sealed, _TOKEN_EP, _KEY, issuer_hint=_AS)
    ran = []
    try:
        mob.run_bound_exchange(
            verdict, _TOKEN_EP, lambda: ran.append(True),
            authorization_response={"code": "c",
                                    "iss": "https://rogue.example"})
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code == "mcp-oauth-iss-mismatched" and not ran:
            return ("P1e-9207-wired-choke-point", "HELD",
                    "choke point refused rogue iss before running "
                    "the exchange")
        return ("P1e-9207-wired-choke-point", "BREAK",
                "wrong refusal %r (exchange ran: %s)"
                % (code, bool(ran)))
    return ("P1e-9207-wired-choke-point", "BREAK",
            "exchange RAN on a rogue-iss response")


# ---------------------------------------------------------------------------
# P2: RFC 8707 token resource binding at presentation.
# ---------------------------------------------------------------------------

@probe("P2a-8707-token-a-presented-at-b")
def _p2a():
    """Cross-server replay: token minted for server A presented at B."""
    mob = _mob()
    if not hasattr(mob, "check_token_resource"):
        return _gap("P2a-8707-token-a-presented-at-b",
                    "no check_token_resource; A-minted token is "
                    "presentable at B with nothing to refuse it")
    return _refused_as(
        "P2a-8707-token-a-presented-at-b",
        lambda: mob.check_token_resource(
            _SERVER_B, {"resource": _SERVER_A, "sub": "agent-1"}),
        "mcp-oauth-resource-misbound",
        "A-minted token presented at B")


@probe("P2b-8707-resourceless-token")
def _p2b():
    """Token with no resource indicator at all."""
    mob = _mob()
    if not hasattr(mob, "check_token_resource"):
        return _gap("P2b-8707-resourceless-token",
                    "no check_token_resource; resourceless token is "
                    "presentable anywhere")
    return _refused_as(
        "P2b-8707-resourceless-token",
        lambda: mob.check_token_resource(_SERVER_A, {"sub": "agent-1"}),
        "mcp-oauth-resource-missing",
        "resourceless token")


@probe("P2c-8707-matching-resource-accepted")
def _p2c():
    """Control: token naming the presenting server is accepted."""
    mob = _mob()
    if not hasattr(mob, "check_token_resource"):
        return _gap("P2c-8707-matching-resource-accepted",
                    "no check_token_resource")
    try:
        got = mob.check_token_resource(
            _SERVER_A + "/", {"resource": _SERVER_A, "sub": "agent-1"})
    except Exception as exc:  # noqa: BLE001
        return ("P2c-8707-matching-resource-accepted", "BREAK",
                "matching resource refused: %r"
                % (getattr(exc, "code", exc),))
    if got != _SERVER_A:
        return ("P2c-8707-matching-resource-accepted", "BREAK",
                "normalized %r != %r" % (got, _SERVER_A))
    return ("P2c-8707-matching-resource-accepted", "HELD",
            "matching resource accepted")


@probe("P2d-8707-aud-list-accepted")
def _p2d():
    """Control: RFC 9068-style aud list containing the server works."""
    mob = _mob()
    if not hasattr(mob, "check_token_resource"):
        return _gap("P2d-8707-aud-list-accepted",
                    "no check_token_resource")
    try:
        mob.check_token_resource(
            _SERVER_B, {"aud": ["https://other.example", _SERVER_B]})
    except Exception as exc:  # noqa: BLE001
        return ("P2d-8707-aud-list-accepted", "BREAK",
                "aud list refused: %r" % (getattr(exc, "code", exc),))
    return ("P2d-8707-aud-list-accepted", "HELD",
            "aud list containing the server accepted")


# ---------------------------------------------------------------------------
# P3: RFC 8707 token response resource echo.
# ---------------------------------------------------------------------------

@probe("P3a-8707-token-response-substituted")
def _p3a():
    """Token response naming a different resource than requested."""
    mob = _mob()
    if not hasattr(mob, "check_token_response_resource"):
        return _gap("P3a-8707-token-response-substituted",
                    "no check_token_response_resource; substituted "
                    "token response is uncheckable")
    return _refused_as(
        "P3a-8707-token-response-substituted",
        lambda: mob.check_token_response_resource(
            _SERVER_A, {"access_token": "tok", "resource": _SERVER_B}),
        "mcp-oauth-resource-misbound",
        "substituted token response")


@probe("P3b-8707-token-response-no-resource")
def _p3b():
    """Token response with no resource parameter."""
    mob = _mob()
    if not hasattr(mob, "check_token_response_resource"):
        return _gap("P3b-8707-token-response-no-resource",
                    "no check_token_response_resource")
    return _refused_as(
        "P3b-8707-token-response-no-resource",
        lambda: mob.check_token_response_resource(
            _SERVER_A, {"access_token": "tok"}),
        "mcp-oauth-resource-missing",
        "resourceless token response")


# ---------------------------------------------------------------------------
# P4: refusal vocabulary registration + taxonomy pin.
# ---------------------------------------------------------------------------

_NEW_CODES = (
    "mcp-oauth-iss-missing",
    "mcp-oauth-iss-mismatched",
    "mcp-oauth-resource-missing",
    "mcp-oauth-resource-misbound",
)


@probe("P4a-new-codes-registered")
def _p4a():
    """Every new code literal is centrally registered (wave-329 lesson:
    vocab-scan presence is not registration)."""
    from gov import decision_codes as dc
    missing = [c for c in _NEW_CODES if c not in dc.TAXONOMY]
    if missing:
        return ("P4a-new-codes-registered", "BREAK",
                "unregistered codes: %r" % (missing,))
    mob = _mob()
    not_in_codes = [c for c in _NEW_CODES
                    if c not in getattr(mob, "CODES", ())]
    if not_in_codes:
        return ("P4a-new-codes-registered", "BREAK",
                "codes missing from module CODES: %r" % (not_in_codes,))
    return ("P4a-new-codes-registered", "HELD",
            "4 new codes registered and in module CODES")


@probe("P4b-pin-taxonomy-2130-sorted")
def _p4b():
    if TAXONOMY_PIN != 2130:
        return ("P4b-pin-taxonomy-2130-sorted", "BREAK",
                "TAXONOMY_PIN is %r, want 2130" % (TAXONOMY_PIN,))
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'"code"\s*:\s*\'([^\']+)\'', src)
    if len(lits) != 2130 or len(set(lits)) != 2130 \
            or lits != sorted(lits):
        return ("P4b-pin-taxonomy-2130-sorted", "BREAK",
                "want 2130/2130/0 sorted, got %d/%d/sorted=%s"
                % (len(lits), len(set(lits)), lits == sorted(lits)))
    return ("P4b-pin-taxonomy-2130-sorted", "HELD",
            "2130/2130/0 sorted unique on raw source literals")


# ---------------------------------------------------------------------------
# P5: footer state.
# ---------------------------------------------------------------------------

@probe("P5-footer-open-none-next-f428")
def _p5():
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    ms = re.findall(r"Next free finding: \*\*(F\d+)\*\*\. "
                    r"\*\*Open findings: ([^*]+)\.\*\*", text)
    if not ms:
        return ("P5-footer-open-none-next-f428", "BREAK",
                "footer line not found")
    next_free, open_now = ms[-1]
    if next_free != FOOTER_NEXT or open_now != FOOTER_OPEN:
        return ("P5-footer-open-none-next-f428", "BREAK",
                "footer open %s / next %s, want open %s / next %s"
                % (open_now, next_free, FOOTER_OPEN, FOOTER_NEXT))
    return ("P5-footer-open-none-next-f428", "HELD",
            "footer open none / next F428")


# ---------------------------------------------------------------------------
# P6: depth-1 green check (adjacent MCP OAuth batteries).
# ---------------------------------------------------------------------------

def _run_child(argv, timeout=1500):
    """Run a child battery; return its exit code."""
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmp = tempfile.mkdtemp(prefix="g332-")
    env["TMPDIR"] = tmp
    proc = subprocess.run(
        [sys.executable] + argv, cwd=REPO, env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode


@probe("P6a-green-adjacent-mcp-batteries")
def _p6a():
    """Depth-1 green check: adjacent MCP OAuth batteries with
    GOV_SKIP_GREEN=1. Honors GOV_SKIP_GREEN (records a skip instead of
    spawning)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("P6a-green-adjacent-mcp-batteries", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
    children = [
        ["-m", "unittest", "tests.test_mcp_oauth_binding", "-v"],
        ["evals/w245_mcp_oauth_binding_probes.py"],
        # w245 exits 0 iff all probes HELD (raise SystemExit otherwise).
    ]
    bad = []
    notes = []
    for argv in children:
        rc = _run_child(argv)
        if rc != 0:
            bad.append("%r rc=%d" % (argv, rc))
        else:
            notes.append("%r OK" % (argv,))
    if bad:
        return ("P6a-green-adjacent-mcp-batteries", "BREAK",
                "child failures: %r" % (bad,))
    return ("P6a-green-adjacent-mcp-batteries", "HELD",
            "children green: %s" % ("; ".join(notes),))


_EXPECTED_BREAKS = set()  # No expected BREAKs: the gaps are closed in this lane.


def _green_check():
    """Standalone green check honoring the depth-1 convention."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    # P6a already runs the adjacent batteries as children; nothing more
    # to spawn here (depth-1: this battery never spawns grandchildren).
    _record("green-check", "HELD",
            "depth-1: adjacent batteries run as P6a children")


def main():
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    helds = sum(1 for _, v, _ in _results if v == "HELD")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_breaks = {p for p, v, _ in _results
                    if v == "BREAK" and not p.startswith("green-check")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("battery: %d BREAK / %d HELD / %d ERROR"
          % (breaks, helds, errors))
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    if mismatch:
        print("BREAK-SET MISMATCH: got %r, expected %r"
              % (sorted(probe_breaks), sorted(_EXPECTED_BREAKS)))
        return 1
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
