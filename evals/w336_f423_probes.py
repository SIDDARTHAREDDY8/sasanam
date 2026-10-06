"""Wave-336 lane 1 battery: F423 closure (PRM URL control-char refusal).

Base: c4acf39e (wave-335 merge). Footer at lane: open none / next F424
(F423 CLOSED here). Pin: 2109 (no new codes; reuses
mcp-oauth-prm-malformed).

F423 (filed 2026-10-05, wave-335 lane 5 as F421; renumbered F421->F423
at the wave-335 merge): gov/mcp_prm.py's URL entry points
(check_prm_url, derive_prm_url, parse_challenge_resource_metadata)
admitted raw ASCII control characters instead of refusing coded --
\\r/\\n/\\t were silently stripped by urlsplit before validation (the
"validated" URL was a mutated copy of the wire value) and every other
control (\\x00-\\x1f, \\x7f) was preserved verbatim in the "validated"
URL (the F417-class shape defect, one layer downstream of validation).

Fix (gov/mcp_prm.py): _reject_control_chars, called first in
_raw_url_guards before urlsplit touches the value, so every ASCII
control character (0x00-0x1f, 0x7f) in a raw PRM-controlled URL
refuses coded mcp-oauth-prm-malformed on all three entry points.

P1a  F423 break case 1 (the strip-mutation shapes): CRLF/CR/LF/TAB in
     a challenge-advertised URL, check_prm_url, and derive_prm_url --
     all refuse coded mcp-oauth-prm-malformed (never silently strip).
P1b  F423 break case 2 (the verbatim shapes): NUL and DEL in
     check_prm_url and the challenge path refuse coded.
P1c  Every ASCII control character (0x00-0x1f, 0x7f) x check_prm_url:
     all 33 refuse coded.
P1d  Every ASCII control character x derive_prm_url: all 33 refuse coded.
P1e  CR/LF/TAB x parse_challenge_resource_metadata: refuse coded
     (the exact challenge path from the break proof).
P2   Legitimate controls: a valid PRM URL passes check_prm_url and
     returns the normalized URL; derive_prm_url is byte-exact per
     RFC 9728 3.1; the challenge path parses a clean header;
     percent-encoded %0D is NOT a raw control char and passes shape
     validation (the guard is on the raw wire value only).
P4   Green check (depth-1): honors GOV_SKIP_GREEN; otherwise runs
     evals/w335_redteam_probes.py as a child with GOV_SKIP_GREEN=1
     (fresh TMPDIR) -- it owns the PRM seam's regression probes.

gov/ changes in this lane: gov/mcp_prm.py only (_reject_control_chars
+ first call in _raw_url_guards + docstring note). Findings: F423
filed OPEN wave-335 lane 5, CLOSED here.
"""

import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)
FOOTER_NEXT = "F478"  # Next free finding number (wave-337 merge: F426 filed by red team).; wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)



_results = []
_PROBES = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _held(pid, note):
    _record(pid, "HELD", note)


def _break(pid, note):
    _record(pid, "BREAK", note)


def _safe(pid, fn):
    try:
        fn()
    except AssertionError as exc:
        _break(pid, "assertion: %s" % exc)
    except Exception:  # noqa: BLE001 - every probe must report, not crash
        _record(pid, "ERROR", traceback.format_exc(limit=3).replace(
            "\n", " | ")[:300])


def _probe(pid):
    def deco(fn):
        _PROBES.append((pid, fn))
        return fn
    return deco


def _run_root():
    d = os.environ.get("TMPDIR") or tempfile.gettempdir()
    os.makedirs(d, exist_ok=True)
    return d


def _tmpd(prefix="w336f423-"):
    return tempfile.mkdtemp(prefix=prefix, dir=_run_root())


from gov import mcp_prm as PRM  # noqa: E402
from gov import decision_codes as dc  # noqa: E402
from gov import mcp_oauth_binding as _mob  # noqa: E402

_RES = "https://mcp.example.com"
_MALFORMED = PRM.MCP_OAUTH_PRM_MALFORMED

_CONTROLS = [chr(c) for c in list(range(0x00, 0x20)) + [0x7f]]


def _expect_code(pid, code, fn):
    """Run fn(); HELD iff it raises with the expected coded refusal."""
    try:
        got = fn()
    except Exception as exc:  # noqa: BLE001
        got_code = getattr(exc, "code", None)
        if got_code == code:
            return True
        _break(pid, "wrong code: want %s, got %r (%r)"
               % (code, got_code, exc))
        return False
    _break(pid, "accepted uncoded (returned %r), want refusal %s"
           % (got, code))
    return False


@_probe("P1a")
def p1a():
    """F423 break case 1: CR/LF/TAB are silently stripped by urlsplit
    before validation on the base tree. Now all three entry points
    refuse coded instead of blessing a mutated URL."""
    pid = "P1a-strip-mutation"
    # The exact challenge shape from the break proof.
    if not _expect_code(
            pid, _MALFORMED,
            lambda: PRM.parse_challenge_resource_metadata(
                'Bearer resource_metadata='
                '"https://mcp.example.com/oauth-protected-resource\r\n.evil"',
                _RES)):
        return
    if not _expect_code(
            pid + "-check-crlf", _MALFORMED,
            lambda: PRM.check_prm_url(
                "https://mcp.example.com/a\r\nb", _RES)):
        return
    if not _expect_code(
            pid + "-derive-tab", _MALFORMED,
            lambda: PRM.derive_prm_url(
                "https://mcp.example.com/to\tols")):
        return
    if not _expect_code(
            pid + "-check-cr", _MALFORMED,
            lambda: PRM.check_prm_url(
                "https://mcp.example.com/a\rb", _RES)):
        return
    if not _expect_code(
            pid + "-check-lf", _MALFORMED,
            lambda: PRM.check_prm_url(
                "https://mcp.example.com/a\nb", _RES)):
        return
    _held(pid, "CR/LF/TAB refuse coded on all three entry points")


@_probe("P1b")
def p1b():
    """F423 break case 2: NUL/DEL were preserved verbatim in the
    "validated" URL on the base tree. Now they refuse coded."""
    pid = "P1b-verbatim-controls"
    if not _expect_code(
            pid, _MALFORMED,
            lambda: PRM.check_prm_url(
                "https://mcp.example.com/a\x00b", _RES)):
        return
    if not _expect_code(
            pid + "-del", _MALFORMED,
            lambda: PRM.check_prm_url(
                "https://mcp.example.com/a\x7fb", _RES)):
        return
    if not _expect_code(
            pid + "-challenge-nul", _MALFORMED,
            lambda: PRM.parse_challenge_resource_metadata(
                'Bearer resource_metadata="https://mcp.example.com/a\x00b"',
                _RES)):
        return
    if not _expect_code(
            pid + "-derive-nul", _MALFORMED,
            lambda: PRM.derive_prm_url(
                "https://mcp.example.com/a\x00b")):
        return
    _held(pid, "NUL/DEL refuse coded on all three entry points")


@_probe("P1c")
def p1c():
    """All 33 ASCII control characters x check_prm_url: every one
    refuses coded."""
    pid = "P1c-all-controls-check"
    for c in _CONTROLS:
        url = "https://mcp.example.com/a%sb" % c
        try:
            got = PRM.check_prm_url(url, _RES)
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "code", None) != _MALFORMED:
                _break(pid, "U+%04X wrong code %r"
                       % (ord(c), getattr(exc, "code", None)))
                return
            continue
        _break(pid, "U+%04X accepted uncoded: %r" % (ord(c), got))
        return
    _held(pid, "all 33 control chars refuse coded on check_prm_url")


@_probe("P1d")
def p1d():
    """All 33 ASCII control characters x derive_prm_url: every one
    refuses coded."""
    pid = "P1d-all-controls-derive"
    for c in _CONTROLS:
        url = "https://mcp.example.com/a%sb" % c
        try:
            got = PRM.derive_prm_url(url)
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "code", None) != _MALFORMED:
                _break(pid, "U+%04X wrong code %r"
                       % (ord(c), getattr(exc, "code", None)))
                return
            continue
        _break(pid, "U+%04X accepted uncoded: %r" % (ord(c), got))
        return
    _held(pid, "all 33 control chars refuse coded on derive_prm_url")


@_probe("P1e")
def p1e():
    """CR/LF/TAB x parse_challenge_resource_metadata (the exact
    attacker-controlled challenge path): refuse coded, never strip."""
    pid = "P1e-challenge-controls"
    for c, name in (("\r", "CR"), ("\n", "LF"), ("\t", "TAB")):
        hdr = ('Bearer resource_metadata="https://mcp.example.com/x%sy"'
               % c)
        try:
            got = PRM.parse_challenge_resource_metadata(hdr, _RES)
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "code", None) != _MALFORMED:
                _break(pid, "%s wrong code %r"
                       % (name, getattr(exc, "code", None)))
                return
            continue
        _break(pid, "%s accepted uncoded: %r" % (name, got))
        return
    _held(pid, "CR/LF/TAB refuse coded on the challenge path")


@_probe("P2")
def p2():
    """Legitimate controls: the fix must not break clean URLs."""
    pid = "P2-legitimate"
    got = PRM.check_prm_url("https://mcp.example.com/.well-known/x", _RES)
    if got != "https://mcp.example.com/.well-known/x":
        _break(pid, "clean URL rejected or mangled: %r" % (got,))
        return
    got = PRM.derive_prm_url("https://mcp.example.com/tools/")
    want = "https://mcp.example.com/.well-known/oauth-protected-resource/tools"
    if got != want:
        _break(pid, "derivation changed: %r != %r" % (got, want))
        return
    got = PRM.parse_challenge_resource_metadata(
        'Bearer resource_metadata="https://mcp.example.com/a"', _RES)
    if got != "https://mcp.example.com/a":
        _break(pid, "clean challenge parse changed: %r" % (got,))
        return
    # Percent-encoded %0D is data, not a raw control char: the guard
    # is on the raw wire value only, so shape validation passes.
    try:
        PRM.check_prm_url("https://mcp.example.com/a%0Db", _RES)
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) == _MALFORMED:
            _break(pid, "percent-encoded %%0D wrongly refused: %r" % (exc,))
            return
        # Other coded refusals (e.g. origin) are the seam's business;
        # only the control-char refusal is pinned here.
    _held(pid, "clean URLs pass; %%0D is data, not a raw control")


@_probe("P3")
def p3():
    pid = "P3-pin-footer"
    if len(dc.TAXONOMY) != TAXONOMY_PIN:
        _break(pid, "pin: want %d, got %d"
               % (TAXONOMY_PIN, len(dc.TAXONOMY)))
        return
    codes = sorted(dc.TAXONOMY)
    if codes != sorted(set(codes)):
        _break(pid, "taxonomy not sorted-unique")
        return
    # Wave-260 lesson: uniqueness on raw source literals, not the
    # deduped dict.
    dc_src = open(os.path.join(REPO, "gov", "decision_codes.py"),
                  encoding="utf-8").read()
    counts = {}
    for m in re.finditer(r'"code":\s*"([^"]+)"', dc_src):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    dupes = {k: v for k, v in counts.items() if v != 1}
    if dupes:
        _break(pid, "duplicate code literals: %r" % (dupes,))
        return
    if "mcp-oauth-prm-malformed" not in dc.TAXONOMY:
        _break(pid, "mcp-oauth-prm-malformed not registered")
        return
    # Raw-literal footer assertions (wave-331 lesson).
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    if "Next free finding: **%s**." % FOOTER_NEXT not in text:
        _break(pid, "footer next-free mismatch")
        return
    if "**Open findings: F476, F477.**" not in text:
        _break(pid, "footer open-findings mismatch (want open F426)")
        return
    if "## F423 " not in text:
        _break(pid, "F423 section missing from FINDINGS.md")
        return
    if "CLOSED 2026-10-05 wave-336 lane 1" not in text:
        _break(pid, "F423 closure not recorded")
        return


# ---------------------------------------------------------------------------
# Green check (depth-1).
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()  # No expected BREAKs on the fixed tree.


def _run_child_output(path, timeout):
    d = _tmpd("w336f423-green-")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d)
    proc = subprocess.run(
        [sys.executable, path],
        capture_output=True, text=True, timeout=timeout, env=env,
        cwd=REPO)
    return proc.returncode, proc.stdout + proc.stderr


def _green_check():
    """Depth-1 green check: the w335 red-team battery (it owns the PRM
    seam's regression probes) as a child with GOV_SKIP_GREEN=1 (fresh
    TMPDIR). Honors GOV_SKIP_GREEN by recording a skip, never
    spawning."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "HELD",
                "skipped: GOV_SKIP_GREEN=1 (depth-1 convention)")
        return
    try:
        rc, out = _run_child_output(
            os.path.join(REPO, "evals", "w335_redteam_probes.py"),
            timeout=1500)
    except Exception as exc:
        _record("green-check", "ERROR", "w335_redteam: %s" % exc)
        return
    bad = re.findall(r"^\s*\[(BREAK|ERROR)\]\s+([A-Za-z0-9_.\-]+)",
                     out, re.M)
    m2 = re.search(r"BREAK-SET MISMATCH:\s*(\[[^\]]*\])", out)
    if m2:
        bad.append(("MISMATCH", m2.group(1)[:120]))
    if rc != 0 or bad:
        _record("green-check", "BREAK",
                "w335_redteam non-green rc=%d: %s" % (rc, bad[:4]))
    else:
        _record("green-check", "HELD", "w335_redteam green")


def main(argv):
    for pid, fn in _PROBES:
        _safe(pid, fn)
    _green_check()
    for pid, verdict, note in _results:
        print("[%s] %s: %s" % (verdict, pid, note))
    breaks = sum(1 for _, v, _ in _results if v == "BREAK")
    errors = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_breaks = {pid for pid, v, _ in _results
                    if v == "BREAK" and pid.startswith("P")}
    mismatch = probe_breaks ^ _EXPECTED_BREAKS
    print("w336_f423 battery: %d BREAK / %d HELD / %d ERROR "
          "(0 BREAKs expected on the fixed tree)"
          % (breaks, len(_results) - breaks - errors, errors))
    if mismatch:
        print("BREAK-SET MISMATCH: %r" % (sorted(mismatch),))
        return 2
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
