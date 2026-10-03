"""Wave-246 cross-vendor URI-normalization probes (red-first).

W246-4 (threat model): the authentication path and the IoC
(indicator-of-compromise) path must see ONE normalized string. If auth
normalizes a URI one way and the IoC matcher another, an attacker can
slip past auth with an encoding the IoC matcher doesn't normalize --
or slip past the IoC with an encoding auth doesn't normalize.

Concrete sites in this tree (all stdlib ``urllib.parse``):

  auth:  gov.executor.ToolExecutor._domain_allowlisted --
         ``urlparse(url).hostname.lower()`` (lowercase only).
  ioc:   gov.canary host extraction ``urlparse(raw).hostname`` +
         CanaryRegistry.match_host -- ``host.strip().lower().rstrip(".")``.
  jwks:  gov.jwks_fetch._normalize_host --
         ``host.lower().rstrip(".")`` + IDNA encode.
  dlp:   gov.dlp path/query scanning -- ``unquote``/``unquote_plus``
         exactly one layer per segment.

Probes:

  (a) auth/ioc agreement -- every URL the auth path ALLOWS must
      resolve to the byte-identical host string the IoC matcher sees.
      An allowed egress the IoC attributes to a different host is an
      IoC blind spot.
  (b) denied representation -- every URL the auth path DENIES must not
      be re-representable so the IoC layer treats it as a DIFFERENT
      host identity than the one auth denied. Divergences that exist
      are PINNED as held behavior (fail-closed on the auth side) with
      a candidacy note for a shared normalizer.
  (c) normalizer pins -- idempotence, case-folding, trailing-dot
      handling, IDNA, and the single-decode-layer discipline.

There is no single normalization point in the tree (executor,
canary, jwks_fetch each roll their own); the divergence PINs document
that gap. A shared ``gov/uri_normalize.py`` is REPORT.md candidacy,
not built in-lane: rewiring the auth decision (e.g. trailing-dot
``trusted.example.`` deny -> allow) is a security-sensitive behavior
change needing full gates.

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback
import types
from urllib.parse import unquote, urlparse

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_EXEC = HAVE_CANARY = HAVE_JWKS = HAVE_DLP = False
try:
    from gov.executor import ToolExecutor as _TE
    HAVE_EXEC = True
except ImportError:
    _TE = None
try:
    from gov.canary import CanaryRegistry as _CR
    HAVE_CANARY = True
except ImportError:
    _CR = None
try:
    from gov import jwks_fetch as _jwks
    HAVE_JWKS = all(hasattr(_jwks, n) for n in ("_normalize_host",))
except ImportError:
    _jwks = None
try:
    from gov import dlp as _dlp
    HAVE_DLP = True
except ImportError:
    _dlp = None

HAVE_ALL = HAVE_EXEC and HAVE_CANARY and HAVE_JWKS and HAVE_DLP

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

ALLOWLIST = ["trusted.example"]

PROBE_NAMES = [
    # (a) auth/ioc agreement on ALLOWED urls
    "agree-plain-host",
    "agree-mixed-case-host",
    "agree-userinfo-legit",
    "agree-encoded-path",
    "agree-double-encoded-path",
    "agree-send-email",
    # (b) denied representations
    "denied-userinfo-evil",
    "denied-pct-encoded-host",
    "denied-trailing-dot",
    "denied-leading-whitespace",
    "denied-idna-raw",
    # (c) normalizer pins
    "normalize-idempotent",
    "normalize-case-fold",
    "normalize-trailing-dot",
    "normalize-idna",
    "normalize-no-pct-decode",
    "normalize-match-host-no-idna",
    "normalize-dlp-single-decode",
]


def _run_probe(name, fn, have):
    if not have:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        return name, "BREAK", "GAP: capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _stub_executor(allowlist):
    """Minimal stand-in carrying only what _domain_allowlisted reads."""
    return types.SimpleNamespace(
        policy=types.SimpleNamespace(
            egress={"domain_allowlist": list(allowlist)}))


def _auth_allow(tool, args):
    """The REAL auth decision via the product's _domain_allowlisted."""
    return bool(_TE._domain_allowlisted(_stub_executor(ALLOWLIST),
                                       tool, args))


def _auth_view(url):
    """Host string the auth path compares (mirrors _domain_allowlisted's
    derivation: ``urlparse(url).hostname.lower()``)."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    return host.lower()


def _registry():
    reg = _CR()
    reg._by_host["trusted.example"] = {"kind": "hostname",
                                       "value": "trusted.example"}
    return reg


def _ioc_view(url):
    """Host string the IoC path feeds to match_host, normalized the way
    CanaryRegistry.match_host normalizes: strip/lower/rstrip-dot."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    return host.strip().lower().rstrip(".")


# ---------------------------------------------------------------- (a)

def _probe_agree_plain_host():
    url = "https://trusted.example/x"
    assert _auth_allow("http_post", {"url": url}), "auth must allow"
    assert _auth_view(url) == _ioc_view(url) == "trusted.example", \
        (_auth_view(url), _ioc_view(url))
    return "auth and IoC see byte-identical host for plain URL"


def _probe_agree_mixed_case_host():
    url = "https://TRUSTED.EXAMPLE/x"
    assert _auth_allow("http_post", {"url": url}), "auth must allow (DNS)"
    assert _auth_view(url) == _ioc_view(url) == "trusted.example", \
        (_auth_view(url), _ioc_view(url))
    return "mixed-case host: both normalize to trusted.example"


def _probe_agree_userinfo_legit():
    url = "https://user:pass@trusted.example/x"
    assert _auth_allow("http_post", {"url": url}), "auth must allow"
    assert _auth_view(url) == _ioc_view(url) == "trusted.example", \
        (_auth_view(url), _ioc_view(url))
    return "userinfo never confuses the host on either path"


def _probe_agree_encoded_path():
    # %6a == 'j': the classic /%6a_security_check auth-bypass shape.
    # Path encoding must not change host identity on either path.
    url = "https://trusted.example/%6a_security_check"
    assert _auth_allow("http_post", {"url": url}), "auth must allow"
    assert _auth_view(url) == _ioc_view(url) == "trusted.example", \
        (_auth_view(url), _ioc_view(url))
    return "percent-encoded path leaves host identity identical"


def _probe_agree_double_encoded_path():
    url = "https://trusted.example/%256a_security_check"
    assert _auth_allow("http_post", {"url": url}), "auth must allow"
    assert _auth_view(url) == _ioc_view(url) == "trusted.example", \
        (_auth_view(url), _ioc_view(url))
    return "double-encoded path leaves host identity identical"


def _probe_agree_send_email():
    assert _auth_allow("send_email", {"to": "ops@trusted.example"}), \
        "auth must allow"
    raw = "ops@trusted.example".rsplit("@", 1)[-1]
    assert raw.lower() == raw.strip().lower().rstrip("."), raw
    return "send_email host agrees across both derivations"


# ---------------------------------------------------------------- (b)

def _probe_denied_userinfo_evil():
    # userinfo attack: the host is evil.example, not trusted.example.
    url = "https://trusted.example@evil.example/x"
    assert not _auth_allow("http_post", {"url": url}), "auth must deny"
    assert _auth_view(url) == _ioc_view(url) == "evil.example", \
        (_auth_view(url), _ioc_view(url))
    return "userinfo-evil: both paths see evil.example; auth denies"


def _probe_denied_pct_encoded_host():
    # Percent-encoded host: neither path decodes it, both deny/miss
    # identically (fail-closed, no normalization asymmetry to exploit).
    url = "https://%74rusted.example/x"
    assert not _auth_allow("http_post", {"url": url}), "auth must deny"
    assert _auth_view(url) == _ioc_view(url) == "%74rusted.example", \
        (_auth_view(url), _ioc_view(url))
    assert _registry().match_host("%74rusted.example") is None
    return "encoded host: no decode on either path; identical deny"


def _probe_denied_trailing_dot():
    # PIN (held behavior -- documents the gap): there is no single
    # normalization point. Auth sees 'trusted.example.' and DENIES
    # (fail-closed: trailing-dot FQDN is not in the allowlist); the IoC
    # path strips the dot and match_host HITS 'trusted.example'.
    # The IoC never invents a DIFFERENT host identity -- its view is
    # always derivable from auth's via the documented normalization
    # (strip/lower/rstrip-dot) -- but the two paths do not see ONE
    # normalized string. Candidacy: shared gov/uri_normalize.py.
    url = "https://trusted.example./x"
    assert not _auth_allow("http_post", {"url": url}), "auth must deny"
    assert _auth_view(url) == "trusted.example.", _auth_view(url)
    assert _ioc_view(url) == "trusted.example", _ioc_view(url)
    assert _ioc_view(url) == _auth_view(url).strip().lower().rstrip(".")
    assert _registry().match_host("trusted.example.") is not None
    return ("PIN: auth denies trailing-dot host; IoC normalizes the dot "
            "away and hits -- no shared normalizer (fail-closed on auth)")


def _probe_denied_leading_whitespace():
    # PIN (held behavior -- documents the gap): auth sees
    # ' trusted.example' and DENIES (fail-closed); the IoC path strips
    # surrounding whitespace and match_host HITS 'trusted.example'.
    # Same candidacy note as the trailing-dot PIN.
    url = "https:// trusted.example/x"
    assert not _auth_allow("http_post", {"url": url}), "auth must deny"
    assert _auth_view(url) == " trusted.example", _auth_view(url)
    assert _ioc_view(url) == "trusted.example", _ioc_view(url)
    assert _ioc_view(url) == _auth_view(url).strip().lower().rstrip(".")
    assert _registry().match_host("  trusted.example  ") is not None
    return ("PIN: auth denies whitespace-padded host; IoC strips and "
            "hits -- no shared normalizer (fail-closed on auth)")


def _probe_denied_idna_raw():
    url = "https://münchen.example/x"
    assert not _auth_allow("http_post", {"url": url}), "auth must deny"
    assert _auth_view(url) == _ioc_view(url), \
        "DIVERGENCE: auth sees %r, IoC sees %r" % (_auth_view(url),
                                                  _ioc_view(url))
    return "auth and IoC see one normalized string"


# ---------------------------------------------------------------- (c)

def _probe_normalize_idempotent():
    f = _jwks._normalize_host
    for h in ("TRUSTED.EXAMPLE.", "münchen.example", "a.b.example"):
        assert f(f(h)) == f(h), h
    n = "  TRUSTED.EXAMPLE. "
    once = n.strip().lower().rstrip(".")
    assert once.strip().lower().rstrip(".") == once
    return "both normalizers are idempotent"


def _probe_normalize_case_fold():
    assert _jwks._normalize_host("TRUSTED.EXAMPLE") == "trusted.example"
    assert _registry().match_host("TRUSTED.EXAMPLE") is not None
    return "case folds identically on both paths"


def _probe_normalize_trailing_dot():
    assert _jwks._normalize_host("trusted.example.") == "trusted.example"
    assert _registry().match_host("trusted.example.") is not None
    return "single trailing dot stripped on both paths"


def _probe_normalize_idna():
    assert _jwks._normalize_host("münchen.example") == \
        "xn--mnchen-3ya.example"
    return "jwks normalizer IDNA-encodes unicode labels"


def _probe_normalize_no_pct_decode():
    # Boundary pin: hostnames must not carry %-encoding; neither the
    # urlparse-based paths nor _normalize_host decode it.
    assert _jwks._normalize_host("%74rusted.example") == "%74rusted.example"
    assert urlparse("https://%74rusted.example/x").hostname == \
        "%74rusted.example"
    return "no percent-decoding in host identity (fail-closed)"


def _probe_normalize_match_host_no_idna():
    reg = _CR()
    reg._by_host["xn--mnchen-3ya.example"] = {"kind": "hostname",
                                             "value": "xn--mnchen-3ya.example"}
    assert reg.match_host("münchen.example") is None, \
        "DIVERGENCE: canary match_host does not IDNA-encode while " \
        "jwks _normalize_host does"
    return "canary match_host skips IDNA (diverges from jwks)"


def _probe_normalize_dlp_single_decode():
    # DLP path segments decode exactly one layer: %256a -> %6a, not 'j'.
    assert unquote("%256a") == "%6a", unquote("%256a")
    assert unquote("%6a") == "j", unquote("%6a")
    return "DLP-relevant decoding is single-layer (no recursive decode)"


_PROBES = {
    "agree-plain-host": (_probe_agree_plain_host, HAVE_ALL),
    "agree-mixed-case-host": (_probe_agree_mixed_case_host, HAVE_ALL),
    "agree-userinfo-legit": (_probe_agree_userinfo_legit, HAVE_ALL),
    "agree-encoded-path": (_probe_agree_encoded_path, HAVE_ALL),
    "agree-double-encoded-path": (_probe_agree_double_encoded_path,
                                  HAVE_ALL),
    "agree-send-email": (_probe_agree_send_email, HAVE_ALL),
    "denied-userinfo-evil": (_probe_denied_userinfo_evil, HAVE_ALL),
    "denied-pct-encoded-host": (_probe_denied_pct_encoded_host, HAVE_ALL),
    "denied-trailing-dot": (_probe_denied_trailing_dot, HAVE_ALL),
    "denied-leading-whitespace": (_probe_denied_leading_whitespace,
                                  HAVE_ALL),
    "denied-idna-raw": (_probe_denied_idna_raw, HAVE_ALL),
    "normalize-idempotent": (_probe_normalize_idempotent, HAVE_ALL),
    "normalize-case-fold": (_probe_normalize_case_fold, HAVE_ALL),
    "normalize-trailing-dot": (_probe_normalize_trailing_dot, HAVE_ALL),
    "normalize-idna": (_probe_normalize_idna, HAVE_ALL),
    "normalize-no-pct-decode": (_probe_normalize_no_pct_decode, HAVE_ALL),
    "normalize-match-host-no-idna": (_probe_normalize_match_host_no_idna,
                                     HAVE_ALL),
    "normalize-dlp-single-decode": (_probe_normalize_dlp_single_decode,
                                    HAVE_ALL),
}


def _run_green_checks():
    """Depth-1 green checks (never spawns another battery's main).

    Honors GOV_SKIP_GREEN=1.
    """
    notes = []
    if GREEN_SKIP:
        notes.append("green checks skipped (GOV_SKIP_GREEN=1)")
        return notes
    import subprocess  # noqa: PLC0415
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    root = os.path.join(os.path.dirname(__file__), "..")
    for mod in ("tests.test_jwks_fetch", "tests.test_canary_fragments"):
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", mod, "-v"],
            cwd=root, env=env, capture_output=True, text=True, timeout=300)
        notes.append("unit %s rc=%d" % (mod, proc.returncode))
        if proc.returncode != 0:
            notes.append("unit tail: %s" % (proc.stderr[-400:],))
    return notes


def main():
    print("wave-246 uri-normalization probes (all modules: %s)" % (HAVE_ALL,))
    results = []
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        results.append((name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    held = sum(1 for _n, s, _d in results if s == "HELD")
    brk = sum(1 for _n, s, _d in results if s == "BREAK")
    err = sum(1 for _n, s, _d in results if s == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(results, brk, held, err)
    probe_lines.emit(results)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (brk, held, err))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
