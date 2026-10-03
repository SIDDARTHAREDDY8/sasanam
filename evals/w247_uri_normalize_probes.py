"""Wave-247 shared URI-normalizer probes (red-first).

W247-1: build ``gov/uri_normalize.py`` -- ONE canonical host
normalization used by executor, simulator, canary, jwks_fetch,
egress_ledger, and sentinel_substitution, so the auth path and the
IoC path always see the byte-identical host string. (W246-4 proved the
sites diverged; this lane unifies them.)

Canonical form: strip surrounding whitespace -> lowercase -> strip
trailing dots -> IDNA-encode to ASCII. Fail-closed: unparseable or
un-normalizable inputs raise ``UriNormalizeError`` with a taxonomy
code.

Explicit behavior changes vs. pre-W247 (all tested here, none silent):
- trailing-dot FQDNs (``trusted.example.``) now normalize to the bare
  name and ALLOW when allowlisted (DNS-correct; previously denied).
- whitespace-padded hosts (`` trusted.example``) now strip and ALLOW
  when allowlisted (previously denied). Safe: no DNS resolver maps a
  whitespace-padded name to a different host.
- unicode hosts now IDNA-encode; the allowlist is normalized through
  the same function, so unicode/unicode, punycode/punycode, and mixed
  pairs compare correctly (previously unicode-vs-punycode was a
  false-negative deny).

Stdlib only. Deterministic. No in-repo git subprocesses.
"""

import os
import sys
import traceback
import types

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_NORM = False
try:
    from gov import uri_normalize as _un
    HAVE_NORM = all(
        hasattr(_un, n) for n in (
            "normalize_host", "normalize_url_host",
            "normalize_email_host", "UriNormalizeError"))
except ImportError:
    _un = None

HAVE_EXEC = HAVE_CANARY = False
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

HAVE_ALL = HAVE_NORM and HAVE_EXEC and HAVE_CANARY

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

ALLOWLIST = ["trusted.example"]
ALLOWLIST_IDNA = ["xn--mnchen-3ya.example"]
ALLOWLIST_UNICODE = ["m\u00fcnchen.example"]


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
    return types.SimpleNamespace(
        policy=types.SimpleNamespace(
            egress={"domain_allowlist": list(allowlist)}))


def _auth_allow(tool, args, allowlist=ALLOWLIST):
    return bool(_TE._domain_allowlisted(
        _stub_executor(allowlist), tool, args))


# ------------------------------------------------------- canonical form

def _probe_norm_strip_lower_dot():
    assert _un.normalize_host("  TRUSTED.EXAMPLE. ") == "trusted.example"
    assert _un.normalize_host("trusted.example") == "trusted.example"
    assert _un.normalize_host("a.b.example..") == "a.b.example"
    return "strip/lower/dot-strip canonical"


def _probe_norm_idna():
    assert _un.normalize_host("m\u00fcnchen.example") == \
        "xn--mnchen-3ya.example"
    assert _un.normalize_host("XN--MNCHEN-3YA.EXAMPLE") == \
        "xn--mnchen-3ya.example"
    return "unicode labels IDNA-encode to punycode"


def _probe_norm_no_pct_decode():
    # Boundary: %-encoding is never decoded in host identity.
    assert _un.normalize_host("%74rusted.example") == "%74rusted.example"
    return "no percent-decoding in host identity"


def _probe_norm_idempotent():
    for h in ("  TRUSTED.EXAMPLE. ", "m\u00fcnchen.example",
              "a.b.example", "%74rusted.example"):
        once = _un.normalize_host(h)
        assert _un.normalize_host(once) == once, h
    return "normalizer is idempotent"


def _probe_norm_empty_refused():
    for bad in ("", "   ", ".", "..."):
        try:
            _un.normalize_host(bad)
        except _un.UriNormalizeError as exc:
            assert exc.code, "error must carry a taxonomy code"
        else:
            raise AssertionError("expected refusal for %r" % (bad,))
    return "empty/dot-only hosts refuse fail-closed with a code"


def _probe_norm_nonstring_refused():
    try:
        _un.normalize_host(None)
    except _un.UriNormalizeError as exc:
        assert exc.code
    else:
        raise AssertionError("expected refusal for None")
    return "non-string host refuses fail-closed"


def _probe_url_host():
    assert _un.normalize_url_host(
        "https://trusted.example./x") == "trusted.example"
    assert _un.normalize_url_host(
        "https://user:pass@TRUSTED.EXAMPLE/x") == "trusted.example"
    assert _un.normalize_url_host(
        "https://m\u00fcnchen.example/x") == "xn--mnchen-3ya.example"
    return "URL host extraction normalizes through the canonical form"


def _probe_url_malformed_refused():
    for bad in ("not a url", "", "https://", "https:///x"):
        try:
            _un.normalize_url_host(bad)
        except _un.UriNormalizeError as exc:
            assert exc.code
        else:
            raise AssertionError("expected refusal for %r" % (bad,))
    return "malformed URLs refuse fail-closed with a code"


def _probe_email_host():
    assert _un.normalize_email_host(
        "ops@trusted.example") == "trusted.example"
    assert _un.normalize_email_host(
        "Ops@TRUSTED.EXAMPLE.") == "trusted.example"
    try:
        _un.normalize_email_host("not-an-email")
    except _un.UriNormalizeError as exc:
        assert exc.code
    else:
        raise AssertionError("expected refusal for missing @")
    return "email host extraction normalizes; missing @ refuses"


# ------------------------------------------------- auth/ioc agreement

def _probe_agree_all_sites():
    # The core W247-1 goal: every site sees the byte-identical string.
    for url, expect in (
            ("https://trusted.example/x", "trusted.example"),
            ("https://TRUSTED.EXAMPLE./x", "trusted.example"),
            ("https://m\u00fcnchen.example/x", "xn--mnchen-3ya.example"),
    ):
        norm = _un.normalize_url_host(url)
        assert norm == expect, (url, norm, expect)
    return "auth and IoC derive the byte-identical host string"


def _probe_flip_trailing_dot_explicit():
    # EXPLICIT flip (W246-4 PIN denied-trailing-dot): DNS-correct --
    # ``trusted.example.`` IS ``trusted.example`` -- so allow when
    # allowlisted. Previously denied; now allowed by design.
    assert _auth_allow(
        "http_post", {"url": "https://trusted.example./x"}), \
        "trailing-dot must now ALLOW when the bare name is allowlisted"
    return "EXPLICIT: trailing-dot deny -> allow (DNS-correct)"


def _probe_flip_whitespace_explicit():
    # EXPLICIT flip (W246-4 PIN denied-leading-whitespace): strip and
    # allow when allowlisted. Safe: no resolver maps a padded name to
    # a different host. Previously denied; now allowed by design.
    assert _auth_allow(
        "http_post", {"url": "https:// trusted.example/x"}), \
        "whitespace-padded must now ALLOW when stripped name allowlisted"
    return "EXPLICIT: whitespace deny -> allow (documented)"


def _probe_flip_idna_explicit():
    # EXPLICIT flip: punycode-allowlisted + unicode request now allows
    # (previously a false-negative deny).
    assert _auth_allow(
        "http_post", {"url": "https://m\u00fcnchen.example/x"},
        ALLOWLIST_IDNA), \
        "unicode request must ALLOW when punycode form is allowlisted"
    return "EXPLICIT: unicode-vs-punycode deny -> allow (documented)"


def _probe_preserve_unicode_allowlist():
    # No flip: unicode allowlist + unicode request still allows --
    # both sides normalize through the same function.
    assert _auth_allow(
        "http_post", {"url": "https://m\u00fcnchen.example/x"},
        ALLOWLIST_UNICODE)
    assert _auth_allow(
        "http_post",
        {"url": "https://xn--mnchen-3ya.example/x"},
        ALLOWLIST_UNICODE)
    return "unicode allowlist keeps allowing both forms"


def _probe_deny_evil():
    assert not _auth_allow("http_post", {"url": "https://evil.example/x"})
    assert not _auth_allow(
        "http_post", {"url": "https://trusted.example.evil.example/x"})
    assert not _auth_allow(
        "http_post", {"url": "https://evil-trusted.example/x"})
    return "non-allowlisted hosts still deny (incl. suffix lookalikes)"


def _probe_subdomain_preserved():
    # Executor suffix semantics preserved: subdomains of an allowlisted
    # domain still allow.
    assert _auth_allow(
        "http_post", {"url": "https://sub.trusted.example/x"})
    return "subdomain suffix matching preserved"


def _probe_send_email():
    assert _auth_allow("send_email", {"to": "ops@trusted.example"})
    assert _auth_allow("send_email", {"to": "ops@TRUSTED.EXAMPLE."})
    assert not _auth_allow("send_email", {"to": "ops@evil.example"})
    return "send_email host derivation uses the canonical form"


def _probe_canary_rewired():
    # CanaryRegistry.match_host must see the canonical form too.
    reg = _CR()
    reg._by_host["trusted.example"] = {"kind": "hostname",
                                       "value": "trusted.example"}
    assert reg.match_host("  TRUSTED.EXAMPLE. ") is not None
    assert reg.match_host("evil.example") is None
    return "canary match_host normalizes through the shared function"


def _probe_error_codes_in_taxonomy():
    # Every refusal code the module can raise must be a real taxonomy
    # code.
    from gov import decision_codes
    for code in ("uri-host-invalid", "uri-host-unparseable"):
        assert code in decision_codes.TAXONOMY, code
    return "refusal codes are registered taxonomy codes"


_PROBES = {
    "norm-strip-lower-dot": (_probe_norm_strip_lower_dot, HAVE_ALL),
    "norm-idna": (_probe_norm_idna, HAVE_ALL),
    "norm-no-pct-decode": (_probe_norm_no_pct_decode, HAVE_ALL),
    "norm-idempotent": (_probe_norm_idempotent, HAVE_ALL),
    "norm-empty-refused": (_probe_norm_empty_refused, HAVE_ALL),
    "norm-nonstring-refused": (_probe_norm_nonstring_refused, HAVE_ALL),
    "url-host": (_probe_url_host, HAVE_ALL),
    "url-malformed-refused": (_probe_url_malformed_refused, HAVE_ALL),
    "email-host": (_probe_email_host, HAVE_ALL),
    "agree-all-sites": (_probe_agree_all_sites, HAVE_ALL),
    "flip-trailing-dot-explicit": (_probe_flip_trailing_dot_explicit,
                                   HAVE_ALL),
    "flip-whitespace-explicit": (_probe_flip_whitespace_explicit, HAVE_ALL),
    "flip-idna-explicit": (_probe_flip_idna_explicit, HAVE_ALL),
    "preserve-unicode-allowlist": (_probe_preserve_unicode_allowlist,
                                   HAVE_ALL),
    "deny-evil": (_probe_deny_evil, HAVE_ALL),
    "subdomain-preserved": (_probe_subdomain_preserved, HAVE_ALL),
    "send-email": (_probe_send_email, HAVE_ALL),
    "canary-rewired": (_probe_canary_rewired, HAVE_ALL),
    "error-codes-in-taxonomy": (_probe_error_codes_in_taxonomy, HAVE_ALL),
}

PROBE_NAMES = list(_PROBES)


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
    for mod in ("tests.test_uri_normalize", "tests.test_canary_fragments",
                "tests.test_jwks_fetch"):
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", mod],
            cwd=root, env=env, capture_output=True, text=True, timeout=300)
        notes.append("unit %s rc=%d" % (mod, proc.returncode))
        if proc.returncode != 0:
            notes.append("unit tail: %s" % (proc.stderr[-500:],))
    return notes


def main():
    print("wave-247 uri_normalize probes (shared module: %s)" % (HAVE_NORM,))
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
