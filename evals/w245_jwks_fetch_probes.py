"""Wave-245 JWKS redirect-poisoning guard probes (W245-10, red-first).

Attacker shape from GHSA-9v7f-9g4p-ffgj / CVE-2026-102267 (verified
2026-09-30 against github.com/advisories -- ID fetched, never carried
on trust after the wave-243 Harbor fabrication incident):
  PyJWT 2.13.0 PyJWKClient followed HTTP redirects while fetching a
  JWKS, without validating the redirect destination. A configured
  trusted endpoint could therefore redirect the client to a different
  host; the redirected response could be used as authoritative key
  material (JWKS trust poisoning -> forged JWT acceptance). The
  upstream fix (2.14.0) disables automatic redirects: a redirect is
  rejected without contacting its destination.

New primitive (gov/jwks_fetch):
  jwks-redirect-cross-host -- 302 to an attacker host refuses
      jwks-redirect-refused; the destination is never contacted
      (transport called exactly once).
  jwks-redirect-chain-first-hop -- a multi-hop chain refuses at the
      FIRST redirect (transport called exactly once).
  jwks-redirect-same-origin -- a same-origin redirect is STILL
      refused: no redirects, period.
  jwks-redirect-location-on-200 -- a Location header on a 200
      refuses jwks-redirect-refused (defensive; Location on a JWKS
      response is anomalous).
  jwks-origin-mismatch-before-transport -- a request URL whose origin
      differs from the pinned issuer origin refuses
      jwks-origin-mismatch BEFORE any transport call (count == 0).
  jwks-pinned-origin-proceeds -- exact pinned-origin match (with
      default-port normalization) proceeds and returns the body.
  jwks-url-malformed -- relative URL, userinfo in netloc, non-http(s)
      scheme, or empty pinned origin refuses jwks-url-malformed
      (jwks-issuer-unpinned when the pinned origin itself is missing).
  jwks-transport-failure -- a raising deployment transport refuses
      jwks-transport-failed, never treated as key material.

Stdlib only. Deterministic: fake transports, no real network, no
in-repo git subprocesses.
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_JWKS = False
try:
    from gov import jwks_fetch as _jf
    HAVE_JWKS = all(hasattr(_jf, n) for n in (
        "fetch_jwks", "JwksFetchError"))
except ImportError:
    _jf = None


def _run_probe(name, fn, have, pin=False):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, ("PIN" if pin else "HELD"), note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


def _expect_refusal(fn, code):
    try:
        fn()
    except _jf.JwksFetchError as exc:
        assert exc.code == code, "code %r, expected %r" % (exc.code, code)
        return "refused %s" % code
    raise AssertionError("no refusal; expected %s" % code)


class _CountingTransport(object):
    """Fake deployment transport. Records every call; never follows."""

    def __init__(self, script):
        # script: list of (status, headers, body) or Exception instances
        self._script = list(script)
        self.calls = []

    def __call__(self, url, timeout_s):
        self.calls.append((url, timeout_s))
        step = self._script.pop(0) if self._script else (200, [], b"{}")
        if isinstance(step, Exception):
            raise step
        return step


_PINNED = "https://idp.example"
_PINNED_URL = "https://idp.example/.well-known/jwks.json"


def _probe_redirect_cross_host():
    t = _CountingTransport([
        (302, [("Location", "https://attacker.invalid/jwks.json")], b""),
    ])
    note = _expect_refusal(
        lambda: _jf.fetch_jwks(_PINNED, _PINNED_URL, t),
        "jwks-redirect-refused")
    assert len(t.calls) == 1, \
        "redirect destination must never be contacted, calls=%r" % (t.calls,)
    return "%s; destination never contacted" % note


def _probe_redirect_chain_first_hop():
    t = _CountingTransport([
        (302, [("location", "https://idp.example/step2")], b""),
        (302, [("Location", "https://attacker.invalid/final")], b""),
    ])
    note = _expect_refusal(
        lambda: _jf.fetch_jwks(_PINNED, _PINNED_URL, t),
        "jwks-redirect-refused")
    assert len(t.calls) == 1, \
        "chain must refuse at first redirect, calls=%r" % (t.calls,)
    return "%s; refused at first hop" % note


def _probe_redirect_same_origin():
    t = _CountingTransport([
        (301, [("Location", "https://idp.example/moved.json")], b""),
    ])
    note = _expect_refusal(
        lambda: _jf.fetch_jwks(_PINNED, _PINNED_URL, t),
        "jwks-redirect-refused")
    return "%s; same-origin redirect still refused" % note


def _probe_location_on_200():
    t = _CountingTransport([
        (200, [("Location", "https://idp.example/other.json")],
         b'{"keys":[]}'),
    ])
    note = _expect_refusal(
        lambda: _jf.fetch_jwks(_PINNED, _PINNED_URL, t),
        "jwks-redirect-refused")
    return "%s; Location on 200 treated as redirect" % note


def _probe_origin_mismatch_before_transport():
    t = _CountingTransport([(200, [], b'{"keys":[]}')])
    note = _expect_refusal(
        lambda: _jf.fetch_jwks(_PINNED, "https://other.example/jwks", t),
        "jwks-origin-mismatch")
    assert len(t.calls) == 0, \
        "mismatched origin must refuse before any transport call"
    note2 = _expect_refusal(
        lambda: _jf.fetch_jwks(_PINNED, "http://idp.example/jwks", t),
        "jwks-origin-mismatch")
    assert len(t.calls) == 0
    return "%s; %s; no transport calls" % (note, note2)


def _probe_pinned_origin_proceeds():
    t = _CountingTransport([(200, [], b'{"keys":[{"kty":"RSA"}]}')])
    body = _jf.fetch_jwks(_PINNED, _PINNED_URL, t)
    assert body == b'{"keys":[{"kty":"RSA"}]}', "body mismatch: %r" % (body,)
    # default-port normalization: :443 must equal the pinned bare origin
    t2 = _CountingTransport([(200, [], b"{}")])
    body2 = _jf.fetch_jwks(_PINNED, "https://idp.example:443/jwks.json", t2)
    assert body2 == b"{}", "default-port normalization failed"
    assert len(t.calls) == 1 and len(t2.calls) == 1
    return "body returned; :443 == bare origin"


def _probe_url_malformed():
    t = _CountingTransport([(200, [], b"{}")])
    note = _expect_refusal(
        lambda: _jf.fetch_jwks(_PINNED, "/relative/jwks.json", t),
        "jwks-url-malformed")
    note2 = _expect_refusal(
        lambda: _jf.fetch_jwks(_PINNED, "https://user:pw@idp.example/j", t),
        "jwks-url-malformed")
    note3 = _expect_refusal(
        lambda: _jf.fetch_jwks(_PINNED, "ftp://idp.example/jwks", t),
        "jwks-url-malformed")
    note4 = _expect_refusal(
        lambda: _jf.fetch_jwks("", _PINNED_URL, t),
        "jwks-issuer-unpinned")
    assert len(t.calls) == 0, "malformed input must never reach transport"
    return "; ".join((note, note2, note3, note4))


def _probe_transport_failure():
    t = _CountingTransport([ConnectionError("down")])
    note = _expect_refusal(
        lambda: _jf.fetch_jwks(_PINNED, _PINNED_URL, t),
        "jwks-transport-failed")
    return "%s; never treated as key material" % note


_PROBES = [
    ("jwks-redirect-cross-host", _probe_redirect_cross_host,
     "HAVE_JWKS", False),
    ("jwks-redirect-chain-first-hop", _probe_redirect_chain_first_hop,
     "HAVE_JWKS", False),
    ("jwks-redirect-same-origin", _probe_redirect_same_origin,
     "HAVE_JWKS", False),
    ("jwks-redirect-location-on-200", _probe_location_on_200,
     "HAVE_JWKS", False),
    ("jwks-origin-mismatch-before-transport",
     _probe_origin_mismatch_before_transport, "HAVE_JWKS", False),
    ("jwks-pinned-origin-proceeds", _probe_pinned_origin_proceeds,
     "HAVE_JWKS", False),
    ("jwks-url-malformed", _probe_url_malformed, "HAVE_JWKS", False),
    ("jwks-transport-failure", _probe_transport_failure,
     "HAVE_JWKS", False),
]


def main():
    # This battery spawns no nested green-check subprocesses, so the
    # probes must always run -- a GOV_SKIP_GREEN early return would make
    # the battery a vacuous pass depth-1 (wave-244 merge lesson).
    flags = {"HAVE_JWKS": HAVE_JWKS}
    results = []
    for name, fn, flag, pin in _PROBES:
        results.append(_run_probe(name, fn, flags[flag], pin=pin))
    held = sum(1 for _, s, _ in results if s in ("HELD", "PIN"))
    total = len(results)
    for name, status, note in results:
        print("%-42s %-6s %s" % (name, status, note.split("\n")[0]))
    print("w245_jwks_fetch: %d/%d HELD-or-PIN" % (held, total))
    return 0 if held == total else 2


if __name__ == "__main__":
    sys.exit(main())
