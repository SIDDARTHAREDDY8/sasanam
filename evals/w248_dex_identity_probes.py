#!/usr/bin/env python3
"""Wave-248 lane 5: dex-shaped federated identity probes.

ADAPTED (patterns only) from dex's connector model (dexidp/dex, Apache-2.0,
Go -- not vendored): (1) connector claim normalization -- upstream IdPs
(OIDC, static) normalized into ONE claim set regardless of who vouched for
the agent; (2) short-lived identity tokens + refresh rotation (no
long-lived agent secrets); (3) groups claim carried for the grant graph.
The SAML connector stays OFF (unmaintained upstream) and must refuse.

Probes (all fail-closed expectations):

  missing-subject-refused    -- OIDC claims without sub -> refused
                                (identity-claims-missing-subject)
  ambiguous-mapping-refused  -- sub and uid both present and disagree ->
                                refused (identity-claims-ambiguous)
  expired-token-refused      -- token with exp in the past -> refused
                                (identity-token-expired)
  wrong-audience-refused     -- verify under a different audience ->
                                refused (identity-token-audience-mismatch)
  tampered-token-refused     -- flipped payload byte -> refused
                                (identity-token-tampered)
  saml-refused               -- connector "saml" -> refused
                                (identity-connector-unsupported)
  refresh-lifetime-capped    -- refresh re-issues a SHORT token (never the
                                refresh token's long lifetime); reuse of a
                                rotated refresh token -> reuse detected and
                                the whole chain revoked.

Red-first: on pristine base the capability is absent and every probe
reports GAP. Stdlib only. Deterministic (fixed keys, injected clock, no
randomness in assertions). No in-repo git subprocesses.
"""

import base64
import json
import os
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_ai = None
try:
    from gov import agent_identity as _ai
except ImportError:
    _ai = None

NEED = ("normalize_claims", "ClaimNormalizationError",
        "IdentityTokenIssuer", "IdentityTokenRejection",
        "RefreshTokenStore")
HAVE_DEX = _ai is not None and all(hasattr(_ai, n) for n in NEED)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

PROBE_NAMES = [
    "missing-subject-refused",
    "ambiguous-mapping-refused",
    "expired-token-refused",
    "wrong-audience-refused",
    "tampered-token-refused",
    "saml-refused",
    "refresh-lifetime-capped",
]

_FIXED_KEY = b"k" * 32
_FIXED_NOW = 1_800_000_000


def _oidc_claims(**over):
    claims = {"sub": "agent-7", "email": "agent-7@example.com",
              "email_verified": True, "groups": ["ops", "readers"]}
    claims.update(over)
    return claims


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on base"
    try:
        note = fn()
    except AssertionError as e:
        return name, "GAP", "not held: %s" % (e,)
    except Exception as e:  # noqa: BLE001 -- probe must not crash
        return name, "GAP", "errored: %r" % (e,)
    return name, "HELD", note


def _expect_code(call, code):
    try:
        call()
    except _ai.IdentityTokenRejection as e:
        assert e.code == code, \
            "got code %r, want %r (%s)" % (e.code, code, e.detail)
        return "refused %s" % code
    except _ai.ClaimNormalizationError as e:
        assert e.code == code, \
            "got code %r, want %r (%s)" % (e.code, code, e.detail)
        return "refused %s" % code
    raise AssertionError("no refusal raised (want %s)" % code)


def _probe_missing_subject_refused():
    claims = _oidc_claims()
    del claims["sub"]
    return _expect_code(
        lambda: _ai.normalize_claims(claims, "oidc"),
        "identity-claims-missing-subject")


def _probe_ambiguous_mapping_refused():
    claims = _oidc_claims(uid="someone-else")
    return _expect_code(
        lambda: _ai.normalize_claims(claims, "oidc"),
        "identity-claims-ambiguous")


def _issue(aud="agents", iat=_FIXED_NOW, lifetime=300, **kw):
    issuer = _ai.IdentityTokenIssuer(_FIXED_KEY, time_fn=lambda: _FIXED_NOW)
    ident = _ai.normalize_claims(_oidc_claims(), "oidc")
    return issuer, issuer.issue(ident, aud, lifetime_seconds=lifetime,
                               now=iat, **kw)


def _probe_expired_token_refused():
    issuer, token = _issue(iat=_FIXED_NOW - 10_000, lifetime=300)
    return _expect_code(
        lambda: issuer.verify_token(token, "agents", now=_FIXED_NOW),
        "identity-token-expired")


def _probe_wrong_audience_refused():
    issuer, token = _issue(aud="agents")
    return _expect_code(
        lambda: issuer.verify_token(token, "other-service", now=_FIXED_NOW),
        "identity-token-audience-mismatch")


def _b64url_decode(part):
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _probe_tampered_token_refused():
    issuer, token = _issue()
    head, sig = token.split(".")
    body = json.loads(_b64url_decode(head).decode("utf-8"))
    body["sub"] = "attacker"
    raw = base64.urlsafe_b64encode(
        json.dumps(body, sort_keys=True,
                   separators=(",", ":")).encode()).decode().rstrip("=")
    forged = raw + "." + sig
    return _expect_code(
        lambda: issuer.verify_token(forged, "agents", now=_FIXED_NOW),
        "identity-token-tampered")


def _probe_saml_refused():
    return _expect_code(
        lambda: _ai.normalize_claims(_oidc_claims(), "saml"),
        "identity-connector-unsupported")


def _probe_refresh_lifetime_capped():
    issuer = _ai.IdentityTokenIssuer(_FIXED_KEY, time_fn=lambda: _FIXED_NOW)
    store = _ai.RefreshTokenStore(time_fn=lambda: _FIXED_NOW)
    ident = _ai.normalize_claims(_oidc_claims(), "oidc")
    rid, secret = store.mint_refresh(ident, "oidc", _oidc_claims(),
                                     lifetime_seconds=86_400)
    token, rid2, secret2 = store.refresh(issuer, rid, secret, "agents")
    got = issuer.verify_token(token, "agents", now=_FIXED_NOW)
    lifetime = got["exp"] - got["iat"]
    assert lifetime <= 3_600, \
        "refreshed identity token lives %ds (want <= 3600)" % lifetime
    assert lifetime <= 300 + 1, \
        "refreshed identity token lives %ds (want the short default)" \
        % lifetime
    # Rotation: the old refresh token is now spent. Reusing it must
    # refuse AND revoke the whole chain (dex reuse detection).
    try:
        store.refresh(issuer, rid, secret, "agents")
    except _ai.IdentityTokenRejection as e:
        assert e.code == "identity-refresh-reuse-detected", \
            "got %r" % e.code
    else:
        raise AssertionError("reused refresh token was accepted")
    # The chain is revoked: even the newest refresh token now fails.
    try:
        store.refresh(issuer, rid2, secret2, "agents")
    except _ai.IdentityTokenRejection as e:
        assert e.code == "identity-refresh-revoked", "got %r" % e.code
    else:
        raise AssertionError("post-reuse chain was not revoked")
    return "refreshed token short; reuse detected; chain revoked"


_PROBES = {name: (globals()["_probe_" + name.replace("-", "_")],
                  HAVE_DEX)
           for name in PROBE_NAMES}


def _run_green_checks():
    """Depth-1 green checks (never spawns another battery's main).

    Honors GOV_SKIP_GREEN=1 (never spawns another battery's main).
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
    for suite in ("tests.test_dex_identity", "tests.test_agent_identity"):
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", suite],
            cwd=root, env=env, capture_output=True, text=True,
            timeout=300)
        notes.append("unit %s rc=%d" % (suite, proc.returncode))
        if proc.returncode != 0:
            notes.append("unit tail: %s" % (proc.stderr[-400:],))
    return notes


def main():
    print("wave-248 dex-identity probes (dex=%s)" % (HAVE_DEX,))
    held = gap = 0
    for name in PROBE_NAMES:
        fn, have = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, have)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-28s %s %s" % (name_r, status, note))
    notes = _run_green_checks()
    for note in notes:
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
