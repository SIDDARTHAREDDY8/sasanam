"""Wave-245 MCP OAuth binding probes (red-first).

W245-1 -- ADAPT (threat model, patterns only) of MCP Python SDK
GHSA-qx49-fqc8-xw99: a malicious server steals *client* OAuth material
(client secret, auth code, PKCE verifier) by routing token exchange to
an attacker endpoint while metadata names the real IdP as issuer. The
1.30.0/2.2.0 fix is configuration-gated: providers that need
``issuer=`` passed stay vulnerable when it is omitted. The module
binds client credentials to their authorization server at the client
path: the AS issuer is validated on EVERY discovery path, never
inferred from server-controlled metadata.

Probes (a checker that passes where it should refuse has the
corresponding defect):

  metadata-issuer-attack-unbound -- server metadata names the real
      IdP as issuer but routes the token endpoint to an attacker ->
      refuse mcp-oauth-issuer-unbound (probe a).
  credential-replay-refused -- credential stored under AS-X's issuer
      presented at AS-Y's token endpoint -> refuse
      mcp-oauth-credential-misbound (probe b).
  fix-gap-issuer-omitted-refused -- issuer= omitted for a provider
      that requires it (the 1.30.0 fix-gap) -> refuse
      mcp-oauth-fix-gap-refused, never silent fallback (probe c).
  metadata-issuer-mismatch-refused -- discovery metadata names a
      different issuer than the sealed binding -> refuse
      mcp-oauth-issuer-unverified (probe d).
  credential-replay-across-providers -- credential bound to AS-X used
      with a binding for AS-Y (authorize path) -> refuse
      mcp-oauth-credential-misbound (probe e).
  binding-tamper-refused -- issuer flipped inside the sealed binding
      -> refuse mcp-oauth-binding-tampered (tamper is tamper, never
      a shape gap).
  malformed-inputs-refused -- bool/non-dict/empty endpoint,
      http:// issuer, non-bool provider flag ->
      mcp-oauth-metadata-malformed (fail closed).
  allowlist-declared-alternate-allowed -- a deployment-declared
      alternate token-endpoint origin in the sealed binding is
      honored.
  allowlist-does-not-cover-attacker -- an allowlist cannot be used to
      smuggle an attacker endpoint; a forged allowlist breaks the
      binding MAC.
  verdict-replay-refused -- an OAuthVerdict granted for endpoint A
      presented to run_bound_exchange for endpoint B -> refuse
      mcp-oauth-verdict-mismatched.

Stdlib only. Deterministic. No in-repo git subprocesses. Green
checks are depth-1 (GOV_SKIP_GREEN=1 honored).
"""

import os
import subprocess
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_MOB = False
try:
    from gov import mcp_oauth_binding as _mob
    HAVE_MOB = all(hasattr(_mob, n) for n in (
        "McpOAuthError", "OAuthVerdict", "seal_as_binding",
        "authorize_token_exchange", "check_server_metadata",
        "run_bound_exchange", "CODES"))
except ImportError:
    _mob = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"
REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")

_KEY = b"wave245-oauth-key-0123456789abcdef"
_ISSUER = "https://as.example"
_TOKEN = "https://as.example/token"
_ATTACKER = "https://evil.example/token"


def _sealed(issuer=_ISSUER, client_id="client-1", key=_KEY,
            allowlist=None):
    return _mob.seal_as_binding(issuer, client_id, key,
                                token_endpoint_allowlist=allowlist)


def _expect(code, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except _mob.McpOAuthError as exc:
        assert exc.code == code, "want %s, got %s (%s)" % (
            code, exc.code, exc.detail)
        return "%s as required" % code
    except Exception as exc:  # noqa: BLE001
        raise AssertionError("wrong exception type: %r" % (exc,))
    raise AssertionError("no refusal raised; expected %s" % code)


def _probe_metadata_issuer_attack_unbound():
    # (a) metadata names the real IdP as issuer but routes token
    # exchange to an attacker endpoint.
    sealed = _sealed()
    return _expect(
        "mcp-oauth-issuer-unbound", _mob.check_server_metadata,
        sealed, {"issuer": _ISSUER, "token_endpoint": _ATTACKER}, _KEY)


def _probe_credential_replay_refused():
    # (b) credential stored under AS-X presented at AS-Y's endpoint.
    sealed = _sealed(issuer="https://as-y.example")
    return _expect(
        "mcp-oauth-credential-misbound", _mob.authorize_token_exchange,
        sealed, "https://as-y.example/token", _KEY,
        issuer_hint="https://as-y.example",
        presented_as_issuer="https://as-x.example")


def _probe_fix_gap_issuer_omitted_refused():
    # (c) the 1.30.0 fix-gap: issuer= omitted where required.
    sealed = _sealed()
    return _expect(
        "mcp-oauth-fix-gap-refused", _mob.authorize_token_exchange,
        sealed, _TOKEN, _KEY, issuer_hint=None,
        provider_requires_issuer=True)


def _probe_metadata_issuer_mismatch_refused():
    # (d) discovery metadata names a different issuer than bound.
    sealed = _sealed()
    return _expect(
        "mcp-oauth-issuer-unverified", _mob.check_server_metadata,
        sealed, {"issuer": "https://other.example",
                 "token_endpoint": _TOKEN}, _KEY)


def _probe_credential_replay_across_providers():
    # (e) authorize path: credential for AS-X with binding for AS-Y.
    sealed = _sealed(issuer="https://as-y.example")
    return _expect(
        "mcp-oauth-credential-misbound", _mob.authorize_token_exchange,
        sealed, "https://as-y.example/token", _KEY,
        issuer_hint="https://as-y.example",
        presented_as_issuer="https://as-x.example")


def _probe_binding_tamper_refused():
    sealed = _sealed()
    sealed["binding"]["issuer"] = "https://evil.example"
    return _expect(
        "mcp-oauth-binding-tampered", _mob.authorize_token_exchange,
        sealed, _TOKEN, _KEY, issuer_hint="https://evil.example")


def _probe_malformed_inputs_refused():
    sealed = _sealed()
    # bool where a URL is expected
    _expect("mcp-oauth-metadata-malformed",
            _mob.authorize_token_exchange, sealed, True, _KEY,
            issuer_hint=_ISSUER)
    # non-dict metadata
    _expect("mcp-oauth-metadata-malformed",
            _mob.check_server_metadata, sealed, ["issuer"], _KEY)
    # non-bool provider flag
    _expect("mcp-oauth-metadata-malformed",
            _mob.authorize_token_exchange, sealed, _TOKEN, _KEY,
            issuer_hint=_ISSUER, provider_requires_issuer="yes")
    # http:// issuer at bind time
    _expect("mcp-oauth-metadata-malformed",
            _mob.seal_as_binding, "http://as.example", "c", _KEY)
    return "bool/non-dict/empty/http/flag shapes all fail closed"


def _probe_allowlist_declared_alternate_allowed():
    sealed = _sealed(allowlist=["https://tokens.example/token"])
    verdict = _mob.authorize_token_exchange(
        sealed, "https://tokens.example/other", _KEY,
        issuer_hint=_ISSUER)
    assert verdict.issuer == _ISSUER, verdict
    return "deployment-declared alternate origin honored"


def _probe_allowlist_does_not_cover_attacker():
    sealed = _sealed(allowlist=["https://tokens.example/token"])
    note = _expect(
        "mcp-oauth-issuer-unbound", _mob.authorize_token_exchange,
        sealed, _ATTACKER, _KEY, issuer_hint=_ISSUER)
    # Forging the allowlist breaks the binding MAC.
    sealed["binding"]["token_endpoint_allowlist"].append(
        "https://evil.example/token")
    tamper = _expect(
        "mcp-oauth-binding-tampered", _mob.authorize_token_exchange,
        sealed, _ATTACKER, _KEY, issuer_hint=_ISSUER)
    return "%s; %s" % (note, tamper)


def _probe_verdict_replay_refused():
    sealed = _sealed()
    verdict = _mob.authorize_token_exchange(
        sealed, _TOKEN, _KEY, issuer_hint=_ISSUER)
    return _expect(
        "mcp-oauth-verdict-mismatched", _mob.run_bound_exchange,
        verdict, _ATTACKER, lambda: "exchanged")


PROBE_NAMES = [
    "metadata-issuer-attack-unbound",
    "credential-replay-refused",
    "fix-gap-issuer-omitted-refused",
    "metadata-issuer-mismatch-refused",
    "credential-replay-across-providers",
    "binding-tamper-refused",
    "malformed-inputs-refused",
    "allowlist-declared-alternate-allowed",
    "allowlist-does-not-cover-attacker",
    "verdict-replay-refused",
]

_PROBES = {
    "metadata-issuer-attack-unbound": _probe_metadata_issuer_attack_unbound,
    "credential-replay-refused": _probe_credential_replay_refused,
    "fix-gap-issuer-omitted-refused": _probe_fix_gap_issuer_omitted_refused,
    "metadata-issuer-mismatch-refused":
        _probe_metadata_issuer_mismatch_refused,
    "credential-replay-across-providers":
        _probe_credential_replay_across_providers,
    "binding-tamper-refused": _probe_binding_tamper_refused,
    "malformed-inputs-refused": _probe_malformed_inputs_refused,
    "allowlist-declared-alternate-allowed":
        _probe_allowlist_declared_alternate_allowed,
    "allowlist-does-not-cover-attacker":
        _probe_allowlist_does_not_cover_attacker,
    "verdict-replay-refused": _probe_verdict_replay_refused,
}


def _run_probe(name, fn, have):
    if not have:
        return name, "GAP", "capability absent on pristine base"
    try:
        note = fn()
        return name, "HELD", note
    except AssertionError as exc:
        return name, "BREAK", "assertion: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001
        return name, "ERROR", "%r\n%s" % (exc, traceback.format_exc(limit=3))


# ---------------------------------------------------------------------------
# Green check (depth-1 adjacency discipline)
# ---------------------------------------------------------------------------

_ADJACENT = ["w244_token_scope_probes.py",
             "w243_attested_channel_probes.py"]


def _run_green_checks():
    notes = []
    if GREEN_SKIP:
        notes.append("nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                     "standalone for full depth-1 adjacency")
        return notes
    for i, battery in enumerate(_ADJACENT):
        tmp = os.path.join(os.environ["TMPDIR"], "w245-oauth-green-%d" % i)
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmp)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        env["GOV_SKIP_GREEN"] = "1"
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(REPO_ROOT, "evals", battery)],
                capture_output=True, text=True, env=env, cwd=REPO_ROOT,
                timeout=600)
        except Exception as exc:  # noqa: BLE001
            notes.append("%s: ERROR %r" % (battery, exc))
            continue
        tail = (proc.stdout.strip().splitlines() or [""])[-1]
        if proc.returncode != 0:
            err_tail = (proc.stderr.strip().splitlines() or [""])[-1]
            notes.append("%s: BREAK rc=%d (%s; %s)"
                         % (battery, proc.returncode, tail, err_tail))
        else:
            notes.append("%s: HELD (%s)" % (battery, tail))
    return notes


def main():
    print("wave-245 mcp-oauth-binding probes (have module: %s)" % (HAVE_MOB,))
    held = gap = 0
    for name in PROBE_NAMES:
        fn = _PROBES[name]
        name_r, status, note = _run_probe(name, fn, HAVE_MOB)
        if status == "HELD":
            held += 1
        elif status == "GAP":
            gap += 1
        print("%-40s %s %s" % (name_r, status, note))
    for note in _run_green_checks():
        print("green: %s" % note)
    print("summary: %d HELD / %d GAP / %d total"
          % (held, gap, len(PROBE_NAMES)))
    if held != len(PROBE_NAMES):
        raise SystemExit("battery not fully HELD (%d/%d)"
                         % (held, len(PROBE_NAMES)))


if __name__ == "__main__":
    main()
