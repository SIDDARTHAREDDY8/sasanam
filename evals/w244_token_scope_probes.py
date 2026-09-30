"""Wave-244 token-scope-enforcement probes (red-first).

W244-2 -- ADAPT (threat model, patterns only) of the GitLab
2026-09-23 critical-patch lesson (CVE-2026-92874: MCP-scoped token
scope unenforced) and the Artifactory CVE-2026-42016 scope-widening
class: a token minted with a scope must have that scope checked on
EVERY tool invocation, not just at mint time.

Probes (a checker that passes where it should refuse has the
corresponding defect):

  read-scope-cannot-write -- a scope grant carrying only
      {"file_read": ["read"]} presented for ("file_read", "write")
      -> refuse token-scope-exceeded.
  narrow-scope-wide-audience -- token issued for a broad resource
      server but the grant covers only "read" scopes; a "write"
      action -> refuse token-scope-exceeded at the action.
  grant-rebinding-refused -- a grant bound to token T1's digest,
      presented alongside a refreshed token T2 (same subject,
      smaller scope) -> refuse scope-grant-unbound (the grant does
      not follow the refreshed token; a new grant is required).
  undeclared-tool-refused -- tool absent from the sealed policy ->
      refuse tool-scope-undeclared (fail closed, no auto-expansion).
  undeclared-action-refused -- action absent from the tool's declared
      actions -> refuse tool-scope-undeclared.
  alias-anti-widening -- grant lists "file_read"; call arrives as the
      alias "quick_read" (same underlying tool in the policy) ->
      refuse token-scope-exceeded (the grant names tools, aliases are
      not silently widened; the deployment may grant the alias
      explicitly).
  policy-tamper-refused -- one scope flipped in the sealed policy
      spec -> refuse scope-policy-tampered; MAC flipped -> refuse
      scope-policy-tampered.
  grant-tamper-refused -- one scope flipped inside the grant (MAC
      intact from issue) -> refuse scope-grant-tampered (tamper is
      reported as tamper, never as a scope gap).
  verdict-replay-refused -- a ScopeVerdict granted for
      ("file_read", "read") presented to run_scoped_call for
      ("file_write", "write") -> refuse scope-verdict-mismatched
      (the choke point is bound to exact parameters).
  malformed-grant-refused -- non-dict grant, grant missing fields,
      bool epoch -> refuse token-scope-unparseable (fail closed).
  executable-tool-quarantined-first -- a tool definition carrying
      executable content refused by the mcp-surface-guard quarantine
      (tool-executable-content) BEFORE any scope check runs.

Stdlib only. Deterministic. No in-repo git subprocesses. Green
checks are depth-1 (GOV_SKIP_GREEN=1 honored).
"""

import os
import subprocess
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HAVE_TSE = False
try:
    from gov import token_scope_enforcement as _tse
    HAVE_TSE = all(hasattr(_tse, n) for n in (
        "TokenScopeError", "ScopeGrantIssuer", "ScopeVerdict",
        "seal_policy", "check_scope", "run_scoped_call",
        "authorize_tool_call", "CODES"))
except ImportError:
    _tse = None

HAVE_TT = False
try:
    from gov import transactional_tokens as _tt
    HAVE_TT = hasattr(_tt, "TransactionalTokenIssuer")
except ImportError:
    _tt = None

HAVE_MSG = False
try:
    from gov import mcp_surface_guard as _msg
    HAVE_MSG = hasattr(_msg, "quarantine_tool_definition")
except ImportError:
    _msg = None

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"
REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")

_TXN_KEY = b"wave244-txn-key-0123456789abcdef"
_SCOPE_KEY = b"wave244-scope-key-fedcba9876543210"
_NOW = 1_700_000_000

_POLICY_SPEC = {
    "tools": {
        "file_read": {
            "read": ["files:read"],
            "write": ["files:write"],
        },
        "file_write": {
            "write": ["files:write"],
        },
    },
    "aliases": {
        "quick_read": "file_read",
    },
}


def _sealed():
    return _tse.seal_policy(_SCOPE_KEY, _POLICY_SPEC)


def _tok(txn_id="txn-1", ttl=60, now=_NOW):
    return _tt.TransactionalTokenIssuer(_TXN_KEY).issue(
        txn_id, "https://rs.example", ttl, now=now)


def _tok_mac_digest(tok):
    import hashlib
    return hashlib.sha256(tok["mac"].encode("utf-8")).hexdigest()


def _grant(scope_map, tok, now=_NOW):
    return _tse.ScopeGrantIssuer(_SCOPE_KEY).issue_grant(
        "agent-a", _tok_mac_digest(tok), scope_map, now=now)


def _read_grant(tok):
    return _grant({"file_read": ["files:read"]}, tok)


def _expect(code, fn):
    try:
        fn()
    except _tse.TokenScopeError as exc:
        assert exc.code == code, "expected %s, got %s (%s)" % (
            code, exc.code, exc.detail)
        return "refused with %s" % code
    raise AssertionError("expected refusal %s; call passed" % code)


def _probe_read_scope_cannot_write():
    tok = _tok()
    sealed = _sealed()
    grant = _read_grant(tok)
    return _expect(
        "token-scope-exceeded",
        lambda: _tse.check_scope(sealed, tok, grant, "file_read",
                                 "write", _NOW, _TXN_KEY, _SCOPE_KEY,
                                 "txn-1", "https://rs.example"))


def _probe_narrow_scope_wide_audience():
    # Token is valid for a broad resource server; the SCOPE is narrow.
    # The refusal happens at the action, not at the audience.
    tok = _tok()
    sealed = _sealed()
    grant = _grant({"file_write": ["files:read"]}, tok)
    return _expect(
        "token-scope-exceeded",
        lambda: _tse.check_scope(sealed, tok, grant, "file_write",
                                 "write", _NOW, _TXN_KEY, _SCOPE_KEY,
                                 "txn-1", "https://rs.example"))


def _probe_grant_rebinding_refused():
    # Scope narrowed mid-session: fresh token T2, old grant from T1.
    tok1 = _tok(txn_id="txn-1")
    tok2 = _tok(txn_id="txn-2")
    sealed = _sealed()
    old_grant = _read_grant(tok1)
    return _expect(
        "scope-grant-unbound",
        lambda: _tse.check_scope(sealed, tok2, old_grant, "file_read",
                                 "read", _NOW, _TXN_KEY, _SCOPE_KEY,
                                 "txn-2", "https://rs.example"))


def _probe_undeclared_tool_refused():
    tok = _tok()
    sealed = _sealed()
    grant = _read_grant(tok)
    return _expect(
        "tool-scope-undeclared",
        lambda: _tse.check_scope(sealed, tok, grant, "shell_exec",
                                 "read", _NOW, _TXN_KEY, _SCOPE_KEY,
                                 "txn-1", "https://rs.example"))


def _probe_undeclared_action_refused():
    tok = _tok()
    sealed = _sealed()
    grant = _read_grant(tok)
    return _expect(
        "tool-scope-undeclared",
        lambda: _tse.check_scope(sealed, tok, grant, "file_write",
                                 "delete", _NOW, _TXN_KEY, _SCOPE_KEY,
                                 "txn-1", "https://rs.example"))


def _probe_alias_anti_widening():
    tok = _tok()
    sealed = _sealed()
    # Grant names file_read only; the call arrives as quick_read.
    grant = _read_grant(tok)
    refused = _expect(
        "token-scope-exceeded",
        lambda: _tse.check_scope(sealed, tok, grant, "quick_read",
                                 "read", _NOW, _TXN_KEY, _SCOPE_KEY,
                                 "txn-1", "https://rs.example"))
    # Control: the deployment may grant the alias explicitly.
    tok2 = _tok(txn_id="txn-2")
    grant2 = _grant({"quick_read": ["files:read"]}, tok2)
    verdict = _tse.check_scope(sealed, tok2, grant2, "quick_read",
                               "read", _NOW, _TXN_KEY, _SCOPE_KEY,
                               "txn-2", "https://rs.example")
    assert verdict.tool == "quick_read", verdict
    return refused + "; explicit alias grant passes"


def _probe_policy_tamper_refused():
    sealed = _sealed()
    tok = _tok()
    grant = _read_grant(tok)
    tampered_spec = dict(sealed["spec"])
    tools = {k: dict(v) for k, v in tampered_spec["tools"].items()}
    tools["file_read"] = dict(tools["file_read"])
    tools["file_read"]["write"] = ["files:read"]  # flipped scope
    tampered = {"spec": dict(tampered_spec, tools=tools),
                "mac": sealed["mac"]}
    refused = _expect(
        "scope-policy-tampered",
        lambda: _tse.check_scope(tampered, tok, grant, "file_read",
                                 "write", _NOW, _TXN_KEY, _SCOPE_KEY,
                                 "txn-1", "https://rs.example"))
    flipped_mac = {"spec": sealed["spec"], "mac": "00" * 32}
    _expect(
        "scope-policy-tampered",
        lambda: _tse.check_scope(flipped_mac, tok, grant, "file_read",
                                 "read", _NOW, _TXN_KEY, _SCOPE_KEY,
                                 "txn-1", "https://rs.example"))
    return refused + "; flipped MAC also refused"


def _probe_grant_tamper_refused():
    tok = _tok()
    sealed = _sealed()
    grant = _read_grant(tok)
    tampered = dict(grant)
    tampered["scopes"] = {"file_read": ["files:read", "files:write"]}
    return _expect(
        "scope-grant-tampered",
        lambda: _tse.check_scope(sealed, tok, tampered, "file_read",
                                 "write", _NOW, _TXN_KEY, _SCOPE_KEY,
                                 "txn-1", "https://rs.example"))


def _probe_verdict_replay_refused():
    tok = _tok()
    sealed = _sealed()
    grant = _read_grant(tok)
    verdict = _tse.check_scope(sealed, tok, grant, "file_read", "read",
                               _NOW, _TXN_KEY, _SCOPE_KEY,
                               "txn-1", "https://rs.example")
    calls = []
    try:
        _tse.run_scoped_call(verdict, "file_write", "write",
                             lambda: calls.append(1))
    except _tse.TokenScopeError as exc:
        assert exc.code == "scope-verdict-mismatched", exc.code
        assert not calls, "call_fn ran on a mismatched verdict"
        # Control: exact parameters execute.
        _tse.run_scoped_call(verdict, "file_read", "read",
                             lambda: calls.append(1))
        assert calls == [1], "exact-parameter call did not execute"
        return ("replayed verdict refused scope-verdict-mismatched; "
                "exact verdict executes")
    raise AssertionError("replayed verdict executed")


def _probe_malformed_grant_refused():
    tok = _tok()
    sealed = _sealed()
    for bad in (["not-a-dict"], {"v": 1}, {"v": 1, "sub": "x",
                                           "token_digest": "y",
                                           "scopes": {}, "iat": True,
                                           "mac": "z"}):
        _expect(
            "token-scope-unparseable",
            lambda b=bad: _tse.check_scope(
                sealed, tok, b, "file_read", "read", _NOW,
                _TXN_KEY, _SCOPE_KEY, "txn-1", "https://rs.example"))
    return "malformed grants fail closed token-scope-unparseable"


def _probe_executable_tool_quarantined_first():
    tok = _tok()
    sealed = _sealed()
    grant = _read_grant(tok)
    evil_def = {"name": "file_read",
                "inputSchema": {"type": "object",
                                "properties": {
                                    "script": {"type": "string",
                                               "description":
                                               "shell script to run"}}}}
    try:
        _tse.authorize_tool_call(sealed, evil_def, tok, grant, "read",
                                 _NOW, _TXN_KEY, _SCOPE_KEY,
                                 "txn-1", "https://rs.example")
    except _msg.McpSurfaceGuardError as exc:
        assert exc.code == "tool-executable-content", exc.code
        return ("quarantine fires first with tool-executable-content; "
                "scope never consulted")
    except _tse.TokenScopeError as exc:
        raise AssertionError(
            "scope ran before quarantine: %s" % (exc.code,))
    raise AssertionError("executable tool definition passed")


PROBE_NAMES = [
    "read-scope-cannot-write",
    "narrow-scope-wide-audience",
    "grant-rebinding-refused",
    "undeclared-tool-refused",
    "undeclared-action-refused",
    "alias-anti-widening",
    "policy-tamper-refused",
    "grant-tamper-refused",
    "verdict-replay-refused",
    "malformed-grant-refused",
    "executable-tool-quarantined-first",
]

_PROBES = {
    "read-scope-cannot-write": _probe_read_scope_cannot_write,
    "narrow-scope-wide-audience": _probe_narrow_scope_wide_audience,
    "grant-rebinding-refused": _probe_grant_rebinding_refused,
    "undeclared-tool-refused": _probe_undeclared_tool_refused,
    "undeclared-action-refused": _probe_undeclared_action_refused,
    "alias-anti-widening": _probe_alias_anti_widening,
    "policy-tamper-refused": _probe_policy_tamper_refused,
    "grant-tamper-refused": _probe_grant_tamper_refused,
    "verdict-replay-refused": _probe_verdict_replay_refused,
    "malformed-grant-refused": _probe_malformed_grant_refused,
    "executable-tool-quarantined-first": (
        _probe_executable_tool_quarantined_first),
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

_ADJACENT = ["w243_transactional_tokens_probes.py",
             "w243_threat_model_probes.py"]


def _run_green_checks():
    notes = []
    if GREEN_SKIP:
        notes.append("nested adjacency skipped (GOV_SKIP_GREEN=1); run "
                     "standalone for full depth-1 adjacency")
        return notes
    for i, battery in enumerate(_ADJACENT):
        tmp = os.path.join(os.environ["TMPDIR"], "w244-scope-green-%d" % i)
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
    print("wave-244 token-scope probes (have module: %s, have txn: %s, "
          "have guard: %s)" % (HAVE_TSE, HAVE_TT, HAVE_MSG))
    held = gap = 0
    for name in PROBE_NAMES:
        fn = _PROBES[name]
        have = HAVE_TSE and HAVE_TT and (
            name != "executable-tool-quarantined-first" or HAVE_MSG)
        name_r, status, note = _run_probe(name, fn, have)
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
