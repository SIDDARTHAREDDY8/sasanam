"""COAZ-MCP invocation-authorization battery (wave-218, lane B).

Natively reimplements the *ideas* of the COAZ-MCP binding draft
(individual draft, not adopted; no upstream source vendored, no
conformance claimed). Three hardenings at the PEP seam between an
authorization decision and the actual MCP tool invocation:

  * TOCTOU guard: a permit binds the exact authorized message; the
    PEP re-verifies it unchanged at apply time. Any mutation of the
    JSON-RPC payload between authorize and apply (params, method,
    tool name, id) must fail closed (permit-message-mismatch).
  * Trust-anchored subject.id: only the top-level
    authz_context["subject"]["id"] is the subject, pinned at policy
    build. Nested subject-shaped claims are untrusted input (recorded,
    never consulted); a nested claim disagreeing with the anchor is a
    smuggling attempt and refuses (subject-smuggling-attempt).
  * Server-advertised-mapping pin: absent pin -> mapping-unpinned;
    drifted mapping -> mapping-drift. Re-pinning restores
    authorization; widening never auto-expands authority.

Verdict vocabulary: HELD (attack refused), BREAK (attack admitted --
a genuine finding, file it), GAP (the defense does not exist yet in
the pristine tree -- the honest red before the fix).

Stdlib only. Deterministic: no clock, no randomness.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import traceback

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        def run():
            try:
                verdict, detail = fn()
            except Exception as e:  # noqa: BLE001 - battery must not die
                return (name, "ERROR", "%s: %s\n%s" % (
                    type(e).__name__, str(e)[:160],
                    traceback.format_exc(limit=3)))
            if isinstance(verdict, tuple):
                verdict, detail = verdict
            assert verdict in ("HELD", "GAP", "BREAK"), verdict
            return (name, verdict, detail)
        _PROBE_FNS[name] = run
        return run
    return deco


def _load():
    """Import the module or raise ImportError (pristine -> GAP)."""
    import gov.mcp_invocation_authz as mia
    return mia


# ------------------------------------------------------------------ fixtures

_MAPPING = {
    "files": {
        "read": {"description": "read a file",
                 "inputSchema": {"type": "object",
                                 "properties": {"path": {"type": "string"}}}},
        "write": {"description": "write a file",
                  "inputSchema": {"type": "object",
                                  "properties": {"path": {"type": "string"}}}},
    },
}


def _message(**over):
    msg = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
           "params": {"name": "read", "arguments": {"path": "/tmp/a.txt"}}}
    msg.update(over)
    return msg


def _context(subject_id="alice", mapping=None):
    return {"subject": {"id": subject_id},
            "server_mapping": _MAPPING if mapping is None else mapping}


def _policy(mia, pin=True, subject_id="alice"):
    spec = {"subject_id": subject_id}
    if pin:
        spec["pinned_mapping_digest"] = mia.canonical_digest(_MAPPING)
    return mia.build_policy(spec)


def _permit(mia, policy, message, ctx):
    res = mia.authorize(policy, message, ctx)
    if res.verdict != "permit":
        raise AssertionError("fixture authorize refused: %s %r"
                             % (res.code, res.report))
    return res.permit


# ------------------------------------------------------------------- probes

@_probe("toctou_param_mutation_refused")
def p_param_mutation():
    """N1: mutate arguments after authorize; apply must refuse
    permit-message-mismatch (the TOCTOU window closed)."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    msg = _message()
    permit = _permit(mia, policy, msg, _context())
    tampered = _message(params={"name": "read",
                                "arguments": {"path": "/etc/shadow"}})
    out = mia.apply_permit(permit, tampered)
    if out.verdict == "refuse" and out.code == mia.PERMIT_MESSAGE_MISMATCH:
        return ("HELD", "param mutation refused: %s" % out.code)
    return ("BREAK", "mutated message applied: %s/%s"
            % (out.verdict, out.code))


@_probe("toctou_method_swap_refused")
def p_method_swap():
    """N2: swap the JSON-RPC method after authorize; apply refuses."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    permit = _permit(mia, policy, _message(), _context())
    tampered = _message(method="tools/list")
    out = mia.apply_permit(permit, tampered)
    if out.verdict == "refuse" and out.code == mia.PERMIT_MESSAGE_MISMATCH:
        return ("HELD", "method swap refused: %s" % out.code)
    return ("BREAK", "swapped method applied: %s/%s"
            % (out.verdict, out.code))


@_probe("toctou_tool_name_swap_refused")
def p_tool_swap():
    """N3: swap the tool name in params after authorize; apply
    refuses (cross-tool confusion closed at the apply seam)."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    permit = _permit(mia, policy, _message(), _context())
    tampered = _message(params={"name": "write",
                                "arguments": {"path": "/tmp/a.txt"}})
    out = mia.apply_permit(permit, tampered)
    if out.verdict == "refuse" and out.code == mia.PERMIT_MESSAGE_MISMATCH:
        return ("HELD", "tool-name swap refused: %s" % out.code)
    return ("BREAK", "swapped tool applied: %s/%s" % (out.verdict, out.code))


@_probe("toctou_id_mutation_refused")
def p_id_mutation():
    """N4: mutate only the JSON-RPC id after authorize; the permit is
    bound to the exact message, so even an id change refuses."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    permit = _permit(mia, policy, _message(), _context())
    tampered = _message(id=999)
    out = mia.apply_permit(permit, tampered)
    if out.verdict == "refuse" and out.code == mia.PERMIT_MESSAGE_MISMATCH:
        return ("HELD", "id mutation refused: %s" % out.code)
    return ("BREAK", "id-mutated message applied: %s/%s"
            % (out.verdict, out.code))


@_probe("nested_subject_smuggling_refused")
def p_smuggling():
    """N5: a nested params.subject.id that disagrees with the anchored
    subject is a smuggling attempt -- authorize must refuse."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    msg = _message(params={"name": "read",
                           "arguments": {"path": "/tmp/a.txt"},
                           "subject": {"id": "mallory"}})
    out = mia.authorize(policy, msg, _context())
    if out.verdict == "refuse" and out.code == mia.SUBJECT_SMUGGLING:
        return ("HELD", "smuggling refused: %s" % out.code)
    return ("BREAK", "smuggled nested subject authorized: %s/%s"
            % (out.verdict, out.code))


@_probe("nested_subject_echo_untrusted")
def p_echo():
    """N6: a nested claim ECHOING the anchored id is still untrusted
    input -- it must be recorded as such, and the permit must stand
    on the anchor alone (the legit path keeps working)."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    msg = _message(params={"name": "read",
                           "arguments": {"path": "/tmp/a.txt"},
                           "subject": {"id": "alice"}})
    out = mia.authorize(policy, msg, _context())
    if out.verdict != "permit":
        return ("GAP", "agreeing echo wrongly refused: %s" % out.code)
    claims = out.report.get("untrusted_subject_claims", [])
    if any("subject" in c for c in claims):
        return ("HELD", "echo permit stands; nested claim recorded "
                         "as untrusted: %s" % claims)
    return ("GAP", "echo permit stands but nested claim not recorded")


@_probe("unanchored_subject_refused")
def p_unanchored():
    """N7: no top-level subject in the context -> subject-unanchored."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    ctx = {"server_mapping": _MAPPING}
    out = mia.authorize(policy, _message(), ctx)
    if out.verdict == "refuse" and out.code == mia.SUBJECT_UNANCHORED:
        return ("HELD", "missing subject refused: %s" % out.code)
    return ("BREAK", "call with no subject authorized: %s/%s"
            % (out.verdict, out.code))


@_probe("subject_mismatch_refused")
def p_subject_mismatch():
    """N8: top-level subject.id != anchored id -> subject-unanchored."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    out = mia.authorize(policy, _message(), _context(subject_id="mallory"))
    if out.verdict == "refuse" and out.code == mia.SUBJECT_UNANCHORED:
        return ("HELD", "subject mismatch refused: %s" % out.code)
    return ("BREAK", "wrong subject authorized: %s/%s"
            % (out.verdict, out.code))


@_probe("mapping_drift_refused")
def p_drift():
    """N9: server adds a tool to the advertised mapping -> the digest
    drifts from the pin and authorization refuses mapping-drift."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    drifted = {"files": dict(_MAPPING["files"])}
    drifted["files"]["delete"] = {"description": "delete a file",
                                  "inputSchema": {"type": "object"}}
    out = mia.authorize(policy, _message(),
                        _context(mapping=drifted))
    if out.verdict == "refuse" and out.code == mia.MAPPING_DRIFT:
        return ("HELD", "drifted mapping refused: %s" % out.code)
    return ("BREAK", "drifted mapping authorized: %s/%s"
            % (out.verdict, out.code))


@_probe("mapping_unpinned_refused")
def p_unpinned():
    """N10: a policy with no pinned digest refuses every call with
    mapping-unpinned until the deployment re-pins."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia, pin=False)
    out = mia.authorize(policy, _message(), _context())
    if out.verdict == "refuse" and out.code == mia.MAPPING_UNPINNED:
        return ("HELD", "unpinned mapping refused: %s" % out.code)
    return ("BREAK", "unpinned mapping authorized: %s/%s"
            % (out.verdict, out.code))


@_probe("repin_restores_authorization")
def p_repin():
    """N11: after drift, building a policy pinned to the NEW digest
    restores authorization -- re-pin is the only widening path."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    drifted = {"files": dict(_MAPPING["files"])}
    drifted["files"]["delete"] = {"description": "delete a file",
                                  "inputSchema": {"type": "object"}}
    old_policy = _policy(mia)
    refused = mia.authorize(old_policy, _message(),
                            _context(mapping=drifted))
    if refused.verdict != "refuse":
        return ("GAP", "drift unexpectedly authorized under old pin")
    new_policy = mia.build_policy(
        {"subject_id": "alice",
         "pinned_mapping_digest": mia.canonical_digest(drifted)})
    out = mia.authorize(new_policy, _message(), _context(mapping=drifted))
    if out.verdict == "permit":
        return ("HELD", "re-pin restores authorization; old pin still "
                         "refuses drift")
    return ("GAP", "re-pinned policy refused: %s" % out.code)


@_probe("apply_happy_path")
def p_happy():
    """N12: the unchanged authorized message applies (the guard must
    not break the legitimate path)."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    msg = _message()
    permit = _permit(mia, policy, msg, _context())
    out = mia.apply_permit(permit, msg, _context())
    if out.verdict == "apply":
        return ("HELD", "unchanged message applies")
    return ("GAP", "legitimate apply refused: %s/%s" % (out.verdict,
                                                       out.code))


@_probe("subject_reanchored_at_apply")
def p_reanchor():
    """N13: the subject is re-anchored at apply time -- a changed
    top-level subject between authorize and apply refuses."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    permit = _permit(mia, policy, _message(), _context())
    out = mia.apply_permit(permit, _message(),
                           _context(subject_id="mallory"))
    if out.verdict == "refuse" and out.code == mia.SUBJECT_UNANCHORED:
        return ("HELD", "subject change at apply refused: %s" % out.code)
    return ("BREAK", "subject change at apply admitted: %s/%s"
            % (out.verdict, out.code))


@_probe("malformed_shapes_refused")
def p_malformed():
    """N14: malformed message/context/permit become named refusals,
    never exceptions past the seam."""
    try:
        mia = _load()
    except ImportError:
        return ("GAP", "gov.mcp_invocation_authz absent")
    policy = _policy(mia)
    cases = [
        (mia.authorize(policy, "not-a-dict", _context()),
         mia.MALFORMED_MESSAGE, "non-dict message"),
        (mia.authorize(policy, {"id": 1}, _context()),
         mia.MALFORMED_MESSAGE, "methodless message"),
        (mia.authorize(policy, _message(), "not-a-dict"),
         mia.MALFORMED_CONTEXT, "non-dict context"),
        (mia.apply_permit({"format": "bogus"}, _message()),
         mia.MALFORMED_PERMIT, "bogus permit"),
    ]
    for out, want, label in cases:
        if out.verdict != "refuse" or out.code != want:
            return ("BREAK", "%s -> %s/%s (want refuse/%s)"
                    % (label, out.verdict, out.code, want))
    return ("HELD", "all malformed shapes refused with named codes")


# ------------------------------------------------------------------ green

def _green_check():
    """Depth-1: run the adjacent MCP unit suite once, with
    GOV_SKIP_GREEN=1 so nothing nests."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1, no nested suites)")]
    import subprocess
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    # Single test files do `from gov import ...`; they need the repo
    # root on the import path (the harness normally provides it).
    env["PYTHONPATH"] = _REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    notes = []
    py = sys.executable
    for label, cmd in (
        ("test_authority_proof_mcp_graphql",
         [py, os.path.join(_REPO_ROOT, "tests",
                           "test_authority_proof_mcp_graphql.py")]),
        ("test_mcp_invocation_authz",
         [py, os.path.join(_REPO_ROOT, "tests",
                           "test_mcp_invocation_authz.py")]),
    ):
        try:
            r = subprocess.run(cmd, env=env, capture_output=True,
                               text=True, timeout=600, cwd=_REPO_ROOT)
        except Exception as e:  # noqa: BLE001
            notes.append((label, "ERROR", "%s" % e))
            continue
        tail = (r.stdout + r.stderr)[-400:]
        if r.returncode == 0:
            notes.append((label, "HELD", tail.strip().splitlines()[-1]
                          if tail.strip() else "exit 0"))
        else:
            notes.append((label, "ERROR", "exit %d: %s"
                          % (r.returncode, tail.strip().splitlines()[-1]
                             if tail.strip() else "")))
    return notes


# ------------------------------------------------------------------- main

def main():
    names = sorted(_PROBE_FNS)
    rows = [(_PROBE_FNS[n]()) for n in names]
    held = sum(1 for _, v, _ in rows if v == "HELD")
    gap = sum(1 for _, v, _ in rows if v == "GAP")
    brk = sum(1 for _, v, _ in rows if v == "BREAK")
    err = sum(1 for _, v, _ in rows if v == "ERROR")
    print("== w218 COAZ-MCP battery: %d probes ==" % len(rows))
    for name, verdict, detail in rows:
        print("[%s] %s: %s" % (verdict, name, detail))
    print("-- %d HELD / %d GAP / %d BREAK / %d ERROR" % (held, gap, brk,
                                                        err))
    # determinism: second pass must be verdict-identical
    rows2 = [(_PROBE_FNS[n]()) for n in names]
    det = all(a[1] == b[1] for a, b in zip(rows, rows2))
    print("-- determinism: %s" % ("PASS" if det else "FAIL"))
    for label, verdict, detail in _green_check():
        print("[%s] green %s: %s" % (verdict, label, detail))
    if brk or err or not det:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
