"""Wave-278 delegation resource-binding battery: RFC 8707 steal.

The three-token delegation module (gov/delegation_tokens.py) bound
tokens to a session and (optionally) a deployment audience, but a
delegation issued for use against MCP server A verified fine when
presented against server B -- the classic confused-deputy shape, and
the documented gap behind prospectus steal #5 (MCP RFC 8707 resource
indicators: servers MUST NOT accept tokens not issued for them; token
passthrough is forbidden). The per-tool grant module
(gov/tool_grant.py) already binds aud+locations; this battery pins the
same discipline for the three-token identity layer.

Mechanism under test (post-fix): issue_delegation() binds a signed
``resource`` claim (the canonical https URI of the intended server)
into the token envelope; spawn_sub_agent() inherits it (never a
parameter -- a spawn cannot re-target, mirroring the aud-inheritance
precedent); verify_token()/verify_delegation_chain()/
DelegationContext.bind()/authorize_action()/enforce_tool_call() all
accept an expected_resource declaration. When the verifier declares a
resource, a missing or mismatched token resource claim refuses
fail-closed with DelegationBindingError. When nothing is declared,
behavior is byte-identical to the pre-binding tree (the aud precedent:
binding is verifier-declared).

Each probe states its post-fix expected verdict. On the pre-fix base
the attack probes BREAK (the gap is live); the control probes HELD
(no behavior change where no resource is declared).

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (synthetic keys, no
random); fresh unique /var/tmp/g278* TMPDIR (`mkdir -p` first);
depth-1 green checks honoring GOV_SKIP_GREEN=1; no in-repo git
subprocesses; stdlib only.
"""

import copy
import os
import re
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TMP = tempfile.mkdtemp(prefix="g278-delegation-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import delegation_tokens as _dt  # noqa: E402
from gov.identity import AgentIdentity  # noqa: E402

TAXONOMY_PIN = 2070 # Wave-277 merge pin; this battery adds no codes.; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2070 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*). # Wave-333 lane 4: pin 2062 -> 2070 (+8 revocation-push-*).


GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_SID = "sess-w278"
_REVOKE_URI = "https://revoke.example.invalid/deleg"
_RSRC_A = "https://mcp-a.example.invalid/server"
_RSRC_B = "https://mcp-b.example.invalid/server"

_RESULTS = []


def _run(pid, expected, fn):
    try:
        verdict, note = fn()
    except Exception as exc:  # noqa: BLE001
        verdict, note = "ERROR", "%s: %s" % (type(exc).__name__, exc)
    ok = (verdict == expected)
    _RESULTS.append((pid, expected, verdict, ok, note))


def _pin_check():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    literals = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK", "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    return "HELD", "taxonomy pin 1588: 1588 unique literals"


class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self, extra_agent_keys=None):
        agent_keys = {"agent-1": self.parent[1]}
        if extra_agent_keys:
            agent_keys.update(extra_agent_keys)
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys=agent_keys)


# A module-level sentinel distinct from "resource=None passed".
_MISSING_SENTINEL = object()


def _trio(keys, session=_SID, now=None, resource=_MISSING_SENTINEL):
    """Mint the standard trio. resource=_MISSING_SENTINEL omits the
    kwarg entirely (base-compatible legacy mint)."""
    user_tok = _dt.issue_user_token(keys.idp[0], "user-7",
                                    ("tool:read_file", "tool:send_email"),
                                    session, ttl_s=3600, now=now)
    agent_tok = _dt.issue_agent_token(keys.authority[0], "agent-1",
                                      "scout", "user-7",
                                      ("tool:read_file", "tool:send_email"),
                                      session, ttl_s=3600, now=now)
    kw = {} if resource is _MISSING_SENTINEL else {"resource": resource}
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "user-7", user_tok, agent_tok,
        ("tool:read_file",), session, _REVOKE_URI,
        ttl_s=3600, now=now, **kw)
    return user_tok, agent_tok, deleg_tok


def _bound_ctx(keys, trust=None, session=_SID, resource=_MISSING_SENTINEL,
               bind_resource=_MISSING_SENTINEL):
    user_tok, agent_tok, deleg_tok = _trio(keys, session=session,
                                          resource=resource)
    ctx = _dt.DelegationContext(
        user_token=user_tok,
        agent_token=agent_tok,
        delegation_token=deleg_tok,
        parent_chain=[],
        trust=trust or keys.trust(),
        session_id=session)
    kw = {} if bind_resource is _MISSING_SENTINEL\
        else {"expected_resource": bind_resource}
    ctx.bind(**kw)
    return ctx


def _identity(session=_SID):
    return AgentIdentity(agent_id="agent-1", role="scout",
                         run_id=session, principal="user-7",
                         provenance="minted")


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _p_cross_server_refused():
    """Token minted for server A, presented at server B: the confused-
    deputy shape. Post-fix: DelegationBindingError."""
    keys = _Keys()
    try:
        ctx = _bound_ctx(keys, resource=_RSRC_A)
    except TypeError:
        return "BREAK", "no resource binding at mint (gap is live)"
    try:
        ctx.authorize("tool:read_file", _RSRC_B)
    except _dt.DelegationBindingError as e:
        return "HELD", "cross-server presentation refused: %s" % (e,)
    return "BREAK", "A-bound token authorized at server B (passthrough)"


def _p_same_server_allowed():
    """Token minted for A, used at A: unaffected (anti-false-positive)."""
    keys = _Keys()
    try:
        ctx = _bound_ctx(keys, resource=_RSRC_A)
    except TypeError:
        ctx = _bound_ctx(keys)  # base: legacy path stays green
    verdict = ctx.authorize("tool:read_file", _RSRC_A)
    if verdict.get("action") == "tool:read_file":
        return "HELD", "same-resource use authorized"
    return "BREAK", "same-resource use refused: %r" % (verdict,)


def _p_passthrough_gate():
    """enforce_tool_call (the executor seam) with a foreign resource."""
    keys = _Keys()
    try:
        ctx = _bound_ctx(keys, resource=_RSRC_A)
    except TypeError:
        return "BREAK", "no resource binding at mint (gap is live)"
    try:
        _dt.enforce_tool_call(ctx, _identity(), "read_file",
                              resource=_RSRC_B)
    except TypeError:
        return "BREAK", "enforce_tool_call takes no resource (gap live)"
    except _dt.DelegationBindingError as e:
        return "HELD", "gate refused passthrough: %s" % (e,)
    return "BREAK", "gate allowed A-bound token at server B"


def _p_unbound_token_at_bound_resource():
    """A resource-less (legacy) token presented to a resource that
    declares binding: fail-closed, it cannot prove it was issued here."""
    keys = _Keys()
    ctx = _bound_ctx(keys)  # no resource claim on the token
    try:
        ctx.authorize("tool:read_file", _RSRC_A)
    except _dt.DelegationBindingError as e:
        return "HELD", "unbound token refused at binding resource: %s" % (e,)
    return "BREAK", "unbound token accepted where binding is declared"


def _p_legacy_no_declaration():
    """No resource anywhere: byte-identical legacy behavior (allowed)."""
    keys = _Keys()
    ctx = _bound_ctx(keys)
    verdict = ctx.authorize("tool:read_file")
    if verdict.get("action") == "tool:read_file":
        return "HELD", "undeclared use still authorized (compat)"
    return "BREAK", "legacy use refused: %r" % (verdict,)


def _p_bound_token_silent_use():
    """Resource-bound token, verifier declares nothing: the aud
    precedent -- binding is verifier-declared, so this stays allowed
    (documented, not a hole: a verifier that wants the check declares
    its resource)."""
    keys = _Keys()
    try:
        ctx = _bound_ctx(keys, resource=_RSRC_A)
    except TypeError:
        return "HELD", "n/a on base (no binding); legacy allowed"
    verdict = ctx.authorize("tool:read_file")
    if verdict.get("action") == "tool:read_file":
        return "HELD", "silent use of bound token allowed (declared-only)"
    return "BREAK", "bound token refused with no declaration: %r" % (verdict,)


def _p_spawn_inherits():
    """A spawn cannot re-target the delegation: the child inherits the
    parent's resource (never a parameter), like aud."""
    keys = _Keys()
    try:
        parent = _bound_ctx(keys, resource=_RSRC_A)
    except TypeError:
        return "BREAK", "no resource binding at mint (gap is live)"
    child = parent.spawn("agent-2", ("tool:read_file",), keys.parent[0])
    tok_res = child.delegation_token.get("resource")
    if tok_res != _RSRC_A:
        return "BREAK", "child resource not inherited: %r" % (tok_res,)
    try:
        child.authorize("tool:read_file", _RSRC_B)
    except _dt.DelegationBindingError as e:
        ok_a = child.authorize("tool:read_file", _RSRC_A)
        if ok_a.get("action") == "tool:read_file":
            return "HELD", "spawn inherits; B refused, A allowed: %s" % (e,)
        return "BREAK", "spawn refused at its own resource"
    return "BREAK", "spawned token usable at a foreign server"


def _p_tampered_resource():
    """The resource claim is signature-covered: flipping it breaks the
    signature, so no re-signing can move a token across servers."""
    keys = _Keys()
    try:
        user_tok, agent_tok, deleg_tok = _trio(keys, resource=_RSRC_A)
        field = "resource"
    except TypeError:
        # Base: pin the same property on an existing signed field.
        user_tok, agent_tok, deleg_tok = _trio(keys)
        field = "session_id"
    ctx = _dt.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=deleg_tok, parent_chain=[],
        trust=keys.trust(), session_id=_SID)
    ctx.bind()
    tampered = copy.deepcopy(deleg_tok)
    tampered[field] = "https://evil.example.invalid/x"
    ctx2 = _dt.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=tampered, parent_chain=[],
        trust=keys.trust(), session_id=_SID)
    try:
        ctx2.bind()
    except _dt.DelegationError as e:
        return "HELD", "tampered %r refused at bind: %s" % (field, e)
    return "BREAK", "tampered %r bound anyway" % (field,)


def _p_chain_bind():
    """Chain-level declaration at bind: a chain bound for A refuses to
    bind for B."""
    keys = _Keys()
    try:
        _bound_ctx(keys, resource=_RSRC_A, bind_resource=_RSRC_B)
    except TypeError:
        return "BREAK", "bind() takes no expected_resource (gap live)"
    except _dt.DelegationBindingError as e:
        return "HELD", "chain refused to bind for foreign resource: %s" % (e,)
    return "BREAK", "A-bound chain bound for server B"


def _p_malformed_uri():
    """Fail-fast at issuance: a non-URI resource is refused loudly, not
    minted into a token."""
    keys = _Keys()
    try:
        _trio(keys, resource="not-a-uri")
    except ValueError as e:
        return "HELD", "malformed resource refused at mint: %s" % (e,)
    except TypeError:
        return "BREAK", "no resource validation at mint (gap live)"
    return "BREAK", "malformed resource minted into a token"


def _p_audience_orthogonal():
    """Resource binding composes with the F132 audience claim: both
    bound, both enforced, neither disturbed."""
    keys = _Keys()
    try:
        user_tok = _dt.issue_user_token(keys.idp[0], "user-7",
                                        ("tool:read_file",),
                                        _SID, ttl_s=3600, audience="deploy-1")
        agent_tok = _dt.issue_agent_token(keys.authority[0], "agent-1",
                                          "scout", "user-7",
                                          ("tool:read_file",),
                                          _SID, ttl_s=3600, audience="deploy-1")
        deleg_tok = _dt.issue_delegation(
            keys.human[0], "user-7", user_tok, agent_tok,
            ("tool:read_file",), _SID, _REVOKE_URI,
            ttl_s=3600, audience="deploy-1", resource=_RSRC_A)
    except TypeError:
        return "HELD", "n/a on base (no resource kwarg); aud path intact"
    trust = keys.trust()
    trust.audience = "deploy-1"
    ctx = _dt.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=deleg_tok, parent_chain=[],
        trust=trust, session_id=_SID).bind(expected_resource=_RSRC_A)
    verdict = ctx.authorize("tool:read_file", _RSRC_A)
    if verdict.get("action") != "tool:read_file":
        return "BREAK", "aud+resource composition refused own use"
    try:
        ctx.authorize("tool:read_file", _RSRC_B)
    except _dt.DelegationBindingError:
        return "HELD", "aud+resource compose; foreign server refused"
    return "BREAK", "aud+resource compose but B allowed"


_PROBES = [
    ("pin-taxonomy-1493", "HELD", _pin_check),
    ("rsrc-cross-server-refused", "HELD", _p_cross_server_refused),
    ("rsrc-same-server-allowed", "HELD", _p_same_server_allowed),
    ("rsrc-passthrough-gate", "HELD", _p_passthrough_gate),
    ("rsrc-unbound-token-at-bound-resource", "HELD",
     _p_unbound_token_at_bound_resource),
    ("rsrc-legacy-no-declaration", "HELD", _p_legacy_no_declaration),
    ("rsrc-bound-token-silent-use", "HELD", _p_bound_token_silent_use),
    ("rsrc-spawn-inherits", "HELD", _p_spawn_inherits),
    ("rsrc-tampered-resource", "HELD", _p_tampered_resource),
    ("rsrc-chain-bind", "HELD", _p_chain_bind),
    ("rsrc-malformed-uri", "HELD", _p_malformed_uri),
    ("rsrc-audience-orthogonal", "HELD", _p_audience_orthogonal),
]


def _green_checks():
    """Depth-1: adjacent delegation + F294 batteries with
    GOV_SKIP_GREEN=1 (they record the skip and do not recurse)."""
    if GREEN_SKIP:
        return [("green-checks", "SKIP",
                 "GOV_SKIP_GREEN=1: recorded, not recursing")]
    import subprocess
    out = []
    for kind, name in (("battery", "w276_f294_probes"),
                       ("unittest", "tests.test_w74_identity"),
                       ("unittest", "tests.test_w86_identity")):
        try:
            if kind == "battery":
                path = os.path.join(REPO, "evals", name + ".py")
                if not os.path.exists(path):
                    out.append((name, "SKIP", "battery absent"))
                    continue
                argv = [sys.executable, path]
            else:
                argv = [sys.executable, "-m", "unittest", name]
            env = dict(os.environ, GOV_SKIP_GREEN="1")
            p = subprocess.run(argv, env=env, cwd=REPO,
                               capture_output=True, text=True, timeout=600)
        except Exception as exc:  # noqa: BLE001
            out.append((name, "BREAK", "green check failed: %s" % (exc,)))
            continue
        tail = (p.stderr or p.stdout or "").strip().split("\n")[-1]
        out.append((name, "HELD" if p.returncode == 0 else "BREAK",
                    "%s rc=%d" % (tail[:120], p.returncode)))
    return out


def main():
    print("w278 delegation resource-binding battery: %d probes (TMPDIR=%s)"
          % (len(_PROBES), _TMP))
    failures = 0
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    for pid, expected, verdict, ok, note in _RESULTS:
        flag = "ok " if ok else "FAIL"
        if not ok:
            failures += 1
        print("[%s] %-36s expected=%-5s got=%-5s %s"
              % (flag, pid, expected, verdict, note))
    print("--- green checks (depth-1) ---")
    for name, verdict, note in _green_checks():
        print("[%s] %s %s" % ("ok " if verdict in ("HELD", "SKIP") else "FAIL",
                              name, note))
        if verdict not in ("HELD", "SKIP"):
            failures += 1
    n_break = sum(1 for r in _RESULTS if r[2] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r[2] == "HELD")
    n_err = sum(1 for r in _RESULTS if r[2] == "ERROR")
    print("probes: %d BREAK / %d HELD / %d ERROR; mismatches: %d"
          % (n_break, n_held, n_err, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
