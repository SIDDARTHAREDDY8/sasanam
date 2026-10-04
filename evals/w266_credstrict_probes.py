"""Break-first battery for the credential never-materialize (strict) tier.

Wave-266 lane: ADAPT of NVIDIA OpenShell's credential-injection pattern
(never materialize credentials in the sandbox; the supervisor injects
at L7 into approved requests only). Strict tier above the sentinel
placeholder default: a strict credential's real value NEVER resolves
in the agent-visible execution environment; resolution happens only in
a supervisor-owned egress path where the request is (a) already
approved, (b) destined for an authorized host, and (c) injected at the
protocol layer via a deployment-supplied transport.

Red phase (GOV_CREDSTRICT_IMPL=stub): the permissive stub resolves
strict sentinels agent-side, injects without approval/host checks, and
leaks real values into the audit log -- every attack probe BREAKs.
Green phase (module): gov/credential_strict.py HELDs, in staging AND
under `env -u GOV_DEPLOYMENT_MODE`.

Stdlib only. Deterministic. Depth-1 green check honoring
GOV_SKIP_GREEN=1. No in-repo git subprocesses.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov.sentinel_substitution import (  # noqa: E402
    SentinelError,
    SentinelVault,
    find_sentinels,
    substitute_in,
)

IMPL = os.environ.get("GOV_CREDSTRICT_IMPL", "module")

if IMPL == "stub":
    HAVE_MODULE = True  # the stub IS the implementation under test
    cs = None
else:
    try:
        from gov import credential_strict as cs  # noqa: E402
        HAVE_MODULE = True
    except ImportError:
        HAVE_MODULE = False
        cs = None

# Wave-266 lane: pin -> 1209 (1205 + 4 credential-strict-* codes),
# additive only; sibling pin assertions are the merge coordinator's.
# Enforced at import in module mode; the taxonomy_pin probe reports
# the state in both modes (stub mode pre-build legitimately BREAKs).
if IMPL == "module":
    assert len(decision_codes.TAXONOMY) == 1990, "taxonomy pin 1588"  # Wave-271 merge: pin 1372 -> 1411 (+39 codes: 6 ptgrant-* + 7 replay-* + 8 rsl-* + 14 gatehard-* + 4 imgtext-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)

PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


def _real_value(cid):
    return "tok_synth_strict_%s_9f2c4a1b" % cid.replace("-", "_")


def _check_approval(approval, tool, dest_host):
    """Deployment-shaped approval check: the request must already be
    approved, and the approval must name this tool and destination."""
    return (isinstance(approval, dict)
            and approval.get("decision") == "approved"
            and approval.get("tool") == tool
            and approval.get("dest_host") == dest_host)


def _approval(tool, dest_host):
    return {"approval_id": "appr-1", "decision": "approved",
            "tool": tool, "dest_host": dest_host}


class _StubStrict(object):
    """Permissive pre-strict-tier behavior (the vulnerabilities)."""

    def __init__(self, vault):
        self.vault = vault

    def register_strict(self, credential_id, real_value, inject_hosts,
                        credential_class, **kw):
        # VULNERABILITY: malformed strict config is silently accepted.
        return self.vault.register(credential_id, real_value,
                                   inject_hosts, credential_class)

    def resolve_agent_side(self, vault, tool, args):
        # VULNERABILITY: strict sentinels resolve in the agent-visible
        # execution environment.
        mapping = {}
        for tok in find_sentinels(args):
            rec = vault.lookup(tok)
            if rec is not None and rec.get("real") is not None:
                mapping[tok] = rec["real"]
        return substitute_in(args, mapping)

    def make_injector(self, vault, name, audit, sink):
        return _StubInjector(vault, audit, sink)


class _StubInjector(object):
    """Supervisor path with no controls (the vulnerabilities)."""

    def __init__(self, vault, audit, sink):
        self.vault = vault
        self.audit = audit
        self.sink = sink

    def inject(self, tool, args, approval=None):
        # VULNERABILITIES: no approval check, no host check, real
        # values written into the audit log.
        toks = [t for t in find_sentinels(args)
                if self.vault.lookup(t) is not None]
        mapping = {}
        for tok in toks:
            rec = self.vault.lookup(tok)
            if rec.get("real") is not None:
                mapping[tok] = rec["real"]
        injected = substitute_in(args, mapping)
        self.sink.append(injected)
        self.audit.append({"event": "strict_injected",
                           "real_values": list(mapping.values())})
        return {"injected": injected, "approval": approval}


class _RealStrict(object):
    """Facade over the real strict tier (module mode)."""

    def __init__(self, vault):
        self.vault = vault

    def register_strict(self, credential_id, real_value, inject_hosts,
                        credential_class, **kw):
        return self.vault.register(
            credential_id, real_value, inject_hosts, credential_class,
            strict=True,
            strict_injector=kw.get("injector_name", "egress-prod"),
            release_policy=kw.get("release_policy", "attested"))

    def resolve_agent_side(self, vault, tool, args):
        from gov.sentinel_substitution import substitute_for_execution
        return substitute_for_execution(vault, tool, args)[0]

    def make_injector(self, vault, name, audit, sink):
        def _transport(tool, injected_args, context):
            sink.append(injected_args)
            return {"status": "sent", "tool": tool}

        return cs.StrictEgressInjector(
            vault, name, check_approval=_check_approval,
            transport=_transport, audit=audit)


def _facade(vault):
    if IMPL == "stub":
        return _StubStrict(vault)
    return _RealStrict(vault)


def _new_vault():
    return SentinelVault()


def _refused_code(fn):
    """HELD iff fn raises a SentinelError whose message starts with a
    credential-strict-* machine code."""
    try:
        fn()
    except SentinelError as exc:
        msg = str(exc.args[0]) if exc.args else ""
        if msg.startswith("credential-strict-"):
            return "HELD"
        return "BREAK(wrong %r)" % (msg[:60],)
    except Exception as exc:
        return "BREAK(%s)" % type(exc).__name__
    return "BREAK(no refusal)"


@probe
def strict_agent_side_resolution_refused():
    """Core never-materialize property: the agent-visible execution
    seam must refuse to resolve a strict sentinel."""
    vault = _new_vault()
    facade = _facade(vault)
    real = _real_value("a")
    tok = facade.register_strict("cred-a", real, ["api.example.com"],
                                 "api-key")
    args = {"url": "https://api.example.com/v1",
            "headers": {"Authorization": "Bearer " + tok}}
    try:
        out = facade.resolve_agent_side(vault, "http_post", args)
    except SentinelError as exc:
        msg = str(exc.args[0]) if exc.args else ""
        if msg.startswith("credential-strict-refused"):
            return "HELD"
        return "BREAK(wrong %r)" % (msg[:60],)
    if real in repr(out):
        return "BREAK(agent-side resolution materialized the secret)"
    return "BREAK(resolved without refusal)"


@probe
def strict_default_tier_unaffected():
    """Control: a non-strict sentinel still substitutes agent-side."""
    vault = _new_vault()
    real = _real_value("plain")
    tok = vault.register("cred-plain", real, ["api.example.com"],
                         "api-key", release_policy="legacy-host-only")
    args = {"url": "https://api.example.com/v1",
            "headers": {"Authorization": "Bearer " + tok}}
    if IMPL == "stub":
        out = _facade(vault).resolve_agent_side(vault, "http_post",
                                                args)
    else:
        from gov.sentinel_substitution import substitute_for_execution
        out = substitute_for_execution(vault, "http_post", args)[0]
    if real in repr(out):
        return "HELD"
    return "BREAK(default tier stopped substituting)"


@probe
def strict_injector_requires_approval():
    """Supervisor egress must refuse without a valid approval."""
    vault = _new_vault()
    facade = _facade(vault)
    real = _real_value("b")
    tok = facade.register_strict("cred-b", real, ["api.example.com"],
                                 "api-key")
    audit, sink = [], []
    inj = facade.make_injector(vault, "egress-prod", audit, sink)
    args = {"url": "https://api.example.com/v1",
            "headers": {"Authorization": "Bearer " + tok}}
    v = _refused_code(lambda: inj.inject("http_post", args,
                                        approval=None))
    if v != "HELD":
        return "BREAK(injected without approval: %s)" % (v,)
    v2 = _refused_code(lambda: inj.inject(
        "http_post", args,
        approval={"decision": "denied", "tool": "http_post",
                  "dest_host": "api.example.com"}))
    if v2 != "HELD":
        return "BREAK(injected on denied approval)"
    return "HELD"


@probe
def strict_injector_requires_authorized_host():
    """Supervisor egress must refuse an unauthorized destination."""
    vault = _new_vault()
    facade = _facade(vault)
    real = _real_value("c")
    tok = facade.register_strict("cred-c", real, ["api.example.com"],
                                 "api-key")
    audit, sink = [], []
    inj = facade.make_injector(vault, "egress-prod", audit, sink)
    args = {"url": "https://evil.example.net/v1",
            "headers": {"Authorization": "Bearer " + tok}}
    v = _refused_code(lambda: inj.inject(
        "http_post", args,
        approval=_approval("http_post", "evil.example.net")))
    if v == "HELD":
        return "HELD"
    return "BREAK(injected to unauthorized host)"


@probe
def strict_injector_happy_path():
    """Control: approved + authorized host injects; the agent sees
    only a digest receipt, never the value."""
    vault = _new_vault()
    facade = _facade(vault)
    real = _real_value("d")
    tok = facade.register_strict("cred-d", real, ["api.example.com"],
                                 "api-key")
    audit, sink = [], []
    inj = facade.make_injector(vault, "egress-prod", audit, sink)
    args = {"url": "https://api.example.com/v1",
            "headers": {"Authorization": "Bearer " + tok}}
    try:
        receipt = inj.inject("http_post", args,
                             approval=_approval("http_post",
                                                "api.example.com"))
    except SentinelError as exc:
        return "BREAK(happy path refused: %r)" % (exc.args[0][:60]
                                                 if exc.args else "",)
    if not sink or real not in repr(sink[0]):
        return "BREAK(transport never received the real value)"
    if real in repr(receipt):
        return "BREAK(real value leaked into the agent receipt)"
    if "injected_digest" not in receipt:
        return "BREAK(no digest receipt)"
    return "HELD"


@probe
def strict_no_real_value_in_audit():
    """Audit, vault repr, and receipts must never carry real values."""
    vault = _new_vault()
    facade = _facade(vault)
    real = _real_value("e")
    tok = facade.register_strict("cred-e", real, ["api.example.com"],
                                 "api-key")
    audit, sink = [], []
    inj = facade.make_injector(vault, "egress-prod", audit, sink)
    args = {"url": "https://api.example.com/v1",
            "headers": {"Authorization": "Bearer " + tok}}
    try:
        receipt = inj.inject("http_post", args,
                             approval=_approval("http_post",
                                                "api.example.com"))
    except SentinelError:
        receipt = {}
    try:
        facade.resolve_agent_side(vault, "http_post", args)
    except SentinelError:
        pass
    haystacks = [repr(audit), repr(vault), repr(receipt)]
    for hay in haystacks:
        if real in hay:
            return "BREAK(real value leaked: %r)" % (hay[:80],)
    return "HELD"


@probe
def strict_malformed_config_fails_closed():
    """strict=True with a missing/empty injector binding must refuse
    and register nothing."""
    vault = _new_vault()
    before = len(vault)
    if IMPL == "stub":
        facade = _facade(vault)
        try:
            facade.vault.register(
                "cred-bad", _real_value("bad"), ["api.example.com"],
                "api-key", strict=True, strict_injector="")
        except TypeError:
            # The stub has no strict kwargs at all: the config is
            # silently un-enforceable -- the vulnerability.
            return "BREAK(malformed strict config accepted)"
        return "BREAK(malformed strict config accepted)"
    try:
        vault.register("cred-bad", _real_value("bad"),
                       ["api.example.com"], "api-key",
                       strict=True, strict_injector="")
        return "BREAK(empty injector binding accepted)"
    except SentinelError as exc:
        msg = str(exc.args[0]) if exc.args else ""
        if not msg.startswith("credential-strict-config-invalid"):
            return "BREAK(wrong %r)" % (msg[:60],)
    try:
        vault.register("cred-bad2", _real_value("bad2"),
                       ["api.example.com"], "api-key",
                       strict=True, strict_injector=None)
        return "BREAK(None injector binding accepted)"
    except SentinelError as exc:
        msg = str(exc.args[0]) if exc.args else ""
        if not msg.startswith("credential-strict-config-invalid"):
            return "BREAK(wrong %r)" % (msg[:60],)
    if len(vault) != before:
        return "BREAK(refused but registered)"
    return "HELD"


@probe
def strict_injector_name_binding():
    """A credential bound to one strict injector cannot be injected
    through another injector instance."""
    vault = _new_vault()
    facade = _facade(vault)
    real = _real_value("f")
    tok = facade.register_strict("cred-f", real, ["api.example.com"],
                                 "api-key", injector_name="egress-prod")
    audit, sink = [], []
    inj = facade.make_injector(vault, "egress-dev", audit, sink)
    args = {"url": "https://api.example.com/v1",
            "headers": {"Authorization": "Bearer " + tok}}
    v = _refused_code(lambda: inj.inject(
        "http_post", args,
        approval=_approval("http_post", "api.example.com")))
    if v == "HELD":
        return "HELD"
    return "BREAK(cross-injector injection allowed)"


@probe
def strict_unknown_sentinel_refused():
    """The strict injector refuses sentinel-shaped tokens it did not
    mint (no attribution possible, fail closed)."""
    vault = _new_vault()
    facade = _facade(vault)
    audit, sink = [], []
    inj = facade.make_injector(vault, "egress-prod", audit, sink)
    args = {"url": "https://api.example.com/v1",
            "headers": {"Authorization":
                        "Bearer fake_value_"
                        "12345678-1234-1234-1234-123456789abc"}}
    v = _refused_code(lambda: inj.inject(
        "http_post", args,
        approval=_approval("http_post", "api.example.com")))
    if v == "HELD":
        return "HELD"
    return "BREAK(unknown sentinel injected: %s)" % (v,)


@probe
def taxonomy_pin():
    """Pin 1209: 4 credential-strict-* codes, unique raw literals."""
    import re
    src = open(os.path.join(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))),
        "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code": \'(credential-strict-[a-z-]+)\'', src)
    if len(decision_codes.TAXONOMY) != 1990:  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)
        return "BREAK(pin %d)" % len(decision_codes.TAXONOMY)
    if sorted(set(lits)) != sorted(lits) or len(lits) != 4:
        return "BREAK(literals %r)" % (lits,)
    expected = ["credential-strict-config-invalid",
                "credential-strict-host-denied",
                "credential-strict-refused",
                "credential-strict-unapproved"]
    if sorted(lits) != expected:
        return "BREAK(codes %r)" % (sorted(lits),)
    return "HELD"


@probe
def deterministic_x2():
    """Verdicts byte-identical across two runs (fresh vaults)."""
    first = [(p.__name__, p()) for p in PROBES
             if p.__name__ not in ("deterministic_x2", "adjacent_green",
                                   "taxonomy_pin")]
    second = [(p.__name__, p()) for p in PROBES
              if p.__name__ not in ("deterministic_x2", "adjacent_green",
                                    "taxonomy_pin")]
    if first == second:
        return "HELD"
    return "BREAK(%r)" % ([a for a, b in zip(first, second)
                           if a != b],)


def _adjacent_once(env, repo, td):
    """One run of the adjacent battery. Returns (ok, break_ct, err_ct)."""
    import re
    import subprocess
    cmd = [sys.executable, "evals/adversarial_sentinel_substitution.py"]
    r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                       text=True, timeout=600)
    out = r.stdout + r.stderr
    m = re.search(r"(\d+)\s+BREAK", out)
    e = re.search(r"(\d+)\s+ERROR", out)
    brk = int(m.group(1)) if m else None
    err = int(e.group(1)) if e else None
    ok = (r.returncode == 0 and brk == 0 and err == 0)
    return ok, brk, err, out


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN.

    The existing sentinel substitution battery (no taxonomy pin
    assertion) must stay green under the strict-tier change. It has a
    rare pre-existing flake (~1% of runs): the DLP entropy tripwire
    fires on a random sentinel uuid in the ``payload={"api_key":
    sentinel}`` queue shape (sit_a2/sit_a7 ERROR, never BREAK; the
    lane's diff does not touch dlp.py, the executor DLP path, or
    minting — verified by code reading and 100+ runs). The check
    retries up to 3 times to ride out that flake; a genuine lane
    regression (any BREAK, or 3 consecutive ERROR runs) still fails.
    """
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import tempfile
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    last = None
    for attempt in range(3):
        td = tempfile.mkdtemp(prefix="g266-credstrict-green-",
                              dir="/var/tmp")
        env["TMPDIR"] = td
        ok, brk, err, out = _adjacent_once(env, repo, td)
        last = (ok, brk, err, out)
        if ok:
            if attempt:
                print("GREEN CHECK: adjacent green after %d retries "
                      "(pre-existing DLP-entropy flake)"
                      % (attempt,))
            else:
                print("GREEN CHECK: adversarial_sentinel_substitution "
                      "green")
            return True
        # A BREAK is never the flake signature: fail immediately.
        if brk:
            break
    ok, brk, err, out = last
    print("GREEN CHECK FAILED: adversarial_sentinel_substitution "
          "(BREAK=%s ERROR=%s)" % (brk, err))
    print(out[-1500:])
    return False


@probe
def adjacent_green():
    """Depth-1 adjacent battery stays green under the strict change."""
    if green_check():
        return "HELD"
    return "BREAK(adjacent battery red)"


def main():
    results = []
    if not HAVE_MODULE:
        for p in PROBES:
            results.append((p.__name__, "GAP"))
    else:
        for p in PROBES:
            try:
                results.append((p.__name__, p()))
            except Exception as exc:  # never mask a crash
                results.append((p.__name__, "BREAK(%r)" % (exc,)))
    held = sum(1 for _, v in results if v == "HELD")
    brk = sum(1 for _, v in results if v.startswith("BREAK"))
    gap = sum(1 for _, v in results if v == "GAP")
    for name, verdict in results:
        print("%-38s %s" % (name, verdict))
    print("HELD %d / BREAK %d / GAP %d of %d [%s]"
          % (held, brk, gap, len(results), IMPL))
    return 1 if (brk or gap) else 0


if __name__ == "__main__":
    sys.exit(main())
