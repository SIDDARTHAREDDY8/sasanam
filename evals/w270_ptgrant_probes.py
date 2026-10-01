"""Break-first battery for gov/tool_grant.py (per-tool MCP authorization).

Red phase: GOV_PTGRANT_IMPL=stub routes every probe through a permissive
foil that grants everything -- all attack probes must BREAK there, proving
the probes are real. Green phase: the real module must HOLD every probe,
deterministic (A==B), in staging and under `env -u GOV_DEPLOYMENT_MODE`.
"""
import base64
import hashlib
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

TAXONOMY_PIN = 1372  # Wave-270 merge: pin 1325 -> 1372 (+47 codes: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).

STUB = os.environ.get("GOV_PTGRANT_IMPL") == "stub"

if not STUB:
    from gov import tool_grant
    from gov import ed25519 as _ed


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

ISS_SEED = bytes.fromhex("01" * 32)
ISS_PUB = _ed.publickey(ISS_SEED) if not STUB else b""

HOLDER_SEED = bytes.fromhex("02" * 32)
HOLDER_PUB = _ed.publickey(HOLDER_SEED) if not STUB else b""

ATTACKER_SEED = bytes.fromhex("03" * 32)
ATTACKER_PUB = _ed.publickey(ATTACKER_SEED) if not STUB else b""

NOW = 1790000000
AUD = "https://mcp.example.internal/fileserver"
SUB = "spiffe://trust-domain/ns/prod/sa/agent-7"


def details_for(tool, **kw):
    d = {
        "type": "https://sasanam.dev/mcp_tool_call",
        "locations": [AUD],
        "actions": ["call"],
        "identifier": "fileserver::" + tool,
        "arg_bounds": {
            "path": {"predicate": "prefix", "params": {"prefix": "/data/shared/"}},
        },
        "supply_chain": {"link_digest": "sha256:" + "ab" * 32, "delegation_ok": True},
        "max_calls": 1,
    }
    d.update(kw)
    return d


def issue(details, **kw):
    iss = tool_grant.Issuer(
        iss="sasanam-tool-as", issuer_seed=ISS_SEED, mandate_lookup=lambda m: {"version": 14},
    )
    if "lifetime_s" not in kw:
        kw["lifetime_s"] = 600
    return iss.issue(
        sub=SUB,
        aud=AUD,
        proof_pub=HOLDER_PUB,
        mandate_id="mnd_9f2",
        mandate_version=14,
        details=details,
        now=NOW,
        **kw,
    )


def ok_usage():
    return tool_grant.UsageStore()


def enforce_env(**kw):
    env = dict(
        issuer_pub=ISS_PUB,
        server_name="fileserver",
        server_uri=AUD,
        now=NOW,
        usage_store=ok_usage(),
        mandate_version_provider=lambda m: 14,
        link_verifier=lambda tool: "sha256:" + "ab" * 32,
    )
    env.update(kw)
    return env


def pop_proof(grant, seed=HOLDER_SEED, **kw):
    return tool_grant.make_pop_proof(seed, grant, method="tools/call",
                                     uri=AUD + "/tools/call", now=NOW, **kw)


def call(tool, args, grant, **kw):
    env = enforce_env(**kw)
    proof = pop_proof(grant)
    return tool_grant.enforce(grant, proof=proof, tool=tool, args=args, **env)


def attack(name, fn, want_code=None):
    """Run an attack probe. Returns (held, evidence)."""
    try:
        verdict = fn()
    except Exception as exc:  # noqa: BLE001 -- probe robustness
        return False, "EXCEPTION: %r" % (exc,)
    ok = bool(verdict.get("ok"))
    code = verdict.get("code")
    if ok:
        return False, "BREAK: granted with code=%r" % (code,)
    if want_code and code != want_code:
        return False, "BREAK: refused but wrong code %r (want %r)" % (code, want_code)
    return True, "HELD: %r" % (code,)


def control(name, fn, want_code="ptgrant-ok"):
    try:
        verdict = fn()
    except Exception as exc:  # noqa: BLE001
        return False, "EXCEPTION: %r" % (exc,)
    if verdict.get("ok") and verdict.get("code") == want_code:
        return True, "OK"
    return False, "FAIL: %r" % (verdict,)


# --------------------------------------------------------------------------
# Attack probes
# --------------------------------------------------------------------------

def p01_forged_signature():
    """A grant signed by the attacker's key must be refused."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    iss = tool_grant.Issuer(iss="sasanam-tool-as", issuer_seed=ATTACKER_SEED,
                            mandate_lookup=lambda m: {"version": 14})
    g = iss.issue(sub=SUB, aud=AUD, proof_pub=ATTACKER_PUB, mandate_id="mnd_9f2",
                  mandate_version=14, details=[details_for("read_file")],
                  lifetime_s=600, now=NOW)
    return call("read_file", {"path": "/data/shared/a.txt"}, g)


def p02_wrong_audience():
    """A grant for server A presented at server B must be refused."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    g = issue([details_for("read_file")])
    env = enforce_env(server_uri="https://mcp.example.internal/otherserver")
    return tool_grant.enforce(g, proof=pop_proof(g), tool="read_file",
                              args={"path": "/data/shared/a.txt"}, **env)


def p03_identifier_exact_match():
    """Grant covers read_file; calling delete_file must be refused."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    g = issue([details_for("read_file")])
    return call("delete_file", {"path": "/data/shared/a.txt"}, g)


def p04_prefix_attack():
    """read_file2 must not match identifier fileserver::read_file."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    g = issue([details_for("read_file")])
    return call("read_file2", {"path": "/data/shared/a.txt"}, g)


def p05_arg_bound_violation():
    """/etc/passwd violates the /data/shared/ prefix bound."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    g = issue([details_for("read_file")])
    return call("read_file", {"path": "/etc/passwd"}, g)


def p06_unknown_predicate():
    """A grant carrying an unregistered predicate must fail closed.

    Fail-closed at issuance: the issuer refuses to mint the grant.
    GrantError with the expected code counts as HELD (refused, loud)."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    d = details_for("read_file")
    d["arg_bounds"] = {"path": {"predicate": "telepathy", "params": {}}}
    try:
        g = issue([d])
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        # GrantError("ptgrant-predicate-unknown") = fail-closed refusal (HELD).
        # Any other exception, or a successful issue, = the refusal did not
        # happen where required (BREAK).
        return {"ok": code != "ptgrant-predicate-unknown",
                "code": code or "ptgrant-refused", "detail": str(exc)}
    return call("read_file", {"path": "/data/shared/a.txt"}, g)


def p07_expired_grant():
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    g = issue([details_for("read_file")], lifetime_s=60)
    env = enforce_env(now=NOW + 61)
    return tool_grant.enforce(g, proof=pop_proof(g), tool="read_file",
                              args={"path": "/data/shared/a.txt"}, **env)


def p08_max_calls_exhausted():
    """One-shot grant: second call must be refused."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    g = issue([details_for("read_file")])
    store = ok_usage()
    env = enforce_env(usage_store=store)
    proof = pop_proof(g)
    v1 = tool_grant.enforce(g, proof=proof, tool="read_file",
                            args={"path": "/data/shared/a.txt"}, **env)
    if not v1.get("ok"):
        return {"ok": True, "code": "first-call-unexpectedly-refused"}
    proof2 = tool_grant.make_pop_proof(HOLDER_SEED, g, method="tools/call",
                                       uri=AUD + "/tools/call", now=NOW + 1,
                                       nonce=b"n2")
    return tool_grant.enforce(g, proof=proof2, tool="read_file",
                              args={"path": "/data/shared/a.txt"}, **env)


def p09_mandate_drift():
    """Mandate narrowed after issuance: enforcement must fail closed."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    g = issue([details_for("read_file")])
    env = enforce_env(mandate_version_provider=lambda m: 15)
    return tool_grant.enforce(g, proof=pop_proof(g), tool="read_file",
                              args={"path": "/data/shared/a.txt"}, **env)


def p10_cnf_confusion():
    """PoP proof from the attacker's key must not satisfy the cnf binding."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    g = issue([details_for("read_file")])
    bad_proof = tool_grant.make_pop_proof(ATTACKER_SEED, g, method="tools/call",
                                          uri=AUD + "/tools/call", now=NOW)
    env = enforce_env()
    return tool_grant.enforce(g, proof=bad_proof, tool="read_file",
                              args={"path": "/data/shared/a.txt"}, **env)


def p11_unknown_caveat():
    """Attenuation with an unrecognized caveat predicate must fail closed.

    Fail-closed at attenuation time: the caveat is refused before it can
    be recorded. GrantError with the expected code counts as HELD."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    g = issue([details_for("read_file")])
    try:
        g2 = tool_grant.attenuate(g, holder_seed=HOLDER_SEED, issuer_pub=ISS_PUB,
                                  caveats=[{"predicate": "mystery", "params": {}}])
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        # GrantError("ptgrant-predicate-unknown") = fail-closed refusal (HELD).
        # Any other exception, or a successful issue, = the refusal did not
        # happen where required (BREAK).
        return {"ok": code != "ptgrant-predicate-unknown",
                "code": code or "ptgrant-refused", "detail": str(exc)}
    return call("read_file", {"path": "/data/shared/a.txt"}, g2)


def p12_supply_chain_mismatch():
    """Link digest mismatch at enforcement must refuse."""
    if STUB:
        return {"ok": True, "code": "stub-foil"}
    g = issue([details_for("read_file")])
    env = enforce_env(link_verifier=lambda tool: "sha256:" + "ff" * 32)
    return tool_grant.enforce(g, proof=pop_proof(g), tool="read_file",
                              args={"path": "/data/shared/a.txt"}, **env)


ATTACKS = [
    ("ptgrant/forged-signature", p01_forged_signature, "ptgrant-signature-invalid"),
    ("ptgrant/confused-audience", p02_wrong_audience, "ptgrant-audience-mismatch"),
    ("ptgrant/identifier-mismatch", p03_identifier_exact_match, "ptgrant-tool-not-covered"),
    ("ptgrant/prefix-confusion", p04_prefix_attack, "ptgrant-tool-not-covered"),
    ("ptgrant/arg-bound-violation", p05_arg_bound_violation, "ptgrant-arg-bound-violated"),
    ("ptgrant/unknown-predicate", p06_unknown_predicate, "ptgrant-predicate-unknown"),
    ("ptgrant/expired", p07_expired_grant, "ptgrant-grant-expired"),
    ("ptgrant/max-calls-exhausted", p08_max_calls_exhausted, "ptgrant-max-calls-exhausted"),
    ("ptgrant/mandate-drift", p09_mandate_drift, "ptgrant-mandate-drift"),
    ("ptgrant/cnf-confusion", p10_cnf_confusion, "ptgrant-pop-invalid"),
    ("ptgrant/unknown-caveat", p11_unknown_caveat, "ptgrant-predicate-unknown"),
    ("ptgrant/supply-chain-mismatch", p12_supply_chain_mismatch, "ptgrant-supply-chain-failed"),
]


def c01_happy_path():
    if STUB:
        return {"ok": True, "code": "ptgrant-ok"}
    g = issue([details_for("read_file")])
    return call("read_file", {"path": "/data/shared/a.txt"}, g)


def c02_attenuated_narrowing():
    """Legit attenuation (tighter bound, same holder): in-scope call
    enforces; out-of-narrowing call is refused."""
    if STUB:
        return {"ok": True, "code": "ptgrant-ok"}
    d = details_for("read_file")
    d["arg_bounds"] = {"path": {"predicate": "prefix", "params": {"prefix": "/data/shared/"}}}
    d["max_calls"] = 5
    g = issue([d])
    g2 = tool_grant.attenuate(g, holder_seed=HOLDER_SEED, issuer_pub=ISS_PUB, caveats=[
        {"predicate": "arg_bound", "params": {"arg": "path", "predicate": "prefix",
                                             "params": {"prefix": "/data/shared/project/"}}},
        {"predicate": "max_calls", "params": {"max_calls": 1}},
    ])
    store = ok_usage()
    env = enforce_env(usage_store=store)
    v1 = tool_grant.enforce(g2, proof=pop_proof(g2), tool="read_file",
                            args={"path": "/data/shared/project/x.txt"}, **env)
    if not v1.get("ok"):
        return {"ok": False, "code": "narrowed-call-unexpectedly-refused", "detail": repr(v1)}
    proof2 = tool_grant.make_pop_proof(HOLDER_SEED, g2, method="tools/call",
                                       uri=AUD + "/tools/call", now=NOW + 1, nonce="c2n2")
    v2 = tool_grant.enforce(g2, proof=proof2, tool="read_file",
                            args={"path": "/data/shared/other.txt"}, **env)
    if v2.get("ok") or v2.get("code") != "ptgrant-arg-bound-violated":
        return {"ok": False, "code": "narrowing-not-enforced", "detail": repr(v2)}
    return {"ok": True, "code": "ptgrant-ok"}


def c03_exchange_narrows():
    """RFC 8693-style exchange: narrower PTG issues, broader parent not revoked."""
    if STUB:
        return {"ok": True, "code": "ptgrant-ok"}
    iss = tool_grant.Issuer(iss="sasanam-tool-as", issuer_seed=ISS_SEED,
                            mandate_lookup=lambda m: {"version": 14})
    parent = iss.issue(sub=SUB, aud=AUD, proof_pub=HOLDER_PUB, mandate_id="mnd_9f2",
                       mandate_version=14,
                       details=[details_for("read_file", max_calls=10)],
                       lifetime_s=600, now=NOW)
    child = iss.exchange(parent, issuer_seed=ISS_SEED,
                         details=[details_for("read_file", max_calls=1)],
                         now=NOW, proof_pub=HOLDER_PUB, lifetime_s=60)
    env = enforce_env()
    vc = tool_grant.enforce(child, proof=pop_proof(child), tool="read_file",
                            args={"path": "/data/shared/a.txt"}, **env)
    if not vc.get("ok"):
        return vc
    # Parent still valid (exchange does not revoke -- documented trap).
    return call("read_file", {"path": "/data/shared/a.txt"}, parent)


def c04_act_is_informational():
    """Nested act claims never change the decision."""
    if STUB:
        return {"ok": True, "code": "ptgrant-ok"}
    g = issue([details_for("read_file")],
              act={"sub": "user:mallory@evil.example", "act": {"sub": "user:admin@example"}})
    return call("read_file", {"path": "/data/shared/a.txt"}, g)


def c05_multi_tool_grant():
    """Two details objects, two tools -- each enforces its own."""
    if STUB:
        return {"ok": True, "code": "ptgrant-ok"}
    g = issue([details_for("read_file"), details_for("list_dir")])
    v1 = call("read_file", {"path": "/data/shared/a.txt"}, g)
    if not v1.get("ok"):
        return v1
    return call("list_dir", {"path": "/data/shared/"}, g)


CONTROLS = [
    ("ptgrant/happy-path", c01_happy_path),
    ("ptgrant/attenuated-narrowing", c02_attenuated_narrowing),
    ("ptgrant/exchange-narrows", c03_exchange_narrows),
    ("ptgrant/act-informational", c04_act_is_informational),
    ("ptgrant/multi-tool", c05_multi_tool_grant),
]


# --------------------------------------------------------------------------
# Green checks (depth-1, honor GOV_SKIP_GREEN)
# --------------------------------------------------------------------------

def green_checks():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("skip", True, "GOV_SKIP_GREEN=1")]
    import subprocess
    out = []
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for mod in ("tests.test_tool_grant",):
        try:
            r = subprocess.run([sys.executable, "-m", "unittest", mod],
                               capture_output=True, text=True, timeout=300,
                               cwd=REPO, env=env)
            out.append((mod, r.returncode == 0, r.stderr[-200:] if r.returncode else "ok"))
        except Exception as exc:  # noqa: BLE001
            out.append((mod, False, repr(exc)))
    return out


def main():
    held = brk = err = 0
    for name, fn, want in ATTACKS:
        h, ev = attack(name, fn, want)
        if h:
            held += 1
            print("HELD   %s -- %s" % (name, ev))
        else:
            if ev.startswith("EXCEPTION"):
                err += 1
                print("ERROR  %s -- %s" % (name, ev))
            else:
                brk += 1
                print("BREAK  %s -- %s" % (name, ev))
    for name, fn in CONTROLS:
        h, ev = control(name, fn)
        if h:
            held += 1
            print("HELD   %s (control) -- %s" % (name, ev))
        else:
            brk += 1
            print("BREAK  %s (control) -- %s" % (name, ev))
    gc = green_checks()
    gfail = [g for g in gc if not g[1]]
    print("RESULT %s HELD=%d BREAK=%d ERROR=%d GREEN=%d/%d" % (
        "OK" if brk == 0 and err == 0 and not gfail else "FAIL",
        held, brk, err, len(gc) - len(gfail), len(gc)))
    return 0 if (brk == 0 and err == 0 and not gfail) else 1


if __name__ == "__main__":
    sys.exit(main())
