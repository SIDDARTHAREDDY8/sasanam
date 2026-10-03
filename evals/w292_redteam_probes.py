"""Wave-292 independent red-team battery (Lane 4): attack the wave-291 merge.

Base: wave-291 merge commit 255478fc50beaf723eed0c4f3824d1a13f621535
(verified via git rev-parse HEAD after clone; ls-remote agrees).
gov/ is byte-identical (attack only, no product code).

Attack surface (all wave-291 additions and residual seams):
  (a) gov/delegation_chain.py -- narrowing at verification: capability
      substitution at hop 2 (does the chain re-verify EVERY hop or only
      the leaf?); proof-of-possession replay across chains (is the
      chain_digest really bound in the PoP message?); ceremony_nonce
      tampering (which code fires; can a stripped-nonce delegation be
      re-wrapped?); root_policy unbounded-but-trusted anchors (can an
      unbounded anchor's delegation escape the root bound?);
      invocation-receipt forgery (is there any receipt-accepting seam?).
  (b) F352-F356 closures, re-pinned (0 BREAK expected) plus seam-edge
      attacks: sink-isolation masking (can a sink failure mask a real
      verification decision?); _is_hex(sig,128) length audit (is 128
      right for every signature path; any fromhex left unguarded in the
      closure modules?); json.load sweep (every file-loading public
      seam hit with a corrupt file).
  (c) Cross-module: revoked credentials -- the older delegation_tokens
      mechanism HAS a revocation seam; the newer delegation_chain has
      none (expected-open design space; wave-292 lanes 2/3 are building
      it -- not filed, documented here).

Re-pins at the public seams:
  F311-F356 (CLOSED) -- 0 BREAK expected (w290_redteam, w289_redteam,
      w291_f352, w291_f353_f355, w291_f354, w291_delegation,
      w290_rebuild, w290_f348_f349 subprocesses).
  F356 (OPEN at base) -- 2 BREAK expected-open
      (rb-execute-unvalidated-keyerror, rb-execute-unvalidated-unknown-op).

New finding filed from F357 with severity label and falsifiable
close-when criteria.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g292-redteam && TMPDIR=/var/tmp/g292-redteam \\
    ~/workspace/.gov-venv/bin/python evals/w292_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g292-redteam2 \\
    ~/workspace/.gov-venv/bin/python evals/w292_redteam_probes.py
"""

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-291 merge: pin 1710 -> 1715 (+5 delegation-*).
TAXONOMY_PIN = 1797  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    silent pass."""
    try:
        fn()
    except Exception:  # noqa: BLE001
        _record(pid, "ERROR", "unexpected exception: %s"
                % traceback.format_exc(limit=3).replace("\n", " | "))
        return
    if not any(p == pid or p.startswith(pid + "-")
               for p, _, _ in _results):
        _record(pid, "ERROR", "probe recorded nothing")


def _literals():
    # Wave-260 lesson: assert on source literals in decision_codes.py,
    # not len(TAXONOMY) (dict dedup hides duplicate inserts).
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1797/1797/0 sorted")


# ---------------------------------------------------------------------------
# F356 re-pins (OPEN at base -- 2 BREAK expected)
# ---------------------------------------------------------------------------

def p_rb_execute_unvalidated_keyerror():
    from gov import evidence_provenance as ep
    try:
        ep.execute_rebuild({}, {})
    except KeyError:
        return _record("rb-execute-unvalidated-keyerror", "BREAK",
                       "execute_rebuild({}) escapes bare KeyError "
                       "(code=None); F356 facet (a) still open")
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code and str(code).startswith("provenance-rebuild"):
            return _record("rb-execute-unvalidated-keyerror", "HELD",
                           "malformed recipe refused coded %s" % code)
        return _record("rb-execute-unvalidated-keyerror", "BREAK",
                       "unexpected %r code=%r" % (e, code))
    _record("rb-execute-unvalidated-keyerror", "BREAK",
            "execute_rebuild({}) did not raise at all")


def p_rb_execute_unvalidated_unknown_op():
    from gov import evidence_provenance as ep
    # Wave-292 merge: the recipe must be shape-valid so it reaches the
    # op check (a missing recipe_format correctly refuses
    # provenance-rebuild-invalid first -- shape before semantics).
    recipe = {"recipe_format": "sasanam-rebuild/1",
              "inputs": ["m"],
              "steps": [{"op": "nope-not-a-transform"},
                        {"op": "sha256"}]}
    try:
        out = ep.execute_rebuild(recipe, {"m": b"x"})
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code == "provenance-rebuild-transform-unknown":
            return _record("rb-execute-unvalidated-unknown-op", "HELD",
                           "unknown op refused coded")
        return _record("rb-execute-unvalidated-unknown-op", "BREAK",
                       "unexpected %r code=%r" % (e, code))
    _record("rb-execute-unvalidated-unknown-op", "BREAK",
            "unknown op silently passed bytes through unchanged "
            "(out=%r); F356 facet (b) still open" % (out,))


# ---------------------------------------------------------------------------
# (a) delegation_chain attacks
# ---------------------------------------------------------------------------

def _keypair():
    from gov import ed25519
    seed = secrets.token_bytes(32)
    return seed, ed25519.publickey(seed).hex()


def _chain3(now):
    from gov import delegation_chain as dc
    rs, rp = _keypair()
    ms, mp = _keypair()
    ls, lp = _keypair()
    r0 = dc.delegate(rs, None, {
        "audience": mp,
        "capabilities": [{"with": "fs:/", "can": ["read", "write"]}],
        "not_before": now - 10, "not_after": now + 3600, "ttl": 3610})
    r1 = dc.delegate(ms, [{"with": "fs:/", "can": ["read", "write"]}], {
        "audience": lp,
        "capabilities": [{"with": "fs:/docs", "can": ["read"]}],
        "not_before": now - 10, "not_after": now + 3600, "ttl": 3610,
        "parent": r0})
    return dc, (rs, rp), (ms, mp), (ls, lp), r0, r1


def p_dlg_hop2_widen_refused():
    # Capability substitution at hop 2: hand-craft a hop whose
    # parent_digest links hop 1 but whose caps EXCEED hop 1's. The
    # chain must re-verify every hop, not just the leaf.
    from gov import delegation_chain as dc
    from gov import ed25519
    now = time.time()
    _, (rs, rp), _, (ls, lp), r0, r1 = _chain3(now)
    body = dict(r1["delegation"])
    body["capabilities"] = [{"with": "fs:/docs", "can": ["read", "write"]}]
    body["issuer"] = lp
    body["audience"] = lp
    body["nonce"] = "w292-evil-nonce-1"
    body["parent_digest"] = dc.digest_of(r1["delegation"])
    sig = ed25519.sign(ls, dc.SIGN_DOMAIN + dc._canonical(body)).hex()
    wide = {"delegation": body, "signature": sig}
    # Sanity: the crafted hop is signature-valid on its own terms.
    dc.DelegationVerifier([rp])._verify_signature(body, sig)
    v = dc.DelegationVerifier([rp])
    try:
        v.verify([r0, r1, wide], {"with": "fs:/docs", "can": "write"},
                 now=now)
    except dc.DelegationAttenuationInverted:
        return _record("dlg-hop2-widen-refused", "HELD",
                       "hop-2 widening refused delegation-attenuation-"
                       "inverted; every hop re-verified")
    except dc.DelegationError as e:
        return _record("dlg-hop2-widen-refused", "BREAK",
                       "widening refused with wrong code %s" % e.code)
    _record("dlg-hop2-widen-refused", "BREAK",
            "hop-2 capability widening VERIFIED")


def p_dlg_issue_time_widen_refused():
    from gov import delegation_chain as dc
    now = time.time()
    _, _, (ms, mp), (ls, lp), r0, _ = _chain3(now)
    try:
        dc.delegate(ms, [{"with": "fs:/docs", "can": ["read"]}], {
            "audience": lp,
            "capabilities": [{"with": "fs:/docs",
                              "can": ["read", "write"]}],
            "not_before": now - 10, "not_after": now + 3600, "ttl": 3610,
            "parent": r0})
    except dc.DelegationWouldWiden:
        return _record("dlg-issue-time-widen-refused", "HELD",
                       "issue-time widening refused "
                       "delegation-would-widen")
    except dc.DelegationError as e:
        return _record("dlg-issue-time-widen-refused", "BREAK",
                       "wrong code %s" % e.code)
    _record("dlg-issue-time-widen-refused", "BREAK",
            "issue-time widening not refused")


def p_dlg_pop_cross_chain_replay_refused():
    # A PoP minted for chain A must not verify against chain B, even
    # when the same invoker key is the leaf audience of both.
    from gov import delegation_chain as dc
    from gov import ed25519
    now = time.time()
    _, (rs, rp), _, (ls, lp), r0, r1 = _chain3(now)
    r2 = dc.delegate(ls, [{"with": "fs:/docs", "can": ["read"]}], {
        "audience": lp,
        "capabilities": [{"with": "fs:/docs", "can": ["read"]}],
        "not_before": now - 10, "not_after": now + 3600, "ttl": 3610, "parent": r1})
    chal = b"w292-fresh-challenge-12345678"
    v = dc.DelegationVerifier([rp], seed=ls)
    leaf_digest = dc.digest_of(r2["delegation"])
    pop_sig = ed25519.sign(
        ls, v._pop_signing_bytes(lp, chal, leaf_digest)).hex()
    # Positive control: the PoP verifies against its own chain.
    v.verify_invocation([r0, r1, r2], {"with": "fs:/docs", "can": "read"},
                        invoker_pubkey_hex=lp, pop_challenge=chal,
                        pop_signature_hex=pop_sig, now=now)
    # Attack: a different chain B with the same leaf audience.
    bs, bp = _keypair()
    rb0 = dc.delegate(bs, None, {
        "audience": lp,
        "capabilities": [{"with": "fs:/", "can": ["read"]}],
        "not_before": now - 10, "not_after": now + 3600, "ttl": 3610})
    vB = dc.DelegationVerifier([rp, bp], seed=ls)
    try:
        vB.verify_invocation([rb0], {"with": "fs:/x", "can": "read"},
                             invoker_pubkey_hex=lp, pop_challenge=chal,
                             pop_signature_hex=pop_sig, now=now)
    except dc.DelegationPopSignatureInvalid:
        return _record("dlg-pop-cross-chain-replay-refused", "HELD",
                       "chain_digest is bound in the PoP message; "
                       "cross-chain replay refused "
                       "delegation-pop-signature-invalid")
    except dc.DelegationError as e:
        return _record("dlg-pop-cross-chain-replay-refused", "BREAK",
                       "wrong code %s" % e.code)
    _record("dlg-pop-cross-chain-replay-refused", "BREAK",
            "PoP replayed across chains VERIFIED")


def p_dlg_graft_custody_splice_refused():
    # An unrelated keyholder grafts a narrower delegation onto an
    # observed sealed delegation (valid sig, valid digest link).
    from gov import delegation_chain as dc
    from gov import ed25519
    now = time.time()
    _, (rs, rp), _, (ls, lp), r0, _ = _chain3(now)
    es, ep_ = _keypair()
    evil_body = {"type": dc.DELEGATION_TYPE, "issuer": ep_,
                 "audience": lp,
                 "capabilities": [{"with": "fs:/docs", "can": ["read"]}],
                 "not_before": now - 10, "not_after": now + 3600,
                 # Wave-292 merge: decay-era fields so the body reaches
                 # the custody-splice check (pre-decay bodies refuse
                 # delegation-expired before it).
                 "issued_at": now - 10, "ttl_seconds": 3610,
                 "generation": 0,
                 "nonce": "w292-graft-1",
                 "parent_digest": dc.digest_of(r0["delegation"]),
                 "ceremony_nonce": None}
    evil_sig = ed25519.sign(
        es, dc.SIGN_DOMAIN + dc._canonical(evil_body)).hex()
    v = dc.DelegationVerifier([rp])
    try:
        v.verify([r0, {"delegation": evil_body, "signature": evil_sig}],
                 {"with": "fs:/docs", "can": "read"}, now=now)
    except dc.DelegationCustodySplice:
        return _record("dlg-graft-custody-splice-refused", "HELD",
                       "grafted hop refused delegation-custody-splice "
                       "(F249 holds)")
    except dc.DelegationError as e:
        return _record("dlg-graft-custody-splice-refused", "BREAK",
                       "wrong code %s" % e.code)
    _record("dlg-graft-custody-splice-refused", "BREAK",
            "grafted custody path VERIFIED")


def p_dlg_untrusted_root_refused():
    from gov import delegation_chain as dc
    now = time.time()
    _, (_, rp), _, _, _, _ = _chain3(now)
    es, _ = _keypair()
    _, lp = _keypair()
    ur0 = dc.delegate(es, None, {
        "audience": lp,
        "capabilities": [{"with": "fs:/", "can": ["read"]}],
        "not_before": now - 10, "not_after": now + 3600, "ttl": 3610})
    v = dc.DelegationVerifier([rp])
    try:
        v.verify([ur0], {"with": "fs:/", "can": "read"}, now=now)
    except dc.DelegationRootUntrusted:
        return _record("dlg-untrusted-root-refused", "HELD",
                       "untrusted root refused")
    except dc.DelegationError as e:
        return _record("dlg-untrusted-root-refused", "BREAK",
                       "wrong code %s" % e.code)
    _record("dlg-untrusted-root-refused", "BREAK",
            "untrusted root VERIFIED")


def p_dlg_root_with_parent_refused():
    from gov import delegation_chain as dc
    from gov import ed25519
    now = time.time()
    _, (_, rp), _, _, _, _ = _chain3(now)
    es, _ = _keypair()
    _, lp = _keypair()
    ur0 = dc.delegate(es, None, {
        "audience": lp,
        "capabilities": [{"with": "fs:/", "can": ["read"]}],
        "not_before": now - 10, "not_after": now + 3600, "ttl": 3610})
    body = dict(ur0["delegation"])
    body["parent_digest"] = "ab" * 32
    sig = ed25519.sign(es, dc.SIGN_DOMAIN + dc._canonical(body)).hex()
    v = dc.DelegationVerifier([rp])
    try:
        v.verify([{"delegation": body, "signature": sig}],
                 {"with": "fs:/", "can": "read"}, now=now)
    except dc.DelegationParentMismatch:
        return _record("dlg-root-with-parent-refused", "HELD",
                       "root carrying a parent_digest refused")
    except dc.DelegationError as e:
        return _record("dlg-root-with-parent-refused", "BREAK",
                       "wrong code %s" % e.code)
    _record("dlg-root-with-parent-refused", "BREAK",
            "root with parent_digest VERIFIED")


def p_dlg_root_policy_escape_refused():
    # A policy-bound anchor's root grant exceeding the bound must
    # refuse; the bound must also be transitive to children.
    from gov import delegation_chain as dc
    now = time.time()
    _, (rs, rp), (ms, mp), _, _, _ = _chain3(now)
    vp = dc.DelegationVerifier(
        [rp], root_policy={rp: [{"with": "fs:/", "can": ["read"]}]})
    rw = dc.delegate(rs, None, {
        "audience": mp,
        "capabilities": [{"with": "fs:/", "can": ["write"]}],
        "not_before": now - 10, "not_after": now + 3600, "ttl": 3610})
    try:
        vp.verify([rw], {"with": "fs:/", "can": "write"}, now=now)
    except dc.DelegationRootExceedsPolicy:
        return _record("dlg-root-policy-escape-refused", "HELD",
                       "root grant exceeding the anchor bound refused "
                       "delegation-root-exceeds-policy")
    except dc.DelegationError as e:
        return _record("dlg-root-policy-escape-refused", "BREAK",
                       "wrong code %s" % e.code)
    _record("dlg-root-policy-escape-refused", "BREAK",
            "root grant escaped its policy bound")


def p_dlg_ceremony_tamper_refused():
    # Flipping the ceremony nonce breaks the signature: the tamper
    # must refuse as a signature failure, never slide into a
    # ceremony-mismatch (which would imply the tampered body was
    # structurally accepted).
    import json as _json
    from gov import delegation_chain as dc
    now = time.time()
    _, _, (ms, mp), _, _, _ = _chain3(now)
    cs, cp = _keypair()
    nonce = "ab" * 16
    cb = dc.delegate(cs, None, {
        "audience": mp,
        "capabilities": [{"with": "fs:/", "can": ["read"]}],
        "not_before": now - 10, "not_after": now + 3600, "ttl": 3610,
        "ceremony_nonce": nonce})
    tampered = _json.loads(_json.dumps(cb))
    tampered["delegation"]["ceremony_nonce"] = "cd" + "ab" * 15
    v = dc.DelegationVerifier([cp])
    try:
        v.verify([tampered], {"with": "fs:/", "can": "read"}, now=now,
                 expected_ceremony_nonce=nonce)
    except dc.DelegationSignatureInvalid:
        return _record("dlg-ceremony-tamper-refused", "HELD",
                       "nonce tamper refused delegation-signature-"
                       "invalid (signature checked before ceremony)")
    except dc.DelegationError as e:
        return _record("dlg-ceremony-tamper-refused", "BREAK",
                       "wrong code %s" % e.code)
    _record("dlg-ceremony-tamper-refused", "BREAK",
            "tampered ceremony nonce VERIFIED")


def p_dlg_ceremony_strip_refused():
    # A delegation minted for NO ceremony, presented where one is
    # expected, must refuse ceremony-mismatch (not silently pass).
    from gov import delegation_chain as dc
    now = time.time()
    _, _, (ms, mp), _, _, _ = _chain3(now)
    cs, cp = _keypair()
    nonce = "ab" * 16
    stripped = dc.delegate(cs, None, {
        "audience": mp,
        "capabilities": [{"with": "fs:/", "can": ["read"]}],
        "not_before": now - 10, "not_after": now + 3600, "ttl": 3610})
    v = dc.DelegationVerifier([cp])
    try:
        v.verify([stripped], {"with": "fs:/", "can": "read"}, now=now,
                 expected_ceremony_nonce=nonce)
    except dc.DelegationCeremonyMismatch:
        return _record("dlg-ceremony-strip-refused", "HELD",
                       "ceremony-less delegation under an expected "
                       "ceremony refused delegation-ceremony-mismatch")
    except dc.DelegationError as e:
        return _record("dlg-ceremony-strip-refused", "BREAK",
                       "wrong code %s" % e.code)
    _record("dlg-ceremony-strip-refused", "BREAK",
            "ceremony-less delegation VERIFIED under an expected nonce")


def p_dlg_receipt_no_accepting_seam():
    # Invocation receipts are signed, but no verify_receipt exists in
    # the module and no other module consumes them: a forged receipt
    # has no accepting seam, so forgery is not a bypass. Pin the
    # documented behavior (seed=None -> signature None, not silent).
    from gov import delegation_chain as dc
    if hasattr(dc.DelegationVerifier, "verify_receipt"):
        return _record("dlg-receipt-no-accepting-seam", "BREAK",
                       "a receipt-accepting seam exists; forgery "
                       "surface unexamined")
    now = time.time()
    _, (rs, rp), _, (ls, lp), r0, r1 = _chain3(now)
    v_noseed = dc.DelegationVerifier([rp])
    rec = v_noseed._mint_receipt(dc.RECEIPT_TYPE, "ab" * 32, "fs:/",
                                 "read", now, {})
    if rec.get("signature") is not None:
        return _record("dlg-receipt-no-accepting-seam", "BREAK",
                       "seedless receipt carries a signature?!")
    _record("dlg-receipt-no-accepting-seam", "HELD",
            "no receipt-accepting seam exists; seedless receipts "
            "carry explicit signature=None (documented)")


# ---------------------------------------------------------------------------
# (b) closure seam edges
# ---------------------------------------------------------------------------

def p_f352_sink_no_mask():
    # A raising sink must neither break issuance (F352) NOR mask a
    # real verification decision: the outcome is computed
    # independently of the sink.
    from gov import ceremony_binding as cb
    import secrets as _secrets
    seed = _secrets.token_bytes(32)
    from gov import ed25519
    pub = ed25519.publickey(seed).hex()
    old = cb._emit
    cb.set_emit(lambda e: (_ for _ in ()).throw(RuntimeError("sink down")))
    try:
        rec = cb.issue_binding(
            operator_seed=seed, operator_keyid="k1",
            challenge_nonce=_secrets.token_bytes(16),
            challenge_purpose="w292-probe",
            content_digest="ab" * 32)
    finally:
        cb.set_emit(old)
    payload = cb.verify_binding(rec, pub)
    if payload.get("challenge_purpose") != "w292-probe":
        return _record("f352-sink-no-mask", "BREAK",
                       "binding did not survive a raising sink")
    _record("f352-sink-no-mask", "HELD",
            "raising sink: issuance succeeds, binding verifies; "
            "no decision masked (documented F345-class trade-off)")


def p_f355_hex_gate_audit():
    # Every bytes.fromhex in the F355 closure modules must be preceded
    # by an _is_hex gate in the same function.
    import ast
    held = True
    notes = []
    for mod in ("gov/ceremony_binding.py", "gov/runtime_posture.py"):
        with open(os.path.join(REPO, mod), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                src = ast.dump(node)
                if "bytes.fromhex" in src or "fromhex" in src:
                    # crude but honest: the function source must name
                    # _is_hex as well as fromhex
                    seg = ast.get_source_segment(
                        open(os.path.join(REPO, mod),
                             encoding="utf-8").read(), node) or ""
                    if "_is_hex" not in seg and "fromhex" in seg:
                        held = False
                        notes.append("%s:%s" % (mod, node.name))
    if held:
        _record("f355-hex-gate-audit", "HELD",
                "all fromhex sites in ceremony_binding/runtime_posture "
                "are _is_hex-gated")
    else:
        _record("f355-hex-gate-audit", "BREAK",
                "unguarded fromhex in %s" % ",".join(notes))


def p_f354_jsonload_coded_sites():
    # The F354-class sweep: corrupt files at the OTHER json.load
    # public seams must refuse coded (not raw JSONDecodeError).
    from gov import keyset as _ks
    from gov import evidence_certs as _ec
    d = tempfile.mkdtemp(prefix="w292-jsonload-")
    bad = os.path.join(d, "bad.json")
    with open(bad, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    # keyset: env-var-driven file load
    os.environ["GOV_AUDIT_KEYSET_FILE"] = bad
    try:
        _ks.keyset_signer_from_config()
    except _ks.KeysetError:
        pass
    except Exception as e:  # noqa: BLE001
        return _record("f354-jsonload-coded-sites", "BREAK",
                       "keyset corrupt file: raw %s" % type(e).__name__)
    finally:
        del os.environ["GOV_AUDIT_KEYSET_FILE"]
    # evidence_certs registry
    try:
        _ec._load_registry(bad)
    except _ec.EvidenceCertError:
        pass
    except Exception as e:  # noqa: BLE001
        return _record("f354-jsonload-coded-sites", "BREAK",
                       "evidence_certs corrupt file: raw %s"
                       % type(e).__name__)
    _record("f354-jsonload-coded-sites", "HELD",
            "keyset + evidence_certs corrupt files refuse coded")


# ---------------------------------------------------------------------------
# New finding F357: verify_enveloped_ledger uncoded parse escapes
# ---------------------------------------------------------------------------

def _bundle_skeleton(corrupt_target=None, corrupt_body=""):
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed)
    d = tempfile.mkdtemp(prefix="w292-ob-")
    files = {
        "ledger.enveloped.jsonl": "",
        "ENVELOPE_PUBKEY.hex": pub.hex(),
        "ledger.jsonl": "",
        "manifest.enveloped.json": "{}",
        "manifest.json": "{}",
    }
    if corrupt_target:
        files[corrupt_target] = corrupt_body
    for name, body in files.items():
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    return d, seed, pub


def _ob_probe(pid, corrupt_target, corrupt_body, sealed_manifest=None):
    from gov import offline_bundle as ob
    from gov import evidence_envelope as ee
    d, seed, pub = _bundle_skeleton(corrupt_target, corrupt_body)
    if sealed_manifest is not None:
        env = ee.seal_manifest(sealed_manifest, seed)
        with open(os.path.join(d, "manifest.enveloped.json"), "w",
                  encoding="utf-8") as fh:
            fh.write(json.dumps(env))
        with open(os.path.join(d, "manifest.json"), "w",
                  encoding="utf-8") as fh:
            fh.write(json.dumps(sealed_manifest))
        if corrupt_target == "manifest.json":
            with open(os.path.join(d, "manifest.json"), "w",
                      encoding="utf-8") as fh:
                fh.write(corrupt_body)
    try:
        ob.verify_enveloped_ledger(d)
    except ob.OfflineBundleError:
        return _record(pid, "HELD",
                       "corrupt %s refused via OfflineBundleError" %
                       corrupt_target)
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK",
                       "corrupt %s escapes raw %s (code=%r): %s" %
                       (corrupt_target, type(e).__name__,
                        getattr(e, "code", None), str(e)[:70]))
    _record(pid, "BREAK", "corrupt %s VERIFIED?!" % corrupt_target)


def p_ob_pubkey_hex_uncoded():
    _ob_probe("ob-pubkey-hex-uncoded", "ENVELOPE_PUBKEY.hex", "zz-not-hex")


def p_ob_manifest_enveloped_uncoded():
    _ob_probe("ob-manifest-enveloped-uncoded", "manifest.enveloped.json",
              "{not json")


def p_ob_ledger_line_uncoded():
    _ob_probe("ob-ledger-line-uncoded", "ledger.jsonl", "{bad line}\n")


def p_ob_manifest_json_uncoded():
    _ob_probe("ob-manifest-json-uncoded", "manifest.json", "[1,2,",
              sealed_manifest={"bundle": "w292"})


def p_ob_valid_bundle_verifies():
    # Positive control: a well-formed bundle verifies True, so the
    # corrupt-file probes above are non-vacuous (they reach the parse
    # sites rather than dying on an earlier check).
    from gov import offline_bundle as ob
    from gov import evidence_envelope as ee
    d, seed, pub = _bundle_skeleton()
    manifest = {"bundle": "w292-control"}
    env = ee.seal_manifest(manifest, seed)
    with open(os.path.join(d, "manifest.enveloped.json"), "w",
              encoding="utf-8") as fh:
        fh.write(json.dumps(env))
    with open(os.path.join(d, "manifest.json"), "w",
              encoding="utf-8") as fh:
        fh.write(json.dumps(manifest))
    try:
        ok = ob.verify_enveloped_ledger(d)
    except Exception as e:  # noqa: BLE001
        return _record("ob-valid-bundle-verifies", "ERROR",
                       "control bundle failed: %r" % (e,))
    if ok is True:
        _record("ob-valid-bundle-verifies", "HELD",
                "well-formed bundle verifies True (probes non-vacuous)")
    else:
        _record("ob-valid-bundle-verifies", "ERROR",
                "control bundle returned %r" % (ok,))


# ---------------------------------------------------------------------------
# Re-pins (subprocess; depth-1 green)
# ---------------------------------------------------------------------------

def _run_battery(rel, expected_breaks, label):
    path = os.path.join(REPO, rel)
    d = tempfile.mkdtemp(prefix="w292-repin-")
    try:
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=900,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("repin-" + label, "ERROR", "subprocess: %r" % (e,))
        return
    out = proc.stdout + proc.stderr
    ms = re.findall(r"(\d+)\s+BREAK", out)
    nbreak = int(ms[-1]) if ms else -1
    if nbreak == expected_breaks:
        _record("repin-" + label, "HELD",
                "%s: %d BREAK as expected" % (rel, nbreak))
    else:
        _record("repin-" + label, "BREAK",
                "%s: %d BREAK, expected %d"
                % (rel, nbreak, expected_breaks))


def p_repins():
    # F311-F356 CLOSED: 0 BREAK expected on the wave-291 merge.
    before = len(_results)
    _run_battery("evals/w290_redteam_probes.py", 0, "w290")
    _run_battery("evals/w289_redteam_probes.py", 0, "w289")
    _run_battery("evals/w291_f352_probes.py", 0, "w291-f352")
    _run_battery("evals/w291_f353_f355_probes.py", 0, "w291-f353f355")
    _run_battery("evals/w291_f354_probes.py", 0, "w291-f354")
    _run_battery("evals/w291_delegation_probes.py", 0, "w291-delegation")
    _run_battery("evals/w290_rebuild_probes.py", 0, "w290-rebuild")
    _run_battery("evals/w290_f348_f349_probes.py", 0, "w290-f348f349")
    seg = _results[before:]
    bad = [p for p, v, _ in seg if v != "HELD"]
    if bad:
        _record("repin-all", "BREAK",
                "re-pin failures: %s" % ",".join(bad))
    else:
        _record("repin-all", "HELD",
                "8/8 prior batteries 0 BREAK as expected")


def _green_checks():
    if SKIP_GREEN:
        return
    for rel in ("evals/w287_tsa_probes.py",
                "evals/w285_tessera_probes.py"):
        _run_battery(rel, 0, "green-" + os.path.basename(rel)[:-3])


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    # F356 re-pins (OPEN at base)
    _safe("rb-execute-unvalidated-keyerror",
          p_rb_execute_unvalidated_keyerror)
    _safe("rb-execute-unvalidated-unknown-op",
          p_rb_execute_unvalidated_unknown_op)
    # (a) delegation_chain
    _safe("dlg-hop2-widen-refused", p_dlg_hop2_widen_refused)
    _safe("dlg-issue-time-widen-refused", p_dlg_issue_time_widen_refused)
    _safe("dlg-pop-cross-chain-replay-refused",
          p_dlg_pop_cross_chain_replay_refused)
    _safe("dlg-graft-custody-splice-refused",
          p_dlg_graft_custody_splice_refused)
    _safe("dlg-untrusted-root-refused", p_dlg_untrusted_root_refused)
    _safe("dlg-root-with-parent-refused", p_dlg_root_with_parent_refused)
    _safe("dlg-root-policy-escape-refused", p_dlg_root_policy_escape_refused)
    _safe("dlg-ceremony-tamper-refused", p_dlg_ceremony_tamper_refused)
    _safe("dlg-ceremony-strip-refused", p_dlg_ceremony_strip_refused)
    _safe("dlg-receipt-no-accepting-seam", p_dlg_receipt_no_accepting_seam)
    # (b) closure seam edges
    _safe("f352-sink-no-mask", p_f352_sink_no_mask)
    _safe("f355-hex-gate-audit", p_f355_hex_gate_audit)
    _safe("f354-jsonload-coded-sites", p_f354_jsonload_coded_sites)
    # F357 (new)
    _safe("ob-pubkey-hex-uncoded", p_ob_pubkey_hex_uncoded)
    _safe("ob-manifest-enveloped-uncoded", p_ob_manifest_enveloped_uncoded)
    _safe("ob-ledger-line-uncoded", p_ob_ledger_line_uncoded)
    _safe("ob-manifest-json-uncoded", p_ob_manifest_json_uncoded)
    _safe("ob-valid-bundle-verifies", p_ob_valid_bundle_verifies)
    _safe("repin-all", p_repins)
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w292_redteam: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
