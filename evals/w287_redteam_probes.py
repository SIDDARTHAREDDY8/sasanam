"""Wave-287 independent red-team battery: attack the wave-286 merge.

Base: wave-286 push 8c811375d504371c448d6440b6f80ce9622eb0c5
(verified via git rev-parse HEAD before work).
gov/ is byte-identical (attack only, no product code).

Attack surface (from the wave-286 merge report):
  (a) gov/evidence_receipt.py -- CCF-pattern inclusion receipts:
      COSE_Sign1-shaped envelope, offline verify, witness cosignatures
      in "unprotected", fork denunciation, bind_receipt re-binding.
  (b) gov/tool_call_policy.py -- declarative tool-call authorization:
      fromSource caller binding, CUSTOM->DENY->ALLOW combining with
      no-match=>DENY, Audit-before-Block, hash-bound alert identity,
      exception routing (SKIPPED w/ digest, verdict stays DENY).
  (c) gov/kms_keyset.py -- keyed HMAC pin: pin_key custody, generate/
      load_pin_key, _repin without key, stale-pin fail-closed.
  (d) F331-F333 closure surfaces (OPEN at base: expected-open).

Re-pins at the public seams:
  F311 (CLOSED) -- w283_f311_probes.py: 0 BREAK expected.
  F312-F315 (CLOSED) -- w283_redteam_probes.py: 0 BREAK expected;
      w284_f312_315_probes.py: 0 BREAK expected.
  F316-F324 (CLOSED) -- w284_redteam_probes.py: 0 BREAK expected.
  F325 (CLOSED) -- w286_f325_probes.py: 0 BREAK expected.
  F326 (CLOSED) -- w286_f326_probes.py: 0 BREAK expected.
  F327-F328 (CLOSED) -- w286_f327_f328_probes.py: 0 BREAK expected.
  F329-F330 (CLOSED) -- w286_f329_f330_probes.py: 0 BREAK expected.

New findings filed (all LOW, OPEN): F334+.

$0 spend, synthetic/local, deterministic (fixed fixtures, no wall-clock
equality assertions). Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g287-redteam && TMPDIR=/var/tmp/g287-redteam \
    ~/workspace/.gov-venv/bin/python evals/w287_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g287-redteam2 \
    ~/workspace/.gov-venv/bin/python evals/w287_redteam_probes.py
"""

import os
import re
import secrets
import subprocess
import sys
import tempfile
import time

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*).
TAXONOMY_PIN = 1750  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
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
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


# ---------------------------------------------------------------------------
# Re-pins: run the earlier batteries as subprocesses (depth-1, no nesting)
# and check their verdict counts against the expected post-wave-286 state.
# ---------------------------------------------------------------------------

_REPIN_BATTERIES = [
    # (battery, expected_breaks, label)
    ("evals/w283_f311_probes.py", 0, "f311-closed"),
    ("evals/w283_redteam_probes.py", 0, "f312-315-closed"),
    ("evals/w284_f312_315_probes.py", 0, "f312-315-closed-b"),
    ("evals/w284_redteam_probes.py", 0, "f316-324-closed"),
    ("evals/w286_f325_probes.py", 0, "f325-closed"),
    ("evals/w286_f326_probes.py", 0, "f326-closed"),
    ("evals/w286_f327_f328_probes.py", 0, "f327-328-closed"),
    ("evals/w286_f329_f330_probes.py", 0, "f329-330-closed"),
]


def _run_repins():
    for rel, expected_breaks, label in _REPIN_BATTERIES:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w287-repin-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record("repin-" + label, "ERROR", "subprocess failed: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        # Wave-286 lesson: take the LAST "N BREAK" match (the footer),
        # not per-probe notes.
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak == expected_breaks:
            _record("repin-" + label, "HELD",
                    "%s: %d BREAK as expected" % (rel, nbreak))
        else:
            _record("repin-" + label, "BREAK",
                    "%s: %d BREAK, expected %d"
                    % (rel, nbreak, expected_breaks))


# ---------------------------------------------------------------------------
# F331 (LOW, OPEN): uncoded exceptions escape gov/evidence_anchor.py
# public seams. render_checkpoint with a non-hex sig raises raw
# ValueError; TransparencyLog with a file as log_root raises raw
# NotADirectoryError. Break-first probe asserts the coded-refusal
# contract: these must refuse with a coded AnchorError.
# ---------------------------------------------------------------------------

def p_f331_render_nonhex():
    from gov import evidence_anchor as ea
    body = {"origin": "o", "size": 1, "root": b"\x00" * 32,
            "timestamp": 1, "witness_policy_id": "w"}
    try:
        ea.render_checkpoint(body, [{"keyid": "k", "sig": "ZZZZ"}])
    except ValueError as e:
        if getattr(e, "code", None) is None:
            return _record("f331-render-nonhex", "BREAK",
                           "raw ValueError escapes render_checkpoint "
                           "(%r) -- expected coded AnchorError" % (e,))
        return _record("f331-render-nonhex", "HELD",
                       "coded refusal: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        return _record("f331-render-nonhex", "HELD",
                       "coded refusal: %s"
                       % getattr(e, "code", type(e).__name__))
    _record("f331-render-nonhex", "BREAK", "malformed sig accepted")


def p_f331_logroot_file():
    from gov import evidence_anchor as ea
    d = tempfile.mkdtemp(prefix="w287-f331-")
    f = os.path.join(d, "notadir")
    with open(f, "w", encoding="utf-8") as fh:
        fh.write("x")
    try:
        ea.TransparencyLog(f, origin="origin", signer_keyid="kid")
    except NotADirectoryError as e:
        if getattr(e, "code", None) is None:
            return _record("f331-logroot-file", "BREAK",
                           "raw NotADirectoryError escapes "
                           "TransparencyLog -- expected coded AnchorError")
        return _record("f331-logroot-file", "HELD",
                       "coded refusal: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        return _record("f331-logroot-file", "HELD",
                       "coded refusal: %s"
                       % getattr(e, "code", type(e).__name__))
    _record("f331-logroot-file", "BREAK", "file log_root accepted")


# ---------------------------------------------------------------------------
# F332 (LOW, OPEN): ExceptionStore.grant accepts a 20-space (or
# tab/newline-mix) justification: the mandatory-justification control's
# letter (>= 20 chars) is satisfied while its purpose is bypassed.
# ---------------------------------------------------------------------------

def _f332_store():
    from gov import governed_exceptions as ge
    reg = ge.CheckRegistry()
    reg.register("W287CHECK", "w287 check", category="cat", severity="low",
                 rationale="a proper rationale text", resource_types=["t"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["alice"])
    return store


def p_f332_whitespace_justification():
    store = _f332_store()
    now = time.time()
    try:
        store.grant("W287CHECK", scope=("resource", "r1"),
                    justification=" " * 20, approver="alice",
                    expiry_ts=now + 3600, created_at=now)
    except Exception as e:  # noqa: BLE001
        return _record("f332-whitespace-justification", "HELD",
                       "refused: %s" % getattr(e, "code",
                                               type(e).__name__))
    _record("f332-whitespace-justification", "BREAK",
            "20-space justification accepted -- mandatory-justification "
            "control bypassed")


# ---------------------------------------------------------------------------
# F333 (LOW, OPEN): WitnessPolicy accepts duplicate public keys under
# distinct key ids: one witness key satisfies a quorum of 2.
# ---------------------------------------------------------------------------

def p_f333_dup_witness_key():
    from gov import evidence_anchor as ea
    from gov import ed25519
    pub = ed25519.publickey(secrets.token_bytes(32)).hex()
    try:
        ea.WitnessPolicy("w287pol", {"w1": pub, "w2": pub}, quorum=2)
    except Exception as e:  # noqa: BLE001
        return _record("f333-dup-witness-key", "HELD",
                       "refused: %s" % getattr(e, "code",
                                               type(e).__name__))
    _record("f333-dup-witness-key", "BREAK",
            "duplicate public key under distinct key ids accepted; "
            "one real key satisfies quorum=2")


# ---------------------------------------------------------------------------
# F334 (LOW, OPEN): suppress_with_exception binds the exception scope by
# caller discipline, not to the denied alert. A DENY alert for tool-b is
# recorded SKIPPED under an exception granted for tool-a: the scope is a
# free parameter, never checked against the suppressed alert's tool or
# the policy name. The module docstring says the scope value "must name
# the denied tool or the policy" -- the code never enforces it.
# ---------------------------------------------------------------------------

def _f334_doc():
    return {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w287pol",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "DENY", "tool": "tool-b", "operation": "exec",
             "severity": 9, "tags": []},
        ],
    }


def p_f334_scope_not_bound_to_alert():
    from gov import tool_call_policy as tp
    store = _f332_store()
    now = time.time()
    store.grant("W287CHECK", scope=("tool", "tool-a"),
                justification="business need for tool-a usage here",
                approver="alice", expiry_ts=now + 3600, created_at=now)
    comp = tp.compile_policy(_f334_doc())
    caller = {"authenticated": True, "identity": "agent-1"}
    d = comp.decide(caller, "tool-b", "exec", args={})
    if d.verdict != "DENY":
        return _record("f334-scope-not-bound", "ERROR",
                       "expected a DENY decision, got %r" % (d.verdict,))
    try:
        rec = tp.suppress_with_exception(
            comp, d.alert["runtime_identity_hash"], store,
            "W287CHECK", ("tool", "tool-a"))
    except Exception as e:  # noqa: BLE001
        return _record("f334-scope-not-bound", "HELD",
                       "scope/alert binding refused: %s"
                       % getattr(e, "code", type(e).__name__))
    sup = rec.get("suppressed_alert", {})
    if rec.get("action") == "SKIPPED" and sup.get("tool") == "tool-b":
        return _record("f334-scope-not-bound", "BREAK",
                       "tool-b DENY alert recorded SKIPPED under a "
                       "tool-a exception scope -- scope not bound to "
                       "the denied alert")
    _record("f334-scope-not-bound", "HELD",
            "suppression bound to the alert's own scope")


# ---------------------------------------------------------------------------
# F335 (LOW, OPEN): uncoded exceptions escape the keyset pin-key custody
# seams. generate_pin_key with a stale <path>.tmp raises raw
# FileExistsError (bricking generation for that path); _repin/from_dict
# on malformed documents raise raw TypeError/KeyError instead of coded
# keyset-* refusals. F327/F331 class.
# ---------------------------------------------------------------------------

def p_f335_pinkey_stale_tmp():
    from gov import kms_keyset as kk
    d = tempfile.mkdtemp(prefix="w287-f335-")
    p = os.path.join(d, "pin.key")
    with open(p + ".tmp", "w", encoding="utf-8") as fh:
        fh.write("stale")
    try:
        kk.generate_pin_key(p)
    except FileExistsError as e:
        if getattr(e, "code", None) is None:
            return _record("f335-pinkey-stale-tmp", "BREAK",
                           "raw FileExistsError escapes generate_pin_key "
                           "-- expected coded keyset-pin-key-invalid; "
                           "generation bricked until manual cleanup")
        return _record("f335-pinkey-stale-tmp", "HELD",
                       "coded refusal: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        return _record("f335-pinkey-stale-tmp", "HELD",
                       "coded refusal: %s"
                       % getattr(e, "code", type(e).__name__))
    _record("f335-pinkey-stale-tmp", "BREAK",
            "stale tmp silently accepted")


def _f335_malformed(label, mutate):
    from gov import kms_keyset as kk
    key = secrets.token_bytes(32)
    ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                          primary_key_id="k", provider_name="fake",
                          pin_key=key)
    doc = ks.to_dict()
    mutate(doc)
    try:
        kk.KmsKeyset._repin(doc, pin_key=key)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) is None:
            return _record(label, "BREAK",
                           "raw %s escapes _repin (%r) -- expected coded "
                           "keyset-* refusal" % (type(e).__name__, e))
        return _record(label, "HELD", "coded refusal: %s" % (e.code,))
    _record(label, "BREAK", "malformed document silently accepted")


def p_f335_pinkey_malformed_doc():
    _f335_malformed("f335-pinkey-malformed-doc",
                    lambda doc: doc["audit_chain"].append({"event": "x"}))


# ---------------------------------------------------------------------------
# F336 (LOW, OPEN): load_pin_key performs no permission check -- a
# world-readable (0644) pin key file loads silently, weakening the
# module's own "separate 0600 file" trust model without a word.
# ---------------------------------------------------------------------------

def p_f336_pinkey_perms():
    from gov import kms_keyset as kk
    d = tempfile.mkdtemp(prefix="w287-f336-")
    p = os.path.join(d, "pin.key")
    kk.generate_pin_key(p)
    os.chmod(p, 0o644)
    try:
        kk.load_pin_key(p)
    except Exception as e:  # noqa: BLE001
        return _record("f336-pinkey-perms", "HELD",
                       "refused: %s" % getattr(e, "code",
                                               type(e).__name__))
    _record("f336-pinkey-perms", "BREAK",
            "world-readable (0644) pin key loaded silently -- no "
            "permission check on the deployment-held secret")


# ---------------------------------------------------------------------------
# F337 (LOW, OPEN): bind_receipt signs anchor tuples it never re-verifies.
# The operator seed and witness quorum are fail-fasted at issuance, but
# the inclusion proof (digest -> root) is trusted from the anchor dict:
# a fabricated anchor with a swapped digest mints an operator-signed
# receipt that verify_receipt_offline rejects (fail closed, issuance
# confusion only).
# ---------------------------------------------------------------------------

def p_f337_bind_no_reverify():
    from gov import evidence_anchor as ea
    from gov import evidence_receipt as er
    d = tempfile.mkdtemp(prefix="w287-f337-")
    seed = secrets.token_bytes(32)
    log = ea.TransparencyLog(d, origin="w287origin", signer_keyid="op1",
                             signer_seed=seed)
    anchored = ea.anchor(log, secrets.token_bytes(32).hex())
    bad = dict(anchored)
    bad["bundle_digest"] = secrets.token_bytes(32).hex()
    try:
        er.bind_receipt(bad, seed)
    except Exception as e:  # noqa: BLE001
        return _record("f337-bind-no-reverify", "HELD",
                       "bind re-verified the inclusion tuple: %s"
                       % getattr(e, "code", type(e).__name__))
    _record("f337-bind-no-reverify", "BREAK",
            "bind_receipt signed a receipt over a swapped digest without "
            "re-verifying the inclusion proof (verify fails closed, but "
            "issuance mints dead signed receipts)")


# ---------------------------------------------------------------------------
# F338 (MEDIUM, OPEN): DENY arg carve-outs are evaded by explicit null /
# wrong-typed args. Missing keys match (fail-closed, documented), but a
# PRESENT null/ill-typed value fails its matcher and falls through to a
# broad ALLOW rule: {"cmd": None} -> ALLOW defeats an explicit DENY
# carve-out on {"cmd": {"regex": ...}}.
# ---------------------------------------------------------------------------

def _f338_doc():
    return {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w287f338",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "ALLOW", "tool": "shell", "operation": "run",
             "severity": 5, "tags": []},
            {"action": "DENY", "tool": "shell", "operation": "run",
             "severity": 9, "tags": [],
             "args": {"cmd": {"regex": "^rm -rf /"}}},
        ],
    }


def p_f338_deny_null_arg():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_f338_doc())
    caller = {"authenticated": True, "identity": "agent-1"}
    try:
        d = comp.decide(caller, "shell", "run", args={"cmd": None})
    except Exception as e:  # noqa: BLE001
        return _record("f338-deny-null-arg", "HELD",
                       "null arg refused coded: %s"
                       % getattr(e, "code", type(e).__name__))
    if d.verdict == "DENY":
        return _record("f338-deny-null-arg", "HELD",
                       "null arg matched the DENY carve-out (fail-closed)")
    _record("f338-deny-null-arg", "BREAK",
            "explicit null arg evaded the DENY carve-out -> %s (wire-"
            "equivalent of under-specification)" % (d.verdict,))


# ---------------------------------------------------------------------------
# F339 (MEDIUM, OPEN): the ReDoS residual in tool_call_policy is
# caller-triggerable and the in-tree F325 gate is not routed: evil
# patterns compile (only MAX_REGEX_LEN + re.compile checked) and
# caller-controlled args hit re.fullmatch at decide time. Probe uses a
# bounded input (n=25, ~seconds) to prove exponential behavior without
# hanging the battery.
# ---------------------------------------------------------------------------

def p_f339_toolpolicy_redos():
    from gov import tool_call_policy as tp
    doc = {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w287f339",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "ALLOW", "tool": "shell", "operation": "run",
             "severity": 5, "tags": []},
            {"action": "DENY", "tool": "shell", "operation": "run",
             "severity": 9, "tags": [],
             "args": {"cmd": {"regex": "^([a-z]+)*$"}}},
        ],
    }
    try:
        comp = tp.compile_policy(doc)
    except Exception as e:  # noqa: BLE001
        return _record("f339-toolpolicy-redos", "HELD",
                       "evil pattern refused at compile: %s"
                       % getattr(e, "code", type(e).__name__))
    caller = {"authenticated": True, "identity": "agent-1"}
    t0 = time.time()
    comp.decide(caller, "shell", "run", args={"cmd": "a" * 25 + "!"})
    dt = time.time() - t0
    if dt > 1.0:
        return _record("f339-toolpolicy-redos", "BREAK",
                       "caller arg triggered exponential backtracking "
                       "(25 chars -> %.1fs); F325 gate not routed" % (dt,))
    _record("f339-toolpolicy-redos", "HELD",
            "bounded-time decide on adversarial arg (%.2fs)" % (dt,))


# ---------------------------------------------------------------------------
# F340 (LOW, OPEN): CompiledToolPolicy is not frozen; the pin is verified
# only at bind() time. Post-bind in-process mutation of _doc (e.g. mode
# flip enforce->audit) silently changes decisions under a still-valid pin.
# ---------------------------------------------------------------------------

def p_f340_policy_not_frozen():
    from gov import tool_call_policy as tp
    doc = {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w287f340",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "DENY", "tool": "shell", "operation": "run",
             "severity": 9, "tags": []},
        ],
    }
    comp = tp.compile_policy(doc)
    b = tp.bind(comp, comp.digest)
    caller = {"authenticated": True, "identity": "agent-1"}
    try:
        b._compiled._doc["mode"] = "audit"
    except Exception:
        return _record("f340-policy-not-frozen", "HELD",
                       "compiled policy frozen post-bind")
    d = b.decide(caller, "shell", "run", args={})
    if d.verdict == "DENY":
        return _record("f340-policy-not-frozen", "HELD",
                       "mutation did not change enforcement")
    _record("f340-policy-not-frozen", "BREAK",
            "post-bind _doc mutation flipped %s while the pin still "
            "matches (no per-decide pin check)" % (d.verdict,))


# ---------------------------------------------------------------------------
# F341 (LOW, OPEN): the suppression record hardcodes "verdict": "DENY"
# even when the suppressed alert was an audit-mode would-deny whose
# actual decision was ALLOW -- evidence misstatement in the audit trail.
# ---------------------------------------------------------------------------

def p_f341_auditmode_verdict():
    from gov import tool_call_policy as tp
    store = _f332_store()
    now = time.time()
    store.grant("W287CHECK", scope=("tool", "shell"),
                justification="business need for shell usage in this run",
                approver="alice", expiry_ts=now + 3600, created_at=now)
    doc = {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w287f341",
        "selector": {"agents": ["agent-1"]},
        "mode": "audit",
        "rules": [
            {"action": "DENY", "tool": "shell", "operation": "run",
             "severity": 9, "tags": []},
        ],
    }
    comp = tp.compile_policy(doc)
    caller = {"authenticated": True, "identity": "agent-1"}
    d = comp.decide(caller, "shell", "run", args={})
    if d.verdict != "ALLOW":
        return _record("f341-auditmode-verdict", "ERROR",
                       "expected audit-mode ALLOW, got %r" % (d.verdict,))
    rec = tp.suppress_with_exception(
        comp, d.alert["runtime_identity_hash"], store,
        "W287CHECK", ("tool", "shell"))
    if rec.get("verdict") == "DENY":
        return _record("f341-auditmode-verdict", "BREAK",
                       "suppression record hardcodes verdict=DENY for an "
                       "audit-mode would-deny whose decision was ALLOW")
    _record("f341-auditmode-verdict", "HELD",
            "suppression record carries the actual verdict")


# ---------------------------------------------------------------------------
# F342 (LOW, OPEN): uncoded TypeError escapes tool_call_policy public
# seams (e.g. tool=None), violating the all-refusals-coded contract.
# ---------------------------------------------------------------------------

def p_f342_uncoded_typeerror():
    from gov import tool_call_policy as tp
    comp = tp.compile_policy(_f338_doc())
    caller = {"authenticated": True, "identity": "agent-1"}
    try:
        comp.decide(caller, None, "run", args={})
    except TypeError as e:
        if getattr(e, "code", None) is None:
            return _record("f342-uncoded-typeerror", "BREAK",
                           "raw TypeError escapes decide(tool=None) -- "
                           "expected coded ToolCallPolicyError")
        return _record("f342-uncoded-typeerror", "HELD",
                       "coded refusal: %s" % (e.code,))
    except Exception as e:  # noqa: BLE001
        return _record("f342-uncoded-typeerror", "HELD",
                       "coded refusal: %s"
                       % getattr(e, "code", type(e).__name__))
    _record("f342-uncoded-typeerror", "BREAK", "tool=None silently allowed")


# ---------------------------------------------------------------------------
# Depth-1 green checks: the wave-286 lane batteries must stay all-HELD.
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    checks = [
        "evals/w286_receipts_probes.py",
        "evals/w286_toolpolicy_probes.py",
        "evals/w285_tessera_probes.py",
        "evals/w285_exceptions_probes.py",
    ]
    for rel in checks:
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w287-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        ms = re.findall(r"(\d+)\s+BREAK", out)
        nbreak = int(ms[-1]) if ms else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_taxonomy_pin()
    _run_repins()
    p_f331_render_nonhex()
    p_f331_logroot_file()
    p_f332_whitespace_justification()
    p_f333_dup_witness_key()
    p_f334_scope_not_bound_to_alert()
    p_f335_pinkey_stale_tmp()
    p_f335_pinkey_malformed_doc()
    p_f336_pinkey_perms()
    p_f337_bind_no_reverify()
    p_f338_deny_null_arg()
    p_f339_toolpolicy_redos()
    p_f340_policy_not_frozen()
    p_f341_auditmode_verdict()
    p_f342_uncoded_typeerror()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w287_redteam: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
