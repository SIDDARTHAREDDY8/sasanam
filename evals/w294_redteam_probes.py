"""Wave-294 independent red-team battery: wave-293 additions under attack.

Targets: gov/tool_rules.py (closed inventory, freeze, digest stability,
secret gate), gov/key_succession.py (old-key transition authority,
overlap-window edges, from_records replay), F361-F364 closure re-pins,
and the F361-F363 seam edges (nested/self-referential structures at
adjacent canonicalization seams).

Base: wave-293 merge 8fa5bbeb3bea7ca16b0c82b3e65ddfdca551acb6
(verified via git rev-parse HEAD before work).

Pin 1742 (no new codes minted by this lane -- attack only; gov/ stays
byte-identical). Next free F365.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses.

Run:
  mkdir -p /var/tmp/g294-rt && TMPDIR=/var/tmp/g294-rt \
    ~/workspace/.gov-venv/bin/python evals/w294_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g294-rtb \
    ~/workspace/.gov-venv/bin/python evals/w294_redteam_probes.py
"""

import os
import re
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"
TAXONOMY_PIN = 2014 # Wave-293 merge: 1723 + 3 toolcall-* + 4 keysuccession-*; Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)



_RESULTS = []


def _record(pid, verdict, note):
    _RESULTS.append((pid, verdict, note))
    return (pid, verdict, note)


def _safe(pid, fn):
    try:
        fn()
    except Exception:  # noqa: BLE001 -- a probe crash is data
        _record(pid, "ERROR", traceback.format_exc(limit=3).strip())


def _literals():
    src = open("gov/decision_codes.py").read()
    return re.findall(r'''["']code["']\s*:\s*["']([^"']+)["']''', src)


def p_taxonomy_pin():
    codes = _literals()
    if len(codes) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "raw literals %d, want %d"
                       % (len(codes), TAXONOMY_PIN))
    if len(set(codes)) != len(codes):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if codes != sorted(codes):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    import gov.decision_codes as dc
    if len(dc.TAXONOMY) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "live dict %d, want %d"
                       % (len(dc.TAXONOMY), TAXONOMY_PIN))
    _record("pin-taxonomy", "HELD",
            "raw literals %d unique sorted; live dict matches" % len(codes))


# ---------------------------------------------------------------------------
# Re-pin green checks: the wave-293 batteries re-run with GOV_SKIP_GREEN=1
# (depth-1: they spawn nothing further). F311-F363 CLOSED -> 0 BREAK;
# Wave-294 merge: F364 CLOSED by lane 1, so w293_redteam now expects 0 BREAK.
# ---------------------------------------------------------------------------

_REPIN_EXPECT = {
    "w293_f360_probes.py": (0, None),
    "w293_sweep_probes.py": (0, None),
    "w293_tool_rules_probes.py": (0, None),
    "w293_key_succession_probes.py": (0, None),
    "w293_redteam_probes.py": (0, None),  # merge: F364 closed by wave-294 lane 1
}


def _run_repin(name):
    pid = "repin-" + name.replace("_probes.py", "")
    d = tempfile.mkdtemp(prefix="g294-repin-")
    try:
        proc = subprocess.run(
            [sys.executable, "evals/" + name],
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d),
            capture_output=True, text=True, timeout=900)
    except Exception as e:  # noqa: BLE001
        return _record(pid, "ERROR", "repin run failed: %r" % (e,))
    want_breaks, want_id = _REPIN_EXPECT[name]
    m = re.search(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR", proc.stdout)
    if not m:
        return _record(pid, "ERROR",
                       "no summary line in repin output; rc=%d tail=%r"
                       % (proc.returncode, proc.stdout[-300:]))
    breaks = int(m.group(1))
    break_ids = re.findall(r"\[BREAK\] ([A-Za-z0-9_.-]+)", proc.stdout)
    if breaks != want_breaks:
        return _record(pid, "BREAK",
                       "%s: %d BREAK, want %d (ids=%r)"
                       % (name, breaks, want_breaks, break_ids))
    if want_id is not None and break_ids != [want_id]:
        return _record(pid, "BREAK",
                       "%s: BREAK ids %r, want [%r]"
                       % (name, break_ids, want_id))
    _record(pid, "HELD",
            "%s re-pinned: %d BREAK as expected" % (name, breaks))


# ---------------------------------------------------------------------------
# Tool rules: helpers
# ---------------------------------------------------------------------------

def _rule_set(extra_tools=(), rules=(), predicates=None):
    from gov import tool_rules as tr
    doc = {"format": tr.RULE_SET_FORMAT, "name": "rt-probe",
           "tools": ["t1", "parent", "child", "term"] + list(extra_tools),
           "rules": list(rules),
           "predicates": dict(predicates or {})}
    return tr.compile_rule_set(doc), tr


def p_tr_depth5_secret_bypass():
    # F365: the secret scan stops at depth 4. A secret nested at depth 5
    # is never scanned and the call is ALLOWED -- the documented bound
    # is the bypass. The module refuses beyond-bound HISTORY coded
    # (MAX_HISTORY_SCAN) but silently allows beyond-bound ARGS.
    rs, tr = _rule_set()
    deep = {"a": {"b": {"c": {"d": {"e": "sk-abcdefghijklmnop"}}}}}
    try:
        rs.check_call("t1", deep)
    except tr.ToolRuleError as e:
        return _record("tr-depth5-secret-bypass", "HELD",
                       "depth-5 secret refused coded %s" % (e.code,))
    _record("tr-depth5-secret-bypass", "BREAK",
            "F365: secret at nesting depth 5 evades the secret gate; "
            "the call is ALLOWED")


def p_tr_64kb_secret_bypass():
    # F365: the secret scan budget is 64KB per scan. A secret placed
    # past the budget in a single large string is never scanned.
    rs, tr = _rule_set()
    big = {"blob": "x" * 70000 + "sk-abcdefghijklmnop"}
    try:
        rs.check_call("t1", big)
    except tr.ToolRuleError as e:
        return _record("tr-64kb-secret-bypass", "HELD",
                       "post-budget secret refused coded %s" % (e.code,))
    _record("tr-64kb-secret-bypass", "BREAK",
            "F365: secret past the 64KB scan budget evades the secret "
            "gate; the call is ALLOWED")


def p_tr_base64_pem_residual():
    # Documented residual (not filed): the pattern set is bounded by
    # design -- a base64-encoded PEM block matches no shape. Confirmed
    # here so the residual is empirical, not assumed.
    import base64
    rs, tr = _rule_set()
    blob = base64.b64encode(b"-----BEGIN PRIVATE KEY-----\nMIIB").decode()
    try:
        rs.check_call("t1", {"k": blob})
    except tr.ToolRuleError as e:
        return _record("tr-base64-pem-residual", "HELD",
                       "base64 PEM refused coded %s" % (e.code,))
    _record("tr-base64-pem-residual", "HELD",
            "base64-encoded PEM evades the bounded pattern set -- "
            "documented residual (lane-2 report), not filed: no "
            "falsifiable close-when for arbitrary encodings")


def p_tr_split_secret_residual():
    # Same class: a secret split across two arg values matches no
    # single-value shape. Documented residual, not filed.
    rs, tr = _rule_set()
    try:
        rs.check_call("t1", {"p1": "sk-abcdefgh", "p2": "ijklmnop"})
    except tr.ToolRuleError as e:
        return _record("tr-split-secret-residual", "HELD",
                       "split secret refused coded %s" % (e.code,))
    _record("tr-split-secret-residual", "HELD",
            "secret split across two arg values evades the "
            "single-value shapes -- documented residual, not filed")


def p_tr_secret_name_nested():
    # Secret-shaped arg NAMES refuse at any depth (the lane's claim).
    rs, tr = _rule_set()
    try:
        rs.check_call("t1", {"wrap": {"api_key": "not-a-real-key"}})
    except tr.ToolRuleError as e:
        if e.code == tr.SECRET_IN_ARGS:
            return _record("tr-secret-name-nested", "HELD",
                           "nested secret-shaped name refused coded")
        return _record("tr-secret-name-nested", "BREAK",
                       "wrong code: %s" % (e.code,))
    _record("tr-secret-name-nested", "BREAK",
            "nested secret-shaped arg name passed the gate")


def p_tr_freeze_mutation():
    # The F330/F340 pattern: post-compile mutation fails at the source.
    rs, tr = _rule_set()
    try:
        rs._doc["name"] = "evil"
    except TypeError:
        return _record("tr-freeze-mutation", "HELD",
                       "post-compile item mutation raises TypeError at "
                       "the source")
    _record("tr-freeze-mutation", "BREAK",
            "frozen rule-set document accepted item mutation")


def p_tr_freeze_aliasing():
    # Mutating the CALLER's original doc after compile must not move
    # the compiled checker (the freeze severs the alias).
    from gov import tool_rules as tr
    doc = {"format": tr.RULE_SET_FORMAT, "name": "alias-probe",
           "tools": ["t1"], "rules": [], "predicates": {}}
    rs = tr.compile_rule_set(doc)
    doc["tools"].append("evil-tool")
    doc["rules"] = "corrupted"
    try:
        rs.check_call("evil-tool", {})
    except tr.ToolRuleError as e:
        if e.code == tr.SEQUENCE_VIOLATED:
            return _record("tr-freeze-aliasing", "HELD",
                           "caller-side doc mutation does not move the "
                           "compiled checker")
        return _record("tr-freeze-aliasing", "BREAK",
                       "wrong code: %s" % (e.code,))
    _record("tr-freeze-aliasing", "BREAK",
            "mutating the caller's doc widened the compiled inventory")


def p_tr_digest_order():
    # The digest covers rule ORDER (input order preserved): two
    # semantically identical rule sets pin differently. Fail-closed
    # direction (a reordered deploy refuses its pin rather than
    # silently deciding), so this is documented, not filed.
    from gov import tool_rules as tr
    r1 = {"kind": "Init", "tool": "t1"}
    r2 = {"kind": "Terminal", "tool": "term"}
    a, _ = _rule_set(rules=[r1, r2])
    b, _ = _rule_set(rules=[r2, r1])
    if a.digest != b.digest:
        return _record("tr-digest-order", "HELD",
                       "digest is order-sensitive; reordered rule sets "
                       "re-pin (fail-closed direction)")
    _record("tr-digest-order", "BREAK",
            "reordered rules pin identically -- digest misses semantics")


def _policy_doc():
    return {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w294-rt-pol",
        "selector": {"agents": ["agent-1"]},
        "mode": "enforce",
        "rules": [
            {"action": "ALLOW", "tool": "*", "operation": "run",
             "severity": 1, "tags": []},
        ],
    }


def _caller():
    return {"authenticated": True, "identity": "agent-1"}


def p_tr_closed_inventory_decide():
    # With a rule set bound, decide() must DENY an undeclared tool
    # coded at the same seam -- no path may execute it.
    from gov import tool_call_policy as tcp
    rs, tr = _rule_set()
    policy = tcp.compile_policy(_policy_doc())
    policy.bind_rule_set(rs)
    d = policy.decide(_caller(), "undeclared-tool", "run", {})
    if d.verdict == "DENY" and d.code == tr.SEQUENCE_VIOLATED:
        return _record("tr-closed-inventory-decide", "HELD",
                       "undeclared tool DENY coded toolcall-sequence-"
                       "violated at the decide seam")
    _record("tr-closed-inventory-decide", "BREAK",
            "undeclared tool: verdict=%r code=%r"
            % (d.verdict, d.code))


def p_tr_terminal_closure():
    rs, tr = _rule_set(rules=[{"kind": "Terminal", "tool": "term"}])
    rs.check_call("term", {}, history=[])
    try:
        rs.check_call("t1", {}, history=[{"tool": "term"}])
    except tr.ToolRuleError as e:
        if e.code == tr.SEQUENCE_VIOLATED:
            return _record("tr-terminal-closure", "HELD",
                           "call after a terminal tool refused coded")
        return _record("tr-terminal-closure", "BREAK",
                       "wrong code: %s" % (e.code,))
    _record("tr-terminal-closure", "BREAK",
            "call after a terminal tool was allowed")


def p_tr_history_override_declared():
    # PolicyBinding derives history from its ALLOW decisions when the
    # caller passes none; an EXPLICIT history overrides the derived
    # one. That is the documented declared-history contract (the
    # harness owns history; the agent cannot inject it), so the
    # override working as documented is HELD, not a finding.
    from gov import tool_call_policy as tcp
    rs, tr = _rule_set(rules=[{"kind": "Child", "tool": "child",
                               "parent": "parent"}])
    policy = tcp.compile_policy(_policy_doc())
    policy.bind_rule_set(rs)
    binding = tcp.bind(policy, policy.digest)
    d = binding.decide(_caller(), "child", "run", {},
                       history=[{"tool": "parent"}])
    if d.verdict == "DENY":
        return _record("tr-history-override-declared", "BREAK",
                       "explicit declared history was ignored")
    _record("tr-history-override-declared", "HELD",
            "explicit history is honored as declared input "
            "(documented declared-history contract)")


# ---------------------------------------------------------------------------
# Key succession
# ---------------------------------------------------------------------------

_SEED_A = bytes(range(1, 33))
_SEED_B = bytes(range(33, 65))
_SEED_C = bytes(range(65, 97))
_SEED_EVIL = bytes(range(97, 129))


def _pub(seed):
    from gov import ed25519
    return ed25519.publickey(seed).hex()


def _to_prepared(ks):
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    c.begin(_pub(_SEED_B), old_seed=_SEED_A, declared_at=1000)
    c.announce(old_seed=_SEED_A, declared_at=1001)
    return c


def _craft_advance_record(ks, window_present=True, window_value=3600):
    from gov import ed25519
    pa, pb = _pub(_SEED_A), _pub(_SEED_B)
    record = {"record_format": ks.SUCCESSION_FORMAT,
              "authority_id": "authority-1",
              "phase_from": "prepared", "phase_to": "completing",
              "old_pubkey": pa, "new_pubkey": pb,
              "declared_at": 1002}
    if window_present:
        record["overlap_window_seconds"] = window_value
    sig = ed25519.sign(_SEED_A, ks._canonical(record)).hex()
    return {"record": record, "signature": sig, "keyid": "old-authority"}


def p_ks_advance_record_not_atomic():
    # F366: advance(record=...) applies the phase transition BEFORE
    # validating the overlap window. A well-signed advance record with
    # a MISSING window raises keysuccession-window-missing but leaves
    # the ceremony poisoned at "completing" with no window -- a state
    # unreachable via the seed path and unreachable via from_records
    # (which checks the window before mutating).
    from gov import key_succession as ks
    c = _to_prepared(ks)
    env = _craft_advance_record(ks, window_present=False)
    code = None
    try:
        c.advance(record=env)
    except ks.KeySuccessionError as e:
        code = e.code
    poisoned = (c.phase == "completing" and c._overlap_window is None)
    if poisoned:
        return _record("ks-advance-record-not-atomic", "BREAK",
                       "F366: malformed advance record raised %r but the "
                       "ceremony is at phase %r with no overlap window "
                       "-- the transition is not atomic"
                       % (code, c.phase))
    _record("ks-advance-record-not-atomic", "HELD",
            "malformed advance record refused before any phase "
            "transition (phase=%r)" % (c.phase,))


def p_ks_from_records_atomic():
    # Contrast: the auditor path checks the window BEFORE mutating, so
    # the same malformed chain refuses without producing a ceremony.
    from gov import key_succession as ks
    c = _to_prepared(ks)
    env = _craft_advance_record(ks, window_present=False)
    try:
        ks.KeySuccession.from_records("authority-1", _pub(_SEED_A),
                                      [c.begin_record, c.announce_record,
                                       env])
    except ks.KeySuccessionError as e:
        if e.code in (ks.WINDOW_MISSING, ks.INVALID_TRANSITION):
            return _record("ks-from-records-atomic", "HELD",
                           "from_records refuses the malformed chain "
                           "coded %s before mutating" % (e.code,))
        return _record("ks-from-records-atomic", "BREAK",
                       "wrong code: %s" % (e.code,))
    _record("ks-from-records-atomic", "BREAK",
            "from_records accepted a windowless advance record")


def p_ks_old_key_forges_completed():
    # Documented compromised-host class (module threat model): whoever
    # holds the old seed can declare any successor, including a full
    # forged chain to "completed" for an attacker key. Confirming the
    # mechanism works AS DOCUMENTED -- falsified-not-filed.
    from gov import key_succession as ks
    from gov import ed25519
    pa, pe = _pub(_SEED_A), _pub(_SEED_EVIL)
    c = ks.KeySuccession("authority-1", pa)
    c.begin(pe, old_seed=_SEED_A, declared_at=1000)
    c.announce(old_seed=_SEED_A, declared_at=1001)
    c.advance(old_seed=_SEED_A, declared_at=1002,
              overlap_window_seconds=3600)
    c.finalize(old_seed=_SEED_A, declared_at=1003)
    if c.phase == "completed" and c.new_pubkey == pe:
        return _record("ks-old-key-forges-completed", "HELD",
                       "old-seed holder can mint a full forged chain "
                       "-- documented compromised-host class, not filed")
    _record("ks-old-key-forges-completed", "BREAK",
            "forged chain did not reach completed: %r" % (c.phase,))


def p_ks_window_edges():
    # 1s .. 30d inclusive; 0 / negative / 30d+1 refuse coded.
    from gov import key_succession as ks
    results = []
    for window, want_ok in ((1, True), (0, False), (-5, False),
                            (30 * 24 * 3600, True),
                            (30 * 24 * 3600 + 1, False)):
        c = _to_prepared(ks)
        env = _craft_advance_record(ks, window_value=window)
        try:
            c.advance(record=env)
            succeeded = True
            wrong_code = None
        except ks.KeySuccessionError as e:
            succeeded = False
            wrong_code = None if e.code == ks.WINDOW_MISSING else e.code
        if wrong_code is not None:
            return _record("ks-window-edges", "BREAK",
                           "window %r: wrong code %s" % (window, wrong_code))
        if succeeded != want_ok:
            return _record("ks-window-edges", "BREAK",
                           "window %r: ok=%r, want %r"
                           % (window, ok, want_ok))
        results.append(window)
    _record("ks-window-edges", "HELD",
            "window bounds enforced: 1 and 30d accepted; 0, negative, "
            "30d+1 refused coded keysuccession-window-missing")


def p_ks_overlap_boundary():
    # The overlap end is inclusive: checked_at == completing_at + window
    # still verifies old-key material; one second later it is a
    # LOUD revocation event.
    from gov import key_succession as ks
    from gov import ed25519
    c = _to_prepared(ks)
    c.advance(old_seed=_SEED_A, declared_at=2000,
              overlap_window_seconds=100)
    pa = _pub(_SEED_A)
    payload = {"status": {"rid": "cred-1"}}
    sig = ed25519.sign(_SEED_A, ks._canonical(payload["status"])).hex()
    env = {"status": payload["status"], "signature": sig}
    ok_end, _ = ks.verify_envelope_with_succession(
        env, c, checked_at=2100)
    if ok_end is not True:
        return _record("ks-overlap-boundary", "BREAK",
                       "old-key material at the inclusive window end "
                       "did not verify")
    try:
        ks.verify_envelope_with_succession(env, c, checked_at=2101)
    except ks.KeySuccessionError as e:
        if e.code == ks.RETIRED_REUSE and e.is_revocation_event:
            return _record("ks-overlap-boundary", "HELD",
                           "inclusive window end verifies; window+1s "
                           "is a LOUD revocation event")
        return _record("ks-overlap-boundary", "BREAK",
                       "wrong code after window: %s" % (e.code,))
    _record("ks-overlap-boundary", "BREAK",
            "old-key material verified past the window end")


def p_ks_from_records_truncated():
    # A truncated chain replays to exactly the phase its records
    # describe -- accurate, not misrepresenting.
    from gov import key_succession as ks
    c = _to_prepared(ks)
    c2 = ks.KeySuccession.from_records("authority-1", _pub(_SEED_A),
                                       [c.begin_record])
    if c2.phase == "preparing" and c2.new_pubkey == _pub(_SEED_B):
        return _record("ks-from-records-truncated", "HELD",
                       "truncated chain replays accurately to "
                       "'preparing'")
    _record("ks-from-records-truncated", "BREAK",
            "truncated replay misrepresents: phase=%r" % (c2.phase,))


def p_ks_from_records_reordered():
    from gov import key_succession as ks
    c = _to_prepared(ks)
    try:
        ks.KeySuccession.from_records("authority-1", _pub(_SEED_A),
                                      [c.announce_record, c.begin_record])
    except ks.KeySuccessionError:
        return _record("ks-from-records-reordered", "HELD",
                       "reordered chain refused coded")
    _record("ks-from-records-reordered", "BREAK",
            "reordered record chain replayed without refusal")


def p_ks_replay_same_envelope():
    # The same envelope applied twice to one ceremony refuses as a
    # replay (checked before the phase expectation).
    from gov import key_succession as ks
    c = ks.KeySuccession("authority-1", _pub(_SEED_A))
    rec = c.begin(_pub(_SEED_B), old_seed=_SEED_A, declared_at=1000)
    try:
        c.announce(record=rec)
    except ks.KeySuccessionError as e:
        if e.code == ks.INVALID_TRANSITION:
            return _record("ks-replay-same-envelope", "HELD",
                           "replayed transition record refused coded")
        return _record("ks-replay-same-envelope", "BREAK",
                       "wrong code: %s" % (e.code,))
    _record("ks-replay-same-envelope", "BREAK",
            "replayed transition record was applied twice")


# ---------------------------------------------------------------------------
# F361-F363 seam edges: self-referential structures at adjacent
# canonicalization seams (the fixes guard the whole _canonical call, so
# nested variants must refuse coded too).
# ---------------------------------------------------------------------------

def _circ():
    d = {}
    d["self"] = d
    return d


def p_se_nested_circular_credential():
    from gov import revocation_status as rs
    from gov import ed25519
    inner = _circ()
    cred = {"credential_format": "sasanam-revocation-credential/1",
            "rid": "cred-1", "holder_pubkey": _pub(_SEED_A),
            "nested": {"deep": inner}}
    env = {"credential": cred, "signature": "ab" * 64,
           "keyid": "registry"}
    try:
        rs.verify_credential(env, _pub(_SEED_A))
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("se-nested-circular-credential", "HELD",
                           "nested circular credential refused coded")
        return _record("se-nested-circular-credential", "BREAK",
                       "wrong code: %s" % (e.code,))
    except (TypeError, ValueError):
        return _record("se-nested-circular-credential", "BREAK",
                       "nested circular structure escaped uncoded")
    _record("se-nested-circular-credential", "BREAK",
            "nested circular credential verified")


def p_se_nested_mixed_keys_status():
    from gov import revocation_status as rs
    status = {"response_format": "sasanam-revocation-status/1",
              "rid": "cred-1", "state": "active", "checked_at": 1500,
              "nested": {1: "int-key", "s": "str-key"}}
    env = {"status": status, "signature": "ab" * 64, "keyid": "registry"}
    try:
        rs.verify_status_response(env, _pub(_SEED_A))
    except rs.RevocationError as e:
        if e.code == "revocation-status-unverifiable":
            return _record("se-nested-mixed-keys-status", "HELD",
                           "nested mixed-type keys refused coded")
        return _record("se-nested-mixed-keys-status", "BREAK",
                       "wrong code: %s" % (e.code,))
    except (TypeError, ValueError):
        return _record("se-nested-mixed-keys-status", "BREAK",
                       "nested mixed-type keys escaped uncoded")
    _record("se-nested-mixed-keys-status", "BREAK",
            "nested mixed-type keys verified")


def p_se_shared_refs_monitor():
    # Shared (non-circular) references: json handles them; the seam
    # must either verify or refuse coded -- never escape uncoded.
    from gov import issuance_monitor as im
    shared = {"rid": "cred-1"}
    report = {"report_format": "sasanam-issuance-monitor-report/1",
              "findings": [], "a": shared, "b": shared}
    try:
        im.verify_monitor_report(
            {"report": report, "signature": "ab" * 64,
             "keyid": "monitor"},
            _pub(_SEED_A))
    except im.MonitorError as e:
        return _record("se-shared-refs-monitor", "HELD",
                       "shared references refused coded %s" % (e.code,))
    except (TypeError, ValueError):
        return _record("se-shared-refs-monitor", "BREAK",
                       "shared references escaped uncoded")
    _record("se-shared-refs-monitor", "HELD",
            "shared references canonicalize without uncoded escape")


def p_se_circular_via_verify_chain():
    # A circular delegation body is normalized away by _seal_body
    # (only validated scalars survive), so verify_chain must refuse
    # coded -- the F363-adjacent _canonical sites only ever see
    # normalized data.
    from gov import delegation_chain as dch
    from gov import ed25519
    seed = bytes(range(200, 232))
    pub = ed25519.publickey(seed).hex()
    body = {"type": "sasanam-delegation/v1",
            "issuer": pub, "audience": pub,
            "capabilities": [{"with": "tool", "can": ["run"]}],
            "not_before": 1000, "issued_at": 1000, "ttl_seconds": 100,
            "not_after": 1100, "generation": 0, "nonce": "n1",
            "parent_digest": None, "ceremony_nonce": None}
    body["smuggled"] = body  # circular extra key (dropped by _seal_body)
    v = dch.DelegationVerifier([pub])
    try:
        v.verify([{"delegation": body, "signature": "ab" * 64}],
                 {"with": "tool", "can": "run"})
    except Exception as e:  # noqa: BLE001 -- any coded refusal is HELD
        code = getattr(e, "code", None)
        if code is not None:
            return _record("se-circular-via-verify-chain", "HELD",
                           "circular body refused coded %s" % (code,))
        return _record("se-circular-via-verify-chain", "BREAK",
                       "uncoded escape: %r" % (e,))
    _record("se-circular-via-verify-chain", "BREAK",
            "circular delegation body verified")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    for name in ("w293_f360_probes.py", "w293_sweep_probes.py",
                 "w293_tool_rules_probes.py",
                 "w293_key_succession_probes.py",
                 "w293_redteam_probes.py"):
        _safe("repin-" + name.replace("_probes.py", ""),
              lambda n=name: _run_repin(n))
    for pid, fn in (
            ("tr-depth5-secret-bypass", p_tr_depth5_secret_bypass),
            ("tr-64kb-secret-bypass", p_tr_64kb_secret_bypass),
            ("tr-base64-pem-residual", p_tr_base64_pem_residual),
            ("tr-split-secret-residual", p_tr_split_secret_residual),
            ("tr-secret-name-nested", p_tr_secret_name_nested),
            ("tr-freeze-mutation", p_tr_freeze_mutation),
            ("tr-freeze-aliasing", p_tr_freeze_aliasing),
            ("tr-digest-order", p_tr_digest_order),
            ("tr-closed-inventory-decide", p_tr_closed_inventory_decide),
            ("tr-terminal-closure", p_tr_terminal_closure),
            ("tr-history-override-declared",
             p_tr_history_override_declared),
            ("ks-advance-record-not-atomic",
             p_ks_advance_record_not_atomic),
            ("ks-from-records-atomic", p_ks_from_records_atomic),
            ("ks-old-key-forges-completed", p_ks_old_key_forges_completed),
            ("ks-window-edges", p_ks_window_edges),
            ("ks-overlap-boundary", p_ks_overlap_boundary),
            ("ks-from-records-truncated", p_ks_from_records_truncated),
            ("ks-from-records-reordered", p_ks_from_records_reordered),
            ("ks-replay-same-envelope", p_ks_replay_same_envelope),
            ("se-nested-circular-credential",
             p_se_nested_circular_credential),
            ("se-nested-mixed-keys-status", p_se_nested_mixed_keys_status),
            ("se-shared-refs-monitor", p_se_shared_refs_monitor),
            ("se-circular-via-verify-chain",
             p_se_circular_via_verify_chain),
    ):
        _safe(pid, fn)
    breaks = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    errors = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    probe_lines.emit(_RESULTS)
    print("w294_redteam: %d BREAK / %d HELD / %d ERROR"
          % (breaks, held, errors))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _RESULTS, breaks, held, errors)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    return 1 if breaks or errors else 0


if __name__ == "__main__":
    sys.exit(main())
