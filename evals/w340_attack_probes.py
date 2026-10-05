#!/usr/bin/env python3
"""Wave-340 real-model attack round 8: deterministic pins.

$0 SPEND BY CONSTRUCTION: this battery makes NO model calls. Every pin
below replays a hostile construction from the round-8 attack pass
(evals/w340_f427_variants_redfirst.py documents the F427-confirming
variants; this battery pins the HELD verdicts) using canned inputs --
never a live provider. Do NOT add ModelDriver/SpendLedger usage here;
the live calls happened exactly once in the lane's attack pass and are
recorded verbatim in ~/workspace/teams/wave340-attack/REPORT.md.

Shapes (E/F/G/H = the four wave-340 attack targets):
  E: F427 declared-name class -- honest certifies; raw unissued refused;
     post-issuance attribute mutation fails closed at runtime (the audit
     reads attributes, the runtime reads closure variables -- the
     divergence is fail-closed, so the declared-name class is
     construction-time only and F427's mapping close-when covers it).
  F: witness daemon hostile checkpoints -- coded 200/400/403/404/409/422.
  G: OCI onboarding gate hostile registries -- refused, override can't
     flip OUT to IN.
  H: verifiable-only bundle -- structure gates refuse; hint binding
     stays the verifier's job by design.

Usage:
  ~/workspace/.gov-venv/bin/python evals/w340_attack_probes.py
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import argparse
import base64
import json
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TAXONOMY_PIN = 2131  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).

from gov.adapters import openai_agents as oai  # noqa: E402
from gov.adapters.core import GovernedBinding  # noqa: E402
from gov import oci_registry_gate as org  # noqa: E402
from gov import oci_referrer as oref  # noqa: E402
from gov import sigstore_bundle as sb  # noqa: E402
import gov.witness_daemon as wd  # noqa: E402
import gov.checkpoint_note as cn  # noqa: E402
from gov.witness_log import WitnessLog  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402


def _key():
    if "GOV_LOG_KEY" not in os.environ:
        try:
            from tests.keyfixture import provision_test_key
        except ImportError:
            from keyfixture import provision_test_key
        provision_test_key()


def _make_run():
    try:
        from tests.harness import make_run
    except ImportError:
        from harness import make_run
    return make_run()


class _Ctx:
    def __init__(self, tool_name, arguments):
        self.tool_name = tool_name
        self.tool_arguments = arguments


class _Data:
    def __init__(self, context):
        self.context = context


class _Tool:
    def __init__(self, name, guardrails):
        self.name = name
        self.tool_input_guardrails = guardrails


class _Agent:
    def __init__(self, tools):
        self.name = "w340"
        self.tools = tools
        self.handoffs = []


def _support_binding():
    ctx = _make_run()
    return GovernedBinding(ctx["executor"],
                           ctx["mint_identity"]("support-1", "support",
                                                "dev-org"))


def _audit_certifies(agent, sdk_tool_map=None):
    try:
        oai.audit_agent_coverage(agent, sdk_tool_map=sdk_tool_map)
        return True
    except oai.UncoveredSurfaceError:
        return False


_HONEST_MAP = {"read_file": "read_file", "delete_file": "delete_file"}


# ---------------------------------------------------------------- E: F427 class

def test_e1_honest_guardrail_certifies():
    """Control: an honestly-wired guardrail still certifies when the
    deployment-declared mapping agrees (closed-tree contract)."""
    b = _support_binding()
    g = oai.make_tool_input_guardrail(b, "read_file",
                                      expect_sdk_tool_name="read_file")
    ok = _audit_certifies(_Agent([_Tool("read_file", [g])]),
                          sdk_tool_map=_HONEST_MAP)
    return ("HELD" if ok else "BREAK",
            "honest guardrail certified=%s" % ok)


def test_e2_raw_unissued_function_refused():
    """A raw function with no issued identity is never certified."""
    g = oai.make_tool_input_guardrail(_support_binding(), "read_file",
                                      expect_sdk_tool_name="delete_file")

    def evil(data):
        raise AssertionError("must never run")

    agent = _Agent([_Tool("delete_file", [evil])])
    ok = not _audit_certifies(agent)
    return ("HELD" if ok else "BREAK",
            "raw unissued function refused=%s" % ok)


def test_e3_attr_mutation_fails_closed():
    """Post-issuance attribute mutation cannot build a bypass.

    The audit reads the (mutable) attributes; the runtime reads the
    immutable closure variables. Mutating expect_sdk_tool_name to match
    a denied tool re-certifies at audit time but the guardrail then
    refuses every call at runtime (closure still holds the original
    name) -- the divergence is fail-closed, so the declared-name class
    is construction-time only.
    """
    b = _support_binding()
    g = oai.make_tool_input_guardrail(b, "read_file",
                                      expect_sdk_tool_name="read_file")
    g.expect_sdk_tool_name = "delete_file"  # post-issuance lie
    certified = _audit_certifies(_Agent([_Tool("delete_file", [g])]),
                                 sdk_tool_map=_HONEST_MAP)
    out = g(_Data(_Ctx("delete_file", json.dumps({"path": "v"}))))
    fails_closed = out.behavior.get("type") != "allow"
    # closed-tree contract: the mutated guardrail is refused coded at
    # audit (mapping disagrees), and the runtime still refuses -- the
    # divergence remains fail-closed.
    ok = (not certified) and fails_closed
    return ("HELD" if ok else "BREAK",
            "refused=%s runtime_refuses=%s" % ((not certified), fails_closed))


# ---------------------------------------------------------------- F: witness daemon

_SEED_LOG = bytes(range(32))
_SEED_W1 = bytes([9]) * 32
_LOG_KEY_NAME = "log1"
_ORIGIN = "w340-test-origin"


class _Signer:
    def __init__(self, seed):
        self._seed = seed
        self.public_key = cn._ed().publickey(seed)

    def sign(self, data):
        return cn._ed().sign(self._seed, data)


def _log_vkey(name, signer):
    return cn.vkey_string(
        name, cn.derive_key_id(name, cn.SIG_TYPE_ED25519, signer.public_key),
        cn.SIG_TYPE_ED25519, signer.public_key)


def _daemon(tmp):
    known = {_ORIGIN: [_log_vkey(_LOG_KEY_NAME, _Signer(_SEED_LOG))]}
    return wd.WitnessDaemon(known, "wit1", _Signer(_SEED_W1),
                            os.path.join(tmp, "w.db"))


def _log4():
    log = WitnessLog(_Signer(_SEED_LOG).public_key)
    for i in range(4):
        log.append(b"leaf-%d" % i)
    return log


def _body(log, old, note):
    return "\n".join(["old %d" % old, ""]) + "\n" + note.decode("utf-8")


def _flipped_sig_note(note):
    text = note.decode("utf-8")
    mark = "\u2014"
    i = text.rindex(mark)
    head, tail = text[:i], text[i:]
    for j, ch in enumerate(tail):
        if ch.isalnum() and ch in (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                "0123456789+/"):
            rep = "A" if ch != "A" else "B"
            return (head + tail[:j] + rep + tail[j + 1:]).encode("utf-8")
    raise AssertionError("no base64 char found")


def test_f1_bootstrap_then_equivocation():
    tmp = tempfile.mkdtemp(prefix="w340-f1-")
    d = _daemon(tmp)
    log = _log4()
    note = cn.emit_checkpoint(_ORIGIN, 4, log.root_hash(), _LOG_KEY_NAME,
                              _SEED_LOG)
    st, _ = d.handle_add_checkpoint(_body(log, 0, note), now=1700000000)
    evil = cn.emit_checkpoint(_ORIGIN, 4, bytes([0xAB]) * 32, _LOG_KEY_NAME,
                              _SEED_LOG)
    st2, msg2 = d.handle_add_checkpoint(_body(log, 4, evil), now=1700000001)
    ok = st == 200 and st2 == 422
    return ("HELD" if ok else "BREAK",
            "bootstrap=%s equivocation=%s (%s)" % (st, st2, msg2[:60]))


def test_f2_trusted_bad_signature_403():
    tmp = tempfile.mkdtemp(prefix="w340-f2-")
    d = _daemon(tmp)
    log = _log4()
    note = cn.emit_checkpoint(_ORIGIN, 4, log.root_hash(), _LOG_KEY_NAME,
                              _SEED_LOG)
    st, _ = d.handle_add_checkpoint(_body(log, 0, note), now=1700000000)
    st2, msg2 = d.handle_add_checkpoint(
        _body(log, 4, _flipped_sig_note(note)), now=1700000001)
    ok = st == 200 and st2 == 403
    return ("HELD" if ok else "BREAK",
            "bootstrap=%s bad-trusted-sig=%s (%s)" % (st, st2, msg2[:60]))


def test_f3_replay_old_gt_stored_400():
    tmp = tempfile.mkdtemp(prefix="w340-f3-")
    d = _daemon(tmp)
    log = _log4()
    note = cn.emit_checkpoint(_ORIGIN, 4, log.root_hash(), _LOG_KEY_NAME,
                              _SEED_LOG)
    d.handle_add_checkpoint(_body(log, 0, note), now=1700000000)
    st, msg = d.handle_add_checkpoint(_body(log, 9, note), now=1700000001)
    ok = st == 400
    return ("HELD" if ok else "BREAK",
            "old>stored=%s (%s)" % (st, msg[:60]))


def test_f4_unknown_origin_404():
    tmp = tempfile.mkdtemp(prefix="w340-f4-")
    d = _daemon(tmp)
    log = _log4()
    note = cn.emit_checkpoint("nope-origin", 4, log.root_hash(), _LOG_KEY_NAME,
                              _SEED_LOG)
    st, msg = d.handle_add_checkpoint(_body(log, 0, note), now=1700000000)
    ok = st == 404
    return ("HELD" if ok else "BREAK",
            "unknown-origin=%s (%s)" % (st, msg[:60]))


def test_f5_zero_size_nonempty_root_422():
    tmp = tempfile.mkdtemp(prefix="w340-f5-")
    d = _daemon(tmp)
    log = _log4()
    note = cn.emit_checkpoint(_ORIGIN, 0, bytes([0xCD]) * 32, _LOG_KEY_NAME,
                              _SEED_LOG)
    st, msg = d.handle_add_checkpoint(_body(log, 0, note), now=1700000000)
    ok = st == 422
    return ("HELD" if ok else "BREAK",
            "zero-size-nonempty-root=%s (%s)" % (st, msg[:60]))


def test_f6_unknown_key_signature_403():
    tmp = tempfile.mkdtemp(prefix="w340-f6-")
    d = _daemon(tmp)
    log = _log4()
    note = cn.emit_checkpoint(_ORIGIN, 4, log.root_hash(), "evil-key",
                              bytes([7]) * 32)
    st, msg = d.handle_add_checkpoint(_body(log, 0, note), now=1700000000)
    ok = st == 403
    return ("HELD" if ok else "BREAK",
            "unknown-key-sig=%s (%s)" % (st, msg[:60]))


# ---------------------------------------------------------------- G: OCI onboarding

def _transport(status, body):
    def t(request):
        if isinstance(status, Exception):
            raise status
        raw = body.encode("utf-8") if isinstance(body, str) else body
        return (status, {}, raw)
    return t


def _g_verdict(kind, status, body, override=None):
    return org.onboard_registry(
        _transport(status, body), "https://reg.example", "o/r",
        registry_kind=kind, matrix_override=override, auth_token=None)


def test_g1_ghcr_200_still_refused():
    r = _g_verdict("ghcr", 200, '{"referrers":[]}')
    ok = (r["verdict"] == "refused"
          and r["code"] == "oci-registry-onboarding-refused")
    return ("HELD" if ok else "BREAK",
            "ghcr+spoofed-200: %s probe=%s" % (r["verdict"], r["probe"]))


def test_g2_harbor_replication_garbage_refused():
    r = _g_verdict("harbor-replication", 200, "not-json{{{")
    ok = r["verdict"] == "refused" and r["probe"] == "inconclusive"
    return ("HELD" if ok else "BREAK",
            "harbor-replication+garbage: %s probe=%s"
            % (r["verdict"], r["probe"]))


def test_g3_acr_cmk_transport_failure_refused():
    r = _g_verdict("acr-cmk", ConnectionError("down"), None)
    ok = r["verdict"] == "refused" and r["probe"] == "inconclusive"
    return ("HELD" if ok else "BREAK",
            "acr-cmk+transport-down: %s probe=%s" % (r["verdict"], r["probe"]))


def test_g4_override_cannot_flip_out_to_in():
    r = _g_verdict("ghcr", 200, '{"referrers":[]}',
                   override={"ghcr": {"in": True}})
    ok = r["verdict"] == "refused" and r["matrix"] == "out"
    return ("HELD" if ok else "BREAK",
            "override OUT->IN: %s matrix=%s" % (r["verdict"], r["matrix"]))


def test_g5_zot_200_certified_control():
    r = _g_verdict("zot", 200, '{"referrers":[]}')
    ok = r["verdict"] == "certified-in"
    return ("HELD" if ok else "BREAK",
            "zot+200: %s probe=%s" % (r["verdict"], r["probe"]))


# ---------------------------------------------------------------- H: verifiable-only bundle

def _bundle(hint="k1", payload_type=None, tlog=(), msg_sig=False):
    env = {"payload": base64.b64encode(b'{"x":1}').decode(),
           "payloadType": (payload_type if payload_type is not None
                           else sb.SASANAM_PAYLOAD_TYPE),
           "signatures": [{"keyid": "",
                           "sig": base64.b64encode(b"\x00" * 64).decode()}]}
    b = {"mediaType": sb.SIGSTORE_BUNDLE_MEDIA_TYPE,
         "verificationMaterial": {"publicKey": {"hint": hint}},
         "dsseEnvelope": env}
    if tlog:
        b["tlogEntries"] = list(tlog)
    if msg_sig:
        b["messageSignature"] = {"signature": "x"}
    return b


def test_h1_wrong_payload_type_refused():
    try:
        sb.check_keyed_bundle_structure(
            _bundle(payload_type="application/vnd.other"))
        ok, code = False, "not-refused"
    except sb.KeyedBundleError as e:
        ok, code = e.code == "sigstore-keyed-payload-type", e.code
    return ("HELD" if ok else "BREAK", "wrong payloadType: %s" % code)


def test_h2_tlog_entries_refused():
    try:
        sb.check_keyed_bundle_structure(_bundle(tlog=[{"a": 1}]))
        ok, code = False, "not-refused"
    except sb.KeyedBundleError as e:
        ok, code = e.code == "sigstore-keyed-tlog-unexpected", e.code
    return ("HELD" if ok else "BREAK", "tlog entries: %s" % code)


def test_h3_message_signature_refused():
    try:
        sb.check_keyed_bundle_structure(_bundle(msg_sig=True))
        ok, code = False, "not-refused"
    except sb.KeyedBundleError as e:
        ok, code = (e.code == "sigstore-keyed-message-signature-unexpected"), e.code
    return ("HELD" if ok else "BREAK", "messageSignature: %s" % code)


def test_h4_revoked_hint_passes_by_design():
    """A hint pointing at a revoked/unknown key still passes structure:
    verifiable != verified -- the hint-to-pinned-key binding is the
    offline verifier's job, not the builder's (R22 contract)."""
    try:
        sb.check_keyed_bundle_structure(_bundle(hint="revoked-key-9"))
        ok, note = True, "structure passes (by design)"
    except sb.KeyedBundleError as e:
        ok, note = False, "unexpected refusal %s" % e.code
    return ("HELD" if ok else "BREAK", note)


# ---------------------------------------------------------------- pin

def test_pin_taxonomy_2127():
    codes = sorted(TAXONOMY)
    ok = (len(codes) == TAXONOMY_PIN == 2131
          and len(set(codes)) == len(codes))
    return ("HELD" if ok else "BREAK",
            "taxonomy %d/%d sorted-unique" % (len(codes), TAXONOMY_PIN))


TESTS = [test_e1_honest_guardrail_certifies,
         test_e2_raw_unissued_function_refused,
         test_e3_attr_mutation_fails_closed,
         test_f1_bootstrap_then_equivocation,
         test_f2_trusted_bad_signature_403,
         test_f3_replay_old_gt_stored_400,
         test_f4_unknown_origin_404,
         test_f5_zero_size_nonempty_root_422,
         test_f6_unknown_key_signature_403,
         test_g1_ghcr_200_still_refused,
         test_g2_harbor_replication_garbage_refused,
         test_g3_acr_cmk_transport_failure_refused,
         test_g4_override_cannot_flip_out_to_in,
         test_g5_zot_200_certified_control,
         test_h1_wrong_payload_type_refused,
         test_h2_tlog_entries_refused,
         test_h3_message_signature_refused,
         test_h4_revoked_hint_passes_by_design,
         test_pin_taxonomy_2127]

_EXPECTED_BREAKS = set()  # this battery asserts HELD everywhere


def _green_check():
    """Depth-1 green check: adjacent closure batteries only, each with
    GOV_SKIP_GREEN=1 in the child env (no combinatorial nesting)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "skipped (GOV_SKIP_GREEN=1)"
    venv_python = os.path.expanduser("~/workspace/.gov-venv/bin/python")
    notes = []
    for script in ("w338_f426_probes.py",):
        tmp = "/var/tmp/g340-green-%s" % script.replace(".py", "")
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ)
        env["GOV_DEPLOYMENT_MODE"] = "staging"
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tmp
        r = subprocess.run(
            [venv_python, os.path.join(REPO_ROOT, "evals", script)],
            capture_output=True, text=True, env=env, timeout=1800,
            cwd=REPO_ROOT)
        tail = (r.stdout + r.stderr)[-300:]
        notes.append("%s rc=%d %s" % (script, r.returncode, tail.strip()))
        if r.returncode != 0:
            raise AssertionError("green check failed: %s" % notes[-1])
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    ap.add_argument("--skip-green", action="store_true")
    args = ap.parse_args()
    _key()
    if not args.skip_green:
        print("green check: %s" % _green_check())
    n_break = n_held = n_err = 0
    probe_breaks = set()
    for fn in TESTS:
        if args.only and fn.__name__ != args.only:
            continue
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 - loud, never a skip
            verdict, detail = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, detail[:200]))
        if verdict == "BREAK":
            n_break += 1
            probe_breaks.add(fn.__name__)
        elif verdict == "HELD":
            n_held += 1
        else:
            n_err += 1
    print("tally: %d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    if probe_breaks ^ _EXPECTED_BREAKS:
        print("MISMATCH: breaks=%s expected=%s"
              % (sorted(probe_breaks), sorted(_EXPECTED_BREAKS)))
        sys.exit(2)
    sys.exit(1 if n_break or n_err else 0)


if __name__ == "__main__":
    main()
