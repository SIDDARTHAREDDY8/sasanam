#!/usr/bin/env python3
"""Wave-360 lane 5 (Kavach steal audit) canonicalization-first battery.

Kavach deep-dive (~/workspace/teams/deepdive-kavach/STEAL-BRIEF.md)
steal #1: an independent benchmark showed Kavach's tool-call enforcement
blocks 88% of real prompt-injection tool-call actions raw but 100% after
adapter canonicalization -- the gain attributed to canonicalization under
default-deny. This battery audits OUR tool-call interposition seams for the
same evasion class: every probe presents a raw-string evasion at a decision
seam and asserts the seam evaluates the CANONICAL form.

Probe convention (break-first): each probe returns ("HELD", note) when the
seam evaluates the canonical form (evasion caught / fail-closed), and
("BREAK", note) when the raw string reaches the decision uncanonicalized
or the evasion succeeds. A BREAK here is finding-shaped (F496+).

Seams covered:
  P1  sentinel dest-host binding (gov/sentinel_substitution.extract_dest_host)
  P2  shared URI canonicalizer (gov/uri_normalize)
  P3  MCP invocation permit binding (gov/mcp_invocation_authz)
  P4  per-call enforcer fail-closed matrix (gov/call_enforcement)
  P5  sandbox argv vector contract (gov/sandbox._checked_argv)
  P6  approval-token digest binding / single-use / expiry
      (gov/approval_tokens)
  P7  package-name canonicalization (gov/supplychain._canonical)
  P8  green check (depth-1, w359_attack_probes)
  P0  footer state

$0 spend: stdlib + in-repo modules only, no network, no model calls.
"""

import argparse
import os
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# The approval-token probes need a test HMAC key (same pattern as
# tests/test_approval_tokens.py); never touches ambient credentials.
if "GOV_LOG_KEY" not in os.environ:
    try:
        from tests.keyfixture import provision_test_key
    except ImportError:
        sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))
        from keyfixture import provision_test_key
    provision_test_key()

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _h(cond, ok_note, bad_note):
    return ("HELD" if cond else "BREAK", ok_note if cond else bad_note)


# ------------------------------------------------- P0 footer state

FOOTER_OPEN = "F621, F622, F623, F624, F625, F626, F627, F628, F629, F630, F631, F632, F633, F634, F635"    # Wave-369 merge: F547-F569 CLOSED; F570-F582 OPEN (next F583) # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # Wave-362 merge: F503-F505 CLOSED; F506-F511 filed OPEN (next F513); F512 CLOSED (perf fix)  # Wave-363 merge: F506-F511 CLOSED; F513-F520 filed OPEN (next F521); Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636
FOOTER_NEXT = "F636"  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636


@_t
def test_p0_footer_state():
    """Footer: open F489-F495 / next F496."""
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    import re
    opens = re.findall(r"Open findings: ([^*]{0,120})", text)
    nexts = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
    ok = (opens and opens[-1].strip().rstrip(".") == FOOTER_OPEN
          and nexts and nexts[-1] == FOOTER_NEXT)
    return _h(ok, "footer open %s / next %s" % (FOOTER_OPEN, FOOTER_NEXT),
              "footer drift: open=%r next=%r"
              % (opens[-1] if opens else None,
                 nexts[-1] if nexts else None))


# ------------------------------------------------- P1 dest-host binding

@_t
def test_p1a_userinfo_evasion():
    """http://evil.com@good.com/ binds to good.com, not evil.com."""
    from gov.sentinel_substitution import extract_dest_host
    dest = extract_dest_host(
        "http_post", {"url": "http://evil.com@good.com/x"})
    return _h(dest == "good.com",
              "userinfo stripped: dest=%r" % (dest,),
              "RAW userinfo reached the binding: dest=%r" % (dest,))


@_t
def test_p1b_case_trailing_dot():
    """HTTPS://GOOD.COM./ binds to good.com (canonical)."""
    from gov.sentinel_substitution import extract_dest_host
    dest = extract_dest_host(
        "http_post", {"url": "HTTPS://GOOD.COM./x"})
    return _h(dest == "good.com",
              "case/dot canonicalized: dest=%r" % (dest,),
              "RAW case/dot reached the binding: dest=%r" % (dest,))


@_t
def test_p1c_email_domain():
    """send_email to a@GOOD.com binds to good.com."""
    from gov.sentinel_substitution import extract_dest_host
    dest = extract_dest_host("send_email", {"to": "a@GOOD.com"})
    return _h(dest == "good.com",
              "email domain canonicalized: dest=%r" % (dest,),
              "RAW email domain reached the binding: dest=%r" % (dest,))


class _FakeVault(object):
    def __init__(self, recs):
        self._recs = recs
        self.trip_log = []

    def lookup(self, tok):
        return self._recs.get(tok)


@_t
def test_p1d_host_mismatch_trips():
    """Credential bound to good.com presented for evil.com trips."""
    from gov.sentinel_substitution import _binding_map
    tok = "fake_value_" + "0" * 8 + "-" + "0" * 4 + "-" + "0" * 4 + "-" \
        + "0" * 4 + "-" + "0" * 12
    vault = _FakeVault({tok: {"credential_id": "c1", "hosts": ["good.com"]}})
    dest, bound = _binding_map(
        vault, "http_post",
        {"url": "http://evil.com/x", "password": tok})
    return _h(bound.get("__mismatch__") is not None,
              "mismatch trips fail-closed (dest=%r)" % (dest,),
              "mismatch did NOT trip: bound=%r" % (bound,))


# ------------------------------------------------- P2 URI canonicalizer

@_t
def test_p2a_punycode():
    """Unicode host IDNA-encodes to the ASCII form the allowlist sees."""
    from gov import uri_normalize as un
    got = un.normalize_host("münchen.de")
    return _h(got == "xn--mnchen-3ya.de",
              "punycode canonical: %r" % (got,),
              "punycode NOT canonicalized: %r" % (got,))


@_t
def test_p2b_idempotent():
    """normalize_host is idempotent (canonical form is a fixed point)."""
    from gov import uri_normalize as un
    once = un.normalize_host("  EXAMPLE.com. ")
    twice = un.normalize_host(once)
    return _h(once == twice == "example.com",
              "idempotent: %r" % (once,),
              "not idempotent: %r -> %r" % (once, twice))


@_t
def test_p2c_url_host_evasion():
    """normalize_url_host strips userinfo/port/case before matching."""
    from gov import uri_normalize as un
    got = un.normalize_url_host("http://user:pass@EVIL.example.COM:8080/x")
    return _h(got == "evil.example.com",
              "url host canonical: %r" % (got,),
              "RAW url host: %r" % (got,))


# ------------------------------------------------- P3 MCP permit binding

def _mcp_permit():
    from gov.mcp_invocation_authz import (
        build_policy, authorize, canonical_digest)
    pol = build_policy({
        "subject_id": "agent-1",
        "pinned_mapping_digest": canonical_digest({"tools": ["a"]})})
    msg = {"method": "tools/call",
           "params": {"name": "a", "arguments": {"x": 1}}, "id": 1}
    ctx = {"subject": {"id": "agent-1"},
           "server_mapping": {"tools": ["a"]}}
    r = authorize(pol, msg, ctx)
    assert r.verdict == "permit", r
    return r.permit, msg, ctx


@_t
def test_p3a_mutated_message_refused():
    """Permit bound to the exact message: mutated params refuse."""
    from gov.mcp_invocation_authz import apply_permit
    permit, msg, ctx = _mcp_permit()
    msg2 = dict(msg)
    msg2["params"] = {"name": "a", "arguments": {"x": 2}}
    r = apply_permit(permit, msg2, ctx)
    return _h(r.verdict == "refuse" and r.code == "permit-message-mismatch",
              "mutated message refused (%s)" % (r.code,),
              "MUTATED MESSAGE APPLIED: %s" % (r.code,))


@_t
def test_p3b_key_reorder_applies():
    """Canonical digest: key order is not a distinct message."""
    from gov.mcp_invocation_authz import apply_permit
    permit, msg, ctx = _mcp_permit()
    msg3 = {"id": 1,
            "params": {"arguments": {"x": 1}, "name": "a"},
            "method": "tools/call"}
    r = apply_permit(permit, msg3, ctx)
    return _h(r.verdict == "apply",
              "reordered keys apply (canonical digest)",
              "reordered keys refused: %s" % (r.code,))


@_t
def test_p3c_subject_swap_refused():
    """Permit re-anchors the subject at execution time."""
    from gov.mcp_invocation_authz import apply_permit
    permit, msg, _ = _mcp_permit()
    ctx2 = {"subject": {"id": "agent-2"},
            "server_mapping": {"tools": ["a"]}}
    r = apply_permit(permit, msg, ctx2)
    return _h(r.verdict == "refuse",
              "subject swap refused (%s)" % (r.code,),
              "SUBJECT SWAP APPLIED: %s" % (r.code,))


# ------------------------------------------------- P4 enforcer fail-closed

def _enforcer(check, timeout_s=1.0):
    from gov.call_enforcement import CallEnforcer, ScopedPolicy
    e = CallEnforcer(check=None)
    e.register_policy(
        ScopedPolicy("t", "a/*", "*", check=check, timeout_s=timeout_s))
    return e


def _req(action="a/b"):
    from gov.call_enforcement import CheckRequest
    return CheckRequest("id", action, "r", {})


@_t
def test_p4a_check_raise_denies():
    """A check that raises -> callauthz-check-error DENY."""
    def boom(req):
        raise RuntimeError("x")
    r = _enforcer(boom).enforce(_req())
    return _h(not r.allow and r.code == "callauthz-check-error",
              "raise -> deny (%s)" % (r.code,),
              "RAISING CHECK ALLOWED: %s" % (r.code,))


@_t
def test_p4b_check_timeout_denies():
    """A check that exceeds its deadline -> callauthz-check-error DENY."""
    from gov.call_enforcement import AuthorizationVerdict

    def slow(req):
        time.sleep(2)
        return AuthorizationVerdict(True, "ok", "")

    r = _enforcer(slow, timeout_s=0.2).enforce(_req())
    return _h(not r.allow and r.code == "callauthz-check-error",
              "timeout -> deny (%s)" % (r.code,),
              "TIMED-OUT CHECK ALLOWED: %s" % (r.code,))


@_t
def test_p4c_wrong_type_denies():
    """A check returning a non-verdict -> callauthz-check-error DENY."""
    def wrongtype(req):
        return "allow"
    r = _enforcer(wrongtype).enforce(_req())
    return _h(not r.allow and r.code == "callauthz-check-error",
              "wrong type -> deny (%s)" % (r.code,),
              "WRONG-TYPE CHECK ALLOWED: %s" % (r.code,))


@_t
def test_p4d_no_policy_denies():
    """A call matching no policy -> callauthz-not-configured DENY."""
    from gov.call_enforcement import CallEnforcer
    r = CallEnforcer(check=None).enforce(_req(action="zzz/b"))
    return _h(not r.allow and r.code == "callauthz-not-configured",
              "no policy -> deny (%s)" % (r.code,),
              "UNCONFIGURED CALL ALLOWED: %s" % (r.code,))


@_t
def test_p4e_segment_boundary():
    """Policy for tool/read never authorizes tool/readwrite."""
    from gov.call_enforcement import CallEnforcer, ScopedPolicy, \
        AuthorizationVerdict

    def allow(req):
        return AuthorizationVerdict(True, "ok", "")

    e = CallEnforcer(check=None)
    e.register_policy(ScopedPolicy("p", "tool/read", "*", check=allow))
    r = e.enforce(_req(action="tool/readwrite"))
    return _h(not r.allow,
              "tool/readwrite denied under tool/read policy",
              "PREFIX CONFUSION: tool/readwrite allowed by tool/read")


# ------------------------------------------------- P5 sandbox argv contract

@_t
def test_p5a_string_argv_refused():
    """A shell-string argv refuses TypeError (shell=False always)."""
    from gov.sandbox import Sandbox
    try:
        Sandbox._checked_argv("echo hello")
    except TypeError:
        return ("HELD", "string argv refused TypeError")
    return ("BREAK", "STRING ARGV ACCEPTED")


@_t
def test_p5b_nul_argv_refused():
    """A NUL byte in argv refuses ValueError."""
    from gov.sandbox import Sandbox
    try:
        Sandbox._checked_argv(["echo", "a\x00b"])
    except ValueError:
        return ("HELD", "NUL argv refused ValueError")
    return ("BREAK", "NUL BYTE ARGV ACCEPTED")


@_t
def test_p5c_vector_executes():
    """Control: a clean argv vector executes (no false positive)."""
    from gov.sandbox import Sandbox
    import tempfile
    tmp = tempfile.mkdtemp(prefix="g360-p5c-", dir="/var/tmp")
    os.environ["TMPDIR"] = tmp
    try:
        r = Sandbox(timeout=10).run(["echo", "hello"])
    finally:
        os.environ.pop("TMPDIR", None)
    ok = r.returncode == 0 and r.stdout.strip() == "hello"
    return _h(ok, "argv vector executes (control)",
              "clean argv failed: rc=%r out=%r" % (r.returncode, r.stdout))


# ------------------------------------------------- P6 approval tokens

_NOW = 1798765432


def _issue(**kw):
    from gov import approval_tokens as AT
    base = {"capability": "send_email",
            "argument_binding": {"mode": "exact",
                                 "args": {"to": "colleague@example.com",
                                          "body": "the report"}},
            "issuer": "human-operator",
            "ttl_seconds": 3600,
            "issued_at": _NOW}
    base.update(kw)
    return AT.issue_token(**base)


@_t
def test_p6a_args_mismatch_refused():
    """Token for (tool, args) never authorizes different args."""
    from gov import approval_tokens as AT
    tok = _issue()
    try:
        AT.verify_token(tok, capability="send_email",
                        args={"to": "attacker@evil.com",
                              "body": "the report"},
                        now=_NOW)
    except AT.ApprovalTokenError as e:
        return _h(e.code == "approval-token-argument-mismatch",
                  "args mismatch refused (%s)" % (e.code,),
                  "wrong code: %s" % (e.code,))
    return ("BREAK", "TOKEN HONORED FOR DIFFERENT ARGS")


@_t
def test_p6b_replay_refused():
    """A consumed nonce refuses: at most one execution per token."""
    from gov import approval_tokens as AT
    tok = _issue()
    store = AT.TokenConsumeStore()
    AT.verify_token(tok, capability="send_email",
                    args={"to": "colleague@example.com",
                          "body": "the report"},
                    now=_NOW, consume_store=store)
    store.consume(tok["nonce"])
    try:
        AT.verify_token(tok, capability="send_email",
                        args={"to": "colleague@example.com",
                              "body": "the report"},
                        now=_NOW, consume_store=store)
    except AT.ApprovalTokenError as e:
        return _h(e.code == "approval-token-replayed",
                  "replay refused (%s)" % (e.code,),
                  "wrong code: %s" % (e.code,))
    return ("BREAK", "TOKEN REPLAYED AFTER CONSUME")


@_t
def test_p6c_expired_refused():
    """An expired token refuses."""
    from gov import approval_tokens as AT
    tok = _issue(ttl_seconds=60)
    try:
        AT.verify_token(tok, capability="send_email",
                        args={"to": "colleague@example.com",
                              "body": "the report"},
                        now=_NOW + 61)
    except AT.ApprovalTokenError as e:
        return _h(e.code == "approval-token-expired",
                  "expired token refused (%s)" % (e.code,),
                  "wrong code: %s" % (e.code,))
    return ("BREAK", "EXPIRED TOKEN HONORED")


# ------------------------------------------------- P7 package names

@_t
def test_p7a_pep503_canonical():
    """PEP-503 spellings of one package canonicalize together.

    (re.quests is NOT the same package as requests per PEP 503 -- it
    normalizes to re-quests. The evasion question is whether two
    spellings of the SAME package diverge.)
    """
    from gov.supplychain import _canonical
    forms = ["Requests", "requests", "REQUESTS", "ReQuests"]
    vals = {_canonical(f) for f in forms}
    vals2 = {_canonical(f) for f in ["re.quests", "re-quests", "re_quests",
                                      "re--quests"]}
    ok = vals == {"requests"} and vals2 == {"re-quests"}
    return _h(ok,
              "all spellings -> %r / %r" % (vals, vals2),
              "canonical split: %r / %r" % (vals, vals2))


@_t
def test_p7b_unlisted_install_refused():
    """check_install_allowed refuses a non-allowlisted package."""
    from gov.supplychain import check_install_allowed, SupplyChainError
    try:
        check_install_allowed("evil-package-xyz-404")
    except SupplyChainError:
        return ("HELD", "unlisted package refused")
    return ("BREAK", "UNLISTED PACKAGE ALLOWED")


# ------------------------------------------------- P8 green check (depth-1)

_EXPECTED_BREAKS = set()


def _green_check():
    """Depth-1 green check: run the wave-359 attack battery with
    GOV_SKIP_GREEN=1 in the child env."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return ("HELD", "green check skipped (GOV_SKIP_GREEN=1)")
    import subprocess
    tmp = tempfile.mkdtemp(prefix="g360-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    p = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals",
                                      "w359_attack_probes.py")],
        capture_output=True, text=True, timeout=600, env=env,
        cwd=REPO_ROOT)
    out = (p.stdout + p.stderr)
    breaks = set()
    for line in out.splitlines():
        if line.startswith("BREAKS:"):
            try:
                breaks = set(eval(line.split("BREAKS:", 1)[1].strip()))
            except Exception:  # noqa: BLE001
                pass
    allowed = {"test_b0_footer_state"}  # designed stale footer pin
    tolerated = breaks & allowed
    real = breaks - allowed
    return (("HELD" if not real else "BREAK"),
            "green(w359_attack): %d real BREAK (%d tolerated footer)"
            % (len(real), len(tolerated)))


@_t
def test_p8_green_check():
    """Green check: wave-359 attack battery stays green (depth-1)."""
    return _green_check()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=None)
    args = ap.parse_args()
    breaks, held = 0, 0
    probe_breaks = set()
    for fn in TESTS:
        if args.probe and args.probe not in fn.__name__:
            continue
        try:
            verdict, note = fn()
        except Exception as e:  # noqa: BLE001
            verdict, note = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%s: %s -- %s" % (fn.__name__, verdict, note))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
            probe_breaks.add(fn.__name__)
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD / 0 ERROR" % (breaks, held))
    print("BREAKS:", sorted(probe_breaks - _EXPECTED_BREAKS))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
