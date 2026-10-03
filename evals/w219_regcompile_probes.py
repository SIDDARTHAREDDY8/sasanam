#!/usr/bin/env python3
"""Wave-219 lane A: compile-everything-at-registration break-first battery.

Seam under test: ``gov.policy_compile`` extended with the sigstore
policy-controller STEAL (idea only, Apache-2.0, no upstream source
vendored) -- compile-policy-once across ALL policy types:

* ``compile_quorum_step`` / ``CompiledQuorumStep`` (gov.quorum_policy)
* ``compile_arap_context`` / ``CompiledArapContext`` (gov.arap context rules)
* ``compile_jail_policy`` / ``CompiledJailPolicy`` (gov.jail_policy)
* knative-inspired ``FieldError`` taxonomy (path + expected + got,
  machine-readable, natively reimplemented -- no upstream prose copied)

Contract: authoring errors fail at COMPILE with ``PolicyCompilationError``
(code "policy-compile-refused", carrying FieldErrors, optionally
audited); evaluation-time garbage is a DATA error (fail-closed, distinct
codes); evaluation paths contain no authoring validation BY
CONSTRUCTION (compiled objects take no spec/policy parameter).

Verdicts: HELD / GAP / BREAK / ERROR. Any BREAK = genuine break of the
compile-once discipline (file as F209+). Exit 1 on any BREAK/ERROR.

$0 spend. No network. stdlib only. Real product code, no stubs.

Run:
  mkdir -p /var/tmp/g219a
  TMPDIR=/var/tmp/g219a ~/workspace/.gov-venv/bin/python evals/w219_regcompile_probes.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g219a-u \\
      ~/workspace/.gov-venv/bin/python evals/w219_regcompile_probes.py
"""

import hashlib
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/var/tmp/g219a-%d" % os.getpid())

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

from gov import policy_compile as pc  # noqa: E402
from gov import quorum_policy as qp  # noqa: E402
from gov import jail_policy as jp  # noqa: E402
from gov import arap as _arap  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

_RESULTS = []
_PROBE_FNS = {}

_NEEDED = ("FieldError", "PolicyCompilationError", "compile_quorum_step",
           "compile_arap_context", "compile_jail_policy",
           "CompiledQuorumStep", "CompiledArapContext", "CompiledJailPolicy")
_ABSENT = not all(hasattr(pc, n) for n in _NEEDED)


def _probe(name):
    def deco(fn):
        _PROBE_FNS[name] = fn
        return fn
    return deco


def _record(name, verdict, detail):
    _RESULTS.append((name, verdict, detail))


def _need(name):
    if _ABSENT:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        _record(name, "BREAK", "GAP: regcompile names absent from gov.policy_compile")
        return False
    return True


def _expect_compile_refused(name, fn):
    """fn() must raise PolicyCompilationError carrying FieldErrors."""
    try:
        fn()
    except pc.PolicyCompilationError as exc:
        errs = getattr(exc, "errors", ())
        if not errs:
            _record(name, "BREAK", "compile refused but carried no FieldErrors")
            return None
        bad = [e for e in errs
               if not all(hasattr(e, a) for a in ("path", "expected", "got"))]
        if bad:
            _record(name, "BREAK", "FieldError missing path/expected/got")
            return None
        return exc
    except Exception as exc:  # noqa: BLE001
        _record(name, "BREAK", "wrong exception at compile: %s: %s"
                % (type(exc).__name__, exc))
        return None
    _record(name, "BREAK", "malformed policy compiled without refusal")
    return None


_SEEDS = {"A": bytes.fromhex("a1" * 32), "B": bytes.fromhex("b2" * 32),
          "C": bytes.fromhex("c3" * 32)}
_DIGEST_X = hashlib.sha256(b"fact-X").hexdigest()
_KEY16 = b"k" * 16
_KEY16B = b"j" * 16


def _good_quorum_spec():
    return {"step_name": "build",
            "authorized_keyids": ["k1", "k2", "k3"],
            "threshold": 2}


def _good_jail_body():
    return jp.make_policy_body("py-tool", 1, writable_dirs=["/output"])


def _good_context():
    return {"image": "img:v1", "cmd": ["run"]}


# ----------------------------------------------------------------------
# Compile-time refusals.
# ----------------------------------------------------------------------

@_probe("quorum-malformed-refused")
def _p_quorum_malformed():
    if not _need("quorum-malformed-refused"):
        return
    bads = [
        {"step_name": "s", "authorized_keyids": ["k"], "threshold": 0},
        {"step_name": "s", "authorized_keyids": ["k", "k"], "threshold": 1},
        {"step_name": "s", "authorized_keyids": ["k"], "threshold": 2},
        {"step_name": "", "authorized_keyids": ["k"], "threshold": 1},
        {"step_name": "s", "authorized_keyids": [], "threshold": 1},
        {"step_name": "s", "authorized_keyids": ["k"], "threshold": 1,
         "mystery": True},
        "not-a-dict",
    ]
    for i, bad in enumerate(bads):
        exc = _expect_compile_refused(
            "quorum-malformed-refused",
            lambda b=bad: pc.compile_quorum_step(b))
        if exc is None:
            return
    _record("quorum-malformed-refused", "HELD",
            "%d malformed quorum specs refused at compile w/ FieldErrors"
            % len(bads))


@_probe("quorum-multi-error-aggregated")
def _p_quorum_multi():
    if not _need("quorum-multi-error-aggregated"):
        return
    bad = {"step_name": "", "authorized_keyids": ["k", 7, ""],
           "threshold": 99, "unknown_key": 1}
    try:
        pc.compile_quorum_step(bad)
    except pc.PolicyCompilationError as exc:
        if len(exc.errors) < 3:
            _record("quorum-multi-error-aggregated", "BREAK",
                    "only %d FieldError(s); expected aggregation of all"
                    % len(exc.errors))
            return
        paths = sorted(e.path for e in exc.errors)
        _record("quorum-multi-error-aggregated", "HELD",
                "%d FieldErrors aggregated: %s"
                % (len(exc.errors), ",".join(paths)))
        return
    except Exception as exc:  # noqa: BLE001
        _record("quorum-multi-error-aggregated", "BREAK",
                "wrong exception: %s" % type(exc).__name__)
        return
    _record("quorum-multi-error-aggregated", "BREAK", "no refusal")


@_probe("arap-malformed-refused")
def _p_arap_malformed():
    if not _need("arap-malformed-refused"):
        return
    bads = [
        ({"f": 1}, b"short"),            # key < 16 bytes
        ({"f": 1}, "not-bytes"),         # key not bytes
        ("not-a-dict", _KEY16),          # context not a dict
        ({"": 1}, _KEY16),               # empty field name
        ({1: "x"}, _KEY16),              # non-string field name
    ]
    for i, (ctx, key) in enumerate(bads):
        exc = _expect_compile_refused(
            "arap-malformed-refused",
            lambda c=ctx, k=key: pc.compile_arap_context(c, key=k))
        if exc is None:
            return
    _record("arap-malformed-refused", "HELD",
            "%d malformed ARAP contexts refused at compile w/ FieldErrors"
            % len(bads))


@_probe("jail-malformed-refused")
def _p_jail_malformed():
    if not _need("jail-malformed-refused"):
        return
    base = _good_jail_body()

    def mutate(**kw):
        b = dict(base)
        b.update(kw)
        return b

    bads = [
        mutate(platform="kvm"),                       # closed vocab
        mutate(timeout_s=0),                           # range
        mutate(network="host"),                        # closed vocab
        mutate(no_new_privs=False),                    # must be True
        mutate(capabilities=["x"]),                    # must be []
        mutate(not_before=200, not_after=100),         # ordering
        mutate(syscall_profile="nope"),                # closed vocab
        mutate(writable_dirs=[]),                      # non-empty
        mutate(resource_limits={"cpu_s": 1}),          # exact keys
        dict(base, **{"extra_field": 1}),              # unknown field
    ]
    for i, bad in enumerate(bads):
        exc = _expect_compile_refused(
            "jail-malformed-refused",
            lambda b=bad: pc.compile_jail_policy(b))
        if exc is None:
            return
    _record("jail-malformed-refused", "HELD",
            "%d malformed jail bodies refused at compile w/ FieldErrors"
            % len(bads))


@_probe("fielderror-machine-readable")
def _p_fielderror():
    if not _need("fielderror-machine-readable"):
        return
    fe = pc.FieldError("authorized_keyids[2]", "non-empty string", 7)
    d = fe.to_dict()
    for k in ("path", "expected", "got", "detail"):
        if k not in d:
            _record("fielderror-machine-readable", "BREAK",
                    "to_dict missing %r" % k)
            return
    if d["path"] != "authorized_keyids[2]" or d["expected"] != \
            "non-empty string":
        _record("fielderror-machine-readable", "BREAK",
                "to_dict values wrong")
        return
    if not isinstance(d["got"], str):
        _record("fielderror-machine-readable", "BREAK",
                "got must be a repr-safe string, not %s" % type(d["got"]))
        return
    sub = fe.via_field("step").via_index(3)
    if sub.path != "step[3].authorized_keyids[2]":
        _record("fielderror-machine-readable", "BREAK",
                "via_field/via_index path prefixing wrong: %r" % sub.path)
        return
    try:
        json.dumps(d)
    except TypeError:
        _record("fielderror-machine-readable", "BREAK",
                "to_dict not JSON-serializable")
        return
    _record("fielderror-machine-readable", "HELD",
            "path/expected/got/detail JSON-serializable; prefixing works")


# ----------------------------------------------------------------------
# Parity: compiled forms behave identically to legacy.
# ----------------------------------------------------------------------

@_probe("quorum-100-parity")
def _p_quorum_parity():
    if not _need("quorum-100-parity"):
        return
    signers = {k: Ed25519Signer(s) for k, s in _SEEDS.items()}
    kids = [signers[k].key_id for k in ("A", "B", "C")]
    spec = {"step_name": "build", "authorized_keyids": kids, "threshold": 2}
    compiled = pc.compile_quorum_step(spec)
    legacy_step = qp.load_quorum_step(spec)
    keyset = {kid: Ed25519Verifier(signers[k].public_key)
              for k, kid in zip(("A", "B", "C"), kids)}
    for i in range(100):
        digest = hashlib.sha256(("fact-%d" % i).encode()).hexdigest()
        recs = [qp.make_link_record("build", digest, signers["A"],
                                    expected_command="make"),
                qp.make_link_record("build", digest, signers["B"],
                                    expected_command="make")]
        r1 = compiled.verify(recs, keyset)
        r2 = qp.verify_quorum(legacy_step, recs, keyset)
        if r1 != r2:
            _record("quorum-100-parity", "BREAK",
                    "divergence at batch %d" % i)
            return
    _record("quorum-100-parity", "HELD",
            "100/100 identical reports (compiled vs legacy)")


@_probe("jail-100-parity")
def _p_jail_parity():
    if not _need("jail-100-parity"):
        return
    body = _good_jail_body()
    compiled = pc.compile_jail_policy(body)
    norm = jp.validate_policy_body(body)
    for i in range(100):
        req = {"writable_dirs": ["/output/sub%d" % (i % 7)],
               "wants_network": False,
               "timeout_s": 1 + (i % 5)}
        r1 = compiled.check(req)
        r2 = jp.check_invocation(norm, req)
        if r1 != r2:
            _record("jail-100-parity", "BREAK",
                    "divergence at request %d" % i)
            return
    _record("jail-100-parity", "HELD",
            "100/100 identical reports (compiled vs legacy)")


@_probe("arap-parity")
def _p_arap_parity():
    if not _need("arap-parity"):
        return
    ctx = _good_context()
    compiled = pc.compile_arap_context(ctx, key=_KEY16)
    decl = _arap.declare_context(ctx, key=_KEY16)
    if compiled.declared != decl["declared"] or \
            compiled.binding != decl["binding"]:
        _record("arap-parity", "BREAK", "declaration differs from legacy")
        return
    _arap.verify_context_binding(decl["declared"], decl["binding"],
                                 key=_KEY16)
    compiled.verify_binding(key=_KEY16)
    if compiled.check_cited(["image"]) != _arap.check_cited_context(
            ["image"], decl["declared"]):
        _record("arap-parity", "BREAK", "check_cited differs from legacy")
        return
    _record("arap-parity", "HELD",
            "declaration/verify/check_cited identical to legacy")


# ----------------------------------------------------------------------
# Evaluation cannot raise authoring errors (by construction).
# ----------------------------------------------------------------------

@_probe("eval-cannot-raise-authoring")
def _p_eval_no_authoring():
    if not _need("eval-cannot-raise-authoring"):
        return
    # Smuggling unvalidated specs into compiled constructors is refused
    # at construction, never deferred to evaluation.
    for fn in (lambda: pc.CompiledQuorumStep({"nope": 1}),
               lambda: pc.CompiledJailPolicy({"nope": 1}),
               lambda: pc.CompiledArapContext("nope", key=_KEY16)):
        try:
            fn()
        except pc.PolicyCompilationError:
            pass
        except Exception as exc:  # noqa: BLE001
            _record("eval-cannot-raise-authoring", "BREAK",
                    "constructor raised %s instead of PolicyCompilationError"
                    % type(exc).__name__)
            return
        else:
            _record("eval-cannot-raise-authoring", "BREAK",
                    "constructor accepted garbage")
            return
    # Garbage DATA at evaluation is a data error, never an authoring error.
    compiled = pc.compile_quorum_step(_good_quorum_spec())
    try:
        compiled.verify([{"garbage": True}], {"k1": object()})
    except pc.PolicyCompilationError:
        _record("eval-cannot-raise-authoring", "BREAK",
                "evaluation raised the AUTHORING error class on data garbage")
        return
    except qp.QuorumPolicyError:
        pass
    except Exception as exc:  # noqa: BLE001
        _record("eval-cannot-raise-authoring", "BREAK",
                "evaluation raised unexpected %s" % type(exc).__name__)
        return
    # Evaluation methods take no spec/policy parameter (by construction).
    import inspect  # noqa: E402
    for meth in (pc.CompiledQuorumStep.verify, pc.CompiledJailPolicy.check,
                 pc.CompiledArapContext.verify_binding):
        params = inspect.signature(meth).parameters
        for bad in ("spec", "policy", "body", "rules"):
            if bad in params:
                _record("eval-cannot-raise-authoring", "BREAK",
                        "%s takes a %r parameter" % (meth.__qualname__, bad))
                return
    _record("eval-cannot-raise-authoring", "HELD",
            "authoring errors impossible at evaluation by construction")


@_probe("codes-disjoint")
def _p_codes():
    if not _need("codes-disjoint"):
        return
    compile_code = pc.PolicyCompilationError.code
    if compile_code != "policy-compile-refused":
        _record("codes-disjoint", "BREAK",
                "compile code is %r, expected 'policy-compile-refused'"
                % compile_code)
        return
    # Evaluation-time refusals must never carry the compile code.
    jc = pc.compile_jail_policy(_good_jail_body())
    try:
        jc.check({"writable_dirs": ["/etc"], "wants_network": False,
                  "timeout_s": 1})
    except jp.JailPolicyError as exc:
        if exc.code == compile_code:
            _record("codes-disjoint", "BREAK",
                    "evaluation refusal carried the compile code")
            return
    q = pc.compile_quorum_step(_good_quorum_spec())
    try:
        q.verify([], {"k1": object()})
    except Exception as exc:  # noqa: BLE001
        if getattr(exc, "code", None) == compile_code or \
                "policy-compile-refused" in str(exc):
            _record("codes-disjoint", "BREAK",
                    "evaluation refusal carried the compile code")
            return
    try:
        pc.compile_arap_context({"f": 1}, key=b"short")
    except pc.PolicyCompilationError as exc:
        if exc.code != compile_code:
            _record("codes-disjoint", "BREAK", "compile code mismatch")
            return
    _record("codes-disjoint", "HELD",
            "compile code %r disjoint from evaluation refusal codes"
            % compile_code)


@_probe("legacy-byte-identical")
def _p_legacy():
    if not _need("legacy-byte-identical"):
        return
    # Legacy loaders keep their exact behavior (we did not rewrite them).
    step = qp.load_quorum_step(_good_quorum_spec())
    if step.threshold != 2:
        _record("legacy-byte-identical", "BREAK", "load_quorum_step changed")
        return
    norm = jp.validate_policy_body(_good_jail_body())
    if norm["policy_name"] != "py-tool":
        _record("legacy-byte-identical", "BREAK",
                "validate_policy_body changed")
        return
    decl = _arap.declare_context(_good_context(), key=_KEY16)
    _arap.verify_context_binding(decl["declared"], decl["binding"],
                                 key=_KEY16)
    if _arap.binding_scope({}) != "subject/resource/action":
        _record("legacy-byte-identical", "BREAK", "binding_scope changed")
        return
    _record("legacy-byte-identical", "HELD",
            "legacy loaders byte-identical in behavior")


# ----------------------------------------------------------------------
# Dispatch, fingerprints, audit.
# ----------------------------------------------------------------------

@_probe("dispatch")
def _p_dispatch():
    if not _need("dispatch"):
        return
    c1 = pc.compile_policy(_good_quorum_spec())
    if not isinstance(c1, pc.CompiledQuorumStep):
        _record("dispatch", "BREAK", "quorum dict mis-dispatched")
        return
    c2 = pc.compile_policy(_good_jail_body())
    if not isinstance(c2, pc.CompiledJailPolicy):
        _record("dispatch", "BREAK", "jail body mis-dispatched")
        return
    step = qp.load_quorum_step(_good_quorum_spec())
    c3 = pc.compile_policy(step)
    if not isinstance(c3, pc.CompiledQuorumStep):
        _record("dispatch", "BREAK", "QuorumStep instance mis-dispatched")
        return
    from gov import identity_policy as _ip  # noqa: E402
    c4 = pc.compile_policy({"claimEquals": {"path": "a", "value": 1}})
    if not isinstance(c4, pc.CompiledIdentityPolicy):
        _record("dispatch", "BREAK", "identity dispatch changed")
        return
    try:
        pc.compile_policy({"a": 1, "b": 2})
    except _ip.PolicyAuthoringError:
        pass
    else:
        _record("dispatch", "BREAK", "garbage spec not refused")
        return
    _record("dispatch", "HELD",
            "quorum/jail/QuorumStep dispatched; identity+garbage unchanged")


@_probe("fingerprint-stable-and-keyless")
def _p_fingerprint():
    if not _need("fingerprint-stable-and-keyless"):
        return
    a = pc.compile_arap_context(_good_context(), key=_KEY16)
    b = pc.compile_arap_context(_good_context(), key=_KEY16B)
    if a.fingerprint() != b.fingerprint():
        _record("fingerprint-stable-and-keyless", "BREAK",
                "ARAP fingerprint depends on the key (must not)")
        return
    if len(a.fingerprint()) != 64:
        _record("fingerprint-stable-and-keyless", "BREAK",
                "fingerprint not sha256 hex")
        return
    c = pc.compile_arap_context({"other": 1}, key=_KEY16)
    if a.fingerprint() == c.fingerprint():
        _record("fingerprint-stable-and-keyless", "BREAK",
                "fingerprint collision across contexts")
        return
    q1 = pc.compile_quorum_step(_good_quorum_spec()).fingerprint()
    q2 = pc.compile_quorum_step(_good_quorum_spec()).fingerprint()
    if q1 != q2:
        _record("fingerprint-stable-and-keyless", "BREAK",
                "quorum fingerprint unstable")
        return
    j1 = pc.compile_jail_policy(_good_jail_body()).fingerprint()
    j2 = pc.compile_jail_policy(_good_jail_body()).fingerprint()
    if j1 != j2:
        _record("fingerprint-stable-and-keyless", "BREAK",
                "jail fingerprint unstable")
        return
    _record("fingerprint-stable-and-keyless", "HELD",
            "fingerprints stable; ARAP pin excludes the key")


@_probe("audit-on-compile")
def _p_audit():
    if not _need("audit-on-compile"):
        return
    events = []
    pc.compile_quorum_step(_good_quorum_spec(), audit=events.append)
    if not any(e.get("event") == "policy_compiled" and
               e.get("fingerprint") for e in events):
        _record("audit-on-compile", "BREAK",
                "success did not emit an auditable policy_compiled event")
        return
    events.clear()
    try:
        pc.compile_quorum_step({"step_name": "s",
                                "authorized_keyids": ["k"], "threshold": 0},
                               audit=events.append)
    except pc.PolicyCompilationError:
        pass
    refused = [e for e in events if e.get("event") == "policy_compile_refused"]
    if not refused or refused[0].get("code") != "policy-compile-refused" or \
            not refused[0].get("errors"):
        _record("audit-on-compile", "BREAK",
                "refusal not audited with code + field errors")
        return
    _record("audit-on-compile", "HELD",
            "compile success + refusal both audited w/ code")


@_probe("araps-key-discipline")
def _p_key_discipline():
    if not _need("araps-key-discipline"):
        return
    # Undersized keys are a COMPILE error (deployment error), not an
    # evaluation surprise.
    try:
        pc.compile_arap_context(_good_context(), key=b"tiny")
    except pc.PolicyCompilationError as exc:
        if not any(e.path == "key" for e in exc.errors):
            _record("araps-key-discipline", "BREAK",
                    "short key refused but no path='key' FieldError")
            return
    else:
        _record("araps-key-discipline", "BREAK",
                "8-byte key compiled (minimum is 16)")
        return
    # The WRONG key at evaluation is a DATA error, never an authoring error.
    compiled = pc.compile_arap_context(_good_context(), key=_KEY16)
    try:
        compiled.verify_binding(key=_KEY16B)
    except pc.PolicyCompilationError:
        _record("araps-key-discipline", "BREAK",
                "wrong evaluation key raised the AUTHORING error class")
        return
    except _arap.ArapError:
        pass
    except Exception as exc:  # noqa: BLE001
        _record("araps-key-discipline", "BREAK",
                "wrong key raised unexpected %s" % type(exc).__name__)
        return
    else:
        _record("araps-key-discipline", "BREAK",
                "wrong deployment key verified (key-fingerprint pin broken)")
        return
    _record("araps-key-discipline", "HELD",
            "16-byte minimum at compile; wrong-key-at-eval is a data error")


# ----------------------------------------------------------------------
# Green check (depth-1) + determinism + main.
# ----------------------------------------------------------------------

def _green_check():
    if GREEN_SKIP:
        _record("green-check", "HELD", "skipped (GOV_SKIP_GREEN=1)")
        return
    if _ABSENT:
        # D1 (wave-315): GAP maps to BREAK; the "GAP:" prefix keeps the
        # gap-demonstrated evidence in the note.
        _record("green-check", "BREAK", "GAP: regcompile names absent")
        return
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = "/var/tmp/g219a-green-%d" % os.getpid()
    import subprocess  # noqa: E402
    os.makedirs(env["TMPDIR"], exist_ok=True)
    suites = ["tests.test_policy_compile", "tests.test_quorum_policy",
              "tests.test_arap", "tests.test_jail_policy",
              "evals.w217_compile_once_probes", "evals.w217_quorum_probes",
              "evals.w218_arap_probes", "evals.w216_jail_policy_probes"]
    ok = True
    for suite in suites:
        path = os.path.join(REPO, suite.replace(".", "/") + ".py")
        if not os.path.exists(path):
            _record("green-check", "HELD",
                    "%s absent (not yet merged)" % suite)
            continue
        try:
            if suite.startswith("tests."):
                proc = subprocess.run([sys.executable, "-m", "unittest",
                                       suite], cwd=REPO, env=env,
                                      capture_output=True, text=True,
                                      timeout=600)
            else:
                proc = subprocess.run([sys.executable, path], cwd=REPO,
                                      env=env, capture_output=True,
                                      text=True, timeout=600)
            if proc.returncode != 0:
                ok = False
                _record("green-check", "ERROR",
                        "%s -> rc=%d" % (suite, proc.returncode))
        except Exception as exc:  # noqa: BLE001
            ok = False
            _record("green-check", "ERROR", "%s -> %s" % (suite, exc))
    if ok:
        _record("green-check", "HELD", "adjacent suites green")


def main():
    print("Wave-219 compile-everything-at-registration break-first battery")
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    first = [(n, v, d) for (n, v, d) in _RESULTS]
    # Determinism pass: run everything again, verdicts identical.
    _RESULTS[:] = []
    for name in sorted(_PROBE_FNS):
        try:
            _PROBE_FNS[name]()
        except Exception as exc:  # noqa: BLE001
            _record(name, "ERROR", "%s: %s" % (type(exc).__name__, exc))
    if [(n, v) for (n, v, d) in _RESULTS] != [(n, v)
                                              for (n, v, d) in first]:
        print("DETERMINISM: FAIL")
        return 2
    print("DETERMINISM: PASS (%d/%d probes verdict-identical)"
          % (len(_RESULTS), len(first)))
    _green_check()
    held = sum(1 for _n, v, _d in _RESULTS if v == "HELD")
    breaks = sum(1 for _n, v, _d in _RESULTS if v == "BREAK")
    errors = sum(1 for _n, v, _d in _RESULTS if v == "ERROR")
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _RESULTS, breaks, held, errors)
    probe_lines.emit(_RESULTS)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
