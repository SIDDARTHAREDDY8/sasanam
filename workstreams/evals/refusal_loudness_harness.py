"""Wave-62 Lane 1 break-first harness: refusal loudness.

Question: the wave-61 guard refuses via SandboxError-to-caller. If the
caller swallows the exception and proceeds anyway, which refusal
channels survive?

Each case runs the swallowing caller in a FRESH SUBPROCESS (honest
stderr capture — in-process redirection would not prove what a real
deployment sees). The parent asserts per-case.

Run:  TMPDIR=/tmp/gov-run python3 workstreams/evals/refusal_loudness_harness.py
Exit 0 = every channel behaved as designed; nonzero = a channel died.
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CHILD = r'''
import os, sys
sys.path.insert(0, {root!r})
mode = sys.argv[1]
receipt_dir = sys.argv[2] if len(sys.argv) > 2 else ""
os.environ["GOV_SANDBOX_SECCOMP_LOG"] = "1"  # staging-tier request...
from gov.sandbox import Sandbox, SandboxError  # noqa: E402
# ...in default deployment_mode="production" -> the guard must refuse.
kw = {}
if receipt_dir:
    kw["refusal_receipt_dir"] = receipt_dir
if mode == "kwarg_wins":
    kw["refusal_receipt_dir"] = sys.argv[3]
sb = Sandbox(**kw)
try:
    sb.run(["/bin/true"])
    print("CHILD: no refusal (unexpected)")
except SandboxError as e:
    print("CHILD: swallowed SandboxError, proceeding anyway")
    if mode == "retry_staging":
        # Legitimate recovery: explicit staging declaration, retry.
        sb2 = Sandbox(deployment_mode="staging", **kw)
        r = sb2.run(["/bin/true"])
        print("CHILD: staging retry ok=%s" % r.ok)
'''.replace("{root!r}", repr(ROOT))

CASES = []


def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


def _child(mode, receipt_dir="", extra_env=None, stderr=subprocess.PIPE,
           extra_arg=""):
    env = dict(os.environ)
    env["GOV_SANDBOX_SECCOMP_LOG"] = "1"
    for k in ("GOV_SANDBOX_REFUSAL_DIR",):
        env.pop(k, None)
    if extra_env:
        env.update(extra_env)
    argv = [sys.executable, "-c", CHILD, mode]
    if receipt_dir or extra_arg:
        argv.append(receipt_dir)
    if extra_arg:
        argv.append(extra_arg)
    return subprocess.run(argv, stdout=subprocess.PIPE, text=True, env=env,
                          stderr=stderr)


@case("swallow_stderr_captured")
def c1():
    """Naive swallower, deployment captures stderr: the stderr record
    must survive the swallow."""
    p = _child("x")
    assert "proceeding anyway" in p.stdout, p.stdout
    assert "GOV-SANDBOX REFUSAL [seccomp-log-tier-guard]" in p.stderr, \
        "stderr record missing:\n%r" % p.stderr
    assert "GOV_SANDBOX_SECCOMP_LOG=1" in p.stderr
    return "stderr record survived the swallow"


@case("swallow_stderr_devnull_receipt")
def c2():
    """Swallower that ALSO drops stderr (stderr->DEVNULL): the structured
    receipt is the surviving channel."""
    d = tempfile.mkdtemp(prefix="refusal-sink-")
    with open(os.devnull, "w") as dn:
        p = subprocess.run(
            [sys.executable, "-c", CHILD, "x", d],
            stdout=subprocess.PIPE, text=True,
            env={**os.environ, "GOV_SANDBOX_SECCOMP_LOG": "1"},
            stderr=dn)
    assert "proceeding anyway" in p.stdout, p.stdout
    assert p.stderr in (None, ""), \
        "stderr should be empty (DEVNULL): %r" % p.stderr
    rec = os.path.join(d, "refusals.jsonl")
    assert os.path.exists(rec), "no receipt written"
    line = open(rec, encoding="utf-8").read().strip()
    obj = json.loads(line)
    assert obj["kind"] == "seccomp-log-tier-guard", obj
    assert obj["deployment_mode"] == "production", obj
    assert "GOV_SANDBOX_SECCOMP_LOG=1" in obj["message"], obj
    assert "ts" in obj and "pid" in obj, obj
    return "receipt survived stderr suppression: %s" % rec


@case("no_sink_by_default")
def c3():
    """No receipt sink configured: stderr still fires; nothing is
    written anywhere."""
    cwd = tempfile.mkdtemp(prefix="refusal-cwd-")
    p = subprocess.run(
        [sys.executable, "-c", CHILD, "x"], capture_output=True, text=True,
        cwd=cwd, env={**os.environ, "GOV_SANDBOX_SECCOMP_LOG": "1"})
    assert "GOV-SANDBOX REFUSAL [seccomp-log-tier-guard]" in p.stderr
    leftovers = os.listdir(cwd)
    assert leftovers == [], "unexpected files written: %r" % leftovers
    return "stderr fired, no sink -> no files, no crash"


@case("broken_sink_still_refuses")
def c4():
    """Receipt sink path exists as a FILE (makedirs fails): the refusal
    itself must still raise — fail-safe, never masked."""
    d = tempfile.mkdtemp(prefix="refusal-broken-")
    f = os.path.join(d, "not-a-dir")
    open(f, "w").write("x")
    p = _child("x", receipt_dir=f)
    assert "no refusal (unexpected)" not in p.stdout, \
        "refusal was masked by sink failure: %r" % p.stdout
    assert "swallowed SandboxError" in p.stdout, \
        "expected the refusal to still raise: %r" % p.stdout
    # The child prints "no refusal" only if run() returned; a raised
    # SandboxError that escaped the try would crash the child instead.
    # Either way the swallower did NOT proceed: assert via stderr record.
    assert "GOV-SANDBOX REFUSAL [seccomp-log-tier-guard]" in p.stderr, \
        p.stderr
    return "broken sink did not mask the refusal"


@case("kwarg_wins_over_env")
def c5():
    """Explicit kwarg beats GOV_SANDBOX_REFUSAL_DIR env."""
    da = tempfile.mkdtemp(prefix="refusal-a-")
    db = tempfile.mkdtemp(prefix="refusal-b-")
    p = _child("kwarg_wins", receipt_dir=db,
               extra_env={"GOV_SANDBOX_REFUSAL_DIR": da},
               extra_arg=db)
    assert "GOV-SANDBOX REFUSAL [seccomp-log-tier-guard]" in p.stderr
    assert os.path.exists(os.path.join(db, "refusals.jsonl")), \
        "receipt not in kwarg dir"
    assert not os.path.exists(os.path.join(da, "refusals.jsonl")), \
        "receipt leaked into env dir"
    return "kwarg receipt dir won over env"


@case("uncaught_still_kills_process")
def c6():
    """No try/except at all: baseline loudness — the process dies with
    a traceback on stderr (unchanged by wave-62)."""
    code = ("import sys; sys.path.insert(0, %r); "
            "import os; os.environ['GOV_SANDBOX_SECCOMP_LOG']='1'; "
            "from gov.sandbox import Sandbox; Sandbox().run(['/bin/true'])"
            % ROOT)
    p = subprocess.run([sys.executable, "-c", code], capture_output=True,
                       text=True)
    assert p.returncode != 0, "uncaught refusal should kill the process"
    assert "SandboxError" in p.stderr, p.stderr[-500:]
    assert "GOV-SANDBOX REFUSAL [seccomp-log-tier-guard]" in p.stderr, \
        "stderr record should precede the traceback"
    return "uncaught refusal: exit=%d, traceback + record on stderr" \
        % p.returncode


@case("legitimate_recovery_unbroken")
def c7():
    """NOT fail-deadly: after swallowing, an explicit staging retry
    proceeds normally — the refusal poisons nothing."""
    d = tempfile.mkdtemp(prefix="refusal-retry-")
    p = _child("retry_staging", receipt_dir=d)
    assert "proceeding anyway" in p.stdout, p.stdout
    assert "staging retry ok=True" in p.stdout, p.stdout
    assert "GOV-SANDBOX REFUSAL [seccomp-log-tier-guard]" in p.stderr
    return "catch-and-remediate flow unbroken (no fail-deadly poisoning)"


def main():
    failures = []
    for name, fn in CASES:
        try:
            detail = fn()
            print("PASS %s: %s" % (name, detail))
        except Exception as e:  # noqa: BLE001 -- harness aggregates
            failures.append("%s: %s: %s" % (name, type(e).__name__, e))
            print("FAIL %s: %s: %s" % (name, type(e).__name__, e))
    if failures:
        print("\n%d/%d cases failed" % (len(failures), len(CASES)))
        sys.exit(1)
    print("\nall %d loudness cases passed" % len(CASES))


if __name__ == "__main__":
    main()
