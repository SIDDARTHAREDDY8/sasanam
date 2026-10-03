"""Shared depth-1 green-check helper implementing the fail-closed
green-check contract (see evals/GREEN_CHECK_CONTRACT.md).

Wave-305: the wave-303 merge dropped the entire module header of
evals/w302_redteam_probes.py (NameError on import), yet the inner green
checks of adjacent batteries passed it vacuously -- the allowlist form
counts "[BREAK]" lines, and a traceback emits none, so a broken child
read as "0 BREAK (all expected) / rest held". This module makes a broken
dependency battery fail the check loudly, never pass as "0 BREAKs".

Stdlib only; no gov imports. Batteries import this as::

    sys.path.insert(0, os.path.join(REPO, "evals"))
    import green_check
"""

import os
import re
import subprocess
import sys
import tempfile

SUMMARY_RE = re.compile(r"(\d+) BREAK / (\d+) HELD / (\d+) ERROR")
TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\)")
BREAK_ID_RE = re.compile(r"\[BREAK\] ([A-Za-z0-9_.\-]+)")

_SKIP_NOTE = "green check skipped (GOV_SKIP_GREEN=1)"


def _child_argv(repo, battery):
    path = battery if os.path.isabs(battery) else os.path.join(repo, battery)
    return [sys.executable, path], path


def check_battery(record, label, battery, *, repo,
                  expect_break_ids=(), expected_summary=None, timeout=600,
                  extra_env=None):
    """Depth-1 green check against a dependency battery.

    record: callable(pid, verdict, note) -- the battery's own recorder.
    label: the situation id recorded (e.g. "green-w302-redteam").
    battery: child battery path, relative to repo (e.g.
        "evals/w302_redteam_probes.py") or absolute.
    repo: absolute repo root; the child runs with cwd=repo.
    expect_break_ids: BREAK ids the child may report (expected-open
        findings). Any other BREAK id records BREAK.
    expected_summary: if given, the child's pinned verbatim summary line
        must appear in the output (the exact-summary form); deviation
        records BREAK.

    Contract: the child MUST emit a parseable summary line (or, for
    unittest-style batteries, a "Ran N tests" + OK verdict) and MUST NOT
    raise; otherwise the check records ERROR (loud, distinct from HELD).
    Additionally fail-closed (wave-307): a summary claiming zero probes
    ran (vacuous child) records ERROR, and a summary reporting any probe
    ERRORs records ERROR -- a degraded dependency is not green.
    GOV_SKIP_GREEN=1 records a skipped note without spawning the child.
    """
    if os.environ.get("GOV_SKIP_GREEN"):
        record(label, "HELD", _SKIP_NOTE)
        return
    argv, path = _child_argv(repo, battery)
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    if extra_env:
        env.update(extra_env)
    env["TMPDIR"] = tempfile.mkdtemp(prefix="green-check-")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, env=env, cwd=repo)
        out = (proc.stdout or "") + (proc.stderr or "")
    except Exception as e:  # noqa: BLE001
        record(label, "ERROR", "green check crashed: %r" % (e,))
        return
    # Fail closed on a broken child: a traceback means the battery
    # raised before running its probes -- a broken dependency, never
    # "0 BREAKs".
    if TRACEBACK_RE.search(out):
        record(label, "ERROR",
               "green-check contract failure: %s raised before emitting "
               "a summary (traceback in output, rc=%d); broken dependency, "
               "not a pass" % (os.path.basename(path), proc.returncode))
        return
    summary = SUMMARY_RE.search(out)
    if summary is not None:
        # Fail closed on a vacuous child: a summary that claims zero
        # probes ran is not evidence of anything -- an emptied probe
        # list (bad merge, early return) must not read as green.
        # (Wave-307: the w302 incident was a crash; the subtler sibling
        # is a child that prints "0 BREAK / 0 HELD / 0 ERROR" without
        # running anything.)
        n_break, n_held, n_err = (int(summary.group(1)),
                                  int(summary.group(2)),
                                  int(summary.group(3)))
        if n_break + n_held + n_err == 0:
            record(label, "ERROR",
                   "green-check contract failure: %s emitted a summary "
                   "claiming zero probes ran (vacuous child); broken "
                   "dependency, not a pass" % os.path.basename(path))
            return
        # Fail closed on a degraded child: probe ERRORs mean the child's
        # probes did not verify cleanly (crashed probes, not a crashed
        # process). A dependency that errored is not green, even with
        # zero BREAKs.
        if n_err > 0:
            record(label, "ERROR",
                   "green-check contract failure: %s reported %d probe "
                   "ERROR(s) [%s]; dependency did not verify cleanly"
                   % (os.path.basename(path), n_err, summary.group(0)))
            return
    if expected_summary is not None:
        if expected_summary in out:
            record(label, "HELD",
                   "%s: expected summary observed" % os.path.basename(path))
        else:
            got = summary.group(0) if summary else "no parseable summary"
            record(label, "BREAK",
                   "%s: expected summary %r not observed; got %s"
                   % (os.path.basename(path), expected_summary, got))
        return
    if summary is None:
        # unittest-style batteries report "Ran N tests" + an OK line
        # instead of the N BREAK / M HELD / K ERROR summary.
        mu = re.search(r"Ran (\d+) tests?", out)
        # A "Ran 0 tests" + OK child ran nothing: vacuous, not green.
        if (mu and int(mu.group(1)) > 0 and proc.returncode == 0
                and re.search(r"^OK", out, re.M)):
            record(label, "HELD",
                   "%s green: %s unittest tests OK"
                   % (os.path.basename(path), mu.group(1)))
            return
        record(label, "ERROR",
               "green-check contract failure: no parseable summary line "
               "'N BREAK / M HELD / K ERROR' in %s (rc=%d); broken "
               "dependency, not a pass"
               % (os.path.basename(path), proc.returncode))
        return
    breaks = BREAK_ID_RE.findall(out)
    unexpected = [b for b in breaks if b not in expect_break_ids]
    if unexpected:
        record(label, "BREAK",
               "%s: unexpected BREAKs %r" % (os.path.basename(path),
                                             unexpected))
    else:
        record(label, "HELD",
               "%s: %d BREAK (all expected) / rest held [%s]"
               % (os.path.basename(path), len(breaks), summary.group(0)))


def check_battery_result(label, battery, *, repo, **kwargs):
    """check_battery variant returning (verdict, note) instead of taking
    a record callback. For batteries whose green checks return tuples."""
    captured = []
    check_battery(lambda pid, verdict, note: captured.append((verdict, note)),
                  label, battery, repo=repo, **kwargs)
    return captured[0]


def check_unittest(record, label, target, *, repo, timeout=600,
                   extra_env=None):
    """Depth-1 green check against an adjacent unittest suite.

    target: "tests.test_x" module form or "tests/test_x.py" file form.
    Requires exit 0 and an OK verdict line; a missing suite *file* is a
    CHECK FAILURE (ERROR), not a skip (a missing *module* surfaces as a
    loud BREAK via non-zero exit). GOV_SKIP_GREEN=1 records a skipped
    note without spawning.
    """
    if os.environ.get("GOV_SKIP_GREEN"):
        record(label, "HELD", _SKIP_NOTE)
        return
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    if extra_env:
        env.update(extra_env)
    env["TMPDIR"] = tempfile.mkdtemp(prefix="green-check-")
    if target.endswith(".py") or "/" in target:
        fspath = (target if os.path.isabs(target)
                  else os.path.join(repo, target))
        if not os.path.exists(fspath):
            record(label, "ERROR",
                   "green-check contract failure: adjacent suite %s "
                   "absent; broken tree, not a pass" % (target,))
            return
        argv = [sys.executable, fspath]
    else:
        argv = [sys.executable, "-m", "unittest", target]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, env=env, cwd=repo)
        combined = (proc.stdout or "") + (proc.stderr or "")
    except Exception as e:  # noqa: BLE001
        record(label, "ERROR", "green check crashed: %r" % (e,))
        return
    if proc.returncode == 0 and "\nOK" in combined:
        record(label, "HELD", "%s OK" % (label,))
    else:
        tail = (combined.strip().splitlines() or ["no output"])[-1]
        record(label, "BREAK", "%s: %s" % (label, tail))


def check_unittest_result(label, target, *, repo, **kwargs):
    """check_unittest variant returning (verdict, note) instead of taking
    a record callback. For batteries whose green checks return tuples."""
    captured = []
    check_unittest(lambda pid, verdict, note: captured.append((verdict, note)),
                   label, target, repo=repo, **kwargs)
    return captured[0]
