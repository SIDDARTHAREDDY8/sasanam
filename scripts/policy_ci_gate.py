#!/usr/bin/env python3
"""Policy-change CI gate: fail-closed runner (wave-346 lane 3).

STEAL (mechanism only) from Archestra's CI-gated policy testing:
a policy change must pass the evidence tests that pin its affected
decision signals BEFORE it lands. ``gov.policy_gate`` does the static
half (impact analysis + battery selection); this script does the
running half: it executes the selected ``evals/`` batteries with
green checks ENABLED and fails closed when any of them breaks.

Usage (git mode -- how CI calls it):
  python3 scripts/policy_ci_gate.py --repo PATH --base REF [--head REF]

Usage (file mode -- manual / red-team use):
  python3 scripts/policy_ci_gate.py --repo PATH \\
      --policy-old OLD.yaml --policy-new NEW.yaml

In git mode the changed-file list comes from ``git diff --name-only``;
old contents come from ``git show <base>:<path>`` and new contents
from the worktree (or ``--head``). In file mode a single
policies/*.yaml pair is analyzed (path is taken from --policy-new's
basename under policies/).

Exit codes (CI-checkable):
  0 -- PASS: a policy surface changed and every selected battery held,
       or no policy surface changed (noted loudly, not silently).
  1 -- FAIL: a selected battery broke/errored/timed out, its summary
       was unparseable, or an affected signal has no pinning battery.
  2 -- gate malfunction (bad args, unreadable repo, git failure,
       analyzer refusal): fail closed, blocks landing.

Each battery runs in the canonical venv python with a fresh unique
TMPDIR under /var/tmp, GOV_DEPLOYMENT_MODE=staging, and green checks
ON (never GOV_SKIP_GREEN=1 -- the skip masks exactly the maintenance
misses this gate exists to catch; wave-320 lesson).
"""

import argparse
import os
import re
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import policy_gate as _pg  # noqa: E402

# Canonical verdict-summary shapes live in gov.policy_gate (single
# source); the runner only interprets them.
_SUMMARY_PATTERNS = _pg.SUMMARY_PATTERNS


DEFAULT_TIMEOUT = 1800


def _parse_summary(output):
    """Return (held, break, err) from the LAST summary line, or None."""
    found = None
    for rx, order in _SUMMARY_PATTERNS:
        for m in rx.finditer(output):
            nums = [int(m.group(i + 1)) for i in range(3)]
            found = (nums[order[0]], nums[order[1]], nums[order[2]])
    return found


def run_battery(repo_root, battery, *, python, timeout, extra_env=None,
                tag="gate"):
    """Run one evals battery. Returns a result dict (never raises)."""
    result = {"battery": battery, "passed": False, "rc": None,
              "held": None, "break": None, "error": None, "note": "",
              "duration_s": 0.0}
    if not re.fullmatch(r"[A-Za-z0-9_\-]+\.py", battery):
        result["note"] = "rejected: not a plain evals battery filename"
        return result
    script = os.path.join(repo_root, "evals", battery)
    if not os.path.isfile(script):
        result["note"] = "rejected: not found under evals/"
        return result
    tmp = "/var/tmp/%s-%s-%d-%d" % (
        tag, battery.replace(".py", ""), os.getpid(),
        int(time.time() * 1000) % 100000)
    try:
        os.makedirs(tmp, exist_ok=True)
    except OSError as e:
        result["note"] = "TMPDIR creation failed: %s" % e
        return result
    env = dict(os.environ)
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    env["TMPDIR"] = tmp
    env.pop("GOV_SKIP_GREEN", None)  # green checks ON, always
    if extra_env:
        env.update(extra_env)
    start = time.time()
    try:
        r = subprocess.run(
            [python, script], capture_output=True, text=True, env=env,
            timeout=timeout, cwd=repo_root)
    except subprocess.TimeoutExpired:
        result["note"] = "TIMEOUT after %ds" % timeout
        result["duration_s"] = round(time.time() - start, 1)
        return result
    except Exception as e:  # noqa: BLE001 - fail closed, keep the cause
        result["note"] = "runner exception: %s: %s" % (type(e).__name__, e)
        result["duration_s"] = round(time.time() - start, 1)
        return result
    result["duration_s"] = round(time.time() - start, 1)
    result["rc"] = r.returncode
    out = (r.stdout or "") + "\n" + (r.stderr or "")
    parsed = _parse_summary(out)
    if parsed is None:
        tail = out.strip().replace("\n", " | ")[-200:]
        result["note"] = ("unparseable verdict summary (fail closed); "
                          "rc=%d tail=%s" % (r.returncode, tail))
        return result
    held, brk, err = parsed
    result["held"], result["break"], result["error"] = held, brk, err
    if r.returncode == 0 and brk == 0 and err == 0:
        result["passed"] = True
    else:
        result["note"] = "rc=%d held=%d break=%d error=%d" % (
            r.returncode, held, brk, err)
    return result


def _impact_is_empty(imp):
    surface = imp["surface"]
    if surface == "policy-yaml":
        return not (imp["added"] or imp["removed"] or imp["modified"]
                    or imp["sections_changed"])
    return not imp.get("changed", False)


def analyze_changes(changes):
    """changes: list of (path, old_text, new_text) -> (surfaces, impacts).

    Raises _pg.PolicyGateError on any malformed input (fail closed).
    """
    surfaces = _pg.changed_surfaces([p for p, _o, _n in changes])
    impacts = []
    for path, old_text, new_text in changes:
        surface = _pg.classify_path(path)
        if surface == "policy-yaml":
            impacts.append(_pg.policy_yaml_impact(old_text, new_text))
        elif surface == "observe-lifecycle":
            impacts.append(_pg.observe_module_impact(old_text, new_text))
        elif surface == "pin-registry":
            impacts.append(_pg.pin_registry_impact(old_text, new_text))
    return surfaces, impacts


def gate_policy_texts(repo_root, changes, *, python=None, timeout=DEFAULT_TIMEOUT,
                      only=None, extra_env=None):
    """Full gate over explicit (path, old_text, new_text) triples.

    ``only`` restricts the run to named batteries -- targeted /
    red-team use only; CI must not filter. ``extra_env`` is merged
    into each battery's environment (test hooks only).

    Returns a report dict with ``verdict`` PASS/FAIL. Never raises for
    gate-relevant failures; raises _pg.PolicyGateError only for
    malformed gate inputs (the CLI converts that to exit 2).
    """
    report = {"verdict": "FAIL", "reason": "", "surfaces": [],
              "impacts": [], "batteries": [], "results": [], "notes": []}
    surfaces, impacts = analyze_changes(changes)
    report["surfaces"] = surfaces
    report["impacts"] = impacts
    if not surfaces or all(_impact_is_empty(i) for i in impacts):
        report["verdict"] = "PASS"
        report["reason"] = "no policy surfaces changed"
        return report
    index = _pg.build_battery_index(repo_root)
    sel = _pg.select_batteries(impacts, index)
    report["notes"] = sel["notes"]
    if sel["unpinned"]:
        report["reason"] = ("policy-gate-no-pinning-battery: affected "
                            "signal(s) with no pinning battery: %s "
                            "(add an evidence test before landing)"
                            % ", ".join(sel["unpinned"]))
        return report
    batteries = sel["batteries"]
    if only:
        batteries = [b for b in batteries if b in set(only)]
        report["notes"].append(
            "TARGETED RUN: --only-battery filter active (%d/%d selected); "
            "this is not a full gate verdict" % (len(batteries),
                                                 len(sel["batteries"])))
    report["batteries"] = batteries
    if not batteries:
        report["reason"] = ("no runnable batteries selected for a "
                            "non-empty policy impact")
        return report
    python = python or os.path.expanduser("~/workspace/.gov-venv/bin/python")
    failures = []
    for battery in batteries:
        res = run_battery(repo_root, battery, python=python, timeout=timeout,
                          extra_env=extra_env)
        report["results"].append(res)
        if not res["passed"]:
            failures.append(battery)
    if failures:
        report["reason"] = "battery failure(s): %s" % ", ".join(failures)
        return report
    report["verdict"] = "PASS"
    report["reason"] = "%d/%d selected batteries held" % (
        len(batteries), len(batteries))
    return report


# --------------------------------------------------------------------------
# git plumbing (CLI only)
# --------------------------------------------------------------------------

def _git(repo, *args):
    try:
        r = subprocess.run(
            ["git", "-C", repo] + list(args), capture_output=True, text=True,
            timeout=120)
    except Exception as e:  # noqa: BLE001
        raise _pg.PolicyGateError("policy-gate: git failed: %s" % e)
    if r.returncode != 0:
        raise _pg.PolicyGateError("policy-gate: git %s failed: %s"
                                  % (" ".join(args), r.stderr.strip()[:200]))
    return r.stdout


def _git_changes(repo, base, head):
    if head:
        names = _git(repo, "diff", "--name-only", "%s...%s" % (base, head))
        show_new = lambda p: _git(repo, "show", "%s:%s" % (head, p))  # noqa: E731
    else:
        names = _git(repo, "diff", "--name-only", base)
        show_new = lambda p: open(os.path.join(repo, p),  # noqa: E731
                                 encoding="utf-8", errors="replace").read()
    changes = []
    for path in sorted(set(names.split())):
        if not _pg.classify_path(path):
            continue
        try:
            old_text = _git(repo, "show", "%s:%s" % (base, path))
        except _pg.PolicyGateError:
            old_text = "policies: []\n"  # new file: old side is empty
        try:
            new_text = show_new(path)
        except (OSError, _pg.PolicyGateError, UnicodeDecodeError):
            new_text = "policies: []\n"  # deleted file: new side is empty
        changes.append((path, old_text, new_text))
    return changes


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Policy-change CI gate: fail closed when a policy "
                    "change breaks its pinning evidence tests.")
    ap.add_argument("--repo", required=True,
                    help="repo root the batteries run in")
    ap.add_argument("--base", help="git base ref (git mode)")
    ap.add_argument("--head", default=None,
                    help="git head ref (default: worktree)")
    ap.add_argument("--policy-old", help="old policy YAML (file mode)")
    ap.add_argument("--policy-new", help="new policy YAML (file mode)")
    ap.add_argument("--only-battery", action="append", default=None,
                    dest="only_battery",
                    help="run only these batteries (repeatable). Targeted / "
                         "red-team use: CI must NOT filter -- the gate's "
                         "fail-closed promise covers the full selection.")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help="per-battery timeout seconds")
    ap.add_argument("--python", default=None,
                    help="interpreter for batteries "
                         "(default: ~/workspace/.gov-venv/bin/python)")
    args = ap.parse_args(argv)

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(os.path.join(repo, "evals")):
        print("policy-gate: not a repo root: %s" % repo, file=sys.stderr)
        return 2
    try:
        if args.policy_old or args.policy_new:
            if not (args.policy_old and args.policy_new):
                print("policy-gate: --policy-old and --policy-new go together",
                      file=sys.stderr)
                return 2
            old_text = open(args.policy_old, encoding="utf-8",
                            errors="replace").read()
            new_text = open(args.policy_new, encoding="utf-8",
                            errors="replace").read()
            name = os.path.basename(args.policy_new)
            changes = [("policies/" + name, old_text, new_text)]
        elif args.base:
            changes = _git_changes(repo, args.base, args.head)
        else:
            print("policy-gate: need --base (git mode) or "
                  "--policy-old/--policy-new (file mode)", file=sys.stderr)
            return 2
        report = gate_policy_texts(
            repo, changes, python=args.python, timeout=args.timeout,
            only=args.only_battery)
    except _pg.PolicyGateError as e:
        print("policy-gate MALFUNCTION: %s" % e, file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 - fail closed
        print("policy-gate MALFUNCTION: %s: %s" % (type(e).__name__, e),
              file=sys.stderr)
        return 2

    print("policy-gate verdict: %s" % report["verdict"])
    print("reason: %s" % report["reason"])
    if report["surfaces"]:
        print("surfaces: %s" % ", ".join(report["surfaces"]))
    for note in report["notes"]:
        print("note: %s" % note)
    for res in report["results"]:
        status = "HELD" if res["passed"] else "BREAK"
        detail = res["note"] or ("held=%s" % res["held"])
        print("  %-42s %s %s (%.1fs)" % (
            res["battery"], status, detail, res["duration_s"]))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
