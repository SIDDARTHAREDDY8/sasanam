#!/usr/bin/env python3
"""Summary-form migration driver (canonical consolidated copy, wave-312 lane B).

Provenance: wave-309 lane F original; wave-310 lane D summary_counts
name-prefix regex; wave-311 lane B spaced-prefix regex.
Wave-312 lane B canonical consolidation (no behavioral change).

For each candidate battery:
  1. Baseline run (staging + clean env), save stdout + rc.
  2. codemod --migrate on the file. If unchanged -> SKIP (record reason).
  3. After runs (staging + clean env).
  4. Compare: rc identical; stdout identical AFTER removing probe lines
     (old indented or new canonical) and coherence-WARNING lines.
  5. Parse check: every canonical probe line in AFTER parses via
     probe_lines.parse_line; line count == summary total (advisory).
Usage: python3 migrate_driver.py <battery_basename> [more...]
Outputs a per-battery verdict line. Safe to re-run: already-migrated
batteries are refused by the codemod and reported SKIP.
"""
import os
import re
import subprocess
import sys

REPO = os.path.expanduser("~/workspace/teams/wave312-summform5/sasanam")
VENV_PY = os.path.expanduser("~/workspace/.gov-venv/bin/python")
CODEMOD = os.path.expanduser("~/workspace/teams/wave312-summform5/codemod_summary_form.py")
TMPBASE = "/var/tmp/g312-mig"

PROBE_LINE_RE = re.compile(r"^\s*\[(BREAK|HELD|ERROR|SKIP)\] ")
# S3 columnar: "pid                  VERDICT  note" (no brackets).
PROBE_LINE_S3_RE = re.compile(r"^[A-Za-z0-9_.\-]+\s+(BREAK|HELD|ERROR|SKIP)\s+")
COH_WARN_RE = re.compile(r"^coherence-WARNING:")


def run_battery(name, env_mode, tag):
    tmpdir = os.path.join(TMPBASE, f"{name}-{tag}")
    os.makedirs(tmpdir, exist_ok=True)
    env = dict(os.environ)
    env["TMPDIR"] = tmpdir
    if env_mode == "staging":
        env["GOV_DEPLOYMENT_MODE"] = "staging"
    else:
        env.pop("GOV_DEPLOYMENT_MODE", None)
    p = subprocess.run(
        [VENV_PY, f"evals/{name}.py"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=900,
    )
    return p.returncode, p.stdout, p.stderr


def strip_probe_lines(text):
    kept = []
    for line in text.splitlines():
        if PROBE_LINE_RE.match(line):
            continue
        if PROBE_LINE_S3_RE.match(line):
            continue
        if COH_WARN_RE.match(line):
            continue
        kept.append(line)
    return "\n".join(kept)


def canonical_probe_lines(text):
    sys.path.insert(0, os.path.join(REPO, "evals"))
    import probe_lines
    lines = [l for l in text.splitlines() if l.startswith("[")]
    bad = []
    for l in lines:
        try:
            probe_lines.parse_line(l)
        except Exception as e:  # noqa: BLE001 - collecting failures
            bad.append((l, str(e)))
    return lines, bad


def summary_counts(text):
    # is the summary (start-of-line), so embedded summaries inside green-check
    # probe notes (e.g. "[0 BREAK / 16 HELD / 0 ERROR]", no colon) are not
    # matched. The summary may have a battery-name prefix ("w285_redteam: 0
    # BREAK / ..." or spaced prefixes like "w303 authority-lifecycle probes:
    # 0 BREAK / ...") or be bare ("0 BREAK / ...").
    m = re.search(r"^(?:[\w\-. ]+:\s*)?(\d+)\s+BREAK\s*/\s*(\d+)\s+HELD\s*/\s*(\d+)\s+ERROR\s*$",
                  text, re.M)
    if m:
        return tuple(int(x) for x in m.groups())
    # Wave-312: HELD-first summary order. Returns (break, held, err,
    # *extra) so the linecount check sums every reported probe bucket
    # (some HBE summaries append GAP/SKIP buckets or a trailing
    # parenthetical). The prefix class includes "/" for names like
    # "w275 F288/F289 closure battery:".
    m = re.search(r"^(?:[\w\-. /]+:\s*)?(\d+)\s+HELD\s*/\s*(\d+)\s+BREAK\s*/\s*(\d+)\s+ERROR"
                  r"(?:\s*/\s*(\d+)\s+GAP\s*/\s*(\d+)\s+SKIP)?(?:\s*\(.*\))?\s*$",
                  text, re.M)
    if m:
        h, b, e = int(m.group(1)), int(m.group(2)), int(m.group(3))
        extra = [int(x) for x in m.groups()[3:] if x is not None]
        return (b, h, e, *extra)
    return None


def main(names):
    for name in names:
        path = os.path.join(REPO, f"evals/{name}.py")
        try:
            rc_s0, out_s0, _ = run_battery(name, "staging", "before-staging")
            rc_c0, out_c0, _ = run_battery(name, "clean", "before-clean")
        except subprocess.TimeoutExpired:
            print(f"{name}: SKIP baseline-timeout", flush=True)
            continue
        before_src = open(path).read()
        cp = subprocess.run([sys.executable, CODEMOD, "--migrate", path],
                            capture_output=True, text=True)
        after_src = open(path).read()
        if after_src == before_src:
            print(f"{name}: SKIP codemod-refused ({cp.stdout.strip() or cp.stderr.strip()})", flush=True)
            continue
        try:
            rc_s1, out_s1, _ = run_battery(name, "staging", "after-staging")
            rc_c1, out_c1, _ = run_battery(name, "clean", "after-clean")
        except subprocess.TimeoutExpired:
            print(f"{name}: FAIL after-timeout (reverting)", flush=True)
            open(path, "w").write(before_src)
            continue
        problems = []
        if rc_s0 != rc_s1:
            problems.append(f"staging-rc {rc_s0}->{rc_s1}")
        if rc_c0 != rc_c1:
            problems.append(f"clean-rc {rc_c0}->{rc_c1}")
        if strip_probe_lines(out_s0) != strip_probe_lines(out_s1):
            problems.append("staging-nonprobetext-differs")
        if strip_probe_lines(out_c0) != strip_probe_lines(out_c1):
            problems.append("clean-nonprobetext-differs")
        lines, bad = canonical_probe_lines(out_s1)
        if bad:
            problems.append(f"unparseable-lines={len(bad)}")
        counts = summary_counts(out_s1)
        if counts is not None:
            total = sum(counts)
            if len(lines) != total:
                problems.append(f"linecount {len(lines)} != summary {total}")
        else:
            problems.append("no-canonical-summary-found")
        if problems:
            print(f"{name}: FAIL {'; '.join(problems)} (reverting)", flush=True)
            open(path, "w").write(before_src)
        else:
            print(f"{name}: MIGRATED lines={len(lines)} summary={counts} rc={rc_s1}", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
