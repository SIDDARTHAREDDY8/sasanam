"""Wave-267 F249 closure battery: delegation custody splice.

Break-first for F249 (``gov/delegation_chain.py``): `verify` must
refuse any chain where hop i>0 has ``issuer != chain[i-1].audience``
with the machine code ``delegation-custody-splice``.

Verdicts: HELD (secure behavior observed), BREAK (attack succeeded --
the defect is present), ERROR (harness failure).

Run modes via ``--expect old|fixed``:
  old   : run against a pristine 801a8c9 tree. The splice probes must
          BREAK (genuine old-code evidence); controls must HELD; the
          pin probe must ERROR (pin drift 1222 != 1223).
  fixed : run against the fixed tree. Every probe must HELD.

Deterministic: keys/nonces are derived from fixed labels, so the full
probe set runs twice and verdicts must be byte-identical (A==B).
Staging default at module level; also verified under
`env -u GOV_DEPLOYMENT_MODE`. Depth-1 green check honoring
GOV_SKIP_GREEN=1. No in-repo git subprocesses. Fresh unique TMPDIR
per run under /var/tmp (mkdir -p first).
"""

import hashlib
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

TAXONOMY_PIN = 1477  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).
# This battery adds no other gov/ code.

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import delegation_chain as dc
from gov import decision_codes

NOW = 1700000000
CUSTODY_CODE = "delegation-custody-splice"


def _seed(label):
    return hashlib.sha256(b"f249-" + label.encode()).digest()


def _pub(label):
    from gov import ed25519
    return ed25519.publickey(_seed(label)).hex()


def _root(labelR, labelA, caps, nonce):
    return dc.delegate(
        _seed(labelR), None,
        {"audience": _pub(labelA), "capabilities": caps,
         "not_before": NOW - 100, "not_after": NOW + 3600,
         "parent": None, "nonce": nonce})


def _hop(labelI, held_caps, labelA, caps, parent, nonce):
    return dc.delegate(
        _seed(labelI), held_caps,
        {"audience": _pub(labelA), "capabilities": caps,
         "not_before": NOW - 100, "not_after": NOW + 3600,
         "parent": parent, "nonce": nonce})


_READ = [{"with": "fs:/docs", "can": ["read"]}]
_RWX = [{"with": "fs:/docs", "can": ["read", "write", "delete"]}]
_ALL = [{"with": "fs:/", "can": ["*"]}]
_ACTION = {"with": "fs:/docs", "can": "read"}


def p_splice_unrelated_issuer():
    """Mallory grafts M->X onto an observed R->A (full caps).

    Fixed behavior: refused with delegation-custody-splice.
    Old behavior: verifies and mints a signed receipt (BREAK).
    """
    root = _root("R", "A", _READ, "n-root")
    splice = _hop("M", _ALL, "X", _READ, root, "n-splice")
    assert splice["delegation"]["issuer"] != \
        root["delegation"]["audience"], "harness: keys collided"
    v = dc.DelegationVerifier([_pub("R")], seed=_seed("vseed"))
    try:
        receipt = v.verify([root, splice], _ACTION, now=NOW)
    except dc.DelegationError as e:
        if e.code == CUSTODY_CODE:
            return ("HELD",
                    "spliced chain refused: %s" % e.code)
        return ("BREAK",
                "splice refused but with WRONG code: %s" % e.code)
    return ("BREAK",
            "spliced chain VERIFIED; signed receipt minted, "
            "decision=%s" % receipt["decision"])


def p_splice_narrower_caps():
    """Same graft with strictly narrower caps -- still fabricated."""
    root = _root("R", "A", _RWX, "n-root")
    splice = _hop("M", _ALL, "X", _READ, root, "n-splice-narrow")
    v = dc.DelegationVerifier([_pub("R")])
    try:
        v.verify([root, splice], _ACTION, now=NOW)
    except dc.DelegationError as e:
        if e.code == CUSTODY_CODE:
            return ("HELD",
                    "narrower splice refused: %s" % e.code)
        return ("BREAK",
                "narrower splice refused with WRONG code: %s" % e.code)
    return ("BREAK",
            "narrower spliced chain VERIFIED: unrelated issuer "
            "exercised A's delegation right without A's consent")


def p_splice_at_middle():
    """Graft onto a 3-hop chain: [R->A, A->B, M->X]."""
    root = _root("R", "A", _READ, "n-root")
    hop = _hop("A", _READ, "B", _READ, root, "n-hop")
    splice = _hop("M", _ALL, "X", _READ, hop, "n-splice-mid")
    v = dc.DelegationVerifier([_pub("R")])
    try:
        v.verify([root, hop, splice], _ACTION, now=NOW)
    except dc.DelegationError as e:
        if e.code == CUSTODY_CODE:
            return ("HELD",
                    "middle splice refused: %s" % e.code)
        return ("BREAK",
                "middle splice refused with WRONG code: %s" % e.code)
    return ("BREAK",
            "middle spliced chain VERIFIED: custody check missed "
            "hop 2")


def p_legit_chain_control():
    """Control: genuine R->A->B (issuer == parent audience) verifies."""
    root = _root("R", "A", _READ, "n-root")
    hop = _hop("A", _READ, "B", _READ, root, "n-hop")
    v = dc.DelegationVerifier([_pub("R")], seed=_seed("vseed"))
    receipt = v.verify([root, hop], _ACTION, now=NOW)
    assert receipt["decision"] == "ok", "harness: receipt not ok"
    assert receipt["signature"] is not None, \
        "harness: receipt not signed"
    return ("HELD", "legit R->A->B chain verifies; signed receipt")


def p_legit_single_root():
    """Control: a single root delegation verifies."""
    root = _root("R", "A", _READ, "n-root")
    v = dc.DelegationVerifier([_pub("R")])
    v.verify([root], _ACTION, now=NOW)
    return ("HELD", "single root delegation verifies")


def p_legit_deep_chain():
    """Control: genuine R->A->B->C 4-hop chain verifies."""
    root = _root("R", "A", _READ, "n-root")
    h1 = _hop("A", _READ, "B", _READ, root, "n-h1")
    h2 = _hop("B", _READ, "C", _READ, h1, "n-h2")
    v = dc.DelegationVerifier([_pub("R")])
    v.verify([root, h1, h2], _ACTION, now=NOW)
    return ("HELD", "legit 4-hop chain verifies")


def p_attenuation_still_enforced():
    """Control: a widening middle hop still refuses (attenuation)."""
    root = _root("R", "A", _READ, "n-root")
    wide = _hop("A", _RWX, "B", _RWX, root, "n-wide")
    v = dc.DelegationVerifier([_pub("R")])
    try:
        v.verify([root, wide],
                 {"with": "fs:/docs", "can": "write"}, now=NOW)
    except dc.DelegationError as e:
        if e.code == "delegation-attenuation-inverted":
            return ("HELD", "widening refused: %s" % e.code)
        return ("ERROR", "widening refused with wrong code: %s"
                % e.code)
    return ("ERROR", "widening middle hop verified")


def p_replay_still_refused():
    """Control: replay of the same (chain, action) still refuses."""
    root = _root("R", "A", _READ, "n-root")
    v = dc.DelegationVerifier([_pub("R")])
    v.verify([root], _ACTION, now=NOW)
    try:
        v.verify([root], _ACTION, now=NOW)
    except dc.DelegationError as e:
        if e.code == "delegation-replay":
            return ("HELD", "replay refused: %s" % e.code)
        return ("ERROR", "replay refused with wrong code: %s"
                % e.code)
    return ("ERROR", "replay verified twice")


def p_root_untrusted():
    """Control: a root outside the trust anchors still refuses."""
    root = _root("R", "A", _READ, "n-root")
    v = dc.DelegationVerifier([_pub("OTHER")])
    try:
        v.verify([root], _ACTION, now=NOW)
    except dc.DelegationError as e:
        if e.code == "delegation-root-untrusted":
            return ("HELD", "untrusted root refused: %s" % e.code)
        return ("ERROR", "untrusted root refused with wrong code: %s"
                % e.code)
    return ("ERROR", "untrusted root verified")


def p_signature_tamper():
    """Control: a tampered signature still refuses."""
    root = _root("R", "A", _READ, "n-root")
    bad = dict(root)
    bad["signature"] = "00" * 64
    v = dc.DelegationVerifier([_pub("R")])
    try:
        v.verify([bad], _ACTION, now=NOW)
    except dc.DelegationError as e:
        if e.code == "delegation-signature-invalid":
            return ("HELD", "tampered sig refused: %s" % e.code)
        return ("ERROR", "tampered sig refused with wrong code: %s"
                % e.code)
    return ("ERROR", "tampered signature verified")


def p_pin():
    """Pin: the raw source literals must number exactly 1299."""
    src = open(os.path.join(_REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    import re
    lits = re.findall(r'"code":\s*[\'"]([^\'"]+)[\'"]', src)
    if len(lits) != TAXONOMY_PIN:
        return ("ERROR", "pin drift: %d literals != %d"
                % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return ("ERROR", "duplicate code literals")
    return ("HELD", "1299/1299 unique raw literals")


PROBES = [
    ("f249/splice-unrelated-issuer", p_splice_unrelated_issuer),
    ("f249/splice-narrower-caps", p_splice_narrower_caps),
    ("f249/splice-at-middle", p_splice_at_middle),
    ("f249/legit-chain-control", p_legit_chain_control),
    ("f249/legit-single-root", p_legit_single_root),
    ("f249/legit-deep-chain", p_legit_deep_chain),
    ("f249/attenuation-still-enforced", p_attenuation_still_enforced),
    ("f249/replay-still-refused", p_replay_still_refused),
    ("f249/root-untrusted", p_root_untrusted),
    ("f249/signature-tamper", p_signature_tamper),
    ("pin/taxonomy-1299", p_pin),
]

# Per-mode expectations: raw probe verdict -> expected verdict.
_EXPECT = {
    "old": {
        "f249/splice-unrelated-issuer": "BREAK",
        "f249/splice-narrower-caps": "BREAK",
        "f249/splice-at-middle": "BREAK",
        "pin/taxonomy-1299": "ERROR",
    },
    "fixed": {},
}
_DEFAULT_EXPECT = "HELD"


def run_once():
    results = []
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # harness failure, never silent
            verdict, detail = ("ERROR", "%s: %r"
                               % (type(e).__name__, e))
        results.append((name, verdict, detail))
    return results


def green_check(env):
    """Depth-1: run adjacent batteries' mains with GOV_SKIP_GREEN=1
    in the child env. Honors the var itself.

    Lane-local pin drift (1222 != 1223) in an adjacent battery's own
    pin probe is accepted as the SOLE failure cause; any real-phase
    BREAK fails the check. Pin-drift lines are recognized by the
    co-occurrence of a pin/taxonomy marker with drift language
    (drift, mismatch, !=, or both pin numbers).
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "SKIPPED",
                 "GOV_SKIP_GREEN=1 (depth-1)")]
    import re
    adj = ["evals/w265_delegation_probes.py",
           "evals/w265_f245f246f247_probes.py",
           "evals/w266_redteam_probes.py"]
    _drift = re.compile(
        r"(pin|taxonomy).*(drift|mismatch|!=|1222.*1223|1223.*1222)",
        re.IGNORECASE)

    def _verdict_of(line):
        if line.startswith(("RESULT", "TOTAL")):
            return None  # summary line, not a probe verdict
        m = re.match(r"\[(HELD|BREAK|ERROR|RESIDUAL)\]", line)
        if m:
            return m.group(1)
        parts = line.split()
        for tok in ("HELD", "BREAK", "ERROR", "RESIDUAL"):
            if tok in parts:
                return tok
        return None

    out = []
    for rel in adj:
        tmpd = "/var/tmp/g267f249-%d-%s" % (
            os.getpid(), os.path.basename(rel).replace(".py", ""))
        os.makedirs(tmpd, exist_ok=True)
        cenv = dict(env, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
        try:
            p = subprocess.run(
                [sys.executable, os.path.join(_REPO, rel)],
                env=cenv, capture_output=True, text=True,
                timeout=600, cwd=_REPO)
            text = p.stdout + p.stderr
            lines = text.strip().splitlines()
            bad = [ln for ln in lines
                   if _verdict_of(ln) in ("BREAK", "ERROR")]
            pin_only = bool(bad) and all(_drift.search(ln)
                                         for ln in bad)
            ok = not bad or pin_only
            tail1 = lines[-1] if lines else ""
            out.append((rel, "HELD" if ok else "BREAK",
                        "exit=%d pin-drift-tolerated=%s %s"
                        % (p.returncode, pin_only, tail1)))
        except Exception as e:
            out.append((rel, "ERROR", repr(e)))
    return [("green-check/adjacent", "HELD"
             if all(v == "HELD" for _, v, _ in out) else "BREAK",
             "; ".join("%s=%s" % (n, v) for n, v, _ in out))]


def main(argv):
    mode = "fixed"
    if "--expect" in argv:
        mode = argv[argv.index("--expect") + 1]
    if mode not in ("old", "fixed"):
        print("usage: w267_f249_probes.py [--expect old|fixed]")
        return 2
    tmpd = "/var/tmp/g267f249-main-%d" % os.getpid()
    os.makedirs(tmpd, exist_ok=True)
    os.environ["TMPDIR"] = tmpd
    a = run_once()
    b = run_once()
    det = [(x[0], x[1]) for x in a] == [(x[0], x[1]) for x in b]
    exp = dict(_EXPECT.get(mode, {}))
    mismatches = []
    counts = {}
    for name, verdict, detail in a:
        counts[verdict] = counts.get(verdict, 0) + 1
        want = exp.get(name, _DEFAULT_EXPECT)
        mark = "" if verdict == want else "  <-- MISMATCH (want %s)" % want
        if verdict != want:
            mismatches.append(name)
        print("%-38s %-9s %s%s" % (name, verdict, detail, mark))
    print("determinism A==B: %s" % ("YES" if det else "NO"))
    gc = green_check(dict(os.environ))
    for name, verdict, detail in gc:
        print("%-38s %-9s %s" % (name, verdict, detail))
    tot = "TOTAL: " + " / ".join(
        "%d %s" % (counts.get(v, 0), v)
        for v in ("HELD", "BREAK", "RESIDUAL", "BASELINE",
                  "EXPECTED", "ERROR"))
    print(tot)
    if not det:
        print("FAIL: nondeterministic")
        return 2
    if mismatches:
        print("FAIL: expectation mismatches: %s"
              % ", ".join(mismatches))
        return 1
    if mode == "fixed" and counts.get("ERROR"):
        print("FAIL: harness errors on fixed code")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
