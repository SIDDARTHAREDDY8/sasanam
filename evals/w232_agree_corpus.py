#!/usr/bin/env python3
"""Wave-232 lane B: conformance corpus for the five-valued agreement table.

STEAL of the *testing discipline* only (probityai/agent-evidence-vectors
per the wave-231 prospectus: a pinned conformance corpus with
must-accept / must-reject / derivability rows and a corpus digest);
every row here is generated from OUR module's spec
(gov/reconcile_agreement.py docstring table) — nothing copied from
their corpus.

What this is: evals/artifacts/w232_agree_corpus.json is a pinned,
machine-readable conformance corpus (60 rows). This battery replays
every row and checks:

* must-accept (40): the input axes produce the exact verdict from the
  docstring table AND the exact pinned table_digest, through four
  derivation paths per cell (direct table, sealed-capsule replay,
  verify recompute, canonical-JSON round trip) plus not-exercised
  evidence-bound rows. The verdict literals are the independent
  source of truth (docstring); the digest pins are frozen from the
  known-good module as regression pins.
* must-reject (13): malformed axes, forged verdict records,
  surgically edited digests, foreign capsules, and authority misuse
  refuse with the exact refusal code.
* derive (7): two or more independent code paths recompute the same
  pinned digest — including deriving a digest from the sealed bytes
  of a different row with the same axes (honest cross-row
  verification).

Pin semantics (honest): each row carries a ``row_hash`` — SHA-256
over the row's literals (corpus integrity). The module's digest
computation for the row is pinned in ``expect.table_digest``
(must-accept and derive rows); the battery recomputes it three ways
(module call, sealed-byte replay, independent derivation written
from the docstring) and refuses ``corpus-pin-mismatch`` on ANY
mismatch — row_hash, corpus_digest, or module digest. This is the
F75-friendly regression net: spec drift in the table or the digest
formula breaks a pin rather than passing quietly.
On a pristine base (module file absent) every row is GAP with the
closed refusal ``corpus-target-absent`` — the documented genuine-red
run (see the lane REPORT for the red-run log). A module file that
exists but fails to import is reported ERROR, never GAP: broken
imports must not masquerade as pristine red.

Battery-local refusal strings (``corpus-target-absent``,
``corpus-pin-mismatch``) are emitted by this battery only; they are
not product decision codes. Merge coordinator: the closed taxonomy
scanner should decide whether they need mapping; do not widen
gov/decision_codes.py for them without that adjudication.

Seams under test:
* gov/reconcile_agreement.agreement_table / not_exercised_verdict /
  verify_table_verdict / seal_table_verdict / table_digest_of /
  deny_authority_use — public functions only.

Verdicts: HELD / GAP / BREAK / ERROR. Any BREAK is a regression or a
genuine product defect.

$0 spend. No network. stdlib only. No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g232b
  TMPDIR=/var/tmp/g232b ~/workspace/.gov-venv/bin/python evals/w232_agree_corpus.py
Standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g232b-u \\
      ~/workspace/.gov-venv/bin/python evals/w232_agree_corpus.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import hashlib
import json
import subprocess
import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

CORPUS_PATH = os.path.join(REPO, "evals", "artifacts",
                           "w232_agree_corpus.json")

try:
    from gov import reconcile_agreement as _ra
    from gov import action_capsule as _ac
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False
    _ra = None
    _ac = None

_MODULE_FILE = os.path.join(REPO, "gov", "reconcile_agreement.py")
_MODULE_ABSENT = not os.path.exists(_MODULE_FILE)
HAVE_MODULE = _IMPORT_OK and not _MODULE_ABSENT


# ----------------------------------------------------------------------
# Independent digest derivation (re-derived from the module docstring:
# domain "reconcile-agreement/v1" over canonical JSON). This is the
# second opinion the module's own digest is checked against, so a
# formula change on either side shows up as a mismatch.
# ----------------------------------------------------------------------

def _battery_table_digest(verdict, decision_reported, effect_observed):
    body = {
        "domain": "reconcile-agreement/v1",
        "verdict": verdict,
        "decision_reported": decision_reported,
        "effect_observed": effect_observed,
    }
    return hashlib.sha256(
        _ac.canonical_json_bytes(body)).hexdigest()


def _battery_not_exercised_digest(decision_digest, superseding_digest,
                                  reason):
    body = {
        "domain": "reconcile-agreement/v1",
        "verdict": "not-exercised",
        "decision_digest": decision_digest,
        "superseding_digest": superseding_digest,
        "reason": reason,
    }
    return hashlib.sha256(
        _ac.canonical_json_bytes(body)).hexdigest()


def _recompute_row_hash(row):
    """Recompute a row's integrity hash from its literals.

    Honest naming: this is the corpus-integrity pin, not the
    module's digest pin. The module's digest computation for the
    row is pinned separately in ``expect.table_digest`` (accept
    and derive rows) and is recomputed by the battery three ways
    (module call, sealed-byte replay, independent derivation).
    """
    payload = {k: row[k] for k in
               ("id", "kind", "module", "module_version",
                "input", "expect")}
    return hashlib.sha256(
        _ac.canonical_json_bytes(payload)).hexdigest()


def _canon_local(obj):
    """Stdlib canonical JSON (JCS-style) for the pristine path, where
    gov/action_capsule is unavailable. Mirrors
    gov/action_capsule.canonical_json_bytes exactly."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ----------------------------------------------------------------------
# Corpus loading + integrity.
# ----------------------------------------------------------------------

def _load_corpus():
    with open(CORPUS_PATH, "r", encoding="utf-8") as fh:
        corpus = json.load(fh)
    rows = corpus["rows"]
    recomputed = hashlib.sha256(
        _ac.canonical_json_bytes(rows)).hexdigest()
    if recomputed != corpus["corpus_digest"]:
        return None, "corpus-pin-mismatch: corpus_digest does not " \
            "recompute from rows (corrupt or drifted corpus file)"
    return corpus, None


def _load_corpus_local():
    """Corpus load + integrity for the pristine path (no _ac)."""
    try:
        with open(CORPUS_PATH, "r", encoding="utf-8") as fh:
            corpus = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        return None, "corpus unreadable: %r" % exc
    recomputed = hashlib.sha256(
        _canon_local(corpus["rows"])).hexdigest()
    if recomputed != corpus["corpus_digest"]:
        return None, "corpus-pin-mismatch: corpus_digest does not " \
            "recompute from rows (corrupt or drifted corpus file)"
    return corpus, None


def _build_specials():
    """Dynamic fixtures for must-reject rows (built from the module,
    never frozen in the corpus — they are attack shapes, not pins)."""
    forge_base = _ra.agreement_table("permitted", "absent")  # disagree
    forged = dict(forge_base)
    forged["verdict"] = "agree"  # the table verdict for these axes is
    # "disagree"; verify_table_verdict must refuse the forgery.
    edited = dict(forge_base)
    head = edited["table_digest"][0]
    edited["table_digest"] = ("0" if head != "0" else "1") \
        + edited["table_digest"][1:]
    foreign = _ac.seal_capsule({
        "attempt": {"action": "something-else", "x": 1},
        "effect": {"status": "admitted", "evidence": "none"},
    })
    verdict = _ra.agreement_table("denied", "absent")
    return {"FORGE": forged, "EDIT": edited, "FOREIGN": foreign,
            "VERDICT": verdict}


def _resolve_special(value, specials):
    if isinstance(value, str) and value.startswith("__special__:"):
        return specials[value[len("__special__:"):]]
    return value


# ----------------------------------------------------------------------
# Row runners. Each returns (verdict, detail).
# ----------------------------------------------------------------------

def _run_must_accept(row, specials):
    inp = row["input"]
    expect = row["expect"]
    fn = inp["fn"]
    try:
        if fn == "table":
            rec = _ra.agreement_table(inp["decision_reported"],
                                      inp["effect_observed"])
            verdict, digest = rec["verdict"], rec["table_digest"]
            indep = _battery_table_digest(verdict,
                                          inp["decision_reported"],
                                          inp["effect_observed"])
        elif fn == "sealed":
            cap = _ra.seal_table_verdict(inp["decision_reported"],
                                         inp["effect_observed"])
            body = _ac.verify_capsule(cap)
            verdict = body["attempt"]["verdict"]
            digest = _ra.table_digest_of(cap)
            indep = _battery_table_digest(verdict,
                                          inp["decision_reported"],
                                          inp["effect_observed"])
        elif fn == "verify":
            rec = _ra.agreement_table(inp["decision_reported"],
                                      inp["effect_observed"])
            digest = _ra.verify_table_verdict(rec)
            verdict = rec["verdict"]
            indep = _battery_table_digest(verdict,
                                          inp["decision_reported"],
                                          inp["effect_observed"])
        elif fn == "roundtrip":
            rec = _ra.agreement_table(inp["decision_reported"],
                                      inp["effect_observed"])
            rec2 = json.loads(_ac.canonical_json_bytes(rec).decode(
                "utf-8"))
            digest = _ra.verify_table_verdict(rec2)
            verdict = rec2["verdict"]
            indep = _battery_table_digest(verdict,
                                          inp["decision_reported"],
                                          inp["effect_observed"])
        elif fn == "not_exercised":
            rec = _ra.not_exercised_verdict(
                inp["decision_digest"], inp["superseding_digest"],
                inp["reason"])
            digest = _ra.verify_table_verdict(rec)
            verdict = rec["verdict"]
            indep = _battery_not_exercised_digest(
                inp["decision_digest"], inp["superseding_digest"],
                inp["reason"])
        else:
            return "ERROR", "unknown must-accept fn %r" % fn
    except Exception as exc:  # noqa: BLE001
        tb = traceback.format_exc(limit=2).strip()
        tail = tb.splitlines()[-1] if tb else ""
        return "BREAK", "must-accept row raised: %r (%s)" % (exc, tail)
    if verdict != expect["verdict"]:
        return "BREAK", "verdict %r != spec %r" % (
            verdict, expect["verdict"])
    if digest != expect["table_digest"]:
        return "BREAK", "corpus-pin-mismatch: recomputed module " \
            "digest != pinned digest (spec drift)"
    if indep != expect["table_digest"]:
        return "BREAK", "corpus-pin-mismatch: independent derivation " \
            "!= pinned digest (digest formula drift)"
    return "HELD", "verdict+digest pinned; independent derivation agrees"


def _run_must_reject(row, specials):
    inp = row["input"]
    expect = row["expect"]
    fn = inp["fn"]
    kwargs = {k: _resolve_special(v, specials)
              for k, v in inp.items() if k != "fn"}
    try:
        if fn == "table":
            _ra.agreement_table(kwargs["decision_reported"],
                                kwargs["effect_observed"])
        elif fn == "not_exercised":
            _ra.not_exercised_verdict(kwargs["decision_digest"],
                                      kwargs["superseding_digest"],
                                      kwargs["reason"])
        elif fn == "verify":
            _ra.verify_table_verdict(kwargs["record"])
        elif fn == "seal":
            _ra.seal_table_verdict(kwargs["decision_reported"],
                                   kwargs["effect_observed"])
        elif fn == "table_digest_of":
            _ra.table_digest_of(kwargs["capsule"])
        elif fn == "deny_authority":
            _ra.deny_authority_use(kwargs["artifact"])
        else:
            return "ERROR", "unknown must-reject fn %r" % fn
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code == expect["refusal"]:
            return "HELD", "refused %s" % code
        return "BREAK", "refused with %r, expected %r" % (
            code, expect["refusal"])
    return "BREAK", "no refusal raised; expected %r" % expect["refusal"]


def _run_derive(row, corpus):
    inp = row["input"]
    expect = row["expect"]
    try:
        if "cell" in inp:
            cell = inp["cell"]
            d, e = cell["decision_reported"], cell["effect_observed"]
            p1 = _ra.agreement_table(d, e)["table_digest"]
            cap = _ra.seal_table_verdict(d, e)
            p2 = _ra.table_digest_of(cap)
            p3 = _ra.verify_table_verdict(
                _ra.agreement_table(d, e))
            if not (p1 == p2 == p3 == expect["digest"]):
                return "BREAK", "corpus-pin-mismatch: derive paths " \
                    "disagree with pinned digest: %s" % (
                    repr((p1 == expect["digest"], p2 == expect["digest"],
                          p3 == expect["digest"])))
        elif "not_exercised" in inp:
            ne = inp["not_exercised"]
            d = _ra.verify_table_verdict(_ra.not_exercised_verdict(
                ne["decision_digest"], ne["superseding_digest"],
                ne["reason"]))
            if d != expect["digest"]:
                return "BREAK", "corpus-pin-mismatch: not-exercised " \
                    "derive != pinned digest"
        elif "cross_row" in inp:
            # Honest cross-row verification: the digest is recomputed
            # from the SEALED BYTES of the referenced row's axes, and
            # compared against that row's pinned digest.
            ref = [r for r in corpus["rows"]
                   if r["id"] == inp["cross_row"]]
            if not ref:
                return "ERROR", "cross_row %r not found" % inp[
                    "cross_row"]
            ref = ref[0]
            cell = ref["input"]
            cap = _ra.seal_table_verdict(cell["decision_reported"],
                                         cell["effect_observed"])
            d = _ra.table_digest_of(cap)
            if d != expect["digest"]:
                return "BREAK", "corpus-pin-mismatch: sealed-byte " \
                    "digest != pinned digest"
            if d != ref["expect"]["table_digest"]:
                return "BREAK", "corpus-pin-mismatch: sealed-byte " \
                    "digest != referenced row's pinned digest"
        elif "roundtrip_cell" in inp:
            cell = inp["roundtrip_cell"]
            rec = _ra.agreement_table(cell["decision_reported"],
                                      cell["effect_observed"])
            rec2 = json.loads(
                _ac.canonical_json_bytes(rec).decode("utf-8"))
            d = _ra.verify_table_verdict(rec2)
            if d != expect["digest"]:
                return "BREAK", "corpus-pin-mismatch: canonical " \
                    "round-trip digest != pinned digest"
        else:
            return "ERROR", "unknown derive shape"
    except Exception as exc:  # noqa: BLE001
        return "BREAK", "derive raised: %r" % exc
    return "HELD", "independent paths converge on pinned digest"


def _run_once():
    if _MODULE_ABSENT:
        # Pristine base: the module is genuinely absent. Corpus
        # integrity is still checked (stdlib-only) so a corrupt
        # corpus cannot hide behind the red.
        corpus, err = _load_corpus_local()
        if err is not None:
            rows = corpus["rows"] if corpus else []
            return [(r.get("id", "?"), "BREAK", err) for r in rows] or [
                ("corpus-integrity", "BREAK", err)]
        return [(r["id"], "GAP",
                 "corpus-target-absent: gov/reconcile_agreement.py "
                 "absent (pristine red)") for r in corpus["rows"]]
    if not _IMPORT_OK:
        # The module file exists but does not import: genuine
        # breakage, never reported as pristine-red.
        corpus, _ = _load_corpus_raw()
        rows = corpus["rows"] if corpus else []
        return [(r.get("id", "?"), "ERROR",
                 "gov/reconcile_agreement.py present but unimportable "
                 "(not pristine red)") for r in rows] or [
            ("corpus", "ERROR",
             "gov/reconcile_agreement.py present but unimportable")]
    corpus, err = _load_corpus()
    if err is not None:
        return [("corpus-integrity", "BREAK", err)]
    specials = _build_specials()
    results = []
    for row in corpus["rows"]:
        t0 = time.time()
        if _recompute_row_hash(row) != row["row_hash"]:
            results.append((row["id"], "BREAK",
                            "corpus-pin-mismatch: row_hash does not "
                            "recompute from row literals (corrupt row)"))
            continue
        try:
            if row["kind"] == "must-accept":
                verdict, detail = _run_must_accept(row, specials)
            elif row["kind"] == "must-reject":
                verdict, detail = _run_must_reject(row, specials)
            elif row["kind"] == "derive":
                verdict, detail = _run_derive(row, corpus)
            else:
                verdict, detail = ("ERROR",
                                   "unknown row kind %r" % row["kind"])
        except Exception as exc:  # noqa: BLE001
            verdict = "ERROR"
            detail = "%r %s" % (exc, traceback.format_exc(limit=2))
        dt = time.time() - t0
        results.append((row["id"], verdict, "%s (%.2fs)" % (detail, dt)))
    return results


def _load_corpus_raw():
    """Load without integrity check (for the pristine-red path)."""
    try:
        with open(CORPUS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def _run_green_checks():
    # Depth-1 green checks (AGENTS.md): children run with
    # GOV_SKIP_GREEN=1 so the nesting never compounds.
    if GREEN_SKIP:
        return [("green-check", "SKIP",
                 "GOV_SKIP_GREEN=1 (depth-1 nesting convention)")]
    notes = []
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    # Adjacent unit suite for the corpus target.
    proc = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_reconcile_agreement"],
        env=env, cwd=REPO, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=600)
    out = proc.stdout.decode("utf-8", "replace")
    notes.append(("tests/test_reconcile_agreement.py",
                  "PASS" if proc.returncode == 0 else "FAIL",
                  "adjacent unit suite green"
                  if proc.returncode == 0 else out[-400:]))
    # decision_effect_agreement untouched: its battery still 8/8 x2.
    proc = subprocess.run(
        [sys.executable, "evals/w230_agree_probes.py"],
        env=env, cwd=REPO, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=600)
    out = proc.stdout.decode("utf-8", "replace")
    ok = proc.returncode == 0 and "8 HELD" in out
    notes.append(("evals/w230_agree_probes.py",
                  "PASS" if ok else "FAIL",
                  "decision_effect_agreement still 8/8 x2"
                  if ok else out[-400:]))
    return notes


def main():
    first = _run_once()
    second = _run_once()
    det_ok = [v for _, v, _d in first] == [v for _, v, _d in second]
    green = _run_green_checks()
    held = sum(1 for _, v, _d in first if v == "HELD")
    gap = sum(1 for _, v, _d in first if v == "GAP")
    brk = sum(1 for _, v, _d in first if v == "BREAK")
    err = sum(1 for _, v, _d in first if v == "ERROR")
    print("w232 agree conformance corpus: %d HELD / %d GAP / %d BREAK / "
          "%d ERROR of %d rows; determinism %s"
          % (held, gap, brk, err, len(first),
             "PASS" if det_ok else "FAIL"))
    for name, verdict, detail in first:
        print("  [%s] %s %s" % (verdict, name, detail))
    for name, status, detail in green:
        print("  [%s] %s %s" % (status, name, detail))
    bad = [n for n, v, _d in first if v in ("BREAK", "ERROR")]
    sys.exit(1 if bad or not det_ok else 0)


if __name__ == "__main__":
    main()
