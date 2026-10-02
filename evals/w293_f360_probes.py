"""Wave-293 closure battery for F360 (Lane 1): verify_enveloped_ledger
uncoded parse escapes must refuse via OfflineBundleError.

Base: wave-292 merge commit 36176e57508aa24c23159e3e6ff44d842b74ed5a
(verified via git rev-parse HEAD after clone; ls-remote agrees).

F360 (LOW): gov/offline_bundle.py::verify_enveloped_ledger -- the
auditor-facing seam for verifying an offline evidence bundle (the
"sell evidence" path) -- leaked four uncoded stdlib parse exceptions
instead of the module's fail-closed OfflineBundleError:
  (a) corrupt ENVELOPE_PUBKEY.hex -> raw ValueError from bytes.fromhex;
  (b) corrupt manifest.enveloped.json -> raw json.JSONDecodeError;
  (c) corrupt ledger.jsonl line -> raw json.JSONDecodeError;
  (d) corrupt manifest.json -> raw json.JSONDecodeError.
The module wraps the analogous ledger.enveloped.jsonl parse
(except ValueError -> OfflineBundleError), so these four were
inconsistent uncoded escapes (F351/F344/F342/F354 class).

Close-when: (1) all four parse sites refuse via OfflineBundleError
(no raw ValueError/JSONDecodeError escapes); (2) the four probes flip
to HELD; (3) adjacent batteries stay green.

Expected: base 4 BREAK / 4+ HELD / 0 ERROR; fixed 0 BREAK / 9+ HELD /
0 ERROR. Deterministic under staging and env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g293-f360 && TMPDIR=/var/tmp/g293-f360 \\
    ~/workspace/.gov-venv/bin/python evals/w293_f360_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g293-f360b \\
    ~/workspace/.gov-venv/bin/python evals/w293_f360_probes.py
"""

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-292 merge: pin 1715 -> 1723 (+4 revocation-* +4 delegation-*).
TAXONOMY_PIN = 1723

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    silent pass."""
    before = len(_results)
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "unexpected exception: %s" % (e,))
        return
    if len(_results) == before:
        _record(pid, "ERROR", "probe recorded nothing")


def p_taxonomy_pin():
    src = open(os.path.join(REPO, "gov", "decision_codes.py"),
               encoding="utf-8").read()
    lits = re.findall(r'''['"]code['"]\s*:\s*['"]([^'"]+)['"]''', src)
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "raw literals %d, expected %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1723/1723/0 sorted")


# ---------------------------------------------------------------------------
# F360 probes: corrupt files must refuse via OfflineBundleError
# ---------------------------------------------------------------------------

def _bundle_skeleton(corrupt_target=None, corrupt_body=""):
    from gov import ed25519
    seed = secrets.token_bytes(32)
    pub = ed25519.publickey(seed)
    d = tempfile.mkdtemp(prefix="w293-ob-")
    files = {
        "ledger.enveloped.jsonl": "",
        "ENVELOPE_PUBKEY.hex": pub.hex(),
        "ledger.jsonl": "",
        "manifest.enveloped.json": "{}",
        "manifest.json": "{}",
    }
    if corrupt_target:
        files[corrupt_target] = corrupt_body
    for name, body in files.items():
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    return d, seed, pub


def _ob_probe(pid, corrupt_target, corrupt_body, sealed_manifest=None):
    from gov import offline_bundle as ob
    from gov import evidence_envelope as ee
    d, seed, pub = _bundle_skeleton(corrupt_target, corrupt_body)
    if sealed_manifest is not None:
        env = ee.seal_manifest(sealed_manifest, seed)
        with open(os.path.join(d, "manifest.enveloped.json"), "w",
                  encoding="utf-8") as fh:
            fh.write(json.dumps(env))
        with open(os.path.join(d, "manifest.json"), "w",
                  encoding="utf-8") as fh:
            fh.write(json.dumps(sealed_manifest))
        if corrupt_target == "manifest.json":
            with open(os.path.join(d, "manifest.json"), "w",
                      encoding="utf-8") as fh:
                fh.write(corrupt_body)
    try:
        ob.verify_enveloped_ledger(d)
    except ob.OfflineBundleError:
        return _record(pid, "HELD",
                       "corrupt %s refused via OfflineBundleError" %
                       corrupt_target)
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK",
                       "corrupt %s escapes raw %s (code=%r): %s" %
                       (corrupt_target, type(e).__name__,
                        getattr(e, "code", None), str(e)[:70]))
    _record(pid, "BREAK", "corrupt %s VERIFIED?!" % corrupt_target)


def p_ob_pubkey_hex_uncoded():
    _ob_probe("ob-pubkey-hex-uncoded", "ENVELOPE_PUBKEY.hex", "zz-not-hex")


def p_ob_manifest_enveloped_uncoded():
    _ob_probe("ob-manifest-enveloped-uncoded", "manifest.enveloped.json",
              "{not json")


def p_ob_ledger_line_uncoded():
    _ob_probe("ob-ledger-line-uncoded", "ledger.jsonl", "{bad line}\n")


def p_ob_manifest_json_uncoded():
    _ob_probe("ob-manifest-json-uncoded", "manifest.json", "[1,2,",
              sealed_manifest={"bundle": "w293"})


def p_ob_valid_bundle_verifies():
    # Positive control: a well-formed bundle verifies True, so the
    # corrupt-file probes above are non-vacuous (they reach the parse
    # sites rather than dying on an earlier check).
    from gov import offline_bundle as ob
    from gov import evidence_envelope as ee
    d, seed, pub = _bundle_skeleton()
    manifest = {"bundle": "w293-control"}
    env = ee.seal_manifest(manifest, seed)
    with open(os.path.join(d, "manifest.enveloped.json"), "w",
              encoding="utf-8") as fh:
        fh.write(json.dumps(env))
    with open(os.path.join(d, "manifest.json"), "w",
              encoding="utf-8") as fh:
        fh.write(json.dumps(manifest))
    try:
        ok = ob.verify_enveloped_ledger(d)
    except Exception as e:  # noqa: BLE001
        return _record("ob-valid-bundle-verifies", "ERROR",
                       "control bundle failed: %r" % (e,))
    if ok is True:
        _record("ob-valid-bundle-verifies", "HELD",
                "well-formed bundle verifies True (probes non-vacuous)")
    else:
        _record("ob-valid-bundle-verifies", "ERROR",
                "control bundle returned %r" % (ok,))


def p_ob_enveloped_line_wrapped():
    # Adjacent hold: the ledger.enveloped.jsonl parse site was ALREADY
    # wrapped (module's own except ValueError -> OfflineBundleError);
    # a corrupt enveloped line must already refuse coded on the base.
    from gov import offline_bundle as ob
    d, seed, pub = _bundle_skeleton()
    with open(os.path.join(d, "ledger.enveloped.jsonl"), "w",
              encoding="utf-8") as fh:
        fh.write("{not json\n")
    try:
        ob.verify_enveloped_ledger(d)
    except ob.OfflineBundleError:
        return _record("ob-enveloped-line-wrapped", "HELD",
                       "corrupt ledger.enveloped.jsonl refuses coded "
                       "(already wrapped)")
    except Exception as e:  # noqa: BLE001
        return _record("ob-enveloped-line-wrapped", "BREAK",
                       "escapes raw %s" % type(e).__name__)
    _record("ob-enveloped-line-wrapped", "BREAK",
            "corrupt ledger.enveloped.jsonl VERIFIED?!")


def p_ob_missing_pubkey_coded():
    # Adjacent hold: missing ENVELOPE_PUBKEY.hex refuses coded on base.
    from gov import offline_bundle as ob
    d, seed, pub = _bundle_skeleton()
    os.remove(os.path.join(d, "ENVELOPE_PUBKEY.hex"))
    try:
        ob.verify_enveloped_ledger(d)
    except ob.OfflineBundleError:
        return _record("ob-missing-pubkey-coded", "HELD",
                       "missing ENVELOPE_PUBKEY.hex refuses coded")
    except Exception as e:  # noqa: BLE001
        return _record("ob-missing-pubkey-coded", "BREAK",
                       "escapes raw %s" % type(e).__name__)
    _record("ob-missing-pubkey-coded", "BREAK",
            "missing pubkey VERIFIED?!")


# ---------------------------------------------------------------------------
# Depth-1 green checks (subprocess; honor GOV_SKIP_GREEN)
# ---------------------------------------------------------------------------

def _run_battery(rel, expected_breaks, label):
    path = os.path.join(REPO, rel)
    d = tempfile.mkdtemp(prefix="w293-repin-")
    try:
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=900,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("repin-" + label, "ERROR", "subprocess: %r" % (e,))
        return
    out = proc.stdout + proc.stderr
    ms = re.findall(r"(\d+)\s+BREAK", out)
    nbreak = int(ms[-1]) if ms else -1
    if nbreak == expected_breaks:
        _record("repin-" + label, "HELD",
                "%s: %d BREAK as expected" % (rel, nbreak))
    else:
        _record("repin-" + label, "BREAK",
                "%s: %d BREAK, expected %d"
                % (rel, nbreak, expected_breaks))


def _green_checks():
    if SKIP_GREEN:
        return
    # w292_redteam's F360 probes (ob-*-uncoded, expected-open on the
    # wave-292 base) now flip to HELD on this fixed tree: merge-time
    # re-pin per the wave-281 precedent.
    _run_battery("evals/w292_redteam_probes.py", 0, "w292-redteam")
    _run_battery("evals/w238_bundle_verify_probes.py", 0, "w238-bundle")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    # F360 probes (4 expected BREAK on the base, 0 after the fix)
    _safe("ob-pubkey-hex-uncoded", p_ob_pubkey_hex_uncoded)
    _safe("ob-manifest-enveloped-uncoded", p_ob_manifest_enveloped_uncoded)
    _safe("ob-ledger-line-uncoded", p_ob_ledger_line_uncoded)
    _safe("ob-manifest-json-uncoded", p_ob_manifest_json_uncoded)
    # Controls / adjacent holds
    _safe("ob-valid-bundle-verifies", p_ob_valid_bundle_verifies)
    _safe("ob-enveloped-line-wrapped", p_ob_enveloped_line_wrapped)
    _safe("ob-missing-pubkey-coded", p_ob_missing_pubkey_coded)
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    for pid, verdict, note in _results:
        print("  [%s] %s: %s" % (verdict, pid, note))
    print("w293_f360: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))


if __name__ == "__main__":
    main()
