"""Wave-288 closure battery: F335 + F336 (LOW, gov/kms_keyset.py pin-key custody).

F335: uncoded exceptions escape the pin-key custody seams -- a stale
<path>.tmp raises raw FileExistsError (bricking generation); _repin /
from_dict on malformed documents raise raw TypeError/KeyError. Every
case must refuse LOUD with a coded keyset-* KeysetError (F327/F331
class).
F336: load_pin_key must refuse LOUD (coded) when the key file is
group/other-readable -- the deployment-held secret's own precondition.

Run:
  mkdir -p /var/tmp/g288-f335 && TMPDIR=/var/tmp/g288-f335 \
    ~/workspace/.gov-venv/bin/python evals/w288_f335_f336_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g288-f335b \
    ~/workspace/.gov-venv/bin/python evals/w288_f335_f336_probes.py
"""

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
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance
# +10 trustvec-*).
TAXONOMY_PIN = 1888  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*)

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "1700/1700/0 sorted")


def _coded_held(pid, fn, expect_break_msg):
    """Run fn(); HELD iff a KeysetError carrying a code escapes."""
    from gov.kms_keyset import KeysetError
    try:
        fn()
    except KeysetError as e:
        if e.code:
            return _record(pid, "HELD", "coded refusal: %s" % (e.code,))
        return _record(pid, "BREAK",
                       "KeysetError without code: %r" % (e,))
    except Exception as e:  # noqa: BLE001
        return _record(pid, "BREAK",
                       "raw %s escapes -- %s" % (type(e).__name__, e))
    return _record(pid, "BREAK", expect_break_msg)


def _fresh_keyset():
    from gov import kms_keyset as kk
    key = secrets.token_bytes(32)
    ks = kk.KmsKeyset.new(template_name="KMS-ENVELOPE/v1",
                          primary_key_id="k", provider_name="fake",
                          pin_key=key)
    return kk, key, ks


# ---------------------------------------------------------------------------
# F335(a): stale <path>.tmp must refuse coded, and name the recovery.
# ---------------------------------------------------------------------------

def p_f335_stale_tmp():
    from gov import kms_keyset as kk
    d = tempfile.mkdtemp(prefix="w288-f335-")
    p = os.path.join(d, "pin.key")
    with open(p + ".tmp", "w", encoding="utf-8") as fh:
        fh.write("stale")
    try:
        kk.generate_pin_key(p)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code is None:
            return _record("f335-stale-tmp", "BREAK",
                           "raw %s escapes generate_pin_key -- expected "
                           "coded keyset-pin-key-invalid" % type(e).__name__)
        msg = str(e).lower()
        if "tmp" not in msg or "remove" not in msg:
            return _record("f335-stale-tmp", "BREAK",
                           "coded refusal %s does not name the recovery "
                           "(stale tmp / manual removal)" % (code,))
        return _record("f335-stale-tmp", "HELD",
                       "coded refusal %s names the recovery" % (code,))
    _record("f335-stale-tmp", "BREAK", "stale tmp silently accepted")


def p_f335_generate_ok():
    from gov import kms_keyset as kk
    d = tempfile.mkdtemp(prefix="w288-f335-")
    p = os.path.join(d, "pin.key")
    try:
        key = kk.generate_pin_key(p)
    except Exception as e:  # noqa: BLE001
        return _record("f335-generate-ok", "BREAK",
                       "clean generate_pin_key refused: %r" % (e,))
    if not os.path.exists(p) or len(key) != 32:
        return _record("f335-generate-ok", "BREAK",
                       "generate did not produce a 32-byte key file")
    _record("f335-generate-ok", "HELD", "clean generation works")


# ---------------------------------------------------------------------------
# F335(b): malformed documents refuse coded at _repin / from_dict.
# ---------------------------------------------------------------------------

def _mutate_and_repin(pid, mutate, note):
    kk, key, ks = _fresh_keyset()
    doc = ks.to_dict()
    mutate(doc)
    _coded_held(pid, lambda: kk.KmsKeyset._repin(doc, pin_key=key),
                note)


def p_f335_repin_nondict_audit():
    _mutate_and_repin(
        "f335-repin-nondict-audit",
        lambda doc: doc["audit_chain"].append(42),
        "non-mapping audit entry silently accepted by _repin")


def p_f335_repin_nodigest_audit():
    _mutate_and_repin(
        "f335-repin-nodigest-audit",
        lambda doc: doc["audit_chain"].append({"event": "x"}),
        "digest-less audit entry silently accepted by _repin")


def p_f335_repin_missing_keys():
    _mutate_and_repin(
        "f335-repin-missing-keys",
        lambda doc: doc.pop("keys"),
        "document missing 'keys' silently accepted by _repin")


def p_f335_fromdict_nodigest_audit():
    kk, key, ks = _fresh_keyset()
    doc = ks.to_dict()
    doc["audit_chain"].append({"event": "x"})
    _coded_held(
        "f335-fromdict-nodigest-audit",
        lambda: kk.KmsKeyset.from_dict(doc, pin_key=key),
        "digest-less audit entry silently accepted by from_dict")


def p_f335_fromdict_nonascii_digest():
    kk, key, ks = _fresh_keyset()
    doc = ks.to_dict()
    doc["keyset_digest"] = "caf\u00e9" * 16  # non-ASCII: raw TypeError pre-fix
    _coded_held(
        "f335-fromdict-nonascii-digest",
        lambda: kk.KmsKeyset.from_dict(doc, pin_key=key),
        "non-ASCII keyset_digest silently accepted by from_dict")


# ---------------------------------------------------------------------------
# F336: permission check on load.
# ---------------------------------------------------------------------------

def _perm_probe(pid, mode):
    from gov import kms_keyset as kk
    d = tempfile.mkdtemp(prefix="w288-f336-")
    p = os.path.join(d, "pin.key")
    kk.generate_pin_key(p)
    os.chmod(p, mode)
    try:
        kk.load_pin_key(p)
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None):
            return _record(pid, "HELD", "refused: %s" % (e.code,))
        return _record(pid, "BREAK",
                       "raw %s escapes load_pin_key" % type(e).__name__)
    if mode & 0o077:
        return _record(pid, "BREAK",
                       "mode %o loaded silently -- no permission check"
                       % (mode,))
    return _record(pid, "HELD", "mode %o loads (0600, no over-refusal)"
                    % (mode,))


def p_f336_perms_644():
    _perm_probe("f336-perms-644", 0o644)


def p_f336_perms_640():
    _perm_probe("f336-perms-640", 0o640)


def p_f336_perms_600_ok():
    _perm_probe("f336-perms-600-ok", 0o600)


# ---------------------------------------------------------------------------
# Depth-1 green checks: wave-284 tink battery (keyset-adjacent) and the
# w287 red-team re-pin probes must stay green / flip to HELD.
# ---------------------------------------------------------------------------

def _green_checks():
    if SKIP_GREEN:
        return
    # (a) adjacent module battery, 0 BREAK expected
    rel = "evals/w284_tink_probes.py"
    d = tempfile.mkdtemp(prefix="w288-green-")
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, rel)],
            capture_output=True, text=True, timeout=600,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("green-tink", "ERROR", "subprocess failed: %r" % (e,))
    else:
        out = proc.stdout + proc.stderr
        m = re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != 0:
            _record("green-tink", "BREAK",
                    "w284_tink: %d BREAK (expected 0)" % nbreak)
        else:
            _record("green-tink", "HELD", "w284_tink: 0 BREAK as expected")
    # (b) the w287 red-team probes must flip to HELD
    rel = "evals/w287_redteam_probes.py"
    d = tempfile.mkdtemp(prefix="w288-repin-")
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, rel)],
            capture_output=True, text=True, timeout=600,
            env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                     GOV_RUN_ROOT=os.path.join(d, "gov-run")))
    except Exception as e:  # noqa: BLE001
        _record("green-redteam", "ERROR", "subprocess failed: %r" % (e,))
        return
    out = proc.stdout + proc.stderr
    for pid in ("f335-pinkey-stale-tmp", "f335-pinkey-malformed-doc",
                "f336-pinkey-perms"):
        m = re.search(r"\[(HELD|BREAK|ERROR)\]\s+" + re.escape(pid)
                      + r"\b", out)
        if m and m.group(1) == "HELD":
            _record("repin-" + pid, "HELD",
                    "w287_redteam probe now HELD as expected")
        else:
            _record("repin-" + pid, "BREAK",
                    "w287_redteam probe %s not HELD" % (pid,))


def main():
    p_taxonomy_pin()
    p_f335_stale_tmp()
    p_f335_generate_ok()
    p_f335_repin_nondict_audit()
    p_f335_repin_nodigest_audit()
    p_f335_repin_missing_keys()
    p_f335_fromdict_nodigest_audit()
    p_f335_fromdict_nonascii_digest()
    p_f336_perms_644()
    p_f336_perms_640()
    p_f336_perms_600_ok()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w288_f335_f336: %d BREAK / %d HELD / %d ERROR"
          % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
