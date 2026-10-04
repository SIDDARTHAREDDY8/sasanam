#!/usr/bin/env python3
"""Wave-234 lane B: NIST IR 8587-style token hygiene for agent credentials.

Re-derived from the W234-8 direction (wave-233 prospectus): agent
credential tokens carry bounded lifetimes (TTL <= 1h at issuance),
explicit audiences, and key-rotation windows; token VALUES are bearer
secrets that must never land in logs -- lines carry
{type, issuer, scope, audience} metadata only.

Seams under test:
* gov/token_hygiene.py -- TokenHygiene.validate_issuance (TTL cap at
  ISSUANCE, explicit audience, key-rotation window); TokenHygiene.present
  (expired refused -- never refreshed; audience mismatch refused);
  token_scrub (defense-in-depth redaction of registered token values);
  TokenRedactor.assert_clean (refuses token-in-log as incident material).
* gov/log.py -- ActionLog.append redacts registered token values from
  the entry BEFORE chain/MAC computation, additively (unconditional
  import, fail-closed).

Attack shapes: mint a 2h token; present an expired token (and retry it);
present at the wrong audience; issue under a 91-day-old high-impact key;
smuggle a registered bearer value into a log event; scan a rendered line
carrying a token value.

Method (diagnosing-bugs): attack shapes at the PUBLIC seams,
deterministic (injectable clocks), minimal, against pushed wave-233 HEAD
55d588664180cbe4657a07c4342df680c28cdc54.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent) is
expected GAP. Any BREAK is a real product defect.

Verification record (2026-09-30):
  genuine-red on base (gov/token_hygiene.py absent): 0 HELD / 8 GAP /
    0 BREAK / 0 ERROR, exit 2
    (transcript: ~/workspace/teams/wave234-tokenhygiene/RED_RUN.log)
  post-implementation: 8/8 HELD x2 -- staging AND
    `env -u GOV_DEPLOYMENT_MODE` clean env, green checks PASS.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins (wave-36 supply-chain probe fails
closed on them; merge enforces add-only by byte-verification).

Run:
  mkdir -p /var/tmp/g234b
  TMPDIR=/var/tmp/g234b ~/workspace/.gov-venv/bin/python evals/w234_tokenhygiene_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import inspect
import json
import sys
import tempfile
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_MODULE = False
_th = None
try:
    from gov import token_hygiene as _th
    HAVE_MODULE = all(hasattr(_th, n) for n in (
        "TokenHygiene", "TokenHygieneError", "TokenRedactor",
        "token_scrub", "register_known_token", "clear_known_tokens",
        "MAX_TTL_SECONDS", "HIGH_IMPACT_KEY_ROTATION_WINDOW_SECONDS"))
except ImportError:
    _th = None

PROBE_NAMES = [
    "tokenhygiene-expired-refused",
    "tokenhygiene-ttl-exceeded",
    "tokenhygiene-audience-missing",
    "tokenhygiene-audience-mismatch",
    "tokenhygiene-key-stale",
    "tokenhygiene-writer-redacts",
    "tokenhygiene-scan-refuses",
    "tokenhygiene-metadata-only",
]

# Fixed reference instant: 2026-09-30T12:00:00Z.
T0 = 1790817600


def _claims(iat, ttl, aud="svc:policy", iss="issuer:1", key_id="k1",
            key_issued_at=None, impact="standard"):
    return {"type": "agent-credential", "iat": iat, "exp": iat + ttl,
            "aud": aud, "iss": iss, "scope": "policy:evaluate",
            "key_id": key_id,
            "key_issued_at": iat if key_issued_at is None else key_issued_at,
            "impact": impact}


def _hold(cond, detail=""):
    return "HELD" if cond else "BREAK\n" + detail


def _probe_expired_refused():
    hyg = _th.TokenHygiene()
    issued = hyg.validate_issuance(_claims(T0, 600), now=T0)
    # Expired at T0+601: refused, and a later retry refuses identically
    # (never refreshed, never tolerated).
    try:
        hyg.present(issued, "svc:policy", now=T0 + 601)
    except _th.TokenHygieneError as exc:
        if exc.code != "token-expired":
            return "BREAK\nwrong code: %r" % (exc.code,)
    else:
        return "BREAK\nexpired token presented without refusal"
    try:
        hyg.present(issued, "svc:policy", now=T0 + 3600)
    except _th.TokenHygieneError as exc:
        return _hold(exc.code == "token-expired",
                     "retry code=%r" % (exc.code,))
    return "BREAK\nretry of expired token presented without refusal"


def _probe_ttl_exceeded():
    hyg = _th.TokenHygiene()
    try:
        hyg.validate_issuance(_claims(T0, 7200), now=T0)
    except _th.TokenHygieneError as exc:
        if exc.code != "token-ttl-exceeded":
            return "BREAK\nwrong code: %r" % (exc.code,)
    else:
        return "BREAK\n2h TTL accepted at issuance"
    # Boundary control: exactly 1h is the cap and must pass.
    try:
        hyg.validate_issuance(_claims(T0, _th.MAX_TTL_SECONDS), now=T0)
    except _th.TokenHygieneError as exc:
        return "BREAK\ncap-exact TTL refused: %r" % (exc.code,)
    return _hold(_th.MAX_TTL_SECONDS == 3600,
                 "MAX_TTL_SECONDS=%r" % (_th.MAX_TTL_SECONDS,))


def _probe_audience_missing():
    hyg = _th.TokenHygiene()
    for bad in (None, ""):
        claims = _claims(T0, 600)
        if bad is None:
            del claims["aud"]
        else:
            claims["aud"] = bad
        try:
            hyg.validate_issuance(claims, now=T0)
        except _th.TokenHygieneError as exc:
            if exc.code != "token-audience-missing":
                return "BREAK\nwrong code for aud=%r: %r" % (bad, exc.code)
        else:
            return "BREAK\naud=%r accepted at issuance" % (bad,)
    return "HELD"


def _probe_audience_mismatch():
    hyg = _th.TokenHygiene()
    issued = hyg.validate_issuance(_claims(T0, 600, aud="svc:policy"), now=T0)
    try:
        hyg.present(issued, "svc:billing", now=T0 + 10)
    except _th.TokenHygieneError as exc:
        return _hold(exc.code == "token-audience-mismatch",
                     "code=%r" % (exc.code,))
    return "BREAK\nwrong-audience presentation accepted"


def _probe_key_stale():
    hyg = _th.TokenHygiene()
    stale_key = T0 - 91 * 86400
    try:
        hyg.validate_issuance(_claims(T0, 600, key_issued_at=stale_key,
                                      impact="high"), now=T0)
    except _th.TokenHygieneError as exc:
        if exc.code != "token-key-stale":
            return "BREAK\nwrong code: %r" % (exc.code,)
    else:
        return "BREAK\n91-day-old high-impact key accepted"
    # Control: standard-impact tokens are not bound by the 90-day
    # high-impact rotation window.
    try:
        hyg.validate_issuance(_claims(T0, 600, key_issued_at=stale_key,
                                      impact="standard"), now=T0)
    except _th.TokenHygieneError as exc:
        return "BREAK\nstandard-impact caught by high-impact window: %r" \
            % (exc.code,)
    return "HELD"


def _probe_writer_redacts():
    from gov.log import ActionLog, verify_chain
    from tests.keyfixture import provision_test_key, scrub_key_env
    secret = "tok-bearer-SECRET-9f3a"
    _th.register_known_token(secret)
    provision_test_key()
    tmp = tempfile.mkdtemp(prefix="w234-tokenhygiene-")
    try:
        log_path = os.path.join(tmp, "audit.log")
        log = ActionLog(log_path)
        log.append({"event": "credential_presented", "agent_id": "a1",
                    "token": secret, "type": "agent-credential"})
        with open(log_path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        if not lines:
            return "ERROR\nno lines written"
        if secret in lines[-1]:
            return "BREAK\ntoken value reached the stored line"
        if "<redacted:token>" not in lines[-1]:
            return "BREAK\nno redaction marker in stored line"
        ok, broken, count = verify_chain(log_path)
        return _hold(ok and count == 1,
                     "chain ok=%r broken=%r count=%r" % (ok, broken, count))
    finally:
        _th.clear_known_tokens()
        scrub_key_env()


def _probe_scan_refuses():
    secret = "tok-bearer-SCAN-77b1"
    _th.register_known_token(secret)
    try:
        redactor = _th.TokenRedactor.from_registry()
        try:
            redactor.assert_clean(
                '{"event":"x","token":"%s"}' % secret)
        except _th.TokenHygieneError as exc:
            return _hold(exc.code == "token-in-log"
                         and "incident" in str(exc).lower(),
                         "code=%r msg=%r"
                         % (exc.code, str(exc)[:100]))
        return "BREAK\nscan accepted a token-bearing line"
    finally:
        _th.clear_known_tokens()


def _probe_metadata_only():
    from gov.log import ActionLog
    from tests.keyfixture import provision_test_key, scrub_key_env
    secret = "tok-bearer-META-c42d"
    _th.register_known_token(secret)
    provision_test_key()
    tmp = tempfile.mkdtemp(prefix="w234-tokenhygiene-meta-")
    try:
        log_path = os.path.join(tmp, "audit.log")
        log = ActionLog(log_path)
        log.append({"event": "credential_presented", "agent_id": "a1",
                    "token": secret, "type": "agent-credential",
                    "issuer": "issuer:1", "scope": "policy:evaluate",
                    "audience": "svc:policy"})
        with open(log_path, "r", encoding="utf-8") as fh:
            line = fh.read().splitlines()[-1]
        body = json.loads(line)
        metadata = {k: body.get(k) for k in
                    ("type", "issuer", "scope", "audience")}
        return _hold(
            secret not in line
            and metadata == {"type": "agent-credential",
                             "issuer": "issuer:1",
                             "scope": "policy:evaluate",
                             "audience": "svc:policy"},
            "metadata=%r" % (metadata,))
    finally:
        _th.clear_known_tokens()
        scrub_key_env()


_PROBES = {
    "tokenhygiene-expired-refused": _probe_expired_refused,
    "tokenhygiene-ttl-exceeded": _probe_ttl_exceeded,
    "tokenhygiene-audience-missing": _probe_audience_missing,
    "tokenhygiene-audience-mismatch": _probe_audience_mismatch,
    "tokenhygiene-key-stale": _probe_key_stale,
    "tokenhygiene-writer-redacts": _probe_writer_redacts,
    "tokenhygiene-scan-refuses": _probe_scan_refuses,
    "tokenhygiene-metadata-only": _probe_metadata_only,
}


def _green_check():
    """Depth-1: adjacent suites run once, never nested."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check: SKIP (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    ok = True
    targets = [
        ["tests/test_token_hygiene.py"],
        ["tests/test_log_integrity.py"],
    ]
    for t in targets:
        cmd = [sys.executable, "-m", "unittest"] + t
        proc = subprocess.run(cmd, cwd=REPO, env=env,
                              capture_output=True, text=True, timeout=600)
        label = " ".join(t)
        if proc.returncode != 0:
            print("green check: FAIL %s\n%s" % (label, proc.stderr[-800:]))
            ok = False
        else:
            print("green check: PASS %s" % label)
    return ok


def _run_all():
    results = {}
    for name in PROBE_NAMES:
        try:
            results[name] = _PROBES[name]()
        except Exception:  # noqa: BLE001
            results[name] = "ERROR\n" + traceback.format_exc(limit=3)
    return results


# D1 verdict mapping (evals/SUMMARY_FORM_POLICIES.md), red-first: GAP -> BREAK.
# The verdict token is the first word of the recorded verdict string; the
# original first line is kept verbatim as the note (evidence preserved), with
# any multi-line detail collapsed to its first line (" // "-joined).
# Unknown tokens fail closed as ERROR (loud, never silent). Raw results keep
# the battery's own vocabulary (count code and exit contract untouched); the
# mapping happens at emission.
_VERDICT_TOKEN_MAP = {"HELD": "HELD", "GAP": "BREAK", "BREAK": "BREAK",
                      "ERROR": "ERROR"}


def _split_row(name, v):
    first = probe_lines.first_line(v)
    tok = (first.split(":")[0].split() or [""])[0]
    mapped = _VERDICT_TOKEN_MAP.get(tok)
    if mapped is None:
        return {"probe_id": name, "verdict": "ERROR",
                "note": "unparseable verdict string: %r" % (first,)}
    _, _, rest = v.partition("\n")
    rest_first = probe_lines.first_line(rest).strip()
    note = first if not rest_first else first + " // " + rest_first
    return {"probe_id": name, "verdict": mapped, "note": note}

def main():
    t0 = time.time()
    if not HAVE_MODULE:
        rows = [{"probe_id": name, "verdict": "BREAK",
                 "note": "GAP (token_hygiene absent)"} for name in PROBE_NAMES]
        probe_lines.emit_dicts(rows)
        print("%d BREAK / %d HELD / %d ERROR" % (len(PROBE_NAMES), 0, 0))
        return 2
    results = _run_all()
    held = sum(1 for v in results.values() if v == "HELD")
    gap = sum(1 for v in results.values() if v.startswith("GAP"))
    brk = sum(1 for v in results.values() if v.startswith("BREAK"))
    err = sum(1 for v in results.values() if v.startswith("ERROR"))
    rows = [_split_row(name, results.get(name, "ERROR: missing"))
            for name in PROBE_NAMES]
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(r["probe_id"], r["verdict"], r["note"]) for r in rows],
        brk + gap, held, err)
    probe_lines.emit_dicts(rows)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    print("%d BREAK / %d HELD / %d ERROR (%.1fs)"
          % (brk + gap, held, err, time.time() - t0))
    green_ok = _green_check()
    return 0 if (brk == 0 and err == 0 and green_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
