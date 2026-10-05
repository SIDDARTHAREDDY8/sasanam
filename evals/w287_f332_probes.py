"""Wave-287 lane 2 battery: close F332 (LOW).

F332: ExceptionStore.grant accepted a 20-space (or tab/newline-mix)
justification: the mandatory-justification control ("a justification
must say something") was satisfied by whitespace. The fix strips
justification and applies the 20-char floor to the STRIPPED content
(fail-closed reading: the floor measures meaningful content), refusing
coded `exception-justification-missing`.

Base: wave-286 push 8c811375d504371c448d6440b6f80ce9622eb0b45
(verified via git rev-parse HEAD before work).

Run:
  mkdir -p /var/tmp/g287-f332 && TMPDIR=/var/tmp/g287-f332 \
    ~/workspace/.gov-venv/bin/python evals/w287_f332_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g287-f332b \
    ~/workspace/.gov-venv/bin/python evals/w287_f332_probes.py
"""

import os
import subprocess
import sys
import tempfile
import time

# Wave-95 lesson: module-level staging default.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*).
TAXONOMY_PIN = 2128 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _literals():
    import re
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


def _store():
    from gov import governed_exceptions as ge
    reg = ge.CheckRegistry()
    reg.register("CKV_AWS_1", "bucket acl", "s3", "high",
                 rationale="public bucket acl check rationale",
                 resource_types=("aws_s3_bucket",))
    st = ge.ExceptionStore(reg)
    st.set_approvers(["alice"])
    return ge, st


def _grant_kwargs(justification):
    now = time.time()
    return dict(check_id="CKV_AWS_1",
                scope=("resource", "aws_s3_bucket.x"),
                justification=justification, approver="alice",
                expiry_ts=now + 3600, created_at=now)


def _expect_refused(pid, justification, must_code):
    ge, st = _store()
    try:
        st.grant(**_grant_kwargs(justification))
    except ge.GovernExceptionError as e:
        if e.code == must_code:
            return _record(pid, "HELD",
                           "refused with coded %s" % (e.code,))
        return _record(pid, "BREAK",
                       "refused but wrong code %r, want %r"
                       % (e.code, must_code))
    _record(pid, "BREAK", "whitespace justification accepted -- F332 open")


def p_f332_spaces():
    _expect_refused("f332-20-spaces", " " * 20,
                    "exception-justification-missing")


def p_f332_ws_mix():
    # >= 20 chars of pure whitespace mix: genuinely exercises the defect.
    _expect_refused("f332-ws-mix", "\t \n  \t\n  \n    \t  \n " * 2,
                    "exception-justification-missing")


def p_f332_sub20_stripped():
    # 19 meaningful chars + padding: fail-closed reading measures the
    # stripped content, so this must still be refused.
    _expect_refused("f332-19-stripped", "   " + "x" * 19 + "   ",
                    "exception-justification-missing")


def _expect_granted(pid, justification):
    ge, st = _store()
    try:
        exc = st.grant(**_grant_kwargs(justification))
    except ge.GovernExceptionError as e:
        return _record(pid, "BREAK",
                       "legitimate justification refused: %s" % (e.code,))
    _record(pid, "HELD", "granted: %s..." % (exc.digest[:8],))


def p_f332_legit():
    _expect_granted(
        "f332-legit-20",
        "Risk accepted: internal bucket, no PII, expires soon.")


def p_f332_legit_padded():
    # No over-refusal: meaningful content with incidental padding grants.
    _expect_granted(
        "f332-legit-padded",
        "  Risk accepted: internal bucket, no PII, expires soon.  ")


def _green_checks():
    if SKIP_GREEN:
        return
    for rel in ("evals/w285_exceptions_probes.py",):
        path = os.path.join(REPO, rel)
        d = tempfile.mkdtemp(prefix="w287-green-")
        try:
            proc = subprocess.run(
                [sys.executable, path], capture_output=True, text=True,
                timeout=600,
                env=dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=d,
                         GOV_RUN_ROOT=os.path.join(d, "gov-run")))
        except Exception as e:  # noqa: BLE001
            _record(os.path.basename(rel), "ERROR", "green check: %r" % (e,))
            continue
        out = proc.stdout + proc.stderr
        import re as _re
        m = _re.search(r"(\d+)\s+BREAK", out)
        nbreak = int(m.group(1)) if m else -1
        if nbreak != 0:
            _record(os.path.basename(rel), "BREAK",
                    "green check: %d BREAK (expected 0)" % nbreak)
        else:
            _record(os.path.basename(rel), "HELD",
                    "green check: 0 BREAK as expected")


def main():
    p_taxonomy_pin()
    p_f332_spaces()
    p_f332_ws_mix()
    p_f332_sub20_stripped()
    p_f332_legit()
    p_f332_legit_padded()
    _green_checks()

    nbreak = sum(1 for _, v, _ in _results if v == "BREAK")
    nheld = sum(1 for _, v, _ in _results if v == "HELD")
    nerr = sum(1 for _, v, _ in _results if v == "ERROR")
    probe_lines.emit(_results)
    print("w287_f332: %d BREAK / %d HELD / %d ERROR" % (nbreak, nheld, nerr))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, nbreak, nheld, nerr)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))


if __name__ == "__main__":
    main()
