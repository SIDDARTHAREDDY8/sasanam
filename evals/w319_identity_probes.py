#!/usr/bin/env python3
"""Wave-319 Lane 2 battery: workload identity (gov/workload_identity.py).

Sasanam agents act with powerful tool grants but the governance layer has no
attested notion of WHICH WORKLOAD is acting. This battery proves the
SPIFFE-semantics attested-identity model at the public seams, RED-FIRST: it is
written before the module exists and must FAIL on the open tree.

Probe map (public seams only -- mint_document / verify_document /
ApprovalQueue.queue(..., attested_identity=...)):
  mint-verify-roundtrip: mint for recognized selectors, verify against the
      same facts -> verified, coded identity-attested.
  mint-unrecognized-selectors-refused: binary_hash not in the attestation
      policy -> identity-mint-refused.
  mint-empty-audience-refused: empty audience -> identity-mint-refused (an
      audience-less document is a passthrough accident waiting to happen).
  mint-excessive-ttl-refused: ttl above the hard max -> identity-mint-refused.
  forged-document-refused: tamper a selector post-mint -> identity-forged
      (the signature covers the canonical selectors).
  unknown-issuer-refused: document signed by a different key ->
      identity-forged.
  expired-document-refused: now past not_after -> identity-expired.
  not-yet-valid-refused: now before not_before -> identity-not-yet-valid.
  audience-mismatch-refused: doc for tool:email presented to tool:files ->
      identity-audience-mismatch.
  replay-to-different-audience-refused: a captured valid document replayed
      at a different audience (same workload facts) ->
      identity-audience-mismatch. The no-token-passthrough doctrine.
  foreign-domain-no-federation-refused: foreign trust domain with no
      federation record -> identity-untrusted-domain (trust never implicit).
  foreign-domain-with-federation-accepted: federation record pins the
      foreign issuer key -> verified.
  selector-mismatch-refused: presented facts differ from the document's
      selectors (stolen document, different workload) ->
      identity-selector-mismatch.
  malformed-document-never-raises: hostile inputs refuse with a typed code,
      never raise.
  approval-record-carries-claim: queue(..., attested_identity=doc) stamps
      the claim; post-queue tampering of the claim breaks the record MAC.
  approval-claim-advisory: a FORGED document still queues fine (advisory,
      not gating) with verified:false + the typed code on the record.
  approval-no-claim: queue without attested_identity -> claim None, no
      behavior change.
  pin-taxonomy / footer-state: standard pins (1946; open F406 / next F407).
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import probe_lines  # noqa: E402  (canonical probe-line emission)

from gov import decision_codes as dc  # noqa: E402
from gov import workload_identity as ai  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402

TAXONOMY_PIN = 1951  # Wave-319 lane 2: pin 1906 -> 1914 (+8 identity-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

FOOTER_NEXT = "F407"
FOOTER_OPEN = "F406"

_results = []
PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


def _held(pid, note):
    _results.append({"probe_id": pid, "verdict": "HELD", "note": note})
    return "HELD", note


def _break(pid, note):
    _results.append({"probe_id": pid, "verdict": "BREAK", "note": note})
    return "BREAK", note


_NOW = 1785000000  # fixed test time (deterministic)
_TRUST_DOMAIN = "prod.sasanam.example"
_AGENT_PATH = "/agent/scheduler-7"
_SPIFFE_ID = "spiffe://%s%s" % (_TRUST_DOMAIN, _AGENT_PATH)
_BINARY_HASH = "ab" * 32
_CHAIN = "cd" * 32


def _issuer():
    seed = bytes(range(32))
    return {"seed": seed, "pub": _ed.publickey(seed)}


def _policy():
    return ai.AttestationPolicy(
        recognized=[(_BINARY_HASH, "production")],
        trust_domain=_TRUST_DOMAIN,
    )


def _selectors():
    return {
        "binary_hash": _BINARY_HASH,
        "invocation_chain": _CHAIN,
        "deployment_mode": "production",
    }


def _mint(issuer, audience="tool:email-sender", ttl=3600, now=_NOW,
          selectors=None, agent_path=_AGENT_PATH):
    return ai.mint_document(
        issuer_seed=issuer["seed"],
        agent_path=agent_path,
        selectors=selectors if selectors is not None else _selectors(),
        audience=audience,
        ttl_seconds=ttl,
        now=now,
        policy=_policy(),
    )


def _verifier(issuer, now=_NOW, federation=None):
    return ai.DocumentVerifier(
        issuer_pubkeys={_TRUST_DOMAIN: issuer["pub"]},
        trust_domain=_TRUST_DOMAIN,
        federation=federation,
        now=now,
    )


@probe("mint-verify-roundtrip")
def _p_roundtrip():
    issuer = _issuer()
    doc = _mint(issuer)
    verdict = _verifier(issuer).verify(
        doc, audience="tool:email-sender", presented_selectors=_selectors())
    if verdict.verified and verdict.code == "identity-attested":
        return _held("mint-verify-roundtrip",
                     "verified spiffe_id=%s" % verdict.spiffe_id)
    return _break("mint-verify-roundtrip",
                  "expected verified/identity-attested, got %r/%r" % (
                      verdict.verified, verdict.code))


@probe("mint-unrecognized-selectors-refused")
def _p_bad_selectors():
    issuer = _issuer()
    bad = dict(_selectors(), binary_hash="ff" * 32)
    try:
        _mint(issuer, selectors=bad)
    except ai.MintRefusal as e:
        if e.code == "identity-mint-refused":
            return _held("mint-unrecognized-selectors-refused", str(e))
        return _break("mint-unrecognized-selectors-refused",
                      "wrong code %r" % e.code)
    return _break("mint-unrecognized-selectors-refused",
                  "minted for unrecognized selectors")


@probe("mint-empty-audience-refused")
def _p_empty_aud():
    issuer = _issuer()
    try:
        _mint(issuer, audience="")
    except ai.MintRefusal as e:
        if e.code == "identity-mint-refused":
            return _held("mint-empty-audience-refused", str(e))
        return _break("mint-empty-audience-refused", "wrong code %r" % e.code)
    return _break("mint-empty-audience-refused", "minted audience-less doc")


@probe("mint-excessive-ttl-refused")
def _p_long_ttl():
    issuer = _issuer()
    try:
        _mint(issuer, ttl=ai.MAX_TTL_SECONDS + 1)
    except ai.MintRefusal as e:
        if e.code == "identity-mint-refused":
            return _held("mint-excessive-ttl-refused", str(e))
        return _break("mint-excessive-ttl-refused", "wrong code %r" % e.code)
    return _break("mint-excessive-ttl-refused", "minted over-max TTL")


@probe("forged-document-refused")
def _p_forged():
    issuer = _issuer()
    doc = _mint(issuer)
    doc = dict(doc)
    doc["selectors"] = dict(doc["selectors"], binary_hash="00" * 32)
    verdict = _verifier(issuer).verify(
        doc, audience="tool:email-sender", presented_selectors=_selectors())
    if not verdict.verified and verdict.code == "identity-forged":
        return _held("forged-document-refused", "tampered selectors refused")
    return _break("forged-document-refused",
                  "got %r/%r" % (verdict.verified, verdict.code))


@probe("unknown-issuer-refused")
def _p_unknown_issuer():
    issuer = _issuer()
    other = {"seed": bytes([9] * 32), "pub": _ed.publickey(bytes([9] * 32))}
    doc = _mint(other)  # signed by a key the verifier never saw
    verdict = _verifier(issuer).verify(
        doc, audience="tool:email-sender", presented_selectors=_selectors())
    if not verdict.verified and verdict.code == "identity-forged":
        return _held("unknown-issuer-refused", "foreign signature refused")
    return _break("unknown-issuer-refused",
                  "got %r/%r" % (verdict.verified, verdict.code))


@probe("expired-document-refused")
def _p_expired():
    issuer = _issuer()
    doc = _mint(issuer, ttl=600, now=_NOW)
    verdict = _verifier(issuer, now=_NOW + 601).verify(
        doc, audience="tool:email-sender", presented_selectors=_selectors())
    if not verdict.verified and verdict.code == "identity-expired":
        return _held("expired-document-refused", "past not_after refused")
    return _break("expired-document-refused",
                  "got %r/%r" % (verdict.verified, verdict.code))


@probe("not-yet-valid-refused")
def _p_early():
    issuer = _issuer()
    doc = _mint(issuer, ttl=600, now=_NOW + 3600)
    verdict = _verifier(issuer, now=_NOW).verify(
        doc, audience="tool:email-sender", presented_selectors=_selectors())
    if not verdict.verified and verdict.code == "identity-not-yet-valid":
        return _held("not-yet-valid-refused", "before not_before refused")
    return _break("not-yet-valid-refused",
                  "got %r/%r" % (verdict.verified, verdict.code))


@probe("audience-mismatch-refused")
def _p_aud_mismatch():
    issuer = _issuer()
    doc = _mint(issuer, audience="tool:email-sender")
    verdict = _verifier(issuer).verify(
        doc, audience="tool:file-writer", presented_selectors=_selectors())
    if not verdict.verified and verdict.code == "identity-audience-mismatch":
        return _held("audience-mismatch-refused",
                     "cross-audience presentation refused")
    return _break("audience-mismatch-refused",
                  "got %r/%r" % (verdict.verified, verdict.code))


@probe("replay-to-different-audience-refused")
def _p_replay():
    issuer = _issuer()
    captured = _mint(issuer, audience="tool:email-sender")
    # Same workload facts (no selector tripwire): purely the audience check.
    verdict = _verifier(issuer).verify(
        captured, audience="tool:file-writer",
        presented_selectors=_selectors())
    if not verdict.verified and verdict.code == "identity-audience-mismatch":
        return _held("replay-to-different-audience-refused",
                     "captured doc cannot hop audiences")
    return _break("replay-to-different-audience-refused",
                  "got %r/%r" % (verdict.verified, verdict.code))


@probe("foreign-domain-no-federation-refused")
def _p_foreign():
    issuer = _issuer()
    foreign_seed = bytes([7] * 32)
    foreign_issuer = {"seed": foreign_seed,
                      "pub": _ed.publickey(foreign_seed)}
    doc = ai.mint_document(
        issuer_seed=foreign_seed,
        agent_path=_AGENT_PATH,
        selectors=_selectors(),
        audience="tool:email-sender",
        ttl_seconds=3600,
        now=_NOW,
        policy=ai.AttestationPolicy(
            recognized=[(_BINARY_HASH, "production")],
            trust_domain="partner.example"),
    )
    verdict = _verifier(issuer).verify(
        doc, audience="tool:email-sender", presented_selectors=_selectors())
    if not verdict.verified and verdict.code == "identity-untrusted-domain":
        return _held("foreign-domain-no-federation-refused",
                     "implicit cross-domain trust refused")
    return _break("foreign-domain-no-federation-refused",
                  "got %r/%r" % (verdict.verified, verdict.code))


@probe("foreign-domain-with-federation-accepted")
def _p_federated():
    issuer = _issuer()
    foreign_seed = bytes([7] * 32)
    foreign_pub = _ed.publickey(foreign_seed)
    doc = ai.mint_document(
        issuer_seed=foreign_seed,
        agent_path=_AGENT_PATH,
        selectors=_selectors(),
        audience="tool:email-sender",
        ttl_seconds=1800,
        now=_NOW,
        policy=ai.AttestationPolicy(
            recognized=[(_BINARY_HASH, "production")],
            trust_domain="partner.example"),
    )
    fed = ai.FederationPolicy(records={
        "partner.example": ai.FederationRecord(
            issuer_pubkey=foreign_pub, max_ttl_seconds=1800),
    })
    verifier = _verifier(issuer, federation=fed)
    verdict = verifier.verify(
        doc, audience="tool:email-sender", presented_selectors=_selectors())
    if verdict.verified and verdict.code == "identity-attested":
        return _held("foreign-domain-with-federation-accepted",
                     "explicit federation record accepts")
    return _break("foreign-domain-with-federation-accepted",
                  "got %r/%r" % (verdict.verified, verdict.code))


@probe("selector-mismatch-refused")
def _p_selector_mismatch():
    issuer = _issuer()
    doc = _mint(issuer)
    other_facts = dict(_selectors(), binary_hash="11" * 32)
    verdict = _verifier(issuer).verify(
        doc, audience="tool:email-sender", presented_selectors=other_facts)
    if not verdict.verified and verdict.code == "identity-selector-mismatch":
        return _held("selector-mismatch-refused",
                     "stolen doc at a different workload refused")
    return _break("selector-mismatch-refused",
                  "got %r/%r" % (verdict.verified, verdict.code))


@probe("malformed-document-never-raises")
def _p_malformed():
    issuer = _issuer()
    verifier = _verifier(issuer)
    hostile = [None, 42, "x", [], {}, {"spiffe_id": 1},
               {"spiffe_id": _SPIFFE_ID}]  # missing everything else
    for h in hostile:
        try:
            verdict = verifier.verify(
                h, audience="tool:email-sender",
                presented_selectors=_selectors())
        except Exception as exc:  # noqa: BLE001
            return _break("malformed-document-never-raises",
                          "raised %r on %r" % (exc, h))
        if verdict.verified:
            return _break("malformed-document-never-raises",
                          "accepted %r" % (h,))
    return _held("malformed-document-never-raises",
                 "%d hostile inputs refused, none raised" % len(hostile))


def _queue_with_claim(attested_identity, tmpdir):
    # Minimal ApprovalQueue construction for the claim seam (mirrors
    # tests/test_approvals_uptime.py): ActionLog + ApprovalQueue(run_dir,
    # log); run_id is the run_dir name; verifier installed write-once via
    # set_identity_verifier. The approval MAC needs a key (F73
    # fail-closed): provision the test key for the queue's lifetime.
    # attested_identity: a workload-identity document dict (wrapped
    # with the re-attested selectors here) or None.
    from pathlib import Path  # noqa: E402
    from gov import approvals as ap  # noqa: E402
    from gov import workload_identity as _wi  # noqa: E402
    from gov.identity import AgentIdentity  # noqa: E402
    from gov.log import ActionLog  # noqa: E402
    from tests.keyfixture import provision_test_key, scrub_key_env  # noqa
    import tempfile  # noqa: E402
    restore = scrub_key_env()
    try:
        provision_test_key()
        run_dir = Path(tempfile.mkdtemp(prefix="w319q-", dir=tmpdir))
        log = ActionLog(run_dir / "actions.jsonl")
        queue = ap.ApprovalQueue(run_dir, log)
        minted = {}

        def _verify(identity):
            return minted.get(identity.agent_id)

        queue.set_identity_verifier(_verify)
        queue.set_attested_identity_verifier(
            _wi.DocumentVerifier(
                issuer_pubkeys={_TRUST_DOMAIN: _ISSUER_PUB},
                trust_domain=_TRUST_DOMAIN, now=_NOW),
            _wi.APPROVAL_QUEUE_AUDIENCE)
        ident = AgentIdentity(agent_id="agent-1", role="agent",
                              run_id=queue.run_id, principal="user:u1")
        minted["agent-1"] = ident
        wrapped = ({"document": attested_identity,
                    "presented_selectors": _selectors()}
                   if attested_identity is not None else None)
        record_id = queue.queue(
            {"tool": "email.send", "args": {"to": "t@local"},
             "identity": ident.as_dict(),
             "agent_justification": "send it"},
            decision=_FakeDecision(),
            caller_identity=ident,
            attested_identity=wrapped,
        )
        return queue, record_id
    finally:
        restore()


_ISSUER_PUB = _ed.publickey(bytes(range(32)))


class _FakeDecision:
    flag = "test"
    reason = "test decision"
    policy_id = "test-policy"


@probe("approval-record-carries-claim")
def _p_claim():
    from gov import workload_identity as _wi  # noqa: E402
    issuer = _issuer()
    doc = _mint(issuer, audience=_wi.APPROVAL_QUEUE_AUDIENCE)
    import tempfile  # noqa: E402
    tmpdir = tempfile.mkdtemp(prefix="w319-")
    queue, record_id = _queue_with_claim(doc, tmpdir)
    rec = queue.get(record_id)
    claim = rec.get("attested_identity")
    if not isinstance(claim, dict):
        return _break("approval-record-carries-claim",
                      "claim missing: %r" % (claim,))
    if not (claim.get("verified") is True
            and claim.get("code") == "identity-attested"
            and claim.get("spiffe_id") == _SPIFFE_ID):
        return _break("approval-record-carries-claim",
                      "claim wrong: %r" % (claim,))
    # Post-queue tampering with the claim breaks the record MAC.
    from gov import approvals as ap  # noqa: E402
    rec2 = dict(queue.get(record_id))
    rec2["attested_identity"] = dict(claim, verified=False)
    if ap.approval_digest_ok(rec2):
        return _break("approval-record-carries-claim",
                      "tampered claim passed the digest")
    return _held("approval-record-carries-claim",
                 "claim stamped MAC-bound; tamper breaks digest")


@probe("approval-claim-advisory")
def _p_advisory():
    from gov import workload_identity as _wi  # noqa: E402
    issuer = _issuer()
    doc = _mint(issuer, audience=_wi.APPROVAL_QUEUE_AUDIENCE)
    doc = dict(doc)
    doc["selectors"] = dict(doc["selectors"], binary_hash="00" * 32)
    import tempfile  # noqa: E402
    tmpdir = tempfile.mkdtemp(prefix="w319-")
    queue, record_id = _queue_with_claim(doc, tmpdir)
    rec = queue.get(record_id)
    claim = rec.get("attested_identity") or {}
    if claim.get("verified") is False and claim.get("code") == \
            "identity-forged":
        return _held("approval-claim-advisory",
                     "forged doc queues; claim records the refusal")
    return _break("approval-claim-advisory",
                  "queue gated or claim wrong: %r" % (claim,))


@probe("approval-no-claim")
def _p_no_claim():
    import tempfile  # noqa: E402
    tmpdir = tempfile.mkdtemp(prefix="w319-")
    queue, record_id = _queue_with_claim(None, tmpdir)
    rec = queue.get(record_id)
    if rec.get("attested_identity") is None:
        return _held("approval-no-claim", "absent claim stays None")
    return _break("approval-no-claim",
                  "unexpected claim: %r" % (rec.get("attested_identity"),))


@probe("pin-taxonomy")
def _p_pin():
    codes = sorted(c["code"] for c in dc.TAXONOMY.values())
    if len(dc.TAXONOMY) == TAXONOMY_PIN and codes == sorted(set(codes)):
        return _held("pin-taxonomy",
                     "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))
    return _break("pin-taxonomy",
                  "taxonomy %d codes, pin %d" % (len(dc.TAXONOMY),
                                                 TAXONOMY_PIN))


@probe("footer-state")
def _p_footer():
    import re  # noqa: E402
    text = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                encoding="utf-8").read()
    found = list(re.finditer(r"Next free finding: \*\*(F\d+)\*\*\. "
                             r"\*\*Open findings: ([^*]*)\*\*", text))
    if not found:
        return _break("footer-state", "footer not found")
    last = found[-1]
    nxt, opens = last.group(1), last.group(2).strip().rstrip(".")
    if nxt == FOOTER_NEXT and opens == FOOTER_OPEN:
        return _held("footer-state",
                     "open %s / next %s" % (FOOTER_OPEN, FOOTER_NEXT))
    return _break("footer-state",
                  "footer %s / %s, want %s / %s"
                  % (nxt, opens, FOOTER_NEXT, FOOTER_OPEN))


def green_check():
    """Depth-1 green check: adjacent seams still green. Honors
    GOV_SKIP_GREEN (the wave-173 convention)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1",
               GOV_DEPLOYMENT_MODE="staging")
    suites = ["tests.test_workload_identity",
              "tests.test_approval_tokens",
              "tests.test_decision_codes",
              "tests.test_goal_specificity_executor"]
    ok = True
    for suite in suites:
        try:
            r = subprocess.run(
                [sys.executable, "-m", "unittest", suite],
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=300)
        except Exception as exc:  # noqa: BLE001
            print("green_check: %s ERROR %r" % (suite, exc))
            ok = False
            continue
        status = "OK" if r.returncode == 0 else "FAIL"
        print("green_check: %s %s" % (suite, status))
        if r.returncode != 0:
            ok = False
    return ok


def main():
    held = broke = errors = 0
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception:  # noqa: BLE001
            verdict, detail = "ERROR", traceback.format_exc(limit=3)
        print("%-42s %s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broke += 1
        else:
            errors += 1
    probe_lines.emit_dicts(
        _results, verdict_key="verdict", pid_key="probe_id",
        note_key="note")
    print("probes: %d held / %d BREAK / %d errors" % (held, broke, errors))
    print("green_check:", "OK" if green_check() else "FAIL")
    return 0 if (broke == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
