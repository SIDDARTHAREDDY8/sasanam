#!/usr/bin/env python3
"""Wave-239 lane A: AAuth R3 vocabulary grant tokens (W239-1).

Mechanism (draft-hardt-aauth-r3-00, prose re-derived): grant tokens carry
operations in a closed vocabulary format, not free-text scopes. ``r3_uri``
(REQUIRED) names the R3 document in effect at approval time; ``r3_s256``
(REQUIRED) is the SHA-256 of that document, base64url without padding --
the hash is the document's identity, not the URI. ``r3_grant_hash``
(REQUIRED) is the SHA-256 of the issued grant lists, so a bearer cannot
widen a narrowed grant post-issuance. ``r3_granted`` (REQUIRED)
lists operations fully authorized; ``r3_per_call`` (OPTIONAL) lists
operations authorized in principle but requiring per-call challenge on the
concrete parameters. Resource enforcement is match -> serve /
per-call -> challenge / no-match -> reject, with no introspection and no
R3 fetch at enforcement time. The per-call proposal binds the eventual
approval by content hash to the exact call that was proposed. The audit
log records r3_uri + r3_s256 as permanent, verifiable provenance.

Attack shapes at the public seams (break-first, red-first on base):

* a token carrying an operation that is not present in the published
  vocabulary (or a vocabulary the consumer does not register) refuses
  ``r3-unknown-operation`` -- unknown operations reject, never serve;
* a token whose ``r3_s256`` does not match the recomputed hash of the
  presented R3 document refuses ``r3-s256-mismatch`` -- the token must pin
  exactly the approval-time document (issuer rejects on hash mismatch);
* per-call proposal parameters edited after content-addressing: the issued
  per-call token no longer matches the challenged call and refuses
  ``r3-per-call-binding-broken`` -- approval binds the exact proposed
  call, never edited params;
* a valid token with a vocabulary-typed granted operation -> serve;
* a valid token with a per-call operation -> challenge, and the
  proposal/challenge flow binds the exact call -> serve;
* an operation matching nothing in the token -> ``r3-no-match`` reject;
* a grant reaching beyond the R3 document's own operation set refuses
  ``r3-grant-beyond-document`` -- the issuer may narrow, never widen;
* malformed tokens/documents refuse ``r3-malformed``;
* a bearer-edited grant list (narrowed grant widened post-issuance)
  refuses ``r3-grant-hash-mismatch`` -- the grant lists are content-bound
  by ``r3_grant_hash``, not trusted bearer state.

Seams under test:
* gov/aauth_r3.py -- issue_grant_token, issue_per_call_token,
  verify_token, check_access, challenge_per_call, audit_provenance,
  r3_s256_of, grant_hash_of, VOCABULARIES, R3Error codes, R3_* constants.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-238 HEAD b074e4264e9ce7e08fa889fb7269765999cacbb5.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g239a
  TMPDIR=/var/tmp/g239a ~/workspace/.gov-venv/bin/python evals/w239_aauth_r3_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HAVE_NEW_API = False
try:
    from gov import aauth_r3 as _r3
    HAVE_NEW_API = all(hasattr(_r3, n) for n in (
        "issue_grant_token", "issue_per_call_token", "verify_token",
        "check_access", "challenge_per_call", "audit_provenance",
        "r3_s256_of", "VOCABULARIES", "R3Error",
        "R3_UNKNOWN_OPERATION", "R3_VOCABULARY_UNKNOWN", "R3_MALFORMED",
        "R3_S256_MISMATCH", "R3_PER_CALL_BINDING_BROKEN", "R3_NO_MATCH",
        "R3_GRANT_BEYOND_DOCUMENT", "SERVE", "CHALLENGE"))
except ImportError:
    _r3 = None

PROBE_NAMES = [
    "r3-unknown-operation-refused",
    "r3-s256-mismatch-refused",
    "r3-per-call-edited-params-refused",
    "r3-granted-operation-serves",
    "r3-per-call-challenges-then-binds",
    "r3-no-match-rejects",
    "r3-grant-beyond-document-refused",
    "r3-malformed-token-refused",
    "r3-grant-list-edited-refused",
]


def _fixture():
    """A registered-vocabulary R3 document and ops against it."""
    vocab = "urn:aauth:vocabulary:mcp"
    doc = {
        "vocabulary": vocab,
        "operations": [
            {"tool": "list_calendar_events"},
            {"tool": "send_email", "server": "mail-1"},
        ],
    }
    granted = [{"tool": "list_calendar_events"}]
    per_call = [{"tool": "send_email", "server": "mail-1"}]
    return vocab, doc, granted, per_call


def _expect_refuse(code, fn):
    try:
        out = fn()
    except _r3.R3Error as exc:
        if exc.code == code:
            return ("HELD", "")
        return ("BREAK", "refused with %r, expected %r" % (exc.code, code))
    except Exception as exc:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(exc).__name__, exc))
    return ("BREAK", "no refusal, returned: %r" % (out,))


def probe_unknown_operation_refused():
    _vocab, doc, granted, _per_call = _fixture()
    # The published vocabulary has no 'weapon' field: closed vocabulary.
    bad = [{"tool": "list_calendar_events", "weapon": "phishing_lure"}]
    return _expect_refuse(_r3.R3_UNKNOWN_OPERATION,
        lambda: _r3.issue_grant_token(doc, bad, r3_uri="r3://issuer/doc1"))


def probe_s256_mismatch_refused():
    _vocab, doc, granted, per_call = _fixture()
    token = _r3.issue_grant_token(doc, granted, per_call,
                                  r3_uri="r3://issuer/doc1")
    token = dict(token)
    # Present the token against an EDITED document: hash no longer matches.
    edited = dict(doc)
    edited = {"vocabulary": doc["vocabulary"],
              "operations": doc["operations"] + [{"tool": "exfiltrate"}]}
    return _expect_refuse(_r3.R3_S256_MISMATCH,
        lambda: _r3.verify_token(token, edited))


def probe_per_call_edited_params_refused():
    _vocab, doc, granted, per_call = _fixture()
    proposal_op = {"tool": "send_email", "server": "mail-1",
                   "arguments": "hi-alice"}
    proposal = {"vocabulary": doc["vocabulary"],
                "operations": [proposal_op]}
    token = _r3.issue_per_call_token(doc, proposal_op,
                                     r3_uri="r3://issuer/proposal-7")
    edited_call = dict(proposal_op)
    edited_call["arguments"] = "hi-alice,also-bob"  # edited after addressing
    return _expect_refuse(_r3.R3_PER_CALL_BINDING_BROKEN,
        lambda: _r3.challenge_per_call(token, proposal, edited_call))


def probe_granted_operation_serves():
    _vocab, doc, granted, per_call = _fixture()
    token = _r3.issue_grant_token(doc, granted, per_call,
                                  r3_uri="r3://issuer/doc1")
    try:
        outcome = _r3.check_access(
            token, doc, {"tool": "list_calendar_events"})
    except _r3.R3Error as exc:
        return ("BREAK", "refused %r: %s" % (exc.code, exc.detail))
    except Exception as exc:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(exc).__name__, exc))
    if outcome == _r3.SERVE:
        return ("HELD", "")
    return ("BREAK", "expected serve, got %r" % (outcome,))


def probe_per_call_challenges_then_binds():
    _vocab, doc, granted, per_call = _fixture()
    token = _r3.issue_grant_token(doc, granted, per_call,
                                  r3_uri="r3://issuer/doc1")
    op = {"tool": "send_email", "server": "mail-1"}
    try:
        outcome = _r3.check_access(token, doc, op)
    except _r3.R3Error as exc:
        return ("BREAK", "refused %r: %s" % (exc.code, exc.detail))
    except Exception as exc:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(exc).__name__, exc))
    if outcome != _r3.CHALLENGE:
        return ("BREAK", "expected challenge, got %r" % (outcome,))
    # Per-call challenge flow: proposal binds the EXACT proposed call.
    proposal_op = {"tool": "send_email", "server": "mail-1",
                   "arguments": "hi-alice"}
    proposal = {"vocabulary": doc["vocabulary"],
                "operations": [proposal_op]}
    pc_token = _r3.issue_per_call_token(doc, proposal_op,
                                        r3_uri="r3://issuer/proposal-7")
    try:
        bound = _r3.challenge_per_call(pc_token, proposal, proposal_op)
    except _r3.R3Error as exc:
        return ("BREAK", "challenge refused %r: %s" % (exc.code, exc.detail))
    except Exception as exc:  # noqa: BLE001
        return ("ERROR", "%s: %s" % (type(exc).__name__, exc))
    if bound == _r3.SERVE:
        return ("HELD", "")
    return ("BREAK", "expected bound serve, got %r" % (bound,))


def probe_grant_beyond_document_refused():
    _vocab, doc, _granted, _per_call = _fixture()
    # The issuer may narrow the grant, never widen it: an operation the
    # R3 document itself does not define refuses at issue time.
    return _expect_refuse(_r3.R3_GRANT_BEYOND_DOCUMENT,
        lambda: _r3.issue_grant_token(doc, [{"tool": "exfiltrate"}],
                                      r3_uri="r3://issuer/doc1"))


def probe_malformed_token_refused():
    _vocab, doc, _granted, _per_call = _fixture()
    return _expect_refuse(_r3.R3_MALFORMED,
        lambda: _r3.verify_token({"r3_uri": "r3://issuer/doc1"}, doc))


def probe_grant_list_edited_refused():
    _vocab, doc, granted, per_call = _fixture()
    token = _r3.issue_grant_token(doc, granted, per_call,
                                  r3_uri="r3://issuer/doc1")
    # Bearer widens the narrowed grant with a document-listed,
    # vocabulary-typed op the issuer never granted.
    token["r3_granted"] = (token["r3_granted"]
                           + [{"tool": "send_email", "server": "mail-1"}])
    return _expect_refuse(_r3.R3_GRANT_HASH_MISMATCH,
        lambda: _r3.verify_token(token, doc))


def probe_no_match_rejects():
    _vocab, doc, granted, per_call = _fixture()
    token = _r3.issue_grant_token(doc, granted, per_call,
                                  r3_uri="r3://issuer/doc1")
    # Vocabulary-typed and well-formed, but authorized nowhere in the token.
    return _expect_refuse(_r3.R3_NO_MATCH,
        lambda: _r3.check_access(token, doc,
                                 {"tool": "list_calendar_events",
                                  "server": "mail-1"}))


_PROBES = {
    "r3-unknown-operation-refused": probe_unknown_operation_refused,
    "r3-s256-mismatch-refused": probe_s256_mismatch_refused,
    "r3-per-call-edited-params-refused": probe_per_call_edited_params_refused,
    "r3-granted-operation-serves": probe_granted_operation_serves,
    "r3-per-call-challenges-then-binds": probe_per_call_challenges_then_binds,
    "r3-no-match-rejects": probe_no_match_rejects,
    "r3-grant-beyond-document-refused": probe_grant_beyond_document_refused,
    "r3-malformed-token-refused": probe_malformed_token_refused,
    "r3-grant-list-edited-refused": probe_grant_list_edited_refused,
}


def _run_one(name, fn):
    try:
        verdict, detail = fn()
    except Exception:  # noqa: BLE001
        return name, "ERROR", traceback.format_exc(limit=3)
    return name, verdict, detail


def main():
    t0 = time.time()
    results = {}
    if not HAVE_NEW_API:
        for name in PROBE_NAMES:
            results[name] = ("GAP", "gov.aauth_r3 absent on this tree")
    else:
        for name in PROBE_NAMES:
            _, verdict, detail = _run_one(name, _PROBES[name])
            results[name] = (verdict, detail)
    held = sum(1 for v, _ in results.values() if v == "HELD")
    gap = sum(1 for v, _ in results.values() if v == "GAP")
    brk = sum(1 for v, _ in results.values() if v == "BREAK")
    err = sum(1 for v, _ in results.values() if v == "ERROR")
    for name in PROBE_NAMES:
        verdict, detail = results[name]
        line = "%-38s %s" % (name, verdict)
        if detail:
            line += "  (%s)" % detail.strip().splitlines()[0]
        print(line)
    print("%d HELD / %d GAP / %d BREAK / %d ERROR (%.1fs)" % (
        held, gap, brk, err, time.time() - t0))
    return 0 if (brk == 0 and err == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
