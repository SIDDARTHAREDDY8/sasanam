#!/usr/bin/env python3
"""INDEPENDENT EVIDENCE VERIFIER (wave-82) — the auditor's tool.

Reads ONLY the exported bundle: ``<bundle_dir>/bundle.json`` and
``<bundle_dir>/witness.json``. It holds NO HMAC chain key, NO gov key
material, and trusts NOTHING in the bundle: every byte is untrusted
input, validated cryptographically where validation is possible, and
flagged honestly where it is not.

Independence design (deliberate, read before trusting this tool):

* stdlib only; zero ``gov`` imports. The Ed25519 verification below is
  a vendored verify-only copy of RFC 8032 section 5.1.7 (byte-format
  compatible with the repo's ``gov/ed25519.py``, which is itself
  validated byte-exact against the RFC 8032 section 7.1 test vectors).
  The anchor-statement format constants (statement field allowlist,
  the ``gov-anchor-statement/v2`` signature domain, the canonical-JSON
  rule, the witness leaf domain) are PUBLIC PROTOCOL constants,
  documented in ``gov/anchor_backend.py`` — they are the wire format,
  not key material. Re-implementing them here keeps this verifier
  independent of the code under audit; a shared-library bug cannot
  silently bless a bad bundle.
* No HMAC key is provisioned, read from the environment, or accepted
  from the bundle. Per-entry chain MACs therefore CANNOT be checked
  here — the report states this loudly (``HONEST_BOUNDARIES``), and no
  verdict ever implies full independent chain verification.
* The anchor public key ships inside the bundle. "Verify, don't trust"
  means: use it to check the signature — a valid signature proves only
  that the key holder endorsed the statement, never that the key is
  the right one.
* The witness log (``witness.json``) is UNTRUSTED input. Receipts are
  validated cryptographically (statement signature, anchor-hash bind,
  Merkle inclusion proof). For the ``fake-witness`` backend used in
  this demo, receipts prove the anchor FORMAT and the verification
  PATH, never third-party attestation — the report says so loudly.

Output is plain language for a non-engineer auditor: sections with
PASS / OPERATOR-ATTESTED-ONLY / CANNOT-VERIFY verdicts, and an
"HONEST BOUNDARIES" section that states exactly what this verifier
cannot check. Exit 0 means the report was produced honestly (even
when verdicts are negative); exit 1 means the bundle could not be
read at all.

SYNTHETIC: this tool inspects synthetic demo evidence only.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Vendored verify-only Ed25519 (RFC 8032, section 5.1.7). Verify path only:
# no key generation, no signing — a verifier has no business holding
# secrets. Byte-format compatible with the RFC; validated byte-exact
# against the RFC 8032 section 7.1 TEST 1 / TEST 2 vectors in the unit
# suite (tests/test_w82_evidence_demo.py).
# ---------------------------------------------------------------------------

_ED_Q = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_Q - 2, _ED_Q)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)


def _ed_inv(x):
    return pow(x, _ED_Q - 2, _ED_Q)


def _ed_xrecover(y):
    xx = (y * y - 1) * _ed_inv((_ED_D * y * y + 1) % _ED_Q) % _ED_Q
    x = pow(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q != 0:
        x = (x * _ED_I) % _ED_Q
    if x & 1:
        x = _ED_Q - x
    return x


_ED_BY = (4 * _ed_inv(5)) % _ED_Q
_ED_BX = _ed_xrecover(_ED_BY)
_ED_B = (_ED_BX, _ED_BY, 1, (_ED_BX * _ED_BY) % _ED_Q)
_ED_IDENTITY = (0, 1, 1, 0)


def _ed_add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = ((Y1 - X1) * (Y2 - X2)) % _ED_Q
    B = ((Y1 + X1) * (Y2 + X2)) % _ED_Q
    C = (T1 * ((2 * _ED_D) % _ED_Q) * T2) % _ED_Q
    Dd = ((2 * Z1) * Z2) % _ED_Q
    E = (B - A) % _ED_Q
    F = (Dd - C) % _ED_Q
    G = (Dd + C) % _ED_Q
    H = (B + A) % _ED_Q
    return ((E * F) % _ED_Q, (G * H) % _ED_Q, (F * G) % _ED_Q,
            (E * H) % _ED_Q)


def _ed_scalarmult(P, e):
    e %= _ED_L
    Q = _ED_IDENTITY
    for i in range(255, -1, -1):
        Q = _ed_add(Q, Q)
        if (e >> i) & 1:
            Q = _ed_add(Q, P)
    return Q


def _ed_encode_point(P):
    X, Y, Z, _T = P
    zinv = _ed_inv(Z)
    x = (X * zinv) % _ED_Q
    y = (Y * zinv) % _ED_Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decode_point(s):
    if len(s) != 32:
        raise ValueError("encoded point must be 32 bytes")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    if y >= _ED_Q:
        raise ValueError("y coordinate out of range")
    x = _ed_xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = _ED_Q - x
    if ((-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_Q) != 0:
        raise ValueError("point not on curve")
    return (x, y, 1, (x * y) % _ED_Q)


def ed25519_verify(pub, msg, sig):
    """RFC 8032 5.1.7 verify. True/False; never raises on malformed input
    (fail-closed for verifiers: malformed is False, never an exception)."""
    if (not isinstance(pub, (bytes, bytearray)) or len(pub) != 32
            or not isinstance(sig, (bytes, bytearray)) or len(sig) != 64):
        return False
    if not isinstance(msg, (bytes, bytearray)):
        return False
    pub, sig, msg = bytes(pub), bytes(sig), bytes(msg)
    try:
        A = _ed_decode_point(pub)
        R = _ed_decode_point(sig[:32])
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _ED_L:
        return False
    k = int.from_bytes(
        hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _ED_L
    lhs = _ed_scalarmult(_ED_B, s)
    rhs = _ed_add(R, _ed_scalarmult(A, k))
    return _ed_encode_point(lhs) == _ed_encode_point(rhs)


# ---------------------------------------------------------------------------
# Witness Merkle inclusion math (fake-witness receipts).
#
# PUBLIC PROTOCOL constants, documented in gov/anchor_backend.py — the
# wire format, not key material: the leaf domain separating witness
# leaves from every other hash use, and the node domain for internal
# tree nodes. Re-implemented here so this verifier does not share code
# with the implementation under audit.
# ---------------------------------------------------------------------------

_WITNESS_LEAF_DOMAIN = b"gov-anchor-witness-leaf/v1\x00"
_WITNESS_NODE_DOMAIN = b"gov-merkle-node/v1\x00"


def _wit_node_hash(left, right):
    return hashlib.sha256(_WITNESS_NODE_DOMAIN + bytes(left) + bytes(right)
                          ).digest()


def _largest_pow2_lt(n):
    k = 1
    while 2 * k < n:
        k *= 2
    return k


def witness_verify_inclusion(leaf, index, proof, root, tree_size):
    """Verify a witness leaf's inclusion under ``root``. True/False;
    never raises on malformed input (fail-closed for verifiers)."""
    if (not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32
            or not isinstance(root, (bytes, bytearray)) or len(root) != 32):
        return False
    if not isinstance(index, int) or not isinstance(tree_size, int):
        return False
    if isinstance(index, bool) or not (0 <= index < tree_size):
        return False
    try:
        proof = [bytes(p) for p in proof]
    except TypeError:
        return False
    if any(len(p) != 32 for p in proof):
        return False
    h = bytes(leaf)
    pos = 0

    def rec(m, n):
        nonlocal h, pos
        if n == 1:
            return True
        if pos >= len(proof):
            return False
        k = _largest_pow2_lt(n)
        sib = proof[pos]
        pos += 1
        if m < k:
            if not rec(m, k):
                return False
            h = _wit_node_hash(h, sib)
        else:
            if not rec(m - k, n - k):
                return False
            h = _wit_node_hash(sib, h)
        return True

    if not rec(index, tree_size):
        return False
    if pos != len(proof):
        return False
    return h == bytes(root)


# ---------------------------------------------------------------------------
# Anchor statement format (PUBLIC PROTOCOL — see gov/anchor_backend.py).
# ---------------------------------------------------------------------------

_STMT_DOMAIN = b"gov-anchor-statement/v2\x00"
_STMT_FIELDS = frozenset({
    "anchor_version", "epoch_id", "seq", "start_seq", "head_hash",
    "merkle_root", "epoch_start_wall", "epoch_close_wall",
    "key_id", "pubkey_hex", "prev_anchor", "log_id", "sig",
})
_STMT_REQUIRED = frozenset(_STMT_FIELDS - {"merkle_root", "sig"})


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _sig_body(statement):
    body = {k: v for k, v in statement.items() if k != "sig"}
    return _STMT_DOMAIN + _canonical(body)


# ---------------------------------------------------------------------------
# The honest boundaries — the core of this tool's credibility. Printed
# first AND last in every report. Whatever this verifier cannot check
# is stated here, not hidden.
# ---------------------------------------------------------------------------

HONEST_BOUNDARIES = [
    "This verifier holds NO copy of the chain's HMAC key. It CANNOT "
    "check per-entry chain MACs.",
    "Entries between anchors are operator-attested; only anchor heads "
    "are independently verified.",
    "The witness in this bundle is a LOCAL test double (fake-witness) "
    "on the operator's own machine: its receipts prove the anchor "
    "FORMAT and the verification PATH, not third-party attestation.",
    "The anchor public key ships inside the bundle. A valid signature "
    "proves only that the key holder endorsed the statement — it does "
    "NOT prove the key is the right one.",
    "A matching head hash means the operator's exported entry and the "
    "operator's signed statement agree. A key holder who can forge the "
    "chain can forge both: this is consistency, not independent "
    "verification.",
    "Records after the last anchor sit in the open epoch — the "
    "unverifiable soft window. The load-bearing guarantee is: no "
    "undetected rewrite of history prior to the last anchor; history "
    "after the last anchor is soft, and the anchor cadence is the "
    "security parameter.",
]

BUNDLE_VERSION = 1


def _hex(b, what, want_len):
    """Parse a hex field from untrusted input; (bytes|None, reason)."""
    if not isinstance(b, str):
        return None, "%s is not a string" % what
    try:
        raw = bytes.fromhex(b)
    except ValueError:
        return None, "%s is not hex" % what
    if len(raw) != want_len:
        return None, "%s has wrong length (want %d bytes)" % (what,
                                                              want_len)
    return raw, None


def verify_statement_sig(statement):
    """Verify the anchor statement's Ed25519 signature under the pubkey
    it ships. Returns (ok, reasons list, anchor_hash|None)."""
    reasons = []
    if not isinstance(statement, dict):
        return False, ["statement is not an object"], None
    extra = set(statement) - _STMT_FIELDS
    if extra:
        reasons.append("statement carries non-allowlisted fields: %s"
                       % sorted(extra))
    missing = _STMT_REQUIRED - set(statement)
    if missing:
        reasons.append("statement missing required fields: %s"
                       % sorted(missing))
    if statement.get("anchor_version") != 2:
        reasons.append("unsupported anchor_version %r (this verifier "
                       "knows v2)" % (statement.get("anchor_version"),))
    if reasons:
        return False, reasons, None
    pub, why = _hex(statement["pubkey_hex"], "pubkey_hex", 32)
    if why:
        return False, [why], None
    sig, why = _hex(statement["sig"], "sig", 64)
    if why:
        return False, [why], None
    body = _sig_body(statement)
    anchor_hash = hashlib.sha256(body).hexdigest()
    if ed25519_verify(pub, body, sig):
        return True, [], anchor_hash
    return False, ["statement signature INVALID under the shipped "
                   "pubkey"], None


def verify_fake_witness_receipt(receipt, anchor_hash, witness):
    """Validate a fake-witness receipt cryptographically, treating the
    witness log as UNTRUSTED. Returns (ok, reasons list)."""
    reasons = []
    if not isinstance(receipt, dict):
        return False, ["receipt is not an object"]
    if receipt.get("backend") != "fake-witness":
        return False, ["receipt backend is %r, not 'fake-witness'"
                       % (receipt.get("backend"),)]
    if receipt.get("anchor_hash") != anchor_hash:
        reasons.append("receipt is for a DIFFERENT anchor hash")
    try:
        leaf = hashlib.sha256(
            _WITNESS_LEAF_DOMAIN + bytes.fromhex(anchor_hash)).digest()
        proof = [bytes.fromhex(p) for p in receipt["inclusion_proof"]]
        root = bytes.fromhex(receipt["log_root"])
        index = receipt["log_index"]
        size = receipt["tree_size"]
    except (KeyError, TypeError, ValueError) as e:
        return False, ["anchor_hash / malformed receipt fields: %s"
                       % (e,)]
    if not witness_verify_inclusion(leaf, index, proof, root, size):
        reasons.append("inclusion proof does NOT verify against the "
                       "receipt's log_root")
    # Cross-check against the UNTRUSTED witness log: the witness claims
    # a log; the receipt must appear in it. A missing receipt here does
    # not un-verify the math above, but it means the witness will not
    # stand behind this receipt.
    w_receipts = (witness or {}).get("receipts")
    if not isinstance(w_receipts, list) or not any(
            isinstance(r, dict) and r.get("anchor_hash") == anchor_hash
            and r.get("log_root") == receipt.get("log_root")
            for r in w_receipts):
        reasons.append("the (untrusted) witness log does not contain "
                       "this receipt")
    if (witness or {}).get("backend_id") != receipt.get("backend_id"):
        reasons.append("receipt backend_id does not match the witness "
                       "log's backend_id")
    return (not reasons), reasons


def verify_bundle(bundle_dir):
    """Verify an exported evidence bundle. Returns a report dict; never
    raises on malformed bundle content (fail-closed: malformed is a
    CANNOT-VERIFY verdict, never an exception)."""
    report = {
        "bundle_dir": str(bundle_dir),
        "run_id": None,
        "bundle_ok": False,
        "bundle_errors": [],
        "epochs": [],
        "open_epoch": None,
        "attribution": {"verdict": "CANNOT-VERIFY", "details": []},
        "stopped_attack": {"verdict": "CANNOT-VERIFY", "details": []},
        "honest_boundaries": list(HONEST_BOUNDARIES),
        # Wave-85: the bypass section is part of the report schema from
        # the start, so even a malformed bundle renders a stable
        # report (CANNOT-VERIFY on the chain, not a missing key).
        "ungoverned_bypasses": {"verdict": "CANNOT-VERIFY",
                                "declarations": [], "refusals": []},
    }
    bdir = Path(bundle_dir)
    try:
        bundle = json.loads((bdir / "bundle.json").read_text(
            encoding="utf-8"))
        witness = json.loads((bdir / "witness.json").read_text(
            encoding="utf-8"))
    except (OSError, ValueError) as e:
        report["bundle_errors"].append("cannot read/parse the bundle: "
                                       "%s" % (e,))
        return report
    if not isinstance(bundle, dict) or not isinstance(witness, dict):
        report["bundle_errors"].append("bundle.json / witness.json are "
                                       "not objects")
        return report
    if bundle.get("bundle_version") != BUNDLE_VERSION:
        report["bundle_errors"].append(
            "bundle_version %r: this verifier knows version %d"
            % (bundle.get("bundle_version"), BUNDLE_VERSION))
        return report
    entries = (bundle.get("chain_segment") or {}).get("entries")
    if not isinstance(entries, list) or not entries:
        report["bundle_errors"].append("chain_segment.entries missing "
                                       "or empty")
        return report
    seqs = [e.get("seq") for e in entries if isinstance(e, dict)]
    if seqs != list(range(1, len(entries) + 1)):
        report["bundle_errors"].append(
            "chain segment seqs are not a clean 1..N run (gaps or "
            "reordering — cannot reason about chaining)")
        return report
    report["bundle_ok"] = True
    report["run_id"] = bundle.get("run_id")
    by_seq = {e["seq"]: e for e in entries}

    # -- per-epoch anchor verification ---------------------------------
    anchors = bundle.get("anchors") or []
    if not isinstance(anchors, list):
        report["bundle_errors"].append("'anchors' is not a list")
        anchors = []
    anchors = sorted(
        [a for a in anchors if isinstance(a, dict)],
        key=lambda a: a.get("checkpoint_seq", 0))
    expect_prev = "GENESIS"
    for a in anchors:
        ep = {"checkpoint_seq": a.get("checkpoint_seq"),
              "epoch_id": a.get("anchored_epoch_id"),
              "grade": "OPERATOR-ATTESTED-ONLY",
              "checks": {}, "reasons": []}
        stmt = a.get("statement")
        receipt = a.get("receipt")
        cs = a.get("checkpoint_seq")
        sig_ok, sig_reasons, anchor_hash = verify_statement_sig(stmt)
        ep["checks"]["statement_sig"] = sig_ok
        ep["reasons"].extend(sig_reasons)
        if anchor_hash is None:
            ep["reasons"].append("anchor hash could not be computed "
                                 "(statement unusable)")
            report["epochs"].append(ep)
            continue
        if a.get("anchor_hash") != anchor_hash:
            ep["checks"]["anchor_hash_bind"] = False
            ep["reasons"].append("bundle's anchor_hash != hash of the "
                                 "signed statement")
        else:
            ep["checks"]["anchor_hash_bind"] = True
        # statement-chain continuity (over sig-valid statements only).
        if sig_ok:
            prev = (stmt or {}).get("prev_anchor")
            if prev != expect_prev:
                ep["checks"]["statement_chain"] = False
                ep["reasons"].append(
                    "statement prev_anchor breaks the anchor chain "
                    "(forked or out-of-order anchor history)")
            else:
                ep["checks"]["statement_chain"] = True
            expect_prev = anchor_hash
        # head binding: CONSISTENCY ONLY (stated in the boundaries).
        entry = by_seq.get(cs) if isinstance(cs, int) else None
        if entry is None:
            ep["checks"]["head_consistency"] = "CANNOT-VERIFY"
            ep["reasons"].append("checkpoint seq %r is not in the "
                                 "exported chain segment" % (cs,))
        elif entry.get("hash") != (stmt or {}).get("head_hash"):
            ep["checks"]["head_consistency"] = "MISMATCH"
            ep["reasons"].append(
                "statement head_hash != the exported entry's hash "
                "field at seq %d (consistency failure)" % cs)
        else:
            ep["checks"]["head_consistency"] = "MATCH"
        # witness receipt (cryptographic, witness UNTRUSTED).
        r_ok, r_reasons = verify_fake_witness_receipt(
            receipt, anchor_hash, witness)
        ep["checks"]["receipt"] = r_ok
        ep["reasons"].extend(r_reasons)
        if not ep["reasons"] and all(
                v is True or v == "MATCH"
                for v in ep["checks"].values()):
            ep["grade"] = "ANCHORED"
        report["epochs"].append(ep)

    # -- the open epoch (the soft window) ------------------------------
    last_close = max(
        [e["checkpoint_seq"] for e in report["epochs"]
         if isinstance(e.get("checkpoint_seq"), int)] or [0])
    tail = len(entries)
    report["open_epoch"] = {
        "start_seq": last_close + 1,
        "tail_seq": tail,
        "unanchored_records": max(0, tail - last_close),
        "grade": "OPERATOR-ATTESTED-ONLY",
        "note": "records after the last anchor: the unverifiable soft "
                "window (see honest boundaries).",
    }

    # -- attribution (who did / approved what) --------------------------
    att = bundle.get("attribution") or {}
    a_details = []
    a_ok = True
    identities = att.get("identities")
    approvals = att.get("approvals")
    chain_agents = sorted({str(e.get("agent_id")) for e in entries
                           if e.get("agent_id")})
    if not isinstance(identities, list) or not identities:
        a_details.append("no identities exported")
        a_ok = False
    else:
        id_agents = {str(i.get("agent_id")) for i in identities
                     if isinstance(i, dict)}
        missing = [a for a in chain_agents if a not in id_agents]
        if missing:
            a_details.append("agents in the chain with no exported "
                             "identity: %s" % missing)
            a_ok = False
        else:
            a_details.append("%d identities cover all %d agents seen "
                             "in the chain" % (len(identities),
                                               len(chain_agents)))
    chain_approvals = {
        e.get("approval_id"): e for e in entries
        if e.get("event") == "approval_decision" and e.get("approval_id")}
    if not isinstance(approvals, list):
        a_details.append("approvals export is not a list")
        a_ok = False
    else:
        bad = []
        for ap in approvals:
            if not isinstance(ap, dict):
                bad.append("non-object approval row")
                continue
            aid = ap.get("approval_id")
            ce = chain_approvals.get(aid)
            if ce is None:
                bad.append("approval %r not found in the chain" % (aid,))
            elif (str(ce.get("decision")) != str(ap.get("decision"))
                  or str(ce.get("decided_by"))
                  != str(ap.get("decided_by"))):
                bad.append("approval %r disagrees with the chain "
                           "record" % (aid,))
        if bad:
            a_details.extend(bad)
            a_ok = False
        else:
            a_details.append("%d approval decision(s): who approved "
                             "what cross-checks against the chain "
                             "(decided_by + decision match)" % len(approvals))
    report["attribution"]["details"] = a_details
    report["attribution"]["verdict"] = "PASS" if a_ok else "CANNOT-VERIFY"

    # -- the stopped attack ---------------------------------------------
    s_details = []
    trips = [e for e in entries
             if e.get("event") == "canary_trip"
             and e.get("decision") == "halted"]
    if not trips:
        s_details.append("no canary_trip (halted) record in the chain")
        report["stopped_attack"]["verdict"] = "FAIL"
    else:
        trip = trips[0]
        s_details.append(
            "stopped-attack record present: seq %s, agent %s, tool %s, "
            "decision %s, flag %s" % (
                trip.get("seq"), trip.get("agent_id"), trip.get("tool"),
                trip.get("decision"), trip.get("flag")))
        if isinstance(trip.get("seq"), int) and trip["seq"] <= last_close:
            s_details.append(
                "the trip record sits at seq %d, inside the anchored "
                "range (<= last anchored checkpoint %d): chained to an "
                "anchored head" % (trip["seq"], last_close))
            report["stopped_attack"]["verdict"] = "PASS"
        else:
            s_details.append(
                "the trip record is AFTER the last anchored checkpoint: "
                "present, but operator-attested-only until the next "
                "anchor")
            report["stopped_attack"]["verdict"] = "ATTESTED-ONLY"
    report["stopped_attack"]["details"] = s_details

    # -- ungoverned bypass declarations (wave-85) -------------------------
    # Every declared skip of the construction checklist, and every
    # refused attempt, rendered LOUDLY: an auditor must not be able to
    # miss that part of this run executed outside the governed core.
    bypass_decls = []
    bypass_refusals = []
    for e in entries:
        ev = e.get("event")
        if ev == "ungoverned_bypass":
            bypass_decls.append({
                "seq": e.get("seq"),
                "reason": e.get("ungoverned_reason"),
                "missing_components": e.get("missing_components"),
                "absent_non_core_components": e.get(
                    "absent_non_core_components"),
                "deployment_mode": e.get("deployment_mode"),
                "caller": "%s:%s in %s" % (
                    e.get("caller_file"), e.get("caller_line"),
                    e.get("caller_function")),
            })
        elif ev == "ungoverned_bypass_refused":
            bypass_refusals.append({
                "seq": e.get("seq"),
                "cause": e.get("refusal_cause"),
                "missing_components": e.get("missing_components"),
                "absent_non_core_components": e.get(
                    "absent_non_core_components"),
                "caller": "%s:%s in %s" % (
                    e.get("caller_file"), e.get("caller_line"),
                    e.get("caller_function")),
            })
    if bypass_decls:
        bypass_verdict = "DECLARED"
    elif bypass_refusals:
        bypass_verdict = "REFUSED-ONLY"
    else:
        bypass_verdict = "NONE"
    report["ungoverned_bypasses"] = {
        "verdict": bypass_verdict,
        "declarations": bypass_decls,
        "refusals": bypass_refusals,
    }

    return report


def render_report(report):
    """Plain-language auditor report."""
    L = []
    L.append("=" * 70)
    L.append("EVIDENCE VERIFICATION REPORT — independent verifier")
    L.append("Bundle: %s" % report["bundle_dir"])
    L.append("Run: %s" % (report["run_id"] or "unknown"))
    L.append("=" * 70)
    L.append("")
    L.append("WHAT THIS VERIFIER CAN AND CANNOT DO")
    L.append("-" * 70)
    for b in report["honest_boundaries"]:
        L.append("  * " + b)
    L.append("")
    if not report["bundle_ok"]:
        L.append("BUNDLE: CANNOT-VERIFY")
        for e in report["bundle_errors"]:
            L.append("  - " + e)
        L.append("")
        L.append("No further checks were possible. See the honest "
                 "boundaries above.")
        return "\n".join(L)

    L.append("ANCHOR EPOCHS (%d checked)" % len(report["epochs"]))
    L.append("-" * 70)
    if not report["epochs"]:
        L.append("  No anchor records in the bundle: every record is "
                 "OPERATOR-ATTESTED-ONLY.")
    for ep in report["epochs"]:
        grade = ep["grade"]
        L.append("  Epoch %s (checkpoint seq %s): %s"
                 % (ep["epoch_id"], ep["checkpoint_seq"], grade))
        for name, val in ep["checks"].items():
            mark = ("ok" if val is True or val == "MATCH"
                    else ("n/a" if val == "CANNOT-VERIFY" else "FAILED"))
            L.append("    - %-18s %s" % (name, mark))
        for r in ep["reasons"]:
            L.append("    ! " + r)
    oe = report["open_epoch"]
    L.append("  Open epoch (seqs %d..%d): %s — %d unanchored record(s)"
             % (oe["start_seq"], oe["tail_seq"], oe["grade"],
                oe["unanchored_records"]))
    L.append("")

    L.append("ATTRIBUTION (who did what, who approved what): %s"
             % report["attribution"]["verdict"])
    L.append("-" * 70)
    for d in report["attribution"]["details"]:
        L.append("  - " + d)
    L.append("  Note: agent_id / role / principal fields are "
             "operator-written chain content — this verifier checks they "
             "are PRESENT and consistent, not that they are true.")
    L.append("")

    L.append("STOPPED ATTACK: %s" % report["stopped_attack"]["verdict"])
    L.append("-" * 70)
    for d in report["stopped_attack"]["details"]:
        L.append("  - " + d)
    L.append("")

    # Wave-85: the construction seam, rendered LOUD. A declared bypass
    # is not hidden in the chain noise — the auditor sees every skip
    # of the checklist, the stated reason, what was missing, and who
    # declared it from where.
    ub = report.get("ungoverned_bypasses") or {}
    ub_verdict = ub.get("verdict", "NONE")
    L.append("UNGOVERNED BYPASS DECLARATIONS: %s%s"
             % (ub_verdict,
                " — AUDITOR ATTENTION REQUIRED"
                if ub_verdict == "DECLARED" else ""))
    L.append("-" * 70)
    if ub_verdict == "NONE":
        L.append("  None: no executor construction in this chain skipped "
                 "the governed core.")
    elif ub_verdict == "CANNOT-VERIFY":
        L.append("  Cannot verify: the bundle's chain could not be parsed, "
                 "so no bypass determination was possible.")
    for d in ub.get("declarations") or []:
        L.append("  !!! BYPASS DECLARED at seq %s:" % (d.get("seq"),))
        L.append("      reason: %r" % (d.get("reason"),))
        L.append("      missing governed core: %s"
                 % (d.get("missing_components"),))
        if d.get("absent_non_core_components"):
            L.append("      also absent (deployment choices, not bypasses): %s"
                     % (d.get("absent_non_core_components"),))
        L.append("      deployment mode: %s" % (d.get("deployment_mode"),))
        L.append("      declared by: %s" % (d.get("caller"),))
        L.append("      meaning: this run's verdicts carry NO governed "
                 "policy-change lineage and NO delegation-identity gate.")
    for r_ in ub.get("refusals") or []:
        L.append("  [refused] ungoverned construction attempt at seq %s: "
                 "cause %s; missing %s; attempted by %s"
                 % (r_.get("seq"), r_.get("cause"),
                    r_.get("missing_components"), r_.get("caller")))
    L.append("")

    anchored = sum(1 for e in report["epochs"]
                   if e["grade"] == "ANCHORED")
    L.append("AUDIT VERDICT")
    L.append("-" * 70)
    L.append("  %d of %d anchored epoch(s) verified ANCHORED; %d "
             "operator-attested-only."
             % (anchored, len(report["epochs"]),
                len(report["epochs"]) - anchored))
    L.append("  Attribution: %s. Stopped attack: %s."
             % (report["attribution"]["verdict"],
                report["stopped_attack"]["verdict"]))
    L.append("  Open epoch: %d record(s) unverifiable until the next "
             "anchor." % oe["unanchored_records"])
    L.append("")
    L.append("HONEST BOUNDARIES (repeated — this is the point)")
    L.append("-" * 70)
    for b in report["honest_boundaries"]:
        L.append("  * " + b)
    L.append("")
    return "\n".join(L)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Independently verify an exported evidence bundle.")
    parser.add_argument("--bundle", required=True,
                        help="bundle directory (bundle.json + witness.json)")
    args = parser.parse_args(argv)
    try:
        report = verify_bundle(args.bundle)
    except Exception as e:  # truly unexpected: honest failure, never a
        # traceback-only death — the auditor gets a verdict, not a crash.
        print("EVIDENCE VERIFICATION REPORT — independent verifier")
        print("VERDICT: CANNOT-VERIFY — the verifier itself failed: %s: %s"
              % (type(e).__name__, e))
        print("No claim is made about the bundle.")
        return 1
    print(render_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
