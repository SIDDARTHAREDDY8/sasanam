"""Adversarial re-run: H24 anchor adapter conformance (break-first).

Targets gov/anchor_adapter.py:
  p1 EQUIVOCATION: anchor conflicting bundles under same bundle_id ->
     must raise EquivocationError.
  p2 NO-BUNDLE-ID: two different bundles without bundle_id -> both
     anchor (append-only, not equivocation). Control: correct behavior.
  p3 MALFORMED: verify_receipt with garbage -> (False, reason), never
     raises. Control.
  p4 REKOR-MALICIOUS-TRANSPORT: transport returns valid-shaped proof
     for a DIFFERENT bundle -> verify must fail on statement mismatch.
  p5 STATEMENT-MALLEABILITY: bundles differing only in key order or
     whitespace produce identical statements (canonical JSON). Control:
     this is correct (not a break).

Verdicts are honest: BREAK = vulnerability found (file as F176+),
HELD = control holds.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov.anchor_adapter import (
    FakeLogAdapter, RekorStubAdapter, mock_rekor_transport,
    bundle_statement, AnchorError, EquivocationError,
)

RESULTS = []


def _report(name, verdict, detail):
    RESULTS.append((name, verdict, detail))
    print("  %-28s %s  %s" % (name, verdict, detail))


def _bundle(i, extra=None):
    b = {"bundle_id": "b%d" % i, "entries": [{"seq": i}],
         "tip": "tip%d" % i}
    if extra:
        b.update(extra)
    return b


def p1_equivocation():
    name = "p1_equivocation_raises"
    a = FakeLogAdapter(os.urandom(32))
    a.anchor(_bundle(1))
    try:
        a.anchor(_bundle(1, {"entries": [{"seq": 999}]}))
        _report(name, "BREAK",
                "conflicting bundle under same bundle_id anchored "
                "without EquivocationError")
    except EquivocationError:
        _report(name, "HELD", "EquivocationError raised (control holds)")
    except Exception as e:
        _report(name, "BREAK",
                "wrong exception: %s" % (type(e).__name__,))


def p2_no_bundle_id():
    name = "p2_no_bundle_id_appends"
    a = FakeLogAdapter(os.urandom(32))
    b1 = {"entries": [{"seq": 1}]}
    b2 = {"entries": [{"seq": 2}]}
    r1 = a.anchor(b1)
    r2 = a.anchor(b2)
    if r1["log_index"] != r2["log_index"]:
        _report(name, "HELD",
                "distinct bundles append at distinct indices (correct)")
    else:
        _report(name, "BREAK", "index collision")


def p3_malformed():
    name = "p3_malformed_never_raises"
    a = FakeLogAdapter(os.urandom(32))
    bad_receipts = [None, "string", 42, {}, {"adapter": "fake-log"},
                    {"adapter": "fake-log", "log_id": "x" * 64}]
    for i, br in enumerate(bad_receipts):
        try:
            ok, err = a.verify_receipt(br, _bundle(1))
            if ok:
                _report(name, "BREAK",
                        "malformed receipt %d verified True" % i)
                return
        except Exception as e:
            _report(name, "BREAK",
                    "verify_receipt raised on malformed input: %s"
                    % (type(e).__name__,))
            return
    _report(name, "HELD", "all malformed receipts -> (False, reason)")


def p4_rekor_malicious_transport():
    name = "p4_rekor_transport_confusion"
    # Malicious transport: returns a valid-shaped proof, but for a
    # DIFFERENT bundle's hash than the one proposed.
    def evil_transport(proposed):
        return {
            "logIndex": 0,
            "verification": {
                "signedEntryTimestamp": "evil",
                "inclusionProof": {
                    "logIndex": 0,
                    "rootHash": "a" * 64,
                    "treeSize": 1,
                    "hashes": ["evil"],
                },
            },
        }
    r = RekorStubAdapter(evil_transport)
    bundle_a = _bundle(10)
    receipt = r.anchor(bundle_a)  # transport ignores proposed, returns evil
    # Verify receipt against a DIFFERENT bundle.
    bundle_b = _bundle(11)
    ok, err = r.verify_receipt(receipt, bundle_b)
    if ok:
        _report(name, "BREAK",
                "rekor-stub receipt verified for wrong bundle "
                "(transport confusion)")
    else:
        _report(name, "HELD",
                "statement mismatch caught: %s" % (str(err)[:60],))


def p5_statement_canonical():
    name = "p5_statement_canonical"
    b1 = {"z": 1, "a": 2, "entries": [{"seq": 1}]}
    b2 = {"a": 2, "entries": [{"seq": 1}], "z": 1}
    s1 = bundle_statement(b1)
    s2 = bundle_statement(b2)
    if s1 == s2:
        _report(name, "HELD",
                "key-order-independent canonical statements (correct)")
    else:
        _report(name, "BREAK", "non-canonical statements")


def main():
    print("ADVERSARIAL H24 anchor-adapter battery (break-first)")
    p1_equivocation()
    p2_no_bundle_id()
    p3_malformed()
    p4_rekor_malicious_transport()
    p5_statement_canonical()
    n_break = sum(1 for _, v, _ in RESULTS if v == "BREAK")
    n_held = sum(1 for _, v, _ in RESULTS if v == "HELD")
    print("ADVERSARIAL-H24: %d BREAK / %d HELD / 0 ERROR" % (n_break, n_held))
    if n_break:
        print("NOTE: BREAKs are CANDIDATE findings (file as F176+), "
              "not residuals.")
    return 0 if n_break == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
