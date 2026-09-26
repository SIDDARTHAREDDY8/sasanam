"""H24: anchor-adapter conformance battery.

The same suite runs against every AnchorAdapter implementation
(FakeLogAdapter, RekorStubAdapter, and any future live Rekor adapter).
GREEN = the adapter satisfies the interface contract; no network is used.

Run: python evals/anchor_adapter_conformance.py
"""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import anchor_adapter as aa


def _bundle(i, **kw):
    b = {"bundle_id": "bundle-%d" % i,
         "format": "evidence-bundle/1.1",
         "entries": [{"seq": i, "note": "test"}]}
    b.update(kw)
    return b


def run_conformance(make_adapter, label):
    """Run the full conformance suite against ``make_adapter()``.

    Returns (passed, failed, notes). ``make_adapter`` is a zero-arg
    factory returning a fresh AnchorAdapter.
    """
    passed, failed, notes = 0, 0, []

    def check(name, cond, note=""):
        nonlocal passed, failed
        if cond:
            passed += 1
        else:
            failed += 1
            notes.append("FAIL %s: %s" % (name, note))

    # c1: anchor returns a receipt dict naming the adapter.
    a = make_adapter()
    b1 = _bundle(1)
    try:
        r1 = a.anchor(b1)
        check("c1_receipt_shape",
              isinstance(r1, dict) and r1.get("adapter") == a.name,
              "receipt=%r" % (r1,))
    except Exception as e:
        check("c1_receipt_shape", False, "raised %r" % (e,))
        r1 = None

    # c2: the receipt verifies against the anchored bundle.
    if r1 is not None:
        ok, err = a.verify_receipt(r1, b1)
        check("c2_receipt_verifies", ok, err or "")
    else:
        check("c2_receipt_verifies", False, "no receipt from c1")

    # c3: idempotent re-anchor of the identical bundle.
    try:
        r1b = a.anchor(b1)
        ok, err = a.verify_receipt(r1b, b1)
        check("c3_idempotent_reanchor", ok, err or "")
    except Exception as e:
        # Idempotency is a SHOULD, not a MUST: an adapter may return a
        # fresh receipt per submission as long as each verifies.
        check("c3_idempotent_reanchor", False, "raised %r" % (e,))

    # c4: a different bundle anchors to a different statement.
    b2 = _bundle(2)
    try:
        r2 = a.anchor(b2)
        check("c4_distinct_bundle_distinct_statement",
              r2.get("statement") != r1.get("statement"),
              "statements collide")
    except Exception as e:
        check("c4_distinct_bundle_distinct_statement", False,
              "raised %r" % (e,))

    # c5: tampered receipt does not verify.
    if r1 is not None:
        bad = dict(r1)
        bad["statement"] = dict(r1.get("statement") or {})
        bad["statement"]["bundle_hash"] = "0" * 64
        ok, _ = a.verify_receipt(bad, b1)
        check("c5_tampered_receipt_rejected", not ok,
              "tampered receipt verified")
        ok2, _ = a.verify_receipt(r1, b2)
        check("c5b_receipt_wrong_bundle_rejected", not ok2,
              "receipt verified against the wrong bundle")
    else:
        check("c5_tampered_receipt_rejected", False, "no receipt from c1")
        check("c5b_receipt_wrong_bundle_rejected", False, "no receipt")

    # c6: malformed bundle raises ValueError (fail-closed, not a receipt).
    for bad_bundle in (None, "nope", 42, ["list"]):
        try:
            a.anchor(bad_bundle)
            check("c6_malformed_bundle_rejected", False,
                  "no raise for %r" % (bad_bundle,))
        except ValueError:
            check("c6_malformed_bundle_rejected", True)
        except Exception as e:
            check("c6_malformed_bundle_rejected", False,
                  "wrong exception %r" % (e,))

    # c7: malformed receipt never verifies (and never raises).
    for bad_receipt in (None, {}, {"adapter": "nope"}):
        try:
            ok, _ = a.verify_receipt(bad_receipt, b1)
            check("c7_malformed_receipt_rejected", not ok,
                  "bad receipt verified: %r" % (bad_receipt,))
        except Exception as e:
            check("c7_malformed_receipt_rejected", False,
                  "raised %r" % (e,))

    return passed, failed, notes


def main():
    total_p, total_f, all_notes = 0, 0, []

    p, f, notes = run_conformance(
        lambda: aa.FakeLogAdapter(b"\x50" * 32), "fake-log")
    print("fake-log adapter: %d passed / %d failed" % (p, f))
    total_p += p; total_f += f; all_notes += notes

    p, f, notes = run_conformance(
        lambda: aa.RekorStubAdapter(aa.mock_rekor_transport()),
        "rekor-stub")
    print("rekor-stub adapter: %d passed / %d failed" % (p, f))
    total_p += p; total_f += f; all_notes += notes

    # Equivocation is adapter-specific (fake-log enforces it).
    a = aa.FakeLogAdapter(b"\x51" * 32)
    b = _bundle(9)
    a.anchor(b)
    evil = _bundle(9, entries=[{"seq": 9, "note": "forged"}])
    try:
        a.anchor(evil)
        print("equivocation: FAIL (no refusal)")
        total_f += 1
    except aa.EquivocationError:
        print("equivocation: refused (EquivocationError)")
        total_p += 1
    except Exception as e:
        print("equivocation: FAIL (wrong exception %r)" % (e,))
        total_f += 1

    for n in all_notes:
        print(" ", n)
    print("CONFORMANCE: %d passed / %d failed" % (total_p, total_f))
    return 1 if total_f else 0


if __name__ == "__main__":
    sys.exit(main())
