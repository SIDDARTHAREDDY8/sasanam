#!/usr/bin/env python3
"""Wave-234 lane C: at-most-once consumption ledger for grants/approvals/receipts.

Attack shapes at the public seams (break-first, red-first on base):
* a consumed authorization instance resubmitted with the full invocation
  envelope must yield the named outcome ``previously-consumed`` -- replay
  is explicit, never a silent release;
* the ledger is keyed to the digest of the FROZEN authorization instance,
  never to an approval id appearing in a record: replaying a closed
  instance's approval id inside a fresh record refuses as consumed and
  does NOT release;
* two grants sharing an idempotency key but targeting different entities
  must NOT collide (EMILIA's sha256(ref:type) regression): idempotency
  keys are length-prefixed, NUL-joined, entity-bound;
* the consumption receipt digest binds the instance: a tampered receipt
  refuses ``consumption-receipt-tampered``;
* crash semantics are write-ahead: the consumption record commits
  (append + fsync) BEFORE release is allowed, so a restarted ledger over
  the same journal reads the instance as consumed, never double-releasable;
* malformed instance digests / key parts refuse with named codes;
* the in-repo SingleUseRegistry is wired additively (no behavior change):
  the adapter commits to the ledger journal BEFORE the registry marks
  consumed.

Seams under test:
* gov/consumption_ledger.py -- ConsumptionLedger.consume /
  is_consumed / consumption_receipt / verify_receipt,
  build_idempotency_key, SingleUseConsumptionAdapter.

Method (diagnosing-bugs): deterministic, minimal, against pushed
wave-233 HEAD 55d588664180cbe4657a07c4342df680c28cdc54.

Verdicts: HELD / GAP / BREAK / ERROR. Pristine run (module absent)
is expected GAP for every probe.

$0 spend. No network. stdlib only. Real product code, no stubs.
No in-repo git subprocess pins.

Run:
  mkdir -p /var/tmp/g234c
  TMPDIR=/var/tmp/g234c ~/workspace/.gov-venv/bin/python evals/w234_consumed_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import sys
import tempfile
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

HAVE_NEW_API = False
try:
    from gov import consumption_ledger as _cl
    HAVE_NEW_API = all(hasattr(_cl, n) for n in (
        "ConsumptionLedger", "ConsumptionError",
        "build_idempotency_key", "SingleUseConsumptionAdapter"))
except ImportError:
    _cl = None

PROBE_NAMES = [
    "consumed-first-consume-releases-receipt",
    "consumed-replay-returns-previously-consumed",
    "consumed-approval-id-replay-refused",
    "consumed-cross-entity-key-no-collision",
    "consumed-idempotency-reuse-refused",
    "consumed-receipt-digest-binds-instance",
    "consumed-write-ahead-survives-restart",
    "consumed-malformed-inputs-refused",
    "consumed-single-use-adapter-wires",
]


def _inst(approval_id, details):
    body = {"approval_id": approval_id, "details": details}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")).hexdigest()


def _expect_code(fn, code):
    """Run fn; return ("HELD", detail) iff a ConsumptionError with the
    exact machine code is raised, else ("BREAK"/"ERROR", detail)."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - battery records, never masks
        got = getattr(exc, "code", None)
        if got is None:
            got = type(exc).__name__
        if got == code:
            return ("HELD", "raised %r" % (got,))
        return ("BREAK", "wrong code: %r (want %r): %s"
                % (got, code, str(exc)[:160]))
    return ("BREAK", "no refusal raised (want %r)" % (code,))


def _rec(results, name, verdict, detail=""):
    results[name] = verdict if not detail else "%s\n  %s" % (verdict, detail)


def _p1_first_consume(results):
    try:
        ledger = _cl.ConsumptionLedger()
        d = _inst("appr-1", {"tool": "git", "args": ["push"]})
        parts = ("approval", "tool", "git", "req-1")
        receipt = ledger.consume(d, parts)
        assert receipt["outcome"] == "consumed", receipt
        assert receipt["instance_digest"] == d, receipt
        assert len(receipt["receipt_digest"]) == 64, receipt
        assert ledger.is_consumed(d) is True
        assert _cl.ConsumptionLedger.verify_receipt(receipt) is True
        _rec(results, PROBE_NAMES[0], "HELD",
             "receipt_digest=%s..." % receipt["receipt_digest"][:16])
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[0], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[0], "ERROR", traceback.format_exc(limit=2))


def _p2_replay(results):
    try:
        ledger = _cl.ConsumptionLedger()
        d = _inst("appr-2", {"tool": "git", "args": ["push"]})
        parts = ("approval", "tool", "git", "req-2")
        first = ledger.consume(d, parts)
        try:
            ledger.consume(d, parts)
            _rec(results, PROBE_NAMES[1], "BREAK",
                 "second consume released silently")
            return
        except _cl.ConsumptionError as exc:
            if exc.code != "previously-consumed":
                _rec(results, PROBE_NAMES[1], "BREAK",
                     "wrong code %r" % (exc.code,))
                return
            # The named outcome carries the original receipt: the replay
            # is explicit, never a silent new release.
            assert getattr(exc, "receipt", None) == first, \
                "replay error must carry the original receipt"
        assert ledger.is_consumed(d) is True
        _rec(results, PROBE_NAMES[1], "HELD",
             "named outcome previously-consumed, original receipt carried")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[1], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[1], "ERROR", traceback.format_exc(limit=2))


def _p3_approval_id_replay(results):
    try:
        ledger = _cl.ConsumptionLedger()
        d = _inst("appr-3", {"tool": "ssh", "host": "bastion"})
        parts = ("approval", "tool", "ssh", "req-3")
        ledger.consume(d, parts)
        # (a) The approval id alone is not a ledger key: there is no
        # by-approval-id API; presenting it refuses as malformed and
        # releases nothing.
        v, detail = _expect_code(
            lambda: ledger.consume("appr-3", parts),
            "consumption-instance-malformed")
        assert v == "HELD", detail
        # (b) A fresh record wrapper replaying the closed instance's
        # approval id recomputes the SAME frozen-instance digest and is
        # refused as consumed -- keyed to the digest, not the id.
        fresh = {"approval_id": "appr-3",
                 "details": {"tool": "ssh", "host": "bastion"}}
        d2 = hashlib.sha256(
            json.dumps(fresh, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8")).hexdigest()
        assert d2 == d, "frozen-instance digest must bind the replayed id"
        v, detail = _expect_code(
            lambda: ledger.consume(d2, parts), "previously-consumed")
        assert v == "HELD", detail
        assert ledger.is_consumed(d) is True
        _rec(results, PROBE_NAMES[2], "HELD",
             "id alone malformed; digest-keyed replay refused as consumed")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[2], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[2], "ERROR", traceback.format_exc(limit=2))


def _p4_cross_entity(results):
    try:
        # Same raw key tail, different entity: must NOT collide (EMILIA).
        k1 = _cl.build_idempotency_key("approval", "tool", "git", "req-7")
        k2 = _cl.build_idempotency_key("approval", "tool", "ssh", "req-7")
        assert k1 != k2, "entity binding must separate the keys"
        assert _cl.build_idempotency_key("approval", "tool", "git", "req-7") \
            == k1, "key derivation must be deterministic"
        ledger = _cl.ConsumptionLedger()
        d1 = _inst("appr-4a", {"tool": "git"})
        d2 = _inst("appr-4b", {"tool": "ssh"})
        r1 = ledger.consume(d1, ("approval", "tool", "git", "req-7"))
        r2 = ledger.consume(d2, ("approval", "tool", "ssh", "req-7"))
        assert r1["bound_key_digest"] == k1
        assert r2["bound_key_digest"] == k2
        assert r1["receipt_digest"] != r2["receipt_digest"]
        _rec(results, PROBE_NAMES[3], "HELD",
             "two entities, one raw key tail: both released, no collision")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[3], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[3], "ERROR", traceback.format_exc(limit=2))


def _p5_idempotency_reuse(results):
    try:
        ledger = _cl.ConsumptionLedger()
        parts = ("approval", "tool", "git", "req-8")
        d1 = _inst("appr-5a", {"tool": "git", "args": ["push"]})
        d2 = _inst("appr-5b", {"tool": "git", "args": ["pull"]})
        ledger.consume(d1, parts)
        # Same entity-bound key, DIFFERENT frozen instance: the key was
        # reused for a different authorization -- fail closed, do not
        # release under the first instance's receipt.
        v, detail = _expect_code(
            lambda: ledger.consume(d2, parts),
            "consumption-idempotency-reused")
        assert v == "HELD", detail
        assert ledger.is_consumed(d1) is True
        assert ledger.is_consumed(d2) is False
        _rec(results, PROBE_NAMES[4], "HELD",
             "reused key on a new instance refused; nothing released")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[4], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[4], "ERROR", traceback.format_exc(limit=2))


def _p6_receipt_tamper(results):
    try:
        ledger = _cl.ConsumptionLedger()
        d = _inst("appr-6", {"tool": "git"})
        receipt = ledger.consume(d, ("approval", "tool", "git", "req-9"))
        bad = dict(receipt)
        bad["instance_digest"] = "00" * 32
        v, detail = _expect_code(
            lambda: _cl.ConsumptionLedger.verify_receipt(bad),
            "consumption-receipt-tampered")
        assert v == "HELD", detail
        bad2 = dict(receipt)
        del bad2["receipt_digest"]
        v, detail = _expect_code(
            lambda: _cl.ConsumptionLedger.verify_receipt(bad2),
            "consumption-receipt-malformed")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[5], "HELD",
             "tampered receipt refused; missing digest refused")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[5], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[5], "ERROR", traceback.format_exc(limit=2))


def _p7_write_ahead(results):
    try:
        tmp = tempfile.mkdtemp(prefix="w234-journal-")
        journal = os.path.join(tmp, "consumed.jsonl")
        d = _inst("appr-7", {"tool": "git"})
        parts = ("approval", "tool", "git", "req-10")
        first = _cl.ConsumptionLedger(journal_path=journal)
        r1 = first.consume(d, parts)
        # "Restart": a new ledger object over the same journal. The
        # write-ahead commit means the instance reads consumed --
        # never double-releasable.
        second = _cl.ConsumptionLedger(journal_path=journal)
        assert second.is_consumed(d) is True, \
            "restarted ledger must read the instance as consumed"
        assert second.consumption_receipt(d)["receipt_digest"] == \
            r1["receipt_digest"], "restarted ledger must return the " \
            "original receipt, not mint a new one"
        v, detail = _expect_code(
            lambda: second.consume(d, parts), "previously-consumed")
        assert v == "HELD", detail
        _rec(results, PROBE_NAMES[6], "HELD",
             "journal replay marks consumed across restart")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[6], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[6], "ERROR", traceback.format_exc(limit=2))


def _p8_malformed(results):
    try:
        ledger = _cl.ConsumptionLedger()
        v, detail = _expect_code(
            lambda: ledger.consume("not-a-digest",
                                   ("approval", "tool", "x", "r")),
            "consumption-instance-malformed")
        assert v == "HELD", detail
        v, detail = _expect_code(
            lambda: ledger.consume("ab" * 32, ()),
            "consumption-key-malformed")
        assert v == "HELD", detail
        v, detail = _expect_code(
            lambda: ledger.consume("ab" * 32, ("only-one",)),
            "consumption-key-malformed")
        assert v == "HELD", detail
        v, detail = _expect_code(
            lambda: ledger.consume("ab" * 32,
                                   ("approval", "tool", "", "r")),
            "consumption-key-malformed")
        assert v == "HELD", detail
        assert ledger.is_consumed("ab" * 32) is False
        _rec(results, PROBE_NAMES[7], "HELD",
             "malformed digest and key parts refused; nothing marked")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[7], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[7], "ERROR", traceback.format_exc(limit=2))


def _p9_adapter(results):
    try:
        from gov import single_use as _su
        tmp = tempfile.mkdtemp(prefix="w234-adapter-")
        journal = os.path.join(tmp, "consumed.jsonl")
        reg = _su.SingleUseRegistry()
        ledger = _cl.ConsumptionLedger(journal_path=journal)
        adapter = _cl.SingleUseConsumptionAdapter(reg, ledger)
        att = hashlib.sha256(b"attestation-9").hexdigest()
        record = reg.issue(att, "issuer-9", "nonce-9")
        receipt, evidence = adapter.consume_attestation(record)
        assert evidence["kind"] == "single-use-attestation", evidence
        assert evidence["jti"] == record["jti"], evidence
        assert receipt["outcome"] == "consumed", receipt
        assert ledger.is_consumed(receipt["instance_digest"]) is True
        # Journal has the write-ahead entry.
        with open(journal, "r", encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        assert len(lines) == 1, lines
        # Second consume: the ledger refuses BEFORE the registry is
        # touched -- previously-consumed is the persistent outcome.
        v, detail = _expect_code(
            lambda: adapter.consume_attestation(record),
            "previously-consumed")
        assert v == "HELD", detail
        # Fail-closed orphan contract: an attestation the registry never
        # issued (well-formed, properly derived jti, but unknown here)
        # refuses at the registry, but the ledger already committed --
        # the digest reads consumed and never releases.
        reg_other = _su.SingleUseRegistry()
        bad = reg_other.issue(att, "issuer-9", "nonce-never-issued-here")
        try:
            adapter.consume_attestation(bad)
            _rec(results, PROBE_NAMES[8], "BREAK",
                 "unissued attestation was not refused")
            return
        except Exception as exc:  # noqa: BLE001 - expected refusal
            assert getattr(exc, "code", None) in (
                "single-use-unknown", "single-use-malformed"), \
                "registry must refuse the unissued record, got %r" % (
                    getattr(exc, "code", None),)
        orphan = hashlib.sha256(
            json.dumps(bad, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("utf-8")).hexdigest()
        assert ledger.is_consumed(orphan) is True, \
            "orphan journal entry must read consumed (fail closed)"
        _rec(results, PROBE_NAMES[8], "HELD",
             "adapter commits write-ahead; registry behavior unchanged; "
             "orphan entries fail closed")
    except AssertionError as exc:
        _rec(results, PROBE_NAMES[8], "BREAK", str(exc)[:200])
    except Exception:  # noqa: BLE001
        _rec(results, PROBE_NAMES[8], "ERROR", traceback.format_exc(limit=2))


def _run_all():
    results = {}
    _p1_first_consume(results)
    _p2_replay(results)
    _p3_approval_id_replay(results)
    _p4_cross_entity(results)
    _p5_idempotency_reuse(results)
    _p6_receipt_tamper(results)
    _p7_write_ahead(results)
    _p8_malformed(results)
    _p9_adapter(results)
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
    if not HAVE_NEW_API:
        rows = [{"probe_id": name, "verdict": "BREAK",
                 "note": "GAP (consumption ledger module absent)"} for name in PROBE_NAMES]
        probe_lines.emit_dicts(rows)
        print("%d BREAK / %d HELD / %d ERROR" % (len(PROBE_NAMES), 0, 0))
        return 2
    results = _run_all()
    def _v(name):
        return results.get(name, "ERROR: missing").split("\n")[0]
    held = sum(1 for name in PROBE_NAMES if _v(name) == "HELD")
    gap = sum(1 for name in PROBE_NAMES if _v(name).startswith("GAP"))
    brk = sum(1 for name in PROBE_NAMES if _v(name).startswith("BREAK"))
    err = sum(1 for name in PROBE_NAMES if _v(name).startswith("ERROR"))
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
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
