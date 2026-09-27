#!/usr/bin/env python3
"""Row-6/14 break round v2: adversarial probes against the two shipped seams.

TARGET 1: ``SkillWatch.fetch_verified_at_use`` (gov/skill_watch.py) — the
fetch-once handoff: the returned bytes must be EXACTLY the bytes hashed
against the pin, with a single observation (no check/use split for a
hostile source to equivocate on).

TARGET 2: strict deployment-anchored ``ToolInventory``
(gov/tool_continuity.py) — ``strict=True`` compares provider bytes
against the deployment table's digest, never first-observed bytes.

Verdicts:
- BREAK    = an attack defeats the seam (unverified bytes handed over,
             quarantine escaped without the governed re-pin flow,
             poisoned baseline accepted in strict mode, ...).
- HELD     = the seam resists the attack (fail-closed quarantine, or the
             attack surface does not exist).
- EXPECTED = demonstrated residual that is NOT a seam bug: the seam
             holds, but a documented system-level gap remains (e.g. the
             executor never calls fetch_verified_at_use — executor.py is
             not this team's file).
- ERROR    = probe/instrumentation problem, not a verdict.

Probes:
  e1  equivocating source: read_bytes() returns V1 then V2; the seam
      must perform exactly ONE read per check and hand over exactly the
      hashed bytes (never hash-V1/hand-V2).
  e2  threaded file swap DURING fetch_verified_at_use: every call must
      return (True, bytes-hashing-to-pin) or (False, None, quarantined)
      — never (True, wrong bytes).
  e3  bytearray source mutated by a second thread: the synchronous
      bytes() copy must make post-return mutation irrelevant.
  e4  digest confusion at approve_repin: bytes/None/uppercase/wrong
      digests refused; the governed path with the true digest works.
  e5  quarantine escape: re-register same id, alias id on the same
      file, approve_repin without request / with wrong digest — the
      quarantine must stand; only the governed flow lifts it.
  e6  UNWIRED SEAM (residual demonstration): the executor calls
      check_at_use (verdict only) and never fetch_verified_at_use, so a
      consumer that re-reads the file after the check can receive bytes
      the check never attested. EXPECTED, not a seam bug.
  e7  pin() reachability: no production module calls ToolInventory.pin()
      (deployment/test-only); the anchor moves only via explicit pin().
  e8  strict/default mode confusion: strict decisions never consult
      _last_seen (even when poisoned); mode is construction-time (no
      public setter).
  e9  undeclared-tool DoS in strict mode: denial is bounded (no
      quarantine-state pollution, deterministic, no exception).
  e10 provider outage vs provider poison in strict mode: the returned
      tuples differ ((False, anchor, None) vs (False, anchor, digest))
      so a caller CAN distinguish; the inventory layer itself emits no
      events (loudness is the caller's job — the executor logs it).
"""

import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import re
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov.skill_watch import (  # noqa: E402
    SkillWatch,
    FileContentSource,
    CallableContentSource,
    SkillWatchError,
)
from gov.tool_continuity import (  # noqa: E402
    ToolInventory,
    tool_definition_digest,
)

RESULTS = []
V1 = b"skill-bytes-version-one"
V2 = b"skill-bytes-version-two-MUTATED!!"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _record(name, verdict, detail):
    RESULTS.append((name, verdict, detail))
    print("%-4s %-8s %s" % (name, verdict, detail))


def _origin():
    return {"registry_url": "https://registry.synthetic.local/s",
            "installer_identity": "deployer",
            "installed_at": "2026-09-27T00:00:00+00:00"}


def _fresh_watch():
    d = Path(tempfile.mkdtemp(prefix="sw-ev2-"))
    p = d / "skill.bin"
    p.write_bytes(V1)
    return SkillWatch(), p


# --------------------------------------------------------------------------
# e1: equivocating source — one read per check, handoff == hashed bytes
# --------------------------------------------------------------------------
def _e1():
    reads = {"n": 0}
    script = [V1, V2]  # register reads V1; the check reads V2

    def fn():
        reads["n"] += 1
        return script[min(reads["n"] - 1, 1)]

    w = SkillWatch()
    w.register_skill("s", CallableContentSource(fn), origin=_origin())
    if reads["n"] != 1:
        return "ERROR", "register did not perform exactly 1 read"
    ok, data, detail = w.fetch_verified_at_use("s")
    # The check must have performed exactly ONE more read (total 2):
    # the V2 read hashes != pin -> quarantine, no bytes handed over.
    if reads["n"] != 2:
        return ("BREAK",
                "check performed %d reads (want exactly 1 per check): "
                "a multi-read check gives a hostile source room to "
                "equivocate" % (reads["n"] - 1,))
    if ok or data is not None:
        return ("BREAK",
                "equivocating source passed the handoff: %r" % (detail,))
    if not w.is_quarantined("s"):
        return "BREAK", "V2 read did not quarantine"
    # Now the positive direction: a stable V1 source hands over V1,
    # and the handed bytes hash to the pin.
    w2 = SkillWatch()
    w2.register_skill("s", CallableContentSource(lambda: V1),
                      origin=_origin())
    ok2, data2, detail2 = w2.fetch_verified_at_use("s")
    if not ok2 or data2 is None:
        return ("BREAK",
                "stable source failed the handoff: %r" % (detail2,))
    if bytes(data2) != V1 or _sha(bytes(data2)) != _sha(V1):
        return "BREAK", "handed bytes != hashed bytes"
    return ("HELD",
            "single observation per check (2 reads total incl. "
            "register); handoff bytes == hashed bytes; equivocation "
            "quarantines")


# --------------------------------------------------------------------------
# e2: threaded file swap during the handoff — invariant, not outcome
# --------------------------------------------------------------------------
def _e2():
    w, path = _fresh_watch()
    w.register_skill("s", FileContentSource(str(path)), origin=_origin())
    pin = _sha(V1)
    stop = threading.Event()
    bad = []

    def writer():
        i = 0
        while not stop.is_set():
            path.write_bytes(V1 if i % 2 == 0 else V2)
            i += 1

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    try:
        for _ in range(60):
            # A fresh watch per call keeps quarantine from masking the
            # invariant (we want the True-branch exercised too).
            # Registration happens with the writer stopped: catching
            # the file mid-truncate at install is a probe race, not a
            # product path (refusing to pin empty bytes is correct).
            stop.set(); t.join()
            path.write_bytes(V1)
            ww = SkillWatch()
            ww.register_skill("s", FileContentSource(str(path)),
                              origin=_origin())
            stop.clear()
            t = threading.Thread(target=writer, daemon=True)
            t.start()
            ok, data, _ = ww.fetch_verified_at_use("s")
            stop.set(); t.join()
            if ok:
                if data is None or _sha(bytes(data)) != _sha(V1):
                    bad.append("True with wrong bytes")
                    break
            else:
                if data is not None:
                    bad.append("False with bytes attached")
                    break
    finally:
        stop.set()
        try:
            t.join()
        except RuntimeError:
            pass
    if bad:
        return "BREAK", bad[0]
    return ("HELD",
            "60 racy handoffs: every call returned (True, pin-matching "
            "bytes) or (False, None, quarantined) — never True with "
            "unhashed bytes")


# --------------------------------------------------------------------------
# e3: bytearray source mutated mid-check by a second thread
# --------------------------------------------------------------------------
def _e3():
    buf = bytearray(V1)
    stop = threading.Event()

    def fn():
        return buf  # caller must copy synchronously

    def mutator():
        while not stop.is_set():
            buf[:] = V2[:len(buf)] if len(buf) >= len(V2) else V2
            buf[:] = V1[:len(buf)]

    w = SkillWatch()
    w.register_skill("s", CallableContentSource(fn), origin=_origin())
    # Stabilize the buffer for registration determinism, then hammer.
    buf[:] = V1
    t = threading.Thread(target=mutator, daemon=True)
    t.start()
    try:
        for _ in range(40):
            ww = SkillWatch()
            buf[:] = V1
            ww.register_skill("s", CallableContentSource(fn),
                              origin=_origin())
            ok, data, _ = ww.fetch_verified_at_use("s")
            if ok and (data is None or _sha(bytes(data)) != _sha(V1)):
                return "BREAK", "True with bytes not hashing to the pin"
            if not ok and data is not None:
                return "BREAK", "False with bytes attached"
    finally:
        stop.set()
        t.join()
    # Post-return mutation of the handed object must be impossible
    # (bytes are immutable) — and the handed bytes must still verify.
    w3 = SkillWatch()
    buf[:] = V1
    w3.register_skill("s", CallableContentSource(fn), origin=_origin())
    ok3, data3, _ = w3.fetch_verified_at_use("s")
    if not ok3:
        return "ERROR", "stable bytearray source failed unexpectedly"
    try:
        data3[0] = 0
        return "BREAK", "handed bytes are mutable"
    except TypeError:
        pass
    if _sha(bytes(data3)) != _sha(V1):
        return "BREAK", "handed bytes do not hash to the pin"
    return ("HELD",
            "racy bytearray: synchronous bytes() copy holds; handed "
            "bytes immutable and pin-matching")


# --------------------------------------------------------------------------
# e4: digest confusion at approve_repin
# --------------------------------------------------------------------------
def _e4():
    def _quarantined_watch():
        w, path = _fresh_watch()
        w.register_skill("s", FileContentSource(str(path)),
                         origin=_origin())
        path.write_bytes(V2)  # poison -> next check quarantines
        ok, _ = w.check_at_use("s")
        assert not ok and w.is_quarantined("s")
        return w, path

    # (a) approve without a prior request -> refused
    w, _ = _quarantined_watch()
    try:
        w.approve_repin("s", {"operator": "op", "new_digest": _sha(V2),
                              "reason": "r"})
        return "BREAK", "approve_repin without request succeeded"
    except SkillWatchError:
        pass
    # (b) non-str digests refused
    for bad_digest in (None, b"", _sha(V2).encode(), 12345):
        w, _ = _quarantined_watch()
        w.request_repin("s", "op:test")
        try:
            w.approve_repin("s", {"operator": "op",
                                  "new_digest": bad_digest,
                                  "reason": "r"})
            return ("BREAK",
                    "approve_repin accepted non-str digest %r"
                    % (bad_digest,))
        except SkillWatchError:
            pass
        if not w.is_quarantined("s"):
            return "BREAK", "refused approval lifted quarantine"
    # (c) uppercase hex (non-canonical form) refused
    w, _ = _quarantined_watch()
    w.request_repin("s", "op:test")
    try:
        w.approve_repin("s", {"operator": "op",
                              "new_digest": _sha(V2).upper(),
                              "reason": "r"})
        return "BREAK", "approve_repin accepted non-canonical hex"
    except SkillWatchError:
        pass
    # (d) well-formed but wrong digest refused (bait-and-switch)
    w, _ = _quarantined_watch()
    w.request_repin("s", "op:test")
    try:
        w.approve_repin("s", {"operator": "op",
                              "new_digest": _sha(b"something else"),
                              "reason": "r"})
        return "BREAK", "approve_repin accepted a stale/wrong digest"
    except SkillWatchError:
        pass
    if not w.is_quarantined("s"):
        return "BREAK", "wrong-digest refusal lifted quarantine"
    # (e) the governed path with the true digest works (designed escape)
    w, _ = _quarantined_watch()
    w.request_repin("s", "op:test")
    got = w.approve_repin("s", {"operator": "op",
                                "new_digest": _sha(V2), "reason": "r"})
    if got != _sha(V2) or w.is_quarantined("s"):
        return "BREAK", "governed re-pin flow failed to lift quarantine"
    ok, data, _ = w.fetch_verified_at_use("s")
    if not ok or bytes(data) != V2:
        return "BREAK", "post-repin handoff wrong"
    return ("HELD",
            "non-str/None/uppercase/wrong digests refused, quarantine "
            "stands; true-digest governed re-pin lifts it")


# --------------------------------------------------------------------------
# e5: quarantine escape attempts
# --------------------------------------------------------------------------
def _e5():
    w, path = _fresh_watch()
    w.register_skill("s", FileContentSource(str(path)), origin=_origin())
    path.write_bytes(V2)
    ok, _ = w.check_at_use("s")
    assert not ok and w.is_quarantined("s")
    # (a) re-registering the same id fails closed
    try:
        w.register_skill("s", FileContentSource(str(path)),
                         origin=_origin())
        return "BREAK", "re-registration of quarantined id succeeded"
    except SkillWatchError:
        pass
    # (b) alias id on the same file: independent pin (TOFU at install),
    # NOT an escape of "s". "s2" pins the CURRENT (poisoned) content as
    # its own baseline — documented install-time semantics — and its
    # later clean attestation is consistent with ITS pin, not with
    # "s"'s. The escape-relevant facts: "s" stays quarantined, pins are
    # per-id, and "s2" did not inherit "s"'s V1 pin.
    w.register_skill("s2", FileContentSource(str(path)), origin=_origin())
    if not w.is_quarantined("s"):
        return "BREAK", "alias registration cleared s quarantine"
    if w._skills["s2"]["pinned_digest"] != _sha(V2):
        return ("BREAK",
                "alias id did not pin the bytes actually present")
    if w._skills["s"]["pinned_digest"] != _sha(V1):
        return "BREAK", "s pin was disturbed by the alias registration"
    ok2, _ = w.check_at_use("s2")
    if not ok2:
        return ("BREAK",
                "alias id failed against its own pin (inconsistent)")
    # (c) approve_repin without request
    try:
        w.approve_repin("s", {"operator": "op",
                              "new_digest": _sha(V2), "reason": "r"})
        return "BREAK", "approve_repin without request lifted quarantine"
    except SkillWatchError:
        pass
    # (d) request + wrong digest
    w.request_repin("s", "op:test")
    try:
        w.approve_repin("s", {"operator": "op",
                              "new_digest": _sha(b"nope"), "reason": "r"})
        return "BREAK", "wrong-digest approval lifted quarantine"
    except SkillWatchError:
        pass
    # Final: the quarantine stands and the handoff stays shut.
    if not w.is_quarantined("s"):
        return "BREAK", "quarantine escaped via one of the attempts"
    okf, dataf, detailf = w.fetch_verified_at_use("s")
    if okf or dataf is not None or detailf != "quarantined":
        return ("BREAK",
                "quarantined skill handed bytes: %r" % (detailf,))
    return ("HELD",
            "re-register refused, alias id independent, unrequested / "
            "wrong-digest approvals refused; quarantine stands")


# --------------------------------------------------------------------------
# e6: UNWIRED SEAM — the executor never calls fetch_verified_at_use
# (residual demonstration; executor.py is not this team's file)
# --------------------------------------------------------------------------
def _e6():
    w, path = _fresh_watch()
    w.register_skill("s", FileContentSource(str(path)), origin=_origin())
    # The executor's actual call pattern (gov/executor.py ~line 7841):
    # check_at_use (verdict only) ...
    ok, detail = w.check_at_use("s")
    if not ok:
        return "ERROR", "clean check failed: %r" % (detail,)
    # ... then, BEFORE the consumer loads the skill bytes, the file is
    # swapped. The consumer re-reads the file itself (nothing calls
    # fetch_verified_at_use in gov/).
    path.write_bytes(V2)
    consumer_bytes = path.read_bytes()  # what a re-reading consumer gets
    if consumer_bytes == V1:
        return "ERROR", "swap did not take effect"
    # The check attested V1; the consumer received V2 — bytes the check
    # never hashed. fetch_verified_at_use WOULD have closed this (it
    # hands over the hashed bytes), but no caller uses it.
    import subprocess
    grep = subprocess.run(
        ["grep", "-rn", "fetch_verified_at_use", "gov/executor.py"],
        capture_output=True, text=True, cwd=str(
            Path(__file__).resolve().parent.parent))
    if "fetch_verified_at_use(" in grep.stdout.replace(
            "fetch_verified_at_use`", ""):
        # A real call site (not a docstring mention) exists.
        return ("HELD",
                "executor now consumes the handoff seam")
    return ("EXPECTED",
            "check_at_use attested V1, consumer re-read got V2 "
            "(unverified); fetch_verified_at_use exists but gov/ "
            "has no non-docstring caller — the check/use split "
            "persists at the consumer layer until the executor is "
            "wired to the handoff (executor.py: not this team's file)")


# --------------------------------------------------------------------------
# e7: pin() reachability — deployment/test-only, anchor moves on explicit pin
# --------------------------------------------------------------------------
_DECL = {"description": "declared tool", "schema": {"x": "string"}}
_POISON = {"description": "RUG PULL description", "schema": {"x": "string"}}


def _e7():
    root = Path(__file__).resolve().parent.parent
    callers = []
    for f in sorted((root / "gov").glob("*.py")):
        text = f.read_text()
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if ".pin(" in s and not s.startswith("def ") \
                    and "def pin(" not in s:
                callers.append("%s:%d" % (f.name, i))
    if callers:
        return ("BREAK",
                "production pin() callers (unreviewed anchor moves): %s"
                % "; ".join(callers))
    # Behavioral: the anchor moves only via explicit pin().
    inv = ToolInventory(definitions={"t": dict(_DECL)},
                        provider=lambda tool: dict(_POISON), strict=True)
    anchor_before = inv.anchor_digest_for("t")
    ok, prev, cur = inv.verify_at_use("t")
    if ok:
        return "BREAK", "strict accepted poisoned provider bytes"
    inv.pin("t", _POISON["description"], _POISON["schema"])
    if inv.anchor_digest_for("t") == anchor_before:
        return "BREAK", "pin() did not move the anchor"
    if inv.is_quarantined("t"):
        return "BREAK", "pin() did not clear the quarantine"
    ok2, _, _ = inv.verify_at_use("t")
    if not ok2:
        return "BREAK", "post-pin verify failed"
    return ("HELD",
            "no production pin() callers in gov/; anchor moves only on "
            "explicit pin() (the reviewed re-declaration workflow)")


# --------------------------------------------------------------------------
# e8: strict/default mode confusion
# --------------------------------------------------------------------------
def _e8():
    if hasattr(ToolInventory, "set_strict"):
        return "BREAK", "public mode setter exists"
    # Default mode TOFU-pins poison...
    inv = ToolInventory(definitions={"t": dict(_DECL)},
                        provider=lambda tool: dict(_POISON))
    ok, _, _ = inv.verify_at_use("t")
    if not ok:
        return "ERROR", "default-mode first sighting should TOFU-allow"
    poisoned_baseline = inv._last_seen.get("t")
    # ...then the deployment "flips" to strict on the same object.
    # Strict must NEVER consult the poisoned _last_seen.
    inv._strict = True
    ok2, prev2, cur2 = inv.verify_at_use("t")
    if ok2:
        return ("BREAK",
                "strict mode honored the poisoned _last_seen baseline")
    if prev2 != inv.anchor_digest_for("t"):
        return ("BREAK",
                "strict verdict did not compare against the anchor")
    # Reverse: strict-first object flipped to default TOFU-pins current
    # provider bytes (documented TOFU — the mode is construction-time).
    inv2 = ToolInventory(definitions={"t": dict(_DECL)},
                         provider=lambda tool: dict(_POISON), strict=True)
    inv2._strict = False
    ok3, _, _ = inv2.verify_at_use("t")
    if not ok3:
        return "BREAK", "default-mode first sighting refused (TOFU broke)"
    return ("HELD",
            "strict ignores _last_seen even when poisoned; no public "
            "mode setter — mode is a construction-time decision")


# --------------------------------------------------------------------------
# e9: undeclared-tool DoS in strict mode — bounded and deterministic
# --------------------------------------------------------------------------
def _e9():
    inv = ToolInventory(definitions={"t": dict(_DECL)},
                        provider=lambda tool: dict(_DECL), strict=True)
    seen = set()
    for _ in range(3):
        ok, prev, cur = inv.verify_at_use("ghost-tool")
        if ok:
            return "BREAK", "strict allowed an undeclared tool"
        if prev is not None:
            return "BREAK", "undeclared denial carried a phantom baseline"
        if cur != tool_definition_digest(
                "ghost-tool", _DECL["description"], _DECL["schema"]):
            return "BREAK", "undeclared denial misreported the digest"
        if inv.is_quarantined("ghost-tool"):
            return ("BREAK",
                    "undeclared denial polluted quarantine state")
        seen.add((ok, prev, cur))
    if len(seen) != 1:
        return "BREAK", "undeclared denial not deterministic"
    # Declared tools are unaffected by the ghost denials.
    okd, _, _ = inv.verify_at_use("t")
    if not okd:
        return "BREAK", "ghost denials impacted a declared tool"
    return ("HELD",
            "undeclared denial: deterministic, no quarantine "
            "pollution, no exception, declared tools unaffected")


# --------------------------------------------------------------------------
# e10: provider outage vs provider poison — caller-distinguishable
# --------------------------------------------------------------------------
def _e10():
    anchor = tool_definition_digest("t", _DECL["description"],
                                    _DECL["schema"])
    # Outage: provider serves nothing.
    inv_o = ToolInventory(definitions={"t": dict(_DECL)},
                          provider=lambda tool: None, strict=True)
    oko, prevo, curo = inv_o.verify_at_use("t")
    # Poison: provider serves attacker bytes.
    inv_p = ToolInventory(definitions={"t": dict(_DECL)},
                          provider=lambda tool: dict(_POISON), strict=True)
    okp, prevp, curp = inv_p.verify_at_use("t")
    if oko or okp:
        return "BREAK", "strict allowed outage/poison"
    if not (inv_o.is_quarantined("t") and inv_p.is_quarantined("t")):
        return "BREAK", "outage/poison did not quarantine"
    if (oko, prevo, curo) == (okp, prevp, curp):
        return ("BREAK",
                "outage and poison return identical tuples — the "
                "caller cannot distinguish them")
    if not (prevo == prevp == anchor and curo is None
            and curp == tool_definition_digest(
                "t", _POISON["description"], _POISON["schema"])):
        return ("BREAK",
                "tuples malformed: %r vs %r" % ((oko, prevo, curo),
                                                (okp, prevp, curp)))
    # Layering note (read-only evidence): the inventory layer emits no
    # events itself — loudness is the caller's job. The executor's
    # call site (gov/executor.py, tool-inventory gate) appends a
    # "tool_quarantined" audit entry rendering (prev -> cur), i.e.
    # "digest <anchor12> -> ?" for outage vs "digest <anchor12> ->
    # <poison12>" for poison. The distinction survives iff the caller
    # logs the tuple — verified by source inspection, not by this
    # probe's execution.
    return ("HELD",
            "outage -> (False, anchor, None); poison -> (False, "
            "anchor, poison-digest): caller-distinguishable; "
            "inventory layer itself is event-silent by design")


PROBES = [
    ("e1", _e1),
    ("e2", _e2),
    ("e3", _e3),
    ("e4", _e4),
    ("e5", _e5),
    ("e6", _e6),
    ("e7", _e7),
    ("e8", _e8),
    ("e9", _e9),
    ("e10", _e10),
]


def main():
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- ERROR, not a verdict
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, str(e)[:200]))
        _record(name, verdict, detail)
    n_break = sum(1 for _, v, _ in RESULTS if v == "BREAK")
    n_held = sum(1 for _, v, _ in RESULTS if v == "HELD")
    n_exp = sum(1 for _, v, _ in RESULTS if v == "EXPECTED")
    n_err = sum(1 for _, v, _ in RESULTS if v == "ERROR")
    print("----")
    print("%d BREAK / %d HELD / %d EXPECTED / %d ERROR"
          % (n_break, n_held, n_exp, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
