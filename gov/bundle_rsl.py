"""Skill-bundle Revision State Log (RSL) -- wave-271.

gittuf-pattern adaptation (pattern only, nothing copied): an append-only,
hash-chained per-bundle state log layered on
:mod:`gov.durable_journal` with

- fork detection via multi-parent check (two state entries for one bundle
  sharing a parent digest, or sharing a sequence number, fail closed);
- revocation-by-annotation: entries are never deleted or rewritten; a
  signed ``rsl-skip`` annotation revokes a state entry and verification
  fails closed on any skipped entry in the chain;
- explicit rollback refusal: pinning or re-recording an ancestor digest
  is a loud ``rsl-rollback-attempt``, never a silent revert;
- ordered TUF-style delegations with an always-last terminal allow-rule:
  the rule file must carry the terminal key's signature over the rule
  body; no implicit default-allow exists at the end of any list;
- principal/threshold validated at rule-CREATION time, not at
  evaluation time (``rsl-threshold-invalid``);
- transition authorizations ``<bundle>/<from>-<to>``: a signed statement
  authorizing the UPGRADE from one state digest to the next, not the
  blob; a state is recorded only when a threshold-satisfying statement
  for ``(tip -> new)`` exists and re-verifies.

Which side of the seam Sasanam sits on: BOTH, explicitly.
``authorize_transition`` / ``record_state`` / ``skip_annotate`` are
PREVENT-time -- they refuse unauthorized appends before the bytes land
in the journal. ``verify`` is VERIFY-time -- an auditor who did not
write the log re-checks the whole chain (forks, skips, transitions,
expiry) without trusting the writer. ``verify`` never raises; it returns
a verdict dict. Mutating operations raise :class:`RSLError` (fail-loud,
carrying the machine ``code``); malformed caller input raises
``ValueError``.

Traps from the gittuf teardown that are NOT copied:

- root-metadata expiry unenforced: Sasanam rule files MUST enforce
  expiry -- ``expires`` is checked at creation and at open against the
  explicit ``now`` (``rsl-rule-expired``). Per-operation re-checks read
  the handle's clock: with a frozen int ``now`` (the deterministic
  default) the re-check is vacuous by construction -- a long-lived
  handle without a clock does NOT observe wall-clock expiry. Pass
  ``now`` as a callable clock (e.g. ``time.time``) to
  ``open_log``/``BundleRSL`` when the deployment needs expiry enforced
  on every operation (F275).
- vendored patched DSSE: the rule wire is plain canonical JSON with one
  Ed25519 signature field; no envelope machinery.
- verify-time-not-prevent-time: gittuf blocks force-pushes at verify
  time; the RSL refuses forks/rollbacks at BOTH times, as stated above.

Determinism: every entry point takes an explicit ``now`` -- a frozen
int for byte-identical scenarios, or a callable clock when the
deployment wants per-operation wall-clock freshness (F275). Ed25519
signatures are deterministic; journal records are canonical JSON.

Honest limits: the RSL authenticates state TRANSITIONS, not bundle
content -- a correctly-authorized transition to a malicious bundle is
out of scope here (content scanning is :mod:`gov.bundle_scan`'s job).
``record_state`` serializes concurrent appends via the journal's
exclusive lock; a tip that moved under the append is refused as a
suspected fork (``rsl-fork-detected``) -- the caller retries, it does
not merge. Skip annotations are trigger-easy by design: any registered
principal may annotate (revocation must be cheap to raise); a malicious
principal can only revoke, never forge state.
"""

import hashlib
import json

from gov import ed25519 as _ed
from gov.durable_journal import Journal, JournalCorrupted

SCHEMA_VERSION = 1

FORK_DETECTED = "rsl-fork-detected"
ROLLBACK_ATTEMPT = "rsl-rollback-attempt"
SKIPPED_REVOKED = "rsl-skipped-revoked"
TERMINAL_UNSIGNED = "rsl-terminal-rule-unsigned"
THRESHOLD_INVALID = "rsl-threshold-invalid"
TRANSITION_UNAUTHORIZED = "rsl-transition-unauthorized"
LOG_CORRUPT = "rsl-log-corrupt"
RULE_EXPIRED = "rsl-rule-expired"

CODES = (FORK_DETECTED, ROLLBACK_ATTEMPT, SKIPPED_REVOKED,
         TERMINAL_UNSIGNED, THRESHOLD_INVALID, TRANSITION_UNAUTHORIZED,
         LOG_CORRUPT, RULE_EXPIRED)


class RSLError(Exception):
    """Fail-loud RSL refusal carrying the machine decision code."""

    def __init__(self, code, detail):
        super(RSLError, self).__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _is_epoch_int(value):
    """True for a real int epoch -- bool is rejected (a programmatic
    True/False is a nonsense epoch, and JSON never carries one)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _resolve_now(now):
    """Resolve the explicit ``now`` to an int epoch.

    ``now`` may be a frozen int (deterministic default -- two identical
    scenarios produce byte-identical journals) or a callable clock
    returning the current epoch as int or float seconds (e.g.
    ``time.time`` -- floats are truncated to int seconds to keep the
    int-epoch discipline) for live expiry on every operation (F275).
    """
    value = now() if callable(now) else now
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("now must resolve to an int or float epoch, not %s"
                         % type(value).__name__)
    return int(value)


# ---------------------------------------------------------------------------
# Small validators
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _hex64(value, where):
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("%s must be a 64-char hex digest" % where)
    try:
        int(value, 16)
    except ValueError:
        raise ValueError("%s must be hex" % where)
    return value


def _nonempty_str(value, where):
    if not isinstance(value, str) or not value:
        raise ValueError("%s must be a non-empty string" % where)
    return value


def _kid_for_seed(principals, seed):
    pub = _ed.publickey(seed).hex()
    for kid, entry in principals.items():
        if entry.get("pub") == pub:
            return kid
    return None


def _delegation_by_name(rule, name):
    for d in rule["delegations"]:
        if d["name"] == name:
            return d
    return None


def _verify_statement_sigs(rule, stmt):
    """Re-verify a transition statement against the rule. Raises RSLError."""
    delegation = _delegation_by_name(rule, stmt.get("delegation"))
    if delegation is None:
        raise RSLError(TRANSITION_UNAUTHORIZED,
                       "unknown delegation %r" % (stmt.get("delegation"),))
    expected_id = _statement_id(stmt["bundle"], stmt["from_digest"],
                                stmt["to_digest"], stmt["delegation"])
    if stmt.get("statement_id") != expected_id:
        raise RSLError(TRANSITION_UNAUTHORIZED,
                       "statement_id mismatch (tampered statement)")
    msg = _canonical({"statement_id": stmt["statement_id"],
                      "bundle": stmt["bundle"],
                      "from_digest": stmt["from_digest"],
                      "to_digest": stmt["to_digest"],
                      "delegation": stmt["delegation"]})
    principals = rule["principals"]
    valid = set()
    for kid, sig_hex in (stmt.get("signatures") or {}).items():
        entry = principals.get(kid)
        if entry is None:
            continue
        try:
            sig = bytes.fromhex(sig_hex)
            pub = bytes.fromhex(entry["pub"])
        except ValueError:
            continue
        if _ed.verify(pub, msg, sig) is True:
            valid.add(kid)
    need = delegation["threshold"]
    have = len([k for k in valid if k in delegation["key_ids"]])
    if have < need:
        raise RSLError(TRANSITION_UNAUTHORIZED,
                       "delegation %r: %d/%d valid signatures" %
                       (delegation["name"], have, need))
    return True


def _verify_skip_sigs(rule, skip):
    """A skip annotation is honored only with a valid principal signature.

    An unsigned/forged skip is dishonored (it cannot revoke, and it
    cannot be used to DoS verification); it stays in the log, audit-
    visible, but powerless. A MALFORMED skip (missing fields, wrong
    shapes) is also dishonored -- it can never brick verification of
    the whole bundle (F274). Malformation is not a signature failure
    and is never honored.
    """
    try:
        msg = _canonical({"bundle": skip["bundle"],
                          "target_seq": skip["target_seq"],
                          "target_digest": skip["target_digest"],
                          "reason": skip["reason"]})
        signatures = skip.get("signatures")
        if signatures is not None and not isinstance(signatures, dict):
            return False
    except (KeyError, TypeError, AttributeError):
        # Malformed skip record: dishonored, never honored, and never
        # allowed to fail the whole-bundle verification (F274).
        return False
    for kid, sig_hex in (signatures or {}).items():
        entry = rule["principals"].get(kid)
        if entry is None:
            continue
        try:
            sig = bytes.fromhex(sig_hex)
            pub = bytes.fromhex(entry["pub"])
        except (ValueError, TypeError, KeyError):
            continue
        if _ed.verify(pub, msg, sig) is True:
            return True
    return False


def _statement_id(bundle, from_digest, to_digest, delegation):
    return hashlib.sha256(_canonical({
        "bundle": bundle, "from_digest": from_digest,
        "to_digest": to_digest, "delegation": delegation})).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Rule files (versioned schema, expiry enforced, threshold at creation)
# ---------------------------------------------------------------------------

def make_rule_file(*, rule_id, bundle, principals, delegations,
                   terminal_key_id, terminal_seed, expires, now):
    """Create a signed RSL rule file (the always-last terminal allow-rule).

    Raises RSLError (machine code) for the enumerated policy failures and
    ValueError for malformed caller input.
    """
    _nonempty_str(rule_id, "rule_id")
    _nonempty_str(bundle, "bundle")
    if not isinstance(principals, dict) or not principals:
        raise ValueError("principals must be a non-empty dict")
    for kid, entry in principals.items():
        _nonempty_str(kid, "principal key id")
        _hex64(entry.get("pub"), "principals[%s].pub" % kid)
    if not isinstance(delegations, list) or not delegations:
        raise ValueError("delegations must be a non-empty ordered list")
    seen = set()
    for i, d in enumerate(delegations):
        where = "delegations[%d]" % i
        name = _nonempty_str(d.get("name"), where + ".name")
        if name in seen:
            raise ValueError("%s: duplicate delegation name" % where)
        seen.add(name)
        kids = d.get("key_ids")
        if not isinstance(kids, list) or not kids:
            raise ValueError("%s.key_ids must be a non-empty list" % where)
        unknown = [k for k in kids if k not in principals]
        if unknown:
            raise ValueError("%s references unknown principals %r" %
                             (where, unknown))
        threshold = d.get("threshold")
        if not isinstance(threshold, int) or not 1 <= threshold <= len(kids):
            raise RSLError(THRESHOLD_INVALID,
                           "%s: threshold %r not in [1, %d] "
                           "(validated at creation, not evaluation)" %
                           (name, threshold, len(kids)))
    if terminal_key_id not in principals:
        raise ValueError("terminal_key_id %r not in principals" %
                         (terminal_key_id,))
    if not isinstance(expires, int) or expires <= _resolve_now(now):
        raise RSLError(RULE_EXPIRED,
                       "rule file expires at %r, now is %r: refusing to "
                       "mint an already-expired rule" % (expires, now))
    if terminal_seed is None:
        raise RSLError(TERMINAL_UNSIGNED,
                       "terminal allow-rule requires the terminal key "
                       "signature; unsigned rule file refused")
    term_pub = _ed.publickey(terminal_seed).hex()
    if term_pub != principals[terminal_key_id]["pub"]:
        raise ValueError("terminal_seed does not match the registered "
                         "terminal pubkey")
    body = {
        "schema_version": SCHEMA_VERSION,
        "rule_id": rule_id,
        "bundle": bundle,
        "principals": principals,
        "delegations": [{"name": d["name"], "key_ids": list(d["key_ids"]),
                         "threshold": d["threshold"]} for d in delegations],
        "terminal": {"key_id": terminal_key_id},
        "expires": expires,
    }
    sig = _ed.sign(terminal_seed, _canonical(body)).hex()
    wire = dict(body)
    wire["signatures"] = {"terminal": {"key_id": terminal_key_id,
                                       "sig": sig}}
    return json.dumps(wire, sort_keys=True)


def _parse_rule(rule_wire, now):
    try:
        wire = json.loads(rule_wire)
    except (ValueError, TypeError):
        raise ValueError("rule_wire is not valid JSON")
    if not isinstance(wire, dict):
        raise ValueError("rule_wire must be a JSON object")
    if wire.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported rule schema_version %r" %
                         (wire.get("schema_version"),))
    for field in ("rule_id", "bundle", "principals", "delegations",
                  "terminal", "expires", "signatures"):
        if field not in wire:
            raise ValueError("rule_wire missing %r" % field)
    body = {k: wire[k] for k in ("schema_version", "rule_id", "bundle",
                                 "principals", "delegations", "terminal",
                                 "expires")}
    # Shape validation before any attribute/item access: malformed
    # caller input must raise ValueError (the module-contract error),
    # never leak raw AttributeError/TypeError (F273).
    term = wire["terminal"]
    if not isinstance(term, dict):
        raise ValueError("terminal must be an object, not %s"
                         % type(term).__name__)
    principals = wire["principals"]
    if not isinstance(principals, dict):
        raise ValueError("principals must be an object, not %s"
                         % type(principals).__name__)
    signatures = wire["signatures"]
    if not isinstance(signatures, dict):
        raise ValueError("signatures must be an object, not %s"
                         % type(signatures).__name__)
    expires = wire["expires"]
    if not _is_epoch_int(expires):
        raise ValueError("expires must be an int epoch, not %s"
                         % type(expires).__name__)
    kid = term.get("key_id")
    if kid not in principals:
        raise ValueError("terminal key not in principals")
    sig_entry = (signatures or {}).get("terminal")
    if sig_entry is not None and not isinstance(sig_entry, dict):
        raise ValueError("signatures.terminal must be an object, not %s"
                         % type(sig_entry).__name__)
    if not sig_entry or sig_entry.get("key_id") != kid:
        raise RSLError(TERMINAL_UNSIGNED,
                       "rule file carries no terminal signature")
    try:
        sig = bytes.fromhex(sig_entry["sig"])
        pub = bytes.fromhex(principals[kid]["pub"])
    except (ValueError, TypeError, KeyError):
        raise RSLError(TERMINAL_UNSIGNED,
                       "terminal signature is malformed")
    if _ed.verify(pub, _canonical(body), sig) is not True:
        raise RSLError(TERMINAL_UNSIGNED,
                       "terminal signature does not verify")
    # Thresholds are enforced at creation, re-checked here defense-in-depth.
    for i, d in enumerate(wire["delegations"]):
        if not isinstance(d, dict):
            raise ValueError("delegations[%d] must be an object" % i)
        kids = d.get("key_ids")
        threshold = d.get("threshold")
        if (not isinstance(kids, list) or not kids
                or not isinstance(threshold, int)):
            raise ValueError("delegations[%d] malformed" % i)
        if not 1 <= threshold <= len(kids):
            raise RSLError(THRESHOLD_INVALID,
                           "delegation %r threshold out of range" %
                           (d.get("name"),))
    if wire["expires"] <= _resolve_now(now):
        raise RSLError(RULE_EXPIRED,
                       "rule file expired at %r (now %r)" %
                       (wire["expires"], now))
    return wire


def open_log(journal_path, rule_wire, now):
    """Open (or create) the RSL at ``journal_path`` under ``rule_wire``.

    ``now`` may be a frozen int (deterministic) or a callable clock
    (live expiry on every operation -- see F275).
    """
    rule = _parse_rule(rule_wire, now)
    try:
        journal = Journal(journal_path)
    except JournalCorrupted as e:
        raise RSLError(LOG_CORRUPT, "journal failed chain verification: "
                                    "%s" % e)
    return BundleRSL(journal, rule, now)


# ---------------------------------------------------------------------------
# The log
# ---------------------------------------------------------------------------

class BundleRSL(object):
    """Prevent-time writer + verify-time auditor for one bundle's RSL."""

    def __init__(self, journal, rule, now):
        self._journal = journal
        self._rule = rule
        self._now = now
        # F275: the expiry clock. A frozen int ``now`` preserves the
        # deterministic discipline; a callable clock is sampled on
        # every operation so a long-lived handle observes expiry.
        self._now_fn = lambda: _resolve_now(now)

    # -- internal scans -------------------------------------------------
    @staticmethod
    def _states(records, bundle):
        return [r["body"] for r in records
                if r["type"] == "rsl-state"
                and r["body"].get("bundle") == bundle]

    @staticmethod
    def _tip_digest(records, bundle):
        tip = None
        for body in BundleRSL._states(records, bundle):
            if tip is None or body["seq"] > tip["seq"]:
                tip = body
        return tip["state_digest"] if tip else None

    def _check_expiry(self):
        now = self._now_fn()
        if self._rule["expires"] <= now:
            raise RSLError(RULE_EXPIRED,
                           "rule file expired at %r (now %r)" %
                           (self._rule["expires"], now))

    def _check_bundle(self, bundle):
        _nonempty_str(bundle, "bundle")
        if bundle != self._rule["bundle"]:
            raise ValueError("bundle %r not covered by this rule file "
                             "(covers %r)" % (bundle, self._rule["bundle"]))

    # -- prevent-time ----------------------------------------------------
    def authorize_transition(self, bundle, from_digest, to_digest,
                             delegation, seeds):
        """Record a signed transition authorization (the UPGRADE from->to).

        The statement is just ink: ``record_state`` re-verifies it at the
        enforcement point before any state lands.
        """
        self._check_expiry()
        self._check_bundle(bundle)
        if from_digest is not None:
            _hex64(from_digest, "from_digest")
        _hex64(to_digest, "to_digest")
        _nonempty_str(delegation, "delegation")
        if _delegation_by_name(self._rule, delegation) is None:
            raise ValueError("unknown delegation %r" % (delegation,))
        if not seeds:
            raise RSLError(TRANSITION_UNAUTHORIZED,
                           "transition authorization requires signatures")
        stmt_id = _statement_id(bundle, from_digest, to_digest, delegation)
        msg = _canonical({"statement_id": stmt_id, "bundle": bundle,
                          "from_digest": from_digest, "to_digest": to_digest,
                          "delegation": delegation})
        sigs = {}
        for seed in seeds:
            kid = _kid_for_seed(self._rule["principals"], seed)
            if kid is None:
                raise RSLError(TRANSITION_UNAUTHORIZED,
                               "transition signed by an unregistered key")
            sigs[kid] = _ed.sign(seed, msg).hex()
        stmt = {"bundle": bundle, "from_digest": from_digest,
                "to_digest": to_digest, "delegation": delegation,
                "signatures": sigs, "statement_id": stmt_id}
        _verify_statement_sigs(self._rule, stmt)  # threshold now, not later
        self._journal.append("rsl-transition", stmt)
        return stmt_id

    def record_state(self, bundle, state_digest, custom_fields=None):
        """Append a new state; refuses forks, rollbacks, and unauthorized
        upgrades before they land. Returns the new per-bundle seq."""
        self._check_expiry()
        self._check_bundle(bundle)
        _hex64(state_digest, "state_digest")
        if custom_fields is not None and not isinstance(custom_fields, dict):
            raise ValueError("custom_fields must be a dict")
        tip = self._tip_digest(self._journal.records, bundle)
        if tip == state_digest:
            raise ValueError("state digest is already the current tip")
        history = {b["state_digest"]
                   for b in self._states(self._journal.records, bundle)}
        if state_digest in history:
            raise RSLError(ROLLBACK_ATTEMPT,
                           "digest %s... is an ancestor of the tip; "
                           "downgrades are refused loudly, never applied "
                           "silently" % state_digest[:16])
        stmt = self._find_transition(bundle, tip, state_digest)
        if stmt is None:
            raise RSLError(TRANSITION_UNAUTHORIZED,
                           "no authorized transition (%s -> %s...); the "
                           "upgrade was never authorized" %
                           (tip[:16] if tip else None, state_digest[:16]))
        _verify_statement_sigs(self._rule, stmt)
        seq = self._next_seq(self._journal.records, bundle)
        entry = {"bundle": bundle, "state_digest": state_digest,
                 "seq": seq, "prev_digest": tip,
                 "transition": stmt["statement_id"],
                 "custom_fields": custom_fields or {}}
        expected_tip = tip

        def _tip_unchanged(records):
            return self._tip_digest(records, bundle) == expected_tip

        appended, _txn = self._journal.append_if([("rsl-state", entry)],
                                                 _tip_unchanged)
        if not appended:
            # The tip moved under the exclusive lock: a concurrent writer
            # forked the log (or raced us). Fail closed; the caller
            # re-reads and retries, it does not merge.
            raise RSLError(FORK_DETECTED,
                           "tip moved during append; refusing as a "
                           "suspected fork")
        return seq

    def skip_annotate(self, bundle, seq, reason, seeds):
        """Revoke a state entry by annotation. Never deletes."""
        self._check_expiry()
        self._check_bundle(bundle)
        if not isinstance(seq, int) or seq < 0:
            raise ValueError("seq must be a non-negative int")
        _nonempty_str(reason, "reason")
        if not seeds:
            raise RSLError(TRANSITION_UNAUTHORIZED,
                           "skip annotation requires a signer")
        states = self._states(self._journal.records, bundle)
        target = next((b for b in states if b["seq"] == seq), None)
        if target is None:
            raise ValueError("no state entry (bundle, seq=%d)" % seq)
        msg = _canonical({"bundle": bundle, "target_seq": seq,
                          "target_digest": target["state_digest"],
                          "reason": reason})
        sigs = {}
        for seed in seeds:
            kid = _kid_for_seed(self._rule["principals"], seed)
            if kid is None:
                raise RSLError(TRANSITION_UNAUTHORIZED,
                               "skip annotation signed by an unregistered "
                               "key")
            sigs[kid] = _ed.sign(seed, msg).hex()
        self._journal.append("rsl-skip", {
            "bundle": bundle, "target_seq": seq,
            "target_digest": target["state_digest"], "reason": reason,
            "signatures": sigs})

    # -- verify-time (never raises) --------------------------------------
    def verify(self, bundle, at_digest=None):
        """Re-check the whole log without trusting the writer."""
        try:
            return self._verify(bundle, at_digest)
        except RSLError as e:
            return {"ok": False, "code": e.code, "detail": e.detail}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "code": LOG_CORRUPT,
                    "detail": "verify failed unexpectedly: %r" % (e,)}

    def _verify(self, bundle, at_digest):
        try:
            journal = Journal(self._journal.path)  # fresh chain-verified read
        except JournalCorrupted as e:
            raise RSLError(LOG_CORRUPT,
                           "journal failed chain verification: %s" % e)
        try:
            self._check_bundle(bundle)
        except ValueError as e:
            raise RSLError(TRANSITION_UNAUTHORIZED,
                           "bundle not covered by this rule file: %s" % e)
        if self._rule["expires"] <= self._now_fn():
            raise RSLError(RULE_EXPIRED,
                           "rule file expired at %r (now %r)" %
                           (self._rule["expires"], self._now_fn()))
        states = self._states(journal.records, bundle)
        if not states:
            raise RSLError(TRANSITION_UNAUTHORIZED,
                           "no state recorded for bundle; no authorized "
                           "transition leads here")
        states.sort(key=lambda b: b["seq"])
        seqs = [b["seq"] for b in states]
        if len(set(seqs)) != len(seqs):
            raise RSLError(FORK_DETECTED,
                           "duplicate per-bundle seq: forked log")
        parents = [b["prev_digest"] for b in states
                   if b["prev_digest"] is not None]
        if len(set(parents)) != len(parents):
            raise RSLError(FORK_DETECTED,
                           "multi-parent: two entries share one parent")
        for i, body in enumerate(states):
            if body["seq"] != i:
                raise RSLError(LOG_CORRUPT,
                               "non-contiguous seq at position %d" % i)
            if i == 0:
                if body["prev_digest"] is not None:
                    raise RSLError(LOG_CORRUPT, "genesis entry has a parent")
            elif body["prev_digest"] != states[i - 1]["state_digest"]:
                raise RSLError(LOG_CORRUPT,
                               "chain break at seq %d" % body["seq"])
        for body in states:
            stmt = self._find_transition_in(journal.records, bundle,
                                            body["prev_digest"],
                                            body["state_digest"])
            if stmt is None or stmt.get("statement_id") != body.get(
                    "transition"):
                raise RSLError(TRANSITION_UNAUTHORIZED,
                               "seq %d references no valid transition "
                               "statement" % body["seq"])
            _verify_statement_sigs(self._rule, stmt)
        for rec in journal.records:
            if rec["type"] != "rsl-skip":
                continue
            skip = rec["body"]
            # F274: a malformed skip is dishonored, never allowed to
            # fail the whole bundle. The dict guard comes FIRST --
            # a non-dict body has no .get, and reaching for "bundle"
            # before the guard would brick verification with a raw
            # AttributeError (the exact DoS class this closes).
            if not isinstance(skip, dict):
                continue  # malformed skip: dishonored
            if skip.get("bundle") != bundle:
                continue
            # Shape-check before the bound comparison (a non-int
            # target_seq would raise TypeError and brick verification
            # via LOG_CORRUPT).
            target_seq = skip.get("target_seq")
            if not _is_epoch_int(target_seq) \
                    or not (0 <= target_seq <= states[-1]["seq"]):
                continue  # malformed skip: dishonored
            if not _verify_skip_sigs(self._rule, skip):
                continue  # forged/unsigned/malformed skip: dishonored
            raise RSLError(SKIPPED_REVOKED,
                           "seq %d revoked by skip annotation: %s" %
                           (skip["target_seq"],
                            skip.get("reason", "?")))
        tip = states[-1]["state_digest"]
        if at_digest is None or at_digest == tip:
            return {"ok": True, "code": None,
                    "detail": "chain verified: %d states, tip %s..." %
                              (len(states), tip[:16])}
        if at_digest in {b["state_digest"] for b in states}:
            raise RSLError(ROLLBACK_ATTEMPT,
                           "requested digest is an ancestor of the tip; "
                           "pinning it as current is a rollback")
        raise RSLError(TRANSITION_UNAUTHORIZED,
                       "unknown state digest; no authorized transition "
                       "leads here")

    # -- helpers ----------------------------------------------------------
    def _next_seq(self, records, bundle):
        states = self._states(records, bundle)
        return max([b["seq"] for b in states], default=-1) + 1

    def _find_transition(self, bundle, from_digest, to_digest):
        return self._find_transition_in(self._journal.records, bundle,
                                        from_digest, to_digest)

    @staticmethod
    def _find_transition_in(records, bundle, from_digest, to_digest):
        for rec in records:
            if rec["type"] != "rsl-transition":
                continue
            body = rec["body"]
            if (body.get("bundle") == bundle
                    and body.get("from_digest") == from_digest
                    and body.get("to_digest") == to_digest):
                return body
        return None
