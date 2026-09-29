"""Opt-in signed-card inventory (wave-214 lane A).

The ASI07 countermeasure at the discovery/inventory seam: an inventory
registry that admits an agent's card ONLY when its flattened-JWS
signatures verify against the deployment's pinned
``CardTrustStore`` (``gov.agent_cards``). This is the ADAPT half of the
A2A §8.4 shape-steal — verification is MUST, never MAY, and unsigned
cards fail closed.

OPT-IN, TIGHTEN-ONLY:

  - ``CardInventory(store=None)`` starts in LEGACY mode: unsigned
    discovery records still admit (the existing
    ``gov.discovery`` census keeps working; nothing already deployed
    breaks).
  - The operator pins a keyset with ``pin_keyset(store)`` — an
    explicit, auditable deployment act. From that moment, admission
    REQUIRES a valid signed card; unsigned, forged, expired, or
    version-drifted cards are refused with the verifier's distinct
    code. Pinning never loosens: there is no silent downgrade back to
    legacy. Re-pinning to a different keyset is likewise an explicit
    operator act (``pin_keyset`` again).
  - Legacy admission records are marked ``mode: "legacy-unsigned"``;
    signed admissions carry ``mode: "signed"`` plus the verified kids.
    A deployment auditing its inventory can enumerate every
    legacy-mode record as residual unsigned trust.

This module never touches ``gov.discovery``: the wiring is by
reference — the deployment calls ``admit_card`` with the card the
discovery census surfaced (or with ``None``-equivalent unsigned
records in legacy mode). No network, no fetch, no A2A transport.

$0 spend, synthetic/local only. No credentials, no network.
"""

import time

from .agent_cards import CardTrustStore, CardVerificationError, verify_card

_LEGACY_MODE = "legacy-unsigned"
_SIGNED_MODE = "signed"


class CardInventory(object):
    """The deployment's signed-card inventory.

    ``store``: a ``CardTrustStore`` or None (legacy mode). ``now_fn``
    injectable for tests.
    """

    def __init__(self, store=None, now_fn=None):
        if store is not None and not isinstance(store, CardTrustStore):
            raise TypeError("store must be a CardTrustStore or None")
        self._store = store
        self._now_fn = now_fn or time.time
        # agent_id -> admission record. Records never mutate in place;
        # re-admission replaces the record (auditable operator act).
        self._records = {}

    # ------------------------------------------------------------------
    # Operator acts
    # ------------------------------------------------------------------

    def pin_keyset(self, store):
        """Pin (or re-pin) the verification keyset. Explicit deployment
        act; from this call on, unsigned cards fail closed."""
        if not isinstance(store, CardTrustStore):
            raise TypeError("store must be a CardTrustStore")
        self._store = store

    @property
    def keyset_pinned(self):
        """True once the operator has pinned a keyset (tighten-only)."""
        return self._store is not None

    # ------------------------------------------------------------------
    # Admission
    # ------------------------------------------------------------------

    def admit_card(self, card, *, now=None):
        """Admit an agent card into the inventory.

        Legacy mode (no keyset pinned): records ``agent_id``/``name``
        with ``mode: "legacy-unsigned"`` — discovery keeps working.
        Pinned mode: ``verify_card`` MUST succeed or
        ``CardVerificationError`` propagates (fail-closed); the record
        carries ``mode: "signed"`` and the verified kids.

        Returns the admission record. Never admits silently: every
        refusal raises with the verifier's distinct code.
        """
        now = self._now_fn() if now is None else now
        if self._store is None:
            agent_id = card.get("agent_id") if isinstance(card, dict) else None
            name = card.get("name") if isinstance(card, dict) else None
            if not isinstance(agent_id, str) or not agent_id:
                raise CardVerificationError(
                    "malformed-card",
                    "legacy admission requires a non-empty agent_id")
            record = {"agent_id": agent_id, "name": name,
                      "mode": _LEGACY_MODE, "admitted_at": now, "kids": []}
            self._records[agent_id] = record
            return record
        result = verify_card(card, self._store, now=now)
        record = {"agent_id": card["agent_id"], "name": result["identity"],
                  "mode": _SIGNED_MODE, "admitted_at": now,
                  "kids": list(result["kids"])}
        self._records[card["agent_id"]] = record
        return record

    # ------------------------------------------------------------------
    # Reads (safe: no key material)
    # ------------------------------------------------------------------

    def lookup(self, agent_id):
        """Return the admission record for ``agent_id`` or None."""
        return self._records.get(agent_id)

    def list_agents(self):
        """Sorted agent_ids currently admitted."""
        return sorted(self._records)

    def describe(self):
        """Safe public description: modes and kids, never key material."""
        return {"keyset_pinned": self.keyset_pinned,
                "records": {aid: {"name": rec["name"], "mode": rec["mode"],
                                  "kids": list(rec["kids"])}
                            for aid, rec in sorted(self._records.items())}}
