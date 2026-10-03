"""Composed memory path: reconcile decisions applied to the bi-temporal store.

``gov/memory_store.py`` (bi-temporal evidence store: episodes, supersession,
signed tombstones, retention schedules) and ``gov/memory_reconcile.py``
(reconciliation seam: ADD/UPDATE/DELETE/NOOP, per-agent namespacing, sharing
grants, poisoning defenses) were built in parallel and never composed. The
wave-299 red team documented six seam hazards (``SeamHazardTest`` in
``evals/w299_redteam_probes.py``); this module resolves them with explicit,
documented decisions. Neither submodule's semantics are changed -- this
module ADAPTS between them (adapters, not rewrites).

Standing design rule: "Recollection is a claim, not a fact."

DECISIONS (each resolves one documented hazard):

1. NAMESPACE (hazard: store has no namespace concept; reconcile mandates
   it). The composer holds ONE ``MemoryStore`` PER NAMESPACE
   (``{namespace: MemoryStore}``), bound explicitly or lazily on first
   write. Namespace isolation is PHYSICAL: a second store object offered
   for an already-bound namespace refuses ``memory-composed-divergent``
   (fork attempt). The store's ``agent_id``/``source_principal`` on
   composed records is the namespace itself; the grant model lives in
   the reconciler and is enforced on every composed recall. Rejected
   alternative: mangling the namespace into the store's statement_key
   (``ns/key``) -- violates the store's id grammar and leaks the grant
   model into string parsing.

2. FACT_ID (hazard: store ``digest(seq, body)`` vs reconcile
   ``digest(namespace, key, value_digest, written_at, supersedes)``).
   The CANONICAL fact id on the composed path is the RECONCILE
   derivation: content-derived, externally reproducible, so a third
   party can recompute it without the engine (evidence discipline).
   The store's seq-derived id stays internal -- it is never exposed
   through the composed API; the composer keeps a
   ``(namespace, key) -> generation -> store_fact_id`` ledger.
   Rejected alternative: store derivation canonical -- ids would be
   verifier-local and unreproducible, breaking offline verification.

3. TOMBSTONE / RE-ADMISSION (hazard: store tombstone is per-KEY and
   permanent; reconcile tombstone is per-RECORD and re-admittable via
   a new ADD). RECONCILE SEMANTICS WIN: a retraction withdraws the
   CLAIM, not the key forever. Implemented WITHOUT touching the store:
   each tombstone generation writes under a new store key --
   generation 0 uses the bare key, generation N>=1 uses
   ``"<key>-g<N>"``. The store's permanent per-key tombstone becomes
   per-GENERATION (each generation's tombstone is permanent and
   auditable -- a feature, not a limitation). ``composed_recall``
   always resolves the latest generation. Cost, documented: composed
   keys must match the store's key grammar ``[a-z][a-z0-9-]`` (the
   reconciler accepts wider keys, but the store grammar is immutable)
   and are limited to 48 chars (room for the suffix inside the
   store's 64-char id grammar); violations refuse
   ``memory-composed-key-invalid`` / ``memory-composed-key-too-long``
   BEFORE the reconcile decision, so a refused key never advances the
   reconciler's inventory. Rejected alternative: store
   semantics win (key dead forever) -- too strong, and it would make
   F374's tombstone hazard permanent by design. Rejected alternative
   for the grammar: an opaque digest-suffixed key encoding -- it would
   preserve slash-keys at the cost of an unauditable translation layer;
   fail-closed narrowing (same principle as the grade decision) won.

4. GRADES (hazard: store ``(letter, int)`` vs reconcile 8-token set).
   The composed path accepts ONLY the reconcile closed vocabulary
   (``A1/A2/B1/B2/C1/C2/C3/D4``) and maps it onto the store by
   splitting (``"C3" -> ("C", 3)``). The store's wider 36-combination
   space is NOT reachable through the composed path -- fail-closed
   narrowing. Rationale: the poisoning defenses key on the 8-token
   set (``_HIGH_RELIABILITY``); widening the vocabulary at the seam
   would weaken them. Rejected alternative: store vocabulary
   canonical -- breaks the conflict-evidence requirement.

5. TEMPORAL MODEL (hazard: store bi-temporal vs reconcile
   single-timeline). The reconcile timeline MAPS ONTO the store's
   bi-temporal model: ``written_at`` becomes BOTH ``valid_at`` and
   ``created_at`` (a composed write asserts a current belief --
   backdating is not offered on this path), and ``expires_at``
   becomes ``retain_until``. ``invalid_at``/``expired_at`` are managed
   by the store's native supersession/retraction. The store's
   bi-temporal recall is AUTHORITATIVE at composed recall: the
   reconciler does not check temporal windows, so a recall before
   ``valid_at`` refuses ``memory-store-expired`` and a lapsed
   retention refuses ``memory-store-retention-lapsed`` -- the store's
   strictness is a feature. Rejected alternative: dropping the
   bi-temporal claim -- would discard the evidence layer's history
   semantics.

6. SIGNATURE DOMAINS (hazard: store = source-key signatures; reconcile
   = namespace-owner signatures). The composed trust anchor is the
   NAMESPACE OWNER's key. The composer holds owner seeds
   (deployment-owned custody, passed at construction) and signs the
   bridge episodes, store facts, and store retractions under the
   owner key. The ORIGINAL observer principal is preserved -- not as
   a store-level signing identity, but in the reconcile decision's
   provenance (signed by the reconciler, re-verifiable). Rationale:
   one writer per namespace store (the composer, for the owner) is
   what makes F374-class retraction-authority attacks impossible on
   the composed path: there is no second writer to migrate authority
   to. Rejected alternative: dual signatures (owner + observer) --
   doubles the key-management surface for no added assurance, since
   the reconciler already authenticated the observer's claim.

BRIDGE EPISODES: the store requires every fact to cite a recorded
episode. The composer records one bridge episode per write:
``{agent_id: namespace, content_digest: value_digest,
source_principal: namespace, source_pubkey: owner_key,
recorded_at: written_at}``, signed by the owner key. The episode
attests "namespace N recorded digest V at T" -- which is true. The
original observer's identity lives in the reconcile provenance.

FORK DETECTION: the composer is the single writer to both layers, so
they cannot diverge through it. If they ever do (a second writer
touched either layer directly), the composed path refuses
``memory-composed-divergent``: at write, an UPDATE/DELETE/NOOP for a
key with no composed ledger entry; at recall, a reconciler-live fact
with no ledger entry, a missing store binding, or a store record
whose digest disagrees with the reconcile record.

All instants are caller-supplied (freshness markers, not a clock).
In-memory per composer (wave-292 decay precedent): not distributed
consensus. The audit sink is F345-class (never breaks the module).

THREAT MODEL: the namespace-owner keys (held by the composer) and the
reconciler seed are the trust anchors. A compromised owner key can
write false facts into its OWN namespace -- compromised-host class;
the poisoning defenses still bound it (rate, evidence, snapshots),
and every decision is signed and re-verifiable. The composer never
exfiltrates keys: signatures are computed in-process, digests and ids
only reach the sink.
"""

import hashlib
import json
import re

from gov import ed25519
from gov import memory_reconcile as _mr
from gov import memory_store as _ms

# ---------------------------------------------------------------------------
# Decision codes (registered at true sorted positions in
# gov/decision_codes.py; pin 1797 -> 1800).
# ---------------------------------------------------------------------------

MC_DIVERGENT = "memory-composed-divergent"
MC_KEY_TOO_LONG = "memory-composed-key-too-long"
MC_KEY_INVALID = "memory-composed-key-invalid"

# Reused (not minted): the submodules' own coded refusals propagate
# with their codes -- memory-reconcile-* for decision/grant/scope
# refusals, memory-store-* for temporal/tombstone/retention refusals.

__all__ = [
    "MemoryComposer",
    "MemoryComposedError",
    "MC_DIVERGENT",
    "MC_KEY_TOO_LONG",
    "MC_KEY_INVALID",
    "MAX_COMPOSED_KEY_LEN",
]

# Composed keys must satisfy the STORE's key grammar (immutable --
# adapters, not rewrites) AND leave room for the "-g<N>" generation
# suffix inside the store's 64-char id limit. The reconciler accepts
# wider keys (up to 256 chars, any charset); the composed path narrows
# fail-closed to the intersection rather than inventing a lossy or
# opaque key encoding. Enforced before the reconcile decision so a
# refused key never advances the reconciler's inventory (no wedge).
_KEY_RE = re.compile(r"^[a-z][a-z0-9-]*$")
MAX_COMPOSED_KEY_LEN = 48

_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


class MemoryComposedError(Exception):
    """Base class; carries the machine ``code`` so every refusal is
    coded -- the F351 contract."""

    code = _mr.RC_INVALID

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise MemoryComposedError(detail, code=code)


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        _fail(_mr.RC_INVALID, "memory material is not canonicalizable "
                              "(circular or non-JSON structure)")


def _check_id(value, what="id"):
    if not isinstance(value, str) or not _ID_RE.match(value):
        _fail(_mr.RC_INVALID,
              "%s must match [a-z][a-z0-9-]{0,63}; got %r" % (what, value))


def _check_seed(value, what="owner seed"):
    if not isinstance(value, bytes) or len(value) != 32:
        _fail(_mr.RC_INVALID, "%s must be 32 raw bytes" % what)


def _split_grade(token):
    """Decision 4: the composed path accepts only the reconcile closed
    grade vocabulary; split onto the store's (letter, int) axes."""
    # The reconciler already validated the token against its closed
    # set; this is a second, independent parse (defense in depth).
    if (not isinstance(token, str) or len(token) < 2
            or token[0] not in "ABCD" or not token[1:].isdigit()):
        _fail(_mr.RC_INVALID,
              "grade token %r is not a closed-vocabulary grade" % (token,))
    return token[0], int(token[1:])


class MemoryComposer:
    """The single composed write/recall path over a MemoryReconciler
    (decisions, grants, poisoning defenses) and per-namespace
    MemoryStores (bi-temporal evidence, episodes, tombstones).

    ``owner_seeds`` maps namespace -> 32-byte ed25519 seed. The
    composer signs bridge episodes, store facts, and store
    retractions under the namespace owner's key (Decision 6);
    custody of these seeds is deployment-owned.
    """

    def __init__(self, reconciler, owner_seeds):
        if not isinstance(reconciler, _mr.MemoryReconciler):
            _fail(_mr.RC_INVALID, "reconciler must be a MemoryReconciler")
        if not isinstance(owner_seeds, dict):
            _fail(_mr.RC_INVALID, "owner_seeds must be a dict of "
                                  "namespace -> 32-byte seed")
        for ns, seed in owner_seeds.items():
            _check_id(ns, "owner_seeds namespace")
            _check_seed(seed, "owner seed for %r" % ns)
        self._reconciler = reconciler
        self._owner_seeds = dict(owner_seeds)
        self._stores = {}    # namespace -> MemoryStore (Decision 1)
        self._ledger = {}    # (namespace, key) -> current generation info

    # -- namespace / store binding (Decision 1) -----------------------

    def bind_store(self, namespace, store):
        """Bind a MemoryStore to a namespace explicitly. The namespace
        must be declared in the reconciler."""
        _check_id(namespace, "namespace")
        if not isinstance(store, _ms.MemoryStore):
            _fail(_mr.RC_INVALID, "store must be a MemoryStore")
        # Same trust plane: read the reconciler's closed inventory
        # (in-process composition; the reconciler offers no getter).
        if namespace not in self._reconciler._namespaces:
            _fail(_mr.RC_UNAUTH_NS,
                  "namespace %r is not declared in the reconciler"
                  % namespace)
        self._stores[namespace] = store

    def _store_for(self, namespace, store):
        """Resolve the store for a namespace: the caller may pass it
        per call (task signature); the first store seen binds, and a
        DIFFERENT store object afterwards is a fork attempt."""
        bound = self._stores.get(namespace)
        if bound is None:
            if store is None:
                _fail(_mr.RC_INVALID,
                      "composed_write requires a store for namespace %r"
                      % namespace)
            if not isinstance(store, _ms.MemoryStore):
                _fail(_mr.RC_INVALID, "store must be a MemoryStore")
            self._stores[namespace] = store
            return store
        if store is not None and store is not bound:
            _fail(MC_DIVERGENT,
                  "a different store object was offered for namespace %r "
                  "than the bound one -- refusing to fork the namespace"
                  % namespace)
        return bound

    # -- owner key (Decision 6) ----------------------------------------

    def _owner(self, namespace):
        seed = self._owner_seeds.get(namespace)
        if seed is None:
            _fail(_mr.RC_UNAUTH_NS,
                  "composer holds no signing key for namespace %r -- "
                  "cannot act for its owner" % namespace)
        pubkey = ed25519.publickey(seed).hex()
        declared = self._reconciler._namespaces.get(namespace)
        if declared is None:
            _fail(_mr.RC_UNAUTH_NS,
                  "namespace %r is not declared in the reconciler"
                  % namespace)
        if declared != pubkey:
            _fail(_mr.RC_UNAUTH_NS,
                  "composer key for %r does not match the reconciler's "
                  "declared owner key" % namespace)
        return seed, pubkey

    # -- bridge episode + store application ----------------------------

    def _bridge_episode(self, mem_store, namespace, owner_seed,
                        owner_pubkey, candidate):
        """Decision: one bridge episode per write, attesting what the
        composer (for the owner) actually did. The original observer
        stays in the reconcile provenance."""
        body = {
            "agent_id": namespace,
            "content_digest": candidate["value_digest"],
            "source_principal": namespace,
            "source_pubkey": owner_pubkey,
            "recorded_at": candidate["written_at"],
        }
        sig = ed25519.sign(owner_seed, _canonical(body)).hex()
        return mem_store.record_episode(
            namespace, candidate["value_digest"], namespace,
            owner_pubkey, sig, candidate["written_at"])

    def _apply_fact(self, mem_store, store_key, candidate, episode_id,
                    namespace, owner_seed, owner_pubkey):
        """Decision 5: written_at -> valid_at AND created_at;
        expires_at -> retain_until. Decision 4: grade token split."""
        reliability, credibility = _split_grade(
            candidate["provenance"]["reliability"])
        body = {
            "statement_key": store_key,
            "statement_digest": candidate["value_digest"],
            "source_episode_ids": [episode_id],
            "source_principal": namespace,
            "source_pubkey": owner_pubkey,
            "valid_at": candidate["written_at"],
            "retain_until": candidate.get("expires_at"),
            "reliability": reliability,
            "credibility": credibility,
            "created_at": candidate["written_at"],
        }
        sig = ed25519.sign(owner_seed, _canonical(body)).hex()
        return mem_store.record_fact(
            store_key, candidate["value_digest"], [episode_id],
            namespace, owner_pubkey, sig,
            candidate["written_at"], candidate["written_at"],
            retain_until=candidate.get("expires_at"),
            reliability=reliability, credibility=credibility)

    def _apply_retract(self, mem_store, store_key, namespace, owner_seed,
                       owner_pubkey, at):
        body = {
            "statement_key": store_key,
            "retractor_principal": namespace,
            "retractor_pubkey": owner_pubkey,
            "retracted_at": at,
        }
        sig = ed25519.sign(owner_seed, _canonical(body)).hex()
        return mem_store.retract_fact(store_key, namespace, owner_pubkey,
                                      sig, at)

    # -- the composed write path ----------------------------------------

    def composed_write(self, namespace, candidate, store, policy, at):
        """Run the reconcile decision, then apply it to the namespace's
        store. Returns {"decision", "store_key", "generation",
        "store_fact_id"}. Every refusal is coded (F351)."""
        _check_id(namespace, "namespace")
        if not isinstance(candidate, dict):
            _fail(_mr.RC_INVALID, "candidate must be a dict")
        if candidate.get("namespace") != namespace:
            _fail(_mr.RC_INVALID,
                  "candidate namespace %r does not match the composed "
                  "namespace %r -- the call is bound to its candidate"
                  % (candidate.get("namespace"), namespace))
        key = candidate.get("key")
        if not isinstance(key, str) or len(key) > MAX_COMPOSED_KEY_LEN:
            _fail(MC_KEY_TOO_LONG,
                  "composed keys are bounded at %d chars (room for the "
                  "tombstone-generation suffix inside the store's id "
                  "grammar); got %d chars"
                  % (MAX_COMPOSED_KEY_LEN,
                     len(key) if isinstance(key, str) else -1))
        if not _KEY_RE.match(key):
            _fail(MC_KEY_INVALID,
                  "composed keys must match the store key grammar "
                  "[a-z][a-z0-9-] (the reconciler accepts wider keys, "
                  "but the store's grammar is immutable); got %r" % key)
        if not isinstance(policy, dict):
            _fail(_mr.RC_INVALID, "policy must be a dict")
        if not isinstance(at, int) or isinstance(at, bool) or at < 0:
            _fail(_mr.RC_INVALID, "at must be a non-negative int")

        owner_seed, owner_pubkey = self._owner(namespace)
        mem_store = self._store_for(namespace, store)

        # The reconciler's own inventory is the history the decision
        # is taken against (same trust plane; the reconciler offers no
        # public history getter). The fork check inside reconcile()
        # then compares the inventory against itself -- which is
        # correct here because the composer is the single writer: any
        # divergence would have to come from outside the composed
        # path, and that is caught at recall/ledger time.
        existing = list(
            self._reconciler._facts.get((namespace, key), []))
        decision = self._reconciler.reconcile(candidate, existing,
                                              policy, at)
        if not self._reconciler.verify_decision(decision):
            _fail(_mr.RC_INVALID, "reconciler decision does not re-verify")

        ledger_key = (namespace, key)
        entry = self._ledger.get(ledger_key)
        d = decision["decision"]

        if d == _mr.RC_ADD:
            if entry is not None:
                if not entry["tombstoned"]:
                    _fail(MC_DIVERGENT,
                          "reconciler decided ADD for (%r, %r) but the "
                          "composer already holds a live generation -- "
                          "the reconciler inventory lost history"
                          % (namespace, key))
                gen = entry["generation"] + 1
                store_key = "%s-g%d" % (key, gen)
            else:
                if existing:
                    _fail(MC_DIVERGENT,
                          "reconciler decided ADD for (%r, %r) with "
                          "existing history the composer never wrote"
                          % (namespace, key))
                gen = 0
                store_key = key
            episode_id = self._bridge_episode(
                mem_store, namespace, owner_seed, owner_pubkey, candidate)
            store_fact_id = self._apply_fact(
                mem_store, store_key, candidate, episode_id,
                namespace, owner_seed, owner_pubkey)
            self._ledger[ledger_key] = {
                "generation": gen,
                "store_key": store_key,
                "tombstoned": False,
                "reconcile_fact_id": decision["fact_id"],
                "store_fact_id": store_fact_id,
            }
        elif d == _mr.RC_UPDATE:
            if entry is None or entry["tombstoned"]:
                _fail(MC_DIVERGENT,
                      "reconciler decided UPDATE for (%r, %r) with no "
                      "live composed generation" % (namespace, key))
            store_key = entry["store_key"]
            gen = entry["generation"]
            episode_id = self._bridge_episode(
                mem_store, namespace, owner_seed, owner_pubkey, candidate)
            store_fact_id = self._apply_fact(
                mem_store, store_key, candidate, episode_id,
                namespace, owner_seed, owner_pubkey)
            entry["reconcile_fact_id"] = decision["fact_id"]
            entry["store_fact_id"] = store_fact_id
        elif d == _mr.RC_DELETE:
            if entry is None or entry["tombstoned"]:
                _fail(MC_DIVERGENT,
                      "reconciler decided DELETE for (%r, %r) with no "
                      "live composed generation" % (namespace, key))
            store_key = entry["store_key"]
            gen = entry["generation"]
            self._apply_retract(mem_store, store_key, namespace,
                                owner_seed, owner_pubkey, at)
            entry["tombstoned"] = True
            store_fact_id = entry["store_fact_id"]
        elif d == _mr.RC_NOOP:
            if entry is None:
                _fail(MC_DIVERGENT,
                      "reconciler decided NOOP for (%r, %r) the composer "
                      "never wrote" % (namespace, key))
            store_key = entry["store_key"]
            gen = entry["generation"]
            store_fact_id = entry["store_fact_id"]
        else:  # pragma: no cover -- the reconciler's vocabulary is closed
            _fail(_mr.RC_INVALID,
                  "unknown reconcile decision %r" % (d,))

        return {"decision": decision,
                "store_key": store_key,
                "generation": gen,
                "store_fact_id": store_fact_id}

    # -- the composed recall path ----------------------------------------

    def composed_recall(self, namespace, scope, caller_namespace, at,
                          grant=None):
        """Grant-enforced (reconciler) + bi-temporal (store) recall.
        Returns the merged claim view. The store's temporal checks are
        authoritative: a claim not yet valid refuses
        ``memory-store-expired``; a lapsed retention refuses
        ``memory-store-retention-lapsed``; a withdrawn claim refuses
        ``memory-store-tombstoned``.

        Cross-namespace recall takes the bearer-grant model from
        ``gov/memory_reconcile.py`` (F376, wave-300): the caller
        presents the signed sharing grant via ``grant``; it is verified
        against the owner namespace's DECLARED owner key, its window,
        the live inventory, and revocation. A bare caller string
        refuses ``memory-reconcile-unauthorized-namespace``."""
        _check_id(namespace, "namespace")
        if not isinstance(scope, dict):
            _fail(_mr.RC_SCOPE_MISSING,
                  "composed recall requires a scope predicate")
        if scope.get("namespace") != namespace:
            _fail(_mr.RC_INVALID,
                  "composed recall is namespace-bound: scope namespace "
                  "%r != %r" % (scope.get("namespace"), namespace))
        key = scope.get("key")
        # Grant model, scope predicate, tombstone exclusion: the
        # reconciler enforces all three (coded refusals propagate).
        rec = self._reconciler.recall(scope, caller_namespace, at,
                                      grant=grant)

        entry = self._ledger.get((namespace, key))
        if entry is None:
            _fail(MC_DIVERGENT,
                  "reconciler holds a live fact for (%r, %r) the "
                  "composer never wrote" % (namespace, key))
        mem_store = self._stores.get(namespace)
        if mem_store is None:
            _fail(MC_DIVERGENT,
                  "no store bound for namespace %r" % namespace)
        # Bi-temporal recall (Decision 5): the store's temporal checks
        # are authoritative; its coded refusals propagate unchanged.
        srec = mem_store.recall(entry["store_key"], at)
        if srec["statement_digest"] != rec["value_digest"]:
            _fail(MC_DIVERGENT,
                  "store and reconciler disagree on the live value for "
                  "(%r, %r): store digest %s != reconcile digest %s"
                  % (namespace, key, srec["statement_digest"][:12],
                     rec["value_digest"][:12]))
        return {
            "namespace": namespace,
            "key": key,
            "value_digest": rec["value_digest"],
            "reconcile_fact_id": rec["fact_id"],   # Decision 2: canonical
            "store_fact_id": srec["fact_id"],      # internal handle only
            "generation": entry["generation"],     # Decision 3
            "state": rec["state"],
            "provenance": dict(rec["provenance"]),
            "reliability_grade": srec["reliability_grade"],
            "corroboration_count": srec["corroboration_count"],
            "source_episode_ids": list(srec["source_episode_ids"]),
            "valid_at": srec["valid_at"],
            "invalid_at": srec["invalid_at"],
            "created_at": srec["created_at"],
            "expired_at": srec["expired_at"],
            "retain_until": srec["retain_until"],
        }

    def composed_history(self, namespace, key, at):
        """Both histories for a key: the reconcile decision lineage
        and the current generation's bi-temporal store history."""
        _check_id(namespace, "namespace")
        if not isinstance(key, str) or not key:
            _fail(_mr.RC_INVALID, "key must be a non-empty string")
        if not isinstance(at, int) or isinstance(at, bool) or at < 0:
            _fail(_mr.RC_INVALID, "at must be a non-negative int")
        entry = self._ledger.get((namespace, key))
        if entry is None:
            _fail(MC_DIVERGENT,
                  "no composed history for (%r, %r)" % (namespace, key))
        mem_store = self._stores.get(namespace)
        if mem_store is None:
            _fail(MC_DIVERGENT,
                  "no store bound for namespace %r" % namespace)
        reconcile_history = [
            {k: r[k] for k in ("fact_id", "namespace", "key",
                               "value_digest", "state", "written_at",
                               "supersedes", "provenance", "expires_at")
             if k in r}
            for r in self._reconciler._facts.get((namespace, key), [])
        ]
        return {"reconcile_history": reconcile_history,
                "generation": entry["generation"],
                "store_history": mem_store.history(entry["store_key"], at)}
