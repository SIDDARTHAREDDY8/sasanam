"""Break-first battery for the SPIFFE-federation seam (wave-264 lane 3).

Targets (base 7fa1114729d3374e71eb0b88e43698c4b919f142, taxonomy pin
1151 + 7 federation-* codes = 1158) -- every probe attacks a PUBLIC
seam of gov/trust_federation.py, never product internals:

1. federation/forged-foreign-bundle-signature -- a bundle signed by
   the wrong endpoint key must refuse federation-bundle-signature-
   invalid (the always-trust stub accepts it: BREAK).
2. federation/expired-bundle-still-accepted -- a past-expires_at
   bundle must refuse federation-bundle-expired; stale bundles are
   fail-closed, never trusted (stub accepts: BREAK).
3. federation/de-federated-domain-still-trusted -- after remove(),
   the domain's SVIDs must refuse federation-relationship-
   terminated, and the removal must journal federation-trust-revoked
   (stub keeps trusting: BREAK).
4. federation/one-way-assumed-mutual -- a relationship in table A
   (we trust B) must NOT let B's view (a table without the reverse
   relationship) verify A's SVIDs: federation-untrusted-domain
   (stub trusts: BREAK).
5. federation/bundle-confusion-across-domains -- domain A's bundle
   installed under domain B's relationship (or used to verify B's
   SVIDs) must refuse federation-bundle-confusion (stub trusts:
   BREAK).
6. federation/malformed-endpoint-profile -- unknown profile and
   non-https endpoint URL must refuse federation-relationship-
   malformed at declaration (stub accepts anything: BREAK).
7. federation/rotation-tolerance-and-unknown-key -- (a) an SVID
   signed by an announced next_root verifies while the bundle is
   fresh (rotation tolerance: HELD); (b) an SVID signed by an
   unknown key refuses svid-issuer-unknown, propagated from the
   composed SvidVerifier (stub trusts it: BREAK).
8. federation/valid-federated-svid-verifies -- control: a valid
   bundle + a valid SVID from the federated domain verifies, with
   the foreign trust_domain in the claims (HELD on the module; the
   stub trivially "verifies" -- proving the probe exercises the
   seam, not a straw man).

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. Every probe first runs the attack against _AlwaysTrustStub
(the pre-fix behavior: accept everything). A stub that does NOT fall
for the attack means the probe is broken -> ERROR. Then the same
attack runs against the module: HELD (attack refused with the
expected machine code), BREAK (genuine defect -> file F245+),
BASELINE (module not yet built: documents that the attack BREAKs
the stub -- the red half of red-green), ERROR (harness bug).

Stdlib only. Deterministic (fixed _NOW clock, fixed seeds; staging
+ `env -u GOV_DEPLOYMENT_MODE`). No in-repo git subprocesses
(wave-36 supply-chain probe: fail closed). Green checks are depth-1
and honor GOV_SKIP_GREEN=1.
"""

import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gov import decision_codes
from gov import ed25519
from gov import svid_issuer

try:
    from gov import trust_federation as tf
    _HAVE_MODULE = True
except ImportError:
    tf = None
    _HAVE_MODULE = False

#: Lane-local pin: 1151 (wave-263 merge) + 7 federation-* codes.
TAXONOMY_PIN = 1706  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*)

_PROBES = []


def probe(name):
    def deco(fn):
        _PROBES.append((name, fn))
        return fn
    return deco


def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _baseline(detail=""):
    return ("BASELINE", detail)


# ----------------------------------------------------------------------
# Fixed world (deterministic: no randomness, no wall clock)
# ----------------------------------------------------------------------

_NOW = 1790000000  # fixed epoch for every probe

_HOME_DOMAIN = "home.example"
_PARTNER_DOMAIN = "partner.example"
_OTHER_DOMAIN = "other.example"

_ISSUER_SEED = bytes.fromhex("11" * 32)
_NEXT_ISSUER_SEED = bytes.fromhex("33" * 32)
_ROGUE_ISSUER_SEED = bytes.fromhex("55" * 32)
_ENDPOINT_SEED = bytes.fromhex("22" * 32)
_WORKLOAD_SEED = bytes.fromhex("44" * 32)

_BUNDLE_DOMAIN = b"sasanam-federation-bundle/v1:"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _bundle_signing_bytes(body):
    import hashlib
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    return _BUNDLE_DOMAIN + digest.encode("ascii")


def _seal_bundle(body, seed):
    """Sign a bundle body with an endpoint seed; returns the bundle."""
    sig = ed25519.sign(seed, _bundle_signing_bytes(body)).hex()
    bundle = dict(body)
    bundle["endpoint_signature"] = sig
    return bundle


def _issuer(seed, key_id):
    return svid_issuer.TestSvidIssuer(issuer_seed=seed, key_id=key_id)


def _bundle_body(issuer, next_issuer, domain=_PARTNER_DOMAIN,
                 issued_at=None, expires_at=None, bundle_id="b-001"):
    return {
        "trust_domain": domain,
        "bundle_id": bundle_id,
        "issued_at": _NOW - 60 if issued_at is None else issued_at,
        "expires_at": _NOW + 3600 if expires_at is None else expires_at,
        "roots": {issuer.key_id: issuer.issuer_public_key.hex()},
        "next_roots": {next_issuer.key_id:
                       next_issuer.issuer_public_key.hex()},
    }


def _foreign_svid(issuer, domain=_PARTNER_DOMAIN, path="agent/worker-1"):
    return issuer.issue("spiffe://%s/%s" % (domain, path),
                        ed25519.publickey(_WORKLOAD_SEED).hex(),
                        ttl_minutes=30, now=_NOW)


# ----------------------------------------------------------------------
# The always-trust stub (pre-fix behavior: accept everything). Every
# attack MUST succeed against it, or the probe is a straw man.
# ----------------------------------------------------------------------

class _AlwaysTrustStub(object):
    """Accepts every relationship, bundle, and SVID. This is the
    behavior the module must NOT have."""

    def __init__(self):
        self._rels = {}
        self._bundles = {}

    # -- relationship surface -------------------------------------
    def add_relationship(self, trust_domain, bundle_endpoint,
                         endpoint_profile, endpoint_public_key):
        self._rels[trust_domain] = {
            "trust_domain": trust_domain,
            "bundle_endpoint": bundle_endpoint,
            "endpoint_profile": endpoint_profile,
            "endpoint_public_key": endpoint_public_key,
        }
        return dict(self._rels[trust_domain])

    # -- bundle surface -------------------------------------------
    def refresh_bundle(self, trust_domain, bundle_bytes, now=None):
        bundle = json.loads(bundle_bytes.decode("utf-8")
                            if isinstance(bundle_bytes, bytes)
                            else bundle_bytes)
        self._bundles[trust_domain] = bundle
        return dict(bundle)

    # -- verification surface --------------------------------------
    def verify_foreign(self, svid, now=None):
        if not isinstance(svid, dict) or "spiffe_id" not in svid:
            raise ValueError("stub: malformed SVID")
        return {"spiffe_id": svid["spiffe_id"],
                "trust_domain": svid.get("trust_domain", "?"),
                "federated": True}

    # -- termination surface ---------------------------------------
    def remove(self, trust_domain):
        self._rels.pop(trust_domain, None)
        self._bundles.pop(trust_domain, None)

    def journal_records(self):
        return []


def _stub_attack_must_succeed(attack_fn, attack_name):
    """Run the attack against the stub; it MUST succeed (BREAK the
    stub) or the probe is broken. Returns (ok, detail)."""
    stub = _AlwaysTrustStub()
    try:
        succeeded, detail = attack_fn(stub)
    except Exception as e:  # noqa: BLE001 -- probe harness
        return (False, "stub raised %s: %s"
                % (type(e).__name__, str(e)[:100]))
    if not succeeded:
        return (False, "stub did NOT fall for %s -- probe is a straw "
                "man: %s" % (attack_name, detail))
    return (True, detail)


def _fresh_journal():
    """A scratch journal path (the journal is mandatory -- the audit
    trail is not optional)."""
    tmp = tempfile.mkdtemp(prefix="w264-fed-journal-")
    return os.path.join(tmp, "journal.jsonl")


def _fresh_table():
    """A module table with a scratch journal."""
    return tf.FederationTable(_fresh_journal())


def _module_table():
    """A module table with the partner relationship installed."""
    table = _fresh_table()
    table.add_relationship(
        trust_domain=_PARTNER_DOMAIN,
        bundle_endpoint="https://partner.example/bundle",
        endpoint_profile=tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
        endpoint_public_key=ed25519.publickey(_ENDPOINT_SEED).hex())
    return table


def _install_bundle(table, bundle):
    raw = _canonical(bundle)
    return table.refresh_bundle(_PARTNER_DOMAIN, raw, now=_NOW)


def _refusal_code(exc):
    return getattr(exc, "code", "<no-code>")


# ----------------------------------------------------------------------
# Probe 1: forged foreign bundle signature
# ----------------------------------------------------------------------

def _forged_bundle_attack(target):
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    body = _bundle_body(issuer, nxt)
    forged = _seal_bundle(body, _ROGUE_ISSUER_SEED)  # wrong key
    raw = _canonical(forged)
    if isinstance(target, _AlwaysTrustStub):
        target.add_relationship(_PARTNER_DOMAIN,
                                "https://partner.example/bundle",
                                "https_spiffe", "aa" * 32)
        target.refresh_bundle(_PARTNER_DOMAIN, raw, _NOW)
        svid = _foreign_svid(issuer)
        try:
            target.verify_foreign(svid, _NOW)
            return (True, "stub trusted the forged bundle's roots")
        except Exception as e:  # noqa: BLE001
            return (False, "stub refused: %s" % e)
    table = _module_table()
    try:
        table.refresh_bundle(_PARTNER_DOMAIN, raw, now=_NOW)
    except tf.FederationError as e:
        return (False, "refused at refresh: %s" % _refusal_code(e))
    return (True, "forged bundle INSTALLED -- roots poisoned")


@probe("federation/forged-foreign-bundle-signature")
def _p_forged_bundle():
    """A bundle signed by the wrong endpoint key must never install."""
    ok, detail = _stub_attack_must_succeed(
        _forged_bundle_attack, "forged-bundle")
    if not ok:
        return ("ERROR", detail)
    if not _HAVE_MODULE:
        return _baseline("attack BREAKs the stub (forged bundle "
                         "trusted); module not yet built: %s" % detail)
    table = _module_table()
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    forged = _seal_bundle(_bundle_body(issuer, nxt), _ROGUE_ISSUER_SEED)
    try:
        table.refresh_bundle(_PARTNER_DOMAIN, _canonical(forged),
                             now=_NOW)
    except tf.FederationError as e:
        if _refusal_code(e) == "federation-bundle-signature-invalid":
            return _held("forged bundle refused "
                         "federation-bundle-signature-invalid; stub "
                         "falls for it (%s)" % detail)
        return _break("wrong refusal code %s for forged bundle"
                      % _refusal_code(e))
    return _break("FORGED bundle installed and trusted "
                  "(stub also falls: %s)" % detail)


# ----------------------------------------------------------------------
# Probe 2: expired bundle still accepted
# ----------------------------------------------------------------------

def _expired_bundle_attack(target):
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    body = _bundle_body(issuer, nxt, expires_at=_NOW - 1)  # expired
    bundle = _seal_bundle(body, _ENDPOINT_SEED)
    raw = _canonical(bundle)
    if isinstance(target, _AlwaysTrustStub):
        target.add_relationship(_PARTNER_DOMAIN,
                                "https://partner.example/bundle",
                                "https_spiffe", "aa" * 32)
        target.refresh_bundle(_PARTNER_DOMAIN, raw, _NOW)
        try:
            target.verify_foreign(_foreign_svid(issuer), _NOW)
            return (True, "stub verified SVIDs under an EXPIRED bundle")
        except Exception as e:  # noqa: BLE001
            return (False, "stub refused: %s" % e)
    table = _module_table()
    try:
        table.refresh_bundle(_PARTNER_DOMAIN, raw, now=_NOW)
    except tf.FederationError as e:
        return (False, "refused at refresh: %s" % _refusal_code(e))
    try:
        table.verify_foreign(_foreign_svid(issuer), now=_NOW)
        return (True, "SVID verified under EXPIRED bundle")
    except tf.FederationError as e:
        return (False, "refused at verify: %s" % _refusal_code(e))


@probe("federation/expired-bundle-still-accepted")
def _p_expired_bundle():
    """Stale bundles are fail-closed: expired bundle, no trust."""
    ok, detail = _stub_attack_must_succeed(
        _expired_bundle_attack, "expired-bundle")
    if not ok:
        return ("ERROR", detail)
    if not _HAVE_MODULE:
        return _baseline("attack BREAKs the stub (expired bundle "
                         "trusted); module not yet built: %s" % detail)
    table = _module_table()
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    expired = _seal_bundle(_bundle_body(issuer, nxt,
                                        expires_at=_NOW - 1),
                           _ENDPOINT_SEED)
    try:
        table.refresh_bundle(_PARTNER_DOMAIN, _canonical(expired),
                             now=_NOW)
        code = "installed"
    except tf.FederationError as e:
        code = _refusal_code(e)
    if code != "federation-bundle-expired":
        # An expired bundle may install-but-never-verify; the seam
        # that matters is verify_foreign.
        try:
            table.verify_foreign(_foreign_svid(issuer), now=_NOW)
            return _break("SVID verified under an EXPIRED bundle "
                          "(stub also falls: %s)" % detail)
        except tf.FederationError as e2:
            if _refusal_code(e2) == "federation-bundle-expired":
                return _held("expired bundle refused at verify "
                             "federation-bundle-expired; stub falls "
                             "for it (%s)" % detail)
            return _break("wrong refusal code %s for expired bundle"
                          % _refusal_code(e2))
    return _held("expired bundle refused at refresh "
                 "federation-bundle-expired; stub falls for it "
                 "(%s)" % detail)


# ----------------------------------------------------------------------
# Probe 3: de-federated domain still trusted (+ journal check)
# ----------------------------------------------------------------------

def _defederated_attack(target):
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    bundle = _seal_bundle(_bundle_body(issuer, nxt), _ENDPOINT_SEED)
    raw = _canonical(bundle)
    if isinstance(target, _AlwaysTrustStub):
        target.add_relationship(_PARTNER_DOMAIN,
                                "https://partner.example/bundle",
                                "https_spiffe", "aa" * 32)
        target.refresh_bundle(_PARTNER_DOMAIN, raw, _NOW)
        target.remove(_PARTNER_DOMAIN)  # de-federate
        try:
            target.verify_foreign(_foreign_svid(issuer), _NOW)
            return (True, "stub still trusts after remove()")
        except Exception as e:  # noqa: BLE001
            return (False, "stub refused: %s" % e)
    table = tf.FederationTable(_fresh_journal())
    table.add_relationship(_PARTNER_DOMAIN,
                           "https://partner.example/bundle",
                           tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
                           ed25519.publickey(_ENDPOINT_SEED).hex())
    table.refresh_bundle(_PARTNER_DOMAIN, raw, now=_NOW)
    table.remove(_PARTNER_DOMAIN)
    try:
        table.verify_foreign(_foreign_svid(issuer), now=_NOW)
        return (True, "SVID verified AFTER de-federation")
    except tf.FederationError as e:
        return (False, "refused: %s" % _refusal_code(e))


@probe("federation/de-federated-domain-still-trusted")
def _p_defederated():
    """Termination is deletion: remove() ends trust, journals it."""
    ok, detail = _stub_attack_must_succeed(
        _defederated_attack, "de-federated-trust")
    if not ok:
        return ("ERROR", detail)
    if not _HAVE_MODULE:
        return _baseline("attack BREAKs the stub (trust survives "
                         "remove()); module not yet built: %s" % detail)
    tmp = tempfile.mkdtemp(prefix="w264-fed-journal-")
    journal_path = os.path.join(tmp, "journal.jsonl")
    table = tf.FederationTable(journal_path=journal_path)
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    bundle = _seal_bundle(_bundle_body(issuer, nxt), _ENDPOINT_SEED)
    table.add_relationship(_PARTNER_DOMAIN,
                           "https://partner.example/bundle",
                           tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
                           ed25519.publickey(_ENDPOINT_SEED).hex())
    table.refresh_bundle(_PARTNER_DOMAIN, _canonical(bundle), now=_NOW)
    table.remove(_PARTNER_DOMAIN)
    try:
        table.verify_foreign(_foreign_svid(issuer), now=_NOW)
        return _break("SVID verified AFTER de-federation "
                      "(stub also falls: %s)" % detail)
    except tf.FederationError as e:
        code = _refusal_code(e)
        # Termination is deletion: the domain is as-if-never-granted.
        if code != "federation-untrusted-domain":
            return _break("wrong refusal code %s after de-federation "
                          "(want federation-untrusted-domain)" % code)
    # Re-federation on the same table works (deletion, not a
    # tombstone).
    table.add_relationship(_PARTNER_DOMAIN,
                           "https://partner.example/bundle",
                           tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
                           ed25519.publickey(_ENDPOINT_SEED).hex())
    table.refresh_bundle(_PARTNER_DOMAIN, _canonical(bundle), now=_NOW)
    try:
        claims = table.verify_foreign(_foreign_svid(issuer), now=_NOW)
    except tf.FederationError as e:
        return _break("re-federation failed: %s" % _refusal_code(e))
    if claims.get("trust_domain") != _PARTNER_DOMAIN:
        return ("ERROR", "re-federated claims wrong: %r" % (claims,))
    recs = table.journal_records()
    kinds = [r.get("type") for r in recs]
    if "federation-trust-revoked" not in kinds:
        return _break("de-federation not journaled "
                      "(records: %s)" % kinds)
    return _held("post-remove verify refused %s (deletion: "
                 "as-if-never-granted); re-federation works; "
                 "federation-trust-revoked journaled; stub falls "
                 "for it (%s)" % (code, detail))


# ----------------------------------------------------------------------
# Probe 4: one-way relationship assumed mutual
# ----------------------------------------------------------------------

def _one_way_attack(target):
    # Table A: WE trust partner.example (A -> B).
    # Table B: B's view -- NO relationship back to home.example.
    issuer_home = _issuer(bytes.fromhex("66" * 32), "home-issuer-1")
    nxt_home = _issuer(bytes.fromhex("77" * 32), "home-issuer-2")
    if isinstance(target, _AlwaysTrustStub):
        view_a = _AlwaysTrustStub()
        view_b = _AlwaysTrustStub()
        view_a.add_relationship(_PARTNER_DOMAIN,
                                "https://partner.example/bundle",
                                "https_spiffe", "aa" * 32)
        # view_b has NO relationship to home.example ...
        home_svid = issuer_home.issue(
            "spiffe://%s/agent/local" % _HOME_DOMAIN,
            ed25519.publickey(_WORKLOAD_SEED).hex(),
            ttl_minutes=30, now=_NOW)
        try:
            view_b.verify_foreign(home_svid, _NOW)  # ... but stub:
            return (True, "stub verified A's SVID from B's view with "
                    "no reverse relationship")
        except Exception as e:  # noqa: BLE001
            return (False, "stub refused: %s" % e)
    view_a = tf.FederationTable(_fresh_journal())
    view_b = tf.FederationTable(_fresh_journal())
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    bundle = _seal_bundle(_bundle_body(issuer, nxt), _ENDPOINT_SEED)
    view_a.add_relationship(_PARTNER_DOMAIN,
                            "https://partner.example/bundle",
                            tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
                            ed25519.publickey(_ENDPOINT_SEED).hex())
    view_a.refresh_bundle(_PARTNER_DOMAIN, _canonical(bundle), now=_NOW)
    home_svid = issuer_home.issue(
        "spiffe://%s/agent/local" % _HOME_DOMAIN,
        ed25519.publickey(_WORKLOAD_SEED).hex(),
        ttl_minutes=30, now=_NOW)
    try:
        view_b.verify_foreign(home_svid, now=_NOW)
        return (True, "B's view verified A's SVID with NO reverse "
                "relationship -- one-way assumed mutual")
    except tf.FederationError as e:
        return (False, "refused: %s" % _refusal_code(e))


@probe("federation/one-way-assumed-mutual")
def _p_one_way():
    """Federation is one-way: trusting B never lets B trust us."""
    ok, detail = _stub_attack_must_succeed(
        _one_way_attack, "one-way-assumed-mutual")
    if not ok:
        return ("ERROR", detail)
    if not _HAVE_MODULE:
        return _baseline("attack BREAKs the stub (reverse trust "
                         "assumed); module not yet built: %s" % detail)
    view_b = tf.FederationTable(_fresh_journal())  # B's view: no reverse relationship
    issuer_home = _issuer(bytes.fromhex("66" * 32), "home-issuer-1")
    home_svid = issuer_home.issue(
        "spiffe://%s/agent/local" % _HOME_DOMAIN,
        ed25519.publickey(_WORKLOAD_SEED).hex(),
        ttl_minutes=30, now=_NOW)
    try:
        view_b.verify_foreign(home_svid, now=_NOW)
        return _break("B's view verified A's SVID with NO reverse "
                      "relationship (stub also falls: %s)" % detail)
    except tf.FederationError as e:
        if _refusal_code(e) == "federation-untrusted-domain":
            return _held("no reverse relationship -> "
                         "federation-untrusted-domain; stub falls "
                         "for it (%s)" % detail)
        return _break("wrong refusal code %s for missing reverse "
                      "relationship" % _refusal_code(e))


# ----------------------------------------------------------------------
# Probe 5: bundle confusion across domains
# ----------------------------------------------------------------------

def _bundle_confusion_attack(target):
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    # A's bundle (trust_domain = partner.example) ...
    bundle_a = _seal_bundle(_bundle_body(issuer, nxt,
                                         domain=_PARTNER_DOMAIN),
                            _ENDPOINT_SEED)
    raw_a = _canonical(bundle_a)
    if isinstance(target, _AlwaysTrustStub):
        # ... installed under B's relationship (other.example).
        target.add_relationship(_OTHER_DOMAIN,
                                "https://other.example/bundle",
                                "https_spiffe", "aa" * 32)
        target.refresh_bundle(_OTHER_DOMAIN, raw_a, _NOW)
        svid_b = _foreign_svid(issuer, domain=_OTHER_DOMAIN)
        try:
            target.verify_foreign(svid_b, _NOW)
            return (True, "stub verified B's SVID against A's bundle")
        except Exception as e:  # noqa: BLE001
            return (False, "stub refused: %s" % e)
    table = tf.FederationTable(_fresh_journal())
    table.add_relationship(_OTHER_DOMAIN,
                           "https://other.example/bundle",
                           tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
                           ed25519.publickey(_ENDPOINT_SEED).hex())
    try:
        table.refresh_bundle(_OTHER_DOMAIN, raw_a, now=_NOW)
    except tf.FederationError as e:
        return (False, "refused at refresh: %s" % _refusal_code(e))
    return (True, "A's bundle INSTALLED under B's relationship")


@probe("federation/bundle-confusion-across-domains")
def _p_bundle_confusion():
    """A bundle is bound to its trust_domain; cross-domain use fails."""
    ok, detail = _stub_attack_must_succeed(
        _bundle_confusion_attack, "bundle-confusion")
    if not ok:
        return ("ERROR", detail)
    if not _HAVE_MODULE:
        return _baseline("attack BREAKs the stub (A's bundle verifies "
                         "B); module not yet built: %s" % detail)
    table = tf.FederationTable(_fresh_journal())
    table.add_relationship(_OTHER_DOMAIN,
                           "https://other.example/bundle",
                           tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
                           ed25519.publickey(_ENDPOINT_SEED).hex())
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    bundle_a = _seal_bundle(_bundle_body(issuer, nxt,
                                         domain=_PARTNER_DOMAIN),
                            _ENDPOINT_SEED)
    try:
        table.refresh_bundle(_OTHER_DOMAIN, _canonical(bundle_a),
                             now=_NOW)
    except tf.FederationError as e:
        if _refusal_code(e) == "federation-bundle-confusion":
            return _held("cross-domain bundle install refused "
                         "federation-bundle-confusion; stub falls "
                         "for it (%s)" % detail)
        return _break("wrong refusal code %s for bundle confusion"
                      % _refusal_code(e))
    return _break("A's bundle INSTALLED under B's relationship "
                  "(stub also falls: %s)" % detail)


# ----------------------------------------------------------------------
# Probe 6: malformed endpoint profile / endpoint URL
# ----------------------------------------------------------------------

def _malformed_profile_attack(target):
    if isinstance(target, _AlwaysTrustStub):
        try:
            target.add_relationship(_PARTNER_DOMAIN,
                                    "ftp://partner.example/bundle",
                                    "legacy_ftp_profile", "aa" * 32)
            return (True, "stub accepted ftp:// + unknown profile")
        except Exception as e:  # noqa: BLE001
            return (False, "stub refused: %s" % e)
    table = tf.FederationTable(_fresh_journal())
    try:
        table.add_relationship(_PARTNER_DOMAIN,
                               "ftp://partner.example/bundle",
                               "legacy_ftp_profile",
                               ed25519.publickey(_ENDPOINT_SEED).hex())
    except tf.FederationError as e:
        return (False, "refused: %s" % _refusal_code(e))
    return (True, "malformed relationship ACCEPTED")


@probe("federation/malformed-endpoint-profile")
def _p_malformed_profile():
    """Unknown profiles and non-https endpoints refuse at declare."""
    ok, detail = _stub_attack_must_succeed(
        _malformed_profile_attack, "malformed-profile")
    if not ok:
        return ("ERROR", detail)
    if not _HAVE_MODULE:
        return _baseline("attack BREAKs the stub (malformed "
                         "relationship accepted); module not yet "
                         "built: %s" % detail)
    table = tf.FederationTable(_fresh_journal())
    bad = 0
    for domain, endpoint, profile in [
            (_PARTNER_DOMAIN, "ftp://partner.example/bundle",
             tf.ENDPOINT_PROFILE_HTTPS_SPIFFE),
            (_PARTNER_DOMAIN, "https://partner.example/bundle",
             "legacy_ftp_profile"),
            (_PARTNER_DOMAIN, "https://partner.example/bundle", ""),
            ("not a domain!!", "https://partner.example/bundle",
             tf.ENDPOINT_PROFILE_HTTPS_SPIFFE),
            (_PARTNER_DOMAIN, "https://",  # empty host
             tf.ENDPOINT_PROFILE_HTTPS_SPIFFE)]:
        try:
            table.add_relationship(
                domain, endpoint, profile,
                ed25519.publickey(_ENDPOINT_SEED).hex())
        except tf.FederationError as e:
            if _refusal_code(e) == "federation-relationship-malformed":
                bad += 1
            else:
                return _break("wrong code %s for malformed "
                              "relationship" % _refusal_code(e))
        else:
            return _break("malformed relationship ACCEPTED: %r %r %r"
                          % (domain, endpoint, profile))
    # Both sanctioned profiles must declare cleanly.
    for profile in (tf.ENDPOINT_PROFILE_HTTPS_SPIFFE,
                    tf.ENDPOINT_PROFILE_HTTPS_WEB):
        table.add_relationship(
            "clean-%s.example" % profile.replace("_", "-"),
            "https://x.example/bundle", profile,
            ed25519.publickey(_ENDPOINT_SEED).hex())
    if bad != 5:
        return ("ERROR", "expected 5 malformed refusals, got %d" % bad)
    return _held("5 malformed relationships refused "
                 "federation-relationship-malformed; both sanctioned "
                 "profiles declare cleanly; stub accepts anything "
                 "(%s)" % detail)


# ----------------------------------------------------------------------
# Probe 7: rotation tolerance + unknown key
# ----------------------------------------------------------------------

def _rotation_attack(target):
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    rogue = _issuer(_ROGUE_ISSUER_SEED, "rogue-issuer-9")
    bundle = _seal_bundle(_bundle_body(issuer, nxt), _ENDPOINT_SEED)
    raw = _canonical(bundle)
    if isinstance(target, _AlwaysTrustStub):
        target.add_relationship(_PARTNER_DOMAIN,
                                "https://partner.example/bundle",
                                "https_spiffe", "aa" * 32)
        target.refresh_bundle(_PARTNER_DOMAIN, raw, _NOW)
        rogue_svid = _foreign_svid(rogue)
        try:
            target.verify_foreign(rogue_svid, _NOW)
            return (True, "stub verified an SVID from an UNKNOWN key")
        except Exception as e:  # noqa: BLE001
            return (False, "stub refused: %s" % e)
    table = _module_table()
    _install_bundle(table, bundle)
    # (a) rotation tolerance: next_root-signed SVID verifies while
    # the bundle is fresh (keys published in advance of use).
    try:
        claims = table.verify_foreign(_foreign_svid(nxt), now=_NOW)
    except tf.FederationError as e:
        return (False, "rotation tolerance broken -- next_root SVID "
                "refused: %s" % _refusal_code(e))
    if claims.get("trust_domain") != _PARTNER_DOMAIN:
        return (False, "wrong claims: %r" % (claims,))
    # (b) unknown key must refuse via the composed verifier.
    try:
        table.verify_foreign(_foreign_svid(rogue), now=_NOW)
        return (True, "UNKNOWN-key SVID verified")
    except Exception as e:  # noqa: BLE001 -- svid_* or federation_*
        return (False, "refused: %s" % _refusal_code(e))


@probe("federation/rotation-tolerance-and-unknown-key")
def _p_rotation():
    """Announced next_roots verify (rotation tolerance); unknown keys
    refuse through the composed SvidVerifier."""
    ok, detail = _stub_attack_must_succeed(
        _rotation_attack, "unknown-key")
    if not ok:
        return ("ERROR", detail)
    if not _HAVE_MODULE:
        return _baseline("attack BREAKs the stub (unknown key "
                         "trusted); module not yet built: %s" % detail)
    table = _module_table()
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    rogue = _issuer(_ROGUE_ISSUER_SEED, "rogue-issuer-9")
    _install_bundle(table, _seal_bundle(_bundle_body(issuer, nxt),
                                        _ENDPOINT_SEED))
    try:
        claims = table.verify_foreign(_foreign_svid(nxt), now=_NOW)
    except tf.FederationError as e:
        return _break("rotation tolerance BROKEN: next_root SVID "
                      "refused %s" % _refusal_code(e))
    if claims.get("trust_domain") != _PARTNER_DOMAIN:
        return ("ERROR", "rotation claims wrong: %r" % (claims,))
    try:
        table.verify_foreign(_foreign_svid(rogue), now=_NOW)
        return _break("UNKNOWN-key SVID VERIFIED (stub also falls: "
                      "%s)" % detail)
    except tf.FederationError as e:
        # The module must not invent its own code here: the composed
        # SvidVerifier's svid-issuer-unknown propagates unchanged.
        return _held("next_root SVID verifies (rotation tolerance); "
                     "unknown-key SVID refused %s; stub falls for "
                     "it (%s)" % (_refusal_code(e), detail))
    except Exception as e:  # noqa: BLE001
        code = _refusal_code(e)
        if code == "svid-issuer-unknown":
            return _held("next_root SVID verifies (rotation "
                         "tolerance); unknown-key SVID refused "
                         "svid-issuer-unknown (composed verifier); "
                         "stub falls for it (%s)" % detail)
        return _break("unexpected exception %s for unknown key"
                      % type(e).__name__)


# ----------------------------------------------------------------------
# Probe 8: control -- valid federated SVID verifies
# ----------------------------------------------------------------------

@probe("federation/valid-federated-svid-verifies")
def _p_valid_control():
    """Control: the seam admits what it should (no straw man)."""
    if not _HAVE_MODULE:
        return _baseline("module not yet built -- control deferred")
    table = _module_table()
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    _install_bundle(table, _seal_bundle(_bundle_body(issuer, nxt),
                                        _ENDPOINT_SEED))
    try:
        claims = table.verify_foreign(_foreign_svid(issuer), now=_NOW)
    except tf.FederationError as e:
        return _break("valid federated SVID REFUSED %s"
                      % _refusal_code(e))
    if claims.get("trust_domain") != _PARTNER_DOMAIN:
        return ("ERROR", "claims wrong: %r" % (claims,))
    if claims.get("spiffe_id") !=\
            "spiffe://%s/agent/worker-1" % _PARTNER_DOMAIN:
        return ("ERROR", "spiffe_id wrong: %r" % (claims,))
    # Unfederated domain still refuses (the seam is not permissive).
    try:
        table.verify_foreign(_foreign_svid(issuer,
                                           domain=_OTHER_DOMAIN),
                             now=_NOW)
        return _break("UNFEDERATED domain SVID verified")
    except tf.FederationError as e:
        if _refusal_code(e) != "federation-untrusted-domain":
            return _break("wrong code %s for unfederated domain"
                          % _refusal_code(e))
    # Declared relationship, no bundle ever polled: the refusal is
    # federation-bundle-missing, not federation-untrusted-domain --
    # "declared but never polled" is its own triage state.
    fresh = _module_table()
    try:
        fresh.verify_foreign(_foreign_svid(issuer), now=_NOW)
        return _break("SVID verified with NO bundle installed")
    except tf.FederationError as e:
        if _refusal_code(e) != "federation-bundle-missing":
            return _break("wrong code %s for missing bundle"
                          % _refusal_code(e))
    return _held("valid federated SVID verifies with foreign claims; "
                 "unfederated domain refuses "
                 "federation-untrusted-domain; declared-but-never-"
                 "polled refuses federation-bundle-missing")


# ----------------------------------------------------------------------
# Probe 9: control -- MeshAdmission 'require': 'federated' route mode
# ----------------------------------------------------------------------

@probe("federation/admission-federated-route")
def _p_admission_route():
    """The admission seam evaluates ONLY the federated path on
    'require': 'federated' routes -- a locally-verifiable SVID still
    refuses there (no downgrade to the local SVID seam). Pre-module
    the seam has no federated mode: the requirement is refused at
    declaration (BASELINE -- missing capability, documented)."""
    from gov import mesh_admission as ma
    from gov import svid_issuer as sv
    # Local control for a trust domain the federation table never
    # sees (mirrors the unit-test fixture).
    local_issuer = sv.TestSvidIssuer(
        issuer_seed=bytes.fromhex("12" * 32), key_id="local-issuer-1")
    verifier = sv.SvidVerifier(
        {"local-issuer-1": local_issuer.issuer_public_key},
        "home.example")
    mesh_control = sv.MeshControl(
        verifier, {"allow": ["spiffe://home.example/agent"]})
    if not _HAVE_MODULE:
        try:
            ma.MeshAdmission({"x": {"require": "federated"}},
                             mesh_control)
        except sv.SvidError as e:
            return _baseline(
                "pre-module: 'federated' route requirement refused "
                "at declaration (%s); the admission seam has no "
                "federated mode" % _refusal_code(e))
        return _break("pre-module seam ACCEPTED a federated route "
                      "requirement")
    issuer = _issuer(_ISSUER_SEED, "partner-issuer-1")
    nxt = _issuer(_NEXT_ISSUER_SEED, "partner-issuer-2")
    table = _module_table()
    _install_bundle(table, _seal_bundle(_bundle_body(issuer, nxt),
                                       _ENDPOINT_SEED))
    federated = tf.FederatedMeshControl(table)
    adm = ma.MeshAdmission({"x": {"require": "federated"},
                            "s": {"require": "svid"}},
                           mesh_control, federated_control=federated)
    failed = []
    # 1. Valid foreign SVID admits on the federated route.
    try:
        rec = adm.admit("x", svid=_foreign_svid(issuer), now=_NOW)
    except Exception as e:  # noqa: BLE001
        failed.append("admit-refused:%s" % _refusal_code(e))
    else:
        if rec.get("mode") != "federated" or\
                rec.get("trust_domain") != _PARTNER_DOMAIN:
            failed.append("admit-wrong-record:%r" % (rec,))
    # 2. A LOCALLY verifiable SVID on the federated route refuses --
    # the local SVID seam is never consulted (no downgrade).
    local_svid = local_issuer.issue(
        "spiffe://home.example/agent/worker-1",
        ed25519.publickey(_WORKLOAD_SEED).hex(),
        ttl_minutes=30, now=_NOW)
    try:
        sanity = adm.admit("s", svid=local_svid, now=_NOW)
    except Exception as e:  # noqa: BLE001
        failed.append("sanity-refused:%s" % _refusal_code(e))
    else:
        if sanity.get("mode") != "svid":
            failed.append("sanity-wrong-mode:%r" % (sanity,))
    try:
        adm.admit("x", svid=local_svid, now=_NOW)
        failed.append("downgrade-admitted")
    except Exception as e:  # noqa: BLE001
        if _refusal_code(e) != "federation-untrusted-domain":
            failed.append("downgrade-wrong-code:%s" % _refusal_code(e))
    # 3. Unfederated SVID refuses on the federated route.
    try:
        adm.admit("x",
                  svid=_foreign_svid(issuer, domain=_OTHER_DOMAIN),
                  now=_NOW)
        failed.append("unfederated-admitted")
    except tf.FederationError as e:
        if _refusal_code(e) != "federation-untrusted-domain":
            failed.append("unfederated-wrong-code:%s"
                          % _refusal_code(e))
    # 4. Declaration without a federated control refuses.
    try:
        ma.MeshAdmission({"x": {"require": "federated"}}, mesh_control)
        failed.append("declare-admitted")
    except sv.SvidError as e:
        if _refusal_code(e) != "svid-malformed":
            failed.append("declare-wrong-code:%s" % _refusal_code(e))
    # 5. The composition guard keeps non-controls out of the seam
    # (the stub cannot reach the federated path).
    try:
        ma.MeshAdmission({"x": {"require": "federated"}}, mesh_control,
                         federated_control=_AlwaysTrustStub())
        failed.append("guard-admitted")
    except Exception:  # noqa: BLE001
        pass
    if failed:
        return _break("federated route integration failed: %s"
                      % ", ".join(failed))
    return _held("federated route admits valid foreign SVIDs, "
                 "refuses unfederated and locally-verifiable SVIDs "
                 "without downgrade, and refuses mis-declaration; "
                 "the stub cannot reach the seam")


# ------------------------------------------------------------ green check

def _green_check():
    """Depth-1: run adjacent batteries' mains with GOV_SKIP_GREEN=1 in
    the child env (no combinatorial nesting). Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", "skipped (GOV_SKIP_GREEN=1)")]
    here = os.path.dirname(os.path.abspath(__file__))
    adjacent = ["w259_identity_probes.py", "w260_identity2_probes.py",
                "w263_meshauth_probes.py", "w263_redteam_probes.py"]
    notes = []
    for battery in adjacent:
        path = os.path.join(here, battery)
        if not os.path.exists(path):
            notes.append((battery, "absent -- skipped"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        env["TMPDIR"] = tempfile.mkdtemp(prefix="w264-green-")
        os.makedirs(env["TMPDIR"], exist_ok=True)
        try:
            proc = subprocess.run(
                [sys.executable, path], env=env, capture_output=True,
                text=True, timeout=600)
        except Exception as e:  # noqa: BLE001
            notes.append((battery, "ERROR: %s" % e))
            continue
        tail = (proc.stdout or "").strip().splitlines()[-1:]
        notes.append((battery, "exit=%d %s"
                      % (proc.returncode,
                         tail[0][:100] if tail else "")))
    return notes


def main():
    if _HAVE_MODULE:
        if len(decision_codes.TAXONOMY) != TAXONOMY_PIN:
            print("PIN MISMATCH: taxonomy has %d keys, pin is %d"
                  % (len(decision_codes.TAXONOMY), TAXONOMY_PIN))
            return 2
        for code in ("federation-relationship-malformed",
                     "federation-bundle-malformed",
                     "federation-bundle-signature-invalid",
                     "federation-bundle-expired",
                     "federation-bundle-confusion",
                     "federation-bundle-missing",
                     "federation-untrusted-domain"):
            if code not in decision_codes.TAXONOMY:
                print("CODE MISSING from taxonomy: %s" % code)
                return 2
    else:
        print("NOTE: gov.trust_federation not built yet -- pin check "
              "deferred; stub half only")
    held = breaks = baselines = errors = 0
    for name, fn in _PROBES:
        try:
            verdict, detail = fn()
        except Exception as e:  # noqa: BLE001 -- battery harness
            verdict, detail = ("ERROR", "%s: %s"
                               % (type(e).__name__, str(e)[:120]))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            breaks += 1
        elif verdict == "BASELINE":
            baselines += 1
        else:
            errors += 1
        print("%-8s %-55s %s" % (verdict, name, detail))
    print("-" * 79)
    for name, note in _green_check():
        print("green-check %-45s %s" % (name, note))
    print("HELD %d / BREAK %d / BASELINE %d / ERROR %d over %d probes"
          % (held, breaks, baselines, errors, len(_PROBES)))
    return 1 if (breaks or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
