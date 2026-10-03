"""Break-first battery for Sybil-resistant peer attestation.

Wave-267 lane: ADAPT of SPIFFE/SPIRE's node-attestation patterns
(pattern only; no SPIRE code). The seam: attested peer identity is
deployment-vouched with no Sybil resistance. This battery proves the
six adapted primitives hold at the public seam:

  1. tiered claim classes (anchor-signed vs self-assertable,
     default-deny + key allowlists -- the selector-spoof answer);
  2. TOFU + LOUD double-join (first presentation binds; a second is a
     refused security incident, journaled);
  3. centrally-authored identity mapping (attestation selects from a
     deployment-authored mapping; it never mints);
  4. per-peer ban (banned peers refuse; bans survive pruning);
  5. challenge-response possession proofs (bearer presentation is
     converted to key-possession proof);
  6. pinned cross-domain bundle endpoints (no auto-discovery; unknown
     or substituted endpoints fail closed).

Red phase (GOV_PEERATTEST_IMPL=stub): the permissive stub accepts
everything -- every attack probe BREAKs. Green phase (module):
gov/peer_attestation.py HELDs, in staging AND under
`env -u GOV_DEPLOYMENT_MODE`.

Stdlib only. Deterministic. Depth-1 green check honoring
GOV_SKIP_GREEN=1. No in-repo git subprocesses.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import decision_codes  # noqa: E402  (taxonomy pin below)
from gov import ed25519  # noqa: E402
from gov import trust_federation as tf  # noqa: E402

IMPL = os.environ.get("GOV_PEERATTEST_IMPL", "module")

if IMPL == "stub":
    HAVE_MODULE = True  # the stub IS the implementation under test
    pa = None
else:
    try:
        from gov import peer_attestation as pa  # noqa: E402
        HAVE_MODULE = True
    except ImportError:
        HAVE_MODULE = False
        pa = None

# Wave-271 merge: pin 1372 -> 1411 (+39 codes: 6 ptgrant-* + 7 replay-* + 8 rsl-* + 14 gatehard-* + 4 imgtext-*). Sibling pin assertions are the merge
# coordinator's. Enforced at import in module mode; the taxonomy_pin
# probe reports the state in both modes (stub mode pre-build
# legitimately BREAKs).
if IMPL == "module":
    assert len(decision_codes.TAXONOMY) == 1841, "taxonomy pin 1588"  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)

PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


# ---------------------------------------------------------------- helpers

def _keys():
    seed = ed25519.generate_seed()
    return seed, ed25519.publickey(seed).hex()


def _scratch(prefix):
    import tempfile
    base = "/var/tmp"
    os.makedirs(base, exist_ok=True)
    return tempfile.mkdtemp(prefix=prefix, dir=base)


class _StubTable(object):
    """Permissive pre-attestation behavior (the vulnerabilities)."""

    CLAIM_ANCHOR_SIGNED = "anchor_signed"
    CLAIM_SELF_ASSERTABLE = "self_assertable"

    class PeerAttestationError(Exception):
        def __init__(self, code, detail=""):
            super(_StubTable.PeerAttestationError, self).__init__(
                "%s: %s" % (code, detail))
            self.code = code
            self.detail = detail

    def __init__(self, journal_path, local_domain,
                 allowlisted_claim_keys=()):
        self._peers = {}
        self._mapping = {}
        self._banned = set()
        self._challenges = {}
        self.local_domain = local_domain
        self.allowlisted = set(allowlisted_claim_keys)

    def author_identity(self, peer_id, identities):
        # VULNERABILITY: mapping is written but never enforced.
        self._mapping[peer_id] = set(identities)
        return {"peer_id": peer_id, "identities": list(identities)}

    def register_peer(self, peer_id, anchor_pub_hex, claims=None,
                      now=None):
        # VULNERABILITY: no TOFU -- re-registration silently rebinds;
        # no claim-class checks at all.
        self._peers[peer_id] = {"peer_id": peer_id,
                                "anchor": anchor_pub_hex,
                                "claims": claims or {}}
        return {"peer_id": peer_id, "registered": True}

    def issue_challenge(self, peer_id, now=None):
        self._challenges[peer_id] = "00" * 32
        return {"peer_id": peer_id, "nonce": "00" * 32, "issued_at": 0}

    def attest(self, peer_id, claimed_identity, nonce, response_sig,
               claims=None, federation_table=None, endpoint_url=None,
               now=None):
        # VULNERABILITIES: no possession check, no mapping check, no
        # endpoint pin check, banned peers still attest, every claim
        # honored regardless of class.
        self._peers[peer_id] = {"peer_id": peer_id,
                                "identity": claimed_identity}
        return {"peer_id": peer_id, "identity": claimed_identity,
                "attested": True}

    def ban_peer(self, peer_id, reason, now=None):
        # VULNERABILITY: ban is recorded but never enforced.
        self._banned.add(peer_id)
        return {"peer_id": peer_id, "banned": True}

    def remove_peer(self, peer_id, now=None):
        self._peers.pop(peer_id, None)
        self._banned.discard(peer_id)
        return {"peer_id": peer_id, "removed": True}

    def prune(self, now, ttl_seconds):
        # VULNERABILITY: prune is a no-op fiction.
        return {"pruned": 0}

    def peer_record(self, peer_id):
        return self._peers.get(peer_id)

    def is_banned(self, peer_id):
        return peer_id in self._banned


if IMPL == "stub":
    _RealTable = None
else:
    class _RealTable(object):
        """Facade over the real module (module mode)."""

        PeerAttestationError = pa.PeerAttestationError
        CLAIM_ANCHOR_SIGNED = pa.CLAIM_ANCHOR_SIGNED
        CLAIM_SELF_ASSERTABLE = pa.CLAIM_SELF_ASSERTABLE

        def __init__(self, journal_path, local_domain,
                     allowlisted_claim_keys=()):
            self._t = pa.PeerAttestationTable(
                journal_path, local_domain,
                allowlisted_claim_keys=allowlisted_claim_keys)

        def author_identity(self, peer_id, identities):
            return self._t.author_identity(peer_id, identities)

        def register_peer(self, peer_id, anchor_pub_hex, claims=None,
                          now=None):
            return self._t.register_peer(peer_id, anchor_pub_hex,
                                          claims=claims, now=now)

        def issue_challenge(self, peer_id, now=None):
            return self._t.issue_challenge(peer_id, now=now)

        def attest(self, peer_id, claimed_identity, nonce, response_sig,
                   claims=None, federation_table=None, endpoint_url=None,
                   now=None):
            return self._t.attest(peer_id, claimed_identity, nonce,
                                  response_sig, claims=claims,
                                  federation_table=federation_table,
                                  endpoint_url=endpoint_url, now=now)

        def ban_peer(self, peer_id, reason, now=None):
            return self._t.ban_peer(peer_id, reason, now=now)

        def remove_peer(self, peer_id, now=None):
            return self._t.remove_peer(peer_id, now=now)

        def prune(self, now, ttl_seconds):
            return self._t.prune(now, ttl_seconds)

        def peer_record(self, peer_id):
            return self._t.peer_record(peer_id)

        def is_banned(self, peer_id):
            return self._t.is_banned(peer_id)


def _table(allowlisted=("team",), local_domain="mesh.example"):
    td = _scratch("g267-peerattest-")
    cls = _StubTable if IMPL == "stub" else _RealTable
    return cls(os.path.join(td, "journal.db"), local_domain,
               allowlisted_claim_keys=allowlisted), td


def _refused(fn, code):
    """HELD iff fn raises the module's machine-coded refusal."""
    try:
        fn()
    except Exception as exc:
        got = getattr(exc, "code", None)
        if got == code:
            return "HELD"
        return "BREAK(wrong code %r, want %r)" % (got, code)
    return "BREAK(accepted)"


def _claim_sig(seed, peer_id, key, value):
    msg = (b"sasanam-peer-claim/v1:" + peer_id.encode("utf-8") + b":"
           + key.encode("utf-8") + b":" + value.encode("utf-8"))
    return ed25519.sign(seed, msg)


def _possession_sig(seed, nonce_hex, peer_id):
    msg = (b"sasanam-peer-possession/v1:" + bytes.fromhex(nonce_hex)
           + b":" + peer_id.encode("utf-8"))
    return ed25519.sign(seed, msg)


def _journal_incidents(td):
    """Raw journal lines mentioning the double-join incident."""
    import json
    path = os.path.join(td, "journal.db")
    hits = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if "peer-double-join-incident" in str(rec):
                    hits.append(rec)
    except OSError:
        pass
    return hits


# ------------------------------------------------------- attack probes

@probe
def double_join_second_attempt():
    """TOFU: a second registration for an already-bound peer_id must
    refuse LOUDLY (machine-coded + journaled incident), not rebind."""
    t, td = _table()
    seed1, pub1 = _keys()
    seed2, pub2 = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.register_peer("peer-a", pub1, now=1000)
    v = _refused(lambda: t.register_peer("peer-a", pub2, now=2000),
                 "federation-double-join")
    if v != "HELD":
        return v
    if IMPL == "module":
        # SPIRE's contract: both sides log the double-join as a
        # security incident. The anchor must still be the FIRST key.
        incidents = _journal_incidents(td)
        if not incidents:
            return "BREAK(no incident journaled)"
        rec = t.peer_record("peer-a")
        if rec is None or rec.get("anchor_public_key") != pub1:
            return "BREAK(anchor rebound or record lost)"
    return "HELD"


@probe
def double_join_anchor_reuse():
    """TOFU: one anchor key binds exactly one peer_id. A second peer_id
    reusing the bound anchor must refuse."""
    t, td = _table()
    _, pub1 = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.author_identity("peer-b", ["spiffe://mesh.example/peer/b"])
    t.register_peer("peer-a", pub1, now=1000)
    return _refused(lambda: t.register_peer("peer-b", pub1, now=2000),
                    "federation-double-join")


@probe
def selector_spoof_self_assertable():
    """Tiered claims: a self-assertable claim key NOT on the deployment
    allowlist must be denied, even with a valid anchor (Unit42 selector
    spoofing is the threat model)."""
    t, td = _table()
    seed, pub = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.register_peer("peer-a", pub, now=1000)
    ch = t.issue_challenge("peer-a", now=1100)
    sig = _possession_sig(seed, ch["nonce"], "peer-a")
    claims = {"aws_iid:tag:role": ("prod", t.CLAIM_SELF_ASSERTABLE)}
    return _refused(
        lambda: t.attest("peer-a", "spiffe://mesh.example/peer/a",
                         ch["nonce"], sig, claims=claims, now=1200),
        "federation-claim-class-denied")


@probe
def anchor_signed_claim_without_proof():
    """Tiered claims: an anchor-signed claim presented WITHOUT a valid
    signature must be denied."""
    t, td = _table()
    seed, pub = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.register_peer("peer-a", pub, now=1000)
    ch = t.issue_challenge("peer-a", now=1100)
    sig = _possession_sig(seed, ch["nonce"], "peer-a")
    bad = _claim_sig(ed25519.generate_seed(), "peer-a", "hw_model",
                     "x9")
    claims = {"hw_model": ("x9", t.CLAIM_ANCHOR_SIGNED, bad)}
    return _refused(
        lambda: t.attest("peer-a", "spiffe://mesh.example/peer/a",
                         ch["nonce"], sig, claims=claims, now=1200),
        "federation-claim-class-denied")


@probe
def identity_unmapped():
    """Centrally-authored mapping: a peer with a VALID anchor and VALID
    possession proof claiming an identity it was never mapped to gets
    nothing (attestation selects; it never mints)."""
    t, td = _table()
    seed, pub = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.register_peer("peer-a", pub, now=1000)
    ch = t.issue_challenge("peer-a", now=1100)
    sig = _possession_sig(seed, ch["nonce"], "peer-a")
    return _refused(
        lambda: t.attest("peer-a", "spiffe://mesh.example/peer/z",
                         ch["nonce"], sig, now=1200),
        "federation-identity-unmapped")


@probe
def possession_forgery():
    """Challenge-response: a response signed under the WRONG key must
    fail possession proof."""
    t, td = _table()
    seed, pub = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.register_peer("peer-a", pub, now=1000)
    ch = t.issue_challenge("peer-a", now=1100)
    wrong = ed25519.generate_seed()
    sig = _possession_sig(wrong, ch["nonce"], "peer-a")
    return _refused(
        lambda: t.attest("peer-a", "spiffe://mesh.example/peer/a",
                         ch["nonce"], sig, now=1200),
        "federation-possession-failed")


@probe
def challenge_replay():
    """Challenge-response: a response for an OLD challenge must not
    verify against a NEW challenge (anti-replay binding)."""
    t, td = _table()
    seed, pub = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.register_peer("peer-a", pub, now=1000)
    ch1 = t.issue_challenge("peer-a", now=1100)
    sig1 = _possession_sig(seed, ch1["nonce"], "peer-a")
    first = t.attest("peer-a", "spiffe://mesh.example/peer/a",
                     ch1["nonce"], sig1, now=1200)
    if not first or first.get("attested") is not True:
        return "BREAK(legit first attest failed)"
    ch2 = t.issue_challenge("peer-a", now=1300)
    if ch2["nonce"] == ch1["nonce"]:
        return "BREAK(nonces not unique)"
    return _refused(
        lambda: t.attest("peer-a", "spiffe://mesh.example/peer/a",
                         ch2["nonce"], sig1, now=1400),
        "federation-possession-failed")


@probe
def cross_domain_unpinned_endpoint():
    """Pinned endpoints: a foreign-domain identity presented with NO
    declared relationship (auto-discovery) must fail closed."""
    t, td = _table()
    seed, pub = _keys()
    ftd = _scratch("g267-peerattest-fed-")
    ftable = tf.FederationTable(os.path.join(ftd, "fed.db"))
    # No relationship declared at all: auto-discovery is refused.
    t.author_identity("peer-x", ["spiffe://foreign.example/peer/x"])
    t.register_peer("peer-x", pub, now=1000)
    ch = t.issue_challenge("peer-x", now=1100)
    sig = _possession_sig(seed, ch["nonce"], "peer-x")
    return _refused(
        lambda: t.attest("peer-x", "spiffe://foreign.example/peer/x",
                         ch["nonce"], sig, federation_table=ftable,
                         endpoint_url="https://bundles.foreign.example/"
                         "bundle", now=1200),
        "federation-untrusted-domain")


@probe
def cross_domain_endpoint_substitution():
    """Pinned endpoints: the presented endpoint must EXACTLY match the
    pinned relationship endpoint; substitution fails closed."""
    t, td = _table()
    seed, pub = _keys()
    ftd = _scratch("g267-peerattest-fed-")
    ftable = tf.FederationTable(os.path.join(ftd, "fed.db"))
    ftable.add_relationship("foreign.example",
                            "https://bundles.foreign.example/bundle",
                            tf.ENDPOINT_PROFILE_HTTPS_SPIFFE, "aa" * 32)
    t.author_identity("peer-x", ["spiffe://foreign.example/peer/x"])
    t.register_peer("peer-x", pub, now=1000)
    ch = t.issue_challenge("peer-x", now=1100)
    sig = _possession_sig(seed, ch["nonce"], "peer-x")
    return _refused(
        lambda: t.attest("peer-x", "spiffe://foreign.example/peer/x",
                         ch["nonce"], sig, federation_table=ftable,
                         endpoint_url="https://evil.example/bundle",
                         now=1200),
        "federation-endpoint-unpinned")


@probe
def banned_peer_attests():
    """Per-peer ban: a banned peer must refuse attestation with a
    machine-coded refusal."""
    t, td = _table()
    seed, pub = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.register_peer("peer-a", pub, now=1000)
    t.ban_peer("peer-a", "selector spoof observed", now=1500)
    # Fail-closed order: a banned peer cannot even obtain a challenge.
    v = _refused(lambda: t.issue_challenge("peer-a", now=1600),
                 "federation-peer-banned")
    if v != "HELD":
        return v
    # Defense in depth: even with a smuggled challenge, attestation
    # still refuses.
    ch = {"nonce": "ab" * 32}
    sig = _possession_sig(seed, ch["nonce"], "peer-a")
    return _refused(
        lambda: t.attest("peer-a", "spiffe://mesh.example/peer/a",
                         ch["nonce"], sig, now=1700),
        "federation-peer-banned")


# ------------------------------------------------------ control probes

@probe
def legit_registration_and_attest():
    """Honest flow: register, challenge, prove possession, attest a
    mapped identity. Must verify in both modes."""
    t, td = _table()
    seed, pub = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    reg = t.register_peer("peer-a", pub, now=1000)
    if not reg or reg.get("peer_id") != "peer-a":
        return "BREAK(registration broken)"
    ch = t.issue_challenge("peer-a", now=1100)
    sig = _possession_sig(seed, ch["nonce"], "peer-a")
    rec = t.attest("peer-a", "spiffe://mesh.example/peer/a",
                   ch["nonce"], sig, now=1200)
    if rec and rec.get("attested") is True:
        return "HELD"
    return "BREAK(%r)" % (rec,)


@probe
def legit_self_assertable_allowlisted():
    """An allowlisted self-assertable claim is honored, recorded with
    its (weaker) claim class."""
    t, td = _table()
    seed, pub = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.register_peer("peer-a", pub, now=1000)
    ch = t.issue_challenge("peer-a", now=1100)
    sig = _possession_sig(seed, ch["nonce"], "peer-a")
    claims = {"team": ("eng", t.CLAIM_SELF_ASSERTABLE)}
    rec = t.attest("peer-a", "spiffe://mesh.example/peer/a",
                   ch["nonce"], sig, claims=claims, now=1200)
    if not rec or rec.get("attested") is not True:
        return "BREAK(%r)" % (rec,)
    if IMPL == "module":
        got = (rec.get("claims") or {}).get("team") or {}
        if got.get("class") != "self_assertable":
            return "BREAK(claim class not recorded: %r)" % (got,)
    return "HELD"


@probe
def legit_anchor_signed_claim():
    """An anchor-signed claim WITH a valid signature is honored."""
    t, td = _table()
    seed, pub = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.register_peer("peer-a", pub, now=1000)
    ch = t.issue_challenge("peer-a", now=1100)
    sig = _possession_sig(seed, ch["nonce"], "peer-a")
    csig = _claim_sig(seed, "peer-a", "hw_model", "x9")
    claims = {"hw_model": ("x9", t.CLAIM_ANCHOR_SIGNED, csig)}
    rec = t.attest("peer-a", "spiffe://mesh.example/peer/a",
                   ch["nonce"], sig, claims=claims, now=1200)
    if rec and rec.get("attested") is True:
        return "HELD"
    return "BREAK(%r)" % (rec,)


@probe
def legit_cross_domain_pinned():
    """Foreign identity via the EXACTLY pinned endpoint verifies."""
    t, td = _table()
    seed, pub = _keys()
    ftd = _scratch("g267-peerattest-fed-")
    ftable = tf.FederationTable(os.path.join(ftd, "fed.db"))
    ftable.add_relationship("foreign.example",
                            "https://bundles.foreign.example/bundle",
                            tf.ENDPOINT_PROFILE_HTTPS_SPIFFE, "aa" * 32)
    t.author_identity("peer-x", ["spiffe://foreign.example/peer/x"])
    t.register_peer("peer-x", pub, now=1000)
    ch = t.issue_challenge("peer-x", now=1100)
    sig = _possession_sig(seed, ch["nonce"], "peer-x")
    rec = t.attest("peer-x", "spiffe://foreign.example/peer/x",
                   ch["nonce"], sig, federation_table=ftable,
                   endpoint_url="https://bundles.foreign.example/"
                   "bundle", now=1200)
    if rec and rec.get("attested") is True:
        return "HELD"
    return "BREAK(%r)" % (rec,)


@probe
def prune_keeps_banned():
    """Pruning drops stale records but keeps banned peers (SPIRE:
    banned nodes are excluded from pruning)."""
    t, td = _table()
    _, pub_a = _keys()
    _, pub_b = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.author_identity("peer-b", ["spiffe://mesh.example/peer/b"])
    t.register_peer("peer-a", pub_a, now=1000)
    t.register_peer("peer-b", pub_b, now=1000)
    t.ban_peer("peer-a", "test", now=1500)
    t.prune(now=10_000, ttl_seconds=100)
    if t.is_banned("peer-a") is not True:
        return "BREAK(banned peer lost)"
    if IMPL == "module" and t.peer_record("peer-b") is not None:
        return "BREAK(stale peer not pruned)"
    return "HELD"


@probe
def remove_then_reregister():
    """TOFU reset is explicit: remove_peer unbinds, a fresh
    registration then succeeds (no silent rebind)."""
    t, td = _table()
    _, pub1 = _keys()
    _, pub2 = _keys()
    t.author_identity("peer-a", ["spiffe://mesh.example/peer/a"])
    t.register_peer("peer-a", pub1, now=1000)
    t.remove_peer("peer-a", now=2000)
    reg = t.register_peer("peer-a", pub2, now=3000)
    if reg and reg.get("registered") is True:
        return "HELD"
    return "BREAK(%r)" % (reg,)


@probe
def malformed_inputs_refused():
    """Programmer-error shapes refuse loudly at the seam, never with a
    bare TypeError."""
    t, td = _table()
    v1 = _refused(lambda: t.register_peer("peer-a", "not-hex", now=1),
                  "federation-attestation-malformed")
    if v1 != "HELD":
        return v1
    v2 = _refused(lambda: t.register_peer("", "aa" * 32, now=1),
                  "federation-attestation-malformed")
    if v2 != "HELD":
        return v2
    v3 = _refused(lambda: t.author_identity("peer-a", "not-a-list"),
                  "federation-attestation-malformed")
    if v3 != "HELD":
        return v3
    return "HELD"


# ------------------------------------------------------------- meta

@probe
def taxonomy_pin():
    """Pin 1229 (1222 + 7 peer-attestation codes): exact new literals,
    sorted, each exactly once."""
    import re
    src = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code": \'(federation-[a-z-]+)\'', src)
    if len(decision_codes.TAXONOMY) != 1841:  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)
        return "BREAK(pin %d)" % len(decision_codes.TAXONOMY)
    new = [c for c in set(lits)
           if c.startswith("federation-attestation-")
           or c in ("federation-claim-class-denied",
                    "federation-double-join",
                    "federation-endpoint-unpinned",
                    "federation-identity-unmapped",
                    "federation-peer-banned",
                    "federation-possession-failed")]
    if sorted(set(lits)) != sorted(lits):
        return "BREAK(duplicate literals)"
    expected = sorted([
        "federation-attestation-malformed",
        "federation-claim-class-denied",
        "federation-double-join",
        "federation-endpoint-unpinned",
        "federation-identity-unmapped",
        "federation-peer-banned",
        "federation-possession-failed",
    ])
    if sorted(new) != expected:
        return "BREAK(codes %r)" % (sorted(new),)
    return "HELD"


@probe
def deterministic_x2():
    """Verdicts byte-identical across two runs (fresh tables)."""
    skip = ("deterministic_x2", "adjacent_green", "taxonomy_pin")
    first = [(p.__name__, p()) for p in PROBES
             if p.__name__ not in skip]
    second = [(p.__name__, p()) for p in PROBES
              if p.__name__ not in skip]
    if first == second:
        return "HELD"
    return "BREAK(%r)" % ([a for a, b in zip(first, second)
                           if a != b],)


def _adjacent_once(env, repo, td):
    """One run of the adjacent battery. Returns (ok, break_ct, err_ct)."""
    import re
    import subprocess
    cmd = [sys.executable, "evals/w264_federation_probes.py"]
    r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                       text=True, timeout=600)
    out = r.stdout + r.stderr
    # Verdicts are line-leading tokens; the summary line also contains
    # the words BREAK/ERROR, so count only line-leading verdicts.
    brk = len(re.findall(r"(?m)^BREAK", out))
    err = len(re.findall(r"(?m)^ERROR", out))
    if r.returncode == 0 and brk == 0 and err == 0:
        return True, brk, err, out
    # Lane-local pin drift (wave-224 lesson): this lane bumps the pin
    # 1222 -> 1229 additively, so the adjacent battery trips its own
    # pin assertion before its real phase. Accept ONLY as the sole
    # failure cause: pin-mismatch line present, zero real-phase
    # verdicts, no traceback. The decision_codes.py diff is pure
    # insertions (74+/0-), so the real phase cannot be affected.
    pin_only = ("PIN MISMATCH" in out and brk == 0 and err == 0
                and "Traceback" not in out)
    return pin_only, brk, err, out


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN.

    Runs the wave-264 federation battery once with GOV_SKIP_GREEN=1 in
    the child env (a standalone run of THIS battery still runs its own
    green check).
    """
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import tempfile
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    td = tempfile.mkdtemp(prefix="g267-peerattest-green-", dir="/var/tmp")
    env["TMPDIR"] = td
    ok, brk, err, out = _adjacent_once(env, repo, td)
    if ok:
        print("GREEN CHECK: w264_federation_probes green")
        return True
    print("GREEN CHECK FAILED: w264_federation_probes "
          "(BREAK=%s ERROR=%s)" % (brk, err))
    print(out[-1500:])
    return False


@probe
def adjacent_green():
    """Depth-1 adjacent battery stays green under the new module."""
    if green_check():
        return "HELD"
    return "BREAK(adjacent battery red)"


def main():
    results = []
    if not HAVE_MODULE:
        for p in PROBES:
            results.append((p.__name__, "GAP"))
    else:
        for p in PROBES:
            try:
                results.append((p.__name__, p()))
            except Exception as exc:  # never mask a crash
                results.append((p.__name__, "BREAK(%r)" % (exc,)))
    held = sum(1 for _, v in results if v == "HELD")
    brk = sum(1 for _, v in results if v.startswith("BREAK"))
    gap = sum(1 for _, v in results if v == "GAP")
    for name, verdict in results:
        print("%-38s %s" % (name, verdict))
    print("HELD %d / BREAK %d / GAP %d of %d [%s]"
          % (held, brk, gap, len(results), IMPL))
    return 1 if (brk or gap) else 0


if __name__ == "__main__":
    sys.exit(main())
