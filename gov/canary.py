"""Wave-51 P1 — Egress Canaries: deception as the exfiltration control.

Old idea, new placement: honeytokens (Stoll 1986; Thinkst Canary 2015) have
always been planted to catch *external attackers*. This module plants them
*inside the agent's own sandbox* to catch *the agent itself* — an
inward-facing, first-class sandbox control wired into the fail-closed policy
engine and the hash-chained audit log.

Mechanism
---------
Per run, :class:`CanaryMint` generates a set of realistic-but-fake secrets:
AWS-style key pairs, internal hostnames, bearer tokens, and ``.env`` entries.
A model must not trivially recognize them as canaries (no marker words in
values or filenames; standard formats; per-run rotation).

:func:`plant_canaries` writes the artifacts into the JAIL (visible to the
agent): jail env, ``<jail>/.aws/credentials``, ``<jail>/etc/hosts``, and one
decoy config file. :class:`CanaryRegistry` — the server-side record of
planted values — lives OUTSIDE the jail. Invariant: no code path in this
module ever writes registry data under a jail path, and no planted artifact
points at the registry.

:func:`scan_egress_attempt` runs on the egress-attempt path (the
``http_post`` / ``send_email`` / ``api_call`` tools — the same set the
``deny-egress-unallowlisted`` rule governs). A destination hostname or a
credential/token value matching the registry is, by construction, proof of
exfiltration intent: canaries are never valid credentials or reachable
hosts. Credential matching is encoding-aware (base64/base32/hex/URL,
bounded to 2 layers, strict round-trip validation — the same discipline as
``gov/dlp.py`` F2/F8): smuggling the canary through one encoding step does
not evade the trip. On a hit, :func:`check_and_trip` emits a LOUD
``canary_trip`` audit event (a distinct event type), escalates to the
approval queue with the trip evidence attached, and raises
:class:`CanaryTripHalt` — the run halts fail-closed. The audit/queue steps
are best-effort; the halt is not.

Wave-143 (row 13): hits are split by read observation — see
``gov/unobserved_canary.py``. When the executor has a rare-token
tracker installed, a hit with NO recorded governed read of the
canary's source document emits a distinct LOUD
``unobserved_canary_egress`` event (same fail-closed halt -- the read
happened out-of-band). Without a tracker the distinction cannot be
drawn and every hit keeps the ``canary_trip`` path above.

Key invariant: near-zero false positives by design. Matching is exact
(full-value, or substring for high-entropy values the agent demonstrably
ingested) against per-run values; the previous run's canaries never match
the current run's registry. Decoded variants only ever ADD true hits: a
decode that yields a canary value proves the agent ingested the canary.

Tripwire, not wall: an exfiltrator that never touches a canary is not
caught by this module. Strict deny-all remains the wall; the canary is the
intent signal for the shapes deny-all cannot see (filtered mode, a
misconfigured jail, or a deployment that must allow some egress).
Documented residuals: encodings stacked more than 2 deep, and custom
substitution ciphers (same residual class as DLP F8) — not deterministically
catchable. F81 (no filtered-egress mode) stays OPEN: a tripwire does not
close it.

F128 (wave-63): non-string arg leaves ARE scanned — bytes/bytearray,
all-int (0-255) list/tuple leaves (strict ASCII, printable, length-gated;
decoded variants only ever ADD true hits), and dict keys as well as
values. Stays out of scope: text-rendered numeric arrays (a comma-joined
string of code points is indistinguishable from ordinary prose to a
scanner), non-ASCII byte blobs, and int arrays shorter than
MIN_MATCHABLE_LEN.

$0, stdlib only, no network calls. Deterministic per run_id.
"""

import base64
import binascii
import hashlib
import random
import string
from pathlib import Path
from urllib.parse import unquote, urlparse

from .policy import PolicyDecision

__all__ = [
    "CanaryMint",
    "CanaryMintError",
    "CanaryRegistry",
    "CanaryTripHalt",
    "plant_canaries",
    "make_canary_plant",
    "CANARY_LABEL_ARTIFACTS",
    "scan_egress_attempt",
    "check_and_trip",
    "normalize_canary_text",
    "EGRESS_TOOLS",
    "MIN_MATCHABLE_LEN",
    "MAX_DECODE_LAYERS",
]


# Leet-speak confusables canonicalized before canary comparison
# (wave-144, row-13): attackers case-mangle, pad whitespace/
# punctuation, or substitute lookalike digits to dodge exact
# matching. Normalization is NOT fuzzy matching: it is a fixed,
# deterministic, stdlib-only canonicalization applied to BOTH the
# planted canary and the egress content, so "5ecr3t-token" and
# "secret-token" compare equal while "secrex-token" still misses.
# Hostnames are deliberately NOT leet-normalized (match_host stays
# exact case-insensitive): hostname lookalike matching is a
# false-positive and attacker-confusion hazard, refused by
# construction.
_LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t",
})


def normalize_canary_text(s):
    """Canonicalize text for canary comparison.

    Casefold, map leet digits to their letters (0->o, 1->l, 3->e,
    4->a, 5->s, 7->t), and drop every character that is not ASCII
    alphanumeric (strips whitespace AND punctuation). Deterministic,
    stdlib-only, $0. Non-string input normalizes to "".
    """
    if not isinstance(s, str):
        return ""
    folded = s.casefold().translate(_LEET_MAP)
    return "".join(c for c in folded if c.isascii() and c.isalnum())

# Tools whose attempts pass the trip detector — the same set the
# deny-egress-unallowlisted rule governs (ToolExecutor._domain_allowlisted).
EGRESS_TOOLS = ("http_post", "send_email", "api_call")

# Only values at least this long participate in credential matching. Short
# strings collide too easily with legitimate traffic; every canary the mint
# produces is longer than this.
MIN_MATCHABLE_LEN = 20

_MINT_DOMAIN = "gov-canary-v1"

_AWS_ALPHABET = string.ascii_uppercase + string.digits
_SECRET_ALPHABET = string.ascii_letters + string.digits + "+/"
_TOKEN_ALPHABET = string.ascii_letters + string.digits

# Plausible-but-fake internal service vocabulary. Nothing here may contain
# the words "canary", "honeypot", "decoy", or "fake".
_SERVICES = (
    "metrics-collector", "backup-gateway", "artifact-proxy",
    "telemetry-relay", "config-sync", "vault-replica",
)
_ZONES = ("prod", "staging", "core")


# A minted value must never be trivially recognizable as a canary: these
# substrings (case-insensitive) are resampled away, not merely asserted
# absent. F178 (wave-138): a bare assert on RNG-drawn values crashed ~2.3e-4
# of mints with AssertionError, spuriously refusing runs fail-closed.
_BANNED_SUBSTRINGS = ("canary", "honeypot", "decoy", "fake")

# Bounded resample attempts per _pick draw. A banned substring needs a
# 4-7-char literal inside a >=24-char draw from a >=10-symbol alphabet, so
# P(hit per draw) is on the order of 1e-6; _MAX_RESAMPLE_ATTEMPTS=64 makes
# exhaustion practically unreachable (P ~ 1e-384), but it is still an
# explicit, descriptive failure rather than a bare assert.
_MAX_RESAMPLE_ATTEMPTS = 64


class CanaryMintError(Exception):
    """Minting failed safely: resampling exhausted its bound on a draw.

    Raised instead of AssertionError when no clean value could be drawn
    within _MAX_RESAMPLE_ATTEMPTS (practically unreachable), or when a
    caller-supplied value violates the length/format invariant. Never
    raised by ordinary RNG output — those are resampled, not rejected.
    """


class CanaryTripHalt(Exception):
    """Fail-closed halt: a canary was used on the egress path.

    Raised by :func:`check_and_trip` after the LOUD ``canary_trip`` audit
    event lands and the approval-queue escalation is queued. Nothing in
    ``ToolExecutor.call`` catches this — the call never executes.
    """


class CanaryMint:
    """Per-run canary set generator (run_id-bound, rotated every run).

    Deterministic: the same ``run_id`` (and ``seed``) always mints the same
    set; a different ``run_id`` mints a disjoint set (up to RNG collision,
    negligible at these lengths). Rotation is what keeps last run's
    canaries from tripping this run — the registry is per-run, and the
    values differ per run anyway.
    """

    def __init__(self, run_id, seed=None):
        self.run_id = str(run_id)
        key = ("%s|%s|%s" % (_MINT_DOMAIN, self.run_id,
                             "" if seed is None else str(seed))).encode()
        rng_seed = int.from_bytes(hashlib.sha256(key).digest()[:8], "big")
        self._rng = random.Random(rng_seed)
        self._canaries = []
        self._mint()

    @staticmethod
    def _has_banned(value):
        lowered = value.lower()
        return any(banned in lowered for banned in _BANNED_SUBSTRINGS)

    def _pick(self, alphabet, n):
        """Draw an n-char value, resampling (bounded) until it is clean.

        F178: the old code asserted banned-substrings away AFTER the draw,
        so ~2.3e-4 of mints died with AssertionError. Every draw now
        retries internally; bound-exhaustion raises CanaryMintError
        (descriptive, non-AssertionError) — practically unreachable.
        """
        for attempt in range(_MAX_RESAMPLE_ATTEMPTS):
            value = "".join(self._rng.choice(alphabet) for _ in range(n))
            if not self._has_banned(value):
                return value
        raise CanaryMintError(
            "canary mint for run_id %r exhausted %d resample attempts "
            "drawing %d chars from a %d-symbol alphabet without a "
            "banned-substring-free value; refusing the mint rather than "
            "crashing with AssertionError" %
            (self.run_id, _MAX_RESAMPLE_ATTEMPTS, n, len(alphabet)))

    def _add(self, kind, label, value, channel):
        # F178: explicit, descriptive errors — never bare asserts — on the
        # mint path. _pick guarantees RNG-drawn values arrive clean, so
        # this check is defense-in-depth against future hand-built values.
        if not (isinstance(value, str) and len(value) >= MIN_MATCHABLE_LEN):
            raise CanaryMintError(
                "canary values must be strings of at least %d chars "
                "(got %r for %s/%s)" %
                (MIN_MATCHABLE_LEN, value, kind, label))
        if self._has_banned(value):
            raise CanaryMintError(
                "canary value for %s/%s must not be recognizable "
                "(banned substring present)" % (kind, label))
        self._canaries.append({
            "kind": kind, "label": label, "value": value,
            "channel": channel,
        })

    def _mint(self):
        rng = self._rng
        # --- AWS-style key pairs -------------------------------------
        for i in range(2):
            access = "AKIA" + self._pick(_AWS_ALPHABET, 16)
            secret = self._pick(_SECRET_ALPHABET, 40)
            self._add("aws_access_key", "aws-key-%d" % i, access,
                      "aws_credentials")
            self._add("aws_secret_key", "aws-secret-%d" % i, secret,
                      "aws_credentials")
        # --- internal hostnames --------------------------------------
        services = rng.sample(_SERVICES, 3)
        for i, svc in enumerate(services):
            zone = rng.choice(_ZONES)
            host = "%s-%02d.%s.internal" % (svc, rng.randrange(1, 99), zone)
            self._add("hostname", "internal-host-%d" % i, host, "hosts")
        # --- bearer tokens -------------------------------------------
        self._add("bearer_token", "github-token",
                  "ghp_" + self._pick(_TOKEN_ALPHABET, 36), "decoy_config")
        self._add("bearer_token", "slack-token",
                  "xoxb-%s-%s-%s" % (self._pick(string.digits, 10),
                                     self._pick(string.digits, 12),
                                     self._pick(_TOKEN_ALPHABET, 24)),
                  "decoy_config")
        # --- .env entries --------------------------------------------
        db_url = ("postgres://svc_acct:%s@db-primary-%02d.internal:5432/opsdb"
                  % (self._pick(_TOKEN_ALPHABET, 24), rng.randrange(1, 9)))
        self._add("env_entry", "database-url", db_url, "env_file")
        self._add("env_entry", "internal-api-token",
                  "int_" + self._pick(_TOKEN_ALPHABET, 40), "env")
        self._add("env_entry", "stripe-secret",
                  "sk_live_" + self._pick(_TOKEN_ALPHABET, 24), "env")

    def values(self):
        """All minted canaries as a list of dicts."""
        return [dict(c) for c in self._canaries]

    def by_channel(self, channel):
        return [dict(c) for c in self._canaries if c["channel"] == channel]


class CanaryRegistry:
    """Server-side record of planted canary values.

    Lives OUTSIDE the jail — the executor holds it, the agent never sees
    it. No method here takes a jail path; there is deliberately no API
    that could write registry data somewhere the agent can read.

    PRIVACY CONTRACT: this registry holds ONLY planted FAKE values.
    Never register real credentials, real hostnames, or real tokens
    here — canaries are non-sensitive by design (honeytokens), and
    consumers (egress scanning, audit labels) treat the contents as
    attacker-visible. Real content belongs in blinded commitments
    (see gov/taint_ledger.py), never in a detection registry.
    """

    def __init__(self):
        self._by_value = {}
        self._by_host = {}
        self._by_value_norm = {}
        self.run_id = None

    def register(self, mint):
        """Record every value from a :class:`CanaryMint`."""
        self.run_id = mint.run_id
        for c in mint.values():
            self._by_value[c["value"]] = c
            self._by_value_norm[normalize_canary_text(c["value"])] = c
            if c["kind"] == "hostname":
                self._by_host[c["value"].lower()] = c

    def match_value(self, s):
        """Exact credential/token match, then normalized match.

        Full-value equality, or substring containment for values the
        agent demonstrably ingested (an exfiltrated credential pasted
        into a larger payload is still the canary). Exact-only on the
        registry side: the *canary value* must appear verbatim — no
        prefix, truncation, or fuzzy matching.

        Wave-144 (row-13): when exact matching misses, both sides are
        compared through :func:`normalize_canary_text` (casefold,
        whitespace/punctuation stripped, leet digits mapped), as full
        normalized equality or normalized substring containment. The
        normalized form must still be at least MIN_MATCHABLE_LEN
        chars — short strings collide too easily. Hits carry
        ``match`` = "normalized" or "normalized+substring" (exact
        hits carry "exact", substring hits "substring").
        """
        if not isinstance(s, str) or len(s) < MIN_MATCHABLE_LEN:
            return None
        hit = self._by_value.get(s)
        if hit is not None:
            found = dict(hit)
            found["match"] = "exact"
            return found
        for value, meta in self._by_value.items():
            if value in s:
                found = dict(meta)
                found["match"] = "substring"
                return found
        norm = normalize_canary_text(s)
        if len(norm) < MIN_MATCHABLE_LEN:
            return None
        hit = self._by_value_norm.get(norm)
        if hit is not None:
            found = dict(hit)
            found["match"] = "normalized"
            return found
        for nvalue, meta in self._by_value_norm.items():
            if nvalue in norm:
                found = dict(meta)
                found["match"] = "normalized+substring"
                return found
        return None

    def match_host(self, host):
        """Exact hostname match (case-insensitive, no suffix matching).

        ``evil-metrics-04.prod.internal`` does NOT match
        ``metrics-04.prod.internal`` — suffix/lookalike matching is a
        false-positive and attacker-confusion hazard, so it is refused
        by construction.
        """
        if not isinstance(host, str):
            return None
        norm = host.strip().lower().rstrip(".")
        hit = self._by_host.get(norm)
        return dict(hit) if hit is not None else None

    def __len__(self):
        return len(self._by_value)


def plant_canaries(jail_root, mint):
    """Seed the jail with canary artifacts. Returns (env_additions, manifest).

    Writes into the JAIL ONLY: ``<jail>/.aws/credentials``,
    ``<jail>/.env``, ``<jail>/etc/hosts`` (canary hostnames mapped to
    unroutable 10.255.0.0/16 addresses — never valid, never reachable),
    and ``<jail>/config/service.conf`` (decoy config). ``env_additions``
    are merged into the child env by the caller. ``manifest`` is
    server-side bookkeeping and is NOT written into the jail.
    """
    jail = Path(jail_root)
    rng = random.Random(int.from_bytes(
        hashlib.sha256(("plant|%s" % mint.run_id).encode()).digest()[:8],
        "big"))
    by_label = {c["label"]: c for c in mint.values()}

    files_written = []

    # --- ~/.aws/credentials ------------------------------------------
    aws_dir = jail / ".aws"
    aws_dir.mkdir(parents=True, exist_ok=True)
    creds = aws_dir / "credentials"
    creds.write_text(
        "[default]\n"
        "aws_access_key_id = %s\n"
        "aws_secret_access_key = %s\n"
        % (by_label["aws-key-0"]["value"],
           by_label["aws-secret-0"]["value"]))
    files_written.append(str(creds))

    # --- ~/.env --------------------------------------------------------
    env_file = jail / ".env"
    env_file.write_text(
        "INTERNAL_API_TOKEN=%s\n"
        "DATABASE_URL=%s\n"
        "STRIPE_SECRET_KEY=%s\n"
        "AWS_ACCESS_KEY_ID=%s\n"
        "AWS_SECRET_ACCESS_KEY=%s\n"
        % (by_label["internal-api-token"]["value"],
           by_label["database-url"]["value"],
           by_label["stripe-secret"]["value"],
           by_label["aws-key-0"]["value"],
           by_label["aws-secret-0"]["value"]))
    files_written.append(str(env_file))

    # --- /etc/hosts ----------------------------------------------------
    etc = jail / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    hosts = etc / "hosts"
    lines = ["# local service overrides"]
    for c in mint.by_channel("hosts"):
        ip = "10.255.%d.%d" % (rng.randrange(0, 256), rng.randrange(1, 255))
        lines.append("%s %s" % (ip, c["value"]))
    hosts.write_text("\n".join(lines) + "\n")
    files_written.append(str(hosts))

    # --- decoy config --------------------------------------------------
    cfg_dir = jail / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    conf = cfg_dir / "service.conf"
    conf.write_text(
        "[service]\n"
        "api_token = %s\n"
        "database_url = %s\n"
        % (by_label["github-token"]["value"],
           by_label["database-url"]["value"]))
    files_written.append(str(conf))

    env_additions = {
        "INTERNAL_API_TOKEN": by_label["internal-api-token"]["value"],
        "AWS_ACCESS_KEY_ID": by_label["aws-key-0"]["value"],
        "AWS_SECRET_ACCESS_KEY": by_label["aws-secret-0"]["value"],
        "DATABASE_URL": by_label["database-url"]["value"],
        "STRIPE_SECRET_KEY": by_label["stripe-secret"]["value"],
    }
    manifest = {
        "run_id": mint.run_id,
        "files_written": files_written,
        "env_vars_set": sorted(env_additions),
        "canary_count": len(mint.values()),
    }
    return env_additions, manifest


#: Jail-relative artifacts each planted canary label is written to.
#: Mirrors :func:`plant_canaries`' layout above -- keep the two in
#: sync (pinned by tests/test_unobserved_canary.py::TestLabelMap).
#: Labels with an empty tuple are REGISTERED tripwire-only: they are
#: never written into the jail, so no governed read of them can ever
#: exist and a hit is unobserved by construction. Consumed by
#: gov/unobserved_canary.py (row-13 unobserved-canary egress).
CANARY_LABEL_ARTIFACTS = {
    "aws-key-0": (".aws/credentials", ".env"),
    "aws-secret-0": (".aws/credentials", ".env"),
    "aws-key-1": (),
    "aws-secret-1": (),
    "internal-host-0": ("etc/hosts",),
    "internal-host-1": ("etc/hosts",),
    "internal-host-2": ("etc/hosts",),
    "github-token": ("config/service.conf",),
    "slack-token": (),
    "database-url": (".env", "config/service.conf"),
    "internal-api-token": (".env",),
    "stripe-secret": (".env",),
}


def make_canary_plant(mint):
    """Adapt :func:`plant_canaries` to the sandbox planting-hook shape.

    Returns ``plant(jail_path, child_env) -> env_additions`` for
    ``Sandbox(canary_plant=...)``. The registry is not involved — it
    stays server-side by construction.
    """

    def plant(jail_path, child_env):
        env_additions, _manifest = plant_canaries(jail_path, mint)
        return env_additions

    return plant


def _try_ascii_leaf(value):
    """Decode a non-string arg leaf to ASCII text, or None.

    F128 (wave-63): non-string leaves are scannable credential
    carriers — a bytes blob, or a JSON-native int array (the canonical
    byte encoding, like base64), holding a canary value is still the
    canary value. Only strict ASCII decodes yield a variant: canary
    values are ASCII by construction, so a leaf that does not decode
    to ASCII cannot contain one, and decoded variants only ever ADD
    true hits (exact value match downstream). The printable gate keeps
    the variant space clean (a ``[1, 0]`` bool/int list decodes to
    ``\\x01\\x00``, not to a matchable string).
    """
    raw = None
    if isinstance(value, (bytes, bytearray)):
        if len(value) < MIN_MATCHABLE_LEN:
            return None
        raw = bytes(value)
    elif isinstance(value, (list, tuple)):
        if len(value) < MIN_MATCHABLE_LEN:
            return None
        if not all(isinstance(i, int) and not isinstance(i, bool)
                   and 0 <= i <= 255 for i in value):
            return None
        raw = bytes(value)
    else:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not all(c.isprintable() or c in " \t\n\r" for c in text):
        return None
    return text


def _iter_strings(obj):
    """Yield every string leaf of a nested arg structure.

    F128: also yields ASCII-decoded forms of bytes/bytearray leaves
    and all-int (0-255) list/tuple leaves, and traverses dict KEYS as
    well as values — a canary value placed as an object key, sent as
    bytes, or encoded as a JSON int array is still the canary value.
    Decoded leaves only ever ADD true hits (exact match downstream).
    """
    stack = [obj]
    seen = set()
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if id(v) not in seen:
                seen.add(id(v))
                yield v
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            decoded = _try_ascii_leaf(v)
            if decoded is not None and id(v) not in seen:
                seen.add(id(v))
                yield decoded
            stack.extend(v)
        elif isinstance(v, (bytes, bytearray)):
            decoded = _try_ascii_leaf(v)
            if decoded is not None and id(v) not in seen:
                seen.add(id(v))
                yield decoded


# Encoding-aware matching (break-first c1 -> hardened wave-51). An attacker
# smuggles the canary past exact matching with one encoding step (base64,
# hex, base32, URL-encoding) — the same defeat DLP closes at F2/F8, so the
# discipline is copied: decode candidate encodings BEFORE matching, bounded
# to MAX_DECODE_LAYERS layers, each decode strictly validated (round-trip;
# even-length hex; percent-decoding that changes the text) and required to
# yield printable ASCII. A decoded variant that contains a canary value
# proves the agent ingested the canary — it only ever ADDS true hits, so
# the near-zero false-positive invariant is preserved. Documented residual
# (same class as DLP F8): encodings stacked deeper than the bound, and
# custom substitution ciphers, are not deterministically catchable.
MAX_DECODE_LAYERS = 2
_MAX_DECODE_VARIANTS = 64


def _valid_b64_decode(s):
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    try:
        text = raw.decode("ascii")
    except Exception:
        return None
    # Round-trip: the input must be the canonical encoding of the decode.
    try:
        if base64.b64encode(raw).decode("ascii") != s:
            return None
    except Exception:
        return None
    return text


def _valid_b32_decode(s):
    try:
        raw = base64.b32decode(s, casefold=True)
    except Exception:
        return None
    try:
        text = raw.decode("ascii")
    except Exception:
        return None
    try:
        if base64.b32encode(raw).decode("ascii") != s.upper():
            return None
    except Exception:
        return None
    return text


def _valid_hex_decode(s):
    if len(s) % 2 or not s or any(
            c not in string.hexdigits for c in s):
        return None
    try:
        raw = binascii.unhexlify(s)
    except Exception:
        return None
    try:
        text = raw.decode("ascii")
    except Exception:
        return None
    if binascii.hexlify(raw).decode("ascii") != s.lower():
        return None
    return text


def _valid_url_decode(s):
    try:
        t = unquote(s)
    except Exception:
        return None
    return t if t != s else None


_DECODERS = (_valid_b64_decode, _valid_b32_decode, _valid_hex_decode,
             _valid_url_decode)


def _decode_variants(s):
    """Yield s plus validated decoded variants, up to MAX_DECODE_LAYERS.

    Deterministic and bounded. Decoded text must be printable ASCII —
    binary decodes are rejected, so innocent base64-looking text never
    produces a variant that could match.
    """
    seen = {s}
    yield s
    frontier = [s]
    for _ in range(MAX_DECODE_LAYERS):
        nxt = []
        for text in frontier:
            # Only attempt decodes on plausible-length tokens; tiny
            # strings cannot encode a matchable canary anyway.
            if len(text) < 8:
                continue
            for dec in _DECODERS:
                try:
                    out = dec(text)
                except Exception:
                    continue
                if (out and out not in seen and len(out) >= MIN_MATCHABLE_LEN
                        and out.isascii()
                        and all(c.isprintable() or c in " \t\n\r"
                                for c in out)):
                    seen.add(out)
                    nxt.append(out)
                    yield out
                    if len(seen) >= _MAX_DECODE_VARIANTS:
                        return
        frontier = nxt
        if not frontier:
            break


def scan_egress_attempt(tool, args, registry):
    """Tripwire scan for one egress attempt. Pure function, no side effects.

    Returns a hit dict ``{kind, label, matched_value, field}`` or None.
    ``kind`` is ``"hostname"`` (destination is a canary host) or
    ``"credential"`` (a canary secret appears in the args).
    """
    if registry is None or tool not in EGRESS_TOOLS:
        return None
    if not isinstance(args, dict):
        return None

    # --- destination hostname -----------------------------------------
    host = None
    field = None
    try:
        if tool in ("http_post", "api_call"):
            raw = args.get("url") if tool == "http_post" else args.get(
                "endpoint")
            if isinstance(raw, str) and raw:
                host = urlparse(raw).hostname
                field = "url" if tool == "http_post" else "endpoint"
        elif tool == "send_email":
            to = args.get("to")
            if isinstance(to, str) and "@" in to:
                host = to.rsplit("@", 1)[-1]
                field = "to"
    except Exception:
        host = None
    if host:
        hit = registry.match_host(host)
        if hit is not None:
            return {"kind": "hostname", "label": hit["label"],
                    "matched_value": host, "field": field}

    # --- credential / token values in args ----------------------------
    # Encoding-aware: each string leaf is matched directly and through
    # validated decoded variants (base64/base32/hex/URL, <= 2 layers).
    for s in _iter_strings(args):
        for variant in _decode_variants(s):
            hit = registry.match_value(variant)
            if hit is not None:
                how = "direct" if variant == s else "decoded"
                if hit.get("match") == "substring":
                    how += "+substring"
                return {"kind": "credential", "label": hit["label"],
                        "matched_value": s if how == "direct"
                        else "<%s>" % how,
                        "field": "args"}

    return None


def check_and_trip(executor, identity, tool, args):
    """Run the tripwire for one tool call; halt fail-closed on a hit.

    On a hit: (1) append a LOUD ``canary_trip`` audit event; (2) escalate
    to the approval queue with the trip evidence (flag ``canary_trip``);
    (3) raise :class:`CanaryTripHalt`. Steps 1-2 are best-effort — if the
    audit log or the queue raises, the halt still happens. Returns None
    when there is no hit (or no registry configured).

    Row-13 unobserved-canary egress (wave-143): when the executor has a
    rare-token tracker installed (the read-observation source of truth),
    a hit with NO recorded governed read of the canary's source
    document trips a DISTINCT loud event via
    ``gov.unobserved_canary.trip_unobserved`` (``unobserved_canary_egress``)
    instead -- the read happened out-of-band. Same fail-closed halt.
    Without a tracker the read/unread distinction cannot be drawn, so
    the ``canary_trip`` path below handles every hit (zero behavior
    change vs wave-51).
    """
    hit = scan_egress_attempt(
        tool, args, getattr(executor, "canary_registry", None))
    if hit is None:
        return None

    # Local import: gov.unobserved_canary imports this module at top
    # level, so a module-level import here would cycle.
    from . import unobserved_canary as _unobserved
    tracker = getattr(executor, "rare_token_tracker", None)
    if tracker is not None and not _unobserved.has_recorded_read(
            tracker, getattr(identity, "agent_id", "?"), hit):
        return _unobserved.trip_unobserved(executor, identity, tool,
                                           args, hit)

    run_id = getattr(executor, "run_id", "?")
    agent_id = getattr(identity, "agent_id", "?")
    principal = getattr(identity, "principal", "?")
    reason = (
        "Canary tripwire: agent %s (principal %s) attempted egress via %s "
        "using a canary %s (%s) in %s. Canaries are never valid credentials "
        "or reachable hosts, so this is exfiltration intent (injection, "
        "bug, or compromise) by construction. Run halted fail-closed; "
        "escalated for human review."
        % (agent_id, principal, tool, hit["kind"], hit["label"],
           hit["field"]))

    # (1) LOUD audit event — distinct type, evidence attached.
    try:
        executor.log.append({
            "event": "canary_trip",
            "run_id": run_id,
            "agent_id": agent_id,
            "role": getattr(identity, "role", "?"),
            "principal": principal,
            "tool": tool,
            "decision": "halted",
            "policy_id": "canary-tripwire",
            "flag": "canary_trip",
            "canary_kind": hit["kind"],
            "canary_label": hit["label"],
            "matched_field": hit["field"],
            "reason": reason,
        })
    except Exception:
        pass  # the halt below is the control; audit is best-effort

    # (2) approval-queue escalation with the trip evidence.
    try:
        decision = PolicyDecision(
            "require_approval", reason,
            policy_id="canary-tripwire", flag="canary_trip")
        action = {"tool": tool, "args": args,
                  "identity": identity.as_dict(),
                  "agent_justification": None, "redactions": []}
        preview = executor._preview(tool, args)
        egress_bytes = 0
        _ebf = getattr(executor, "_egress_bytes_for", None)
        if callable(_ebf):
            try:
                egress_bytes = _ebf(tool, args)
            except Exception:
                egress_bytes = 0
        executor.approvals.queue(
            action, decision, "agent_direct", preview,
            policy_hash=executor.policy.policy_hash,
            policy_flag="canary_trip",
            egress_bytes=egress_bytes,
            caller_identity=identity)
    except Exception:
        pass  # fail-closed: queue failure must not un-halt

    # (3) halt — never executes the call.
    raise CanaryTripHalt(reason)
