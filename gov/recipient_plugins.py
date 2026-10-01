"""Pluggable envelope recipients: the age-plugin protocol shape, in-process.

Age-plugin-protocol ADAPT (``str4d/age-plugin-yubikey``, MIT OR
Apache-2.0; pattern only -- no age code is vendored, no age stanza
bytes are parsed): the recombination the wave-262 prospectus ranked
#1 for wave-263 (D1, w258-D1 follow-up).

What is stolen (the protocol shape, not the code):

* **Recipient-namespace routing.** In age, a plugin binary named
  ``age-plugin-<name>`` owns the recipient namespace ``age1<name>1...``;
  new recipient kinds arrive as new binaries and the core never
  changes. Here a plugin class declares ``LABEL_NAMESPACE``
  (e.g. ``"gov1sym"``) and owns every recipient label with that
  prefix (e.g. ``gov1sym1alice``). :meth:`PluginRegistry.route`
  resolves a wire label to its plugin; the envelope core calls the
  plugin interface and never changes when a new recipient type is
  added -- registration is the only integration point.
* **The two state machines.** Age runs ``recipient-v1`` (seal side)
  and ``identity-v1`` (open side) as stanza machines over a spawned
  binary. Here they are the two plugin methods: ``wrap`` (seal side)
  and ``unwrap`` (open side). A plugin may emit MULTIPLE wire
  entries per recipient (the quorum plugin emits one per share),
  exactly as an age plugin may emit multiple stanzas.
* **Framework-enforced label consistency.** Age enforces that every
  stanza in one execution carries consistent labels when the plugin
  implements ``RecipientWithLabels``. Here the framework checks at
  seal time that every wire label a plugin emits routes back to that
  same plugin (``recipient-plugin-label-inconsistent``) and that
  every wrap is exactly 48 bytes
  (``recipient-plugin-malformed-wrap``) -- the SASENV1 wire format
  never changes shape.

Out-of-process seam: the stanza protocol for a future spawned-binary
plugin is documented in :data:`SUBPROCESS_PROTOCOL` and sketched by
:data:`SubprocessPlugin` (refuses loudly until configured). Plugin
binaries are trust-anchor software: verify transparent-release
provenance before the envelope core will ever spawn them.

Wire contract (unchanged SASENV1): each recipient entry carries the
full recipient *label* in the id field and exactly 48 wrap bytes.
Bare labels (no ``gov1`` prefix) route to the symmetric plugin as the
legacy namespace, so envelopes sealed before this module existed open
identically.

Error contract:

* Seal time: plugin problems are policy failures with specific
  machine codes (``recipient-plugin-identity-refused``,
  ``recipient-plugin-malformed-wrap``,
  ``recipient-plugin-label-inconsistent``,
  ``recipient-plugin-wrap-refused``) -- no key-dependent content.
  At the :class:`gov.encrypted_envelopes.EnvelopeVault` boundary
  these surface as ``EnvelopeRefusal`` carrying the plugin's code
  (one exception type per boundary; the code is the contract).
* Open time: ANY plugin failure (protocol or raw exception) converts
  to the single generic ``envelope-open-refused`` at the vault
  boundary, after data-independent work. A plugin's ``unwrap`` NEVER
  raises on wrong key material -- it returns 32 garbage bytes and the
  tag check is the single authenticity decision, exactly like
  :class:`gov.encrypted_envelopes.KeyWrap`.
* Registration: ``recipient-plugin-namespace-conflict``.
* Routing: ``recipient-plugin-unknown-label``.

HONEST RESIDUALS (read before deploying)
----------------------------------------
* This is **recipient agility, not a new cipher**. The HMAC-CTR +
  encrypt-then-MAC honest residual from
  :mod:`gov.encrypted_envelopes` stands unchanged: this module adds
  no cryptographic primitive, only a routing and namespacing layer
  around the existing key wrap.
* A quorum recipient counts **shares, not distinct humans**: nothing
  stops a deployment from issuing the same key material under two
  share ids (mirrors the ``gov.key_groups`` residual). Separation of
  duty is a deployment custody property, not a cryptographic one.
* The quorum plugin is Shamir k-of-n over GF(256): k-1 shares are
  cryptographically insufficient. But a WRONG share among the k
  poisons reconstruction -- the plugin returns one candidate and the
  tag refuses. Supply exactly the shares you hold.
* ``gov.key_groups.GroupVault`` composes where it fits and differs
  where it does not: key_groups wraps the SAME data key under each
  member (any single share is cryptographically sufficient; the
  quorum is a policy count of tag-verified wraps), while this
  plugin's shares are Shamir-split (k-1 shares are mathematically
  insufficient). Use key_groups for policy quorum, this plugin for
  cryptographic threshold.
* The symmetric plugin's default KEM is byte-compatible with
  :class:`gov.encrypted_envelopes.KeyWrap` (same
  ``symmetric-hmac-wrap/v1`` algorithm, same KDF info strings;
  cross-compat is unit-tested). A deployment injects its own KEM
  (e.g. X25519) through the vault, exactly as before.
"""

import hashlib
import hmac
import re
import secrets
import struct

WRAP_LEN = 48  # wire slot per recipient entry; framework-enforced
_MIN_KEY_MATERIAL = 16
_MAX_LABEL_BYTES = 128  # matches encrypted_envelopes.MAX_ID_LEN
_MAX_SHARES = 16

# Namespaces live under the gov1 root so a bare legacy id can never
# collide with a plugin namespace.
_NAMESPACE_RE = re.compile(r"^gov1[0-9a-z]{1,16}$")
_GOV1_PREFIX = "gov1"

# Must stay byte-identical to gov.encrypted_envelopes._DOMAIN: the
# symmetric plugin's default KEM is the same named algorithm
# (symmetric-hmac-wrap/v1) and cross-compat is pinned by unit test.
_ENVELOPE_DOMAIN = b"sasanam-envelope/v1/"

_PLUGIN_DOMAIN = b"sasanam-recipient-plugin/v1/"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class RecipientPluginError(Exception):
    """Base class for all recipient-plugin refusals. Carries ``code``."""

    def __init__(self, code, detail):
        super(RecipientPluginError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# KDF / stream cipher (self-contained; mirrors encrypted_envelopes)
# ---------------------------------------------------------------------------

def _kdf(domain, key, info, length):
    out = bytearray()
    counter = 1
    while len(out) < length:
        out += hmac.new(key, domain + info + struct.pack(">I", counter),
                        hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _keystream(domain, key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(key, domain + b"stream:" + nonce +
                        struct.pack(">Q", counter),
                        hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _as_bytes(value):
    if isinstance(value, bytearray):
        return bytes(value)
    return value


# ---------------------------------------------------------------------------
# GF(256) Shamir secret sharing (stdlib; AES polynomial 0x11b)
# ---------------------------------------------------------------------------

def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xff) ^ (0x1b if hi else 0)
        b >>= 1
    return p


def _gf_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        e >>= 1
    return r


def _gf_inv(a):
    if a == 0:
        raise ValueError("gf inverse of zero")
    return _gf_pow(a, 254)


def _share_x(share_id):
    """Deterministic non-zero Shamir x coordinate for a share id."""
    digest = hashlib.sha256(b"quorum-x:" + share_id.encode("utf-8"))
    return 1 + (int.from_bytes(digest.digest(), "big") % 255)


def _shamir_split(secret, k, xs, rand_bytes):
    """Split ``secret`` (bytes) into shares at x coordinates ``xs``.

    ``k`` is the threshold; ``rand_bytes`` supplies coefficient
    randomness (``secrets.token_bytes`` in production, injectable for
    known-answer tests). Returns ``[(x, y_bytes)]`` in ``xs`` order.
    """
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("secret must be non-empty bytes")
    if not (2 <= k <= len(xs)):
        raise ValueError("bad threshold")
    if any(not 1 <= x <= 255 for x in xs) or len(set(xs)) != len(xs):
        raise ValueError("x coordinates must be distinct non-zero bytes")
    shares = dict((x, bytearray()) for x in xs)
    for s in secret:
        coeff = [s] + list(rand_bytes(k - 1))
        if len(coeff) != k:
            raise ValueError("rand_bytes short")
        for x in xs:
            acc = 0
            pw = 1
            for c in coeff:
                acc ^= _gf_mul(c, pw)
                pw = _gf_mul(pw, x)
            shares[x].append(acc)
    return [(x, bytes(shares[x])) for x in xs]


def _shamir_combine(pairs):
    """Lagrange-interpolate the secret at x=0 from ``(x, y_bytes)``."""
    if not pairs:
        raise ValueError("no shares")
    nbytes = len(pairs[0][1])
    if any(len(y) != nbytes for _x, y in pairs):
        raise ValueError("ragged shares")
    xs = [x for x, _y in pairs]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate x")
    secret = bytearray()
    for j in range(nbytes):
        acc = 0
        for i, (xi, yi) in enumerate(pairs):
            num, den = 1, 1
            for m, (xm, _ym) in enumerate(pairs):
                if m == i:
                    continue
                num = _gf_mul(num, xm)
                den = _gf_mul(den, xi ^ xm)
            acc ^= _gf_mul(yi[j], _gf_mul(num, _gf_inv(den)))
        secret.append(acc)
    return bytes(secret)


# ---------------------------------------------------------------------------
# Plugin interface
# ---------------------------------------------------------------------------

class RecipientPlugin(object):
    """One recipient type: a label namespace plus the two state
    machines (age's ``recipient-v1`` / ``identity-v1``).

    ``NAME`` is the plugin's registry name (e.g.
    ``"symmetric-hmac/v1"``); ``LABEL_NAMESPACE`` is the label prefix
    it owns (e.g. ``"gov1sym"``). Subclasses implement :meth:`wrap`
    and :meth:`unwrap`. Construction never raises; misuse is refused
    at registration or at seal/open time with machine codes.
    """

    NAME = "base/v0"
    LABEL_NAMESPACE = None

    def wrap(self, envelope_key, label, identity):
        """Seal side (age ``recipient-v1``).

        ``envelope_key`` is the fresh 32-byte envelope key;
        ``label`` the recipient label; ``identity`` the
        deployment-supplied seal-time identity dict. Returns a
        non-empty list of ``(label, wrap_bytes)`` wire entries --
        every label under this plugin's namespace, every wrap
        exactly 48 bytes (both framework-enforced). Raises
        :class:`RecipientPluginError` on refusal; any other
        exception is converted to ``recipient-plugin-wrap-refused``.
        """
        raise NotImplementedError

    def unwrap(self, entries, identity):
        """Open side (age ``identity-v1``).

        ``entries`` is ``[(label, wrap_bytes)]`` for this plugin's
        wire entries; ``identity`` maps label -> deployment-supplied
        open-time identity dict. Returns a single ``(label,
        candidate)`` pair -- the combined 32-byte candidate envelope
        key, labeled by the first entry (the candidate is a
        combination of shares, not one share; the vault names the
        verified entry on success). The vault tries the candidate
        against the tag. NEVER raises on wrong key material: return
        garbage and let the tag decide. Raises
        :class:`RecipientPluginError` only for structural problems
        (missing identity, too few shares); the vault converts every
        unwrap failure to ``envelope-open-refused``.
        """
        raise NotImplementedError


class PluginRecipient(object):
    """A seal-time recipient: label + plugin reference + identity.

    ``plugin`` is a registry name (``"symmetric-hmac/v1"``) or a
    registered plugin instance. ``identity`` is the dict the plugin
    needs at seal time (symmetric: ``{"key_material": bytes}``;
    quorum: ``{"shares": {share_id: bytes}, "quorum": k}``).
    Construction never raises; :meth:`seal_plugin` validates.
    """

    def __init__(self, label, plugin, identity=None):
        self.label = label
        self.plugin = plugin
        self.identity = identity if identity is not None else {}


# ---------------------------------------------------------------------------
# Registry: namespace ownership + routing (framework-enforced)
# ---------------------------------------------------------------------------

class PluginRegistry(object):
    """Owns label-namespace -> plugin bindings.

    ``register`` refuses loudly (``recipient-plugin-namespace-conflict``)
    when a plugin claims another plugin's namespace: exact claim,
    prefix overlap in either direction (routing would be ambiguous),
    duplicate plugin name, or a malformed namespace. ``route``
    resolves a wire label to its plugin (longest matching prefix;
    the no-prefix-overlap invariant makes it unique) or refuses
    ``recipient-plugin-unknown-label``. Labels with no ``gov1``
    prefix fall back to the legacy plugin (the pre-module symmetric
    behavior for bare ids); a registry without one refuses those too.
    """

    def __init__(self, legacy_plugin=None):
        self._by_namespace = {}
        self._by_name = {}
        self._legacy = legacy_plugin

    def set_legacy(self, plugin):
        self._legacy = plugin
        return plugin

    def register(self, plugin):
        ns = plugin.LABEL_NAMESPACE
        name = plugin.NAME
        if not isinstance(ns, str) or not _NAMESPACE_RE.match(ns):
            raise RecipientPluginError(
                "recipient-plugin-namespace-conflict",
                "malformed label namespace %r (want ^gov1[0-9a-z]{1,16}$)"
                % (ns,))
        if not isinstance(name, str) or not name:
            raise RecipientPluginError(
                "recipient-plugin-namespace-conflict",
                "malformed plugin name %r" % (name,))
        if name in self._by_name:
            raise RecipientPluginError(
                "recipient-plugin-namespace-conflict",
                "plugin name %r already registered" % (name,))
        for existing in self._by_namespace:
            if (existing == ns or existing.startswith(ns)
                    or ns.startswith(existing)):
                raise RecipientPluginError(
                    "recipient-plugin-namespace-conflict",
                    "namespace %r conflicts with registered %r" %
                    (ns, existing))
        self._by_namespace[ns] = plugin
        self._by_name[name] = plugin
        return plugin

    def route(self, label):
        """Resolve a wire label to its plugin or refuse."""
        if not isinstance(label, str) or not label:
            raise RecipientPluginError(
                "recipient-plugin-unknown-label",
                "recipient label must be a non-empty str")
        matches = [ns for ns in self._by_namespace
                   if label.startswith(ns)]
        if matches:
            # No-prefix-overlap invariant: at most one match.
            ns = max(matches, key=len)
            return self._by_namespace[ns]
        if label.startswith(_GOV1_PREFIX):
            raise RecipientPluginError(
                "recipient-plugin-unknown-label",
                "no plugin claims namespace of label %r" % (label,))
        if self._legacy is not None:
            return self._legacy
        raise RecipientPluginError(
            "recipient-plugin-unknown-label",
            "no plugin claims label %r and no legacy plugin set" %
            (label,))

    def get(self, name):
        """Look up a plugin by registry name or refuse."""
        try:
            return self._by_name[name]
        except (KeyError, TypeError):
            raise RecipientPluginError(
                "recipient-plugin-unknown-label",
                "no plugin registered under name %r" % (name,))

    def namespaces(self):
        return sorted(self._by_namespace)

    def names(self):
        return sorted(self._by_name)


# ---------------------------------------------------------------------------
# Shipped plugin 1: symmetric HMAC wrap (the existing stdlib recipient)
# ---------------------------------------------------------------------------

class _HmacWrap(object):
    """Default KEM ``symmetric-hmac-wrap/v1``.

    Byte-compatible with ``gov.encrypted_envelopes.KeyWrap``: same
    domain, same KDF info strings (pinned by cross-compat unit test).
    ``unwrap`` never raises on a wrong key -- garbage bytes, so the
    tag is the single authenticity decision.
    """

    name = "symmetric-hmac-wrap/v1"

    @staticmethod
    def _wrap_key(label_bytes, key_material):
        return _kdf(_ENVELOPE_DOMAIN, key_material,
                    b"wrap:" + struct.pack(">H", len(label_bytes)) +
                    label_bytes, 32)

    def wrap(self, envelope_key, label_bytes, key_material):
        nonce = secrets.token_bytes(16)
        wk = self._wrap_key(label_bytes, key_material)
        return nonce + _xor(envelope_key,
                            _keystream(_ENVELOPE_DOMAIN, wk, nonce, 32))

    def unwrap(self, wrapped, label_bytes, key_material):
        nonce, masked = wrapped[:16], wrapped[16:]
        wk = self._wrap_key(label_bytes, key_material)
        return _xor(masked,
                    _keystream(_ENVELOPE_DOMAIN, wk, nonce, 32))


class SymmetricPlugin(RecipientPlugin):
    """The existing stdlib recipient, adapted as the default plugin.

    Namespace ``gov1sym``; also serves as the legacy fallback for
    bare (pre-module) labels. Seal identity: ``{"key_material":
    bytes}`` (>= 16 bytes). Open identity: ``{label:
    {"key_material": bytes}}``. A deployment injects its own KEM
    (duck-typed ``wrap``/``unwrap``) via the constructor -- the vault
    wires its configured KEM here, so ``EnvelopeVault(kem=...)``
    keeps working through the plugin path.
    """

    NAME = "symmetric-hmac/v1"
    LABEL_NAMESPACE = "gov1sym"

    def __init__(self, kem=None):
        self._kem = kem if kem is not None else _HmacWrap()

    @staticmethod
    def _key_material(identity):
        if not isinstance(identity, dict):
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "symmetric identity must be a dict")
        km = _as_bytes(identity.get("key_material"))
        if not isinstance(km, bytes) or len(km) < _MIN_KEY_MATERIAL:
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "key material must be bytes >= %d" % _MIN_KEY_MATERIAL)
        return km

    def wrap(self, envelope_key, label, identity):
        km = self._key_material(identity)
        label_bytes = label.encode("utf-8")
        return [(label, self._kem.wrap(envelope_key, label_bytes, km))]

    def unwrap(self, entries, identity):
        if not isinstance(identity, dict):
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "symmetric open identity must be a dict")
        out = []
        for label, wrap in entries:
            sub = identity.get(label)
            km = self._key_material(sub)
            # Never raises on wrong key: garbage candidate, tag decides.
            out.append((label, self._kem.unwrap(
                wrap, label.encode("utf-8"), km)))
        return out


# ---------------------------------------------------------------------------
# Shipped plugin 2: Shamir k-of-n quorum recipient
# ---------------------------------------------------------------------------

class QuorumPlugin(RecipientPlugin):
    """Cryptographic threshold recipient: k-of-n Shamir shares.

    Namespace ``gov1quorum``. Seal identity: ``{"shares":
    {share_id: key_material}, "quorum": k}`` with 2 <= k <= n <= 16.
    Each share's 32 Shamir y-values are wrapped under that share's
    key material (same HMAC-CTR shape, ``quorum-wrap:`` KDF info);
    the wire label ``gov1quorum1<group>1<share_id>`` carries the
    share id (x coordinate derived deterministically from it;
    duplicate-x refused at seal so one share can never count twice).
    Open identity: ``{"shares": {share_id: key_material}}`` (per
    label, or merged across the plugin's labels). Fewer than k
    usable shares -> ``recipient-plugin-identity-refused``; a wrong
    share poisons reconstruction and the tag refuses.

    Counts shares, not distinct humans: a deployment issuing the
    same key material under two share ids defeats separation of
    duty -- a custody property, not a cryptographic one.
    """

    NAME = "quorum-shamir/v1"
    LABEL_NAMESPACE = "gov1quorum"

    # -- seal ------------------------------------------------------

    @staticmethod
    def _seal_identity(identity):
        if not isinstance(identity, dict):
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "quorum identity must be a dict")
        shares = identity.get("shares")
        quorum = identity.get("quorum")
        if not isinstance(shares, dict) or not shares:
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "quorum identity needs a non-empty 'shares' dict")
        if (not isinstance(quorum, int) or isinstance(quorum, bool)
                or quorum < 2 or quorum > len(shares)):
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "quorum k must satisfy 2 <= k <= n_shares, got %r" %
                (quorum,))
        if len(shares) > _MAX_SHARES:
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "too many shares (max %d)" % _MAX_SHARES)
        checked = {}
        xs = set()
        for share_id, km in shares.items():
            if (not isinstance(share_id, str) or not share_id
                    or len(share_id.encode("utf-8")) > 64):
                raise RecipientPluginError(
                    "recipient-plugin-identity-refused",
                    "share id must be a non-empty str <= 64 bytes")
            km = _as_bytes(km)
            if not isinstance(km, bytes) or len(km) < _MIN_KEY_MATERIAL:
                raise RecipientPluginError(
                    "recipient-plugin-identity-refused",
                    "share %r: key material must be bytes >= %d" %
                    (share_id, _MIN_KEY_MATERIAL))
            x = _share_x(share_id)
            if x in xs:
                # One share counting twice toward the quorum.
                raise RecipientPluginError(
                    "recipient-plugin-identity-refused",
                    "share ids %r collide on Shamir x=%d" %
                    (share_id, x))
            xs.add(x)
            checked[share_id] = (x, km)
        return checked, quorum

    @staticmethod
    def _wrap_share(y_values, label_bytes, key_material):
        wk = _kdf(_PLUGIN_DOMAIN, key_material,
                  b"quorum-wrap:" + struct.pack(">H", len(label_bytes)) +
                  label_bytes, 32)
        nonce = secrets.token_bytes(16)
        return nonce + _xor(y_values,
                            _keystream(_PLUGIN_DOMAIN, wk, nonce, 32))

    def wrap(self, envelope_key, label, identity):
        checked, quorum = self._seal_identity(identity)
        group = secrets.token_hex(8)
        prefix = self.LABEL_NAMESPACE + "1" + group + "1"
        share_ids = list(checked)
        xs = [checked[sid][0] for sid in share_ids]
        try:
            split = _shamir_split(envelope_key, quorum, xs,
                                  secrets.token_bytes)
        except ValueError as e:
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "shamir split failed: %s" % e)
        out = []
        for share_id, (_x, y_values) in zip(share_ids, split):
            wlabel = prefix + share_id
            if len(wlabel.encode("utf-8")) > _MAX_LABEL_BYTES:
                raise RecipientPluginError(
                    "recipient-plugin-identity-refused",
                    "share label too long for %r" % (share_id,))
            _x, km = checked[share_id]
            out.append((wlabel, self._wrap_share(
                y_values, wlabel.encode("utf-8"), km)))
        return out

    # -- open ------------------------------------------------------

    def _parse_share_label(self, label):
        # Label shape: "gov1quorum1" + <16 hex group> + "1" + <share_id>.
        # The group is fixed-width, so the split is unambiguous even
        # when the group hex or the share id contains "1".
        prefix = self.LABEL_NAMESPACE + "1"
        if not label.startswith(prefix):
            raise RecipientPluginError(
                "recipient-plugin-label-inconsistent",
                "label %r not under namespace %r" %
                (label, self.LABEL_NAMESPACE))
        rest = label[len(prefix):]
        if len(rest) < 18 or rest[16] != "1":
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "malformed quorum share label %r" % (label,))
        share_id = rest[17:]
        if not share_id:
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "malformed quorum share label %r" % (label,))
        return share_id

    def unwrap(self, entries, identity):
        if not isinstance(identity, dict):
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "quorum open identity must be a dict")
        # Merge per-label {"shares": {...}} dicts (callers key
        # identities by wire label; every label carries the shares).
        shares = {}
        for _label, sub in identity.items():
            if isinstance(sub, dict) and isinstance(
                    sub.get("shares"), dict):
                for sid, km in sub["shares"].items():
                    shares[sid] = _as_bytes(km)
        if not shares:
            # Also accept a single {"shares": {...}} identity.
            sub = identity.get("shares")
            if isinstance(sub, dict):
                shares = {sid: _as_bytes(km)
                          for sid, km in sub.items()}
        points = []
        seen_x = set()
        for label, wrap in entries:
            share_id = self._parse_share_label(label)
            km = shares.get(share_id)
            if km is None:
                continue  # caller does not hold this share
            if not isinstance(km, bytes) or not km:
                raise RecipientPluginError(
                    "recipient-plugin-identity-refused",
                    "share %r: key material must be non-empty bytes" %
                    (share_id,))
            x = _share_x(share_id)
            if x in seen_x:
                continue
            seen_x.add(x)
            label_bytes = label.encode("utf-8")
            wk = _kdf(_PLUGIN_DOMAIN, km,
                      b"quorum-wrap:" +
                      struct.pack(">H", len(label_bytes)) + label_bytes,
                      32)
            nonce, masked = wrap[:16], wrap[16:]
            y_values = _xor(masked, _keystream(_PLUGIN_DOMAIN, wk,
                                               nonce, 32))
            # Wrong share material -> garbage y_values; the tag is
            # the single authenticity decision, never this method.
            points.append((x, y_values))
        # The seal-time quorum k is not on the wire (labels carry no
        # key material); the caller must hold enough shares. Fewer
        # usable shares than the sealed k reconstructs a wrong key
        # and the tag refuses -- fail closed either way.
        if not points:
            raise RecipientPluginError(
                "recipient-plugin-identity-refused",
                "no usable shares supplied")
        points.sort(key=lambda p: p[0])
        return [(entries[0][0], _shamir_combine(points))]


# ---------------------------------------------------------------------------
# Out-of-process seam: documented, not spawned
# ---------------------------------------------------------------------------

SUBPROCESS_PROTOCOL = """\
Out-of-process recipient plugins (age-plugin-style), DOCUMENTED SEAM --
not implemented in this module. A future SubprocessPlugin transport
spawns `<binary> --age-plugin=<machine>` and speaks two stanza state
machines over stdin/stdout (UTF-8 lines, then raw bytes):

  recipient-v1 (seal side):
    -> add-recipient <label>          # label already routed to this binary
    -> add-identity <label> <identity-json>
    -> wrap-file-key
    <32-byte envelope key, raw>
    <- ok
    -> <label>                        # repeated per emitted wire entry
    -> <base64 wrap bytes, 48 bytes decoded>
    <- ok
    (any step may instead reply: <- error <machine-code> <human>)

  identity-v1 (open side):
    -> unwrap-file-key
    -> <label>                        # repeated per wire entry
    -> <base64 wrap bytes>
    -> <identity-json>                # per-label open identity
    <- ok
    <32-byte candidate envelope key, raw>   # repeated per candidate
    (any step may instead reply: <- error <machine-code> <human>)

Framework invariants the transport must preserve: every emitted label
routes back to the spawning plugin's namespace (label consistency);
every wrap decodes to exactly 48 bytes; a plugin that errors during
wrap/unwrap produces a machine-coded refusal, never partial
plaintext. TRUST ANCHOR: plugin binaries see envelope keys -- they
are trust-anchor software. Verify transparent-release provenance
(w261 Oak D2) before the envelope core will spawn them; never spawn
a plugin binary from an untrusted PATH.
"""


class SubprocessPlugin(RecipientPlugin):
    """Documented seam for out-of-process (age-plugin-style) plugins.

    NOT IMPLEMENTED: :meth:`wrap`/:meth:`unwrap` refuse loudly with
    machine codes until a deployment wires the
    :data:`SUBPROCESS_PROTOCOL` transport AND the provenance gate
    for the plugin binary. The class exists so the protocol has a
    typed home in the registry; registering it is allowed (its
    namespace participates in conflict checks) but any use refuses.
    """

    NAME = "subprocess-stub/v1"

    def __init__(self, binary, label_namespace):
        self.binary = binary
        if (not isinstance(label_namespace, str)
                or not _NAMESPACE_RE.match(label_namespace)):
            raise RecipientPluginError(
                "recipient-plugin-namespace-conflict",
                "malformed label namespace %r" % (label_namespace,))
        self.LABEL_NAMESPACE = label_namespace
        # Namespace-qualified name: several subprocess stubs with
        # different namespaces can share one registry.
        self.NAME = "subprocess-stub/v1:" + label_namespace

    def wrap(self, envelope_key, label, identity):
        raise RecipientPluginError(
            "recipient-plugin-wrap-refused",
            "out-of-process plugin not configured (binary %r); see "
            "SUBPROCESS_PROTOCOL" % (self.binary,))

    def unwrap(self, entries, identity):
        raise RecipientPluginError(
            "recipient-plugin-unwrap-refused",
            "out-of-process plugin not configured (binary %r); see "
            "SUBPROCESS_PROTOCOL" % (self.binary,))


# ---------------------------------------------------------------------------
# Default registry
# ---------------------------------------------------------------------------

def default_registry(symmetric_kem=None):
    """Build the default registry: symmetric (default + legacy
    fallback) and quorum plugins. ``symmetric_kem`` injects the
    deployment KEM into the symmetric plugin (the vault passes its
    configured KEM so ``EnvelopeVault(kem=...)`` keeps working)."""
    reg = PluginRegistry()
    sym = SymmetricPlugin(kem=symmetric_kem)
    reg.register(sym)
    reg.set_legacy(sym)
    reg.register(QuorumPlugin())
    return reg
