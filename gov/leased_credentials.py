"""Leased credentials — OpenBao-style lease lifecycle as a governance primitive.

ADAPTED DESIGN — credit: ``openbao/openbao`` lease lifecycle semantics
(open-source docs, pinned at upstream ``v2.6.0`` source commit
``03e3a243b6f07d17c60ce0a182adee7cf4c424eb``; wave-212 drift pass
2026-09-29: **v2.7.0 GA** (2026-09-23) confirmed current -- lease/renew/
revoke/wrapping APIs unchanged (additive only: revoke-self with wrapping
tokens). Sources read 2026-09-29).

Upstream concepts ADAPTED (behavioral, over the HTTP API — NO OpenBao
source copied, NO OpenBao code vendored; MPL-2.0 therefore does not
attach to this private repo):
  * dynamic secrets are "minted on demand"; every dynamic credential
    carries a lease/TTL;
  * leases are renewable (renewable flag, max TTL bound);
  * expiry triggers automatic backend cleanup/revocation;
  * explicit revocation for incident response;
  * revoking a parent cascades to child leases;
  * response wrapping returns a one-use token instead of the plaintext
    secret (interception/malfeasance detection, separate wrapping TTL).

SIBLING, not a mutation: this module does NOT touch ``gov/kms.py`` or
``gov/kms_vault.py``. Key custody (wrap/unwrap data keys) and
credential leasing (mint/revoke short-lived secrets) are different
primitives with different failure modes; the ``KmsProvider`` seam is
unchanged.

The core governance primitive here is the LEASE RECORD::

    {lease_id, credential_id, agent_id, run_id, credential_kind,
     source_path, issued_at, expires_at, renewable, max_ttl_s, state}

Operations (all fail closed): ``issue_lease``, ``renew_lease``,
``revoke_lease``, ``lease_status`` / ``lease_record``,
``deliver`` (sentinel-substituted secret for an authorized host),
``wrap_for_delivery`` / ``unwrap`` (one-use, host-bound response
wrapping).

FAIL-CLOSED CONTRACT
--------------------
* An unknown renewal result (transport error, HTTP 404, "lease not
  found", unparseable body) is treated as loss of custody: the lease
  is marked ``dead`` and every subsequent delivery refuses. A "valid"
  verdict is never cached across an unknown renewal.
* Expiry is evaluated on every ``deliver`` against the injected clock;
  an expired lease refuses with a ``use_refused`` audit event.
* ``lease_status(..., recheck=True)`` reconciles local state against
  the server (``GET /v1/sys/leases/lookup``); server-side revocation
  or loss of the lease invalidates the local record. The default
  ``recheck=False`` trusts local state plus expiry — mid-lease
  server-side revocation is only discovered at recheck/renew time;
  this is documented below as an honest residual, not hidden.
* Renewal past the max TTL is refused without mutating local expiry
  (a definite server refusal is definite — it does not mark the
  lease dead; an *unknown* result does).
* The transport returning any definite failure at issue time means
  nothing is issued and nothing is registered locally.

A LEASE IS A REVOCATION PROMISE, NOT AN EXFILTRATION BOUND
---------------------------------------------------------
Stated explicitly, on the record: lease expiry proves the credential
*should* be dead after the lease ends — it proves NOTHING about
whether the secret was copied while the lease was alive. Expiry is a
revocation promise the server can keep; it is not evidence of
non-exfiltration. Evidence bundles must record lease
issuance/renewal/revocation as *lifecycle events*, never as
"credential was safe" claims. The sentinel substitution layer is what
keeps the real secret out of the agent's hands; the lease is what
bounds how long a compromised copy remains *authorized*.

DELIVERY MODEL (sentinel substitution + response wrapping)
---------------------------------------------------------
Agents never see real secrets. ``issue_lease`` returns a
``fake_value_<uuid4>`` placeholder (same shape as
``gov/sentinel_substitution.py``; NO dependency on that module —
this module is self-contained so the lease seam stays separable,
and the placeholder shape is a shared design language). The manager
holds the real secret server-side (``self._secrets``, process memory
ONLY, never logged, never serialized — ``repr`` is redacted).

``deliver(lease_id, *, sentinel, dest_host)`` substitutes the secret
ONLY when: the sentinel is bound to this lease, the lease is live,
and the exact-FQDN host binding matches ``inject_hosts`` (lowercase,
trailing-dot stripped, NO wildcards — the same discipline as
``gov/sentinel_substitution.py``). Every delivery decision is
audited (no secrets, no token material).

Response wrapping (interception detection): ``wrap_for_delivery``
returns a one-use ``wrap_<uuid4>`` token with its own wrapping TTL
instead of the secret. ``unwrap`` burns the token on first use;
a second unwrap fails; an unwrap from a non-bound host fails AND
burns the token, auditing ``unwrap_intercepted`` — a token that was
read by someone else is detected as intercepted, exactly the
malfeasance-detection property upstream's wrapping provides.

LIFECYCLE EVENTS
----------------
Every operation appends a ``lease_event`` dict to the injected
``audit_log`` (any object with ``append(dict)`` — the hash-chained
audit log in production, a list in tests). Events carry
``event="lease_lifecycle"``, an ``action`` (issue/renew/renew_failed/
revoke/revoke_failed/use_refused/wrap/unwrap/unwrap_intercepted/
wrap_expired), lease/credential/agent/run ids, and a ``detail``
string. They NEVER carry real secrets, sentinel->secret bindings, or
the operator token.

HONEST RESIDUALS (prototype)
----------------------------
* Prototype rule (same as sentinel_substitution): secrets issued in
  tests must be DLP-clean synthetic values — asserted at
  ``issue_lease`` against ``gov.dlp.find_credential``. The F111
  credential_manifest owns the production version of this rule.
* No live OpenBao/Vault round trip from this network; the
  ``UrllibLeaseTransport`` and the API shapes (``POST /v1/sys/leases/
  renew``, ``PUT /v1/sys/leases/revoke``, ``GET /v1/sys/leases/lookup``,
  from public API docs) are unproven against a real server. The
  hermetic ``FakeLeaseTransport`` proves the *manager's* fail-closed
  logic, not wire interoperability.
* A lease bound to a spoofable ``agent_id`` is theater — issuance
  should require the same short-lived signed agent tokens the dex
  identity direction provides (memory, 2026-09-29).
* Token-revocation cascades can strand legitimate consumers mid-task;
  consumers must handle mid-lease invalidation as a first-class,
  fail-closed path (``deliver`` raising ``LeaseError``).
* Mid-lease server-side revocation is discovered only at
  ``recheck=True`` or renew time; ``deliver`` between checks trusts
  local state plus expiry. Operators that need tighter bounds should
  recheck on a shorter cadence than the lease TTL.

$0 spend. No network in tests. stdlib only.
"""

import abc
import base64
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

_log = logging.getLogger("gov.leased_credentials")

_UPSTREAM_PIN = ("openbao/openbao v2.6.0 commit "
                 "03e3a243b6f07d17c60ce0a182adee7cf4c424eb "
                 "(sources read 2026-09-29)")

_SENTINEL_PREFIX = "fake_value_"
_WRAP_PREFIX = "wrap_"
_UUID_HEX_RE = re.compile(r"^[0-9a-f]{32}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9.-]{0,251}"
                      r"[A-Za-z0-9])?$")
_ERROR_SUMMARY_LEN = 300


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class LeaseError(Exception):
    """Any fail-closed lease refusal: expiry, revocation, unknown state,
    host mismatch, wrapping violation, or misconfiguration."""


class LeaseTransportError(Exception):
    """I/O-level failure talking to the lease server (connection refused,
    timeout, TLS error, broken pipe). Messages must not carry request or
    response bodies."""


# ---------------------------------------------------------------------------
# Transport abstraction — the seam that keeps tests network-free.
# ---------------------------------------------------------------------------

class LeaseTransport(abc.ABC):
    """One injectable HTTP call against the lease-server API.

    ``request`` returns ``(status_code: int, response_body: bytes)``.
    HTTP error statuses are RETURNED (not raised) so the caller can map
    them to :class:`LeaseError`; only I/O failures raise
    :class:`LeaseTransportError`.
    """

    @abc.abstractmethod
    def request(self, method, path, headers, body):
        """``method``/``path`` are strings (``path`` starts with
        ``/v1/``), ``headers`` is a dict, ``body`` is bytes
        (``b""`` for GET)."""


class UrllibLeaseTransport(LeaseTransport):
    """Real stdlib transport (urllib). Production use only — never in
    unit tests. ``base_url`` looks like ``https://openbao.internal:8200``.
    Auth is the ``X-Vault-Token`` header."""

    def __init__(self, base_url, *, timeout_s=10, allow_http=False,
                 ca_bundle=None):
        if not base_url.startswith(("https://", "http://")):
            raise LeaseError("base_url must be an absolute http(s) URL")
        if base_url.startswith("http://") and not allow_http:
            raise LeaseError("http:// base_url requires allow_http=True")
        self._base = base_url.rstrip("/")
        self._timeout = timeout_s
        self._ca_bundle = ca_bundle

    def request(self, method, path, headers, body):
        url = self._base + path
        req = urllib.request.Request(url, data=body or b"", method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout,
                                        cafile=self._ca_bundle) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read()
            except Exception:
                return e.code, b""
        except Exception as e:  # network I/O failure: never the body
            raise LeaseTransportError("%s %s failed: %s"
                                      % (method, path, type(e).__name__))


class FakeLeaseTransport(LeaseTransport):
    """In-process lease server for hermetic tests. Implements the same
    API shapes as a real OpenBao/Vault lease server (public-docs
    shapes, from memory of the published API — no OpenBao code
    involved):

      POST /v1/leases/issue            {credential_id, agent_id,
                                        run_id, credential_kind,
                                        source_path, ttl_s, max_ttl_s,
                                        renewable}
        -> 200 {lease_id, lease_duration, renewable, max_lease_ttl}
      POST /v1/sys/leases/renew        {lease_id, increment}
        -> 200 {lease_id, lease_duration, renewable}
        -> 400 {errors: [...]} when unknown or past max TTL
      PUT  /v1/sys/leases/revoke       {lease_id}
        -> 200 {} (idempotent; marks revoked, does not delete)
      GET  /v1/sys/leases/lookup?lease_id=...
        -> 200 {lease_id, state, ...} / 404 {errors: ["lease not found"]}

    ``down=True`` simulates a dead server: every call raises
    :class:`LeaseTransportError`. ``forget_lease(lease_id)`` simulates
    out-of-band loss of the lease (renewal state becomes UNKNOWN).
    """

    def __init__(self, *, down=False, now=None):
        self.down = down
        self._now = now or time.time
        self._leases = {}  # lease_id -> server record
        self.requests = []

    def _check(self):
        if self.down:
            raise LeaseTransportError("fake transport is down")

    def forget_lease(self, lease_id):
        """Test hook: lose the lease out-of-band (unknown state)."""
        self._leases.pop(lease_id, None)

    def server_lease_ids(self):
        return list(self._leases)

    def request(self, method, path, headers, body):
        self._check()
        self.requests.append((method, path))
        if path == "/v1/leases/issue" and method == "POST":
            return self._issue(body)
        if path == "/v1/sys/leases/renew" and method == "POST":
            return self._renew(body)
        if path == "/v1/sys/leases/revoke" and method == "PUT":
            return self._revoke(body)
        if path.startswith("/v1/sys/leases/lookup") and method == "GET":
            return self._lookup(path)
        return 404, json.dumps({"errors": ["unknown endpoint"]}).encode()

    def _issue(self, body):
        try:
            req = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            return 400, json.dumps({"errors": ["unparseable body"]}).encode()
        ttl = max(1, int(req.get("ttl_s", 3600)))
        max_ttl = int(req.get("max_ttl_s", ttl))
        if max_ttl < ttl:
            max_ttl = ttl
        lease_id = "lc_lease_" + uuid.uuid4().hex
        now = self._now()
        self._leases[lease_id] = {
            "lease_id": lease_id, "issued_at": now,
            "lease_duration": ttl, "max_ttl": max_ttl,
            "renewable": bool(req.get("renewable", True)),
            "state": "active",
        }
        return 200, json.dumps({
            "lease_id": lease_id, "lease_duration": ttl,
            "renewable": bool(req.get("renewable", True)),
            "max_lease_ttl": max_ttl,
        }).encode()

    def _renew(self, body):
        try:
            req = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            return 400, json.dumps({"errors": ["unparseable body"]}).encode()
        lease_id = req.get("lease_id")
        rec = self._leases.get(lease_id)
        if rec is None:
            return 400, json.dumps(
                {"errors": ["lease not found"]}).encode()
        if rec["state"] != "active":
            return 400, json.dumps(
                {"errors": ["lease is %s" % rec["state"]]}).encode()
        if not rec["renewable"]:
            return 400, json.dumps(
                {"errors": ["lease is not renewable"]}).encode()
        now = self._now()
        elapsed = now - rec["issued_at"]
        increment = req.get("increment")
        increment = (rec["lease_duration"] if increment is None
                     else max(1, int(increment)))
        # Definite refusal: the requested extension would exceed the
        # max TTL bound from issuance.
        if elapsed + increment >= rec["max_ttl"]:
            return 400, json.dumps(
                {"errors": ["renewal increment exceeds max lease TTL"]},
            ).encode()
        new_duration = increment
        rec["issued_at"] = now
        rec["lease_duration"] = new_duration
        return 200, json.dumps({
            "lease_id": lease_id, "lease_duration": new_duration,
            "renewable": True,
        }).encode()

    def _revoke(self, body):
        try:
            req = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            return 400, json.dumps({"errors": ["unparseable body"]}).encode()
        lease_id = req.get("lease_id")
        rec = self._leases.get(lease_id)
        if rec is not None:
            rec["state"] = "revoked"
        return 200, b"{}"

    def _lookup(self, path):
        qs = urllib.parse.urlparse(path).query
        lease_id = urllib.parse.parse_qs(qs).get("lease_id", [None])[0]
        rec = self._leases.get(lease_id)
        if rec is None:
            return 404, json.dumps(
                {"errors": ["lease not found"]}).encode()
        return 200, json.dumps({
            "lease_id": lease_id, "state": rec["state"],
            "lease_duration": rec["lease_duration"],
            "issued_at": rec["issued_at"],
        }).encode()


# ---------------------------------------------------------------------------
# Lease record
# ---------------------------------------------------------------------------

class LeaseRecord(object):
    """Client-side view of an issued lease. Immutable after issue
    except for renew-driven ``expires_at`` and terminal ``state``
    transitions (active -> revoked/dead). ``state`` transitions are
    monotonic: once revoked or dead, a record never returns to
    active."""

    __slots__ = ("lease_id", "credential_id", "agent_id", "run_id",
                 "credential_kind", "source_path", "issued_at",
                 "expires_at", "renewable", "max_ttl_s", "state")

    def __init__(self, *, lease_id, credential_id, agent_id, run_id,
                 credential_kind, source_path, issued_at, expires_at,
                 renewable, max_ttl_s):
        self.lease_id = lease_id
        self.credential_id = credential_id
        self.agent_id = agent_id
        self.run_id = run_id
        self.credential_kind = credential_kind
        self.source_path = source_path
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.renewable = renewable
        self.max_ttl_s = max_ttl_s
        self.state = "active"

    def to_dict(self):
        # No secrets anywhere near a lease record; the secret lives
        # only in the manager's process-memory binding.
        return {
            "lease_id": self.lease_id, "credential_id": self.credential_id,
            "agent_id": self.agent_id, "run_id": self.run_id,
            "credential_kind": self.credential_kind,
            "source_path": self.source_path, "issued_at": self.issued_at,
            "expires_at": self.expires_at, "renewable": self.renewable,
            "max_ttl_s": self.max_ttl_s, "state": self.state,
        }

    def __repr__(self):
        return ("LeaseRecord(lease_id=%r, credential_id=%r, state=%r, "
                "expires_at=%r)" % (self.lease_id, self.credential_id,
                                    self.state, self.expires_at))


# ---------------------------------------------------------------------------
# Audit event constructor
# ---------------------------------------------------------------------------

def lease_event(*, action, lease_id, credential_id, agent_id, run_id,
                detail=""):
    """Build the ``lease_lifecycle`` audit event dict.

    ``action`` is one of: issue, renew, renew_failed, revoke,
    revoke_failed, use_refused, wrap, unwrap, unwrap_intercepted,
    wrap_expired. Never carries secrets, bindings, or the operator
    token.
    """
    return {
        "event": "lease_lifecycle",
        "action": action,
        "lease_id": lease_id,
        "credential_id": credential_id,
        "agent_id": agent_id,
        "run_id": run_id,
        "detail": str(detail)[:_ERROR_SUMMARY_LEN],
        "upstream_pin": _UPSTREAM_PIN,
    }


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class LeasedCredentialManager(object):
    """Operator-side lease manager. The lease server is reached through
    the injectable ``transport``; the manager holds the real secrets
    in process memory ONLY (``self._secrets`` — never logged, never
    serialized; ``repr`` is redacted).

    ``audit_log`` is any object with ``append(dict)`` (the
    hash-chained audit log in production, a list in tests).
    ``now`` is the clock (epoch seconds); inject it in tests.
    ``token`` is the operator credential for the lease server —
    sent in the ``X-Vault-Token`` header, NEVER logged. Exactly one of
    ``token`` and ``credential_provider`` (a
    :class:`gov.spiffe_credential_provider.CredentialProvider` supplying
    short-lived tokens) must be given -- never both, never neither.
    """

    def __init__(self, transport, *, token=None, credential_provider=None,
                 audit_log=None, now=None, wrapping_ttl_s=60):
        if transport is None:
            raise LeaseError("a transport is required")
        if (token is None) == (credential_provider is None):
            raise LeaseError(
                "exactly one of token / credential_provider is required")
        if token is not None and not token:
            raise LeaseError("an operator token is required")
        if credential_provider is not None and not hasattr(
                credential_provider, "current_token"):
            raise LeaseError(
                "credential_provider must expose current_token(), got %r"
                % (type(credential_provider).__name__,))
        self.transport = transport
        self._token = token
        self._credential_provider = credential_provider
        self._audit_log = audit_log
        self._now = now or time.time
        self._wrapping_ttl_s = max(1, int(wrapping_ttl_s))
        self._leases = {}    # lease_id -> LeaseRecord
        self._sentinels = {}  # sentinel -> dict(lease_id, real, hosts)
        self._secrets = {}   # lease_id -> real secret (memory only)
        self._wraps = {}     # wrap token -> dict(sentinel, dest, deadline,
                             #                   burned)

    def __repr__(self):
        return ("LeasedCredentialManager(leases=%d, wraps=%d, "
                "secrets=REDACTED)" % (len(self._leases),
                                       len(self._wraps)))

    def _auth_headers(self):
        """The operator auth header for one request. A static token is
        used as-is; a credential provider is asked for a fresh
        short-lived token per request.

        Note: a credential-provider refusal propagates as
        :class:`gov.kms.KmsError` (``SpiffeError``), not
        :class:`LeaseError` -- it is an authentication failure, not a
        lease failure, and existing ``except KmsError`` fail-closed
        handlers catch it with the machine ``code`` intact."""
        if self._credential_provider is not None:
            token = self._credential_provider.current_token()
        else:
            token = self._token
        return {"X-Vault-Token": token}

    # ------------------------------------------------------------- audit

    def _audit(self, action, rec, detail=""):
        if self._audit_log is None:
            return
        self._audit_log.append(lease_event(
            action=action, lease_id=rec.lease_id,
            credential_id=rec.credential_id, agent_id=rec.agent_id,
            run_id=rec.run_id, detail=detail))

    # ------------------------------------------------------------- issue

    def issue_lease(self, *, credential_id, agent_id, run_id,
                    credential_kind, source_path, inject_hosts,
                    ttl_s=3600, max_ttl_s=None, renewable=True,
                    secret):
        """Issue a lease and register its secret. Returns
        ``(LeaseRecord, sentinel)`` — the AGENT sees only the sentinel
        (``fake_value_<uuid4>``); the secret is held server-side.

        Fail-closed: any transport failure means nothing is issued and
        nothing is registered locally.
        """
        for name, val in (("credential_id", credential_id),
                          ("agent_id", agent_id),
                          ("run_id", run_id),
                          ("credential_kind", credential_kind),
                          ("source_path", source_path)):
            if not isinstance(val, str) or not val.strip():
                raise LeaseError("%s must be a non-empty string" % name)
        hosts = self._normalize_hosts(inject_hosts)
        if max_ttl_s is None:
            max_ttl_s = max(1, int(ttl_s))
        ttl_s = max(1, int(ttl_s))
        max_ttl_s = max(ttl_s, int(max_ttl_s))
        if secret is None:
            raise LeaseError("a secret is required at issue time")
        # Prototype rule: only DLP-clean synthetic values (mirrors
        # gov/sentinel_substitution.py; F111 owns the production rule).
        try:
            from . import dlp as _dlp
            if isinstance(secret, str) and \
                    _dlp.find_credential(secret) is not None:
                raise LeaseError(
                    "secret for %r is credential-shaped: refused "
                    "(prototype rule — provision DLP-clean synthetic "
                    "values; F111 owns the production version)"
                    % (credential_id,))
        except ImportError:
            pass

        req = {"credential_id": credential_id, "agent_id": agent_id,
               "run_id": run_id, "credential_kind": credential_kind,
               "source_path": source_path, "ttl_s": ttl_s,
               "max_ttl_s": max_ttl_s, "renewable": bool(renewable)}
        try:
            status, body = self.transport.request(
                "POST", "/v1/leases/issue",
                self._auth_headers(),
                json.dumps(req).encode("utf-8"))
        except LeaseTransportError as e:
            raise LeaseError("issue failed: lease server unreachable: %s"
                             % (e,))
        if status != 200:
            raise LeaseError("issue refused by lease server (status %d): %s"
                             % (status, _safe_summary(body)))
        try:
            resp = json.loads(body.decode("utf-8"))
            lease_id = resp["lease_id"]
            duration = int(resp["lease_duration"])
        except (ValueError, KeyError, TypeError) as e:
            raise LeaseError("issue returned an unparseable body: %s" % (e,))
        if not isinstance(lease_id, str) or not lease_id:
            raise LeaseError("issue returned an empty lease id")

        now = self._now()
        rec = LeaseRecord(
            lease_id=lease_id, credential_id=credential_id,
            agent_id=agent_id, run_id=run_id,
            credential_kind=credential_kind, source_path=source_path,
            issued_at=now, expires_at=now + duration,
            renewable=bool(resp.get("renewable", renewable)),
            max_ttl_s=max_ttl_s)
        sentinel = _SENTINEL_PREFIX + uuid.uuid4().hex
        self._leases[lease_id] = rec
        self._secrets[lease_id] = secret
        self._sentinels[sentinel] = {"lease_id": lease_id,
                                     "hosts": hosts,
                                     "credential_id": credential_id}
        self._audit("issue", rec,
                    "ttl=%ds max_ttl=%ds hosts=%d" % (duration, max_ttl_s,
                                                      len(hosts)))
        return rec, sentinel

    # ------------------------------------------------------------- renew

    def renew_lease(self, lease_id, *, increment_s=None):
        """Renew a lease. A definite server refusal (past max TTL,
        non-renewable) raises :class:`LeaseError` WITHOUT killing the
        lease — the definite answer is that the lease continues until
        its current expiry. An UNKNOWN result (transport error, 404,
        "not found", unparseable body) marks the lease ``dead`` and
        raises :class:`LeaseError` — never cache "valid" across an
        unknown renewal."""
        rec = self._get(lease_id)
        if increment_s is not None:
            increment_s = max(1, int(increment_s))
        try:
            status, body = self.transport.request(
                "POST", "/v1/sys/leases/renew",
                self._auth_headers(),
                json.dumps({"lease_id": lease_id,
                            "increment": increment_s}).encode("utf-8"))
        except LeaseTransportError as e:
            return self._renew_unknown(rec, "transport error: %s" % (e,))
        if status == 404:
            return self._renew_unknown(rec, "server returned 404")
        try:
            resp = json.loads(body.decode("utf-8"))
        except ValueError:
            return self._renew_unknown(rec, "unparseable renew body")
        if status != 200:
            errors = " ".join(resp.get("errors", [])) \
                if isinstance(resp, dict) else ""
            if "not found" in errors.lower():
                return self._renew_unknown(rec, "server: %s" % errors)
            # Definite refusal (e.g. past max TTL): refuse the
            # increment, keep the lease alive until current expiry.
            self._audit("renew_failed", rec, "definite: %s" % errors)
            raise LeaseError("renew refused by lease server: %s" % (errors,))
        try:
            duration = int(resp["lease_duration"])
        except (ValueError, KeyError, TypeError) as e:
            return self._renew_unknown(rec, "unparseable renew body: %s"
                                       % (e,))
        rec.expires_at = self._now() + duration
        self._audit("renew", rec, "new ttl=%ds" % duration)
        return rec

    def _renew_unknown(self, rec, detail):
        # UNKNOWN renewal state: loss of custody. Mark dead, audit
        # loudly, fail closed. The lease never recovers.
        rec.state = "dead"
        self._audit("renew_failed", rec,
                    "UNKNOWN renewal state (%s): lease marked dead, "
                    "fail-closed" % detail)
        raise LeaseError("renewal status unknown (%s): lease %r marked "
                         "dead — fail-closed" % (detail, rec.lease_id))

    # ------------------------------------------------------------ revoke

    def revoke_lease(self, lease_id, *, reason):
        """Explicit revocation (incident response). A failed revocation
        (transport down, unknown response) still marks the lease
        ``dead`` locally — the server state is unknown, so the safe
        direction is to deny all future delivery — audits
        ``revoke_failed`` loudly, and raises."""
        rec = self._get(lease_id)
        if not isinstance(reason, str) or not reason.strip():
            raise LeaseError("a revocation reason is required")
        try:
            status, body = self.transport.request(
                "PUT", "/v1/sys/leases/revoke",
                self._auth_headers(),
                json.dumps({"lease_id": lease_id}).encode("utf-8"))
        except LeaseTransportError as e:
            rec.state = "dead"
            self._audit("revoke_failed", rec,
                        "transport error: %s — state unknown, "
                        "marked dead fail-closed" % (e,))
            raise LeaseError("revocation of %r failed (%s): state unknown, "
                             "marked dead" % (lease_id, e))
        if status != 200:
            rec.state = "dead"
            detail = _safe_summary(body)
            self._audit("revoke_failed", rec,
                        "status %d: %s — marked dead fail-closed"
                        % (status, detail))
            raise LeaseError("revocation of %r refused (status %d): "
                             "marked dead" % (lease_id, status))
        rec.state = "revoked"
        self._audit("revoke", rec, "reason: %s" % (reason,))
        return rec

    # ------------------------------------------------------------ status

    def _get(self, lease_id):
        rec = self._leases.get(lease_id)
        if rec is None:
            raise LeaseError("unknown lease %r" % (lease_id,))
        return rec

    def lease_record(self, lease_id):
        """Return the local :class:`LeaseRecord` (raises on unknown)."""
        return self._get(lease_id)

    def lease_status(self, lease_id, *, recheck=False):
        """Return "active", "revoked", "expired", or "dead".

        ``recheck=True`` reconciles against the server lookup and
        mutates local state to match: a server-side revocation or a
        server-side unknown lease invalidates the local record (never
        cache "valid" across a recheck).
        """
        rec = self._get(lease_id)
        if rec.state in ("revoked", "dead"):
            return rec.state
        if recheck:
            rec.state = self._reconcile(rec)
            if rec.state in ("revoked", "dead"):
                return rec.state
        if self._now() >= rec.expires_at:
            return "expired"
        return "active"

    def _reconcile(self, rec):
        try:
            status, body = self.transport.request(
                "GET", "/v1/sys/leases/lookup?lease_id=" +
                urllib.parse.quote(rec.lease_id, safe=""),
                self._auth_headers(), b"")
        except LeaseTransportError:
            return "dead"  # unknown server state: fail closed
        if status == 404:
            return "dead"  # server lost the lease: unknown -> dead
        if status != 200:
            return "dead"
        try:
            resp = json.loads(body.decode("utf-8"))
        except ValueError:
            return "dead"
        state = resp.get("state", "unknown")
        if state == "revoked":
            self._audit("revoke", rec, "discovered at server recheck")
            return "revoked"
        if state != "active":
            return "dead"
        return "active"

    def issued_lease_ids(self):
        return list(self._leases)

    # ------------------------------------------------------------ guard

    def _guard_active(self, rec):
        st = self.lease_status(rec.lease_id)
        if st != "active":
            self._audit("use_refused", rec, "lease is %s" % st)
            raise LeaseError("credential use refused: lease %r is %s"
                             % (rec.lease_id, st))
        return True

    # ------------------------------------------------------------ delivery

    def deliver(self, lease_id, *, sentinel, dest_host):
        """Substitute the real secret for an authorized host — the
        lease-bound analogue of sentinel substitution. Fail-closed
        unless: the sentinel is bound to THIS lease, the lease is
        live, and the host binding matches. Every decision is
        audited."""
        rec = self._get(lease_id)
        bind = self._sentinels.get(sentinel)
        if bind is None or bind["lease_id"] != lease_id:
            self._audit("use_refused", rec, "unknown/mismatched sentinel")
            raise LeaseError("credential use refused: sentinel not bound "
                             "to lease %r" % (lease_id,))
        self._guard_active(rec)
        host = self._normalize_host(dest_host)
        if host not in bind["hosts"]:
            self._audit("use_refused", rec,
                        "host %r not in inject_hosts" % (dest_host,))
            raise LeaseError("credential use refused: %r is not an "
                             "authorized host for credential %r"
                             % (dest_host, rec.credential_id))
        return self._secrets[lease_id]

    # ---------------------------------------------------- response wrap

    def wrap_for_delivery(self, lease_id, *, sentinel, dest_host):
        """Return a one-use ``wrap_<uuid4>`` token for the credential
        instead of the secret itself. The token is host-bound to
        ``dest_host`` and expires after the wrapping TTL. Audits
        ``wrap``."""
        rec = self._get(lease_id)
        bind = self._sentinels.get(sentinel)
        if bind is None or bind["lease_id"] != lease_id:
            self._audit("use_refused", rec, "unknown/mismatched sentinel")
            raise LeaseError("wrap refused: sentinel not bound to lease %r"
                             % (lease_id,))
        self._guard_active(rec)
        host = self._normalize_host(dest_host)
        if host not in bind["hosts"]:
            self._audit("use_refused", rec,
                        "wrap to unauthorized host %r" % (dest_host,))
            raise LeaseError("wrap refused: %r is not an authorized host"
                             % (dest_host,))
        token = _WRAP_PREFIX + uuid.uuid4().hex
        self._wraps[token] = {
            "sentinel": sentinel, "dest": host,
            "deadline": self._now() + self._wrapping_ttl_s,
            "burned": False,
        }
        self._audit("wrap", rec, "one-use token issued for %r" % (host,))
        return token

    def unwrap(self, wrap_token, *, dest_host):
        """Redeem a wrap token exactly once. The token is burned on
        first use; a second use fails; use from a different host fails
        AND burns the token (interception detection — the legitimate
        recipient will find their token already burned). The lease is
        re-guarded at unwrap time: a lease that died between wrap and
        unwrap refuses."""
        entry = self._wraps.get(wrap_token)
        if entry is None or entry["burned"]:
            raise LeaseError("unwrap refused: unknown or burned token")
        host = self._normalize_host(dest_host)
        entry["burned"] = True
        rec = self._get_by_sentinel(entry["sentinel"])
        if host != entry["dest"]:
            self._audit("unwrap_intercepted", rec,
                        "token presented from %r, bound to %r — "
                        "possible interception; token burned" % (dest_host,
                                                                entry["dest"]))
            raise LeaseError("unwrap refused: token is bound to a "
                             "different host — burned as intercepted")
        if self._now() > entry["deadline"]:
            self._audit("wrap_expired", rec, "token expired before unwrap")
            raise LeaseError("unwrap refused: wrap token expired")
        bind = self._sentinels.get(entry["sentinel"])
        if bind is None:
            self._audit("use_refused", rec, "sentinel unbound at unwrap")
            raise LeaseError("unwrap refused: sentinel unbound")
        self._guard_active(rec)
        self._audit("unwrap", rec, "one-use token redeemed for %r"
                    % (host,))
        return self._secrets[rec.lease_id]

    def _get_by_sentinel(self, sentinel):
        bind = self._sentinels.get(sentinel)
        if bind is None:
            raise LeaseError("unknown sentinel")
        return self._get(bind["lease_id"])

    # ------------------------------------------------------------ hosts

    @staticmethod
    def _normalize_host(host):
        if not isinstance(host, str) or not host.strip():
            raise LeaseError("dest_host must be a non-empty string")
        norm = host.strip().lower().rstrip(".")
        if not _HOST_RE.match(norm):
            raise LeaseError("dest_host %r is not a valid FQDN" % (host,))
        return norm

    def _normalize_hosts(self, inject_hosts):
        if not inject_hosts:
            raise LeaseError("inject_hosts must be non-empty")
        if not isinstance(inject_hosts, (list, tuple)):
            raise LeaseError("inject_hosts must be a list")
        out = set()
        for h in inject_hosts:
            out.add(self._normalize_host(h))
        return sorted(out)


def _safe_summary(body):
    try:
        txt = body.decode("utf-8", "replace")
    except Exception:
        return "<undecodable>"
    return txt[:_ERROR_SUMMARY_LEN]


__all__ = [
    "LeaseError",
    "LeaseTransportError",
    "LeaseTransport",
    "UrllibLeaseTransport",
    "FakeLeaseTransport",
    "LeaseRecord",
    "lease_event",
    "LeasedCredentialManager",
]
