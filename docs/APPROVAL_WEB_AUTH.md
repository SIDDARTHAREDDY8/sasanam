# Approval-Web Authentication — v1.0

The approval web console (`gov/approval_web.py`) is a **localhost
operator console with a single shared token**. That is the whole v1
auth mechanism, described here honestly. SSO/OIDC is explicitly OUT
of v1 (`workstreams/architect/SHIP_PLAN.md` §2 — "Full SSO/OIDC for
the approval console ... v1 documents the reverse-proxy +
external-IdP pattern").

## The v1 mechanism (as implemented)

1. **Startup token.** At startup the app generates
   `secrets.token_urlsafe(32)` and prints it to the operator's
   terminal (`gov/approval_web.py`; `ApprovalWebApp.__init__`).
   `--token` overrides it (for tests and operator-managed secrets).
2. **Login.** `POST /login` with the token mints a server-side
   session and returns a cookie:
   `session=<id>; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`
   (8h TTL). Sessions are **in-memory only** — no persistence, no
   cross-process sharing. Every route except `/login` requires a
   valid session.
3. **One operator principal.** There is no per-human identity. Every
   session decides as `web/human-operator` (`WEB_DECIDED_BY`), one
   shared audit label for all web decisions. The module docstring is
   explicit: "a session binds a single operator principal —
   `WEB_DECIDED_BY`". Anyone holding the token *is* the operator.
4. **CSRF.** Every decision form carries a per-session CSRF token
   compared with `hmac.compare_digest`; POSTs additionally require a
   same-origin `Origin`/`Referer` when present (defense in depth —
   the module's words, not a primary control).
5. **Logout.** `POST /logout` destroys the server-side session.
6. **Canonical decision path (auth-adjacent guarantee).** The POST
   handler reads only `decision` / `reason` / `csrf` from the form;
   tool, args, identity, and policy are re-read from the queue record
   and the decision goes through `ApprovalQueue.decide()` — the exact
   method the CLI uses. The web layer cannot approve anything the CLI
   could not.
7. **Fail closed.** Corrupt queue data or an unavailable queue lock
   turns list/decide into 500/503 refusals; replayed decisions hit
   the canonical pending-state check (409). Refusals are audit-logged
   (`web_auth_failure`, `web_csrf_failure`, `web_decision_refused`).

## Explicit limits of the v1 mechanism

- **Single shared credential.** Compromise of the token = full
  approval authority. There is no second factor, no per-human login,
  no way to tell two operators apart in the audit log.
- **No brute-force protection.** A wrong token is audit-logged
  (`web_auth_failure`) and refused — there is no rate limiting or
  lockout (`workstreams/platform/DESIGN.md` §8 lists rate-limiting as
  pre-network-exposure hardening). Over localhost this is a residual;
  over a network it is a real attack surface.
- **No SSO/OIDC/mTLS.** In v1, by written decision. The documented
  v1 pattern is the reverse proxy in front of the loopback console
  (see `docs/DEPLOYMENT_TLS_REFERENCE.md`); an external IdP can gate
  the proxy, but the console itself will still not know who you are.
- **Sessions die with the process.** Restarting the console invalidates
  all sessions and (unless `--token` is used) generates a new token.
- **Non-localhost binds warn, they do not refuse.** Binding beyond
  `127.0.0.1`/`localhost`/`::1` prints a startup WARNING and is
  "unsupported without TLS + real auth" — the console does not stop
  you. Do not rely on the warning as a control.
- **Cookie hardening gap.** The session cookie has `HttpOnly` and
  `SameSite=Strict` but **no `Secure` flag** (also called out in
  DESIGN.md §8). With the loopback-only bind behind a TLS proxy this
  is a residual; it must be fixed before any non-loopback topology.
- **Break-glass is CLI-only.** Break-glass records render read-only;
  POSTing a decision for one is refused (409 + audit). Emergency
  decisions stay on the CLI by design.

## Operator setup steps

1. Bind loopback only (the default):
   `python -m gov.approval_web --rundir <run_dir> --port 8734`
   (or let it pick `--latest`).
2. Read the token from the terminal where the server started.
   Treat it like a password: do not paste it into chat, tickets, or
   shared terminals. Terminal scrollback retains it — clear or lock
   the terminal when done.
3. Open `http://127.0.0.1:8734/`, log in at `/login`. Sessions last
   8h; log out (`POST /logout`, the button on every page) when done.
4. If the console must be reachable off-host, put it behind the
   reverse-proxy reference in `docs/DEPLOYMENT_TLS_REFERENCE.md`
   first — never expose the bare console to a network.
5. `--token` for operator-managed secrets: prefer injecting it from
   your secrets store into the process environment over typing it.
   Note it lands in the process argv (visible in `ps` to other local
   users) — on a shared host, prefer the generated token printed to a
   private terminal.
6. Restart = new token (unless `--token`). After any suspected
   token exposure, restart the console and re-login.

## Residual risks (v1, accepted)

| Risk | Why it stands |
|---|---|
| Token in terminal scrollback / logs | Printed at startup by design; operator hygiene only. |
| Shared credential, no attribution | One token, one `web/human-operator` label — two operators are indistinguishable in the audit log. |
| No login rate limiting | Residual over localhost; becomes real over any network exposure. |
| No session persistence | By design (in-memory); restart logs everyone out. |
| No `Secure` cookie flag | Residual under loopback bind; must be fixed before non-loopback. |
| No per-operator auth story | v1 scope decision; SSO/OIDC deferred to v2. |

## v2 upgrades (not v1)

Per `workstreams/architect/SHIP_PLAN.md` §2 and
`workstreams/platform/DESIGN.md` §8, the v2 auth story is: real
authentication (OIDC/mTLS client certs), per-operator identities with
`decided_by` bound to the authenticated principal, `Secure` +
`__Host-` cookie prefixes, login rate limiting, and session
persistence/sharing. None of this is designed or built in v1 — the
list above is the backlog, not a promise.

## Honest boundary

The repo's test suite verifies the mechanism (token check, session
expiry, CSRF refusal, fail-closed paths) — it cannot verify your
operational hygiene around the token. The v1 auth story's strength is
exactly one secret kept on one terminal. **If the token leaves that
terminal, you have no other control.** Operate accordingly.
