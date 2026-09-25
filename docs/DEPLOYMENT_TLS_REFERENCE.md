# Deployment TLS Reference — v1.0

**v1 does not terminate TLS in-repo.** The approval web console
(`gov/approval_web.py`) is stdlib `http.server.ThreadingHTTPServer`
with no `SSLContext` — there is no certificate handling, no cipher
configuration, and no TLS code path to audit. Per
`workstreams/architect/SHIP_PLAN.md` §2 ("The B5 cap ... deployment
hardening minimum"), the v1 TLS story is a **reverse-proxy deployment
reference**, not a built TLS stack. This doc is that reference.

> **Honest callout (matches `docs/KEY_CUSTODY_RUNBOOK.md` tone):**
> every config below is a reference pattern, not an exercised
> deployment. No TLS-fronted approval-web deployment has been run or
> tested in this program. Steps you have not verified in your own
> environment are yours to verify.

## Reference topology

```
                 TLS (443)                plaintext loopback
operator ──► reverse proxy ──► approval-web on 127.0.0.1:8734
             (Caddy or nginx)              (gov/approval_web.py)
```

- The proxy terminates TLS and is the only listener on a
  network-visible interface.
- The approval web binds **127.0.0.1 only** (the default `--host`).
  Any non-localhost bind prints a startup warning and is explicitly
  unsupported without TLS + real auth in front
  (`gov/approval_web.py` `--host` help). The session cookie and the
  startup token must never cross cleartext on the wire.
- The same pattern fronts any other HTTP surface you deploy (the
  approval web is the only one shipped in v1).

## Minimal Caddy example

```caddyfile
# Caddyfile — approval web at https://approve.example.com
approve.example.com {
    reverse_proxy 127.0.0.1:8734
}
```

Caddy fetches and renews a public CA (Let's Encrypt) certificate
automatically on first request. Operator-owned DNS pointing
`approve.example.com` at the host is required.

## Minimal nginx example

```nginx
server {
    listen 80;
    server_name approve.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl;
    server_name approve.example.com;

    ssl_certificate     /etc/nginx/certs/approve.example.com.crt;
    ssl_certificate_key /etc/nginx/certs/approve.example.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8734;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Certificate expectations

- **Operator-provided.** Bring your own certificates: public CA
  (preferred), ACME (Caddy), or your organization's internal CA.
- **No self-signed certificates in production.** Self-signed or
  privately-rooted certs without a managed trust store on operator
  browsers create click-through habits that defeat the whole point.
  Staging exceptions must be documented per-deployment, never silent.
- **Renewal is the operator's.** Caddy renews automatically; nginx
  needs certbot/systemd-timer or your CA's agent. Monitor expiry
  (`openssl x509 -enddate`) — an expired cert is a denial of service
  on the approval path.
- **Private keys:** 0600, owned by the proxy user, never in the repo
  or in a run dir.

## What is NOT covered (v2 or operator-owned)

- **mTLS between components.** Nothing in v1 does mutual TLS — not the
  proxy-to-app hop (loopback by construction), not Vault transit
  (token auth only, per the key-custody runbook), not anything else.
- **Certificate rotation automation.** No code watches or rotates
  certificates; renewal is the proxy's job per the examples above.
- **In-repo TLS.** Binding the approval web directly to a
  network interface with in-repo TLS is not a v1 configuration. Don't.
- **HSTS / security-header hardening** beyond what your proxy ships by
  default — operator's call.
- **Cookie hardening gap (known):** the v1 session cookie is
  `HttpOnly; SameSite=Strict` but carries **no `Secure` flag**
  (`gov/approval_web.py`; `workstreams/platform/DESIGN.md` §8 lists
  `Secure` + `__Host-` prefixes as pre-network-exposure hardening).
  With the loopback-only backend bind this is a residual, not a wire
  exposure — but if your topology ever changes, this is the first
  thing to fix.

## Verification checklist (operator-run, copy-paste)

```bash
BASE=https://approve.example.com

# 1. TLS handshake works, cert is valid and not expiring soon
curl -sSI "$BASE/login" | head -5
echo | openssl s_client -connect approve.example.com:443 -servername approve.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate

# 2. Plain HTTP does not serve the app (redirects to HTTPS or refused)
curl -sSI "http://approve.example.com/login" | head -3

# 3. The app itself is not reachable directly off-host
curl -sS -m 5 http://$(hostname -I | awk '{print $1}'):8734/login && \
  echo "FAIL: app exposed off loopback" || echo "OK: loopback-only"

# 4. Auth still required through the proxy (no anonymous queue)
curl -sSI "$BASE/" | head -3        # expect 302 to /login
curl -s -o /dev/null -w "%{http_code}\n" "$BASE/"   # expect 302

# 5. No TLS version below 1.2 negotiates
nmap --script ssl-enum-ciphers -p 443 approve.example.com 2>/dev/null | grep -E "TLSv1\.0|TLSv1\.1" \
  && echo "FAIL: old TLS enabled" || echo "OK: TLS 1.2+ only"
```

Checks 1–4 need only `curl`/`openssl`; check 5 needs `nmap`
(optional). **Run this checklist after every proxy or certificate
change** — it is the entire v1 TLS assurance story.

## Honest boundary

This reference cannot be verified by the repo's test suite — the proxy
is your infrastructure, not our code. TLS terminates at your proxy,
which means **your proxy's configuration is the security boundary**:
a misconfigured proxy (cleartext passthrough, expired cert,
proxy-to-app over a network interface) silently voids everything in
this doc. The checklist above is the minimum evidence the boundary
holds.
