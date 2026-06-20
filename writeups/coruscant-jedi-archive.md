---
title: "Coruscant Jedi Archive — Bleichenbacher e=3 Signature Forgery"
ctf: "bitCTF"
date: 2026-06-20
category: crypto
difficulty: medium
points: TBD
flag_format: "bitctf{...}"
author: "CL4Y"
---

# Coruscant Jedi Archive — Bleichenbacher e=3 Signature Forgery

## TL;DR

The Archive's `/issue` endpoint produces canonical PKCS#1 v1.5 SHA-256 RSA
signatures (`e = 3`, 1024-bit modulus) on transit passes. Its `/dock`
verifier is broken in two compounding ways:

1. It only accepts signatures whose recovered plaintext has **exactly one
   `0xFF`** padding byte: `00 01 FF 00 ASN.1 ...`. The canonical full-FF
   signatures emitted by `/issue` are rejected.
2. After the prefix, it only compares the **first 20 bytes** of the
   SHA-256 digest. The remaining 12 bytes — and everything after them —
   are not checked.

With `e = 3` and a controllable upper 43 bytes of `s³ mod n`, an integer
cube root produces a forged signature for any claims payload. Forging a
token whose claims contain the privileged routing tuple opens the vault.

## Reconnaissance

### Service shape

```
GET  /pubkey  → {"e": 3, "n": "1365…955437"}        (1024-bit n, e = 3)
POST /issue   {"callsign": "<name>"}                → {"token": "<msg>.<sig>"}
POST /dock    {"token": "<msg>.<sig>"}              → granted | rejected
```

The token format is `b64u(claims_json).b64u(sig_bytes)`.

### What `/issue` actually signs

`/issue` ignores every key in the request body except `callsign` and
unconditionally signs:

```json
{"callsign":"<name>","clearance":"transit","dock":"annulus-gate",
 "manifest":"civilian","role":"pilot","sector":"outer-rim"}
```

The signature decodes (via `s³ mod n`) to a textbook
EMSA-PKCS1-v1_5 SHA-256 block:

```
00 01 FF FF FF … FF 00 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
<32-byte SHA-256(claims_json)>
```

— full FF padding, full DigestInfo, full 32-byte hash. Standard PKCS#1
v1.5. So far so boring.

### What `/dock` actually accepts

Submitting the freshly-issued token back to `/dock` is rejected:

```
POST /dock {"token":"…the issued token…"} → 403 {"reason":"signature invalid"}
```

That mismatch is the whole challenge. The signer and the verifier
disagree about what a valid signature is. Probing systematically:

| forged prefix planted in `s³ mod n`           | result              |
|-----------------------------------------------|---------------------|
| `00 01 00 ASN.1 <hash> …`                     | signature invalid   |
| `00 01 FF 00 ASN.1 <hash> …`                  | **accepted**        |
| `00 01 FF FF FF FF FF FF FF FF 00 ASN.1 <hash> …` | signature invalid |

The verifier wants **exactly one** `0xFF` padding byte. The issuer
emits ~76, so canonical signatures bounce off.

A second sweep — keeping the prefix correct and zeroing successive
tail bytes of the hash — shows where the verifier actually stops
reading:

```
keep first 32 bytes of hash, zero rest → 200  ✓
keep first 24                          → 200  ✓
keep first 20                          → 200  ✓
keep first 16                          → 403  ✗
keep first 12                          → 403  ✗
```

Binary searching pins it at **20**. Only the first 20 bytes of the
SHA-256 digest are compared; the remaining 12 bytes (and the entire
tail of the modulus-sized buffer) are ignored.

### Why the forgery works arithmetically

We want `s³ mod n` to have the shape:

```
M = 00 01 FF 00 ASN1 <SHA256(claims)> <85 bytes of don't-care>
```

`M` is laid out so the controlled prefix sits in the high 43 bytes
of the 128-byte modulus. With `M` so close to 0, `M < n` and
`s³ < n` for any `s ≤ ⌈M^(1/3)⌉`, so the modular reduction never
fires — we are just taking an integer cube root.

Cube-rooting moves us up by at most `3·s²` ≈ `2^678` ≈ 85 bytes, so
the upper 43 bytes of `M` survive untouched. That is exactly the
region the verifier looks at: 4 prefix bytes + 19 ASN.1 + 20 hash
bytes = 43.

This is the canonical **Bleichenbacher '06 / BERserk** attack against
PKCS#1 v1.5 with small `e`, with the extra twist that the digest
comparison is shortened from 32 → 20 bytes (which would have
slightly tightened the attack window for `e = 65537` but here `e = 3`
makes both reductions free).

## Solution

### Forge

```python
#!/usr/bin/env python3
"""Coruscant Jedi Archive — e=3 PKCS#1 v1.5 forgery."""
import base64, hashlib, json, requests
from sympy import integer_nthroot

URL    = "http://64.225.16.190:5000"
ASN1   = bytes.fromhex("3031300d060960864801650304020105000420")
MODLEN = 128

n = int(requests.get(f"{URL}/pubkey").json()["n"])

def b64u(b):     return base64.urlsafe_b64encode(b).decode().rstrip("=")

def forge(msg):
    h    = hashlib.sha256(msg).digest()
    pref = b"\x00\x01\xff\x00" + ASN1 + h     # exactly ONE FF byte
    M    = pref + b"\x00" * (MODLEN - len(pref))
    target = int.from_bytes(M, "big")
    root, exact = integer_nthroot(target, 3)
    if not exact:
        root += 1                              # ceil — first 43 bytes survive
    return root.to_bytes(MODLEN, "big")

def dock(claims):
    j   = json.dumps(claims, separators=(",",":"), sort_keys=True).encode()
    tok = f"{b64u(j)}.{b64u(forge(j))}"
    return requests.post(f"{URL}/dock", json={"token": tok}).json()
```

### Probe the route table

`/issue` only ever produces the visitor tuple
`(annulus-gate, civilian, outer-rim, transit)`, which dispatches to
`"Docking granted for pilot class."`. Any single field flipped to a
non-canonical value comes back as `routing mismatch` — the verifier
runs the signature check first, then a 4-tuple lookup
`(dock, manifest, sector, clearance) → response`. `role` and
`callsign` are not part of the route key.

The vault tuple is in a separate row of that route table. With the
forgery in hand, walking the table is a brute force over the four
restricted fields:

```python
# (illustrative — full sweep details in solve.py)
for clearance, dock_, manifest, sector in itertools.product(CLR, DOCK, MAN, SEC):
    res = dock({"callsign":"luke", "clearance":clearance, "dock":dock_,
                "manifest":manifest, "role":"pilot", "sector":sector})
    if "vault" in res.get("message","").lower():
        print(res); break
```

The hit lands on `(<dock>, <manifest>, <sector>, <clearance>) =
(<TBD>, <TBD>, <TBD>, <TBD>)`, whose response carries the flag.

### Submit

```
POST /dock {"token":"<b64u(vault_claims)>.<b64u(forged_sig)>"}
→ 200 {"message":"Vault unlocked — flag: bitctf{<TBD>}","status":"accepted"}
```

## Flag

```
bitctf{<TBD>}
```

## Why the author's hint matters

> *"Compare what the service issues to what it actually accepts, and pay
> close attention to how much of an RSA signature really seems to matter."*

Two distinct loosenings — fewer FF bytes than RFC-compliant, fewer hash
bytes than the digest length — compound. Either alone would be
exploitable with `e = 3`; together they make the cube-root forge a
two-line Python script.

## Take-aways

- **Never roll a custom PKCS#1 v1.5 parser.** Use `cryptography`'s
  `padding.PKCS1v15()` (which uses constant-time, full-block comparison)
  or RSA-PSS. Hand-written verifiers leak in two recurring ways: lax
  padding (BERserk / Bleichenbacher '06) and short digest comparisons.
- **Avoid `e = 3` for signatures.** The textbook countermeasure to both
  bug families is `e = 65537`, which leaves no headroom for cube-rooted
  garbage to hide in.
- **For sigantures, hash comparison must be constant-time, full length.**
  Memcmp-style early-exit comparisons truncate to the first mismatched
  byte and create attacks even where the padding parser is correct.
