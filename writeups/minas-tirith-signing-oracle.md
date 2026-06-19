---
title: "Minas Tirith Signing Oracle — One Ring Nonce Collapse"
ctf: "bitCTF"
date: 2026-06-19
category: crypto
difficulty: medium
points: TBD
flag_format: "bitctf{...}"
author: "CL4Y"
---

# Minas Tirith Signing Oracle — One Ring Nonce Collapse

## Summary

An ECDSA (secp256k1) signing oracle returns each signature **plus the top
236 bits of the per-signature nonce** (`nonce_msb = k >> 20`). Only 20
bits per nonce are hidden — a textbook **Hidden Number Problem**. With
~25 signatures, a Boneh–Venkatesan LLL lattice recovers the private key,
and we forge a signature on the sealed decree `"one ring to rule them all"`.

## Solution

### Step 1: Probe the oracle

```text
GET  /pubkey   → curve=secp256k1, pub_x, pub_y, unknown_bits=20, protected_message="one ring to rule them all"
POST /sign     → {r, s, h, nonce_msb}   (nonce_msb = k >> 20)
POST /sign     for the protected message → "that decree is sealed"
POST /verify   → {"status":"accepted", "flag":"..."} on a valid forgery
```

`unknown_bits = 20` plus a per-signature `nonce_msb` is the bright neon
sign for HNP.

### Step 2: HNP lattice → recover `d` → forge the decree

For each signature `low_i = (s_i⁻¹·h_i + s_i⁻¹·r_i·d − nonce_msb_i·2²⁰) mod n`
with `0 ≤ low_i < 2²⁰`. Write `t_i = s_i⁻¹·r_i`, `u_i = s_i⁻¹·h_i − nonce_msb_i·2²⁰`
so `low_i ≡ t_i·d + u_i (mod n)`. Build the standard Boneh–Venkatesan
basis; after LLL one row encodes `(n·low_0, …, n·low_{m−1}, d·B, n·B)`.

```python
#!/usr/bin/env python3
import requests, hashlib
from Crypto.Util.number import inverse
from fpylll import IntegerMatrix, LLL
import ecdsa
from ecdsa import SigningKey, SECP256k1

BASE = "http://192.241.166.148:5000"
n  = 115792089237316195423570985008687907852837564279074904382605163141518161494337
UNK, B = 20, 1 << 20
PROTECTED = "one ring to rule them all"
m = 25

# 1. Collect signatures with leaked nonce_msb
sigs = [requests.post(f"{BASE}/sign", json={"message": f"req-{i}"}).json()
        for i in range(m)]

# 2. Build HNP equations
ts, us = [], []
for sg in sigs:
    r, s, h, nm = int(sg["r"]), int(sg["s"]), int(sg["h"]), int(sg["nonce_msb"])
    sinv = inverse(s, n)
    ts.append((sinv * r) % n)
    us.append((sinv * h - nm * B) % n)

# 3. Boneh-Venkatesan lattice (m+2 dim, scaled to keep all target coords ~ n*B)
M = IntegerMatrix(m + 2, m + 2)
for i in range(m):       M[i, i] = n * n
for j in range(m):
    M[m,   j] = n * ts[j]
    M[m+1, j] = n * us[j]
M[m,   m]   = B
M[m+1, m+1] = n * B
LLL.reduction(M)

# 4. Pull d from the row whose last coord is +/- n*B
d = None
for row in M:
    if abs(row[m+1]) == n * B:
        sign = 1 if row[m+1] > 0 else -1
        if (sign * row[m]) % B == 0:
            cand = ((sign * row[m]) // B) % n
            sg = sigs[0]
            r, s, h, nm = (int(sg[k]) for k in ("r","s","h","nonce_msb"))
            if (((h + r*cand) * inverse(s, n)) % n) >> UNK == nm:
                d = cand; break
print(f"d = {d}")

# 5. Forge with the recovered key and submit
digest = hashlib.sha256(PROTECTED.encode()).digest()
sig = SigningKey.from_secret_exponent(d, curve=SECP256k1).sign_digest(digest)
r_sig = int.from_bytes(sig[:32], "big")
s_sig = int.from_bytes(sig[32:], "big")
print(requests.post(f"{BASE}/verify",
      json={"message": PROTECTED, "r": str(r_sig), "s": str(s_sig)}).text)
# {"flag":"bitctf{{0n3_r1ng_n0nc3_70_ru13_7h3_curv3}}","status":"accepted"}
```

## Flag

```
bitctf{{0n3_r1ng_n0nc3_70_ru13_7h3_curv3}}
```
