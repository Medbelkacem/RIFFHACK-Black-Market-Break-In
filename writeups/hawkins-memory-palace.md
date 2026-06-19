---
title: "Hawkins Lab Memory Snapshot — Vecna's Memory Palace"
ctf: "bitCTF"
date: 2026-06-19
category: forensics
difficulty: medium
points: TBD
flag_format: "bitctf{...}"
author: "CL4Y"
---

# Hawkins Lab Memory Snapshot — Vecna's Memory Palace

## Summary

A "corrupted" memory capture interleaves six fragmented records with explicit
decoys (`cache_shadow`, `noise_*`) and themed misdirection (`DEC0Y_PIPE`).
The `analyst_note` confirms the metadata is intact — reassemble by `POS`,
hex-decode the concatenation, and the result is plain ASCII XOR'd with a
**repeating 7-byte key** that the snapshot's `radio_tag`/`tv_tag` ROT13s
spell out: `UNJX VAF` → `HAWK INS` → `HAWKINS`.

## Solution

### Step 1: Reassemble by POS, ignore the decoys

Each `memfrag[i]` decodes to `RID=X|POS=Y|SIZE=53|BLOB=<53 hex chars>`.
`cache_shadow[*]` (`deadcafebabe`, `AAAAA`) and the `noise_*` lines are
distractors. Concatenating the six BLOBs in `POS` order (6 × 53 = 318
hex chars) and hex-decoding gives 159 bytes of XOR'd text.

### Step 2: Recover the 7-byte key, decrypt, submit

Crib-dragging the plaintext guess `artifact_name` across the ciphertext
returns the key fragment `WKINSHAWKINSH` at offset 2 — exactly `HAWKINS`
cycling, with the radio_tag/tv_tag ROT13 puns (`UNJX`→`HAWK`,
`VAF`→`INS`, `clockface=13`) all pointing at the same key.

```python
#!/usr/bin/env python3
import base64, re, requests
BASE = "http://204.48.25.67:5000"

# 1. Pull the snapshot, parse memfrags, ignore cache_shadow / noise (decoys)
snap = requests.get(f"{BASE}/download/memory_snapshot.bin").text
frags = []
for line in snap.splitlines():
    m = re.match(r'memfrag\[\d+\]=(.+)', line)
    if m:
        kv = dict(p.split('=', 1) for p in
                  base64.b64decode(m.group(1) + '==').decode().split('|'))
        frags.append(kv)

# 2. Reassemble in POS order, hex-decode the full concatenation
frags.sort(key=lambda f: int(f['POS']))
raw = bytes.fromhex(''.join(f['BLOB'] for f in frags))   # 159 bytes

# 3. Repeating-XOR with HAWKINS (recovered via crib drag of "artifact_name")
plain = bytes(b ^ b'HAWKINS'[i % 7] for i, b in enumerate(raw))
print(plain.decode())
# {"artifact_name":"mindflayer_loader.dll","campaign":"starcourt_nightshift",
#  "sha1":"7f9c2ba4e88f827d616045507605853ed73b809a",
#  "unlock_token":"SCOOPS-AHOY-1985"}

# 4. Submit the three required fields
import json
rec = json.loads(plain)
r = requests.post(f"{BASE}/submit", json={
    "artifact_name": rec["artifact_name"],
    "sha1":          rec["sha1"],
    "unlock_token":  rec["unlock_token"],
})
print(r.text)
# {"flag":"bitctf{{v3cn45_m3m0ry_p4l4c3_br34ch}}","status":"validated"}
```

## Flag

```
bitctf{{v3cn45_m3m0ry_p4l4c3_br34ch}}
```
