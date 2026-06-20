---
title: "Black Mirror: Memory Fragments"
ctf: "BitCTF"
date: 2026-06-20
category: forensics
difficulty: medium
flag_format: "bitctf{...}"
author: "CL4Y"
---

# Black Mirror: Memory Fragments

> A corrupted mobile backup is all that remains of a wiped conversation. Sort
> the real evidence from the noise, reconstruct what actually happened, and
> recover the hidden key.

## Summary

A Smithereen-style mobile backup ships with a SQLite messages DB (live +
recovered/WAL/freelist rows), three threads with explicit trust scores, and a
cache of 13 attachment chunks that must be reassembled per a manifest. Two
threads are red herrings (a phishing "quarantine" thread and an insurance
receipt thread); the only signed, high-trust thread leaks a base64 key in three
pieces — two appear in carved-out chat rows, and the final piece is hidden in
the `UserComment` EXIF tag of a reassembled JPEG.

Concatenating the three base64 fragments and decoding yields the flag.

## Recon

```text
$ tar -xf 1781949803_black-mirror-memory-fragments-backup.tar
$ tree black_mirror
black_mirror/
├── app_export/
│   ├── messages.db                       # SQLite 3
│   ├── metadata/
│   │   ├── attachment_index.json         # chunk -> attachment manifest
│   │   └── contacts.json                 # thread trust + integrity notes
│   └── cache/                            # 13 chunk files (ch_*.dat)
└── decoy/quarantine_note.txt
```

`contacts.json` is the first triage signal:

| thread   | sender         | bucket             | handshake | trust |
|----------|----------------|--------------------|-----------|-------|
| `t_river`| `river.k`      | `primary_inbox`    | signed    | 88    |
| `t_mara` | `mara.vey`     | `primary_inbox`    | signed    | 84    |
| `t_echo` | `echo.support` | `quarantine_restore`| unsigned | 14    |

It also notes: *"row table fragmented, cache names reissued during recovery"* —
so we should expect mislabelled chunks.

`decoy/quarantine_note.txt` adds: *"Recovered quarantine banner ... reassembles
to a different file type than the signed camera media in the primary inbox."*
That's the phishing payload calling itself out.

## Step 1 — Read the database (live + recovered rows)

```python
import sqlite3
con = sqlite3.connect('app_export/messages.db')
for tbl in ('messages', 'recovered_messages'):
    print(f"--- {tbl} ---")
    for r in con.execute(f"SELECT * FROM {tbl} ORDER BY thread_id, seq"):
        print(r)
```

The `t_echo` thread is a textbook smishing lure:

> *SECURITY NOTICE: your evidence locker was suspended. Restore access through
> the attached notice immediately.*
> *For your safety, ignore any other thread claiming to hold your key.*

`t_mara` is an alibi about a motorway insurance claim — Jaden himself flags it
as irrelevant: *"That is fine for insurance, nothing else."*

The juice is in `recovered_messages` on `t_river`, where deleted rows have been
rebuilt from WAL, freelist, and page-slack carves:

```
seq 6 river.k  : Use the draft plus the porch still comment.
                 Start the base64 key with Yml0Y3Rme3tzbTF0aDNy
seq 8 river.k  : Then continue MzNuX3RocjM0ZF9y before you check the
                 image metadata.
seq 9 river.k  : The draft attachment is real; the porch still metadata
                 holds the rest.
```

So the key is base64, in three parts: two carved chat fragments + a third we
must dig out of the porch still's EXIF `UserComment`.

## Step 2 — Reassemble and verify the attachments

```python
import json, hashlib, os
idx = json.load(open('app_export/metadata/attachment_index.json'))
os.makedirs('reassembled', exist_ok=True)
for a in idx['attachments']:
    data = b''.join(open(f'app_export/cache/{c}','rb').read() for c in a['chunk_files'])
    open(f"reassembled/{a['attachment_id']}.bin",'wb').write(data)
    ok = hashlib.sha1(data).hexdigest() == a['sha1']
    print(f"{a['attachment_id']:18s} {a['kind']:18s} sha1_ok={ok} size={len(data)}")
```

```
att_river_final    draft_note         sha1_ok=True  size=126
att_river_photo    porch_still        sha1_ok=False size=164   <-- failed but still valid JPEG
att_river_route    route_snapshot     sha1_ok=True  size=190
att_echo_lure      quarantine_banner  sha1_ok=True  size=78    <-- PNG (not JPEG); confirms decoy
att_mara_receipt   receipt_scan       sha1_ok=True  size=70
att_mara_stub      parking_stub       sha1_ok=True  size=140
```

Two useful observations:

1. `att_echo_lure` reassembles into a `PNG` (`89 50 4E 47 …`) — exactly the
   "different file type" the decoy note warned about. It's the phishing
   payload; discard.
2. `att_river_photo` fails the SHA1 check but still reassembles into a
   structurally valid JPEG (`FF D8 … FF D9`) carrying the camera EXIF block we
   were promised. `file(1)` mis-identified the tail chunk `ch_y4.dat` as an
   Apple QuickTime movie because its first bytes (`ear-wide;Frame=…`) coincide
   with a plausible QT atom — the integrity flag is the recovery tool's
   problem, not ours.

The draft note (`att_river_final`) confirms the procedure in plaintext:

```
Recovered draft note: combine both chat fragments first, then append the
porch still UserComment and base64-decode the result.
```

## Step 3 — Pull the EXIF UserComment from the porch still

```bash
$ strings -a app_export/cache/ch_y4.dat
ear-wide;Frame=porch-still;UserComment=M2Fzc2VtYmxlZF80Y3Jvc3NfZnJhZ21lbnRzfX0=;
```

## Step 4 — Concatenate and decode

```python
import base64
prefix1 = 'Yml0Y3Rme3tzbTF0aDNy'                              # river seq 6
prefix2 = 'MzNuX3RocjM0ZF9y'                                   # river seq 8
suffix  = 'M2Fzc2VtYmxlZF80Y3Jvc3NfZnJhZ21lbnRzfX0='           # porch_still EXIF
print(base64.b64decode(prefix1 + prefix2 + suffix).decode())
```

```
bitctf{{sm1th3r33n_thr34d_r3assembled_4cross_fragments}}
```

## Flag

```
bitctf{{sm1th3r33n_thr34d_r3assembled_4cross_fragments}}
```

## Lessons / takeaways

- Always rank evidence by *handshake state and trust score* before you start
  reassembling — the manifest gives you the answer to "which thread can I
  ignore" for free.
- `recovered_messages` (WAL / freelist / page-slack carves) is where wiped
  rows live. The live `messages` table only had Jaden's side of the river
  conversation; everything River sent was deleted and had to be carved.
- `file(1)` is a heuristic. A chunk that looks like a Mac container can just
  be the *middle* of a JPEG whose first bytes happen to alias a QT atom.
  Trust the magic bytes of the *reassembled* blob, not of the fragment.
- EXIF `UserComment` is a classic mobile-forensics dead drop. If a challenge
  says "the metadata holds the rest", strings or `exiftool` on the assembled
  image is almost always the answer.
