# Sailor Spectrum — Idol-Rehearsal Leak

- **Platform:** Riffhack CTF (Biterra) — team `ZKaMYBbs`
- **Author:** CL4Y
- **Artifact:** `1781863998_sailor_spectrum_evidence.zip` (5 201 bytes)
  - `luna_selfie.png` (5 743 bytes) — 640×360 RGB gradient PNG with a payload glued to the back
  - `moon_chat.pcap` (694 bytes) — chat plaintext leaked over UDP
- **Category:** Forensics — file-carving (appended-data stego) + clear-text PCAP for context
- **Flag:** `bitctf{{m00n_pr15m_p4yl04d}}` — yes, the **literal** doubled braces are part of the flag.

## TL;DR

A ZIP archive containing `diary_entry.txt` is concatenated to the end of
`luna_selfie.png`. The PNG renders normally (just a gradient), but a carving
tool — or anything that scans for the `PK\x03\x04` local-file-header sentinel
— recovers the trailing ZIP. The diary spells out the flag. The accompanying
PCAP is plain-text UDP between two characters (Luna and Artemis) describing
the exact technique they used; it doubles as a hint and a story beat, no
decryption needed.

## Recon

```
$ unzip -l 1781863998_sailor_spectrum_evidence.zip
   5743  ...  luna_selfie.png
    694  ...  moon_chat.pcap
```

PNG header is fine, but the file size (5 743) is larger than a real 640×360
PNG with one IDAT would normally be — already a smell. The first hint comes
from the PCAP, so peek there first.

## The PCAP — clear-text leak

```
$ strings moon_chat.pcap
DATA01:Artemis: That idol selfie felt too heavy. Did you stash
DATA02:the intel? Luna: Affirmative. Append the rehearsal diary
DATA03:after the MOONSHINE marker. Artemis: Got it. Carve after
DATA04:the sentinel, it's still a ZIP. Luna: Remember, the
DATA05:instructions live only in this capture. Delete after
DATA06:listening.
```

UDP payloads carry the conversation in the clear (the headers each have a
short prefix like `DATA01:` followed by raw text). The conversation tells us
the whole technique:

- payload type = **ZIP**
- placement = **after the MOONSHINE marker** in the PNG
- recovery = **carve after the sentinel**

## The PNG — appended ZIP

```
$ binwalk luna_selfie.png
DECIMAL    HEX     DESCRIPTION
0          0x0     PNG image, 640 x 360, 8-bit/color RGB, non-interlaced
41         0x29    Zlib compressed data, default compression
5416       0x1528  Zip archive data, ..., name: diary_entry.txt
5721       0x1659  End of Zip archive, footer length: 22
```

Exactly what the chat described — a ZIP starting at offset `0x1528` with a
single entry `diary_entry.txt`. `unzip` happily processes it despite the
preamble:

```
$ unzip -o luna_selfie.png -d extracted/
warning [luna_selfie.png]:  5416 extra bytes at beginning or within zipfile
  (attempting to process anyway)
  inflating: extracted/diary_entry.txt
```

`diary_entry.txt`:

```
Dear Luna,

I slipped the rehearsal diary behind the MOONSHINE marker in the selfie,
just like the idol manager asked. Anyone inspecting pixel data without
carving tools should only see a pretty gradient.

Flag: bitctf{{m00n_pr15m_p4yl04d}}

— Usagi
```

**`bitctf{{m00n_pr15m_p4yl04d}}`** — the literal-double-brace form is what the
flag scorer accepts. The single-brace variant was rejected, so this is a
challenge-author quirk rather than a Python-f-string artifact; treat the
braces as opaque flag content.

## Why "the gradient refuses to keep the secret quiet"

The PNG itself is a literal gradient — `IDAT` decodes to a smooth colour ramp;
LSB inspection of the pixel data yields nothing. The challenge wording
("the gradient refuses to keep the guardians' secret quiet") teases that
the *secret* is not in the gradient at all, but in what's *behind* it on disk
(i.e., past the `IEND` chunk). PNG parsers stop at `IEND` and discard the
trailing bytes, which is exactly what makes this a common amateur stego
technique — and exactly what `binwalk`/`unzip`/`PK\x03\x04`-scan defeats in
seconds.

## One-liner solution

```
$ unzip -p 1781863998_sailor_spectrum_evidence.zip luna_selfie.png \
    | python3 -c 'import sys,zipfile,io; d=sys.stdin.buffer.read(); \
        z=zipfile.ZipFile(io.BytesIO(d[d.find(b"PK\x03\x04"):])); \
        print(z.read(z.namelist()[0]).decode())'
```

## Take-aways

- Whenever a PNG/JPG seems oversized for its visible content, **scan for
  `PK\x03\x04`, `Rar!`, `7z\xbcaf\x27\x1c`, `ustar`** before reaching for LSB
  steg. Appended-data is dramatically more common in amateur stego than true
  pixel-domain hiding.
- `binwalk` is the right first tool here. `unzip` is forgiving enough to
  process an archive even with arbitrary preamble bytes — no manual carving
  needed.
- The PCAP doubled as both flavour and tutorial. Don't ignore plain-text
  payloads in a capture — `strings` and `tcp.payload` filters first, decrypt
  only when forced.
