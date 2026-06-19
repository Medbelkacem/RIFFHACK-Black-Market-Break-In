# Orbital Docking Handshake — arm64 Mach-O Reverse

- **Platform:** Riffhack CTF (Biterra) — team `ZKaMYBbs`
- **Author:** CL4Y
- **Artifact:** `orbital_docking_handshake` (Mach-O 64-bit ARM64, PIE, with stack canary, 34 856 bytes, **not stripped**)
- **Category:** Reverse — runtime-built buffer + computed alignment + XOR-decoded flag
- **Recovered values:**
  - **Docking phrase:** `dockhandsync`
  - **Alignment window:** `1108`
  - **Flag:** `bitctf{{0rb1t4l_d0ck1ng_r0ut1n3}}` *(literal double braces)*

## TL;DR

`main()` calls three helper functions in order:

1. **`_build_expected_phrase(out)`** — XORs 12 bytes at `0x100000a95` with the
   mask `((i*0x11) + 0x1b) & 0xff` and stores the result. Decodes to
   `dockhandsync`.
2. **`_compute_grid_offset(phrase)`** — `(Σ phrase[i]·(i+3)) mod 1000 + 200`.
   On `"dockhandsync"` that is `(10908 mod 1000) + 200 = 1108`.
3. Read user's phrase + numeric alignment, compare with `strcmp` /
   equality. On match, call **`_print_flag(phrase, alignment)`**, which
   XORs 33 bytes at `0x100000aa1` with `k = (i*5 + phrase[i%12] + alignment) & 0xff`.

Because every value the binary checks against is *also* derived from the
same 12 obfuscated bytes — and `_print_flag` is entirely deterministic —
the whole challenge collapses to ~10 lines of Python. No need to run the
binary, no emulator, no qemu-aarch64.

## Recon

`rabin2 -I` gives us the basics:

```
arch=arm   bits=64   bintype=mach0   pic=true   canary=true   stripped=false
```

Symbols visible because the binary isn't stripped (`rabin2 -i / -z`):

```
sym._main                  0x1000004b0
sym._build_expected_phrase 0x100000684
sym._compute_grid_offset   0x100000704
sym._compare_identity      0x100000784
sym._print_flag            0x1000007b8
sym._mask_for              0x1000008b0
```

Two constant blobs sit in `__TEXT.__const`:

```
0x100000a95  7f 43 5e 25 37 11 ef f6 d0 cd ab b5     ; "obfuscated phrase" — 12 bytes
0x100000aa1  da a1 b5 ad a4 a8 9b a0 df 88 96 df     ; "encoded flag"     — 33 bytes
             80 30 91 55 68 3a 7f 7c 1a 58 57 75
             42 70 4c 32 79 28 6b 2e 1a
```

The "lightest reversing path" hint that the challenge ships with is real —
all the work is in those two blobs plus three tiny functions.

## The three helpers, decoded

### `_mask_for(i)`

```
mul x8, x8, 0x11    ; * 17
add x8, x8, 0x1b    ; + 27
and w0, w8, 0xff    ; truncate to byte
```

→ `mask(i) = (17*i + 27) & 0xff`.

### `_build_expected_phrase(out)`

Loops `i = 0..11`, reads the byte at `0x100000a95 + i`, XORs with
`mask(i)`, writes to `out[i]`, then null-terminates at `out[12]`.

Plugging in `i = 0..11`:

```python
mask = [(17*i + 27) & 0xff for i in range(12)]
obf  = bytes.fromhex("7f435e253711eff6d0cdabb5")
phrase = bytes(b ^ m for b, m in zip(obf, mask))
# -> b'dockhandsync'
```

So the docking phrase is **`dockhandsync`**.

### `_compute_grid_offset(s)`

```python
total = 0
for i, c in enumerate(s):              # c is ldrb -> unsigned byte
    total = (total + c * (i + 3)) & 0xffffffff
return (total % 1000) + 200            # sdiv / mul / sub / +200
```

On `"dockhandsync"`:

```
d*3 + o*4 + c*5 + k*6 + h*7 + a*8 + n*9 + d*10 + s*11 + y*12 + n*13 + c*14
= 300 + 444 + 495 + 642 + 728 + 776 + 990 + 1000 + 1265 + 1452 + 1430 + 1386
= 10908
10908 mod 1000 = 908   →   908 + 200 = 1108
```

So the alignment window is **`1108`**.

### `_print_flag(phrase, alignment)`

```python
for i in range(33):
    k = (i*5 + phrase[i % 12] + alignment) & 0xff   # add x8, x8, w9, sxtw
    flag[i] = encoded[i] ^ k
```

Note the `mul x8, x18, 5` and `add x8, x8, w9, sxtw` — `w9` is
`phrase_char + alignment`, which is comfortably positive (phrase
characters are 0x61–0x79), so the `sxtw` is a no-op in practice and you
can read it as plain unsigned addition.

## One-shot solver

```python
encoded = bytes.fromhex(
    "daa1b5ada4a89ba0df8896df80309155683a7f7c1a58577542704c3279286b2e1a")
obf = bytes.fromhex("7f435e253711eff6d0cdabb5")

mask     = lambda i: ((i * 0x11) + 0x1b) & 0xff
phrase   = bytes(b ^ mask(i) for i, b in enumerate(obf))
align    = (sum(c * (i + 3) for i, c in enumerate(phrase)) % 1000) + 200
flag     = bytes(b ^ ((i * 5 + phrase[i % 12] + align) & 0xff)
                 for i, b in enumerate(encoded))

print(phrase.decode(), align, flag.decode(), sep="\n")
```

Output:

```
dockhandsync
1108
bitctf{{0rb1t4l_d0ck1ng_r0ut1n3}}
```

## Why "lightest reversing path"

The challenge text — *"the docking console hides its handshake phrase in a
runtime-built buffer behind one more computed alignment value. Use the
lightest reversing path"* — was honest:

- The binary is **not stripped**, so r2's `afl` hands you the function
  table for free.
- The two helpers are simple enough that you can transcribe them straight
  out of the disassembly into Python without writing a single test case.
- You don't have to **run** the binary at all. There's no live state, no
  side channel, no random source — every value is a pure function of the
  12 obfuscated bytes baked into `__TEXT.__const`. Static reverse beats
  emulation here.

If the binary *had* been stripped, the workflow would have been: r2's
`aaa` to discover the helpers from the call graph, name them by their
behaviour (`xor decode`, `multiply-accumulate`, `xor decode with index`)
and apply the same Python sketch.

## Take-aways

- For tiny reverse challenges, **transcribe, don't trace**. Once each
  helper fits on a Post-it, port it to Python and ignore the runtime.
- Watch for **byte order** when copy-pasting from hex viewers — the radare
  pretty-printer interleaves quad-word reads with ASCII gloss, which can
  flip adjacent bytes if you read off the wrong column. `p8 <N> @ <addr>`
  is the unambiguous form. I bit this on the first pass and got two
  garbage bytes in the middle of the flag until I noticed.
- `ldrsb` vs `ldrb` matters in general but not here: phrase characters are
  printable ASCII (< 128), so sign extension is a no-op.
