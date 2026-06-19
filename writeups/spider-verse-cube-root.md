# Spider-Verse Cube-Root — Small-`e` RSA Without Padding

- **Platform:** Riffhack CTF (Biterra) — team `ZKaMYBbs`
- **Author:** CL4Y
- **Target:** `https://world-e247c8636e6e4494a2c104ac79-qaxup.ondigitalocean.app/broadcast`
- **Category:** Crypto — RSA with `e=3` and unpadded plaintext (Coppersmith-trivial / textbook)
- **Flag:** `bitctf{{sp1d3r_cub3d_br0adca57}}`

## TL;DR

`/broadcast` returns the same RSA triple `(n, e=3, c)` on every fetch.
The challenge body literally tells you the attack:

> *"The multiversal antenna only trusts perfect cubes."*

When `e = 3` and the message `m` is short enough that `m³ < n`, the modular
reduction never fires — the "ciphertext" is just the *real* integer cube of
the plaintext. Take the integer cube root and read the message off.

## Recon

```
$ curl -s https://.../broadcast
{
  "ciphertext": "16061189851687597120996926301104657943371254567888...",
  "e": 3,
  "lore": "The multiversal antenna only trusts perfect cubes.",
  "n": "13729576627505561553465122037700891800302066704745712330..."
}
```

- `e = 3` — small public exponent.
- Same response on every request (deterministic — no padding/blinding).
- `n` is ~1024 bits, so any plaintext with `bit_length(m) ≤ ~341` keeps
  `m³ < n`.

## The attack

When `e = 3` and `m³ < n`, encryption is the identity in the integers:

```
c = m^3 mod n = m^3   (because m^3 < n)
```

So the decryption is just an integer cube root, no factoring needed.

```python
import gmpy2
c = 16061189851687597120996926301104657943371254567888...
m, exact = gmpy2.iroot(c, 3)        # integer cube root
assert exact                         # confirms m^3 == c exactly
raw = int(m).to_bytes((int(m).bit_length() + 7) // 8, "big")
print(raw)
# b'Miles::bitctf{{sp1d3r_cub3d_br0adca57}}'
```

`gmpy2.iroot(c, 3)` returns the floor of the real cube root and a flag
telling us whether the result is exact. Here it is, confirming the
attacker's assumption: the plaintext is **`Miles::bitctf{{sp1d3r_cub3d_br0adca57}}`**
and the flag is the bracketed tail.

## Why "the numbers seem friendlier than they should"

The challenge author telegraphs the bug three ways:

1. **`e = 3`** — the smallest legal RSA public exponent.
2. **No padding** — modern RSA (OAEP / PKCS#1 v1.5) randomises the
   message so two encryptions of the same `m` differ. Here the broadcast
   is byte-identical on every fetch, which is the deterministic-textbook
   tell.
3. **Short `m`** — only 311 bits versus a ~1024-bit `n`, so `m³` lives in
   a tiny corner of the modulus.

Together those three preconditions are the canonical small-`e` textbook
RSA recipe.

## Variants worth knowing (none needed here)

If the plaintext had been long enough that `m³ ≥ n` but still partially
known (e.g. a fixed `"Miles::"` prefix + a short unknown suffix), the next
step would be **Coppersmith's method** to recover the small unknown root
of a univariate polynomial mod `n`. SageMath's `small_roots()` does it in
two lines. If three different ciphertexts of the *same* `m` had been
broadcast under different `n_i` with `e = 3`, **Håstad's broadcast attack**
recovers `m³` via CRT, then takes the cube root.

In this challenge the easiest variant — integer cube root — already
works, which is the "lightest reversing path" of crypto.

## Take-aways

- Whenever `e ∈ {3, 5, 7}` and you see an unpadded ciphertext shorter than
  `n`, try **`iroot(c, e)`** before anything else.
- If `iroot` returns `exact=True`, the attack is over. If not, escalate to
  Coppersmith.
- Deterministic broadcast endpoints are an RSA padding smell — modern
  schemes randomise, textbook RSA doesn't.
