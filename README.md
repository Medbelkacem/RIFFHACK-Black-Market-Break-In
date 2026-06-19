# RIFFHACK: Black Market Break-In

Write-ups for the **Riffhack CTF (Biterra)** event — a black-market-themed jeopardy CTF spanning web, pwn, reverse, crypto, forensics, and misc.

- **Event:** Riffhack CTF — *Black Market Break-In*
- **Team:** `ZKaMYBbs`
- **Author:** CL4Y
- **Flag formats:** `bitflag{...}` (web track) and `bitctf{...}` (binary / crypto / forensics / misc)

---

## Index

### Web — the marketplace itself

| Challenge | Bug class | Difficulty |
| --- | --- | --- |
| [Marketplace — Overview](writeups/marketplace-overview.md) | Recon / multi-bug summary | medium |
| [The Crawler's Courtesy](writeups/crawlers-courtesy.md) | `robots.txt` info disclosure | easy |
| [The Trusted Return Address](writeups/trusted-return-address.md) | Open redirect + credential handoff leak | easy |
| [Marketplace — Admin Middleware Bypass](writeups/marketplace-admin-middleware-bypass.md) | CVE-2025-29927 Next.js middleware bypass | easy |
| [Marketplace — Vendor Verification SSRF](writeups/marketplace-vendor-verification-ssrf.md) | SSRF → IMDS user-data leak | easy |
| [Marketplace — Operator Reputation IDOR](writeups/marketplace-operator-reputation-idor.md) | IDOR via trusted handle | easy |
| [Marketplace — Order History IDOR](writeups/marketplace-order-history-idor.md) | IDOR via Review UIDs | easy |
| [InGen Systems Specimen Catalogue](writeups/ingen-specimen-catalogue.md) | "Life finds a way" web challenge | easy |
| [Vault 101 RobCo Termlink](writeups/vault101-overseer-directive.md) | Overseer's sealed directive | easy |

### Pwn — overflows and ret2win

| Challenge | Technique | Difficulty |
| --- | --- | --- |
| [Samus Stack Smash](writeups/samus-stack-smash.md) | `gets()` overflow → ret2win | easy |
| [Barbie Core](writeups/barbie-core.md) | Keystream calibration bypass + ret2win | medium |

### Reverse

| Challenge | Technique | Difficulty |
| --- | --- | --- |
| [Orbital Docking Handshake](writeups/orbital-docking-handshake.md) | arm64 Mach-O — XOR-decoded flag + computed alignment | medium |

### Crypto

| Challenge | Technique | Difficulty |
| --- | --- | --- |
| [Spider-Verse Cube-Root](writeups/spider-verse-cube-root.md) | Textbook RSA with `e=3`, unpadded plaintext | easy |
| [Minas Tirith Signing Oracle](writeups/minas-tirith-signing-oracle.md) | One Ring nonce collapse — ECDSA repeated nonce | medium |

### Forensics

| Challenge | Technique | Difficulty |
| --- | --- | --- |
| [Sailor Spectrum](writeups/sailor-spectrum.md) | Appended-ZIP PNG stego + plaintext PCAP | easy |
| [Hawkins Lab Memory Snapshot](writeups/hawkins-memory-palace.md) | Vecna's Memory Palace — memory forensics | medium |

### Misc

| Challenge | Technique | Difficulty |
| --- | --- | --- |
| [Aperture Test Chambers](writeups/aperture-test-chambers.md) | Lights Out × 20 — linear algebra over GF(2) | medium |

---

## Layout

```
.
├── README.md
└── writeups/
    ├── aperture-test-chambers.md
    ├── barbie-core.md
    ├── crawlers-courtesy.md
    ├── hawkins-memory-palace.md
    ├── ingen-specimen-catalogue.md
    ├── marketplace-admin-middleware-bypass.md
    ├── marketplace-operator-reputation-idor.md
    ├── marketplace-order-history-idor.md
    ├── marketplace-overview.md
    ├── marketplace-vendor-verification-ssrf.md
    ├── minas-tirith-signing-oracle.md
    ├── orbital-docking-handshake.md
    ├── sailor-spectrum.md
    ├── samus-stack-smash.md
    ├── spider-verse-cube-root.md
    ├── trusted-return-address.md
    └── vault101-overseer-directive.md
```

Each write-up contains:

- target host / artifact
- short root-cause description
- a complete solve path from challenge data to flag
- the recovered flag

---

## Disclaimer

Targets, hosts and IPs referenced inside are **scoped to the Riffhack CTF event**. They were live only during the competition window and are included for reproducibility of the solve, not as ongoing testing targets.
