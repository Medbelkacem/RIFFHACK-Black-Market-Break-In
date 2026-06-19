# The Crawler's Courtesy

- **Platform:** Riffhack CTF (Biterra) — team `ZKaMYBbs`
- **Author:** CL4Y
- **Target:** `http://159.89.237.133/`
- **Category:** Web — Information Disclosure (robots.txt enumeration)
- **Flag:** `bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}`

## TL;DR

The marketplace's `robots.txt` lists a `Disallow:` entry for an "internal handoff" path that the operators expected crawlers to skip. Visiting that path directly returns the flag — `robots.txt` is a *crawler courtesy*, not access control.

## Recon

The target is a Next.js site (`X-Powered-By: Next.js`, `_next/static/*`) styled as a fictional "exploit kit marketplace."

```
$ curl -s http://159.89.237.133/robots.txt
User-Agent: *
Allow: /
Disallow: /operator-cache-drop
```

A single `Disallow:` rule pointing at `/operator-cache-drop` — exactly the loose thread the challenge name (`The Crawler's Courtesy`) telegraphs.

## Exploitation

Request the disallowed path directly:

```
$ curl -s http://159.89.237.133/operator-cache-drop \
    | python3 -c 'import re,sys,html; t=sys.stdin.read(); \
        t=re.sub(r"<script.*?</script>","",t,flags=re.S); \
        t=re.sub(r"<style.*?</style>","",t,flags=re.S); \
        t=re.sub(r"<[^>]+>"," ",t); print(re.sub(r"\s+"," ",t))'
```

Output (relevant excerpt):

> **Operator Cache Crawler — quarantine bucket**
> This path was left out of normal navigation so search crawlers would not index internal handoff scraps.
> Recovered scrap: `bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}`

That's the flag.

## Root Cause

`robots.txt` is a *suggestion* to well-behaved web crawlers (Googlebot, etc.). It has no enforcement on:

- adversaries who simply read the file and visit the listed paths
- search engines that ignore the directive
- archives like the Wayback Machine

Putting a secret URL behind `Disallow:` is the opposite of hiding it — you have **explicitly published the URL** in a file every scanner reads first.

## Fix

- Treat `robots.txt` as public navigation hints, never as a security boundary.
- Protect sensitive paths with authentication and authorization (e.g. session check + role gate).
- If a URL truly should not be indexed, gate it behind auth **and** add `X-Robots-Tag: noindex, nofollow` response header, **and** keep the path itself unguessable (random token), **and** still authenticate the request.
- Consider serving an empty or minimal `robots.txt` so any disclosed path is exposed only by deliberate leak, not by site policy.

## Tools Used

- `curl` — fetch `robots.txt` and the hidden path
- `python3` — strip HTML to extract the flag from the page body

## Time to Solve

~2 minutes.
