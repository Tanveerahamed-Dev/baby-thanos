# P4 synthetic HSRP IPv4 census wire v1

This project-owned format supplies framed test evidence for EI-R11 under
[`baby-thanos.p4.synthetic/1`](p4-synthetic-case-contracts-v1.md). The parser
recognizes one exact node/interface pair, one response and IPv4 HSRP group
identifiers. Its operation and command labels identify a synthetic artifact.
Cisco command output and field qualification are outside this grammar.

## Wire

Each line ends with one LF byte, including the final line. The artifact uses
ASCII bytes with an ASCII or UTF-8 capture codec. Spaces, spelling, field order
and case are exact. The first line is the scope, followed by zero or more group
lines and one final success footer:

```text
baby-thanos.hsrp-census/1 node=NODE interface=INTERFACE af=ipv4 protocol=hsrp groups=all
group node=NODE interface=INTERFACE id=GROUP
success rows=COUNT sha256=DIGEST
```

- `NODE` is `node:GROUP_ID:NODE_ID`. Each identifier matches
  `[a-z][a-z0-9_-]{0,31}`. The exact node and interface come from the expected
  scope. Every row repeats both labels and must match that scope.
- `INTERFACE` matches `[A-Za-z][A-Za-z0-9./:_-]{0,63}`. Interface labels
  preserve case and spelling.
- `GROUP` is canonical decimal in 0–4095 with unique identifiers. Records
  retain their wire order. `COUNT` is canonical decimal in 0–4096 and equals
  the number of group lines. The artifact limit is 680,000 bytes.
- `DIGEST` is the 64-character lowercase hexadecimal SHA-256 of the exact original prefix
  from byte zero to the start of the footer. It includes the scope and each
  group line with their LF bytes. A zero-group response still binds its scope.

A zero-row census requires the complete scope and a verified success footer.
For accepted input, parsekit accounts for every byte including LF. Field spans
index original token bytes, record spans exclude the LF, and scope raw bytes
include the LF. The reported body span marks the digest input.

Unexpected framing, extra content, wrong scope, group conflicts, inconsistent
counts or hashes, unsupported encoding and negative capture integrity leave the
census unresolved. A caller's complete scope/view flags cannot qualify the bytes.
The digest verifies format integrity. Before using a census for EI-R11, an owning
admission path must separately bind exact original capture provenance, the
declared target, complete read scope and an admissible view. The parser produces
source spans and diagnostics. Preflight refusals may omit parse accounting.
Fact production and absence findings require their
own separately reviewed owner.
