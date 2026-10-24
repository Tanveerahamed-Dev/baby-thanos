# Declared raw-output mutations

`tools/mutations.py` is a standard-library truth-harness utility. `OPERATORS` is
immutable: each declaration exposes its complete byte-token set and permitted
bidirectional transitions. Numeric sets are generated, never arbitrary strings.

| Operator | Declared vocabulary | Engine v1 use |
|---|---|---|
| ospf-state | FULL ↔ EXSTART, EXCHANGE, INIT, 2WAY | U2a/U2b; U3 operand |
| duplex | full/half, a-full/a-half, Full-duplex/Half-duplex | L1-02/L1-10; preserves auto prefix |
| psu-state | OK/Ok ↔ Absent; OK ↔ Not Present/failed; active ↔ bad-input | L1-05 logic only |
| native-vlan | decimal 1–4094 | U4a/U4b one-end operand |
| err-disabled | connected ↔ err-disabled | L1-01 |
| admin-up-oper-down | is up, line protocol is up/down; is up/down | L1-01; select oper header, preserve admin line |
| mtu | decimal 68–65535 | U1a; U3 operand; no header conversion |
| duplicate-address | hosts 1–254 in the three documentation IPv4 /24s | C-19 swap operand |

`apply_span(raw, operator, start, end, after)` changes exactly one caller-selected
field at the half-open **byte** span `[start,end)`. It refuses absent, partial,
undeclared and no-op tokens; it never searches for a fallback occurrence. All bytes
outside the span survive, including UTF-8 prefixes, CRLF and missing final newlines.
It is a bare text transform and supplies no tier or device-semantic claim.

`mutate(parent, operator, start, end, after, witness, witness_start, witness_end)`
checks the internal consistency of caller descriptions: digests, declared H/L/P,
a known identical family/exact train, and replacement bytes at the witness span.
`Capture` is untrusted caller data, never admitted source or witness evidence.
The output receipt has `qualification: unqualified`, kind `unqualified_text_edit`
and **no tier field**. This remains true for a self-consistent invented pair with
nonexistent provenance links. It records declared IDs/hashes/links, edit bytes and
spans, output hash and a deterministic edit ID; it cannot assign tier M.

Actual M issuance remains deferred until both source and witness are bound to
validated admission/provenance evidence. V's current public schema accepts P/S
fixtures and refuses M. Do not promote these edit receipts into truth records.
The caller still owns field selection, grammar, peer/domain/bay identity and
independent labels. A VLAN edit on a non-trunk is not a mismatch; duplicate
addresses need a closed common domain; MTU plus EXSTART does not prove causation.
I1–I10 bundle operators and signed truth records are a separate harness contract.

Four Q raw files remain byte-identical to `q/public-corpus` commit
`ef92126e9f2ae2161c02f050f4fba29932dc117e` under `fixtures/mutations/q/`.
Their adapted `provenance.yaml` records use MU-prefixed IDs, sibling `file`, full
notice text and `format_floor: false`; original source metadata remains pinned
in Q's commit. Ancillary files are outside fixtures. Source-specific notices and
NTC's copyright licence are in `docs/contract/mutation-sources/`. Root `LICENSE`
contains the complete identical Apache terms (only an extra terminal blank line).
Q lacks eligible same-train fault-token witnesses. No M fixture, format-floor,
measured accuracy or verified-device claim is supplied. Hosted Linux/Windows tests
check the entire shared fixture gate, caller-tier spoofing, planted refusals,
inverse controls, byte preservation and fresh-process hash-seed determinism.
