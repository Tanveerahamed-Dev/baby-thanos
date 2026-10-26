# ADR-0021: Bounded P2 configured intent and static inheritance

Status: accepted

Date: 2026-10-26

Extends ADR-0020 only for configuration-enabled input; its v1 SHOW contract stays
frozen. The owner requested completion of P2 config/inheritance. Generic model,
store, kernel, relations, dependencies and source-fence grants need no change.

Input `atlas-brain.synthetic-p2/1` retains its three operations and bytes.
New `atlas-brain.synthetic-p2/2` adds only `iosxe.show_running_config`
(rendered `show running-config`) and requires at least one such capture.
Every declared node/port remains expected; an uncollected node is NOT_COLLECTED.
JSON retains only group/node/port/capture declarations, never template or VLAN
values. Capture identity binds the exact schema, registry bytes, source, path,
operation and raw hash. Config recognition is separate from unchanged SHOW guards.

Inner `atlas-brain.p2-demo/1` and its catalogue/output bytes stay frozen.
Config input emits `atlas-brain.p2-demo/2`; outer runner-manifest/2 is unchanged.
V2 adds pack-owned `l2.vlan_trunk.configured_mode` (text),
`l2.vlan_trunk.configured_native` (integer), and
`l2.vlan_trunk.configured_allowed` (canonical text).
One `l2.vlan_trunk/parse_config` step writes each declared endpoint once.
`l2.vlan_trunk/check_config` reads declared peer/configured facts and emits
`configured_native_mismatch` and `configured_allowed_asymmetry`.
Existing observed facts/checks stay independent. Both families are visible;
no cross-basis comparison, overwrite, winner, health or alignment claim follows.

The project-defined synthetic CLI allowlist accepts exact interface/template
blocks, explicit mode trunk/access, exact `no switchport` as routed mode,
native 1..4094 and allowed numeric/range/all/none statements. The sole admitted
negation is `no switchport`; all other no/default forms are unsupported.
Optional exact command/prompt, version/hostname/build/current-config metadata,
blank/! separators and a final end are accounted; no unknown line is ignored.
This is not a vendor-qualified full running-config grammar.
[Cisco template concepts](https://github.com/CiscoDevNet/terraform-provider-iosxe/blob/c845160406f9a2d1ca899db4c51cf35b8a0c0912/gen/definitions/template.yaml)
and [binding](https://github.com/CiscoDevNet/terraform-provider-iosxe/blob/c845160406f9a2d1ca899db4c51cf35b8a0c0912/docs/resources/interface_ethernet.md)
support source/template concepts, not CLI precedence, train or format-floor claims.

A block is one exact (kind, identifier). Static single-parent template chains in
the same node capture may contain at most 16 parent edges (interface-to-first
template is edge 1). Every edge/header/definition must be cited. Fully resolved
chains may combine disjoint or identical definitions; unequal definitions
conflict. No child override or last-line precedence is assumed.
Duplicate blocks/attributes conflict even when identical within a block.

Missing parent, cycles and multiple parent references are INHERITANCE_UNRESOLVED;
edge 17 is BUDGET_EXCEEDED. Unsupported merge/range/profile/dynamic/delta/no/default
syntax is PARSE_UNSUPPORTED_VARIANT; other unrecognised or incomplete body text
is PARSE_PARTIAL. Error/truncated/empty retain CAPTURE_ERROR/CAPTURE_TRUNCATED/
EMPTY_UNREGISTERED. Only a fully exhausted valid chain may yield DEFAULT_UNKNOWN
for omitted mode/native/allowed. Nothing supplies VLAN 1, all, none or Absent.
Resolved access/routed modes suppress native/allowed as NOT_OBSERVABLE.

Known configured values use Basis.CONFIGURED and prove supplied statements only.
Native/allowed positives require resolved trunk mode and its evidence. Unknowns
retain targeted config needs. Reciprocal, resolved configured differences are
conditional synthetic problems; equal untimed values remain AS_OF_MISSING.
Coverage, read scope, view and collector time stay unknown. Every config receipt
binds capture, owner and invoking node before any estate step. Recursive proof
resolution validates registry/schema/capture/operation/span/hash custody.
V1 pinned bytes, depth 16/17, defaults, missing/cyclic/duplicate/conflicting and
unsupported chains, mixed independent bases, denominator retention and both-end
proofs require hosted Linux/Windows regressions and independent review. P3 is not started.
