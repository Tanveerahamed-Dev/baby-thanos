# ADR-0017: Capture-scoped interface answers

Status: accepted

Date: 2026-10-25

P1 adds the owner `l1.interface` for `l1.interface.admin` and
`l1.interface.oper`, produced by `l1.interface/parse` through the existing
single-owner FactStore writer. Its check `l1.interface.admin_up_oper_down`
reports both inconsistent directions as problem. The runner only projects
pack-owned states, verdicts, observed counts and evidence requests.

Two narrow IOS-XE-compatible forms are admitted: `show interfaces` header
records and the `show ip interface brief` table. An exact command prompt can
bind partial/error/empty output; raw responses need their anchored header.
Filename, directory, interface abbreviation and hostname never establish a
cross-file device join. Mixed command/system/configuration contexts refuse.

The first interface/status column is a hardware/admin observation; line protocol
is the oper state for this check. Explicit up proves enabled, administratively
down proves disabled; physical down alone leaves admin not_observable.
See the Cisco interface/status field definitions:
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/release/17-9/command_reference/b_179_9600_cr/interface_and_hardware_commands.html

Inherited ordered byte rules and closed token maps retain raw spans. Missing or
unmapped states remain unknown; duplicate exact names (including malformed twins)
conflict before one fact write. Body lines not modelled by this pack remain
unrecognised/partial, never silently ignored. Partial captures cannot produce OK;
a complete observed mismatch may remain a problem. Explicit truncation/pager
makes state inputs unknown; failed/empty commands expose zero rows and unknown
coverage. Every unknown and problem supplies the next command to collect.

The denominator is only observed unique names in that capture, not an estate
population. Coverage is always unknown; no observed rows cannot become healthy.
With no interface command, an additive `interface_coverage` NOT_COLLECTED record
requests `show interfaces` for `node:unresolved`, without inventing a device.
P1 rows/findings live under `facts[capture_id]`; P0 fact values are unchanged.
The summary says execution status to distinguish command success from health.

Truth is measured synthetic/regression coverage, not device/train qualification.
Support is explicitly labelled `variant_support: allowlisted` in each P1 result.
Full-command public format-floor coverage remains a stated shortfall; no lab,
holdout or verified claim is made. No new API grants or runtime dependencies.
Existing ADRs, fence maps and inherited admission/inventory tests are unchanged.
