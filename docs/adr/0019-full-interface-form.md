# ADR-0019: Exact full-command echo and Autostate oper spellings

Status: accepted by the delegated project lead; delivery requires independent review and exact-head hosted checks

Date: 2026-10-25

This bounded P1 compatibility decision does not close P1, qualify a device/train,
or authorize P2. The user delegated project lead decisions on this date.

A pinned public Genie full-command capture begins with an unprompted exact
command echo before numbered interface headers:
https://github.com/CiscoTestAutomation/genieparser/blob/e62f9467a383997e190e04679d769c5c009e7460/src/genie/libs/parser/iosxe/tests/ShowInterfaces/cli/equal/golden_output2_output.txt#L2
CiscoDevNet independently documents both Autostate oper spellings:
https://github.com/CiscoDevNet/cisco-ios-xe-openapi-swagger/blob/88a4ee3c714d418999bd669c8e40aff85ba7d5cf/scripts/mdt-telemetry/docs/cli-reference.md#L1248
https://github.com/CiscoDevNet/cisco-ios-xe-openapi-swagger/blob/88a4ee3c714d418999bd669c8e40aff85ba7d5cf/scripts/mdt-telemetry/docs/cli-reference.md#L1295

Admission may recognize a first nonblank line exactly equal to
`show interfaces` only when the next nonblank line matches the existing numbered
full-interface header grammar. Blank selection may use strip; retained command
characters are not trimmed. Only the inspection list drops that leading echo;
the Capture, capture ID, line accounting and evidence hashes retain all raw bytes.
The pack consumes the echo through one exact literal rule.

The closed oper map adds precisely `up , Autostate Enabled` and
`down , Autostate Enabled`, retaining the complete original token span and hash.
No splitting, trimming, case folding or arbitrary modifier stripping is allowed.
Other spellings remain unknown. Physical down still cannot prove admin state.
Unmodelled body records remain partial, and coverage remains denominator_open.

Scoped, filtered, padded, repeated, late and other bare commands remain refused.
Existing mixed-command, system/configuration, control-text, caret, error and
truncation guards remain in force. Caret pairing still requires a real prompt echo.
Numberless full-interface names remain unsupported. P0 behavior, brief named-family
rules, ownership, identity, read scope, view consistency and dependencies are unchanged.
This adds no standard-library grant and establishes no collection-session success.

Validation requires generated synthetic inputs, LF/CRLF custody and hash assertions,
strict negative spellings, diagnostic/refusal cases, previous-output preservation,
determinism, complete hosted checks on the exact head and independent review.
No public raw capture or upstream expected-result oracle is imported.
The cited public sources establish format examples, not authenticity, privacy
clearance, a public format-floor result, truth coverage, or device qualification.
