# ADR-0016: Single-response recognition before system fact binding

Status: accepted

Date: 2026-10-25

Amends ADR-0015's capture-recognition rule. An IOS-XE banner anywhere in a
file is insufficient: configuration banner text can contain the same strings.
The runner must establish a constrained response envelope before assigning the
`iosxe.show_version` operation. This changes recognition, not pack-owned facts.

The first nonblank payload line must be an IOS-XE banner with a token boundary,
or the whole payload must contain only the three supported system-record forms.
An optional initial exact `HOST[>#] ?show version` and one terminal bare prompt
are allowed; when both exist, the complete prompt must match. Interior prompts,
repeated response banners, recognized configuration markers, competing platform
banners and unsupported command echoes refuse with `evidence_unsupported_capture`.
Rejection checks ignore case and indentation, but field parsing and raw bytes
are unchanged. Exact field records take precedence over rejection keywords so
a hostname such as `show` does not become a spurious command. Recognized closing
configuration/cancel markers (`end`, `!`, `^`, `^C`) also refuse.

Recognition uses physical LF/CRLF lines, matching the pack parser. Bare CR,
NEL and Unicode line/paragraph separators refuse as `evidence_invalid_text`.
Existing error/pager refusals retain precedence. Partial captures and duplicate
fields still reach the owning pack and retain its unknown/conflict semantics.

No APIs, dependencies or capability grants are added. Synthetic CLI regressions
cover configuration banners, command/response conflicts, casing, line endings,
whole-folder refusal, preserved prior outputs, hostname twins and exact raw spans.
The existing multibyte-span test now places Unicode inside the permitted header;
all value, byte-slice, digest and missing-clock assertions remain intact.

This is response recognition, not authenticated collector provenance. Headerless
fragments are still explicit supplied evidence, and arbitrary promptless
concatenation cannot be universally identified. ADR-0015's stable-tree assumption,
file/byte budgets and separate Lead review before merge remain in force.
