# ADR-0032: Retained request input custody

Status: proposed.

Additive retain_requests/validate_retained_requests helpers operate on valid,
already-admitted CaptureRequest graphs. Before parser invocation the caller
retains copied IDs, original Request/Capture pointers and detached asdict values.
After invocation it verifies the same ID census, both pointers and value equality
before materializing facts. Reordering is allowed; equal object replacements refuse.
Empty input is valid custody, never health or expected-population closure.

The valid graph contains closed dataclasses, tuples, scalars, enums and bytes;
nested metadata/scope/time/lines/evidence and original raw bytes are retained.
Callers keep snapshots private and unchanged. They are not admission tokens,
nominal-type validation, registration, parser-execution, semantic/proof or universal
code-mutation authority. Existing execute_parsers/validate_receipts behavior and
profiles/output bytes stay unchanged until an explicit owning consumer opts in.
The dependent registered VIP producer remains required and must use both barriers.
