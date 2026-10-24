# Public fixture provenance, M0

Run `python tools/provenance.py` from the repository root. An absent default `fixtures/` is allowed before corpus import; an
explicit missing root is refused. Each fixture directory contains exactly one
raw file and `provenance.yaml`; every other file needs its own record/directory.

The exact YAML subset is UTF-8, LF or CRLF, blank lines, two-space-indented block mappings,
lowercase snake_case keys, and scalar strings, `null`, `true`, `false`, or nonnegative decimal integers. Strings are JSON double-quoted
strings or bare ASCII tokens matching `[A-Za-z][A-Za-z0-9_.-]*`. No comments,
single quotes, flow collections, lists, tags, anchors, aliases,
document markers, duplicate/unknown keys, floats or negative integers are accepted.
All fields below are required. `file` names one sibling raw file. Repository
commits are full lowercase 40/64-character hashes; paths are relative POSIX paths.

```yaml
fixture_id: example-version
file: output.txt
tier: P
source:
  kind: library_testdata
  repository:
    url: "https://github.com/example/corpus"
    commit: "<full source commit hash>"
    path: "samples/output.txt"
platform:
  family: iosxe
  model: C8000V
  version: "17.1"
  version_basis: source_stated
licence:
  name: "<source licence name>"
  redistribution: public
  notice: "<full required notice text, or explicit no-notice statement>"
sha256: "<SHA-256 of raw output.txt bytes>"
privacy:
  scanner_version: "<scanner version or pinned source commit>"
  result: pass
  exemption: null
```

The public M0 subset accepts P/library_testdata and S/synthetic. H and L belong
in the private truth repository. M is refused until parent/mutation/token-witness
validation exists. Excluded sources are never accepted. The required `privacy` receipt and optional `capture` use the exact S6 keys;
`source.archive_sha256` and `line_count` are validated; `capture.utc` requires zero offset.
`format_floor` may only be false here; parser-census approval is deferred.
Unknown version uses `version: unstated` and `version_basis: unknown`; family/model may be known;
S may also use `observed`.
P requires `source_stated` for a stated platform/version; P never proves accuracy.
This gate checks declared provenance and byte integrity, not upstream authenticity,
licence correctness, privacy clearance or parser-census qualification.

Q import: add `file: raw.txt` to each record. Move inventories, README and licence
files outside fixtures/; preserve required notice text in the record's licence.notice
and keep upstream licence files under docs/contract/. No ancillary file bypass exists.
