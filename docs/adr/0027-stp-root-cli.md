# ADR-0027: Fixed Root observation CLI

Status: proposed.

The named `--format p4-root-observations` selects the fixed Root folder API.
Only parent/coordinator roles admit it; workers keep the legacy witness protocol.
Existing CLI formats, argument forwarding, stdout and output bytes stay fixed.

Root publication writes the exact five budget-checked API files, including the manifest.
No runner metadata is added after the API budget check. Input/output limits
therefore retain their existing combined meaning. The shared publisher keeps
fresh-output/path checks, exclusive staging, readback verification and rename.
Its stable-tree guarantees do not promise fsync or hostile-race protection.

Root analysis, schema/profile, manifest and inventory checks close before
coordinator/worker witnesses or staging. Actual process witnesses close before
publication. After successful publication, stdout emits a canonical
`P4_ROOT_CLI_RECEIPT`, bound to the manifest and actual execution witness.
The usual status follows. Parent counts stay forwarded metadata, not attestation.
This receipt measures runner witnesses only;
it neither admits source evidence nor proves protocol checks or host isolation.

Root reports remain synthetic observations, preserving Unknowns and original
source requirements. No intended root, topology, health, platform qualification,
retained hosted Root demo, full P4, EX-02, M1 or P5 acceptance is established.
