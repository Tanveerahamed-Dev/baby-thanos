# ADR-0013: Runner egress tripwire and explicit child-spawn admission

Status: accepted

Date: 2026-10-24

Extends ADR-0002; every existing global, AST, path-read and ZIP grant is unchanged.
M0 PR 2 (`atlas_brain/runner/`, PLAN section 8.2) needs process spawn, process
identity, an audit hook and the exact egress calls its witness deliberately attempts,
so that the offline tripwire is proven by a negative control and never assumed.

The runner is not a new evidence channel. The coordinator and every worker are plain
re-invocations of the same interpreter (`python -m atlas_brain.runner`); each process
installs the audit hook before parsing arguments or spawning children, an audit hook
cannot be removed, and a probe that fails to deny refuses the run with exit code 2.
Counts are written to `MANIFEST.json`; no dynamic import, exec/eval, shell, network
transport, mutable default or private attribute read is added.

Admissions live in a new exact map `RUNNER_API` (path -> endpoints), kept separate
from `STDLIB_API`/`SCOPED_API`/`RUNTIME_API` so the inherited ADR-0002 exact
inventories stay byte-stable. The map is additive only and grants nothing to any
path not listed below.

| API | Using path | Reason |
|---|---|---|
| subprocess.run | atlas_brain/runner/__init__.py | Python API spawns the CLI (which spawns the coordinator). |
| sys.executable | atlas_brain/runner/__init__.py | Re-invoke the current interpreter; never a shell. |
| subprocess.run | atlas_brain/runner/cli.py | CLI parent spawns the coordinator child explicitly. |
| sys.argv | atlas_brain/runner/cli.py | Read the operator command line. |
| sys.executable | atlas_brain/runner/cli.py | Re-invoke the current interpreter for the coordinator. |
| sys.stderr | atlas_brain/runner/cli.py | Stable refusal message channel. |
| subprocess.run | atlas_brain/runner/coordinator.py | Coordinator spawns each explicit worker process. |
| sys.executable | atlas_brain/runner/coordinator.py | Re-invoke the current interpreter for every worker. |
| sys.addaudithook | atlas_brain/runner/tripwire.py | Install deny-and-count egress hook before any work. |
| socket.AF_INET | atlas_brain/runner/tripwire.py | Witness target family for the connect probe. |
| socket.SOCK_STREAM | atlas_brain/runner/tripwire.py | Witness target socket type for the connect probe. |
| socket.getaddrinfo | atlas_brain/runner/tripwire.py | Deny and count DNS egress. |
| socket.socket | atlas_brain/runner/tripwire.py | Create the witness socket object. |
| socket.socket.connect | atlas_brain/runner/tripwire.py | Deny and count TCP connect egress. |
| socket.socket.close | atlas_brain/runner/tripwire.py | Close the witness socket after denial. |
| http.client.HTTPConnection | atlas_brain/runner/tripwire.py | Deny and count http.client egress. |
| http.client.HTTPConnection.connect | atlas_brain/runner/tripwire.py | Deny and count the HTTP connection attempt. |
| http.client.HTTPConnection.close | atlas_brain/runner/tripwire.py | Close the witness connection after denial. |
| urllib.request.urlopen | atlas_brain/runner/tripwire.py | Deny and count urllib request egress. |

Worker steps are assigned deterministically and reported on stdout; output bytes do
not depend on the worker count. `tests/runner/` proves byte-identical double runs,
1-vs-4-worker byte identity, denial-and-count in parent, coordinator and workers, and
the stable `evidence_dir_missing` refusal (exit 2). Independent review is still
required before merge; this admission does not accept the runner behaviour.
