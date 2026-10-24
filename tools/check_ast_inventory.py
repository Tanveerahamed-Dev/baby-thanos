"""Check actual AST uses and source-fence admission; never execute K source.

This verifies source admission, not K's lint, type or kernel-freeze acceptance.
"""
import ast
import json
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

from tools.fence import SCOPED_API, source_allowed

SOURCES = {
    "atlas_brain/kernel/token_lints.py": "df6016ef31d086ef836d5666d629aad132a66890",
    "atlas_brain/kernel/lints.py": "fb1ce4754a1fa9d2e43f121b6a82cb7d832e3c5b",
    "atlas_brain/evidence/parsekit/token_lint.py": "1b2661492e19387ba0bd602d085d0e93ee1ee177",
    "atlas_brain/evidence/parsekit/token_audit.py": "7082fec06a7253d028b359ada44423d2c0391587",
}
STARRED_HEAD = "b5ddc54f6e4aa6332094561f79bda0af4fa3f690"
STARRED_BLOB = "772852e25f13425aca12cc2c77b0c849794dd9f1"
STARRED_DIGEST = "36817d7a9e4e75a935fc25a848008343cb7cadd0745af835607f61658f019f4f"


def tracked_borrowing_probe(sources):
    tool = str(Path(__file__).with_name("fence.py").resolve())
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for path, source in sources.items():
            file = root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(source, encoding="utf-8")
        (root / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", directory], check=True)
        subprocess.run(["git", "-C", directory, "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=root, check=True)
        plant = root / "atlas_brain/model/runtime.py"
        plant.parent.mkdir(parents=True)
        refusals = {}
        for label, source in (
            ("runtime_global_reexport", "from atlas_brain.kernel.lints import sha256; digest = sha256(raw)"),
            ("runtime_pk_global_reexport", "from atlas_brain.evidence.parsekit.token_audit import dataclass; dataclass(Record)"),
        ):
            plant.write_text(source + "\n", encoding="utf-8")
            subprocess.run(["git", "-C", directory, "add", "."], check=True)
            result = subprocess.run([sys.executable, tool], cwd=root, capture_output=True, text=True, check=False)
            if result.returncode != 1 or "scope fence: 1 refused" not in result.stdout:
                raise ValueError(f"real tracked-file gate accepted {label}")
            refusals[label] = "refused"
    return {"pinned_source_tree": "allowed", **refusals}


def main() -> int:
    receipts = []
    sources = {path: subprocess.check_output(["git", "show", f"{revision}:{path}"], encoding="utf-8")
               for path, revision in SOURCES.items()}
    for path, revision in SOURCES.items():
        source = sources[path]
        used = {f"ast.{node.attr}" for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "ast"}
        expected = SCOPED_API[path] - ({"ast.Starred"} if path == "atlas_brain/kernel/lints.py" else set())
        if used != expected:
            raise ValueError("AST admission differs from the approved request's actual uses")
        if not source_allowed(source, sources, path):
            raise ValueError("K source fails the amended source-admission gate")
        receipts.append({"path": path, "source_head": revision, "apis": sorted(used), "source_fence": "allowed"})
    historical_probe = tracked_borrowing_probe(sources)
    path = "atlas_brain/kernel/lints.py"
    raw = subprocess.check_output(["git", "show", f"{STARRED_HEAD}:{path}"])
    blob = subprocess.check_output(["git", "rev-parse", f"{STARRED_HEAD}:{path}"], text=True).strip()
    if blob != STARRED_BLOB or sha256(raw).hexdigest() != STARRED_DIGEST:
        raise ValueError("Starred source differs from the exact public pin")
    source = raw.decode("utf-8")
    used = {f"ast.{node.attr}" for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "ast"}
    historical_used = next(set(row["apis"]) for row in receipts if row["path"] == path)
    if (used != SCOPED_API[path] - {"ast.parse"} or used - historical_used != {"ast.Starred"}
            or historical_used - used != {"ast.parse"} or used | historical_used != SCOPED_API[path]):
        raise ValueError("historical and Starred source inventories do not exactly cover the grant")
    sources[path] = source
    if not source_allowed(source, sources, path):
        raise ValueError("exact Starred using source fails source admission")
    receipts.append({"path": path, "source_head": STARRED_HEAD, "source_blob": blob,
                     "source_sha256": STARRED_DIGEST, "apis": sorted(used), "source_fence": "allowed"})
    print(json.dumps({"ast_inventory": receipts, "unique_apis": len(set().union(*SCOPED_API.values())),
                      "tracked_probe": historical_probe,
                      "starred_tracked_probe": tracked_borrowing_probe(sources)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
