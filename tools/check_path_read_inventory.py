"""Read pinned admission source as data and verify both actual public path uses."""
import ast
import hashlib
import json
import subprocess

from tools.fence import RUNTIME_API, import_bindings

USING = "atlas_brain/evidence/admission.py"
REVISION = "ca64e4d0912e2ad7dbacff8ef2394fc8c5a4a307"
DIGEST = "9ab117baf6efe2908ea3aca450852421bdebf268b2f87ee70611cd4a52343870"


def main():
    source = subprocess.check_output(["git", "show", f"{REVISION}:{USING}"])
    current = subprocess.check_output(["git", "show", f"HEAD:{USING}"])
    if source != current or hashlib.sha256(source).hexdigest() != DIGEST:
        raise ValueError("using source changed; re-pin exact path admission")
    tree = ast.parse(source.decode("utf-8"))
    aliases = import_bindings(tree, USING)[0]
    def qualified(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, "")
        if isinstance(node, ast.Call):
            return qualified(node.func)
        base = qualified(node.value) if isinstance(node, ast.Attribute) else ""
        return base + "." + node.attr if base else ""
    used = {qualified(node) for node in ast.walk(tree) if qualified(node) in RUNTIME_API[USING]}
    if used != RUNTIME_API[USING]:
        raise ValueError("read grant differs from actual source inventory")
    print(json.dumps({"source_head": REVISION, "source_sha256": DIGEST, "path": USING,
                      "used_apis": sorted(used), "scope": "source read inventory; consumer not executed"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
