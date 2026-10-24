"""Child-process audit witness for the engine's current import surface and output boundary."""
import argparse
import importlib.util
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path


def contract_path(path, root: Path, *, directory: bool = False) -> bool:
    """S1 1.12 result-directory grammar; this does not validate payloads or catalogue membership."""
    if not isinstance(path, (str, bytes, os.PathLike)):
        return False
    candidate = Path(os.fsdecode(path))
    if not candidate.is_absolute():
        return False
    try:
        relative = candidate.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return False
    if directory:
        return relative in {"facts", "checks"}
    return (relative in {"result.json", "MANIFEST.sha256"}
            or re.fullmatch(r"facts/[a-z][a-z0-9_]*\.jsonl", relative) is not None
            or re.fullmatch(r"checks/[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.jsonl", relative) is not None)


def engine_census():
    spec = importlib.util.find_spec("atlas_brain")
    if spec is None or spec.origin is None or not spec.submodule_search_locations:
        raise RuntimeError("engine package unavailable")
    root = Path(spec.origin).resolve().parent
    modules = {}
    for source in root.rglob("*.py"):
        if source.is_symlink() or not source.resolve().is_relative_to(root):
            raise RuntimeError("engine source link refused")
        parts = source.relative_to(root).with_suffix("").parts
        parts = parts[:-1] if parts[-1] == "__init__" else parts
        name = ".".join(("atlas_brain", *parts))
        if name in modules:
            raise RuntimeError("ambiguous engine source")
        modules[name] = str(source.resolve())
    if "atlas_brain" not in modules or len(modules) < 2:
        raise RuntimeError("engine witness exercised no modules")
    return sorted(modules.items())


def child_probe(args, payload) -> int:
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    violations, imported = [], []
    reason, code = None, 1
    terminate = os._exit
    sys.dont_write_bytecode = True
    mutations = {"os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.link", "os.symlink", "os.chmod", "os.chown", "os.utime", "os.truncate"}
    def audit(event, values):
        checked = False
        try:
            paths = []
            if event == "open" and values[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                paths = values[:1]
            elif event in mutations:
                paths = values[:2] if event in {"os.rename", "os.link", "os.symlink"} else values[:1]
            if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty", "os.startfile", "os.startfile/2", "os.link", "os.symlink"}:
                paths = [None]
            for path in paths:
                if not contract_path(path, root, directory=event == "os.mkdir"):
                    violations.append(event)
                    print(json.dumps({"nonce": payload["nonce"], "completed": False, "modules": imported,
                                      "violations": violations, "reason": "audit refusal"}), flush=True)
                    terminate(1)
            checked = True
        finally:
            if not checked:
                terminate(1)
    sys.addaudithook(audit)
    try:
        if args.probe == "engine":
            for name, expected_path in payload["census"]:
                module = importlib.import_module(name)
                if (Path(module.__file__).resolve() != Path(expected_path)
                        or Path(module.__spec__.origin).resolve() != Path(expected_path)):
                    raise RuntimeError("import origin differs from planned source")
                imported.append(name)
        elif args.probe == "launch":
            subprocess.run([sys.executable, "-c", "pass"], check=True)
        elif args.probe == "fork":
            if not hasattr(os, "fork"):
                reason, code = "fork probe unavailable", 2
            else:
                pid = os.fork()
                if pid == 0:
                    os._exit(0)
                os.waitpid(pid, 0)
        elif args.probe == "rename":
            target = root / "result.json"
            target.write_text("{}", encoding="utf-8")
            target.rename(root.parent / "forbidden")
        else:
            target = root / "result.json" if args.probe == "inside" else root / "notes.txt" if args.probe == "noncontract" else root.parent / "forbidden"
            target.write_text("{}", encoding="utf-8")
        if reason is None:
            code = int(bool(violations))
    except (RuntimeError, OSError, ImportError, SystemExit) as error:
        reason = type(error).__name__
    print(json.dumps({"nonce": payload["nonce"], "completed": code == 0, "modules": imported,
                      "violations": violations, "reason": reason}, sort_keys=True))
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--probe", choices=("engine", "inside", "noncontract", "outside", "rename", "launch", "fork"), default="engine")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        return child_probe(args, json.load(sys.stdin))
    nonce = secrets.token_hex(16)
    try:
        census = engine_census() if args.probe == "engine" else []
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--child", "--root", str(args.root), "--probe", args.probe],
            input=json.dumps({"nonce": nonce, "census": census}), capture_output=True, text=True, check=False,
            env={**os.environ, "PYTHONPATH": os.pathsep.join(str(Path(p).resolve()) for p in sys.path)},
        )
        receipt = json.loads(result.stdout)
        if not isinstance(receipt, dict) or receipt.get("nonce") != nonce:
            raise ValueError("missing completion receipt")
        completed = (result.returncode == 0 and not result.stderr and receipt.get("completed") is True
                     and receipt.get("modules") == [name for name, _ in census] and receipt.get("violations") == [])
        receipt.pop("nonce")
        receipt["completed"] = completed
        print(json.dumps(receipt, sort_keys=True))
        return 0 if completed else 2 if result.returncode == 2 else 1
    except (OSError, ValueError, RuntimeError, ImportError):
        print(json.dumps({"completed": False, "violations": [], "reason": "missing completion receipt or invalid census"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
