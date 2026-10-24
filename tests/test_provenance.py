import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.provenance import validate_tree

RAW = b"synthetic output\r\n"
RECORD = Path("fixtures/validator-synthetic/provenance.yaml").read_text(encoding="utf-8")


class ProvenanceTests(unittest.TestCase):
    def check_tree(self, record=RECORD, raw=RAW, extra=None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "fixtures"
            case = root / "example"
            case.mkdir(parents=True)
            (case / "raw.txt").write_bytes(raw)
            if record is not None:
                (case / "provenance.yaml").write_text(record, encoding="utf-8")
            if extra:
                (case / extra).write_bytes(b"unrecorded")
            return validate_tree(root)

    def test_planted_missing_record(self):
        self.assertTrue(self.check_tree(None))

    def test_planted_hash_mismatch_and_line_ending_change(self):
        self.assertTrue(self.check_tree(raw=RAW.replace(b"\r\n", b"\n")))

    def test_every_required_field_is_enforced(self):
        for line in RECORD.splitlines(keepends=True):
            if line.strip():
                with self.subTest(field=line.strip().split(":")[0]):
                    self.assertTrue(self.check_tree(RECORD.replace(line, "", 1)))

    def test_planted_invalid_values(self):
        for old, new in [
            ("tier: S", "tier: excluded"), ("tier: S", "tier: H"),
            ("tier: S", "tier: L"), ("kind: synthetic", "kind: library_testdata"),
            ("redistribution: public", "redistribution: unknown"),
            ("redistribution: public", "redistribution: private_only"),
            ("redistribution: public", "redistribution: link_only"),
            ('name: Apache-2.0', 'name: ""'),
            (next(line.strip() for line in RECORD.splitlines() if line.strip().startswith("notice:")), "notice: null"),
            ('"7324467b2a0e910c32c9ea9a497163ff242ec4b6"', '"main"'),
            ("https://github.com/Tanveerahamed-Dev/atlas-brain-staging", "file:///corpus"),
            ('path: "tests/test_provenance.py"', 'path: "../raw.txt"'),
            ("file: raw.txt", "file: ../raw.txt"),
            ('version: unstated', 'version: "17.1"'),
            ("version_basis: unknown", "version_basis: observed"),
        ]:
            with self.subTest(value=new):
                self.assertTrue(self.check_tree(RECORD.replace(old, new)))

    def test_planted_unsupported_yaml(self):
        for text in [
            RECORD + "tier: S\n", RECORD + "extra: value\n",
            RECORD.replace("tier: S", "tier: &anchor S"),
            RECORD.replace("tier: S", "tier: *anchor"),
            RECORD.replace("tier: S", "tier: [S]"),
            RECORD.replace("tier: S", "tier: {value: S}"),
            RECORD.replace("tier: S", "tier: S # comment"),
            RECORD.replace("tier: S", "tier: 'S'"),
            RECORD.replace("tier: S", "tier: |\n  S"),
            RECORD.replace("  kind:", "\tkind:"), "---\n" + RECORD,
            RECORD.replace("source:\n", "source: null\n"),
            RECORD.replace("source:\n", "source:\n    nested: value\n"),
        ]:
            with self.subTest(record=text):
                self.assertTrue(self.check_tree(text))

    def test_planted_unrecorded_extra_and_reserved_name(self):
        self.assertTrue(self.check_tree(extra="extra.txt"))
        self.assertTrue(self.check_tree(RECORD.replace("file: raw.txt", "file: provenance.yaml")))

    def test_positive_synthetic_and_public_stated_or_unstated(self):
        self.assertEqual(self.check_tree(), [])
        public = RECORD.replace("tier: S", "tier: P").replace("kind: synthetic", "kind: library_testdata")
        self.assertEqual(self.check_tree(public.replace("family: unstated", "family: iosxe")), [])
        stated = public.replace("family: unstated", "family: iosxe").replace("model: unstated", "model: C8000V").replace("version: unstated", 'version: "17.1"').replace("version_basis: unknown", "version_basis: source_stated")
        self.assertEqual(self.check_tree(stated), [])

    def test_cli_refuses_orphan_record_and_missing_explicit_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "fixtures"
            result = subprocess.run([sys.executable, "tools/provenance.py", str(root)], capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            root.mkdir()
            self.assertEqual(validate_tree(root), [])
            (root / "provenance.yaml").write_text(RECORD, encoding="utf-8")
            self.assertTrue(validate_tree(root))

    def test_q_capture_privacy_and_inventory_extensions(self):
        extended = RECORD + "\ncapture:\n  tool: unstated\n  form: synthetic.raw\n  utc: null\n  attempted: null\n  succeeded: null\n  read_scope: unstated\nline_count: 1\nformat_floor: false\n"
        self.assertEqual(self.check_tree(extended), [])
        for old, new in [("succeeded: null", "succeeded: true"), ("result: pass", "result: fail"), ("line_count: 1", "line_count: true"), ("format_floor: false", "format_floor: true")]:
            self.assertTrue(self.check_tree(extended.replace(old, new)))
    def test_planted_floor_is_deferred_to_parser_census(self):
        stated = RECORD.replace("tier: S", "tier: P").replace("kind: synthetic", "kind: library_testdata").replace("family: unstated", "family: iosxe").replace("model: unstated", "model: C8000V").replace("version: unstated", 'version: "17.1"').replace("version_basis: unknown", "version_basis: source_stated")
        for raw in (RAW, b""):
            record = stated.replace(hashlib.sha256(RAW).hexdigest(), hashlib.sha256(raw).hexdigest())
            self.assertTrue(self.check_tree(record + "format_floor: true\nline_count: " + str(int(bool(raw))) + "\n", raw))

    def test_planted_missing_privacy_record(self):
        self.assertTrue(self.check_tree(RECORD.split("\nprivacy:", 1)[0] + "\n"))

    def test_capture_utc_requires_zero_offset(self):
        capture = "capture:\n  tool: unstated\n  form: synthetic.raw\n  utc: TIME\n  attempted: null\n  succeeded: null\n  read_scope: unstated\n"
        for stamp in ('"2026-10-20T12:00:00Z"', '"2026-10-20T12:00:00+00:00"'):
            self.assertEqual(self.check_tree(RECORD + capture.replace("TIME", stamp)), [])
        self.assertTrue(self.check_tree(RECORD + capture.replace("TIME", '"2026-10-20T15:00:00+03:00"')))
    def test_planted_duplicate_ids_and_invalid_encoding(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "fixtures"
            for name in ("first", "second"):
                case = root / name
                case.mkdir(parents=True)
                (case / "raw.txt").write_bytes(RAW)
                (case / "provenance.yaml").write_text(RECORD, encoding="utf-8")
            self.assertTrue(validate_tree(root))
            (root / "second" / "provenance.yaml").write_bytes(b"\xff")
            self.assertTrue(validate_tree(root))
    def test_planted_symlink_file_directory_and_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "fixtures"
            root.mkdir()
            target = Path(folder) / "target"
            target.mkdir()
            link = root / "linked"
            if sys.platform == "win32":
                subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)
                self.assertTrue(link.is_junction())
            else:
                link.symlink_to(target, target_is_directory=True)
            self.assertTrue(validate_tree(root))
            self.assertTrue(validate_tree(link))
            if sys.platform == "win32":
                link.rmdir()
                return
            link.unlink()
            (root / "dangling.txt").symlink_to(target / "missing")
            self.assertTrue(validate_tree(root))
