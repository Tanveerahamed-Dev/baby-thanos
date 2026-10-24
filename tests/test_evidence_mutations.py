"""Evidence-loss mechanics only: synthetic controls never become truth cases."""
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from tools.evidence_mutations import drop_form, truncate
from tools.provenance import record

TEMPLATE = Path("fixtures/validator-synthetic/provenance.yaml").read_text(encoding="utf-8")
TEMPLATE_HASH = sha256(Path("fixtures/validator-synthetic/raw.txt").read_bytes()).hexdigest()


def fixture(root, name, raw):
    directory = root / "fixtures" / name
    directory.mkdir(parents=True)
    text = TEMPLATE.replace(TEMPLATE.splitlines()[0], f"fixture_id: {name}")
    text = text.replace(TEMPLATE_HASH, sha256(raw).hexdigest())
    text = text.replace('path: "tests/test_provenance.py"', f'path: "fixtures/{name}/raw.txt"')
    (directory / "raw.txt").write_bytes(raw)
    (directory / "provenance.yaml").write_text(text, encoding="utf-8")
    return f"fixtures/{name}/provenance.yaml", sha256(raw).hexdigest()


class EvidenceMutationTests(unittest.TestCase):
    def test_drop_is_absent_and_zero_cut_is_present_empty(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            parent = fixture(root, "parent", b"sw-a is up\r\nstate: FULL\r\n")
            context = fixture(root, "population", b"independently supplied population\n")
            output, receipt = drop_form(root, *parent, (context,))
            self.assertIsNone(output)
            self.assertEqual(receipt["artifact"], {"present": False, "sha256": None})
            self.assertEqual(receipt["derived_attempt"], {"attempted": "unknown", "succeeded": "unknown"})
            self.assertEqual(receipt["retained_context"][0]["fixture_id"], "population")
            empty, truncated = truncate(root, *parent, 0)
            self.assertEqual(empty, b"")
            self.assertEqual(truncated["artifact"], {"present": True, "sha256": sha256(b"").hexdigest()})
            self.assertNotEqual(receipt["derivation_id"], truncated["derivation_id"])
            self.assertEqual((root / "fixtures/parent/raw.txt").read_bytes(), b"sw-a is up\r\nstate: FULL\r\n")

    def test_every_byte_cut_preserves_prefix_and_exact_deleted_span(self):
        raw = "sw-a é\r\nstate: FULL\r\nunterminated".encode()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            parent = fixture(root, "parent", raw)
            for cut in range(len(raw)):
                with self.subTest(cut=cut):
                    output, receipt = truncate(root, *parent, cut)
                    self.assertEqual(output, raw[:cut])
                    edit = receipt["edit"]
                    self.assertEqual(edit, {"start": cut, "end": len(raw), "after_hex": "",
                                            "removed_sha256": sha256(raw[cut:]).hexdigest()})
                    self.assertEqual(output + raw[edit["start"]:edit["end"]], raw)
                    self.assertNotIn("tier", receipt)
                    self.assertNotIn("truth", receipt)
                    self.assertEqual(receipt["qualification"], "unqualified")
                    self.assertEqual(receipt["capture_relationship"], "not_verified")

    def test_planted_missing_context_stale_digest_noop_and_invalid_cut(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            parent = fixture(root, "parent", b"FULL")
            context = fixture(root, "context", b"population")
            alias = fixture(root, "alias", b"FULL")
            same_source = fixture(root, "same-source", b"other bytes")
            same_path = root / same_source[0]
            same_path.write_bytes(same_path.read_bytes().replace(b"fixtures/same-source/raw.txt", b"fixtures/parent/raw.txt"))
            for references in ((), (parent,), (context, context), (alias,), (same_source,)):
                with self.subTest(references=references), self.assertRaises(ValueError):
                    drop_form(root, *parent, references)
            for cut in (-1, 4, 5, True, 1.5):
                with self.subTest(cut=cut), self.assertRaises(ValueError):
                    truncate(root, *parent, cut)
            with self.assertRaises(ValueError):
                truncate(root, parent[0], "0" * 64, 1)
            with self.assertRaises(ValueError):
                drop_form(root, *parent, ((context[0], "0" * 64),))
            for path in ("../provenance.yaml", "/provenance.yaml", "fixtures\\parent\\provenance.yaml",
                         "fixtures/parent/raw.txt", "fixtures/missing/provenance.yaml"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    truncate(root, path, parent[1], 1)

    def test_shared_gate_refuses_invalid_or_changed_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            parent = fixture(root, "parent", b"FULL")
            path = root / parent[0]
            original = path.read_bytes()
            for changed in (original.replace(b"tier: S", b"tier: M"),
                            original.replace(b"redistribution: public", b"redistribution: private_only")):
                path.write_bytes(changed)
                with self.assertRaises(ValueError):
                    truncate(root, *parent, 1)
            path.write_bytes(original)
            (path.parent / "orphan.txt").write_bytes(b"unrecorded")
            with self.assertRaises(ValueError):
                truncate(root, *parent, 1)
            (path.parent / "orphan.txt").unlink()
            for target in (path, path.parent / "raw.txt"):
                def change_after_validation(candidate, target=target):
                    admitted = record(candidate)
                    target.write_bytes(target.read_bytes() + b"\n")
                    return admitted
                with patch("tools.evidence_mutations.record", side_effect=change_after_validation), self.assertRaises(ValueError):
                    truncate(root, *parent, 1)
                path.write_bytes(original)
                (path.parent / "raw.txt").write_bytes(b"FULL")

    def test_linked_ancestor_is_refused_before_reading_fixture(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            parent = fixture(root, "parent", b"FULL")
            original = Path.is_symlink
            def linked(path):
                return path == root / "fixtures" or original(path)
            with patch.object(Path, "is_symlink", linked), self.assertRaises(ValueError):
                truncate(root, *parent, 1)

    def test_determinism_ignores_root_and_context_order(self):
        results = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                parent = fixture(root, "parent", b"FULL\n")
                a = fixture(root, "population-a", b"population a")
                b = fixture(root, "population-b", b"population b")
                first = drop_form(root, *parent, (a, b))
                self.assertEqual(first, drop_form(root, *parent, (b, a)))
                results.append(first)
        self.assertEqual(results[0], results[1])

    def test_real_q_source_preserves_unknowns_without_m_or_label_claim(self):
        parent = "fixtures/tier-p/nxos/show-interface/provenance.yaml"
        digest = "29a640c1c921fa7e6c685b6295f41c2b6898b57d2da290304c90ed6febbe7485"
        context = ("fixtures/tier-p/nxos/show-interface-status/provenance.yaml",
                   "3296040bf6d8fec6ae4db793794ab66d5fd36137ec0df3ab05069354e7f88094")
        raw = Path(parent).with_name("raw.txt").read_bytes()
        output, receipt = truncate(Path("."), parent, digest, raw.index(b"\n") + 1)
        self.assertEqual(output, raw[:raw.index(b"\n") + 1])
        self.assertEqual(receipt["parent"]["platform"]["version_basis"], "unknown")
        self.assertEqual(receipt["parent"]["capture"]["attempted"], None)
        self.assertEqual(receipt["parent"]["raw_sha256"], digest)
        self.assertEqual(receipt["parent"]["provenance_sha256"], sha256(Path(parent).read_bytes()).hexdigest())
        missing, dropped = drop_form(Path("."), parent, digest, (context,))
        self.assertIsNone(missing)
        self.assertEqual(dropped["qualification"], "unqualified")
        self.assertNotIn("tier", dropped)
        self.assertEqual(Path(parent).with_name("raw.txt").read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
