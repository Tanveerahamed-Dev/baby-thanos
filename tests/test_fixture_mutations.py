"""Fixture-bound state edits; all generated sources below are synthetic controls."""
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from tools.evidence_mutations import _snapshot, mutate_fixture
from tools.mutations import OPERATORS

TEMPLATE = Path("fixtures/validator-synthetic/provenance.yaml").read_text(encoding="utf-8")
TEMPLATE_HASH = sha256(Path("fixtures/validator-synthetic/raw.txt").read_bytes()).hexdigest()


def fixture(root, name, raw, changes=()):
    directory = root / "fixtures" / name
    directory.mkdir(parents=True, exist_ok=True)
    text = TEMPLATE.replace(TEMPLATE.splitlines()[0], f"fixture_id: {name}")
    text = text.replace(TEMPLATE_HASH, sha256(raw).hexdigest())
    text = text.replace('path: "tests/test_provenance.py"', f'path: "fixtures/{name}/raw.txt"')
    text = text.replace("family: unstated", "family: iosxe").replace("model: unstated", "model: synthetic-model")
    text = text.replace("version: unstated", "version: test-train").replace("version_basis: unknown", "version_basis: observed")
    for old, new in changes:
        text = text.replace(old, new)
    (directory / "raw.txt").write_bytes(raw)
    (directory / "provenance.yaml").write_text(text, encoding="utf-8")
    return f"fixtures/{name}/provenance.yaml", sha256(raw).hexdigest()


def edit(root, parent, witness):
    return mutate_fixture(root, parent, "ospf-state", 0, 4, b"EXSTART", witness, 0, 7)


class FixtureMutationTests(unittest.TestCase):
    def test_every_declared_transition_binds_two_snapshots_and_preserves_bytes(self):
        prefix = "sw-a é\r\n ".encode()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for operator, spec in OPERATORS.items():
                pairs = spec.transitions or {(min(spec.tokens), max(spec.tokens))}
                for before, after in sorted(pairs):
                    with self.subTest(operator=operator, before=before, after=after):
                        raw = prefix + before + b"/DR\r\n " + before
                        donor = b" " + after + b"/DR\r\n"
                        parent, witness = fixture(root, "parent", raw), fixture(root, "witness", donor)
                        args = (root, parent, operator, len(prefix), len(prefix) + len(before),
                                after, witness, 1, 1 + len(after))
                        output, receipt = mutate_fixture(*args)
                        self.assertEqual(output, prefix + after + raw[len(prefix) + len(before):])
                        self.assertEqual((output, receipt), mutate_fixture(*args))
                        self.assertEqual(receipt["parent"]["raw_sha256"], parent[1])
                        self.assertEqual(receipt["token_witness"]["snapshot"]["raw_sha256"], witness[1])
                        self.assertEqual(receipt["token_witness"]["span"], [1, 1 + len(after)])
                        self.assertEqual(receipt["edit"], {"start": len(prefix), "end": len(prefix) + len(before),
                                                          "before_hex": before.hex(), "after_hex": after.hex()})
                        self.assertEqual(receipt["sha256"], sha256(output).hexdigest())
                        self.assertEqual(receipt["qualification"], "unqualified")
                        self.assertEqual(receipt["witness_status"], "lexical_only")
                        self.assertEqual(receipt["capture_relationship"], "not_verified")
                        self.assertNotIn("tier", receipt)
                        self.assertNotIn("truth", receipt)
                        restored, _ = mutate_fixture(root, witness, operator, 1, 1 + len(after), before,
                                                     parent, len(prefix), len(prefix) + len(before))
                        self.assertEqual(restored, b" " + before + donor[1 + len(after):])
                        self.assertEqual((root / parent[0]).with_name("raw.txt").read_bytes(), raw)

    def test_planted_stale_parent_or_witness_and_missing_paths_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            parent, witness = fixture(root, "parent", b"FULL"), fixture(root, "witness", b"EXSTART")
            for changed in ((parent[0], "0" * 64), ("fixtures/missing/provenance.yaml", parent[1])):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    edit(root, changed, witness)
                with self.subTest(changed=changed, side="witness"), self.assertRaises(ValueError):
                    edit(root, parent, changed)

    def test_planted_unknown_mismatched_or_unsupported_family_train_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            parent = fixture(root, "parent", b"FULL")
            for changes in (
                (("family: iosxe", "family: nxos"),),
                (("family: iosxe", "family: other"),),
                (("version: test-train", "version: other-train"),),
                (("version: test-train", "version: unstated"), ("version_basis: observed", "version_basis: unknown")),
            ):
                with self.subTest(changes=changes):
                    witness = fixture(root, "witness", b"EXSTART", changes)
                    with self.assertRaisesRegex(ValueError, "family/train"):
                        edit(root, parent, witness)
                    changed_parent = fixture(root, "other-parent", b"FULL", changes)
                    clean_witness = fixture(root, "other-witness", b"EXSTART")
                    with self.assertRaisesRegex(ValueError, "family/train"):
                        edit(root, changed_parent, clean_witness)
            for changes in ((("family: iosxe", "family: other"),),
                            (("version: test-train", "version: unknown"),)):
                bad_parent = fixture(root, "bad-parent", b"FULL", changes)
                bad_witness = fixture(root, "bad-witness", b"EXSTART", changes)
                with self.subTest(both=changes), self.assertRaisesRegex(ValueError, "family/train"):
                    edit(root, bad_parent, bad_witness)

    def test_planted_absent_partial_or_undeclared_tokens_and_noop_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            parent = fixture(root, "parent", b"FULL")
            for raw, start, end in ((b"EXCHANGE", 0, 7), (b"EXSTARTED", 0, 7), (b"EXSTART", -1, 7)):
                witness = fixture(root, "witness", raw)
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    mutate_fixture(root, parent, "ospf-state", 0, 4, b"EXSTART", witness, start, end)
            witness = fixture(root, "witness", b"EXSTART")
            for operator, start, end, after in (("unknown", 0, 4, b"EXSTART"),
                                               ("ospf-state", True, 4, b"EXSTART"),
                                               ("ospf-state", 0, 4, b"invented")):
                with self.subTest(operator=operator, after=after), self.assertRaises(ValueError):
                    mutate_fixture(root, parent, operator, start, end, after, witness, 0, 7)
            with self.assertRaises(ValueError):
                mutate_fixture(root, parent, "ospf-state", 0, 4, b"FULL", parent, 0, 4)

    def test_conflicting_identity_alias_refuses_but_explicit_self_witness_works(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            parent = fixture(root, "parent", b"FULL EXSTART")
            output, receipt = mutate_fixture(root, parent, "ospf-state", 0, 4, b"EXSTART", parent, 5, 12)
            self.assertEqual(output, b"EXSTART EXSTART")
            self.assertEqual(receipt["parent"], receipt["token_witness"]["snapshot"])
            for changes in ((("fixture_id: witness", "fixture_id: parent"),),
                            (('path: "fixtures/witness/raw.txt"', 'path: "fixtures/parent/raw.txt"'),)):
                witness = fixture(root, "witness", b"EXSTART", changes)
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    edit(root, parent, witness)

    def test_source_bound_receipts_do_not_depend_on_absolute_root(self):
        results = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                parent, witness = fixture(root, "parent", b"FULL"), fixture(root, "witness", b"EXSTART")
                result = edit(root, parent, witness)
                self.assertEqual(result[1]["parent"]["provenance_sha256"], sha256((root / parent[0]).read_bytes()).hexdigest())
                self.assertEqual(result[1]["token_witness"]["snapshot"]["declared_source_tier"], "S")
                results.append(result)
        self.assertEqual(results[0], results[1])

    def test_one_path_cannot_name_two_different_sidecar_snapshots(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            parent = fixture(root, "parent", b"FULL EXSTART")
            changed = False
            def read_then_change(*args):
                nonlocal changed
                snapshot = _snapshot(*args)
                if not changed:
                    path = root / parent[0]
                    path.write_bytes(path.read_bytes() + b"\n")
                    changed = True
                return snapshot
            with patch("tools.evidence_mutations._snapshot", side_effect=read_then_change), self.assertRaises(ValueError):
                mutate_fixture(root, parent, "ospf-state", 0, 4, b"EXSTART", parent, 5, 12)

    def test_q_known_train_has_no_half_token_and_unversioned_source_is_not_attested(self):
        known = ("fixtures/tier-p/nxos/show-interface-status/provenance.yaml",
                 "3296040bf6d8fec6ae4db793794ab66d5fd36137ec0df3ab05069354e7f88094")
        unknown = ("fixtures/tier-p/nxos/show-interface/provenance.yaml",
                   "29a640c1c921fa7e6c685b6295f41c2b6898b57d2da290304c90ed6febbe7485")
        raw = Path(known[0]).with_name("raw.txt").read_bytes()
        start = raw.index(b"full")
        with self.assertRaises(ValueError):
            mutate_fixture(Path("."), known, "duplex", start, start + 4, b"half", known, start, start + 4)
        with self.assertRaisesRegex(ValueError, "family/train"):
            mutate_fixture(Path("."), unknown, "duplex", 0, 4, b"half", known, start, start + 4)


if __name__ == "__main__":
    unittest.main()
