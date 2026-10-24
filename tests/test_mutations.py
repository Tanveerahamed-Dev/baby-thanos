"""Planted counterexamples; all in-memory attestations below are synthetic test doubles."""
import os
import subprocess
import sys
import unittest
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

from tools.mutations import OPERATORS, Capture, apply_span, mutate
from tools.provenance import validate_tree

CASES = (
    ("ospf-state", b"FULL", b"EXSTART"),
    ("duplex", b"full", b"half"),
    ("duplex", b"a-full", b"a-half"),
    ("duplex", b"Full-duplex", b"Half-duplex"),
    ("psu-state", b"OK", b"Absent"),
    ("native-vlan", b"1", b"20"),
    ("err-disabled", b"connected", b"err-disabled"),
    ("admin-up-oper-down", b"is up, line protocol is up", b"is up, line protocol is down"),
    ("admin-up-oper-down", b"is up", b"is down"),
    ("mtu", b"1500", b"1400"),
    ("duplicate-address", b"192.0.2.1", b"192.0.2.2"),
)


def capture(raw, **changes):
    # Deliberately self-declared data: it must never receive a source tier.
    result = Capture("synthetic-double", "iosxe", "test-train", "P", raw,
                     sha256(raw).hexdigest(), "fixtures/mutations/test-double")
    return replace(result, **changes)


class MutationTests(unittest.TestCase):
    def test_entire_fixture_tree_passes_shared_provenance_gate(self):
        self.assertEqual(validate_tree(Path("fixtures")), [])

    def test_planted_self_declared_sources_never_assign_tier_m(self):
        for tier in ("H", "L", "P"):
            with self.subTest(tier=tier):
                parent = capture(b"FULL", tier=tier, provenance="fixtures/missing-parent/provenance.yaml")
                witness = capture(b"EXSTART", tier=tier, provenance="fixtures/missing-witness/provenance.yaml")
                output, receipt = mutate(parent, "ospf-state", 0, 4, b"EXSTART", witness, 0, 7)
                self.assertEqual(output, b"EXSTART")
                self.assertNotIn("tier", receipt)
                self.assertEqual(receipt["qualification"], "unqualified")
                self.assertEqual(receipt["source"]["kind"], "unqualified_text_edit")

    def test_all_operators_have_exact_deterministic_edits_and_controls(self):
        self.assertEqual({c[0] for c in CASES}, set(OPERATORS))
        for operator, before, after in CASES:
            with self.subTest(operator=operator, before=before):
                prefix = "sw-a é\r\n ".encode()
                raw = prefix + before + b" /DR\r\n " + before
                start, end = len(prefix), len(prefix) + len(before)
                expected = prefix + after + raw[end:]
                self.assertIn(before, OPERATORS[operator].tokens)
                self.assertIn(after, OPERATORS[operator].tokens)
                self.assertEqual(apply_span(raw, operator, start, end, after), expected)
                self.assertEqual(apply_span(expected, operator, start, start + len(after), before), raw)
                witness = capture(b" " + after + b"\r\n", fixture_id="witness-double")
                args = (capture(raw), operator, start, end, after, witness, 1, 1 + len(after))
                output, receipt = mutate(*args)
                self.assertEqual((output, receipt), mutate(*args))
                self.assertEqual(output, expected)
                self.assertNotIn("tier", receipt)
                self.assertEqual(receipt["qualification"], "unqualified")
                self.assertEqual(receipt["source"]["parent_fixture"], "synthetic-double")
                self.assertEqual(receipt["sha256"], sha256(output).hexdigest())
                self.assertEqual(receipt["edit"], {"start": start, "end": end,
                                                  "before_hex": before.hex(), "after_hex": after.hex()})
                self.assertEqual(receipt["source"]["token_witness"]["span"], [1, 1 + len(after)])
                self.assertEqual(receipt["source"]["parent_sha256"], sha256(raw).hexdigest())
                self.assertEqual(receipt["source"]["parent_provenance"], args[0].provenance)

    def test_planted_absent_undeclared_substring_and_invalid_spans_refused(self):
        for raw, operator, start, end, after in (
            (b"DOWN", "ospf-state", 0, 4, b"EXSTART"),
            (b"FULL", "ospf-state", 0, 4, b"invented"),
            (b"FULL", "missing", 0, 4, b"EXSTART"),
            (b"FULLNESS", "ospf-state", 0, 4, b"EXSTART"),
            (b"a-full", "duplex", 2, 6, b"half"),
            (b"full", "duplex", -1, 4, b"half"),
            (b"full", "duplex", 0, 5, b"half"),
            (b"full", "duplex", 2, 2, b"half"),
            (b"full", "duplex", True, 4, b"half"),
            (b"full", "duplex", 0, 4, b"full"),
            (b"1", "native-vlan", 0, 1, b"4095"),
            (b"1500", "mtu", 0, 4, b"0"),
            (b"192.0.2.1", "duplicate-address", 0, 9, b"192.0.2.0"),
        ):
            with self.subTest(raw=raw, operator=operator, start=start), self.assertRaises(ValueError):
                apply_span(raw, operator, start, end, after)

    def test_planted_wrong_witness_and_untrusted_capture_metadata_refused(self):
        parent, witness = capture(b"FULL"), capture(b"EXSTART")
        for changed in (
            {"family": "nxos"}, {"train": "other-train"}, {"train": None},
            {"train": "unknown"}, {"train": " unknown "}, {"train": "unstated"}, {"tier": "M"}, {"tier": "S"},
            {"sha256": "0" * 64}, {"provenance": ""}, {"fixture_id": ""},
        ):
            for side in ("parent", "witness"):
                with self.subTest(changed=changed, side=side):
                    p = replace(parent, **changed) if side == "parent" else parent
                    w = replace(witness, **changed) if side == "witness" else witness
                    with self.assertRaises(ValueError):
                        mutate(p, "ospf-state", 0, 4, b"EXSTART", w, 0, 7)
        for w, start, end in ((capture(b"EXCHANGE"), 0, 7), (witness, -1, 7),
                              (capture(b"EXSTARTED"), 0, 7), (witness, 0, 8)):
            with self.subTest(witness=w.raw), self.assertRaises(ValueError):
                mutate(parent, "ospf-state", 0, 4, b"EXSTART", w, start, end)

    def test_declared_transition_set_and_numeric_endpoints(self):
        for operator, declaration in OPERATORS.items():
            for before, after in declaration.transitions:
                with self.subTest(operator=operator, before=before, after=after):
                    self.assertEqual(apply_span(before, operator, 0, len(before), after), after)
        for operator, before, after in (("native-vlan", b"1", b"4094"),
                                        ("mtu", b"68", b"65535")):
            self.assertEqual(apply_span(before, operator, 0, len(before), after), after)
        with self.assertRaises(TypeError):
            OPERATORS["injected"] = OPERATORS["duplex"]

    def test_receipt_is_identical_across_processes_and_hash_seeds(self):
        script = (
            "import json\n"
            "from hashlib import sha256\n"
            "from tools.mutations import Capture, mutate\n"
            "def double(raw):\n"
            "    return Capture('double', 'nxos', 'test-train', 'P', raw, sha256(raw).hexdigest(), 'fixtures/double')\n"
            "out, receipt = mutate(double(b'FULL'), 'ospf-state', 0, 4, b'EXSTART', double(b'EXSTART'), 0, 7)\n"
            "print(json.dumps([out.hex(), receipt], sort_keys=True, separators=(',', ':')))\n"
        )
        outputs = [subprocess.check_output([sys.executable, "-c", script],
                   env=dict(os.environ, PYTHONHASHSEED=seed)) for seed in ("1", "98765")]
        self.assertEqual(outputs[0], outputs[1])

    def test_pinned_q_inputs_refuse_unsupported_tier_m_claims(self):
        root = Path("fixtures/mutations/q")
        cases = (
            ("nxos/show-interface-status", "nxos", "6.2(14)", "duplex", b"full", b"half",
             "3296040bf6d8fec6ae4db793794ab66d5fd36137ec0df3ab05069354e7f88094"),
            ("nxos/show-interface", "nxos", None, "admin-up-oper-down", b"is up", b"is down",
             "29a640c1c921fa7e6c685b6295f41c2b6898b57d2da290304c90ed6febbe7485"),
            ("nxos/show-environment", "nxos", None, "psu-state", b"Ok", b"Absent",
             "747fa1adb364620e04f98828366d3be13ded0dd4b7b1480d83d16b681a8d7557"),
            ("iosxe/show-interfaces-trunk", "iosxe", None, "native-vlan", b"1", b"20",
             "4aeed8b2d8544e6cd36573dcdc96b4d5ee600f3376a67637f3abe29c6b2f96e3"),
        )
        for path, family, train, operator, before, after, digest in cases:
            with self.subTest(path=path):
                raw = (root / path / "raw.txt").read_bytes()
                self.assertEqual(sha256(raw).hexdigest(), digest)
                start = raw.index(before) if operator != "native-vlan" else raw.index(b"not-trunking  1") + 14
                source = Capture(path, family, train, "P", raw, digest,
                                 f"{root.as_posix()}/{path}/provenance.yaml")
                with self.assertRaises(ValueError):
                    mutate(source, operator, start, start + len(before), after, source, 0, len(after))
                edited = apply_span(raw, operator, start, start + len(before), after)
                self.assertEqual(edited, raw[:start] + after + raw[start + len(before):])


if __name__ == "__main__":
    unittest.main()
