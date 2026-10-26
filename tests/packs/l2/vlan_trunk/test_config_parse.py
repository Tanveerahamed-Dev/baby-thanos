"""Pure generated config grammar controls; no admission or device qualification."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.admission import AdmissionRefused
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.synthetic import Node
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.vlan_trunk import config_parse as parser

P, Q = "Gi1/0/1", "Gi1/0/2"
BODY = (b"interface Gi1/0/1\n switchport mode trunk\n switchport trunk native vlan 10\n"
        b" switchport trunk allowed vlan 10,20\n!\nend\n")


def fixture(raw):
    row = {"id": "a", "discovery_id": "sw-a", "ports": [P, Q]}
    registry = json.dumps({"group": "demo", "nodes": [row]}).encode()
    ref = k.RegistryRef(table="synthetic_p2.nodes", row_id="a",
                        table_digest=sha256(registry).hexdigest(), citation="/nodes/0")
    node = Node(group="demo", id="a", discovery_id="sw-a", ports=(P, Q),
                declaration=k.Known(value="a", basis=k.Basis.DECLARED, evidence=(ref,), raw="a"))
    capture = Capture(id=k.CaptureId("cap:" + sha256(raw).hexdigest()), source=node.key,
                      operation="iosxe.show_running_config", rendered="show running-config",
                      codec="utf-8", raw=raw, integrity=k.IntegrityState.COMPLETE,
                      lines=text_lines(raw, "utf-8"), read_scope=k.ReadScope.UNKNOWN,
                      view=k.ViewConsistency.UNKNOWN)
    return node, capture


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_sections_fields_and_exhaustive_accounting_retain_original_bytes(ending):
    raw = BODY.replace(b"\n", ending)
    node, capture = fixture(raw)
    doc = parser.parse_capture(capture, node)
    assert doc.capture is capture and doc.reason is None and doc.parse.quality == "complete"
    assert b"".join(raw[line.span.start:line.span.end] for line in doc.parse.lines) == raw
    section, = doc.sections
    assert section.kind == "interface" and section.name.raw == P
    assert raw[section.header.start:section.header.end] == b"interface " + P.encode()
    assert raw[section.name.span.start:section.name.span.end] == P.encode()
    assert [(key, value.raw) for key, value in section.entries] == [
        ("mode", "trunk"), ("native", "10"), ("allowed", "10,20")]
    for _, value in section.entries:
        assert raw[value.span.start:value.span.end] == value.raw.encode()


@pytest.mark.parametrize("opening,closing", [
    (b"", b""), (b"show running-config\n", b""),
    (b"unrelated-host#show running-config\n", b"unrelated-host#\n"),
    (b"Building configuration...\nCurrent configuration : 123 bytes\nversion 17.9\nhostname unrelated\n", b""),
])
def test_supported_wrappers_are_accounted_but_do_not_supply_identity(opening, closing):
    node, capture = fixture(opening + BODY + closing)
    doc = parser.parse_capture(capture, node)
    assert doc.reason is None and capture.source == node.key == "node:demo:a"


@pytest.mark.parametrize("raw", [
    BODY.removesuffix(b"end\n"), BODY + b"interface Gi1/0/1\n",
    BODY + b"end\n", b"sw-a#show running-config\n" + BODY + b"sw-b#\n",
    b"hostname unrelated\nversion 17.9\n" + BODY, b"version 17.9\nversion 17.9\n" + BODY,
    BODY.replace(b" switchport mode trunk", b" strange-command trunk"),
    BODY.replace(b"!\nend\n", b"!\nsw-a#show interfaces\nend\n"),
])
def test_missing_end_late_data_and_mixed_context_poison_the_whole_document(raw):
    node, capture = fixture(raw)
    doc = parser.parse_capture(capture, node)
    assert doc.reason is k.UnknownReason.PARSE_PARTIAL


@pytest.mark.parametrize("line", [
    b" source template EDGE merge", b"interface range Gi1/0/1 - 2", b"port-profile EDGE",
    b"dynamic-template EDGE", b" switchport trunk allowed vlan add 30",
    b" switchport trunk allowed vlan remove 10", b" switchport trunk allowed vlan except 20",
    b" default switchport trunk native vlan", b" no switchport trunk native vlan",
    b" no shutdown",
])
def test_unadmitted_inheritance_and_delta_forms_have_a_distinct_node_wide_reason(line):
    node, capture = fixture(BODY.replace(b"!\nend\n", line + b"\n!\nend\n"))
    doc = parser.parse_capture(capture, node)
    assert doc.reason is k.UnknownReason.PARSE_UNSUPPORTED_VARIANT


@pytest.mark.parametrize("line", [b"interface Gi1/0/99\n", b"interface Gi1/0/99 malformed\n"])
def test_observed_undeclared_local_mentions_are_never_silently_discarded(line):
    node, capture = fixture(BODY.replace(b"end\n", line + b"end\n"))
    with pytest.raises(AdmissionRefused, match="synthetic_undeclared_port"):
        parser.parse_capture(capture, node)


def test_duplicate_attributes_are_retained_for_resolver_conflict_not_dropped():
    raw = BODY.replace(b" switchport trunk native vlan 10\n", b" switchport trunk native vlan 10\n" * 2)
    node, capture = fixture(raw)
    doc = parser.parse_capture(capture, node)
    section, = doc.sections
    assert len([entry for entry in section.entries if entry[0] == "native"]) == 2


@pytest.mark.parametrize("integrity,reason", [
    (k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED),
])
def test_capture_integrity_cannot_be_repaired_by_plausible_configuration(integrity, reason):
    node, capture = fixture(BODY)
    doc = parser.parse_capture(replace(capture, integrity=integrity), node)
    assert doc.reason is reason


@pytest.mark.parametrize("change", [
    {"source": k.EntityKey("node:demo:b")}, {"operation": "iosxe.show_interfaces_trunk"},
    {"rendered": "show running-config interface Gi1/0/1"}, {"codec": "latin-1"},
])
def test_capture_identity_operation_and_codec_are_not_inferred_from_body(change):
    node, capture = fixture(BODY)
    with pytest.raises(ValueError, match="^unsupported_config_capture$"):
        parser.parse_capture(replace(capture, **change), node)


@pytest.mark.parametrize("metadata", [
    b"Building configuration...", b"Current configuration : 123 bytes", b"version 17.9", b"hostname unrelated",
])
def test_wrapper_metadata_cannot_restart_after_a_configuration_block(metadata):
    node, capture = fixture(BODY.replace(b"!\nend\n", b"!\n" + metadata + b"\nend\n"))
    doc = parser.parse_capture(capture, node)
    assert doc.reason is k.UnknownReason.PARSE_PARTIAL and doc.parse.quality == "partial"


def test_template_and_exact_binding_retain_definition_edge_and_header_spans():
    raw = (b"template EDGE\n switchport mode trunk\n switchport trunk native vlan 10\n!\n"
           b"interface Gi1/0/1\n source template EDGE\n!\nend\n")
    node, capture = fixture(raw)
    doc = parser.parse_capture(capture, node)
    assert doc.reason is None and doc.parse.quality == "complete"
    assert [(section.kind, section.name.raw) for section in doc.sections] == [
        ("template", "EDGE"), ("interface", P)]
    parent, child = doc.sections
    key, binding = child.entries[0]
    assert (key, binding.raw, binding.value) == ("source", "EDGE", "EDGE")
    assert raw[binding.span.start:binding.span.end] == b"EDGE"
    for section in (parent, child):
        assert raw[section.header.start:section.header.end] == (
            section.kind + " " + section.name.raw).encode()
    assert b"".join(raw[line.span.start:line.span.end] for line in doc.parse.lines) == raw


@pytest.mark.parametrize("kind,name", [("interface", P), ("template", "EDGE")])
def test_duplicate_block_identities_and_distinct_spans_survive_for_the_resolver(kind, name):
    block = (kind + " " + name + "\n switchport trunk native vlan 10\n!\n").encode()
    node, capture = fixture(block * 2 + b"end\n")
    doc = parser.parse_capture(capture, node)
    assert doc.reason is None and len(doc.sections) == 2
    left, right = doc.sections
    assert (left.kind, left.name.raw) == (right.kind, right.name.raw) == (kind, name)
    assert left.header != right.header and left.entries[0][1].span != right.entries[0][1].span
    assert left.entries[0][1].raw == right.entries[0][1].raw == "10"


@pytest.mark.parametrize("kind,token,expected", [
    ("native", "1", 1), ("native", "4094", 4094), ("native", "0", None),
    ("native", "4095", None), ("native", "001", None), ("native", "10000", None),
    ("allowed", "none", "none"), ("allowed", "all", "1-4094"),
    ("allowed", "1-3,2", "1-3"), ("allowed", "01", None),
])
def test_canonical_value_boundaries_are_explicit_not_defaults(kind, token, expected):
    assert parser.canonical_value(kind, token) == expected
