"""Pure generated static-template resolution; no defaults or precedence guesses."""
import json
from hashlib import sha256

import pytest

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.synthetic import Node
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.vlan_trunk import config_parse as parser
from atlas_brain.packs.l2.vlan_trunk import config_resolve as resolver

P, Q = "Gi1/0/1", "Gi1/0/2"
ATTRS = " switchport mode trunk\n switchport trunk native vlan 10\n switchport trunk allowed vlan 10,20\n"
CHAIN = (b"template BASE\n switchport mode trunk\n switchport trunk native vlan 10\n!\n"
         b"template EDGE\n source template BASE\n switchport trunk allowed vlan 10,20\n!\n"
         b"interface Gi1/0/1\n source template EDGE\n!\nend\n")


def rows(raw):
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
    return resolver.resolve(parser.parse_capture(capture, node), node)


def point(raw):
    return next(row for row in rows(raw) if row.port == P)


def direct(commands=ATTRS):
    return ("interface " + P + "\n" + commands + "!\nend\n").encode()


def chain(edges):
    return ("".join("template T" + str(index) + "\n"
                    + (" source template T" + str(index + 1) + "\n" if index < edges else ATTRS)
                    + "!\n" for index in range(1, edges + 1))
            + "interface " + P + "\n source template T1\n!\nend\n").encode()


def test_real_inherited_values_retain_every_binding_header_and_operand_span():
    row = point(CHAIN)
    assert (row.mode.value, row.native.value, row.allowed.value) == ("trunk", 10, "10,20")
    required = {b"template BASE", b"template EDGE", b"interface Gi1/0/1", b"BASE", b"EDGE"}
    for value in (row.mode, row.native, row.allowed):
        assert isinstance(value, resolver.ConfigValue)
        assert all(0 <= span.start < span.end <= len(CHAIN) for span in value.spans)
        assert required <= {CHAIN[span.start:span.end] for span in value.spans}
    assert b"trunk" in {CHAIN[s.start:s.end] for s in row.native.spans}
    assert b"10" in {CHAIN[s.start:s.end] for s in row.native.spans}
    assert b"10,20" in {CHAIN[s.start:s.end] for s in row.allowed.spans}


@pytest.mark.parametrize("extra", [" switchport trunk native vlan 10\n",
                                   " switchport trunk allowed vlan 20,10\n"])
def test_equal_and_disjoint_definitions_across_blocks_need_no_precedence_choice(extra):
    row = point(CHAIN.replace(b" source template EDGE\n", b" source template EDGE\n" + extra.encode()))
    assert (row.mode.value, row.native.value, row.allowed.value) == ("trunk", 10, "10,20")


@pytest.mark.parametrize("raw", [
    CHAIN.replace(b"template BASE\n switchport mode trunk\n switchport trunk native vlan 10\n!\n", b""),
    CHAIN.replace(b"template BASE\n", b"template BASE\n source template EDGE\n"),
    CHAIN.replace(b" source template EDGE\n", b" source template EDGE\n source template BASE\n"),
    CHAIN.replace(b" source template EDGE\n", b" source template EDGE\n source template EDGE\n"),
    direct(ATTRS + " source template MISSING\n"),
])
def test_graph_gaps_are_not_hidden_by_direct_values_or_identical_parent_bindings(raw):
    row = point(raw)
    assert all(isinstance(value, resolver.ConfigGap)
               and value.reason is k.UnknownReason.INHERITANCE_UNRESOLVED
               for value in (row.mode, row.native, row.allowed))


@pytest.mark.parametrize("raw", [
    CHAIN.replace(b" source template EDGE\n", b" source template EDGE\n switchport trunk native vlan 20\n"),
    direct(ATTRS + " switchport trunk native vlan 10\n"),
    CHAIN.replace(b"template EDGE\n", b"template BASE\n!\ntemplate EDGE\n"),
    direct().removesuffix(b"end\n") + direct(),
])
def test_duplicate_blocks_attributes_and_conflicting_layers_never_vote_or_take_last(raw):
    row = point(raw)
    assert isinstance(row.native, resolver.ConfigGap) and row.native.reason is k.UnknownReason.CONFLICTING_EVIDENCE


@pytest.mark.parametrize("edges,reason", [(16, None), (17, k.UnknownReason.BUDGET_EXCEEDED)])
def test_depth_counts_interface_to_first_template_as_parent_edge_one(edges, reason):
    row = point(chain(edges))
    if reason is None:
        assert (row.mode.value, row.native.value, row.allowed.value) == ("trunk", 10, "10,20")
    else:
        assert all(isinstance(value, resolver.ConfigGap) and value.reason is reason
                   for value in (row.mode, row.native, row.allowed))


@pytest.mark.parametrize("mode,value", [(" switchport mode access\n", "access"), (" no switchport\n", "routed")])
def test_access_and_explicit_routed_mode_do_not_create_trunk_operands(mode, value):
    row = point(direct(ATTRS.replace(" switchport mode trunk\n", mode)))
    assert isinstance(row.mode, resolver.ConfigValue) and row.mode.value == value
    assert all(isinstance(field, resolver.ConfigGap) and field.reason is k.UnknownReason.NOT_OBSERVABLE
               for field in (row.native, row.allowed))


@pytest.mark.parametrize("missing", ["mode", "native", "allowed"])
def test_omitted_properties_have_no_implicit_native_one_or_allowed_all(missing):
    commands = {"mode": " switchport mode trunk\n", "native": " switchport trunk native vlan 10\n",
                "allowed": " switchport trunk allowed vlan 10,20\n"}
    row = point(direct("".join(value for key, value in commands.items() if key != missing)))
    fields = (row.mode, row.native, row.allowed) if missing == "mode" else (getattr(row, missing),)
    assert all(isinstance(value, resolver.ConfigGap) and value.reason is k.UnknownReason.DEFAULT_UNKNOWN
               for value in fields)


@pytest.mark.parametrize("line,reason", [
    (b" source template EDGE merge\n", k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    (b" strange-command value\n", k.UnknownReason.PARSE_PARTIAL),
])
def test_document_poison_reaches_every_declared_endpoint_including_unobserved_ones(line, reason):
    result = rows(CHAIN.replace(b"template BASE\n", b"template BASE\n" + line))
    assert tuple(row.port for row in result) == (P, Q)
    assert all(isinstance(value, resolver.ConfigGap) and value.reason is reason
               for row in result for value in (row.mode, row.native, row.allowed))


def test_template_names_are_case_sensitive_not_alias_guesses():
    row = point(CHAIN.replace(b" source template EDGE\n", b" source template edge\n"))
    assert row.mode.reason is k.UnknownReason.INHERITANCE_UNRESOLVED
