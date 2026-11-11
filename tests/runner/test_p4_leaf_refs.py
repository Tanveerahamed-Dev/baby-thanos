import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.p4_admission import SCHEMA
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import global_parse as gp
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.runner import p4_refs as r

P = "GigabitEthernet1/0/1"
LIMITS = Budgets(1000000, 1000000, 1000)


def estate(root, guard=b"enabled", protocol=b"LACP", ending=b"\n", trailer=b""):
    discovery = b"Device ID: fixture-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": n, "discovery_id": "fixture-" + n, "ports": [P, "Gi1/0/1", "Gi1/0/2"]} for n in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail", "sha256": sha256(discovery).hexdigest()}]})
    tree = b"".join(f"Port 1 ({P}) of VLAN{v:04} is designated forwarding\n".encode() +
        (b"   Root guard is " + guard + b" on the port\n" if guard else b"") for v in (1, 2)) + trailer
    channel = (b"Number of channel-groups in use: 2\nNumber of aggregators: 2\nGroup Port-channel Protocol Ports\n"
        b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n2 Po2(SD) " + protocol + b" Gi1/0/2(D)\n")
    files = {"p2.json": base, "discovery.txt": discovery, "tree.txt": tree.replace(b"\n", ending), "ec.txt": channel.replace(b"\n", ending)}
    side = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "context": "round", "base_sha256": sha256(base).hexdigest(),
        "targets": [{"id": "tree", "node": "a", "operation": stp.stp.OP, "params": {"port": P, "vlans": [3, 2, 1]}},
                    {"id": "ec", "node": "b", "operation": ec.parse_summary.OP, "params": {"groups": ["3", "2", "1"], "ports": ["Gi1/0/1", "Gi1/0/2"]}},
                    {"id": "cold", "node": "a", "operation": ec.parse_summary.OP, "params": {"groups": ["4"], "ports": []}}],
        "captures": [{"target": t, "path": t + ".txt", "sha256": sha256(files[t + ".txt"]).hexdigest()} for t in ("tree", "ec")]}
    for path, raw in (files | {"p4.json": canonical(side)}).items():
        (root / path).write_bytes(raw)
    return side


def execute(root):
    peer = gp.SummaryPack[stp.stp.Result](LIMITS)
    tree = stp.build_root_guard_global(root, LIMITS, peers=(peer,))
    return tree, peer.finish(tree.execution)


def assert_leaf(original, leaf, execution):
    envelope = execution.envelope
    if type(original) is k.RegistryRef:
        raw = envelope.base.raw if original.table.startswith("synthetic_p2") else envelope.raw
        value = json.loads(raw)
        for part in original.citation.split("/")[1:]:
            value = value[int(part)] if type(value) is list else value[part]
        assert leaf == {"kind": "registry", "table": original.table, "row_id": original.row_id,
                        "table_digest": sha256(raw).hexdigest(), "citation": original.citation, "value": value}
    else:
        capture = next(o.receipt.capture for o in execution.executed if o.receipt.capture.id == original.capture)
        member = next(m for m in envelope.captures if m.id == original.capture)
        common = {"kind": "capture", "capture": capture.id, "target": member.target.id, "path": member.path,
                  "source": capture.source, "operation": capture.operation, "rendered": capture.rendered,
                  "role": str(original.role), "sha256": original.excerpt_sha256, "capture_sha256": capture.bytes_sha256}
        if type(original.locator) is k.ByteSpan:
            raw = capture.raw[original.locator.start:original.locator.end]
            common.update(locator="bytes", start=original.locator.start, end=original.locator.end)
        else:
            raw = capture.raw
            common["locator"] = "whole_capture"
        assert leaf == common and original.excerpt_sha256 == sha256(raw).hexdigest()


@pytest.mark.parametrize("guard,protocol", [(b"enabled", b"LACP"), (b"disabled", b"-")])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_real_owners_resolve_all_original_refs_without_reparsing_or_losing_false_dash(tmp_path, monkeypatch, guard, protocol, ending):
    estate(tmp_path, guard, protocol, ending)
    tree, channel = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    for module in (stp.stp, ec.parse_summary):
        monkeypatch.setattr(module, "parse_capture", lambda *args: pytest.fail("leaf resolver reparsed input"))
    rows = [(stp.ROOT_GUARD, row) for row in tree.result.rows] + [(ec.REPORTED_PROTOCOL, row) for row in channel.rows]
    for fact, row in rows:
        scope = index.scope(fact, row.subject)
        assert row.value.evidence[:3] == scope.declarations
        assert all(a is not b for a, b in zip(row.value.evidence[:3], scope.declarations, strict=True))
        leaves = index.resolve(scope, row.value.evidence, positive=type(row.value) is k.Known)
        for original, projected in zip(row.value.evidence, leaves, strict=True):
            assert_leaf(original, projected, tree.execution)
    assert tree.result.rows[0].value.value is (guard == b"enabled")
    assert next(row for row in channel.rows if row.group == "2").value.value == ("none_reported" if protocol == b"-" else "lacp")


def test_structural_registry_subsequence_accepts_equal_copies_and_capture_interleaving_in_input_order(tmp_path):
    estate(tmp_path)
    tree, _ = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    row = tree.result.rows[0]
    scope = index.scope(stp.ROOT_GUARD, row.subject)
    node, context, target = (replace(ref) for ref in scope.declarations)
    spans = row.value.evidence[3:]
    evidence = (spans[0], node, spans[1], context, target) + spans[2:]
    leaves = index.resolve(scope, evidence, positive=True)
    for original, projected in zip(evidence, leaves, strict=True):
        assert_leaf(original, projected, tree.execution)


@pytest.mark.parametrize("plant", ["missing", "duplicate", "reorder", "replace", "node", "target", "citation", "table", "digest"])
def test_registry_subsequence_requires_exact_three_order_and_count(tmp_path, plant):
    estate(tmp_path)
    tree, _ = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    row = tree.result.rows[0]
    scope = index.scope(stp.ROOT_GUARD, row.subject)
    refs = scope.declarations
    if plant in ("missing", "duplicate", "reorder", "replace"):
        changed = {"missing": refs[1:], "duplicate": refs + (refs[0],),
                   "reorder": (refs[1], refs[0], refs[2]), "replace": (refs[0], refs[0], refs[2])}[plant]
    else:
        foreign = (next(t for t in tree.execution.envelope.targets if t.id == "ec").node.declaration.evidence[0] if plant == "node" else
            next(t for t in tree.execution.envelope.targets if t.id == "cold").declaration.evidence[0] if plant == "target" else
            replace(refs[0], **({"citation": "/nodes/999"} if plant == "citation" else {"table": "foreign.nodes"} if plant == "table" else {"table_digest": "0" * 64})))
        changed = (refs[0], refs[1], foreign) if plant == "target" else (foreign, refs[1], refs[2])
    with pytest.raises(r.RunnerRefused, match="^p4_projection_registry$"):
        index.resolve(scope, changed + row.value.evidence[3:], positive=True)


@pytest.mark.parametrize("kind", ["tree", "ec"])
@pytest.mark.parametrize("positive", [False, True])
def test_same_capture_same_value_different_cell_cannot_be_resolved(tmp_path, kind, positive):
    estate(tmp_path)
    tree, channels = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    rows = tree.result.rows if kind == "tree" else tuple(row for row in channels.rows if row.target.node.id == "b")
    fact = stp.ROOT_GUARD if kind == "tree" else ec.REPORTED_PROTOCOL
    assert rows[0].value.value == rows[1].value.value
    with pytest.raises(r.RunnerRefused, match="^p4_projection_scope$"):
        index.resolve(index.scope(fact, rows[0].subject), rows[1].value.evidence, positive=positive)


@pytest.mark.parametrize("plant", ["declared", "whole", "empty", "subspan", "hash", "capture", "factref", "pointer", "xml", "role", "fallback"])
def test_bad_capture_proofs_and_missing_positive_field_never_resolve(tmp_path, plant):
    estate(tmp_path)
    tree, _ = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    source = tree.result.rows[0]
    scope = index.scope(stp.ROOT_GUARD, tree.result.rows[2].subject if plant == "fallback" else source.subject)
    capture = next(o.receipt.capture for o in tree.execution.executed if o.receipt.capture.operation == stp.stp.OP)
    original = next(e for e in source.value.evidence if type(e) is k.EvidenceRef)
    leaf = original
    evidence = source.value.evidence
    if plant == "declared":
        evidence = scope.declarations
    elif plant == "factref":
        evidence += (scope.reference,)
    elif plant in ("whole", "fallback"):
        leaf = replace(leaf, locator=k.WholeCapture() if plant == "whole" else k.ByteSpan(start=0, end=len(capture.raw)),
                       role=k.EvidenceRole.WITNESS if plant == "whole" else k.EvidenceRole.SUBJECT, excerpt_sha256=capture.bytes_sha256)
        evidence = scope.declarations + (leaf,)
    else:
        if plant == "capture":
            other = next(o.receipt.capture for o in tree.execution.executed if o.receipt.capture.operation == ec.parse_summary.OP)
            leaf = replace(leaf, capture=other.id, excerpt_sha256=sha256(other.raw[leaf.locator.start:leaf.locator.end]).hexdigest())
        elif plant in ("empty", "subspan"):
            span = k.ByteSpan(start=0, end=0) if plant == "empty" else k.ByteSpan(start=leaf.locator.start + 1, end=leaf.locator.end - 1)
            leaf = replace(leaf, locator=span, excerpt_sha256=sha256(capture.raw[span.start:span.end]).hexdigest())
        else:
            leaf = replace(leaf, **({"excerpt_sha256": "0" * 64} if plant == "hash" else {"locator": k.FieldPointer(pointer="/guard")} if plant == "pointer" else
                                   {"locator": k.XmlPath(path="/guard")} if plant == "xml" else {"role": k.EvidenceRole.WITNESS}))
        evidence = tuple(leaf if e is original else e for e in evidence)
    with pytest.raises(r.RunnerRefused, match="^p4_projection_"):
        index.resolve(scope, evidence, positive=True)


@pytest.mark.parametrize("mode", ["header", "error", "partial"])
def test_no_field_or_incomplete_cell_cannot_borrow_header_or_token_as_positive(tmp_path, mode):
    estate(tmp_path, guard=None if mode == "header" else b"enabled", trailer=b"% Invalid input\n" if mode == "error" else b"unrecognised trailer\n" if mode == "partial" else b"")
    tree, _ = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    item = next(o for o in tree.execution.executed if o.receipt.capture.operation == stp.stp.OP)
    parsed = item.value.rows[0]
    span = parsed.spans[0] if mode == "header" else dict(parsed.fields)["root_guard"].span
    scope = index.scope(stp.ROOT_GUARD, tree.result.rows[0].subject)
    leaf = k.EvidenceRef(capture=item.receipt.capture.id, locator=span, role=k.EvidenceRole.SUBJECT,
                         excerpt_sha256=sha256(item.receipt.capture.raw[span.start:span.end]).hexdigest())
    evidence = scope.declarations + (leaf,)
    assert index.resolve(scope, evidence)
    with pytest.raises(r.RunnerRefused, match="^p4_projection_" + ("positive" if mode == "header" else "capture") + "$"):
        index.resolve(scope, evidence, positive=True)


@pytest.mark.parametrize("plant", ["clone", "other", "element", "list", "boolean"])
def test_scope_identity_and_evidence_shape_are_checked_before_resolution(tmp_path, plant):
    estate(tmp_path)
    tree, _ = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    scope = index.scope(stp.ROOT_GUARD, tree.result.rows[0].subject)
    other = r.ProofIndex(tree.execution, LIMITS)
    supplied = replace(scope) if plant == "clone" else other.scope(scope.reference.fact, scope.reference.subject) if plant == "other" else scope
    evidence = (object(),) if plant == "element" else list(scope.declarations) if plant == "list" else scope.declarations
    with pytest.raises(r.RunnerRefused, match="^p4_projection_"):
        index.resolve(supplied, evidence, positive=1 if plant == "boolean" else False)


def test_registry_records_are_independent_deep_copies_and_unknown_declared_only_is_valid(tmp_path):
    estate(tmp_path)
    tree, channels = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    scope = index.scope(stp.ROOT_GUARD, tree.result.rows[0].subject)
    expected = canonical(index.resolve(scope, scope.declarations))
    changed = index.resolve(scope, scope.declarations)
    changed[0]["value"]["ports"].clear()
    changed[2]["value"]["params"]["vlans"].clear()
    assert canonical(index.resolve(scope, scope.declarations)) == expected
    cold = next(row for row in channels.rows if row.group == "4")
    uncaptured = index.scope(ec.REPORTED_PROTOCOL, cold.subject)
    assert len(index.resolve(uncaptured, cold.value.evidence)) == 3
    with pytest.raises(r.RunnerRefused, match="^p4_projection_positive$"):
        index.resolve(uncaptured, cold.value.evidence, positive=True)


@pytest.mark.parametrize("plant", ["valid", "empty", "registry", "fact", "foreign", "list", "positive"])
def test_metadata_accepts_capture_leaves_only_without_positive_capability_or_recursion(tmp_path, plant):
    estate(tmp_path)
    tree, _ = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    item, other = tree.execution.executed
    capture = item.receipt.capture
    scope = next(s for s in index.scopes if s.target.id == next(m.target.id for m in tree.execution.envelope.captures if m.id == capture.id))
    evidence = capture.collected_utc.evidence
    if plant == "empty":
        assert index.metadata_evidence(capture.id, ()) == []
    elif plant == "valid":
        leaves = index.metadata_evidence(capture.id, evidence)
        assert len(leaves) == 1 and "collected_utc" not in leaves[0]
        assert_leaf(evidence[0], leaves[0], tree.execution)
    elif plant == "positive":
        with pytest.raises(TypeError):
            index.metadata_evidence(capture.id, evidence, positive=True)
    else:
        evidence = (scope.declarations[0],) if plant == "registry" else (scope.reference,) if plant == "fact" else other.receipt.capture.collected_utc.evidence if plant == "foreign" else list(evidence)
        with pytest.raises(r.RunnerRefused, match="^p4_projection_"):
            index.metadata_evidence(capture.id, evidence)


@pytest.mark.parametrize("context", ["subject_byte", "subject_whole", "metadata_byte", "metadata_whole"])
@pytest.mark.parametrize("role", list(k.EvidenceRole))
def test_every_role_is_checked_in_each_subject_and_metadata_context(tmp_path, context, role):
    estate(tmp_path)
    tree, _ = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    row = tree.result.rows[0]
    scope = index.scope(stp.ROOT_GUARD, row.subject)
    original = next(e for e in row.value.evidence if type(e) is k.EvidenceRef)
    capture = next(c for c in index.captures if c.id == original.capture)
    whole = context.endswith("whole")
    leaf = replace(original, role=role, **({"locator": k.WholeCapture(), "excerpt_sha256": capture.bytes_sha256} if whole else {}))
    allowed = k.EvidenceRole.WITNESS if context == "subject_whole" else k.EvidenceRole.SUBJECT
    def resolve():
        return index.resolve(scope, scope.declarations + (leaf,)) if context.startswith("subject") else index.metadata_evidence(capture.id, (leaf,))
    if role is allowed:
        records = resolve()
        assert_leaf(leaf, records[-1], tree.execution)
    else:
        with pytest.raises(r.RunnerRefused, match="^p4_projection_"):
            resolve()


@pytest.mark.parametrize("mode", ["empty", "beyond", "bool", "float"])
def test_metadata_byte_bounds_are_nonempty_exact_integers_within_original_bytes(tmp_path, mode):
    estate(tmp_path)
    tree, _ = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    capture = index.captures[0]
    span = k.ByteSpan(start=0, end=0 if mode == "empty" else len(capture.raw) + 1 if mode == "beyond" else 3)
    if mode in ("bool", "float"):
        object.__setattr__(span, "start", True if mode == "bool" else 0.0)
    excerpt = capture.raw[1:3] if mode == "bool" else capture.raw[:3] if mode == "float" else capture.raw[:span.end]
    leaf = k.EvidenceRef(capture=capture.id, locator=span, role=k.EvidenceRole.SUBJECT, excerpt_sha256=sha256(excerpt).hexdigest())
    with pytest.raises(r.RunnerRefused, match="^p4_projection_span$"):
        index.metadata_evidence(capture.id, (leaf,))
