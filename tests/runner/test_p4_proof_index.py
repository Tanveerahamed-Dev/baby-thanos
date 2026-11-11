from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.p4_admission import SCHEMA
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import OperationBinding, PackDeclaration
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import global_parse as gp
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.runner import p4_pipeline as pipe
from atlas_brain.runner import p4_refs as r
from atlas_brain.runner.pack_runtime import Handler, Parser

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


def execute(root, *extra):
    peer = gp.SummaryPack[stp.stp.Result](LIMITS)
    tree = stp.build_root_guard_global(root, LIMITS, peers=(peer, *extra))
    return tree, peer.finish(tree.execution)


@pytest.mark.parametrize("guard,protocol", [(b"enabled", b"LACP"), (b"disabled", b"-")])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_actual_run_builds_bound_immutable_cell_scopes_and_preserves_false_dash(tmp_path, monkeypatch, guard, protocol, ending):
    estate(tmp_path, guard, protocol, ending)
    tree, channel = execute(tmp_path)
    for module in (stp.stp, ec.parse_summary):
        monkeypatch.setattr(module, "parse_capture", lambda *args: pytest.fail("index reparsed evidence"))
    index = r.ProofIndex(tree.execution, LIMITS)
    rows = [(stp.ROOT_GUARD, row) for row in tree.result.rows] + [(ec.REPORTED_PROTOCOL, row) for row in channel.rows]
    assert index.execution is tree.execution and {s.reference for s in index.scopes} == {k.FactRef(fact=f, subject=row.subject) for f, row in rows}
    assert len(index.scopes) == 7 and type(index.scopes) is type(index.captures) is tuple
    for fact, row in rows:
        scope = index.scope(fact, row.subject)
        assert index.scope(fact, row.subject) is scope and scope.declarations == row.value.evidence[:3]
        assert dict(scope.labels)["node"] == row.target.node.id and scope.target.node is row.target.node
        if type(row.value) is k.Known:
            pairs = {(e.capture, e.locator) for e in row.value.evidence if type(e) is k.EvidenceRef}
            assert len(scope.positive) == 1 and scope.positive <= pairs <= scope.spans
        else:
            assert not scope.positive and not scope.spans
    original = {e.receipt.capture.id: e.receipt.capture for e in tree.execution.executed}
    assert all(c is original[c.id] and c.read_scope is k.ReadScope.UNKNOWN and c.view is k.ViewConsistency.UNKNOWN
               and c.collected_utc.reason is k.UnknownReason.AS_OF_MISSING for c in index.captures)
    assert index.registry_sha256 == sha256((tmp_path / "p4.json").read_bytes()).hexdigest()
    assert index.base_registry_sha256 == sha256((tmp_path / "p2.json").read_bytes()).hexdigest()
    assert tree.result.rows[0].value.value is (guard == b"enabled")
    assert next(row for row in channel.rows if row.group == "2").value.value == ("none_reported" if protocol == b"-" else "lacp")
    changed = replace(tree.execution, envelope=replace(tree.execution.envelope, targets=tuple(reversed(tree.execution.envelope.targets))),
                      executed=tuple(replace(e) for e in reversed(tree.execution.executed)))
    other = r.ProofIndex(changed, LIMITS)
    assert index.scopes == other.scopes and index.captures == other.captures
    assert replace(scope) == scope and replace(scope) is not scope
    assert other.scope(scope.reference.fact, scope.reference.subject) is not scope
    for name in ("scopes", "captures"):
        with pytest.raises(AttributeError):
            setattr(index, name, ())
    with pytest.raises(AttributeError):
        scope.labels = ()
    with pytest.raises(r.RunnerRefused, match="^p4_projection_scope$"):
        index.scope(scope.reference.fact, k.EntityKey("subject:missing"))


@pytest.mark.parametrize("kind", ["tree", "ec"])
def test_same_capture_identical_value_neighbour_has_disjoint_record_and_token_spans(tmp_path, kind):
    estate(tmp_path)
    tree, channel = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    rows = tree.result.rows if kind == "tree" else tuple(row for row in channel.rows if row.target.node.id == "b")
    fact = stp.ROOT_GUARD if kind == "tree" else ec.REPORTED_PROTOCOL
    left, right = (index.scope(fact, row.subject) for row in rows[:2])
    assert rows[0].value.value == rows[1].value.value and left.target is right.target
    assert left.spans and right.spans and left.spans.isdisjoint(right.spans) and left.positive.isdisjoint(right.positive)
    absent = index.scope(fact, rows[2].subject)
    assert absent.spans == absent.positive == frozenset()


@pytest.mark.parametrize("kind,mode", [(k, m) for k in ("tree", "ec") for m in ("global", "row", "missing", "duplicate")] + [("tree", "header")])
def test_global_or_local_unknown_and_missing_or_duplicate_specific_token_cannot_be_positive(tmp_path, mode, kind):
    estate(tmp_path, guard=None if mode == "header" else b"enabled")
    tree, channel = execute(tmp_path)
    entries = tree.execution.executed
    selected = next(e for e in entries if e.receipt.capture.operation == (stp.stp.OP if kind == "tree" else ec.parse_summary.OP))
    value, first = selected.value, selected.value.rows[0]
    field = "root_guard" if kind == "tree" else "protocol"
    if mode == "header":
        scope = r.ProofIndex(tree.execution, LIMITS).scope(stp.ROOT_GUARD, tree.result.rows[0].subject)
        assert tree.result.rows[0].value.reason is k.UnknownReason.FIELD_NOT_PRINTED and scope.spans and not scope.positive
        return
    if mode == "global":
        value = replace(value, reason=k.UnknownReason.PARSE_PARTIAL)
    else:
        fields = tuple(p for p in first.fields if p[0] != field) if mode == "missing" else first.fields
        if mode == "duplicate":
            fields += (next(p for p in first.fields if p[0] == field),)
        changed = replace(first, fields=fields, reason=k.UnknownReason.PARSE_PARTIAL if mode == "row" else None)
        value = replace(value, rows=(changed,) + value.rows[1:])
    selected = replace(selected, value=value)
    assert selected.receipt.parse is selected.value.parse and selected.receipt.parse.quality == "complete"
    execution = replace(tree.execution, executed=tuple(selected if e.receipt.capture.id == selected.receipt.capture.id else e for e in entries))
    index = r.ProofIndex(execution, LIMITS)
    row = tree.result.rows[0] if kind == "tree" else next(row for row in channel.rows if row.group == "1")
    scope = index.scope(stp.ROOT_GUARD if kind == "tree" else ec.REPORTED_PROTOCOL, row.subject)
    assert not scope.positive


@pytest.mark.parametrize("trailer", [b"% Invalid input\n", b"unexpected synthetic trailer\n"])
def test_failed_capture_or_partial_parse_keeps_scopes_but_no_positive_eligibility(tmp_path, trailer):
    estate(tmp_path, trailer=trailer)
    tree, _ = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    scopes = [s for s in index.scopes if s.reference.fact == stp.ROOT_GUARD]
    assert len(scopes) == 3 and all(not s.positive for s in scopes)


@pytest.mark.parametrize("plant", ["registry", "base", "owner", "context", "registration", "source", "operation", "hash", "missing", "duplicate", "rich", "cross", "parse", "node"])
def test_constructor_refuses_bad_original_registry_capture_receipt_and_rich_profile(tmp_path, plant):
    estate(tmp_path)
    tree, _ = execute(tmp_path)
    execution, entries = tree.execution, tree.execution.executed
    item = next(e for e in entries if e.receipt.capture.operation == stp.stp.OP)
    if plant in ("registry", "base"):
        envelope = replace(execution.envelope, **({"raw": execution.envelope.raw + b"\n"} if plant == "registry" else {"base": replace(execution.envelope.base, raw=execution.envelope.base.raw + b"\n")}))
        execution = replace(execution, envelope=envelope)
    elif plant == "node":
        target = next(t for t in execution.envelope.targets if t.id == "tree")
        changed = replace(target, node=replace(target.node, discovery_id="other"))
        execution = replace(execution, envelope=replace(execution.envelope, targets=tuple(changed if t is target else t for t in execution.envelope.targets)))
    elif plant in ("missing", "duplicate"):
        execution = replace(execution, executed=tuple(e for e in entries if e is not item) if plant == "missing" else entries + (item,))
    else:
        if plant in ("rich", "cross"):
            value = object() if plant == "rich" else next(e.value for e in entries if e is not item)
            item = replace(item, value=value, receipt=replace(item.receipt, parse=value.parse) if plant == "cross" else item.receipt)
        else:
            changes = {"owner": {"owner": ec.STEP.id}, "context": {"context": "wrong"}, "registration": {"registration_sha256": "0" * 64},
                "source": {"capture": replace(item.receipt.capture, source=k.EntityKey("node:wrong"))},
                "operation": {"capture": replace(item.receipt.capture, operation=ec.parse_summary.OP)},
                "hash": {"capture": replace(item.receipt.capture, raw=item.receipt.capture.raw + b"changed")},
                "parse": {"parse": replace(item.receipt.parse)}}[plant]
            item = replace(item, receipt=replace(item.receipt, **changes))
        execution = replace(execution, executed=tuple(item if e.receipt.capture.operation == stp.stp.OP else e for e in entries))
    with pytest.raises(r.RunnerRefused, match="^p4_projection_"):
        r.ProofIndex(execution, LIMITS)


@pytest.mark.parametrize("removed", ["tree", "ec", "captures"])
def test_zero_one_pack_targets_and_uncaptured_declared_scopes_survive(tmp_path, removed):
    side = estate(tmp_path)
    if removed != "captures":
        side["targets"] = [t for t in side["targets"] if t["operation"] != (stp.stp.OP if removed == "tree" else ec.parse_summary.OP)]
    side["captures"] = [] if removed == "captures" else [c for c in side["captures"] if c["target"] != removed]
    for path in ("tree.txt", "ec.txt") if removed == "captures" else (removed + ".txt",):
        (tmp_path / path).unlink()
    (tmp_path / "p4.json").write_bytes(canonical(side))
    tree, _ = execute(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    assert len(index.scopes) == (4 if removed == "tree" else 3 if removed == "ec" else 7)
    if removed == "captures":
        assert index.captures == () and all(not scope.spans and not scope.positive and len(scope.declarations) == 3 for scope in index.scopes)


def test_actual_third_zero_target_pack_changes_the_profile_and_is_refused(tmp_path):
    estate(tmp_path)
    step = StepSpec(id=StepId("test.extra/parse"), pack=k.PackId("test.extra"), kind="parse_build", scope="device", reads=(), produces=(), evaluator="test.extra.parse")
    declaration = PackDeclaration(pack=step.pack, entity_kinds=(), facts=(), relations=(), steps=(step,),
                                  operations=(OperationBinding(operation="synthetic.extra", step=step.id),))
    class Extra(pipe.Pack[stp.stp.Result | ec.parse_summary.Result]):
        def declaration(self):
            return declaration
        def prepare(self, envelope):
            return pipe.Prepared[stp.stp.Result | ec.parse_summary.Result](targets=(), requests=(),
                handlers=(Handler[stp.stp.Result | ec.parse_summary.Result](binding=declaration.operations[0], parser=Parser[stp.stp.Result | ec.parse_summary.Result]()),))
    tree, channel = execute(tmp_path, Extra())
    assert len(channel.rows) == 4
    with pytest.raises(r.RunnerRefused, match="^p4_projection_profile$"):
        r.ProofIndex(tree.execution, LIMITS)
