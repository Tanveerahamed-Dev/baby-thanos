"""Legacy STP owning-value closure; no Root-extension, projection or Source authority."""
from dataclasses import replace
from enum import StrEnum

import pytest
from test_peer_component import reader
from test_peer_execution import forbidden, no_writers
from test_peer_version_owner import folder
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepSpec
from atlas_brain.model.store import FactStore, FactWriter, bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import peer_execution as runtime
from atlas_brain.runner import p4_pipeline as pipeline


class Alias(StrEnum):
    ROLE = "designated"
    FACT = "l2.stp.root_guard"
    STEP = "l2.stp/parse_root_guard"


def checking(component, view=None, outputs=None):
    return component.tree_owner.validate_root_guard_values(component.tree,
        reader(component.tree.store, "l2.stp") if view is None else view,
        component.execution.executed if outputs is None else outputs)


def refuses(component, **arguments):
    with pytest.raises(ValueError):
        checking(component, **arguments)


def actual(root, monkeypatch, unknown=False):
    def changed(side, _files):
        next(target for target in side["targets"] if target["id"] == "tree")["params"]["vlans"] = [1, 2]
    folder(root, change=changed if unknown else None)
    component = runtime.build_peer_state_version_component(root, LIMITS)
    no_writers(monkeypatch)
    for module, name in ((pipeline, "execute_parsers"), (FactWriter, "write"), (stp.stp, "parse_capture"),
            (ec.parse_summary, "parse_capture"), (fhrp.hsrp, "parse_capture"), (runtime.all_hsrp, "parse_capture"),
            (stp, "projection_leaves"), (stp, "root_projection_leaves")):
        monkeypatch.setattr(module, name, forbidden)
    assert len(checking(component)) == 1
    assert len(component.tree.rows) == (2 if unknown else 1)
    return component


def replace_cell(component, fact, unknown, mutate):
    row = next(row for row in component.tree.rows
        if (type(stp.original_state(fact, row)) is k.Unknown) is unknown)
    value = replace(stp.original_state(fact, row))
    mutate(value)
    replacement = replace(row, **{"value" if fact == stp.ROOT_GUARD else "role": value})
    object.__setattr__(component.tree, "rows", tuple(replacement if current is row else current for current in component.tree.rows))
    component.tree.store.values[k.FactRef(fact=fact, subject=row.subject)] = value


def evidence_change(value, kind, mutate):
    original = next(ref for ref in value.evidence if type(ref) is kind)
    changed = replace(original)
    mutate(changed)
    object.__setattr__(value, "evidence", tuple(changed if ref is original else ref for ref in value.evidence))


def test_real_four_store_component_and_repeated_legacy_reader_closure_do_not_replay_work(tmp_path, monkeypatch):
    component = actual(tmp_path, monkeypatch)
    assert sum(len(result.store.values) for result in (component.tree, component.channel, component.state, component.version)) == 14
    targets = checking(component)
    assert targets == tuple(component.tree_owner.plan.indexed[key] for key in sorted(component.tree_owner.plan.indexed))
    assert checking(component) == targets and len(component.tree.store.values) == 2
    for fact, row, value in stp.fact_rows(component.tree):
        assert reader(component.tree.store, "l2.stp").read(fact=fact, subject=row.subject) is value


@pytest.mark.parametrize("fact", [stp.ROOT_GUARD, stp.REPORTED_ROLE])
@pytest.mark.parametrize("plant", ["value", "value_alias", "raw", "basis", "evidence", "ref_role_alias", "span_alias", "registry_digest"])
def test_known_cells_reclose_values_raw_basis_and_deep_original_evidence(tmp_path, monkeypatch, fact, plant):
    component = actual(tmp_path, monkeypatch)
    def changing(value):
        if plant in ("value", "value_alias"):
            object.__setattr__(value, "value", {"value": False if fact == stp.ROOT_GUARD else "root",
                "value_alias": 1 if fact == stp.ROOT_GUARD else Alias.ROLE}[plant])
        elif plant in ("raw", "basis", "evidence"):
            object.__setattr__(value, plant, {"raw": "tampered", "basis": k.Basis.DECLARED, "evidence": value.evidence[:-1]}[plant])
        elif plant == "ref_role_alias":
            evidence_change(value, k.EvidenceRef, lambda ref: object.__setattr__(ref, "role", ref.role.value))
        elif plant == "registry_digest":
            evidence_change(value, k.RegistryRef, lambda ref: object.__setattr__(ref, "table_digest", "0" * 64))
        else:
            original = next(ref for ref in value.evidence if type(ref) is k.EvidenceRef
                and type(ref.locator) is k.ByteSpan and ref.locator.start == 0)
            locator, ref = replace(original.locator), replace(original)
            object.__setattr__(locator, "start", False)
            object.__setattr__(ref, "locator", locator)
            object.__setattr__(value, "evidence", tuple(ref if item is original else item for item in value.evidence))
    replace_cell(component, fact, False, changing)
    refuses(component)


@pytest.mark.parametrize("fact", [stp.ROOT_GUARD, stp.REPORTED_ROLE])
@pytest.mark.parametrize("plant", ["reason", "reason_alias", "detail", "candidates", "need_operation", "need_params", "need_refs", "need_delay",
    "candidates_graph", "need_resolves_graph", "need_reruns_graph", "need_unprintable_graph"])
def test_unknown_cells_preserve_reason_candidates_and_complete_next_evidence(tmp_path, monkeypatch, fact, plant):
    component = actual(tmp_path, monkeypatch, unknown=True)
    assert len(component.tree.store.values) == 4
    def changing(value):
        if plant in ("reason", "reason_alias", "detail", "candidates", "candidates_graph"):
            field = "reason" if plant.startswith("reason") else "candidates" if plant.startswith("candidates") else plant
            altered = {"reason": k.UnknownReason.CAPTURE_ERROR, "reason_alias": value.reason.value,
                "detail": "tampered", "candidates": ("planted",), "candidates_graph": ([],)}[plant]
            object.__setattr__(value, field, altered)
        else:
            need = replace(value.next_evidence[0])
            field, altered = {"need_operation": ("operation", "iosxe.show_clock"), "need_params": ("params", []),
                "need_refs": ("resolves", ("l2.stp.wrong",)), "need_delay": ("after_s", False),
                "need_resolves_graph": ("resolves", ([],)), "need_reruns_graph": ("reruns", ([],)),
                "need_unprintable_graph": ("unprintable", ([],))}[plant]
            object.__setattr__(need, field, altered)
            object.__setattr__(value, "next_evidence", (need,))
    replace_cell(component, fact, True, changing)
    refuses(component)


@pytest.mark.parametrize("plant", ["reader_store", "reader_type", "reader_grant", "owners", "owner_alias", "missing_cell", "extra_cell", "cell_copy", "rows", "executed"])
def test_actual_reader_store_owners_and_complete_cells_are_required(tmp_path, monkeypatch, plant):
    component = actual(tmp_path, monkeypatch)
    result, view = component.tree, None
    row = result.rows[0]
    ref = k.FactRef(fact=stp.ROOT_GUARD, subject=row.subject)
    if plant in ("reader_store", "reader_type"):
        view = reader(FactStore(), "l2.stp") if plant == "reader_store" else object()
    elif plant == "reader_grant":
        view = bind_reader(result.store, step=StepSpec(id="l2.stp/missing_role", pack="l2.stp", kind="check",
            scope="estate", reads=(stp.ROOT_GUARD,), produces=(), evaluator="l2.stp.inspect"))
    elif plant in ("owners", "owner_alias"):
        result.store.owners[stp.ROOT_GUARD] = Alias.STEP if plant.endswith("alias") else "l2.stp/wrong"
    elif plant == "missing_cell":
        result.store.values.pop(ref)
    elif plant == "extra_cell":
        result.store.values[k.FactRef(fact=stp.ROOT_GUARD, subject="stp_port_vlan:" + "0" * 64)] = row.value
    elif plant == "cell_copy":
        result.store.values[ref] = replace(row.value)
    else:
        object.__setattr__(result, "rows" if plant == "rows" else "executed", (*result.rows, row) if plant == "rows" else ())
    refuses(component, view=view)


@pytest.mark.parametrize("plant", ["missing", "duplicate", "capture", "value", "parse", "registration", "context", "cache", "span"])
def test_actual_owner_capture_cache_receipts_and_raw_spans_remain_bound(tmp_path, monkeypatch, plant):
    component = actual(tmp_path, monkeypatch)
    outputs = component.execution.executed
    original = next(out for out in outputs if out.receipt.capture.operation == stp.stp.OP)
    changed = original
    if plant == "missing":
        outputs = tuple(out for out in outputs if out is not original)
    elif plant == "duplicate":
        outputs = (*outputs, original)
    elif plant == "cache":
        component.tree_owner.produced[original.receipt.capture.id] = replace(original.value)
    elif plant == "span":
        record = next(record for record in original.value.parse.records if record.rule_id.startswith("header_"))
        object.__setattr__(record, "span", k.ByteSpan(start=0, end=1))
    else:
        if plant == "capture":
            changed = replace(original, receipt=replace(original.receipt, capture=replace(original.receipt.capture)))
        elif plant == "value":
            changed = replace(original, value=replace(original.value))
        else:
            field, value = {"parse": ("parse", replace(original.receipt.parse)), "registration": ("registration_sha256", "0" * 64),
                "context": ("context", "wrong")}[plant]
            changed = replace(original, receipt=replace(original.receipt, **{field: value}))
        outputs = tuple(changed if out is original else out for out in outputs)
    refuses(component, outputs=outputs)


@pytest.mark.parametrize("plant", ["node", "context", "port", "vlans", "subject", "vlan", "proofs", "cold_census"])
def test_current_declared_node_port_vlan_and_cold_census_define_the_rows(tmp_path, monkeypatch, plant):
    component = actual(tmp_path, monkeypatch, unknown=True)
    result, owner = component.tree, component.tree_owner
    row = result.rows[0]
    if plant == "proofs":
        object.__setattr__(owner.plan, "proofs", {})
    elif plant == "cold_census":
        object.__setattr__(result, "rows", tuple(item for item in result.rows if item.vlan != 2))
        for ref in tuple(result.store.values):
            if ref.subject not in {item.subject for item in result.rows}:
                result.store.values.pop(ref)
    else:
        target = replace(row.target)
        if plant in ("node", "context", "port", "vlans"):
            object.__setattr__(target, plant, {"node": replace(target.node), "context": "wrong",
                "port": "Gi1/0/99", "vlans": (1,)}[plant])
            changed = replace(row, target=target)
        else:
            changed = replace(row, **{plant: "stp_port_vlan:" + "0" * 64 if plant == "subject" else 2})
        object.__setattr__(result, "rows", tuple(changed if item is row else item for item in result.rows))
    refuses(component)


@pytest.mark.parametrize("plant", ["roots_alias", "root_boolean_alias", "scalar", "scalar_alias", "captured_step", "live_step", "captured_declaration", "extended"])
def test_legacy_literal_profile_refuses_live_captured_scalar_and_extended_drift(tmp_path, monkeypatch, plant):
    component = actual(tmp_path, monkeypatch)
    owner = component.tree_owner
    if plant == "roots_alias":
        object.__setattr__(owner.producer, "roots", 0)
    elif plant == "root_boolean_alias":
        kind = replace(stp.DECLARATION.entity_kinds[0])
        object.__setattr__(kind, "root", 0)
        declaration = replace(stp.DECLARATION, entity_kinds=(kind,))
        monkeypatch.setattr(stp, "DECLARATION", declaration)
        object.__setattr__(owner.producer, "declaration", declaration)
    elif plant.startswith("scalar"):
        monkeypatch.setattr(stp, "ROOT_GUARD", Alias.FACT if plant.endswith("alias") else "l2.stp.wrong")
    elif plant in ("captured_step", "live_step"):
        changed = replace(stp.STEP, evaluator="l2.stp.wrong")
        if plant == "live_step":
            monkeypatch.setattr(stp, "STEP", changed)
        else:
            object.__setattr__(owner.producer, "step", changed)
    elif plant == "captured_declaration":
        object.__setattr__(owner.producer, "declaration", replace(stp.DECLARATION))
    else:
        object.__setattr__(owner, "producer", replace(owner.producer, declaration=stp.ROOT_DECLARATION, step=stp.ROOT_STEP, roots=True))
    refuses(component)


def test_equal_target_and_cell_copies_with_original_nodes_are_current_data_not_origin_tokens(tmp_path, monkeypatch):
    component = actual(tmp_path, monkeypatch)
    for key, target in tuple(component.tree_owner.plan.indexed.items()):
        component.tree_owner.plan.indexed[key] = replace(target)
    object.__setattr__(component.tree, "rows", tuple(replace(row, target=replace(row.target)) for row in component.tree.rows))
    for fact in (stp.ROOT_GUARD, stp.REPORTED_ROLE):
        replace_cell(component, fact, False, lambda _value: None)
    assert checking(component)


@pytest.mark.parametrize("plant", ["node_id", "target_id", "member_path", "capture_id", "row_subject", "fact_subject", "plan_key"])
def test_identifier_graph_refuses_before_hashes_sets_or_dictionary_lookups(tmp_path, monkeypatch, plant):
    component = actual(tmp_path, monkeypatch)
    owner, result = component.tree_owner, component.tree
    if plant == "plan_key":
        key = next(iter(owner.plan.indexed))
        owner.plan.indexed[0] = owner.plan.indexed.pop(key)
    else:
        value, field = {"node_id": (owner.envelope.base.nodes[0], "id"), "target_id": (owner.envelope.targets[0], "id"),
            "member_path": (owner.envelope.captures[0], "path"), "capture_id": (owner.plan.requests[0].capture, "id"),
            "row_subject": (result.rows[0], "subject"), "fact_subject": (next(iter(result.store.values)), "subject")}[plant]
        object.__setattr__(value, field, [])
    refuses(component)
