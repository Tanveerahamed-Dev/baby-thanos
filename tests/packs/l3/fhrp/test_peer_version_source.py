"""Fresh VERSION Source ownership; returned frozen carriers supply no deep origin seal."""
from dataclasses import replace
from enum import StrEnum

import pytest
from test_peer_execution import forbidden
from test_peer_version_proofs import inputs
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactStore, FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import peer_execution as components
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.runner import p4_fhrp_version_source as factory
from atlas_brain.runner import p4_pipeline as pipeline
from atlas_brain.runner.p4_refs import FhrpVersionProofIndex

FACT = vo.profile.REPORTED_PROTOCOL_VERSION
FIELDS = ("bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth", "numeric_digits", "compression_ratio", "archive_index_bytes")
STAGES = {"index": (factory, "FhrpVersionProofIndex"), "graph": (factory, "order_steps"),
    "tree": (stp.RootGuardPack, "validate_root_guard_values"), "channel": (ec.ProtocolOwner, "validate_reported_protocol_values"),
    "state": (fhrp.StateOwner, "validate_gateway_source_values"), "version": (vo.PeerGlobalVersionOwner, "validate_values"),
    "base": (factory.observations, "close_owned_facts"), "proof": (FhrpVersionProofIndex, "close_protocol_version")}


def install(monkeypatch, change=None, *, copied=False):
    produce, constructor, made, published = components.build_peer_state_version_component, factory.FhrpVersionSource, [], []
    paths = ((FactWriter, "write"), (pipeline, "execute_parsers"),
        *((module, "bind_writer") for module in (stp, ec, fhrp, vo)),
        *((module, "parse_capture") for module in (stp.stp, ec.parse_summary, fhrp.hsrp, components.all_hsrp)))
    originals = tuple((module, name, getattr(module, name)) for module, name in paths)
    def producing(*args):
        for module, name, original in originals:
            monkeypatch.setattr(module, name, original)
        result = produce(*args)
        made.append(result)
        for module, name, _ in originals:
            monkeypatch.setattr(module, name, forbidden)
        replacement = None if change is None else change(result)
        return replace(result, execution=replace(result.execution)) if copied else result if replacement is None else replacement
    def publishing(**kwargs):
        published.append(kwargs)
        return constructor(**kwargs)
    monkeypatch.setattr(components, "build_peer_state_version_component", producing)
    monkeypatch.setattr(factory, "FhrpVersionSource", publishing)
    return made, published


def after(monkeypatch, made, stage, change):
    canonical, calls, changed = factory.custody.canonical_peer_state_version_outputs, [], []
    def act():
        if not changed:
            changed.append(True)
            change(made[-1])
    def closing(*args):
        result = canonical(*args)
        if made:
            calls.append(result)
            if stage == "canonical":
                act()
        return result
    monkeypatch.setattr(factory.custody, "canonical_peer_state_version_outputs", closing)
    if stage != "canonical":
        module, name = (factory.profile, "compile_peer_state_version_profile") if stage == "final" else STAGES[stage]
        original = getattr(module, name)
        def checking(*args, **kwargs):
            result = original(*args, **kwargs)
            if made and (stage != "final" or len(calls) >= 2):
                act()
            return result
        monkeypatch.setattr(module, name, checking)
    return changed


@pytest.fixture
def rejected(tmp_path, monkeypatch):
    inputs(valid := tmp_path / "valid")
    reference = factory.prepare_fhrp_version_source(valid, replace(LIMITS))
    inputs(root := tmp_path / "changed")
    def run(change=None, *, stage=None, call=None, error=ValueError):
        made, published = install(monkeypatch, change if stage is None else None)
        if stage is not None:
            changed = after(monkeypatch, made, stage, change)
        if call is not None:
            monkeypatch.setattr(components, "build_peer_state_version_component", forbidden)
            monkeypatch.setattr(factory.profile, "compile_peer_state_version_profile", forbidden)
        with pytest.raises(error):
            factory.prepare_fhrp_version_source(root, replace(LIMITS)) if call is None else call(root, reference)
        assert not published and (bool(made) if call is None else not made) and (stage is None or changed)
    return run


def trace(monkeypatch, module, name, log, *, active=None, label=None):
    original = getattr(module, name)
    def observing(*args, **kwargs):
        if label is not None and (active is None or active):
            log.append(label)
        result = original(*args, **kwargs)
        if label is None:
            log.append((args, kwargs, result))
        return result
    monkeypatch.setattr(module, name, observing)


@pytest.mark.parametrize("copied", [False, True])
def test_fresh_repeated_calls_own_one_real_batch_four_stores_readers_graph_and_all_closures(tmp_path, monkeypatch, copied):
    inputs(tmp_path)
    batches, writes, events, readers, graphs = [], [], [], [], []
    for module, name, log in ((pipeline, "execute_parsers", batches), (FactWriter, "write", writes),
            (factory, "bind_reader", readers), (factory, "order_steps", graphs)):
        trace(monkeypatch, module, name, log)
    made, published = install(monkeypatch, copied=copied)
    def copying(component):
        for result in (component.tree, component.channel, component.state, component.version):
            result.store.owners = dict(result.store.owners)
            result.store.values = {replace(ref): value for ref, value in result.store.values.items()}
    changed = after(monkeypatch, made, "final", copying)
    for label in ("tree", "channel", "state", "version", "base", "proof"):
        trace(monkeypatch, *STAGES[label], events, active=made, label=label)
    first = factory.prepare_fhrp_version_source(tmp_path, LIMITS)
    assert changed
    first_events = tuple(events)
    events.clear()
    second = factory.prepare_fhrp_version_source(tmp_path, LIMITS)
    assert first_events == tuple(events) == ("tree", "channel", "state", "version", "base", "proof", "version")
    assert len(made) == len(published) == len(batches) == len(graphs) == 2 and len(writes) == 28 and len(readers) == 8
    for index, source in enumerate((first, second)):
        component = made[index]
        assert source.source is component.version and source.execution.envelope is component.execution.envelope
        assert source.execution.executed is batches[index][2] and source.proofs.execution is source.execution
        assert source.proofs.protocol_version_result is source.source and source.proofs.protocol_version_owner is component.version_owner
        domains = component.state_owner.plan.indexed
        assert source.domains == tuple(domains[key] for key in sorted(domains))
        assert all(any(target.node is node for node in source.execution.envelope.base.nodes) for target in source.domains)
        stores = (component.tree.store, component.channel.store, component.state.store, component.version.store)
        assert len({id(store) for store in stores}) == 4 and [len(store.values) for store in stores] == [2, 2, 5, 5]
        for store, (_, _, reader) in zip(stores, readers[index * 4:index * 4 + 4], strict=True):
            assert type(reader) is FactReader and reader.store is store
            assert reader.step.reads == tuple(sorted(store.owners)) and not reader.step.produces
        steps = graphs[index][0][0]
        assert len(steps) == len({step.id for step in steps}) == 8 and len(source.proofs.scopes) == 14
        assert all(source.proofs.resolve_protocol_version_reference(k.FactRef(fact=FACT, subject=row.subject)) for row in source.source.rows)
    assert first.execution is not second.execution and first.source.store is not second.source.store
    assert first.source.rows == second.source.rows and first.domains == second.domains


@pytest.mark.parametrize("stage", ["canonical", *STAGES, "final"])
def test_every_failed_closure_stage_prevents_source_construction(rejected, stage):
    def refusing(_component):
        raise ValueError("planted_" + stage)
    rejected(refusing, stage=stage)


@pytest.mark.parametrize("family", ["tree", "channel", "state", "version"])
@pytest.mark.parametrize("plant", ["value", "evidence", "missing", "owners"])
def test_actual_component_semantics_evidence_store_and_census_are_closed_before_publication(rejected, family, plant):
    def changing(component):
        result = getattr(component, family)
        row = next(row for row in result.rows if type(row.value) is k.Known)
        if plant == "value":
            value = row.value
            object.__setattr__(value, "value", not value.value if type(value.value) is bool else "1" if value.value == "2" else "2")
            if family == "version":
                object.__setattr__(value, "raw", value.value)
        elif plant == "evidence":
            ref = next(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
            object.__setattr__(row.value, "evidence", tuple(replace(ref, excerpt_sha256="0" * 64) if item is ref else item for item in row.value.evidence))
        elif plant == "missing":
            result.store.values.pop(next(iter(result.store.values)))
        else:
            result.store.owners[next(iter(result.store.owners))] = "wrong/owner"
    rejected(changing)


@pytest.mark.parametrize("plant", ["need", "candidates", "receipt", "cache", "registration", "version_copy", "owner"])
def test_unknown_needs_cache_receipts_registration_and_actual_version_owner_remain_closed(rejected, plant):
    def changing(component):
        result = component.version
        if plant in ("need", "candidates"):
            value = next(row.value for row in result.rows if type(row.value) is k.Unknown)
            object.__setattr__(value.next_evidence[0], "reruns", ("wrong/step",)) if plant == "need" else object.__setattr__(value, "candidates", ("synthetic:other",))
        elif plant == "receipt":
            object.__setattr__(component.execution, "executed", tuple(replace(out, receipt=replace(out.receipt)) for out in component.execution.executed))
        elif plant == "cache":
            key = next(iter(component.version_owner.inputs.produced))
            component.version_owner.inputs.produced[key] = replace(component.version_owner.inputs.produced[key])
        elif plant == "registration":
            object.__setattr__(component.execution.envelope, "registration_sha256", "0" * 64)
        else:
            object.__setattr__(component, "version" if plant == "version_copy" else "version_owner", replace(result) if plant == "version_copy" else object())
    rejected(changing)


@pytest.mark.parametrize("which", range(4))
@pytest.mark.parametrize("plant", ["store", "grant", "copy"])
def test_each_reader_is_actual_store_bound_declared_and_returns_original_cells(rejected, monkeypatch, which, plant):
    bind, calls = factory.bind_reader, []
    def reading(store, *, step):
        calls.append(store)
        if len(calls) - 1 == which:
            if plant == "store":
                other = FactStore()
                other.owners, other.values = dict(store.owners), dict(store.values)
                store = other
            elif plant == "grant":
                step = replace(step, reads=())
        return bind(store, step=step)
    monkeypatch.setattr(factory, "bind_reader", reading)
    if plant == "copy":
        read = FactReader.read
        def copying(self, **kwargs):
            value = read(self, **kwargs)
            return replace(value) if calls and self.store is calls[which] else value
        monkeypatch.setattr(FactReader, "read", copying)
    rejected()
    assert len(calls) == 4


@pytest.mark.parametrize("stage", ["canonical", "final"])
@pytest.mark.parametrize("plant", ["owners", "owner_alias", "fact_alias", "subject_alias", "fact_original", "subject_original", "fact_mutate", "subject_mutate", "cell", "budget", "envelope", "result", "ledger"])
def test_late_mutable_maps_keys_cells_and_retained_identities_cannot_publish_a_stale_source(rejected, stage, plant):
    def changing(component):
        result, store = component.version, component.version.store
        if plant in ("owners", "owner_alias"):
            store.owners = {fact: "wrong/owner" if plant == "owners" else StrEnum("Alias", {"VALUE": owner}).VALUE for fact, owner in store.owners.items()}
        elif plant.startswith(("fact_", "subject_")):
            pairs = tuple(store.values.items())
            original = pairs[0][0]
            ref, field = (replace(original) if plant.endswith("alias") else original), plant.split("_")[0]
            object.__setattr__(ref, field, "synthetic:other" if plant.endswith("mutate") else StrEnum("Alias", {"VALUE": getattr(ref, field)}).VALUE)
            store.values = {ref if key is original else key: value for key, value in pairs}
        elif plant == "cell":
            row = result.rows[0]
            object.__setattr__(row, "value", value := replace(row.value))
            store.values[k.FactRef(fact=FACT, subject=row.subject)] = value
        elif plant == "budget":
            object.__setattr__(component.tree_owner.budgets, "bundle_bytes", 0)
        else:
            target, name, value = (component.execution, "envelope", replace(component.execution.envelope)) if plant == "envelope" else (
                (component, "version", replace(result)) if plant == "result" else (component.execution, "executed", tuple(out for out in component.execution.executed)))
            object.__setattr__(target, name, value)
    rejected(changing, stage=stage)


@pytest.mark.parametrize("operand,value", [*[(name, value) for name in ("root", "budgets") for value in (None, 7, "text", "carrier")],
    *[(field, value) for field in FIELDS for value in (False, [], 0, -1)],
    *[("keyword", name) for name in ("component", "source", "profile", "callback", "execution")]])
def test_invalid_inputs_and_supplied_carriers_or_profiles_refuse_before_compilation_or_producer(rejected, operand, value):
    def calling(root, reference):
        budgets = replace(LIMITS)
        if operand in FIELDS:
            object.__setattr__(budgets, operand, value)
            return factory.prepare_fhrp_version_source(root, budgets)
        if operand == "keyword":
            return factory.prepare_fhrp_version_source(root, budgets, **{value: reference})
        item = reference if value == "carrier" else value
        return factory.prepare_fhrp_version_source(item if operand == "root" else root, item if operand == "budgets" else budgets)
    rejected(call=calling, error=TypeError if operand == "keyword" else ValueError)
