"""Fresh fixed mixed seven-fact production; no global proof, report or admission seal."""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactReader, FactStore, bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build, version_profile, vrrp_inputs, vrrp_profile
from atlas_brain.packs.l3.fhrp import mixed_execution as execution
from atlas_brain.packs.l3.fhrp.version_owner import (
    RootMixedGlobalVersionOwner,
    VersionResult,
)
from atlas_brain.packs.l3.fhrp.vrrp_owner import (
    RootMixedVRRPOwner,
    VRRPResult,
)

type Cell = k.Known[bool] | k.Known[str] | k.Unknown
type Cells = tuple[tuple[k.FactId, k.EntityKey, Cell], ...]
type RootCell = Cell | k.Known[int]
type RootCells = tuple[tuple[k.FactId, k.EntityKey, RootCell], ...]
type OwnedResult = stp.Result | ec.Result | build.Result | VersionResult | VRRPResult
type Held = tuple[FactStore, tuple[object, ...], Cells]
type Results = tuple[stp.Result, ec.Result, build.Result, VersionResult, VRRPResult]
type Subjects = tuple[tuple[k.EntityKey, ...], tuple[k.EntityKey, ...], tuple[k.EntityKey, ...], tuple[k.EntityKey, ...]]
type HeldResults = tuple[Held, Held, Held, Held, Held]
type RootHeld = tuple[FactStore, tuple[object, ...], RootCells]
type RootHeldResults = tuple[RootHeld, RootHeld, RootHeld, RootHeld, RootHeld]


@dataclass(frozen=True, slots=True, kw_only=True)
class MixedComponent:
    source: execution.MixedExecution
    tree: stp.Result
    channel: ec.Result
    state: build.Result
    version: VersionResult
    vrrp: VRRPResult


@dataclass(frozen=True, slots=True, kw_only=True)
class _Retained:
    component: MixedComponent
    subjects: Subjects
    held: RootHeldResults


@dataclass(frozen=True, slots=True, kw_only=True)
class RootMixedComponent:
    source: execution.RootMixedExecution
    tree: stp.Result
    channel: ec.Result
    state: build.Result
    version: VersionResult
    vrrp: VRRPResult


@dataclass(frozen=True, slots=True, kw_only=True)
class _RootRetained:
    component: RootMixedComponent
    subjects: Subjects
    held: RootHeldResults


def _need(condition: bool, code: str) -> None:
    k.require(condition, "fhrp_mixed_component_" + code)


def _cells(items: tuple[tuple[k.FactId, stp.Row | ec.Row | build.Row, Cell], ...]) -> Cells:
    _need(all(type(row) in (stp.Row, ec.Row, build.Row) for _, row, _ in items), "cell")
    return tuple((fact, row.subject, value) for fact, row, value in items)


def _root_cells(items: tuple[tuple[k.FactId, stp.Row | ec.Row | build.Row, RootCell], ...]) -> RootCells:
    _need(all(type(row) in (stp.Row, ec.Row, build.Row) for _, row, _ in items), "cell")
    return tuple((fact, row.subject, value) for fact, row, value in items)


def _reader(result: OwnedResult, step: StepSpec, subjects: tuple[k.EntityKey, ...], held: RootHeld, cells: RootCells) -> FactReader:
    store, rows, original = held
    _need(result.store is store and result.rows is rows, "store")
    _need(all(type(fact) is str and type(subject) is str for fact, subject, _ in cells), "population")
    _need(len(cells) == len(original) and all(a == x and b == y and c is z
        for (a, b, c), (x, y, z) in zip(cells, original, strict=True)), "cell")
    _need(type(store) is FactStore and type(store.owners) is dict and type(store.values) is dict
        and all(type(fact) is str and type(owner) is str for fact, owner in store.owners.items())
        and store.owners == {fact: step.id for fact in step.produces}, "store")
    _need(all(type(ref) is k.FactRef and type(ref.fact) is str and type(ref.subject) is str for ref in store.values)
        and all(type(subject) is str for subject in subjects) and len(set(subjects)) == len(subjects), "population")
    expected = {k.FactRef(fact=fact, subject=subject) for fact in step.produces for subject in subjects}
    _need(set(store.values) == expected and len(cells) == len(expected)
        and {k.FactRef(fact=fact, subject=subject) for fact, subject, _ in cells} == expected, "population")
    read_step = StepSpec(id=StepId(step.id + "_mixed_values"), pack=step.pack,
        kind="derive", scope="estate", reads=step.produces, produces=(), evaluator=step.pack + ".mixed_values")
    reader = bind_reader(store, step=read_step)
    _need(type(reader) is FactReader and reader.store is store and reader.step is read_step, "reader")
    for fact, subject, value in cells:
        _need(type(value) in (k.Known, k.Unknown) and store.values[k.FactRef(fact=fact, subject=subject)] is value
            and reader.read(fact=fact, subject=subject) is value, "cell")
    return reader


def _close(run: object, source: execution.MixedExecution | execution.RootMixedExecution,
    results: Results, subjects: Subjects, held: RootHeldResults, budgets: Budgets,
) -> None:
    _validate_source(run, source, budgets)
    tree, channel, state_result, version_result, vrrp_result = results
    tree_subjects, channel_subjects, hsrp_subjects, vrrp_subjects = subjects
    tree_held, channel_held, state_held, version_held, vrrp_held = held
    state, version, owner = source.fhrp.state, source.fhrp.version, source.fhrp.vrrp_owner
    if state is None or version is None or owner is None:
        raise ValueError("fhrp_mixed_component_source")
    outputs = source.execution.executed
    stores = (tree.store, channel.store, state_result.store, version_result.store, vrrp_result.store)
    _need(all(first is not second for index, first in enumerate(stores) for second in stores[index + 1:]), "store")
    if isinstance(source, execution.RootMixedExecution):
        if not isinstance(version, RootMixedGlobalVersionOwner) or not isinstance(owner, RootMixedVRRPOwner):
            raise ValueError("fhrp_mixed_component_source")
        stp.RootObservationPack[ec.parse_summary.Result | execution.FhrpValue].validate_root_values(source.tree, tree,
            _reader(tree, stp.ROOT_STEP, tree_subjects, tree_held, _root_cells(stp.root_fact_rows(tree))), source.execution)
        ec.ProtocolOwner.validate_reported_protocol_values(source.channel.owner, channel,
            _reader(channel, ec.STEP, channel_subjects, channel_held, _cells(ec.fact_rows(channel))), outputs)
        build.StateOwner.validate_gateway_source_values(state, state_result,
            _reader(state_result, build.STEP, hsrp_subjects, state_held, _cells(build.fact_rows(state_result))), outputs)
        RootMixedGlobalVersionOwner.validate_values(version, version_result,
            _reader(version_result, version_profile.STEP, hsrp_subjects, version_held,
                tuple((version_profile.REPORTED_PROTOCOL_VERSION, row.subject, row.value) for row in version_result.rows)))
        RootMixedVRRPOwner.validate_values(owner, vrrp_result,
            _reader(vrrp_result, vrrp_profile.STEP, vrrp_subjects, vrrp_held,
                tuple((vrrp_profile.REPORTED_VRRP_STATE, row.subject, row.value) for row in vrrp_result.rows)))
        _validate_source(run, source, budgets)
        return
    source.tree.validate_root_guard_values(tree, _reader(tree, stp.STEP, tree_subjects, tree_held,
        _cells(stp.fact_rows(tree))), outputs)
    source.channel.owner.validate_reported_protocol_values(channel, _reader(channel, ec.STEP, channel_subjects, channel_held,
        _cells(ec.fact_rows(channel))), outputs)
    state.validate_gateway_source_values(state_result, _reader(state_result, build.STEP, hsrp_subjects, state_held,
        _cells(build.fact_rows(state_result))), outputs)
    version.validate_values(version_result, _reader(version_result, version_profile.STEP, hsrp_subjects, version_held,
        tuple((version_profile.REPORTED_PROTOCOL_VERSION, row.subject, row.value) for row in version_result.rows)))
    owner.validate_values(vrrp_result, _reader(vrrp_result, vrrp_profile.STEP, vrrp_subjects, vrrp_held,
        tuple((vrrp_profile.REPORTED_VRRP_STATE, row.subject, row.value) for row in vrrp_result.rows)))
    _validate_source(run, source, budgets)


class MixedComponentRun:
    """Consume one fresh invocation; failed later finishing retains prior returned results.

    A Store whose finish fails before returning is not retained here.
    """

    def __init__(self, root: Path, budgets: Budgets) -> None:
        self.root, self.budgets, self.attempted = root, budgets, False
        self.source: execution.MixedExecution | None = None
        self.tree: stp.Result | None = None
        self.channel: ec.Result | None = None
        self.state: build.Result | None = None
        self.version: VersionResult | None = None
        self.vrrp: VRRPResult | None = None
        self.result: MixedComponent | None = None
        self.retained: _Retained | None = None

    def build(self) -> MixedComponent:
        _need(type(self) is MixedComponentRun and self.attempted is False and self.source is None
            and self.tree is None and self.channel is None and self.state is None
            and self.version is None and self.vrrp is None and self.result is None and self.retained is None, "once")
        self.attempted = True
        budgets = self.budgets
        source = execution.execute_mixed_inputs(self.root, budgets)
        self.source = source
        results, subjects, held = _produce(self, source, budgets)
        tree, channel, state_result, version_result, vrrp_result = results
        _need(self.attempted is True and self.source is source and self.tree is tree and self.channel is channel
            and self.state is state_result and self.version is version_result and self.vrrp is vrrp_result and self.result is None, "source")
        result = MixedComponent(source=source, tree=tree, channel=channel, state=state_result, version=version_result, vrrp=vrrp_result)
        self.retained = _Retained(component=result, subjects=subjects, held=held)
        self.result = result
        return result


    def current_component(self) -> MixedComponent:
        """Reclose current original cells on demand; returned records are not sealed."""
        _need(type(self) is MixedComponentRun and self.attempted is True and type(self.retained) is _Retained, "source")
        retained = self.retained
        if retained is None:
            raise ValueError("fhrp_mixed_component_source")
        _need(type(retained.component) is MixedComponent and type(retained.subjects) is tuple and len(retained.subjects) == 4
            and all(type(subjects) is tuple and all(type(subject) is str for subject in subjects) for subjects in retained.subjects)
            and type(retained.held) is tuple and len(retained.held) == 5 and all(type(held) is tuple and len(held) == 3
                and type(held[0]) is FactStore and type(held[1]) is tuple and type(held[2]) is tuple
                and all(type(cell) is tuple and len(cell) == 3 and type(cell[0]) is str and type(cell[1]) is str
                    and type(cell[2]) in (k.Known, k.Unknown) for cell in held[2]) for held in retained.held), "source")
        result = retained.component
        _need(self.result is result and self.source is result.source and self.tree is result.tree and self.channel is result.channel
            and self.state is result.state and self.version is result.version and self.vrrp is result.vrrp, "source")
        _close(self, result.source, (result.tree, result.channel, result.state, result.version, result.vrrp),
            retained.subjects, retained.held, self.budgets)
        return result


def _produce(run: MixedComponentRun | RootMixedComponentRun,
    source: execution.MixedExecution | execution.RootMixedExecution, budgets: Budgets,
) -> tuple[Results, Subjects, RootHeldResults]:
    self = run
    _validate_source(self, source, budgets)
    hsrp, local, state, version, owner = source.fhrp.hsrp, source.fhrp.vrrp_inputs, source.fhrp.state, source.fhrp.version, source.fhrp.vrrp_owner
    if hsrp is None or local is None or state is None or version is None or owner is None:
        raise ValueError("fhrp_mixed_component_source")
    tree_targets = stp.declared_root_guard_targets(source.execution.envelope, budgets)
    fresh = SummaryPack[execution.Value](budgets)
    fresh.prepare(source.execution.envelope)
    actual, wanted = source.channel.owner.plan.indexed, fresh.owner.plan.indexed
    _need(type(actual) is dict and all(type(key) is tuple and len(key) == 2
        and all(type(value) is str for value in key) for key in actual) and set(actual) == set(wanted)
        and all(actual[key].node is target.node and actual[key] == target for key, target in wanted.items())
        and source.channel.owner.plan.proofs == fresh.owner.plan.proofs, "population")
    tree_subjects = tuple(stp.subject(row.target, vlan) for row in tree_targets for vlan in row.target.vlans)
    channel_subjects = tuple(ec.subject(target, group) for target in wanted.values() for group in target.groups)
    hsrp_subjects = tuple(build.subject(target, interface, group) for target in hsrp.version.targets for interface, group in target.groups)
    vrrp_subjects = tuple(vrrp_inputs.subject(target, interface, group) for target in local.vrrp.targets for interface, group in target.groups)
    _need(all(all(type(subject) is str for subject in subjects) and len(set(subjects)) == len(subjects)
        for subjects in (tree_subjects, channel_subjects, hsrp_subjects, vrrp_subjects)), "population")
    _validate_source(self, source, budgets)
    outputs = source.execution.executed
    self.tree = tree = source.tree.finish(source.execution)
    tree_held = tree.store, tree.rows, (_root_cells(stp.root_fact_rows(tree))
        if isinstance(source, execution.RootMixedExecution) else _cells(stp.fact_rows(tree)))
    self.channel = channel = source.channel.finish(source.execution)
    channel_held = channel.store, channel.rows, _cells(ec.fact_rows(channel))
    self.state = state_result = state.finish(tuple(state.own(output) for output in outputs if output.receipt.capture.operation == build.hsrp.OP))
    state_held = state_result.store, state_result.rows, _cells(build.fact_rows(state_result))
    self.version = version_result = version.finish(tuple(output for output in outputs if output.receipt.capture.operation == version_profile.parser.OP))
    version_held = version_result.store, version_result.rows, tuple((version_profile.REPORTED_PROTOCOL_VERSION, row.subject, row.value) for row in version_result.rows)
    self.vrrp = vrrp_result = owner.finish()
    vrrp_held = vrrp_result.store, vrrp_result.rows, tuple((vrrp_profile.REPORTED_VRRP_STATE, row.subject, row.value) for row in vrrp_result.rows)
    results = tree, channel, state_result, version_result, vrrp_result
    subjects = tree_subjects, channel_subjects, hsrp_subjects, vrrp_subjects
    held = tree_held, channel_held, state_held, version_held, vrrp_held
    _close(self, source, results, subjects, held, budgets)
    return results, subjects, held


class RootMixedComponentRun:
    """Consume one fresh invocation; failed later finishing retains prior returned results.

    A Store whose finish fails before returning is not retained here.
    """

    def __init__(self, root: Path, budgets: Budgets) -> None:
        self.root, self.budgets, self.attempted = root, budgets, False
        self.source: execution.RootMixedExecution | None = None
        self.tree: stp.Result | None = None
        self.channel: ec.Result | None = None
        self.state: build.Result | None = None
        self.version: VersionResult | None = None
        self.vrrp: VRRPResult | None = None
        self.result: RootMixedComponent | None = None
        self.retained: _RootRetained | None = None

    def build(self) -> RootMixedComponent:
        _need(type(self) is RootMixedComponentRun and self.attempted is False and self.source is None
            and self.tree is None and self.channel is None and self.state is None
            and self.version is None and self.vrrp is None and self.result is None and self.retained is None, "once")
        self.attempted = True
        budgets = self.budgets
        source = execution.execute_root_mixed_inputs(self.root, budgets)
        self.source = source
        results, subjects, held = _produce(self, source, budgets)
        tree, channel, state_result, version_result, vrrp_result = results
        _need(self.attempted is True and self.source is source and self.tree is tree and self.channel is channel
            and self.state is state_result and self.version is version_result and self.vrrp is vrrp_result and self.result is None, "source")
        result = RootMixedComponent(source=source, tree=tree, channel=channel, state=state_result, version=version_result, vrrp=vrrp_result)
        self.retained = _RootRetained(component=result, subjects=subjects, held=held)
        self.result = result
        return result


    def current_component(self) -> RootMixedComponent:
        """Reclose current original cells on demand; returned records are not sealed."""
        _need(type(self) is RootMixedComponentRun and self.attempted is True and type(self.retained) is _RootRetained, "source")
        retained = self.retained
        if retained is None:
            raise ValueError("fhrp_mixed_component_source")
        _need(type(retained.component) is RootMixedComponent and type(retained.subjects) is tuple and len(retained.subjects) == 4
            and all(type(subjects) is tuple and all(type(subject) is str for subject in subjects) for subjects in retained.subjects)
            and type(retained.held) is tuple and len(retained.held) == 5 and all(type(held) is tuple and len(held) == 3
                and type(held[0]) is FactStore and type(held[1]) is tuple and type(held[2]) is tuple
                and all(type(cell) is tuple and len(cell) == 3 and type(cell[0]) is str and type(cell[1]) is str
                    and type(cell[2]) in (k.Known, k.Unknown) for cell in held[2]) for held in retained.held), "source")
        result = retained.component
        _need(self.result is result and self.source is result.source and self.tree is result.tree and self.channel is result.channel
            and self.state is result.state and self.version is result.version and self.vrrp is result.vrrp, "source")
        _close(self, result.source, (result.tree, result.channel, result.state, result.version, result.vrrp),
            retained.subjects, retained.held, self.budgets)
        return result


def _validate_source(run: object, source: execution.MixedExecution | execution.RootMixedExecution, budgets: Budgets) -> None:
    if isinstance(source, execution.RootMixedExecution):
        _need(type(run) is RootMixedComponentRun, "source")
        execution.validate_root_mixed_execution(source, budgets)
    else:
        _need(type(run) is MixedComponentRun, "source")
        execution.validate_mixed_execution(source, budgets)


def build_mixed_component(root: Path, budgets: Budgets) -> MixedComponent:
    return MixedComponentRun(root, budgets).build()


def build_mixed_source(root: Path, budgets: Budgets) -> MixedComponentRun:
    """Own one fresh root/budget invocation and retain its current-value comparison source."""
    source = MixedComponentRun(root, budgets)
    source.build()
    return source


def build_root_mixed_component(root: Path, budgets: Budgets) -> RootMixedComponent:
    return RootMixedComponentRun(root, budgets).build()


def build_root_mixed_source(root: Path, budgets: Budgets) -> RootMixedComponentRun:
    source = RootMixedComponentRun(root, budgets)
    source.build()
    return source
