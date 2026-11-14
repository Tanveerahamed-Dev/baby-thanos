"""Fresh fixed VERSION Source closure for trusted callbacks and frozen kernel payloads.
Current map/cell checks are not a deep-mutation, execution-origin or field seal.
"""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.p4_admission import Envelope
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactStore, bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import peer_canonical as custody
from atlas_brain.packs.l3.fhrp import peer_execution as components
from atlas_brain.packs.l3.fhrp import peer_profile as profile
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.packs.l3.fhrp import version_profile as version
from atlas_brain.runner import p4 as observations
from atlas_brain.runner import p4_pipeline
from atlas_brain.runner.p4_refs import FhrpVersionProofIndex, VersionValue


@dataclass(frozen=True, slots=True, kw_only=True)
class FhrpVersionSource:
    source: vo.VersionResult
    execution: p4_pipeline.Result[VersionValue]
    domains: tuple[fhrp.Target, ...]
    proofs: FhrpVersionProofIndex


def _budget_values(budgets: Budgets) -> tuple[int, ...]:
    return (budgets.bundle_bytes, budgets.artifact_bytes, budgets.artifacts, budgets.nesting_depth,
            budgets.numeric_digits, budgets.compression_ratio, budgets.archive_index_bytes)


def prepare_fhrp_version_source(root: Path, budgets: Budgets) -> FhrpVersionSource:
    """Own one fresh snapshot and all closures; never admit a supplied component or Source."""
    k.require(isinstance(root, Path) and type(budgets) is Budgets, "fhrp_version_source_input")
    expected = _budget_values(budgets)
    k.require(all(type(value) is int and value > 0 for value in expected), "fhrp_version_source_budget")
    first = profile.compile_peer_state_version_profile()
    metadata = first.catalogue_bytes, first.registration_bytes, first.registration_sha256
    component = components.build_peer_state_version_component(root, budgets)
    k.require(type(component) is components.PeerStateVersionComponent, "fhrp_version_source_component")
    execution = component.execution
    k.require(type(execution) is p4_pipeline.Result, "fhrp_version_source_component")
    envelope, outputs = execution.envelope, execution.executed
    k.require(type(envelope) is Envelope, "fhrp_version_source_component")
    tree, channel, state, source = component.tree, component.channel, component.state, component.version
    tree_owner, channel_owner = component.tree_owner, component.channel_owner
    state_owner, version_owner = component.state_owner, component.version_owner
    k.require(type(tree) is stp.Result and type(channel) is ec.Result and type(state) is fhrp.Result
              and type(source) is vo.VersionResult and type(tree_owner) is stp.RootGuardPack
              and type(channel_owner) is ec.ProtocolOwner and type(state_owner) is fhrp.StateOwner
              and type(version_owner) is vo.PeerGlobalVersionOwner, "fhrp_version_source_component")
    stores = tree.store, channel.store, state.store, source.store
    k.require(all(type(store) is FactStore and type(store.owners) is dict
              and all(type(fact) is str and type(owner) is str for fact, owner in store.owners.items())
              and type(store.values) is dict and all(type(ref) is k.FactRef
                  and type(ref.fact) is str and type(ref.subject) is str for ref in store.values)
              for store in stores), "fhrp_version_source_store")
    cells = tuple((store, dict(store.owners), tuple((ref.fact, ref.subject, value)
                  for ref, value in store.values.items())) for store in stores)

    def current() -> tuple[object, ...]:
        return (component.execution, execution.envelope, execution.executed,
            envelope.raw, envelope.base, envelope.base.raw, envelope.base.nodes, envelope.base.captures,
            envelope.targets, envelope.captures,
            component.tree, component.channel, component.state, component.version,
            component.tree_owner, component.channel_owner, component.state_owner, component.version_owner,
            tree.store, channel.store, state.store, source.store,
            tree.rows, channel.rows, state.rows, source.rows,
            tree.executed, channel.executed, state.executed, source.executed)

    held = current()

    def guard() -> None:
        values = _budget_values(budgets)
        k.require(all(type(value) is int and value > 0 for value in values) and values == expected,
                  "fhrp_version_source_budget")
        k.require(all(type(store.owners) is dict
                  and all(type(fact) is str and type(owner) is str for fact, owner in store.owners.items())
                  and store.owners == owners and type(store.values) is dict and all(type(ref) is k.FactRef
                      and type(ref.fact) is str and type(ref.subject) is str for ref in store.values)
                  and len(store.values) == len(original)
                  and {(ref.fact, ref.subject) for ref in store.values} == {(fact, subject) for fact, subject, _ in original}
                  and all(store.values.get(k.FactRef(fact=fact, subject=subject)) is value
                          for fact, subject, value in original)
                  for store, owners, original in cells), "fhrp_version_source_store")
        k.require(all(actual is original for actual, original in zip(current(), held, strict=True))
                  and type(fhrp.REPORTED_STATE) is str and fhrp.REPORTED_STATE == "l3.fhrp.reported_state"
                  and all(type(value) is str for value in (tree_owner.registration, channel_owner.registration,
                      state_owner.registration, source.registration_sha256, envelope.registration_sha256))
                  and tree_owner.envelope is envelope and tree_owner.budgets is budgets
                  and version_owner.envelope is envelope and version_owner.budgets is budgets
                  and tree_owner.registration == channel_owner.registration == state_owner.registration
                      == source.registration_sha256 == envelope.registration_sha256 == metadata[2],
                  "fhrp_version_source_identity")

    guard()
    custody.canonical_peer_state_version_outputs(execution, state_owner, version_owner, budgets)
    guard()
    index = FhrpVersionProofIndex(execution, budgets)
    k.require(index.execution is execution and index.budgets is budgets, "fhrp_version_source_identity")
    guard()
    tree_step = StepSpec(id=StepId("l2.stp/prepare_fhrp_version_source"), pack=stp.PACK, kind="derive", scope="estate",
        reads=stp.STEP.produces, produces=(), evaluator="l2.stp.prepare_fhrp_version_source")
    channel_step = StepSpec(id=StepId("l2.etherchannel/prepare_fhrp_version_source"), pack=ec.PACK, kind="derive", scope="estate",
        reads=ec.STEP.produces, produces=(), evaluator="l2.etherchannel.prepare_fhrp_version_source")
    state_step = StepSpec(id=StepId("l3.fhrp/prepare_version_state_source"), pack=fhrp.PACK, kind="derive", scope="estate",
        reads=(fhrp.REPORTED_STATE,), produces=(), evaluator="l3.fhrp.prepare_version_state_source")
    version_step = StepSpec(id=StepId("l3.fhrp/prepare_protocol_version_source"), pack=version.PACK, kind="derive", scope="estate",
        reads=(version.REPORTED_PROTOCOL_VERSION,), produces=(), evaluator="l3.fhrp.prepare_fhrp_version_source")
    order_steps((stp.STEP, ec.STEP, fhrp.STEP, version.STEP, tree_step, channel_step, state_step, version_step))
    guard()
    tree_reader, channel_reader = bind_reader(tree.store, step=tree_step), bind_reader(channel.store, step=channel_step)
    state_reader, version_reader = bind_reader(state.store, step=state_step), bind_reader(source.store, step=version_step)
    tree_owner.validate_root_guard_values(tree, tree_reader, outputs)
    guard()
    channel_owner.validate_reported_protocol_values(channel, channel_reader, outputs)
    guard()
    domains = state_owner.validate_gateway_source_values(state, state_reader, outputs)
    guard()
    version_owner.validate_values(source, version_reader)
    guard()
    observations.close_owned_facts(index, tree, channel, state)
    guard()
    index.close_protocol_version(source, version_reader, version_owner)
    guard()
    custody.canonical_peer_state_version_outputs(execution, state_owner, version_owner, budgets)
    guard()
    current_metadata = profile.compile_peer_state_version_profile()
    k.require(metadata == (current_metadata.catalogue_bytes, current_metadata.registration_bytes,
                           current_metadata.registration_sha256), "fhrp_version_source_registration")
    guard()
    return FhrpVersionSource(source=source, execution=execution, domains=domains, proofs=index)
