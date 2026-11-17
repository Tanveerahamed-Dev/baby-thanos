"""Owning positive HSRP presence; no census absence, baseline, health or view API."""
from pathlib import Path

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model import handle_comparison as handles
from atlas_brain.model import pack_registration as registration
from atlas_brain.model import store as storage
from atlas_brain.model.specs import FactSpec, StepId, StepSpec
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import reported_presence_custody as custody
from atlas_brain.packs.l3.fhrp import reported_presence_graph as graph
from atlas_brain.packs.l3.fhrp import reported_presence_parts as parts
from atlas_brain.packs.l3.fhrp import required_report_premises as premises
from atlas_brain.packs.l3.fhrp import required_report_profile as profile
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.packs.l3.fhrp.reported_presence_parts import Result, Row
from atlas_brain.runner import p4_pipeline

FACT = k.FactId("l3.fhrp.reported_group_present")
STEP = StepSpec(id=StepId("l3.fhrp/derive_reported_presence"),pack=state.PACK,kind="derive",scope="device",
    reads=(state.REPORTED_STATE,),produces=(FACT,),evaluator="l3.fhrp.build_reported_presence")
DECLARATION = registration.PackDeclaration(pack=state.PACK,entity_kinds=state.DECLARATION.entity_kinds,
    facts=state.DECLARATION.facts+(FactSpec(id=FACT,pack=state.PACK,subject="fhrp_local",value_type="boolean",step=STEP.id),),
    relations=(),steps=(state.STEP,STEP),operations=(state.BINDING,))


def _need(condition: bool) -> None:
    k.require(condition,"hsrp_presence_source")


def contract() -> registration.PackDeclaration:
    return parts.positive_contract(FACT,STEP,DECLARATION)


class PresencePack(StandbyBriefPack[object]):
    """Trusted preparation only; the folder builder owns all subsequent custody."""
    def __init__(self,budgets: Budgets,*,_required: profile.Inputs | None=None,_factory: PresenceRun | None=None) -> None:
        super().__init__(budgets)
        self.requirement_inputs=_required
        self.factory=_factory
        self.premises: premises.Retained | None=None
        self.bindings: custody.PlanBindings | None=None
        self.original_run: tuple[type[object],object] | None=None

    def declaration(self) -> registration.PackDeclaration:
        declared=contract()
        _need(self.requirement_inputs is None or type(self.requirement_inputs) is profile.Inputs)
        return declared if self.requirement_inputs is None else profile.declaration()

    def prepare(self,envelope: p4.Envelope) -> p4_pipeline.Prepared[object]:
        contract()
        prepared=StandbyBriefPack[object].prepare(self,envelope)
        self.bindings=custody.retain_plan(self.owner,envelope,self.budgets)
        self.original_run=(type(self.run),self.run)
        if self.requirement_inputs is not None:
            self.premises=premises.retain(envelope,self.budgets,
                tuple(self.owner.plan.indexed.values()),self.requirement_inputs)
        if self.factory is not None:PresenceRun.retain_prepare(self.factory,self)
        return prepared


class PresenceRun:
    """One actual fixed-profile run; retained comparisons do not admit supplied carriers."""
    @classmethod
    def open_folder(cls,root: Path,budgets: Budgets) -> PresenceRun:
        _need(cls is PresenceRun)
        return PresenceRun(root,budgets)

    @classmethod
    def open_required_report_folder(cls,root: Path,budgets: Budgets,
        policies: tuple[policy.GatewayPolicy,...],baseline_raw: bytes | None,
    ) -> PresenceRun:
        _need(cls is PresenceRun)
        return PresenceRun(root,budgets,_requirements=profile.Inputs(policies=policies,baseline_raw=baseline_raw))

    def __init__(self,root: Path,budgets: Budgets,*,_requirements: profile.Inputs | None=None) -> None:
        _need(type(self) is PresenceRun and (_requirements is None or type(_requirements) is profile.Inputs))
        self.budgets=budgets
        self.requirements=_requirements
        self.original_bindings: custody.PlanBindings | None=None
        self.original_premises: premises.Retained | None=None
        self.run_type: type[object]=object
        self.original_run: object=object()
        self.pack=PresencePack(budgets,_required=_requirements,_factory=self)
        tree,channel=stp.RootGuardPack[object](budgets),SummaryPack[object](budgets)
        execution=p4_pipeline.execute_p4_folder(root,budgets,packs=(tree,channel,self.pack))
        _need(type(self) is PresenceRun and type(self.pack) is PresencePack and type(execution) is p4_pipeline.Result
            and self.pack.bindings is self.original_bindings)
        run,plan=self.pack.run,self.pack.bindings
        if run is None or plan is None:raise ValueError("hsrp_presence_source")
        _need(type(run) is self.run_type and run is self.original_run)
        self.owner,self.plan,self.execution=run.owner,plan,execution
        self.held=custody.retain_execution(plan,self.owner,execution,budgets)
        self.labels=tuple((key,target.node.id) for key,target in sorted(plan.indexed.items()))
        self.original=graph.source_rows_bytes(PresenceRun.canonical_rows(self),plan.indexed,plan.targets)
        # All original comparison data above precedes every real pack Writer.
        stp.RootGuardPack[object].finish(tree,execution)
        PresenceRun.close_inputs(self)
        SummaryPack[object].finish_current(channel,execution)
        PresenceRun.close_inputs(self)
        source=StandbyBriefPack[object].finish(self.pack,execution)
        PresenceRun.close_inputs(self)
        _need(type(source) is state.Result and type(source.rows) is tuple and type(source.executed) is tuple
            and type(source.store) is storage.FactStore)
        graph.source_rows_bytes(source.rows,plan.indexed,plan.targets)
        self.source,self.original_rows,self.source_outputs=source,source.rows,source.executed
        self.source_store=source.store
        self.source_cells=tuple((row,row.value) for row in source.rows)
        self.source_maps=(source.store.owners,source.store.values)
        sources=PresenceRun.close_source(self)
        accesses=tuple((state.REPORTED_STATE,row.subject) for row in sources)
        source_store=self.source_store
        reader=storage.bind_reader(source_store,step=STEP)
        _need(type(reader) is storage.FactReader and reader.store is self.source_store and reader.step is STEP)
        reader_anchor=handles.retain_handle(reader)
        observed: list[storage.StoredState]=[]
        for fact,subject in accesses:
            handles.compare_reader(reader_anchor,reader,fact=fact,subject=subject)
            observed.append(storage.FactReader.read(reader,fact=fact,subject=subject))
        sources=PresenceRun.close_source(self)
        _need(type(reader) is storage.FactReader and reader.store is self.source_store and reader.step is STEP
            and all(value is row.value for value,row in zip(observed,sources,strict=True)))
        rows=tuple(Row(source=row,value=k.Known(value=True,raw=None,basis=k.Basis.DERIVED,
            evidence=(k.FactRef(fact=state.REPORTED_STATE,subject=row.subject),)) if type(row.value) is k.Known else row.value)
            for row in sources)
        self.presence_store=storage.FactStore()
        self.presence_maps=(self.presence_store.owners,self.presence_store.values)
        self.original_presence_rows=rows
        self.presence_cells=tuple((row,row.value) for row in rows)
        self.result=Result(source=source,store=self.presence_store,rows=rows)
        self.original_result=self.result
        writer=storage.bind_writer(self.presence_store,step=STEP)
        _need(type(writer) is storage.FactWriter and writer.store is self.presence_store and writer.step is STEP)
        writer_anchor=handles.retain_handle(writer)
        writes=tuple((FACT,row.source.subject,row.value) for row in rows)
        for fact,subject,value in writes:
            handles.compare_writer(writer_anchor,writer,fact=fact,subject=subject,value=value)
            storage.FactWriter.write(writer,fact=fact,subject=subject,value=value)
        PresenceRun.close(self)
        _need(type(writer) is storage.FactWriter and writer.store is self.presence_store and writer.step is STEP)

    def retain_prepare(self,pack: PresencePack) -> None:
        """Capture this factory's real prepare before parser exposure; not supplied-pack admission."""
        _need(type(self) is PresenceRun and type(pack) is PresencePack and pack is self.pack
            and pack.factory is self and self.original_bindings is None and type(pack.bindings) is custody.PlanBindings)
        if pack.original_run is None:raise ValueError("hsrp_presence_source")
        self.run_type,self.original_run=pack.original_run
        self.original_bindings,self.original_premises=pack.bindings,pack.premises

    def canonical_rows(self) -> tuple[state.Row,...]:
        _need(type(self) is PresenceRun)
        _need(type(self.pack) is PresencePack and type(self.execution) is p4_pipeline.Result
            and type(self.plan) is custody.PlanBindings and type(self.held) is custody.ExecutionBindings)
        _need(self.requirements is None or type(self.requirements) is profile.Inputs)
        _need(self.pack.factory is self and self.pack.requirement_inputs is self.requirements
            and self.pack.bindings is self.original_bindings and self.pack.premises is self.original_premises)
        declaration=PresencePack.declaration(self.pack)
        compiled=registration.compile_packs((stp.DECLARATION,ec.DECLARATION,declaration))
        pack,execution,plan=self.pack,self.execution,self.plan
        run=pack.run
        _need(type(run) is self.run_type and run is self.original_run and run is not None)
        if run is None:raise ValueError("hsrp_presence_source")
        _need(run.owner is self.owner and pack.budgets is self.budgets and type(run.registration) is str
            and run.envelope is execution.envelope and run.registration==plan.registration and self.held.plan is plan)
        owned=custody.close_execution(self.held,self.owner,execution,self.budgets)
        _need(run.registration==compiled.registration_sha256)
        if self.requirements is None:_need(self.original_premises is None)
        else:
            _need(type(self.original_premises) is premises.Retained)
            if self.original_premises is None:raise ValueError("hsrp_presence_source")
            premises.close(self.original_premises,run.envelope,self.budgets,self.requirements)
        _need(type(self.labels) is tuple and all(type(item) is tuple and len(item)==2
            and type(item[0]) is tuple and len(item[0])==2 and all(type(part) is str for part in item[0])
            and type(item[1]) is str for item in self.labels))
        _need(self.labels==tuple((key,target.node.id) for key,target in sorted(plan.indexed.items())))
        return state.StateOwner.reclose_current_rows(self.owner,run.envelope,self.budgets,owned)

    def close_inputs(self) -> tuple[state.Row,...]:
        wanted=PresenceRun.canonical_rows(self)
        _need(type(self.original) is bytes
            and graph.source_rows_bytes(wanted,self.plan.indexed,self.plan.targets)==self.original)
        return wanted

    def close_source(self) -> tuple[state.Row,...]:
        wanted=PresenceRun.close_inputs(self)
        source,rows=self.source,self.original_rows
        _need(type(self.pack.finished) is bool and self.pack.finished
            and type(self.owner.finished) is bool and self.owner.finished and type(source) is state.Result
            and source.store is self.source_store and source.rows is rows and type(rows) is tuple
            and source.executed is self.source_outputs and type(self.source_outputs) is tuple
            and type(self.source_cells) is tuple and type(self.source_maps) is tuple and len(self.source_maps)==2)
        _need(all(type(cell) is tuple and len(cell)==2 and type(cell[0]) is state.Row for cell in self.source_cells))
        _need(len(self.source_outputs)==len(self.held.produced_values)
            and all(type(out) is type(original_out) and out.receipt is original_out.receipt and out.value is original_out.value
                for out,original_out in zip(self.source_outputs,
                    (out for out in self.held.outputs if out.receipt.capture.operation==state.hsrp.OP),strict=True)))
        current=graph.source_rows_bytes(rows,self.plan.indexed,self.plan.targets)
        _need(current==self.original==graph.source_rows_bytes(wanted,self.plan.indexed,self.plan.targets)
            and len(rows)==len(self.source_cells) and all(row is before and row.value is value
                for row,(before,value) in zip(rows,self.source_cells,strict=True)))
        parts.compare_store(self.source_store,state.REPORTED_STATE,state.STEP.id,
            tuple((row.subject,value) for row,value in self.source_cells),self.source_maps)
        return rows

    def close(self) -> Result:
        sources=PresenceRun.close_source(self)
        result=self.result
        _need(type(result) is Result and result is self.original_result and result.source is self.source
            and result.store is self.presence_store and result.rows is self.original_presence_rows
            and type(result.rows) is tuple and len(result.rows)==len(sources)
            and type(self.presence_cells) is tuple and type(self.presence_maps) is tuple and len(self.presence_maps)==2)
        _need(all(type(cell) is tuple and len(cell)==2 and type(cell[0]) is Row for cell in self.presence_cells)
            and len(result.rows)==len(self.presence_cells))
        for row,source,(original,value) in zip(result.rows,sources,self.presence_cells,strict=True):
            _need(type(row) is Row and row is original and row.source is source and row.value is value)
            parts.validate_positive_value(value,source.value,source.subject)
        parts.compare_store(self.presence_store,FACT,STEP.id,tuple((row.source.subject,row.value) for row in result.rows),self.presence_maps)
        return result

    def required_premises(self) -> premises.baseline.BaselinePreparation:
        """Fresh-own the actual pre-parser declared premises; never adopt external preparations."""
        PresenceRun.close(self)
        _need(type(self.original_premises) is premises.Retained)
        if self.original_premises is None:raise ValueError("hsrp_presence_source")
        return self.original_premises.prepared

    def source_rows(self) -> tuple[state.Row,...]:
        """Fresh-own current original Source rows; never admit an external Source."""
        return PresenceRun.close(self).source.rows

    def presence_rows(self) -> tuple[Row,...]:
        """Fresh-own current positive/Unknown facts; no detached-view or absence seal."""
        return PresenceRun.close(self).rows


def build_reported_presence(root: Path,budgets: Budgets) -> Result:
    """Convenience result; C01 must retain its own actual live factory run."""
    return PresenceRun.close(PresenceRun.open_folder(root,budgets))
