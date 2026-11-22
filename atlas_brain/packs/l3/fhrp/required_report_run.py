"""Ordinary-folder owning missing-required-report predicate; no canonical endpoint or health."""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model import handle_comparison as handles
from atlas_brain.model import store as storage
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import redundancy_baseline as baseline
from atlas_brain.packs.l3.fhrp import reported_presence as present
from atlas_brain.packs.l3.fhrp import required_report_profile as profile


@dataclass(frozen=True,slots=True,kw_only=True)
class Row:
    subject: k.EntityKey
    requirement: baseline.Requirement
    operands: tuple[present.Row,...]
    value: k.Known[bool] | k.Unknown


@dataclass(frozen=True,slots=True,kw_only=True)
class Result:
    store: storage.FactStore
    rows: tuple[Row,...]


def _need(condition: bool) -> None:
    k.require(condition,"fhrp_required_reports")


class RequiredReportRun:
    """Own a new literal required-profile folder run; never adopt supplied result carriers."""
    def __init__(self,root: Path,budgets: Budgets,policies: tuple[policy.GatewayPolicy,...],baseline_raw: bytes | None) -> None:
        _need(type(self) is RequiredReportRun)
        live=present.PresenceRun.open_required_report_folder(root,budgets,policies,baseline_raw)
        _need(type(self) is RequiredReportRun)
        self.live,self.original_live=live,live
        self.baseline=present.PresenceRun.required_premises(self.live)
        self.original_baseline=self.baseline
        self.read_attempted=False
        RequiredReportRun.read_presence(self)
        rows=RequiredReportRun.expected_rows(self)
        self.store=storage.FactStore()
        self.maps=(self.store.owners,self.store.values)
        self.result=Result(store=self.store,rows=rows)
        self.original_result=self.result
        self.rows=rows
        self.cells=tuple((row,row.value) for row in rows)
        writer=storage.bind_writer(self.store,step=profile.STEP)
        _need(type(writer) is storage.FactWriter and writer.store is self.store and writer.step is profile.STEP)
        writer_anchor=handles.retain_handle(writer)
        writes=tuple((profile.MISSING,row.subject,row.value) for row in rows)
        for fact,subject,value in writes:
            handles.compare_writer(writer_anchor,writer,fact=fact,subject=subject,value=value)
            storage.FactWriter.write(writer,fact=fact,subject=subject,value=value)
        RequiredReportRun.close(self)
        _need(type(writer) is storage.FactWriter and writer.store is self.store and writer.step is profile.STEP)

    def read_presence(self) -> tuple[present.Row,...]:
        _need(type(self) is RequiredReportRun and type(self.read_attempted) is bool and not self.read_attempted)
        self.read_attempted=True
        operands=present.PresenceRun.presence_rows(self.live)
        accesses=tuple((profile.PRESENCE,row.source.subject) for row in operands)
        source_store=self.live.result.store
        reader=storage.bind_reader(source_store,step=profile.STEP)
        _need(type(reader) is storage.FactReader and reader.store is self.live.result.store and reader.step is profile.STEP)
        reader_anchor=handles.retain_handle(reader)
        observed: list[storage.StoredState]=[]
        for fact,subject in accesses:
            handles.compare_reader(reader_anchor,reader,fact=fact,subject=subject)
            observed.append(storage.FactReader.read(reader,fact=fact,subject=subject))
        current=RequiredReportRun.current_operands(self)
        _need(type(reader) is storage.FactReader and reader.store is self.live.result.store and reader.step is profile.STEP
            and all(value is row.value for value,row in zip(observed,current,strict=True)))
        return current

    def current_operands(self) -> tuple[present.Row,...]:
        _need(type(self) is RequiredReportRun and self.live is self.original_live)
        profile.declaration()
        rows=present.PresenceRun.presence_rows(self.live)
        _need(present.PresenceRun.required_premises(self.live) is self.baseline
            and self.baseline is self.original_baseline)
        return rows

    def expected_rows(self) -> tuple[Row,...]:
        operands=RequiredReportRun.current_operands(self)
        indexed={row.source.subject:row for row in operands}
        _need(len(indexed)==len(operands))
        result: list[Row]=[]
        for requirement in self.baseline.rows:
            points=requirement.expected_participants
            selected=tuple(indexed[point.subject] for point in (requirement.scope.participants if points is None else points))
            value=requirement.primary_gap
            if value is None:
                value=next((row.value for row in selected if type(row.value) is k.Unknown),None)
            if value is None:
                _need(points is not None and len(points)>0
                    and all(type(row.value) is k.Known and row.value.value is True for row in selected))
                refs=requirement.baseline.evidence+requirement.population.evidence+requirement.binding.evidence
                derived=k.Known(value=False,raw=None,basis=k.Basis.DERIVED,evidence=refs+tuple(
                    k.FactRef(fact=profile.PRESENCE,subject=row.source.subject) for row in selected))
                state: k.Known[bool] | k.Unknown=derived
            else:state=value
            subject=k.EntityKey("fhrp_requirement:"+sha256(canonical(("atlas-brain.fhrp-required-report/1",
                self.baseline.scope.sha256,requirement.scope.policy_id))).hexdigest())
            result.append(Row(subject=subject,requirement=requirement,operands=selected,value=state))
        return tuple(result)

    def close(self) -> Result:
        wanted=RequiredReportRun.expected_rows(self)
        result=self.result
        _need(type(result) is Result and result is self.original_result and result.store is self.store
            and result.rows is self.rows and type(result.rows) is tuple and len(result.rows)==len(wanted)
            and type(self.cells) is tuple and len(self.cells)==len(wanted))
        _need(type(self.store) is storage.FactStore and type(self.store.owners) is dict and type(self.store.values) is dict
            and type(self.maps) is tuple and len(self.maps)==2
            and self.store.owners is self.maps[0] and self.store.values is self.maps[1])
        _need(all(type(key) is str and type(owner) is str for key,owner in self.store.owners.items())
            and all(type(ref) is k.FactRef and type(ref.fact) is str and type(ref.subject) is str for ref in self.store.values)
            and all(type(cell) is tuple and len(cell)==2 for cell in self.cells))
        for row,expected,(original,value) in zip(result.rows,wanted,self.cells,strict=True):
            _need(type(row) is Row and row is original and row.value is value and type(row.subject) is str
                and row.subject==expected.subject and row.requirement is expected.requirement
                and type(row.operands) is tuple and len(row.operands)==len(expected.operands)
                and all(actual is before for actual,before in zip(row.operands,expected.operands,strict=True)))
            if type(expected.value) is k.Unknown:_need(value is expected.value)
            else:
                _need(type(value) is k.Known and type(value.value) is bool and value.value is False
                    and value.raw is None and value.basis is k.Basis.DERIVED and type(value.evidence) is tuple
                    and all(type(ref) is k.RegistryRef or type(ref) is k.FactRef for ref in value.evidence))
                for ref in value.evidence:
                    if type(ref) is k.FactRef:_need(type(ref.fact) is str and type(ref.subject) is str)
                    elif type(ref) is k.RegistryRef:_need(type(ref.table) is str and type(ref.row_id) is str
                        and type(ref.table_digest) is str and type(ref.citation) is str)
                _need(value==expected.value)
        _need(self.store.owners=={profile.MISSING:profile.STEP.id} and len(self.store.values)==len(result.rows)
            and all(self.store.values.get(k.FactRef(fact=profile.MISSING,subject=row.subject)) is row.value for row in result.rows))
        return result
