"""Fresh fixed-profile primitive proof records from the caller's actual owning Run; never admission."""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets, record, strict_json
from atlas_brain.kernel import states as k
from atlas_brain.model import handle_comparison as handles
from atlas_brain.model import store
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import reported_presence as presence
from atlas_brain.packs.l3.fhrp import required_report_profile as profile
from atlas_brain.packs.l3.fhrp import required_report_run as required
from atlas_brain.packs.l3.fhrp import required_report_wire as wire
from atlas_brain.runner import p4_root_mixed_records as records


@dataclass(frozen=True,slots=True,kw_only=True)
class Projection:
    header: dict[str,object]
    inputs: tuple[bytes,...]
    captures: tuple[dict[str,object],...]
    registry: tuple[tuple[dict[str,object],bytes],...]
    local: wire.Rows
    requirements: wire.Rows


def _need(condition: bool) -> None:
    k.require(condition,"required_report_proof")


def _registry(ref: k.RegistryRef,raws: dict[str,bytes | None],budgets: Budgets) -> tuple[str,dict[str,object],bytes]:
    _need(type(ref) is k.RegistryRef and all(type(value) is str for value in
        (ref.table,ref.row_id,ref.table_digest,ref.citation)))
    _need(ref.table in raws)
    raw=raws[ref.table]
    _need(type(raw) is bytes)
    if raw is None:raise ValueError("required_report_proof")
    _need(sha256(raw).hexdigest()==ref.table_digest)
    fields=(("schema","semantic_group","group","nodes","captures") if ref.table.startswith("synthetic_p2.") else
        ("schema","semantic_group","context","base_sha256","targets","captures") if ref.table.startswith("synthetic_p4.") else
        ("schema","semantic_group","context","registration_sha256","registry_sha256","base_registry_sha256","gateways")
        if ref.table=="declared_fhrp_gateways" else
        ("schema","semantic_group","context","registry_sha256","base_registry_sha256","registration_sha256","requirements"))
    data=record(strict_json(raw,budgets.nesting_depth,budgets.numeric_digits),fields)
    heads={"synthetic_p2.nodes":"nodes","synthetic_p4.targets":"targets",
        "declared_fhrp_gateways":"gateways","declared_fhrp_redundancy_baseline":"requirements"}
    if ref.table in ("synthetic_p2.groups","synthetic_p4.context"):
        field="group" if ref.table=="synthetic_p2.groups" else "context"
        _need(ref.citation=="/"+field and data[field]==ref.row_id)
        value=data[field]
    else:
        parts=ref.citation.split("/")
        _need(len(parts) in (3,4) and parts[0]=="" and parts[1]==heads[ref.table]
            and 1<=len(parts[2])<=6 and parts[2].isascii() and parts[2].isdecimal())
        index=int(parts[2])
        _need(str(index)==parts[2])
        rows=data[parts[1]]
        if type(rows) is not list:raise ValueError("required_report_proof")
        entries=cast(list[object],rows)
        _need(0<=index<len(entries))
        row_fields=(("id","discovery_id","ports") if ref.table=="synthetic_p2.nodes" else
            ("id","node","operation","params") if ref.table=="synthetic_p4.targets" else
            ("id","domain","vlan","address_family","protocol","group","key","participants") if ref.table=="declared_fhrp_gateways" else
            ("id","domain","vlan","address_family","protocol","group","expected_participants","permitted_alternatives"))
        row=record(entries[index],row_fields)
        _need(row["id"]==ref.row_id)
        if len(parts)==4:
            _need(ref.table=="declared_fhrp_redundancy_baseline" and parts[3]=="expected_participants")
            value=row[parts[3]]
        else:value=row
    identity="registry-"+sha256(canonical((ref.table,ref.row_id,ref.table_digest,ref.citation))).hexdigest()
    return identity,{"id":identity,"table":ref.table,"row_id":ref.row_id,"table_sha256":ref.table_digest,
        "pointer":ref.citation,"raw":ref.table_digest,"encoding":"hex"},canonical(value)


def _project(run: required.RequiredReportRun) -> Projection:
    """Call after the final projection Reader; close fresh labels, values and all proof chains."""
    result=required.RequiredReportRun.close(run)
    live=run.live
    owned=presence.PresenceRun.close(live)
    prepared=presence.PresenceRun.required_premises(live)
    envelope=live.execution.envelope
    source=owned.source
    inputs=(envelope.base.raw,envelope.raw)+tuple(cap.raw for cap in envelope.base.captures)+tuple(
        member.raw for member in envelope.captures)+(prepared.scope.raw,)+(() if prepared.baseline_raw is None else (prepared.baseline_raw,))
    raw_by_table={"synthetic_p2.groups":envelope.base.raw,"synthetic_p2.nodes":envelope.base.raw,
        "synthetic_p4.context":envelope.raw,"synthetic_p4.targets":envelope.raw,
        "declared_fhrp_gateways":prepared.scope.raw,"declared_fhrp_redundancy_baseline":prepared.baseline_raw}
    registry: dict[str,tuple[dict[str,object],bytes]]={}
    outputs={out.receipt.capture.id:out for out in source.executed}
    def references(value: k.Known[bool] | k.Known[str] | k.Unknown,scope: state.Row | None) -> dict[str,object]:
        registered: list[str]=[]
        captures: list[dict[str,object]]=[]
        facts: list[dict[str,object]]=[]
        for ref in value.evidence:
            if type(ref) is k.RegistryRef:
                identity,record,fragment=_registry(ref,raw_by_table,live.budgets)
                registry[identity]=(record,fragment)
                registered.append(identity)
            elif type(ref) is k.FactRef:
                facts.append({"fact":ref.fact,"subject":ref.subject})
            else:
                if type(ref) is not k.EvidenceRef or scope is None:raise ValueError("required_report_proof")
                _need(ref.capture in outputs)
                out=outputs[ref.capture]
                capture=out.receipt.capture
                _need(capture.source==scope.target.node.key and capture.operation==state.hsrp.OP)
                claims=tuple((parsed,points) for parsed,points in state.reported_state_proofs(out)
                    if parsed.interface.raw==scope.interface and parsed.group.raw==scope.group)
                if type(ref.locator) is k.ByteSpan:
                    point=ref.locator
                    _need(type(point.start) is int and type(point.end) is int and 0<=point.start<point.end<=len(capture.raw)
                        and ref.role is (k.EvidenceRole.SUBJECT if type(value) is k.Known else k.EvidenceRole.WITNESS))
                    _need(len(claims)==1 and point in claims[0][1] if type(value) is k.Known
                        else any(point==parsed.span for parsed,_points in claims))
                    actual=sha256(capture.raw[point.start:point.end]).hexdigest()
                else:
                    _need(type(ref.locator) is k.WholeCapture and type(value) is k.Unknown and ref.role is k.EvidenceRole.WITNESS)
                    actual=sha256(capture.raw).hexdigest()
                _need(actual==ref.excerpt_sha256)
                if type(value) is k.Known:_need(capture.integrity is k.IntegrityState.COMPLETE and out.receipt.parse.quality=="complete")
                captures.append(records.evidence_record(ref,"p4"))
        return {"registry":registered,"captures":captures,"facts":facts}
    dependencies: list[k.FactRef]=[]
    def cell(fact: k.FactId,subject: k.EntityKey,value: k.Known[bool] | k.Known[str] | k.Unknown,
             scalar: type[bool | str],labels: dict[str,object],scope: state.Row | None,
             parents: tuple[k.FactRef,...]=()) -> dict[str,object]:
        supplied=tuple(ref for ref in value.evidence if type(ref) is k.FactRef)
        _need(supplied==(parents if type(value) is k.Known and fact!=state.REPORTED_STATE else ()))
        dependencies.extend(parents)
        return {"fact":fact,"subject":subject,"local":labels,"value":records.state_record(value,scalar),
            "evidence":[records.evidence_record(ref,"p4") for ref in value.evidence],"proof":references(value,scope),
            "dependencies":[{"fact":ref.fact,"subject":ref.subject} for ref in parents]}
    local: wire.Rows={}
    for row in owned.rows:
        source_row=row.source
        labels: dict[str,object]={"context":source_row.target.context,"node":source_row.target.node.key,"interface":source_row.interface,
            "group":source_row.group,"address_family":"ipv4","protocol":"hsrp"}
        local[source_row.subject,state.REPORTED_STATE]=cell(state.REPORTED_STATE,source_row.subject,source_row.value,str,labels,source_row)
        reference=k.FactRef(fact=state.REPORTED_STATE,subject=source_row.subject)
        record=cell(profile.PRESENCE,source_row.subject,row.value,bool,labels,source_row,(reference,))
        record["source"]={"fact":reference.fact,"subject":reference.subject,"same_original_unknown":row.value is source_row.value}
        local[source_row.subject,profile.PRESENCE]=record
    policies={item.id:item for item in prepared.policies}
    requirements: wire.Rows={}
    for row in result.rows:
        requirement=row.requirement
        declared=policies[requirement.scope.policy_id]
        scope=next((operand.source for operand in row.operands if operand.value is row.value),None)
        record=cell(profile.MISSING,row.subject,row.value,bool,{"requirement":declared.id,"domain":declared.domain,
            "vlan":declared.vlan,"address_family":declared.address_family,"protocol":declared.protocol,"group":declared.group},scope,
            tuple(k.FactRef(fact=profile.PRESENCE,subject=operand.source.subject) for operand in row.operands))
        record["premises"]=[{"name":name,"value":records.state_record(value,str),
            "evidence":[records.evidence_record(ref,"p4") for ref in value.evidence],"proof":references(value,None)}
            for name,value in (("baseline",requirement.baseline),("population",requirement.population),("binding",requirement.binding))]
        record["operands"]=[{"fact":profile.PRESENCE,"subject":operand.source.subject} for operand in row.operands]
        record["expected_participants"]=None if requirement.expected_participants is None else [
            {"target":point.target_id,"node":point.node,"interface":point.interface,"group":point.group,"subject":point.subject}
            for point in requirement.expected_participants]
        record["declared_binding_participants"]=[{"target":point.target_id,"node":point.node,"interface":point.interface,
            "group":point.group,"subject":point.subject} for point in requirement.scope.participants]
        record["declared_anycast_permissions"]=requirement.declared_anycast_permissions
        requirements[row.subject,profile.MISSING]=record
    capture_records=tuple(records.capture_record(out.receipt.capture,"p4",sha256(out.receipt.capture.raw).hexdigest())
        for out in sorted(source.executed,key=lambda out:out.receipt.capture.id))
    header: dict[str,object]={"schema":"atlas-brain.required-report-presence/1","semantic_group":"declared_synthetic",
        "scope":"declared_required_report_presence_only","health":"not_assessed","true_missing_report":"not_implemented",
        "context":envelope.context,"group":envelope.base.id,"registration_sha256":envelope.registration_sha256,
        "source_registries":{"p2":sha256(envelope.base.raw).hexdigest(),"p4":sha256(envelope.raw).hexdigest()},
        "declared_policy":{"raw":prepared.scope.sha256,"origin":"canonical_typed_policy_input"},
        "external_baseline":None if prepared.baseline_raw is None else {"raw":sha256(prepared.baseline_raw).hexdigest()},
        "denominator":dict(prepared.denominator),"source_denominator":{"declared_groups":len(source.rows),
            "reported_groups":sum(type(row.value) is k.Known for row in source.rows),
            "unknown_groups":sum(type(row.value) is k.Unknown for row in source.rows)},
        "input_artifacts":len(inputs),"input_bytes":sum(map(len,inputs)),"source_members":[{"target":member.target.id,"path":member.path,
            "node":member.target.node.key,"operation":member.target.operation,"raw":member.sha256} for member in envelope.captures]}
    available={k.FactRef(fact=k.FactId(fact),subject=k.EntityKey(subject)) for subject,fact in (*local,*requirements)}
    _need(all(ref in available for ref in dependencies))
    required.RequiredReportRun.close(run)
    return Projection(header=header,inputs=inputs,captures=capture_records,
        registry=tuple(registry[key] for key in sorted(registry)),local=local,requirements=requirements)


def project_folder(root: Path,budgets: Budgets,policies: tuple[policy.GatewayPolicy,...],baseline_raw: bytes | None,
) -> tuple[required.RequiredReportRun,required.Result,Projection]:
    """Own the actual fixed factory and final projection reads; no supplied-carrier proof admission."""
    run=required.RequiredReportRun(root,budgets,policies,baseline_raw)
    result=required.RequiredReportRun.close(run)
    flat=tuple((profile.MISSING,row.subject,row.value) for row in result.rows)
    _need(bool(flat))
    last_fact,last_subject,_last_value=flat[-1]
    original_store,project_step=result.store,profile.PROJECT
    reader=store.bind_reader(original_store,step=project_step)
    _need(type(reader) is store.FactReader)
    _need(required.RequiredReportRun.close(run) is result and profile.PROJECT is project_step
        and reader.store is original_store and reader.step is project_step)
    anchors=handles.retain_handle(reader)
    observed: list[store.StoredState]=[]
    for fact,subject,_expected in flat:
        handles.compare_reader(anchors,reader,fact=fact,subject=subject)
        observed.append(store.FactReader.read(reader,fact=fact,subject=subject))
    handles.compare_reader(anchors,reader,fact=last_fact,subject=last_subject)
    current=required.RequiredReportRun.close(run)
    _need(current is result and profile.PROJECT is project_step and all(actual is expected for actual,(_fact,_subject,expected)
        in zip(observed,flat,strict=True)))
    return run,result,_project(run)
