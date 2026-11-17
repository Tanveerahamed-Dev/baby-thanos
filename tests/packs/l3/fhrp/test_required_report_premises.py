"""Original required-profile declared premises; no product activation or origin admission."""
from dataclasses import replace
from hashlib import sha256

import pytest
from test_gateway_source import LIMITS, folder

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration, store
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import required_report_premises as premises
from atlas_brain.packs.l3.fhrp import required_report_profile as profile
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.runner import p4_pipeline

SELECTORS=(("hsrp","Vl10"),("hsrp-cold","BD10"))


def forbid_observations(monkeypatch):
    def forbidden(*_args,**_kwargs):
        pytest.fail("declared premise phase reached parser/Reader/Writer")
    monkeypatch.setattr(state.hsrp,"parse_capture",forbidden)
    monkeypatch.setattr(stp.stp,"parse_capture",forbidden)
    monkeypatch.setattr(ec.parse_summary,"parse_capture",forbidden)
    monkeypatch.setattr(store.FactReader,"read",forbidden)
    monkeypatch.setattr(store.FactWriter,"write",forbidden)


def original(root,case="ready"):
    files=folder(root)
    declarations=(stp.DECLARATION,ec.DECLARATION,profile.declaration())
    envelope=p4.admit_folder(root,LIMITS,declarations=declarations)
    owner=StandbyBriefPack(LIMITS)
    owner.prepare(envelope)
    domains=tuple(owner.owner.plan.indexed.values())
    policies=(policy.GatewayPolicy(id="gateway10",domain=None if "domain" in case else "campus_a",
        vlan=10,address_family="ipv4",protocol="hsrp",group="1",participants=SELECTORS),)
    document={"schema":"atlas-brain.declared-fhrp-redundancy-baseline/1","semantic_group":"declared_synthetic",
        "context":envelope.context,"registry_sha256":sha256(envelope.raw).hexdigest(),
        "base_registry_sha256":sha256(envelope.base.raw).hexdigest(),"registration_sha256":envelope.registration_sha256,
        "requirements":[{"id":"gateway10","domain":"campus_a","vlan":10,"address_family":"ipv4","protocol":"hsrp","group":"1",
            "expected_participants":[{"target_id":target,"interface":interface} for target,interface in SELECTORS],
            "permitted_alternatives":[]}]}
    if "population" in case:document["requirements"][0]["expected_participants"]=None
    if case=="binding":document["requirements"][0]["expected_participants"]=document["requirements"][0]["expected_participants"][:1]
    raw=None if "baseline" in case else canonical(document)
    configured=profile.Inputs(policies=policies,baseline_raw=raw)
    return envelope,domains,configured,document,files


def test_actual_compiler_and_step_bound_read_write_permissions_include_the_boolean_producer():
    declared=profile.declaration()
    compiled=registration.compile_packs((stp.DECLARATION,ec.DECLARATION,declared))
    assert profile.STEP in compiled.steps and profile.STEP.kind=="check" and profile.STEP.produces==(profile.MISSING,)
    assert next(spec for spec in declared.facts if spec.id==profile.MISSING).step==profile.STEP.id
    subject=k.EntityKey("requirement:permission_only")
    witness=k.FactRef(fact=k.FactId("l3.fhrp.reported_state"),subject=subject)
    positive=k.Known(value=True,raw=None,basis=k.Basis.DERIVED,evidence=(witness,))
    source=store.FactStore()
    producer=next(step for step in declared.steps if step.produces==(profile.PRESENCE,))
    store.bind_writer(source,step=producer).write(fact=profile.PRESENCE,subject=subject,value=positive)
    assert store.bind_reader(source,step=profile.STEP).read(fact=profile.PRESENCE,subject=subject) is positive
    missing=k.Known(value=False,raw=None,basis=k.Basis.DERIVED,evidence=(k.FactRef(fact=profile.PRESENCE,subject=subject),))
    output=store.FactStore()
    writer=store.bind_writer(output,step=profile.STEP)
    writer.write(fact=profile.MISSING,subject=subject,value=missing)
    reader=store.bind_reader(output,step=profile.PROJECT)
    assert reader.read(fact=profile.MISSING,subject=subject) is missing
    with pytest.raises(ValueError):writer.write(fact=profile.PRESENCE,subject=subject,value=positive)
    with pytest.raises(ValueError):reader.read(fact=profile.PRESENCE,subject=subject)


@pytest.mark.parametrize("case,reason",[("ready",None),("baseline","no_baseline"),("population","denominator_open"),
    ("domain","join_unproven"),("binding","join_unproven"),("baseline_domain","no_baseline"),
    ("population_domain","denominator_open")])
def test_actual_admitted_owner_premises_keep_original_bytes_identities_priority_and_all_needs(tmp_path,monkeypatch,case,reason):
    forbid_observations(monkeypatch)
    root=tmp_path/"inputs"
    envelope,domains,configured,_document,files=original(root,case)
    held=premises.retain(envelope,LIMITS,domains,configured)
    actual=held.prepared
    assert premises.close(held,envelope,LIMITS,configured) is actual
    assert actual.scope.envelope is envelope and actual.policies is configured.policies and actual.domains is domains
    assert actual.scope.raw is held.scope_raw and actual.baseline_raw is held.baseline_raw
    row,=actual.rows
    assert row.primary_gap is (None if reason is None else next(value for value in
        (row.baseline,row.population,row.binding) if type(value) is k.Unknown))
    if reason is not None:assert row.primary_gap.reason.value==reason
    assert all(value is original for value,original in zip(
        (row.baseline,row.population,row.binding),held.cells[0][2:5],strict=True))
    assert {p.name:p.read_bytes() for p in root.iterdir()}==files


@pytest.mark.parametrize("fault",["scope_bytes","baseline_bytes","policy","row_clone","gateway_clone",
    "baseline_state","population_state","binding_state","primary","point","denominator","coverage",
    "opaque_state","opaque_key","opaque_point","opaque_policy","scope_container","float_policy"])
def test_current_premise_graphs_close_before_comparison_recomputation_or_foreign_hooks(tmp_path,monkeypatch,fault):
    forbid_observations(monkeypatch)
    envelope,domains,configured,_document,_files=original(tmp_path/"inputs","baseline" if fault=="primary" else "ready")
    held=premises.retain(envelope,LIMITS,domains,configured)
    current=held.prepared
    row=current.rows[0]
    calls=[]
    class Equal(str):
        def __eq__(self,_other):calls.append("equality");raise AssertionError
        def __hash__(self):calls.append("hash");raise AssertionError
        def __deepcopy__(self,_memo):calls.append("deepcopy");raise AssertionError
    class Foreign:
        def __getattribute__(self,name):calls.append(name);raise AssertionError
    if fault=="scope_bytes":object.__setattr__(current.scope,"raw",current.scope.raw+b" ")
    elif fault=="baseline_bytes":object.__setattr__(configured,"baseline_raw",b"{}")
    elif fault=="policy":object.__setattr__(configured.policies[0],"vlan",11)
    elif fault=="float_policy":object.__setattr__(configured.policies[0],"vlan",10.0)
    elif fault=="row_clone":object.__setattr__(current,"rows",tuple(replace(value) for value in current.rows))
    elif fault=="gateway_clone":object.__setattr__(row,"scope",replace(row.scope))
    elif fault=="baseline_state":object.__setattr__(row.baseline,"raw","forged")
    elif fault=="population_state":object.__setattr__(row.population,"raw","forged")
    elif fault=="binding_state":object.__setattr__(row.binding,"raw","forged")
    elif fault=="primary":object.__setattr__(row.primary_gap,"next_evidence",())
    elif fault=="point":object.__setattr__(row.expected_participants[0],"interface","Vl999")
    elif fault=="denominator":object.__setattr__(current,"denominator",(("requested_requirements",True),))
    elif fault=="coverage":object.__setattr__(current.scope.coverage,"detail","forged")
    elif fault=="opaque_state":object.__setattr__(row.baseline,"value",Equal(row.baseline.value))
    elif fault=="opaque_key":object.__setattr__(row.baseline_key,"domain",Equal(row.baseline_key.domain))
    elif fault=="opaque_point":object.__setattr__(row.expected_participants[0],"interface",Equal(row.expected_participants[0].interface))
    elif fault=="opaque_policy":object.__setattr__(configured.policies[0],"id",Equal(configured.policies[0].id))
    else:object.__setattr__(current,"scope",Foreign())
    with pytest.raises(ValueError):premises.close(held,envelope,LIMITS,configured)
    assert calls==[]


@pytest.mark.parametrize("fault",["registration","context","empty_population","boolean_vlan","unknown_target","noncanonical"])
def test_bad_original_baseline_refuses_in_genuine_prepare_before_any_pipeline_parser(tmp_path,monkeypatch,fault):
    forbid_observations(monkeypatch)
    root=tmp_path/"inputs"
    _envelope,_domains,configured,document,_files=original(root)
    if fault=="registration":document["registration_sha256"]="a2766c4b44c30ed9665a8f00eedddb81d7d876f59cc84581f752e0a2e2449324"
    elif fault=="context":document["context"]="foreign"
    elif fault=="empty_population":document["requirements"][0]["expected_participants"]=[]
    elif fault=="boolean_vlan":document["requirements"][0]["vlan"]=True
    elif fault=="unknown_target":document["requirements"][0]["expected_participants"][0]["target_id"]="foreign"
    raw=canonical(document)+(b"\n" if fault=="noncanonical" else b"")
    configured=replace(configured,baseline_raw=raw)
    class PreparingPack(StandbyBriefPack):
        def declaration(self):return profile.declaration()
        def prepare(self,envelope):
            prepared=super().prepare(envelope)
            premises.retain(envelope,self.budgets,tuple(self.owner.plan.indexed.values()),configured)
            return prepared
    with pytest.raises(ValueError):
        p4_pipeline.execute_p4_folder(root,LIMITS,packs=(stp.RootGuardPack(LIMITS),SummaryPack(LIMITS),PreparingPack(LIMITS)))


def test_extra_policy_and_baseline_bytes_use_the_same_genuine_admission_budget(tmp_path,monkeypatch):
    forbid_observations(monkeypatch)
    root=tmp_path/"inputs"
    envelope,domains,configured,_document,_files=original(root)
    held=premises.retain(envelope,LIMITS,domains,configured)
    raws=(envelope.raw,envelope.base.raw)+tuple(member.raw for member in envelope.captures)+tuple(cap.raw for cap in envelope.base.captures)
    limits=replace(LIMITS,bundle_bytes=sum(map(len,raws))+len(held.scope_raw)+len(held.baseline_raw)-1)
    actual=p4.admit_folder(root,limits,declarations=(stp.DECLARATION,ec.DECLARATION,profile.declaration()))
    owner=StandbyBriefPack(limits)
    owner.prepare(actual)
    with pytest.raises(BudgetExceeded):
        premises.retain(actual,limits,tuple(owner.owner.plan.indexed.values()),configured)


@pytest.mark.parametrize("field,changed",[("kind","derive"),("produces",()),("reads",()),("project_reads",())])
def test_literal_required_profile_drift_refuses_before_actual_parser_dispatch(tmp_path,monkeypatch,field,changed):
    forbid_observations(monkeypatch)
    root=tmp_path/"inputs"
    folder(root)
    if field=="project_reads":monkeypatch.setattr(profile,"PROJECT",replace(profile.PROJECT,reads=changed))
    else:monkeypatch.setattr(profile,"STEP",replace(profile.STEP,**{field:changed}))
    class FixedPack(StandbyBriefPack):
        def declaration(self):
            return profile.declaration()
    with pytest.raises(ValueError):
        p4_pipeline.execute_p4_folder(root,LIMITS,packs=(stp.RootGuardPack(LIMITS),SummaryPack(LIMITS),FixedPack(LIMITS)))
    with pytest.raises(ValueError):profile.declaration()


def test_equal_input_record_does_not_replace_original_retained_comparison_pointer(tmp_path,monkeypatch):
    forbid_observations(monkeypatch)
    envelope,domains,configured,_document,_files=original(tmp_path/"inputs")
    held=premises.retain(envelope,LIMITS,domains,configured)
    with pytest.raises(ValueError):premises.close(held,envelope,LIMITS,replace(configured))
