"""Actual fixed factory owns original pre-parser data; no missing-report predicate yet."""
import json
from dataclasses import replace

import pytest
from presence_test_support import capture
from required_report_cases import original_inputs
from test_gateway_source import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model import store
from atlas_brain.packs.l3.fhrp import reported_presence as presence
from atlas_brain.packs.l3.fhrp import required_report_premises as premises


@pytest.mark.parametrize("case,reason",[
    ("ready",None),("permission",None),("baseline",k.UnknownReason.NO_BASELINE),("unmatched",k.UnknownReason.NO_BASELINE),
    ("population",k.UnknownReason.DENOMINATOR_OPEN),("domain",k.UnknownReason.JOIN_UNPROVEN),("binding",k.UnknownReason.JOIN_UNPROVEN),
    ("baseline_domain",k.UnknownReason.NO_BASELINE),("population_domain",k.UnknownReason.DENOMINATOR_OPEN),
    ("baseline_missing",k.UnknownReason.NO_BASELINE),("missing",k.UnknownReason.NOT_COLLECTED),("both",k.UnknownReason.NOT_COLLECTED),
    ("partial",k.UnknownReason.PARSE_PARTIAL),("error",k.UnknownReason.CAPTURE_ERROR),
    ("truncated",k.UnknownReason.CAPTURE_TRUNCATED),("conflict",k.UnknownReason.CONFLICTING_EVIDENCE),
    ("header",k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE),
])
def test_actual_factory_returns_original_source_presence_and_all_declared_premises(tmp_path,monkeypatch,case,reason):
    root=tmp_path/"inputs"
    _envelope,policies,raw,files=original_inputs(root,case)
    parse=presence.state.hsrp.parse_capture
    parsed=[]
    def parsing(capture):
        parsed.append(capture.id)
        return parse(capture)
    monkeypatch.setattr(presence.state.hsrp,"parse_capture",parsing)
    live=presence.PresenceRun.open_required_report_folder(root,replace(LIMITS),policies,raw)
    prepared=presence.PresenceRun.required_premises(live)
    assert live.original_premises.prepared is prepared and prepared.policies is policies and prepared.baseline_raw is raw
    assert live.original_bindings is live.pack.bindings and live.original_run is live.pack.run
    rows=presence.PresenceRun.presence_rows(live)
    indexed={row.source.subject:row for row in rows}
    requirement,=prepared.rows
    points=requirement.expected_participants
    selected=tuple(indexed[point.subject] for point in (requirement.scope.participants if points is None else points))
    gap=requirement.primary_gap or next((row.value for row in selected if type(row.value) is k.Unknown),None)
    if reason is None:
        assert gap is None and all(type(row.value) is k.Known and row.value.value is True for row in selected)
    else:assert type(gap) is k.Unknown and gap.reason is reason
    assert len(rows)==6 and all(row.value is row.source.value for row in rows if type(row.value) is k.Unknown)
    assert {p.name:p.read_bytes() for p in root.iterdir()}==files
    assert len(parsed)==len(set(parsed))==(0 if case=="both" else 1 if "missing" in case else 2)
    monkeypatch.setattr(presence.state.hsrp,"parse_capture",lambda *_:pytest.fail("factory reparsed"))
    monkeypatch.setattr(store.FactReader,"read",lambda *_a,**_k:pytest.fail("pure factory close read"))
    monkeypatch.setattr(store.FactWriter,"write",lambda *_a,**_k:pytest.fail("pure factory close wrote"))
    assert presence.PresenceRun.close(live) is live.result
    assert presence.PresenceRun.required_premises(live) is prepared


@pytest.mark.parametrize("fault",["policy","premise_rebase","run","bindings","factory_class","inputs_clone"])
def test_actual_parser_callback_cannot_rebase_the_already_retained_genuine_prepare(tmp_path,monkeypatch,fault):
    root=tmp_path/"inputs"
    _envelope,policies,raw,_files=original_inputs(root)
    seen=capture(monkeypatch,presence.PresencePack)
    parse=presence.state.hsrp.parse_capture
    hit=[]
    def parsing(capture):
        pack=seen["pack"]
        if not hit:
            hit.append(True)
            assert pack.factory.original_premises is pack.premises and pack.factory.original_bindings is pack.bindings
            assert pack.factory.original_run is pack.run
            if fault in ("policy","premise_rebase"):object.__setattr__(policies[0],"vlan",11)
            if fault=="premise_rebase":
                document=json.loads(pack.requirement_inputs.baseline_raw)
                document["requirements"][0]["vlan"]=11
                object.__setattr__(pack.requirement_inputs,"baseline_raw",canonical(document))
                pack.premises=premises.retain(pack.run.envelope,pack.budgets,pack.premises.domains,pack.requirement_inputs)
                assert pack.premises.prepared.rows[0].primary_gap is None
            elif fault=="run":pack.run=replace(pack.run)
            elif fault=="bindings":pack.bindings=replace(pack.bindings)
            elif fault=="inputs_clone":pack.requirement_inputs=replace(pack.requirement_inputs)
            elif fault=="factory_class":
                class Hook(type(pack.factory)):
                    __slots__=()
                    def __getattribute__(self,_name):pytest.fail("factory class hook")
                object.__setattr__(pack.factory,"__class__",Hook)
        return parse(capture)
    monkeypatch.setattr(presence.state.hsrp,"parse_capture",parsing)
    with pytest.raises(ValueError):presence.PresenceRun.open_required_report_folder(root,replace(LIMITS),policies,raw)
    assert hit==[True]


def test_actual_factory_refuses_old_registration_before_dispatching_any_parser(tmp_path,monkeypatch):
    root=tmp_path/"inputs"
    _envelope,policies,raw,_files=original_inputs(root)
    document=json.loads(raw)
    document["registration_sha256"]="a2766c4b44c30ed9665a8f00eedddb81d7d876f59cc84581f752e0a2e2449324"
    raw=canonical(document)
    monkeypatch.setattr(presence.state.hsrp,"parse_capture",lambda *_:pytest.fail("old registration parsed"))
    monkeypatch.setattr(presence.stp.stp,"parse_capture",lambda *_:pytest.fail("old registration parsed STP"))
    monkeypatch.setattr(presence.ec.parse_summary,"parse_capture",lambda *_:pytest.fail("old registration parsed EC"))
    with pytest.raises(ValueError):presence.PresenceRun.open_required_report_folder(root,replace(LIMITS),policies,raw)
