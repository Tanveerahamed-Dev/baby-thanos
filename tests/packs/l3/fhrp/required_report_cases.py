"""Original input fixtures for fixed required-report factory and predicate tests."""
import json
from dataclasses import replace
from functools import partial
from hashlib import sha256

import pytest
from presence_test_support import inputs
from test_gateway_source import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.model import store
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import reported_presence as presence
from atlas_brain.packs.l3.fhrp import required_report_profile as profile

SELECTORS=(("hsrp","Vl10"),("hsrp-cold","BD10"))


def original_inputs(root,case="ready",multiple=False):
    mode=next((mode for mode in ("both","partial","error","truncated","conflict") if mode in case),"hsrp" if "missing" in case else "normal")
    files=inputs(root,mode)
    if case=="header":
        files["hsrp.txt"]=b"P indicates configured to preempt.\n|\nInterface Grp Pri P State Active Standby Virtual IP\n"
        side=json.loads(files["p4.json"])
        for row in side["captures"]:row["sha256"]=sha256(files[row["path"]]).hexdigest()
        files["p4.json"]=canonical(side)
        for name,raw in files.items():(root/name).write_bytes(raw)
    envelope=p4.admit_folder(root,LIMITS,declarations=(stp.DECLARATION,ec.DECLARATION,profile.declaration()))
    policies=tuple(policy.GatewayPolicy(id="gateway"+str(index),domain=None if "domain" in case else "campus_a",
        vlan=10+index,address_family="ipv4",protocol="hsrp",group="1",participants=(selector,) if multiple else SELECTORS)
        for index,selector in enumerate(SELECTORS if multiple else SELECTORS[:1]))
    requirements=[{"id":item.id,"domain":"campus_a","vlan":item.vlan,"address_family":"ipv4","protocol":"hsrp","group":"1",
        "expected_participants":[{"target_id":target,"interface":interface} for target,interface in item.participants],
        "permitted_alternatives":[]} for item in policies]
    if "population" in case:requirements[0]["expected_participants"]=None
    if case=="binding":requirements[0]["expected_participants"]=requirements[0]["expected_participants"][:1]
    if case=="permission":requirements[0]["permitted_alternatives"]=[{"id":"allowed","requirement_id":policies[0].id,"mechanism":"declared_anycast"}]
    document={"schema":"atlas-brain.declared-fhrp-redundancy-baseline/1","semantic_group":"declared_synthetic",
        "context":envelope.context,"registry_sha256":sha256(envelope.raw).hexdigest(),
        "base_registry_sha256":sha256(envelope.base.raw).hexdigest(),"registration_sha256":envelope.registration_sha256,
        "requirements":[] if case=="unmatched" else requirements}
    return envelope,policies,None if "baseline" in case else canonical(document),files



def budget_inputs(root, limit):
    """Prepare fixture inputs and exact or reduced limits before any observations."""
    envelope, policies, raw, files = original_inputs(root)
    assert raw is not None
    declared = profile.Inputs(policies=policies, baseline_raw=raw)
    pack = presence.PresencePack(LIMITS, _required=declared)
    pack.prepare(envelope)
    assert pack.premises is not None
    members = (*files.values(), pack.premises.scope_raw, raw)
    largest = max(map(len, members))
    budgets = replace(LIMITS,
        bundle_bytes=sum(map(len, members)) - (limit == "bundle"),
        artifacts=len(members) - (limit == "count"),
        artifact_bytes={"exact": largest, "bundle": largest, "count": largest,
            "artifact": len(raw) - 1, "artifact_boundary": largest - 1}[limit])
    return budgets, policies, raw


def _unexpected_observation(name, *_args, **_kwargs):
    pytest.fail(f"unexpected {name} observation")


def forbid_observations(monkeypatch):
    """Trip real pack parsers and store methods; return originals for isolated smoke tests."""
    targets = {
        "hsrp": (presence.state.hsrp, "parse_capture"),
        "stp": (presence.stp.stp, "parse_capture"),
        "ec": (presence.ec.parse_summary, "parse_capture"),
        "reader": (store.FactReader, "read"),
        "writer": (store.FactWriter, "write"),
    }
    originals = {name: (owner, attr, getattr(owner, attr)) for name, (owner, attr) in targets.items()}
    for name, (owner, attr, _) in originals.items():
        monkeypatch.setattr(owner, attr, partial(_unexpected_observation, name))
    return originals
