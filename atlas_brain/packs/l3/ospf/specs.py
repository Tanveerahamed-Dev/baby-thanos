"""Owned P3 sample and settled-fact declarations; no mutable series values."""
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import (
    EntityKindSpec,
    FactSpec,
    RelationSpec,
    StepId,
    StepSpec,
)
from atlas_brain.packs.l1.link.build import PEER

PACK = k.PackId("l3.ospf")
STATE = k.FactId("l3.ospf.state")
ROLE = k.FactId("l3.ospf.neighbor_role")
NEIGHBOR_ID = k.FactId("l3.ospf.neighbor_router_id")
NEIGHBOR_ADDRESS = k.FactId("l3.ospf.neighbor_address")
ROUTER_ID = k.FactId("l3.ospf.local_router_id")
ADDRESS = k.FactId("l3.ospf.local_address")
PROCESS = k.FactId("l3.ospf.process")
AREA = k.FactId("l3.ospf.area")
NETWORK = k.FactId("l3.ospf.network_type")
VRF = k.FactId("l3.ospf.printed_vrf")
IGNORE = k.FactId("l3.ospf.mtu_ignore")
CLOCK = k.FactId("l3.ospf.collector_clock")
EARLIEST = k.FactId("l3.ospf.collected_earliest_us")
LATEST = k.FactId("l3.ospf.collected_latest_us")
ADJACENCY = k.FactId("l3.ospf.adjacency")
INTERFACE = k.FactId("l3.ospf.interface")
IDS = tuple(sorted((STATE, ROLE, NEIGHBOR_ID, NEIGHBOR_ADDRESS, ROUTER_ID, ADDRESS, PROCESS, AREA,
                    NETWORK, VRF, IGNORE, CLOCK, EARLIEST, LATEST, ADJACENCY, INTERFACE)))
STEP = StepSpec(id=StepId("l3.ospf/parse_samples"), pack=PACK, kind="parse_build",
                scope="device", reads=(), produces=IDS, evaluator="l3.ospf.build_sample")
FACTS = (
    FactSpec(id=STATE, pack=PACK, subject="ospf_sample", value_type="text", step=STEP.id),
    FactSpec(id=ROLE, pack=PACK, subject="ospf_sample", value_type="text", step=STEP.id),
    FactSpec(id=NEIGHBOR_ID, pack=PACK, subject="ospf_sample", value_type="text", step=STEP.id),
    FactSpec(id=NEIGHBOR_ADDRESS, pack=PACK, subject="ospf_sample", value_type="text", step=STEP.id),
    FactSpec(id=ROUTER_ID, pack=PACK, subject="ospf_sample", value_type="text", step=STEP.id),
    FactSpec(id=ADDRESS, pack=PACK, subject="ospf_sample", value_type="text", step=STEP.id),
    FactSpec(id=PROCESS, pack=PACK, subject="ospf_sample", value_type="integer", step=STEP.id),
    FactSpec(id=AREA, pack=PACK, subject="ospf_sample", value_type="integer", step=STEP.id),
    FactSpec(id=NETWORK, pack=PACK, subject="ospf_sample", value_type="text", step=STEP.id),
    FactSpec(id=VRF, pack=PACK, subject="ospf_sample", value_type="text", step=STEP.id),
    FactSpec(id=IGNORE, pack=PACK, subject="ospf_sample", value_type="boolean", step=STEP.id),
    FactSpec(id=CLOCK, pack=PACK, subject="ospf_sample", value_type="text", step=STEP.id),
    FactSpec(id=EARLIEST, pack=PACK, subject="ospf_sample", value_type="integer", step=STEP.id),
    FactSpec(id=LATEST, pack=PACK, subject="ospf_sample", value_type="integer", step=STEP.id),
    FactSpec(id=ADJACENCY, pack=PACK, subject="ospf_sample", value_type="entity_ref", step=STEP.id),
    FactSpec(id=INTERFACE, pack=PACK, subject="ospf_sample", value_type="entity_ref", step=STEP.id),
)
KINDS = (
    EntityKindSpec(id="ospf_adjacency", pack=PACK, root=False),
    EntityKindSpec(id="ospf_sample", pack=PACK, root=False),
)
RELATIONS = (
    RelationSpec(id="l3.ospf.adjacency_samples", pack=PACK, source="ospf_adjacency", target="ospf_sample", cardinality="one_to_many"),
    RelationSpec(id="l3.ospf.interface_samples", pack=PACK, source="interface", target="ospf_sample", cardinality="one_to_many"),
)
CONTEXT = k.FactId("l3.ospf.context_match")
PERSISTENT = k.FactId("l3.ospf.sampled_persistence")
SPAN = k.FactId("l3.ospf.minimum_separation_us")
SETTLE = StepSpec(id=StepId("l3.ospf/settle"), pack=PACK, kind="derive", scope="estate",
                  reads=tuple(sorted((PEER,) + IDS)), produces=tuple(sorted((CONTEXT, PERSISTENT, SPAN))),
                  evaluator="l3.ospf.settle")
SETTLED_FACTS = (
    FactSpec(id=CONTEXT, pack=PACK, subject="ospf_adjacency", value_type="boolean", step=SETTLE.id),
    FactSpec(id=PERSISTENT, pack=PACK, subject="ospf_adjacency", value_type="boolean", step=SETTLE.id),
    FactSpec(id=SPAN, pack=PACK, subject="ospf_adjacency", value_type="integer", step=SETTLE.id),
)
