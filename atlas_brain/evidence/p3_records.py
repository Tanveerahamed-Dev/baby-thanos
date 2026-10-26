"""Immutable declared P3 scope and sample identities; no clock reads."""
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.synthetic import Node, SyntheticGroup
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import TimeInterval

SCHEMA = "atlas-brain.synthetic-p3/1"
OPERATIONS = {
    "iosxe.show_interfaces": "show interfaces",
    "iosxe.show_ip_interface": "show ip interface",
    "iosxe.show_ip_ospf_neighbor": "show ip ospf neighbor",
    "iosxe.show_ip_ospf_interface": "show ip ospf interface",
    "iosxe.show_running_config_all": "show running-config all",
}


@dataclass(frozen=True, slots=True, kw_only=True)
class Endpoint:
    node: Node
    port: str
    process: int
    router_id: str
    address: str
    vrf: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Adjacency:
    id: str
    domain: str
    area: int
    left: Endpoint
    right: Endpoint
    declaration: k.Known[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class Sample:
    id: str
    time: TimeInterval | None
    captures: tuple[Capture, ...]
    declaration: k.Known[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class P3Group:
    base: SyntheticGroup
    raw: bytes
    adjacencies: tuple[Adjacency, ...]
    samples: tuple[Sample, ...]


def registry_ref(raw: bytes, table: str, identifier: str, index: int) -> k.RegistryRef:
    """Retain the exact source-row index even when admitted records sort."""
    k.require(table in ("adjacencies", "samples"), "p3_registry_table")
    k.require(type(index) is int and index >= 0, "p3_registry_index")
    return k.RegistryRef(table="synthetic_p3." + table, row_id=identifier,
                         table_digest=sha256(raw).hexdigest(), citation=f"/{table}/{index}")


def _scope(point: Endpoint) -> tuple[str, str, int, str, str, str]:
    return (str(point.node.key), point.port, point.process, point.router_id, point.address, point.vrf)


def _context(adjacency: Adjacency) -> tuple[object, ...]:
    return (SCHEMA, adjacency.id, adjacency.domain, adjacency.area,
            _scope(adjacency.left), _scope(adjacency.right))


def adjacency_subject(adjacency: Adjacency) -> k.EntityKey:
    """A declared adjacency subject excludes registry bytes and sampling state."""
    return k.EntityKey("ospf_adjacency:" + sha256(canonical(_context(adjacency))).hexdigest())


def sample_subject(adjacency: Adjacency, point: Endpoint, sample: Sample) -> k.EntityKey:
    """Scope and round identity survive capture removal and list reordering."""
    k.require(point in (adjacency.left, adjacency.right), "p3_endpoint_outside_adjacency")
    identity = _context(adjacency) + (_scope(point), sample.id)
    return k.EntityKey("ospf_sample:" + sha256(canonical(identity)).hexdigest())
