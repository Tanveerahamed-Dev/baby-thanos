"""Original declared HSRP intent, literal policy premises and no observation calls."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_gateway_source import LIMITS, folder

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import redundancy_baseline as baseline
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack

SELECTORS = (("hsrp", "Vl10"), ("hsrp-cold", "BD10"))
REGISTRATION = "a2766c4b44c30ed9665a8f00eedddb81d7d876f59cc84581f752e0a2e2449324"


@pytest.fixture(autouse=True)
def no_observations(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("baseline preparation reached parser/Reader/Writer")
    monkeypatch.setattr(state.hsrp, "parse_capture", forbidden)
    monkeypatch.setattr(stp.stp, "parse_capture", forbidden)
    monkeypatch.setattr(ec.parse_summary, "parse_capture", forbidden)
    monkeypatch.setattr(FactReader, "read", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)


def inputs(root, missing=None, domain="campus_a"):
    files = folder(root, missing)
    envelope = p4.admit_folder(root, LIMITS, declarations=(stp.DECLARATION, ec.DECLARATION, state.DECLARATION))
    pack = StandbyBriefPack(LIMITS)
    pack.prepare(envelope)
    domains = tuple(pack.owner.plan.indexed.values())
    policies = (policy.GatewayPolicy(id="gateway10", domain=domain, vlan=10,
        address_family="ipv4", protocol="hsrp", group="1", participants=SELECTORS),)
    assert envelope.context == "round" and envelope.registration_sha256 == REGISTRATION
    document = {"schema": "atlas-brain.declared-fhrp-redundancy-baseline/1", "semantic_group": "declared_synthetic",
        "context": "round", "registry_sha256": sha256(envelope.raw).hexdigest(),
        "base_registry_sha256": sha256(envelope.base.raw).hexdigest(), "registration_sha256": REGISTRATION,
        "requirements": [{"id": "gateway10", "domain": "campus_a", "vlan": 10, "address_family": "ipv4",
            "protocol": "hsrp", "group": "1", "expected_participants": [
                {"target_id": target, "interface": interface} for target, interface in SELECTORS],
            "permitted_alternatives": []}]}
    return envelope, domains, policies, document, files


def original_scope_bytes(envelope, domain):
    registry, base = sha256(envelope.raw).hexdigest(), sha256(envelope.base.raw).hexdigest()
    key = None if domain is None else {"envelope_sha256": sha256(canonical((
        "atlas-brain.synthetic-p4/1", REGISTRATION, registry, base, "round"))).hexdigest(),
        "domain": domain, "vlan": 10, "address_family": "ipv4", "protocol": "hsrp", "group": "1"}
    points = []
    for (target, interface), node in zip(SELECTORS, ("a", "b"), strict=True):
        subject = "fhrp_local:" + sha256(canonical(("atlas-brain.fhrp-local/1", "round",
            "node:demo:" + node, interface, "ipv4", "hsrp", "1"))).hexdigest()
        points.append({"target_id": target, "node": "node:demo:" + node,
            "interface": interface, "group": "1", "subject": subject})
    return canonical({"schema": "atlas-brain.declared-fhrp-gateway-policy/1", "semantic_group": "declared_synthetic",
        "context": "round", "registration_sha256": REGISTRATION, "registry_sha256": registry, "base_registry_sha256": base,
        "gateways": [{"id": "gateway10", "domain": domain, "vlan": 10, "address_family": "ipv4",
            "protocol": "hsrp", "group": "1", "key": key, "participants": points}]})


def unknown(reason, detail, refs, points, source=False):
    return k.Unknown(reason=k.UnknownReason(reason), detail=detail, evidence=refs, candidates=(),
        next_evidence=tuple(k.EvidenceNeed(node=p.node, operation="iosxe.show_standby_brief",
            params=(("group", "1"), ("interface", p.interface)), resolves=(),
            reruns=("l3.fhrp/prepare_gateway_source" if source else "l3.fhrp/prepare_redundancy_baseline",),
            after_s=None, unprintable=("declared_l2_domain" if source else detail,)) for p in points))


@pytest.mark.parametrize("case,wanted", [
    ("ready", (None, None, None)), ("absent", ("no_baseline", "denominator_open", None)),
    ("unmatched", ("no_baseline", "denominator_open", None)),
    ("population", (None, "denominator_open", None)), ("domain", (None, None, "join_unproven")),
    ("absent_domain", ("no_baseline", "denominator_open", "join_unproven")),
    ("population_domain", (None, "denominator_open", "join_unproven")),
    ("unbound", (None, None, "join_unproven")),
])
def test_literal_complete_premises_priority_bytes_refs_needs_and_denominators(tmp_path, case, wanted):
    domain = None if case in ("domain", "absent_domain", "population_domain") else "campus_a"
    envelope, domains, policies, document, files = inputs(tmp_path / "inputs", domain=domain)
    if case == "unmatched":
        document["requirements"] = []
    elif case in ("population", "population_domain"):
        document["requirements"][0]["expected_participants"] = None
    elif case == "unbound":
        document["requirements"][0]["expected_participants"] = document["requirements"][0]["expected_participants"][:1]
    raw = None if case in ("absent", "absent_domain") else canonical(document)
    prepared = baseline.prepare_redundancy_baseline(envelope, LIMITS, policies, domains, raw)
    row, = prepared.rows
    scope_raw = original_scope_bytes(envelope, domain)
    assert prepared.scope.raw == scope_raw and prepared.scope.sha256 == sha256(scope_raw).hexdigest()
    assert prepared.scope.envelope is envelope and prepared.policies is policies and prepared.domains is domains
    assert prepared.baseline_raw is raw and prepared.baseline_sha256 == (None if raw is None else sha256(raw).hexdigest())
    points = tuple(policy.BoundParticipant(**p) for p in json.loads(scope_raw)["gateways"][0]["participants"])
    assert row.scope is prepared.scope.rows[0] and row.scope.participants == points
    refs = (k.RegistryRef(table="declared_fhrp_gateways", row_id="gateway10",
        table_digest=sha256(scope_raw).hexdigest(), citation="/gateways/0"),)
    declaration = () if raw is None or case == "unmatched" else (k.RegistryRef(table="declared_fhrp_redundancy_baseline",
        row_id="gateway10", table_digest=sha256(raw).hexdigest(), citation="/requirements/0"),)
    def known(evidence):
        return k.Known(value="gateway10", raw="gateway10", basis=k.Basis.DECLARED, evidence=evidence)
    expected_points = None if wanted[1] else points[:1] if case == "unbound" else points
    expected_baseline = unknown("no_baseline", "declared_redundancy_baseline_missing", refs, points) if wanted[0] else known(declaration)
    expected_population = unknown("denominator_open", "closed_expected_fhrp_population_required",
        refs + declaration, points) if wanted[1] else known((replace(declaration[0], citation="/requirements/0/expected_participants"),))
    expected_binding = (unknown("join_unproven", "declared_gateway_domain_missing", refs, points, True)
        if domain is None else unknown("join_unproven", "declared_gateway_binding_unproven", refs + declaration, expected_points)
        if case == "unbound" else known(refs))
    assert (row.baseline, row.population, row.binding) == (expected_baseline, expected_population, expected_binding)
    assert row.primary_gap is (row.baseline if wanted[0] else row.population if wanted[1] else row.binding if wanted[2] else None)
    assert row.expected_participants == expected_points and row.declared_anycast_permissions == ()
    if domain is None:
        assert row.binding is row.scope.binding
    key_data = json.loads(original_scope_bytes(envelope, "campus_a"))["gateways"][0]["key"]
    assert row.baseline_key == (None if not declaration else policy.GatewayKey(**key_data))
    count = 0 if expected_points is None else len(expected_points)
    assert prepared.denominator == (("requested_requirements", 1), ("declared_binding_participant_occurrences", 2),
        ("enumerated_baseline_participant_occurrences", count), ("expected_participant_occurrences", None if wanted[1] else count),
        ("requirements_with_open_expected_population", int(bool(wanted[1]))))
    assert sum(len(target.groups) for target in prepared.domains) == 6
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("missing", ["hsrp", "both"])
def test_removing_capture_entries_preserves_declared_scope_and_expected_subjects(tmp_path, missing):
    envelope, domains, policies, document, files = inputs(tmp_path / "inputs", missing)
    prepared = baseline.prepare_redundancy_baseline(envelope, LIMITS, policies, domains, canonical(document))
    assert len(prepared.rows[0].expected_participants) == 2 and prepared.rows[0].primary_gap is None
    assert prepared.scope.raw == original_scope_bytes(envelope, "campus_a")
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("change", ["domains", "nodes", "order"])
def test_original_scope_keys_and_creation_order_cannot_coalesce_requirements(tmp_path, change):
    envelope, domains, policies, document, _ = inputs(tmp_path / "inputs")
    if change == "order":
        domains = tuple(reversed(domains))
    else:
        policies = tuple(replace(policies[0], id="gateway" + str(index), domain=domain, participants=(selector,))
            for index, (domain, selector) in enumerate(zip(("campus_a", "campus_b"), SELECTORS, strict=True)))
        document["requirements"] = [{**document["requirements"][0], "id": p.id, "domain": p.domain,
            "expected_participants": [{"target_id": p.participants[0][0], "interface": p.participants[0][1]}]} for p in policies]
        if change == "nodes":
            policies = tuple(replace(p, domain="campus_a", vlan=10 + index) for index, p in enumerate(policies))
            for index, row in enumerate(document["requirements"]):
                row.update(domain="campus_a", vlan=10 + index)
    result = baseline.prepare_redundancy_baseline(envelope, LIMITS, policies, domains, canonical(document))
    assert all(row.primary_gap is None for row in result.rows)
    assert len(result.rows) == (1 if change == "order" else 2)
    assert len({row.baseline_key for row in result.rows}) == len(result.rows)
    assert {point.node for row in result.rows for point in row.scope.participants} == {"node:demo:a", "node:demo:b"}


@pytest.mark.parametrize("plant", ["duplicate_json", "unknown", "version", "noncanonical", "context", "p4_hash", "p2_hash",
    "registration", "semantic_group", "protocol", "foreign_id", "duplicate_id", "duplicate_selector", "empty_population", "unknown_target",
    "wrong_operation", "wrong_interface", "foreign_domain", "bool_vlan", "float_vlan"])
def test_closed_canonical_schema_and_original_selector_provenance_refuse(tmp_path, plant):
    envelope, domains, policies, document, _ = inputs(tmp_path / "inputs")
    row = document["requirements"][0]
    if plant in ("version", "context", "p4_hash", "p2_hash", "registration", "semantic_group"):
        field = {"version": "schema", "context": "context", "p4_hash": "registry_sha256",
            "p2_hash": "base_registry_sha256", "registration": "registration_sha256", "semantic_group": "semantic_group"}[plant]
        document[field] = "foreign" if plant in ("version", "context", "semantic_group") else "0" * 64
    elif plant == "unknown": row["complete"] = True
    elif plant == "foreign_id": row["id"] = "foreign"
    elif plant == "duplicate_id": document["requirements"].append(dict(row))
    elif plant == "duplicate_selector": row["expected_participants"] *= 2
    elif plant == "empty_population": row["expected_participants"] = []
    elif plant == "unknown_target": row["expected_participants"][0]["target_id"] = "foreign"
    elif plant == "wrong_operation": row["expected_participants"][0]["target_id"] = "ec"
    elif plant == "wrong_interface": row["expected_participants"][0]["interface"] = "Vl999"
    elif plant == "foreign_domain": row["domain"] = "foreign"
    elif plant == "bool_vlan": row["vlan"] = True
    elif plant == "protocol": row["protocol"] = "vrrp"
    raw = canonical(document)
    if plant == "duplicate_json": raw = raw.replace(b'"context":', b'"context":"round","context":', 1)
    elif plant == "noncanonical": raw += b"\n"
    elif plant == "float_vlan": raw = raw.replace(b'"vlan":10', b'"vlan":10.0', 1)
    with pytest.raises(ValueError):
        baseline.prepare_redundancy_baseline(envelope, LIMITS, policies, domains, raw)


@pytest.mark.parametrize("plant", ["permission", "duplicate", "foreign"])
def test_anycast_permission_is_retained_without_becoming_an_exclusion(tmp_path, plant):
    envelope, domains, policies, document, _ = inputs(tmp_path / "inputs")
    alternative = {"id": "gateway10_anycast", "requirement_id": "gateway10", "mechanism": "declared_anycast"}
    document["requirements"][0]["permitted_alternatives"] = [alternative] * (2 if plant == "duplicate" else 1)
    if plant == "foreign":
        alternative["requirement_id"] = "other_requirement"
    if plant == "permission":
        result = baseline.prepare_redundancy_baseline(envelope, LIMITS, policies, domains, canonical(document))
        assert result.rows[0].declared_anycast_permissions == ("gateway10_anycast",)
        assert result.rows[0].primary_gap is None and type(result.rows[0].baseline.value) is str
    else:
        with pytest.raises(ValueError):
            baseline.prepare_redundancy_baseline(envelope, LIMITS, policies, domains, canonical(document))


@pytest.mark.parametrize("limit", ["artifact", "bundle", "count"])
def test_original_source_policy_and_baseline_share_unchanged_budgets(tmp_path, limit):
    envelope, domains, policies, document, _ = inputs(tmp_path / "inputs")
    raw = canonical(document)
    source = (envelope.raw, envelope.base.raw) + tuple(m.raw for m in envelope.captures) + tuple(c.raw for c in envelope.base.captures)
    changes = {"artifact": {"artifact_bytes": len(raw) - 1},
        "bundle": {"bundle_bytes": sum(map(len, source)) + len(original_scope_bytes(envelope, "campus_a")) + len(raw) - 1},
        "count": {"artifacts": len(source) + 1}}[limit]
    with pytest.raises(BudgetExceeded):
        baseline.prepare_redundancy_baseline(envelope, replace(LIMITS, **changes), policies, domains, raw)
