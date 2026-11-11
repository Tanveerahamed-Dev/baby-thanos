"""Generated EtherChannel protocol facts, independent of membership intent."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.synthetic import admit_members
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l2.etherchannel import build as b
from atlas_brain.runner import pack_runtime
from atlas_brain.runner.pack_receipts import CaptureRequest

PORTS = ("Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4")
DISCOVERY = b"Device ID: fixture-b\n"
MANIFEST = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "fixture",
    "nodes": [{"id": n, "discovery_id": "fixture-" + n, "ports": list(PORTS)} for n in ("a", "b")],
    "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail", "sha256": sha256(DISCOVERY).hexdigest()}]}
A, B = admit_members({"p2.json": canonical(MANIFEST), "discovery.txt": DISCOVERY}).nodes
COMPLETE, U = k.IntegrityState.COMPLETE, k.UnknownReason


def target(**changes):
    return replace(b.Target(context="first", node=A, groups=("2", "1"), ports=PORTS), **changes)


def table(protocol="LACP"):
    return (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n--+--+--+--\n"
            + f"1 Po1(SU) {protocol} Gi1/0/1(P) Gi1/0/2(s)\n   Gi1/0/3(D)\n".encode())


def request(item, raw=None, identity="a", integrity=COMPLETE):
    raw = table() if raw is None else raw
    return CaptureRequest(context=item.context, capture=Capture(id=k.CaptureId("cap:" + identity), source=item.node.key, operation=b.parse_summary.OP,
        rendered=b.parse_summary.COMMAND, codec="utf-8", raw=raw, integrity=integrity,
        lines=text_lines(raw, "utf-8"), read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN))


def watch(monkeypatch):
    calls, real = [], b.parse_summary.parse_capture
    def spy(*args):
        calls.append(None)
        calls[-1] = real(*args)
        return calls[-1]
    monkeypatch.setattr(b.parse_summary, "parse_capture", spy)
    return calls


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["body", "command", "prompt"])
@pytest.mark.parametrize("token,value", [("LACP", "lacp"), ("PAgP", "pagp"), ("-", "none_reported")])
def test_registered_protocol_is_observed_without_membership_or_mode_inference(monkeypatch, ending, frame, token, value):
    item, calls = target(), watch(monkeypatch)
    raw = table(token)
    if frame != "body":
        raw = b.parse_summary.COMMAND.encode() + b"\n" + raw
    if frame == "prompt":
        raw = b"fixture#" + raw + b"fixture#\n"
    raw = raw.replace(b"\n", ending)
    supplied = request(item, raw)
    result = b.build_reported_protocol((item,), (supplied,))
    row, absent = result.rows
    assert (row.group, absent.group, absent.value.reason) == ("1", "2", U.SUBJECT_ABSENT_FROM_CAPTURE)
    assert row.value.value == value and type(row.value.value) is str and row.value.raw == token and row.value.basis is k.Basis.OBSERVED
    assert result.store.owners == {fact: b.STEP.id for fact in b.STEP.produces} and len(result.store.values) == 2 * len(b.STEP.produces)
    assert set(result.store.values) == {k.FactRef(fact=fact, subject=b.subject(item, group)) for fact in b.STEP.produces for group in ("1", "2")}
    assert result.store.values[k.FactRef(fact=b.REPORTED_PROTOCOL, subject=row.subject)] is row.value
    assert {fact.id for fact in b.DECLARATION.facts} == {b.REPORTED_PROTOCOL, b.REPORTED_MEMBER_TOKENS}
    fact = next(fact for fact in b.DECLARATION.facts if fact.id == b.REPORTED_PROTOCOL)
    assert (fact.id, fact.step, fact.value_type) == (b.REPORTED_PROTOCOL, b.STEP.id, "text")
    output, = result.executed
    assert len(calls) == 1 and output.value is calls[0] and output.receipt.parse is output.value.parse
    assert output.receipt.capture is supplied.capture and output.receipt.context == item.context
    assert output.receipt.owner == b.STEP.id and output.receipt.registration_sha256 == compile_packs((b.DECLARATION,)).registration_sha256
    assert output.value.missing_ports == (PORTS[3],) and [m.flag.raw for m in output.value.rows[0].members] == ["P", "s", "D"]
    assert row.member_tokens.value == "Gi1/0/1(P) Gi1/0/2(s) Gi1/0/3(D)"
    assert tuple(r for r in row.value.evidence if type(r) is k.RegistryRef) == A.declaration.evidence
    refs = [r for r in row.value.evidence if type(r) is k.EvidenceRef]
    assert len(refs) == 3
    for ref in refs:
        assert ref.capture == supplied.capture.id and type(ref.locator) is k.ByteSpan
        assert sha256(raw[ref.locator.start:ref.locator.end]).hexdigest() == ref.excerpt_sha256
    assert {raw[r.locator.start:r.locator.end] for r in refs} == {b"1", token.encode(), next(line for line in raw.splitlines() if line.startswith(b"1 Po1"))}


@pytest.mark.parametrize("raw,integrity,reason", [
    (table() + b"unmodeled\n", COMPLETE, U.PARSE_PARTIAL), (table("passive"), COMPLETE, U.PARSE_PARTIAL),
    (table("on"), COMPLETE, U.PARSE_PARTIAL), (table().replace(b"Po1", b"Po2"), COMPLETE, U.PARSE_PARTIAL),
    (table() + b"1 Po1(SU) LACP\n", COMPLETE, U.CONFLICTING_EVIDENCE),
    (table(), k.IntegrityState.ERROR, U.CAPTURE_ERROR), (table(), k.IntegrityState.TRUNCATED, U.CAPTURE_TRUNCATED),
    (table(), k.IntegrityState.PAGING_ARTIFACTS, U.CAPTURE_TRUNCATED), (b"", COMPLETE, U.EMPTY_UNREGISTERED),
    (None, COMPLETE, U.NOT_COLLECTED),
    *[(table().replace(b"LACP ", b"LACP" + gap), COMPLETE, U.PARSE_PARTIAL) for gap in (b"\xc2\xa0", b"\xe2\x80\x83")],
])
def test_parser_damage_and_conflicts_dominate_plausible_protocol(raw, integrity, reason):
    item = target()
    result = b.build_reported_protocol((item,), () if raw is None else (request(item, raw, integrity=integrity),))
    assert all(type(row.value) is k.Unknown and row.value.reason is reason for row in result.rows)
    assert all(type(row.member_tokens) is k.Unknown and row.member_tokens.reason is reason for row in result.rows)
    member_need, = result.rows[0].member_tokens.next_evidence
    assert (member_need.node, member_need.operation, member_need.params, member_need.resolves, member_need.reruns, member_need.after_s, member_need.unprintable) == (item.node.key, b.parse_summary.OP, (), (b.REPORTED_MEMBER_TOKENS,), (b.STEP.id,), None, ())
    need, = result.rows[0].value.next_evidence
    assert (need.node, need.operation, need.params, need.resolves, need.reruns) == (A.key, b.parse_summary.OP, (), (b.REPORTED_PROTOCOL,), (b.STEP.id,))


def test_declared_groups_survive_capture_loss_and_order_without_port_membership_claims():
    item = target()
    targets = (item, target(node=B), target(context="second"))
    original = b.build_reported_protocol(targets, (request(item),))
    missing = b.build_reported_protocol(targets, ())
    assert [r.subject for r in original.rows] == [r.subject for r in missing.rows] and len(missing.rows) == 6
    assert all(r.value.reason is U.NOT_COLLECTED for r in missing.rows)
    changed = tuple(replace(t, groups=tuple(reversed(t.groups)), ports=tuple(reversed(t.ports))) for t in reversed(targets))
    assert b.build_reported_protocol(changed, (request(item),)).rows == original.rows
    empty_ports = target(groups=("1",), ports=())
    raw = table("-").split(b"1 Po1")[0] + b"1 Po1(SD) -\n"
    assert b.build_reported_protocol((empty_ports,), (request(empty_ports, raw),)).rows[0].value.value == "none_reported"
    assert b.subject(target(groups=("10", "2")), "10") != b.subject(target(groups=("1", "2")), "1")


@pytest.mark.parametrize("change,code", [
    ({"groups": ()}, "invalid_etherchannel_population"), ({"groups": ("0",)}, "invalid_etherchannel_population"),
    ({"groups": ("65536",)}, "invalid_etherchannel_population"), ({"groups": ("01",)}, "invalid_etherchannel_population"),
    ({"groups": (True,)}, "invalid_etherchannel_population"), ({"groups": (1,)}, "invalid_etherchannel_population"), ({"groups": (1.0,)}, "invalid_etherchannel_population"),
    ({"groups": ["1"]}, "invalid_etherchannel_population"), ({"groups": ("1", "1")}, "invalid_etherchannel_population"),
    ({"ports": (PORTS[0], PORTS[0])}, "invalid_etherchannel_population"), ({"ports": list(PORTS)}, "invalid_etherchannel_population"), ({"ports": ("Gi99",)}, "synthetic_undeclared_port"),
    ({"context": ""}, "etherchannel_target"), ({"node": object()}, "etherchannel_target"),
    (None, "etherchannel_duplicate_target")])
@pytest.mark.parametrize("empty", [False, True])
def test_late_invalid_targets_refuse_even_without_any_capture(monkeypatch, change, code, empty):
    item, calls = target(), watch(monkeypatch)
    with pytest.raises(ValueError, match="^" + code + "$"):
        b.build_reported_protocol((item, target(groups=("3",)) if change is None else target(**change)), () if empty else (request(item),))
    assert calls == []


@pytest.mark.parametrize("plant,code", [("context", "etherchannel_request_target"), ("source", "etherchannel_request_target"),
    ("operation", "etherchannel_request_target"), ("command", "etherchannel_request_target"),
    ("scope", "etherchannel_request_scope"), ("codec", "unsupported_etherchannel_summary"),
    ("duplicate", "etherchannel_duplicate_target_capture")])
def test_late_request_fault_never_follows_an_earlier_parser_or_writer(monkeypatch, plant, code):
    item, calls = target(), watch(monkeypatch)
    later = request(item, identity="z")
    capture = later.capture
    if plant == "context":
        later = replace(later, context="other")
    else:
        changes = {"source": {"source": B.key}, "operation": {"operation": None}, "command": {"rendered": "show etherchannel"},
            "scope": {"metadata": replace(capture.resolved_metadata, scope=replace(capture.scope, vrf="other"))},
            "codec": {"codec": "latin-1"}, "duplicate": {}}[plant]
        later = replace(later, capture=replace(capture, **changes))
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before full preflight"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        b.build_reported_protocol((item,), (request(item), later))
    assert calls == []


@pytest.mark.parametrize("plant,code", [("association", "etherchannel_receipt_parse"), ("result", "etherchannel_receipt_parse"),
    ("missing", "etherchannel_parser_population"), ("extra", "etherchannel_parser_population"),
    ("duplicate", "etherchannel_parser_population"), ("rowtype", "etherchannel_parser_population"),
    ("enum", "etherchannel_protocol_value"), ("neighbor", "etherchannel_members_record")])
def test_late_rich_or_same_value_wrong_group_proof_refuses_before_writer(monkeypatch, plant, code):
    first, last = target(), target(node=B)
    actual = b.execute_parsers
    def forged(*args):
        outputs = actual(*args)
        item = outputs[-1]
        rows = item.value.rows
        if plant == "association":
            return outputs[:-1] + (replace(item, receipt=replace(item.receipt, parse=replace(item.receipt.parse))),)
        if plant == "result":
            return outputs[:-1] + (replace(item, value=object()),)
        if plant in ("enum", "neighbor"):
            fields = dict(rows[0].fields)
            fields["protocol"] = replace(fields["protocol"], value="LACP") if plant == "enum" else dict(rows[1].fields)["protocol"]
            rows = (replace(rows[0], fields=tuple(fields.items()), spans=rows[1].spans if plant == "neighbor" else rows[0].spans), rows[1])
            if plant == "enum":
                records = tuple(replace(record, fields=tuple((name, fields["protocol"] if name == "protocol" else value) for name, value in record.fields)) if record.span == rows[0].spans[0] else record for record in item.value.parse.records)
                parsed = replace(item.value.parse, records=records)
                item = replace(item, value=replace(item.value, parse=parsed), receipt=replace(item.receipt, parse=parsed))
        else:
            rows = {"missing": (), "extra": rows + (replace(rows[0], group="3"),), "duplicate": rows + rows[:1], "rowtype": (object(),)}[plant]
        return outputs[:-1] + (replace(item, value=replace(item.value, rows=rows)),)
    monkeypatch.setattr(b, "execute_parsers", forged)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before validating late proof"))
    raw = table().split(b"1 Po1")[0].replace(b": 1", b": 2") + b"1 Po1(SU) LACP Gi1/0/1(P)\n2 Po2(SU) LACP Gi1/0/2(s)\n"
    with pytest.raises(ValueError, match="^" + code + "$"):
        b.build_reported_protocol((first, last), (request(first), request(last, raw, "z")))


def test_runtime_receipt_barrier_must_pass_before_private_store_registration(monkeypatch):
    def refuse(*args):
        raise ValueError("planted_receipt_barrier")
    monkeypatch.setattr(pack_runtime, "validate_receipts", refuse)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before receipt barrier"))
    item = target()
    with pytest.raises(ValueError, match="^planted_receipt_barrier$"):
        b.build_reported_protocol((item,), (request(item),))


def test_multi_digit_declared_groups_follow_parser_lexical_order():
    item = target(groups=("2", "10"))
    raw = table().split(b"1 Po1")[0].replace(b": 1", b": 2") + b"2 Po2(SD) PAgP Gi1/0/1(s)\n10 Po10(SU) LACP Gi1/0/2(P)\n"
    result = b.build_reported_protocol((item,), (request(item, raw),))
    assert [(row.group, row.value.value) for row in result.rows] == [("10", "lacp"), ("2", "pagp")]
