from dataclasses import replace

import pytest
from test_global_protocol_finish import BODY, build, scenario
from test_reported_protocol_build import request, table, target

from atlas_brain.evidence.parsekit.rules import Captured
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as ec

FLAGS = ("P", "bndl", "D", "I", "s", "susp", "H", "hot-sby", "u", "w", "d", "f")


def wrapped(flag="P", ending=b"\n", style="wrap"):
    raw = BODY.replace(b"Gi1/0/1(P)\n", f"Gi1/0/1({flag})\n   Gi1/0/2(D)\n".encode())
    if style == "reverse":
        raw = BODY.replace(b"Gi1/0/1(P)\n", f"Gi1/0/2(D)\n   Gi1/0/1({flag})\n".encode())
    if style == "tabs":
        raw = raw.replace(b" LACP ", b"\tLACP\t").replace(b"   Gi", b"\tGi")
    return raw.replace(b"\n", ending)


def required(raw):
    spans = {}
    for label, line in (("record", next(line for line in raw.splitlines() if line.split()[0] == b"1")),
                        ("wrap", next(line for line in raw.splitlines() if line[:1] in (b" ", b"\t") and line.lstrip(b" \t").startswith(b"Gi")))):
        start = raw.index(line)
        spans[label] = k.ByteSpan(start=start, end=start + len(line))
    for label, token in (("group", b"1"), ("channel", b"Po1")):
        start = raw.index(token, spans["record"].start)
        spans[label] = k.ByteSpan(start=start, end=start + len(token))
    for i, port in enumerate(sorted((b"Gi1/0/1", b"Gi1/0/2"), key=raw.index)):
        start = raw.index(port)
        closing = raw.index(b")", start)
        spans[f"port{i}"] = k.ByteSpan(start=start, end=start + len(port))
        spans[f"flag{i}"] = k.ByteSpan(start=start + len(port) + 1, end=closing)
        spans[f"token{i}"] = k.ByteSpan(start=start, end=closing + 1)
    return spans


@pytest.mark.parametrize("flag,ending,style", [(flag, ending, "wrap") for flag in FLAGS for ending in (b"\n", b"\r\n")]
    + [("P", b"\n", "tabs"), ("P", b"\n", "reverse")])
def test_real_global_snapshot_yields_exact_immutable_raw_roster_proofs_without_replay(tmp_path, monkeypatch, flag, ending, style):
    raw = wrapped(flag, ending, style)
    scenario(tmp_path, raw)
    peer, tree = build(tmp_path)
    result = peer.finish(tree.execution)
    output, = result.executed
    domain = next(row.target for row in result.rows if row.target.node.key == output.receipt.capture.source)
    monkeypatch.setattr(ec, "bind_writer", lambda *args, **kwargs: pytest.fail("proof accessor wrote facts"))
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("proof accessor reparsed capture"))
    proofs = ec.reported_member_proofs(domain, output)
    assert type(proofs) is tuple and tuple(proof.group for proof in proofs) == ("1", "2")
    proof, absent = proofs
    expected = f"Gi1/0/2(D) Gi1/0/1({flag})" if style == "reverse" else f"Gi1/0/1({flag}) Gi1/0/2(D)"
    assert proof.text == expected and type(proof.spans) is tuple
    assert proof.spans == tuple(sorted(required(raw).values(), key=lambda span: (span.start, span.end))) and proof.anchor == required(raw)["port0"]
    assert absent.text is absent.anchor is None and absent.spans == ()
    assert type(ec.parse_summary.MEMBER_FLAGS) is tuple and ec.parse_summary.MEMBER_FLAGS == FLAGS
    assert ec.reported_member_proofs(domain, output) == proofs
    with pytest.raises(AttributeError):
        proof.text = "changed"


def test_empty_member_column_has_no_positive_raw_claims():
    item = target()
    result = ec.build_reported_protocol((item,), (request(item, BODY.replace(b" Gi1/0/1(P)", b"")),))
    proofs = ec.reported_member_proofs(item, result.executed[0])
    assert tuple(proof.group for proof in proofs) == ("1", "2") and all(proof.text is proof.anchor is None and proof.spans == () for proof in proofs)


@pytest.mark.parametrize("plant", ["port_value", "flag_value", "full_token", "omit", "duplicate", "reorder", "wrap_span", "foreign_flag", "other_group", "late_group", "record_order", "prompt_barrier", "extra_group", "adjacent_tokens"])
def test_mutated_rich_members_are_refused_atomically_by_accessor(monkeypatch, plant):
    item, execute = target(), ec.execute_parsers
    raw = table().replace(b"(s)", b"(P)").replace(b"(D)", b"(P)")
    if plant in ("other_group", "late_group"):
        raw = raw.replace(b"in use: 1", b"in use: 2").replace(b"aggregators: 1", b"aggregators: 2") + b"2 Po2(SU) LACP Gi1/0/4(P)\n"
    elif plant == "record_order":
        raw = BODY.replace(b"in use: 1", b"in use: 2").replace(b"aggregators: 1", b"aggregators: 2").replace(b"Gi1/0/1(P)\n", b"Gi1/0/1(P)\n   Gi1/0/2(P)\n") + b"2 Po2(SU) LACP Gi1/0/3(P)\n   Gi1/0/4(P)\n"
    elif plant == "prompt_barrier":
        raw = BODY.replace(b"Gi1/0/1(P)\n", b"Gi1/0/1(P)\n   Gi1/0/2(P)\n   Gi1/0/3(P)\n")
    elif plant == "extra_group":
        raw = BODY.replace(b"in use: 1", b"in use: 3").replace(b"aggregators: 1", b"aggregators: 3") + b"2 Po2(SU) LACP Gi1/0/2(P)\n3 Po3(SU) LACP Gi1/0/3(P)\n"
    elif plant == "adjacent_tokens":
        raw = BODY.replace(b"Gi1/0/1(P)", b"Gi1/0/1(P)Gi1/0/2(D)")
    parse = ec.parse_summary.parse_capture
    def coherent(capture, groups, ports):
        value = parse(capture, groups + ("3",) if plant == "extra_group" else groups, ports)
        if plant == "extra_group":
            return replace(value, rows=tuple(row for row in value.rows if row.group != "3"))
        members = []
        for port, flag in (("Gi1/0/1", "P"), ("Gi1/0/2", "D")):
            start = capture.raw.index(port.encode())
            end = start + len(port)
            members.append(ec.parse_summary.Member(port=Captured(port, k.ByteSpan(start=start, end=end), port),
                flag=Captured(flag, k.ByteSpan(start=end + 1, end=end + 2), flag), span=k.ByteSpan(start=start, end=end + 3)))
        return replace(value, reason=None, parse=replace(value.parse, quality="complete"),
                       rows=(replace(value.rows[0], members=tuple(members), reason=None),) + value.rows[1:])
    if plant in ("extra_group", "adjacent_tokens"):
        monkeypatch.setattr(ec.parse_summary, "parse_capture", coherent)
    def forged(*args):
        outputs = execute(*args)
        original = outputs[0]
        if plant in ("extra_group", "adjacent_tokens"):
            return outputs
        if plant in ("record_order", "prompt_barrier"):
            left, right = original.value.rows
            records = list(original.value.parse.records)
            if plant == "record_order":
                late = next(record for record in records if record.span == right.spans[-1])
                records.remove(late)
                records.insert(next(i for i, record in enumerate(records) if record.span == right.spans[0]), late)
                left = replace(left, members=left.members + (right.members[-1],), spans=left.spans + (right.spans[-1],))
                right = replace(right, members=right.members[:-1], spans=right.spans[:-1])
            else:
                ended = next(record for record in records if record.rule_id == "wrap")
                records = [replace(record, rule_id="prompt") if record is ended else record for record in records]
                left = replace(left, members=(left.members[0], left.members[2]), spans=(left.spans[0], left.spans[2]))
            parsed = replace(original.value.parse, records=tuple(records))
            value = replace(original.value, rows=(left, right), parse=parsed)
            return (replace(original, value=value, receipt=replace(original.receipt, parse=parsed)),) + outputs[1:]
        selected = 1 if plant == "late_group" else 0
        row = original.value.rows[selected]
        first, *rest = row.members
        if plant in ("port_value", "flag_value", "full_token"):
            first = replace(first, **({"port": replace(first.port, value="Gi1/0/4")} if plant == "port_value" else
                {"flag": replace(first.flag, value="D")} if plant == "flag_value" else {"span": rest[-1].span}))
        if plant == "foreign_flag":
            first = replace(first, flag=rest[-1].flag)
        elif plant == "other_group":
            first = original.value.rows[1].members[0]
        elif plant == "late_group":
            first = replace(first, flag=replace(first.flag, value="D"))
        members = (first, *rest)
        members = members[:-1] if plant == "omit" else members + (first,) if plant == "duplicate" else tuple(reversed(members)) if plant == "reorder" else members
        changed = replace(row, members=members, spans=row.spans[:1] if plant == "wrap_span" else row.spans)
        value = replace(original.value, rows=tuple(changed if i == selected else original_row for i, original_row in enumerate(original.value.rows)))
        return (replace(original, value=value),) + outputs[1:]
    monkeypatch.setattr(ec, "execute_parsers", forged)
    plan = ec._plan((item,), (request(item, raw),), None)
    handler = ec.Handler(binding=ec.BINDING, parser=ec._Adapter(plan.by_capture))
    out, = forged((ec.DECLARATION,), (handler,), plan.requests)
    monkeypatch.setattr(ec, "bind_writer", lambda *args, **kwargs: pytest.fail("proof accessor wrote facts"))
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("proof accessor reparsed capture"))
    with pytest.raises(ValueError, match="^etherchannel_members_"):
        ec.reported_member_proofs(item, out)


@pytest.mark.parametrize("plant", ["association", "operation", "rendered", "codec", "missing", "extra", "reordered", "capture", "partial"])
def test_public_accessor_enforces_shape_and_returns_no_positive_claims_for_damage(monkeypatch, plant):
    item = target()
    output, = ec.build_reported_protocol((item,), (request(item),)).executed
    if plant == "association":
        output = replace(output, receipt=replace(output.receipt, parse=replace(output.receipt.parse)))
    elif plant in ("operation", "rendered", "codec", "capture"):
        change = {"operation": {"operation": "synthetic.other"}, "rendered": {"rendered": "show etherchannel"},
                  "codec": {"codec": "latin-1"}, "capture": {"integrity": k.IntegrityState.TRUNCATED}}[plant]
        output = replace(output, receipt=replace(output.receipt, capture=replace(output.receipt.capture, **change)))
    elif plant == "partial":
        parsed = replace(output.value.parse, quality="partial")
        output = replace(output, value=replace(output.value, parse=parsed), receipt=replace(output.receipt, parse=parsed))
    else:
        rows = output.value.rows
        rows = rows[:-1] if plant == "missing" else rows + (replace(rows[0], group="3"),) if plant == "extra" else tuple(reversed(rows))
        output = replace(output, value=replace(output.value, rows=rows))
    monkeypatch.setattr(ec, "bind_writer", lambda *args, **kwargs: pytest.fail("proof accessor wrote facts"))
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("proof accessor reparsed capture"))
    if plant in ("capture", "partial"):
        proofs = ec.reported_member_proofs(item, output)
        assert tuple(proof.group for proof in proofs) == ("1", "2") and all(proof.text is proof.anchor is None and proof.spans == () for proof in proofs)
    else:
        with pytest.raises(ValueError, match="^etherchannel_members_record$"):
            ec.reported_member_proofs(item, output)
