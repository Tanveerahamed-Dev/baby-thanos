"""Direct VERSION Store completion; lifecycle tests do not establish source admission."""
from dataclasses import replace

import pytest
from test_parse_hsrp_all import BODY, capture
from test_reported_state_build import B, target

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactWriter, bind_reader
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import version_inputs as source_inputs
from atlas_brain.packs.l3.fhrp import version_owner as owning
from atlas_brain.runner.pack_receipts import CaptureRequest

FACT, OWNER = "l3.fhrp.reported_protocol_version", "l3.fhrp/parse_hsrp_all_version"
GROUPS = (("Vlan10", "0"), ("Vl10", "0"), ("Vlan99", "2"))


def item(**changes):
    declared = target(groups=GROUPS, **changes)
    return replace(declared, node=replace(declared.node))


def request(subject, raw=BODY, identity="a", integrity=k.IntegrityState.COMPLETE):
    sample = replace(capture(raw, integrity), source=subject.node.key, id=k.CaptureId("cap:" + identity))
    return CaptureRequest(context=subject.context, capture=sample)


def forbid_writes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("wrote before the complete custody batch was validated")
    monkeypatch.setattr(FactWriter, "write", forbidden)


@pytest.mark.parametrize("empty", [False, True])
def test_direct_finish_closes_once_then_publishes_exact_store_rows_owned_outputs_and_grants(monkeypatch, empty):
    subject = item()
    execution = owning.execute_local_version_inputs(() if empty else (subject,), () if empty else (request(subject),))
    actual, close, write = execution.owner, execution.owner.canonical_rows, FactWriter.write
    closures, written = [], []
    def closing(outputs):
        assert actual.production_attempted is True and actual.production is None
        rows = close(outputs)
        closures.append(rows)
        return rows
    def writing(self, **kwargs):
        assert len(closures) == 1 and actual.production is None
        written.append(kwargs["value"])
        return write(self, **kwargs)
    monkeypatch.setattr(actual, "canonical_rows", closing)
    monkeypatch.setattr(FactWriter, "write", writing)
    result = actual.finish(execution.executed)
    assert type(result) is owning.VersionResult and actual.production is result and actual.production_attempted is True
    assert len(closures) == 1 and result.rows is closures[0]
    assert result.store.owners == {FACT: OWNER} and len(result.store.values) == len(result.rows) == (0 if empty else len(GROUPS))
    assert written == [row.value for row in result.rows]
    assert result.registration_sha256 == actual.inputs.registration_sha256
    assert all(result.store.values[k.FactRef(fact=FACT, subject=row.subject)] is row.value for row in result.rows)
    assert all(out is actual.inputs.owned[out.receipt.capture.id] for out in result.executed)
    assert all(out.receipt is execution.executed[index].receipt and out.value is execution.executed[index].value
               for index, out in enumerate(result.executed))
    consumer = StepSpec(id=StepId("l3.fhrp/test_finish"), pack=build.PACK, kind="check", scope="device",
                        reads=(FACT,), produces=(), evaluator="l3.fhrp.test_finish")
    assert all(bind_reader(result.store, step=consumer).read(fact=FACT, subject=row.subject) is row.value for row in result.rows)
    if result.rows:
        with pytest.raises(ValueError, match="undeclared_read"):
            bind_reader(result.store, step=build.SOURCE_STEP).read(fact=FACT, subject=result.rows[0].subject)
    def forbidden(*args, **kwargs):
        pytest.fail("finish diagnostic or retry replayed parser or dispatcher")
    monkeypatch.setattr(owning.parser, "parse_capture", forbidden)
    monkeypatch.setattr(owning, "execute_parsers", forbidden)
    assert close(execution.executed) == result.rows
    with pytest.raises(ValueError, match="production_once"):
        actual.finish(execution.executed)


@pytest.mark.parametrize("failure", ["closure", "writer"])
def test_first_failed_finish_is_consumed_and_never_publishes_a_result(monkeypatch, failure):
    subject = item()
    execution = owning.execute_local_version_inputs((subject,), (request(subject),))
    actual, original_write, writes = execution.owner, FactWriter.write, []
    def writing(self, **kwargs):
        if writes:
            raise RuntimeError("synthetic_writer_failure")
        original_write(self, **kwargs)
        writes.append(self.store)
    if failure == "closure":
        def forbidden(*args, **kwargs):
            pytest.fail("bound Writer before full candidate closure")
        monkeypatch.setattr(owning, "bind_writer", forbidden)
        with pytest.raises(ValueError):
            actual.finish(())
        assert writes == []
    else:
        monkeypatch.setattr(FactWriter, "write", writing)
        with pytest.raises(RuntimeError, match="synthetic_writer_failure"):
            actual.finish(execution.executed)
        assert len(writes) == 1 and len(writes[0].values) == 1
    assert actual.production_attempted is True and actual.production is None
    with pytest.raises(ValueError, match="production_once"):
        actual.finish(execution.executed)
    assert len(actual.canonical_rows(execution.executed)) == len(GROUPS)
    assert actual.production is None


@pytest.mark.parametrize("field", ["ports", "line_span"])
def test_late_input_graph_refusal_precedes_retention_and_writer_and_consumes_finish(monkeypatch, field):
    subject = item()
    supplied = request(subject)
    execution = owning.execute_local_version_inputs((subject,), (supplied,))
    snapshot = source_inputs.asdict if field == "ports" else source_inputs.custody.asdict
    bad = subject if field == "ports" else supplied
    def snapshotting(value):
        if value is bad:
            pytest.fail("traversed late malformed input before its graph guard")
        return snapshot(value)
    if field == "ports":
        object.__setattr__(subject.node, "ports", list(subject.node.ports))
        monkeypatch.setattr(source_inputs, "asdict", snapshotting)
    else:
        object.__setattr__(supplied.capture.lines[0].span, "start", [])
        monkeypatch.setattr(source_inputs.custody, "asdict", snapshotting)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        execution.owner.finish(execution.executed)
    assert execution.owner.production is None and execution.owner.production_attempted is True
    with pytest.raises(ValueError, match="production_once"):
        execution.owner.finish(execution.executed)


def test_completion_narrows_an_actual_owned_subset_without_claiming_global_composition():
    first, second = item(), item(node=B)
    execution = owning.execute_local_version_inputs((first, second), (request(first), request(second, identity="b")))
    subset = tuple(execution.owner.own(out) for out in reversed(execution.executed))
    result = execution.owner.finish(subset)
    assert len(result.rows) == len(result.store.values) == 2 * len(GROUPS)
    assert tuple(out.receipt.capture.id for out in result.executed) == tuple(out.receipt.capture.id for out in subset)
    assert all(out is execution.owner.inputs.owned[out.receipt.capture.id] for out in result.executed)
