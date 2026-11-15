"""Old seven-fact registry refusal precedes capture-map work after a genuine current closure."""
from dataclasses import replace

import pytest
from test_mixed_proofs import actual, custody, references

from atlas_brain.kernel import states as k
from atlas_brain.runner import p4_mixed_refs as proofs


def test_registry_refusal_precedes_capture_map_materialization_after_real_current_closure(tmp_path, monkeypatch):
    source, index = actual(tmp_path, monkeypatch)
    reference, state = references(source.result)[0]
    envelope = source.source.execution.envelope
    accepted, evidence, captures = source.result, state.evidence, envelope.captures
    original_ref = next(ref for ref in evidence if type(ref) is k.RegistryRef and ref.table == "synthetic_p2.nodes")
    invalid_ref = replace(original_ref, citation="/nodes/999")
    invalid_evidence = tuple(invalid_ref if ref is original_ref else ref for ref in evidence)
    assert invalid_ref.table == original_ref.table and invalid_ref.row_id == original_ref.row_id
    assert invalid_ref.table_digest == original_ref.table_digest and invalid_ref.citation != original_ref.citation
    iterations, closed = [], []

    class CaptureMapTripwire:
        def __iter__(self):
            iterations.append(self)
            raise AssertionError("capture map materialized")

    tripwire = CaptureMapTripwire()
    with pytest.raises(AssertionError, match="^capture map materialized$"):
        iter(tripwire)
    assert len(iterations) == 1 and iterations[0] is tripwire
    iterations.clear()
    getter = proofs.owning.MixedComponentRun.current_component

    def current(attempt):
        result = getter(attempt)
        assert attempt is source and result is accepted
        assert state.evidence is evidence and envelope.captures is captures
        closed.append(result)
        object.__setattr__(state, "evidence", invalid_evidence)
        object.__setattr__(envelope, "captures", tripwire)
        return result

    try:
        with monkeypatch.context() as patch:
            patch.setattr(proofs.owning.MixedComponentRun, "current_component", current)
            with pytest.raises(ValueError, match="^p4_mixed_proofs_registry$"):
                index.resolve(reference)
            assert len(closed) == 1 and closed[0] is accepted
            assert state.evidence is invalid_evidence and envelope.captures is tripwire
            assert iterations == []
    finally:
        object.__setattr__(state, "evidence", evidence)
        object.__setattr__(envelope, "captures", captures)

    assert proofs.owning.MixedComponentRun.current_component is getter
    assert state.evidence is evidence and envelope.captures is captures and source.result is accepted
    custody(source, reference, state, index.resolve(reference))
    assert iterations == []
