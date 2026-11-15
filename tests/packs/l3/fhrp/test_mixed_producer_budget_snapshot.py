"""Old seven-fact production keeps its pre-execution budget; later current access rechecks identity."""
from dataclasses import replace

import pytest
from test_mixed_component import FIELDS, spec
from test_mixed_context import admitted
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import mixed_component as component


def test_execute_time_budget_rebind_keeps_original_production_snapshot_and_rejects_current_access(tmp_path, monkeypatch):
    admitted(tmp_path)
    original = replace(LIMITS)
    rebound = replace(original)
    assert rebound == original and rebound is not original
    run = component.MixedComponentRun(tmp_path, original)
    execute = component.execution.execute_mixed_inputs
    validate = component.execution.validate_mixed_execution
    bind = component.bind_reader
    executed, validations, readers = [], [], []

    def executing(root, budgets):
        assert root is run.root is tmp_path and budgets is original and run.budgets is original
        source = execute(root, budgets)
        assert type(source) is component.execution.MixedExecution and source.budgets is original
        assert run.attempted is True and run.source is None and run.result is run.retained is None
        assert all(getattr(run, field) is None for field in FIELDS)
        executed.append(source)
        run.budgets = rebound
        return source

    def validating(source, budgets):
        validations.append((source, budgets))
        return validate(source, budgets)

    def binding(store, *, step):
        reader = bind(store, step=step)
        readers.append(reader)
        return reader

    monkeypatch.setattr(component.execution, "execute_mixed_inputs", executing)
    monkeypatch.setattr(component.execution, "validate_mixed_execution", validating)
    monkeypatch.setattr(component, "bind_reader", binding)
    result = run.build()
    assert len(executed) == 1
    source = executed[0]
    assert result is run.result is run.retained.component and result.source is run.source is source
    assert run.budgets is rebound and source.budgets is original
    assert len(validations) == 4 and all(value is source and budgets is original for value, budgets in validations)
    owned = tuple(getattr(result, field) for field in FIELDS)
    assert tuple(len(value.rows) for value in owned) == (1, 1, 5, 5, 2)
    assert len({id(value.store) for value in owned}) == len(readers) == 5
    assert sum(len(spec(field).produces) for field in FIELDS) == 7
    for field, value, reader, held in zip(FIELDS, owned, readers, run.retained.held, strict=True):
        store, rows, cells = held
        step = spec(field)
        assert value is getattr(run, field) and value.store is store and value.rows is rows
        assert reader.store is store and reader.step.reads == step.produces and not reader.step.produces
        assert store.owners == {fact: step.id for fact in step.produces}
        assert set(store.values) == {k.FactRef(fact=fact, subject=row.subject) for row in rows for fact in step.produces}
        assert len(store.values) == len(cells) and all(store.values[k.FactRef(fact=fact, subject=subject)] is state
            for fact, subject, state in cells)

    retained = run.retained
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_current$"):
        run.current_component()
    assert len(validations) == 5 and validations[-1][0] is source and validations[-1][1] is rebound
    assert len(readers) == 5 and run.result is result and run.retained is retained
    run.budgets = original
    assert run.current_component() is result
    assert len(readers) == 10 and len(validations) == 7
    assert all(value is source for value, _ in validations)
    assert all(budgets is original for _, budgets in (*validations[:4], *validations[5:]))
