"""Deterministic producer graph; every defect is refused by name."""
from atlas_brain.kernel.states import require
from atlas_brain.model.specs import StepId, StepSpec


def _cycle_members(pending: tuple[StepId, ...], needs: dict[StepId, set[StepId]]) -> tuple[StepId, ...]:
    """Return every pending step that can reach itself through remaining needs."""
    members: list[StepId] = []
    for node in pending:
        seen: set[StepId] = set()
        frontier = sorted(needs[node])
        while frontier:
            current = frontier.pop()
            if current == node:
                members.append(node)
                break
            if current not in seen:
                seen.add(current)
                frontier.extend(sorted(needs[current]))
    return tuple(members)


def order_steps(steps: tuple[StepSpec, ...]) -> tuple[StepSpec, ...]:
    """Topologically order steps; lexicographic among ready steps, cycles refused."""
    require(type(steps) is tuple and all(type(step) is StepSpec for step in steps), 'invalid_steps')
    by_id = {step.id: step for step in steps}
    require(len(by_id) == len(steps), 'duplicate_step')
    producers: dict[str, StepId] = {}
    for step in sorted(steps, key=lambda item: item.id):
        for fact in step.produces:
            require(fact not in producers, 'duplicate_producer:' + fact)
            producers[fact] = step.id
    needs: dict[StepId, set[StepId]] = {}
    for step in sorted(steps, key=lambda item: item.id):
        dependencies: set[StepId] = set()
        for fact in step.reads:
            require(fact in producers, 'missing_producer:' + fact)
            dependencies.add(producers[fact])
        require(step.scope == 'estate' or all(by_id[owner].scope == 'device' for owner in sorted(dependencies)),
                'device_reads_estate:' + step.id)
        needs[step.id] = dependencies
    dependents: dict[StepId, set[StepId]] = {step_id: set() for step_id in by_id}
    for step_id in sorted(needs):
        for owner in sorted(needs[step_id]):
            dependents[owner].add(step_id)
    ready = sorted(step_id for step_id in needs if not needs[step_id])
    result: list[StepSpec] = []
    while ready:
        step_id = ready.pop(0)
        result.append(by_id[step_id])
        for dependent in sorted(dependents[step_id]):
            needs[dependent].remove(step_id)
            if not needs[dependent]:
                ready.append(dependent)
                ready.sort()
    pending = tuple(sorted(step_id for step_id in needs if needs[step_id]))
    require(not pending, 'cyclic_steps:' + ','.join(_cycle_members(pending, needs)))
    return tuple(result)
