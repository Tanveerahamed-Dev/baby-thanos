from dataclasses import FrozenInstanceError

import pytest

from atlas_brain.kernel.time import BoundSource, TimeInterval


@pytest.mark.parametrize('earliest,latest,bound,clock', [
    (2, 1, BoundSource.COLLECTOR_RECORDED, 'collector:synthetic'),
    (True, 2, BoundSource.COLLECTOR_RECORDED, 'collector:synthetic'),
    (0, 1.5, BoundSource.COLLECTOR_RECORDED, 'collector:synthetic'),
    (0, 1, 'collector_recorded', 'collector:synthetic'),
    (0, 1, BoundSource.UNBOUNDED, 'collector:synthetic'),
    (None, 1, BoundSource.COLLECTOR_RECORDED, 'collector:synthetic'),
    (0, 1, BoundSource.CAPTURE_CONCURRENT, ''),
    (0, 1, BoundSource.CAPTURE_CONCURRENT, 'node:sw-a'),
])
def test_invalid_interval_plants(earliest, latest, bound, clock):
    with pytest.raises(ValueError):
        TimeInterval(earliest=earliest, latest=latest, clock=clock, bound=bound)


@pytest.mark.parametrize('earliest,latest', [(None, None), (None, 0), (0, None)])
def test_unbounded_sides_are_retained(earliest, latest):
    interval = TimeInterval(earliest=earliest, latest=latest,
                            clock='collector:synthetic', bound=BoundSource.UNBOUNDED)
    assert (interval.earliest, interval.latest) == (earliest, latest)


def test_inclusive_bounds_exact_shape_and_immutability():
    assert len(BoundSource) == 5
    interval = TimeInterval(earliest=-1, latest=-1, clock='node:sw-a/epoch:one',
                            bound=BoundSource.PER_EVENT_QUALITY)
    assert interval.earliest == interval.latest == -1
    assert not hasattr(interval, '__dict__')
    with pytest.raises(FrozenInstanceError):
        interval.latest = 2
    with pytest.raises(TypeError):
        TimeInterval(earliest=0, latest=0, clock='collector:synthetic')
