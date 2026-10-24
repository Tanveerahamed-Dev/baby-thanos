import pytest

from atlas_brain.kernel.lints import nested_unbounded


@pytest.mark.parametrize('pattern', ['(a+)+', '(a*)*', '((a+))+', '(ab+){1,}', '(a{1,})+'])
def test_nested_unbounded_repetition_is_refused(pattern):
    assert nested_unbounded(pattern)


@pytest.mark.parametrize('pattern', ['a+', '(ab)+', '[()+*]+', r'\(a\+\)\+', r'(a+)\+', '(a{2})+'])
def test_plain_bounded_and_escaped_shapes_remain_valid(pattern):
    assert not nested_unbounded(pattern)
