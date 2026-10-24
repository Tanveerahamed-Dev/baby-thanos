"""A character class is a new atom; nested group repetition still refuses."""
import pytest

from atlas_brain.kernel.lints import nested_unbounded


@pytest.mark.parametrize('pattern', ['(a+)[b]+', '(a+)[b]*', '(a+)[b]{1,}', '(?:a+)[b]+', '(a+)[()]+'])
def test_class_repetition_is_not_repetition_of_the_preceding_group(pattern):
    assert nested_unbounded(pattern) is False


@pytest.mark.parametrize('pattern', ['(a+)+', '(a+)[b]+(c+)+', '((a+)[b]+)+'])
def test_genuinely_nested_group_repetition_is_still_refused(pattern):
    assert nested_unbounded(pattern) is True
