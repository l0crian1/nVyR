"""Restoration compares unordered multi-leaves without hiding real changes."""
import pytest

from smoketests.support import assert_configuration_restored


def test_multi_value_order_is_not_a_configuration_change():
    assert_configuration_restored({'events': ['new', 'destroy']}, {'events': ['destroy', 'new']})


@pytest.mark.parametrize('actual', [
    {}, {'events': ['new']}, {'events': ['new', 'new']},
    {'events': ['new', 'destroy', 'update']}, {'events': 'new'},
    {'events': ['new', 'destroy'], 'extra': {}},
])
def test_real_changes_are_not_accepted(actual):
    with pytest.raises(AssertionError, match='Configuration differs'):
        assert_configuration_restored({'events': ['new', 'destroy']}, actual)
