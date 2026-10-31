"""Module-lived namespaces for native operational views with no configd ownership."""

import uuid

import pytest

from nvyr.helpers.process import cmd


@pytest.fixture(scope='module')
def native_namespace():
    """Keep kernel objects alive across compatible observations, then remove once."""
    name = 'nvyr-op-' + uuid.uuid4().hex[:10]
    cmd(['ip', 'netns', 'add', name])
    try:
        yield name
    finally:
        cmd(['ip', 'netns', 'delete', name])
