"""Disposable network namespaces for operational tests that need isolated kernel state."""

import uuid

import pytest

from nvyr.helpers.process import cmd


@pytest.fixture
def namespace():
    """Create once per function and remove all its rules and connections at teardown."""
    name = 'nvyr-op-' + uuid.uuid4().hex[:10]
    cmd(['ip', 'netns', 'add', name])
    try:
        yield name
    finally:
        cmd(['ip', 'netns', 'delete', name])
