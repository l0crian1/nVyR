"""Run the installed-router Lua smoketest against disposable packaged FRR."""

import os
from pathlib import Path

import pytest

from functionaltests import test_frr_scripting


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_FRR_SCRIPTING_TEST') != '1',
                                reason='requires the built FRR packages in a privileged disposable container')


def test_lua_hook_executes_when_zebra_installs_route():
    """Use the same isolated hook-execution test as an installed router."""
    assert Path('/.dockerenv').exists(), 'run only in an isolated disposable container'
    test_frr_scripting.test_lua_hook_executes_when_zebra_installs_route()
