"""Own compatible interface devices and VRFs once across all interface scripts."""

from pathlib import Path
import shlex

import pytest

from smoketests.assertions import assert_bgp_resources_unused, assert_config_names_unused, assert_not_in, link_inventory
from smoketests.support import configuration_case


CONFIGURATION = Path(__file__).resolve().parents[1] / 'configs/interfaces.conf'


@pytest.fixture(scope='package', autouse=True)
def interface_topology(config, request):
    """Build all compatible addresses, VLANs and routing domains in one commit."""
    commands = [line for line in CONFIGURATION.read_text().splitlines()
                if line and not line.startswith('#')]
    names = {shlex.split(command)[3] for command in commands if command.startswith('set interfaces ')}
    names.discard('lo')
    names.update(('NVYRIFSMOKE', 'NVYRIFSMOKE2', 'IFDELETE1', 'IFDELETE2'))
    original = config.get_config()
    assert_config_names_unused(original, *names)
    devices = link_inventory()
    for name in names:
        assert_not_in(name, devices)
    for name, table in (('NVYRIFSMOKE', 41010), ('NVYRIFSMOKE2', 41011),
                        ('IFDELETE1', 41990), ('IFDELETE2', 41991)):
        assert_bgp_resources_unused(original, name, table)

    with configuration_case(config, request, original):
        for command in commands:
            config.set(command)
        config.commit()
        yield config.get_config()


@pytest.fixture(autouse=True)
def interface_configuration(config, request, interface_topology):
    """Discard incomplete commands; independent links need no per-case reset."""
    try:
        yield
    finally:
        # Each case owns its links or individual loopback values. Their completed
        # mutations can remain until package cleanup. Ethernet separately resets
        # its one physical port because those cases intentionally reuse it.
        config.discard()
