"""MACsec provisioning checks that cannot be observed from a negotiated link."""

from types import SimpleNamespace

import pytest

from nvyr.config_scripts import interface_macsec
from nvyr.errors import ValidationError
from nvyr.helpers.process import operational_argv
from nvyr.lexer import lex
from nvyr.op_scripts import macsec


@pytest.mark.parametrize('bits', [128, 256])
def test_generate_pasteable_key_pair(controller, session, bits):
    command = f'generate macsec preshared-key bits {bits}'
    tokens = lex(command)
    binding = controller.operational.operational(tokens).node['command']
    assert operational_argv(binding, tokens, command) == ['macsec.nvyr.op', 'generate', '--bits', str(bits)]
    output = macsec.generate(bits)
    _, name, _, key = output.split()
    assert len(bytes.fromhex(name)) == 16
    assert len(bytes.fromhex(key)) == bits // 8
    controller.execute('set interfaces macsec macsec1 mka preshared-key ' + output, session)


def test_reject_incomplete_and_duplicate_channels():
    association = {'ckn': '01'}
    link = {'source-interface': 'eth1', 'mka': {'preshared-key': association}}
    config = {'interfaces': {'macsec1': link}, 'inventory': {'eth1': {}}, 'vrfs': {},
              'bridge-members': set(), 'bond-members': set()}
    context = SimpleNamespace(recovery=False)
    with pytest.raises(ValidationError, match='both cak and ckn'):
        interface_macsec.verify(config, context)
    association['cak'] = 'ab' * 16
    config['interfaces']['macsec2'] = dict(link, **{'sci-port': '1'})
    with pytest.raises(ValidationError, match='duplicate SCI port 1 on eth1'):
        interface_macsec.verify(config, context)
