"""Read-only interface detail, offload, queue, hardware and transceiver views.

One physical-port selection serves every observation; no interface is created or
modified. Unsupported hardware is reported explicitly by the operational command.
"""

from contextlib import closing
import json

import pytest


if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.helpers.process import cmd
from nvyr.protocol import Client
from smoketests.assertions import assert_equal, assert_in, assert_true


@pytest.fixture(scope='module')
def ethernet_port():
    """Inspect a physical Ethernet port without changing it or requiring a spare."""
    links = json.loads(cmd(['ip', '-j', '-d', 'link', 'show']))
    for link in links:
        if link.get('link_type') == 'ether' and not link.get('linkinfo', {}).get('info_kind'):
            return link['ifname']
    pytest.skip('No physical Ethernet interface available for read-only diagnostics')


def test_ethernet_detail(ethernet_port):
    """The public detail command includes topology fields and driver link data."""
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text=f'show interfaces {ethernet_port} detail')['text']
    assert_in('Link-group', output)
    assert_in('IPv6 link-local', output)
    assert_true('Speed' in output or 'Ethernet link settings' in output)


def test_interface_raw_json(ethernet_port):
    """The installed raw command returns valid, scoped JSON for API consumers."""
    records = json.loads(cmd(['interfaces.nvyr.op', 'show', '--intf_name', ethernet_port, '--raw']))
    assert_equal([item['ifname'] for item in records], [ethernet_port])


def test_offload_display(ethernet_port):
    """Offloads have a tabulated active-state view and a structured raw record."""
    records = json.loads(cmd(['interfaces.nvyr.op', 'hardware', 'offload', '--intf_name', ethernet_port, '--raw']))
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text=f'show interfaces {ethernet_port} offload')['text']
    assert_in(ethernet_port, output)
    if records[ethernet_port] is not None:
        assert_in('Feature', output)
        assert_in('Enabled', output)
    else:
        assert_in('Not supported', output)


def test_queue_display(ethernet_port):
    """Independent channel/ring support must not make the combined view fail."""
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text=f'show interfaces {ethernet_port} queues')['text']
    assert_in(ethernet_port, output)
    assert_true('Channels' in output or 'Channel information is not supported.' in output)
    assert_true('Ring' in output)


def test_hardware_counter_display(ethernet_port):
    """Native driver counters retain full unsigned integer precision in raw output."""
    records = json.loads(cmd(['interfaces.nvyr.op', 'hardware', 'hardware-statistics',
                             '--intf_name', ethernet_port, '--raw']))
    assert_equal(list(records), [ethernet_port])
    counters = records[ethernet_port]
    if counters:
        assert_true(all(isinstance(value, int) and value >= 0 for name, value in counters))
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text=f'show interfaces {ethernet_port} hardware-statistics')['text']
    assert_in('Counter' if counters else ('Not supported' if counters is None else 'No hardware statistics'), output)


def test_transceiver_display(ethernet_port):
    """Copper ports report unsupported optics; optical ports expose decoded data."""
    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text=f'show interfaces {ethernet_port} transceiver')['text']
    assert_in(ethernet_port, output)
    assert_true(' | ' in output or 'Not supported' in output or 'No transceiver data' in output)
