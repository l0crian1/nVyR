"""Dual-stack local DNS and VRF isolation in the shared routed-network suite.

Listeners, records and VRFs are installed with the common scenario, not per
test. Cache transport/TLS failure matrices live in the isolated native DNS lab.
"""

import json

import dns.message
import dns.query
import dns.rcode
import pytest

from nvyr.helpers.process import cmd


@pytest.mark.parametrize('address', ['127.0.0.1', '::1'])
@pytest.mark.parametrize('transport', [dns.query.udp, dns.query.tcp])
def test_local_names_both_families(address, transport):
    for kind, expected in [('A', '192.0.2.222'), ('AAAA', '2001:db8::222')]:
        reply = transport(dns.message.make_query('forwarding.example.org', kind), address, port=1053, timeout=3)
        assert reply.rcode() == dns.rcode.NOERROR
        assert reply.answer[0][0].address == expected


def test_vrf_listener_and_separate_cache():
    script = ('import dns.message,dns.query; '
              'r=dns.query.udp(dns.message.make_query("forwarding.example.org","AAAA"),'
              '"198.18.210.1",port=1053,timeout=3); print(r.answer[0][0].address)')
    assert cmd(['ip', 'vrf', 'exec', 'NVYRDHCPSMOKE', 'python3', '-c', script]).strip() == '2001:db8::222'
    default = json.loads(cmd(['dns_forwarding.nvyr.op', 'show', 'status', '--raw']))
    scoped = json.loads(cmd(['dns_forwarding.nvyr.op', 'show', 'status', '--vrf', 'NVYRDHCPSMOKE', '--raw']))
    assert default['VRF'] == 'default'
    assert scoped['VRF'] == 'NVYRDHCPSMOKE'
    assert scoped['State'] == 'Running'
