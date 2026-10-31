"""The configured protocol vocabulary is fixed, name-only, and shared."""

import pytest

from nvyr.errors import ValidationError
from nvyr.helpers.validators import IP_PROTOCOLS, ip_protocol
from nvyr.schema import Schema
from nvyr.tree import lookup


EXPECTED = frozenset("""
ip icmp igmp ggp ipencap st tcp egp igp pup
udp hmp xns-idp rdp iso-tp4 dccp xtp ddp idpr-cmtp ipv6
ipv6-route ipv6-frag idrp rsvp gre esp ah skip ipv6-icmp ipv6-nonxt
ipv6-opts rspf vmtp eigrp ospf ax.25 ipip etherip encap pim
ipcomp vrrp l2tp isis sctp fc mobility-header udplite mpls-in-ip manet
hip shim6 wesp rohc ethernet
""".split())


def test_validator_accepts_exactly_the_requested_names():
    assert isinstance(IP_PROTOCOLS, frozenset)
    assert IP_PROTOCOLS == EXPECTED
    assert all(ip_protocol(name) for name in EXPECTED)
    assert all(not ip_protocol(str(number)) for number in range(256))

    for value in ('', 'all', 'icmpv6', 'hopopt', 'mptcp', 'TCP', ' tcp', 'tcp ',
                  'tcp\n', 'tcp; drop', 'tcp udp', '6-17', '0x06'):
        assert not ip_protocol(value)


def protocol_nodes(node, path=()):
    """Keep schema paths so rule and group-entry contracts can be checked separately."""
    for name, child in node.get('children', {}).items():
        child_path = (*path, name)
        # Map match selectors choose a field; they do not accept protocol values.
        if name == 'protocol' and not child.get('valueless'):
            yield child_path, child

        yield from protocol_nodes(child, child_path)


def test_all_firewall_and_nat_nodes_use_shared_choices_and_validator():
    schema = Schema.bundled()
    nodes = dict(protocol_nodes(schema.root['children']['firewall'], ('firewall',)))
    nodes.update(protocol_nodes(schema.root['children']['nat'], ('nat',)))

    # Check every family and consumer without tying coverage to a schema-wide total.
    for prefix in [('firewall',), ('firewall', 'fail-safe')]:
        for family in ('ipv4', 'ipv6', 'inet'):
            rule = (*prefix, family, 'forward', 'filter', 'rule')
            assert (*rule, 'protocol') in nodes
            assert (*rule, 'not', 'protocol') in nodes
            assert (*rule, 'connection', 'protocol') in nodes

            for group in ('map', 'match-group'):
                assert (*prefix, 'group', group, family, 'entry', 'protocol') in nodes

    for direction in ('source', 'destination'):
        assert ('nat', direction, 'rule', 'protocol') in nodes

    for path, node in nodes.items():
        # Timeout objects select one supported transport, rather than matching
        # arbitrary packet protocols. Keep their narrower contract explicit.
        if 'timeout-group' in path:
            assert not node.get('multi') and not node.get('_negated'), path
            assert set(node['choices']) == {'tcp', 'udp'}, path
            assert node['validators']['checks'] == {
                'list': {'name': 'list', 'args': {'values': 'tcp udp'}}}, path
            schema.validate(node, 'tcp')
            schema.validate(node, 'udp')
            for value in ('icmp', 'sctp', '6', 'all'):
                with pytest.raises(ValidationError):
                    schema.validate(node, value)
            continue

        # Rule matches allow alternatives; each group element supplies one key value.
        assert node['multi'] is ('entry' not in path), path
        assert bool(node.get('_negated')) == ('not' in path), path
        assert set(node['choices']) == EXPECTED, path
        assert node['validators']['checks'] == {'ip-protocol': {'name': 'ip-protocol'}}, path

        for name in EXPECTED:
            schema.validate(node, name)

        for value in ('6', 'all', 'icmpv6', 'unknown'):
            with pytest.raises(ValidationError, match='supported IP protocol name'):
                schema.validate(node, value)


def test_protocol_completion_abbreviation_multi_value_and_commit(controller, engine, session):
    prefix = 'firewall ipv4 forward filter rule 10'
    completion = controller.completion('set ' + prefix + ' protocol ', session, explicit=True)
    candidates = dict(completion['candidates'])

    assert EXPECTED <= candidates.keys()
    assert candidates['tcp'] == 'Transmission Control Protocol'
    assert candidates['rdp'] == 'Reliable Data Protocol'
    assert candidates['ipv6-frag'] == 'IPv6 fragment header'
    assert not {'all', 'icmpv6', '6'} & candidates.keys()
    assert controller.completion('set ' + prefix + ' protocol os', session)['replacement'] == 'ospf'
    assert controller.completion('set ' + prefix + ' protocol sct', session)['replacement'] == 'sctp'

    controller.execute('set ' + prefix + ' action accept pro ospf pro sctp', session)

    assert engine.commit(session)['results']['firewall']['success']
    assert lookup(engine.running, (*prefix.split(), 'protocol')) == ['ospf', 'sctp']

    with pytest.raises(ValidationError):
        controller.execute('set ' + prefix + ' protocol 6', session)
