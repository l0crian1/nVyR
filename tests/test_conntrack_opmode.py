"""Connection normalization, filtering, presentation and operational dispatch."""

import json
import socket

import pytest

from nvyr.errors import OperationalError
from nvyr.helpers import access, conntrack as tracking
from nvyr.op_scripts import conntrack


def attributes(**values):
    return {'attrs': list(values.items())}


def message(*, status=24, family=socket.AF_INET, protocol=6):
    """A source-NAT connection with accounting, labels and a separate reply tuple."""
    version = 4 if family == socket.AF_INET else 6
    source = '192.0.2.10' if version == 4 else '2001:db8::10'
    destination = '198.51.100.20' if version == 4 else '2001:db8:1::20'
    translated = '203.0.113.1' if version == 4 else '2001:db8:2::1'
    original = attributes(CTA_TUPLE_IP=attributes(**{f'CTA_IP_V{version}_SRC': source,
                                                    f'CTA_IP_V{version}_DST': destination}),
                          CTA_TUPLE_PROTO=attributes(CTA_PROTO_NUM=protocol, CTA_PROTO_SRC_PORT=12345,
                                                     CTA_PROTO_DST_PORT=443), CTA_TUPLE_ZONE=7)
    reply = attributes(CTA_TUPLE_IP=attributes(**{f'CTA_IP_V{version}_SRC': destination,
                                                 f'CTA_IP_V{version}_DST': translated}),
                       CTA_TUPLE_PROTO=attributes(CTA_PROTO_NUM=protocol, CTA_PROTO_SRC_PORT=443,
                                                  CTA_PROTO_DST_PORT=45678))
    return {'nfgen_family': family, **attributes(
        CTA_TUPLE_ORIG=original, CTA_TUPLE_REPLY=reply, CTA_STATUS=status, CTA_TIMEOUT=90,
        CTA_MARK=100, CTA_ZONE=5, CTA_ID=123, CTA_LABELS=1 | (1 << 127),
        CTA_COUNTERS_ORIG=attributes(CTA_COUNTERS_PACKETS=4, CTA_COUNTERS_BYTES=240),
        CTA_PROTOINFO=attributes(CTA_PROTOINFO_TCP=attributes(CTA_PROTOINFO_TCP_STATE=3)))}


def test_normalized_metadata_preserves_absent_accounting():
    record = tracking.normalize(message(status=24 | (1 << 14)))
    assert record['nat'] == ['snat']
    assert record['labels'] == [0, 127]
    assert record['state'] == 'established'
    assert record['zone'] == 5
    assert record['original']['zone'] == 7
    assert record['original']['packets'] == 4
    assert 'packets' not in record['reply']
    assert record['status'] == ['confirmed', 'snat', 'offload']


def test_icmp_identifiers_and_type_code_remain_visible():
    data = message(protocol=1)
    original = tracking._attr(data, 'CTA_TUPLE_ORIG')
    protocol = tracking._attr(original, 'CTA_TUPLE_PROTO')
    protocol['attrs'] = list(attributes(CTA_PROTO_NUM=1, CTA_PROTO_ICMP_ID=18,
                                      CTA_PROTO_ICMP_TYPE=8, CTA_PROTO_ICMP_CODE=0)['attrs'])
    record = tracking.normalize(data)
    assert record['original']['icmp-id'] == 18
    assert record['original']['icmp-type'] == 8
    assert record['original']['icmp-code'] == 0
    assert 'source-port' not in record['original']
    assert 'state' not in record


def test_helper_netlink_decoding_and_detail(capsys):
    """Helper metadata is nested on the wire, not a top-level string."""
    data = message()
    data['attrs'].append(('CTA_HELP', attributes(CTA_HELP_NAME='ftp')))
    outgoing = tracking.ConnectionMessage()
    outgoing.update(data)
    outgoing.encode()
    incoming = tracking.ConnectionMessage(outgoing.data)
    incoming.decode()

    record = tracking.normalize(incoming)
    assert record['helper'] == 'ftp'
    conntrack._detail(record)
    output = capsys.readouterr().out
    assert 'Helper' in output and 'ftp' in output
    assert 'helper' not in tracking.normalize(message())


@pytest.mark.parametrize(('protocol', 'name', 'number', 'expected'), [
    (6, 'TCP', 9, 'syn-sent2'), (132, 'SCTP', 4, 'established'),
    (33, 'DCCP', 4, 'open'), (6, 'TCP', 99, 'unknown (99)'),
])
def test_protocol_specific_state_decoding(protocol, name, number, expected):
    data = message(protocol=protocol)
    information = tracking._attr(data, 'CTA_PROTOINFO')
    information['attrs'] = [(f'CTA_PROTOINFO_{name}', attributes(**{f'CTA_PROTOINFO_{name}_STATE': number}))]
    assert tracking.normalize(data)['state'] == expected


@pytest.fixture
def kernel(monkeypatch):
    clients = []

    class Client:
        def __init__(self, nfgen_family=socket.AF_INET):
            self.family = nfgen_family
            self.closed = False
            self.arguments = None
            clients.append(self)

        def register_policy(self, policy):
            self.policy = policy

        def dump(self, **arguments):
            self.arguments = arguments
            return [message(family=self.family)]

        def close(self):
            self.closed = True

        def count(self):
            return 12

        def conntrack_max_size(self):
            return 100

        def stat(self):
            return [{'cpu': 0, 'drop': 2, 'insert_failed': 1}, {'cpu': 7, 'drop': 3, 'insert_failed': 4}]

    monkeypatch.setattr(tracking, 'Conntrack', Client)
    return clients


def test_unfiltered_dump_reads_both_families_and_closes_sockets(kernel):
    records = tracking.read()
    assert [record['family'] for record in records] == ['ipv4', 'ipv6']
    assert all(client.closed for client in kernel)
    assert all(client.arguments == {} for client in kernel)


def test_address_filter_infers_family_and_filters_original_tuple(kernel):
    assert len(tracking.read(source_address='2001:db8::10', protocol='tcp', state='established')) == 1
    assert len(kernel) == 1
    assert kernel[0].family == socket.AF_INET6
    assert 'tuple_orig' in kernel[0].arguments
    assert 'tuple_reply' not in kernel[0].arguments


def test_state_filter_does_not_return_other_states(kernel):
    assert tracking.read(state='syn-sent') == []


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_offload_filter_selects_current_status_and_preserves_counters(kernel, monkeypatch, family):
    statuses = [8, 8 | (1 << 14), 8 | (1 << 15), 8 | (1 << 14) | (1 << 15)]
    monkeypatch.setattr(tracking.Conntrack, 'dump', lambda client, **kwargs: [
        message(status=status, family=client.family) for status in statuses])

    records = tracking.read(family=family, offload=True)
    assert [record['status-mask'] for record in records] == statuses[1:]
    assert all(record['family'] == family for record in records)
    assert all(record['original']['packets'] == 4 for record in records)
    assert all(record['original']['bytes'] == 240 for record in records)
    assert len(tracking.read(family=family)) == 4
    assert tracking.read(family=family, offload=True, state='syn-sent') == []


def test_address_filters_compare_canonical_original_addresses(kernel):
    assert len(tracking.read(source_address='2001:0db8:0:0:0:0:0:10')) == 1
    assert tracking.read(destination_address='2001:db8::99') == []
    assert all(client.arguments == {} for client in kernel)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_accounting_filter_includes_zero_counters_and_either_direction(kernel, monkeypatch, family):
    def dump(client, **kwargs):
        records = []
        for identifier, direction, packets in [(1, None, None), (2, 'ORIG', 0), (3, 'REPLY', 7)]:
            data = message(family=client.family, status=8 | (1 << 14))
            data['attrs'] = [(key, value) for key, value in data['attrs']
                             if key not in ('CTA_COUNTERS_ORIG', 'CTA_ID')]
            data['attrs'].append(('CTA_ID', identifier))
            if direction:
                data['attrs'].append(('CTA_COUNTERS_' + direction,
                                      attributes(CTA_COUNTERS_PACKETS=packets, CTA_COUNTERS_BYTES=packets * 60)))
            records.append(data)
        return records

    monkeypatch.setattr(tracking.Conntrack, 'dump', dump)

    assert len(tracking.read(family=family)) == 3
    records = tracking.read(family=family, accounting=True, offload=True)
    assert [record['id'] for record in records] == [2, 3]
    assert records[0]['original']['packets'] == 0
    assert records[1]['reply']['packets'] == 7
    assert tracking.read(family=family, accounting=True, state='syn-sent') == []


def test_statistics_reject_connection_filters():
    with pytest.raises(OperationalError, match='Statistics cannot be combined'):
        conntrack.show('show conntrack statistics ipv4')


@pytest.mark.parametrize('filters', [
    {'family': 'ipv4', 'source_address': '::1'},
    {'source_address': '::1', 'destination_address': '192.0.2.1'},
    {'source_address': 'not-an-ip'}, {'family': 'ipx'},
    {'protocol': 'udp', 'state': 'established'}, {'state': 'new'},
])
def test_invalid_filters_fail_before_opening_socket(kernel, filters):
    with pytest.raises(OperationalError):
        tracking.read(**filters)
    assert kernel == []


def test_netlink_errors_are_operational_errors(kernel, monkeypatch):
    def unavailable(**kwargs):
        raise OSError('permission denied')
    monkeypatch.setattr(tracking, 'Conntrack', unavailable)
    with pytest.raises(OperationalError, match='Cannot read connection tracking: permission denied'):
        tracking.read()


def test_statistics_sum_per_cpu_without_summing_cpu_numbers(kernel):
    assert tracking.statistics() == {'entries': 12, 'maximum': 100, 'utilization': 12.0,
                                     'counters': {'drop': 5, 'insert_failed': 5}}


def test_filters_parse_with_anchor_and_no_family_keyword():
    path, values = conntrack._options('run show conntrack ipv6 protocol tcp offload accounting state established source-address ::1 detail')
    assert tuple(path) == ('show', 'conntrack')
    assert values == {'family': 'ipv6', 'protocol': 'tcp', 'state': 'established',
                      'source_address': '::1', 'offload': True, 'accounting': True, 'detail': True}
    with pytest.raises(OperationalError, match='Choose only one'):
        conntrack._options('show conntrack ipv4 ipv6')


def test_translation_selection_and_double_nat(monkeypatch, capsys):
    source = tracking.normalize(message(status=24))
    destination = tracking.normalize(message(status=40))
    both = tracking.normalize(message(status=56))
    ordinary = tracking.normalize(message(status=8))
    records = [source, destination, both, ordinary]
    monkeypatch.setattr(tracking, 'read', lambda **kwargs: records)
    assert json.loads(conntrack.show('show nat translations', raw=True)) == records[:3]
    assert json.loads(conntrack.show('show nat source translations', raw=True)) == [source, both]
    assert json.loads(conntrack.show('show nat destination translations', raw=True)) == [destination, both]
    conntrack.show('show nat translations')
    output = capsys.readouterr().out
    assert '203.0.113.1:45678' in output
    assert '192.0.2.10:12345' in output
    assert 'SNAT+DNAT' in output


def test_ipv6_table_and_detailed_metadata(monkeypatch, capsys):
    record = tracking.normalize(message(family=socket.AF_INET6))
    monkeypatch.setattr(tracking, 'read', lambda **kwargs: [record])
    conntrack.show('show conntrack ipv6')
    assert '[2001:db8::10]:12345' in capsys.readouterr().out
    conntrack.show('show conntrack ipv6 detail')
    output = capsys.readouterr().out
    assert ' | ' in output and '0, 127' in output and 'Original zone' in output
    assert 'Reply packets' not in output

    conntrack.show('show conntrack ipv6', strip_private='all')
    masked = capsys.readouterr().out
    assert '[<ipv6>]:12345' in masked and '2001:db8:' not in masked
    hidden = json.loads(conntrack.show('show conntrack ipv6 detail', raw=True, strip_private='all'))[0]
    assert hidden['original']['source-address'] == hidden['reply']['destination-address'] == '<ipv6>'
    assert record['original']['source-address'] == '2001:db8::10'


def test_empty_tables_and_statistics_display(monkeypatch, capsys, kernel):
    monkeypatch.setattr(tracking, 'read', lambda **kwargs: [])
    conntrack.show('show conntrack')
    assert 'No matching connections.' in capsys.readouterr().out
    conntrack.show('show nat translations')
    assert 'No matching NAT translations.' in capsys.readouterr().out
    conntrack.statistics()
    output = capsys.readouterr().out
    assert 'Current entries' in output and '12.00%' in output and ' | ' in output


@pytest.mark.parametrize('field', ['source', 'destination'])
@pytest.mark.parametrize('reverse', [False, True])
def test_endpoint_sort_uses_numeric_addresses_then_ports(monkeypatch, field, reverse):
    records = []
    for identifier, address, port in [(1, '192.0.2.10', 9), (2, '192.0.2.2', 100),
                                      (3, '192.0.2.2', 20), (4, '192.0.2.2', None),
                                      (5, '2001:db8::2', 9), (6, '2001:db8::10', 9)]:
        record = tracking.normalize(message())
        record['id'] = identifier
        record['original'][field + '-address'] = address
        record['original'][field + '-port'] = port
        records.append(record)
    monkeypatch.setattr(tracking, 'read', lambda **kwargs: records)

    line = f'show nat translations sort-by {field}' + (' reverse' if reverse else '')
    result = json.loads(conntrack.show(line, raw=True))
    assert [record['id'] for record in result] == ([6, 5, 1, 2, 3, 4] if reverse else [3, 2, 4, 1, 5, 6])


@pytest.mark.parametrize('field', ['packets', 'bytes', 'state', 'timeout'])
@pytest.mark.parametrize('reverse', [False, True])
def test_sort_values_keeps_missing_last(monkeypatch, field, reverse):
    records = []
    for identifier, value in [(1, None), (2, 0), (3, 10), (4, 2)]:
        record = tracking.normalize(message())
        record['id'] = identifier
        if field in ('packets', 'bytes'):
            record['original'][field] = value
            record['reply'][field] = value
        else:
            record[field] = {None: None, 0: 'close', 10: 'syn-sent', 2: 'established'}[value] if field == 'state' else value
        records.append(record)
    monkeypatch.setattr(tracking, 'read', lambda **kwargs: records)

    result = json.loads(conntrack.show(f'show conntrack sort-by {field}' + (' reverse' if reverse else ''), raw=True))
    descending = (field != 'state') != reverse
    assert [record['id'] for record in result] == ([3, 4, 2, 1] if descending else [2, 4, 3, 1])


@pytest.mark.parametrize('view', ['show conntrack', 'show nat translations'])
@pytest.mark.parametrize('option', ['accounting', 'sort-by packets', 'sort-by bytes'])
def test_accounting_summary_combines_directions_without_enabling_filter(monkeypatch, capsys, view, option):
    record = tracking.normalize(message())
    record['reply'].update(packets=6, bytes=360)
    calls = []
    monkeypatch.setattr(tracking, 'read', lambda **kwargs: calls.append(kwargs) or [record])

    conntrack.show(f'{view} {option}')
    output = capsys.readouterr().out
    assert 'Packets' in output and 'Bytes' in output
    assert 'State' not in output and 'Timeout' not in output
    assert '10' in output and '600' in output
    assert calls == [{'accounting': True} if option == 'accounting' else {}]

    conntrack.show(f'{view} {option} detail')
    output = capsys.readouterr().out
    assert 'Original packets' in output and 'Reply packets' in output


def test_incomplete_accounting_totals_are_missing(monkeypatch, capsys):
    record = tracking.normalize(message())
    monkeypatch.setattr(tracking, 'read', lambda **kwargs: [record])

    assert conntrack._total(record, 'packets') is None
    conntrack.show('show conntrack sort-by bytes')
    output = capsys.readouterr().out
    assert 'Packets' in output and 'Bytes' in output
    assert '—' in output
    assert len(json.loads(conntrack.show('show conntrack sort-by bytes', raw=True))) == 1


def test_reverse_requires_sort_before_reading_connections(monkeypatch):
    monkeypatch.setattr(tracking, 'read', lambda **kwargs: pytest.fail('Unexpected connection dump'))
    with pytest.raises(OperationalError, match='reverse requires sort-by'):
        conntrack.show('show conntrack reverse')
    with pytest.raises(OperationalError, match='Statistics cannot be combined'):
        conntrack.show('show conntrack statistics sort-by bytes')


@pytest.mark.parametrize(('line', 'arguments'), [
    ('show conntrack', ['conntrack.nvyr.op', 'show', 'show conntrack']),
    ('show conntrack statistics', ['conntrack.nvyr.op', 'show', 'show conntrack statistics']),
    ('show conntrack ipv4 state established', ['conntrack.nvyr.op', 'show', 'show conntrack ipv4 state established']),
    ('show conntrack ipv4 offload detail', ['conntrack.nvyr.op', 'show', 'show conntrack ipv4 offload detail']),
    ('show conntrack offload ipv6', ['conntrack.nvyr.op', 'show', 'show conntrack offload ipv6']),
    ('show conntrack ipv4 accounting detail', ['conntrack.nvyr.op', 'show', 'show conntrack ipv4 accounting detail']),
    ('show conntrack ipv6 offload accounting', ['conntrack.nvyr.op', 'show', 'show conntrack ipv6 offload accounting']),
    ('show nat translations accounting', ['conntrack.nvyr.op', 'show', 'show nat translations accounting']),
    ('show conntrack accounting sort-by source reverse', ['conntrack.nvyr.op', 'show', 'show conntrack accounting sort-by source reverse']),
    ('show nat translations sort-by bytes', ['conntrack.nvyr.op', 'show', 'show nat translations sort-by bytes']),
    ('show nat translations ipv4 offload', ['conntrack.nvyr.op', 'show', 'show nat translations ipv4 offload']),
    ('show nat66 destination rule 10 detail', ['nat.nvyr.op', 'show', '--tree', 'nat66', '--direction', 'destination', '--rule', '10', '--detail']),
    ('show nat source', ['nat.nvyr.op', 'show', '--tree', 'nat', '--direction', 'source']),
    ('show nat destination rule 10 detail', ['nat.nvyr.op', 'show', '--tree', 'nat', '--direction', 'destination', '--rule', '10', '--detail']),
    ('show nat source translations ipv6', ['conntrack.nvyr.op', 'show', 'show nat source translations ipv6']),
])
def test_read_only_commands_available_to_operator(controller, monkeypatch, line, arguments):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'output\n')
    token = access.role.set('read-only')
    try:
        controller.execute(line)
    finally:
        access.role.reset(token)
    assert calls == [arguments]
