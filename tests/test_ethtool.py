"""Kernel record decoding and optional Ethernet diagnostic capabilities."""

import ctypes
import errno
import struct
import sys

import pytest

from nvyr.errors import OperationalError
from nvyr.helpers import ethtool
from nvyr.helpers.process import CommandResult


def test_json_link_query_uses_argument_array(monkeypatch):
    calls = []

    def execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return CommandResult('[{"ifname":"eth0","speed":1000}]', '', 0)

    monkeypatch.setattr(ethtool, 'cli_cmd', execute)
    assert ethtool.json_data('eth0', 'link')['speed'] == 1000
    assert calls[0][0] == ['ethtool', '--json', 'eth0']
    assert calls[0][1]['env']['LC_ALL'] == 'C'


@pytest.mark.parametrize('stdout', ['', '[]', '[{}]'])
def test_unsupported_json_is_unavailable(monkeypatch, stdout):
    monkeypatch.setattr(ethtool, 'cli_cmd', lambda *args, **kwargs:
                        CommandResult(stdout, 'netlink error: Operation not supported\n', 1))
    assert ethtool.json_data('eth0', 'transceiver') is None


@pytest.mark.parametrize('stderr', ['netlink error: Operation not permitted',
                                   'netlink error: No such device',
                                   'JSON output not available for this subcommand',
                                   'netlink error: Operation not supported\nnetlink error: Input/output error'])
def test_real_failures_are_not_hidden(monkeypatch, stderr):
    monkeypatch.setattr(ethtool, 'cli_cmd', lambda *args, **kwargs: CommandResult('[]', stderr, 1))
    with pytest.raises(OperationalError, match='ethtool'):
        ethtool.json_data('eth0', 'link')


@pytest.mark.parametrize('data', ['invalid', '{}', '[1]', '[{"ifname":"eth1"}]', '[{}, {}, 1]'])
def test_invalid_json_contract_is_rejected(monkeypatch, data):
    monkeypatch.setattr(ethtool, 'cli_cmd', lambda *args, **kwargs: CommandResult(data, '', 0))
    with pytest.raises(OperationalError):
        ethtool.json_data('eth0', 'link')


@pytest.mark.parametrize('name', ['--help', 'eth0;id', 'e' * 16, 'eth0\n'])
def test_names_cannot_be_options_or_shell_syntax(monkeypatch, name):
    monkeypatch.setattr(ethtool, 'cli_cmd', lambda *args, **kwargs: pytest.fail('Invalid name executed'))
    with pytest.raises(OperationalError, match='interface name'):
        ethtool.json_data(name, 'offload')


def test_link_fields_keep_negotiated_pause_distinct(monkeypatch):
    replies = {
        'link': {'speed': 2500, 'duplex': 'Full', 'auto-negotiation': True,
                 'supported-link-modes': ['1000baseT/Full', '2500baseT/Full'],
                 'advertised-link-modes': ['2500baseT/Full'],
                 'link-partner-advertised-link-modes': ['1000baseT/Full'],
                 'port': 'Twisted Pair', 'link-state': ['Autoneg', 'No partner detected']},
        'pause': {'autonegotiate': True, 'rx': True, 'tx': True,
                  'negotiated': {'rx': False, 'tx': False}},
        'fec': {'config': ['Auto', 'RS'], 'active': ['RS']},
        'eee': {'status': 'inactive'},
    }
    monkeypatch.setattr(ethtool, 'json_data', lambda name, operation, **kwargs: replies[operation])
    monkeypatch.setattr(ethtool, 'driver_info', lambda name: {'Driver': 'igc', 'Firmware version': ''})

    fields = dict(ethtool.link_details('eth0'))
    assert fields['Speed'] == '2.5 Gbit/s'
    assert fields['RX pause'] == 'Enabled'
    assert fields['RX pause negotiated'] == 'Disabled'
    assert fields['FEC active'] == 'RS'
    assert fields['Partner advertised link modes'] == '1000baseT/Full'
    assert fields['Firmware version'] == ''
    assert fields['Energy Efficient Ethernet'] == 'Enabled (inactive)'


@pytest.mark.parametrize('speed', [None, 0, -1, 0xffffffff])
def test_unknown_speed_never_becomes_a_rate(monkeypatch, speed):
    monkeypatch.setattr(ethtool, 'json_data', lambda name, operation, **kwargs:
                        {'speed': speed} if operation == 'link' else None)
    monkeypatch.setattr(ethtool, 'driver_info', lambda name: None)
    assert dict(ethtool.link_details('eth0'))['Speed'] == ''


@pytest.mark.parametrize('status', [0, 1])
def test_partial_link_json_retains_fields_and_reports_diagnostics(monkeypatch, status):
    """ethtool can report ENODEV on stderr while returning valid JSON and rc 0."""
    diagnostic = 'netlink error: failed to retrieve link settings\nnetlink error: No such device\n'
    monkeypatch.setattr(ethtool, 'cli_cmd', lambda *args, **kwargs:
                        CommandResult('[{"ifname":"eth1","link-detected":false}]',
                                      diagnostic * 2, status))

    warnings = []
    assert ethtool.json_data('eth1', 'link', warnings=warnings) == {
        'ifname': 'eth1', 'link-detected': False}
    assert warnings == ['netlink error: failed to retrieve link settings; netlink error: No such device']
    with pytest.raises(OperationalError, match='No such device'):
        ethtool.json_data('eth1', 'link')


def test_detail_keeps_driver_and_eee_after_independent_query_failures(monkeypatch):
    def execute(argv, **kwargs):
        if '--show-pause' in argv:
            return CommandResult('', 'netlink error: No such device', 1)
        if '--show-fec' in argv:
            return CommandResult('', 'netlink error: Operation not supported', 1)
        if '--show-eee' in argv:
            return CommandResult('[{"ifname":"eth1","status":"inactive"}]', '', 0)
        return CommandResult('[{"ifname":"eth1","port":"MII"}]',
                             'netlink error: No such device', 0)

    monkeypatch.setattr(ethtool, 'cli_cmd', execute)
    monkeypatch.setattr(ethtool, 'driver_info', lambda name: {'Driver': 'r8169'})

    rows = ethtool.link_details('eth1')
    fields = dict(rows)

    assert rows.count(('Ethernet diagnostics', 'Currently unavailable')) == 1
    assert 'No such device' not in str(rows)
    assert 'Pause settings' not in fields
    assert 'FEC settings' not in fields
    assert fields['Speed'] == '' and fields['Duplex'] == ''
    assert fields['Port medium'] == 'MII'
    assert fields['Driver'] == 'r8169'
    assert fields['Energy Efficient Ethernet'] == 'Enabled (inactive)'


def test_detail_reports_malformed_data_and_driver_errors(monkeypatch):
    monkeypatch.setattr(ethtool, 'cli_cmd', lambda *args, **kwargs:
                        CommandResult('invalid', '', 0))

    def driver(name):
        raise OperationalError('Permission denied')

    monkeypatch.setattr(ethtool, 'driver_info', driver)

    rows = ethtool.link_details('eth1')

    assert rows == [('Ethernet diagnostics', 'Currently unavailable')]
    with pytest.raises(OperationalError, match='invalid ethtool link JSON'):
        ethtool.json_data('eth1', 'link')
    with pytest.raises(OperationalError, match='Permission denied'):
        ethtool.driver_info('eth1')


def test_partial_pause_detail_keeps_reported_values_and_blanks_missing_fields(monkeypatch):
    def execute(argv, **kwargs):
        if '--show-pause' in argv:
            return CommandResult('[{"ifname":"eth1","rx":false}]',
                                 'netlink error: No such device', 0)
        return CommandResult('[]', 'netlink error: Operation not supported', 1)

    monkeypatch.setattr(ethtool, 'cli_cmd', execute)
    monkeypatch.setattr(ethtool, 'driver_info', lambda name: {'Driver': 'r8169'})

    fields = dict(ethtool.link_details('eth1'))

    assert fields['Ethernet diagnostics'] == 'Currently unavailable'
    assert fields['RX pause'] == 'Disabled'
    assert fields['TX pause'] == ''
    assert fields['Pause autonegotiation'] == ''
    assert fields['Driver'] == 'r8169'


def test_driver_uapi_record(monkeypatch):
    def ioctl(name, payload):
        assert len(payload) == 196
        assert struct.unpack_from('=I', payload)[0] == 3
        result = bytearray(payload)
        result[4:7] = b'igc'
        result[68:71] = b'1.2'
        result[100:112] = b'0000:01:00.0'
        return result

    monkeypatch.setattr(ethtool, '_ioctl', ioctl)
    assert ethtool.driver_info('eth0') == {
        'Driver': 'igc', 'Driver version': '', 'Firmware version': '1.2', 'Bus address': '0000:01:00.0'}


def test_channel_uapi_record(monkeypatch):
    monkeypatch.setattr(ethtool, '_ioctl', lambda name, payload:
                        struct.pack('=9I', 0x3c, 8, 8, 1, 16, 2, 2, 0, 4))
    assert ethtool.channels('eth0') == [['RX', 2, 8], ['TX', 2, 8], ['Other', 0, 1], ['Combined', 4, 16]]


def test_statistic_names_and_unsigned_values(monkeypatch):
    def ioctl(name, payload):
        command = struct.unpack_from('=I', payload)[0]
        if command == 0x37:
            return struct.pack('=IIQI', command, 0, 2, 2)
        if command == 0x1b:
            return struct.pack('=III32s32s', command, 1, 2, b'rx_crc_errors', b'tx_packets')
        return struct.pack('=IIQQ', command, 2, 0, 2 ** 63 + 5)

    monkeypatch.setattr(ethtool, '_ioctl', ioctl)
    assert ethtool.hardware_statistics('eth0') == [['rx_crc_errors', 0], ['tx_packets', 2 ** 63 + 5]]


def test_statistics_size_change_requires_retry(monkeypatch):
    replies = iter([struct.pack('=IIQI', 0x37, 0, 2, 1),
                    struct.pack('=III32s', 0x1b, 1, 2, b'rx'),
                    struct.pack('=IIQ', 0x1d, 1, 0)])
    monkeypatch.setattr(ethtool, '_ioctl', lambda *args: next(replies))
    with pytest.raises(OperationalError, match='retry'):
        ethtool.hardware_statistics('eth0')


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux ioctl boundary')
def test_ioctl_mutates_pointed_buffer_and_sizes_ifreq(monkeypatch):
    import fcntl

    def ioctl(descriptor, operation, request):
        assert operation == 0x8946
        assert len(request) == (40 if struct.calcsize('P') == 8 else 32)
        name, pointer = struct.unpack_from('@16sP', request)
        assert name.rstrip(b'\0') == b'eth0'
        ctypes.memmove(pointer, b'abcd', 4)

    monkeypatch.setattr(fcntl, 'ioctl', ioctl)
    assert ethtool._ioctl('eth0', b'\0' * 4) == b'abcd'


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux ioctl boundary')
@pytest.mark.parametrize('code', [errno.EOPNOTSUPP, errno.EPERM, errno.ENODEV])
def test_ioctl_only_suppresses_unsupported(monkeypatch, code):
    import fcntl

    def ioctl(*args):
        raise OSError(code, 'kernel error')

    monkeypatch.setattr(fcntl, 'ioctl', ioctl)
    if code == errno.EOPNOTSUPP:
        assert ethtool._ioctl('eth0', b'\0' * 4) is None
    else:
        with pytest.raises(OperationalError, match='kernel error'):
            ethtool._ioctl('eth0', b'\0' * 4)


def test_module_lane_labels_and_units_are_retained():
    rows = dict(ethtool.transceiver_rows({
        'ifname': 'eth0', 'vendor_name': 'Example', 'module_temperature': 38.2,
        'module_voltage': 3.3, 'laser_wavelength': 850,
        'channels': [{'tx_power': {'mW': 0.6, 'dBm': -2.2}}, {'tx_power': {'mW': 0.5, 'dBm': -3.0}}],
    }))
    assert rows['Vendor name'] == 'Example'
    assert rows['Module temperature'] == '38.2 °C'
    assert rows['Module voltage'] == '3.3 V'
    assert rows['Laser wavelength'] == '850 nm'
    assert rows['Channels 1 / tx power / dBm'] == '-2.2'
    assert rows['Channels 2 / tx power / dBm'] == '-3.0'


def test_optical_alarms_are_states_not_enable_settings():
    rows = dict(ethtool.transceiver_rows({'module_temperature_high_alarm': False,
                                        'rx_los': [False, True]}))
    assert rows['Module temperature high alarm'] == 'No'
    assert rows['Rx los'] == 'Lane 1: No\nLane 2: Yes'
