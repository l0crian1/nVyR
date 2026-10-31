"""Read-only Ethernet diagnostics using ethtool JSON and Linux ioctl records.

The packaged ethtool supplies Netlink JSON and decodes transceiver EEPROMs.
Driver information, channels and driver-defined statistics have no JSON command
in ethtool 6.14, so read their documented Linux UAPI records directly.
"""

import ctypes
import errno
import json
import re
import socket
import struct

from nvyr.errors import OperationalError
from nvyr.helpers.process import cli_cmd


JSON_OPTIONS = {
    'link': (),
    'offload': ('--show-features',),
    'rings': ('--show-ring',),
    'pause': ('--show-pause',),
    'eee': ('--show-eee',),
    'fec': ('--show-fec',),
    'transceiver': ('--dump-module-eeprom',),
}
UNAVAILABLE_ERRORS = {errno.EOPNOTSUPP, errno.ENODATA}


def _validate_name(name):
    """Keep device names within Linux limits, including direct script calls."""
    if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_.:-]{0,14}', name):
        raise OperationalError('Invalid interface name.')


def json_data(name, operation, *, warnings=None):
    """Return one device record; optionally retain partial data with diagnostics.

    Aggregate detail views supply a warning list so one unavailable diagnostic
    does not hide the remaining information. Focused queries remain strict.
    """
    _validate_name(name)
    result = cli_cmd(['ethtool', '--json', *JSON_OPTIONS[operation], name],
                     env={'LC_ALL': 'C', 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})

    diagnostics = [line.strip() for line in result.stderr.splitlines() if line.strip()]
    unsupported = diagnostics and all(
        line in {'netlink error: Operation not supported', 'netlink error: No data available'}
        for line in diagnostics
    )
    if (result.returncode or diagnostics) and not unsupported:
        message = '; '.join(dict.fromkeys(diagnostics)) or f'exit status {result.returncode}'
        if warnings is None:
            raise OperationalError(f'{name}: ethtool {operation}: {message}')
        warnings.append(message)

    if not result.stdout.strip() and (unsupported or warnings):
        return None

    try:
        records = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise OperationalError(f'{name}: invalid ethtool {operation} JSON') from error

    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise OperationalError(f'{name}: unexpected ethtool {operation} response')
    records = [item for item in records if item]
    if not records:
        return None
    if len(records) != 1 or records[0].get('ifname', name) != name:
        raise OperationalError(f'{name}: unexpected ethtool {operation} device')

    return records[0]


def _ioctl(name, payload):
    """Use SIOCETHTOOL with a mutable buffer and a correctly sized ifreq."""
    import fcntl

    _validate_name(name)
    buffer = ctypes.create_string_buffer(bytes(payload), len(payload))
    request = struct.pack('@16sP', name.encode('ascii'), ctypes.addressof(buffer))
    # Linux ifreq's union includes ifmap (24 bytes on 64-bit, 16 on 32-bit).
    request = request.ljust(40 if struct.calcsize('P') == 8 else 32, b'\0')

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as descriptor:
            fcntl.ioctl(descriptor.fileno(), 0x8946, request)
    except OSError as error:
        if error.errno in UNAVAILABLE_ERRORS:
            return None
        raise OperationalError(f'{name}: Ethernet diagnostics: {error.strerror}') from error

    return buffer.raw


def driver_info(name):
    """Decode struct ethtool_drvinfo (ETHTOOL_GDRVINFO)."""
    payload = bytearray(196)
    struct.pack_into('=I', payload, 0, 0x00000003)
    data = _ioctl(name, payload)
    if data is None:
        return None

    result = {}
    for field, offset in (('Driver', 4), ('Driver version', 36),
                          ('Firmware version', 68), ('Bus address', 100)):
        result[field] = data[offset:offset + 32].split(b'\0', 1)[0].decode('utf-8', errors='replace')
    return result


def channels(name):
    """Decode struct ethtool_channels (ETHTOOL_GCHANNELS)."""
    data = _ioctl(name, struct.pack('=9I', 0x0000003c, *([0] * 8)))
    if data is None:
        return None

    values = struct.unpack('=9I', data)
    return [[label, values[index + 5], values[index + 1]]
            for index, label in enumerate(('RX', 'TX', 'Other', 'Combined'))]


def hardware_statistics(name):
    """Pair driver-provided statistic names with their unsigned 64-bit values."""
    # ETH_SS_STATS is string set 1. GSSET_INFO provides its allocation size.
    info = _ioctl(name, struct.pack('=IIQI', 0x00000037, 0, 1 << 1, 0))
    if info is None or not struct.unpack_from('=Q', info, 8)[0] & (1 << 1):
        return None
    count = struct.unpack_from('=I', info, 16)[0]
    if not count:
        return []
    if count > 65536:
        raise OperationalError(f'{name}: unexpected hardware statistic count {count}')

    names = _ioctl(name, struct.pack('=III', 0x0000001b, 1, count) + bytes(count * 32))
    counters = _ioctl(name, struct.pack('=II', 0x0000001d, count) + bytes(count * 8))
    if names is None or counters is None:
        return None
    if struct.unpack_from('=I', names, 8)[0] != count or struct.unpack_from('=I', counters, 4)[0] != count:
        raise OperationalError(f'{name}: hardware statistics changed during query; retry the command')

    rows = []
    for index in range(count):
        offset = 12 + index * 32
        label = names[offset:offset + 32].split(b'\0', 1)[0].decode('utf-8', errors='replace')
        value = struct.unpack_from('=Q', counters, 8 + index * 8)[0]
        rows.append([label, value])
    return rows


def value_text(value):
    """Preserve unavailable values and units supplied by ethtool."""
    if value is None or value == '':
        return 'Unknown'
    if isinstance(value, bool):
        return 'Enabled' if value else 'Disabled'
    if isinstance(value, list):
        return '\n'.join(value_text(item) for item in value) or 'Not reported'
    return str(value)


def _detail_unavailable(rows):
    """Summarize incomplete diagnostics once without guessing their cause."""
    note = ('Ethernet diagnostics', 'Currently unavailable')
    if note not in rows:
        rows.append(note)


def _detail_value(value):
    """Leave absent detail values blank while retaining reported false/zero."""
    return '' if value is None or value == '' else value_text(value)


def _detail_json(name, operation, rows):
    """Keep partial data and one availability note in the aggregate view."""
    warnings = []
    try:
        data = json_data(name, operation, warnings=warnings)
    except OperationalError as error:
        warnings.append(str(error))
        data = None

    if warnings:
        _detail_unavailable(rows)
    elif data is None and operation == 'link':
        rows.append(('Ethernet link settings', 'Not supported'))
    return data


def link_details(name):
    """Collect the useful link fields without including large diagnostic lists."""
    rows = []
    link = _detail_json(name, 'link', rows)
    if link is not None:
        speed = link.get('speed')
        if isinstance(speed, int) and 0 < speed < 0xffffffff:
            speed = f'{speed / 1000:g} Gbit/s' if speed >= 1000 else f'{speed} Mbit/s'
        else:
            speed = ''
        rows.extend([('Speed', speed), ('Duplex', _detail_value(link.get('duplex')))])
        for label, field in (
            ('Autonegotiation', 'auto-negotiation'),
            ('Supported link modes', 'supported-link-modes'),
            ('Advertised link modes', 'advertised-link-modes'),
            ('Partner advertised link modes', 'link-partner-advertised-link-modes'),
            ('Port medium', 'port'), ('Link diagnosis', 'link-state'),
        ):
            if field in link:
                rows.append((label, _detail_value(link[field])))

    pause = _detail_json(name, 'pause', rows)
    if pause is not None:
        for label, key in (('RX pause', 'rx'), ('TX pause', 'tx'), ('Pause autonegotiation', 'autonegotiate')):
            rows.append((label, _detail_value(pause.get(key))))
        for direction, value in pause.get('negotiated', {}).items():
            rows.append((f'{direction.upper()} pause negotiated', _detail_value(value)))

    fec = _detail_json(name, 'fec', rows)
    if fec is not None:
        rows.extend([('FEC configured', _detail_value(fec.get('config'))),
                     ('FEC active', _detail_value(fec.get('active')))])

    eee = _detail_json(name, 'eee', rows)
    if eee is not None:
        status = eee.get('status')
        if status in {'active', 'inactive'}:
            status = f'Enabled ({status})'
        rows.append(('Energy Efficient Ethernet', _detail_value(status)))

    try:
        driver = driver_info(name)
    except OperationalError:
        _detail_unavailable(rows)
        driver = None
    if driver is not None:
        rows.extend((label, _detail_value(value)) for label, value in driver.items())
    return rows


def transceiver_rows(data, prefix=''):
    """Keep module-specific measurements, units and lane identities intact."""
    rows = []
    for key, value in data.items():
        if key == 'ifname':
            continue
        label = key.replace('_', ' ').replace('-', ' ')
        label = f'{prefix} / {label}' if prefix else label[:1].upper() + label[1:]
        if isinstance(value, dict):
            rows.extend(transceiver_rows(value, label))
        elif isinstance(value, list) and any(isinstance(item, dict) for item in value):
            for index, item in enumerate(value, 1):
                if isinstance(item, dict):
                    rows.extend(transceiver_rows(item, f'{label} {index}'))
                else:
                    rows.append((f'{label} {index}', value_text(item)))
        else:
            rendered = value_text(value)
            if isinstance(value, bool):
                rendered = 'Yes' if value else 'No'
            elif isinstance(value, list) and all(isinstance(item, bool) for item in value):
                rendered = '\n'.join(f'Lane {index}: {"Yes" if item else "No"}'
                                     for index, item in enumerate(value, 1)) or 'Not reported'
            # ethtool JSON omits these units; the EEPROM decoder has already
            # converted the measurements to Celsius, volts, mA and nanometres.
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if key.startswith('module_temperature'):
                    rendered += ' °C'
                elif key.startswith('module_voltage'):
                    rendered += ' V'
                elif key.startswith('laser_bias_current'):
                    rendered += ' mA'
                elif key in {'laser_wavelength', 'laser_wavelength_tolerance'}:
                    rendered += ' nm'
            rows.append((label, rendered))
    return rows
