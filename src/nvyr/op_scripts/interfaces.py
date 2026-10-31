#!/usr/bin/env python3
"""Interface display commands backed by kernel interface data."""

import json
import re
import textwrap

from tabulate import tabulate
from nvyr import opmode
from nvyr.helpers import ethtool
from nvyr.helpers.process import cmd
from nvyr.helpers.output import detailed_output
from nvyr.helpers.interfaces import exists, visible_link
from nvyr.helpers.strip_private import strip_ip, strip_mac, strip_value
from nvyr.errors import OperationalError


INTF_TYPES = {
    'ethernet': 'eth',
    'dummy': 'dum'
}


def _get_kernel_data(raw, ifname = None, intf_type = None, detail = False,
                     statistics = False, strip_private = False):
    address_show_cmd = ['ip', '-j', '-d', '-s', 'address', 'show']

    if ifname:
        # Check if the interface exists
        if not exists(ifname):
            raise OperationalError(f"{ifname} does not exist!")

        # Formatted output needs the bridge metadata even for a single port.
        # Raw queries retain their native scoped response.
        if raw:
            address_show_cmd += ['dev', ifname]

    kernel_interface = json.loads(cmd(address_show_cmd))

    if strip_private:
        kernel_interface = _mask_kernel_data(kernel_interface, strip_private)

    # Return early if raw
    if raw:
        return kernel_interface, None

    # Format the kernel data
    kernel_interface_out = _format_kernel_data(kernel_interface, intf_type, detail, statistics, ifname)

    if ifname and not detail:
        kernel_interface = [interface for interface in kernel_interface if interface.get('ifname') == ifname]

    return kernel_interface, kernel_interface_out


def _mask_kernel_data(value, mode='all', field=None):
    """Mask a copy before either raw output or table layout is constructed."""
    if isinstance(value, dict):
        return {key: _mask_kernel_data(item, mode, key) for key, item in value.items()}

    if isinstance(value, list):
        return [_mask_kernel_data(item, mode, field) for item in value]

    if isinstance(value, str):
        if field == 'ifalias':
            return strip_value(value, mode)

        masked = strip_ip(value, mode)
        if masked != value:
            return masked

        # Address and broadcast fields can hold either an IP or a link address.
        if field in {'address', 'broadcast', 'permaddr'} and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5,}[0-9a-fA-F]{2}', value):
            return strip_mac(value, mode)

    return value


def _interface_vrf(interface, by_name):
    """Display container ports in the routing domain of their bridge."""
    info = interface.get('linkinfo', {})
    if info.get('info_slave_kind') == 'vrf':
        return interface['master']

    if interface.get('ifname', '').startswith('pd') and info.get('info_kind') == 'veth':
        bridge = by_name.get(interface.get('master'), {})
        bridge_info = bridge.get('linkinfo', {})
        if bridge_info.get('info_kind') == 'bridge' and bridge_info.get('info_slave_kind') == 'vrf':
            return bridge['master']

    return 'default'


def _format_kernel_data(data, intf_type, detail, statistics, ifname=None):
    output_list = []
    tmpInfo = {}
    by_name = {interface['ifname']: interface for interface in data}

    # Sort interfaces by name
    for interface in sorted(data, key=lambda x: x.get('ifname', '')):
        interface_name = interface.get('ifname', '')

        if ifname and interface_name != ifname:
            continue

        # Use the same link-type/kind filtering as interface completion.
        if not visible_link(interface):
            continue
        elif intf_type and not interface_name.startswith(INTF_TYPES[intf_type]):
            continue

        # Detailed kernel link data distinguishes VRF membership from bridge/bond masters.
        vrf = _interface_vrf(interface, by_name)

        # Get the device model; ex. Intel Corporation Ethernet Controller I225-V
        dev_model = interface.get('parentdev', '')

        if detail and 'parentdev' in interface:
            parentdev = interface['parentdev']
            if re.match(r'^[0-9a-fA-F]{4}:', parentdev):
                dev_model = cmd(['lspci', '-nn', '-s', parentdev]).split(']:')[1].strip()

        # Get the IP addresses on interface
        ip_list = []
        has_global = False

        for ip in interface['addr_info']:
            if ip.get('scope') in ('global', 'host'):
                has_global = True
                local = ip.get('local', '-')
                prefixlen = ip.get('prefixlen', '')
                ip_list.append(f"{local}/{prefixlen}")

        # If no global IP address, add '-'; indicates no IP address on interface
        if not has_global:
            ip_list.append('-')

        rx_stats = interface.get('stats64', {}).get('rx', {})
        tx_stats = interface.get('stats64', {}).get('tx', {})

        sl_status = ('A' if not 'UP' in interface['flags'] else 'u') + '/' + ('D' if interface['operstate'] == 'DOWN' else 'u')

        # Generate temporary dict to hold data
        tmpInfo['ifname'] = interface_name
        tmpInfo['ip'] = ip_list
        tmpInfo['mac'] = interface.get('address', 'n/a') #if is_interface_has_mac(interface_name) else 'n/a'
        tmpInfo['mtu'] = interface.get('mtu', '')
        tmpInfo['vrf'] = vrf
        tmpInfo['status'] = sl_status
        tmpInfo['description'] = "\n".join(textwrap.wrap(interface.get('ifalias', ''), width=50))

        tmpInfo['device'] = dev_model
        tmpInfo['alternate_names'] = interface.get('altnames', '')
        tmpInfo['minimum_mtu'] = interface.get('min_mtu', '')
        tmpInfo['maximum_mtu'] = interface.get('max_mtu', '')

        tmpInfo['rx_packets'] = rx_stats.get('packets', "")
        tmpInfo['rx_bytes'] = rx_stats.get('bytes', "")
        tmpInfo['rx_errors'] = rx_stats.get('errors', "")
        tmpInfo['rx_dropped'] = rx_stats.get('dropped', "")
        tmpInfo['rx_over_errors'] = rx_stats.get('over_errors', '')
        tmpInfo['multicast'] = rx_stats.get('multicast', "")

        tmpInfo['tx_packets'] = tx_stats.get('packets', "")
        tmpInfo['tx_bytes'] = tx_stats.get('bytes', "")
        tmpInfo['tx_errors'] = tx_stats.get('errors', "")
        tmpInfo['tx_dropped'] = tx_stats.get('dropped', "")
        tmpInfo['tx_carrier_errors'] = tx_stats.get('carrier_errors', "")
        tmpInfo['tx_collisions'] = tx_stats.get('collisions', "")

        # Order the stats based on 'detail' or 'statistics'
        if detail:
            stat_keys = [
                "rx_packets", "rx_bytes", "rx_errors", "rx_dropped",
                "rx_over_errors", "multicast",
                "tx_packets", "tx_bytes", "tx_errors", "tx_dropped",
                "tx_carrier_errors", "tx_collisions",
            ]
        elif statistics:
            stat_keys = [
                "rx_packets", "rx_bytes", "tx_packets", "tx_bytes",
                "rx_dropped", "tx_dropped", "rx_errors", "tx_errors",
            ]
        else:
            stat_keys = []

        stat_list = [tmpInfo.get(k, "") for k in stat_keys]

        # Generate output list; detail adds more fields
        output_list.append([tmpInfo['ifname'],
                            *(['\n'.join(tmpInfo['ip'])] if not statistics else []),
                            *([tmpInfo['mac']] if not statistics else []),
                            *([tmpInfo['vrf']] if not statistics else []),
                            *([tmpInfo['mtu']] if not statistics else []),
                            *([tmpInfo['status']] if not statistics else []),
                            *([tmpInfo['description']] if not statistics else []),
                            *([tmpInfo['device']] if detail else []),
                            *(['\n'.join(tmpInfo['alternate_names'])] if detail else []),
                            *([tmpInfo['minimum_mtu']] if detail else []),
                            *([tmpInfo['maximum_mtu']] if detail else []),
                            *(stat_list if any([detail, statistics]) else [])])

    return output_list


def _link_reference(interface, data):
    """Resolve only local link indices; remote namespaces can reuse an index."""
    index = interface.get('link_index')
    if 'link_netnsid' in interface:
        return f'Index {index if index is not None else "unknown"} (another network namespace)'
    if interface.get('link'):
        return interface['link']
    for link in data:
        if index is not None and link.get('ifindex') == index:
            return link['ifname']
    if index is not None:
        return f'Index {index} (name unavailable)'
    return 'Unknown'


def _detail_fields(interface, data):
    """Add topology fields to every link and Ethernet fields to hardware ports."""
    info = interface.get('linkinfo', {})
    kind = info.get('info_kind')
    group = interface.get('group', 0)
    if group in (0, 'default'):
        group = 0
    elif re.fullmatch(r'-?\d+', str(group)):
        group = int(group) & 0xffffffff

    addresses = []
    for address in interface.get('addr_info', []):
        if address.get('family') == 'inet6' and address.get('scope') == 'link':
            addresses.append(f"{address['local']}/{address['prefixlen']}")
    fields = [('Link-group', group), ('IPv6 link-local', '\n'.join(addresses) or '—')]

    if kind == 'vlan':
        vlan = info.get('info_data', {})
        fields.extend([('Parent', _link_reference(interface, data)),
                       ('VLAN ID', vlan.get('id', 'Unknown')),
                       ('VLAN protocol', vlan.get('protocol', 'Unknown'))])
    elif kind == 'veth':
        fields.append(('Peer', _link_reference(interface, data)))

    if not kind and interface.get('link_type') == 'ether':
        fields.extend(ethtool.link_details(interface['ifname']))
    return fields


def _hardware_data(name, view):
    """Collect only the diagnostic category selected by the command."""
    if view == 'queues':
        return {'channels': ethtool.channels(name), 'rings': ethtool.json_data(name, 'rings')}
    if view == 'hardware-statistics':
        return ethtool.hardware_statistics(name)
    return ethtool.json_data(name, view)


def _hardware_output(name, view, data):
    """Render the focused views without replacing unknown fields with zero."""
    print(f'{name} {view}\n')
    if data is None:
        print('Not supported or no data available.\n')
        return

    if view == 'offload':
        rows = []
        for feature, settings in data.items():
            if isinstance(settings, dict) and 'active' in settings:
                active = settings['active']
                enabled = 'Unknown' if active is None else ('Yes' if active else 'No')
                rows.append([feature, enabled])
        print(tabulate(rows, headers=['Feature', 'Enabled']) if rows else 'No offload features reported.')
    elif view == 'queues':
        channels = data['channels']
        print(tabulate(channels, headers=['Channels', 'Current', 'Maximum'])
              if channels is not None else 'Channel information is not supported.')
        print()
        rings = data['rings']
        if rings is None:
            print('Ring information is not supported.')
        else:
            rows = []
            for key in ('rx', 'rx-mini', 'rx-jumbo', 'tx'):
                if key in rings or f'{key}-max' in rings:
                    rows.append([key.upper(), rings.get(key, 'Unknown'), rings.get(f'{key}-max', 'Unknown')])
            print(tabulate(rows, headers=['Ring', 'Current', 'Maximum']))
    elif view == 'hardware-statistics':
        print(tabulate(data, headers=['Counter', 'Value'], disable_numparse=True, colalign=('left', 'right'))
              if data else 'No hardware statistics reported.')
    elif view == 'transceiver':
        rows = ethtool.transceiver_rows(data)
        if rows:
            detailed_output([[value for _, value in rows]], [label for label, _ in rows])
        else:
            print('No transceiver data reported.')
    print()


@opmode.command
def hardware(view: str, intf_name: str | None = None, intf_type: str | None = None,
             raw: bool = False, strip_private: str | None = None):
    """Read hardware diagnostics for a selected interface or all Ethernet ports."""
    if view not in {'offload', 'queues', 'hardware-statistics', 'transceiver'}:
        raise OperationalError('Unknown interface diagnostic view.')
    if intf_name and not exists(intf_name):
        raise OperationalError(f'{intf_name} does not exist!')

    links = json.loads(cmd(['ip', '-j', '-d', 'link', 'show']))
    selected = []
    for link in links:
        if intf_name:
            if link['ifname'] == intf_name:
                selected.append(link)
        elif link.get('link_type') == 'ether' and not link.get('linkinfo', {}).get('info_kind'):
            if not intf_type or link['ifname'].startswith(INTF_TYPES[intf_type]):
                selected.append(link)
    if not selected:
        raise OperationalError('No matching interfaces found.')

    records = {}
    for interface in sorted(selected, key=lambda item: item['ifname']):
        name = interface['ifname']
        data = _hardware_data(name, view)
        if strip_private and view == 'transceiver' and data is not None:
            data = _mask_transceiver(data, strip_private)
        records[name] = data
        if not raw:
            _hardware_output(name, view, data)
    if raw:
        return json.dumps(records)


def _mask_transceiver(value, mode='all'):
    """Hide module serial identifiers in shared diagnostic reports."""
    if isinstance(value, list):
        return [_mask_transceiver(item, mode) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if 'serial' in key.lower() or key.lower() == 'vendor_sn':
                result[key] = strip_value(str(item), mode)
            else:
                result[key] = _mask_transceiver(item, mode)
        return result
    return value


@opmode.command
def show(raw: bool = False, intf_name: str | None = None, intf_type: str | None = None, detail: bool = False, statistics: bool = False, strip_private: str | None = None):
    raw_data, data = _get_kernel_data(raw, intf_name, intf_type, detail, statistics, strip_private)

    # Return early if raw
    if raw:
        return json.dumps(raw_data)
    elif detail:
        detail_header = ['Interface', 'IP Address', 'MAC', 'VRF', 'MTU', 'S/L', 'Description',
                        'Device', 'Alternate Names','Minimum MTU', 'Maximum MTU', 'RX Packets', 'RX Bytes',
                        'RX Errors', 'RX Dropped', 'Receive Overrun Errors', 'Received Multicast', 'TX Packets', 'TX Bytes',
                        'TX Errors', 'TX Dropped', 'Transmit Carrier Errors', 'Transmit Collisions']        
        by_name = {interface['ifname']: interface for interface in raw_data}
        for row in data:
            extra = _detail_fields(by_name[row[0]], raw_data)
            headers = detail_header[:7] + [label for label, _ in extra] + detail_header[7:]
            values = row[:7] + [value for _, value in extra] + row[7:]
            detailed_output([values], headers)
    elif statistics:
        statistics_header = ['Interface', 'Rx Packets', 'Rx Bytes', 'Tx Packets', 'Tx Bytes', 'Rx Dropped', 'Tx Dropped', 'Rx Errors', 'Tx Errors']
        print(tabulate(data, headers=statistics_header))
    else:        
        headers = ['Interface', 'IP Address', 'MAC', 'VRF', 'MTU', 'S/L', 'Description']
        print('Codes: S - State, L - Link, u - Up, D - Down, A - Admin Down')    
        print(tabulate(data, headers=headers))


if __name__ == '__main__':
    opmode.run()
