"""Linux bond attributes and member reconciliation on netlinkd's existing socket."""

from pyroute2.netlink import NLM_F_ACK, NLM_F_REQUEST
from pyroute2.netlink.rtnl import RTM_NEWLINK
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg
from pyroute2.netlink.rtnl.ifinfmsg.plugins.bond import bond

from nvyr.errors import ValidationError
from nvyr.helpers.bond_config import FIELDS, MODES, PROBE_MODES


class BondMessage(ifinfmsg):
    """Decode the shipping kernel's bond UAPI beyond Debian pyroute2's older map."""

    class ifinfo(ifinfmsg.ifinfo):
        class bond_data(bond):
            nla_map = bond.nla_map[:26] + (
                ('IFLA_BOND_AD_ACTOR_SYSTEM', 'l2addr'), ('IFLA_BOND_TLB_DYNAMIC_LB', 'uint8'),
                ('IFLA_BOND_PEER_NOTIF_DELAY', 'uint32'), ('IFLA_BOND_AD_LACP_ACTIVE', 'uint8'),
                ('IFLA_BOND_MISSED_MAX', 'uint8'), ('IFLA_BOND_NS_IP6_TARGET', '*ipaddr'),
                ('IFLA_BOND_COUPLED_CONTROL', 'uint8'), ('IFLA_BOND_BROADCAST_NEIGH', 'uint8'),
                ('IFLA_BOND_LACP_STRICT', 'uint8'),
            )

        data_map = dict(ifinfmsg.ifinfo.data_map, bond=bond_data)

        class bond_slave_data(ifinfmsg.ifinfo.bond_slave_data):
            nla_map = ifinfmsg.ifinfo.bond_slave_data.nla_map[:7] + (
                ('IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE', 'uint8'),
                ('IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE', 'uint16'),
                ('IFLA_BOND_SLAVE_PRIO', 'int32'), ('IFLA_BOND_SLAVE_ACTOR_PORT_PRIO', 'uint16'),
            )


# pyroute2 caches compiled attribute tables on each class. Compile our subclasses
# explicitly, otherwise they inherit a parent's already-compiled (older) table.
for codec in (BondMessage.ifinfo.bond_data, BondMessage.ifinfo.bond_slave_data, BondMessage.ifinfo, BondMessage):
    codec().compile_nla()


def attributes(device, member=False):
    original = device['message']
    message = BondMessage(data=original.data, offset=original.offset)
    message.decode()
    info = message.get_attr('IFLA_LINKINFO')
    data = info.get_attr('IFLA_INFO_SLAVE_DATA' if member else 'IFLA_INFO_DATA')
    prefix = 'IFLA_BOND_SLAVE_' if member else 'IFLA_BOND_'
    return {key.removeprefix(prefix): value for key, value in data['attrs'] if key.startswith(prefix)}


def write(kernel, name, changes, *, member=False):
    if not changes:
        return
    message = BondMessage()
    message['index'] = kernel.device(name)['index']
    prefix = 'IFLA_BOND_SLAVE_' if member else 'IFLA_BOND_'
    section = 'IFLA_INFO_SLAVE_' if member else 'IFLA_INFO_'
    options = [(prefix + key, value) for key, value in changes.items()]
    message['attrs'] = [('IFLA_LINKINFO', {'attrs': [(section + 'KIND', 'bond'),
                                                    (section + 'DATA', {'attrs': options})]})]
    try:
        tuple(kernel.ipr.nlm_request(message, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK))
    finally:
        kernel.refresh(name)


def defaults(device):
    data = attributes(device)
    result = {key: data[key] for key, _ in FIELDS.values() if key in data}
    # These attributes are reported only after entering LACP mode; an absent target list is empty.
    return {'AD_ACTOR_SYS_PRIO': 65535, 'AD_ACTOR_SYSTEM': '00:00:00:00:00:00',
            'AD_USER_PORT_KEY': 0, 'ARP_IP_TARGET': [], 'NS_IP6_TARGET': [], **result}


def differences(current, desired):
    return {key: value for key, value in desired.items()
            if current.get(key, [] if key in ('NS_IP6_TARGET', 'ARP_IP_TARGET') else 0) != value}


def detach(kernel, port):
    device = kernel.device(port)
    kernel.ipr.link('set', index=device['index'], master=0)
    kernel.refresh(port)
    kernel.state(port, device['up'])


def reconcile(kernel, name, intent, baseline):
    current = attributes(kernel.device(name))
    desired = baseline | intent['options']
    mode = MODES[desired['MODE']]
    # Setting LACP/TLB/ALB mode enables Linux's 100 ms monitor if no monitor was configured.
    if mode not in PROBE_MODES and 'MIIMON' not in intent['options'] and not baseline['MIIMON']:
        desired['MIIMON'] = 100
    if desired['ARP_INTERVAL']:
        desired['MIIMON'] = 0
    changes = differences(current, desired)
    master = kernel.device(name)['index']
    ports = intent['members']
    attached = [link.get_attr('IFLA_IFNAME') for link in kernel.ipr.get_links(master=master)
                if link.get_attr('IFLA_MASTER') == master]

    changing_mode = 'MODE' in changes
    for port in attached:
        if changing_mode or 'FAIL_OVER_MAC' in changes or port not in ports:
            detach(kernel, port)
    if changing_mode:
        kernel.state(name, False)
        write(kernel, name, {'MODE': desired['MODE']})
        current = attributes(kernel.device(name))
        changes = differences(current, desired)

    # Only send attributes implemented by the selected kernel mode.
    if mode != '802.3ad':
        for key in ('AD_ACTOR_SYS_PRIO', 'AD_ACTOR_SYSTEM', 'AD_USER_PORT_KEY', 'AD_LACP_ACTIVE',
                    'AD_LACP_RATE', 'COUPLED_CONTROL', 'LACP_STRICT', 'BROADCAST_NEIGH'):
            changes.pop(key, None)
    if mode not in PROBE_MODES:
        for key in ('ARP_INTERVAL', 'ARP_VALIDATE', 'MISSED_MAX'):
            changes.pop(key, None)
    if mode != 'balance-rr':
        changes.pop('PACKETS_PER_SLAVE', None)
    if mode not in ('balance-tlb', 'balance-alb'):
        changes.pop('TLB_DYNAMIC_LB', None)
    if changes.keys() & {'AD_LACP_ACTIVE', 'AD_LACP_RATE', 'AD_SELECT', 'TLB_DYNAMIC_LB',
                         'AD_USER_PORT_KEY', 'COUPLED_CONTROL'}:
        kernel.state(name, False)

    # The kernel needs a positive MII interval when setting or clearing delay ticks.
    if not desired['MIIMON']:
        delays = {key: changes.pop(key) for key in ('UPDELAY', 'DOWNDELAY', 'PEER_NOTIF_DELAY') if key in changes}
        write(kernel, name, delays)
    write(kernel, name, changes)

    # Release nonzero queue assignments first so two ports can swap IDs in one commit.
    for port in ports.keys() & set(attached):
        device = kernel.device(port)
        if device and device['attributes']['vrf'] == master:
            queue = attributes(device, member=True).get('QUEUE_ID', 0)
            if queue and queue != ports[port]['QUEUE_ID']:
                write(kernel, port, {'QUEUE_ID': 0}, member=True)
    for port, policy in ports.items():
        device = kernel.device(port)
        owner = device['attributes']['vrf']
        if owner != master:
            if owner:
                raise ValidationError(f'{port}: already attached to another master')
            was_up = device['up']
            kernel.state(port, False)
            try:
                kernel.ipr.link('set', index=device['index'], master=master)
            finally:
                kernel.refresh(port)
                kernel.state(port, was_up)
        actual = attributes(kernel.device(port), member=True)
        wanted = dict(policy)
        if mode != '802.3ad':
            wanted.pop('ACTOR_PORT_PRIO')
        if mode not in ('active-backup', 'balance-tlb', 'balance-alb'):
            wanted.pop('PRIO')
        write(kernel, port, differences(actual, wanted), member=True)

    primary = intent['primary']
    preferred = kernel.device(primary)['index'] if primary else 0
    # Enslaving a device can revive a previous primary preference in the kernel.
    kernel.refresh(name)
    if mode in ('active-backup', 'balance-tlb', 'balance-alb') and attributes(kernel.device(name)).get('PRIMARY', 0) != preferred:
        write(kernel, name, {'PRIMARY': preferred})
