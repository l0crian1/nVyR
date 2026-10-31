"""Exercise boot protection in a disposable namespace, never on the router's links."""

from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

from nvyr.config_scripts import firewall, firewall_failsafe
from nvyr.helpers import nftables
from nvyr.helpers.dependencies import Dependencies
from nvyr.helpers.process import cmd
from nvyr.modules import CommitContext
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree
from smoketests.assertions import assert_equal, assert_false, assert_in, assert_not_equal, assert_true


def commit_context(configuration, directory, *, previous=None, startup=False, owner='firewall_failsafe'):
    """Supply the production scripts with the same schema and ownership snapshots as configd."""
    schema = Schema.bundled()
    schema.validate_configuration(configuration)
    effective = schema.defaults(configuration)
    previous = previous or {}
    previous_effective = schema.defaults(previous)
    current = schema.ownership.snapshot(effective)
    prior = schema.ownership.snapshot(previous_effective)
    root = schema.owners[owner][0]
    return CommitContext(
        ReadOnlyTree(effective), ReadOnlyTree(previous), owner, root, startup,
        previous_effective=ReadOnlyTree(previous_effective), startup=startup,
        state_directory=directory, dependencies=Dependencies(schema),
        sections=ReadOnlyTree(current.sections.get(owner, {})),
        previous_sections=ReadOnlyTree(prior.sections.get(owner, {})))


def load_failsafe(context):
    """Run the real verification, shared renderer and apply path."""
    configuration = firewall_failsafe.get_config(context)
    firewall_failsafe.verify(configuration, context)
    rendered = firewall_failsafe.generate(configuration, context)
    firewall_failsafe.apply(rendered, context)


def packet_received(family, port):
    """Send one local UDP datagram through OUTPUT and INPUT in the isolated network."""
    address = '127.0.0.1' if family == 'ipv4' else '::1'
    socket_family = socket.AF_INET if family == 'ipv4' else socket.AF_INET6
    with socket.socket(socket_family, socket.SOCK_DGRAM) as receiver:
        receiver.bind((address, port))
        receiver.settimeout(0.2)
        with socket.socket(socket_family, socket.SOCK_DGRAM) as sender:
            sender.sendto(b'failsafe', (address, port))
        try:
            return receiver.recv(64) == b'failsafe'
        except socket.timeout:
            return False


def table_snapshot():
    """Retain handles and counters when proving a rejected load changed nothing."""
    output = cmd(['nft', '-j', '-a', 'list', 'table', 'inet', firewall_failsafe.TABLE])
    return json.loads(output)['nftables'][1:]


def exercise(family, scenario, directory):
    """Check one independently named scenario using a fresh isolated ruleset."""
    address = '127.0.0.1' if family == 'ipv4' else '::1'
    configuration = {'firewall': {'fail-safe': {family: {
        'input': {'filter': {'default-action': 'drop', 'rule': {
            '10': {'action': 'accept', 'inbound-interface': ['future0']},
            '20': {'action': 'jump', 'jump-target': 'FIRST',
                   'protocol': ['udp'], 'destination-port': ['44445'],
                   'source-address-group': 'LOCAL'},
            '30': {'map': 'PORTS'},
        }}},
        'name': {
            'FIRST': {'rule': {'10': {'action': 'jump', 'jump-target': 'SECOND'}}},
            'SECOND': {'rule': {'10': {'action': 'accept'}}},
        },
    }, 'group': {
        'address-group': {family: {'LOCAL': {'address': [address]}}},
        'map': {family: {'PORTS': {
            'match': {'protocol': True, 'destination-port': True},
            'result-type': 'verdict',
            'entry': {'allowed': {'protocol': 'udp', 'destination-port': '44447',
                                  'result': {'action': 'jump', 'jump-target': 'FIRST'}}},
        }}},
    }}}}
    context = commit_context(configuration, directory, startup=True)
    load_failsafe(context)
    assert_true(nftables.manager.table_exists(firewall_failsafe.TABLE))

    # The configured interface is deliberately absent when the firewall loads.
    cmd(['ip', 'link', 'add', 'future0', 'type', 'dummy'])
    cmd(['ip', 'link', 'set', 'lo', 'up'])
    assert_true(packet_received(family, 44445), 'Nested jumps must allow the selected UDP port')
    assert_true(packet_received(family, 44447), 'The verdict map must resolve its local jump target')
    assert_false(packet_received(family, 44446), 'The fail-safe default must drop other traffic')

    if scenario == 'replace':
        # Replace the full table, including chains referenced by other chains.
        changed = deepcopy(configuration)
        changed['firewall']['fail-safe'][family]['name']['SECOND']['rule']['10']['action'] = 'drop'
        current = commit_context(changed, directory, previous=configuration)
        load_failsafe(current)
        assert_false(packet_received(family, 44445))
        assert_false(packet_received(family, 44447))
        return

    if scenario == 'delete':
        # Removing an active fail-safe removes its whole table.
        load_failsafe(commit_context({}, directory, previous=configuration))
        assert_false(nftables.manager.table_exists(firewall_failsafe.TABLE))
        assert_true(packet_received(family, 44446))
        return

    # A successful main load removes boot protection in the same transaction.
    configuration['firewall'][family] = {'input': {'filter': {'default-action': 'accept'}}}
    main_context = commit_context(configuration, directory, owner='firewall', startup=True)
    main = firewall.get_config(main_context)
    firewall.verify(main, main_context)
    rendered = firewall.generate(main, main_context)
    assert_in('destroy table inet nvyr_filter_failsafe', rendered)

    if scenario == 'failure':
        # Submit a genuinely invalid native batch, bypassing the preflight check.
        before = table_snapshot()
        invalid = rendered + '\nadd rule inet nvyr_filter input jump DOES_NOT_EXIST\n'
        result = subprocess.run(['nft', '-f', '-'], input=invalid, text=True, capture_output=True)
        assert_not_equal(result.returncode, 0, result.stdout + result.stderr)
        assert_equal(table_snapshot(), before)
        assert_false(packet_received(family, 44446))
        return

    firewall.apply(rendered, main_context)
    assert_false(nftables.manager.table_exists(firewall_failsafe.TABLE))
    assert_true(packet_received(family, 44446))

    # Edits and rollback after handover validate without reactivating the table.
    inactive = replace(context, startup=False, recovery=False)
    load_failsafe(inactive)
    load_failsafe(replace(inactive, recovery=True))
    assert_false(nftables.manager.table_exists(firewall_failsafe.TABLE))
    assert_true(packet_received(family, 44446))


if __name__ == '__main__':
    # Refuse accidental direct execution in the router's main network namespace.
    assert_not_equal(os.readlink('/proc/self/ns/net'), os.readlink('/proc/1/ns/net'))
    family, scenario = sys.argv[1:]
    assert_in(family, ('ipv4', 'ipv6'))
    assert_in(scenario, ('handover', 'replace', 'failure', 'delete'))
    with tempfile.TemporaryDirectory(prefix='nvyr-failsafe-test-') as temporary:
        exercise(family, scenario, Path(temporary))
