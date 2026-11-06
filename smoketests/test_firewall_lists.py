"""CLI list/CSV imports, column anchoring, native comments and timer generation.

Uses the ordinary shared firewall fixture. No packet/convergence checks or extra topology.
"""

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_firewall_object, assert_in
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_imported_groups_and_timer(config, tmp_path):
    source = tmp_path / 'addresses'
    source.write_text('192.0.2.10\n192.0.2.20\n')
    csv = tmp_path / 'flows.csv'
    csv.write_text('192.0.2.10,198.51.100.20,443,tcp,drop\n')

    config.set(f'set firewall group address-group ipv4 SMOKEFEED from-list A source {source}')
    config.set(f'set firewall group address-group ipv4 SMOKEFEED from-list B source {source}')
    config.set('set firewall group address-group ipv4 SMOKEFEED from-list A interval 1h')
    config.set('set firewall group map ipv4 SMOKEFEED match source-address destination-address destination-port protocol')
    config.set('set firewall group map ipv4 SMOKEFEED result-type verdict')
    config.set(f'set firewall group map ipv4 SMOKEFEED from-csv POLICY source {csv}')
    config.set('set firewall group map ipv4 SMOKEFEED from-csv POLICY column source-address 1 destination-address 2 destination-port 3 protocol 4 result action 5')
    config.commit()

    assert_firewall_object('set', 'ipv4_address_group_SMOKEFEED', '192.0.2.10', 'A, B')
    assert_firewall_object('map', 'ipv4_map_SMOKEFEED', '443', 'drop', 'POLICY')
    assert_in('nvyr-task-firewalllists-', cmd(['systemctl', 'list-timers', '--all', '--no-pager']))
