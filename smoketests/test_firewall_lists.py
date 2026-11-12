"""CLI list/CSV imports, column anchoring, native comments and timer generation.

Uses the ordinary shared firewall fixture. No packet/convergence checks or extra topology.
"""

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_firewall_object, assert_in
from smoketests.firewall_support import firewall_environment, firewall_suite


@pytest.fixture
def feed_directory():
    # configd has PrivateTmp; use a shared path for files it must import.
    with TemporaryDirectory(prefix='nvyr-smoke-feeds-', dir='/run') as directory:
        yield Path(directory)


def test_imported_groups_and_timer(config, feed_directory):
    """Imports install native membership, provenance and a scheduled refresh."""
    source = feed_directory / 'addresses'
    source.write_text('192.0.2.10\n192.0.2.20\n')
    csv = feed_directory / 'flows.csv'
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


def test_unavailable_initial_source_installs_empty_group(config, feed_directory):
    """An unavailable feed leaves a usable empty group without aborting the commit."""
    source = feed_directory / 'missing'
    config.set(f'set firewall group address-group ipv4 SMOKEEMPTY from-list SOURCE source {source}')
    config.set('set firewall ipv4 forward filter rule 10 source-address-group SMOKEEMPTY action drop')
    config.commit()

    output = cmd(['nft', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_SMOKEEMPTY'])
    assert 'elements =' not in output
    assert '@ipv4_address_group_SMOKEEMPTY' in cmd(['nft', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_forward'])


def test_csv_invalid_rows_keep_valid_entries(config, feed_directory):
    """Bad and ambiguous rows are omitted while unrelated valid rows are installed."""
    source = feed_directory / 'entries.csv'
    source.write_text('192.0.2.10,drop\ninvalid.example,accept\n192.0.2.20,drop\n192.0.2.20,accept\n')
    config.set('set firewall group map ipv4 SMOKECONFLICT match source-address')
    config.set('set firewall group map ipv4 SMOKECONFLICT result-type verdict')
    config.set(f'set firewall group map ipv4 SMOKECONFLICT from-csv SOURCE source {source}')
    config.set('set firewall group map ipv4 SMOKECONFLICT from-csv SOURCE column source-address 1 result action 2')
    config.commit()

    output = cmd(['nft', 'list', 'map', 'inet', 'nvyr_filter', 'ipv4_map_SMOKECONFLICT'])
    assert '192.0.2.10' in output
    assert '192.0.2.20' not in output
    assert 'invalid.example' not in output
