"""Package inventory, exact selection and described operational completions."""

import json

import pytest

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import packages, suggestors
from nvyr.op_scripts import system


@pytest.fixture
def inventory(monkeypatch):
    def query(arguments, **options):
        assert arguments == ['dpkg-query', '-W',
                             '-f=${binary:Package}\t${Version}\t${Architecture}\t${binary:Summary}\n']
        assert options['env']['LC_ALL'] == 'C'
        assert options['timeout'] == 5
        return ('libc6:amd64\t2.41-12\tamd64\tGNU C Library\n'
                'frr\t10.40\tamd64\tFRRouting suite\n'
                'frr-pythontools\t10.40\tall\tFRRouting tools\n')

    monkeypatch.setattr(packages, 'cmd', query)


def test_inventory_and_table_preserve_versions(inventory):
    records = packages.inventory()
    assert [record['package'] for record in records] == ['frr', 'frr-pythontools', 'libc6:amd64']
    assert records[0]['version'] == '10.40'
    assert json.loads(system.packages(raw=True)) == records

    output = system.packages()
    for text in ('Package', 'Version', 'Architecture', 'Description', '10.40', 'FRRouting suite'):
        assert text in output
    assert '|' not in output


def test_exact_selection_and_architecture(inventory):
    assert 'frr-pythontools' not in system.packages('frr')
    assert json.loads(system.packages('libc6:amd64', raw=True))[0]['package'] == 'libc6:amd64'
    with pytest.raises(OperationalError, match='was not found'):
        system.packages('frr*')


def test_described_completion(controller, session, inventory):
    for command, scope in [('show system packages ', None),
                           ('run show system packages ', session)]:
        candidates = dict(controller.completion(command, scope, explicit=True)['candidates'])
        assert candidates['frr'] == 'FRRouting suite'
        assert candidates['libc6:amd64'] == 'GNU C Library'


def test_empty_inventory(monkeypatch):
    monkeypatch.setattr(packages, 'cmd', lambda *args, **kwargs: '')
    assert system.packages() == 'No packages found.\n'
    assert json.loads(system.packages(raw=True)) == []
    assert suggestors.installed_packages(None) == []


def test_backend_failure_is_visible_but_does_not_break_completion(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise OperationalError('Package database unavailable')

    monkeypatch.setattr(packages, 'cmd', fail)
    assert suggestors.installed_packages(None) == []
    with pytest.raises(SystemExit) as result:
        opmode.run(['packages'], namespace=vars(system))

    assert result.value.code == 1
    assert capsys.readouterr().err == 'Package database unavailable\n'


def test_malformed_inventory_is_not_reported_as_success(monkeypatch):
    monkeypatch.setattr(packages, 'cmd', lambda *args, **kwargs: 'broken row\n')
    with pytest.raises(OperationalError, match='Invalid package inventory'):
        system.packages()
