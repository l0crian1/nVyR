"""CLI translation to Unbound, removal and validation; no DNS packet tests.

All compatible settings share one module configuration. Conflicting transports,
disabled instances and removal deliberately change that configuration.
"""

from copy import deepcopy
import json

import pytest

from nvyr.helpers import dns_forwarding as dns
from nvyr.helpers.process import cmd
from smoketests.assertions import assert_config_commit_rejected
from smoketests.support import configuration_case, prepared_test


@pytest.fixture(scope='module')
def dns_suite(config, request):
    original = config.get_config()
    baseline = deepcopy(original)
    baseline.get('service', {}).pop('dns', None)

    def setup(session):
        session.load(baseline, replace=True)
        for command in (
            'listen-address 127.0.0.1', 'listen-address ::1', 'port 1053',
            'allow-from 127.0.0.0/8', 'allow-from ::1/128',
            'name-server 192.0.2.53 port 853 tls authentication-name dns.example.org',
            'domain home.example.org name-server 192.0.2.54',
            'domain home.example.org disable-cache',
            'cache message-size 4m', 'cache rrset-size 8m', 'cache maximum-ttl 600',
            'cache maximum-negative-ttl 30', 'cache prefetch', 'cache prefetch-dnssec',
            'cache serve-expired maximum-age 300 reply-ttl 10 client-timeout 100',
            'dnssec insecure-domain home.example.org', 'local-data static-host-mapping',
            'options threads 2', 'options hide-identity', 'options hide-version',
            'logging verbosity 2', 'logging servfail',
        ):
            session.set('set service dns forwarding ' + command)
        session.commit()

    def cleanup(session):
        session.discard()
        session.load(original, replace=True)
        session.commit()

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, setup, cleanup, stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def dns_case(config, request, dns_suite):
    with configuration_case(config, request, dns_suite):
        yield


def test_native_configuration():
    path = dns.ROOT / dns.instance_id('default') / 'unbound.conf'
    cmd(['unbound-checkconf', str(path)])
    text = path.read_text()
    for directive in ('interface: 127.0.0.1', 'interface: ::1',
                      'forward-addr: 192.0.2.53@853#dns.example.org', 'forward-addr: 192.0.2.54@53',
                      'forward-no-cache: yes', 'msg-cache-size: 4m', 'rrset-cache-size: 8m',
                      'serve-expired-client-timeout: 100', 'num-threads: 2', 'hide-identity: yes'):
        assert directive in text


def test_mixed_transport_rejected(config):
    config.set('set service dns forwarding name-server 192.0.2.55')
    assert_config_commit_rejected(config, 'TLS and plaintext')


def test_self_forwarding_rejected(config):
    config.delete('delete service dns forwarding name-server')
    config.set('set service dns forwarding name-server 127.0.0.1 port 1053')
    assert_config_commit_rejected(config, 'points to this DNS listener')


def test_successive_commits_remain_applicable(config):
    # Deliberate configuration changes must not exhaust systemd's automatic start limit.
    for verbosity in (1, 2, 1, 2, 1, 2):
        config.set(f'set service dns forwarding logging verbosity {verbosity}')
        config.commit()
        assert dns.control('default', 'get_option', 'verbosity').strip() == str(verbosity)


def test_disable_and_remove(config):
    config.set('set service dns forwarding disable')
    config.commit()
    assert not (dns.ROOT / dns.instance_id('default') / 'unbound.conf').exists()
    config.delete('delete service dns forwarding')
    config.commit()
    assert json.loads((dns.ROOT / 'intent.json').read_text())['instances'] == {}
