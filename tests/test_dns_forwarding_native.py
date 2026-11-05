"""Native forwarding, cache, TLS, local records and listener tests in one lab.

Run with NVYR_DNS_NATIVE=1 inside a disposable Linux container. Both IPv4 and
IPv6 clients share the same upstream and forwarder; no host DNS is replaced.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import time

import dns.message
import dns.query
import dns.rcode
import pytest

from nvyr.helpers import logging_formatters
from nvyr.helpers import dns_forwarding
from nvyr.helpers.template import render

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_DNS_NATIVE') != '1', reason='requires disposable native Unbound lab')


def query(name, kind='A', *, address='127.0.0.1', port=15353, tcp=False):
    request = dns.message.make_query(name, kind)
    return (dns.query.tcp if tcp else dns.query.udp)(request, address, port=port, timeout=2)


@contextmanager
def daemon(directory, text):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / 'unbound.conf'
    path.write_text(text)
    subprocess.run(['unbound-checkconf', str(path)], check=True, capture_output=True)
    with (directory / 'log').open('w+') as log:
        process = subprocess.Popen(['unbound', '-d', '-c', str(path)], stdout=log, stderr=log)
        try:
            for _ in range(100):
                result = subprocess.run(['unbound-control', '-c', str(path), 'status'], capture_output=True)
                if result.returncode == 0:
                    break
                if process.poll() is not None:
                    log.seek(0)
                    pytest.fail(log.read())
                time.sleep(.05)
            else:
                pytest.fail('Unbound did not start')
            yield path
        finally:
            process.terminate()
            process.wait(timeout=10)


def native_text(directory, configuration, *, records=(), learned=None):
    (directory / 'socket').mkdir(parents=True, exist_ok=True)
    text = render('dns/unbound.conf.j2', dict(configuration=configuration, listeners=['127.0.0.1', '::1'],
                  learned=learned or {'.': []}, records=list(records), directory=str(directory),
                  state=str(directory), identifier='74657374'))
    # Test daemons remain in a private temporary directory and retain the invoking user.
    return text.replace('username: "unbound"', 'username: ""').replace('use-syslog: yes', 'use-syslog: no')


@pytest.mark.parametrize('retained', [False, True])
def test_dnssec_state_ownership_after_image_change(monkeypatch, retained):
    account = pwd.getpwnam('unbound')
    # An accessible parent lets the real daemon drop privileges as it does on boot.
    with tempfile.TemporaryDirectory(prefix='nvyr-dns-state-') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        monkeypatch.setattr(dns_forwarding, 'STATE', root)
        directory = root / dns_forwarding.instance_id('default')
        key = directory / 'root.key'
        content = Path('/usr/share/dns/root.key').read_text()
        if retained:
            directory.mkdir(mode=0o700)
            content = '; Retained trust-anchor state\n' + content
            key.write_text(content)
            key.chmod(0o600)
            # Simulate a copied key whose old numeric owner is not today's Unbound.
            os.chown(key, 0, 0)

        dns_forwarding.initialize_state('default')

        assert key.read_text() == content
        assert (key.stat().st_uid, key.stat().st_gid) == (account.pw_uid, account.pw_gid)
        section = {'port': '15360'}
        text = native_text(directory, section, records=['ownership.test. 60 IN A 192.0.2.80'])
        text = text.replace('username: ""', 'username: "unbound"')
        os.chown(directory / 'socket', account.pw_uid, account.pw_gid)
        with daemon(directory, text):
            assert query('ownership.test', port=15360).answer[0][0].address == '192.0.2.80'


@pytest.fixture(scope='module')
def lab(tmp_path_factory):
    root = tmp_path_factory.mktemp('dns-native')
    upstream = {'port': '15354', 'dnssec': {'disable': None}}
    records = ['example.org. 300 IN A 192.0.2.80', 'example.org. 300 IN AAAA 2001:db8::80']
    text = native_text(root / 'upstream', upstream, records=records) + '\nserver:\n local-zone: "conditional.example.net." static\n'
    configuration = {'port': '15353', 'dnssec': {'disable': None}, 'cache': {'prefetch': None},
                     'name-server': {'127.0.0.1': {'port': '15354'}},
                     'domain': {'conditional.example.net': {'name-server': {'::1': {'port': '15354'}}}}}
    local = ['local.test. 60 IN A 192.0.2.1', 'local.test. 60 IN AAAA 2001:db8::1',
             '1.2.0.192.in-addr.arpa. 60 IN PTR local.test.']
    with daemon(root / 'upstream', text), daemon(root / 'forwarder', native_text(root / 'forwarder', configuration,
                records=local, learned={'.': [], 'conditional.example.net': []})) as path:
        yield root, path


@pytest.mark.parametrize('address,tcp', [('127.0.0.1', False), ('127.0.0.1', True), ('::1', False), ('::1', True)])
def test_forwarding_both_transports_and_families(lab, address, tcp):
    response = query('example.org', address=address, tcp=tcp)
    assert response.rcode() == dns.rcode.NOERROR
    assert response.answer[0][0].address == '192.0.2.80'
    response = query('example.org', 'AAAA', address=address, tcp=tcp)
    assert response.answer[0][0].address == '2001:db8::80'


def test_local_forward_and_reverse(lab):
    assert query('local.test').answer[0][0].address == '192.0.2.1'
    assert query('local.test', 'AAAA').answer[0][0].address == '2001:db8::1'
    assert str(query('1.2.0.192.in-addr.arpa', 'PTR').answer[0][0].target) == 'local.test.'


def test_cache_and_conditional_ipv6_forwarding(lab):
    _, path = lab
    query('example.org')
    query('example.org')
    stats = subprocess.check_output(['unbound-control', '-c', str(path), 'stats_noreset'], text=True)
    counters = dict(line.split('=', 1) for line in stats.splitlines() if '=' in line)
    assert int(counters['total.num.cachehits']) > 0
    assert query('absent.conditional.example.net').rcode() == dns.rcode.NXDOMAIN
    subprocess.run(['unbound-control', '-c', str(path), 'flush_zone', 'test'], check=True)


def test_empty_forwarders_fail_closed_without_recursion(tmp_path):
    section = {'port': '15355', 'dnssec': {'disable': None}}
    with daemon(tmp_path / 'empty', native_text(tmp_path / 'empty', section)):
        assert query('unavailable.example', port=15355).rcode() == dns.rcode.SERVFAIL


def test_scoped_ipv6_listener_binding(tmp_path):
    section = {'port': '15359', 'dnssec': {'disable': None}}
    text = native_text(tmp_path / 'scoped', section)
    text = text.replace('interface: ::1', 'interface: fe80::1%lo')
    # ip-freebind permits the lab address; native binding still requires its scope.
    with daemon(tmp_path / 'scoped', text):
        pass


def test_every_native_directive(tmp_path):
    section = {'port':'15356', 'name-server': {'192.0.2.53': {'tls': {'authentication-name':'dns.test'}}},
        'dnssec': {'disable': None, 'insecure-domain': ['home.test']},
        'cache': {'message-size':'4m','rrset-size':'8m','minimum-ttl':'0','maximum-ttl':'600',
                  'maximum-negative-ttl':'60','prefetch':None,'prefetch-dnssec':None,
                  'serve-expired':{'maximum-age':'600','reply-ttl':'15','client-timeout':'100'}},
        'options': {'threads':'2','edns-buffer-size':'1232','maximum-udp-size':'1232','outgoing-range':'512',
                    'queries-per-thread':'512','incoming-tcp':'10','outgoing-tcp':'10','tcp-idle-timeout':'5000',
                    'minimal-responses':None,'hide-identity':None,'hide-version':None,'qname-minimisation':{'strict':None}},
        'logging': {'verbosity':'2','queries':None,'replies':None,'servfail':None,'validation-failures':None}}
    with daemon(tmp_path / 'all', native_text(tmp_path / 'all', section)):
        pass


def test_tls_certificate_identity_and_cached_reload(tmp_path):
    key, certificate = tmp_path / 'key.pem', tmp_path / 'certificate.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=dns.example.org', '-addext', 'subjectAltName=DNS:dns.example.org',
                    '-keyout', str(key), '-out', str(certificate)], check=True, capture_output=True)
    upstream = {'port': '15357', 'dnssec': {'disable': None}}
    upstream_text = native_text(tmp_path / 'tls-upstream', upstream, records=['secure.example.org. 300 IN A 192.0.2.77'])
    upstream_text += f'\nserver:\n tls-port: 15357\n tls-service-key: "{key}"\n tls-service-pem: "{certificate}"\n'
    section = {'port': '15358', 'dnssec': {'disable': None},
               'name-server': {'127.0.0.1': {'port': '15357', 'tls': {'authentication-name': 'dns.example.org'}}}}
    text = native_text(tmp_path / 'tls-client', section).replace('/etc/ssl/certs/ca-certificates.crt', str(certificate))
    with daemon(tmp_path / 'tls-upstream', upstream_text), \
            daemon(tmp_path / 'tls-client', text) as path:
        assert query('secure.example.org', port=15358).answer[0][0].address == '192.0.2.77'
        # A reload retains the cache but installs newly generated local records.
        path.write_text(text + '\nserver:\n local-data: "changed.example.org. 10 IN AAAA 2001:db8::77"\n')
        subprocess.run(['unbound-control', '-c', str(path), 'reload_keep_cache'], check=True, capture_output=True)
        assert query('changed.example.org', 'AAAA', port=15358).answer[0][0].address == '2001:db8::77'

        # Certificate failure must not silently retry the same upstream in plaintext.
        path.write_text(text.replace('#dns.example.org', '#wrong.example.org'))
        subprocess.run(['unbound-control', '-c', str(path), 'reload'], check=True, capture_output=True)
        response = query('secure.example.org', port=15358)
        assert response.rcode() == dns.rcode.SERVFAIL


def test_native_log_collector_configuration(tmp_path):
    if not shutil.which('rsyslogd'):
        pytest.skip('requires rsyslog')

    text = logging_formatters.render({})['rsyslog']
    text = text.replace('/run/nvyr-logging', str(tmp_path)).replace('$FileGroup nvyr-access', '$FileGroup root')
    text = text.replace('$DirGroup nvyr-access', '$DirGroup root')
    path = tmp_path / 'rsyslog.conf'
    path.write_text(text)

    result = subprocess.run(['rsyslogd', '-N1', '-f', str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
