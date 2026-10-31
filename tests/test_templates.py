import stat

import pytest

from nvyr.helpers import template, nftables_lifecycle, nftables_formatters
from tests.lifecycle import firewall_context
from nvyr.tree import ReadOnlyTree


def test_helpers_in_includes_imports_and_isolated_render_contexts(tmp_path):
    (tmp_path / 'service.j2').write_text('{% import "macro.j2" as m %}{% include "part.j2" %}{{ m.format(value) }}\n')
    (tmp_path / 'part.j2').write_text('{{ value }}:')
    (tmp_path / 'macro.j2').write_text('{% macro format(value) %}{{ decorate(value) }}{% endmacro %}')
    renderer = template.TemplateRenderer(tmp_path)

    @renderer.register('decorate')
    def decorate(value):
        return '<' + value + '>'

    assert renderer.render('service.j2', {'value': 'a&b'}) == 'a&b:<a&b>\n'
    assert renderer.render('service.j2', {'value': 'next'}) == 'next:<next>\n'

    with pytest.raises(template.RenderingError, match='value'):
        renderer.render('service.j2')

    # Registration after a render replaces the environment instead of modifying it.
    renderer.register('extra', lambda: 'later')
    (tmp_path / 'extra.j2').write_text('{{ extra() }}')

    assert renderer.render('extra.j2') == 'later'

    with pytest.raises(template.RenderingError, match='decorate'):
        template.TemplateRenderer(tmp_path).render('service.j2', {'value': 'x'})


def test_bundled_template_accepts_read_only_configuration():
    configuration = ReadOnlyTree({'firewall': {'ipv4': {'forward': {'filter': {'default-action': 'accept'}}}}})
    rendered = template.render('firewall/filter.nft.j2', {
        'configuration': configuration,
        'objects': nftables_lifecycle.object_paths(configuration),
        'interface_contexts': nftables_formatters.nft_interface_contexts(configuration),
        'lifecycle': {'remove': set(), 'rebuild': {('chain', 'forward'), ('chain', 'ipv4_forward')}},
    })

    assert 'chain ipv4_forward {' in rendered and 'counter accept comment "default|default-action accept"' in rendered


def test_nft_rendering_does_not_repeat_schema_validation(monkeypatch):
    from nvyr.config_scripts import firewall, nat
    from nvyr.helpers import validators
    from nvyr.schema import Schema

    schema = Schema.bundled()
    tree = {'firewall': {'ipv4': {'input': {'filter': {'default-log': True, 'rule': {
        '10': {'action': 'accept', 'protocol': ['tcp'], 'source-address': {'192.0.2.1/24': {}},
               'destination-port': ['80'], 'counter': {}, 'log': {}},
        '20': {'disable': True}}}}}},
        'nat': {'source': {'rule': {'10': {'protocol': ['tcp'], 'log': {}, 'outbound-interface': ['eth0'],
            'translation': {'address': '203.0.113.0/24', 'port': '8080-8090'}}}}}}
    schema.validate_configuration(tree)
    effective = ReadOnlyTree(schema.defaults(tree))

    for script in (firewall, nat):
        script.verify(effective, None)

    def repeated(*args, **kwargs):
        pytest.fail('Rendering repeated an individual value validator')

    for name in ('address', 'port', 'text', 'integer_range', 'ipv4_address', 'ipv6_address',
                 'inet_address', 'network', 'ip_range', 'length', 'byte_length'):
        monkeypatch.setattr(validators, name, repeated)

    context = firewall_context(effective, ReadOnlyTree({}), 'firewall', ('firewall',),
                            previous_effective=ReadOnlyTree({}), schema=schema)
    filtering = firewall.generate(effective, context)

    assert 'ip saddr { 192.0.2.1/24 }' in filtering and 'th dport { 80 }' in filtering
    assert 'log prefix "[ipv4-INP-filter-10-A]" counter accept comment "10|"' in filtering
    assert 'comment "20|' not in filtering
    assert 'snat ip to 203.0.113.0/24 :8080-8090 comment "10|"' in filtering


@pytest.mark.parametrize('source', ['{{ missing }}', '{% invalid %}', '{% include "absent.j2" %}'])
def test_failed_render_leaves_destination_intact(tmp_path, source):
    destination = tmp_path / 'service.conf'
    destination.write_text('previous\n')
    (tmp_path / 'service.j2').write_text(source)

    with pytest.raises(template.RenderingError, match='service.j2'):
        template.TemplateRenderer(tmp_path).render_to_file('service.j2', destination)

    assert destination.read_text() == 'previous\n'
    assert not list(tmp_path.glob('.nvyr-*'))


def test_atomic_write_permissions_ownership_and_replace_failure(tmp_path, monkeypatch):
    destination = tmp_path / 'service.conf'
    destination.write_text('old\n')
    previous = destination.stat()
    template.write(destination, 'new & unescaped\n', mode=0o640)
    current = destination.stat()

    assert destination.read_text() == 'new & unescaped\n'
    assert stat.S_IMODE(current.st_mode) == 0o640
    assert (current.st_uid, current.st_gid) == (previous.st_uid, previous.st_gid)

    def fail(*args):
        raise OSError('simulated disk failure')

    monkeypatch.setattr(template.os, 'replace', fail)

    with pytest.raises(template.RenderingError, match='simulated disk failure'):
        template.write(destination, 'incomplete')

    assert destination.read_text() == 'new & unescaped\n'
    assert not list(tmp_path.glob('.nvyr-*'))


def test_renderer_registration_and_missing_template_errors(tmp_path):
    renderer = template.TemplateRenderer(tmp_path)

    with pytest.raises(ValueError, match='identifier'):
        renderer.register('bad-name')

    with pytest.raises(TypeError, match='callable'):
        renderer.register('bad', 42)

    with pytest.raises(ValueError, match='already registered'):
        renderer.register('json_text', str)

    with pytest.raises(template.RenderingError, match='absent.j2'):
        renderer.render('absent.j2')
