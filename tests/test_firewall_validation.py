import pytest

from nvyr.tree import lookup


PREFIX = 'firewall ipv4 forward filter rule '


@pytest.mark.parametrize('suffix,problem,fix', [
    ('10', 'action is required', '10 action accept'),
    ('20 description unfinished', 'action is required', '20 action drop'),
    ('30 destination-port 22', 'destination-port requires an explicit port protocol (dccp, sctp, tcp, udp, udplite)', '30 protocol tcp'),
])
def test_firewall_verify_stops_before_generate_retains_candidate_and_allows_repair(
        controller, engine, session, suffix, problem, fix):
    number = suffix.split()[0]
    if number == '30':
        controller.execute('set ' + PREFIX + '30 action accept', session)

    controller.execute('set ' + PREFIX + suffix, session)
    controller.execute('set system host-name still-commits', session)
    module = engine.modules['firewall']
    module.calls.clear()
    result = engine.commit(session)

    assert result['results']['firewall'] == {
        'success': False, 'error': PREFIX + number + ': ' + problem}
    assert result['results']['system']['success']
    assert 'firewall' not in engine.running
    assert session.mutations and all(m.owner == 'firewall' for m in session.mutations)
    assert [stage for _, stage, _ in module.calls] == ['get_config', 'verify']

    controller.execute('set ' + PREFIX + fix, session)

    assert engine.commit(session)['results']['firewall']['success']
    assert not session.mutations


def test_every_rule_checked_and_removed_action_or_protocol_rejected(controller, engine, session):
    controller.execute('set ' + PREFIX + '1 action accept', session)
    controller.execute('set ' + PREFIX + '2 description incomplete', session)

    assert 'rule 2: action' in engine.commit(session)['results']['firewall']['error']

    controller.execute('set ' + PREFIX + '2 action drop', session)
    controller.execute('set ' + PREFIX + '2 destination-port 443', session)
    controller.execute('set ' + PREFIX + '2 protocol tcp', session)

    assert engine.commit(session)['results']['firewall']['success']

    for field, problem in [('action', 'action is required'), ('protocol', 'requires an explicit port protocol')]:
        controller.execute('delete ' + PREFIX + '2 ' + field, session)

        assert problem in engine.commit(session)['results']['firewall']['error']
        assert lookup(engine.running, tuple(PREFIX.split()) + ('2', field))

        engine.discard(session)

    controller.execute('delete firewall', session)

    assert engine.commit(session)['results']['firewall']['success']
