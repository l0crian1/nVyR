"""Human-readable packet journeys, with native evidence available in detail."""

import re
import textwrap

from tabulate import tabulate

from nvyr.helpers.firewall_trace import rule_path


MISSING = '—'


def safe(value):
    """Do not allow saved descriptions or native text to control the user's terminal."""
    text = str(value)
    return ''.join(character if character.isprintable() else repr(character)[1:-1] for character in text)


def endpoint(packet, side):
    """Keep IPv6 addresses unambiguous when a transport port was observed."""
    address = packet.get(side + '-address', MISSING)
    port = packet.get(side + '-port')
    if port is None:
        return address
    if ':' in address:
        address = '[' + address + ']'
    return f'{address}:{port}'


def location(event):
    """Use CLI paths for nVyR rules and full native identities for other tables."""
    return event.get('path') or ' '.join(event.get(key, '?') for key in ('family', 'table', 'chain'))


def packet_description(packet):
    """Describe only observed headers, including ICMP type/code and TCP flags."""
    text = f"{packet.get('protocol', '?').upper()} {endpoint(packet, 'source')} → {endpoint(packet, 'destination')}"
    for field in ('icmp-type', 'icmp-code', 'tcp-flags', 'inbound-interface',
                  'outbound-interface', 'slave-interface', 'ttl', 'hop-limit', 'mark'):
        if field in packet:
            text += f'; {field} {packet[field]}'
    return text


def explain(event):
    """Describe traversal without claiming an evaluated statement produced a side effect."""
    if event['event'] == 'packet':
        return packet_description(event.get('packet', {}))
    if event['event'] == 'conntrack':
        fields = event.get('connection', {})
        return 'Connection: ' + '; '.join(f"{key} {', '.join(value) if isinstance(value, list) else value}"
                                          for key, value in fields.items())
    verdict = event.get('verdict', '')
    if verdict.startswith(('jump ', 'goto ')):
        if 'target-path' in event:
            return verdict.split()[0].capitalize() + ' ' + event['target-path']
        return verdict.capitalize()
    if verdict == 'return':
        return 'Return from this chain'
    if event['event'] == 'policy':
        return 'Base-chain policy: ' + verdict
    description = event.get('comment', '').partition('|')[2]
    label = event.get('comment', '').partition('|')[0]
    generated = {'vrf-bypass': 'Preliminary VRF OUTPUT pass',
                 'zone-dispatch': 'Zone policy dispatch',
                 'global-offload': 'Global flowtable enrollment'}
    text = generated.get(label, description or 'Rule evaluated')
    if verdict:
        text += ': ' + verdict
    return text


def evidence(trace):
    """Keep the complete event ledger separate from the readable journey."""
    lines = ['Native evidence', '']
    for number, event in enumerate(trace['steps'], 1):
        if event.get('new-pass'):
            lines.append('--- New observation pass (ID reuse or recirculation) ---')
        hook = f" [{event['hook']}]" if event.get('hook') else ''
        handle = f" (handle {event['handle']})" if 'handle' in event else ''
        lines.append(f"{number}. {location(event)}{hook}{handle}")
        lines.append('   ' + explain(event))
        if event.get('expression'):
            lines.append('   Expression: ' + event['expression'])
        if event.get('references'):
            lines.append('   Uses: ' + '; '.join(event['references']))
        for field, change in event.get('changes', {}).items():
            lines.append(f"   Observed {field}: {change['before']} → {change['after']}")
        lines.append(f"   Capture line {event['line']}; received {event.get('timestamp') or MISSING}")
        lines.append('   ' + event['raw'])
        lines.append('')
    return lines


def chain_location(event):
    """Resolve a chain independently of the current rule's special-purpose path."""
    return rule_path(event['table'], event['chain'], '') or ' '.join(
        event[key] for key in ('family', 'table', 'chain'))


def chain_description(path):
    """Translate known CLI chain paths into prose, retaining unfamiliar identities."""
    if path in ('nat source', 'nat destination'):
        return path.split()[1] + ' NAT'
    words = path.split()
    if not words or words[0] != 'firewall':
        return path
    failsafe = len(words) > 1 and words[1] == 'fail-safe'
    if failsafe:
        words.pop(1)
    if len(words) != 4:
        return path
    _, family, hook, priority = words
    family = {'ipv4': 'IPv4 ', 'ipv6': 'IPv6 ', 'inet': ''}.get(family, family + ' ')
    prefix = 'fail-safe ' if failsafe else ''
    if hook == 'name':
        return f'named {prefix}{family}chain {priority}'
    raw = ' raw' if priority == 'raw' else ''
    return f'the {prefix}{family}{hook}{raw} firewall'


def statement_text(event):
    """Ignore quoted log prefixes and object names when recognizing statements."""
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', event.get('expression', ''))


def nat_operation(event):
    """Distinguish translation statements from conntrack snat/dnat status matches."""
    match = re.search(r'\b(dnat|snat)(?: ip6?)? to\b|\b(masquerade|redirect)\b', statement_text(event))
    return (match.group(1) or match.group(2)) if match else None


def rule_action(event):
    """Describe a recorded rule's operation, independently of the traversal summary."""
    verdict = event.get('verdict', '')
    expression = statement_text(event)
    words = expression.split()
    operation = nat_operation(event)
    actions = []
    if 'nftrace' in words:
        actions.append('Enabled tracing' if 'meta nftrace set 1' in expression else 'Changed tracing')
    if 'notrack' in words:
        actions.append('Selected untracked processing')
    if 'log' in words:
        actions.append('Included packet logging')
    if 'flow' in words and 'add' in words:
        actions.append('Attempted flowtable enrollment')
    if 'tcp option maxseg size set ' in expression:
        actions.append('Set TCP MSS: ' + expression.split('tcp option maxseg size set ', 1)[1])
    if operation:
        names = {'dnat': 'destination NAT', 'snat': 'source NAT',
                 'masquerade': 'masquerade', 'redirect': 'redirect'}
        actions.append('Applied ' + names[operation])
    if 'reject' in words:
        response = expression.partition('reject')[2].strip()
        response = 'with a TCP reset' if response == 'with tcp reset' else response
        actions.append(('Rejected ' + response).strip())
    if event.get('comment', '').startswith('vrf-bypass'):
        actions.append('Accepted the preliminary VRF output pass')
    elif verdict.startswith(('jump ', 'goto ')):
        verb, target = verdict.split(' ', 1)
        destination = chain_description(event.get('target-path', target))
        if verb == 'jump':
            actions.append('Jumped to ' + destination)
        else:
            actions.append('Transferred to ' + destination + ' (goto; no return to this rule)')
    else:
        decisions = {'accept': 'Accepted', 'drop': 'Dropped', 'return': 'Returned',
                     'continue': 'Continued'}
        decision = decisions.get(verdict, 'Verdict: ' + verdict if verdict else '')
        if decision:
            actions.append(decision)
    if not actions:
        actions.append('Evaluated: ' + event.get('expression', MISSING))
    elif actions == ['Continued'] and expression:
        actions.insert(0, 'Evaluated: ' + event['expression'])
    following = [action[0].lower() + action[1:] for action in actions[1:]]
    return '; '.join([actions[0], *following]) + '.'


def observation_passes(steps):
    """Keep reused IDs and recirculation separate in every section of the report."""
    passes = []
    current = []
    for event in steps:
        if event.get('new-pass') and current:
            passes.append(current)
            current = []
        current.append(event)
    if current:
        passes.append(current)
    return passes


def chain_visits(steps):
    """Retain consecutive visits, including jump targets without their own events.

    A jump verdict identifies the destination even when an empty chain emits no
    event. Such a visit is labelled as a target with no recorded events, never
    silently discarded or promoted into proof that a rule did or did not match.
    """
    visits = []
    seen = set()

    def append(identity, *, via=None):
        visit = {'identity': identity, 'events': [], 'via': via,
                 'revisited': identity in seen}
        visits.append(visit)
        seen.add(identity)
        return visit

    for event in steps:
        identity = tuple(event[key] for key in ('family', 'table', 'chain'))
        if not visits or visits[-1]['identity'] != identity:
            if visits:
                previous = visits[-1]
                via = previous['via']
                no_rule_hits = not any(item['event'] == 'rule' for item in previous['events'])
                if via and via.get('verdict', '').startswith('jump ') and no_rule_hits:
                    caller = tuple(via[key] for key in ('family', 'table', 'chain'))
                    if identity == caller:
                        previous['return-line'] = event['line']
            append(identity)
        visits[-1]['events'].append(event)
        verdict = event.get('verdict', '')
        if verdict.startswith(('jump ', 'goto ')):
            target = (event['family'], event['table'], verdict.split(' ', 1)[1])
            append(target, via=event)
    return visits


def visit_result(visit):
    """Explain each visit without inventing matches for packet-only observations."""
    events = visit['events']
    rules = [event for event in events if event['event'] == 'rule']
    decisions = [event for event in events if event.get('verdict')]
    if visit.get('return-line'):
        return 'No rule hit recorded; returned'
    if not events:
        return 'Jump/goto target; no chain events recorded'
    if not decisions:
        return 'Observed; no rule hit recorded' if not rules else 'Rule observed; no verdict recorded'
    final = decisions[-1]
    verdict = final['verdict']
    if final['event'] == 'policy':
        result = 'Base-chain policy: ' + verdict.upper()
    elif not rules and verdict == 'return':
        result = 'No rule hit recorded; returned'
    else:
        result = rule_action(final).rstrip('.')
        label = final.get('comment', '').partition('|')[0]
        if label.isdecimal():
            result = f'Rule {label}: ' + result[0].lower() + result[1:]
        elif label == 'default':
            result = 'Default action: ' + result[0].lower() + result[1:]
    if visit['revisited']:
        result = 'Revisited; ' + result[0].lower() + result[1:]
    return result


def rule_label(event):
    """Use short rule identities in prose and full CLI paths in the rules section."""
    path = event.get('path', '')
    label = event.get('comment', '').partition('|')[0]
    if path.startswith('nat ') and label.isdecimal():
        return path.split()[1].capitalize() + ' NAT rule ' + label
    if label.isdecimal():
        context = chain_description(chain_location(event)).removeprefix('the ')
        return 'Rule ' + label + ' in ' + context
    if event['event'] == 'policy':
        return 'The base-chain policy in ' + event['chain']
    if label == 'zone-dispatch':
        return 'The zone lookup'
    if path.endswith('global-options state-policy'):
        return 'The global connection-state policy'
    return location(event)


def narrative(steps, visits):
    """Summarize significant observations, leaving the complete itinerary below."""
    bullets = []
    packets = [event for event in steps if 'packet' in event]
    first = packets[0]['packet'] if packets else {}
    inbound = first.get('inbound-interface')
    outbound = first.get('outbound-interface')
    if inbound:
        flags = ' with TCP ' + first['tcp-flags'].upper() + ' set' if first.get('tcp-flags') else ''
        bullets.append(f'The packet arrived on interface "{inbound}"{flags}.')
    elif outbound:
        bullets.append(f'The packet was first seen on the output path through "{outbound}".')
    else:
        bullets.append('No arrival interface was recorded.')
    if 'icmp-type' in first:
        bullets.append(f"ICMP type {first['icmp-type']}, code {first.get('icmp-code', MISSING)}.")

    previous_packet = {}
    connection = {}
    previous_visit = None
    for visit in visits:
        has_rule_hits = any(event['event'] == 'rule' for event in visit['events'])
        if visit['revisited'] and previous_visit:
            prior = previous_visit['events']
            if previous_visit.get('return-line') or (prior and prior[-1].get('verdict') == 'return'):
                event = visit['events'][0] if visit['events'] else None
                if event:
                    bullets.append('Processing resumed in ' + chain_description(chain_location(event)) + f" (L{event['line']}).")
        if visit.get('return-line') and not visit['events']:
            bullets.append(f"{visit['identity'][2]} returned with no rule hit recorded (L{visit['via']['line']}–L{visit['return-line']}).")
        for event in visit['events']:
            reference = f"L{event['line']}"
            packet = event.get('packet')
            if packet is not None:
                egress = packet.get('outbound-interface')
                old_egress = previous_packet.get('outbound-interface')
                if egress and egress != old_egress:
                    if old_egress:
                        bullets.append(f'The output path changed from "{old_egress}" to "{egress}" ({reference}).')
                    elif event.get('hook') == 'forward':
                        bullets.append(f'The forwarding path used egress interface "{egress}" ({reference}).')
                    elif egress != outbound:
                        bullets.append(f'Egress interface "{egress}" was observed ({reference}).')
                changes = event.get('changes', {})
                for side in ('source', 'destination'):
                    if any(side + suffix in changes for suffix in ('-address', '-port')):
                        bullets.append(f"The {side} changed from {endpoint(previous_packet, side)} to {endpoint(packet, side)} ({reference}).")
                for field, name in (('ttl', 'TTL'), ('hop-limit', 'IPv6 hop limit')):
                    if field in changes:
                        change = changes[field]
                        bullets.append(f"{name} changed from {change['before']} to {change['after']} ({reference}).")
                previous_packet = packet
            observed = event.get('connection', {})
            if observed:
                states = observed.get('state')
                if states and states != connection.get('state'):
                    bullets.append('Connection tracking classified the packet as ' + ', '.join(states) + f' ({reference}).')
                direction = observed.get('direction')
                if direction and direction != connection.get('direction'):
                    bullets.append(f'It was travelling in the {direction} direction of the connection ({reference}).')
                if 'zone' in observed and observed.get('zone') != connection.get('zone'):
                    bullets.append(f"Connection tracking used zone {observed['zone']} ({reference}).")
                connection = observed
            if event['event'] not in ('rule', 'verdict'):
                continue
            verdict = event.get('verdict', '')
            expression = statement_text(event)
            # Family dispatch and tracing enablement are retained in Rules hit;
            # omit them only from the concise story.
            if expression.startswith('meta nfproto vmap ') or expression == 'meta nftrace set 1':
                continue
            significant = verdict not in ('', 'continue') or nat_operation(event)
            significant = significant or any(token in expression for token in ('notrack', 'flow add', 'maxseg size set'))
            if significant:
                if event['event'] == 'verdict' and verdict == 'return' and not has_rule_hits:
                    bullets.append(f"{event['chain']} returned with no rule hit recorded ({reference}).")
                else:
                    action = rule_action(event).rstrip('.')
                    action = action[0].lower() + action[1:]
                    bullets.append(f"{rule_label(event)} {action} ({reference}).")
        previous_visit = visit

    decisions = [event for event in steps if event.get('verdict')]
    if decisions:
        final = decisions[-1]
        bullets.append(f"Last observed verdict: {final['verdict'].upper()} at {location(final)} (L{final['line']}).")
    else:
        bullets.append('No verdict was recorded.')
    return bullets


def section(title):
    """Use the agreed report sections, not a heading for every processing event."""
    return ['', title, '─' * 76]


def wrapped(text, *, indent='', continuation=None):
    """Wrap prose while keeping evidence references and hanging indents readable."""
    return textwrap.wrap(safe(text), width=100, initial_indent=indent,
                         subsequent_indent=continuation if continuation is not None else indent,
                         break_long_words=False, break_on_hyphens=False)


def visits_table(visits):
    """Show native family/table identity and every chain visit in encounter order."""
    rows = []
    for visit in visits:
        family, table, chain = visit['identity']
        source = visit['events'][0] if visit['events'] else visit['via']
        rows.append([safe(family + ' ' + table), safe(chain), f"L{source['line']}", safe(visit_result(visit))])
    if not rows:
        return 'No chain visits recorded.'
    return tabulate(rows, headers=['Table', 'Chain', 'Evidence', 'What happened'],
                    disable_numparse=True, maxcolwidths=[28, 30, None, 48])


def rules_hit(steps):
    """Keep rule hits distinct from packet observations and base-chain policies."""
    lines = []
    for event in steps:
        if event['event'] != 'rule':
            continue
        if lines:
            lines.append('')
        lines.extend(wrapped(f"L{event['line']}  {location(event)}", continuation='      '))
        description = event.get('comment', '').partition('|')[2]
        if description:
            lines.extend(wrapped('Description: ' + description, indent='      '))
        lines.extend(wrapped(rule_action(event), indent='      '))
        if event.get('references'):
            lines.extend(wrapped('Uses: ' + '; '.join(event['references']), indent='      '))
    return lines or ['No rule hits recorded.']


def changes_table(steps):
    """List all observed changes, including ports, TTL, marks and interface changes."""
    rows = []
    names = {'ttl': 'TTL', 'dscp': 'DSCP', 'ecn': 'ECN', 'tcp-flags': 'TCP flags'}
    for event in steps:
        for field, change in event.get('changes', {}).items():
            label = names.get(field, field.replace('-', ' ').capitalize())
            rows.append([f"L{event['line']}", label, change['before'], change['after']])
    if not rows:
        return 'No packet-header changes recorded.'
    return tabulate([[safe(value) for value in row] for row in rows],
                    headers=['Location', 'Field', 'Before', 'After'], disable_numparse=True)


def outcome(steps):
    """Report the last observed decision even when a later header was captured."""
    decisions = [event for event in steps if event.get('verdict')]
    if not decisions:
        return ['No verdict was recorded.']
    final = decisions[-1]
    verdict = final['verdict']
    lines = wrapped(f"{verdict.upper()} — last observed decision at {location(final)} (L{final['line']}).")
    if verdict == 'accept':
        lines.append('Acceptance does not confirm end-to-end delivery.')
    elif verdict in ('continue', 'return') or verdict.startswith(('jump ', 'goto ')):
        lines.append('No subsequent accept or drop was recorded.')
    return lines


def story(trace, *, detail=False):
    """Render the agreed story, itinerary, rule hits, changes and outcome layout."""
    lines = [f"Trace {safe(trace['id'])}", '═' * 76]
    for warning in trace['warnings']:
        lines.extend(wrapped('Warning: ' + warning))
    passes = observation_passes(trace['steps'])
    for number, steps in enumerate(passes, 1):
        if len(passes) > 1:
            lines.extend(['', f'OBSERVATION PASS {number}', '═' * 76])
        packets = [event['packet'] for event in steps if 'packet' in event]
        packet = packets[0] if packets else {}
        ingress = next((item['inbound-interface'] for item in packets if item.get('inbound-interface')), MISSING)
        egress = next((item['outbound-interface'] for item in reversed(packets) if item.get('outbound-interface')), MISSING)
        protocol = packet.get('protocol', '?').upper().replace('IPV6-ICMP', 'ICMPv6')
        flow = f"{protocol} {endpoint(packet, 'source')} → {endpoint(packet, 'destination')}"
        lines.extend(['', 'Flow       ' + safe(flow), 'Ingress    ' + safe(ingress), 'Egress     ' + safe(egress)])
        visits = chain_visits(steps)
        lines.extend(section('STORY'))
        for bullet in narrative(steps, visits):
            lines.extend(wrapped(bullet, indent='• ', continuation='  '))
        lines.extend(section('TABLES AND CHAINS VISITED'))
        lines.append(visits_table(visits))
        lines.extend(section('RULES HIT'))
        lines.extend(rules_hit(steps))
        lines.extend(section('OBSERVED CHANGES'))
        lines.append(changes_table(steps))
        lines.extend(section('OUTCOME'))
        lines.extend(outcome(steps))
    if not passes:
        lines.extend(['', 'No individual events were retained for this trace.'])
    if detail:
        lines.extend(['', '-' * 80, '', *evidence(trace)])
    # Preserve newlines generated by tables while escaping native evidence at
    # the last boundary as well as user-controlled fields before tabulation.
    return '\n'.join('\n'.join(safe(part) for part in line.split('\n')) for line in lines)


def render(report, *, stories=False, detail=False):
    """Render a compact index or full selected journeys, without hiding capture warnings."""
    lines = ['Warning: ' + warning for warning in report['warnings']]
    ending = report.get('end')
    if ending:
        lines.append(f"Capture stopped: {ending['reason']}; {report['events']} events recorded.")
    lines.append('')
    traces = report['traces']
    if not traces:
        lines.append('No matching packet traces.')
    elif stories or detail:
        lines.append(('\n' + '-' * 80 + '\n\n').join(story(trace, detail=detail) for trace in traces))
    else:
        rows = []
        for trace in traces:
            packet = trace['first']
            rows.append([trace['id'], packet.get('family', MISSING).replace('ip', 'IP'),
                         packet.get('protocol', MISSING), endpoint(packet, 'source'),
                         endpoint(packet, 'destination'), ', '.join(trace['interfaces']) or MISSING,
                         trace['events'], trace['passes'], trace['last-verdict'] or MISSING,
                         trace['last-location'] or MISSING])
        lines.append(tabulate([[safe(value) for value in row] for row in rows],
                             headers=['Trace', 'Family', 'Protocol', 'Source', 'Destination',
                                      'Interfaces', 'Events', 'Passes', 'Last verdict', 'Location'], disable_numparse=True))
    if report['unparsed']:
        lines.append('\nUnparsed native evidence (first 20):')
        lines.extend(f"Line {event['line']}: {safe(event['raw'])}" for event in report['unparsed'])
    return '\n'.join(lines)
