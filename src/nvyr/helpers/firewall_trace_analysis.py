"""Reconstruct observed packet journeys from nVyR captures.

Trace IDs identify native packet traces, not connections. Ordered observations
are retained across repeated hooks and named-chain returns; no delivery, routing
decision, elapsed kernel time or missing packet field is invented.
"""

import json
import ipaddress

from nvyr.errors import OperationalError
from nvyr.helpers import firewall_trace


MAX_BYTES = 128 * 1024 * 1024
MAX_EVENTS = 250000
MAX_TRACES = 10000
MAX_LINE = 1024 * 1024
OBSERVED_FIELDS = ('source-address', 'destination-address', 'source-port', 'destination-port',
                   'inbound-interface', 'outbound-interface', 'slave-interface', 'mark',
                   'ttl', 'hop-limit', 'dscp', 'ecn', 'tcp-flags')


def records(stream):
    """Read bounded JSONL with actionable errors instead of skipping damaged evidence."""
    total = 0
    line_number = 0
    while True:
        try:
            line = stream.readline(MAX_LINE + 1)
        except UnicodeError:
            raise OperationalError(f'Trace capture is not valid UTF-8 near line {line_number + 1}.') from None
        if not line:
            return
        line_number += 1
        total += len(line.encode('utf-8'))
        if len(line) > MAX_LINE or total > MAX_BYTES:
            raise OperationalError('Trace capture exceeds the 1 MiB event or 128 MiB file analysis limit.')
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):
            raise OperationalError(f'Invalid trace JSON at line {line_number}.') from None
        if not isinstance(record, dict) or not isinstance(record.get('event'), str):
            raise OperationalError(f'Invalid trace record at line {line_number}.')
        yield line_number, record


def _new_trace(identifier):
    """Keep aggregate counts separate from packet snapshots and the selected timeline."""
    return {'id': identifier, 'events': 0, 'observations': 0, 'first': {}, 'last': {},
            'interfaces': [], 'hooks': [], 'paths': [], 'changes': [], 'steps': [],
            'last-verdict': None, 'last-location': None, 'warnings': [], 'passes': 1, 'connections': []}


def _append_unique(values, value):
    """Preserve encounter order in summary labels without sorting the packet journey."""
    if value and value not in values:
        values.append(value)


def _location(event):
    """Prefer the captured CLI path; retain native identities for unmanaged tables."""
    return event.get('path') or ' '.join(event.get(key, '?') for key in ('family', 'table', 'chain'))


def _matches_packet(packet, filters):
    """Apply tuple filters to a single observation, including translated observations."""
    for field in ('family', 'protocol', 'source-address', 'destination-address',
                  'source-port', 'destination-port'):
        if field in filters and packet.get(field) != str(filters[field]):
            return False
    return True


def analyze(stream, *, identifier=None, detail=False, filters=None):
    """Return a structured report; only requested stories retain individual events."""
    filters = dict(filters or {})
    for field in ('source-address', 'destination-address'):
        if field in filters:
            filters[field] = str(ipaddress.ip_address(filters[field]))
    for field in ('source-port', 'destination-port'):
        if field in filters:
            filters[field] = str(int(filters[field]))
    traces = {}
    contexts = {}
    chains = {}
    metadata = None
    ending = None
    unknown = []
    event_count = 0

    for line_number, record in records(stream):
        kind = record['event']
        if kind == 'capture':
            if metadata is not None or event_count or record.get('format') != 1:
                raise OperationalError('Invalid or unsupported trace capture header.')
            metadata = record
            if not isinstance(record.get('chains'), list):
                raise OperationalError('Invalid chain metadata in trace capture.')
            for chain in record.get('chains', []):
                if not isinstance(chain, dict) or not all(isinstance(chain.get(key), str)
                                                        for key in ('family', 'table', 'name')):
                    raise OperationalError('Invalid chain metadata in trace capture.')
                chains[(chain['family'], chain['table'], chain['name'])] = chain
            continue
        if kind == 'capture-end':
            if ending is not None or record.get('events') != event_count or record.get('reason') not in ('duration', 'eof', 'interrupted'):
                raise OperationalError('Trace capture event count does not match its footer.')
            ending = record
            continue
        if ending is not None:
            raise OperationalError('Trace contains events after its capture footer.')
        event_count += 1
        if event_count > MAX_EVENTS:
            raise OperationalError('Trace analysis exceeds 250,000 events; capture a shorter interval.')

        # Reparse the retained native evidence, rather than trusting cached derived fields.
        if not isinstance(record.get('raw'), str):
            raise OperationalError(f'Missing native trace text at line {line_number}.')
        event = firewall_trace.event_record(record['raw'])
        event['timestamp'] = record.get('timestamp')
        event['line'] = line_number
        trace_id = event.get('id')
        if trace_id is None:
            if len(unknown) < 20:
                unknown.append({'line': line_number, 'raw': record['raw']})
            continue
        if identifier is not None and trace_id != identifier:
            continue
        if trace_id not in traces:
            if len(traces) >= MAX_TRACES:
                raise OperationalError('Trace analysis exceeds 10,000 packet traces; select an ID or capture less traffic.')
            traces[trace_id] = _new_trace(trace_id)
            contexts[trace_id] = {'packet-match': False, 'previous-packet': {}, 'hook': None,
                                  'observed-at': set(), 'paths': set(), 'table': None}
        trace = traces[trace_id]
        context = contexts[trace_id]
        trace['events'] += 1
        trace.setdefault('started', event['timestamp'])
        trace['ended'] = event['timestamp']

        chain = chains.get((event['family'], event['table'], event['chain']), {})
        if chain.get('hook'):
            context['hook'] = chain['hook']
        elif context['table'] != (event['family'], event['table']):
            context['hook'] = None
        context['table'] = (event['family'], event['table'])
        event['hook'] = context['hook']
        _append_unique(trace['hooks'], event['hook'])
        path = event.get('path')
        if path and path not in context['paths']:
            trace['paths'].append(path)
            context['paths'].add(path)

        packet = event.get('packet')
        if packet is not None:
            trace['observations'] += 1
            if not trace['first']:
                trace['first'] = packet
            trace['last'] = packet
            context['packet-match'] |= _matches_packet(packet, filters)
            for field in ('inbound-interface', 'outbound-interface', 'slave-interface'):
                _append_unique(trace['interfaces'], packet.get(field))

            # Missing fields are unavailable evidence, not a removal or a zero value.
            previous = context['previous-packet']
            observed_at = (event['family'], event['table'], event['chain'],
                           packet.get('inbound-interface'), packet.get('outbound-interface'))
            # The kernel hashes an skb pointer, flow hash and ingress device. A
            # recycled skb can reuse an ID immediately, even in a short capture.
            # A revisit is a new observed pass (or recirculation), not a rewrite.
            changed_identity = any(field in previous and field in packet and previous[field] != packet[field]
                                   for field in ('ip-id', 'icmp-sequence', 'family'))
            if observed_at in context['observed-at'] or changed_identity:
                trace['passes'] += 1
                event['new-pass'] = True
                context['observed-at'].clear()
                previous = {}
            context['observed-at'].add(observed_at)
            changes = {field: {'before': previous[field], 'after': packet[field]}
                       for field in OBSERVED_FIELDS
                       if field in previous and field in packet and previous[field] != packet[field]}
            if changes:
                change = {'line': line_number, 'location': _location(event), 'fields': changes}
                trace['changes'].append(change)
                event['changes'] = changes
            context['previous-packet'] = packet

        if event.get('connection'):
            _append_unique(trace['connections'], event['connection'])

        verdict = event.get('verdict')
        if verdict:
            trace['last-verdict'] = verdict
            trace['last-location'] = _location(event)
        if detail or identifier is not None:
            trace['steps'].append(event)

    warnings = []
    if metadata is None:
        warnings.append('Capture has no hook metadata; native chain names are retained without guessing hooks.')
    if ending is None:
        warnings.append('Capture has no completion record; it may have been interrupted or truncated.')
    if unknown:
        warnings.append('Some native events could not be decoded; their text is retained below.')

    selected = []
    for trace_id, trace in traces.items():
        context = contexts[trace_id]
        packet_filters = any(key in filters for key in ('family', 'protocol', 'source-address',
                             'destination-address', 'source-port', 'destination-port'))
        if packet_filters and not context['packet-match']:
            continue
        if 'verdict' in filters and trace['last-verdict'] != filters['verdict']:
            continue
        if 'hook' in filters and filters['hook'] not in trace['hooks']:
            continue
        if 'path' in filters and not any(path == filters['path'] or path.startswith(filters['path'] + ' ')
                                        for path in trace['paths']):
            continue
        if not trace['observations']:
            trace['warnings'].append('No packet header observation was captured for this trace.')
        if trace['passes'] > 1:
            trace['warnings'].append('Repeated observation passes: native trace ID reuse or packet recirculation. Changes are compared only within each pass.')
        selected.append(trace)

    return {'capture': metadata, 'end': ending, 'events': event_count,
            'traces': selected, 'warnings': warnings, 'unparsed': unknown}


def read(path, **options):
    """Analyze a persistent capture through the same constrained file boundary as capture."""
    with firewall_trace.read_capture(path) as stream:
        return analyze(stream, **options)
