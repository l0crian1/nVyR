"""Render reviewable storyteller samples from the real Linux/nftables corpus.

Run with PYTHONPATH=src:. python -m tests.trace_examples. No live router or
privileges are needed; every example is produced by the operational renderer.
"""

import io
import json
from pathlib import Path

from nvyr.helpers import firewall_trace_analysis, firewall_trace_output


def load_corpus():
    """Load native scenario collections, including focused follow-up captures."""
    fixtures = Path(__file__).parent / 'fixtures/firewall_trace'
    corpus = {}
    for path in sorted(fixtures.glob('*.json')):
        corpus.update(json.loads(path.read_text(encoding='utf-8')))
    return corpus


def report_for(fixture):
    """Replay the saved native events with their original chain metadata."""
    records = [{'event': 'capture', 'format': 1, 'chains': fixture['chains']}]
    records.extend({'event': 'native', 'raw': line} for line in fixture['events'])
    records.append({'event': 'capture-end', 'reason': 'duration', 'events': len(fixture['events'])})
    stream = io.StringIO(''.join(json.dumps(record) + '\n' for record in records))
    return firewall_trace_analysis.analyze(stream, detail=True)


def example_trace(report, scenario):
    """Prefer a complete, single-pass journey; select the VRF transition when relevant."""
    traces = report['traces']
    if scenario == 'vrf-output':
        traces = [trace for trace in traces if any(
            change['fields'].get('outbound-interface', {}).get('before') == 'TRACEVRF'
            for change in trace['changes'])]
    elif scenario in ('dnat-address-port', 'dnat-port-only', 'snat', 'masquerade'):
        side = 'destination' if scenario.startswith('dnat') else 'source'
        traces = [trace for trace in traces if any(
            side + '-address' in change['fields'] or side + '-port' in change['fields']
            for change in trace['changes'])]
        # Prefer the initial translation rule as well as its observed result;
        # established packets can be translated without visiting a NAT rule.
        initial = [trace for trace in traces if any(
            step.get('path', '').startswith('nat ') and step['event'] == 'rule'
            for step in trace['steps'])]
        if initial:
            traces = initial
    return min(traces, key=lambda trace: (trace['passes'], -trace['events']))


def main():
    """Write all scenarios, one full detail example, and the unfiltered trace index."""
    root = Path(__file__).resolve().parents[1]
    corpus = load_corpus()
    output = root / 'dist/trace-story-examples'
    output.mkdir(parents=True, exist_ok=True)
    contents = ['Packet storyteller examples', '',
                'Rendered from actual Linux 6.18 / nftables 1.1.7 captures.',
                'Each file contains one selected native trace ID, including all its observed passes.',
                'Recreate with: PYTHONPATH=src:. python -m tests.trace_examples', '']
    for scenario, fixture in sorted(corpus.items()):
        report = report_for(fixture)
        selected = example_trace(report, scenario)
        filename = scenario + '.txt'
        text = firewall_trace_output.story(selected)
        (output / filename).write_text(text + '\n', encoding='utf-8')
        contents.append(filename)
        if scenario == 'dnat-address-port':
            (output / 'dnat-address-port-detail.txt').write_text(
                firewall_trace_output.story(selected, detail=True) + '\n', encoding='utf-8')
            (output / 'trace-index.txt').write_text(
                firewall_trace_output.render(report) + '\n', encoding='utf-8')
    (output / 'README.txt').write_text('\n'.join(contents) + '\n', encoding='utf-8')
    print(f'Wrote {len(corpus)} stories, detail and index examples to {output}')


if __name__ == '__main__':
    main()
