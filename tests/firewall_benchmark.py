"""Time real firewall stages without changing the host's active firewall.

Run from a checkout on a router, in a fresh network namespace:
  sudo unshare --net env PYTHONPATH=src python3 -m tests.firewall_benchmark --apply --profile

Without --apply, this only measures get_config, verify and generate.
Preparation is reported separately; candidate insertion and configd RPC are excluded.
"""

import argparse
import cProfile
import json
import os
from pathlib import Path
import pstats
import statistics
import subprocess
import tempfile
import time

from nvyr.config_scripts import firewall
from nvyr.helpers import nftables
from nvyr.helpers.dependencies import Dependencies
from nvyr.modules import CommitContext
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree


def configuration(count):
    """Use the same five settings as the anchored candidate benchmark."""
    rules = {}
    for number in range(1, count + 1):
        rules[str(number)] = {
            'action': 'accept',
            'source-address': {'1.1.1.1': {}},
            'destination-address': {'2.2.2.2': {}},
            'destination-port': ['22'],
            'protocol': ['tcp'],
        }
    return {'firewall': {'ipv4': {'forward': {'filter': {'rule': rules}}}}}


def context_for(schema, explicit, directory):
    """Prepare the defaults and ownership metadata supplied by Engine._lifecycle."""
    effective = schema.defaults(explicit)
    previous_effective = schema.defaults({})
    current = schema.ownership.snapshot(effective)
    prior = schema.ownership.snapshot(previous_effective)
    return CommitContext(
        ReadOnlyTree(effective), ReadOnlyTree({}), 'firewall', schema.owners['firewall'][0],
        previous_effective=ReadOnlyTree(previous_effective), state_directory=directory,
        scripts=ReadOnlyTree(current.registrations), previous_scripts=ReadOnlyTree(prior.registrations),
        sections=ReadOnlyTree(current.sections.get('firewall', {})),
        previous_sections=ReadOnlyTree(prior.sections.get('firewall', {})),
        dependencies=Dependencies(schema),
    )


def time_call(function, *args):
    start = time.perf_counter()
    result = function(*args)
    return result, time.perf_counter() - start


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--count', type=int, default=10000)
    parser.add_argument('--repeat', type=int, default=5)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--profile', action='store_true')
    args = parser.parse_args()
    if args.count <= 0 or args.repeat <= 0:
        parser.error('count and repeat must be positive')

    # Applying this benchmark requires a separate, initially empty network namespace.
    if args.apply:
        if os.geteuid() != 0:
            parser.error('--apply requires root inside a fresh network namespace')
        if os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino:
            parser.error('--apply requires a separate network namespace; use unshare --net')
        existing = subprocess.check_output(['nft', '--json', 'list', 'tables'], text=True)
        if any('table' in item for item in json.loads(existing)['nftables']):
            parser.error('--apply requires a namespace without existing nftables tables')

    schema = Schema.bundled()
    explicit = configuration(args.count)
    schema.validate_configuration(explicit)
    samples = []
    native_call = nftables.rc_cmd
    lifecycle_plan = firewall.nftables_lifecycle.plan
    render_template = firewall.render
    native_timings = {}
    generation_timings = {}

    def timed_native(command, **options):
        start = time.perf_counter()
        result = native_call(command, **options)
        name = 'nft_check' if '--check' in command else 'nft_load'
        native_timings[name] = time.perf_counter() - start
        return result

    def timed_plan(*arguments):
        result, generation_timings['lifecycle_plan'] = time_call(lifecycle_plan, *arguments)
        return result

    def timed_render(*arguments):
        result, generation_timings['template_render'] = time_call(render_template, *arguments)
        return result

    try:
        # Instrument subprocess wall time while retaining the actual apply behavior.
        nftables.rc_cmd = timed_native
        firewall.nftables_lifecycle.plan = timed_plan
        firewall.render = timed_render
        with tempfile.TemporaryDirectory(prefix='nvyr-firewall-benchmark-') as directory:
            for run in range(args.repeat):
                if args.apply and run:
                    subprocess.run(['nft', 'delete', 'table', 'inet', 'nvyr_filter'], check=True)

                sample = {'run': run + 1}
                context, sample['prepare'] = time_call(context_for, schema, explicit, directory)
                data, sample['get_config'] = time_call(firewall.get_config, context)
                _, sample['verify'] = time_call(firewall.verify, data, context)
                generation_timings.clear()
                generated, sample['generate'] = time_call(firewall.generate, data, context)
                sample.update(generation_timings)
                sample['generated_bytes'] = len(generated.encode('utf-8'))

                if args.apply:
                    native_timings.clear()
                    _, sample['apply'] = time_call(firewall.apply, generated, context)
                    sample.update(native_timings)
                    installed = json.loads(subprocess.check_output(
                        ['nft', '--json', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_forward'], text=True))
                    rules = [item['rule'] for item in installed['nftables'] if 'rule' in item]
                    if len(rules) != args.count + 1:
                        raise AssertionError(f'Expected {args.count} numbered rules plus default, found {len(rules)}')
                    sample['installed_rules'] = len(rules)

                samples.append(sample)
                print(json.dumps(sample), flush=True)

            stages = ['prepare', 'get_config', 'verify', 'generate', 'lifecycle_plan', 'template_render']
            if args.apply:
                stages += ['apply', 'nft_check', 'nft_load']
            print(json.dumps({'median_seconds': {
                stage: statistics.median(sample[stage] for sample in samples) for stage in stages
            }}), flush=True)

            if args.profile:
                # Use a fresh context so cached change discovery does not distort the profile.
                firewall.nftables_lifecycle.plan = lifecycle_plan
                firewall.render = render_template
                context = context_for(schema, explicit, directory)
                profiler = cProfile.Profile()
                profiler.runcall(firewall.generate, firewall.get_config(context), context)
                print('GENERATION PROFILE (instrumented times, separate from stage samples)', flush=True)
                pstats.Stats(profiler).strip_dirs().sort_stats('cumulative').print_stats(30)
                print('GENERATION SELF TIME', flush=True)
                pstats.Stats(profiler).strip_dirs().sort_stats('tottime').print_stats(20)
    finally:
        nftables.rc_cmd = native_call
        firewall.nftables_lifecycle.plan = lifecycle_plan
        firewall.render = render_template


if __name__ == '__main__':
    main()
