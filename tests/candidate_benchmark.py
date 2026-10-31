"""Measure candidate insertion without RPC, commit work or host changes.

Run: PYTHONPATH=src:. python -m tests.candidate_benchmark
Add --profile to report where insertion spends its time.
"""

import argparse
import cProfile
import pstats
import tempfile
import time

from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.schema import Schema
from nvyr.storage import Store
from tests.lifecycle import LifecycleStub


def insert_rules(controller, session, count):
    """Use the same five-setting anchored command as the live performance test."""
    for number in range(1, count + 1):
        controller.execute(
            f'set firewall ipv4 forward filter rule {number} action accept '
            'source-address 1.1.1.1 destination-address 2.2.2.2 destination-port 22 protocol tcp',
            session,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--counts', type=int, nargs='+', default=[2500, 5000, 10000])
    parser.add_argument('--profile', action='store_true')
    args = parser.parse_args()
    if any(count <= 0 for count in args.counts):
        parser.error('counts must be positive')

    schema = Schema.bundled()
    modules = {owner: LifecycleStub() for owner in schema.owners}
    with tempfile.TemporaryDirectory(prefix='nvyr-candidate-benchmark-') as directory:
        engine = Engine(schema, modules, Store(directory))
        controller = Controller(engine)
        session = engine.open('benchmark', 'local')
        try:
            for count in args.counts:
                engine.discard(session)
                start = time.perf_counter()
                insert_rules(controller, session, count)
                elapsed = time.perf_counter() - start
                print(f'{count:,} rules: {elapsed:.3f}s ({count / elapsed:,.0f} rules/s)', flush=True)

            if args.profile:
                engine.discard(session)
                profiler = cProfile.Profile()
                profiler.runcall(insert_rules, controller, session, args.counts[-1])
                pstats.Stats(profiler).strip_dirs().sort_stats('cumulative').print_stats(30)
        finally:
            engine.close(session)


if __name__ == '__main__':
    main()
