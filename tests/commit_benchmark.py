"""Measure engine commit overhead without applying host configuration.

Run: PYTHONPATH=src:. python -m tests.commit_benchmark
Use --sequential for the original single-edit replay, or --profile for an
additional profiled run. Lifecycle test doubles exclude feature/backend costs.
"""

import argparse
import cProfile
import pstats
import tempfile
import time

from nvyr import engine as engine_module
from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.schema import Schema
from nvyr.storage import Store
from nvyr.tree import apply, lookup
from tests.candidate_benchmark import insert_rules
from tests.lifecycle import LifecycleStub


def sequential(tree, mutations):
    """Reference the previous algorithm without maintaining a second implementation."""
    for mutation in mutations:
        tree = apply(tree, mutation)
    return tree


def measure(schema, count, *, profile=False):
    """Stage actual anchored commands, then time a commit to private storage."""
    with tempfile.TemporaryDirectory(prefix='nvyr-commit-benchmark-') as directory:
        modules = {owner: LifecycleStub() for owner in schema.owners}
        engine = Engine(schema, modules, Store(directory))
        controller = Controller(engine)
        session = engine.open('benchmark', 'local')
        try:
            started = time.perf_counter()
            insert_rules(controller, session, count)
            staging = time.perf_counter() - started
            view = engine.view
            overlay_elapsed = 0

            def timed_view(*args, **kwargs):
                nonlocal overlay_elapsed
                started = time.perf_counter()
                result = view(*args, **kwargs)
                overlay_elapsed += time.perf_counter() - started
                return result

            engine.view = timed_view
            profiler = cProfile.Profile()
            started = time.perf_counter()
            result = profiler.runcall(engine.commit, session) if profile else engine.commit(session)
            elapsed = time.perf_counter() - started

            assert result['results']['firewall']['success'], result
            rules = lookup(engine.running, ('firewall', 'ipv4', 'forward', 'filter', 'rule'))
            assert len(rules) == count
            print(f'{count:,} rules: staging={staging:.3f}s candidate={overlay_elapsed:.3f}s '
                  f'commit={elapsed:.3f}s', flush=True)

            if profile:
                pstats.Stats(profiler).strip_dirs().sort_stats('cumulative').print_stats(25)
        finally:
            engine.close(session)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--counts', type=int, nargs='+', default=[8192, 16384, 32768, 50000])
    parser.add_argument('--sequential', action='store_true')
    parser.add_argument('--profile', action='store_true')
    args = parser.parse_args()
    if any(count <= 0 for count in args.counts):
        parser.error('counts must be positive')

    schema = Schema.bundled()
    original_overlay = engine_module.overlay
    try:
        if args.sequential:
            engine_module.overlay = sequential

        for count in args.counts:
            measure(schema, count)

        if args.profile:
            measure(schema, args.counts[-1], profile=True)
    finally:
        engine_module.overlay = original_overlay


if __name__ == '__main__':
    main()
