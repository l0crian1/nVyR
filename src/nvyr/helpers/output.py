"""Shared terminal presentation helpers for operational scripts."""

from tabulate import tabulate


def elapsed_time(seconds):
    """Format elapsed whole seconds, retaining unknown values as an em dash."""
    if seconds is None:
        return '—'

    hours, remainder = divmod(max(0, int(seconds)), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f'{hours:02}:{minutes:02}:{seconds:02}'


def detailed_output(dataset, headers):
    """Print each record as a headerless label/value table, separated by a blank line."""
    for data in dataset:
        print(tabulate(zip(headers, data), tablefmt='presto'))
        print()
