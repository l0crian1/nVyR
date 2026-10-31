#!/usr/bin/env python3
"""Scoped file logs; follow streams new records until Ctrl-C."""

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import log_reader


@opmode.command
def show(service: str, name: str = '', vrf: str = 'default', family: str = '',
         hook: str = '', stage: str = '', rule: str = '', chain: str = '',
         group: str = '', direction: str = '', follow: bool = False):
    paths, pattern = log_reader.select(service, name=name, vrf=vrf, family=family,
                                       hook=hook, stage=stage, rule=rule, chain=chain, group=group, direction=direction)
    found = False
    try:
        for path, line in log_reader.records(paths, pattern, follow=follow):
            found = True
            if service == 'container':
                line = log_reader.container_line(line)
            print(line, end='' if line.endswith('\n') else '\n', flush=follow)
    except (KeyboardInterrupt, BrokenPipeError):
        return
    except OSError as error:
        raise OperationalError(f'Cannot read selected logs: {error}') from error

    if not found and not follow:
        print('No matching log entries.')


if __name__ == '__main__':
    opmode.run()
