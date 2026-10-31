#!/usr/bin/env python3
"""Schedule developer login revocation without changing the current session."""

from nvyr.helpers import developer_access
from nvyr import opmode


@opmode.command
def disable():
    return developer_access.disable()


if __name__ == '__main__':
    opmode.run()
