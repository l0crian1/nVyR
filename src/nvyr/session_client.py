"""Container entrypoint: all authoritative work remains on configd's socket."""

import os
from pathlib import Path
import sys

from nvyr.cli import main as cli_main


def main():
    history = Path(os.environ['HOME']) / '.history'
    sys.argv = ['nvyr', '--history-directory', str(history)]
    cli_main()


if __name__ == '__main__':
    main()
