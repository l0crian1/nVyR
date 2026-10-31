"""Stable VRF conntrack identities and an independent, atomic nftables table."""

from dataclasses import dataclass
import json
from pathlib import Path

from nvyr.storage import atomic_json

BOOT_ID = Path('/proc/sys/kernel/random/boot_id')


def map_elements(members, zones):
    """Format the shared interface lookup using the allocated VRF identities."""
    elements = []
    for interface, vrf in sorted(members.items()):
        elements.append(f'{json.dumps(interface)} : {zones[vrf]}')

    return ', '.join(elements)


@dataclass(frozen=True)
class Allocation:
    """Stable zone assignment plus the ledger to reserve before native apply."""

    path: Path
    ledger: dict
    zones: dict


def read_ledger(directory):
    """Read one allocation snapshot without reserving or recycling any IDs."""
    path = Path(directory) / 'vrf-conntrack.json'
    boot = BOOT_ID.read_text().strip()
    ledger = json.loads(path.read_text()) if path.exists() else {}
    return path, boot, ledger


def reserve(allocation):
    """Persist before native apply; failed transactions must not recycle IDs.

    Deleted identities also retain their reservation until reboot. Configd
    serializes application and recovery, and nftables loads its table atomically.
    """
    atomic_json(allocation.path, allocation.ledger)
