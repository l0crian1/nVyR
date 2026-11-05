#!/usr/bin/env python3

import json

from nvyr_helpers import log_message, ntfy, ping_test, ping_targets
from nvyr.config_session import ConfigurationSession
from nvyr.helpers.process import cmd
from nvyr.tree import lookup

# Variables
addresses = [*ping_targets["cloudflare"], *ping_targets["google"], *ping_targets["quad9"]]
peer = "10.1.2.2"
ntfy_server = "10.5.5.80"

bgp_data = json.loads(cmd(["vtysh", "-c", f"show ip bgp neighbor {peer} json"]))
def_sent = lookup(bgp_data, (peer, 'addressFamilyInfo', 'ipv4Unicast', 'defaultSent'), False)

pingcheck = ping_test(addresses)

if pingcheck:
    #log_message("DEBUG: At least one address is reachable. No action needed.", "ispcheck.py")
    if not def_sent:
        log_message(f"Service restored. Restoring default route to {peer}...", "ispcheck.py")
        ntfy(f"ISP checks passed. Restoring default route to peer {peer}", f"http://{ntfy_server}/bgp")

        with ConfigurationSession() as config:
            config.request_lock(force=True)
            config.set(f'set protocols bgp neighbor {peer} address-family ipv4-unicast default-originate')
            config.commit()
else:
    if def_sent:
        log_message(f"All addresses failed to respond. Withdrawing default route to {peer}...", "ispcheck.py")
        ntfy(f"ISP checks failed. Withdrawing default route to peer {peer}", f"http://{ntfy_server}/bgp")

        with ConfigurationSession() as config:
            config.request_lock(force=True)
            config.delete(f'delete protocols bgp neighbor {peer} address-family ipv4-unicast default-originate')
            config.commit()
