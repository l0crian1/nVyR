"""Ownership of global MPLS forwarding commands, excluding the LDP block."""


PREFIXES = ('mpls lsp ', 'mpls fec nexthop-resolution')


class Mpls:
    def select(self, text, scopes):
        commands = sorted(line for line in text.splitlines() if line.startswith(PREFIXES))
        return {scope: commands if scope == 'global' else [] for scope in scopes}

    def replace(self, text, desired):
        lines = [line for line in text.splitlines()
                 if line.strip() != 'end' and not ('global' in desired and line.startswith(PREFIXES))]
        lines.extend(desired.get('global', ()))
        return '\n'.join([*lines, 'end', ''])


adapter = Mpls()
