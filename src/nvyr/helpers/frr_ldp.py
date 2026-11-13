"""Own the complete nested MPLS LDP block in integrated FRR configuration."""


def lines(text):
    inside = False
    for line in text.splitlines():
        if line == 'mpls ldp':
            inside = True
        elif line and not line[0].isspace() and line != 'exit':
            inside = False
        yield line, inside
        if line == 'exit':
            inside = False


def canonical(text):
    """Retain AF/interface boundaries while ignoring native writer ordering."""
    sections = {(): set()}
    context = ()
    for line, owned in lines(text):
        value = line.strip()
        if not owned or not value or value.startswith('!') or value == 'mpls ldp':
            continue
        if value.startswith('address-family '):
            context = (value,)
            sections.setdefault(context, set())
        elif value.startswith('interface '):
            context = (context[0], value)
            sections.setdefault(context, set())
        elif value == 'exit-address-family':
            context = ()
        elif value == 'exit':
            context = context[:1] if len(context) == 2 else ()
        else:
            # Only process timers have fixed defaults. AF/interface timers inherit
            # when absent, so explicit overrides must remain even at those values.
            process_default = not context and value in {'discovery hello interval 5', 'discovery hello holdtime 15',
                         'discovery targeted-hello interval 5', 'discovery targeted-hello holdtime 45',
                         'wait-for-sync 10'}
            if process_default or len(context) == 1 and value == 'session holdtime 180':
                continue
            if value == 'install allow-broken-lsp':
                value = 'install allow-broken-lsps'
            sections[context].add(value)

    output = ['mpls ldp', *(' ' + line for line in sorted(sections[()]))]
    for family in sorted(key for key in sections if len(key) == 1):
        output.append(' ' + family[0])
        output.extend('  ' + line for line in sorted(sections[family]))
        for interface in sorted(key for key in sections if len(key) == 2 and key[:1] == family):
            output.append('  ' + interface[1])
            output.extend('   ' + line for line in sorted(sections[interface]))
            output.append('  exit')
        output.append(' exit-address-family')
    return '\n'.join([*output, 'exit'])


class Ldp:
    def desired(self, text):
        return self.select(text, ['mpls ldp']) if 'mpls ldp' in text.splitlines() else {}

    def select(self, text, scopes):
        present = 'mpls ldp' in text.splitlines()
        return {scope: [canonical(text)] if scope == 'mpls ldp' and present else [] for scope in scopes}

    def replace(self, text, desired):
        output = [line for line, owned in lines(text)
                  if not (owned and 'mpls ldp' in desired) and line.strip() != 'end']
        for blocks in desired.values():
            output.extend(blocks)
        return '\n'.join([*output, 'end', ''])


adapter = Ldp()
