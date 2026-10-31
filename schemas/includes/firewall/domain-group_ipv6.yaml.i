ipv6:
  kind: tag_node
  anchor: true
  dependency: firewall-domain-group-ipv6
  description: Named IPv6 domain group
  validators:
    regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
  hints:
    name: Group name
  children: # ipv6

    include_schema:
    - file: firewall/group-description.yaml.i
    - file: nftables/counter.yaml.i
    - file: nftables/last-used.yaml.i

    domain:
      kind: leaf_node
      multi: true
      description: Exact DNS name to resolve; does not include subdomains
      validators:
        dns-name: {}
      hints:
        hostname: DNS hostname or domain

    lookup:
      kind: node
      anchor: true
      description: DNS lookup settings
      children:

        rounds:
          kind: leaf_node
          description: Back-to-back lookups per domain on each refresh
          validators:
            integer-range: {minimum: 1, maximum: 100}
          hints:
            1-100: Number of lookup rounds
          default:
            mode: direct
            value: '1'

    include-group:
      kind: leaf_node
      multi: true
      description: Include configured members of another group of the same type
      depends: firewall-domain-group-ipv6
      validators:
        regex: {pattern: '[A-Za-z_][A-Za-z0-9_-]{0,62}'}
      hints:
        name: Existing domain-group IPv6 name
      suggestors:
        config-path: {path: 'firewall group domain-group ipv6'}
