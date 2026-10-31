rule:
  kind: tag_node
  description: Select a firewall rule
  validators:
    integer-range: {minimum: 1, maximum: 999999}
  hints:
    number: Firewall rule number
  children: # rule

    limit:
      kind: node
      description: Installed rate and connection limits with active keys

    quota:
      kind: node
      description: Installed quota allowance and consumption

    include_schema:
    - file: operational/firewall_detail.yaml.i
