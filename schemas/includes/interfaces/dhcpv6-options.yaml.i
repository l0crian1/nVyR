dhcpv6-options:
  kind: node
  anchor: true
  description: DHCPv6 client identity and requested options
  children:

    duid:
      kind: leaf_node
      description: Override the persistent DHCPv6 client identifier
      validators:
        dhcp-identifier: {minimum: 3, maximum: 130}
      hints:
        hex: Complete DUID in colon-separated hexadecimal bytes

    rapid-commit:
      kind: leaf_node
      valueless: true
      description: Accept a lease in a two-message exchange when offered

    no-release:
      kind: leaf_node
      valueless: true
      description: Keep the lease on the server when the client exits

    no-request-dns:
      kind: leaf_node
      valueless: true
      description: Omit recursive DNS servers from the DHCPv6 option request

    no-request-domain-search:
      kind: leaf_node
      valueless: true
      description: Omit the domain search list from the DHCPv6 option request

    parameters-only:
      kind: leaf_node
      valueless: true
      description: Request configuration information without an address or prefix
