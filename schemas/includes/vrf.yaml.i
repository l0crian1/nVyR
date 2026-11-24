vrf:
  kind: node
  description: Virtual routing and forwarding instances
  script:
    name: vrf_conntrack
    priority: 4
    watch-before:
    - vrf name * table
    - interfaces
    - container network
  children: # vrf

    name:
      kind: tag_node
      rename: false
      description: VRF instance
      dependency: vrf
      validators:
        regex: {pattern: '(?!default$)[a-zA-Z][a-zA-Z0-9_.-]{0,14}'}
      hints:
        name: VRF device name (1-15 characters; default is reserved)
      script:
        name: vrf
        priority: 5
      children: # name

        service:
          kind: node
          description: Services in this VRF
          children:

            include_schema:
            - file: service/dns.yaml.i
              replace:
                /children/forwarding/script/register/vrf: {tag: name}
            - file: service/dhcp-server.yaml.i
              remove:
              - /children/update-hostfile
              replace:
                /script/register/vrf: {tag: name}
            - file: service/dhcpv6-server.yaml.i
              remove:
              - /children/update-hostfile
              replace:
                /script/register/vrf: {tag: name}

        protocols:
          kind: node
          description: Routing protocols in this VRF
          children: # protocols

            include_schema:
            - file: protocols/static.yaml.i
              replace:
                /script/register/vrf: {tag: name}
            - file: protocols/bgp.yaml.i
              remove:
              - /children/neighbor/children/address-family/children/l2vpn-evpn
              - /children/peer-group/children/address-family/children/l2vpn-evpn
              - /children/parameters/children/labeled-unicast
              - /children/address-family/children/ipv4-vpn
              - /children/neighbor/children/address-family/children/ipv4-vpn
              - /children/peer-group/children/address-family/children/ipv4-vpn
              - /children/address-family/children/ipv6-vpn
              - /children/neighbor/children/address-family/children/ipv6-vpn
              - /children/peer-group/children/address-family/children/ipv6-vpn
              - /children/address-family/children/ipv4-labeled-unicast
              - /children/address-family/children/ipv6-labeled-unicast
              - /children/neighbor/children/address-family/children/ipv4-labeled-unicast
              - /children/neighbor/children/address-family/children/ipv6-labeled-unicast
              - /children/peer-group/children/address-family/children/ipv4-labeled-unicast
              - /children/peer-group/children/address-family/children/ipv6-labeled-unicast
              replace:
                /children/address-family/children/l2vpn-evpn:
                  include_schema:
                  - file: protocols/bgp/evpn-tenant.yaml.i
                    as: null
                /script/register/vrf: {tag: name}
            - file: protocols/ospf.yaml.i
              remove:
              - /children/options/children/opaque-lsa
              - /children/router-info
              - /children/ldp-sync
              - /children/interface/children/ldp-sync
              replace:
                /script/register/vrf: {tag: name}
            - file: protocols/ospfv3.yaml.i
              replace:
                /script/register/vrf: {tag: name}

            - file: protocols/isis.yaml.i
              remove:
              - /children/ldp-sync
              - /children/interface/children/ldp-sync
              replace:
                /script/register/vrf: {tag: name}
            - file: protocols/rip.yaml.i
              replace:
                /script/register/vrf: {tag: name}
            - file: protocols/ripng.yaml.i
              replace:
                /script/register/vrf: {tag: name}

        vni:
          kind: tag_node
          description: Layer 3 VXLAN network identifier for this VRF
          anchor: true
          script: {name: evpn-vni, priority: 44}
          validators:
            mode: AND
            regex: {pattern: '[1-9][0-9]{0,7}'}
            integer-range: {minimum: 1, maximum: 16777215}
          hints:
            1-16777215: Tenant L3VNI
          children:

            prefix-routes-only:
              kind: leaf_node
              description: Use the L3VNI only for prefix routes; omit its RT from MAC/IP advertisements
              valueless: true

        table:
          kind: leaf_node
          description: Unique routing table ID for this VRF
          validators:
            integer-ranges: {ranges: [[100, 251], [256, 4294967295]]}
          hints:
            100-251: Routing table ID
            256-4294967295: Routing table ID
