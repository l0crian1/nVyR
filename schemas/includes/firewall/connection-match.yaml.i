connection:
  kind: node
  anchor: true
  description: Connection fields included in the lookup key
  children:

    state:
      kind: leaf_node
      valueless: true
      description: Include connection state in the lookup key

    direction:
      kind: leaf_node
      valueless: true
      description: Include connection direction in the lookup key

    family:
      kind: leaf_node
      valueless: true
      description: Include connection family in the lookup key

    mark:
      kind: leaf_node
      valueless: true
      description: Include connection mark in the lookup key

    zone:
      kind: leaf_node
      valueless: true
      description: Include connection zone in the lookup key

    id:
      kind: leaf_node
      valueless: true
      description: Include connection id in the lookup key

    helper:
      kind: leaf_node
      valueless: true
      description: Include connection helper in the lookup key

    expiration:
      kind: leaf_node
      valueless: true
      description: Include connection expiration in the lookup key

    original:
      kind: node
      anchor: true
      description: Inspect the stored original direction
      children:

        packets:
          kind: leaf_node
          valueless: true
          description: Include original-direction packet count in the lookup key

        bytes:
          kind: leaf_node
          valueless: true
          description: Include original-direction byte count in the lookup key

        average-packet-size:
          kind: leaf_node
          valueless: true
          description: Include original-direction average packet size in the lookup key

        zone:
          kind: leaf_node
          valueless: true
          description: Include original-direction zone in the lookup key

        source-address:
          kind: leaf_node
          valueless: true
          description: Include original-direction source address in the lookup key

        source-port:
          kind: leaf_node
          valueless: true
          description: Include original-direction source port in the lookup key

        destination-address:
          kind: leaf_node
          valueless: true
          description: Include original-direction destination address in the lookup key

        destination-port:
          kind: leaf_node
          valueless: true
          description: Include original-direction destination port in the lookup key

    reply:
      kind: node
      anchor: true
      description: Inspect the stored reply direction
      children:

        packets:
          kind: leaf_node
          valueless: true
          description: Include reply-direction packet count in the lookup key

        bytes:
          kind: leaf_node
          valueless: true
          description: Include reply-direction byte count in the lookup key

        average-packet-size:
          kind: leaf_node
          valueless: true
          description: Include reply-direction average packet size in the lookup key

        zone:
          kind: leaf_node
          valueless: true
          description: Include reply-direction zone in the lookup key

        source-address:
          kind: leaf_node
          valueless: true
          description: Include reply-direction source address in the lookup key

        source-port:
          kind: leaf_node
          valueless: true
          description: Include reply-direction source port in the lookup key

        destination-address:
          kind: leaf_node
          valueless: true
          description: Include reply-direction destination address in the lookup key

        destination-port:
          kind: leaf_node
          valueless: true
          description: Include reply-direction destination port in the lookup key

    total:
      kind: node
      anchor: true
      description: Accounting across both connection directions
      children:

        packets:
          kind: leaf_node
          valueless: true
          description: Include both-direction packet count in the lookup key

        bytes:
          kind: leaf_node
          valueless: true
          description: Include both-direction byte count in the lookup key

        average-packet-size:
          kind: leaf_node
          valueless: true
          description: Include both-direction average packet size in the lookup key

    status:
      kind: leaf_node
      valueless: true
      description: Include connection status in the lookup key

    protocol:
      kind: leaf_node
      valueless: true
      description: Include connection protocol in the lookup key
