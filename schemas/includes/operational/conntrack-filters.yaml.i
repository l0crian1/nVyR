children:
  ipv4:
    kind: leaf_node
    valueless: true
    description: IPv4 connections only
  ipv6:
    kind: leaf_node
    valueless: true
    description: IPv6 connections only

  include_schema:
  - file: nftables/protocol.yaml.i
    remove: [/multi]

  state:
    kind: leaf_node
    description: Transport connection state (TCP, SCTP or DCCP)
    validators:
      list:
        values: >-
          none syn-sent syn-recv established fin-wait close-wait last-ack time-wait close syn-sent2
          closed cookie-wait cookie-echoed shutdown-sent shutdown-recd shutdown-ack-sent
          heartbeat-sent heartbeat-acked request respond partopen open closereq closing timewait
    choices:
      none: No protocol state established yet
      syn-sent: TCP SYN sent
      syn-recv: TCP SYN received
      established: TCP or SCTP connection established
      fin-wait: TCP FIN sent
      close-wait: TCP waiting for local close
      last-ack: TCP waiting for final acknowledgement
      time-wait: TCP waiting after closure
      close: TCP closed
      syn-sent2: TCP simultaneous open
      closed: SCTP closed
      cookie-wait: SCTP awaiting cookie
      cookie-echoed: SCTP cookie echoed
      shutdown-sent: SCTP shutdown sent
      shutdown-recd: SCTP shutdown received
      shutdown-ack-sent: SCTP shutdown acknowledged
      heartbeat-sent: SCTP legacy heartbeat sent
      heartbeat-acked: SCTP legacy heartbeat acknowledged
      request: DCCP request sent
      respond: DCCP response received
      partopen: DCCP partially open
      open: DCCP open
      closereq: DCCP close requested
      closing: DCCP closing
      timewait: DCCP waiting after closure

  source-address:
    kind: leaf_node
    description: Original source address before NAT
    validators:
      mode: OR
      ipv4-address: {}
      ipv6-address: {}
    hints:
      x.x.x.x: IPv4 source address
      x:x:x:x:x:x: IPv6 source address

  destination-address:
    kind: leaf_node
    description: Original destination address before NAT
    validators:
      mode: OR
      ipv4-address: {}
      ipv6-address: {}
    hints:
      x.x.x.x: IPv4 destination address
      x:x:x:x:x:x: IPv6 destination address

  detail:
    kind: leaf_node
    valueless: true
    description: Show original and reply tuples, status, and available accounting
