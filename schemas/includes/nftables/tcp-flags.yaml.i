tcp-flags:
  kind: leaf_node
  multi: true
  joinable: {negatable: true}
  description: TCP flag requirements; repeat for alternative combinations
  validators:
    tcp-flags: {}
  hints:
    flag: Flag required set; use not for clear and and to combine
  choices:
    fin: Finish sending data
    syn: Synchronize sequence numbers
    rst: Reset the connection
    psh: Push buffered data
    ack: Acknowledgment field is significant
    urg: Urgent pointer is significant
    ecn: ECN echo
    cwr: Congestion window reduced
