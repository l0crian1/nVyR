generate:
  kind: node
  description: Generate diagnostic reports
  access: net-admin
  children:

    system:
      kind: node
      description: System diagnostic reports
      children:

        diagnostics:
          kind: node
          description: Save a bounded diagnostic archive in /config/diagnostics
          command: ['diagnostics.nvyr.op', 'generate']
          stream: true
