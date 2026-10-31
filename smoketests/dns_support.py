"""Deterministic DNS responder, bound only inside an isolated test network namespace."""

import socketserver
import struct
import threading

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.reversename
import dns.rrset


def respond(wire, tcp=False):
    """Return known answers, explicit errors, and a truncated UDP response for TCP coverage."""
    request = dns.message.from_wire(wire)
    response = dns.message.make_response(request)
    question = request.question[0]
    name = question.name.to_text()
    kind = dns.rdatatype.to_text(question.rdtype)
    if name == 'missing.example.test.':
        response.set_rcode(dns.rcode.NXDOMAIN)
    elif name == 'broken.example.test.':
        response.set_rcode(dns.rcode.SERVFAIL)
    elif name == 'tcp.example.test.' and not tcp:
        response.flags |= dns.flags.TC
    else:
        answers = {
            ('example.test.', 'A'): '192.0.2.10',
            ('example.test.', 'AAAA'): '2001:db8::10',
            ('example.test.', 'MX'): '10 mail.example.test.',
            ('tcp.example.test.', 'A'): '192.0.2.11',
            ('10.2.0.192.in-addr.arpa.', 'PTR'): 'host.example.test.',
            (dns.reversename.from_address('2001:db8::10').to_text(), 'PTR'): 'host6.example.test.',
        }
        if name == 'alias.example.test.':
            response.answer.append(dns.rrset.from_text(name, 300, 'IN', 'CNAME', 'example.test.'))
            name = 'example.test.'
        value = answers.get((name, kind))
        if value is not None:
            response.answer.append(dns.rrset.from_text(name, 300, 'IN', kind, value))
    return response.to_wire()


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        """Answer one datagram without relying on the system resolver."""
        wire, connection = self.request
        connection.sendto(respond(wire), self.client_address)


class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        """Honor DNS-over-TCP framing after the resolver retries a truncated reply."""
        length = struct.unpack('!H', self.rfile.read(2))[0]
        response = respond(self.rfile.read(length), tcp=True)
        self.wfile.write(struct.pack('!H', len(response)) + response)


def serve():
    """Publish readiness only after both DNS transports have bound successfully."""
    with socketserver.UDPServer(('127.0.0.1', 53), UDPHandler) as udp:
        with socketserver.TCPServer(('127.0.0.1', 53), TCPHandler) as tcp:
            threading.Thread(target=tcp.serve_forever, daemon=True).start()
            print('ready', flush=True)
            udp.serve_forever()


if __name__ == '__main__':
    serve()
