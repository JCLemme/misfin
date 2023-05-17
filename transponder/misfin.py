import os
import sys
import socket
import datetime

from transponder.identity import Identity, PeerIdentity, LocalIdentity

import OpenSSL.SSL as ossl
import OpenSSL.crypto as ocrypt

from cryptography import x509
from cryptography.x509 import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# transponder - development misfin client/server
# misfin protocol requests, responses, and networking
# lem (2023)

# this is software in flux - don't rely on it


max_request_size = 2048
default_port = 1958


class Request:
    """ A Misfin request - here's some data, here's where it's going. """

    def __init__(self, recipient: Identity, payload: str):
        self.recipient = recipient
        self.payload = payload

        if len(self.build()) > 2048: 
            raise ValueError("Request is too large to send ({} bytes)".format(len(self.build())))

    def build(self):
        return "misfin://{} {}\r\n".format(self.recipient.address(), self.payload)

    @classmethod
    def incoming(cls, raw):
        """ Reassemble a Request sent by a client. """
        # Auto-convert from a bytes object, makes socket code a little cleaner
        if isinstance(raw, bytes): raw = raw.decode("utf-8")

        # Maybe this isn't even a Misfin request...
        if not raw.startswith("misfin://"): raise TypeError("Not a Misfin request")
        raw = raw.removeprefix("misfin://")

        # Make sure we have the whole request
        if "\r\n" not in raw: raise ValueError("Incomplete request - didn't end with crlf")
        header, _ = raw.split("\r\n", 1)
    
        try:
            # Split up the relevant bits of the header
            address, payload = header.split(" ", 1)
            return cls(Identity(address), payload)
        except:
            raise ValueError("Malformed request")


class Response:
    """ Tells the client what to do - either a go ahead, or some flavor of error. """

    # Handy error messages for a server to send.
    # Note that 20, 30, and 31 shouldn't use these messages, but they are included 
    # here for completeness
    meta_tags = {
        20: "message accepted",

        30: "mailbox changed, look here",
        31: "mailbox changed, look here (permanent)",

        40: "temporary error",
        41: "server is unavailable",
        42: "cgi error",
        43: "proxying error",
        44: "slow down",
        45: "mailbox full",

        50: "permanent error",
        51: "mailbox doesn't exist",
        52: "mailbox has been removed",
        53: "that domain isn't served here",
        59: "bad request",

        60: "certificate required",
        61: "you can't send mail there",
        62: "your certificate is invalid",
        63: "you're lying about your certificate",
        64: "prove it"
    }

    @classmethod
    def of(cls, status, meta=None):
        """ Build a Response object for a status code. """
        ob = cls.__new__(cls)
        ob.status = str(status)
        if meta is None: ob.meta = Response.meta_tags[status]
        else: ob.meta = meta
        return ob

    # Some shortcuts for responses that actually use the meta tag
    def delivered(fingerprint): 
        return Response.of(20, fingerprint)

    def redirect(to):
        return Response.of(30, to)

    def redirect_forever(to):
        return Response.of(31, to)

    @classmethod
    def incoming(cls, resp):
        """ Creates a Response object from the server's response. """
        ob = cls.__new__(cls)

        # Auto-convert from a bytes object, makes socket code a little cleaner
        if isinstance(resp, bytes): resp = resp.decode("utf-8")

        try:
            ob.status, ob.meta = resp.split(" ", 1)
            return ob
        except:
            raise ValueError("Malformed response")
    
    def build(self):
        return bytes("{} {}\r\n".format(self.status, self.meta), "utf-8")

    def __str__(self):
        return "{} {}".format(self.status, self.meta)

    def was_successful(self): return self.status[0] == "2"
    def was_redirect(self): return self.status[0] == "3"
    def was_temporary_error(self): return self.status[0] == "4"
    def was_permanent_error(self): return self.status[0] == "5"
    def was_certificate_error(self): return self.status[0] == "6"


def _receive_line(conn, size=max_request_size, timeout=20, until=b"\r\n"):
    """ Receives a Misfin request/response, with configurable timeout etc. """
    """ Note that this doesn't guarantee the received data will be valid... """
    raw = b""
    conn.settimeout(timeout)

    try:
        while len(raw) <= size and until not in raw: 
            try: raw += conn.recv(size - len(raw))
            except ossl.WantReadError: pass

    except socket.timeout:
        pass

    return raw


def _validate_nothing(conn, cert, err, depth, rtrn):
    """ Callback that lets us steal certificate verification from OpenSSL. """
    """ This is !!!DANGEROUS!!! but necessary to allow us to accept self-signed certs. """
    return True


def send_as(sender: LocalIdentity, req: Request, check_valid_method=_validate_nothing):
    """ Sends a Misfin message. """
    # For some reason, this block doesn't survive being moved to a separate function, so it's
    # repeated below in an ugly way.
    context = ossl.Context( ossl.TLS_CLIENT_METHOD )
    context.set_verify( ossl.VERIFY_PEER | ossl.VERIFY_FAIL_IF_NO_PEER_CERT, callback=check_valid_method)
    context.use_certificate( ocrypt.X509.from_cryptography(sender._cert) )
    context.use_privatekey( ocrypt.PKey.from_cryptography_key(sender._private) )
    sock = ossl.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    sock.connect((req.recipient.hostname, default_port))
    sock.set_connect_state()
    sock.do_handshake()

    # Send our message and see if the destination accepts.
    sock.sendall(req.build())
    response = Response.incoming(_receive_line(sock))

    # Skadoodle
    sock.shutdown()
    sock.close()
    return response


def receive_from(conn, server: LocalIdentity, peer: PeerIdentity, on_letter_received):
    """ Receives a Misfin message from a client. """
    # Do we want to receive this message?
    try:
        req = Request.incoming(_receive_line(conn))
        resp = on_letter_received(server, peer, req)
        conn.sendall(resp.build())

    except ossl.ZeroReturnError:
        # The client closed the connection intentionally. Carry on...
        pass

    except ossl.SysCallError:
        # Pretty sure this is also OK...
        pass

    except Exception as err:
        # Something fucked up, be nice and tell the client before handling it.
        conn.sendall(Response.of(40).build())
        conn.shutdown()
        conn.close()

        print("Error during receive - here's what we recovered:")
        print(peer.address())
        print(req.payload)

        raise err

    # Skadoodle
    conn.shutdown()
    conn.close()

    return req


def receive_forever(server: LocalIdentity, on_letter_received, check_valid_method=_validate_nothing):
    """ Receives Misfin messages, forever and ever. """
    # See above.
    context = ossl.Context( ossl.TLS_SERVER_METHOD )
    context.set_verify( ossl.VERIFY_PEER | ossl.VERIFY_FAIL_IF_NO_PEER_CERT, callback=check_valid_method)
    context.use_certificate( ocrypt.X509.from_cryptography(server._cert) )
    context.use_privatekey( ocrypt.PKey.from_cryptography_key(server._private) )
    sock = ossl.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    sock.bind((server.hostname, default_port))
    sock.listen(3)

    while True:
        print("")
        try:
            # Set up a connection...
            conn, addr = sock.accept()
            conn.set_accept_state()
            conn.do_handshake()

            print("Incoming connection at {}".format(datetime.datetime.utcnow()))

            # ...and do something about it
            peer = PeerIdentity(conn.get_peer_certificate())
            receive_from(conn, server, peer, on_letter_received)

        except Exception as err:
            #raise err
            print(type(err).__name__, err)
            print("Aborting due to exception.")







# Shhhhh don't look 

def do_via_tls(credentials: LocalIdentity, hostname: str, port: int, lo):
    """ Sets up a TLS client context, and hands it off to a more useful function. """
    context = ossl.Context( ossl.TLS_CLIENT_METHOD )
    context.set_verify( ossl.VERIFY_PEER | ossl.VERIFY_FAIL_IF_NO_PEER_CERT, callback=check_valid_method)
    context.use_certificate( ocrypt.X509.from_cryptography(credentials._cert) )
    context.use_privatekey( ocrypt.PKey.from_cryptography_key(credentials._private) )
    sock = ossl.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))    

    sock.connect((hostname, port))
    sock.set_connect_state()
    sock.do_handshake()

    result = callback(sock)

    sock.shutdown()
    sock.close()
    return result
