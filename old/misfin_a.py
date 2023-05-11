import os
import sys
import time
import socket
import datetime

import OpenSSL.SSL as ossl
import OpenSSL.crypto as ocrypt

from cryptography import x509
from cryptography.x509 import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
 
#   _______
#  |==   []|  misfin(a) protocol
#  |  ==== |  implemented in one file
#  '-------'  lem (2023)


# ----------
# Certificate handling.

# A nice round number...
default_expiry = datetime.timedelta(days=32768)

class Identity:
    """ An identified user, either local (i.e. with a private key) or a peer. """
    def __init__(self, cert, private=None, password=None):
        """ Load an Identity from certificate and key objects, or from PEM data. """
        if isinstance(cert, bytes):
            self._cert = x509.load_pem_x509_certificate(cert)
        elif isinstance(cert, ocrypt.X509):
            self._cert = cert.to_cryptography()
        elif isinstance(cert, x509.Certificate):
            self._cert = cert
        else:
            raise TypeError("Can't load certificate")

        if isinstance(private, bytes):
            self._private = serialization.load_pem_private_key(private, password=password)
        elif isinstance(private, rsa.RSAPrivateKey) or private is None:
            self._private = private
        else:
            raise TypeError("Can't load private key")

    def _build_name(mailbox, blurb, additional_names=[]):
        """ Builds an x509 Name with the right format for a Misfin certificate. """
        mandatory = [x509.NameAttribute(NameOID.USER_ID, mailbox), x509.NameAttribute(NameOID.COMMON_NAME, blurb)]
        return x509.Name(mandatory + additional_names)

    def _build_key():
        """ Common method for building a private key. """
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _build_cert(pubkey, privkey, subject, issuer, hostname, is_ca, expires_in):
        """ Common method for building and signing an x509 certificate. """
        return x509.CertificateBuilder() \
                .subject_name(subject) \
                .issuer_name(issuer) \
                .public_key(pubkey) \
                .serial_number(x509.random_serial_number()) \
                .not_valid_before(datetime.datetime.utcnow()) \
                .not_valid_after(datetime.datetime.utcnow() + expires_in) \
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False) \
                .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True) \
        .sign(privkey, hashes.SHA256())

    @classmethod
    def new(cls, mailbox, blurb, hostname, is_ca=False, additional_names=[], expires_in=default_expiry):
        """ Generate a new, self-signed identity. """
        ob = cls.__new__(cls)

        ob._private = Identity._build_key()
        subject = Identity._build_name(mailbox, blurb, additional_names)
        ob._cert = Identity._build_cert(ob._private.public_key(), ob._private, subject, subject, hostname, is_ca, expires_in)

        return ob

    @classmethod
    def child_of(cls, parent, mailbox, blurb, additional_names=[], expires_in=default_expiry):
        """ Generate a child certificate, signed by a parent certificate. """
        if not parent.is_ca(): raise TypeError("Parent certificate can't be used to sign children")
        if parent.is_peer(): raise TypeError("Parent certificate is missing a private key")

        ob = cls.__new__(cls)
        ob._private = Identity._build_key()
        subject = Identity._build_name(mailbox, blurb, additional_names)

        csr = x509.CertificateSigningRequestBuilder() \
                .subject_name(subject) \
        .sign(ob._private, hashes.SHA256())

        ob._cert = Identity._build_cert(
                    csr.public_key(), parent._private, 
                    subject, parent._cert.subject, parent.hostname(), 
                    is_ca=False, expires_in=expires_in
        )

        return ob

    def as_pem(self, encryption=serialization.NoEncryption()):
        """ Serializes the Identity as PEM data. """
        built = self._cert.public_bytes(serialization.Encoding.PEM)
        if self._private is not None:
            built += self._private.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=encryption
            )

        return built

    # Ugly ugly ugly.
    # Note that these are hardcoded to the first found result for their attribute.
    # Misfin certs don't support multiple values for USER_ID and COMMON_NAME, and support for
    # multiple hostnames is possible but not implemented.
    def is_peer(self):
        return self._private is None
    def is_ca(self): 
        return self._cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    def hostname(self): 
        return self._cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)[0] # ew
    def blurb(self): 
        return self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    def mailbox(self):  
        return self._cert.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value
    def parent_blurb(self): 
        return self._cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    def parent_mailbox(self):  
        return self._cert.issuer.get_attributes_for_oid(NameOID.USER_ID)[0].value
    
    # Built addresses.
    def address(self): return self.mailbox() + "@" + self.hostname()
    def parent_address(self): return self.parent_mailbox() + "@" + self.hostname()

    # For TOFU.
    def fingerprint(self, hash_method=hashes.SHA256()): 
        raw = self._cert.fingerprint(hash_method)
        return ":".join("%02x" % b for b in raw)


# ----------
# Requests and responses.


class Request:
    """ The basic unit of data transfer for Misfin. Here's some data, here's where it's going. """

    def __init__(self, mailbox, host, subject, mime, body=None):
        self.mailbox = mailbox
        self.host = host
        self.subject = subject
        self.mime = mime
        self.body = body

    @classmethod
    def from_incoming(cls, req):
        """ Create a Request object from the client's greeting. """
        ob = cls.__new__(cls)
    
        # Auto-convert from a bytes object, makes socket code a little cleaner
        if isinstance(req, bytes): req = req.decode("utf-8")

        # Maybe this isn't even a Misfin request...
        if not req.startswith("misfin://"): raise TypeError("Not a Misfin request")
        req = req.removeprefix("misfin://")

        # Make sure we have the whole request, and save any body that might have made it through
        if "\r\n" not in req: raise ValueError("Incomplete request")
        header, ob.body = req.split("\r\n", 1)
    
        try:
            # Split up the relevant bits of the header
            dest, ob.mime, ob.subject = header.split(" ", 2)
            ob.mailbox, ob.host = dest.split("@", 1)
            return ob
        except:
            raise ValueError("Malformed request")

    def build(self):
        """ Builds the Misfin request greeting. """
        return "misfin://{}@{} {} {}\r\n".format(self.mailbox, self.host, self.mime, self.subject)
    
    def append_body(self, data):
        """ Appends more data to the message body - useful for large files. """
        if isinstance(data, bytes): data = data.decode("utf-8")
        if self.body is None: self.body = data
        else: self.body += data

# A Misfin server response - either a go ahead, or some flavor of error.
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
        54: "filetype not allowed",
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
    def proceed(max_size): 
        return Response.of(20, max_size)

    def redirect(to):
        return Response.of(30, to)

    def redirect_forever(to):
        return Response.of(31, to)

    @classmethod
    def from_server(cls, resp):
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
        return "{} {}\r\n".format(self.status, self.meta)

    def __str__(self):
        return "{} {}".format(self.status, self.meta)

    def was_successful(self): return self.status[0] == "2"
    def send_max(self): return int(self.meta)

    def was_redirect(self): return self.status[0] == "3"
    def was_temporary_error(self): return self.status[0] == "4"
    def was_permanent_error(self): return self.status[0] == "5"
    def was_certificate_error(self): return self.status[0] == "6"


# ----------
# Sending, receiving, and TLS.


# Default port to communicate over.
default_port = 1958

# Maximum amount of data to accept - by default, anyway.
max_request_size = 1024
max_request_data = 1024 * 1024

def _validate_nothing(conn, cert, err, depth, rtrn):
    """ Callback that lets us steal certificate verification from OpenSSL. """
    """ This is !!!DANGEROUS!!! but necessary to allow us to accept self-signed certs. """
    return True

def send_as(sender, request, port=default_port, check_valid_method=_validate_nothing):
    """ Sends a Misfin message as a user. """

    # For some reason, this block doesn't survive being moved to a separate function, so it's
    # repeated below in an ugly way.
    context = ossl.Context( ossl.TLS_CLIENT_METHOD )
    context.set_verify( ossl.VERIFY_PEER | ossl.VERIFY_FAIL_IF_NO_PEER_CERT, callback=check_valid_method)
    context.use_certificate( ocrypt.X509.from_cryptography(sender._cert) )
    context.use_privatekey( ocrypt.PKey.from_cryptography_key(sender._private) )
    sock = ossl.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    sock.connect((request.host, port))
    sock.set_connect_state()
    sock.do_handshake()

    # Send the first bit of our message and see if the destination accepts.
    sock.write(bytes(request.build(), "utf-8"))
    response = Response.from_server(sock.read(max_request_size))
    if not response.was_successful(): return response

    # They're happy, so send over the rest.
    if response.send_max() >= len(request.body):
        sock.sendall(bytes(request.body, 'utf-8'))
    else:
        raise ValueError("Message is {} bytes, but server only accepts {}".format(len(request.body), response.send_max()))

    # Skadoodle
    sock.shutdown()
    sock.close()
    return True

def _allow_anything(server, peer, request):
    """ Callback that accepts any message to the server's mailbox. """
    """ SCARY! Only use for testing. """
    print("Incoming from {} ({})".format(peer.blurb(), peer.address()))
    print("Fingerprint is {}".format(peer.fingerprint()))
    print("Message type is {}, subject: {}".format(request.mime, request.subject))

    if request.mailbox == server.mailbox():
        return Response.proceed(max_request_data)
    else:
        print("...but we aren't {}, we're {}".format(server.mailbox(), request.mailbox))
        return Response.of(51)

def _echo_messages(server, peer, message):
    """ Callback that prints messages to the console, or bytes received for non-text mimetypes. """
    """ Not really scary, but still just for testing. """
    if message.mime.startswith("text/"):
        print(message.body)
    else:
        print("Content is {} bytes long - not printing though".format(len(message.body)))

def receive_from(connection, server, peer, is_allowed_method, received_method):
    """ Receives a Misfin message from a client. """
    # Do we want to receive this message?
    try:
        request = Request.from_incoming(connection.read(max_request_size))
        response = is_allowed_method(server, peer, request)
        connection.write(bytes(response.build(), 'utf-8'))

        if response.was_successful():
            # Get some bytes, but not too many.
            to_get = response.send_max()
            while to_get > 0:
                # The client should yeet the connection when they finish sending, so
                # catch that and interpret it as "we're done here".
                try: 
                    got = connection.recv(to_get)
                except ossl.Error:
                    got = b""
                if len(got) < 1: break
                request.append_body(got)
                to_get -= len(got)

    except Exception as err:
        # Something fucked up, be nice and tell the client.
        connection.write(bytes(Response.of(40).build(), "utf-8"))
        raise err

    # Skadoodle
    connection.shutdown()
    connection.close()

    # Call the callback, or! just handle the return
    received_method(server, peer, request)
    return request

def receive_forever(server, is_allowed_method=_allow_anything, received_method=_echo_messages, check_valid_method=_validate_nothing, port=default_port):
    """ Receives Misfin messages, forever and ever. """
    # See above.
    context = ossl.Context( ossl.TLS_SERVER_METHOD )
    context.set_verify( ossl.VERIFY_PEER | ossl.VERIFY_FAIL_IF_NO_PEER_CERT, callback=check_valid_method)
    context.use_certificate( ocrypt.X509.from_cryptography(server._cert) )
    context.use_privatekey( ocrypt.PKey.from_cryptography_key(server._private) )
    sock = ossl.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    sock.bind((server.hostname(), port))
    sock.listen(3)

    while True:
        print("")
        try:
            # Set up a connection...
            connection, addr = sock.accept()
            connection.set_accept_state()
            connection.do_handshake()

            # ...and do something about it
            peer = Identity(connection.get_peer_certificate())
            receive_from(connection, server, peer, is_allowed_method, received_method)

        except ossl.Error as err:
            print("Client disconnected before finishing.")

        except Exception as err:
            print(err)
            print("Aborting receive due to exception.")

# ----------
# Stupid simple command-line interface.


if __name__ == "__main__":

    # I wasn't kidding.
    def print_usage():
        print("usage: python -m misfin_a [make-cert mailbox blurb hostname output.who]")
        print("usage:                    [cert-from parent.who mailbox blurb output.who]")
        print("usage:                    [send-as identity.who destination 'subject' 'message']")
        print("usage:                    [receive-as identity.who]")
        sys.exit(-1)

    try:
        command = sys.argv[1]

        if command == "make-cert":
            mailbox, blurb, hostname, output = sys.argv[2:]

            ident = Identity.new(mailbox, blurb, hostname, is_ca=True)
            with open(output, "wb") as dest: dest.write(ident.as_pem())

            print("Generated cert for {} ({}) - saved to {}".format(ident.blurb(), ident.address(), output))

        elif command == "cert-from":
            parent, mailbox, blurb, output = sys.argv[2:]

            loaded_pem = open(parent, "rb").read()
            parent_ident = Identity(loaded_pem, loaded_pem)
            ident = Identity.child_of(parent_ident, mailbox, blurb)
            with open(output, "wb") as dest: dest.write(ident.as_pem())

            print("Generated cert for {} ({}), child of {} ({}) - saved to {}".format(ident.blurb(), ident.address(), ident.parent_blurb(), ident.parent_address(), output))

        elif command == "send-as":
            sender, destination, subject, message = sys.argv[2:]
            mailbox, host = destination.split("@", 1)

            loaded_pem = open(sender, "rb").read()
            ident = Identity(loaded_pem, loaded_pem)
            msg = Request(mailbox, host, subject, mime="text/gemini", body=message)

            print(send_as(ident, msg))

        elif command == "receive-as":
            loaded_pem = open(sys.argv[2], "rb").read()
            ident = Identity(loaded_pem, loaded_pem)

            print("Receiving for {} ({})".format(ident.blurb(), ident.address()))
            receive_forever(ident)

    except Exception as err:
        # Hehe
        raise err
        print(err)
        print_usage()
