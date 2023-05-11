import os
import sys
import datetime

import OpenSSL.SSL as ossl
import OpenSSL.crypto as ocrypt

from cryptography import x509
from cryptography.x509 import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# transponder - development misfin client/server
# identities and certificate handling
# lem (2023)

# this is software in flux - don't rely on it


# A nice round number...
default_expiry = datetime.timedelta(days=32768)


class Identity:
    """ A Misfin identity - mailbox, mailserver, and blurb. """

    def __init__(self, address, hostname=None, blurb=None, fingerprint=None):
        """ Make an identity, gracefully handling formatted addresses. """
        self.blurb = blurb
        self.fingerprint = fingerprint

        if hostname is None:
            # Assume the address is complete
            self.mailbox, self.hostname = address.split("@", 1)
        else:
            self.mailbox = address
            self.hostname = hostname

    def address(self):
        """ Just the contact address. """
        return "{}@{}".format(self.mailbox, self.hostname)

    def longform(self):
        """ A written form of the address that's easier to read. """
        return "{} ({})".format(self.blurb, self.address())

    def tofu(self):
        """ A format for storing the identity as text, vis-a-vis "trust on first use" validation. """
        if self.fingerprint is None: 
            raise ValueError("No fingerprint to store for validation")
        return "{} {} {}".format(self.address(), self.fingerprint, self.blurb)

    @classmethod 
    def from_tofu(cls, raw):
        """ Rebuilds an Identity from a string built by the above. """
        address, fingerprint, blurb = raw.split(" ", 2)
        return cls(address, fingerprint=fingerprint, blurb=blurb)


class PeerIdentity(Identity):
    """ An Identity constructed from a Misfin certificate. """

    def __init__(self, cert):
        """ Make a PeerIdentity, gracefully handling different cert types. """
        if isinstance(cert, bytes):
            self._cert = x509.load_pem_x509_certificate(cert)
        elif isinstance(cert, ocrypt.X509):
            self._cert = cert.to_cryptography()
        elif isinstance(cert, x509.Certificate):
            self._cert = cert
        else:
            raise TypeError("Can't load certificate")

        # Extract the juicy deets - very, very ugly
        hostname = self._cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)[0] # ew
        blurb = self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        mailbox = self._cert.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value

        # Pretty up the fingerprint
        fingerprint = "".join("%02x" % b for b in self._cert.fingerprint(hashes.SHA256()))

        super().__init__(mailbox, hostname, blurb, fingerprint)

    def is_ca(self):
        return self._cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca

    def as_pem(self):
        """ Serializes the PeerIdentity as PEM data. """
        return self._cert.public_bytes(serialization.Encoding.PEM)


class LocalIdentity(PeerIdentity):
    """ An Identity that can send messages (i.e. has a private key). """

    def __init__(self, cert, private, password=None):
        """ Make a LocalIdentity for an extant cert/key pair. """
        if isinstance(private, bytes):
            self._private = serialization.load_pem_private_key(private, password=password)
        elif isinstance(private, rsa.RSAPrivateKey) or private is None:
            self._private = private
        else:
            raise TypeError("Can't load private key")

        super().__init__(cert)

    def as_pem(self, encrypt=serialization.NoEncryption()):
        cert_data = super().as_pem()
        return cert_data + self._private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encrypt
        )

    # Below are methods for making new identities...
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
        private = LocalIdentity._build_key()
        subject = LocalIdentity._build_name(mailbox, blurb, additional_names)
        cert = LocalIdentity._build_cert(private.public_key(), private, subject, subject, hostname, is_ca, expires_in)

        return cls(cert, private)

    @classmethod
    def child_of(cls, parent, mailbox, blurb, additional_names=[], expires_in=default_expiry):
        """ Generate a child certificate, signed by a parent certificate. """
        if not parent.is_ca(): raise TypeError("Parent certificate can't be used to sign children")
        if not isinstance(parent, LocalIdentity): raise TypeError("Parent certificate is missing a private key")

        private = LocalIdentity._build_key()
        subject = LocalIdentity._build_name(mailbox, blurb, additional_names)

        csr = x509.CertificateSigningRequestBuilder() \
                .subject_name(subject) \
        .sign(private, hashes.SHA256())

        cert = LocalIdentity._build_cert(
                csr.public_key(), parent._private, 
                subject, parent._cert.subject, parent.hostname, 
                is_ca=False, expires_in=expires_in
        )

        return cls(cert, private)

