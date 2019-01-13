#!/usr/bin/env python
"""
Created on 13/01/2019
Author pacellig

This class acts as a facilitator for handling a x509 certificates:

    - x509 certificate generation
    - x509 certificate deserialization from PEM-encoded file
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import ConfigParser
import datetime
import io
import base64

import RSAKeyHelper


class CertificateHelper:
    def __init__(self, config_file=None, pem_path=None):
        """
        Generate a CertificateHelper object, starting from:
        :param config_file: File containing the configurations needed
        :param pem_path: A PEM - Encoded Certificate
        """
        self.config_file = config_file
        self.config = None

        self.cert_file = None
        self.cert = None

        if config_file is not None:
            self._load_configurations()
            self.rsa_key_helper_instance = RSAKeyHelper.RSAKeyHelper(config_file)
        elif pem_path is not None:
            self.get_from_pem(pem_path)

    def generate_certificate(self, key=None, passphrase=None):
        if key is None:
            key = self.rsa_key_helper_instance.generate_RSA_keypair(passphrase)

        # Various details about who we are. For a self-signed certificate the
        # subject and issuer are always the same.
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, unicode(self.config.get("cert-defaults", "COUNTRY_NAME"))),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, unicode(self.config.get("cert-defaults", "STATE_OR_PROVINCE_NAME"))),
            x509.NameAttribute(NameOID.LOCALITY_NAME, unicode(self.config.get("cert-defaults", "LOCALITY_NAME"))),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, unicode(self.config.get("cert-defaults", "ORGANIZATION_NAME"))),
            x509.NameAttribute(NameOID.COMMON_NAME, unicode(self.config.get("cert-defaults", "COMMON_NAME"))),
        ])

        cert = x509.CertificateBuilder().subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)) \
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(unicode(self.config.get("cert-defaults", "DNSName")))]),
                           critical=False, ) \
            .sign(key, hashes.SHA256(), default_backend())

        # Write our certificate out to disk.
        with open(self.cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        self.cert = cert
        return self.cert

    def get_certificate_fingerprint(self):
        return self.cert.fingerprint(hashes.SHA256())

    def get_certificate_fingerprint_base64_encoded(self):
        return base64.b64encode(self.get_certificate_fingerprint())

    def get_from_pem(self, path_to_pem_file):
        """
        Loads a x509 certificate from file into an object.
        :param path_to_pem_file:
        :return:
        """
        x509_obj = None
        with open(path_to_pem_file, 'rb') as cert_file:
            data = cert_file.read()
        # Convert the raw certificate data into a certificate object, first
        # as a PEM-encoded certificate and, if that fails, then as a
        # DER-encoded certificate. If both fail, the certificate cannot be
        # loaded.
        try:
            x509_obj = x509.load_pem_x509_certificate(data, default_backend())
        except Exception:
            try:
                x509_obj = x509.load_der_x509_certificate(data, default_backend())
            except Exception:
                print "Failed to load certificate from " + str(path_to_pem_file)
        self.cert = x509_obj
        return x509_obj

    def _load_configurations(self):
        """
        Load all the needed configurations from configuration file.
        :return:
        """
        with open(self.config_file) as f:
            configs = f.read()
        config = ConfigParser.RawConfigParser(allow_no_value=True)
        config.readfp(io.BytesIO(configs))
        self.config = config
        #
        self.cert_file = self.config.get("cert-paths", "cert_file")
