#!/usr/bin/env python
"""
Created on 13/01/2019
Author pacellig

This class provides utilities for creating and importing JWK, either starting form existing RSA keys and
x509 certificates, or creating them as needed.

Each JWK might contain:

    alg: is the algorithm for the key
    kty: is the key type
    use: is how the key was meant to be used. For the example above sig represents signature.
    x5c: is the x509 certificate chain
    e: is the exponent for a standard pem
    n: is the modulus for a standard pem
    kid: is the unique identifier for the key
    x5t: is the thumbprint of the x.509 cert (SHA-1 thumbprint)

"""
import RSAKeyHelper
import CertificateHelper

from jwcrypto import jwk
import ConfigParser
import json
import io


class JWKHelper:
    def __init__(self, config_file, rsa_keypair_pem=None, certificate_pem=None):
        self.config_file = config_file
        self.config = None

        self.rsa_passphrase = None
        self.cert_passphrase = None
        self.key_use = None         # might be 'sig' or 'enc'
        self._load_configurations()

        # Keys and certificates instances
        self.rsa_keypair_pem = rsa_keypair_pem
        self.rsa_keypair = None
        self.certificate_pem = certificate_pem

        self._json_jwk_obj = None

        # Setup
        self._verify_JWK_completeness()

    def _verify_JWK_completeness(self):
        """
        Create (filling) a complete JWK object.
        :return:
        """
        if not self.rsa_keypair_pem:
            # Generate RSA keypair AND certificate
            rsa_key_helper = RSAKeyHelper.RSAKeyHelper(self.config_file)
            self.rsa_keypair = rsa_key_helper.generate_RSA_keypair(passphrase=self.rsa_passphrase)
            self.rsa_keypair_pem = self.config.get('key-paths', 'key_file')
        if not self.certificate_pem:
            # Generate certificate
            cert_helper = CertificateHelper.CertificateHelper(self.config_file)
            cert_helper.generate_certificate(key=self.rsa_keypair, passphrase=self.rsa_passphrase)
            self.certificate_pem = self.config.get('cert-paths', 'cert_file')
        if self.rsa_keypair_pem and self.certificate_pem:
            self.create_from_rsa_pem(self.rsa_keypair_pem, self.rsa_passphrase)
            # Fill with key use and certificate details
            if 'alg' not in self.json_jwk_obj:
                self.json_jwk_obj[u'alg'] = u'RS256'
            if 'use' not in self.json_jwk_obj:
                self.json_jwk_obj[u'use'] = unicode(self.key_use)
            if 'x5t' not in self.json_jwk_obj:
                self.json_jwk_obj[u'x5t'] = unicode(self._make_certificate_x5t_from_pem(self.certificate_pem))

    @staticmethod
    def get_from_json(json_obj):
        """
        Creates a JWK object from a json file.
        :param json_obj:
        :return:
        """
        json_obj = json.loads(json_obj)
        jwk_obj = jwk.JWK(**json_obj)
        #jwk_obj = jwk_obj.from_json(json.dumps(json_obj))
        return jwk_obj

    def create_from_rsa_pem(self, pem_file_path, passphrase):
        """
        Creates a JWKHelper object from a RSA keypair.
        Returns the json serialization of the object.
        :param pem_file_path: path to pem file
        :param passphrase: password for decrypting
        :return: json
        """
        pem_key = JWKHelper._get_from_pem(pem_file_path, passphrase)
        self._json_jwk_obj = JWKHelper._get_json_key(JWKHelper._get_pubkey(pem_key))
        return self.json_jwk_obj

    @staticmethod
    def _get_from_pem(path_to_pem_file, passphrase):
        """
        Deserialize a RSA key into a jwk.JWK object from a PEM file.
        TODO: add try except block
        :return:
        """
        with open(path_to_pem_file, "rb") as f:
            pem_key = jwk.JWK.from_pem(f.read(), password=bytes(passphrase))
        return pem_key

    @staticmethod
    def _get_json_key(key):
        """
        Return the json serialization for the key.
        :param key:
        :return:
        """
        json_obj = json.loads(key)
        return json_obj

    @staticmethod
    def _get_pubkey(rsa_key_pair):
        """
        Extract the RSA public key from a RSA_keypair.
        :param RSA_keypair:
        :return:
        """
        pub_key = rsa_key_pair.export(private_key=False)
        return pub_key

    @staticmethod
    def _make_certificate_x5t_from_pem(path_to_pem_file):
        cert_helper = CertificateHelper.CertificateHelper(pem_path=path_to_pem_file)
        return cert_helper.get_certificate_fingerprint_base64_encoded()

    @staticmethod
    def export_to_json(jwk_obj):
        return json.dumps(jwk_obj)

    @staticmethod
    def export_to_pem(jwk_obj):
        pass

    @property
    def json_jwk_obj(self):
        return self._json_jwk_obj

    # # # Configurations

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
        self.rsa_passphrase = config.get("key-defaults", "passphrase")
        self.cert_passphrase = config.get("cert-defaults", "passphrase")
        self.key_use = config.get("key-defaults", 'key_use')