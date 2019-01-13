#!/usr/bin/env python
"""
Created on 13/01/2019
Author pacellig

This class acts as a facilitator for handling a RSA key pair, particularly:
    - Key pair creation using parameters from configuration file
    - Loading of public key from a PEM-encoded file
    - Loading of private key from a PEM-encoded file
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import io
import ConfigParser


class RSAKeyHelper:
    def __init__(self, config_file):
        self.config_file = config_file
        self.config = None

        self.default_passphrase = None
        self.key_file = None
        self.public_exponent = 65537
        self.key_size = 2048

        self._load_configurations()

    def generate_RSA_keypair(self, passphrase=None):
        if passphrase is None:
            passphrase = self.default_passphrase

        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=self.public_exponent,
            key_size=self.key_size,
            backend=default_backend()
        )
        # Store the key
        with open(self.key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(bytes(passphrase)),
            ))
        return key

    @staticmethod
    def load_public_key_from_pem(pem_encoded_data=None, file_path=None):
        """
        Loads a public key either from data or from file path.
        :param pem_encoded_data:
        :return:
        """
        if pem_encoded_data is None and file_path is not None:
            with open(file_path, "rb") as key_file:
                pem_encoded_data = key_file.read()
        key = serialization.load_pem_public_key(
                                                        pem_encoded_data,
                                                        backend=default_backend()
                                                        )
        return key

    @staticmethod
    def load_private_key_from_pem(pem_encoded_data=None, file_path=None, password=None):
        """
        Loads a public key either from data or from file path.
        :param pem_encoded_data:
        :return:
        """
        if pem_encoded_data is None and file_path is not None:
            with open(file_path, "rb") as key_file:
                pem_encoded_data = key_file.read()

        try:
            key = serialization.load_pem_private_key(
                                                    pem_encoded_data,
                                                    password=password,
                                                    backend=default_backend()
                                                )
        except ValueError:
            key = None
        return key

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
        self.default_passphrase = config.get("key-defaults", "passphrase")
        self.public_exponent = int(config.get("key-defaults", "public_exponent"))
        self.key_size = int(config.get("key-defaults", "key_size"))
        self.key_file = config.get("key-paths", "key_file")
