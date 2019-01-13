#!/usr/bin/env python
"""
Created on 13/01/2019
Author pacellig
"""

import unittest

from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey as RSA_PRIVATE_INSTANCE
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey as RSA_PUBLIC_INSTANCE
from cryptography.hazmat.backends.openssl.x509 import _Certificate as X509CERTIFICATE_INSTANCE
from jwcrypto.jwk import JWK as JWK_INSTANCE

import RSAKeyHelper
import CertificateHelper
from JWKHelper import JWKHelper


class RSAMethods(unittest.TestCase):

    def test_rsa_instance_creation(self):
        rsa_key_helper = RSAKeyHelper.RSAKeyHelper('config.ini')
        key_pair = rsa_key_helper.generate_RSA_keypair()
        self.assertEqual(True,
                         isinstance(key_pair, RSA_PRIVATE_INSTANCE))

    def test_rsa_private_key_loading(self):
        # Test with good password
        rsa_key_helper = RSAKeyHelper.RSAKeyHelper('config.ini')
        kfp = rsa_key_helper.load_private_key_from_pem(file_path='key.pem', password='p4$$phr4ase')
        self.assertEqual(True,
                         isinstance(kfp, RSA_PRIVATE_INSTANCE))

        # Test with wrong password
        kfp = rsa_key_helper.load_private_key_from_pem(file_path='key.pem', password='WrongWrong')
        self.assertEqual(False,
                         isinstance(kfp, RSA_PRIVATE_INSTANCE))

    def test_rsa_public_key_loading(self):
        rsa_key_helper = RSAKeyHelper.RSAKeyHelper('config.ini')
        kfp = rsa_key_helper.load_private_key_from_pem(file_path='key.pem', password='p4$$phr4ase').public_key()
        self.assertEqual(True,
                         isinstance(kfp, RSA_PUBLIC_INSTANCE))


class X509methods(unittest.TestCase):

    def test_x509_generation(self):
        cert_helper = CertificateHelper.CertificateHelper('config.ini')
        self.assertEqual(X509CERTIFICATE_INSTANCE,
                         type(cert_helper.generate_certificate()))

    def test_x509_generation_with_key(self):
        rsa_key_helper = RSAKeyHelper.RSAKeyHelper('config.ini')
        cert_helper = CertificateHelper.CertificateHelper('config.ini')
        self.assertEqual(X509CERTIFICATE_INSTANCE,
                         type(cert_helper.generate_certificate(key=rsa_key_helper.generate_RSA_keypair())))

    def test_load_cert_from_pem(self):
        cert_helper = CertificateHelper.CertificateHelper('config.ini')
        self.assertEqual(X509CERTIFICATE_INSTANCE,
                         type(cert_helper.get_from_pem('cert.pem')))


class JWKMethods(unittest.TestCase):

    def test_JWK_generation(self):
        # Verify dictionary generation
        jwk_obj = JWKHelper('config.ini', 'key.pem', 'cert.pem').json_jwk_obj
        self.assertEqual(dict, type(jwk_obj))

        # Verify dictionary completeness
        complete = True
        parameters = ['alg', 'kty', 'use', 'e', 'n', 'kid', 'x5t']
        for param in parameters:
            if param not in jwk_obj:
                complete = False
                break
        self.assertEqual(True, complete)

    def test_JWK_from_file(self):
        with open('jwk_file.json', 'r') as fr:
            data = fr.read()
        self.assertEqual(JWK_INSTANCE, type(JWKHelper.get_from_json(data)))


if __name__ == '__main__':
    unittest.main()
