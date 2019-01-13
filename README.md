# Python easy JSON Web Key 

This project provides utilities and examples to easily create and handle JSON Web Key (JWK) objects. 

## Getting Started

In order to get a grasp on how to use the code, have a look at the tests.

The project is divided into 3 main classes:

* [RSAKeyHelper](RSAKeyHelper.py) : This class acts as a facilitator for handling a RSA key pair.
* [CertificateHelper](CertificateHelper.py) : This class acts as a facilitator for handling a x509 certificates.
* [JWKHelper](JWKHelper.py) : This class provides utilities for creating and importing JWK, either starting form existing RSA keys and
x509 certificates, or creating them as needed.

### Prerequisites

This code has been developed with Python 2.7.15rc
 

In order to install the required libraries, simply run :

```bash
pip install -r requirements.txt
```

## Running the tests

```bash
python tests.py 
```

## Authors

* **Giuseppe Pacelli** 

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
