
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class SignerLocal:
    def __init__(self, certificate_file, key_file):
        with open(certificate_file, "rb") as cert:
            self._certificate = x509.load_pem_x509_certificate(cert.read(), default_backend())
        with open(key_file, "rb") as key:
            self._private_key = serialization.load_pem_private_key(key.read(), password=None, backend=default_backend())

    def _serial(self):
        return str(self._certificate.serial_number) # String, as JSON rounds large integers

    def _sign(self, data):
        # TODO: Use correct algorithm for type of key in certificate, assuming EC crypto
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
