
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class CertificatesLocal:
    def __init__(self, directory):
        self._directory = directory

    def _verify(self, serial, data, signature):
        certificate_filename = self._directory + '/' + str(int(serial)) + '-bundle.pem'
        with open(certificate_filename, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        pubkey = cert.public_key()
        pubkey.verify(signature, data, ec.ECDSA(hashes.SHA256()))
