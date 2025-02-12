from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class SignerInMemory:
    def __init__(self, certificate_provider, certificates, private_key):
        self._certificate_provider = certificate_provider
        self._certificates = certificates
        self._private_key = private_key

    def serial(self):
        return str(
            self._certificates[0].serial_number
        )  # String, as JSON rounds large integers

    def certificates_for_record(self):
        if not self._certificate_provider.policy_include_certificates_in_record:
            return None
        return self._certificates.copy()

    def sign(self, data):
        # TODO: Use correct algorithm for type of key in certificate, assuming EC crypto
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))


class SignerFiles(SignerInMemory):
    def __init__(self, certificate_provider, certificate_file, key_file):
        with open(certificate_file, "rb") as certs:
            certificates = x509.load_pem_x509_certificates(certs.read())
        with open(key_file, "rb") as key:
            private_key = serialization.load_pem_private_key(key.read(), password=None)
        super().__init__(certificate_provider, certificates, private_key)
