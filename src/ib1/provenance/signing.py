
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class SignerLocal:
    def __init__(self, certificate_provider, certificate_file, key_file):
        self._certificate_provider = certificate_provider
        with open(certificate_file, "rb") as cert:
            self._certificates = x509.load_pem_x509_certificates(cert.read())
        with open(key_file, "rb") as key:
            self._private_key = serialization.load_pem_private_key(key.read(), password=None)

    def _serial(self):
        return str(self._certificates[0].serial_number) # String, as JSON rounds large integers

    def _certificates_for_record(self):
        if not self._certificate_provider.policy_include_certificates_in_record():
            return None
        return self._certificates.copy();

    def _sign(self, data):
        # TODO: Use correct algorithm for type of key in certificate, assuming EC crypto
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
