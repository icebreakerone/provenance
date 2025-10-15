from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ib1.provenance.certificates import CertificateProviderBase as CertificateProvider


class SignerInMemory:
    def __init__(
        self,
        certificate_provider: CertificateProvider,
        certificates: list[x509.Certificate],
        private_key=None,
    ):
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
    def __init__(
        self,
        certificate_provider: CertificateProvider,
        certificate_file: str,
        key_file: str,
    ):
        with open(certificate_file, "rb") as certs:
            certificates = x509.load_pem_x509_certificates(certs.read())
        with open(key_file, "rb") as key:
            private_key = serialization.load_pem_private_key(key.read(), password=None)
        super().__init__(certificate_provider, certificates, private_key)


class SignerKMS(SignerInMemory):
    def __init__(
        self,
        certificate_provider: CertificateProvider,
        certificates: list[x509.Certificate],
        kms_client,
        key_id,
    ):
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 is required for SignerKMS")
        if kms_client is None or key_id is None:
            raise ValueError("kms_client and key_id are required for SignerKMS")
        self._kms_client = kms_client
        self._key_id = key_id
        super().__init__(certificate_provider, certificates)

    def sign(self, data):
        return self._kms_client.sign(KeyId=self._key_id, Message=data)
