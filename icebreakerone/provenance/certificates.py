
import json
import base64
import datetime

from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class CertificatesLocal:
    def __init__(self, directory, root_ca_certificate):
        self._directory = directory
        with open(root_ca_certificate, "rb") as f:
            self._ca_store = Store(x509.load_pem_x509_certificates(f.read()))

    def _verify(self, serial, sign_timestamp, data, signature):
        certificate_filename = self._directory + '/' + str(int(serial)) + '-bundle.pem'
        with open(certificate_filename, "rb") as f:
            certs = x509.load_pem_x509_certificates(f.read())
        # first certificate in file is signing certificate
        signing_cert, *issuer_chain = certs
        # 1) check certificate chain validity at the time of signature
        verification_time = datetime.datetime.fromisoformat(sign_timestamp)
        verifier = (PolicyBuilder().
                        store(self._ca_store).
                        time(verification_time).
                        build_client_verifier())
        verifier.verify(signing_cert, issuer_chain)
        # 2) check signature on data
        pubkey = signing_cert.public_key()
        pubkey.verify(signature, data, ec.ECDSA(hashes.SHA256()))
